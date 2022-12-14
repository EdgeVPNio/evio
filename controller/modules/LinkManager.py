# EdgeVPNio
# Copyright 2020, University of Florida
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import os
import threading
import types
from collections import namedtuple
import time
from framework.ControllerModule import ControllerModule
from framework.CBT import CBT
from .Tunnel import TunnelEvents, TunnelStates, DataplaneTypes

LinkSetupTimeout = 120
TapNamePrefix = ""

class Link():
    _REFLECT = set(
        ["lnkid", "_creation_state", "status_retry"])

    def __init__(self, lnkid, state):
        self.lnkid = lnkid
        self._creation_state = state
        self.status_retry = 0
        self.stats = {}

    def __repr__(self):
        _keys = self._REFLECT if hasattr(
            self, "_REFLECT") else self.__dict__.keys()
        return "{{{}}}".format(", ".join((f"\"{k}\": {self.__dict__[k]!r}" for k in _keys)))

    @property
    def creation_state(self):
        return self._creation_state

    @creation_state.setter
    def creation_state(self, new_state):
        "todo: implement transition checks"
        self._creation_state = new_state


class Tunnel():
    def __init__(self, tnlid, overlay_id, peer_id, tnl_state, state_timeout, dataplane):
        self.tnlid = tnlid
        self.overlay_id = overlay_id
        self.peer_id = peer_id
        self.tap_name = None
        self.mac = None
        self.fpr = None
        self.link = None
        self.peer_mac = None
        self._tunnel_state = tnl_state
        self.creation_start_time = time.time()
        self.timeout = time.time() + state_timeout  # timeout for current phase
        self.dataplane = dataplane

    def __repr__(self):
        _keys = self._REFLECT if hasattr(
            self, "_REFLECT") else self.__dict__.keys()
        return "{{{}}}".format(", ".join((f"\"{k}\": {self.__dict__[k]!r}" for k in _keys)))

    @property
    def tunnel_state(self):
        return self._tunnel_state

    @tunnel_state.setter
    def tunnel_state(self, new_state):
        "todo: implement transition checks"
        self._tunnel_state = new_state


class LinkManager(ControllerModule):
    TAPNAME_MAXLEN = 15
    _REFLECT = set(["_peers", "_tunnels"])

    def __init__(self, cfx_handle, module_config, module_name):
        super(LinkManager, self).__init__(
            cfx_handle, module_config, module_name)
        self._tunnels = {}   # maps tunnel id to its descriptor
        self._links = {}     # maps link id to tunnel id
        self._lock = threading.Lock()  # serializes access to _overlays, _links
        self._link_updates_publisher = None
        self._ignored_net_interfaces = dict()

    def initialize(self):
        self._link_updates_publisher = \
            self.publish_subscription("LNK_TUNNEL_EVENTS")
        publishers = self.get_registered_publishers()
        if "TincanInterface" not in publishers or "TCI_TINCAN_MSG_NOTIFY" not in self.get_available_subscriptions("TincanInterface"):
            raise RuntimeError("The TincanInterface MESSAGE NOTIFY subscription is not available. Link Manager cannot continue.")
        self.start_subscription("TincanInterface","TCI_TINCAN_MSG_NOTIFY")
        if "OverlayVisualizer" in publishers and "VIS_DATA_REQ" in self.get_available_subscriptions("OverlayVisualizer"):
            self.start_subscription("OverlayVisualizer", "VIS_DATA_REQ")
        else:
            self.logger.info("Overlay visualizer capability unavailable")

        for olid in self.config["Overlays"]:
            self._ignored_net_interfaces[olid] = set()
            ol_cfg = self.config["Overlays"][olid]
            if "IgnoredNetInterfaces" in ol_cfg:
                for ign_inf in ol_cfg["IgnoredNetInterfaces"]:
                    self._ignored_net_interfaces[olid].add(ign_inf)

        self.logger.info("Module Loaded")

    def _get_ignored_tap_names(self, overlay_id, new_inf_name=None):
        ign_tap_names = set()
        if new_inf_name:
            ign_tap_names.add(new_inf_name)

        if not self.config["Overlays"][overlay_id].get("AllowRecursiveTunneling", False):
            # Ignore ALL the evio tap devices (regardless of their overlay id/link id)
            for tnlid in self._tunnels:
                if self._tunnels[tnlid].tap_name:
                    ign_tap_names.add(
                        self._tunnels[tnlid].tap_name)
            for tap_name in self._ignored_net_interfaces.values():
                ign_tap_names |= tap_name
        else:
            ign_tap_names |= self._ignored_net_interfaces[overlay_id]
        return ign_tap_names

    def is_complete_link(self, tnlid):
        is_complete = (self._tunnels.get(tnlid, False) and
                       self._tunnels[tnlid].link and
                       self._tunnels[tnlid].link.creation_state == 0xC0)
        return is_complete

    def req_handler_add_ign_inf(self, cbt):
        ign_inf_details = cbt.request.params
        for olid in ign_inf_details:
            self._ignored_net_interfaces[olid] |= ign_inf_details[olid]
        cbt.set_response(None, True)
        self.complete_cbt(cbt)

    def req_handler_remove_tnl(self, cbt):
        """Remove the tunnel and link given either the overlay id and peer id, or the tunnel id"""
        try:
            olid = cbt.request.params["OverlayId"]
            peer_id = cbt.request.params["PeerId"]
            tnlid = cbt.request.params["TunnelId"]
            # todo: if tnlid not in self._tunnels
            if self._tunnels[tnlid].tunnel_state == TunnelStates.ONLINE or \
                    self._tunnels[tnlid].tunnel_state == TunnelStates.OFFLINE:
                tn = self._tunnels[tnlid].tap_name
                params = {"OverlayId": olid, "TunnelId": tnlid,
                        "PeerId": peer_id, "TapName": tn}
                rtnl_cbt = self.create_linked_cbt(cbt)
                rtnl_cbt.set_request(
                    self.module_name, "TincanInterface", "TCI_REMOVE_TUNNEL", params)
                self.submit_cbt(rtnl_cbt)
            else:
                cbt.set_response("Tunnel busy, retry operation", False)
                self.complete_cbt(cbt)            
        except Exception as err:
            cbt.set_response("Insufficient parameters", False)
            self.complete_cbt(cbt)

    # def req_handler_remove_link(self, cbt):
    #     """Remove the link given either the overlay id and peer id, or the link id or tunnel id"""
    #     # not currently being used
    #     olid = cbt.request.params.get("OverlayId", None)
    #     peer_id = cbt.request.params.get("PeerId", None)
    #     lnkid = cbt.request.params.get("LinkId", None)
    #     tnlid = cbt.request.params.get("TunnelId", None)
    #     if self._tunnels[tnlid].tunnel_state == TunnelStates.ONLINE or \
    #             self._tunnels[tnlid].tunnel_state == TunnelStates.OFFLINE:
    #         params = {"OverlayId": olid, "TunnelId": tnlid,
    #                   "LinkId": lnkid, "PeerId": peer_id}
    #         self.register_cbt("TincanInterface", "TCI_REMOVE_LINK", params)
    #     else:
    #         cbt.set_response("Tunnel busy, retry operation", False)
    #         self.complete_cbt(cbt)

    def _update_tunnel_descriptor(self, tnl_desc, tnlid):
        """
        Update the tunnel desc with with lock owned
        """
        self._tunnels[tnlid].mac = tnl_desc["MAC"]
        self._tunnels[tnlid].tap_name = tnl_desc["TapName"]
        self._tunnels[tnlid].fpr = tnl_desc["FPR"]

    def _query_link_stats(self):
        """Query the status of links that have completed creation process"""
        params = []
        for tnlid in self._tunnels:
            link = self._tunnels[tnlid].link
            if link and link.creation_state == 0xC0:
                params.append(tnlid)
        if params:
            self.register_cbt("TincanInterface",
                              "TCI_QUERY_LINK_STATS", params)

    def resp_handler_query_link_stats(self, cbt):
        if not cbt.response.status:
            self.logger.warning("Link stats update error: %s",
                                cbt.response.data)
            self.free_cbt(cbt)
            return
        if not cbt.response.data:
            self.free_cbt(cbt)
            return
        data = cbt.response.data
        # Handle any connection failures and update tracking data
        for tnlid in data:
            for lnkid in data[tnlid]:
                if data[tnlid][lnkid]["Status"] == "UNKNOWN":
                    self._tunnels.pop(tnlid, None)
                elif tnlid in self._tunnels:
                    tnl = self._tunnels[tnlid]
                    if data[tnlid][lnkid]["Status"] == "OFFLINE":
                        # tincan indicates offline so recheck the link status
                        retry = tnl.link.status_retry
                        if retry >= 2 and tnl.tunnel_state == TunnelStates.CREATING:
                            # link is stuck creating so destroy it
                            olid = tnl.overlay_id
                            peer_id = tnl.peer_id
                            params = {"OverlayId": olid, "TunnelId": tnlid, "LinkId": lnkid,
                                      "PeerId": peer_id, "TapName": tnl.tap_name}
                            self.register_cbt(
                                "TincanInterface", "TCI_REMOVE_TUNNEL", params)
                        elif (tnl.tunnel_state == TunnelStates.QUERYING) or \
                             (retry >= 1 and tnl.tunnel_state == TunnelStates.ONLINE):
                            # LINK_STATE_DOWN event or QUERY_LNK_STATUS response - post notify
                            tnl.tunnel_state = TunnelStates.OFFLINE
                            olid = tnl.overlay_id
                            peer_id = tnl.peer_id
                            param = {
                                "UpdateType": TunnelEvents.Disconnected, "OverlayId": olid,
                                "PeerId": peer_id, "TunnelId": tnlid, "LinkId": lnkid,
                                "TapName": tnl.tap_name}
                            self._link_updates_publisher.post_update(param)
                        else:
                            self.logger.warning("Link %s is offline, no further attempts to to query its stats will be made.", tnlid)
                    elif data[tnlid][lnkid]["Status"] == "ONLINE":
                        tnl.tunnel_state = TunnelStates.ONLINE
                        tnl.link.stats = data[tnlid][lnkid]["Stats"]
                        tnl.link.status_retry = 0
                    else:
                        self.logger.warning("Unrecognized tunnel state ",
                                 "%s:%s", lnkid, data[tnlid][lnkid]["Status"])
        self.free_cbt(cbt)

    def _remove_link_from_tunnel(self, tnlid):
        tnl = self._tunnels.get(tnlid)
        if tnl:
            if tnl.link and tnl.link.lnkid:
                self._links.pop(tnl.link.lnkid)
            tnl.link = None
            tnl.tunnel_state = TunnelStates.OFFLINE

    def link_id(self, tnlid):
        tnl = self._tunnels.get(tnlid, None)
        if tnl and tnl.link:
            return tnl.link.lnkid
        return None

    def tunnel_id(self, lnkid):
        return self._links.get(lnkid)

    def _assign_link_to_tunnel(self, tnlid, lnkid, state):
        if tnlid in self._tunnels:
            self._tunnels[tnlid].link = Link(lnkid, state)
        self._links[lnkid] = tnlid

    def resp_handler_remove_tunnel(self, rmv_tnl_cbt):
        """
        Clean up the tunnel meta data. Even of the CBT fails it is safe to discard
        as this is because Tincan has no record of it.
        """
        parent_cbt = rmv_tnl_cbt.parent
        tnlid = rmv_tnl_cbt.request.params["TunnelId"]
        lnkid = self.link_id(tnlid)
        peer_id = rmv_tnl_cbt.request.params["PeerId"]
        olid = rmv_tnl_cbt.request.params["OverlayId"]
        tap_name = rmv_tnl_cbt.request.params["TapName"]
        self._tunnels.pop(tnlid, None)
        self._links.pop(lnkid, None)
        self.free_cbt(rmv_tnl_cbt)
        if parent_cbt:
            parent_cbt.set_response("Tunnel removed", True)
            self.complete_cbt(parent_cbt)
        # Notify subscribers of tunnel removal
        param = {
            "UpdateType": TunnelEvents.Removed, "OverlayId": olid, "TunnelId": tnlid, "LinkId": lnkid,
            "PeerId": peer_id, "TapName": tap_name}
        self._link_updates_publisher.post_update(param)
        self.logger.info("Tunnel %s removed: %s:%s<->%s",
                         tnlid[:7], olid[:7], self.node_id[:7], peer_id[:7])

    # def resp_handler_remove_link(self, rmv_tnl_cbt):
    #     parent_cbt = rmv_tnl_cbt.parent
    #     tnlid = rmv_tnl_cbt.request.params["TunnelId"]
    #     lnkid = self.link_id(tnlid)
    #     peer_id = rmv_tnl_cbt.request.params["PeerId"]
    #     olid = rmv_tnl_cbt.request.params["OverlayId"]
    #     # Notify subscribers of link removal
    #     param = {
    #         "UpdateType": TunnelEvents.Removed, "OverlayId": olid, "TunnelId": tnlid, "LinkId": lnkid,
    #         "PeerId": peer_id}
    #     if self._tunnels[tnlid].tap_name:
    #         param["TapName"] = self._tunnels[tnlid].tap_name
    #     self._remove_link_from_tunnel(tnlid)
    #     self.free_cbt(rmv_tnl_cbt)
    #     if parent_cbt:
    #         parent_cbt.set_response("Link removed", True)
    #         self.complete_cbt(parent_cbt)
    #     self._link_updates_publisher.post_update(param)
    #     self.logger.info("Link %s from Tunnel %s removed: %s:%s<->%s",
    #              lnkid[:7], tnlid[:7], olid[:7], self.node_id[:7], peer_id[:7])

    def req_handler_query_tunnels_info(self, cbt):
        results = {}
        for tnlid in self._tunnels:
            if self._tunnels[tnlid].tunnel_state == TunnelStates.ONLINE:
                results[tnlid] = {"OverlayId": self._tunnels[tnlid].overlay_id,
                                  "TunnelId": tnlid, "PeerId": self._tunnels[tnlid].peer_id,
                                  "Stats": self._tunnels[tnlid].link.stats,
                                  "TapName": self._tunnels[tnlid].tap_name,
                                  "MAC": self._tunnels[tnlid].mac,
                                  "PeerMac": self._tunnels[tnlid].peer_mac}
        cbt.set_response(results, status=True)
        self.complete_cbt(cbt)

    def _create_tunnel(self, params, parent_cbt=None):
        overlay_id = params["OverlayId"]
        tnlid = params["TunnelId"]
        lnkid = params["LinkId"]
        peer_id = params["PeerId"]
        tap_name_prefix = self.config["Overlays"][overlay_id].get(
            "TapNamePrefix", TapNamePrefix)
        end_i = self.TAPNAME_MAXLEN - len(tap_name_prefix)
        tap_name = tap_name_prefix + str(peer_id[:end_i])
        self.logger.debug("IgnoredNetInterfaces: %s",
                 self._get_ignored_tap_names(overlay_id, tap_name))
        create_tnl_params = {
            "OverlayId": overlay_id,
            "NodeId": self.node_id,
            "TunnelId": tnlid,
            "LinkId": lnkid,
            "StunServers": self.config.get("Stun", []),
            "TapName": tap_name,
            "IgnoredNetInterfaces": list(
                self._get_ignored_tap_names(overlay_id, tap_name))
        }
        if self.config.get("Turn"):
            create_tnl_params["TurnServers"] = self.config["Turn"]

        if parent_cbt:
            tnl_cbt = self.create_linked_cbt(parent_cbt)
            tnl_cbt.set_request(self.module_name, "TincanInterface",
                                "TCI_CREATE_TUNNEL", create_tnl_params)
        else:
            tnl_cbt = self.create_cbt(self.module_name, "TincanInterface",
                                      "TCI_CREATE_TUNNEL", create_tnl_params)
        self.submit_cbt(tnl_cbt)

    def _request_peer_endpoint(self, params, parent_cbt):
        overlay_id = params["OverlayId"]
        tnlid = params["TunnelId"]
        endp_param = {
            "NodeData": {
                "FPR": self._tunnels[tnlid].fpr,
                "MAC": self._tunnels[tnlid].mac,
                "UID": self.node_id}}
        endp_param.update(params)

        remote_act = dict(overlay_id=overlay_id,
                          recipient_id=parent_cbt.request.params["PeerId"],
                          recipient_cm="LinkManager",
                          action="LNK_REQ_LINK_ENDPT",
                          params=endp_param)
        if parent_cbt:
            endp_cbt = self.create_linked_cbt(parent_cbt)
            endp_cbt.set_request(self.module_name, "Signal",
                                 "SIG_REMOTE_ACTION", remote_act)
        else:
            endp_cbt = self.create_cbt(self.module_name, "Signal",
                                       "SIG_REMOTE_ACTION", remote_act)
        # Send the message via SIG server to peer
        self.submit_cbt(endp_cbt)

    def _rollback_link_creation_changes(self, tnlid):
        """
        Removes links that failed the setup handshake.
        """
        if tnlid not in self._tunnels:
            return
        creation_state = self._tunnels[tnlid].link.creation_state
        if creation_state < 0xC0:
            olid = self._tunnels[tnlid].overlay_id
            peer_id = self._tunnels[tnlid].peer_id
            lnkid = self.link_id(tnlid)
            params = {"OverlayId": olid, "PeerId": peer_id, "TunnelId": tnlid,
                      "LinkId": lnkid, "TapName": self._tunnels[tnlid].tap_name}
            self.register_cbt("TincanInterface", "TCI_REMOVE_TUNNEL", params)
            self._tunnels.pop(tnlid, None)
            self._links.pop(lnkid, None)
            self.logger.info("Initiating removal of incomplete link: "
                     "PeerId: %s, LinkId: %s, CreateState: %s",
                     peer_id[:7], tnlid[:7], format(creation_state, "02X"))

    def req_handler_auth_tunnel(self, cbt):
        """Node B"""
        olid = cbt.request.params["OverlayId"]
        peer_id = cbt.request.params["PeerId"]
        tnlid = cbt.request.params["TunnelId"]
        if tnlid in self._tunnels:
            cbt.set_response("Tunnel auth failed, resource already exist for peer:tunnel {0}:{1}"
                             .format(peer_id, tnlid[:7]), False)
            self.complete_cbt(cbt)
        else:
            self._tunnels[tnlid] = Tunnel(tnlid, olid, peer_id,
                                          tnl_state=TunnelStates.AUTHORIZED,
                                          state_timeout=self.config.get("LinkSetupTimeout", LinkSetupTimeout),
                                          dataplane=DataplaneTypes.Tincan)
            self.logger.debug("TunnelId:%s auth for peer:%s completed",
                     tnlid[:7], peer_id[:7])
            cbt.set_response(
                "Authorization completed, TunnelId:{0}".format(tnlid[:7]), True)
            lnkupd_param = {
                "UpdateType": TunnelEvents.Authorized, "OverlayId": olid, "PeerId": peer_id,
                "TunnelId": tnlid}
            self.complete_cbt(cbt)
            self._link_updates_publisher.post_update(lnkupd_param)

    def req_handler_create_tunnel(self, cbt):
        """
        Handle the request for capability LNK_CREATE_TUNNEL.
        The caller provides the overlay id and the peer id which the link
        connects. The link id is generated here but it is returned to the
        caller after the local endpoint creation is completed asynchronously.
        The link is not necessarily ready for read/write at this time. The link
        status can be queried to determine when it is writeable. The link id is
        communicated in the request and will be the same at both nodes.
        """
        # Create Link: Phase 1 Node A
        olid = cbt.request.params["OverlayId"]
        peer_id = cbt.request.params["PeerId"]
        tnlid = cbt.request.params["TunnelId"]
        if tnlid in self._tunnels:
            # Tunnel already exists
            tnl = self._tunnels[tnlid]
            if not tnl.link:
                # we need to create the link
                lnkid = tnlid
                self.logger.debug("Create Link:%s Tunnel exists. "
                                  "Skipping phase 1/5 Node A - Peer: %s",
                                  lnkid[:7], peer_id[:7])

                self.logger.debug("Create Link:%s Phase 2/5 Node A - Peer: %s",
                                  lnkid[:7], peer_id[:7])
                self._assign_link_to_tunnel(tnlid, lnkid, 0xA2)
                tnl.tunnel_state = TunnelStates.CREATING
                # create and send remote action to request endpoint from peer
                params = {
                    "OverlayId": olid,
                    "TunnelId": tnlid,
                    "LinkId": lnkid,
                    "NodeData": {
                        "FPR": tnl.fpr,
                        "MAC": tnl.mac,
                        "UID": self.node_id
                    }
                }
                remote_act = dict(overlay_id=olid,
                                  recipient_id=peer_id,
                                  recipient_cm="LinkManager",
                                  action="LNK_REQ_LINK_ENDPT",
                                  params=params)

                endp_cbt = self.create_linked_cbt(cbt)
                endp_cbt.set_request(
                    self.module_name, "Signal", "SIG_REMOTE_ACTION", remote_act)
                # Send the message via SIG server to peer
                self.submit_cbt(endp_cbt)
            else:
                # Link already exists, TM should clean up first
                cbt.set_response("Failed, duplicate link requested to "
                                 "overlay id: {0} peer id: {1}"
                                 .format(olid, peer_id), False)
                self.complete_cbt(cbt)
            return
        # No tunnel exists, going to create it.
        tnlid = cbt.request.params["TunnelId"]
        lnkid = tnlid
        self._tunnels[tnlid] = Tunnel(tnlid, olid, peer_id, tnl_state=TunnelStates.CREATING,
                                      state_timeout=self.config.get("LinkSetupTimeout", LinkSetupTimeout),
                                      dataplane=DataplaneTypes.Tincan)
        self._assign_link_to_tunnel(tnlid, lnkid, 0xA1)

        self.logger.debug("Create Link:%s Phase 1/5 Node A - Peer: %s",
                          lnkid[:7], peer_id[:7])
        params = {"OverlayId": olid, "TunnelId": tnlid,
                  "LinkId": lnkid, "PeerId": peer_id}
        self._create_tunnel(params, parent_cbt=cbt)

    def resp_handler_create_tunnel(self, cbt):
        # Create Tunnel: Phase 2 Node A
        parent_cbt = cbt.parent
        lnkid = cbt.request.params["LinkId"]
        tnlid = cbt.request.params["TunnelId"]
        peer_id = parent_cbt.request.params["PeerId"]
        tap_name = cbt.request.params["TapName"]
        resp_data = cbt.response.data
        if not cbt.response.status:
            self._deauth_tnl(self._tunnels[tnlid])
            self.free_cbt(cbt)
            parent_cbt.set_response("Failed to create tunnel", False)
            self.complete_cbt(parent_cbt)
            self.logger.warning("The create tunnel operation failed:%s",
                                resp_data)
            return
        # transistion connection connection state
        self._tunnels[tnlid].link.creation_state = 0xA2
        # store the overlay data
        overlay_id = cbt.request.params["OverlayId"]  # config overlay id
        self.logger.debug("Create Link:%s Phase 2/5 Node A", lnkid[:7])
        self._update_tunnel_descriptor(resp_data, tnlid)
        # lnkupd_param = {"UpdateType": TunnelEvents.Created, "OverlayId": overlay_id, "PeerId": peer_id,
        #                 "TunnelId": tnlid, "LinkId": lnkid, "TapName": tap_name}
        # self._link_updates_publisher.post_update(lnkupd_param)
        # create and send remote action to request endpoint from peer
        params = {"OverlayId": overlay_id, "TunnelId": tnlid, "LinkId": lnkid}
        self._request_peer_endpoint(params, parent_cbt)
        self.free_cbt(cbt)

    def req_handler_req_link_endpt(self, lnk_endpt_cbt):
        params = lnk_endpt_cbt.request.params
        olid = params["OverlayId"]
        tnlid = params["TunnelId"]
        node_data = params["NodeData"]
        peer_id = node_data["UID"]
        # if olid not in self.config["Overlays"]:
        #     self.logger.warning("The requested overlay is not specified in "
        #                      "local config, it will not be created")
        #     lnk_endpt_cbt.set_response(
        #         "Unknown overlay id specified in request", False)
        #     self.complete_cbt(lnk_endpt_cbt)
        #     return
        if tnlid not in self._tunnels:
            msg = str("The requested lnk endpt was not authorized it will not be created. "
                      "TunnelId={0}, PeerId={1}".format(tnlid, peer_id))
            self.logger.warning(msg)
            lnk_endpt_cbt.set_response(msg, False)
            self.complete_cbt(lnk_endpt_cbt)
            return
        if self._tunnels[tnlid].link:
            msg = str("A link already exist for this tunnel, it will not be created. "
                      "TunnelId={0}, PeerId={1}".format(tnlid, peer_id))
            self.logger.warning(msg)
            lnk_endpt_cbt.set_response(msg, False)
            self.complete_cbt(lnk_endpt_cbt)
            return
        lnkid = tnlid
        self._tunnels[tnlid].tunnel_state = TunnelStates.CREATING
        self._tunnels[tnlid].timeout = time.time() + self.config.get("LinkSetupTimeout", LinkSetupTimeout)
        self._assign_link_to_tunnel(tnlid, lnkid, 0xB1)
        self.logger.debug("Create Link:%s Phase 1/4 Node B", lnkid[:7])
        # Send request to Tincan
        tap_name_prefix = self.config["Overlays"][olid].get("TapNamePrefix", TapNamePrefix)[
            :3]
        end_i = self.TAPNAME_MAXLEN - len(tap_name_prefix)
        tap_name = tap_name_prefix + str(peer_id[:end_i])
        self.logger.debug("IgnoredNetInterfaces: %s",
                          self._get_ignored_tap_names(olid, tap_name))
        create_link_params = {
            "OverlayId": olid,
            # overlay params
            "TunnelId": tnlid,
            "NodeId": self.node_id,
            "StunServers": self.config.get("Stun", []),
            "TapName": tap_name,
            "IgnoredNetInterfaces": list(
                self._get_ignored_tap_names(olid, tap_name)),
            # link params
            "LinkId": lnkid,
            "NodeData": {
                "FPR": node_data["FPR"],
                "MAC": node_data["MAC"],
                "UID": node_data["UID"]}}
        if self.config.get("Turn"):
            create_link_params["TurnServers"] = self.config["Turn"]
        lcbt = self.create_linked_cbt(lnk_endpt_cbt)
        lcbt.set_request(self.module_name, "TincanInterface",
                         "TCI_CREATE_LINK", create_link_params)
        self.submit_cbt(lcbt)

    def _complete_link_endpt_request(self, cbt):
        # Create Link: Phase 4 Node B
        parent_cbt = cbt.parent
        resp_data = cbt.response.data
        lnkid = cbt.request.params["LinkId"]
        tnlid = self.tunnel_id(lnkid)
        peer_id = cbt.request.params["NodeData"]["UID"]
        if not cbt.response.status:
            self.free_cbt(cbt)
            parent_cbt.set_response(resp_data, False)
            if parent_cbt and parent_cbt.child_count == 0:
                self.complete_cbt(parent_cbt)
            self.logger.warning(
                "Failed to create connection endpoint for request link: %s. Response data= %s",
                lnkid, cbt.response.data)
            self._rollback_link_creation_changes(tnlid)
            return
        self.logger.debug(
            "Create Link:%s Phase 2/4 Node B - Peer: %s", lnkid[:7], peer_id[:7])
        self._tunnels[tnlid].link.creation_state = 0xB2
        # store the overlay data
        self._update_tunnel_descriptor(resp_data, tnlid)
        # add the peer MAC to the tunnel descr
        node_data = cbt.request.params["NodeData"]
        self._tunnels[tnlid].peer_mac = node_data["MAC"]
        # respond with this nodes connection parameters
        node_data = {
            "MAC": resp_data["MAC"],
            "FPR": resp_data["FPR"],
            "UID": self.node_id,
            "CAS": resp_data["CAS"]
        }
        data = {
            "OverlayId": cbt.request.params["OverlayId"],
            "TunnelId": tnlid,
            "LinkId": lnkid,
            "NodeData": node_data
        }
        self.free_cbt(cbt)
        parent_cbt.set_response(data, True)
        self.complete_cbt(parent_cbt)

    def _complete_link_creation(self, cbt, parent_cbt):
        params = parent_cbt.request.params
        lnkid = params["LinkId"]
        tnlid = self.tunnel_id(lnkid)
        peer_id = params["NodeData"]["UID"]
        self._tunnels[tnlid].link.creation_state = 0xC0
        self.logger.debug(
            "Create Link:%s Phase 4/4 Node B - Peer: %s", lnkid[:7], peer_id[:7])
        peer_id = params["NodeData"]["UID"]
        olid = params["OverlayId"]
        resp_data = cbt.response.data
        node_data = {
            "MAC": resp_data["MAC"],
            "FPR": resp_data["FPR"],
            "UID": self.node_id,
            "CAS": resp_data["CAS"]
        }
        data = {
            "OverlayId": cbt.request.params["OverlayId"],
            "TunnelId": tnlid,
            "LinkId": lnkid,
            "NodeData": node_data
        }
        parent_cbt.set_response(data=data, status=True)
        self.free_cbt(cbt)
        self.complete_cbt(parent_cbt)
        self.logger.info("Tunnel %s Link %s accepted: %s:%s<-%s",
                         tnlid[:7], lnkid[:7], olid[:7], self.node_id[:7],
                         peer_id[:7])

    def _create_link_endpoint(self, rem_act, parent_cbt):
        """
        Send the Createlink control to local Tincan
        """
        # Create Link: Phase 5 Node A
        lnkid = rem_act["data"]["LinkId"]
        tnlid = self.tunnel_id(lnkid)
        peer_id = rem_act["recipient_id"]
        if tnlid not in self._tunnels:
            # abort the handshake as the process timed out
            parent_cbt.set_response("Tunnel creation timeout failure", False)
            self.complete_cbt(parent_cbt)
            return
        self._tunnels[tnlid].link.creation_state = 0xA3
        self.logger.debug("Create Link:%s Phase 3/5 Node A - Peer: %s",
                          lnkid[:7], peer_id[:7])
        node_data = rem_act["data"]["NodeData"]
        olid = rem_act["overlay_id"]
        # add the peer MAC to the tunnel descr
        self._tunnels[tnlid].peer_mac = node_data["MAC"]
        cbt_params = {"OverlayId": olid, "TunnelId": tnlid, "LinkId": lnkid,
                      "NodeData": {
                          "UID": node_data["UID"],
                          "MAC": node_data["MAC"],
                          "CAS": node_data["CAS"],
                          "FPR": node_data["FPR"]}}
        lcbt = self.create_linked_cbt(parent_cbt)
        lcbt.set_request(self.module_name, "TincanInterface",
                         "TCI_CREATE_LINK", cbt_params)
        self.submit_cbt(lcbt)

    def _send_local_cas_to_peer(self, cbt):
        # Create Link: Phase 6 Node A
        lnkid = cbt.request.params["LinkId"]
        tnlid = self.tunnel_id(lnkid)
        peer_id = cbt.request.params["NodeData"]["UID"]
        self._tunnels[tnlid].link.creation_state = 0xA4
        self.logger.debug("Create Link:%s Phase 4/5 Node A - Peer: %s",
                          lnkid[:7], peer_id[:7])
        local_cas = cbt.response.data["CAS"]
        parent_cbt = cbt.parent
        olid = cbt.request.params["OverlayId"]
        peerid = parent_cbt.request.params["PeerId"]
        params = {
            "OverlayId": olid,
            "TunnelId": tnlid,
            "LinkId": lnkid,
            "NodeData": {
                "UID": self.node_id, "MAC": cbt.response.data["MAC"],
                "CAS": local_cas, "FPR": cbt.response.data["FPR"]}}
        remote_act = dict(overlay_id=olid, recipient_id=peerid, recipient_cm="LinkManager",
                          action="LNK_ADD_PEER_CAS", params=params)
        lcbt = self.create_linked_cbt(parent_cbt)
        lcbt.set_request(self.module_name, "Signal",
                         "SIG_REMOTE_ACTION", remote_act)
        self.submit_cbt(lcbt)
        self.free_cbt(cbt)

    def req_handler_add_peer_cas(self, cbt: CBT):
        # Create Link: Phase 7 Node B
        params = cbt.request.params
        olid = params["OverlayId"]
        lnkid = params["LinkId"]
        tnlid = self.tunnel_id(lnkid)
        peer_id = params["NodeData"]["UID"]
        if tnlid not in self._tunnels:
            self.logger.info("A response to an aborted add peer CAS operation was discarded: %s",
                             str(cbt))
            cbt.set_response("This request was aborted", False)
            self.complete_cbt(cbt)
            return
        self._tunnels[tnlid].link.creation_state = 0xB3
        self.logger.debug("Create Link:%s Phase 3/4 Node B - Peer: %s",
                          lnkid[:7], peer_id[:7])
        lcbt = self.create_linked_cbt(cbt)
        lcbt.set_request(self.module_name, "TincanInterface",
                         "TCI_CREATE_LINK", params)
        self.submit_cbt(lcbt)

    def resp_handler_create_link_endpt(self, cbt):
        parent_cbt = cbt.parent
        resp_data = cbt.response.data
        if not cbt.response.status:
            self.logger.warning("Create link endpoint failed :%s", cbt)
            lnkid = cbt.request.params["LinkId"]
            self._rollback_link_creation_changes(lnkid)
            self.free_cbt(cbt)
            parent_cbt.set_response(resp_data, False)
            self.complete_cbt(parent_cbt)
            return

        if parent_cbt.request.action == "LNK_REQ_LINK_ENDPT":
            """
            To complete this request the responding node has to supply its own
            NodeData and CAS. The NodeData was previously queried and is stored
            on the parent cbt. Add the cas and send to peer.
            """
            self._complete_link_endpt_request(cbt)

        elif parent_cbt.request.action == "LNK_CREATE_TUNNEL":
            """
            Both endpoints are created now but the peer doesn't have our cas.
            It already has the node data so no need to send that again.
            """
            self._send_local_cas_to_peer(cbt)

        elif parent_cbt.request.action == "LNK_ADD_PEER_CAS":
            """
            The link creation handshake is complete on Node B, complete the outstanding request
            and publish notifications via subscription.
            """
            self._complete_link_creation(cbt, parent_cbt)

    def _complete_create_link_request(self, parent_cbt):
        # Create Link: Phase 9 Node A
        # Complete the cbt that started this all
        olid = parent_cbt.request.params["OverlayId"]
        peer_id = parent_cbt.request.params["PeerId"]
        tnlid = parent_cbt.request.params["TunnelId"]
        lnkid = self.link_id(tnlid)
        self._tunnels[tnlid].link.creation_state = 0xC0
        self.logger.debug("Create Link:%s Phase 5/5 Node A - Peer: %s",
                          tnlid[:7], peer_id[:7])
        parent_cbt.set_response(data={"LinkId": lnkid}, status=True)
        self.complete_cbt(parent_cbt)
        self.logger.debug("Tunnel %s created: %s:%s->%s",
                          lnkid[:7], olid[:7], self.node_id[:7], peer_id[:7])

    def resp_handler_remote_action(self, cbt):
        parent_cbt = cbt.parent
        resp_data = cbt.response.data
        if not cbt.response.status:
            lnkid = cbt.request.params["params"]["LinkId"]
            tnlid = self.tunnel_id(lnkid)
            self.logger.debug(
                "The remote action requesting a connection endpoint link %s has failed",
                tnlid)
            self._rollback_link_creation_changes(tnlid)
            self.free_cbt(cbt)
            parent_cbt.set_response(resp_data, False)
            self.complete_cbt(parent_cbt)
        else:
            rem_act = cbt.response.data
            self.free_cbt(cbt)
            if rem_act["action"] == "LNK_REQ_LINK_ENDPT":
                self._create_link_endpoint(rem_act, parent_cbt)
            elif rem_act["action"] == "LNK_ADD_PEER_CAS":
                self._complete_create_link_request(parent_cbt)

    def req_handler_tincan_msg(self, cbt):
        lts = time.time()
        if cbt.request.params["Command"] == "LinkStateChange":
            lnkid = cbt.request.params["LinkId"]
            tnlid = cbt.request.params["TunnelId"]
            if (cbt.request.params["Data"] == "LINK_STATE_DOWN") and \
                    (self._tunnels[tnlid].tunnel_state != TunnelStates.QUERYING):
                self.logger.debug("LINK %s STATE is DOWN cbt=%s", tnlid, cbt)
                # issue a link state check only if it not already being done
                self._tunnels[tnlid].tunnel_state = TunnelStates.QUERYING
                self.register_cbt("TincanInterface",
                                  "TCI_QUERY_LINK_STATS", [tnlid])
            elif cbt.request.params["Data"] == "LINK_STATE_UP":
                tnlid = self.tunnel_id(lnkid)
                olid = self._tunnels[tnlid].overlay_id
                peer_id = self._tunnels[tnlid].peer_id
                lnk_status = self._tunnels[tnlid].tunnel_state
                self._tunnels[tnlid].tunnel_state = TunnelStates.ONLINE
                if lnk_status != TunnelStates.QUERYING:
                    param = {
                        "UpdateType": TunnelEvents.Connected, "OverlayId": olid, "PeerId": peer_id,
                        "TunnelId": tnlid, "LinkId": lnkid, "ConnectedTimestamp": lts,
                        "TapName": self._tunnels[tnlid].tap_name,
                        "MAC": self._tunnels[tnlid].mac,
                        "PeerMac": self._tunnels[tnlid].peer_mac,
                        "Dataplane": self._tunnels[tnlid].dataplane}
                    self._link_updates_publisher.post_update(param)
                elif lnk_status == TunnelStates.QUERYING:
                    # Do not post a notification if the the connection state was being queried
                    self._tunnels[tnlid].link.status_retry = 0
            cbt.set_response(data=None, status=True)
        else:
            cbt.set_response(data=None, status=True)
        self.complete_cbt(cbt)

    def process_cbt(self, cbt):
        with self._lock:
            if cbt.op_type == "Request":
                if cbt.request.action == "LNK_CREATE_TUNNEL":
                    # Create Link: Phase 1 Node A
                    # TOP wants a new link, first SIGnal peer to create endpt
                    self.req_handler_create_tunnel(cbt)

                elif cbt.request.action == "LNK_REQ_LINK_ENDPT":
                    # Create Link: Phase 3 Node B
                    # Rcvd peer req to create endpt, send to TCI
                    self.req_handler_req_link_endpt(cbt)

                elif cbt.request.action == "LNK_ADD_PEER_CAS":
                    # Create Link: Phase 7 Node B
                    # CAS rcvd from peer, sends to TCI to update link's peer CAS info
                    self.req_handler_add_peer_cas(cbt)

                elif cbt.request.action == "LNK_REMOVE_TUNNEL":
                    self.req_handler_remove_tnl(cbt)

                # elif cbt.request.action == "LNK_REMOVE_LINK":
                #     self.req_handler_remove_link(cbt)

                elif cbt.request.action == "LNK_QUERY_TUNNEL_INFO":
                    self.req_handler_query_tunnels_info(cbt)

                elif cbt.request.action == "VIS_DATA_REQ":
                    self.req_handler_query_viz_data(cbt)

                elif cbt.request.action == "TCI_TINCAN_MSG_NOTIFY":
                    self.req_handler_tincan_msg(cbt)

                elif cbt.request.action == "LNK_ADD_IGN_INF":
                    self.req_handler_add_ign_inf(cbt)

                elif cbt.request.action == "LNK_AUTH_TUNNEL":
                    self.req_handler_auth_tunnel(cbt)
                else:
                    self.req_handler_default(cbt)
            elif cbt.op_type == "Response":
                if cbt.request.action == "SIG_REMOTE_ACTION":
                    # Create Link: Phase 5 Node A
                    # Attempt to create our end of link
                    # Create Link: Phase 9 Node A
                    # Link created, notify others
                    self.resp_handler_remote_action(cbt)

                elif cbt.request.action == "TCI_CREATE_LINK":
                    # Create Link: Phase 4 Node B
                    # Create Link: Phase 6 Node A
                    # SIGnal to peer to update CAS
                    # Create Link: Phase 8 Node B
                    # Complete setup
                    self.resp_handler_create_link_endpt(cbt)

                elif cbt.request.action == "TCI_CREATE_TUNNEL":
                    # Create Link: Phase 2 Node A
                    # Retrieved our node data for response
                    self.resp_handler_create_tunnel(cbt)

                elif cbt.request.action == "TCI_QUERY_LINK_STATS":
                    self.resp_handler_query_link_stats(cbt)

                elif cbt.request.action == "TCI_REMOVE_LINK":
                    self.resp_handler_remove_link(cbt)

                elif cbt.request.action == "TCI_REMOVE_TUNNEL":
                    self.resp_handler_remove_tunnel(cbt)

                else:
                    self.resp_handler_default(cbt)

    def _deauth_tnl(self, tnl):
        self.logger.info("Deauthorizing tunnel %s", tnl.tnlid)
        param = {
            "UpdateType": TunnelEvents.AuthExpired, "OverlayId": tnl.overlay_id,
            "PeerId": tnl.peer_id, "TunnelId": tnl.tnlid, "TapName": tnl.tap_name}
        self._link_updates_publisher.post_update(param)
        self._tunnels.pop(tnl.tnlid, None)

    def deauthorize_expired_tunnels(self):
        deauth = []
        for tnl in self._tunnels.values():
            if tnl.tunnel_state == TunnelStates.AUTHORIZED and time.time() > tnl.timeout:
                deauth.append(tnl)
        for tnl in deauth:
            self._deauth_tnl(tnl)
                
    def _cleanup_expired_incomplete_links(self):
        rollbk = []
        for tnlid, tnl in self._tunnels.items():
            if tnl.link is not None and tnl.link.creation_state == 0xB2 and \
                    time.time() > tnl.timeout:
                rollbk.append(tnlid)
                self.logger.debug("Link expired %s", tnl)
        for tnlid in rollbk:
            self._rollback_link_creation_changes(tnlid)

    def timer_method(self, is_exiting=False):
        if is_exiting:
            return
        with self._lock:
            self.deauthorize_expired_tunnels()
            self._cleanup_expired_incomplete_links()
            # self._query_link_stats()

    def terminate(self):
        self.logger.info("Module Terminating")

    def req_handler_query_viz_data(self, cbt):
        tnls = dict()
        for tnlid in self._tunnels:
            if self._tunnels[tnlid].link is None:
                continue
            tnl_data = {}
            if self._tunnels[tnlid].tap_name:
                tnl_data["TapName"] = self._tunnels[tnlid].tap_name
            if self._tunnels[tnlid].mac:
                tnl_data["MAC"] = self._tunnels[tnlid].mac
            for stat_entry in self._tunnels[tnlid].link.stats:
                if stat_entry["best_conn"] == True:
                    lvals = stat_entry["local_candidate"].split(":")
                    rvals = stat_entry["remote_candidate"].split(":")
                    if len(lvals) < 10 or len(rvals) < 8:
                        continue
                    tnl_data["LocalEndpoint"] = {
                        "Proto": lvals[7], "External": lvals[5]+":"+lvals[6], "Internal": lvals[8]+":"+lvals[9]}
                    tnl_data["RemoteEndpoint"] = {
                        "Proto": rvals[7], "External": rvals[5]+":"+rvals[6]}
                    continue
            overlay_id = self._tunnels[tnlid].overlay_id
            if overlay_id not in tnls:
                tnls[overlay_id] = dict()
            tnls[overlay_id][tnlid] = tnl_data

        cbt.set_response({"LinkManager": tnls}, bool(tnls))
        self.complete_cbt(cbt)
"""
###################################################################################################
Link Manager state and event specifications
###################################################################################################

If LM fails a CBT there will be no further events fired for the tunnel.
Once tunnel goes online an explicit CBT LNK_REMOVE_TUNNEL is required.
Partially created tunnels that fails will be removed automatically by LM.

Events
(1) TunnelEvents.AuthExpired - After a successful completion of CBT LNK_AUTH_TUNNEL, the tunnel
descriptor is created and TunnelEvents.Authorized is fired. 
(2) TunnelEvents.AuthExpired - If no action is taken on the tunnel within LinkSetupTimeout LM will
fire TunnelEvents.AuthExpired and remove the associated tunnel descriptor.
(3) ##REMOVED## TunnelEvents.Created - On both nodes A & B, on a successful completion of CBT TCI_CREATE_TUNNEL,
the TAP device exists and TunnelEvents.Created is fired.
(4) TunnelEvents.Connected - After Tincan delivers the online event to LM TunnelEvents.Connected
is fired.
(5) TunnelEvents.Disconnected - After Tincan signals link offline or QUERYy_LNK_STATUS discovers
offline TunnelEvents.Disconnected is fired.
(6) TunnelEvents.Removed - After the TAP device is removed TunnelEvents.Removed is fired and the
tunnel descriptor is removed. Tunnel must be in TunnelStates.ONLINE or TunnelStates.OFFLINE

 Internal States
(1) TunnelStates.AUTHORIZED - After a successful completion of CBT LNK_AUTH_TUNNEL, the tunnel
descriptor exists.
(2) TunnelStates.CREATING - entered on reception of CBT LNK_CREATE_TUNNEL.
(3) TunnelStates.QUERYING - entered before issuing CBT TCI_QUERY_LINK_STATS. Happens when 
LinkStateChange is LINK_STATE_DOWN and state is not already TunnelStates.QUERYING; OR 
TCI_QUERY_LINK_STATS is OFFLINE and state is not already TunnelStates.QUERYING.
(4) TunnelStates.ONLINE - entered when CBT TCI_QUERY_LINK_STATS is ONLINE or LinkStateChange is
LINK_STATE_UP.
(5) TunnelStates.OFFLINE - entered when QUERY_LNK_STATUS is OFFLINE or LinkStateChange is
LINK_STATE_DOWN event.
"""