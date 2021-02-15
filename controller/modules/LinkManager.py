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
from collections import namedtuple
import time
from framework.ControllerModule import ControllerModule


LinkEvent = ["LnkEvCreating", "LnkEvCreated", "LnkEvConnected", "LnkEvDisconnected", "LnkEvRemoved",
             "LnkEvAuthorized", "LnkEvDeauthorized"]

class Link():
    def __init__(self, lnkid, state):
        self.lnkid = lnkid
        self._creation_state = state
        self.status_retry = 0
        self.stats = {}

    def __repr__(self):
        state = "Link<lnkid=%s, creation_state=0x%02x, status_retry=%s, stats=%s>" % \
                (self.lnkid[:7], self._creation_state, self.status_retry, self.stats)
        return state

    def __str__(self):
        state = "Link<lnkid=%s, creation_state=0x%02x, status_retry=%s>" % \
                (self.lnkid[:7], self._creation_state, self.status_retry)
        return state

    @property
    def creation_state(self):
        return self._creation_state

    @creation_state.setter
    def creation_state(self, new_state):
        "todo: implement transition checks"
        self._creation_state = new_state

TUNNEL_STATES = ["TNL_AUTHORIZED", "TNL_CREATING", "TNL_QUERYING", "TNL_ONLINE", "TNL_OFFLINE"]
TunnelStates = namedtuple("TunnelStates", TUNNEL_STATES)

class Tunnel():
    STATES = TunnelStates("TNL_AUTHORIZED", "TNL_CREATING", "TNL_QUERYING",
                          "TNL_ONLINE", "TNL_OFFLINE")
    def __init__(self, tnlid, overlay_id, peer_id, tnl_state="TNL_AUTHORIZED", state_timeout=45):
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
        self.timeout = time.time() + state_timeout # timeout for current phase

    def __repr__(self):
        state = "Tunnel<tnlid=%s, overlay_id=%s, peer_id=%s, tap_name=%s, mac=%s, link=%s, "\
                "peer_mac=%s, tunnel_state=%s, creation_start_time=%s>" % \
                (self.tnlid[:7], self.overlay_id[:7], self.peer_id[:7], self.tap_name, self.mac,
                 self.link, self.peer_mac, self.tunnel_state, self.creation_start_time)
        return state

    def __str__(self):
        state = "Tunnel<tnlid=%s, overlay_id=%s, peer_id=%s, tap_name=%s, mac=%s, link=%s, "\
                "peer_mac=%s, tunnel_state=%s, creation_start_time=%s>" % \
                (self.tnlid[:7], self.overlay_id[:7], self.peer_id[:7], self.tap_name, self.mac,
                 self.link, self.peer_mac, self.tunnel_state, self.creation_start_time)
        return state

    @property
    def tunnel_state(self):
        return self._tunnel_state

    @tunnel_state.setter
    def tunnel_state(self, new_state):
        "todo: implement transition checks"
        self._tunnel_state = new_state

class LinkManager(ControllerModule):

    def __init__(self, cfx_handle, module_config, module_name):
        super(LinkManager, self).__init__(cfx_handle, module_config, module_name)
        self._tunnels = {}   # maps tunnel id to its descriptor
        self._peers = {}     # maps overlay id to peers map, which maps peer id to tunnel id
        self._links = {}     # maps link id to tunnel id
        self._lock = threading.Lock()  # serializes access to _overlays, _links
        self._link_updates_publisher = None
        self._ignored_net_interfaces = dict()

    def __repr__(self):
        state = "LinkManager<_peers=%s, _tunnels=%s>" % (self._peers, str(self._tunnels))
        return state

    def initialize(self):
        self._link_updates_publisher = \
            self._cfx_handle.publish_subscription("LNK_TUNNEL_EVENTS")
        self._cfx_handle.start_subscription("TincanInterface",
                                            "TCI_TINCAN_MSG_NOTIFY")
        try:
            # Subscribe for data request notifications from OverlayVisualizer
            self._cfx_handle.start_subscription("OverlayVisualizer",
                                                "VIS_DATA_REQ")
        except NameError as err:
            if "OverlayVisualizer" in str(err):
                self.register_cbt("Logger", "LOG_WARNING",
                                  "OverlayVisualizer module not loaded."
                                  " Visualization data will not be sent.")

        for olid in self.config["Overlays"]:
            self._peers[olid] = dict()
            self._ignored_net_interfaces[olid] = set()
            ol_cfg = self.config["Overlays"][olid]
            if "IgnoredNetInterfaces" in ol_cfg:
                for ign_inf in ol_cfg["IgnoredNetInterfaces"]:
                    self._ignored_net_interfaces[olid].add(ign_inf)

        self.register_cbt("Logger", "LOG_INFO", "Module Loaded")

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
        olid = cbt.request.params.get("OverlayId", None)
        peer_id = cbt.request.params.get("PeerId", None)
        tnlid = cbt.request.params.get("TunnelId", None)
        if olid is not None and peer_id is not None:
            tnlid = self._peers[olid][peer_id]
        elif tnlid is not None:
            olid = self._tunnels[tnlid].overlay_id
        else:
            cbt.set_response("Insufficient parameters", False)
            self.complete_cbt(cbt)
            return
        if self._tunnels[tnlid].tunnel_state == Tunnel.STATES.TNL_ONLINE or \
            self._tunnels[tnlid].tunnel_state == Tunnel.STATES.TNL_OFFLINE:
            tn = self._tunnels[tnlid].tap_name
            params = {"OverlayId": olid, "TunnelId": tnlid, "PeerId": peer_id, "TapName": tn}
            rtnl_cbt = self.create_linked_cbt(cbt)
            rtnl_cbt.set_request(self.module_name, "TincanInterface", "TCI_REMOVE_TUNNEL", params)
            self.submit_cbt(rtnl_cbt)
        else:
            cbt.set_response("Tunnel busy, retry operation", False)
            self.complete_cbt(cbt)

    def req_handler_remove_link(self, cbt):
        """Remove the link given either the overlay id and peer id, or the link id or tunnel id"""
        # not currently being used
        olid = cbt.request.params.get("OverlayId", None)
        peer_id = cbt.request.params.get("PeerId", None)
        lnkid = cbt.request.params.get("LinkId", None)
        tnlid = cbt.request.params.get("TunnelId", None)
        if olid is not None and peer_id is not None:
            tnlid = self._peers[olid][peer_id]
            lnkid = self.link_id(tnlid)
        elif tnlid is not None:
            olid = self._tunnels[tnlid].overlay_id
            lnkid = self.link_id(tnlid)
        elif lnkid is not None:
            tnlid = self.tunnel_id(lnkid)
            olid = self._tunnels[tnlid].overlay_id
        else:
            cbt.set_response("Insufficient parameters", False)
            self.complete_cbt(cbt)
            return

        if self._tunnels[tnlid].tunnel_state == Tunnel.STATES.TNL_ONLINE or \
            self._tunnels[tnlid].tunnel_state == Tunnel.STATES.TNL_OFFLINE:
            params = {"OverlayId": olid, "TunnelId": tnlid, "LinkId": lnkid, "PeerId": peer_id}
            self.register_cbt("TincanInterface", "TCI_REMOVE_LINK", params)
        else:
            cbt.set_response("Tunnel busy, retry operation", False)
            self.complete_cbt(cbt)

    def _update_tunnel_descriptor(self, tnl_desc, tnlid):
        """
        Update the tunnel desc with with lock owned
        """
        self._tunnels[tnlid].mac = tnl_desc["MAC"]
        self._tunnels[tnlid].tap_name = tnl_desc["TapName"]
        self._tunnels[tnlid].fpr = tnl_desc["FPR"]
        self.register_cbt("Logger", "LOG_DEBUG", "Updated tunnels:{}".format(self._tunnels[tnlid]))

    def _query_link_stats(self):
        """Query the status of links that have completed creation process"""
        params = []
        for lnkid in self._tunnels:
            link = self._tunnels[lnkid].link
            if link and link.creation_state == 0xC0:
                params.append(lnkid)
        if params:
            self.register_cbt("TincanInterface", "TCI_QUERY_LINK_STATS", params)

    def resp_handler_query_link_stats(self, cbt):
        if not cbt.response.status:
            self.register_cbt("Logger", "LOG_WARNING", "Link stats update error: {0}"
                              .format(cbt.response.data))
            self.free_cbt(cbt)
            return
        if not cbt.response.data:
            self.free_cbt(cbt)
            return
        data = cbt.response.data
        #self.register_cbt("Logger", "LOG_DEBUG", "Tunnel stats: {0}".format(data))
        # Handle any connection failures and update tracking data
        for tnlid in data:
            for lnkid in data[tnlid]:
                if data[tnlid][lnkid]["Status"] == "UNKNOWN":
                    self._cleanup_removed_tunnel(tnlid)
                elif tnlid in self._tunnels:
                    tnl = self._tunnels[tnlid]
                    if data[tnlid][lnkid]["Status"] == "OFFLINE":
                        # tincan indicates offline so recheck the link status
                        retry = tnl.link.status_retry
                        if retry >= 2 and tnl.tunnel_state == Tunnel.STATES.TNL_CREATING:
                            # link is stuck creating so destroy it
                            olid = tnl.overlay_id
                            peer_id = tnl.peer_id
                            params = {"OverlayId": olid, "TunnelId": tnlid, "LinkId": lnkid,
                                      "PeerId": peer_id, "TapName": tnl.tap_name}
                            self.register_cbt("TincanInterface", "TCI_REMOVE_TUNNEL", params)
                        #elif retry >= 1 and tnl.tunnel_state == Tunnel.STATES.TNL_QUERYING:
                        elif retry >= 0 and tnl.tunnel_state == Tunnel.STATES.TNL_QUERYING:
                            # link went offline so notify top
                            tnl.tunnel_state = Tunnel.STATES.TNL_OFFLINE
                            olid = tnl.overlay_id
                            peer_id = tnl.peer_id
                            param = {
                                "UpdateType": "LnkEvDisconnected", "OverlayId": olid,
                                "PeerId": peer_id, "TunnelId": tnlid, "LinkId": lnkid,
                                "TapName": tnl.tap_name}
                            self._link_updates_publisher.post_update(param)
                        else:
                            tnl.link.status_retry = retry + 1
                    elif data[tnlid][lnkid]["Status"] == "ONLINE":
                        tnl.tunnel_state = Tunnel.STATES.TNL_ONLINE
                        #tnl.link.ice_role = data[tnlid][lnkid]["IceRole"]
                        tnl.link.stats = data[tnlid][lnkid]["Stats"]
                        tnl.link.status_retry = 0
                    else:
                        self.register_cbt("Logger", "LOG_WARNING", "Unrecognized tunnel state "
                                          "{0}:{1}".format(lnkid, data[tnlid][lnkid]["Status"]))
        self.free_cbt(cbt)

    def _cleanup_tunnel(self, tnl):
        """ Remove the tunnel data """
        del self._peers[tnl.overlay_id][tnl.peer_id]
        del self._tunnels[tnl.tnlid]

    def _cleanup_removed_tunnel(self, tnlid):
        """ Remove the tunnel data """
        tnl = self._tunnels.pop(tnlid, None)
        if tnl:
            peer_id = tnl.peer_id
            olid = tnl.overlay_id
            del self._peers[olid][peer_id]

    def _remove_link_from_tunnel(self, tnlid):
        tnl = self._tunnels.get(tnlid)
        if tnl:
            if tnl.link and tnl.link.lnkid:
                self._links.pop(tnl.link.lnkid)
            tnl.link = None
            tnl.tunnel_state = Tunnel.STATES.TNL_OFFLINE

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
        # Notify subscribers of tunnel removal
        param = {
            "UpdateType": "LnkEvRemoved", "OverlayId": olid, "TunnelId": tnlid, "LinkId": lnkid,
            "PeerId": peer_id}
        if tnlid not in self._tunnels:
            return # this would be an invalid condition, possible double remove request
        if self._tunnels[tnlid].tap_name:
            param["TapName"] = self._tunnels[tnlid].tap_name
        self._link_updates_publisher.post_update(param)
        self._cleanup_tunnel(self._tunnels[tnlid])
        self.free_cbt(rmv_tnl_cbt)
        if parent_cbt:
            parent_cbt.set_response("Tunnel removed", True)
            self.complete_cbt(parent_cbt)
        self.register_cbt("Logger", "LOG_INFO", "Tunnel {0} removed: {1}:{2}<->{3}"
                          .format(tnlid[:7], olid[:7], self.node_id[:7], peer_id[:7]))
        #self.register_cbt("Logger", "LOG_DEBUG", "State:\n" + str(self))

    def resp_handler_remove_link(self, rmv_tnl_cbt):
        parent_cbt = rmv_tnl_cbt.parent
        tnlid = rmv_tnl_cbt.request.params["TunnelId"]
        lnkid = self.link_id(tnlid)
        peer_id = rmv_tnl_cbt.request.params["PeerId"]
        olid = rmv_tnl_cbt.request.params["OverlayId"]
        # Notify subscribers of link removal
        param = {
            "UpdateType": "LnkEvRemoved", "OverlayId": olid, "TunnelId": tnlid, "LinkId": lnkid,
            "PeerId": peer_id}
        if self._tunnels[tnlid].tap_name:
            param["TapName"] = self._tunnels[tnlid].tap_name
        self._link_updates_publisher.post_update(param)
        self._remove_link_from_tunnel(tnlid)
        self.free_cbt(rmv_tnl_cbt)
        if parent_cbt:
            parent_cbt.set_response("Link removed", True)
            self.complete_cbt(parent_cbt)
        self.register_cbt("Logger", "LOG_INFO", "Link {0} from Tunnel {1} removed: {2}:{3}<->{4}"
                          .format(lnkid[:7], tnlid[:7], olid[:7], self.node_id[:7],
                                  peer_id[:7]))

    def req_handler_query_tunnels_info(self, cbt):
        results = {}
        for tnlid in self._tunnels:
            if self._tunnels[tnlid].tunnel_state == Tunnel.STATES.TNL_ONLINE:
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
        ol_type = self.config["Overlays"][overlay_id]["Type"]
        tnlid = params["TunnelId"]
        lnkid = params["LinkId"]
        peer_id = params["PeerId"]
        tap_name = self.config["Overlays"][overlay_id]["TapName"][:8] + str(peer_id[:7])
        if os.name == "nt":
            tap_name = self.config["Overlays"][overlay_id]["TapName"]
        self.log("LOG_DEBUG", "IgnoredNetInterfaces: %s",
                 self._get_ignored_tap_names(overlay_id, tap_name))
        create_tnl_params = {
            "OverlayId": overlay_id,
            "NodeId": self.node_id,
            "TunnelId": tnlid,
            "LinkId": lnkid,
            "StunServers": self.config.get("Stun", []),
            "Type": ol_type,
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

        remote_act = dict(OverlayId=overlay_id,
                          RecipientId=parent_cbt.request.params["PeerId"],
                          RecipientCM="LinkManager",
                          Action="LNK_REQ_LINK_ENDPT",
                          Params=endp_param)
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
        Removes links that failed the setup handshake. Does not currently complete pending CBTs.
        This needs to be handled or these CBTs will remain in the pending queue.
        """
        if tnlid not in self._tunnels:
            return
        creation_state = self._tunnels[tnlid].link.creation_state
        if creation_state < 0xC0:
            olid = self._tunnels[tnlid].overlay_id
            peer_id = self._tunnels[tnlid].peer_id
            lnkid = self.link_id(tnlid)
            params = {"OverlayId": olid, "PeerId": peer_id, "TunnelId": tnlid, "LinkId": lnkid}
            self.register_cbt("TincanInterface", "TCI_REMOVE_TUNNEL", params)

            self.register_cbt("Logger", "LOG_INFO", "Initiated removal of incomplete link: "
                              "PeerId:{2}, LinkId:{0}, CreateState:{1}"
                              .format(tnlid[:7], format(creation_state, "02X"), peer_id[:7]))

    def req_handler_auth_tunnel(self, cbt):
        """Node B"""
        olid = cbt.request.params["OverlayId"]
        peer_id = cbt.request.params["PeerId"]
        tnlid = cbt.request.params["TunnelId"]
        if peer_id in self._peers[olid] or tnlid in self._tunnels:
            cbt.set_response("Tunnel auth failed, resource already exist for peer:tunnel {0}:{1}"
                             .format(peer_id, tnlid[:7]), False)
        else:
            self._peers[olid][peer_id] = tnlid
            self._tunnels[tnlid] = Tunnel(tnlid, olid, peer_id)
            self.register_cbt("Logger", "LOG_DEBUG", "TunnelId:{0} auth for Peer:{1} completed"
                              .format(tnlid[:7], peer_id[:7]))
            cbt.set_response("Auth completed, TunnelId:{0}".format(tnlid[:7]), True)
            lnkupd_param = {
                "UpdateType": "LnkEvAuthorized", "OverlayId": olid, "PeerId": peer_id,
                "TunnelId": tnlid}
            self._link_updates_publisher.post_update(lnkupd_param)
        self.complete_cbt(cbt)

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
        if peer_id in self._peers[olid]:
            # Tunnel already exists
            tnlid = self._peers[olid][peer_id]
            tnl = self._tunnels[tnlid]
            if not tnl.link:
                # we need to create the link
                lnkid = tnlid
                self.register_cbt("Logger", "LOG_DEBUG", "Create Link:{} Tunnel exists. "
                                  "Skipping phase 1/5 Node A - Peer: {}"
                                  .format(lnkid[:7], peer_id[:7]))
                lnkupd_param = {
                    "UpdateType": "LnkEvCreating", "OverlayId": olid, "PeerId": peer_id,
                    "TunnelId": tnlid, "LinkId": lnkid}
                self._link_updates_publisher.post_update(lnkupd_param)

                self.register_cbt("Logger", "LOG_DEBUG",
                                  "Create Link:{} Phase 2/5 Node A - Peer: {}"
                                  .format(lnkid[:7], peer_id[:7]))
                self._assign_link_to_tunnel(tnlid, lnkid, 0xA2)
                tnl.tunnel_state = Tunnel.STATES.TNL_CREATING
                #tnl.creation_start_time = time.time()

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
                remote_act = dict(OverlayId=olid,
                                  RecipientId=peer_id,
                                  RecipientCM="LinkManager",
                                  Action="LNK_REQ_LINK_ENDPT",
                                  Params=params)

                endp_cbt = self.create_linked_cbt(cbt)
                endp_cbt.set_request(self.module_name, "Signal", "SIG_REMOTE_ACTION", remote_act)
                # Send the message via SIG server to peer
                self.submit_cbt(endp_cbt)
            else:
                # Link already exists, TM should clean up first
                cbt.set_response("A link already exist or is being created for "
                                 "overlay id: {0} peer id: {1}"
                                 .format(olid, peer_id), False)
                self.complete_cbt(cbt)
            return
        # No tunnel exists, going to create it.
        tnlid = cbt.request.params["TunnelId"]
        lnkid = tnlid
        # index for quick peer->link lookup
        self._peers[olid][peer_id] = tnlid
        self._tunnels[tnlid] = Tunnel(tnlid, olid, peer_id, Tunnel.STATES.TNL_CREATING,
                                      self.config["LinkSetupTimeout"])
        self._assign_link_to_tunnel(tnlid, lnkid, 0xA1)

        self.register_cbt("Logger", "LOG_DEBUG", "Create Link:{} Phase 1/5 Node A - Peer: {}"
                          .format(lnkid[:7], peer_id[:7]))
        lnkupd_param = {"UpdateType": "LnkEvCreating", "OverlayId": olid, "PeerId": peer_id,
                        "TunnelId": tnlid, "LinkId": lnkid}
        self._link_updates_publisher.post_update(lnkupd_param)

        params = {"OverlayId": olid, "TunnelId": tnlid, "LinkId": lnkid,
                  "Type": self.config["Overlays"][olid]["Type"], "PeerId": peer_id}
        self._create_tunnel(params, parent_cbt=cbt)

    def resp_handler_create_tunnel(self, cbt):
        # Create Link: Phase 2 Node A
        parent_cbt = cbt.parent
        lnkid = cbt.request.params["LinkId"]
        tnlid = cbt.request.params["TunnelId"]
        peer_id = parent_cbt.request.params["PeerId"]
        tap_name = cbt.request.params["TapName"]
        resp_data = cbt.response.data
        if not cbt.response.status:
            self._cleanup_removed_tunnel(lnkid)
            self.free_cbt(cbt)
            parent_cbt.set_response(resp_data, False)
            self.complete_cbt(parent_cbt)
            self.register_cbt("Logger", "LOG_WARNING", "The create tunnel operation failed:{}"
                              .format(parent_cbt.response.data))
            return
        # transistion connection connection state
        self._tunnels[tnlid].link.creation_state = 0xA2
        # store the overlay data
        overlay_id = cbt.request.params["OverlayId"]  # config overlay id
        self.register_cbt("Logger", "LOG_DEBUG", "Create Link:{} Phase 2/5 Node A"
                          .format(lnkid[:7]))
        self._update_tunnel_descriptor(resp_data, tnlid)
        lnkupd_param = {"UpdateType": "LnkEvCreated", "OverlayId": overlay_id, "PeerId": peer_id,
                        "TunnelId": tnlid, "LinkId": lnkid, "TapName": tap_name}
        self._link_updates_publisher.post_update(lnkupd_param)        
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
        if olid not in self.config["Overlays"]:
            self.register_cbt("Logger", "LOG_WARNING", "The requested overlay is not specified in "
                              "local config, it will not be created")
            lnk_endpt_cbt.set_response("Unknown overlay id specified in request", False)
            self.complete_cbt(lnk_endpt_cbt)
            return
        if peer_id not in self._peers[olid] or tnlid not in self._tunnels:
            msg = str("The requested lnk endpt was not authorized it will not be created. "
                      "TunnelId={0}, PeerId={1}".format(tnlid, peer_id))
            self.register_cbt("Logger", "LOG_WARNING", msg)
            lnk_endpt_cbt.set_response(msg, False)
            self.complete_cbt(lnk_endpt_cbt)
            return
        if self._tunnels[tnlid].link:
            msg = str("A link already exist for this tunnel, it will not be created. "
                      "TunnelId={0}, PeerId={1}".format(tnlid, peer_id))
            self.register_cbt("Logger", "LOG_WARNING", msg)
            lnk_endpt_cbt.set_response(msg, False)
            self.complete_cbt(lnk_endpt_cbt)
            return
        lnkid = tnlid
        self._tunnels[tnlid].tunnel_state = Tunnel.STATES.TNL_CREATING
        self._tunnels[tnlid].timeout = time.time() + self.config["LinkSetupTimeout"]
        self._assign_link_to_tunnel(tnlid, lnkid, 0xB1)
        # publish notification of link creation initiated Node B
        lnkupd_param = {
            "UpdateType": "LnkEvCreating", "OverlayId": olid, "PeerId": peer_id,
            "TunnelId": tnlid, "LinkId": lnkid}
        self._link_updates_publisher.post_update(lnkupd_param)
        # Send request to Tincan
        ol_type = self.config["Overlays"][olid]["Type"]
        tap_name = self.config["Overlays"][olid]["TapName"][:8] + str(peer_id[:7])
        self.log("LOG_DEBUG", "IgnoredNetInterfaces: %s",
                 self._get_ignored_tap_names(olid, tap_name))
        create_link_params = {
            "OverlayId": olid,
            # overlay params
            "TunnelId": tnlid,
            "NodeId": self.node_id,
            "StunServers": self.config.get("Stun", []),
            "Type": ol_type,
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
            if parent_cbt.child_count == 1:
                self.complete_cbt(parent_cbt)
            self.register_cbt("Logger", "LOG_WARNING", "Create link endpoint failed :{}"
                              .format(cbt.response.data))
            self._rollback_link_creation_changes(tnlid)

            return
        self.register_cbt("Logger", "LOG_DEBUG", "Create Link:{} Phase 2/4 Node B - Peer: {}"
                          .format(lnkid[:7], peer_id[:7]))
        # store the overlay data
        self._update_tunnel_descriptor(resp_data, tnlid)
        # add the peer MAC to the tunnel descr
        node_data = cbt.request.params["NodeData"]
        self._tunnels[tnlid].peer_mac = node_data["MAC"]
        self._tunnels[tnlid].link.creation_state = 0xB2
        tap_name = cbt.request.params["TapName"]
        lnkupd_param = {"UpdateType": "LnkEvCreated", "OverlayId": cbt.request.params["OverlayId"],
                        "PeerId": peer_id, "TunnelId": tnlid, "LinkId": lnkid, "TapName": tap_name}
        self._link_updates_publisher.post_update(lnkupd_param)        
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
        rem_act = parent_cbt.request.params
        lnkid = rem_act["LinkId"]
        tnlid = self.tunnel_id(lnkid)
        peer_id = rem_act["NodeData"]["UID"]
        self._tunnels[tnlid].link.creation_state = 0xC0
        self.register_cbt("Logger", "LOG_DEBUG", "Create Link:{} Phase 4/4 Node B - Peer: {}"
                          .format(lnkid[:7], peer_id[:7]))
        peer_id = rem_act["NodeData"]["UID"]
        olid = rem_act["OverlayId"]
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
        self.register_cbt("Logger", "LOG_INFO", "Tunnel {0} Link {1} accepted: {2}:{3}<-{4}"
                          .format(tnlid[:7], lnkid[:7], olid[:7], self.node_id[:7],
                                  peer_id[:7]))

    def _create_link_endpoint(self, rem_act, parent_cbt):
        """
        Send the Createlink control to local Tincan
        """
        # Create Link: Phase 5 Node A
        lnkid = rem_act["Data"]["LinkId"]
        tnlid = self.tunnel_id(lnkid)
        peer_id = rem_act["RecipientId"]
        if tnlid not in self._tunnels:
            # abort the handshake as the process timed out
            parent_cbt.set_response("Tunnel creation timeout failure", False)
            self.complete_cbt(parent_cbt)
            return
        self._tunnels[tnlid].link.creation_state = 0xA3
        self.register_cbt("Logger", "LOG_DEBUG", "Create Link:{} Phase 3/5 Node A - Peer: {}"
                          .format(lnkid[:7], peer_id[:7]))
        node_data = rem_act["Data"]["NodeData"]
        olid = rem_act["OverlayId"]
        # add the peer MAC to the tunnel descr
        self._tunnels[tnlid].peer_mac = node_data["MAC"]
        cbt_params = {"OverlayId": olid, "TunnelId": tnlid, "LinkId": lnkid, "Type": "TUNNEL",
                      "NodeData": {
                          "UID": node_data["UID"],
                          "MAC": node_data["MAC"],
                          "CAS": node_data["CAS"],
                          "FPR": node_data["FPR"]}}
        lcbt = self.create_linked_cbt(parent_cbt)
        lcbt.set_request(self.module_name, "TincanInterface", "TCI_CREATE_LINK", cbt_params)
        self.submit_cbt(lcbt)

    def _send_local_cas_to_peer(self, cbt):
        # Create Link: Phase 6 Node A
        lnkid = cbt.request.params["LinkId"]
        tnlid = self.tunnel_id(lnkid)
        peer_id = cbt.request.params["NodeData"]["UID"]
        self._tunnels[tnlid].link.creation_state = 0xA4
        self.register_cbt("Logger", "LOG_DEBUG", "Create Link:{} Phase 4/5 Node A - Peer: {}"
                          .format(lnkid[:7], peer_id[:7]))
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
        remote_act = dict(OverlayId=olid, RecipientId=peerid, RecipientCM="LinkManager",
                          Action="LNK_ADD_PEER_CAS", Params=params)
        lcbt = self.create_linked_cbt(parent_cbt)
        lcbt.set_request(self.module_name, "Signal", "SIG_REMOTE_ACTION", remote_act)
        self.submit_cbt(lcbt)
        self.free_cbt(cbt)

    def req_handler_add_peer_cas(self, cbt):
        # Create Link: Phase 7 Node B
        params = cbt.request.params
        olid = params["OverlayId"]
        lnkid = params["LinkId"]
        tnlid = self.tunnel_id(lnkid)
        peer_id = params["NodeData"]["UID"]
        if peer_id not in self._peers[olid] or tnlid not in self._tunnels \
            or self._tunnels[tnlid].link is None:
            self._cleanup_removed_tunnel(tnlid)
            self.register_cbt("Logger", "LOG_DEBUG",
                              "A response to an aborted add peer CAS operation was discarded: {0}".
                              format(str(cbt)))
            return

        self._tunnels[tnlid].link.creation_state = 0xB3
        self.register_cbt("Logger", "LOG_DEBUG", "Create Link:{} Phase 3/4 Node B - Peer: {}"
                          .format(lnkid[:7], peer_id[:7]))
        lcbt = self.create_linked_cbt(cbt)
        params["Type"] = self.config["Overlays"][olid]["Type"]
        lcbt.set_request(self.module_name, "TincanInterface", "TCI_CREATE_LINK", params)
        self.submit_cbt(lcbt)

    def resp_handler_create_link_endpt(self, cbt):
        parent_cbt = cbt.parent
        resp_data = cbt.response.data
        if not cbt.response.status:
            self.register_cbt("Logger", "LOG_WARNING", "Create link endpoint failed :{}"
                              .format(cbt))
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
        if peer_id not in self._peers[olid]:
            self.register_cbt("Logger", "LOG_DEBUG",
                              "A response to an aborted create link operation was discarded: {0}".
                              format(parent_cbt))
            return
        tnlid = self._peers[olid][peer_id]
        lnkid = self.link_id(tnlid)
        self._tunnels[tnlid].link.creation_state = 0xC0
        self.register_cbt("Logger", "LOG_DEBUG", "Create Link:{} Phase 5/5 Node A - Peer: {}"
                          .format(tnlid[:7], peer_id[:7]))
        parent_cbt.set_response(data={"LinkId": lnkid}, status=True)
        self.complete_cbt(parent_cbt)
        self.register_cbt("Logger", "LOG_INFO", "Tunnel {0} created: {1}:{2}->{3}"
                          .format(lnkid[:7], olid[:7], self.node_id[:7], peer_id[:7]))

    def resp_handler_remote_action(self, cbt):
        parent_cbt = cbt.parent
        resp_data = cbt.response.data
        if not cbt.response.status:
            lnkid = cbt.request.params["Params"]["LinkId"]
            tnlid = self.tunnel_id(lnkid)
            self._rollback_link_creation_changes(tnlid)
            self.free_cbt(cbt)
            parent_cbt.set_response(resp_data, False)
            self.complete_cbt(parent_cbt)
        else:
            rem_act = cbt.response.data
            self.free_cbt(cbt)
            if rem_act["Action"] == "LNK_REQ_LINK_ENDPT":
                self._create_link_endpoint(rem_act, parent_cbt)
            elif rem_act["Action"] == "LNK_ADD_PEER_CAS":
                self._complete_create_link_request(parent_cbt)

    def req_handler_tincan_msg(self, cbt):
        lts = time.time()
        if cbt.request.params["Command"] == "LinkStateChange":
            if cbt.request.params["Data"] == "LINK_STATE_DOWN":
                # issue a link state check
                lnkid = cbt.request.params["LinkId"]
                tnlid = cbt.request.params["TunnelId"]
                self.log("LOG_DEBUG", "LINK STATE DOWN cbt=%s", cbt)
                self._tunnels[tnlid].tunnel_state = Tunnel.STATES.TNL_QUERYING
                self.register_cbt("TincanInterface", "TCI_QUERY_LINK_STATS", [tnlid])
            elif cbt.request.params["Data"] == "LINK_STATE_UP":
                lnkid = cbt.request.params["LinkId"]
                tnlid = self.tunnel_id(lnkid)
                olid = self._tunnels[tnlid].overlay_id
                peer_id = self._tunnels[tnlid].peer_id
                lnk_status = self._tunnels[tnlid].tunnel_state
                self._tunnels[tnlid].tunnel_state = Tunnel.STATES.TNL_ONLINE
                if lnk_status != Tunnel.STATES.TNL_QUERYING:
                    param = {
                        "UpdateType": "LnkEvConnected", "OverlayId": olid, "PeerId": peer_id,
                        "TunnelId": tnlid, "LinkId": lnkid, "ConnectedTimestamp": lts,
                        "TapName": self._tunnels[tnlid].tap_name,
                        "MAC": self._tunnels[tnlid].mac,
                        "PeerMac": self._tunnels[tnlid].peer_mac}
                    self._link_updates_publisher.post_update(param)
                elif lnk_status == Tunnel.STATES.TNL_QUERYING:
                    # Do not post a notification if the the connection state was being queried
                    self._tunnels[tnlid].link.status_retry = 0
                # if the lnk_status is TNL_OFFLINE the recconect event came in too late and the
                # tear down has already been issued. This scenario is unlikely as the recheck time
                # is long enough such that the webrtc reconnect attempts will have been abandoned.
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

                elif cbt.request.action == "LNK_REMOVE_LINK":
                    self.req_handler_remove_link(cbt)

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
                    parent_cbt = cbt.parent
                    cbt_data = cbt.response.data
                    cbt_status = cbt.response.status
                    self.free_cbt(cbt)
                    if (parent_cbt is not None and parent_cbt.child_count == 1):
                        parent_cbt.set_response(cbt_data, cbt_status)
                        self.complete_cbt(parent_cbt)

    def _deauth_tnl(self, tnl):
        self.register_cbt("Logger", "LOG_INFO", "Tunnel {0} auth timed out".format(tnl.tnlid))
        param = {
            "UpdateType": "LnkEvDeauthorized", "OverlayId": tnl.overlay_id,
            "PeerId": tnl.peer_id, "TunnelId": tnl.tnlid, "TapName": tnl.tap_name}
        self._link_updates_publisher.post_update(param)
        self._cleanup_tunnel(tnl)

    def _cleanup_expired_incomplete_links(self):
        deauth = []
        rollbk = []
        for tnlid, tnl in self._tunnels.items():
            if tnl.tunnel_state == Tunnel.STATES.TNL_AUTHORIZED and time.time() > tnl.timeout:
                deauth.append(tnl)
            elif  tnl.link is not None and tnl.link.creation_state != 0xC0 and \
                time.time() > tnl.timeout:
                rollbk.append(tnlid)
        for tnl in deauth:
            self._deauth_tnl(tnl)
        for tnlid in rollbk:
            self._rollback_link_creation_changes(tnlid)

    def timer_method(self):
        with self._lock:
            self._cleanup_expired_incomplete_links()
            self._query_link_stats()
            self.log("LOG_DEBUG", "Timer LNK State=%s", str(self))

    def terminate(self):
        pass

    def req_handler_query_viz_data(self, cbt):
        nid = self.node_id
        tnls = dict()
        for tnlid in self._tunnels:
            if self._tunnels[tnlid].link is None:
                continue
            tnl_data = {
                "NodeId": nid,
                "PeerId": self._tunnels[tnlid].peer_id,
                "TunnelState": self._tunnels[tnlid].tunnel_state
                }

            if self._tunnels[tnlid].tap_name:
                tnl_data["TapName"] = self._tunnels[tnlid].tap_name
            if self._tunnels[tnlid].mac:
                tnl_data["MAC"] = self._tunnels[tnlid].mac
            #if "IceRole" in self._tunnels[tnlid]["Link"]:
            #    tnl_data["IceRole"] = self._tunnels[tnlid]["Link"]["IceRole"]
            if self._tunnels[tnlid].link.stats:
                tnl_data["Stats"] = self._tunnels[tnlid].link.stats
            overlay_id = self._tunnels[tnlid].overlay_id

            if overlay_id not in tnls:
                tnls[overlay_id] = dict()
            if nid not in tnls[overlay_id]:
                tnls[overlay_id][nid] = dict()
            tnls[overlay_id][nid][tnlid] = tnl_data

        cbt.set_response({"LinkManager": tnls}, bool(tnls))
        self.complete_cbt(cbt)
