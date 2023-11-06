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

import threading
import time

import broker
from broker import LINK_SETUP_TIMEOUT
from broker.cbt import CBT
from broker.controller_module import ControllerModule
from broker.remote_action import RemoteAction

from .tunnel import DATAPLANE_TYPES, TUNNEL_EVENTS, TUNNEL_STATES


class Link:
    _REFLECT: list[str] = ["lnkid", "_creation_state", "status_retry"]

    def __init__(self, lnkid, state):
        self.lnkid = lnkid
        self._creation_state = state
        self.status_retry = 0
        self.stats = {}

    def __repr__(self):
        return broker.introspect(self)

    @property
    def creation_state(self):
        return self._creation_state

    @creation_state.setter
    def creation_state(self, new_state):
        self._creation_state = new_state


class Tunnel:
    def __init__(
        self,
        tnlid: str,
        overlay_id: str,
        peer_id: str,
        tnl_state,
        dataplane,
    ):
        self.tnlid = tnlid
        self.overlay_id = overlay_id
        self.peer_id = peer_id
        self.tap_name = None
        self.mac = None
        self.fpr = None
        self.link = None
        self.peer_mac = None
        self.state = tnl_state
        self.dataplane = dataplane

    def __repr__(self):
        return broker.introspect(self)

    @property
    def tunnel_state(self):
        return self.state

    @tunnel_state.setter
    def tunnel_state(self, new_state):
        self.state = new_state

    def is_tnl_online(self) -> bool:
        return bool(self.tunnel_state == TUNNEL_STATES.ONLINE)


class LinkManager(ControllerModule):
    TAPNAME_MAXLEN = 15
    _REFLECT: list[str] = ["_tunnels"]

    def __init__(self, nexus, module_config):
        super().__init__(nexus, module_config)
        self._tunnels: dict[str, Tunnel] = {}  # maps tunnel id to its descriptor
        self._links = {}  # maps link id to tunnel id
        self._lock = threading.Lock()  # serializes access to _overlays, _links
        self._link_updates_publisher = None
        self._ignored_net_interfaces = dict()

    def initialize(self):
        self._register_abort_handlers()
        self._register_req_handlers()
        self._register_resp_handlers()
        self._link_updates_publisher = self.publish_subscription("LNK_TUNNEL_EVENTS")
        publishers = self.get_registered_publishers()
        if (
            "TincanTunnel" not in publishers
            or "TCI_TUNNEL_EVENT"
            not in self.get_available_subscriptions("TincanTunnel")
        ):
            raise RuntimeError(
                "The TincanTunnel MESSAGE NOTIFY subscription is not available."
                "Link Manager cannot continue."
            )
        self.start_subscription("TincanTunnel", "TCI_TUNNEL_EVENT")
        if (
            "OverlayVisualizer" in publishers
            and "VIS_DATA_REQ" in self.get_available_subscriptions("OverlayVisualizer")
        ):
            self.start_subscription("OverlayVisualizer", "VIS_DATA_REQ")
        else:
            self.logger.info("Overlay visualizer capability unavailable")

        for olid in self.config["Overlays"]:
            self._ignored_net_interfaces[olid] = set()
            ol_cfg = self.config["Overlays"][olid]
            if "IgnoredNetInterfaces" in ol_cfg:
                for ign_inf in ol_cfg["IgnoredNetInterfaces"]:
                    self._ignored_net_interfaces[olid].add(ign_inf)

        self.logger.info("Controller module loaded")

    def terminate(self):
        self.logger.info("Controller module terminating")

    def abort_handler_tunnel(self, cbt: CBT):
        self.logger.debug("Aborting CBT %s", cbt)
        if isinstance(cbt.request.params, RemoteAction):
            tnlid = cbt.request.params.params["TunnelId"]
        else:
            tnlid = cbt.request.params["TunnelId"]
        self._rollback_link_creation_changes(tnlid)

    def req_handler_auth_tunnel(self, cbt: CBT):
        """Node B"""
        olid = cbt.request.params["OverlayId"]
        peer_id = cbt.request.params["PeerId"]
        tnlid = cbt.request.params["TunnelId"]
        if tnlid in self._tunnels:
            cbt.set_response(
                "Tunnel auth failed, resource already exist for peer:tunnel {0}:{1}".format(
                    peer_id, tnlid[:7]
                ),
                False,
            )
            self.complete_cbt(cbt)
        else:
            tnl = Tunnel(
                tnlid,
                olid,
                peer_id,
                tnl_state=TUNNEL_STATES.AUTHORIZED,
                dataplane=DATAPLANE_TYPES.Tincan,
            )
            self._tunnels[tnlid] = tnl
            self.register_timed_transaction(
                tnl,
                self.is_tnl_online,
                self.on_tnl_timeout,
                LINK_SETUP_TIMEOUT,
            )
            self.logger.debug(
                "Tunnel %s authorized for peer %s.", tnlid[:7], peer_id[:7]
            )
            cbt.set_response(
                "Authorization completed, TunnelId:{0}".format(tnlid[:7]), True
            )
            lnkupd_param = {
                "UpdateType": TUNNEL_EVENTS.Authorized,
                "OverlayId": olid,
                "PeerId": peer_id,
                "TunnelId": tnlid,
            }
            self.complete_cbt(cbt)
            self._link_updates_publisher.post_update(lnkupd_param)

    def req_handler_create_tunnel(self, cbt: CBT):
        """Create Link: Phase 1 Node A
        Handle the request for capability LNK_CREATE_TUNNEL.
        The caller provides the overlay id and the peer id which the link
        connects. The link id is set here to match the tunnel id, and it is returned
        to the caller after the local endpoint creation is completed asynchronously.
        The link is not necessarily ready for read/write at this time. The link
        status can be queried to determine when it is writeable. The link id is
        communicated in the request and will be the same at both nodes.
        """
        olid = cbt.request.params["OverlayId"]
        peer_id = cbt.request.params["PeerId"]
        tnlid = cbt.request.params["TunnelId"]
        if tnlid in self._tunnels:
            # Tunnel already exists
            tnl = self._tunnels[tnlid]
            if not tnl.link:
                # we need to create the link
                lnkid = tnlid
                self.logger.debug(
                    "Create Link:%s Tunnel exists. "
                    "Skipping phase 1/5 Node A - Peer: %s",
                    lnkid[:7],
                    peer_id[:7],
                )

                self.logger.debug(
                    "Create Link:%s Phase 2/5 Node A - Peer: %s", lnkid[:7], peer_id[:7]
                )
                self._assign_link_to_tunnel(tnlid, lnkid, 0xA2)
                tnl.tunnel_state = TUNNEL_STATES.CREATING
                # create and send remote action to request endpoint from peer
                params = {
                    "OverlayId": olid,
                    "TunnelId": tnlid,
                    "LinkId": lnkid,
                    "NodeData": {"FPR": tnl.fpr, "MAC": tnl.mac, "UID": self.node_id},
                }
                rem_act = RemoteAction(
                    overlay_id=olid,
                    recipient_id=peer_id,
                    recipient_cm="LinkManager",
                    action="LNK_REQ_LINK_ENDPT",
                    params=params,
                )
                rem_act.submit_remote_act(self, cbt)
            else:
                # Link already exists, TM should clean up first
                cbt.set_response(
                    "Failed, duplicate link requested to "
                    "overlay id: {0} peer id: {1}".format(olid, peer_id),
                    False,
                )
                self.complete_cbt(cbt)
            return
        # No tunnel exists, going to create it.
        tnlid = cbt.request.params["TunnelId"]
        lnkid = tnlid
        self._tunnels[tnlid] = Tunnel(
            tnlid,
            olid,
            peer_id,
            tnl_state=TUNNEL_STATES.CREATING,
            dataplane=DATAPLANE_TYPES.Tincan,
        )
        self._assign_link_to_tunnel(tnlid, lnkid, 0xA1)

        self.logger.debug(
            "Creating link %s to peer %s (1/5 Initiator)", lnkid[:7], peer_id[:7]
        )
        params = {
            "OverlayId": olid,
            "TunnelId": tnlid,
            "LinkId": lnkid,
            "PeerId": peer_id,
        }
        self._create_tunnel(params, parent_cbt=cbt)

    def req_handler_req_link_endpt(self, lnk_endpt_cbt):
        """Create Link: Phase 3 Node B
        Rcvd peer req to create endpt, send to TCI
        """
        params = lnk_endpt_cbt.request.params
        olid = params["OverlayId"]
        tnlid = params["TunnelId"]
        node_data = params["NodeData"]
        peer_id = node_data["UID"]
        if tnlid not in self._tunnels:
            msg = str(
                "The requested lnk endpt was not authorized it will not be created. "
                "TunnelId={0}, PeerId={1}".format(tnlid, peer_id)
            )
            self.logger.info(msg)
            lnk_endpt_cbt.set_response(msg, False)
            self.complete_cbt(lnk_endpt_cbt)
            return
        if self._tunnels[tnlid].link:
            msg = str(
                "A link already exist for this tunnel, it will not be created. "
                "TunnelId={0}, PeerId={1}".format(tnlid, peer_id)
            )
            self.logger.warning(msg)
            lnk_endpt_cbt.set_response(msg, False)
            self.complete_cbt(lnk_endpt_cbt)
            return
        lnkid = tnlid
        self._tunnels[tnlid].tunnel_state = TUNNEL_STATES.CREATING
        self._assign_link_to_tunnel(tnlid, lnkid, 0xB1)
        self.logger.debug(
            "Creating link %s to peer %s (1/4 Target)", lnkid[:7], peer_id[:7]
        )
        # Send request to Tincan
        tap_name = self._gen_tap_name(olid, peer_id)
        self.logger.debug(
            "Ignored Network Interfaces: %s",
            self._get_ignored_tap_names(olid, tap_name),
        )
        create_link_params = {
            "OverlayId": olid,
            # overlay params
            "TunnelId": tnlid,
            "NodeId": self.node_id,
            "StunServers": self.config.get("Stun", []),
            "TapName": tap_name,
            "IgnoredNetInterfaces": list(self._get_ignored_tap_names(olid, tap_name)),
            # link params
            "LinkId": lnkid,
            "NodeData": {
                "FPR": node_data["FPR"],
                "MAC": node_data["MAC"],
                "UID": node_data["UID"],
            },
        }
        if self.config.get("Turn"):
            create_link_params["TurnServers"] = self.config["Turn"]
        self.register_cbt(
            "TincanTunnel", "TCI_CREATE_LINK", create_link_params, lnk_endpt_cbt
        )

    def req_handler_add_peer_cas(self, cbt: CBT):
        # Create Link: Phase 7 Node B
        params = cbt.request.params
        lnkid = params["LinkId"]
        tnlid = self.tunnel_id(lnkid)
        peer_id = params["NodeData"]["UID"]
        if tnlid not in self._tunnels:
            self.logger.info(
                "An request for an aborted tunnel was discarded: %s",
                cbt,
            )
            cbt.set_response({"Message": "This tunnel was aborted"}, False)
            self.complete_cbt(cbt)
            return
        self._tunnels[tnlid].link.creation_state = 0xB3
        self.logger.debug(
            "Creating link %s to peer %s (3/4 Target)", lnkid[:7], peer_id[:7]
        )
        self.register_cbt("TincanTunnel", "TCI_CREATE_LINK", params, cbt)

    def req_handler_tincan_msg(self, cbt: CBT):
        lts = time.time()
        tnlid = cbt.request.params["TunnelId"]
        if tnlid not in self._tunnels:
            cbt.set_response(data=None, status=True)
            self.complete_cbt(cbt)
            return
        elif cbt.request.params["Command"] == "LinkConnected":
            lnkid = cbt.request.params["LinkId"]
            self.logger.debug("Link %s is connected", lnkid)
            olid = self._tunnels[tnlid].overlay_id
            peer_id = self._tunnels[tnlid].peer_id
            lnk_status = self._tunnels[tnlid].tunnel_state
            self._tunnels[tnlid].tunnel_state = TUNNEL_STATES.ONLINE
            if lnk_status != TUNNEL_STATES.QUERYING:
                param = {
                    "UpdateType": TUNNEL_EVENTS.Connected,
                    "OverlayId": olid,
                    "PeerId": peer_id,
                    "TunnelId": tnlid,
                    "LinkId": lnkid,
                    "ConnectedTimestamp": lts,
                    "TapName": self._tunnels[tnlid].tap_name,
                    "MAC": self._tunnels[tnlid].mac,
                    "PeerMac": self._tunnels[tnlid].peer_mac,
                    "Dataplane": self._tunnels[tnlid].dataplane,
                }
                self._link_updates_publisher.post_update(param)
            elif lnk_status == TUNNEL_STATES.QUERYING:
                # Do not post a notification if the the connection state was being queried
                self._tunnels[tnlid].link.status_retry = 0
        elif cbt.request.params["Command"] == "LinkDisconnected":
            if self._tunnels[tnlid].tunnel_state != TUNNEL_STATES.QUERYING:
                # issue a link state check only if it not already being done
                self.logger.debug("Link %s is disconnected", tnlid)
                self._tunnels[tnlid].tunnel_state = TUNNEL_STATES.QUERYING
                cbt.set_response(data=None, status=True)
                self.register_deferred_call(
                    5,
                    self.register_cbt,
                    ("TincanTunnel", "TCI_QUERY_LINK_INFO", {"TunnelId": tnlid}),
                )  # issue link stat check in 5 secs as the link can reconnect
        elif cbt.request.params["Command"] == "TincanTunnelFailed":
            lnkid = self.link_id(tnlid)
            if lnkid:
                self._links.pop(lnkid, None)
            tnl = self._tunnels.pop(tnlid)
            tnl.tunnel_state = TUNNEL_STATES.FAILED
            param = {
                "UpdateType": TUNNEL_EVENTS.Removed,
                "OverlayId": tnl.overlay_id,
                "PeerId": tnl.peer_id,
                "TunnelId": tnlid,
                "LinkId": lnkid,
                "TapName": tnl.tap_name,
            }
            self._link_updates_publisher.post_update(param)
        else:
            self.logger.warning(
                "Unexpected Tincan event command received %s",
                cbt.request.params["Command"],
            )
        cbt.set_response(data=None, status=True)
        self.complete_cbt(cbt)

    def req_handler_query_tunnels_info(self, cbt: CBT):
        results = {}
        for tnlid in self._tunnels:
            if self._tunnels[tnlid].tunnel_state == TUNNEL_STATES.ONLINE:
                results[tnlid] = {
                    "OverlayId": self._tunnels[tnlid].overlay_id,
                    "TunnelId": tnlid,
                    "PeerId": self._tunnels[tnlid].peer_id,
                    "Stats": self._tunnels[tnlid].link.stats,
                    "TapName": self._tunnels[tnlid].tap_name,
                    "MAC": self._tunnels[tnlid].mac,
                    "PeerMac": self._tunnels[tnlid].peer_mac,
                }
        cbt.set_response(results, status=True)
        self.complete_cbt(cbt)

    def req_handler_remove_tnl(self, cbt: CBT):
        """Remove the tunnel and link given either the overlay id and peer id, or the tunnel id"""
        try:
            olid = cbt.request.params["OverlayId"]
            peer_id = cbt.request.params["PeerId"]
            tnlid = cbt.request.params["TunnelId"]
            if tnlid not in self._tunnels:
                cbt.set_response("No record", True)
                self.complete_cbt(cbt)
            elif (
                self._tunnels[tnlid].tunnel_state == TUNNEL_STATES.AUTHORIZED
                or self._tunnels[tnlid].tunnel_state == TUNNEL_STATES.ONLINE
                or self._tunnels[tnlid].tunnel_state == TUNNEL_STATES.OFFLINE
            ):
                tn = self._tunnels[tnlid].tap_name
                params = {
                    "OverlayId": olid,
                    "TunnelId": tnlid,
                    "PeerId": peer_id,
                    "TapName": tn,
                }
                self.register_cbt("TincanTunnel", "TCI_REMOVE_TUNNEL", params, cbt)
            else:
                cbt.set_response("Tunnel busy, retry operation", False)
                self.complete_cbt(cbt)
        except KeyError as err:
            cbt.set_response(f"Insufficient parameters {err}", False)
            self.complete_cbt(cbt)

    def _update_tunnel_descriptor(self, tnl_desc, tnlid):
        self._tunnels[tnlid].mac = tnl_desc["MAC"]
        self._tunnels[tnlid].tap_name = tnl_desc["TapName"]
        self._tunnels[tnlid].fpr = tnl_desc["FPR"]

    def req_handler_add_ign_inf(self, cbt: CBT):
        ign_inf_details = cbt.request.params
        for olid in ign_inf_details:
            self._ignored_net_interfaces[olid] |= ign_inf_details[olid]
        cbt.set_response(None, True)
        self.complete_cbt(cbt)

    def req_handler_query_viz_data(self, cbt: CBT):
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
                if stat_entry["best_conn"]:
                    lvals = stat_entry["local_candidate"].split(":")
                    rvals = stat_entry["remote_candidate"].split(":")
                    if len(lvals) < 10 or len(rvals) < 8:
                        continue
                    tnl_data["LocalEndpoint"] = {
                        "Proto": lvals[7],
                        "External": lvals[5] + ":" + lvals[6],
                        "Internal": lvals[8] + ":" + lvals[9],
                    }
                    tnl_data["RemoteEndpoint"] = {
                        "Proto": rvals[7],
                        "External": rvals[5] + ":" + rvals[6],
                    }
                    continue
            overlay_id = self._tunnels[tnlid].overlay_id
            if overlay_id not in tnls:
                tnls[overlay_id] = dict()
            tnls[overlay_id][tnlid] = tnl_data

        cbt.set_response({"LinkManager": tnls}, bool(tnls))
        self.complete_cbt(cbt)

    def resp_handler_create_link_endpt(self, cbt: CBT):
        """Create Link: Phase 4 Node B
        Create Link: Phase 6 Node A
        SIGnal to peer to update CAS
        Create Link: Phase 8 Node B
        Complete setup"""
        parent_cbt = cbt.parent
        resp_data = cbt.response.data
        if not cbt.response.status or parent_cbt is None:
            self.logger.warning(
                "Create link endpoint failed or the parent expired CBT:%s ", cbt
            )
            lnkid = cbt.request.params["LinkId"]
            self._rollback_link_creation_changes(lnkid)
            self.free_cbt(cbt)
            if parent_cbt:
                parent_cbt.set_response(resp_data, False)
                self.complete_cbt(parent_cbt)
            return

        if parent_cbt.request.action == "LNK_REQ_LINK_ENDPT":
            """
            To complete this request Node B has to supply its own
            NodeData and CAS. The NodeData was previously queried and is stored
            on the parent cbt. Add the cas and send to peer.
            """
            self._complete_link_endpt_request(cbt)

        elif parent_cbt.request.action == "LNK_CREATE_TUNNEL":
            """
            Both endpoints are created now but Node A must send its CAS. The peer
            (node B)already has the node data so no need to send that again.
            """
            self._send_local_cas_to_peer(cbt)

        elif parent_cbt.request.action == "LNK_ADD_PEER_CAS":
            """
            The link creation handshake is complete on Node B, complete the outstanding request
            and publish notifications via subscription.
            """
            self._complete_link_creation(cbt, parent_cbt)

    def resp_handler_remote_action(self, cbt: CBT):
        parent_cbt = cbt.parent
        resp_data = cbt.response.data
        rem_act: RemoteAction
        if not cbt.response.status or parent_cbt is None:
            rem_act = cbt.request.params
            lnkid = rem_act.params["LinkId"]
            tnlid = self.tunnel_id(lnkid)
            self.logger.debug(
                "The remote action requesting a connection endpoint link %s has failed or the parent expired",
                tnlid,
            )
            self._rollback_link_creation_changes(tnlid)
            self.free_cbt(cbt)
            if parent_cbt:
                parent_cbt.set_response(resp_data, False)
                self.complete_cbt(parent_cbt)
        else:
            rem_act = cbt.response.data
            self.free_cbt(cbt)
            if rem_act.action == "LNK_REQ_LINK_ENDPT":
                self._create_link_endpoint(rem_act, parent_cbt)
            elif rem_act.action == "LNK_ADD_PEER_CAS":
                self._complete_create_link_request(parent_cbt)
            else:
                self.logger("Unsupported Remote Action %s", rem_act)

    def resp_handler_create_tunnel(self, cbt: CBT):
        # Create Tunnel: Phase 2 Node A
        parent_cbt = cbt.parent
        lnkid = cbt.request.params["LinkId"]
        tnlid = cbt.request.params["TunnelId"]
        resp_data = cbt.response.data
        if not cbt.response.status or parent_cbt is None:
            self._deauth_tnl(tnlid)
            self.free_cbt(cbt)
            if parent_cbt:
                parent_cbt.set_response("Failed to create tunnel", False)
                self.complete_cbt(parent_cbt)
            self.logger.warning(
                "The create tunnel operation failed: %s or the parent expired",
                resp_data,
            )
            return
        # transistion connection connection state
        self._tunnels[tnlid].link.creation_state = 0xA2
        # store the overlay data
        overlay_id = cbt.request.params["OverlayId"]
        self.logger.debug(
            "Creating link %s to peer %s (2/5 Initiator)", lnkid[:7], None
        )
        self._update_tunnel_descriptor(resp_data, tnlid)
        # create and send remote action to request endpoint from peer
        params = {"OverlayId": overlay_id, "TunnelId": tnlid, "LinkId": lnkid}
        self._request_peer_endpoint(params, parent_cbt)
        self.free_cbt(cbt)

    def resp_handler_remove_tunnel(self, rmv_tnl_cbt: CBT):
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
            "UpdateType": TUNNEL_EVENTS.Removed,
            "OverlayId": olid,
            "TunnelId": tnlid,
            "LinkId": lnkid,
            "PeerId": peer_id,
            "TapName": tap_name,
        }
        self._link_updates_publisher.post_update(param)
        self.logger.info(
            "Tunnel %s removed: %s:%s<->%s",
            tnlid[:7],
            olid[:7],
            self.node_id[:7],
            peer_id[:7],
        )

    def resp_handler_query_link_stats(self, cbt: CBT):
        resp_data = cbt.response.data
        if not cbt.response.status:
            self.logger.warning("Link stats update error: %s", cbt.response.data)
            self.free_cbt(cbt)
            return
        # Handle any connection failures and update tracking data
        tnlid = resp_data["TunnelId"]
        lnkid = resp_data["LinkId"]
        if tnlid in self._tunnels:
            tnl = self._tunnels[tnlid]
            if resp_data["Status"] == "OFFLINE":
                # tincan indicates offline so recheck the link status
                retry = tnl.link.status_retry
                if (tnl.tunnel_state == TUNNEL_STATES.QUERYING) or (
                    retry >= 1 and tnl.tunnel_state == TUNNEL_STATES.ONLINE
                ):
                    # LINK_STATE_DOWN event or QUERY_LNK_STATUS response - post notify
                    tnl.tunnel_state = TUNNEL_STATES.OFFLINE
                    olid = tnl.overlay_id
                    peer_id = tnl.peer_id
                    param = {
                        "UpdateType": TUNNEL_EVENTS.Disconnected,
                        "OverlayId": olid,
                        "PeerId": peer_id,
                        "TunnelId": tnlid,
                        "LinkId": lnkid,
                        "TapName": tnl.tap_name,
                    }
                    self._link_updates_publisher.post_update(param)
            elif resp_data["Status"] == "ONLINE":
                tnl.tunnel_state = TUNNEL_STATES.ONLINE
                tnl.link.stats = resp_data["Stats"]
                tnl.link.status_retry = 0
            else:
                self.logger.warning(
                    "Unrecognized tunnel state ",
                    "%s:%s",
                    lnkid,
                    resp_data["Status"],
                )
        self.free_cbt(cbt)

    def on_tnl_timeout(self, tnl: Tunnel, timeout: float):
        self._rollback_link_creation_changes(tnl.tnlid)

    def _register_abort_handlers(self):
        self._abort_handler_tbl = {
            "SIG_REMOTE_ACTION": self.abort_handler_tunnel,
            "TCI_CREATE_LINK": self.abort_handler_tunnel,
            "TCI_CREATE_TUNNEL": self.abort_handler_tunnel,
            "TCI_REMOVE_TUNNEL": self.abort_handler_tunnel,
            "TCI_QUERY_LINK_INFO": self.abort_handler_default,
            "TCI_REMOVE_LINK": self.abort_handler_default,
            "LNK_TUNNEL_EVENTS": self.abort_handler_default,
        }

    def _register_req_handlers(self):
        self._req_handler_tbl = {
            "LNK_CREATE_TUNNEL": self.req_handler_create_tunnel,
            "LNK_REQ_LINK_ENDPT": self.req_handler_req_link_endpt,
            "LNK_ADD_PEER_CAS": self.req_handler_add_peer_cas,
            "LNK_REMOVE_TUNNEL": self.req_handler_remove_tnl,
            "LNK_QUERY_TUNNEL_INFO": self.req_handler_query_tunnels_info,
            "VIS_DATA_REQ": self.req_handler_query_viz_data,
            "TCI_TUNNEL_EVENT": self.req_handler_tincan_msg,
            "LNK_ADD_IGN_INF": self.req_handler_add_ign_inf,
            "LNK_AUTH_TUNNEL": self.req_handler_auth_tunnel,
        }

    def _register_resp_handlers(self):
        self._resp_handler_tbl = {
            "SIG_REMOTE_ACTION": self.resp_handler_remote_action,
            "TCI_CREATE_LINK": self.resp_handler_create_link_endpt,
            "TCI_CREATE_TUNNEL": self.resp_handler_create_tunnel,
            "TCI_QUERY_LINK_INFO": self.resp_handler_query_link_stats,
            "TCI_REMOVE_TUNNEL": self.resp_handler_remove_tunnel,
        }

    def _gen_tap_name(self, overlay_id: str, peer_id: str) -> str:
        tap_name_prefix = self.config["Overlays"][overlay_id].get(
            "TapNamePrefix", overlay_id[:5]
        )
        end_i = self.TAPNAME_MAXLEN - len(tap_name_prefix)
        tap_name = tap_name_prefix + str(peer_id[:end_i])
        return tap_name

    def _get_ignored_tap_names(self, overlay_id, new_inf_name=None):
        ign_netinf = set()
        if new_inf_name:
            ign_netinf.add(new_inf_name)

        if not self.config["Overlays"][overlay_id].get(
            "AllowRecursiveTunneling", False
        ):
            # Ignore ALL the evio tap devices (regardless of their overlay id/link id)
            for tnlid in self._tunnels:
                if self._tunnels[tnlid].tap_name:
                    ign_netinf.add(self._tunnels[tnlid].tap_name)
        # add the global ignore list
        ign_netinf.update(self.config.get("IgnoredNetInterfaces", []))
        # add the overlay specifc list
        ign_netinf |= self._ignored_net_interfaces[overlay_id]
        return ign_netinf

    def is_tnl_online(self, tnl: Tunnel) -> bool:
        return tnl.is_tnl_online()

    def _remove_link_from_tunnel(self, tnlid):
        tnl = self._tunnels.get(tnlid)
        if tnl:
            if tnl.link and tnl.link.lnkid:
                self._links.pop(tnl.link.lnkid)
            tnl.link = None
            tnl.tunnel_state = TUNNEL_STATES.OFFLINE

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

    def _create_tunnel(self, params, parent_cbt):
        overlay_id = params["OverlayId"]
        tnlid = params["TunnelId"]
        lnkid = params["LinkId"]
        peer_id = params["PeerId"]
        tap_name = self._gen_tap_name(overlay_id, peer_id)
        self.logger.debug(
            "IgnoredNetInterfaces: %s",
            self._get_ignored_tap_names(overlay_id, tap_name),
        )
        create_tnl_params = {
            "OverlayId": overlay_id,
            "NodeId": self.node_id,
            "TunnelId": tnlid,
            "LinkId": lnkid,
            "StunServers": self.config.get("Stun", []),
            "TapName": tap_name,
            "IgnoredNetInterfaces": list(
                self._get_ignored_tap_names(overlay_id, tap_name)
            ),
        }
        if self.config.get("Turn"):
            create_tnl_params["TurnServers"] = self.config["Turn"]

        self.register_cbt(
            "TincanTunnel", "TCI_CREATE_TUNNEL", create_tnl_params, parent_cbt
        )

    def _request_peer_endpoint(self, params: dict, parent_cbt: CBT):
        overlay_id = params["OverlayId"]
        tnlid = params["TunnelId"]
        endp_param = {
            "NodeData": {
                "FPR": self._tunnels[tnlid].fpr,
                "MAC": self._tunnels[tnlid].mac,
                "UID": self.node_id,
            }
        }
        endp_param.update(params)
        rem_act = RemoteAction(
            overlay_id=overlay_id,
            recipient_id=parent_cbt.request.params["PeerId"],
            recipient_cm="LinkManager",
            action="LNK_REQ_LINK_ENDPT",
            params=endp_param,
        )
        rem_act.submit_remote_act(self, parent_cbt)

    def _create_link_endpoint(self, rem_act: RemoteAction, parent_cbt: CBT):
        """
        Send the Create Link control to local Tincan to initiate link NAT traversal
        """
        # Create Link: Phase 5 Node A
        lnkid = rem_act.data["LinkId"]
        tnlid = self.tunnel_id(lnkid)
        peer_id = rem_act.recipient_id
        if tnlid not in self._tunnels:
            # abort the handshake as the process timed out
            parent_cbt.set_response("Tunnel creation timeout failure", False)
            self.complete_cbt(parent_cbt)
            return
        self._tunnels[tnlid].link.creation_state = 0xA3
        self.logger.debug(
            "Creating link %s to peer %s (3/5 Initiator)", lnkid[:7], peer_id[:7]
        )
        node_data = rem_act.data["NodeData"]
        olid = rem_act.overlay_id
        # add the peer MAC to the tunnel descr
        self._tunnels[tnlid].peer_mac = node_data["MAC"]
        cbt_params = {
            "OverlayId": olid,
            "TunnelId": tnlid,
            "LinkId": lnkid,
            "NodeData": {
                "UID": node_data["UID"],
                "MAC": node_data["MAC"],
                "CAS": node_data["CAS"],
                "FPR": node_data["FPR"],
            },
        }
        self.register_cbt("TincanTunnel", "TCI_CREATE_LINK", cbt_params, parent_cbt)

    def _complete_create_link_request(self, parent_cbt: CBT):
        # Create Link: Phase 9 Node A
        # Complete the cbt that started this all
        olid = parent_cbt.request.params["OverlayId"]
        peer_id = parent_cbt.request.params["PeerId"]
        tnlid = parent_cbt.request.params["TunnelId"]
        if tnlid not in self._tunnels:
            # abort the handshake as the process timed out
            parent_cbt.set_response("Tunnel creation timeout failure", False)
            self.complete_cbt(parent_cbt)
            return
        lnkid = self.link_id(tnlid)
        tnl = self._tunnels[tnlid]
        tnl.link.creation_state = 0xC0
        self.logger.debug(
            "Creating link %s to peer %s (5/5 Initiator)", tnlid[:7], peer_id[:7]
        )
        parent_cbt.set_response(data={"LinkId": lnkid}, status=True)
        self.complete_cbt(parent_cbt)
        self.logger.info(
            "Tunnel %s created: %s:%s->%s",
            lnkid[:7],
            olid[:7],
            self.node_id[:7],
            peer_id[:7],
        )
        if not tnl.is_tnl_online():
            self.register_timed_transaction(
                tnl,
                self.is_tnl_online,
                self.on_tnl_timeout,
                LINK_SETUP_TIMEOUT,
            )

    def _complete_link_endpt_request(self, cbt: CBT):
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
                lnkid,
                cbt.response.data,
            )
            self._rollback_link_creation_changes(tnlid)
            return
        self.logger.debug(
            "Creating link %s to peer %s (2/4 Target)", lnkid[:7], peer_id[:7]
        )
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
            "CAS": resp_data["CAS"],
        }
        data = {
            "OverlayId": cbt.request.params["OverlayId"],
            "TunnelId": tnlid,
            "LinkId": lnkid,
            "NodeData": node_data,
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
            "Creating link %s to peer %s (4/4 Target)", lnkid[:7], peer_id[:7]
        )
        peer_id = params["NodeData"]["UID"]
        olid = params["OverlayId"]
        resp_data = cbt.response.data
        node_data = {
            "MAC": resp_data["MAC"],
            "FPR": resp_data["FPR"],
            "UID": self.node_id,
            "CAS": resp_data["CAS"],
        }
        data = {
            "OverlayId": cbt.request.params["OverlayId"],
            "TunnelId": tnlid,
            "LinkId": lnkid,
            "NodeData": node_data,
        }
        parent_cbt.set_response(data=data, status=True)
        self.free_cbt(cbt)
        self.complete_cbt(parent_cbt)
        self.logger.info(
            "Tunnel %s accepted: %s:%s<-%s",
            tnlid[:7],
            olid[:7],
            self.node_id[:7],
            peer_id[:7],
        )

    def _send_local_cas_to_peer(self, cbt: CBT):
        # Create Link: Phase 6 Node A
        lnkid = cbt.request.params["LinkId"]
        tnlid = self.tunnel_id(lnkid)
        peer_id = cbt.request.params["NodeData"]["UID"]
        self._tunnels[tnlid].link.creation_state = 0xA4
        self.logger.debug(
            "Creating link %s to peer %s (4/5 Initiator)", lnkid[:7], peer_id[:7]
        )
        local_cas = cbt.response.data["CAS"]
        parent_cbt = cbt.parent
        olid = cbt.request.params["OverlayId"]
        peerid = parent_cbt.request.params["PeerId"]
        params = {
            "OverlayId": olid,
            "TunnelId": tnlid,
            "LinkId": lnkid,
            "NodeData": {
                "UID": self.node_id,
                "MAC": cbt.response.data["MAC"],
                "CAS": local_cas,
                "FPR": cbt.response.data["FPR"],
            },
        }
        self.free_cbt(cbt)
        rem_act = RemoteAction(
            overlay_id=olid,
            recipient_id=peerid,
            recipient_cm="LinkManager",
            action="LNK_ADD_PEER_CAS",
            params=params,
        )
        rem_act.submit_remote_act(self, parent_cbt)

    def _deauth_tnl(self, tnlid: str):
        tnl = self._tunnels.get(tnlid)
        if not tnl:
            return
        self.logger.info("Deauthorizing tunnel %s", tnlid)
        param = {
            "UpdateType": TUNNEL_EVENTS.AuthExpired,
            "OverlayId": tnl.overlay_id,
            "PeerId": tnl.peer_id,
            "TunnelId": tnlid,
            "TapName": tnl.tap_name,
        }
        self._link_updates_publisher.post_update(param)
        self._cleanup_failed_tunnel_data(tnl)

    def _rollback_link_creation_changes(self, tnlid):
        """
        Removes links that failed the setup handshake.
        """
        if tnlid not in self._tunnels:
            return
        tnl = self._tunnels[tnlid]
        self._cleanup_failed_tunnel_data(tnl)
        if (
            tnl.tunnel_state == TUNNEL_STATES.CREATING
            or tnl.tunnel_state == TUNNEL_STATES.QUERYING
            or tnl.tunnel_state == TUNNEL_STATES.OFFLINE
        ):
            olid = tnl.overlay_id
            peer_id = tnl.peer_id
            lnkid = self.link_id(tnlid)
            params = {
                "OverlayId": olid,
                "PeerId": peer_id,
                "TunnelId": tnlid,
                "LinkId": lnkid,
                "TapName": tnl.tap_name,
            }
            self.logger.info(
                "Initiating removal of incomplete tunnnel: "
                "Tap: %s, TnlId: %s, CreateState: %s",
                tnl.tap_name,
                tnlid[:7],
                format(tnl.link.creation_state, "02X"),
            )
            self.register_cbt("TincanTunnel", "TCI_REMOVE_TUNNEL", params)

    def _cleanup_failed_tunnel_data(self, tnl: Tunnel):
        self.logger.debug("Removing failed tunnel data %s", tnl)
        if tnl:
            self._tunnels.pop(tnl.tnlid, None)
        if tnl.link:
            self._links.pop(tnl.link.lnkid, None)
