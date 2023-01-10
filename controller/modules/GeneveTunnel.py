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

import time

from framework.ControllerModule import ControllerModule
from framework.Modlib import RemoteAction
from pyroute2 import IPRoute

from .Tunnel import DataplaneTypes, Tunnel, TunnelEvents, TunnelStates

GeneveSetupTimeout = 120


class GeneveTunnel(ControllerModule):
    TAPNAME_MAXLEN = 15
    _REFLECT = set(["_tunnels"])

    def __init__(self, cfx_handle, module_config, module_name):
        super().__init__(cfx_handle, module_config, module_name)
        self._ipr = IPRoute()
        self._tunnels = {}  # tunnel id -> TunnelDescriptor
        self._gnv_updates_publisher = None

    def initialize(self):
        self._gnv_updates_publisher = self.publish_subscription("GNV_TUNNEL_EVENTS")
        self.logger.info("Module loaded")

    def process_cbt(self, cbt):
        if cbt.op_type == "Request":
            if cbt.request.action == "GNV_AUTH_TUNNEL":
                self.req_handler_auth_tunnel(cbt)
            elif cbt.request.action == "GNV_CREATE_TUNNEL":
                # node A sends data to node B
                self.req_handler_create_tunnel(cbt)
            elif cbt.request.action == "GNV_REMOVE_TUNNEL":
                self.req_handler_remove_tunnel(cbt)
            elif cbt.request.action == "GNV_EXCHANGE_ENDPT":
                # node B accepts data from node A, creates tunnel on node B and completes cbt with endpoint data
                self.req_handler_exchnge_endpt(cbt)
            elif cbt.request.action == "GNV_UPDATE_MAC":
                self.req_handler_update_peer_mac(cbt)
            else:
                self.req_handler_default(cbt)
        elif cbt.op_type == "Response":
            if cbt.request.action == "SIG_REMOTE_ACTION":
                # response to call create tunnel command on node A
                self.resp_handler_remote_action(cbt)  # extracts fields from rem action
            else:
                self.resp_handler_default(cbt)

    def timer_method(self, is_exiting=False):
        deauth = []
        if is_exiting:
            return
        for tnl in self._tunnels.values():
            if tnl.state == TunnelStates.AUTHORIZED and time.time() > tnl.timeout:
                deauth.append(tnl)
        self._deauth_tnls(deauth)

    def terminate(self):
        for tnl in self._tunnels.values():
            self._remove_tunnel(tnl.tap_name)
        self._tunnels.clear()
        self.logger.info("Module Terminating")

    def _deauth_tnls(self, tnls: list):
        for tnl in tnls:
            self.logger.info("Deauthorizing tunnel %s", tnl.tnlid)
            param = {
                "UpdateType": TunnelEvents.AuthExpired,
                "OverlayId": tnl.overlay_id,
                "PeerId": tnl.peer_id,
                "TunnelId": tnl.tnlid,
                "TapName": tnl.tap_name,
            }
            self._gnv_updates_publisher.post_update(param)
            self._tunnels.pop(tnl.tnlid, None)
            self._remove_tunnel(tnl.tap_name)

    def _create_tunnel(self, tap_name, vnid, remote_addr):
        try:
            self.logger.info(
                "Creating Geneve tunnel %s vnid=%s, remote addr=%s",
                tap_name,
                vnid,
                remote_addr,
            )
            self._ipr.link(
                "add",
                ifname=tap_name,
                kind="geneve",
                geneve_id=vnid,
                geneve_remote=remote_addr,
            )
            x = self._ipr.link_lookup(ifname=tap_name)[0]
            # bring link up
            self._ipr.link("set", index=x, state="up")
        except Exception as e:
            self.logger.warning(
                "Failed to create Geneve tunnel %s, error code: %s", tap_name, str(e)
            )

    def _remove_tunnel(self, tap_name):
        try:
            self.logger.info("Removing Geneve tunnel %s", tap_name)
            idx = self._ipr.link_lookup(ifname=tap_name)
            if idx:
                self._ipr.link("del", index=idx[0])
        except Exception as e:
            self.logger.warning(
                "Failed to remove geneve tunnel %s, error code: %s", tap_name, str(e)
            )

    def _is_tunnel_exist(self, tap_name):
        idx = self._ipr.link_lookup(ifname=tap_name)
        if len(idx) == 1:
            return True
        return False

    def _is_tunnel_authorized(self, tunnel_id):
        tnl = self._tunnels.get(tunnel_id)
        if tnl and tnl.state == TunnelStates.AUTHORIZED:
            return True
        return False

    def req_handler_auth_tunnel(self, cbt):
        """Node B"""
        olid = cbt.request.params["OverlayId"]
        peer_id = cbt.request.params["PeerId"]
        tnlid = cbt.request.params["TunnelId"]
        if tnlid in self._tunnels:
            cbt.set_response(
                f"Geneve tunnel authorization failed, a tunnel with ID {tnlid[:7]} already exist for peer{peer_id[:7]}",
                False,
            )
        else:
            tap_name = self.get_tap_name(peer_id, olid)
            self._tunnels[tnlid] = Tunnel(
                tnlid,
                olid,
                peer_id,
                TunnelStates.AUTHORIZED,
                GeneveSetupTimeout,
                tap_name,
                DataplaneTypes.Geneve,
            )
            self.logger.debug(
                "TunnelId:%s authorization for Peer:%s completed",
                tnlid[:7],
                peer_id[:7],
            )
            cbt.set_response(
                f"Geneve tunnel authorization completed, TunnelId:{tnlid[:7]}", True
            )
            event_param = {
                "UpdateType": TunnelEvents.Authorized,
                "OverlayId": olid,
                "PeerId": peer_id,
                "TunnelId": tnlid,
            }
            self._gnv_updates_publisher.post_update(event_param)
        self.complete_cbt(cbt)

    def req_handler_create_tunnel(self, cbt):
        """Role A"""
        olid = cbt.request.params["OverlayId"]
        tnlid = cbt.request.params["TunnelId"]
        loc_id = cbt.request.params["VNId"]
        peer_id = cbt.request.params["PeerId"]
        tap_name = self.get_tap_name(peer_id, olid)

        if tnlid in self._tunnels or self._is_tunnel_exist(tap_name):
            cbt.set_response(data=f"Tunnel {tnlid} already exists", status=False)
            self.complete_cbt(cbt)
        else:
            self._tunnels[tnlid] = Tunnel(
                tnlid,
                olid,
                peer_id,
                TunnelStates.AUTHORIZED,
                GeneveSetupTimeout,
                tap_name,
                DataplaneTypes.Geneve,
            )
            params = {
                "OverlayId": olid,
                "NodeId": self.node_id,
                "TunnelId": tnlid,
                "VNId": loc_id,
                "EndPointAddress": self.config["Overlays"][olid]["EndPointAddress"],
            }
            rem_act = RemoteAction(
                overlay_id=olid,
                recipient_id=peer_id,
                recipient_cm="GeneveTunnel",
                action="GNV_EXCHANGE_ENDPT",
                params=params,
            )
            # Send the message via SIG server to peer
            rem_act.submit_remote_act(self, cbt)

    def req_handler_exchnge_endpt(self, cbt):
        """Role B"""
        params = cbt.request.params
        olid = params["OverlayId"]
        tnlid = params["TunnelId"]
        vnid = params["VNId"]
        peer_id = params["NodeId"]
        endpnt_address = params["EndPointAddress"]
        if olid not in self.config["Overlays"]:
            self.logger.warning(
                "The requested overlay is not specified in "
                "local config, it will not be created"
            )
            cbt.set_response("Unknown overlay id specified in request", False)
            self.complete_cbt(cbt)
            return
        if not self._is_tunnel_authorized(tnlid):
            msg = str(
                "The requested link endpoint was not authorized. It will not be created. "
                f"TunnelId={tnlid}, PeerId={peer_id}, VNID={vnid}"
            )
            self.logger.warning(msg)
            cbt.set_response(msg, False)
            self.complete_cbt(cbt)
            return
        if vnid is None:
            msg = str(
                "The VNID is NULL. Tunnel cannot be created. "
                f"TunnelId={tnlid}, PeerId={peer_id}"
            )
            self.logger.warning(msg)
            cbt.set_response(msg, False)
            self.complete_cbt(cbt)
            return
        # Send request to create tunnel
        try:
            tap_name = self._tunnels[tnlid].tap_name
            self._create_tunnel(tap_name, vnid, endpnt_address)
            msg = {
                "EndPointAddress": self.config["Overlays"][olid]["EndPointAddress"],
                "VNId": vnid,
                "NodeId": self.node_id,
                "TunnelId": tnlid,
                "MAC": self._tunnels[tnlid].mac,
                "Dataplane": self._tunnels[tnlid].dataplane,
            }
            cbt.set_response(msg, True)
            self.complete_cbt(cbt)
        except Exception as err:
            msg = str("Creation of geneve tunnel failed. Error=%s", err)
            self.logger.warning(msg)
            cbt.set_response(msg, False)
        self.submit_cbt(cbt)

    def req_handler_update_peer_mac(self, cbt):
        """Role B"""
        params = cbt.request.params
        olid = params["OverlayId"]
        tnlid = params["TunnelId"]
        peer_id = params["NodeId"]
        if not self._is_tunnel_authorized:
            # the in-progress tunnel was removed in the deauth method
            cbt.set_response("The request expired and was cancelled", False)
            self.complete_cbt(cbt)
            return
        self._tunnels[tnlid].peer_mac = params["MAC"]
        # tunnel connected is simulated here, BF module will check peer liveliness
        self._tunnels[tnlid].state = TunnelStates.ONLINE
        gnv_param = {
            "UpdateType": TunnelEvents.Connected,
            "OverlayId": olid,
            "PeerId": peer_id,
            "TunnelId": tnlid,
            "ConnectedTimestamp": time.time(),
            "TapName": self._tunnels[tnlid].tap_name,
            "MAC": self._tunnels[tnlid].mac,
            "PeerMac": self._tunnels[tnlid].peer_mac,
            "Dataplane": self._tunnels[tnlid].dataplane,
        }
        self._gnv_updates_publisher.post_update(gnv_param)
        cbt.set_response("Peer MAC added", True)
        self.complete_cbt(cbt)

    def req_handler_remove_tunnel(self, cbt):
        peer_id = cbt.request.params["PeerId"]
        olid = cbt.request.params["OverlayId"]
        tnlid = cbt.request.params["TunnelId"]
        tap_name = self._tunnels[tnlid].tap_name

        if self._is_tunnel_exist(tap_name):
            if self._tunnels[tnlid].state != TunnelStates.ONLINE:
                cbt.set_response(
                    data=f"Invalid Tunnel state for removal request {self._tunnels[tnlid]}",
                    status=False,
                )
                self.complete_cbt(cbt)
            else:
                self._tunnels[tnlid].state = TunnelStates.OFFLINE
                self._remove_tunnel(tap_name)
                self._tunnels.pop(tnlid)
                # self._peers[olid].pop(peer_id)
                cbt.set_response(data=f"Tunnel {tap_name} deleted", status=True)
                self.complete_cbt(cbt)
                gnv_param = {
                    "UpdateType": TunnelEvents.Removed,
                    "OverlayId": olid,
                    "PeerId": peer_id,
                    "TunnelId": tnlid,
                    "TapName": tap_name,
                }
                self._gnv_updates_publisher.post_update(gnv_param)
        else:
            cbt.set_response(data=f"Tunnel {tap_name} does not exists", status=False)
            self.complete_cbt(cbt)

    def resp_handler_remote_action(self, cbt):
        """Role A"""
        parent_cbt = cbt.parent
        resp_data = cbt.response.data
        rem_act = cbt.request.params
        tnlid = rem_act.params["TunnelId"]
        if not cbt.response.status:
            if self._is_tunnel_authorized(tnlid):
                self._deauth_tnls([self._tunnels[tnlid]])
            self.free_cbt(cbt)
            if parent_cbt:
                parent_cbt.set_response(resp_data, False)
                self.complete_cbt(parent_cbt)
        elif not self._is_tunnel_authorized(tnlid):
            # the request expired and has already been removed
            self.free_cbt(cbt)
            if parent_cbt:
                parent_cbt.set_response("The request expired and was cancelled", False)
                self.complete_cbt(parent_cbt)
            return
        elif rem_act.action == "GNV_UPDATE_MAC":
            rem_act = cbt.response.data
            olid = rem_act.overlay_id
            peer_id = rem_act.recipient_id
            tnlid = rem_act.params["TunnelId"]
            self._tunnels[tnlid].state = TunnelStates.ONLINE
            gnv_param = {
                "UpdateType": TunnelEvents.Connected,
                "OverlayId": olid,
                "PeerId": peer_id,
                "TunnelId": tnlid,
                "ConnectedTimestamp": time.time(),
                "TapName": self._tunnels[tnlid].tap_name,
                "MAC": self._tunnels[tnlid].mac,
                "PeerMac": self._tunnels[tnlid].peer_mac,
                "Dataplane": self._tunnels[tnlid].dataplane,
            }
            self._gnv_updates_publisher.post_update(gnv_param)
            self.free_cbt(cbt)
            parent_cbt.set_response("Geneve tunnel created", True)
            self.complete_cbt(parent_cbt)
        elif rem_act.action == "GNV_EXCHANGE_ENDPT":
            rem_act = cbt.response.data
            olid = rem_act.overlay_id
            peer_id = rem_act.data["NodeId"]
            tnlid = rem_act.data["TunnelId"]
            vnid = rem_act.data["VNId"]
            self._tunnels[tnlid].peer_mac = rem_act.data["MAC"]
            endpnt_address = rem_act.data["EndPointAddress"]
            tap_name = self.get_tap_name(peer_id, olid)
            if vnid is None:
                msg = str(
                    "The VNID is NULL. Tunnel cannot be created. "
                    f"TunnelId={tnlid}, PeerId={peer_id}"
                )
                self.logger.warning(msg)
                parent_cbt.set_response(msg, False)
                self.complete_cbt(parent_cbt)
                return
            self._create_tunnel(tap_name, vnid, endpnt_address)
            params = {
                "OverlayId": olid,
                "NodeId": self.node_id,
                "TunnelId": tnlid,
                "MAC": self._tunnels[tnlid].mac,
            }
            remote_act = RemoteAction(
                overlay_id=olid,
                recipient_id=peer_id,
                recipient_cm="GeneveTunnel",
                action="GNV_UPDATE_MAC",
                params=params,
            )
            remote_act.submit_remote_act(self, parent_cbt)
            self.free_cbt(cbt)

    def get_tap_name(self, peer_id, olid):
        tap_name_prefix = self.config["Overlays"][olid].get("TapNamePrefix", "")
        end_i = self.TAPNAME_MAXLEN - len(tap_name_prefix)
        tap_name = tap_name_prefix + str(peer_id[:end_i])
        return tap_name
