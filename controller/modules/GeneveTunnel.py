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

from pyroute2 import IPRoute
from pyroute2 import NDB
from framework.Modlib import RemoteAction
from framework.ControllerModule import ControllerModule
from .Tunnel import TunnelEvents, TunnelStates

class TunnelDescriptor():
    _REFLECT = set(
        ["tunnel_id", "overlay_id", "peer_id", "state"])

    def __init__(self, tunnel_id, overlay_id, peer_id, tunnel_state):
        self.tunnel_id = tunnel_id
        self.overlay_id = overlay_id
        self.peer_id = peer_id
        self.state = tunnel_state
    
    def __repr__(self):
        items = set()
        for k in TunnelDescriptor._REFLECT:
            items.add(f"\"{k}\": {self.__dict__[k]!r}")
        return "{{{}}}".format(", ".join(items))

class GeneveTunnel(ControllerModule):
    TAPNAME_MAXLEN = 15
    _REFLECT = set(["_peers", "_tunnels"])

    def __init__(self, cfx_handle, module_config, module_name):
        super(GeneveTunnel, self).__init__(
            cfx_handle, module_config, module_name)
        self.ipr = IPRoute()
        self.ndb = NDB()
        self._peers = {}        
        self._tunnels = {} # overlay id tunnel id  
        self._gnv_updates_publisher = None
    
    def __repr__(self):
        items = set()
        for k in GeneveTunnel._REFLECT:
            items.add(f"\"{k}\": {self.__dict__[k]!r}")
        return "{{{}}}".format(", ".join(items))

    def initialize(self):
        for olid in self.config["Overlays"]:
            self._peers[olid] = dict()

        self._gnv_updates_publisher = \
            self.publish_subscription("GNV_TUNNEL_EVENTS")
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
                # node B accepts data from node A, complete cbt with endpoint data, create tunnel on node B
                self.req_handler_exchnge_endpt(cbt)
            else:
                self.req_handler_default(cbt)
        elif cbt.op_type == "Response":
            if cbt.request.action == "SIG_REMOTE_ACTION":
                # response - call create tunnel command on node A
                self.resp_handler_remote_action(cbt) # extracts fields from rem action
            else:    
                parent_cbt = cbt.parent
                cbt_data = cbt.response.data
                cbt_status = cbt.response.status
                if (parent_cbt is not None and parent_cbt.child_count == 1):
                    parent_cbt.set_response(cbt_data, cbt_status)
                    self.complete_cbt(parent_cbt)

    def timer_method(self):
        pass

    def terminate(self):
        pass

    def _create_geneve_tunnel(self, tap_name, vnid, remote_addr):
        try:
            self.logger.info(f"Creating Geneve tunnel {tap_name} vnid={vnid}, remote addr={remote_addr}")
            self.ipr.link("add",
                        ifname=tap_name,
                        kind="geneve",
                        geneve_id=vnid,
                        geneve_remote=remote_addr)
        except Exception as e:
            self.logger.warning("Failed to create Geneve tunnel %s, error code: %s",
                                tap_name, str(e))

    def _remove_geneve_tunnel(self, tap_name):
        try:        
            self.logger.info(f"Removing Geneve tunnel {tap_name}")
            self.ipr.link("del", index=self.ipr.link_lookup(ifname=tap_name)[0])
        except Exception as e:
            self.logger.warning("Failed to remove geneve tunnel %s, error code: %s",
                                tap_name, str(e))
      
    def _is_tunnel_exist(self, tap_name):
        idx = self.ipr.link_lookup(ifname=tap_name)
        if len(idx)==1:
            return True
        return False

    def _is_tunnel_authorized(self, tunnel_id):
        tun = self._tunnels.get(tunnel_id)
        if tun is not None and tun.state in (TunnelStates.AUTHORIZED, TunnelStates.ONLINE, TunnelStates.OFFLINE):
            return True
        return False
    
    def _is_tunnel_connected(self, tap_name):
        # get link info of our tunnel, parse it to extract data
        eth = self.ipr.link("get", index=self.ipr.link_lookup(ifname=tap_name)[0])
        state = eth[0]['state']
        

    def req_handler_auth_tunnel(self, cbt):
        olid = cbt.request.params["OverlayId"]
        peer_id = cbt.request.params["PeerId"]
        tnlid = cbt.request.params["TunnelId"]
        if peer_id in self._peers[olid] or self._is_tunnel_authorized(tnlid):
            cbt.set_response("Geneve tunnel authorization failed, resource already exist for peer:tunnel {0}:{1}"
                             .format(peer_id, tnlid[:7]), False)
        else:
            self._tunnels[tnlid] = TunnelDescriptor(tnlid, olid, peer_id,
                                                    TunnelStates.AUTHORIZED)
            self._peers[olid][peer_id] = tnlid
            self.logger.debug("TunnelId:%s authorization for Peer:%s completed",
                              tnlid[:7], peer_id[:7])
            cbt.set_response(
                f"Geneve tunnel authorization completed, TunnelId:{tnlid[:7]}", True)
            event_param = {"UpdateType": TunnelEvents.Authorized, "OverlayId": olid,
                           "PeerId": peer_id, "TunnelId": tnlid}
            self._gnv_updates_publisher.post_update(event_param)
        self.complete_cbt(cbt)

    def req_handler_create_tunnel(self, cbt):
        """Role A"""
        olid = cbt.request.params["OverlayId"]
        tnlid = cbt.request.params["TunnelId"]
        loc_id = cbt.request.params["VNId"]
        peer_id = cbt.request.params["PeerId"]
        tap_name = self.get_tap_name(peer_id, olid)

        # if not self._is_tunnel_authorized(tunnel_id):
        #     cbt.set_response(data=f"Tunnel {tunnel_id} not authorized", status=False)
        #     self.complete_cbt(cbt)
        if tnlid in self._tunnels or self._is_tunnel_exist(tap_name):
            cbt.set_response(
                data=f"Tunnel {tnlid} already exists", status=False)
            self.complete_cbt(cbt)
        else:
            self._tunnels[tnlid] = TunnelDescriptor(tnlid, olid, peer_id,
                                                    TunnelStates.AUTHORIZED)
            params = {
                    "OverlayId": olid, 
                    "NodeId": self.node_id,
                    "TunnelId": tnlid, 
                    "VNId": loc_id,
                    "EndPointAddress": self.config["Overlays"][olid]["EndPointAddress"]
                }
            remote_act = RemoteAction(overlay_id=olid,
                                    recipient_id=peer_id,
                                    recipient_cm="GeneveTunnel",
                                    action="GNV_EXCHANGE_ENDPT",
                                    params=params)
            # Send the message via SIG server to peer
            remote_act.submit_remote_act(self, cbt)

    def req_handler_exchnge_endpt(self, cbt):
        """Role B"""
        params = cbt.request.params
        olid = params["OverlayId"]
        tnlid = params["TunnelId"]
        vnid = params["VNId"]
        peer_id = params["NodeId"]
        endpnt_address = params["EndPointAddress"]
        if olid not in self.config["Overlays"]:
            self.logger.warning("The requested overlay is not specified in "
                             "local config, it will not be created")
            cbt.set_response(
                "Unknown overlay id specified in request", False)
            self.complete_cbt(cbt)
            return
        if not self._is_tunnel_authorized(tnlid):
            msg = str("The requested link endpoint was not authorized. It will not be created. "
            "TunnelId={0}, PeerId={1}, VNID={2}".format(tnlid, peer_id, vnid))
            self.logger.warning(msg)
            cbt.set_response(msg, False)
            self.complete_cbt(cbt)
            return
        if vnid is None:
            msg = str("The VNID is NULL. Tunnel cannot be created. "
            "TunnelId={0}, PeerId={1}".format(tnlid, peer_id))
            self.logger.warning(msg)
            cbt.set_response(msg, False)
            self.complete_cbt(cbt)
            return
        # publish notification of link creation initiated
        event_param = {
            "UpdateType": TunnelEvents.Creating, "OverlayId": olid, "PeerId": peer_id,
            "TunnelId": tnlid}
        self._gnv_updates_publisher.post_update(event_param)
        # Send request to create tunnel
        try:
            tap_name = self.get_tap_name(peer_id, olid)
            self._create_geneve_tunnel(tap_name, vnid, endpnt_address)
            self.logger.info("Inside req_handler_exchnge_endpt")
            self._is_tunnel_connected(tap_name)
            msg = {"EndPointAddress": self.config["Overlays"][olid]["EndPointAddress"],
                   "VNId": vnid, "NodeId": self.node_id}
            cbt.set_response(msg, True)
            self.complete_cbt(cbt)
            event_param = {"UpdateType": TunnelEvents.Created, "OverlayId": olid,
                "PeerId": peer_id, "TunnelId": tnlid,
                "TapName": self.get_tap_name(peer_id, olid)}
            self._gnv_updates_publisher.post_update(event_param)
            # to be triggered when tunnel is connected
            # gnv_param = {
            #             "UpdateType": "LnkEvConnected", "OverlayId": olid, "PeerId": peer_id,
            #             "TunnelId": tnlid, "ConnectedTimestamp": lts,
            #             "TapName": self._tunnels[tnlid].tap_name,
            #             "MAC": self._tunnels[tnlid].mac,
            #             "PeerMac": self._tunnels[tnlid].peer_mac}
            # self._gnv_updates_publisher.post_update(gnv_param)
        except Exception as e:
            msg = str("Creation of geneve tunnel failed. Error={0}".format(e))
            self.logger.warning(msg)
            cbt.set_response(msg, False)
        self.submit_cbt(cbt)

    def req_handler_remove_tunnel(self, cbt):
        peer_id = cbt.request.params["PeerId"]
        olid = cbt.request.params["OverlayId"]
        tnlid = cbt.request.params["TunnelId"]
        tap_name = self.get_tap_name(peer_id, olid)
 
        if self._is_tunnel_exist(tap_name):
            self._remove_geneve_tunnel(tap_name)
            gnv_param = {
                "UpdateType": TunnelEvents.Removed, "OverlayId": olid, "PeerId": peer_id,
                "TunnelId": tnlid}
            self._gnv_updates_publisher.post_update(gnv_param)            
            cbt.set_response(
                data=f"Tunnel {tap_name} deleted", status=True)
            self.complete_cbt(cbt)
        else:
            cbt.set_response(
                data=f"Tunnel {tap_name} does not exists", status=False)

    def resp_handler_remote_action(self, cbt):
        parent_cbt = cbt.parent
        resp_data = cbt.response.data
        if not cbt.response.status:
            self.free_cbt(cbt)
            parent_cbt.set_response(resp_data, False)
            self.complete_cbt(parent_cbt)
        else:
            rem_act = RemoteAction.response(cbt)
            
            if rem_act.action == "GNV_EXCHANGE_ENDPT":
                olid = rem_act.overlay_id
                peer_id = rem_act.data["NodeId"]
                tnlid = cbt.request.params["TunnelId"]
                vnid = rem_act.data["VNId"]
                endpnt_address = rem_act.data["EndPointAddress"]
                tap_name = self.get_tap_name(peer_id, olid)
                if vnid is None:
                    msg = str("The VNID is NULL. Tunnel cannot be created. "
                    "TunnelId={0}, PeerId={1}".format(tnlid, peer_id))
                    self.logger.warning(msg)
                    parent_cbt.set_response(msg, False)
                    self.complete_cbt(parent_cbt)
                    return
                self._create_geneve_tunnel(tap_name, vnid, endpnt_address)
                self.logger.info("Inside resp_handler_remote_action")
                self._is_tunnel_connected(tap_name)
                self.free_cbt(cbt)
                parent_cbt.set_response("Geneve tunnel created", True)
                self.complete_cbt(parent_cbt)

    def get_tap_name(self, peer_id, olid):
        tap_name_prefix = self.config["Overlays"][olid].get(
            "TapNamePrefix", "")
        end_i = self.TAPNAME_MAXLEN - len(tap_name_prefix)
        tap_name = tap_name_prefix + str(peer_id[:end_i])
        return tap_name
