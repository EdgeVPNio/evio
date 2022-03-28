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

import types
from framework.Modlib import RemoteAction
from framework.ControllerModule import ControllerModule
from pyroute2 import IPRoute
from pyroute2 import NDB

GnvTunnelStates = types.SimpleNamespace(GNV_AUTHORIZED="GNV_AUTHORIZED",
                                     GNV_CREATING="GNV_CREATING",
                                     GNV_QUERYING="GNV_QUERYING",
                                     GNV_ONLINE="GNV_ONLINE",
                                     GNV_OFFLINE="GNV_OFFLINE")

class TunnelDescriptor():
    _REFLECT = set(
        ["tunnel_id", "overlay_id", "peer_id", "state"])

    def __init__(self, tunnel_id, overlay_id, peer_id):
        self.tunnel_id = tunnel_id
        self.overlay_id = overlay_id
        self.peer_id = peer_id
        self.state = GnvTunnelStates.GNV_CREATING
    
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
        self._peers = None        
        self._tunnels = None# overlay id tunnel id  
        self._gnv_updates_publisher = None
    
    def __repr__(self):
        items = set()
        for k in GeneveTunnel._REFLECT:
            items.add(f"\"{k}\": {self.__dict__[k]!r}")
        return "{{{}}}".format(", ".join(items))

    def initialize(self):
        self._peers = {}
        self._tunnels = {} # overlay id tunnel id  
        self._link_updates_publisher = \
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
            # TODO: check option for port
            self.ipr.link("add",
                        ifname=tap_name,
                        kind="geneve",
                        geneve_id=vnid,
                        geneve_remote=remote_addr)
        except Exception as e:
            self.log("LOG_INFO", "Error creating tunnel. Reported error: %s", str(e))

    def _remove_geneve_tunnel(self, tap_name):
        try:        
            self.ipr.link("del", index=self.ipr.link_lookup(ifname=tap_name)[0])
        except Exception as e:
            self.log("LOG_INFO", "Error deleting tunnel. Reported error: %s", str(e))
      
    def _is_tunnel_exist(self, tap_name):
        idx = self.ipr.link_lookup(ifname=tap_name)
        if len(idx)==1:
            return True
        return False

    def _is_tunnel_authorized(self, tunnel_id):
        tun = self._tunnels.get(tunnel_id)
        if tun is not None and tun.state in [GnvTunnelStates.GNV_AUTHORIZED, GnvTunnelStates.GNV_QUERYING, 
                    GnvTunnelStates.GNV_ONLINE]:
            return True
        return False

    def req_handler_auth_tunnel(self, cbt):
        olid = cbt.request.params["OverlayId"]
        peer_id = cbt.request.params["PeerId"]
        tnlid = cbt.request.params["TunnelId"]
        if peer_id in self._peers[olid] or self._is_tunnel_authorized(tnlid):
            cbt.set_response("Geneve tunnel auth failed, resource already exist for peer:tunnel {0}:{1}"
                             .format(peer_id, tnlid[:7]), False)
        else:
            self._tunnels[tnlid] = TunnelDescriptor(tnlid, olid, peer_id)
            self._tunnels[tnlid].state = GnvTunnelStates.GNV_AUTHORIZED
            self._peers[olid][peer_id] = tnlid
            self.log("LOG_DEBUG", "TunnelId:%s auth for Peer:%s completed",
                     tnlid[:7], peer_id[:7])
            cbt.set_response(
                "Geneve tunnel auth completed, TunnelId:{0}".format(tnlid[:7]), True)
        self.complete_cbt(cbt)

    def req_handler_create_tunnel(self, cbt):
        olid = cbt.request.params["OverlayId"]
        tunnel_id = cbt.request.params["TunnelId"]
        location_id = cbt.request.params["LocationId"]
        peer_id = cbt.request.params["PeerId"]
        
        tap_name = self.getTapName(peer_id, olid)

        if not self._is_tunnel_authorized(tunnel_id):
            cbt.set_response(data=f"Tunnel {tap_name} not authorized", status=False)
        if not self._is_tunnel_exist(tap_name):
            params = {
                "OverlayId": olid, 
                "PeerId": peer_id,
                "TunnelId": tunnel_id, 
                "LocationId": location_id,
                "EndPointAddress": self.config["Overlays"][olid]["EndPointAddress"],
                "TapNamePrefix": tap_name_prefix
            }
            remote_act = dict(OverlayId=olid,
                                  RecipientId=peer_id,
                                  RecipientCM="GeneveTunnel",
                                  Action="GNV_EXCHANGE_ENDPT",
                                  Params=params)
            # Send the message via SIG server to peer
            endp_cbt = self.create_linked_cbt(cbt)
            endp_cbt.set_request(self.module_name, "Signal",
                                 "SIG_REMOTE_ACTION", remote_act)
            self.submit_cbt(endp_cbt)
        else:
            cbt.set_response(
                data=f"Tunnel {tap_name} already exists", status=False)
        self.complete_cbt(cbt)

    def req_handler_exchnge_endpt(self, cbt):
        params = cbt.request.params
        olid = params["OverlayId"]
        tnlid = params["TunnelId"]
        locid = params["LocationId"]
        peerid = params["PeerId"]
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
            "TunnelId={0}, PeerId={1}, LocationId={2}".format(tnlid, peerid, locid))
            self.logger.warning(msg)
            cbt.set_response(msg, False)
            self.complete_cbt(cbt)
            return
        # TODO: query pyroute for tunnel states, read docs
        self._tunnels[tnlid].state = GnvTunnelStates.GNV_CREATING
        # publish notification of link creation initiated Node B
        gnv_param = {
            "UpdateType": "GnvTnlCreating", "OverlayId": olid, "PeerId": peerid,
            "TunnelId": tnlid, "LocationId": locid}
        self._gnv_updates_publisher.post_update(gnv_param) 
        # Send request to create tunnel
        try:
            tap_name = self.getTapName(peerid, olid)
            vnid = locid
            self._create_geneve_tunnel(tap_name, vnid, endpnt_address)
            msg = self.config["Overlays"][olid]["EndPointAddress"]
            cbt.set_response(msg, True)
            self.complete_cbt(cbt)
        except Exception as e:
            msg = str("Creation of geneve tunnel failed. Error={0}".format(e))
            self.logger.warning(msg)
            cbt.set_response(msg, False)
            self.complete_cbt(cbt)
            return
        self.submit_cbt(cbt)

    def req_handler_remove_tunnel(self, cbt):
        peer_id = cbt.request.params["PeerId"]
        olid = cbt.request.params["OverlayId"]
        tap_name = self.getTapName(peer_id, olid)
 
        if self._is_tunnel_exist(tap_name):
            self._remove_geneve_tunnel(tap_name)
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
            rem_act = cbt.response.data
            peer_id = cbt.request.params["PeerId"]
            olid = cbt.request.params["OverlayId"]
            endpnt_address = rem_act["Data"]["EndPointAddress"]
            vnid = cbt.request.params["LocationId"]

            tap_name = self.getTapName(peer_id, olid)
            
            if rem_act["Action"] == "GNV_EXCHANGE_ENDPT":
                self._create_geneve_tunnel(tap_name, vnid, endpnt_address)
                self.free_cbt(cbt)
                msg = "Geneve tunnel created"
                parent_cbt.set_response(msg, True)
                self.complete_cbt(parent_cbt)

    def getTapName(self, peer_id, olid):
        tap_name_prefix = self.config["Overlays"][olid].get(
            "TapNamePrefix", "")
        end_i = self.TAPNAME_MAXLEN - len(tap_name_prefix)
        tap_name = tap_name_prefix + str(peer_id[:end_i])
        return tap_name
