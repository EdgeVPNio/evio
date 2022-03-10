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
from framework.ControllerModule import ControllerModule
from pyroute2 import IPRoute
from pyroute2 import NDB

GnvTunnelStates = types.SimpleNamespace(GNV_AUTHORIZED="GNV_AUTHORIZED",
                                     GNV_CREATING="GNV_CREATING",
                                     GNV_QUERYING="GNV_QUERYING",
                                     GNV_ONLINE="GNV_ONLINE",
                                     GNV_OFFLINE="GNV_OFFLINE")

class TunnelDescriptor():
    def __init__(self, tunnel_id, overlay_id, peer_id):
        self.tunnel_id = tunnel_id
        self.overlay_id = overlay_id
        self.peer_id = peer_id
        self.state = GnvTunnelStates.GNV_CREATING
    
    def __repr__(self): 
        return "TunnelDescriptor<:tunnel_id=% s, overlay_id=% s, peer_id=% s state=% s>" % (
            self.tunnel_id, self.overlay_id, self.peer_id, self.state) 

class GeneveTunnel(ControllerModule):

    def __init__(self, cfx_handle, module_config, module_name):
        super(GeneveTunnel, self).__init__(
            cfx_handle, module_config, module_name)
        self.ipr = IPRoute()
        self.ndb = NDB()
        self._tunnels = {}   # maps tunnel id to its descriptor
        self._auth_tunnels = {} # overlay id tunnel id  
    
    def initialize(self):
        self.logger.info("Module loaded")

    def process_cbt(self, cbt):
        if cbt.op_type == "Request":
            if cbt.request.action == "GNV_CREATE_TUNNEL":
                self.req_handler_create_tunnel(cbt)
            elif cbt.request.action == "GNV_REMOVE_TUNNEL":
                self.req_handler_remove_tunnel(cbt)
            else:
                self.req_handler_default(cbt)
        elif cbt.op_type == "Response":
            parent_cbt = cbt.parent
            cbt_data = cbt.response.data
            cbt_status = cbt.response.status
            self.free_cbt(cbt)
            if (parent_cbt is not None and parent_cbt.child_count == 1):
                parent_cbt.set_response(cbt_data, cbt_status)
                self.complete_cbt(parent_cbt)

    def timer_method(self):
        self.register_cbt("Topology", "GNV_CREATE_TUNNEL", None)

    def terminate(self):
        pass

    def _create_geneve_tunnel(self, dev_name, id, remote_addr, dst_port=None):
        try:            
            self.ipr.link("add",
                        ifname=dev_name,
                        kind="geneve",
                        geneve_id=id,
                        geneve_remote=remote_addr)
        except Exception as e:
            self.log("LOG_INFO", "Error creating tunnel. Reported error: %s", str(e))

    def _remove_geneve_tunnel(self, dev_name):
        try:        
            self.ipr.link("del", index=self.ipr.link_lookup(ifname=dev_name)[0])
        except Exception as e:
            self.log("LOG_INFO", "Error deleting tunnel. Reported error: %s", str(e))
      
    def _is_tunnel_exist(self, dev_name):
        idx = self.ipr.link_lookup(ifname=dev_name)
        if len(idx)==1:
            return True
        return False

    def _is_tunnel_authorized(self, tunnel_id):
        tun = self._auth_tunnels.get(tunnel_id)
        if tun is not None and tun.state == GnvTunnelStates.GNV_AUTHORIZED:
            return True
        return False

    def req_handler_auth_tunnel(self, cbt):
        olid = cbt.request.params["OverlayId"]
        peer_id = cbt.request.params["PeerId"]
        tnlid = cbt.request.params["TunnelId"]
        if not self._is_tunnel_authorized(tnlid):
            self._auth_tunnels[tnlid] = TunnelDescriptor(tnlid, olid, peer_id)
            self._auth_tunnels[tnlid].state = GnvTunnelStates.GNV_AUTHORIZED
            cbt.set_response(None, True)
        else:
            cbt.set_response("Geneve tunnel auth failed, resource already exist for peer:tunnel {0}:{1}"
                             .format(peer_id, tnlid[:7]), False)
            self.free_cbt(cbt)
        self.complete_cbt(cbt)

    def req_handler_create_tunnel(self, cbt):
        tunnel_id = cbt.request.params["TunnelId"]
        remote_addr = cbt.request.params["RemoteAddr"]
        dst_port = cbt.request.params["DstPort"]
        dev_name = cbt.request.params["DeviceName"]
        location_id = cbt.request.params["LocationId"]
        if not self._is_tunnel_authorized(tunnel_id):
            cbt.set_response(data=f"Tunnel {dev_name} not authorized", status=False)
        if not self._is_tunnel_exist(dev_name):
            self._create_geneve_tunnel(
                dev_name, location_id, remote_addr, dst_port)
            cbt.set_response(
                data=f"Tunnel {dev_name} created", status=True)
        else:
            cbt.set_response(
                data=f"Tunnel {dev_name} already exists", status=False)
        self.complete_cbt(cbt)

    def req_handler_remove_tunnel(self, cbt):
        dev_name = cbt.request.params["DeviceName"]
        if self._is_tunnel_exist(dev_name):
            self._remove_geneve_tunnel(dev_name)
            cbt.set_response(
                data=f"Tunnel {dev_name} deleted", status=True)
        else:
            cbt.set_response(
                data=f"Tunnel {dev_name} does not exists", status=False)
        self.free_cbt(cbt)
