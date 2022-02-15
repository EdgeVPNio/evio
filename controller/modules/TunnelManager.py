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
import framework.Modlib as Modlib
from distutils import spawn
from socket import AF_INET
from pyroute2 import IPRoute
from pyroute2 import NDB

TunnelStates = types.SimpleNamespace(TNL_AUTHORIZED="TNL_AUTHORIZED",
                                     TNL_CREATING="TNL_CREATING",
                                     TNL_QUERYING="TNL_QUERYING",
                                     TNL_ONLINE="TNL_ONLINE",
                                     TNL_OFFLINE="TNL_OFFLINE")

TunnelEvents =types.SimpleNamespace(TnlEvAuthorized="TnlEvAuthorized",
                                    TnlEvDeauthorized="TnlEvDeauthorized",
                                    TnlEvCreating="TnlEvCreating",
                                    TnlEvCreated="TnlEvCreated",
                                    TnlEvConnected="TnlEvConnected",
                                    TnlEvDisconnected="TnlEvDisconnected",
                                    TnlEvRemoved="TnlEvRemoved")
class Tunnel():
    def __init__(self, tnlid, overlay_id, peer_id, tnl_state, state_timeout):
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

    def __repr__(self):
        items = (f"\"{k}\": {v!r}" for k, v in self.__dict__.items())
        return "{{{}}}".format(", ".join(items))

    @property
    def tunnel_state(self):
        return self._tunnel_state

    @tunnel_state.setter
    def tunnel_state(self, new_state):
        "todo: implement transition checks"
        self._tunnel_state = new_state


class TunnelManager(ControllerModule):

    def __init__(self, cfx_handle, module_config, module_name):
        super(TunnelManager, self).__init__(cfx_handle, module_config, module_name)
        self.ipr = IPRoute()
        self.ndb = NDB()
        self._peers = {}     # maps overlay id to peers map, which maps peer id to tunnel id
        self._tunnels = {}   # maps tunnel id to its descriptor
        self._tnl_updates_publisher = None

    def initialize(self):
        self._tnl_updates_publisher = \
            self._cfx_handle.publish_subscription("TNL_TUNNEL_EVENTS")
        for olid in self.config["Overlays"]:
            self._peers[olid] = dict()

    def req_handler_create_tunnel(self, cbt):
        """
        invoked by TOP, cbt contains the remote's LANID and encryption flag if it exists.
        inspect the LAN ID and tunnel encryption parameters to determine the type of tunnel to
        be created. Issue create tunnel request to the appropriate tunnel class.
        """
        lanid = cbt.request.params.get("LANID", None)
        encrypt = cbt.request.params.get("RequireEncryption", None)
        is_same_lan = False
        if lanid is not None:
            for olid in self.config["Overlays"]:
                if self.config["Overlays"][olid].get("LANID", None) == lanid:
                    is_same_lan = True
                    if encrypt is None:
                        cbt.set_response("GENEVE tunnel in order", True)
                        create_geneve_tunnel(self, cbt)
                    else:
                        cbt.set_response("WireGuard tunnel in order", True)
                        create_wireguard_tunnel(self, cbt)
                    pass
        if is_same_lan is False:
            cbt.set_response("Tincan tunnel in order", True)
            create_tincan_tunnel(self, cbt)
        return

    def req_handler_remove_tunnel(self, cbt):
        dev_name = cbt.request.params["DeviceName"]
        self._del_tunnel(dev_name)
        cbt.response.set_response(data=f"Tunnel {dev_name} deleted", status=True)

    def req_handler_auth_tunnel(self, cbt):
        """Node B"""
        olid = cbt.request.params["OverlayId"]
        peer_id = cbt.request.params["PeerId"]
        tnlid = cbt.request.params["TunnelId"]
        self._peers[olid][peer_id] = tnlid
        self._tunnels[tnlid] = Tunnel(tnlid, olid, peer_id,
                                        tnl_state=TunnelStates.TNL_AUTHORIZED,
                                        state_timeout=120)
        self.log("LOG_DEBUG", "TunnelId:%s auth for Peer:%s completed",
                            tnlid[:7], peer_id[:7])
        cbt.set_response(
            f"TunnelId:{tnlid[:7]} authorized", True)
        tnl_upd_param = {
            "UpdateType": TunnelEvents.TnlEvAuthorized, "OverlayId": olid,
            "PeerId": peer_id, "TunnelId": tnlid}
        self._tnl_updates_publisher.post_update(tnl_upd_param)
        self.complete_cbt(cbt)

    def process_cbt(self, cbt):
        if cbt.op_type == "Request":
            if cbt.request.action == "TNL_CREATE_TUNNEL":
                self.req_handler_create_tunnel(cbt)
            elif cbt.request.action == "TNL_REMOVE_TUNNEL":
                self.req_handler_remove_tunnel(cbt)
            elif cbt.request.action == "TNL_AUTH_TUNNEL":
                self.req_handler_auth_tunnel(cbt)
            else:
                self.req_handler_default(cbt)
        elif cbt.op_type == "Response":
            self.free_cbt(cbt)

    def create_geneve_tunnel():
        raise NotImplementedError

    def create_wireguard_tunnel():
        raise NotImplementedError

    def create_tincan_tunnel():
        raise NotImplementedError
