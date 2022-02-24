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

class TunnelSelector():

    def __init__(self, top_man, overlay_id, node_id, loc_id, req_encr):
        self._top = top_man
        self._overlay_id = overlay_id
        self._node_id = node_id
        self._loc_id = loc_id
        self._req_encr = req_encr
        self._tunnels = {} # Maps tunnel_id to 'type', 'state', and 'time'

    def authorize_tunnel(self, peer_id, tunnel_id, peer_loc_id):
        if self._loc_id is not None and self._loc_id == peer_loc_id:
            params = {"OverlayId": self._overlay_id, "PeerId": peer_id, "TunnelId": tunnel_id, "LocationId": peer_loc_id}
            self.logger.info("Sending request for GENEVE tunnel authorization ...")
            self._tunnels[tunnel_id] = {'type': 'GENEVE', 'state': 'authorized', 'time': time.time()}
            self._top.register_cbt("GeneveTunnel", "GNV_AUTH_TUNNEL", params)
        else:
            params = {"OverlayId": self._overlay_id, "PeerId": peer_id, "TunnelId": tunnel_id}
            self.logger.info("Sending request for Tincan tunnel authorization ...")
            self._tunnels[tunnel_id] = {'type': 'Tincan', 'state': 'authorized', 'time': time.time()}
            self._top.register_cbt("LinkManager", "LNK_AUTH_TUNNEL", params)

    def expire_authorized_tunnel(self, peer_id, tunnel_id):
        self.logger.info("Expiring tunnel authorization ...")
        del self._tunnels[tunnel_id]

    def create_tunnel(self, peer_id, tunnel_id):
        params = {"OverlayId": self._overlay_id, "PeerId": peer_id, "TunnelId": tunnel_id}
        if self._tunnels[tunnel_id]['state'] == 'authorized':
            current_time = time.time()
            if current_time - self._tunnels[tunnel_id]['time'] < 180:
                if self._tunnels[tunnel_id]['type'] == "GENEVE":
                    self.logger.info("Sending request for GENEVE tunnel creation ...")
                    self._tunnels[tunnel_id] = {'state': 'created', 'time': time.time()}
                    self._top.register_cbt("GeneveTunnel", "GNV_CREATE_TUNNEL", params)
                else:
                    self.logger.info("Sending request for Tincan tunnel creation ...")
                    self._tunnels[tunnel_id] = {'state': 'created', 'time': time.time()}
                    self._top.register_cbt("LinkManager", "LNK_CREATE_TUNNEL", params)
            else:
                self.logger.warning("Tunnel authorization already expired")
                del self._tunnels[tunnel_id]
        else:
            self.logger.warning("Tunnel to create is not authorized")

    def remove_tunnel(self, peer_id, tunnel_id):
        params = {"OverlayId": self._overlay_id, "PeerId": peer_id, "TunnelId": tunnel_id}
        if self._tunnels[tunnel_id]['state'] == 'created':
            if self._tunnels[tunnel_id]['type'] == "GENEVE":
                self.logger.info("Sending request for GENEVE tunnel removal ...")
                self._top.register_cbt("GeneveTunnel", "GNV_REMOVE_TUNNEL", params)
            else:
                self.logger.info("Sending request for Tincan tunnel removal ...")
                self._top.register_cbt("LinkManager", "LNK_REMOVE_TUNNEL", params)
            del self._tunnels[tunnel_id]
            self.logger.info("Tunnel removed from journal")
        else:
            self.logger.warning("Tunnel to remove does not exist")
