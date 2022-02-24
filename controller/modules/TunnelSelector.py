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
        self.overlay_id = overlay_id
        self.prefix_len = prefix_len
        self.node_id = node_id
        self.loc_id = loc_id
        self.req_encr = req_encr
        #tunnel_type: Maps tunnel_id to tunnel_type, peer_tunnel: Maps peer_id to tunnel_id
        self.tunnels_authorized = {'tunnel_type': {}, 'peer_tunnel': {}}
        self.tunnels_created = {'tunnel_type': {}, 'peer_tunnel': {}}

    def authorize_tunnel(self, peer_id, tunnel_id, peer_loc_id):
        params = {"OverlayId": self.overlay_id, "PeerId": peer_id, "TunnelId": tunnel_id, "PeerLocId": peer_loc_id}
        if self.loc_id is not None and self.loc_id == peer_loc_id:
            self.logger.info("Sending request for GENEVE tunnel authorization ...")
            self.tunnels_authorized['peer_tunnel'][peer_id] = tunnel_id
            self.tunnels_authorized['tunnel_type'][tunnel_id] = "GENEVE"
            self._top.register_cbt("GeneveTunnel", "GNV_AUTH_TUNNEL", params)
        else:
            self.logger.info("Sending request for Tincan tunnel authorization ...")
            self.tunnels_authorized['peer_tunnel'][peer_id] = tunnel_id
            self.tunnels_authorized['tunnel_type'][tunnel_id] = "Tincan"
            self._top.register_cbt("LinkManager", "LNK_AUTH_TUNNEL", params)

    def expire_authorize_tunnel(self, peer_id, tunnel_id):
        self.logger.info("Expiring tunnel authorization ...")
        del self.tunnels_authorized['peer_tunnel'][peer_id]
        del self.tunnels_authorized['tunnel_type'][tunnel_id]

    def create_tunnel(self, peer_id, tunnel_id):
        params = {"OverlayId": self.overlay_id, "PeerId": peer_id, "TunnelId": tunnel_id}
        if self.tunnels_authorized['tunnel_type'][tunnel_id]:
            if self.tunnels_authorized['tunnel_type'][tunnel_id] == "GENEVE":
                self.logger.info("Sending request for GENEVE tunnel creation ...")
                self._top.register_cbt("GeneveTunnel", "GNV_CREATE_TUNNEL", params)
                self.tunnels_created['peer_tunnel'][peer_id] = tunnel_id
                self.tunnels_created['tunnel_type'][tunnel_id] = "GENEVE"
            else:
                self.logger.info("Sending request for Tincan tunnel creation ...")
                self._top.register_cbt("LinkManager", "LNK_CREATE_TUNNEL", params)
                self.tunnels_created['peer_tunnel'][peer_id] = tunnel_id
                self.tunnels_created['tunnel_type'][tunnel_id] = "Tincan"
            del self.tunnels_authorized['peer_tunnel'][peer_id]
            del self.tunnels_authorized['tunnel_type'][tunnel_id]
        else:
            self.logger.warning("Tunnel to create is not authorized")

    def remove_tunnel(self, peer_id):
        params = {"OverlayId": self.overlay_id, "PeerId": peer_id}
        tunnel_id = self.tunnels_created['peer_tunnel'][peer_id]
        if tunnel_id:
            if self.tunnels_created['tunnel_type'][tunnel_id] == "GENEVE":
                self.logger.info("Sending request for GENEVE tunnel removal ...")
                self._top.register_cbt("GeneveTunnel", "GNV_REMOVE_TUNNEL", params)
            else:
                self.logger.info("Sending request for Tincan tunnel removal ...")
                self._top.register_cbt("LinkManager", "LNK_REMOVE_TUNNEL", params)
            del self.tunnels_created['peer_tunnel'][peer_id]
            del self.tunnels_created['tunnel_type'][tunnel_id]
            self.logger.info("Tunnel removed from journal")
        else:
            self.logger.warning("Tunnel to remove does not exist")
