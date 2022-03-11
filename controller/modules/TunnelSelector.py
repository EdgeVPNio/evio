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
from .NetworkGraph import EdgeState, EdgeTypesIn, OpType, transpose_edge_type
from .NetworkGraph import ConnectionEdge, ConnEdgeAdjacenctList
from framework.Modlib import RemoteAction

EdgeRequest = namedtuple("EdgeRequest",
                         ["overlay_id", "edge_id", "edge_type", "initiator_id",
                          "recipient_id", "location_id", "capability"])
EdgeResponse = namedtuple("EdgeResponse", ["is_accepted", "data"])
EdgeNegotiate = namedtuple(
    "EdgeNegotiate", EdgeRequest._fields + EdgeResponse._fields)

SupportedTunnels = ["GENEVE", "TINCAN"]
'''
NOTES:
No need to track which tunnels are authorized. The NetworkBuilder already does.
'''


class TunnelSelector():
    _REFLECT = set(["_loc_id", "_encr_req", "_tunnels"])

    def __init__(self, top_man, overlay_id, node_id, loc_id, encr_req):
        self._top = top_man
        self._overlay_id = overlay_id
        self._node_id = node_id
        self._loc_id = loc_id
        self._encr_req = encr_req
        self._tunnels = {}  # Maps tunnel_id to 'type', 'state', and 'time'
        self.logger = top_man.logger

    def __repr__(self):
        items = set()
        for k in TunnelSelector._REFLECT:
            items.add(f"\"{k}\": {self.__dict__[k]!r}")
        return "{{{}}}".format(", ".join(items))

    @property
    def supported_tunnels(self) -> list:
        return SupportedTunnels

    def resolve_request_collision(self, edge_req, conn_edge):
        """ An connection edge was already initiated by this node so resolve the collision """
        peer_id = edge_req.initiator_id
        edge_state = conn_edge.edge_state
        edge_resp = None
        if edge_state in (EdgeState.Authorized, EdgeState.Created, EdgeState.Connected):
            # Likely a duplicated Remote Action from Signal
            if conn_edge.edge_id == edge_req.edge_id:
                msg = f"E1 - A valid edge already exists. TunnelId={self._adj_list[peer_id].edge_id[:7]}"
                edge_resp = EdgeResponse(is_accepted=False, data=msg)
                self.logger.debug(msg)
            else:
                self.logger.debug(
                    f"Collision on expired edge request: {edge_req}")
        elif edge_state == EdgeState.Initialized:
            edge_resp = EdgeResponse(
                is_accepted=True, data="Precollision edge permitted")
            del self._adj_list[peer_id]
        elif edge_state == EdgeState.PreAuth and self._node_id < edge_req.initiator_id:
            msg = f"E2 - Node {self._node_id} superceeds edge request due to collision, "
            "edge={self._adj_list[peer_id].edge_id[:7]}"
            edge_resp = EdgeResponse(is_accepted=False, data=msg)
            self.logger.debug(msg)
        elif edge_state == EdgeState.PreAuth and self._node_id > edge_req.initiator_id:
            conn_edge.edge_type = transpose_edge_type(edge_req.edge_type)
            conn_edge.edge_id = edge_req.edge_id
            msg = f"E0 - Node {self._node_id} accepts edge collision override."
            " CE:{conn_edge.edge_id[:7]} remapped -> edge:{edge_req.edge_id[:7]}"

            edge_resp = EdgeResponse(is_accepted=True, data=msg)
            self.logger.debug(msg)
        else:
            edge_resp = EdgeResponse(False, "E6 - Request colides with an edge being destroyed."
                                            "Try later")
        return edge_resp

    def negotiate_incoming_tunnel(self, edge_req):
        """ Role B1 """
        self.logger.debug(f"Rcvd EdgeRequest={edge_req}")
        edge_resp = None
        peer_id = edge_req.initiator_id
        if edge_req.edge_type == "CETypeSuccessor":
            edge_resp = EdgeResponse(
                is_accepted=True, data="Successor edge permitted")
        elif edge_req.edge_type == "CETypeStatic":
            edge_resp = EdgeResponse(
                is_accepted=True, data="Static edge permitted")
        elif edge_req.edge_type == "CETypeOnDemand":
            edge_resp = EdgeResponse(
                is_accepted=True, data="On-demand edge permitted")
        elif not self._adj_list.is_threshold(EdgeTypesIn.ILongDistance):
            edge_resp = EdgeResponse(
                is_accepted=True, data="Any edge permitted")
        else:
            edge_resp = EdgeResponse(is_accepted=False,
                                     data="E5 - Too many existing edges.")

        return edge_resp

    def authorize_incoming_tunnel(self, edge_req, parent_cbt):
        self.logger.info(f"Authorizing peer edge from {self._overlay_id}:{edge_req.initiator_id[:7]}->{self._node_id[:7]}")
        params = {"OverlayId": self._overlay_id,
                  "PeerId": edge_req.initiator_id, "TunnelId": edge_req.edge_id}
        cbt = self._top.create_linked_cbt(parent_cbt)
        # cbt.set_request(self._top.module_name, "LinkManager",
        #                 "LNK_AUTH_TUNNEL", params)
        tunnel_id = edge_req.edge_id
        if self._loc_id == edge_req.location_id and not self._encr_req and "GENEVE" in edge_req.capability and "GENEVE" in self.supported_tunnels:
            self.logger.info(f"Sending request for GENEVE tunnel {edge_req.edge_id} authorization ...")
            self._tunnels[tunnel_id] = {'type': 'GENEVE', 'state': 'authorized', 'time': time.time()}
            cbt.set_request(self._top.module_name, "GeneveTunnel",
                            "GNV_AUTH_TUNNEL", params)
            self._top.submit_cbt(cbt)
        elif "TINCAN" in edge_req.capability and "TINCAN" in self.supported_tunnels:
            self.logger.info(f"Sending request for Tincan tunnel {edge_req.edge_id} authorization ...")
            self._tunnels[tunnel_id] = {'type': 'TINCAN', 'state': 'authorized', 'time': time.time()}
            cbt.set_request(self._top.module_name, "LinkManager",
                            "LNK_AUTH_TUNNEL", params)
            self._top.submit_cbt(cbt)
        else:
            self.logger.warning(f"Warning in authorizing Tunnel: Tunnel {edge_req.edge_id} not supported")

    def expire_authorized_tunnel(self, peer_id, tunnel_id):
        self.logger.info("Expiring tunnel authorization ...")
        del self._tunnels[tunnel_id]

    def create_tunnel(self, peer_id, tunnel_id):
        params = {"OverlayId": self._overlay_id,
                  "PeerId": peer_id, "TunnelId": tunnel_id}
        # self._top.register_cbt("LinkManager", "LNK_CREATE_TUNNEL", params)
        if self._tunnels[tunnel_id]:
            if self._tunnels[tunnel_id]['type']:
                if self._tunnels[tunnel_id]['state'] == 'created':
                    self.logger.warning(f"Warning in creating Tunnel: Tunnel {self._tunnels[tunnel_id]} already registered as created in journal")
                else:
                    if self._tunnels[tunnel_id]['type'] == 'GENEVE':
                        self.logger.info(f"Sending request for GENEVE tunnel {self._tunnels[tunnel_id]} creation ...")
                        self._tunnels[tunnel_id] = {'state': 'created', 'time': time.time()}
                        self._top.register_cbt("GeneveTunnel", "GNV_CREATE_TUNNEL", params)
                    elif self._tunnels[tunnel_id]['type'] == 'TINCAN':
                        self.logger.info(f"Sending request for Tincan tunnel {self._tunnels[tunnel_id]} creation ...")
                        self._tunnels[tunnel_id] = {'state': 'created', 'time': time.time()}
                        self._top.register_cbt("LinkManager", "LNK_CREATE_TUNNEL", params)
                    else:
                        self.logger.warning(f"Warning in creating Tunnel: Tunnel type {self._tunnels[tunnel_id]['type']} not supported")
            else:
                self.logger.warning(f"Warning in creating Tunnel: Tunnel type {self._tunnels[tunnel_id]['type']} not registered in journal")
        else:
            self.logger.warning(f"Warning in creating Tunnel: Tunnel ID {self._tunnels[tunnel_id]} not registered in journal")

    def remove_tunnel(self, peer_id, tunnel_id):
        params = {"OverlayId": self._overlay_id,
                  "PeerId": peer_id, "TunnelId": tunnel_id}
        # self._top.register_cbt("LinkManager", "LNK_REMOVE_TUNNEL", params)
        if self._tunnels[tunnel_id]:
            if self._tunnels[tunnel_id]['state']:
                if self._tunnels[tunnel_id]['state'] == 'created':
                    if self._tunnels[tunnel_id]['type'] == 'GENEVE':
                        self.logger.info(f"Sending request for GENEVE tunnel {self._tunnels[tunnel_id]} removal ...")
                        self._top.register_cbt("GeneveTunnel", "GNV_REMOVE_TUNNEL", params)
                        del self._tunnels[tunnel_id]
                        self.logger.info(f"GENEVE Tunnel {self._tunnels[tunnel_id]} removed from journal")
                    elif self._tunnels[tunnel_id]['type'] == 'TINCAN':
                        self.logger.info(f"Sending request for Tincan tunnel {self._tunnels[tunnel_id]} removal ...")
                        self._top.register_cbt("LinkManager", "LNK_REMOVE_TUNNEL", params)
                        del self._tunnels[tunnel_id]
                        self.logger.info(f"Tincan Tunnel {self._tunnels[tunnel_id]} removed from journal")
                    else:
                        self.logger.warning(f"Warning in removing tunnel: Tunnel type {self._tunnels[tunnel_id]['type']} not supported")
                else:
                    self.logger.warning(f"Warning in removing tunnel: Tunnel {self._tunnels[tunnel_id]} not registered in journal")
            else:
                self.logger.warning(f"Warning in removing tunnel: Tunnel {self._tunnels[tunnel_id]} state not registered in journal")
        else:
            self.logger.warning(f"Warning in removing tunnel: Tunnel ID {self._tunnels[tunnel_id]} not registered in journal")

    def negotiate_outgoing_tunnel(self, edge_id, edge_type, peer_id):
        """ Role A1
        Begin the handshake to negotiate the creation on a new edge between the initiator
        Node A and the recipient Node B
        """
        er = EdgeRequest(overlay_id=self._overlay_id, edge_id=edge_id, edge_type=edge_type,
                         recipient_id=peer_id, initiator_id=self._node_id, location_id=self._loc_id,
                         capability=self.supported_tunnels)

        self.logger.debug(f"Requesting edge auth edge_req={er}")
        edge_params = er._asdict()
        rem_act = RemoteAction(self._overlay_id, recipient_id=er.recipient_id,
                               recipient_cm="Topology", action="TOP_NEGOTIATE_EDGE",
                               params=edge_params)
        rem_act.submit_remote_act(self._top)

    def complete_negotiate_outgoing_tunnel(self, edge_nego):
        pass


    def on_tunnel_event(self, event):
        pass
