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
from copy import deepcopy
from collections import namedtuple
from .NetworkGraph import ConnectionEdge, ConnEdgeAdjacenctList
from .NetworkGraph import EdgeState, EdgeTypesOut, OpType, transpose_edge_type


"""
CE enters the nego list with state CEStatePreAuth
Successful auth updates the state to CEStateAuthorized and removes it from nego list
"""

ConcurrencyLevel = 1


class NetworkBuilder():
    _DEL_RETRY_INTERVAL = 10
    _EDGE_PROTECTION_AGE = 180
    _REFLECT = set(
        ["_adj_list", "_net_transitions"])  # , "_negotiated_edges"])

    def __init__(self, top_man, overlay_id, node_id, tunnel_selector):
        self._adj_list = ConnEdgeAdjacenctList(overlay_id, node_id)
        self._net_transitions = None
        self._top = top_man
        self._tun_man = tunnel_selector
        self._concurrency_level = ConcurrencyLevel
        self.logger = top_man.logger

    def __repr__(self):
        items = set()
        for k in NetworkBuilder._REFLECT:
            items.add(f"\"{k}\": {self.__dict__[k]!r}")
        return "{{{}}}".format(", ".join(items))

    @property
    def is_ready(self):
        """
        Is the NetworkBuilder ready for a new NetGraph? This means all the network 
        transition operations have been completed.
        """
        return not bool(self._net_transitions)

    def get_adj_list(self):
        return deepcopy(self._adj_list)

    def refresh(self, net_transitions=None):
        """
        Transitions the overlay network overlay to the desired state specified by network transition ops.
        """
        self.logger.debug("New network transitions: %s", str(net_transitions))
        assert ((self.is_ready and net_transitions != None) or
                (not self.is_ready and net_transitions == None)),\
            "Netbuilder is not ready for a new net graph"

        if net_transitions and self.is_ready:
            self._net_transitions = net_transitions
            self._adj_list.min_successors = net_transitions.min_successors
            self._adj_list.max_ldl = net_transitions.max_ldl
            self._adj_list.max_ond = net_transitions.max_ondemand
        self._process_net_transitions()

    def _process_net_transitions(self):
        counter = 0
        while self._net_transitions:
            update_initiated = True
            update = self._net_transitions.head()
            if update.operation == OpType.Add:
                update_initiated = self._initiate_negotiate_edge(
                    update.conn_edge)
            elif update.operation == OpType.Remove:
                update_initiated = self._initiate_remove_edge(update.conn_edge)
            elif update.operation == OpType.Update:
                update_initiated = self._update_edge_properties(
                    update.conn_edge)
            if update_initiated:
                self._net_transitions.pop()
            counter += 1
            if counter >= self._concurrency_level:
                # or self._net_transitions.is_priority_change:
                return

    def _update_edge_properties(self, new_conn_edge):
        self._adj_list.update_edge_type(new_conn_edge)
        return True

    def _initiate_negotiate_edge(self, ce):
        if ce.peer_id not in self._adj_list:
            ce.edge_state = EdgeState.PreAuth
            self._adj_list[ce.peer_id] = ce
            self._tun_man.negotiate_outgoing_tunnel(
                ce.edge_id, ce.edge_type, ce.peer_id)
            return True

    def _all_successors_connected(self):
        sl = self._adj_list.select_edges(
            [("CETypeSuccessor", EdgeState.Connected)])
        return len(sl) >= self._adj_list.min_successors

    def _initiate_remove_edge(self, conn_edge):
        if conn_edge.edge_state == EdgeState.Connected and \
                conn_edge.edge_type in [*EdgeTypesOut.__dict__.values()] and \
                time.time() - conn_edge.connected_time >= NetworkBuilder._EDGE_PROTECTION_AGE:
            conn_edge.marked_for_delete = True
            self.logger.debug(
                "Marked conn_edge for delete: %s", str(conn_edge))
            if conn_edge.edge_type == EdgeTypesOut.Successor and \
                    not self._all_successors_connected():
                return False
            conn_edge.edge_state = EdgeState.Deleting
            self._tun_man.remove_tunnel(conn_edge.peer_id, conn_edge.edge_id)
            return True

    def complete_negotiate_edge(self, edge_nego):
        """ Role A2 """
        self.logger.debug("Completing Edge Negotiation=%s", str(edge_nego))
        if edge_nego.recipient_id not in self._adj_list:
            # edge_nego.recipient_id not in self._negotiated_edges:
            self.logger.warning("The peer specified in edge negotiation %s is not in current adjacency "
                                " list. The request has been discarded.")
            return
        peer_id = edge_nego.recipient_id
        edge_id = edge_nego.edge_id
        ce = self._adj_list[edge_nego.recipient_id]
        if not edge_nego.is_accepted:
            # if E2 (request superceeded) do nothing here. The corresponding CE instance will
            # be converted in resolve_collision_request(). If E1, the request is outdate, just
            # discard.
            if not edge_nego.data[:2] in ("E1", "E2"):
                ce.edge_state = EdgeState.Deleting
                del self._adj_list[ce.peer_id]
        else:
            if ce.edge_state != EdgeState.PreAuth:
                self.logger.warning("The following EdgeNegotiate cannot be completed as the "
                                    "current state of it's conn edge is invalid for this "
                                    "operation. The request has been discarded. "
                                    "ce=%s, edge_nego=%s", ce, edge_nego)
                return
            if ce.edge_id != edge_nego.edge_id:
                self.logger.error("EdgeNego parameters does not match current "
                                  "adjacency list. The transaction has been discarded.")
                ce.edge_state = EdgeState.Deleting
                del self._adj_list[ce.peer_id]
                return
            ce.edge_state = EdgeState.Authorized
            self._tun_man.complete_negotiate_outgoing_tunnel(edge_nego)
            self._tun_man.create_tunnel(peer_id, edge_id)

    def negotiate_incoming_edge_request(self, edge_req, neg_edge_cbt):
        """ Role B1 
        If the request is accepted a new incoming conn_edge is addded to the adjacency
        list.
        """
        self.logger.debug("Rcvd EdgeRequest=%s", str(edge_req))
        edge_resp = None
        peer_id = edge_req.initiator_id
        if peer_id in self._adj_list:
            edge_resp = self._tun_man.resolve_request_collision(
                edge_req, self._adj_list[peer_id])
        else:
            edge_resp = self._tun_man.negotiate_incoming_tunnel(edge_req)

        if edge_resp and edge_resp.is_accepted:
            if edge_resp.data[:2] != "E0":
                et = transpose_edge_type(edge_req.edge_type)
                ce = ConnectionEdge(
                    peer_id=peer_id, edge_id=edge_req.edge_id, edge_type=et)
                ce.edge_state = EdgeState.PreAuth
                self._adj_list[ce.peer_id] = ce
            self._tun_man.authorize_incoming_tunnel(edge_req, neg_edge_cbt)
        return edge_resp

    def on_edge_update(self, event):
        """
        Updates the connection edge's current state based on the provided event. The number of CEs
        not in the EdgeState CEStateConnected is used to limit the number of edges being
        constructed concurrently.
        """
        peer_id = event["PeerId"]
        edge_id = event["TunnelId"]
        overlay_id = event["OverlayId"]
        if event["UpdateType"] == "LnkEvAuthorized":
            ce = self._adj_list[peer_id]
            ce.edge_state = EdgeState.Authorized
        elif event["UpdateType"] == "LnkEvAuthExpired":
            ce = self._adj_list[peer_id]
            assert ce.edge_state == EdgeState.Authorized, "Deauth CE={0}".format(
                ce)
            ce.edge_state = EdgeState.Deleting
            del self._adj_list[peer_id]
            # del self._pending_adj_list[peer_id]
        elif event["UpdateType"] == "LnkEvCreating":
            conn_edge = self._adj_list[peer_id]
            conn_edge.edge_state = EdgeState.Created
        elif event["UpdateType"] == "LnkEvCreated":
            pass
        elif event["UpdateType"] == "LnkEvConnected":
            self._adj_list[peer_id].edge_state = EdgeState.Connected
            self._adj_list[peer_id].connected_time = \
                event["ConnectedTimestamp"]
            # del self._pending_adj_list[peer_id]
        elif event["UpdateType"] == "LnkEvDisconnected":
            # the local topology did not request removal of the connection
            self.logger.debug("%s event recvd peer_id: %s, edge_id: %s",
                              EdgeState.Disconnected, peer_id, edge_id)
            self._adj_list[peer_id].edge_state = EdgeState.Disconnected
            self._tun_man.remove_tunnel(peer_id, edge_id)
        elif event["UpdateType"] == "LnkEvRemoved":
            self._adj_list[peer_id].edge_state = EdgeState.Deleting
            del self._adj_list[peer_id]
            # del self._pending_adj_list[peer_id]
        elif event["UpdateType"] == "RemoveEdgeFailed":
            # leave the node in the adj list and marked for removal to be retried.
            # the retry occurs too quickly and causes too many attempts before it succeeds
            # self._refresh_in_progress -= 1
            self._adj_list[peer_id].created_time = \
                time.time() + NetworkBuilder._DEL_RETRY_INTERVAL
        else:
            self._top.log(
                "LOG_WARNING", "Invalid UpdateType specified for event")
        self._tun_man.on_tunnel_event(event)
