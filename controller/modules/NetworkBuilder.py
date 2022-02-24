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


EdgeRequest = namedtuple("EdgeRequest",
                         ["overlay_id", "edge_id", "edge_type", "initiator_id",
                          "recipient_id", "location_id", "encryption_required"])
EdgeResponse = namedtuple("EdgeResponse", ["is_accepted", "data"])
EdgeNegotiate = namedtuple(
    "EdgeNegotiate", EdgeRequest._fields + EdgeResponse._fields)

"""
CE enters the nego list with state CEStatePreAuth
Successful auth updates the state to CEStateAuthorized and removes it from nego list
"""


class NetworkBuilder():
    _DEL_RETRY_INTERVAL = 10
    _EDGE_PROTECTION_AGE = 180
    _REFLECT = set(
        ["_adj_list", "_net_transitions"]) #, "_negotiated_edges"])

    def __init__(self, top_man, overlay_id, node_id, concurrency_level=1):
        self._adj_list = ConnEdgeAdjacenctList(overlay_id, node_id)
        # self._pending_adj_list = None
        self._net_transitions = None
        # self._negotiated_edges = {}
        self._top = top_man
        self._concurrency_level = concurrency_level
        
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
        self._top.logger.debug("New network transitions: %s", str(net_transitions))
        assert ((self.is_ready and bool(net_transitions)) or
                (not self.is_ready and not bool(net_transitions))),\
            "Netbuilder is not ready for a new net graph"

        if net_transitions and self.is_ready:
            self._net_transitions = net_transitions
            # self._pending_adj_list = net_graph
            # self._current_adj_list.max_successors = net_graph.max_successors
            # self._current_adj_list.max_ldl = net_graph.max_ldl
            # self._current_adj_list.max_ondemand = net_graph.max_ondemand
            # self._adj_list.update_closest()
            # self._process_pending_adj_list()
        self._process_net_transitions()
        # self._create_new_edges()
        # self._remove_edge()

    def _process_net_transitions(self):
        counter = 0
        while self._net_transitions:
            update = self._net_transitions.head()
            if update.operation == OpType.Add:
                self._initiate_create_edge(update.conn_edge)
            elif update.operation == OpType.Remove:
                self._initiate_remove_edge(update.conn_edge)
            elif update.operation == OpType.Update:
                self._update_edge_properties()
            self._net_transitions.pop()
            counter += 1
            if counter >= self._concurrency_level:
            #or self._net_transitions.is_priority_change:
                return

            
    def update_edge_state(self, event):
        """
        Updates the connection edge's current state based on the provided event. The number of CEs
        not in the EdgeState CEStateConnected is used to limit the number of edges being
        constructed concurrently.
        """
        peer_id = event["PeerId"]
        edge_id = event["TunnelId"]
        overlay_id = event["OverlayId"]
        if event["UpdateType"] == "LnkEvAuthorized":
            self._add_incoming_auth_conn_edge(peer_id)
        elif event["UpdateType"] == "LnkEvDeauthorized":
            ce = self._adj_list[peer_id]
            assert ce.edge_state == EdgeState.Authorized, "Deauth CE={0}".format(
                ce)
            ce.edge_state = EdgeState.Deleting
            del self._adj_list[peer_id]
            # del self._pending_adj_list[peer_id]
        elif event["UpdateType"] == "LnkEvCreating":
            conn_edge = self._adj_list.conn_edges.get(peer_id, None)
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
            self._top.logger.debug("%s event recvd peer_id: %s, edge_id: %s",
                                   EdgeState.Disconnected, peer_id, edge_id)
            self._adj_list[peer_id].edge_state = EdgeState.Disconnected
            self._top.top_remove_edge(overlay_id, peer_id, edge_id)
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

    def _initiate_remove_edge(self, conn_edge):
        if conn_edge.edge_state == EdgeState.Connected and \
            conn_edge.edge_type in [*EdgeTypesOut.__dict__.values()] and \
            time.time() - conn_edge.connected_time >= NetworkBuilder._EDGE_PROTECTION_AGE:
                conn_edge.marked_for_delete = True
                self._top.logger.debug("Marked conn_edge for delete: %s", str(conn_edge))
                if conn_edge.edge_type == EdgeTypesOut.Successor and \
                    not self._adj_list.is_successors_fully_connected():
                        return
                self._remove_edge(conn_edge)

                            
    def _remove_edge(self, conn_edge=None):
        overlay_id = self._adj_list.overlay_id
        if not conn_edge:
            for peer_id in self._adj_list:
                ce = self._adj_list[peer_id]
                if ce.marked_for_delete and ce.edge_state == EdgeState.Connected:
                    conn_edge = ce
        if conn_edge:
            if conn_edge.marked_for_delete and conn_edge.edge_state == EdgeState.Connected:
                conn_edge.edge_state = EdgeState.Deleting
                self._top.top_remove_edge(overlay_id, conn_edge.peer_id, conn_edge.edge_id)
                
    # def _mark_edges_for_removal(self):
    #     """
    #     Anything edge the set (Active - Pending) is marked for deletion but do not remove
    #     negotiated edges.
    #     """
    #     for peer_id in self._adj_list:
    #         if self._adj_list[peer_id].edge_type in ng.EdgeTypesIn:
    #             continue  # do not remove incoming edges
    #         if peer_id in self._pending_adj_list:
    #             continue  # the edge should be maintained
    #         if self._adj_list[peer_id].edge_state != EdgeState.Connected:
    #             # don't delete an edge before it completes the create process. if it fails LNK will
    #             # initiate the removal.
    #             continue
    #         if time.time() - self._adj_list[peer_id].connected_time < 30:
    #             continue  # events get supressed
    #         self._adj_list[peer_id].marked_for_delete = True
    #         self._top.log("LOG_DEBUG", "Marked connedge for delete: %s",
    #                       str(self._adj_list[peer_id]))

    def _remove_edges(self):
        """
        Removes a connected edge that was previousls marked for deletion. Minimize churn by
        removing a single edge per invokation.
        """
        overlay_id = self._adj_list.overlay_id
        for peer_id in self._adj_list:
            ce = self._adj_list[peer_id]
            if (ce.marked_for_delete and ce.edge_state == EdgeState.Connected):
                ce.edge_state = EdgeState.Deleting
                self._top.top_remove_edge(overlay_id, peer_id, ce.edge_id)
                return

    def _initiate_create_edge(self, ce):
        if ce.peer_id not in self._adj_list:
            ce.edge_state = EdgeState.PreAuth
            self._adj_list[ce.peer_id] = ce
            self._negotiate_new_edge(ce.edge_id, ce.edge_type, ce.peer_id)
                       
    # def _create_new_edges(self):
    #     for peer_id, ce in self._negotiated_edges.items():
    #         if ce.edge_state == EdgeState.Initialized:
    #             # avoid repeat auth request by only acting on CEStateInitialized
    #             ce.edge_state = EdgeState.PreAuth
    #             self._negotiate_new_edge(ce.edge_id, ce.edge_type, peer_id)

    # def _process_pending_adj_list(self):
    #     """
    #     Sync the network state by determining the difference between the active and pending net
    #     graphs. Create new successors edges before removing existing ones.
    #     """
    #     rmv_list = []
    #     if self._adj_list.overlay_id != self._pending_adj_list.overlay_id:
    #         raise ValueError("Overlay ID mismatch adj lists, active:{0}, pending:{1}".
    #                          format(self._adj_list.overlay_id,
    #                                 self._pending_adj_list.overlay_id))
    #     self._mark_edges_for_removal()

    #     # Any edge in set (Pending - Active) is added for nego
    #     for peer_id in self._pending_adj_list:
    #         ce = self._pending_adj_list[peer_id]
    #         # if ce.edge_type == "CETypeLongDistance" and \
    #         #    self._current_adj_list.num_ldl >= self._current_adj_list.max_ldl:
    #         #    continue
    #         if peer_id not in self._negotiated_edges and peer_id not in self._adj_list:
    #             self._adj_list[peer_id] = ce
    #             self._negotiated_edges[peer_id] = ce
    #         else:
    #             rmv_list.append(peer_id)

    #     for peer_id in rmv_list:
    #         del self._pending_adj_list[peer_id]

    def _negotiate_new_edge(self, edge_id, edge_type, peer_id):
        """ Role A1 """
        olid = self._adj_list.overlay_id
        nid = self._adj_list.node_id
        er = EdgeRequest(overlay_id=olid, edge_id=edge_id, edge_type=edge_type,
                         recipient_id=peer_id, initiator_id=nid, location_id=0,
                         encryption_required=False)
        self._top.top_send_negotiate_edge_req(er)

    def _resolve_request_collision(self, edge_req):
        nid = self._top.node_id
        peer_id = edge_req.initiator_id
        ce = self._adj_list[peer_id]
        edge_state = ce.edge_state
        edge_resp = None
        if edge_state in (EdgeState.Authorized, EdgeState.Created, EdgeState.Connected):
            # Likely a duplicated Remote Action from Signal
            if ce.edge_id == edge_req.edge_id:
                msg = "E1 - A valid edge already exists. TunnelId={0}"\
                    .format(self._adj_list[peer_id].edge_id[:7])
                edge_resp = EdgeResponse(is_accepted=False, data=msg)
                self._top.logger.debug(msg)
            else:
                self._top.logger.debug("Collision on expired edge request: %s", edge_req)
        elif edge_state == EdgeState.Initialized:
            edge_resp = EdgeResponse(
                is_accepted=True, data="Precollision edge permitted")
            del self._adj_list[peer_id]
            # del self._pending_adj_list[peer_id]
            # del self._negotiated_edges[peer_id]
        elif edge_state == EdgeState.PreAuth and nid < edge_req.initiator_id:
            msg = f"E2 - Node {nid} superceeds edge request due to collision, "
            "edge={self._adj_list[peer_id].edge_id[:7]}"
            edge_resp = EdgeResponse(is_accepted=False, data=msg)
            self._top.logger.debug(msg)
        elif edge_state == EdgeState.PreAuth and nid > edge_req.initiator_id:
            ce.edge_type = transpose_edge_type(edge_req.edge_type)
            ce.edge_id = edge_req.edge_id
            msg = "E0 - Node {2} accepts edge collision override. CE:{0} remapped -> edge:{1}"\
                .format(ce, edge_req.edge_id[:7], nid)
            edge_resp = EdgeResponse(is_accepted=True, data=msg)
            self._top.logger.debug(msg)
        else:
            edge_resp = EdgeResponse(False, "E6 - Request colides with an edge being destroyed."
                                            "Try later")
        assert bool(edge_resp), "NetBuilder={0}".format(self)
        return edge_resp

    def negotiate_incoming_edge(self, edge_req):
        """ Role B1 """
        self._top.logger.debug("Rcvd EdgeRequest=%s", str(edge_req))
        edge_resp = None
        peer_id = edge_req.initiator_id
        if peer_id in self._adj_list:
            edge_resp = self._resolve_request_collision(edge_req)
        elif edge_req.edge_type == "CETypeSuccessor":
            edge_resp = EdgeResponse(
                is_accepted=True, data="Successor edge permitted")
        elif edge_req.edge_type == "CETypeStatic":
            edge_resp = EdgeResponse(
                is_accepted=True, data="Static edge permitted")
        elif edge_req.edge_type == "CETypeOnDemand":
            edge_resp = EdgeResponse(
                is_accepted=True, data="On-demand edge permitted")
        elif not self._adj_list.is_threshold_ildl():
            edge_resp = EdgeResponse(
                is_accepted=True, data="Any edge permitted")
        else:
            edge_resp = EdgeResponse(is_accepted=False,
                                     data="E5 - Too many existing edges.")

        if edge_resp and edge_resp.is_accepted and edge_resp.data[:2] != "E0":
            et = transpose_edge_type(edge_req.edge_type)
            ce = ConnectionEdge(
                peer_id=peer_id, edge_id=edge_req.edge_id, edge_type=et)
            ce.edge_state = EdgeState.PreAuth
            #self._negotiated_edges[peer_id] = ce
            # self._top.logger.debug("New CE=%s added to negotiated_edges=%s", str(ce),
            #                       str(self._negotiated_edges))
        return edge_resp

    def _add_incoming_auth_conn_edge(self, peer_id):
        """ Role B2 """
        # ce = self._negotiated_edges.pop(peer_id)
        ce = self._adj_list.get(peer_id)
        ce.edge_state = EdgeState.Authorized
        self._adj_list.add_conn_edge(ce)

    def complete_edge_negotiation(self, edge_nego):
        """ Role A2 """
        self._top.logger.debug("Completing Edge Negotiation=%s", str(edge_nego))
        if edge_nego.recipient_id not in self._adj_list:
                # edge_nego.recipient_id not in self._negotiated_edges:
            self._top.logger.warning("The peer specified in edge negotiation %s is not in current adjacency "
                                   " list. The request has been discarded.")
            return
        peer_id = edge_nego.recipient_id
        edge_id = edge_nego.edge_id

        #ce = self._negotiated_edges.get(
        ce = self._adj_list[edge_nego.recipient_id]  # do not pop here, E0 needed
        if not ce:
            # OK - Collision override occurred, CE was popped in role B2 (above). Completion
            return
        if ce.edge_state != EdgeState.PreAuth:
            self._top.logger.warning("The following EdgeNegotiate cannot be completed as the "
                                     "current state of it's conn edge is invalid for this "
                                     "operation. The request has been discarded. "
                                     "ce=%s, edge_nego=%s", ce, edge_nego)
            return
            # order can vary, in other case handled below.
        if not edge_nego.is_accepted:
            # if E2 (request superceeded) do nothing here. The corresponding CE instance will
            # be converted in resolve_collision_request().
            if edge_nego.data[:2] == "E1":
                #check edge_id
                pass
            elif edge_nego.data[:2] != "E2":
                ce.edge_state = EdgeState.Deleting
                # self._negotiated_edges.pop(ce.peer_id)
                # del self._pending_adj_list[peer_id]
                del self._adj_list[ce.peer_id]
        else:
            if ce.edge_id != edge_nego.edge_id:
                self._top.logger.error("EdgeNego parameters does not match current "
                                       "adjacency list. The transaction has been discarded.")
                ce.edge_state = EdgeState.Deleting
                # self._negotiated_edges.pop(ce.peer_id)
                # del self._pending_adj_list[peer_id]
                del self._adj_list[ce.peer_id]
            else:
                ce.edge_state = EdgeState.Authorized
                # self._negotiated_edges.pop(ce.peer_id)
                self._top.top_add_edge(
                    self._adj_list.overlay_id, peer_id, edge_id)
