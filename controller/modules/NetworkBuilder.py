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
from .NetworkGraph import ConnectionEdge
from .NetworkGraph import ConnEdgeAdjacenctList
import modules.NetworkGraph as ng


EdgeRequest = namedtuple("EdgeRequest",
                         ["overlay_id", "edge_id", "edge_type", "initiator_id", "recipient_id"])
EdgeResponse = namedtuple("EdgeResponse", ["is_accepted", "data"])
EdgeNegotiate = namedtuple("EdgeNegotiate", EdgeRequest._fields + EdgeResponse._fields)

"""
CE enters the nego list with state CEStatePreAuth
Successful auth updates the state to CEStateAuthorized and removes it from nego list
"""
class NetworkBuilder():
    _DEL_RETRY_INTERVAL = 10
    """description of class"""
    def __init__(self, top_man, overlay_id, node_id, max_wrkld):
        self._current_adj_list = ConnEdgeAdjacenctList(overlay_id, node_id)
        self._pending_adj_list = None
        self._negotiated_edges = {}
        self._refresh_in_progress = 0
        self._max_concurrent_wrkload = max_wrkld
        #self._lock = threading.Lock()
        self._top = top_man
        self._ops = {}

    def __repr__(self):
        state = "current_adj_list=%s, pending_adj_list=%s, negotiated_edges=%s, "\
                "refresh_in_progress=%s, _max_concurrent_wrkload=%s" % \
                (self._current_adj_list, self._pending_adj_list, self._negotiated_edges,
                 self._refresh_in_progress, self._max_concurrent_wrkload)
        return state

    @property
    def is_ready(self):
        """
        Is the NetworkBuilder ready for a new NetGraph? This means all the entries in the
        pending adj list has been cleared.
        """
        #with self._lock:
        return self._is_ready()

    def _is_ready(self):
        return not bool(self._pending_adj_list)

    def _is_max_concurrent_workload(self):
        return self._refresh_in_progress >= self._max_concurrent_wrkload

    def get_adj_list(self):
        #with self._lock:
        return deepcopy(self._current_adj_list)

    def refresh(self, net_graph=None):
        """
        Transitions the overlay network overlay to the desired state specified by pending
        adjacency list.
        """
        #with self._lock:
        self._top.log("LOG_DEBUG", "New net graph: %s", str(net_graph))
        assert ((self._is_ready() and bool(net_graph)) or
                (not self._is_ready() and not bool(net_graph))),\
                    "Netbuilder is not ready for a new net graph"

        if net_graph and self._is_ready():
            self._pending_adj_list = net_graph
            self._current_adj_list.max_successors = net_graph.max_successors
            self._current_adj_list.max_ldl = net_graph.max_ldl
            self._current_adj_list.max_ondemand = net_graph.max_ondemand
            self._current_adj_list.update_closest()
            self._process_pending_adj_list()
        self._create_new_edges()
        self._remove_edges()

    def update_edge_state(self, event):
        """
        Updates the connection edge's current state based on the provided event. The number of CEs
        not in the EdgeState CEStateConnected is used to limit the number of edges being
        constructed concurrently.
        """
        peer_id = event["PeerId"]
        edge_id = event["TunnelId"]
        overlay_id = event["OverlayId"]
        #with self._lock:
        if event["UpdateType"] == "LnkEvAuthorized":
            self._add_incoming_auth_conn_edge(peer_id)
        elif event["UpdateType"] == "LnkEvDeauthorized":
            ce = self._current_adj_list[peer_id]
            assert ce.edge_state == "CEStateAuthorized", "Deauth CE={0}".format(ce)
            ce.edge_state = "CEStateDeleting"
            del self._current_adj_list[peer_id]
            del self._pending_adj_list[peer_id]
            self._refresh_in_progress -= 1
        elif event["UpdateType"] == "LnkEvCreating":
            conn_edge = self._current_adj_list.conn_edges.get(peer_id, None)
            conn_edge.edge_state = "CEStateCreated"
        elif event["UpdateType"] == "LnkEvConnected":
            self._current_adj_list[peer_id].edge_state = "CEStateConnected"
            self._current_adj_list[peer_id].connected_time = \
                event["ConnectedTimestamp"]
            del self._pending_adj_list[peer_id]
            self._refresh_in_progress -= 1
        elif event["UpdateType"] == "LnkEvDisconnected":
            # the local topology did not request removal of the connection
            self._top.log("LOG_DEBUG", "CEStateDisconnected event recvd peer_id: %s, edge_id: %s",
                          peer_id, edge_id)
            self._current_adj_list[peer_id].edge_state = "CEStateDisconnected"
            self._refresh_in_progress += 1
            self._top.top_remove_edge(overlay_id, peer_id)
        elif event["UpdateType"] == "LnkEvRemoved":
            self._current_adj_list[peer_id].edge_state = "CEStateDeleting"
            del self._current_adj_list[peer_id]
            del self._pending_adj_list[peer_id]
            self._refresh_in_progress -= 1
        elif event["UpdateType"] == "RemoveEdgeFailed":
            # leave the node in the adj list and marked for removal to be retried.
            # the retry occurs too quickly and causes too many attempts before it succeeds
            self._refresh_in_progress -= 1
            self._current_adj_list[peer_id].created_time = \
                time.time() + NetworkBuilder._DEL_RETRY_INTERVAL
        else:
            self._top.log("LOG_WARNING", "Invalid UpdateType specified for event")
        assert self._refresh_in_progress >= 0, "refresh in progress is negative {}"\
            .format(self._refresh_in_progress)

    def _mark_edges_for_removal(self):
        """
        Anything edge the set (Active - Pending) is marked for deletion but do not remove
        negotiated edges.
        """
        for peer_id in self._current_adj_list:
            if self._current_adj_list[peer_id].edge_type in ng.EdgeTypesIn:
                continue # do not remove incoming edges
            if peer_id in self._pending_adj_list:
                continue # the edge should be maintained
            if self._current_adj_list[peer_id].edge_state != "CEStateConnected":
                # don't delete an edge before it completes the create process. if it fails LNK will
                # initiate the removal.
                continue
            if time.time() - self._current_adj_list[peer_id].connected_time < 30:
                continue # events get supressed
            self._current_adj_list[peer_id].marked_for_delete = True
            self._top.log("LOG_DEBUG", "Marked connedge for delete: %s",
                          str(self._current_adj_list[peer_id]))

    def _remove_edges(self):
        """
        Removes a connected edge that was previousls marked for deletion. Minimize churn by
        removing a single edge per invokation.
        """
        overlay_id = self._current_adj_list.overlay_id
        for peer_id in self._current_adj_list:
            if self._is_max_concurrent_workload():
                return
            ce = self._current_adj_list[peer_id]
            if (ce.marked_for_delete and ce.edge_state == "CEStateConnected"):
                self._refresh_in_progress += 1
                ce.edge_state = "CEStateDeleting"
                self._top.top_remove_edge(overlay_id, peer_id)
                return

    def _create_new_edges(self):
        for peer_id, ce in self._negotiated_edges.items():
            if self._is_max_concurrent_workload():
                return
            if ce.edge_state == "CEStateInitialized":
                # avoid repeat auth request by only acting on CEStateInitialized
                ce.edge_state = "CEStatePreAuth"
                self._negotiate_new_edge(ce.edge_id, ce.edge_type, peer_id)

    def _process_pending_adj_list(self):
        """
        Sync the network state by determining the difference between the active and pending net
        graphs. Create new successors edges before removing existing ones.
        """
        rmv_list = []
        if self._current_adj_list.overlay_id != self._pending_adj_list.overlay_id:
            raise ValueError("Overlay ID mismatch adj lists, active:{0}, pending:{1}".
                             format(self._current_adj_list.overlay_id,
                                    self._pending_adj_list.overlay_id))
        self._mark_edges_for_removal()

        # Any edge in set (Pending - Active) is added for nego
        for peer_id in self._pending_adj_list:
            ce = self._pending_adj_list[peer_id]
            #if ce.edge_type == "CETypeLongDistance" and \
            #    self._current_adj_list.num_ldl >= self._current_adj_list.max_ldl:
            #    continue
            if peer_id not in self._negotiated_edges and peer_id not in self._current_adj_list:
                self._current_adj_list[peer_id] = ce
                self._negotiated_edges[peer_id] = ce
            else:
                rmv_list.append(peer_id)

        for peer_id in rmv_list:
            del self._pending_adj_list[peer_id]

    def _negotiate_new_edge(self, edge_id, edge_type, peer_id):
        """ Role A1 """
        self._refresh_in_progress += 1
        olid = self._current_adj_list.overlay_id
        nid = self._current_adj_list.node_id
        er = EdgeRequest(overlay_id=olid, edge_id=edge_id, edge_type=edge_type,
                         recipient_id=peer_id, initiator_id=nid)
        self._top.top_send_negotiate_edge_req(er)

    def _resolve_request_collision(self, edge_req):
        nid = self._top.node_id
        peer_id = edge_req.initiator_id
        ce = self._current_adj_list[peer_id]
        edge_state = ce.edge_state
        edge_resp = None
        if edge_state in ("CEStateAuthorized", "CEStateCreated", "CEStateConnected"):
            msg = "E1 - A valid edge already exists. TunnelId={0}"\
                .format(self._current_adj_list[peer_id].edge_id[:7])
            edge_resp = EdgeResponse(is_accepted=False, data=msg)
            self._top.log("LOG_DEBUG", msg)
        elif edge_state == "CEStateInitialized":
            edge_resp = EdgeResponse(is_accepted=True, data="Precollision edge permitted")
            del self._current_adj_list[peer_id]
            del self._pending_adj_list[peer_id]
            del self._negotiated_edges[peer_id]
        elif edge_state == "CEStatePreAuth" and nid < edge_req.initiator_id:
            msg = "E2 - Node {0} superceeds edge request due to collision, "\
                        "edge={1}".format(nid, self._current_adj_list[peer_id].edge_id[:7])
            edge_resp = EdgeResponse(is_accepted=False, data=msg)
            self._top.log("LOG_DEBUG", msg)
        elif edge_state == "CEStatePreAuth" and nid > edge_req.initiator_id:
            ce.edge_type = ng.transpose_edge_type(edge_req.edge_type)
            ce.edge_id = edge_req.edge_id
            msg = "E0 - Node {2} accepts edge collision override. CE:{0} remapped -> edge:{1}"\
                .format(ce, edge_req.edge_id[:7], nid)
            edge_resp = EdgeResponse(is_accepted=True, data=msg)
            self._top.log("LOG_DEBUG", msg)
        else:
            edge_resp = EdgeResponse(False, "E6 - Request colides with an edge being destroyed."\
                                            "Try later")
        assert bool(edge_resp), "NetBuilder={0}".format(self)
        return edge_resp

    def negotiate_incoming_edge(self, edge_req):
        """ Role B1 """
        self._top.log("LOG_DEBUG", "Rcvd EdgeRequest=%s", str(edge_req))
        edge_resp = None
        peer_id = edge_req.initiator_id
        if peer_id in self._current_adj_list:
            edge_resp = self._resolve_request_collision(edge_req)
        elif edge_req.edge_type == "CETypeSuccessor":
            edge_resp = EdgeResponse(is_accepted=True, data="Successor edge permitted")
        elif edge_req.edge_type == "CETypeEnforced":
            edge_resp = EdgeResponse(is_accepted=True, data="Enforced edge permitted")
        elif edge_req.edge_type == "CETypeOnDemand":
            edge_resp = EdgeResponse(is_accepted=True, data="On-demand edge permitted")
        elif not self._current_adj_list.is_threshold_ildl():
            edge_resp = EdgeResponse(is_accepted=True, data="Any edge permitted")
        else:
            edge_resp = EdgeResponse(is_accepted=False,
                                     data="E5 - Too many existing edges.")

        if edge_resp.is_accepted and edge_resp.data[:2] != "E0":
            et = ng.transpose_edge_type(edge_req.edge_type)
            ce = ConnectionEdge(peer_id=peer_id, edge_id=edge_req.edge_id, edge_type=et)
            ce.edge_state = "CEStatePreAuth"
            self._negotiated_edges[peer_id] = ce
            self._top.log("LOG_DEBUG", "New CE=%s added to negotiated_edges=%s", str(ce),
                          str(self._negotiated_edges))
        return edge_resp

    def _add_incoming_auth_conn_edge(self, peer_id):
        """ Role B2 """
        self._refresh_in_progress += 1
        ce = self._negotiated_edges.pop(peer_id)
        ce.edge_state = "CEStateAuthorized"
        self._current_adj_list.add_conn_edge(ce)

    def complete_edge_negotiation(self, edge_nego):
        """ Role A2 """
        self._top.log("LOG_DEBUG", "EdgeNegotiate=%s", str(edge_nego))
        #with self._lock:
        if edge_nego.recipient_id not in self._current_adj_list and \
            edge_nego.recipient_id not in self._negotiated_edges:
            self._top.log("LOG_ERROR", "Peer Id from edge negotiation not in current adjacency " \
                " list or _negotiated_edges. The transaction has been discarded.")
            return
        peer_id = edge_nego.recipient_id
        edge_id = edge_nego.edge_id

        ce = self._negotiated_edges.get(edge_nego.recipient_id, None) # do not pop here, E0 needed
        if not ce:
            return # OK - Collision override occurred, CE was popped in role B2 (above). Completion
                   # order can vary, in other case handled below.
        if not edge_nego.is_accepted:
            self._refresh_in_progress -= 1
            # if E2 (request superceeded) do nothing here. The corresponding CE instance will
            # be converted in resolve_collision_request().
            if edge_nego.data[:2] != "E2":
                ce.edge_state = "CEStateDeleting"
                self._negotiated_edges.pop(ce.peer_id)
                del self._pending_adj_list[peer_id]
                del self._current_adj_list[ce.peer_id]
        else:
            if ce.edge_id != edge_nego.edge_id:
                self._top.log("LOG_ERROR", "EdgeNego parameters does not match current " \
                    "adjacency list, The transaction has been discarded.")
                ce.edge_state = "CEStateDeleting"
                self._negotiated_edges.pop(ce.peer_id)
                del self._pending_adj_list[peer_id]
                del self._current_adj_list[ce.peer_id]
                self._refresh_in_progress -= 1
            else:
                ce.edge_state = "CEStateAuthorized"
                self._negotiated_edges.pop(ce.peer_id)
                self._top.top_add_edge(self._current_adj_list.overlay_id, peer_id, edge_id)
