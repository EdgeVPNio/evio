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

import math
import random

from .NetworkGraph import ConnectionEdge, EdgeTypesIn, EdgeTypesOut
from .NetworkGraph import ConnEdgeAdjacenctList
from .NetworkGraph import GraphTransformation
from .NetworkGraph import EdgeStates


class GraphBuilder():
    """
    Creates the adjacency list of connections edges from this node that are necessary to
    maintain the Topology
    """
    def __init__(self, cfg, top=None):
        self._overlay_id = cfg["OverlayId"]
        self._node_id = cfg["NodeId"]
        self._peers = None
        # static is a list of peer ids that should always have a direct edge
        self._static_edges = cfg.get("StaticEdges", [])
        # only create edges from the static list
        self._manual_topo = cfg.get("ManualTopology", False)
        self._min_successors = int(cfg["MinSuccessors"])
        # the number of symphony edges that shoulb be maintained
        self._max_ldl_cnt = int(cfg["MaxLongDistEdges"])
        self._max_ond = int(cfg["MaxOnDemandEdges"])
        # Currently active adjacency list, needed to minimize changes in chord selection
        self._nodes = []
        self._my_idx = 0
        self._top = top
        self._relink = False
        if self._manual_topo and not self._static_edges:
            self._top.log("LOG_WARNING", "Ad hoc topology specified but no peers are"
                          "provided, config=%s", str(cfg))

    def _build_static(self, adj_list):
        for peer_id in self._static_edges:
            ce = ConnectionEdge(peer_id, edge_type="CETypeStatic")
            adj_list[peer_id] = ce

    def _get_successors(self):
        """ Generate a list of successor UIDs from the list of peers """
        successors = []
        num_peers = len(self._peers)
        num_nodes = len(self._nodes)
        successor_index = self._my_idx + 1
        num_succ = self._min_successors if (num_peers >= self._min_successors) else num_peers
        for _ in range(num_succ):
            successor_index %= num_nodes
            successors.append(self._nodes[successor_index])
            successor_index += 1
        return successors

    def _build_successors(self, adj_list, transition_adj_list):
        num_ideal_conn_succ = 0
        successors = self._get_successors()
        suc_ces = transition_adj_list.select_edges([("CETypeSuccessor", EdgeStates.Connected)])
        # add the ideal successors to the new adj list
        for peer_id in successors:
            if peer_id not in adj_list:
                if peer_id in suc_ces:
                    # this is an ideal succ that was previously connected
                    num_ideal_conn_succ += 1
                    del suc_ces[peer_id]
                    adj_list[peer_id] = transition_adj_list[peer_id]
                else:
                    adj_list[peer_id] = ConnectionEdge(peer_id, edge_type="CETypeSuccessor")
        # do not remove the existing successor until the new one is connected
        sucl = sorted(suc_ces, reverse=True)
        for peer_id in sucl:
            # these are to be replaced when the ideal ones are in connected state
            if num_ideal_conn_succ < self._min_successors:
                # not an ideal successor but keep until better succ is connected
                adj_list[peer_id] = transition_adj_list[peer_id]
                num_ideal_conn_succ += 1
            else:
                break

    @staticmethod
    def symphony_prob_distribution(network_sz, samples)->list:
        """exp (log(n) * (rand() - 1.0))"""
        results = [None]*(samples)
        for i in range(0, samples):
            rnd_val = random.random()
            results[i] = math.exp(math.log10(network_sz) * (rnd_val - 1.0))
        return results

    def _get_long_dist_candidates(self, num_ldl)->list:
        # Calculates long distance link candidates.
        long_dist_candidates = []
        net_sz = len(self._nodes)
        if net_sz > 1:
            num_ldl = min(num_ldl, net_sz)
            node_off = GraphBuilder.symphony_prob_distribution(net_sz, num_ldl)
            for i in node_off:
                idx = math.floor(net_sz*i)
                ldl_idx = (self._my_idx + idx) % net_sz
                long_dist_candidates.append(self._nodes[ldl_idx])
        return long_dist_candidates

    def _build_long_dist_links(self, adj_list, transition_adj_list):
        # Preserve existing incoming ldl
        ldlnks = {}
        if 2 * self._min_successors > len(self._peers):
            return  # not enough peers to build LDL
        if not self._relink:
            ldlnks = transition_adj_list.select_edges_by_type(["CETypeLongDistance"])
        num_existing_ldl = 0
        for ce in ldlnks:
            if ce.edge_state in (EdgeStates.Initialized, EdgeStates.PreAuth, EdgeStates.Authorized, 
                                 EdgeStates.Created, EdgeStates.Connected) and \
                ce.peer_id not in adj_list and not self.is_too_close(ce.peer_id):
                adj_list[ce.peer_id] = transition_adj_list[ce.peer_id]
                # adj_list[ce.peer_id] = ConnectionEdge(ce.peer_id, ce.edge_id, ce.edge_type)
                num_existing_ldl += 1
                if num_existing_ldl >= self._max_ldl_cnt:
                    return
        num_ldl = self._max_ldl_cnt - num_existing_ldl
        ldl = self._get_long_dist_candidates(num_ldl)
        for peer_id in ldl:
            if peer_id not in adj_list:
                oce = transition_adj_list.get(peer_id)
                if (oce is None) or (oce is not None and oce.edge_type == EdgeTypesOut.Successor):
                    adj_list[peer_id] = ConnectionEdge(peer_id, edge_type="CETypeLongDistance")

    def _build_ondemand_links(self, adj_list, transition_adj_list, request_list):
        ond = {}
        # add existing on demand links
        existing = transition_adj_list.select_edges_by_type(EdgeTypesOut.OnDemand)
        for ce in existing:
            if ce.edge_state in (EdgeStates.Initialized, EdgeStates.PreAuth, EdgeStates.Authorized,
                                 EdgeStates.Created, EdgeStates.Connected) and ce.peer_id not in adj_list:
                ond[ce.peer_id] = ConnectionEdge(ce.peer_id, ce.edge_id, ce.edge_type)
        task_rmv = []
        for task in request_list:
            peer_id = task["PeerId"]
            op = task["Operation"]
            if op == "ADD":
                task_rmv.append(task)
                if peer_id in self._peers and (peer_id not in adj_list or
                                               peer_id not in transition_adj_list):
                    ce = ConnectionEdge(peer_id, edge_type="CETypeOnDemand")
                    ond[peer_id] = ce
            elif op == "REMOVE":
                self._top.log("LOG_DEBUG", "Processing OND Removal, popping %s", peer_id)
                ond.pop(peer_id, None)
                if peer_id not in transition_adj_list:
                    # only clear the task after the tunnel has been removed by NetworkBuilder
                    task_rmv.append(task)
        for peer_id in ond:
            if peer_id not in adj_list:
                adj_list[peer_id] = ond[peer_id]
        for task in task_rmv:
            request_list.remove(task)

    def build_adj_list(self, peers, transition_adj_list, request_list=None, relink=False):
        self._relink = relink
        self._prep(peers)
        if request_list is None:
            request_list = []
        adj_list = ConnEdgeAdjacenctList(self._overlay_id, self._node_id,
                                         self._min_successors, self._max_ldl_cnt, self._max_ond)
        self._build_static(adj_list)
        if not self._manual_topo:
            self._build_successors(adj_list, transition_adj_list)
            self._build_long_dist_links(adj_list, transition_adj_list)
            self._build_ondemand_links(adj_list, transition_adj_list, request_list)
        return adj_list

    def get_transformation(self, peers, initial_adj_list, request_list=None, relink=False):
        new_adj_list = self.build_adj_list(peers, initial_adj_list, request_list, relink)
        return GraphTransformation(initial_adj_list, new_adj_list)
        
    def build_adj_list_ata(self,):
        """
        Generates a new adjacency list from the list of available peers
        """
        adj_list = ConnEdgeAdjacenctList(self._overlay_id, self._node_id,
                                         self._min_successors, self._max_ldl_cnt, self._max_ond)
        for peer_id in self._peers:
            if self._static_edges and peer_id in self._static_edges:
                ce = ConnectionEdge(peer_id)
                ce.edge_type = "CETypeStatic"
                adj_list[peer_id] = ce
            elif not self._manual_topo and self._node_id < peer_id:
                ce = ConnectionEdge(peer_id)
                ce.edge_type = "CETypeSuccessor"
                adj_list[peer_id] = ce
        return adj_list

    def _distance(self, peer_id):
        dst = 0
        nsz = max(1, len(self._nodes))
        try:
            pr_i = self._nodes.index(peer_id)
            dst = (pr_i + nsz - self._my_idx) % nsz
        except ValueError as er:
            self._top.log("LOG_WARNING", "%s, continuing ...", str(er))
        return dst

    def _ideal_closest_distance(self):
        nsz = max(1, len(self._nodes))
        off = math.exp(-1 * math.log10(nsz))
        return math.floor(nsz * off)

    def is_too_close(self, peer_id):
        return self._distance(peer_id) < self._ideal_closest_distance()

    def _prep(self, peers):
        self._peers = peers
        self._nodes = list(self._peers)
        self._nodes.append(self._node_id)
        self._nodes.sort()
        self._my_idx = self._nodes.index(self._node_id)
