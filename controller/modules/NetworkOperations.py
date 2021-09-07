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
from .NetworkGraph import EdgeTypesOut

OpType = ["OpTypeAdd", "OpTypeRemove", "OpTypeUpdate"]

class OperationsModel():
    def __init__(self, conn_edge, op_type, priority):
        self.conn_edge = conn_edge
        self.op_type = op_type
        self.op_priority = priority
        self.is_completed = False

    def __repr__(self):
        items = (f"\"{k}\": {v!r}" for k, v in self.__dict__.items())
        return "{{{}}}".format(", ".join(items))

class NetworkOperations():
    def __init__(self):
        self.operations = {}
        self._remain = 0
        
    def __iter__(self):
        sorted_list = sorted(
            self.operations, key=lambda x: self.operations[x].op_priority)
        for x in sorted_list:
            if not self.operations[x].is_completed:
                self.operations[x].is_completed = True
                if self._remain > 0:
                    self._remain -= 1
                yield self.operations[x]

    def __repr__(self):
        items = (f"\"{k}\": {v!r}" for k, v in self.__dict__.items())
        return "{{{}}}".format(", ".join(items))
    
    def __bool__(self):
        return bool(self._remain != 0)
    
    def diff(self, curr_net_graph, tgt_net_graph):
        for peer_id in tgt_net_graph.conn_edges:
            if peer_id not in curr_net_graph.conn_edges:
                # Op Add
                if tgt_net_graph.conn_edges[peer_id].edge_type == 'CETypeEnforced':
                    op = OperationsModel(
                        tgt_net_graph.conn_edges[peer_id], OpType[0], 1)
                    self.operations[peer_id] = op
                elif tgt_net_graph.conn_edges[peer_id].edge_type == "CETypeSuccessor":
                    op = OperationsModel(
                        tgt_net_graph.conn_edges[peer_id], OpType[0], 2)
                    self.operations[peer_id] = op
                elif tgt_net_graph.conn_edges[peer_id].edge_type == "CETypeOnDemand":
                    op = OperationsModel(
                        tgt_net_graph.conn_edges[peer_id], OpType[0], 4)
                    self.operations[peer_id] = op
                elif tgt_net_graph.conn_edges[peer_id].edge_type == "CETypeLongDistance":
                    op = OperationsModel(
                        tgt_net_graph.conn_edges[peer_id], OpType[0], 7)
                    self.operations[peer_id] = op
            else:
                # Op Update
                op = OperationsModel(
                    tgt_net_graph.conn_edges[peer_id], OpType[2], 0)
                self.operations[peer_id] = op

        for peer_id in curr_net_graph.conn_edges:
            if peer_id not in tgt_net_graph.conn_edges:
                if curr_net_graph.conn_edges[peer_id].edge_type in EdgeTypesOut:
                    # Op Remove
                    if curr_net_graph.conn_edges[peer_id].edge_state == "CEStateConnected" and\
                           time.time() - curr_net_graph[peer_id].connected_time > 30:
                        if curr_net_graph.conn_edges[peer_id].edge_type == "CETypeOnDemand":
                            op = OperationsModel(
                                curr_net_graph.conn_edges[peer_id], OpType[1], 3)
                            self.operations[peer_id] = op
                        elif curr_net_graph.conn_edges[peer_id].edge_type == "CETypeSuccessor":
                            op = OperationsModel(
                                curr_net_graph.conn_edges[peer_id], OpType[1], 5)
                            self.operations[peer_id] = op
                        elif curr_net_graph.conn_edges[peer_id].edge_type == \
                            "CETypeLongDistance":
                            op = OperationsModel(
                                curr_net_graph.conn_edges[peer_id], OpType[1], 6)
                            self.operations[peer_id] = op
        self._remain = len(self.operations)
