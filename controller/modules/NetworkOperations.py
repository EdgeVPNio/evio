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

from .NetworkGraph import ConnEdgeAdjacenctList
from .NetworkGraph import ConnectionEdge
from .NetworkGraph import EdgeTypesOut


class OperationsModel():
    def __init__(self, conn_edge, op_type, priority):
        self.conn_edge = conn_edge
        self.op_type = op_type
        self.op_priority = priority

    # def __repr__(self):
    #     msg = "connEdge = %s, opType = %s, opPriority=%s>" % \
    #           (self.conn_edge, self.op_type, self.op_priority)
    #     return msg
    def __repr__(self):
        items = (f"\"{k}\": {v!r}" for k, v in self.__dict__.items())
        return "{{{}}}".format(", ".join(items))

class NetworkOperations():
    def __init__(self, current_Network_State, desired_Network_State):
        self.current_Network_State = current_Network_State
        self.desired_Network_State = desired_Network_State
        self.operations = {}

    def __iter__(self):
        sorted_list = sorted(
            self.operations, key=lambda x: self.operations[x].op_priority)
        for x in sorted_list:
            yield self.operations[x]

    # def __repr__(self):
    #     msg = "currentNetworkState = %s, desiredNetworkState = %s, numOfOperations=%d, " \
    #           "Operations=%s>" % \
    #           (self.current_Network_State, self.desired_Network_State,
    #            len(self.operations), self.operations)
    #     return msg
    def __repr__(self):
        items = (f"\"{k}\": {v!r}" for k, v in self.__dict__.items())
        return "{{{}}}".format(", ".join(items))
      
    def diff(self):

        for edge in self.desired_Network_State.conn_edges:
            if edge not in self.current_Network_State.conn_edges:
                if self.desired_Network_State.conn_edges[edge].edge_type == 'CETypeEnforced':
                    op = OperationsModel(
                        self.desired_Network_State.conn_edges[edge], "opTypeAdd", 1)
                    self.operations[edge] = op
                elif self.desired_Network_State.conn_edges[edge].edge_type == "CETypeSuccessor":
                    op = OperationsModel(
                        self.desired_Network_State.conn_edges[edge], "opTypeAdd", 2)
                    self.operations[edge] = op
                elif self.desired_Network_State.conn_edges[edge].edge_type == "CETypeOnDemand":
                    op = OperationsModel(
                        self.desired_Network_State.conn_edges[edge], "opTypeAdd", 4)
                    self.operations[edge] = op
                elif self.desired_Network_State.conn_edges[edge].edge_type == "CETypeLongDistance":
                    op = OperationsModel(
                        self.desired_Network_State.conn_edges[edge], "opTypeAdd", 7)
                    self.operations[edge] = op
            else:
                op = OperationsModel(
                    self.desired_Network_State.conn_edges[edge], "opTypeUpdate", 0)
                self.operations[edge] = op

        for edge in self.current_Network_State.conn_edges:
            if edge not in self.desired_Network_State.conn_edges:
                if self.current_Network_State.conn_edges[edge].edge_type in EdgeTypesOut:
                    if self.current_Network_State.conn_edges[edge].edge_state == "CEStateConnected":
                        if self.current_Network_State.conn_edges[edge].edge_type == "CETypeOnDemand":
                            op = OperationsModel(
                                self.current_Network_State.conn_edges[edge], "opTypeRemove", 3)
                            self.operations[edge] = op
                        elif self.current_Network_State.conn_edges[edge].edge_type == "CETypeSuccessor":
                            op = OperationsModel(
                                self.current_Network_State.conn_edges[edge], "opTypeRemove", 5)
                            self.operations[edge] = op
                        elif self.current_Network_State.conn_edges[edge].edge_type == "CETypeLongDistance":
                            op = OperationsModel(
                                self.current_Network_State.conn_edges[edge], "opTypeRemove", 6)
                            self.operations[edge] = op
