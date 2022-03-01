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

from collections import deque, namedtuple
import time
import types
try:
    import simplejson as json
except ImportError:
    import json
import struct
import uuid
from collections.abc import MutableMapping

EdgeTypesOut = types.SimpleNamespace(  # Unknown="CETypeUnknown",
    Static="CETypeStatic",
    Successor="CETypeSuccessor",
    LongDistance="CETypeLongDistance",
    OnDemand="CETypeOnDemand")

EdgeTypesIn = types.SimpleNamespace(  # Unknown="CETypeUnknown",
    IStatic="CETypeIStatic",
    Predecessor="CETypePredecessor",
    ILongDistance="CETypeILongDistance",
    IOnDemand="CETypeIOnDemand")

EdgeTypes = [*EdgeTypesOut.__dict__.values()] + \
    [*EdgeTypesIn.__dict__.values()]

EdgeState = types.SimpleNamespace(Initialized="CEStateInitialized",
                                  PreAuth="CEStatePreAuth",
                                  Authorized="CEStateAuthorized",
                                  Created="CEStateCreated",
                                  Connected="CEStateConnected",
                                  Disconnected="CEStateDisconnected",
                                  Deleting="CEStateDeleting")

OpType = types.SimpleNamespace(Add="OpTypeAdd",
                               Remove="OpTypeRemove",
                               Update="OpTypeUpdate")

UpdatePriority = types.SimpleNamespace(ModifyExisting=0,
                                       AddStatic=1,
                                       AddSucc=2,
                                       RmvOnd=3,
                                       AddOnd=4,
                                       RmvSucc=5,
                                       RmvLongDst=6,
                                       AddLongDst=7)


def transpose_edge_type(edge_type):
    et = None
    if edge_type == "CETypeStatic":
        et = EdgeTypesIn.IStatic
    elif edge_type == "CETypeSuccessor":
        et = EdgeTypesIn.Predecessor
    elif edge_type == "CETypeLongDistance":
        et = EdgeTypesIn.ILongDistance
    elif edge_type == "CETypeOnDemand":
        et = EdgeTypesIn.IOnDemand
    elif edge_type == "CETypeIStatic":
        et = EdgeTypesOut.Static
    elif edge_type == "CETypePredecessor":
        et = EdgeTypesOut.Successor
    elif edge_type == "CETypeILongDistance":
        et = EdgeTypesOut.LongDistance
    elif edge_type == "CETypeIOnDemand":
        et = EdgeTypesOut.OnDemand
    return et


class ConnectionEdge():
    """ A discriptor of the edge/link between two peers."""
    _PACK_STR = '!16s16sff18s19s?'

    def __init__(self, peer_id=None, edge_id=None, edge_type="CETypeUnknown"):
        self.peer_id = peer_id
        self.edge_id = edge_id
        if not self.edge_id:
            self.edge_id = uuid.uuid4().hex
        self.created_time = time.time()
        self.connected_time = None
        self.edge_state = EdgeState.Initialized
        self.edge_type = edge_type
        # self.marked_for_delete = False

    def __key__(self):
        return int(self.peer_id, 16)

    def __eq__(self, other):
        return self.__key__() == other.__key__()

    def __ne__(self, other):
        return self.__key__() != other.__key__()

    def __lt__(self, other):
        return self.__key__() < other.__key__()

    def __le__(self, other):
        return self.__key__() <= other.__key__()

    def __gt__(self, other):
        return self.__key__() > other.__key__()

    def __ge__(self, other):
        return self.__key__() >= other.__key__()

    def __hash__(self):
        return hash(self.__key__())

    def __repr__(self):
        items = (f"\"{k}\": {v!r}" for k, v in self.__dict__.items())
        return "{{{}}}".format(", ".join(items))

    def __iter__(self):
        yield("peer_id", self.peer_id)
        yield("edge_id", self.edge_id)
        yield("created_time", self.created_time)
        yield("connected_time", self.connected_time)
        yield("edge_state", self.edge_state)
        yield("edge_type", self.edge_type)
        # yield("marked_for_delete", self.marked_for_delete)

    def serialize(self):
        return struct.pack(ConnectionEdge._PACK_STR, self.peer_id, self.edge_id, self.created_time,
                           self.connected_time, self.edge_state, self.edge_type)
        # ,self.marked_for_delete)

    @classmethod
    def from_bytes(cls, data):
        ce = cls()
        (ce.peer_id, ce.edge_id, ce.created_time, ce.connected_time, ce.edge_state,
         ce.edge_type) = struct.unpack_from(cls._PACK_STR, data)
        return ce

    def to_json(self):
        return json.dumps(dict(self))

    @classmethod
    def from_json_str(cls, json_str):
        ce = cls()
        jce = json.loads(json_str)
        ce.peer_id = jce["peer_id"]
        ce.edge_id = jce["edge_id"]
        ce.created_time = jce["created_time"]
        ce.connected_time = jce["connected_time"]
        ce.edge_state = jce["edge_state"]
        ce.edge_type = jce["edge_type"]
        return ce


class ConnEdgeAdjacenctList(MutableMapping):
    """ A series of ConnectionEdges that are incident on the local node"""

    def __init__(self, overlay_id, node_id, min_succ=1, max_ldl=1, max_ond=1):
        self._overlay_id = overlay_id
        self._node_id = node_id
        self._conn_edges = {}
        self.min_successors = min_succ
        self.max_ldl = max_ldl
        self.max_ond = max_ond
        self.num_ldl = 0
        self.num_ldli = 0
        self.num_succ = 0
        self.num_succi = 0
        self.num_ond = 0
        self.num_ondi = 0

    def __len__(self):
        return len(self._conn_edges)

    def __repr__(self):
        items = (f"\"{k}\": {v!r}" for k, v in self.__dict__.items())
        return "{{{}}}".format(", ".join(items))

    def __bool__(self):
        return bool(self._conn_edges)

    def __setitem__(self, peer_id, ce):
        self.add_conn_edge(peer_id, ce)

    def __getitem__(self, peer_id):
        return self._conn_edges[peer_id]

    def __delitem__(self, peer_id):
        self.remove_conn_edge(peer_id)

    def __iter__(self):
        return iter(self._conn_edges)

    @property
    def node_id(self):
        return self._node_id

    @property
    def overlay_id(self):
        return self._overlay_id

    def is_threshold(self, edge_type):
        if edge_type == EdgeTypesIn.ILongDistance:
            return bool(self.num_ldli >= self.max_ldl)
        if edge_type == EdgeTypesIn.IOnDemand:
            return bool(self.num_ondi >= self.max_ond)
        else:
            raise RuntimeWarning("EdgeType threshold not implemented")
        # return bool(self.num_ldli >= math.ceil(self.max_ldl * 1.5))

    def add_conn_edge(self, peer_id, ce):
        self.remove_conn_edge(peer_id)
        self._conn_edges[peer_id] = ce
        # self.update_closest()
        if ce.edge_type == "CETypeLongDistance":
            self.num_ldl += 1
        if ce.edge_type == "CETypeILongDistance":
            self.num_ldli += 1
        elif ce.edge_type == "CETypeSuccessor":
            self.num_succ += 1
        elif ce.edge_type == "CETypePredecessor":
            self.num_succi += 1
        elif ce.edge_type == "CETypeOnDemand":
            self.num_ond += 1
        elif ce.edge_type == "CETypeIOnDemand":
            self.num_ondi += 1

    def remove_conn_edge(self, peer_id):
        ce = self._conn_edges.pop(peer_id, None)
        if not ce:
            return
        if ce.edge_type == "CETypeLongDistance":
            self.num_ldl -= 1
        if ce.edge_type == "CETypeILongDistance":
            self.num_ldli -= 1
        elif ce.edge_type == "CETypeSuccessor":
            self.num_succ -= 1
        elif ce.edge_type == "CETypePredecessor":
            self.num_succi -= 1
        elif ce.edge_type == "CETypeOnDemand":
            self.num_ond -= 1
        elif ce.edge_type == "CETypeIOnDemand":
            self.num_ondi -= 1
        # return ce

    def update_edge_type(self, new_conn_edge):
        ce = self._conn_edges.get(new_conn_edge.peer_id)
        if ce:
            ce.edge_type = new_conn_edge.edge_type

    def select_edges_by_type(self, edge_type):
        conn_edges = []
        for ce in self._conn_edges.values():
            if ce.edge_type in edge_type:
                conn_edges.append(ce)
        return conn_edges

    def select_edges_by_state(self, edge_state):
        conn_edges = []
        for ce in self._conn_edges.values():
            if ce.edge_state in edge_state:
                conn_edges.append(self._conn_edges[ce.peer_id])
        return conn_edges

    def select_edges(self, edges):
        """
        Input is a list of edge type/state tuples
        Output is a list of peer ids that have edges of STATE and STATE
        """
        conn_edges = {}
        for peer_id in self._conn_edges:
            for etup in edges:
                if (self._conn_edges[peer_id].edge_type == etup[0] and
                        self._conn_edges[peer_id].edge_state == etup[1]):
                    conn_edges[peer_id] = self._conn_edges[peer_id]
        return conn_edges


class NetUpdate():
    def __init__(self, conn_edge, op_type, priority):
        self.conn_edge = conn_edge
        self.operation = op_type
        self.priority = priority
        self.is_completed = False

    def __repr__(self):
        items = (f"\"{k}\": {v!r}" for k, v in self.__dict__.items())
        return "{{{}}}".format(", ".join(items))


class NetworkTransitions():
    def __init__(self, curr_net_graph, tgt_net_graph):
        self._updates = deque()
        self._prev_priority = 0
        self.min_successors = tgt_net_graph.min_successors
        self.max_ldl = tgt_net_graph.max_ldl
        self.max_ondemand = tgt_net_graph.max_ondemand
        self._diff(curr_net_graph, tgt_net_graph)

    def __iter__(self):
        return iter(self._updates)

    def __repr__(self):
        items = (f"\"{k}\": {v!r}" for k, v in self.__dict__.items())
        return "{{{}}}".format(", ".join(items))

    def __bool__(self):
        return bool(self._updates)

    def __len__(self):
        return self._updates

    def __getitem__(self, index):
        return self._updates[index]

    def _diff(self, current, target):
        for peer_id in target:
            if peer_id not in current:
                # Op Add
                if target[peer_id].edge_type == EdgeTypesOut.Static:
                    op = NetUpdate(
                        target[peer_id], OpType.Add, UpdatePriority.AddStatic)  # 1
                    self._updates.append(op)
                elif target[peer_id].edge_type == EdgeTypesOut.Successor:
                    op = NetUpdate(
                        target[peer_id], OpType.Add, UpdatePriority.AddSucc)  # 2
                    self._updates.append(op)
                elif target[peer_id].edge_type == EdgeTypesOut.OnDemand:
                    op = NetUpdate(
                        target[peer_id], OpType.Add, UpdatePriority.AddOnd)  # 4
                    self._updates.append(op)
                elif target[peer_id].edge_type == EdgeTypesOut.LongDistance:
                    op = NetUpdate(
                        target[peer_id], OpType.Add, UpdatePriority.AddLongDst)  # 7
                    self._updates.append(op)
            else:
                # Op Update
                if current[peer_id].edge_type != target[peer_id].edge_type:
                    op = NetUpdate(
                        target[peer_id], OpType.Update, UpdatePriority.ModifyExisting)  # 0
                    self._updates.append(op)

        for peer_id in current:
            if peer_id not in target:
                # Op Remove
                if current[peer_id].edge_type == EdgeTypesOut.OnDemand:
                    op = NetUpdate(
                        current[peer_id], OpType.Remove, UpdatePriority.RmvOnd)  # 3
                    self._updates.append(op)
                elif current[peer_id].edge_type == EdgeTypesOut.Successor:
                    op = NetUpdate(
                        current[peer_id], OpType.Remove, UpdatePriority.RmvSucc)  # 5
                    self._updates.append(op)
                elif current[peer_id].edge_type == EdgeTypesOut.LongDistance:
                    op = NetUpdate(
                        current[peer_id], OpType.Remove, UpdatePriority.RmvLongDst)  # 6
                    self._updates.append(op)
        if self._updates:
            self._updates = sorted(self._updates, key=lambda x: x.priority)
            self._prev_priority = self._updates[0].priority

    def head(self):
        if self._updates:
            return self._updates[0]
        return None

    def pop(self):
        if self._updates:
            self._prev_priority = self._updates[0].priority
            del self._updates[0]

    def push_back(self, update):
        self._updates.append(update)
