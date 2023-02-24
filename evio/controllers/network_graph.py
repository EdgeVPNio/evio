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
from collections import deque, namedtuple
from collections.abc import MutableMapping
from typing import Optional

try:
    import simplejson as json
except ImportError:
    import json

import uuid

import broker

from .tunnel import DATAPLANE_TYPES

EdgeTypesOut = namedtuple(
    "EdgeTypesOut",
    ["Undefined", "Static", "Successor", "LongDistance", "OnDemand"],
    defaults=[
        "CETypeUndefined",
        "CETypeStatic",
        "CETypeSuccessor",
        "CETypeLongDistance",
        "CETypeOnDemand",
    ],
)
EDGE_TYPE_OUT = EdgeTypesOut()

EdgeTypesIn = namedtuple(
    "EdgeTypesIn",
    ["Undefined", "IStatic", "Predecessor", "ILongDistance", "IOnDemand"],
    defaults=[
        "CETypeUndefined",
        "CETypeIStatic",
        "CETypePredecessor",
        "CETypeILongDistance",
        "CETypeIOnDemand",
    ],
)
EDGE_TYPE_IN = EdgeTypesIn()

EdgeStates = namedtuple(
    "EdgeStates",
    [
        "Initialized",
        "PreAuth",
        "Authorized",
        "Created",
        "Connected",
        "Disconnected",
        "Deleting",
    ],
    defaults=[
        "CEStateInitialized",
        "CEStatePreAuth",
        "CEStateAuthorized",
        "CEStateCreated",
        "CEStateConnected",
        "CEStateDisconnected",
        "CEStateDeleting",
    ],
)
EDGE_STATES = EdgeStates()

ConnectionRole = namedtuple(
    "ConnectionRole",
    ["Undefined", "Initiator", "Target"],
    defaults=["ConnRoleUndefined", "ConnRoleInitiator", "ConnRoleTarget"],
)
CONNECTION_ROLE = ConnectionRole()

OpType = namedtuple(
    "OpType",
    ["Add", "Remove", "Update"],
    defaults=["OpTypeAdd", "OpTypeRemove", "OpTypeUpdate"],
)
OP_TYPE = OpType()

UpdatePriority = namedtuple(
    "UpdatePriority",
    [
        "ModifyExisting",
        "AddStatic",
        "AddSucc",
        "RmvOnd",
        "AddOnd",
        "RmvSucc",
        "RmvLongDst",
        "AddLongDst",
    ],
    defaults=[0, 1, 2, 3, 4, 5, 6, 7],
)
UPDATE_PRIORITY = UpdatePriority()


def transpose_edge_type(edge_type: str) -> str:
    tet = None
    if edge_type == EDGE_TYPE_OUT.Static:
        tet = EDGE_TYPE_IN.IStatic
    elif edge_type == EDGE_TYPE_OUT.Successor:
        tet = EDGE_TYPE_IN.Predecessor
    elif edge_type == EDGE_TYPE_OUT.LongDistance:
        tet = EDGE_TYPE_IN.ILongDistance
    elif edge_type == EDGE_TYPE_OUT.OnDemand:
        tet = EDGE_TYPE_IN.IOnDemand
    elif edge_type == EDGE_TYPE_IN.IStatic:
        tet = EDGE_TYPE_OUT.Static
    elif edge_type == EDGE_TYPE_IN.Predecessor:
        tet = EDGE_TYPE_OUT.Successor
    elif edge_type == EDGE_TYPE_IN.ILongDistance:
        tet = EDGE_TYPE_OUT.LongDistance
    elif edge_type == EDGE_TYPE_IN.IOnDemand:
        tet = EDGE_TYPE_OUT.OnDemand
    else:
        raise ValueError(
            f"Invalid edge type for transpose. Value:{edge_type} Type:{type(edge_type)}"
        )
    return tet


class ConnectionEdge:
    """A discriptor of the edge/link between two peers."""

    # _PACK_STR = '!16s16sff18s19s?'

    def __init__(
        self,
        peer_id: str,
        edge_id: Optional[str] = None,
        edge_type: str = EDGE_TYPE_OUT.Undefined,
        dataplane: str = DATAPLANE_TYPES.Undefined,
        role: str = CONNECTION_ROLE.Undefined,
        edge_state: str = EDGE_STATES.Initialized,
    ):
        self.peer_id = peer_id
        self.edge_id = edge_id
        if not self.edge_id:
            self.edge_id = uuid.uuid4().hex
        self.created_time = time.time()
        self.connected_time = None
        self.edge_state = edge_state
        self.edge_type = edge_type
        self.dataplane = dataplane
        self.role = role

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
        return broker.introspect(self)

    def __iter__(self):
        yield ("peer_id", self.peer_id)
        yield ("edge_id", self.edge_id)
        yield ("created_time", self.created_time)
        yield ("connected_time", self.connected_time)
        yield ("edge_state", self.edge_state)
        yield ("edge_type", self.edge_type)
        yield ("dataplane", self.dataplane)

    @classmethod
    def from_json_str(cls, json_str):
        jce = json.loads(json_str)
        ce = cls(
            peer_id=jce["peer_id"],
            edge_id=jce["edge_id"],
            dataplane=jce["dataplane"],
            edge_state=jce["edge_state"],
        )
        ce.created_time = jce["created_time"]
        ce.connected_time = jce["connected_time"]
        ce.edge_type = jce["edge_type"]
        return ce


class ConnEdgeAdjacenctList(MutableMapping):
    """A collection of ConnectionEdges that are incident on the local node"""

    def __init__(self, overlay_id: str, node_id: str, min_succ=1, max_ldl=1, max_ond=1):
        self._overlay_id: str = overlay_id
        self._node_id: str = node_id
        self._conn_edges: dict[str, ConnectionEdge] = {}
        self.min_successors = min_succ
        self.max_long_distance = max_ldl
        self.max_ondemand = max_ond
        self.num_ldl = 0
        self.num_ldli = 0
        self.num_succ = 0
        self.num_succi = 0
        self.num_ond = 0
        self.num_ondi = 0
        self.num_stat = 0
        self.num_stati = 0

    def __len__(self):
        return len(self._conn_edges)

    def __repr__(self):
        return broker.introspect(self)

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
    def node_id(self) -> str:
        return self._node_id

    @property
    def overlay_id(self) -> str:
        return self._overlay_id

    def is_threshold(self, edge_type: str):
        if edge_type == EDGE_TYPE_IN.ILongDistance:
            return bool(self.num_ldli >= self.max_long_distance)
        if edge_type == EDGE_TYPE_IN.IOnDemand:
            return bool(self.num_ondi >= self.max_ondemand)
        if edge_type == EDGE_TYPE_OUT.Successor:
            return bool(self.num_succ <= self.min_successors)
        else:
            raise RuntimeWarning("EdgeType threshold not implemented")

        # def is_all_successors_connected(self):
        #     matches = self.select_edges(
        #         edge_type=EDGE_TYPE_OUT.Successor, edge_state=EDGE_STATES.Connected
        #     )
        # return len(matches) >= self.min_successors

    def add_conn_edge(self, peer_id: str, ce: ConnectionEdge):
        self.remove_conn_edge(peer_id)
        self._conn_edges[peer_id] = ce
        self._incr_edge_type_count(ce.edge_type)

    def remove_conn_edge(self, peer_id: str):
        ce = self._conn_edges.pop(peer_id, None)
        if ce:
            self._decr_edge_type_count(ce.edge_type)

    def _decr_edge_type_count(self, edge_type: str):
        if edge_type == EDGE_TYPE_OUT.LongDistance:
            self.num_ldl -= 1
            assert self.num_ldl >= 0, "Invalid edge count"
        elif edge_type == EDGE_TYPE_IN.ILongDistance:
            self.num_ldli -= 1
            assert self.num_ldli >= 0, "Invalid edge count"
        elif edge_type == EDGE_TYPE_OUT.Successor:
            self.num_succ -= 1
            assert self.num_succ >= 0, "Invalid edge count"
        elif edge_type == EDGE_TYPE_IN.Predecessor:
            self.num_succi -= 1
            assert self.num_succi >= 0, "Invalid edge count"
        elif edge_type == EDGE_TYPE_OUT.OnDemand:
            self.num_ond -= 1
            assert self.num_ond >= 0, "Invalid edge count"
        elif edge_type == EDGE_TYPE_IN.IOnDemand:
            self.num_ondi -= 1
            assert self.num_ondi >= 0, "Invalid edge count"
        elif edge_type == EDGE_TYPE_OUT.Static:
            self.num_stat -= 1
            assert self.num_stat >= 0, "Invalid edge count"
        elif edge_type == EDGE_TYPE_IN.IStatic:
            self.num_stati -= 1
            assert self.num_stati >= 0, "Invalid edge count"
        else:
            raise ValueError(f"Invalid edge type {edge_type}")

    def _incr_edge_type_count(self, edge_type: str):
        if edge_type == EDGE_TYPE_OUT.LongDistance:
            self.num_ldl += 1
        elif edge_type == EDGE_TYPE_IN.ILongDistance:
            self.num_ldli += 1
        elif edge_type == EDGE_TYPE_OUT.Successor:
            self.num_succ += 1
        elif edge_type == EDGE_TYPE_IN.Predecessor:
            self.num_succi += 1
        elif edge_type == EDGE_TYPE_OUT.OnDemand:
            self.num_ond += 1
        elif edge_type == EDGE_TYPE_IN.IOnDemand:
            self.num_ondi += 1
        elif edge_type == EDGE_TYPE_OUT.Static:
            self.num_stat += 1
        elif edge_type == EDGE_TYPE_IN.IStatic:
            self.num_stati += 1
        else:
            raise ValueError(f"Invalid edge type {edge_type}")

    def update_edge(self, new_conn_edge: ConnectionEdge):
        ce = self._conn_edges.get(new_conn_edge.peer_id)
        if ce:
            self._decr_edge_type_count(ce.edge_type)
            ce.edge_type = new_conn_edge.edge_type
            self._incr_edge_type_count(ce.edge_type)

    def select_edges(
        self,
        edge_type: Optional[str] = None,
        edge_state: Optional[str] = None,
    ) -> dict[str, ConnectionEdge]:
        """returns the filtered edges in the adjacency list that match
        edge_type and/or edge_state"""
        matches = {}
        type_match = {}
        state_match = {}
        for peer_id, ce in self._conn_edges.items():
            if edge_type and edge_type == ce.edge_type:
                type_match[peer_id] = ce
            if edge_state and edge_state == ce.edge_state:
                state_match[peer_id] = ce
        if edge_type is not None and edge_state is not None:
            for peer_id, ce in type_match.items():
                if peer_id in state_match:
                    matches[peer_id] = ce
        elif edge_type is not None:
            matches = type_match
        elif edge_state is not None:
            matches = state_match
        return matches


class GraphEdit:
    def __init__(self, conn_edge: ConnectionEdge, op_type: str, priority: int):
        self.conn_edge: ConnectionEdge = conn_edge
        self.operation: str = op_type
        self.priority: int = priority

    def __repr__(self):
        return broker.introspect(self)


class GraphTransformation:
    def __init__(
        self, from_net_graph: ConnEdgeAdjacenctList, to_net_graph: ConnEdgeAdjacenctList
    ):
        self._edits: deque = deque()
        self._prev_priority = 0
        self.min_successors: int = to_net_graph.min_successors
        self.max_long_distance: int = to_net_graph.max_long_distance
        self.max_ondemand: int = to_net_graph.max_ondemand
        self._diff(from_net_graph, to_net_graph)

    def __iter__(self):
        return iter(self._edits)

    def __repr__(self):
        return broker.introspect(self)

    def __bool__(self):
        return bool(self._edits)

    def __len__(self):
        return self._edits

    def __getitem__(self, index):
        return self._edits[index]

    def _diff(self, current: ConnEdgeAdjacenctList, target: ConnEdgeAdjacenctList):
        for peer_id in target:
            if peer_id not in current:
                # Op Add
                if target[peer_id].edge_type == EDGE_TYPE_OUT.Static:
                    op = GraphEdit(
                        target[peer_id], OP_TYPE.Add, UPDATE_PRIORITY.AddStatic
                    )  # 1
                    self._edits.append(op)
                elif target[peer_id].edge_type == EDGE_TYPE_OUT.Successor:
                    op = GraphEdit(
                        target[peer_id], OP_TYPE.Add, UPDATE_PRIORITY.AddSucc
                    )  # 2
                    self._edits.append(op)
                elif target[peer_id].edge_type == EDGE_TYPE_OUT.OnDemand:
                    op = GraphEdit(
                        target[peer_id], OP_TYPE.Add, UPDATE_PRIORITY.AddOnd
                    )  # 4
                    self._edits.append(op)
                elif target[peer_id].edge_type == EDGE_TYPE_OUT.LongDistance:
                    op = GraphEdit(
                        target[peer_id], OP_TYPE.Add, UPDATE_PRIORITY.AddLongDst
                    )  # 7
                    self._edits.append(op)
            else:
                # Op Update
                if current[peer_id].edge_type != target[peer_id].edge_type:
                    op = GraphEdit(
                        target[peer_id], OP_TYPE.Update, UPDATE_PRIORITY.ModifyExisting
                    )  # 0
                    self._edits.append(op)

        for peer_id in current:
            if peer_id not in target:
                # Op Remove
                if current[peer_id].edge_type == EDGE_TYPE_OUT.OnDemand:
                    op = GraphEdit(
                        current[peer_id], OP_TYPE.Remove, UPDATE_PRIORITY.RmvOnd
                    )  # 3
                    self._edits.append(op)
                elif current[peer_id].edge_type == EDGE_TYPE_OUT.Successor:
                    op = GraphEdit(
                        current[peer_id], OP_TYPE.Remove, UPDATE_PRIORITY.RmvSucc
                    )  # 5
                    self._edits.append(op)
                elif current[peer_id].edge_type == EDGE_TYPE_OUT.LongDistance:
                    op = GraphEdit(
                        current[peer_id], OP_TYPE.Remove, UPDATE_PRIORITY.RmvLongDst
                    )  # 6
                    self._edits.append(op)
        if self._edits:
            self._edits = sorted(self._edits, key=lambda x: x.priority)
            self._prev_priority = self._edits[0].priority

    def head(self):
        if self._edits:
            return self._edits[0]
        return None

    def pop(self):
        if self._edits:
            self._prev_priority = self._edits[0].priority
            del self._edits[0]

    def push_back(self, update):
        self._edits.append(update)
