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

import logging
import math
import threading
import time
from collections import namedtuple
from copy import deepcopy

# from datetime import datetime
from random import randint
from typing import Optional

import broker
from broker.cbt import CBT
from broker.controller_module import ControllerModule
from broker.remote_action import RemoteAction

from .graph_builder import GraphBuilder
from .network_graph import (
    CONNECTION_ROLE,
    EDGE_STATES,
    EDGE_TYPE_IN,
    EDGE_TYPE_OUT,
    OP_TYPE,
    ConnectionEdge,
    ConnEdgeAdjacenctList,
    EdgeStates,
    GraphTransformation,
    transpose_edge_type,
)
from .peer_profile import DEFAULT_ROLE, ROLES
from .tunnel import DATAPLANE_TYPES, TUNNEL_EVENTS, DataplaneTypes

MIN_SUCCESSORS = 2
MAX_ON_DEMAND_EDGES = 3
PEER_DISCOVERY_COALESCE = 1
EXCLUSION_BASE_INTERVAL = 60
MAX_SUCCESSIVE_FAILS = 4
TRIM_CHECK_INTERVAL = 300
MAX_CONCURRENT_OPS = 1
SUCCESSIVE_FAIL_INCR = 1
SUCCESSIVE_FAIL_DECR = 2
STALE_INTERVAL = float(2 * 3600)  # 2 hrs

EdgeRequest = namedtuple(
    "EdgeRequest",
    [
        "overlay_id",
        "edge_id",
        "edge_type",
        "initiator_id",
        "recipient_id",
        "location_id",
        "capability",
    ],
)

EdgeResponse = namedtuple("EdgeResponse", ["is_accepted", "message", "dataplane"])

EdgeNegotiate = namedtuple(
    "EdgeNegotiate", [*EdgeRequest._fields, *EdgeResponse._fields]
)


class DiscoveredPeer:
    def __init__(self, peer_id):
        self.peer_id: str = peer_id
        self.is_banned: bool = (
            False  # bars conn attempts from local node, the peer can still recon
        )
        self.successive_fails: int = 0
        self.available_time: float = time.time()
        self.last_checkin: float = self.available_time

    def __repr__(self):
        return broker.introspect(self)

    def exclude(self):
        self.successive_fails += SUCCESSIVE_FAIL_INCR
        self.available_time = (
            randint(1, 4) * EXCLUSION_BASE_INTERVAL * self.successive_fails
        ) + time.time()
        if self.successive_fails >= MAX_SUCCESSIVE_FAILS:
            self.is_banned = True

    def restore(self):
        self.is_banned = False
        self.successive_fails = 0

    def presence(self):
        self.last_checkin = time.time()
        self.available_time = self.last_checkin
        if self.is_banned and self.successive_fails <= 0:
            self.restore()
        elif self.is_banned and self.successive_fails > 0:
            self.successive_fails -= SUCCESSIVE_FAIL_DECR

    @property
    def is_stale(self):
        return bool(time.time() - self.last_checkin >= STALE_INTERVAL)

    @property
    def is_available(self):
        return bool(
            (not self.is_banned)  # successive_fails < max_successive_fails
            # the falloff wait period is over
            and (time.time() >= self.available_time)
            and (time.time() - self.last_checkin < STALE_INTERVAL - 600)
        )  # 10 mins before a node is stale


class NetworkOverlay:
    _REFLECT: list[str] = [
        "_max_concurrent_edits",
        "_refc",
        "node_id",
        "overlay_id",
        "new_peer_count",
        "_graph_transformation",
        "known_peers",
        "pending_auth_conn_edges",
        "ond_peers",
        "adjacency_list",
        "_loc_id",
        "_encr_req",
    ]

    def __init__(self, node_id, overlay_id, **kwargs):
        # used to limit number of concurrent operations initiated
        self._max_concurrent_edits = kwargs.get("MaxConcurrentOps", MAX_CONCURRENT_OPS)
        self._refc: int = self._max_concurrent_edits
        self._reflk = threading.Lock()
        self.node_id: str = node_id
        self.overlay_id: str = overlay_id
        self.logger: logging.Logger = kwargs["Logger"]
        self.new_peer_count: int = 0
        self._graph_transformation: GraphTransformation = None
        # self.transformation: GraphTransformation = None
        self.known_peers: dict[str, DiscoveredPeer] = {}
        self.pending_auth_conn_edges: dict[str, tuple[EdgeRequest, EdgeResponse]] = {}
        self.ond_peers: list[dict] = []
        self.adjacency_list = ConnEdgeAdjacenctList(overlay_id, node_id)
        self._loc_id: int = kwargs.get("LocationId")
        self._encr_req: bool = kwargs.get("EncryptionRequired", False)

    def __repr__(self):
        return broker.introspect(self)

    @property
    def location_id(self):
        return self._loc_id

    @property
    def is_encr_required(self):
        return self._encr_req

    @property
    def transformation(self):
        return self._graph_transformation

    @transformation.setter
    def transformation(self, new_transformation):
        """
        Transitions the overlay network overlay to the desired state specified by network
        transition ops.
        """
        self.logger.debug("New transformation: %s", str(new_transformation))
        assert not self.transformation, "Graph transformation is not empty"

        if new_transformation and not self.transformation:
            self._graph_transformation = new_transformation
            self.adjacency_list.min_successors = new_transformation.min_successors
            self.adjacency_list.max_long_distance = new_transformation.max_long_distance
            self.adjacency_list.max_ondemand = new_transformation.max_ondemand

    def acquire(self):
        with self._reflk:
            if self._refc == 0:
                raise ValueError(
                    "Reference count at zero, no more graph edits can be initiated."
                )
            self._refc -= 1

    def release(self):
        with self._reflk:
            if self._refc == self._max_concurrent_edits:
                raise ValueError(
                    "Reference count at maximum, invalid attempt to complete graph edit."
                )
            self._refc += 1

    @property
    def is_idle(self) -> bool:
        """Is the current transition operation completed"""
        with self._reflk:
            if self._refc < 0 or self._refc > self._max_concurrent_edits:
                raise ValueError(f"Invalid reference count {self._refc}")
            return bool(self._refc == self._max_concurrent_edits)

    @property
    def can_acquire(self):
        with self._reflk:
            return bool(self._refc > 0)

    def get_adj_list(self):
        return deepcopy(self.adjacency_list)


class Topology(ControllerModule):

    _DEL_RETRY_INTERVAL = 10
    _EDGE_PROTECTION_AGE = 180
    _REFLECT: list[str] = ["_net_ovls"]

    def __init__(self, nexus, module_config):
        super().__init__(nexus, module_config)
        self._is_topo_update_pending = False
        self._net_ovls: dict[str, NetworkOverlay] = {}
        self._last_trim_time: float = time.time()
        self._trim_check_interval: int = self.config.get(
            "TrimCheckInterval", TRIM_CHECK_INTERVAL
        )

    def initialize(self):
        publishers = self.get_registered_publishers()
        if (
            "Signal" not in publishers
            or "SIG_PEER_PRESENCE_NOTIFY"
            not in self.get_available_subscriptions("Signal")
        ):
            raise RuntimeError(
                "The Signal PEER PRESENCE subscription is not available. Topology cannot continue."
            )
        self.start_subscription("Signal", "SIG_PEER_PRESENCE_NOTIFY")
        if (
            "LinkManager" not in publishers
            or "LNK_TUNNEL_EVENTS"
            not in self.get_available_subscriptions("LinkManager")
        ):
            raise RuntimeError(
                "LinkManager's TUNNEL EVENTS subscription is unavailable. Topology cannot continue."
            )
        self.start_subscription("LinkManager", "LNK_TUNNEL_EVENTS")
        if (
            "GeneveTunnel" in publishers
            and "GNV_TUNNEL_EVENTS" in self.get_available_subscriptions("GeneveTunnel")
        ):
            self.start_subscription("GeneveTunnel", "GNV_TUNNEL_EVENTS")
        else:
            self.logger.warning("Geneve tunnel capability unavailable")
        for olid in self.overlays:
            self._net_ovls[olid] = NetworkOverlay(
                self.node_id,
                olid,
                Logger=self.logger,
                LocationId=self.config["Overlays"][olid].get("LocationId"),
                EncryptionRequired=self.config["Overlays"][olid].get(
                    "EncryptionRequired"
                ),
                MaxConcurrentOps=self.config.get(
                    "MaxConcurrentOps", MAX_CONCURRENT_OPS
                ),
            )

        # Subscribe for data request notifications from OverlayVisualizer
        if (
            "OverlayVisualizer" in publishers
            and "VIS_DATA_REQ" in self.get_available_subscriptions("OverlayVisualizer")
        ):
            self.start_subscription("OverlayVisualizer", "VIS_DATA_REQ")
        else:
            self.logger.info("Overlay visualizer capability unavailable")
        self.logger.info("Controller module loaded")

    def terminate(self):
        self.logger.info("Module Terminating")

    def process_cbt(self, cbt: CBT):
        # with self._lock:
        if cbt.op_type == "Request":
            if cbt.request.action == "SIG_PEER_PRESENCE_NOTIFY":
                self.req_handler_peer_presence(cbt)
            elif cbt.request.action == "VIS_DATA_REQ":
                self.req_handler_vis_data(cbt)
            elif cbt.request.action in ("LNK_TUNNEL_EVENTS", "GNV_TUNNEL_EVENTS"):
                self.req_handler_tunnl_update(cbt)
            elif cbt.request.action == "TOP_REQUEST_OND_TUNNEL":
                self.req_handler_req_ond_tunnels(cbt)
            elif cbt.request.action == "TOP_NEGOTIATE_EDGE":
                self.req_handler_negotiate_edge(cbt)
            elif cbt.request.action == "TOP_QUERY_KNOWN_PEERS":
                self.req_handler_query_known_peers(cbt)
            elif cbt.request.action == "_TOPOLOGY_UPDATE_":
                self._req_handler_manage_topology(cbt)
            else:
                self.req_handler_default(cbt)
        elif cbt.op_type == "Response":
            if cbt.request.action == "SIG_REMOTE_ACTION":
                self.resp_handler_remote_action(cbt)
            elif cbt.request.action in ("LNK_AUTH_TUNNEL", "GNV_AUTH_TUNNEL"):
                self.resp_handler_auth_tunnel(cbt)
            elif cbt.request.action in ("LNK_CREATE_TUNNEL", "GNV_CREATE_TUNNEL"):
                self.resp_handler_create_tnl(cbt)
            elif cbt.request.action in ("LNK_REMOVE_TUNNEL", "GNV_REMOVE_TUNNEL"):
                self.resp_handler_remove_tnl(cbt)
            if cbt.request.action == "_TOPOLOGY_UPDATE_":
                self._resp_handler_complete_topo_update(cbt)
            else:
                self.resp_handler_default(cbt)

    def timer_method(self, is_exiting=False):
        if is_exiting:
            return
        if not self._is_topo_update_pending:
            self._start_topo_update()

    def _start_topo_update(self):
        if self._is_topo_update_pending:
            return
        self._is_topo_update_pending = True
        self.register_internal_cbt("_TOPOLOGY_UPDATE_")

    def _resp_handler_complete_topo_update(self, cbt):
        if not self._is_topo_update_pending:
            self.logger.warning("Topology update flag already false")
        self._is_topo_update_pending = False
        self.free_cbt(cbt)

    def req_handler_peer_presence(self, cbt: CBT):
        """
        Handles peer presence notification. Determines when to build a new graph and refresh
        connections.
        """
        peer = cbt.request.params
        peer_id = peer["PeerId"]
        olid = peer["OverlayId"]
        disc = self._net_ovls[olid].known_peers.get(peer_id)
        if disc and disc.is_available:
            disc.presence()
            cbt.set_response(None, True)
            self.complete_cbt(cbt)
            return
        if not disc:
            disc = DiscoveredPeer(peer_id)
            self._net_ovls[olid].known_peers[peer_id] = disc
        disc.presence()
        if disc.is_available:
            self._net_ovls[olid].new_peer_count += 1
            if self._net_ovls[olid].new_peer_count >= self.config.get(
                "PeerDiscoveryCoalesce", PEER_DISCOVERY_COALESCE
            ):
                self.logger.debug(
                    "Overlay:%s new peer %s discovered - Coalesced %s of %s, "
                    "attempting overlay update",
                    olid,
                    peer_id,
                    self._net_ovls[olid].new_peer_count,
                    self.config.get("PeerDiscoveryCoalesce", PEER_DISCOVERY_COALESCE),
                )
                self._update_overlay(olid)
            else:
                self.logger.info(
                    "Overlay:%s, new peers %s discovered - Coalesced %s of %s, "
                    "delaying overlay update",
                    olid,
                    peer_id,
                    self._net_ovls[olid].new_peer_count,
                    self.config.get("PeerDiscoveryCoalesce", PEER_DISCOVERY_COALESCE),
                )
        cbt.set_response(None, True)
        self.complete_cbt(cbt)

    def req_handler_vis_data(self, cbt: CBT):
        topo_data: dict = {}
        try:
            for olid, net_ovl in self._net_ovls.items():
                topo_data[olid] = {}
                adjl = net_ovl.adjacency_list
                for k in adjl:
                    ce = adjl[k]
                    ced = {
                        "PeerId": ce.peer_id,
                        "CreatedTime": ce.created_time,
                        "ConnectedTime": ce.connected_time,
                        "State": ce.edge_state,
                        "Type": ce.edge_type,
                    }
                    topo_data[olid][ce.edge_id] = ced
            cbt.set_response({"Topology": topo_data}, bool(topo_data))
            self.complete_cbt(cbt)
        except KeyError:
            cbt.set_response(data=None, status=False)
            self.complete_cbt(cbt)
            self.logger("Topology data not available %s", cbt.response.data)

    def _process_tnl_event(self, update: TUNNEL_EVENTS):
        event = update["UpdateType"]
        peer_id = update["PeerId"]
        overlay_id = update["OverlayId"]
        ovl = self._net_ovls[overlay_id]
        if event == TUNNEL_EVENTS.Authorized:
            """Role B"""
            ce = ovl.adjacency_list[peer_id]
            if ce.edge_state != EDGE_STATES.PreAuth:
                raise RuntimeError(f"Invalid edge state {ce}")
            ce.edge_state = EDGE_STATES.Authorized
        elif event == TUNNEL_EVENTS.AuthExpired:
            """Role B"""
            ce = ovl.adjacency_list[peer_id]
            if ce.edge_state != EDGE_STATES.Authorized:
                raise RuntimeError(f"Invalid edge state {ce}")
            ce.edge_state = EDGE_STATES.Deleting
            del ovl.adjacency_list[peer_id]
            if peer_id in ovl.known_peers:
                ovl.known_peers[peer_id].exclude()
        elif event == TUNNEL_EVENTS.Connected:
            """Roles A & B"""
            ce = ovl.adjacency_list[peer_id]
            # assert ce.edge_state == EDGE_STATES.Created, f"Invalid edge state {ce}"
            if ce.edge_state != EDGE_STATES.Authorized:
                raise RuntimeError(f"Invalid edge state {ce}")
            ce.edge_state = EDGE_STATES.Connected
            ce.connected_time = update["ConnectedTimestamp"]
            ovl.known_peers[peer_id].restore()
            if ce.edge_type in EDGE_TYPE_OUT:
                ovl.release()
                self._process_next_transition(ovl)
        elif event == TUNNEL_EVENTS.Disconnected:
            ce = ovl.adjacency_list[peer_id]
            if ce.edge_state != EDGE_STATES.Connected:
                raise RuntimeError(
                    f"Tunnel disconnected event is invalid for edge state {ce}"
                )
            # the local topology did not request removal of the connection
            if (
                time.time() - ce.connected_time < Topology._EDGE_PROTECTION_AGE
            ) and peer_id in ovl.known_peers:
                ovl.known_peers[peer_id].exclude()
            ce.edge_state = EDGE_STATES.Disconnected
            # ovl.acquire()
            self._remove_tunnel(ovl, ce.dataplane, peer_id, ce.edge_id)
        elif event == TUNNEL_EVENTS.Removed:
            """Roles A & B"""
            ce = ovl.adjacency_list.get(peer_id, None)
            if (
                ce
                and ce.role == CONNECTION_ROLE.Initiator
                and ce.edge_state == EDGE_STATES.Authorized
            ):
                # ce will be none as the resp handler for the failed create tunnel
                # would have removed the CE
                raise RuntimeError(
                    f"Tunnel removed event is invalid for authorized initiator CE= {ce}"
                )
            elif (
                ce
                and ce.role == CONNECTION_ROLE.Initiator
                and ce.edge_state == EDGE_STATES.Connected
            ):  # topo initiated the removal
                raise RuntimeError(
                    f"Expected ce as None, resp handler remove tnl should clean up but got {ce}"
                )
            elif ce and ce.edge_state == EDGE_STATES.Disconnected:
                ce.edge_state = EDGE_STATES.Deleting
            elif (
                ce
                and ce.role == CONNECTION_ROLE.Target
                and ce.edge_state == EDGE_STATES.Authorized
            ):
                # Tunnel/Link cm handles creating the tunnel. Only need to remove CE from adj list.
                ovl.adjacency_list.pop(peer_id, None)
                # raise RuntimeError(f"Tunnel removed event is invalid for auth tgt since tnl cm
                # handles creating the tunnel {ce}")
            elif (
                ce
                and ce.role == CONNECTION_ROLE.Target
                and ce.edge_state == EDGE_STATES.Connected
            ):  # the peer disconnected
                raise RuntimeError(
                    f"The target node should not initiate removal on connect edges {ce}"
                )
            elif ce:
                self.logger.error(
                    "Tunnel event remove is unexpected for conn edge %s", ce
                )
        else:
            self.logger.warning("Invalid UpdateType specified for event %s", event)

    def req_handler_tunnl_update(self, cbt: CBT):
        event = cbt.request.params
        try:
            self._process_tnl_event(event)
        except RuntimeError as rte:
            self.logger.warning(rte)
        finally:
            cbt.set_response(None, True)
            self.complete_cbt(cbt)

    def req_handler_req_ond_tunnels(self, cbt: CBT):
        """
        Add the request params for creating an on demand tunnel
        overlay_id, peer_id, ADD/REMOVE op string
        """
        try:
            for op in cbt.request.params:
                olid = op["OverlayId"]
                peer_id = op["PeerId"]
                opc = op["Operation"]
                ovl = self._net_ovls[olid]
                if opc not in ("REMOVE", "ADD", "DISCONN"):
                    raise ValueError(f"Invalid on-demand operation requested {opc}")
                if opc == "REMOVE" or (
                    opc == "ADD"
                    and peer_id in ovl.known_peers
                    and ovl.known_peers[peer_id].is_available
                ):
                    ovl.ond_peers.append(op)
                elif opc == "DISCONN":
                    self._process_tnl_event(
                        {
                            "UpdateType": TUNNEL_EVENTS.Disconnected,
                            "OverlayId": olid,
                            "PeerId": peer_id,
                        }
                    )
                cbt.set_response("On-demand request accepted", True)
        except ValueError as verr:
            cbt.set_response("", False)
            self.logger.warning(verr)
        except KeyError as kerr:
            cbt.set_response("", False)
            self.logger.warning(kerr)
        except RuntimeError as rte:
            cbt.set_response("", False)
            self.logger.warning(rte)
        self.complete_cbt(cbt)

    def req_handler_negotiate_edge(self, edge_cbt: CBT):
        """Role B1, decide if the request for an incoming edge is accepted or rejected"""
        edge_req = EdgeRequest(**edge_cbt.request.params)
        olid = edge_req.overlay_id
        if olid not in self.config["Overlays"]:
            self.logger.warning(
                "The edge request was refused as [%s] is not a valid overlay ID", olid
            )
            edge_cbt.set_response("Unknown overlay id specified in edge request", False)
            self.complete_cbt(edge_cbt)
            return
        peer_id = edge_req.initiator_id
        if peer_id not in self._net_ovls[olid].known_peers:
            # this node miss the presence notification, so add to KnownPeers
            self._net_ovls[olid].known_peers[peer_id] = DiscoveredPeer(peer_id)
        if self.config["Overlays"][olid].get("Role", DEFAULT_ROLE).casefold() in (
            "leaf".casefold(),
            ROLES,
        ):
            self.logger.info(
                "The edge request was refused as this is a pendant device."
            )
            edge_cbt.set_response(
                "E6 - Not accepting incoming connections, leaf device", False
            )
            self.complete_cbt(edge_cbt)
            return
        net_ovl = self._net_ovls[olid]
        edge_resp: EdgeResponse = None
        self.logger.debug("Rcvd EdgeRequest=%s", str(edge_req))
        peer_id = edge_req.initiator_id
        if peer_id in net_ovl.adjacency_list:
            edge_resp = self._resolve_request_collision(
                net_ovl, edge_req, net_ovl.adjacency_list[peer_id]
            )
        else:
            edge_resp = self._negotiate_response(net_ovl, edge_req)

        if edge_resp and edge_resp.is_accepted:
            net_ovl.pending_auth_conn_edges[peer_id] = (edge_req, edge_resp)
            if edge_resp.message[:2] != "E0":
                et = transpose_edge_type(edge_req.edge_type)
                ce = ConnectionEdge(
                    peer_id=peer_id,
                    edge_id=edge_req.edge_id,
                    edge_type=et,
                    dataplane=edge_resp.dataplane,
                    role=CONNECTION_ROLE.Target,
                )
                ce.edge_state = EDGE_STATES.PreAuth
                net_ovl.adjacency_list[ce.peer_id] = ce
            self._authorize_incoming_tunnel(
                net_ovl, peer_id, edge_req.edge_id, edge_resp.dataplane, edge_cbt
            )
        else:
            edge_cbt.set_response(edge_resp._asdict(), edge_resp.is_accepted)
            self.complete_cbt(edge_cbt)

    def req_handler_query_known_peers(self, cbt: CBT):
        ovl_peers: dict[str, list[str]] = {}
        if cbt.request.params and "OverlayId" in cbt.request.params:
            olid: str = cbt.request.params["OverlayId"]
            if olid in self._net_ovls:
                ovl_peers[olid] = []
                for peer_id, peer in self._net_ovls[olid].known_peers.items():
                    if peer.is_available:
                        ovl_peers[olid].append(peer_id)
        else:
            for olid in self._net_ovls:
                ovl_peers[olid] = []
                for peer_id, peer in self._net_ovls[olid].known_peers.items():
                    if peer.is_available:
                        ovl_peers[olid].append(peer_id)
        cbt.set_response(ovl_peers, True)
        self.complete_cbt(cbt)

    def resp_handler_auth_tunnel(self, cbt: CBT):
        """Role B2
        LNK auth completed, add the CE to Netbuilder and send response to initiator ie., Role A
        """
        olid = cbt.request.params["OverlayId"]
        peer_id = cbt.request.params["PeerId"]
        if cbt.response.status:
            _, edge_resp = self._net_ovls[olid].pending_auth_conn_edges.pop(peer_id)
        else:
            self._net_ovls[olid].pending_auth_conn_edges.pop(peer_id, None)
            edge_resp = EdgeResponse(
                False, f"E4 - Failed to negotiate tunnel: {cbt.response.data}", None
            )
        nego_cbt = cbt.parent
        self.free_cbt(cbt)
        nego_cbt.set_response(edge_resp._asdict(), edge_resp.is_accepted)
        self.complete_cbt(nego_cbt)

    def resp_handler_remote_action(self, cbt: CBT):
        """Role Node A, initiate edge creation on successful neogtiation"""
        if not cbt.response.status and (
            not cbt.response.data or isinstance(cbt.response.data, str)
        ):
            rem_act = cbt.request.params
            self.logger.info("The remote action timed out %s", cbt)
            olid = rem_act.overlay_id
            ovl = self._net_ovls[olid]
            peer_id = rem_act.recipient_id
            del ovl.adjacency_list[peer_id]
            ovl.known_peers[peer_id].exclude()
            ovl.release()
            self.free_cbt(cbt)
            self._process_next_transition(ovl)
            return

        rem_act = cbt.response.data
        olid = rem_act.overlay_id
        ovl = self._net_ovls[olid]
        if rem_act.action == "TOP_NEGOTIATE_EDGE":
            try:
                self.logger.debug("Recv remote act: %s", rem_act)
                edge_nego = EdgeNegotiate(**rem_act.params, **rem_act.data)
                self._complete_negotiate_edge(ovl, edge_nego)
            except TypeError as excp:
                self.logger.warning("Invalid EdgeNegotiate %s.", excp)
                peer_id = rem_act.recipient_id
                ce = ovl.adjacency_list.get(peer_id)
                if ce and ce.edge_state == EDGE_STATES.PreAuth:
                    ovl.adjacency_list.pop(peer_id)
                ovl.release()
            finally:
                self.free_cbt(cbt)
        else:
            self.logger.warning("Unrecognized remote action %s", rem_act.action)

    def resp_handler_create_tnl(self, cbt: CBT):
        params = cbt.request.params
        olid = params["OverlayId"]
        ovl = self._net_ovls[olid]
        peer_id = params["PeerId"]
        if not cbt.response.status:
            ce = ovl.adjacency_list.get(peer_id)
            if ce is None:
                self.free_cbt(cbt)
                return
            self.logger.warning(
                "Failed to create topology edge to %s. %s", peer_id, cbt.response.data
            )
            ovl.known_peers[peer_id].exclude()
            del ovl.adjacency_list[peer_id]
            ovl.release()
            self._process_next_transition(ovl)
        self.free_cbt(cbt)

    def resp_handler_remove_tnl(self, cbt: CBT):
        params = cbt.request.params
        olid = params["OverlayId"]
        ovl = self._net_ovls[olid]
        peer_id = params["PeerId"]
        ce = ovl.adjacency_list.pop(peer_id, None)
        if not cbt.response.status:
            self.logger.warning(
                "Failed to remove topology edge. Reason: %s", cbt.response.data
            )
        self.free_cbt(cbt)
        ce_state = ""
        if ce:
            ce_state = ce.edge_state
            ce.edge_state = EDGE_STATES.Deleting
            del ce
        if ce_state == EDGE_STATES.Connected:
            ovl.release()
            self._process_next_transition(ovl)

    ################################################################################################

    def _req_handler_manage_topology(self, cbt: Optional[CBT] = None):
        # Periodically refresh the topology, making sure desired links exist and exipred
        # ones are removed.
        for olid in self._net_ovls:
            if (time.time() - self._last_trim_time) >= self._trim_check_interval:
                self._trim_inactive_peers(olid)
            self._update_overlay(olid)
        cbt.set_response(None, True)
        self.complete_cbt(cbt)

    def _trim_inactive_peers(self, olid):
        rmv = []
        for peer_id, peer in self._net_ovls[olid].known_peers.items():
            if peer.is_stale:
                rmv.append(peer_id)
        self.logger.debug("Removing stale peers %s", rmv)
        for peer_id in rmv:
            self._net_ovls[olid].known_peers.pop(peer_id)
        self._last_trim_time = time.time()

    def _update_overlay(self, olid: str):
        ovl = self._net_ovls[olid]
        if not ovl.transformation and ovl.can_acquire:
            ovl.new_peer_count = 0
            ovl_cfg = self.config["Overlays"][olid]
            enf_lnks = ovl_cfg.get("StaticEdges", [])
            peer_list = [
                peer_id
                for peer_id in ovl.known_peers
                if ovl.known_peers[peer_id].is_available
            ]
            if not peer_list:
                return
            min_succ = int(ovl_cfg.get("MinSuccessors", MIN_SUCCESSORS))
            max_ond = int(ovl_cfg.get("MaxOnDemandEdges", MAX_ON_DEMAND_EDGES))
            num_peers = len(peer_list) if len(peer_list) > 1 else 2
            max_ldl = int(
                ovl_cfg.get("MaxLongDistEdges", math.floor(math.log(num_peers + 1, 2)))
            )
            manual_topo = ovl_cfg.get("ManualTopology", False)
            if self.config["Overlays"][olid].get("Role", DEFAULT_ROLE).casefold() in (
                "leaf".casefold(),
                ROLES,
            ):
                manual_topo = True
            params = {
                "OverlayId": olid,
                "NodeId": self.node_id,
                "ManualTopology": manual_topo,
                "StaticEdges": enf_lnks,
                "MinSuccessors": min_succ,
                "MaxLongDistEdges": max_ldl,
                "MaxOnDemandEdges": max_ond,
            }
            gb = GraphBuilder(params, logger=self.logger)
            ovl.transformation = gb.get_transformation(
                peer_list, ovl.get_adj_list(), ovl.ond_peers
            )
        self._process_next_transition(ovl)

    def _process_next_transition(self, net_ovl: NetworkOverlay):
        while net_ovl.transformation and net_ovl.can_acquire:
            # start a new op
            try:
                tns = net_ovl.transformation.head()
                if tns.operation == OP_TYPE.Add:
                    self._initiate_negotiate_edge(net_ovl, tns.conn_edge)
                elif tns.operation == OP_TYPE.Remove:
                    self._initiate_remove_edge(net_ovl, tns.conn_edge.peer_id)
                elif tns.operation == OP_TYPE.Update:
                    self._update_edge(net_ovl, tns.conn_edge)
                else:
                    self.logger.error(
                        "Unexpected transition operation encountered %s", tns.operation
                    )
            except Exception as excp:
                self.logger.warning(str(excp))
            finally:
                net_ovl.transformation.pop()

    ################################################################################################

    def _initiate_negotiate_edge(self, net_ovl: NetworkOverlay, ce: ConnectionEdge):
        """Role A1
        Begin the handshake to negotiate the creation on a new edge between the initiator
        Node A and the recipient Node B
        """
        if ce.peer_id not in net_ovl.adjacency_list:
            ce.edge_state = EDGE_STATES.PreAuth
            net_ovl.adjacency_list[ce.peer_id] = ce
            if net_ovl.is_encr_required:
                dp_types = [DATAPLANE_TYPES.Tincan]
            else:
                dp_types = [DATAPLANE_TYPES.Geneve, DATAPLANE_TYPES.Tincan]

            er = EdgeRequest(
                overlay_id=net_ovl.overlay_id,
                edge_id=ce.edge_id,
                edge_type=ce.edge_type,
                recipient_id=ce.peer_id,
                initiator_id=self.node_id,
                location_id=net_ovl.location_id,
                capability=dp_types,
            )
            edge_params = er._asdict()
            self.logger.info("Initiating %s", er)
            rem_act = RemoteAction(
                net_ovl.overlay_id,
                er.recipient_id,
                "Topology",
                "TOP_NEGOTIATE_EDGE",
                edge_params,
            )
            net_ovl.acquire()
            rem_act.submit_remote_act(self)
            return True
        return False

    def _complete_negotiate_edge(
        self, net_ovl: NetworkOverlay, edge_nego: EdgeNegotiate
    ):
        """Role A2"""
        self.logger.debug("Completing %s", str(edge_nego))
        if edge_nego.recipient_id not in net_ovl.adjacency_list:
            self.logger.warning(
                "The peer specified in edge negotiation %s is not in current "
                "adjacency  list. The request has been discarded."
            )
            return
        peer_id = edge_nego.recipient_id
        edge_id = edge_nego.edge_id
        ce = net_ovl.adjacency_list[edge_nego.recipient_id]
        if not edge_nego.is_accepted:
            # if E2 (request superceeded) do nothing here. The corresponding CE instance will
            # be converted in resolve_collision_request(). If E1, the request is outdate, just
            # discard.
            if not edge_nego.message[:2] in ("E1", "E2"):
                ce.edge_state = EDGE_STATES.Deleting
                del net_ovl.adjacency_list[ce.peer_id]
            net_ovl.known_peers[peer_id].exclude()
            net_ovl.release()  # release on explicit negotiate fail
            self._process_next_transition(net_ovl)
        else:
            if ce.edge_state != EDGE_STATES.PreAuth:
                self.logger.warning(
                    "The following EdgeNegotiate cannot be completed as the "
                    "current state of it's conn edge is invalid for this "
                    "operation. The request has been discarded. "
                    "ce=%s, edge_nego=%s",
                    ce,
                    edge_nego,
                )
                return
            ce.edge_state = EDGE_STATES.Authorized
            if net_ovl.is_encr_required and edge_nego.dataplane not in [
                DATAPLANE_TYPES.Tincan,
            ]:
                self.logger.error(
                    "The negotiated dataplane violates the scope of what was requested."
                    " The transaction has been discarded. %s",
                    edge_nego,
                )
                ce.edge_state = EDGE_STATES.Deleting
                del net_ovl.adjacency_list[ce.peer_id]
                net_ovl.known_peers[peer_id].exclude()
                net_ovl.release()  # release on explicit negotiate fail
                self._process_next_transition(net_ovl)
                return
            ce.dataplane = edge_nego.dataplane
            self._create_tunnel(net_ovl, ce.dataplane, peer_id, edge_id)

    def _authorize_incoming_tunnel(
        self,
        net_ovl: NetworkOverlay,
        peer_id: str,
        edge_id: str,
        dataplane: DataplaneTypes,
        neg_edge_cbt: CBT,
    ):
        """->Role B1"""
        self.logger.info(
            "Authorizing peer edge %s from %s:%s->%s",
            edge_id,
            net_ovl.overlay_id,
            peer_id[:7],
            self.node_id[:7],
        )
        params = {
            "OverlayId": net_ovl.overlay_id,
            "PeerId": peer_id,
            "TunnelId": edge_id,
        }
        cbt = self.create_linked_cbt(neg_edge_cbt)
        if dataplane == DATAPLANE_TYPES.Geneve:
            cbt.set_request(self.name, "GeneveTunnel", "GNV_AUTH_TUNNEL", params)
        elif dataplane == DATAPLANE_TYPES.Tincan:
            cbt.set_request(self.name, "LinkManager", "LNK_AUTH_TUNNEL", params)
        self.submit_cbt(cbt)

    def _resolve_request_collision(
        self, net_ovl: NetworkOverlay, edge_req: EdgeRequest, conn_edge: ConnectionEdge
    ):
        """An connection edge was already initiated by this node so resolve the collision"""
        edge_state: EdgeStates = conn_edge.edge_state
        edge_resp: EdgeResponse = None
        dp_type = self._select_tunnel_type(net_ovl, edge_req)
        if edge_state in (EDGE_STATES.Authorized, EDGE_STATES.Connected):
            # Likely a duplicated Remote Action from Signal
            if conn_edge.edge_id == edge_req.edge_id:
                msg = f"E1 - A valid matching edge already exists: {conn_edge.edge_id[:7]}"
                edge_resp = EdgeResponse(is_accepted=False, message=msg, dataplane=None)
            else:
                msg = (
                    f"E7 - An existing {conn_edge.edge_state} edge with id "
                    f"{conn_edge.edge_id[:7]} already exist"
                )
                edge_resp = EdgeResponse(is_accepted=False, message=msg, dataplane=None)
        elif (
            edge_state in (EDGE_STATES.Initialized, EDGE_STATES.PreAuth)
            and self.node_id < edge_req.initiator_id
        ):
            msg = f"E2 - Node {self.node_id} superceeds edge request due to collision, "
            "edge={net_ovl.adjacency_list[peer_id].edge_id[:7]}"
            edge_resp = EdgeResponse(is_accepted=False, message=msg, dataplane=dp_type)
        elif (
            edge_state in (EDGE_STATES.Initialized, EDGE_STATES.PreAuth)
            and self.node_id > edge_req.initiator_id
        ):
            conn_edge.edge_type = transpose_edge_type(edge_req.edge_type)
            conn_edge.role = CONNECTION_ROLE.Target
            conn_edge.edge_id = edge_req.edge_id
            conn_edge.dataplane = dp_type
            msg = f"E0 - Node {self.node_id} accepts edge collision override."
            " CE:{conn_edge.edge_id[:7]} remapped -> edge:{edge_req.edge_id[:7]}"
            edge_resp = EdgeResponse(is_accepted=True, message=msg, dataplane=dp_type)
        else:
            edge_resp = EdgeResponse(
                False,
                "E6 - Request colides with an edge being destroyed. Try later",
                dataplane=dp_type,
            )
        return edge_resp

    def _negotiate_response(self, net_ovl: NetworkOverlay, edge_req: EdgeRequest):
        """Role B1"""
        edge_resp: EdgeResponse = None
        dp_type = self._select_tunnel_type(net_ovl, edge_req)

        if edge_req.edge_type == "CETypeSuccessor":
            edge_resp = EdgeResponse(
                is_accepted=True, message="Successor edge permitted", dataplane=dp_type
            )
        elif edge_req.edge_type == "CETypeStatic":
            edge_resp = EdgeResponse(
                is_accepted=True, message="Static edge permitted", dataplane=dp_type
            )
        elif edge_req.edge_type == "CETypeOnDemand":
            edge_resp = EdgeResponse(
                is_accepted=True, message="On-demand edge permitted", dataplane=dp_type
            )
        elif not net_ovl.adjacency_list.is_threshold(EDGE_TYPE_IN.ILongDistance):
            edge_resp = EdgeResponse(
                is_accepted=True, message="Any edge permitted", dataplane=dp_type
            )
        else:
            edge_resp = EdgeResponse(
                is_accepted=False,
                message="E5 - Too many existing edges.",
                dataplane=None,
            )
        return edge_resp

    def _select_tunnel_type(
        self, net_ovl: NetworkOverlay, edge_req: EdgeRequest
    ) -> DATAPLANE_TYPES:
        dp_type = DATAPLANE_TYPES.Tincan
        if (
            edge_req.location_id is not None
            and edge_req.location_id == net_ovl.location_id
        ):
            if (
                DATAPLANE_TYPES.Geneve in edge_req.capability
                and not net_ovl.is_encr_required
            ):
                dp_type = DATAPLANE_TYPES.Geneve
        return dp_type

    ################################################################################################
    def _create_tunnel(
        self,
        net_ovl: NetworkOverlay,
        dataplane: DataplaneTypes,
        peer_id: str,
        tunnel_id: str,
    ):
        params = {
            "OverlayId": net_ovl.overlay_id,
            "PeerId": peer_id,
            "TunnelId": tunnel_id,
        }
        if dataplane == DATAPLANE_TYPES.Geneve:
            params["VNId"] = self.config["Overlays"][net_ovl.overlay_id].get(
                "LocationId"
            )
            self.register_cbt("GeneveTunnel", "GNV_CREATE_TUNNEL", params)
        elif dataplane == DATAPLANE_TYPES.Tincan:
            self.register_cbt("LinkManager", "LNK_CREATE_TUNNEL", params)
        else:
            self.logger.warning(
                "Create tunnel request failed, due to invalid tunnel type %s", dataplane
            )

    def _initiate_remove_edge(self, net_ovl: NetworkOverlay, peer_id: str) -> bool:
        if peer_id not in net_ovl.adjacency_list:
            return False
        ce = net_ovl.adjacency_list[peer_id]
        if (
            ce.edge_state == EDGE_STATES.Connected
            and ce.edge_type in EDGE_TYPE_OUT
            and time.time() - ce.connected_time >= Topology._EDGE_PROTECTION_AGE
        ):
            if (
                ce.edge_type == EDGE_TYPE_OUT.Successor
                and net_ovl.adjacency_list.is_threshold(
                    EDGE_TYPE_OUT.Successor
                )  # succ threshold -> at/below the min required
            ):
                return False
            self.logger.info("Removing edge %s", ce)
            net_ovl.acquire()
            self._remove_tunnel(net_ovl, ce.dataplane, ce.peer_id, ce.edge_id)
            return True
        return False

    def _remove_tunnel(
        self,
        net_ovl: NetworkOverlay,
        dataplane: DataplaneTypes,
        peer_id: str,
        tunnel_id: str,
    ):
        params = {
            "OverlayId": net_ovl.overlay_id,
            "PeerId": peer_id,
            "TunnelId": tunnel_id,
        }
        if dataplane == DATAPLANE_TYPES.Geneve:
            self.register_cbt("GeneveTunnel", "GNV_REMOVE_TUNNEL", params)
        elif dataplane == DATAPLANE_TYPES.Tincan:
            self.register_cbt("LinkManager", "LNK_REMOVE_TUNNEL", params)
        else:
            msg = (
                f"Remove tunnel {tunnel_id} failed, invalid dataplane type {dataplane}"
            )
            self.logger.error(msg)
            raise RuntimeError(msg)

    def _update_edge(
        self, net_ovl: NetworkOverlay, new_conn_edge: ConnectionEdge
    ) -> bool:
        if new_conn_edge.peer_id not in net_ovl.adjacency_list:
            return False
        ce = net_ovl.adjacency_list[new_conn_edge.peer_id]
        if ce.edge_state != EDGE_STATES.Connected:
            return False
        self.logger.debug("Updating conn edge %s to %s", ce, new_conn_edge)
        net_ovl.adjacency_list.update_edge(new_conn_edge)
        return False
