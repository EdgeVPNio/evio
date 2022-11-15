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
from random import randint
import threading
import time
from copy import deepcopy
from collections import namedtuple
from datetime import datetime
from framework.CFx import CFX
from framework.ControllerModule import ControllerModule
from framework.Modlib import RemoteAction
from .NetworkGraph import ConnectionEdge, ConnEdgeAdjacenctList, GraphTransformation
from .NetworkGraph import EdgeStates, EdgeTypesOut, EdgeTypesIn, OpType, transpose_edge_type
from .GraphBuilder import GraphBuilder
from .Tunnel import TunnelEvents, DataplaneTypes

MinSuccessors = 2
MaxOnDemandEdges = 3
PeerDiscoveryCoalesce = 1
ExclusionBaseInterval = 60
MaxSuccessiveFails = 4
TrimCheckInterval = 300
MaxConcurrentOps = 1
SuccessiveFailsIncr = 1
SuccessiveFailsDecr = 2
StaleInterval = float(2 * 3600)  # 2 hrs
DefaultRole = "Switch"

EdgeRequest = namedtuple("EdgeRequest",
                         ["overlay_id", "edge_id", "edge_type", "initiator_id",
                          "recipient_id", "location_id", "capability"])

EdgeResponse = namedtuple("EdgeResponse",
                          ["is_accepted", "message", "dataplane"])

EdgeNegotiate = namedtuple("EdgeNegotiate",
                           [*EdgeRequest._fields, *EdgeResponse._fields])

class DiscoveredPeer():
    def __init__(self, peer_id, **kwargs):
        self.peer_id = peer_id
        self.is_banned = False  # bars conn attempts from local node, the peer can still recon
        self.successive_fails = 0
        self.available_time = time.time()
        self.last_checkin = self.available_time

    def __repr__(self):
        items = (f"\"{k}\": {v!r}" for k, v in self.__dict__.items())
        return "{{{}}}".format(", ".join(items))

    def exclude(self):
        self.successive_fails += SuccessiveFailsIncr
        self.available_time = (randint(1, 4) * ExclusionBaseInterval *
                               self.successive_fails) + time.time()
        if self.successive_fails >= MaxSuccessiveFails:
            self.is_banned = True

    def restore(self):
        self.is_banned = False
        self.successive_fails = 0

    def presence(self):
        self.available_time = time.time()
        self.last_checkin = self.available_time
        if self.is_banned and self.successive_fails <= 0:
            self.restore()
        elif self.is_banned and self.successive_fails > 0:
            self.successive_fails -= SuccessiveFailsDecr

    @property
    def is_stale(self):
        return bool(time.time() - self.last_checkin >= StaleInterval)

    @property
    def is_available(self):
        return bool((not self.is_banned)  # successive_fails < max_successive_fails
                    # the falloff wait period is over
                    and (time.time() >= self.available_time)
                    and (time.time() - self.last_checkin < StaleInterval - 600))  # 10 mins before a node is stale


class NetworkOverlay():
    _REFLECT = set(["_max_concurrent_edits", "_refc", "node_id", "overlay_id",
                    "new_peer_count", "_graph_transformation", "known_peers",
                    "pending_auth_conn_edges", "ond_peers", "adjacency_list", "_loc_id", "_encr_req"])

    def __init__(self, node_id, overlay_id, **kwargs):
        # used to limit number of concurrent operations initiated
        self._max_concurrent_edits = kwargs.get(
            "MaxConcurrentOps", MaxConcurrentOps)
        self._refc = self._max_concurrent_edits
        self.node_id = node_id
        self.overlay_id = overlay_id
        self.logger = kwargs["Logger"]
        self.new_peer_count = 0
        self._graph_transformation = None
        self.transformation: GraphTransformation = None
        self.known_peers: dict[str, DiscoveredPeer] = {}
        self.pending_auth_conn_edges: dict[str, tuple] = {}
        self.ond_peers = []
        self.adjacency_list = ConnEdgeAdjacenctList(overlay_id, node_id)
        self._loc_id = kwargs.get("LocationId")
        self._encr_req = kwargs.get("EncryptionRequired", False)

    def __repr__(self):
        items = set()
        if hasattr(self, "_REFLECT"):
            for k in self._REFLECT:
                items.add(f"\"{k}\": {self.__dict__[k]!r}")
        return "{{{}}}".format(", ".join(items))

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
        Transitions the overlay network overlay to the desired state specified by network transition ops.
        """
        self.logger.debug("New transformation: %s", str(new_transformation))
        assert not self.transformation, "Graph transformation is not empty"

        if new_transformation and not self.transformation:
            self._graph_transformation = new_transformation
            self.adjacency_list.min_successors = new_transformation.min_successors
            self.adjacency_list.max_long_distance = new_transformation.max_long_distance
            self.adjacency_list.max_ondemand = new_transformation.max_ondemand

    def acquire(self):
        assert self._refc > 0, "Reference count at zero, cannot acquire"
        self._refc -= 1

    def release(self):
        assert self._refc < self._max_concurrent_edits, "Reference count at maximum, invalid attempt to release"
        self._refc += 1

    @property
    def is_idle(self):
        """Is the current transition operation completed"""
        assert self._refc >= 0 or self._refc <= self._max_concurrent_edits, f"Invalid reference count {self._refc}"
        return self._refc == self._max_concurrent_edits

    def get_adj_list(self):
        return deepcopy(self.adjacency_list)


class Topology(ControllerModule, CFX):

    _DEL_RETRY_INTERVAL = 10
    _EDGE_PROTECTION_AGE = 180
    _REFLECT = set(["_net_ovls"])

    def __init__(self, cfx_handle, module_config, module_name):
        super(Topology, self).__init__(cfx_handle, module_config, module_name)
        self._net_ovls = {}
        self._lock = threading.Lock()
        self._last_trim_time = time.time()
        self._trim_check_interval = self.config.get(
            "TrimCheckInterval", TrimCheckInterval)

    def initialize(self):
        publishers = self.get_registered_publishers()
        if "Signal" not in publishers or "SIG_PEER_PRESENCE_NOTIFY" not in self.get_available_subscriptions("Signal"):
            raise RuntimeError(
                "The Signal PEER PRESENCE subscription is not available. Topology cannot continue.")
        self.start_subscription("Signal", "SIG_PEER_PRESENCE_NOTIFY")
        if "LinkManager" not in publishers or "LNK_TUNNEL_EVENTS" not in self.get_available_subscriptions("LinkManager"):
            raise RuntimeError(
                "The LinkManager TUNNEL EVENTS subscription is not available. Topology cannot continue.")
        self.start_subscription("LinkManager", "LNK_TUNNEL_EVENTS")
        if "GeneveTunnel" in publishers and "GNV_TUNNEL_EVENTS" in self.get_available_subscriptions("GeneveTunnel"):
            self.start_subscription("GeneveTunnel", "GNV_TUNNEL_EVENTS")
        else:
            self.logger.warning("Geneve tunnel capability unavailable")
        for olid in self.overlays:
            self._net_ovls[olid] = NetworkOverlay(self.node_id, olid,
                                                  Logger=self.logger,
                                                  LocationId=self.config["Overlays"][olid].get(
                                                      "LocationId"),
                                                  EncryptionRequired=self.config["Overlays"][olid].get("EncryptionRequired"))
        # Subscribe for data request notifications from OverlayVisualizer
        if "OverlayVisualizer" in publishers and "VIS_DATA_REQ" in self.get_available_subscriptions("OverlayVisualizer"):
            self.start_subscription("OverlayVisualizer", "VIS_DATA_REQ")
        else:
            self.logger.info("Overlay visualizer capability unavailable")
        self.logger.info("Module loaded")

    def terminate(self):
        pass

    def process_cbt(self, cbt):
        with self._lock:
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
                else:
                    self.logger.debug("No action matched for CBT response")
                    parent_cbt = cbt.parent
                    cbt_data = cbt.response.data
                    cbt_status = cbt.response.status
                    self.free_cbt(cbt)
                    if (parent_cbt is not None and parent_cbt.child_count == 1):
                        parent_cbt.set_response(cbt_data, cbt_status)
                        self.complete_cbt(parent_cbt)

    def timer_method(self):
        with self._lock:
            self._manage_topology()

    def req_handler_peer_presence(self, cbt):
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
            if self._net_ovls[olid].new_peer_count >= self.config.get("PeerDiscoveryCoalesce", PeerDiscoveryCoalesce):
                self.logger.debug("Overlay:%s new peer %s discovered - Coalesced %s of %s, "
                                  "attempting overlay update",
                                  olid, peer_id, self._net_ovls[olid].new_peer_count,
                                  self.config.get("PeerDiscoveryCoalesce", PeerDiscoveryCoalesce))
                self._update_overlay(olid)
            else:
                self.logger.info("Overlay:%s, new peers %s discovered - Coalesced %s of %s, "
                                 "delaying overlay update",
                                 olid, peer_id, self._net_ovls[olid].new_peer_count,
                                 self.config.get("PeerDiscoveryCoalesce", PeerDiscoveryCoalesce))
        cbt.set_response(None, True)
        self.complete_cbt(cbt)

    def req_handler_vis_data(self, cbt):
        topo_data = {}
        try:
            for olid in self._net_ovls:
                topo_data[olid] = {}
                adjl = self._net_ovls[olid].adjacency_list
                for k in adjl:
                    ce = adjl[k]
                    ced = {"PeerId": ce.peer_id,
                           "CreatedTime": ce.created_time,
                           "ConnectedTime": ce.connected_time,
                           "State": ce.edge_state, "Type": ce.edge_type}
                    topo_data[olid][ce.edge_id] = ced
            cbt.set_response({"Topology": topo_data}, bool(topo_data))
            self.complete_cbt(cbt)
        except KeyError:
            cbt.set_response(data=None, status=False)
            self.complete_cbt(cbt)
            self.log("LOG_WARNING", "Topology data not available %s",
                     cbt.response.data)
            
    def _process_tnl_event(self, update):
        event = update["UpdateType"]
        peer_id = update["PeerId"]
        overlay_id = update["OverlayId"]        
        ovl = self._net_ovls[overlay_id]
        if event == TunnelEvents.Authorized:
            """ Role B """
            ce = ovl.adjacency_list[peer_id]
            assert ce.edge_state == EdgeStates.PreAuth, f"Invalid edge state {ce}"
            ce.edge_state = EdgeStates.Authorized
        elif event == TunnelEvents.AuthExpired:
            """ Role B """
            ce = ovl.adjacency_list[peer_id]
            assert ce.edge_state == EdgeStates.Authorized, f"Invalid edge state {ce}"
            ce.edge_state = EdgeStates.Deleting
            del ovl.adjacency_list[peer_id]
            # ToDo: if peer_id in ovl.known_peers:
            ovl.known_peers[peer_id].exclude()
            self.logger.debug("Excluding peer %s until %s", peer_id,
                              str(datetime.fromtimestamp(
                                  ovl.known_peers[peer_id].available_time)))
        elif event == TunnelEvents.Created:
            """Roles A & B"""
            ce = ovl.adjacency_list[peer_id]
            assert ce.edge_state == EdgeStates.Authorized, f"Invalid edge state {ce}"
            ce.edge_state = EdgeStates.Created
        elif event == TunnelEvents.Connected:
            """Roles A & B"""
            ce = ovl.adjacency_list[peer_id]
            assert ce.edge_state == EdgeStates.Created, f"Invalid edge state {ce}"
            ce.edge_state = EdgeStates.Connected
            ce.connected_time = update["ConnectedTimestamp"]
            ovl.known_peers[peer_id].restore()
            if ce.edge_type in EdgeTypesOut:
                ovl.release()
                self._process_next_transition(ovl)
        elif event == TunnelEvents.Disconnected:
            ce = ovl.adjacency_list[peer_id]
            assert ce.edge_state in (
                EdgeStates.Created, EdgeStates.Connected), f"Invalid edge state {ce}"
            # the local topology did not request removal of the connection
            if (ce.edge_state == EdgeStates.Created) or \
                    (time.time() - ce.connected_time < Topology._EDGE_PROTECTION_AGE and peer_id in ovl.known_peers):
                ovl.known_peers[peer_id].exclude()
            ce.edge_state = EdgeStates.Disconnected
            self._remove_tunnel(ovl, ce.dataplane, peer_id, ce.edge_id)
        elif event == TunnelEvents.Removed:
            """Roles A & B"""
            ce = ovl.adjacency_list.get(peer_id)
            del ovl.adjacency_list[peer_id]
            if ce is not None and ce.edge_state == EdgeStates.Connected:  # topo initiated the removal
                ovl.release()
                self._process_next_transition(ovl)
            elif ce is not None and ce.edge_state == EdgeStates.Disconnected:  # the peer disconnected
                ce.edge_state = EdgeStates.Deleting
            else:
                self.logger.error(
                    "Tunnel event remove is unexpected for conn edge %s", ce)
        else:
            self.logger.warning(
                "Invalid UpdateType specified for event %s", event)
        
    def req_handler_tunnl_update(self, cbt):
        event = cbt.request.params
        self._process_tnl_event(event)
        cbt.set_response(None, True)
        self.complete_cbt(cbt)

    def req_handler_req_ond_tunnels(self, cbt):
        """
        Add the request params for creating an on demand tunnel
        overlay_id, peer_id, ADD/REMOVE op string
        """
        for op in cbt.request.params:
            olid = op["OverlayId"]
            peer_id = op["PeerId"]
            if olid in self._net_ovls:
                ovl = self._net_ovls[olid]
                if (op["Operation"] == "REMOVE" or
                    (op["Operation"] == "ADD" and
                     peer_id in ovl.known_peers and
                     ovl.known_peers[peer_id].is_available)):
                    ovl.ond_peers.append(op)
                    self.log(
                        "LOG_DEBUG", "Added on-demand tunnel request to queue %s", op)
                elif op["Operation"] == "DISCONN":
                    if peer_id in ovl.adjacency_list:
                        self._process_tnl_event({"UpdateType": TunnelEvents.Disconnected,
                                                "OverlayId": olid, "PeerId": peer_id})
                    else:
                         self.logger.warning(
                         "The requested OND_DISCONN edge does not exist, peer_id=%s",
                         peer_id)
                else:
                    self.logger.warning("Invalid OND operation requested %s", op["Operation"])
            else:
                self.logger.warning("Invalid on-demand tunnel request parameter, OverlayId=%s",
                                    olid)

    def req_handler_negotiate_edge(self, edge_cbt):
        """ Role B1, decide if the request for an incoming edge is accepted or rejected """
        edge_req = EdgeRequest(**edge_cbt.request.params)
        olid = edge_req.overlay_id
        if olid not in self.config["Overlays"]:
            self.log("LOG_WARNING",
                     "The requested overlay is not specified in "
                     "local config, the edge request is discarded")
            edge_cbt.set_response(
                "Unknown overlay id specified in edge request", False)
            self.complete_cbt(edge_cbt)
            return
        peer_id = edge_req.initiator_id
        if peer_id not in self._net_ovls[olid].known_peers:
            # this node miss the presence notification, so add to KnownPeers
            self._net_ovls[olid].known_peers[peer_id] = DiscoveredPeer(
                peer_id)
        if self.config["Overlays"][olid].get("Role", DefaultRole).casefold() == "leaf".casefold():
            self.log("LOG_INFO", "Rejected edge negotiation, "
                     "this leaf device is not accepting edge requests")
            edge_cbt.set_response(
                "E6 - Not accepting incoming connections, leaf device", False)
            self.complete_cbt(edge_cbt)
            return
        net_ovl = self._net_ovls[olid]
        edge_resp: EdgeResponse = None
        self.logger.debug("Rcvd EdgeRequest=%s", str(edge_req))
        peer_id = edge_req.initiator_id
        if peer_id in net_ovl.adjacency_list:
            edge_resp = self._resolve_request_collision(
                net_ovl, edge_req, net_ovl.adjacency_list[peer_id])
        else:
            edge_resp = self._negotiate_response(net_ovl, edge_req)

        if edge_resp and edge_resp.is_accepted:
            net_ovl.pending_auth_conn_edges[peer_id] = (edge_req, edge_resp)
            if edge_resp.message[:2] != "E0":
                et = transpose_edge_type(edge_req.edge_type)
                ce = ConnectionEdge(
                    peer_id=peer_id, edge_id=edge_req.edge_id, edge_type=et,
                    dataplane=edge_resp.dataplane)
                ce.edge_state = EdgeStates.PreAuth
                net_ovl.adjacency_list[ce.peer_id] = ce
            self._authorize_incoming_tunnel(net_ovl, peer_id, edge_req.edge_id,
                                            edge_resp.dataplane, edge_cbt)
        else:
            edge_cbt.set_response(edge_resp, edge_resp.is_accepted)
            self.complete_cbt(edge_cbt)

    def req_handler_query_known_peers(self, cbt):
        peer_list = {}
        for olid in self._net_ovls:
            if not olid in peer_list:
                peer_list[olid] = []
            for peer_id, peer in self._net_ovls[olid].known_peers.items():
                if peer.is_available:
                    peer_list[olid].append(peer_id)
        cbt.set_response(peer_list, True)
        self.complete_cbt(cbt)

    def resp_handler_auth_tunnel(self, cbt):
        """ Role B
            LNK auth completed, add the CE to Netbuilder and send response to initiator ie., Role A
        """
        olid = cbt.request.params["OverlayId"]
        peer_id = cbt.request.params["PeerId"]
        if cbt.response.status:
            _, edge_resp = self._net_ovls[olid].pending_auth_conn_edges.pop(
                peer_id)
        else:
            self._net_ovls[olid].pending_auth_conn_edges.pop(peer_id, None)
            edge_resp = EdgeResponse(False,
                                     f"E4 - Failed to negotiate tunnel: {cbt.response.data}",
                                     None)
        nego_cbt = cbt.parent
        self.free_cbt(cbt)
        nego_cbt.set_response(edge_resp, edge_resp.is_accepted)
        self.complete_cbt(nego_cbt)

    def resp_handler_remote_action(self, cbt):
        """ Role Node A, initiate edge creation on successful neogtiation """
        if not cbt.response.status and (not cbt.response.data or type(cbt.response.data) == str):
            rem_act = RemoteAction.request(cbt)
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

        rem_act = RemoteAction.response(cbt)
        olid = rem_act.overlay_id
        ovl = self._net_ovls[olid]
        if olid not in self.config["Overlays"]:
            self.log("LOG_WARNING", "The specified overlay is not in the"
                     "local config, the rem act response is discarded")
            self.free_cbt(cbt)
            return

        if rem_act.action == "TOP_NEGOTIATE_EDGE":
            edge_nego = EdgeNegotiate(**rem_act.params,
                                      **rem_act.data)
            self._complete_negotiate_edge(ovl, edge_nego)
            self.free_cbt(cbt)
        else:
            self.logger.warning("Unrecognized remote action %s",
                                rem_act.action)

    def resp_handler_create_tnl(self, cbt):
        params = cbt.request.params
        olid = params["OverlayId"]
        ovl = self._net_ovls[olid]
        peer_id = params["PeerId"]
        if not cbt.response.status:
            ce = ovl.adjacency_list.get(peer_id)
            if ce is None:
                self.free_cbt(cbt)
                return
            if ce.edge_state == EdgeStates.Connected:
                self.logger.warning("Response failed but tunnel to %s is connected - preserving tunnel. %s",
                                    peer_id, cbt.response.data)
            else:
                self.logger.warning("Failed to create topology edge to %s. %s",
                                    peer_id, cbt.response.data)
                ovl.known_peers[peer_id].exclude()
                del ovl.adjacency_list[peer_id]
                ovl.release()
                self._process_next_transition(ovl)
        self.free_cbt(cbt)

    def resp_handler_remove_tnl(self, cbt):
        params = cbt.request.params
        olid = params["OverlayId"]
        ovl = self._net_ovls[olid]
        peer_id = params["PeerId"]
        if not cbt.response.status:
            self.logger.warning(
                "Failed to remove topology edge. Reason: %s", cbt.response.data)
            ovl.release()
            self._process_next_transition(ovl)
        self.free_cbt(cbt)
###################################################################################################

    def _manage_topology(self):
        # Periodically refresh the topology, making sure desired links exist and exipred
        # ones are removed.
        for olid in self._net_ovls:
            if (time.time() - self._last_trim_time) >= self._trim_check_interval:
                self._trim_inactive_peers(olid)
            self._update_overlay(olid)

    def _trim_inactive_peers(self, olid):
        rmv = []
        for peer_id, peer in self._net_ovls[olid].known_peers.items():
            if peer.is_stale:
                rmv.append(peer_id)
        self.logger.debug(f"Removing stale peers {rmv}")
        for peer_id in rmv:
            self._net_ovls[olid].known_peers.pop(peer_id)
        self._last_trim_time = time.time()

    def _update_overlay(self, olid):
        ovl = self._net_ovls[olid]
        if not ovl.transformation and ovl.is_idle:
            ovl.new_peer_count = 0
            ovl_cfg = self.config["Overlays"][olid]
            enf_lnks = ovl_cfg.get("StaticEdges", [])
            peer_list = [peer_id for peer_id in ovl.known_peers
                         if ovl.known_peers[peer_id].is_available]
            if not peer_list:
                return
            min_succ = int(ovl_cfg.get("MinSuccessors", MinSuccessors))
            max_ond = int(ovl_cfg.get("MaxOnDemandEdges", MaxOnDemandEdges))
            num_peers = len(peer_list) if len(peer_list) > 1 else 2
            max_ldl = int(ovl_cfg.get("MaxLongDistEdges",
                          math.floor(math.log(num_peers+1, 2))))
            manual_topo = ovl_cfg.get("ManualTopology", False)
            if self.config["Overlays"][olid].get("Role", DefaultRole).casefold() == \
                    "leaf".casefold():
                manual_topo = True
            params = {"OverlayId": olid, "NodeId": self.node_id, "ManualTopology": manual_topo,
                      "StaticEdges": enf_lnks, "MinSuccessors": min_succ,
                      "MaxLongDistEdges": max_ldl, "MaxOnDemandEdges": max_ond}
            gb = GraphBuilder(params, top=self)
            ovl.transformation = gb.get_transformation(peer_list,
                                                       ovl.get_adj_list(),
                                                       ovl.ond_peers)
        self._process_next_transition(ovl)

    def _process_next_transition(self, net_ovl):
        suspend = False
        while not suspend:  # was the edit discarded?
            suspend = True
            if net_ovl.transformation and net_ovl.is_idle:  # start a new op
                tns = net_ovl.transformation.head()
                if tns.operation == OpType.Add:
                    suspend = self._initiate_negotiate_edge(
                        net_ovl, tns.conn_edge)
                elif tns.operation == OpType.Remove:
                    suspend = self._initiate_remove_edge(
                        net_ovl, tns.conn_edge.peer_id)
                elif tns.operation == OpType.Update:
                    suspend = self._update_edge(net_ovl, tns.conn_edge)
                else:
                    self.logger.error(
                        "Unexpected transition operation encountered %s", tns.operation)
                net_ovl.transformation.pop()
###################################################################################################

    def _initiate_negotiate_edge(self, net_ovl, ce):
        """ Role A1
        Begin the handshake to negotiate the creation on a new edge between the initiator
        Node A and the recipient Node B
        """
        if ce.peer_id not in net_ovl.adjacency_list:
            ce.edge_state = EdgeStates.PreAuth
            net_ovl.adjacency_list[ce.peer_id] = ce
            if net_ovl.is_encr_required:
                dp_types = [DataplaneTypes.WireGuard,
                                DataplaneTypes.Tincan]
            else:
                dp_types = [DataplaneTypes.Geneve,
                                DataplaneTypes.Tincan]

            er = EdgeRequest(overlay_id=net_ovl.overlay_id, edge_id=ce.edge_id,
                             edge_type=ce.edge_type, recipient_id=ce.peer_id,
                             initiator_id=self.node_id,
                             location_id=net_ovl.location_id,
                             capability=dp_types)
            edge_params = er._asdict()
            self.logger.debug("Negotiating %s", er)
            rem_act = RemoteAction(net_ovl.overlay_id, er.recipient_id,
                                   "Topology", "TOP_NEGOTIATE_EDGE", edge_params)
            net_ovl.acquire()
            rem_act.submit_remote_act(self)
            return True
        return False

    def _authorize_incoming_tunnel(self, net_ovl, peer_id, edge_id, dataplane, neg_edge_cbt):

        self.logger.info("Authorizing peer edge %s from %s:%s->%s",
                         edge_id, net_ovl.overlay_id, peer_id[:7], self.node_id[:7])
        params = {"OverlayId": net_ovl.overlay_id,
                  "PeerId": peer_id, "TunnelId": edge_id}
        cbt = self.create_linked_cbt(neg_edge_cbt)
        if dataplane == DataplaneTypes.Geneve:
            cbt.set_request(self.module_name, "GeneveTunnel",
                            "GNV_AUTH_TUNNEL", params)
        elif dataplane == DataplaneTypes.WireGuard:
            cbt.set_request(self.module_name, "WireGuard",
                            "WGD_AUTH_TUNNEL", params)
        else:
            cbt.set_request(self.module_name, "LinkManager",
                            "LNK_AUTH_TUNNEL", params)
        self.submit_cbt(cbt)

    def _complete_negotiate_edge(self, net_ovl, edge_nego):
        """ Role A2 """
        self.logger.debug("Completing %s", str(edge_nego))
        if edge_nego.recipient_id not in net_ovl.adjacency_list:
            self.logger.warning("The peer specified in edge negotiation %s is not in current "
                                "adjacency  list. The request has been discarded.")
            return
        peer_id = edge_nego.recipient_id
        edge_id = edge_nego.edge_id
        ce = net_ovl.adjacency_list[edge_nego.recipient_id]
        if not edge_nego.is_accepted:
            # if E2 (request superceeded) do nothing here. The corresponding CE instance will
            # be converted in resolve_collision_request(). If E1, the request is outdate, just
            # discard.
            if not edge_nego.message[:2] in ("E1", "E2"):
                ce.edge_state = EdgeStates.Deleting
                del net_ovl.adjacency_list[ce.peer_id]
            # ToDo: if peer_id in net_ovl.known_peers:
            net_ovl.known_peers[peer_id].exclude()
            net_ovl.release()  # release on explicit negotiate fail
            self._process_next_transition(net_ovl)
        else:
            if ce.edge_state != EdgeStates.PreAuth:
                self.logger.warning("The following EdgeNegotiate cannot be completed as the "
                                    "current state of it's conn edge is invalid for this "
                                    "operation. The request has been discarded. "
                                    "ce=%s, edge_nego=%s", ce, edge_nego)
                return
            if ce.edge_id != edge_nego.edge_id:


                return
            ce.edge_state = EdgeStates.Authorized
            if (net_ovl.is_encr_required and 
                edge_nego.dataplane not in [DataplaneTypes.WireGuard, DataplaneTypes.Tincan]):
                self.logger.error("The negotiated dataplane violates the scope of what was requested."
                                  " The transaction has been discarded. %s", edge_nego)
                ce.edge_state = EdgeStates.Deleting
                del net_ovl.adjacency_list[ce.peer_id]
                net_ovl.known_peers[peer_id].exclude()
                net_ovl.release()  # release on explicit negotiate fail
                self._process_next_transition(net_ovl)
                return
            ce.dataplane = edge_nego.dataplane
            self._create_tunnel(
                net_ovl, ce.dataplane, peer_id, edge_id)

    def _resolve_request_collision(self, net_ovl, edge_req, conn_edge):
        """ An connection edge was already initiated by this node so resolve the collision """
        peer_id = edge_req.initiator_id
        edge_state = conn_edge.edge_state
        edge_resp = None
        dp_type = self._select_tunnel_type(net_ovl, edge_req)
        if edge_state in (EdgeStates.Authorized, EdgeStates.Connected):
            # Likely a duplicated Remote Action from Signal
            if conn_edge.edge_id == edge_req.edge_id:
                msg = f"E1 - A valid matching edge already exists: {conn_edge.edge_id[:7]}"
                edge_resp = EdgeResponse(
                    is_accepted=False, message=msg, dataplane=None)
            else:
                msg = (f"E7 - An existing {conn_edge.edge_state} edge with a different id"
                       f"{conn_edge.edge_id[:7]} alread exist")
                edge_resp = EdgeResponse(
                    is_accepted=False, message=msg, dataplane=None)
        elif edge_state == EdgeStates.Initialized:
            edge_resp = EdgeResponse(
                is_accepted=True, message="Precollision edge permitted", dataplane=dp_type)
            del net_ovl.adjacency_list[peer_id]
        elif edge_state == EdgeStates.PreAuth and self.node_id < edge_req.initiator_id:
            msg = f"E2 - Node {self.node_id} superceeds edge request due to collision, "
            "edge={net_ovl.adjacency_list[peer_id].edge_id[:7]}"
            edge_resp = EdgeResponse(
                is_accepted=False, message=msg, dataplane=None)
        elif edge_state == EdgeStates.PreAuth and self.node_id > edge_req.initiator_id:
            conn_edge.edge_type = transpose_edge_type(edge_req.edge_type)
            conn_edge.edge_id = edge_req.edge_id
            msg = f"E0 - Node {self.node_id} accepts edge collision override."
            " CE:{conn_edge.edge_id[:7]} remapped -> edge:{edge_req.edge_id[:7]}"
            edge_resp = EdgeResponse(
                is_accepted=True, message=msg, dataplane=dp_type)
        else:
            edge_resp = EdgeResponse(False, "E6 - Request colides with an edge being destroyed."
                                            "Try later", dataplane=dp_type)
        return edge_resp

    def _negotiate_response(self, net_ovl, edge_req):
        """ Role B1 """
        edge_resp = None
        dp_type = self._select_tunnel_type(net_ovl, edge_req)

        if edge_req.edge_type == "CETypeSuccessor":
            edge_resp = EdgeResponse(
                is_accepted=True, message="Successor edge permitted", dataplane=dp_type)
        elif edge_req.edge_type == "CETypeStatic":
            edge_resp = EdgeResponse(
                is_accepted=True, message="Static edge permitted", dataplane=dp_type)
        elif edge_req.edge_type == "CETypeOnDemand":
            edge_resp = EdgeResponse(
                is_accepted=True, message="On-demand edge permitted", dataplane=dp_type)
        elif not net_ovl.adjacency_list.is_threshold(EdgeTypesIn.ILongDistance):
            edge_resp = EdgeResponse(
                is_accepted=True, message="Any edge permitted", dataplane=dp_type)
        else:
            edge_resp = EdgeResponse(
                is_accepted=False, message="E5 - Too many existing edges.", dataplane=None)
        return edge_resp

    def _select_tunnel_type(self, net_ovl, edge_req):
        dp_type = DataplaneTypes.Tincan
        if edge_req.location_id is not None and edge_req.location_id == net_ovl.location_id:
            if net_ovl.is_encr_required:
                dp_type = DataplaneTypes.WireGuard
            else:
                dp_type = DataplaneTypes.Geneve
        return dp_type

###################################################################################################
    def _create_tunnel(self, net_ovl, dataplane, peer_id, tunnel_id):
        params = {"OverlayId": net_ovl.overlay_id,
                  "PeerId": peer_id, "TunnelId": tunnel_id}
        if dataplane == DataplaneTypes.Geneve:
            params["VNId"] = self.config["Overlays"][net_ovl.overlay_id].get(
                "LocationId")
            self.register_cbt("GeneveTunnel", "GNV_CREATE_TUNNEL", params)
        elif dataplane == DataplaneTypes.WireGuard:
            params["LocationId"] = self.config["Overlays"][net_ovl.overlay_id].get(
                "LocationId")
            self.register_cbt("WireGuard", "WGD_CREATE_TUNNEL", params)
        elif dataplane == DataplaneTypes.Tincan:
            self.register_cbt("LinkManager", "LNK_CREATE_TUNNEL", params)
        else:
            self.logger.warning(
                f"Create tunnel request failed, due to invalid tunnel type {dataplane}")

    def _initiate_remove_edge(self, net_ovl, peer_id):
        if not peer_id in net_ovl.adjacency_list:
            return False
        ce = net_ovl.adjacency_list[peer_id]
        if ce.edge_state == EdgeStates.Connected and \
                ce.edge_type in EdgeTypesOut and \
                time.time() - ce.connected_time >= Topology._EDGE_PROTECTION_AGE:
            if ce.edge_type == EdgeTypesOut.Successor and \
                    not net_ovl.adjacency_list.is_all_successors_connected():
                return False
            self.logger.info("Removing edge %s", ce)
            net_ovl.acquire()
            self._remove_tunnel(net_ovl, ce.dataplane,
                                ce.peer_id, ce.edge_id)
            return True
        return False

    def _remove_tunnel(self, net_ovl, dataplane, peer_id, tunnel_id):
        params = {"OverlayId": net_ovl.overlay_id,
                  "PeerId": peer_id, "TunnelId": tunnel_id}
        if dataplane == DataplaneTypes.Geneve:
            self.register_cbt("GeneveTunnel", "GNV_REMOVE_TUNNEL", params)
        elif dataplane == DataplaneTypes.WireGuard:
            self.register_cbt("WireGuard", "WGD_REMOVE_TUNNEL", params)
        elif dataplane == DataplaneTypes.Tincan:
            self.register_cbt("LinkManager", "LNK_REMOVE_TUNNEL", params)
        else:
            self.logger.warning(
                f"Remove tunnel request failed, due to invalid tunnel type {dataplane}")

    def _update_edge(self, net_ovl, new_conn_edge):
        if not new_conn_edge.peer_id in net_ovl.adjacency_list:
            return False
        ce = net_ovl.adjacency_list[new_conn_edge.peer_id]
        if ce.edge_state != EdgeStates.Connected:
            return False
        self.logger.debug(f"Updating conn edge {ce} to {new_conn_edge}")
        net_ovl.adjacency_list.update_edge(new_conn_edge)
        return False
