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
from .NetworkGraph import ConnectionEdge, ConnEdgeAdjacenctList, NetworkTransitions
from .NetworkGraph import EdgeStates, EdgeTypesOut, EdgeTypesIn, OpType, transpose_edge_type
from .GraphBuilder import GraphBuilder
from .Tunnel import TunnelEvents

MinSuccessors = 1
MaxOnDemandEdges = 0
PeerDiscoveryCoalesce = 1
ExclusionBaseInterval = 60
TrimCheckInterval = 3600
MaxConcurrentOps = 1

EdgeRequest = namedtuple("EdgeRequest",
                         ["overlay_id", "edge_id", "edge_type", "initiator_id",
                          "recipient_id", "location_id", "capability"])

EdgeResponse = namedtuple("EdgeResponse",
                           ["is_accepted", "message", "tunnel_type"])

EdgeNegotiate = namedtuple("EdgeNegotiate",
                            [*EdgeRequest._fields, *EdgeResponse._fields])

SUPPORTED_TUNNELS = namedtuple("SUPPORTED_TUNNELS",
                               ["Geneve", "WireGuard", "Tincan"],
                               defaults=["Geneve", "WireGuard", "Tincan"])
SupportedTunnels = SUPPORTED_TUNNELS()

class DiscoveredPeer():
    def __init__(self, peer_id, **kwargs):
        self.peer_id = peer_id
        self.is_banned = False  # bars conn attempts from local node, the peer can still recon
        self.successive_fails = 0
        self.available_time = time.time()
        self.last_checkin = self.available_time
        self.exclusion_base_interval = kwargs.get(
            "ExclusionBaseInterval", ExclusionBaseInterval)
        self.expiry_interval = kwargs.get(
            "ExpiryInterval", randint(16, 24) * 3600)  # 16-24 hrs
        self.max_successive_fails = kwargs.get("MaxSuccessiveFails", 4)
        self.successive_fails_incr = kwargs.get("SuccessiveFailsIncr", 1)
        self.successive_fails_decr = kwargs.get("SuccessiveFailsDecr", 2)

    def __repr__(self):
        items = (f"\"{k}\": {v!r}" for k, v in self.__dict__.items())
        return "{{{}}}".format(", ".join(items))

    def exclude(self):
        self.successive_fails += self.successive_fails_incr
        self.available_time = (randint(1, 4) * self.exclusion_base_interval *
                               self.successive_fails) + time.time()
        if self.successive_fails >= self.max_successive_fails:
            self.is_banned = True

    def restore(self):
        self.is_banned = False
        self.successive_fails = 0

    def presence(self):
        self.available_time = time.time()
        self.last_checkin = self.available_time
        if self.is_banned and self.successive_fails == 0:
            self.restore()
        elif self.is_banned and self.successive_fails > 0:
            self.successive_fails -= self.successive_fails_decr

    def is_expired(self):
        return bool(time.time() - self.last_checkin >= self.expiry_interval)

    @property
    def is_available(self):
        return bool((not self.is_banned)  # successive_fails < max_successive_fails
                    # the falloff wait period is over
                    and (time.time() >= self.available_time)
                    and (time.time() - self.last_checkin < self.expiry_interval + 1800))  # 30 mins before expiry


class NetworkOverlay():
    def __init__(self, node_id, overlay_id, **kwargs):
        self._lck = threading.Lock()
        # used to limit number of concurrent operations initiated
        self._refc = kwargs.get("MaxConcurrentOps", MaxConcurrentOps)
        self.node_id = node_id
        self.overlay_id = overlay_id
        self.logger = kwargs["Logger"]
        self.new_peer_count = 0
        self._net_transition = None
        self.transition: NetworkTransitions = None
        self.known_peers: dict[str, DiscoveredPeer] = {}
        self.pending_auth_conn_edges: dict[str, tuple] = {}
        self.ond_peers = []
        self.adjacency_list = ConnEdgeAdjacenctList(overlay_id, node_id)
        self._loc_id = kwargs.get("LocationId")
        self._encr_req = kwargs.get("EncryptionRequired", False)

    def __repr__(self):
        items = (f"\"{k}\": {v!r}" for k, v in self.__dict__.items())
        return "{{{}}}".format(", ".join(items))

    @property
    def location_id(self):
        return self._loc_id

    @property
    def is_encr_required(self):
        return self._encr_req

    @property
    def transition(self):
        return self._net_transition

    @transition.setter
    def transition(self, transitions):
        """
        Transitions the overlay network overlay to the desired state specified by network transition ops.
        """
        self.logger.debug("New network transitions: %s", str(transitions))
        assert ((self.is_ready and self.is_transition_completed()) or
                (not self.is_ready and not self.is_transition_completed())),\
            "Netbuilder is not ready for a new net graph"

        if transitions and self.is_ready:
            self._net_transition = transitions
            self.adjacency_list.min_successors = transitions.min_successors
            self.adjacency_list.max_long_distance = transitions.max_long_distance
            self.adjacency_list.max_ondemand = transitions.max_ondemand

    def is_transition_completed(self):
        """
        Is the overlay ready for a new NetGraph? This means all the network 
        transition operations have been completed.
        """
        return not bool(self._net_transition)

    def acquire(self):
        with self._lck:
            assert self._refc > 0, "Reference count at zero, cannot acquire"
            self._refc -= 1

    def release(self):
        with self._lck:
            assert self._refc < MaxConcurrentOps, "Reference count at maximum, invalid attempt to release"
            self._refc += 1

    def is_ready(self):
        """Is the current transition operation completed"""
        with self._lck:
            assert self._refc > 0 or self._refc < MaxConcurrentOps, f"Invalid reference count {self._refc}"
            return self._refc == MaxConcurrentOps

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
        self.start_subscription("Signal", "SIG_PEER_PRESENCE_NOTIFY")
        self.start_subscription("LinkManager", "LNK_TUNNEL_EVENTS")
        self.start_subscription("GeneveTunnel", "GNV_TUNNEL_EVENTS")
        for olid in self.overlays:
            self._net_ovls[olid] = NetworkOverlay(self.node_id, olid,
                                                  Logger=self.logger,
                                                  LocationId=self.config["Overlays"][olid].get(
                                                      "LocationId"),
                                                  EncryptionRequired=self.config["Overlays"][olid].get("EncryptionRequired"))
        try:
            # Subscribe for data request notifications from OverlayVisualizer
            self.start_subscription("OverlayVisualizer",
                                    "VIS_DATA_REQ")
        except NameError as err:
            if "OverlayVisualizer" in str(err):
                self.log("LOG_WARNING",
                         "OverlayVisualizer module not loaded. "
                         "Visualization data will not be sent.")
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
            self.trace_state()

    def req_handler_peer_presence(self, cbt):
        """
        Handles peer presence notification. Determines when to build a new graph and refresh
        connections.
        """
        peer = cbt.request.params
        peer_id = peer["PeerId"]
        olid = peer["OverlayId"]
        new_disc = False
        disc = self._net_ovls[olid].known_peers.get(peer_id)
        if not disc:
            disc = DiscoveredPeer(peer_id)
            self._net_ovls[olid].known_peers[peer_id] = disc
            new_disc = True
        disc.presence()
        if new_disc or not disc.is_available:
            self._net_ovls[olid].new_peer_count += 1
            if self._net_ovls[olid].new_peer_count >= self.config.get("PeerDiscoveryCoalesce", PeerDiscoveryCoalesce):
                self.logger.debug("Overlay %s - Coalesced %s new peer discovery, "
                                  "initiating overlay update",
                                  olid, self._net_ovls[olid].new_peer_count)
                self._update_overlay(olid)
            else:
                self.logger.info("Overlay %s, %s new peers discovered, "
                                 "delaying overlay update",
                                 olid, self._net_ovls[olid].new_peer_count)
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

    def req_handler_tunnl_update(self, cbt):
        event = cbt.request.params
        peer_id = event["PeerId"]
        edge_id = event["TunnelId"]
        overlay_id = event["OverlayId"]
        ovl = self._net_ovls[overlay_id]
        if event["UpdateType"] in ("LnkEvAuthorized", TunnelEvents.Authorized):
            """ Role B """
            ovl.adjacency_list[peer_id].edge_state = EdgeStates.Authorized
        elif event["UpdateType"] in ("LnkEvAuthExpired", TunnelEvents.AuthExpired):
            """ Role B """
            ce = ovl.adjacency_list[peer_id]
            assert ce.edge_state == EdgeStates.Authorized, "Deauth CE={0}".format(
                ce)
            ce.edge_state = EdgeStates.Deleting
            del ovl.adjacency_list[peer_id]
            ovl.known_peers[peer_id].exclude()
            self.logger.debug("Excluding peer %s until %s", peer_id,
                              str(datetime.fromtimestamp(
                                  ovl.known_peers[peer_id].available_time)))
        elif event["UpdateType"] in ("LnkEvCreating", TunnelEvents.Creating):
            conn_edge = ovl.adjacency_list[peer_id]
            conn_edge.edge_state = EdgeStates.Created
        elif event["UpdateType"] in ("LnkEvCreated", TunnelEvents.Created):
            pass
        elif event["UpdateType"] in ("LnkEvConnected", TunnelEvents.Connected):
            """Roles A & B"""
            ce = ovl.adjacency_list[peer_id]
            ce.edge_state = EdgeStates.Connected
            ce.connected_time = event["ConnectedTimestamp"]
            ovl.known_peers[peer_id].restore()
            if ce.edge_type in EdgeTypesOut:
                ovl.release()
                self._process_next_transition(ovl)
        elif event["UpdateType"] in ("LnkEvDisconnected", TunnelEvents.Disconnected):
            # the local topology did not request removal of the connection
            ce = ovl.adjacency_list[peer_id]
            ce.edge_state = EdgeStates.Disconnected
            self._remove_tunnel(ovl, ce.tunnel_type, peer_id, edge_id)
        elif event["UpdateType"] in ("LnkEvRemoved", TunnelEvents.Removed):
            """Roles A & B"""
            ce = ovl.adjacency_list[peer_id]
            ce.edge_state = EdgeStates.Deleting
            del ovl.adjacency_list[peer_id]
            if ce.edge_type in EdgeTypesOut:
                ovl.release()
                self._process_next_transition(ovl)
        else:
            self.logger.warning("Invalid UpdateType specified for event")
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
            if (olid in self._net_ovls and peer_id in self._net_ovls[olid].known_peers and
                    self._net_ovls[olid].known_peers[peer_id].is_available):
                self._net_ovls[olid].ond_peers.append(op)
                self.log(
                    "LOG_DEBUG", "Added on-demand tunnel request to queue %s", op)
            else:
                self.log("LOG_WARNING",
                         "Invalid on-demand tunnel request parameter, OverlayId=%s, PeerId=%s",
                         olid, peer_id)

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
        if self.config["Overlays"][olid].get("Role", "Switch").casefold() == "leaf".casefold():
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
                    tunnel_type=edge_resp.tunnel_type)
                ce.edge_state = EdgeStates.PreAuth
                net_ovl.adjacency_list[ce.peer_id] = ce                
            self._authorize_incoming_tunnel(net_ovl, peer_id, edge_req.edge_id,
                                            edge_resp.tunnel_type, edge_cbt)        
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
        peer_id = params["PeerId"]
        ovl = self._net_ovls[olid]
        if not cbt.response.status:
            self.logger.warning("Failed to create topology edge to %s. %s",
                                cbt.request.params["PeerId"], cbt.response.data)
            ovl.known_peers[peer_id].exclude()
            ovl.adjacency_list[peer_id].edge_state = EdgeStates.Deleting
            del ovl.adjacency_list[peer_id]
        self.free_cbt(cbt)

    def resp_handler_remove_tnl(self, cbt):
        params = cbt.request.params
        olid = params["OverlayId"]
        peer_id = params["PeerId"]
        ovl = self._net_ovls[olid]        
        if not cbt.response.status:
            self.logger.warning(
                     "Failed to remove topology edge %s, will retry operation", cbt.response.data)
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
        self.logger.debug("Checking for expired peers")
        for peer_id, peer in self._net_ovls[olid].known_peers.items():
            if peer.is_expired():
                rmv.append(peer_id)
        for peer_id in rmv:
            self.logger.debug(f"Removing expired peer {peer_id}")
            self._net_ovls[olid].known_peers.pop(peer_id)
        self._last_trim_time = time.time()

    def _update_overlay(self, olid):
        net_ovl = self._net_ovls[olid]

        if not net_ovl.transition:
            net_ovl.new_peer_count = 0
            ovl_cfg = self.config["Overlays"][olid]
            enf_lnks = ovl_cfg.get("StaticEdges", [])
            peer_list = [peer_id for peer_id in net_ovl.known_peers
                         if net_ovl.known_peers[peer_id].is_available]
            if not peer_list:
                return
            max_succ = int(ovl_cfg.get("MinSuccessors", MinSuccessors))
            max_ond = int(ovl_cfg.get("MaxOnDemandEdges", MaxOnDemandEdges))
            num_peers = len(peer_list) if len(peer_list) > 1 else 2
            max_ldl = int(ovl_cfg.get("MaxLongDistEdges",
                          math.floor(math.log(num_peers+1, 2))))
            manual_topo = ovl_cfg.get("ManualTopology", False)
            if self.config["Overlays"][olid].get("Role", "Switch").casefold() == \
                    "leaf".casefold():
                manual_topo = True
            params = {"OverlayId": olid, "NodeId": self.node_id, "ManualTopology": manual_topo,
                      "StaticEdges": enf_lnks, "MinSuccessors": max_succ,
                      "MaxLongDistEdges": max_ldl, "MaxOnDemandEdges": max_ond}
            gb = GraphBuilder(params, top=self)
            net_ovl.transition = gb.get_network_transitions(peer_list,
                                                            net_ovl.get_adj_list(),
                                                            net_ovl.ond_peers)
        self._process_next_transition(net_ovl)

    def _process_next_transition(self, net_ovl):
        if not (net_ovl.transition and net_ovl.is_ready):
            return
        tns = net_ovl.transition.head()
        update_initiated = False
        if tns.operation == OpType.Add:
            update_initiated = self._initiate_negotiate_edge(
                net_ovl, tns.conn_edge)
        elif tns.operation == OpType.Remove:
            update_initiated = self._initiate_remove_edge(
                net_ovl, tns.conn_edge)
        elif tns.operation == OpType.Update:
            update_initiated = True
            net_ovl.adjacency_list.update_edge_type(tns.conn_edge)
        if update_initiated:
            net_ovl.transition.pop()
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
                tunnel_types = [SupportedTunnels.WireGuard,
                                SupportedTunnels.Tincan]
            else:
                tunnel_types = [SupportedTunnels.Geneve,
                                SupportedTunnels.Tincan]

            er = EdgeRequest(overlay_id=net_ovl.overlay_id, edge_id=ce.edge_id,
                             edge_type=ce.edge_type, recipient_id=ce.peer_id,
                             initiator_id=self.node_id,
                             location_id=net_ovl.location_id,
                             capability=tunnel_types)
            edge_params = er._asdict()
            self.logger.debug("Negotiating %s", er)
            rem_act = RemoteAction(net_ovl.overlay_id, er.recipient_id,
                                   "Topology", "TOP_NEGOTIATE_EDGE", edge_params)
            net_ovl.acquire()
            rem_act.submit_remote_act(self)
            return True
        return False

    def _authorize_incoming_tunnel(self, net_ovl, peer_id, edge_id, tunnel_type, neg_edge_cbt):

        self.logger.info("Authorizing peer edge %s from %s:%s->%s",
                         edge_id, net_ovl.overlay_id, peer_id[:7], self.node_id[:7])
        params = {"OverlayId": net_ovl.overlay_id,
                  "PeerId": peer_id, "TunnelId": edge_id}
        cbt = self.create_linked_cbt(neg_edge_cbt)
        if tunnel_type == SupportedTunnels.Geneve:
            cbt.set_request(self.module_name, "GeneveTunnel",
                            "GNV_AUTH_TUNNEL", params)
        elif tunnel_type == SupportedTunnels.WireGuard:
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
                self.logger.error("EdgeNego parameters does not match current "
                                  "adjacency list. The transaction has been discarded.")
                ce.edge_state = EdgeStates.Deleting
                del net_ovl.adjacency_list[ce.peer_id]
                return
            ce.edge_state = EdgeStates.Authorized
            self._create_tunnel(
                net_ovl, edge_nego.tunnel_type, peer_id, edge_id)

    def _resolve_request_collision(self, net_ovl, edge_req, conn_edge):
        """ An connection edge was already initiated by this node so resolve the collision """
        peer_id = edge_req.initiator_id
        edge_state = conn_edge.edge_state
        edge_resp = None
        tnl_type = self._select_tunnel_type(net_ovl, edge_req)
        if edge_state in (EdgeStates.Authorized, EdgeStates.Connected):
            # Likely a duplicated Remote Action from Signal
            if conn_edge.edge_id == edge_req.edge_id:
                msg = f"E1 - A valid matching edge already exists: {conn_edge.edge_id[:7]}"
                edge_resp = EdgeResponse(
                    is_accepted=False, message=msg, tunnel_type=None)
            else:
                msg = (f"E7 - An existing {conn_edge.edge_state} edge with a different id"
                       f"{conn_edge.edge_id[:7]} alread exist")
                edge_resp = EdgeResponse(
                    is_accepted=False, message=msg, tunnel_type=None)
        elif edge_state == EdgeStates.Initialized:
            edge_resp = EdgeResponse(
                is_accepted=True, message="Precollision edge permitted", tunnel_type=tnl_type)
            del net_ovl.adjacency_list[peer_id]
        elif edge_state == EdgeStates.PreAuth and self.node_id < edge_req.initiator_id:
            msg = f"E2 - Node {self.node_id} superceeds edge request due to collision, "
            "edge={net_ovl.adjacency_list[peer_id].edge_id[:7]}"
            edge_resp = EdgeResponse(
                is_accepted=False, message=msg, tunnel_type=None)
        elif edge_state == EdgeStates.PreAuth and self.node_id > edge_req.initiator_id:
            conn_edge.edge_type = transpose_edge_type(edge_req.edge_type)
            conn_edge.edge_id = edge_req.edge_id
            msg = f"E0 - Node {self.node_id} accepts edge collision override."
            " CE:{conn_edge.edge_id[:7]} remapped -> edge:{edge_req.edge_id[:7]}"
            edge_resp = EdgeResponse(
                is_accepted=True, message=msg, tunnel_type=tnl_type)
        else:
            edge_resp = EdgeResponse(False, "E6 - Request colides with an edge being destroyed."
                                            "Try later", tunnel_type=tnl_type)
        return edge_resp

    def _negotiate_response(self, net_ovl, edge_req):
        """ Role B1 """
        self.logger.debug("Rcvd EdgeRequest=%s", str(edge_req))
        edge_resp = None
        tnl_type = self._select_tunnel_type(net_ovl, edge_req)

        if edge_req.edge_type == "CETypeSuccessor":
            edge_resp = EdgeResponse(
                is_accepted=True, message="Successor edge permitted", tunnel_type=tnl_type)
        elif edge_req.edge_type == "CETypeStatic":
            edge_resp = EdgeResponse(
                is_accepted=True, message="Static edge permitted", tunnel_type=tnl_type)
        elif edge_req.edge_type == "CETypeOnDemand":
            edge_resp = EdgeResponse(
                is_accepted=True, message="On-demand edge permitted", tunnel_type=tnl_type)
        elif not self._adj_list.is_threshold(EdgeTypesIn.ILongDistance):
            edge_resp = EdgeResponse(
                is_accepted=True, message="Any edge permitted")
        else:
            edge_resp = EdgeResponse(is_accepted=False,
                                     message="E5 - Too many existing edges.", tunnel_type=None)
        return edge_resp

    def _select_tunnel_type(self, net_ovl, edge_req):
        tunnel_type = SupportedTunnels.Tincan
        if edge_req.location_id == net_ovl.location_id:
            if net_ovl.is_encr_required:
                tunnel_type = SupportedTunnels.WireGuard
            else:
                tunnel_type = SupportedTunnels.Geneve
        return tunnel_type

###################################################################################################
    def _create_tunnel(self, net_ovl, tunnel_type, peer_id, tunnel_id):
        params = {"OverlayId": net_ovl.overlay_id,
                  "PeerId": peer_id, "TunnelId": tunnel_id}
        if tunnel_type == SupportedTunnels.Geneve:
            params["LocationId"] = self.config["Overlays"][net_ovl.overlay_id].get("LocatioId")
            self.register_cbt("GeneveTunnel", "GNV_CREATE_TUNNEL", params)
        elif tunnel_type == SupportedTunnels.WireGuard:
            params["LocationId"] = self.config["Overlays"][net_ovl.overlay_id].get("LocatioId")
            self.register_cbt("WireGuard", "WGD_CREATE_TUNNEL", params)
        elif tunnel_type == SupportedTunnels.Tincan:
            self.register_cbt("LinkManager", "LNK_CREATE_TUNNEL", params)
        else:
            self.logger.warning(
                f"Create tunnel request failed, due to invalid tunnel type {tunnel_type}")

    def _initiate_remove_edge(self, net_ovl, conn_edge):
        if conn_edge.edge_state == EdgeStates.Connected and \
                conn_edge.edge_type in EdgeTypesOut and \
                time.time() - conn_edge.connected_time >= Topology._EDGE_PROTECTION_AGE:
            if conn_edge.edge_type == EdgeTypesOut.Successor and \
                    not self._all_successors_connected():
                return False
            conn_edge.edge_state = EdgeStates.Deleting
            self._remove_tunnel(net_ovl, conn_edge.tunnel_type,
                                conn_edge.peer_id, conn_edge.edge_id)
            return True
        return False

    def _remove_tunnel(self, net_ovl, tunnel_type, peer_id, tunnel_id):
        net_ovl.acquire()
        params = {"OverlayId": net_ovl.overlay_id,
                  "PeerId": peer_id, "TunnelId": tunnel_id}
        if tunnel_type == SupportedTunnels.Geneve:
            self.register_cbt("GeneveTunnel", "GNV_REMOVE_TUNNEL", params)
        elif tunnel_type == SupportedTunnels.WireGuard:
            self.register_cbt("WireGuard", "WGD_REMOVE_TUNNEL", params)
        elif tunnel_type == SupportedTunnels.Tincan:
            self.register_cbt("LinkManager", "LNK_REMOVE_TUNNEL", params)
        else:
            self.logger.warning(
                f"Remove tunnel request failed, due to invalid tunnel type {tunnel_type}")
