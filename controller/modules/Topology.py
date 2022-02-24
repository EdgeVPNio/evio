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
from datetime import datetime
from framework.CFx import CFX
from framework.ControllerModule import ControllerModule
from framework.Modlib import RemoteAction
from .NetworkBuilder import NetworkBuilder
from .TunnelSelector import TunnelSelector
from .NetworkBuilder import EdgeRequest
from .NetworkBuilder import EdgeResponse
from .NetworkBuilder import EdgeNegotiate
from .GraphBuilder import GraphBuilder
from .TunnelSelector import authorize_tunnel
from .TunnelSelector import create_tunnel
from .TunnelSelector import remove_tunnel

MaxSuccessors = 1
MaxOnDemandEdges = 0
PeerDiscoveryCoalesce = 1
ExclusionBaseInterval = 60
TrimCheckInterval = 3600
class DiscoveredPeer():
    def __init__(self, peer_id, **kwargs):
        self.peer_id = peer_id
        self.is_banned = False # bars conn attempts from local node, the peer can still recon
        self.successive_fails = 0
        self.available_time = time.time()
        self.last_checkin = self.available_time
        self.exclusion_base_interval = kwargs.get("ExclusionBaseInterval", ExclusionBaseInterval)
        self.expiry_interval = kwargs.get("ExpiryInterval", randint(16, 24) * 3600) # 16-24 hrs
        self.max_successive_fails =  kwargs.get("MaxSuccessiveFails", 4)
        self.successive_fails_incr =  kwargs.get("SuccessiveFailsIncr", 1)
        self.successive_fails_decr =  kwargs.get("SuccessiveFailsDecr", 2)

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
        return bool((not self.is_banned) # successive_fails < max_successive_fails
                    and (time.time() >= self.available_time) # the falloff wait period is over
                    and (time.time() - self.last_checkin < self.expiry_interval + 1800)) # 30 mins before expiry

class Topology(ControllerModule, CFX):
    _REFLECT = set(["_net_ovls"])
    def __init__(self, cfx_handle, module_config, module_name):
        super(Topology, self).__init__(cfx_handle, module_config, module_name)
        self._net_ovls = {}
        self._lock = threading.Lock()
        self._topo_changed_publisher = None
        self._last_trim_time = time.time()
        self._trim_check_interval = self.config.get("TrimCheckInterval", TrimCheckInterval)

    def initialize(self):
        self._topo_changed_publisher = self.publish_subscription("TOP_TOPOLOGY_CHANGE")
        self.start_subscription("Signal", "SIG_PEER_PRESENCE_NOTIFY")
        self.start_subscription("LinkManager", "LNK_TUNNEL_EVENTS")
        nid = self.node_id
        for olid in self.overlays:
            loc_id = self.config["OverlayId"][olid].get("LocationId", None)
            req_encr = self.config["OverlayId"][olid].get("RequireEncryption", False)
            self._net_ovls[olid] = dict(NewPeerCount=0,
                                        NetBuilder=NetworkBuilder(self, olid, nid),
                                        TunnelSelector=TunnelSelector(self, olid, nid, loc_id, req_encr),
                                        KnownPeers=dict(), PendingAuthConnEdges=dict(),
                                        OndPeers=[])
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

    def req_handler_peer_presence(self, cbt):
        """
        Handles peer presence notification. Determines when to build a new graph and refresh
        connections.
        """
        peer = cbt.request.params
        peer_id = peer["PeerId"]
        olid = peer["OverlayId"]
        new_disc = False
        disc = self._net_ovls[olid]["KnownPeers"].get(peer_id)
        if not disc:
            disc = DiscoveredPeer(peer_id)
            self._net_ovls[olid]["KnownPeers"][peer_id] = disc
            new_disc = True
        disc.presence()
        if new_disc or not disc.is_available:
            self._net_ovls[olid]["NewPeerCount"] += 1
            if self._net_ovls[olid]["NewPeerCount"] >= self.config.get("PeerDiscoveryCoalesce", PeerDiscoveryCoalesce):
                self.log("LOG_DEBUG",
                         "Overlay %s - Coalesced %s new peer discovery, "
                         "initiating network refresh",
                         olid, self._net_ovls[olid]["NewPeerCount"])
                self._update_overlay(olid)
            else:
                self.log("LOG_DEBUG",
                         "Overlay %s, %s new peers discovered, "
                         "delaying refresh",
                         olid, self._net_ovls[olid]["NewPeerCount"])
        cbt.set_response(None, True)
        self.complete_cbt(cbt)

    def req_handler_vis_data(self, cbt):
        topo_data = {}
        try:
            for olid in self._net_ovls:
                topo_data[olid] = {}
                nb = self._net_ovls[olid]["NetBuilder"]
                if nb:
                    adjl = nb.get_adj_list()
                    for k in adjl.conn_edges:
                        ce = adjl.conn_edges[k]
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

    def req_handler_tnl_data_update(self, cbt):
        params = cbt.request.params
        olid = params["OverlayId"]
        peer_id = params["PeerId"]
        if peer_id not in self._net_ovls[olid]["KnownPeers"]:
            self.logger.warn(f"Peer {peer_id} misssig from known list, adding")
            disc = DiscoveredPeer(peer_id)
            self._net_ovls[olid]["KnownPeers"][peer_id] = disc
            disc.presence()
        if params["UpdateType"] == "LnkEvConnected":
            self._net_ovls[olid]["KnownPeers"][peer_id].restore()
            self._do_topo_change_post(olid)
        elif params["UpdateType"] == "LnkEvDeauthorized":
            self._net_ovls[olid]["KnownPeers"][peer_id].exclude()
            self.log("LOG_DEBUG", "Excluding peer %s until %s", peer_id,
                     str(datetime.fromtimestamp(
                         self._net_ovls[olid]["KnownPeers"][peer_id].available_time)))
        elif params["UpdateType"] == "LnkEvRemoved":
            self._do_topo_change_post(olid)
        self._net_ovls[olid]["NetBuilder"].update_edge_state(params)
        self._update_overlay(olid)
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
            if (olid in self._net_ovls and peer_id in self._net_ovls[olid]["KnownPeers"] and
                    self._net_ovls[olid]["KnownPeers"][peer_id].is_available):
                self._net_ovls[olid]["OndPeers"].append(op)
                self.log("LOG_DEBUG", "Added on-demand tunnel request to queue %s", op)
            else:
                self.log("LOG_WARNING",
                        "Invalid on-demand tunnel request parameter, OverlayId=%s, PeerId=%s",
                        olid, peer_id)

    def req_handler_negotiate_edge(self, edge_cbt):
        """ Role B, decide if the request for an incoming edge is accepted or rejected """
        edge_req = EdgeRequest(**edge_cbt.request.params)
        olid = edge_req.overlay_id
        if olid not in self.config["Overlays"]:
            self.log("LOG_WARNING",
                     "The requested overlay is not specified in "
                     "local config, the edge request is discarded")
            edge_cbt.set_response("Unknown overlay id specified in edge request", False)
            self.complete_cbt(edge_cbt)
            return
        peer_id = edge_req.initiator_id
        if peer_id not in self._net_ovls[olid]["KnownPeers"]:
            # this node miss the presence notification, so add to KnownPeers
            self._net_ovls[olid]["KnownPeers"][peer_id] = DiscoveredPeer(peer_id)
        if self.config["Overlays"][olid].get("Role", "Switch").casefold() == "leaf".casefold():
            self.log("LOG_INFO", "Rejected edge negotiation, "
                     "this leaf device is not accepting edge requests")
            edge_cbt.set_response("E6 - Not accepting incoming connections, leaf device", False)
            self.complete_cbt(edge_cbt)
            return
        edge_resp = self._net_ovls[olid]["NetBuilder"].negotiate_incoming_edge(edge_req)
        if edge_resp.is_accepted:
            peer_id = edge_req.initiator_id
            edge_id = edge_req.edge_id
            self._net_ovls[olid]["PendingAuthConnEdges"][peer_id] = (edge_req, edge_resp)
            self._net_ovls[olid]["TunnelSelector"].authorize_tunnel(peer_id, edge_id)
            #self._authorize_edge(olid, peer_id, edge_id, parent_cbt=edge_cbt)
        else:
            edge_cbt.set_response(edge_resp.data, False)
            self.complete_cbt(edge_cbt)

    def req_handler_query_known_peers(self, cbt):
        peer_list = {}
        for olid in self._net_ovls:
            if not olid in peer_list:
                peer_list[olid] = []
            for peer_id, peer in self._net_ovls[olid]["KnownPeers"].items():
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
            _, edge_resp = self._net_ovls[olid]["PendingAuthConnEdges"].pop(peer_id)
        else:
            self._net_ovls[olid]["PendingAuthConnEdges"].pop(peer_id, None)
            edge_resp = EdgeResponse("E4 - Tunnel nego failed {0}"
                                     .format(cbt.response.data), False)
        nego_cbt = cbt.parent
        self.free_cbt(cbt)
        nego_cbt.set_response(edge_resp.data, edge_resp.is_accepted)
        self.complete_cbt(nego_cbt)

    def resp_handler_remote_action(self, cbt):
        """ Role Node A, initiate edge creation on successful neogtiation """
        rem_act = RemoteAction.from_cbt(cbt)
        olid = rem_act.overlay_id
        if olid not in self.config["Overlays"]:
            self.log("LOG_WARNING", "The specified overlay is not in the"
                     "local config, the rem act response is discarded")
            self.free_cbt(cbt)
            return
        if not cbt.response.status:
            peer_id = rem_act.recipient_id
            self._net_ovls[olid]["KnownPeers"][peer_id].exclude()
            # net builder needs the response, even if failed
        if rem_act.action == "TOP_NEGOTIATE_EDGE":
            edge_nego = rem_act.params
            edge_nego["is_accepted"] = rem_act.status
            edge_nego["data"] = rem_act.data
            edge_nego = EdgeNegotiate(**edge_nego)
            self._net_ovls[olid]["NetBuilder"].complete_edge_negotiation(edge_nego)
            self.free_cbt(cbt)
        else:
            self.log("LOG_WARNING", "Unrecognized remote action %s",
                     rem_act.action)

    def resp_handler_create_tnl(self, cbt):
        params = cbt.request.params
        olid = params["OverlayId"]
        peer_id = params["PeerId"]
        if not cbt.response.status:
            self.log("LOG_WARNING", "Failed to create topology edge to %s. %s",
                     cbt.request.params["PeerId"], cbt.response.data)
            self._net_ovls[olid]["KnownPeers"][peer_id].exclude()
        self.free_cbt(cbt)

    def resp_handler_remove_tnl(self, cbt):
        if not cbt.response.status:
            self.log("LOG_WARNING", "Failed to remove topology edge %s", cbt.response.data)
            params = cbt.request.params
            params["UpdateType"] = "RemoveEdgeFailed"
            params["TunnelId"] = None
            olid = params["OverlayId"]
            self._net_ovls[olid]["NetBuilder"].update_edge_state(params)
        self.free_cbt(cbt)

    def process_cbt(self, cbt):
        with self._lock:
            if cbt.op_type == "Request":
                if cbt.request.action == "SIG_PEER_PRESENCE_NOTIFY":
                    self.req_handler_peer_presence(cbt)
                elif cbt.request.action == "VIS_DATA_REQ":
                    self.req_handler_vis_data(cbt)
                elif cbt.request.action == "LNK_TUNNEL_EVENTS":
                    self.req_handler_tnl_data_update(cbt)
                elif cbt.request.action == "TOP_REQUEST_OND_TUNNEL":
                    self.req_handler_req_ond_tunnels(cbt)
                elif cbt.request.action == "TOP_NEGOTIATE_EDGE":
                    self.req_handler_negotiate_edge(cbt)
                elif cbt.request.action == "TOP_QUERY_KNOWN_PEERS":
                    self.req_handler_query_known_peers(cbt)
                else:
                    self.req_handler_default(cbt)
            elif cbt.op_type == "Response":
                if cbt.request.action == "LNK_CREATE_TUNNEL":
                    self.resp_handler_create_tnl(cbt)
                elif cbt.request.action == "LNK_REMOVE_TUNNEL":
                    self.resp_handler_remove_tnl(cbt)
                elif cbt.request.action == "SIG_REMOTE_ACTION":
                    self.resp_handler_remote_action(cbt)
                elif cbt.request.action == "LNK_AUTH_TUNNEL":
                    self.resp_handler_auth_tunnel(cbt)
                else:
                    parent_cbt = cbt.parent
                    cbt_data = cbt.response.data
                    cbt_status = cbt.response.status
                    self.free_cbt(cbt)
                    if (parent_cbt is not None and parent_cbt.child_count == 1):
                        parent_cbt.set_response(cbt_data, cbt_status)
                        self.complete_cbt(parent_cbt)

    def _manage_topology(self):
        # Periodically refresh the topology, making sure desired links exist and exipred
        # ones are removed.
        for olid in self._net_ovls:
            if (time.time() - self._last_trim_time) >= self._trim_check_interval:
                self._trim_inactive_peers(olid)
            self._update_overlay(olid)

    def timer_method(self):
        with self._lock:
            self._manage_topology()
            self.trace_state()

    def top_add_edge(self, overlay_id, peer_id, edge_id):
        """
        Instruct LinkManager to commence building a tunnel to the specified peer
        """
        self.logger.info("Creating peer edge %s:%s->%s",
                         overlay_id[:7], self.node_id[:7], peer_id[:7])
        self._net_ovls[overlay_id]["TunnelSelector"].create_tunnel(peer_id, edge_id)
        return
        params = {"OverlayId": overlay_id, "PeerId": peer_id, "TunnelId": edge_id}
        self.register_cbt("LinkManager", "LNK_CREATE_TUNNEL", params)

    def top_remove_edge(self, overlay_id, peer_id):
        self.log("LOG_INFO", "Removing peer edge %s:%s->%s",
                 overlay_id, self.node_id[:7], peer_id[:7])
        self._net_ovls[overlay_id]["TunnelSelector"].remove_tunnel(peer_id)
        return
        params = {"OverlayId": overlay_id, "PeerId": peer_id}
        self.register_cbt("LinkManager", "LNK_REMOVE_TUNNEL", params)

    def top_send_negotiate_edge_req(self, edge_req):
        """Role Node A, Send a request to create an edge to the peer """
        olid = edge_req.overlay_id
        edge_req.location_id = self.config["OverlayId"][olid].get("LocationId", None)
        edge_req.encryption_required = self.config["OverlayId"][olid].get("EncryptionRequired", None)
        self.log("LOG_DEBUG", "Requesting edge auth edge_req=%s", edge_req)
        edge_params = edge_req._asdict()
        rem_act = RemoteAction(olid, recipient_id=edge_req.recipient_id,
                               recipient_cm="Topology", action="TOP_NEGOTIATE_EDGE",
                               params=edge_params)
        rem_act.submit_remote_act(self)

    def _do_topo_change_post(self, overlay_id):
        # create and post the dict of adjacent connection edges
        adjl = self._net_ovls[overlay_id]["NetBuilder"].get_adj_list()
        topo = {}
        for peer_id in adjl.conn_edges:
            if adjl.conn_edges[peer_id].edge_state == "CEStateConnected":
                topo[peer_id] = dict(adjl.conn_edges[peer_id]) # create a dict from CE
        update = {"OverlayId": overlay_id, "Topology": topo}
        self._topo_changed_publisher.post_update(update)

    def _trim_inactive_peers(self, olid):
        rmv = []
        self.logger.debug("Checking for expired peers")
        for peer_id, peer in self._net_ovls[olid]["KnownPeers"].items():
            if peer.is_expired():
                rmv.append(peer_id)
        for peer_id in rmv:
            self.logger.debug(f"Removing expired peer {peer_id}")
            self._net_ovls[olid]["KnownPeers"].pop(peer_id)
        self._last_trim_time = time.time()

    def _update_overlay(self, olid):
        net_ovl = self._net_ovls[olid]
        nb = net_ovl["NetBuilder"]
        if nb.is_ready:
            net_ovl["NewPeerCount"] = 0
            ovl_cfg = self.config["Overlays"][olid]
            enf_lnks = ovl_cfg.get("EnforcedEdges", [])
            peer_list = [peer_id for peer_id in net_ovl["KnownPeers"] \
                if net_ovl["KnownPeers"][peer_id].is_available]
            if not peer_list:
                return
            max_succ = int(ovl_cfg.get("MaxSuccessors", MaxSuccessors))
            max_ond = int(ovl_cfg.get("MaxOnDemandEdges", MaxOnDemandEdges))
            num_peers = len(peer_list) if len(peer_list) > 1 else 2
            max_ldl = int(ovl_cfg.get("MaxLongDistEdges", math.ceil(math.log(num_peers+1, 2))))
            manual_topo = ovl_cfg.get("ManualTopology", False)
            if self.config["Overlays"][olid].get("Role", "Switch").casefold() == \
                "leaf".casefold():
                manual_topo = True
            params = {"OverlayId": olid, "NodeId": self.node_id, "ManualTopology": manual_topo,
                      "EnforcedEdges": enf_lnks, "MaxSuccessors": max_succ,
                      "MaxLongDistEdges": max_ldl, "MaxOnDemandEdges": max_ond}
            gb = GraphBuilder(params, top=self)
            curr_adjl = nb.get_adj_list()
            adjl = gb.build_adj_list(peer_list, curr_adjl, net_ovl["OndPeers"], relink=False)
            nb.refresh(adjl)
        else:
            nb.refresh()

    def _authorize_edge(self, overlay_id, peer_id, edge_id, parent_cbt, peer_loc_id):
        self.log("LOG_INFO", "Authorizing peer edge from %s:%s->%s",
                 overlay_id, peer_id[:7], self.node_id[:7])
        params = {"OverlayId": overlay_id, "PeerId": peer_id, "TunnelId": edge_id}
        cbt = self.create_linked_cbt(parent_cbt)
        cbt.set_request(self.module_name, "LinkManager", "LNK_AUTH_TUNNEL", params)
        self.submit_cbt(cbt)
