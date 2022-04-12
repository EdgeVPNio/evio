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

import importlib
import logging
import time
import uuid
import unittest
from unittest.mock import MagicMock, Mock, patch

from framework.CBT import CBT
from modules.Topology import DiscoveredPeer, SupportedTunnels, Topology, EdgeRequest, EdgeNegotiate
from modules.NetworkGraph import ConnectionEdge, ConnEdgeAdjacenctList, EdgeStates, EdgeTypesOut, EdgeTypesIn
from modules.NetworkGraph import GraphTransformation, UpdatePriority

TunnelCapabilities=["Geneve", "WireGuard", "Tincan"]
class TopologyTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TopologyTest, self).__init__(*args, **kwargs)
        self.top: Topology = None

    @classmethod
    def setUpClass(self):
        # _logger = logging.getLogger()
        # _logger.setLevel(logging.DEBUG)
        # # Console Logger
        # console_handler = logging.StreamHandler()
        # console_log_formatter = logging.Formatter(
        #     "[%(asctime)s.%(msecs)03d] %(levelname)s:%(name)s: %(message)s",
        #     datefmt="%H:%M:%S")
        # console_handler.setFormatter(console_log_formatter)
        # _logger.addHandler(console_handler)
        self.config = {
            "Topology": {
                "Enabled": True,
                "PeerDiscoveryCoalesce": 1,
                "CacheExpiry": 5,
                "Overlays": {
                    "A0FB389": {
                        "MinSuccessors": 2,
                        "MaxOnDemandEdges": 3,
                        "Role": "Switch",
                        "LocationId": 12345,
                        "EncryptionRequired": False,
                        "StaticEdges": ["512", "1024"]
                    }
                },
                "NodeId": "1234434323"
            }
        }

    @classmethod
    def tearDownClass(self):
        self.config = None

    def setUp(self):
        """
        Setup the variables and the mocks required by the unit tests.
        :return: The signal object and signal dictionary
        """
        cfx_handle = Mock()
        module = importlib.import_module("modules.{0}"
                                         .format("Topology"))
        module_class = getattr(module, "Topology")
        self.top = module_class(
            cfx_handle, self.config["Topology"], "Topology")
        cfx_handle._cm_instance = self.top
        cfx_handle._cm_config = self.config["Topology"]

    def tearDown(self):
        self.top = None

    def test_initialize(self):
        self.top.initialize()
        self.assertTrue(self.top._net_ovls)
        print("passed: test_initialize")

    # def test_do_topo_change_post(self):
    #     # self.top._do_topo_change_post(overlay_id)
    #     pass

    # def test_trim_inactive_peers(self):
    #     # self.top._trim_inactive_peers(olid)
    #     pass

    def test_process_cbt_request_no_action_match(self):
        self.top.initialize()
        with self.assertLogs(level=logging.WARNING):
            cbt = CBT("NO_ONE", "Topology", "INVALID_REQ_CODE", {
                      "OverlayId": "A0FB389", "NodeId": "1234434323"})
            self.top.process_cbt(cbt)
        print("passed: test_process_cbt_request_no_action_match")

    def test_process_cbt_response_no_action_match(self):
        self.top.initialize()
        with self.assertLogs(level=logging.DEBUG):
            cbt = CBT("Topology", "Topology", "INVALID_REQ_CODE", {
                      "OverlayId": "A0FB389", "NodeId": "1234434323"})
            cbt.set_response({}, status=True)
            self.top.process_cbt(cbt)
        print("passed: test_process_cbt_response_no_action_match")

    def _create_peers(self, olid, num):
        self.top._net_ovls[olid].known_peers.clear()
        for peer_id in range(1, num):
            self.top._net_ovls[olid].known_peers[str(
                peer_id)] = DiscoveredPeer(str(peer_id))

    # def test_update_overlay(self):
    #     self.top.initialize()
    #     for olid in self.config["Topology"]["Overlays"]:
    #         self._create_peers(olid, 256)
    #         self.assertTrue(self.top._net_ovls[olid].is_idle)
    #         self.top._update_overlay(olid)
    #         ovl = self.top._net_ovls[olid]
    #         while ovl.transformation:
    #             self.top._process_next_transition(ovl)
    #         self.assertFalse(ovl.transformation)
    #         self.assertTrue(ovl.is_idle)
    #     print("passed: test_update_overlay")

    def test_req_handler_negotiate_edge(self):
        self.top.initialize()
        overlay_id = "A0FB389"
        params = {"overlay_id": overlay_id, "edge_id": "a9e7dd3091a444da8b106e8299dd2ff2",
                  "edge_type": "CETypeStatic", "initiator_id": self.top.node_id,
                  "recipient_id": "512", "location_id": 12345,
                  "capability": TunnelCapabilities}
        edge_cbt = CBT("Signal", "Topology", "TOP_NEGOTIATE_EDGE", params)
        self.top.process_cbt(edge_cbt)
        self.assertEqual(self.top._net_ovls[overlay_id].pending_auth_conn_edges
                         [params["initiator_id"]][0].initiator_id,params["initiator_id"])
        self.assertTrue(self.top._net_ovls[overlay_id].pending_auth_conn_edges
                        [params["initiator_id"]][1].is_accepted) 
        print("passed: test_req_handler_negotiate_edge")

    def test_req_handler_tunnl_update(self):
        self.top.initialize()
        overlay_id = "A0FB389"
        peer_id = "256"
        tnlid = uuid.uuid4().hex
        tap_name = "tnl123456"
        mac = "0c123261aaba"
        peer_mac = "0b77fe26100ba"
        lts = time.time() - 2
        ovl = self.top._net_ovls[overlay_id]
        self._create_peers(overlay_id, int(peer_id)+1)
        ce = ConnectionEdge(peer_id, tnlid, EdgeTypesOut.Successor, "Geneve")
        ce.edge_state = EdgeStates.PreAuth
        ovl.adjacency_list[peer_id] = ce
        params = {"UpdateType": "LnkEvAuthorized", "OverlayId": overlay_id, "PeerId": peer_id,
                "TunnelId": tnlid}
        cbt =  CBT("Geneve", "Topology", "GNV_TUNNEL_EVENTS", params)
        self.top.process_cbt(cbt)
        self.assertTrue(peer_id in ovl.adjacency_list)
        self.assertEqual(ovl.adjacency_list[peer_id].edge_state, EdgeStates.Authorized)
        
        params = {
            "UpdateType": "LnkEvAuthExpired", "OverlayId": overlay_id,
            "PeerId": peer_id, "TunnelId": tnlid, "TapName": tap_name}
        cbt =  CBT("Geneve", "Topology", "GNV_TUNNEL_EVENTS", params)
        self.top.process_cbt(cbt)
        self.assertFalse(ovl.adjacency_list)
        self.assertEqual(ce.edge_state, EdgeStates.Deleting)


        ce = ConnectionEdge(peer_id, tnlid, EdgeTypesOut.Successor, "Geneve")
        ce.edge_state = EdgeStates.PreAuth
        ovl.adjacency_list[peer_id] = ce
        params = {"UpdateType": "LnkEvAuthorized", "OverlayId": overlay_id, "PeerId": peer_id,
                "TunnelId": tnlid}
        cbt =  CBT("Geneve", "Topology", "GNV_TUNNEL_EVENTS", params)
        self.top.process_cbt(cbt)
        self.assertTrue(peer_id in ovl.adjacency_list)
        self.assertEqual(ovl.adjacency_list[peer_id].edge_state, EdgeStates.Authorized)

        params = {"UpdateType": "LnkEvCreated", "OverlayId": overlay_id, "PeerId": peer_id,
                        "TunnelId": tnlid, "TapName": tap_name}
        cbt =  CBT("Geneve", "Topology", "GNV_TUNNEL_EVENTS", params)
        self.top.process_cbt(cbt)
        self.assertTrue(peer_id in ovl.adjacency_list)
        self.assertEqual(ovl.adjacency_list[peer_id].edge_state, EdgeStates.Created)
                
        params = {"UpdateType": "LnkEvConnected", "OverlayId": overlay_id, "PeerId": peer_id,
                 "TunnelId": tnlid, "ConnectedTimestamp": lts,
                 "TapName": tap_name, "MAC": mac, "PeerMac": peer_mac}
        cbt =  CBT("Geneve", "Topology", "GNV_TUNNEL_EVENTS", params)
        ovl.acquire()
        self.top.process_cbt(cbt)
        self.assertTrue(peer_id in ovl.adjacency_list)
        self.assertEqual(ovl.adjacency_list[peer_id].edge_state, EdgeStates.Connected)
        
        params = {"UpdateType": "LnkEvDisconnected", "OverlayId": overlay_id,
                  "PeerId": peer_id, "TunnelId": tnlid,"TapName": tap_name}
        cbt =  CBT("Geneve", "Topology", "GNV_TUNNEL_EVENTS", params)
        self.top.process_cbt(cbt)
        self.assertTrue(peer_id in ovl.adjacency_list)
        self.assertEqual(ovl.adjacency_list[peer_id].edge_state, EdgeStates.Disconnected)
        
        params = {
            "UpdateType": "LnkEvRemoved", "OverlayId": overlay_id, "TunnelId": tnlid,
            "PeerId": peer_id}
        cbt =  CBT("Geneve", "Topology", "GNV_TUNNEL_EVENTS", params)
        ovl.acquire()
        self.top.process_cbt(cbt)
        self.assertFalse(ovl.adjacency_list)
        self.assertEqual(ce.edge_state, EdgeStates.Deleting)
     
        print("passed: test_req_handler_tunnl_update")
        
        
###################################################################################################
# ConnEdgeAdjacenctList
###################################################################################################      
 
###################################################################################################
# TunnelSelector
###################################################################################################      
    
    def test_negotiate_edge(self):
        pass
  
###################################################################################################
# Negotiate
###################################################################################################
        
    def test_initiate_negotiate_edge(self):
        self.top.initialize()
        ce = ConnectionEdge("128", uuid.uuid4().hex, EdgeTypesOut.Successor)
        ovl = self.top._net_ovls["A0FB389"]
        self.top._initiate_negotiate_edge(ovl, ce)
        self.assertTrue("128" in ovl.adjacency_list)
        self.assertEqual(ovl.adjacency_list["128"].edge_state, EdgeStates.PreAuth)
        print("passed: test_initiate_negotiate_edge")

    def test_select_tunnel_type(self):
        overlay_id = "A0FB389"
        self.top.initialize()
        cbt = CBT("Signal", "Topology", "TOP_NEGOTIATE_EDGE", {})
        edge_req = EdgeRequest(overlay_id=overlay_id, edge_id=uuid.uuid4().hex,
                               edge_type=EdgeTypesOut.Static, recipient_id=self.top.node_id,
                               initiator_id="256",
                               location_id=self.top.config["Overlays"][overlay_id]["LocationId"],
                               capability=TunnelCapabilities)
        ovl = self.top._net_ovls[overlay_id]
        tunnel_type = self.top._select_tunnel_type(ovl, edge_req)
        self.assertEqual(SupportedTunnels.Geneve, tunnel_type)

        edge_req = EdgeRequest(overlay_id=overlay_id, edge_id=uuid.uuid4().hex,
                               edge_type=EdgeTypesOut.Static, recipient_id=self.top.node_id,
                               initiator_id="256",
                               location_id=67890,
                               capability=TunnelCapabilities)        
        tunnel_type = self.top._select_tunnel_type(ovl, edge_req)
        self.assertEqual(SupportedTunnels.Tincan, tunnel_type)
        print("passed: test_select_tunnel_type")

    def test_select_tunnel_type_wireguard(self):
        overlay_id = "A0FB389"
        self.top.config["Overlays"][overlay_id]["EncryptionRequired"] = True
        self.top.initialize()
        cbt = CBT("Signal", "Topology", "TOP_NEGOTIATE_EDGE", {})
        edge_req = EdgeRequest(overlay_id=overlay_id, edge_id=uuid.uuid4().hex,
                               edge_type=EdgeTypesOut.Static, recipient_id=self.top.node_id,
                               initiator_id="256",
                               location_id=self.top.config["Overlays"][overlay_id]["LocationId"],
                               capability=TunnelCapabilities)
        ovl = self.top._net_ovls[overlay_id]

        tunnel_type = self.top._select_tunnel_type(ovl, edge_req)
        self.assertEqual(SupportedTunnels.WireGuard, tunnel_type)

        edge_req = EdgeRequest(overlay_id=overlay_id, edge_id=uuid.uuid4().hex,
                               edge_type=EdgeTypesOut.Static, recipient_id=self.top.node_id,
                               initiator_id="256",
                               location_id=67890,
                               capability=TunnelCapabilities)        
        tunnel_type = self.top._select_tunnel_type(ovl, edge_req)
        self.assertEqual(SupportedTunnels.Tincan, tunnel_type)
        print("passed: test_select_tunnel_type_wireguard")

    def test_authorize_incoming_tunnel_geneve(self):
        overlay_id = "A0FB389"
        self.top.initialize()
        cbt = CBT("Signal", "Topology", "TOP_NEGOTIATE_EDGE", {})
        ovl = self.top._net_ovls[overlay_id]
        self.top._authorize_incoming_tunnel(ovl, "128", uuid.uuid4().hex, SupportedTunnels.Geneve, cbt)
        print("passed: test_authorize_incoming_tunnel_geneve")
    
    def test_authorize_incoming_tunnel_wireguard(self):
        overlay_id = "A0FB389"
        self.top.initialize()
        cbt = CBT("Signal", "Topology", "TOP_NEGOTIATE_EDGE", {})
        ovl = self.top._net_ovls[overlay_id]
        self.top._authorize_incoming_tunnel(ovl, "128", uuid.uuid4().hex, SupportedTunnels.WireGuard, cbt)
        print("passed: test_authorize_incoming_tunnel_wireguard")
    
    def test_authorize_incoming_tunnel_tincan(self):
        overlay_id = "A0FB389"
        self.top.initialize()
        cbt = CBT("Signal", "Topology", "TOP_NEGOTIATE_EDGE", {})
        ovl = self.top._net_ovls[overlay_id]
        self.top._authorize_incoming_tunnel(ovl, "128", uuid.uuid4().hex, SupportedTunnels.Tincan, cbt)
        print("passed: test_authorize_incoming_tunnel_tincan")
            
    def test_negotiate_incoming_edge_request(self):
        overlay_id = "A0FB389"
        peer_id = "2"
        self.top.initialize()
        self._create_peers(overlay_id, int(peer_id)+1)
        er = EdgeRequest(overlay_id=overlay_id, edge_id=uuid.uuid4().hex, edge_type=EdgeTypesOut.Static,
                         recipient_id=self.top.node_id, initiator_id=peer_id,
                         location_id=self.top.config["Overlays"][overlay_id]["LocationId"],
                         capability=TunnelCapabilities)
        cbt = CBT("Signal", "Topology", "TOP_NEGOTIATE_EDGE", er._asdict())
        ovl = self.top._net_ovls[overlay_id]
        self.top.req_handler_negotiate_edge(cbt)
        _, edge_resp = ovl.pending_auth_conn_edges[peer_id]
        self.assertIsNotNone(edge_resp)
        self.assertTrue(edge_resp.is_accepted)
        self.assertEqual(ovl.adjacency_list[er.initiator_id].edge_state, EdgeStates.PreAuth)

        print("passed: test_negotiate_incoming_edge_request")
    
    def test_negotiate_incoming_edge_request_collision_fail(self):
        overlay_id = "A0FB389"
        peer_id = "2"
        self.top.initialize()
        self._create_peers(overlay_id, int(peer_id)+1)
        ovl = self.top._net_ovls[overlay_id]
        existing_edge_id = uuid.uuid4().hex
        ce = ConnectionEdge(peer_id, existing_edge_id, EdgeTypesOut.LongDistance)
        ce.edge_state = EdgeStates.Connected
        ovl.adjacency_list[peer_id] = ce
        er = EdgeRequest(overlay_id=overlay_id, edge_id=uuid.uuid4().hex, edge_type=EdgeTypesOut.Static,
                         recipient_id=self.top.node_id, initiator_id=peer_id,
                         location_id=self.top.config["Overlays"][overlay_id]["LocationId"],
                         capability=TunnelCapabilities)
        cbt = CBT("Signal", "Topology", "TOP_NEGOTIATE_EDGE", er._asdict())
        self.top.req_handler_negotiate_edge(cbt)
        self.assertIsNone(ovl.pending_auth_conn_edges.get(peer_id))
        self.assertFalse(cbt.response.status)
        self.assertEqual(ce.edge_state, EdgeStates.Connected)
        
        er = EdgeRequest(overlay_id=overlay_id, edge_id=existing_edge_id, edge_type=EdgeTypesOut.Static,
                         recipient_id=self.top.node_id, initiator_id=peer_id,
                         location_id=self.top.config["Overlays"][overlay_id]["LocationId"],
                         capability=TunnelCapabilities)
        cbt = CBT("Signal", "Topology", "TOP_NEGOTIATE_EDGE", er._asdict())
        ovl = self.top._net_ovls[overlay_id]
        ce.edge_state = EdgeStates.Authorized
        self.top.req_handler_negotiate_edge(cbt)
        self.assertIsNone(ovl.pending_auth_conn_edges.get(peer_id))
        self.assertFalse(cbt.response.status)
        self.assertEqual(ce.edge_state, EdgeStates.Authorized)
        
        print("passed: test_negotiate_incoming_edge_request_collision_fail")                            
        
    def test_complete_negotiate_edge(self):
        peer_id = "2"
        overlay_id = "A0FB389"
        self.top.initialize()
        self._create_peers(overlay_id, int(peer_id)+1)
        ce = ConnectionEdge(peer_id, uuid.uuid4().hex, EdgeTypesOut.OnDemand)
        ce.edge_state = EdgeStates.PreAuth
        ovl = self.top._net_ovls[overlay_id]
        ovl.adjacency_list[ce.peer_id]= ce
        en = EdgeNegotiate(overlay_id=overlay_id, edge_id=ce.edge_id, edge_type=ce.edge_type,
                          recipient_id=ce.peer_id, initiator_id=self.top.node_id,
                          location_id=self.top.config["Overlays"][overlay_id]["LocationId"],
                          capability=TunnelCapabilities, is_accepted=True, message="Edge Accepted",
                          tunnel_type=SupportedTunnels.Tincan)
        self.top._complete_negotiate_edge(ovl, en)
        self.assertEqual(ovl.adjacency_list[peer_id].edge_state, EdgeStates.Authorized)
        print("passed: test_complete_negotiate_edge")
      
    def test_complete_negotiate_edge_accept_collision(self):
        peer_id = "2"
        overlay_id = "A0FB389"
        self.top.initialize()
        self._create_peers(overlay_id, int(peer_id)+1)
        ce = ConnectionEdge(peer_id, uuid.uuid4().hex, EdgeTypesOut.OnDemand)
        ce.edge_state = EdgeStates.PreAuth
        ovl = self.top._net_ovls[overlay_id]
        ovl.adjacency_list[ce.peer_id]= ce
        msg = f"E1 - A valid edge already exists. TunnelId={ce.edge_id[:7]}"

        en = EdgeNegotiate(overlay_id=overlay_id, edge_id=ce.edge_id, edge_type=ce.edge_type,
                           recipient_id=ce.peer_id, initiator_id=ovl.adjacency_list.node_id,
                           location_id=self.top.config["Overlays"][overlay_id]["LocationId"],
                           capability=TunnelCapabilities, is_accepted=True, message="Edge Accepted",
                           tunnel_type=SupportedTunnels.Geneve)
        self.top._complete_negotiate_edge(ovl, en)
        self.assertEqual(ovl.adjacency_list[peer_id].edge_state, EdgeStates.Authorized)
        print("passed: test_complete_negotiate_edge_accept_collision")        

    def test_complete_negotiate_edge_reject_collision(self):
        peer_id = "2"
        overlay_id = "A0FB389"
        self.top.initialize()
        self._create_peers(overlay_id, int(peer_id)+1)
        ce = ConnectionEdge(peer_id, uuid.uuid4().hex, EdgeTypesOut.OnDemand)
        ce.edge_state = EdgeStates.PreAuth
        ovl = self.top._net_ovls[overlay_id]
        ovl.adjacency_list[ce.peer_id]= ce
        msg = f"E2 - Node {peer_id} superceeds edge request due to collision, edge={ce.edge_id[:7]}"
        en = EdgeNegotiate(overlay_id=overlay_id, edge_id=ce.edge_id, edge_type=ce.edge_type,
                         recipient_id=ce.peer_id, initiator_id=ovl.adjacency_list.node_id,
                         location_id=self.top.config["Overlays"][overlay_id]["LocationId"],
                         capability=TunnelCapabilities,
                         is_accepted=False, message=msg, tunnel_type=SupportedTunnels.Tincan)
        ovl.acquire()
        self.top._complete_negotiate_edge(ovl, en)
        self.assertEqual(ovl.adjacency_list[peer_id].edge_state, EdgeStates.PreAuth)
        print("passed: test_complete_negotiate_edge_reject_collision")
              
    def test_complete_negotiate_edge_reject(self):
        peer_id = "2"
        overlay_id = "A0FB389"
        self.top.initialize()
        self._create_peers(overlay_id, int(peer_id)+1)
        ce = ConnectionEdge(peer_id, uuid.uuid4().hex, EdgeTypesOut.OnDemand)
        ce.edge_state = EdgeStates.PreAuth
        ovl = self.top._net_ovls[overlay_id]
        ovl.adjacency_list[ce.peer_id]= ce
        en = EdgeNegotiate(overlay_id=overlay_id, edge_id=ce.edge_id, edge_type=ce.edge_type,
                         recipient_id=ce.peer_id, initiator_id=ovl.adjacency_list.node_id,
                         location_id=self.top.config["Overlays"][overlay_id]["LocationId"],
                         capability=TunnelCapabilities,
                         is_accepted=False, message="E5 - Too many existing edges.",
                         tunnel_type=SupportedTunnels.Tincan)
        ovl.acquire() # increase the ref count to indicate an operation has been started
        self.top._complete_negotiate_edge(ovl, en)
        self.assertEqual(ce.edge_state, EdgeStates.Deleting)
        self.assertNotIn(peer_id, ovl.adjacency_list)
        print("passed: test_complete_negotiate_edge_reject")
                
    def test_initiate_remove_edge(self):
        peer_id = "256"
        self.top.initialize()
        ovl = self.top._net_ovls["A0FB389"]
        ce = ConnectionEdge(peer_id, uuid.uuid4().hex, EdgeTypesOut.LongDistance)
        ce.connected_time = time.time() - (Topology._EDGE_PROTECTION_AGE + 1)
        ce.edge_state = EdgeStates.Connected
        ovl.adjacency_list[peer_id]= ce
        
        is_rem = self.top._initiate_remove_edge(ovl, peer_id)
        self.assertTrue(is_rem)
        self.assertEqual(ovl.adjacency_list[peer_id].edge_state, EdgeStates.Deleting)
        print("passed: test_initiate_remove_edge")
            
###################################################################################################
# GraphTransformation
###################################################################################################

    def test_graph_transformation(self):
        '''Hand crafted test dataset to yeild predetermined results for asserts'''
        adjl1 = ConnEdgeAdjacenctList("A0FB389", "1234434323")
        ce = (ConnectionEdge(
            peer_id="8", edge_id="e8", edge_type="CETypeLongDistance"))
        adjl1[ce.peer_id]= ce
        
        ce = ConnectionEdge(
            peer_id="1", edge_id="e1", edge_type="CETypeSuccessor")
        adjl1[ce.peer_id]= ce
        
        ce = ConnectionEdge(
            peer_id="7", edge_id="e7", edge_type="CETypeLongDistance")
        adjl1[ce.peer_id]= ce
        
        ce = ConnectionEdge(
            peer_id="2", edge_id="e2", edge_type="CETypeSuccessor")
        adjl1[ce.peer_id]= ce
        
        ce = ConnectionEdge(
            peer_id="3", edge_id="e3", edge_type="CETypeLongDistance")
        adjl1[ce.peer_id]= ce
        
        ce = ConnectionEdge(
            peer_id="6", edge_id="e6", edge_type="CETypeStatic")
        adjl1[ce.peer_id]= ce
        
        self.assertEqual(len(adjl1), 6)
        nts = GraphTransformation(ConnEdgeAdjacenctList(
            "A0FB389", "1234434323"), adjl1)
        self.assertTrue(nts[0].priority == UpdatePriority.AddStatic)
        self.assertTrue(nts[1].priority == UpdatePriority.AddSucc)
        self.assertTrue(nts[2].priority == UpdatePriority.AddSucc)
        self.assertTrue(nts[3].priority == UpdatePriority.AddLongDst)
        self.assertTrue(nts[4].priority == UpdatePriority.AddLongDst)
        self.assertTrue(nts[5].priority == UpdatePriority.AddLongDst)
        adjl2 = ConnEdgeAdjacenctList("A0FB389", "1234434323")
        
        ce = ConnectionEdge(
            peer_id="8", edge_id="e8", edge_type="CETypeLongDistance")
        adjl2[ce.peer_id]= ce
        
        ce = ConnectionEdge(
            peer_id="1", edge_id="e1", edge_type="CETypeSuccessor")
        adjl2[ce.peer_id]= ce
        
        ce = ConnectionEdge(
            peer_id="7", edge_id="e7", edge_type="CETypeLongDistance")
        adjl2[ce.peer_id]= ce
        
        ce = ConnectionEdge(
            peer_id="3", edge_id="e3", edge_type="CETypeSuccessor")
        adjl2[ce.peer_id]= ce
        
        ce = ConnectionEdge(
            peer_id="4", edge_id="e4", edge_type="CETypeLongDistance")
        adjl2[ce.peer_id]= ce
        
        ce = ConnectionEdge(
            peer_id="9", edge_id="e9", edge_type="CETypeLongDistance")
        adjl2[ce.peer_id]= ce
        
        ce = ConnectionEdge(
            peer_id="5", edge_id="e5", edge_type="CETypeOnDemand")
        adjl2[ce.peer_id]= ce
        self.assertEqual(len(adjl2), 7)
        nts = GraphTransformation(adjl1, adjl2)
        self.assertTrue(nts[0].priority == UpdatePriority.ModifyExisting)
        self.assertTrue(nts[1].priority == UpdatePriority.AddOnd)
        self.assertTrue(nts[2].priority == UpdatePriority.RmvSucc)
        self.assertTrue(nts[3].priority == UpdatePriority.AddLongDst)
        self.assertTrue(nts[4].priority == UpdatePriority.AddLongDst)
        # note: there is no update entry for the enforced edge being removed as there is no such operation
        while nts:
            self.assertTrue(nts.head())
            nts.pop()
        self.assertFalse(nts)
        print("passed: test_graph_transformation\n")

###################################################################################################
# ConnEdgeAdjacenctList
###################################################################################################

    def test_conn_edge_adjacency_list(self):
        adjl1 = ConnEdgeAdjacenctList("A0FB389", "1234434323", min_succ=1, max_ldl=1, max_ond=1)        
        ce = ConnectionEdge(
            peer_id="1", edge_id="e1", edge_type=EdgeTypesOut.Successor)
        self.assertFalse(adjl1.is_all_successors_connected())
        
        adjl1[ce.peer_id]= ce
        ce.edge_state = EdgeStates.Connected       
        self.assertTrue(adjl1.is_all_successors_connected())
        
        adjl1.min_successors = 2
        self.assertFalse(adjl1.is_all_successors_connected())
        
        ce2 = ConnectionEdge(
            peer_id="3", edge_id="e3", edge_type=EdgeTypesOut.Successor)
        ce2.edge_state = EdgeStates.Connected       
        adjl1[ce2.peer_id]= ce2   
        self.assertTrue(adjl1.is_all_successors_connected())
        
        adjl1.remove_conn_edge(ce2.peer_id)
        self.assertFalse(adjl1.is_all_successors_connected())
        self.assertFalse(adjl1.is_threshold(EdgeTypesIn.ILongDistance))
        
        ce3 = ConnectionEdge(
            peer_id="3", edge_id="e3", edge_type=EdgeTypesIn.ILongDistance)
        adjl1[ce3.peer_id]= ce3
        self.assertTrue(adjl1.is_threshold(EdgeTypesIn.ILongDistance))
        
        ce4 = ConnectionEdge(
            peer_id="3", edge_id="e3", edge_type=EdgeTypesOut.OnDemand)
        adjl1[ce3.peer_id]= ce4
        ce5 = ConnectionEdge(
            peer_id="3", edge_id="e3", edge_type=EdgeTypesOut.LongDistance)
        adjl1.update_edge(ce5)
        self.assertTrue(ce4.edge_type == EdgeTypesOut.LongDistance)
        
        print("passed: test_conn_edge_adjacency_list\n")
        
###################################################################################################
# Main
###################################################################################################
if __name__ == "__main__":
    # unittest.main()
    suite = unittest.TestSuite()
    # NetworkTransition
    suite.addTest(TopologyTest("test_graph_transformation"))
    suite.addTest(TopologyTest("test_conn_edge_adjacency_list"))
    # TopologyManager
    suite.addTest(TopologyTest("test_initialize"))
    suite.addTest(TopologyTest("test_initiate_negotiate_edge"))
    suite.addTest(TopologyTest("test_negotiate_incoming_edge_request"))
    suite.addTest(TopologyTest("test_negotiate_incoming_edge_request_collision_fail"))
    suite.addTest(TopologyTest("test_authorize_incoming_tunnel_geneve"))
    suite.addTest(TopologyTest("test_authorize_incoming_tunnel_wireguard"))
    suite.addTest(TopologyTest("test_authorize_incoming_tunnel_tincan"))
    suite.addTest(TopologyTest("test_select_tunnel_type"))
    suite.addTest(TopologyTest("test_select_tunnel_type_wireguard"))
    suite.addTest(TopologyTest("test_complete_negotiate_edge"))
    suite.addTest(TopologyTest("test_complete_negotiate_edge_accept_collision"))
    suite.addTest(TopologyTest("test_complete_negotiate_edge_reject_collision"))
    suite.addTest(TopologyTest("test_complete_negotiate_edge_reject"))
    suite.addTest(TopologyTest("test_initiate_remove_edge"))
    # suite.addTest(TopologyTest("test_update_overlay"))
    suite.addTest(TopologyTest("test_process_cbt_request_no_action_match"))
    suite.addTest(TopologyTest("test_process_cbt_response_no_action_match"))
    suite.addTest(TopologyTest("test_req_handler_negotiate_edge"))
    suite.addTest(TopologyTest("test_req_handler_tunnl_update"))
    
    runner = unittest.TextTestRunner()
    runner.run(suite)    
