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
from modules.Topology import DiscoveredPeer, Topology
from modules.NetworkGraph import ConnectionEdge, ConnEdgeAdjacenctList, EdgeState, EdgeTypes, EdgeTypesOut
from modules.NetworkGraph import NetworkTransitions, UpdatePriority
from modules.NetworkBuilder import NetworkBuilder
from modules.TunnelSelector import EdgeRequest, EdgeNegotiate

TunnelCapabilities=["GENEVE", "TINCAN"]
class TopologyTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TopologyTest, self).__init__(*args, **kwargs)

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
                        "MaxSuccessors": 2,
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
        self.top._net_ovls[olid]["KnownPeers"].clear()
        for peer_id in range(1, num):
            self.top._net_ovls[olid]["KnownPeers"][str(
                peer_id)] = DiscoveredPeer(str(peer_id))

    def test_update_overlay(self):
        self.top.initialize()
        for olid in self.config["Topology"]["Overlays"]:
            self._create_peers(olid, 256)
            self.assertTrue(self.top._net_ovls[olid]["NetBuilder"].is_ready)
            self.top._update_overlay(olid)
            while not self.top._net_ovls[olid]["NetBuilder"].is_ready:
                self.top._update_overlay(olid)
        print("passed: test_update_overlay")

    def test_req_handler_negotiate_edge(self):
        self.top.initialize()
        overlay_id = "A0FB389"
        params = {"overlay_id": overlay_id, "edge_id": "a9e7dd3091a444da8b106e8299dd2ff2",
                  "edge_type": "CETypeStatic", "initiator_id": self.top.node_id,
                  "recipient_id": "512", "location_id": 12345,
                  "capability": TunnelCapabilities}
        edge_cbt = CBT("Signal", "Topology", "TOP_NEGOTIATE_EDGE", params)
        self.top.req_handler_negotiate_edge(edge_cbt)
        self.assertEqual(self.top._net_ovls[overlay_id]["PendingAuthConnEdges"][params["initiator_id"]][0].initiator_id,
                         params["initiator_id"])
        self.assertTrue(self.top._net_ovls[overlay_id]["PendingAuthConnEdges"][params["initiator_id"]][1].is_accepted) 
        print("passed: test_req_handler_negotiate_edge")

  
###################################################################################################
# ConnEdgeAdjacenctList
###################################################################################################      
 
###################################################################################################
# TunnelSelector
###################################################################################################      
    
    def test_negotiate_edge(self):
        pass
  
###################################################################################################
# NetworkBuilder
###################################################################################################
        
    def test_initiate_negotiate_edge(self):
        self.top.initialize()
        ce = ConnectionEdge("128", uuid.uuid4().hex, EdgeTypesOut.Successor)
        netb = self.top._net_ovls["A0FB389"]["NetBuilder"]
        netb._initiate_negotiate_edge(ce)
        self.assertTrue(netb._adj_list)
        self.assertEqual(ce.edge_state, EdgeState.PreAuth)
        print("passed: test_initiate_negotiate_edge")
    
    def test_negotiate_incoming_edge_request(self):
        overlay_id = "A0FB389"
        self.top.initialize()
        cbt = CBT("Signal", "Topology", "TOP_NEGOTIATE_EDGE", {})
        er = EdgeRequest(overlay_id=overlay_id, edge_id=uuid.uuid4().hex, edge_type=EdgeTypesOut.Static,
                         recipient_id=self.top.node_id, initiator_id="256",
                         location_id=self.top.config["Overlays"][overlay_id]["LocationId"],
                         capability=TunnelCapabilities,
                         )
        netb = self.top._net_ovls[overlay_id]["NetBuilder"]
        netb.negotiate_incoming_edge_request(er, cbt)
        self.assertEqual(netb._adj_list[er.initiator_id].edge_state, EdgeState.PreAuth)

        print("passed: test_negotiate_incoming_edge_request")
        
    def test_complete_edge_negotiation(self):
        self.top.initialize()
        ce = ConnectionEdge("256", uuid.uuid4().hex, EdgeTypesOut.OnDemand)
        ce.edge_state = EdgeState.PreAuth
        netb = self.top._net_ovls["A0FB389"]["NetBuilder"]
        netb._adj_list.add_conn_edge(ce)
        en = EdgeNegotiate(overlay_id="A0FB389", edge_id=ce.edge_id, edge_type=ce.edge_type,
                         recipient_id=ce.peer_id, initiator_id=netb._adj_list.node_id,
                         location_id=self.top.config["Overlays"]["A0FB389"]["LocationId"],
                         capability=TunnelCapabilities,
                         is_accepted=True, data="Edge Accepted")
        netb.complete_edge_negotiation(en)
        self.assertEqual(ce.edge_state, EdgeState.Authorized)
        print("passed: test_complete_edge_negotiation")
      
    def test_complete_edge_negotiation_accept_collision(self):
        self.top.initialize()
        ce = ConnectionEdge("256", uuid.uuid4().hex, EdgeTypesOut.OnDemand)
        ce.edge_state = EdgeState.PreAuth
        netb = self.top._net_ovls["A0FB389"]["NetBuilder"]
        netb._adj_list.add_conn_edge(ce)
        msg = f"E1 - A valid edge already exists. TunnelId={ce.edge_id[:7]}"

        en = EdgeNegotiate(overlay_id="A0FB389", edge_id=ce.edge_id, edge_type=ce.edge_type,
                         recipient_id=ce.peer_id, initiator_id=netb._adj_list.node_id,
                         location_id=self.top.config["Overlays"]["A0FB389"]["LocationId"],
                         capability=TunnelCapabilities,
                         is_accepted=True, data="Edge Accepted")
        netb.complete_edge_negotiation(en)
        self.assertEqual(ce.edge_state, EdgeState.Authorized)
        print("passed: test_complete_edge_negotiation_accept_collision")        

    def test_complete_edge_negotiation_reject_collision(self):
        self.top.initialize()
        ce = ConnectionEdge("256", uuid.uuid4().hex, EdgeTypesOut.OnDemand)
        ce.edge_state = EdgeState.PreAuth
        netb = self.top._net_ovls["A0FB389"]["NetBuilder"]
        netb._adj_list.add_conn_edge(ce)
        msg = f"E2 - Node {'256'} superceeds edge request due to collision, edge={ce.edge_id[:7]}"
        en = EdgeNegotiate(overlay_id="A0FB389", edge_id=ce.edge_id, edge_type=ce.edge_type,
                         recipient_id=ce.peer_id, initiator_id=netb._adj_list.node_id,
                         location_id=self.top.config["Overlays"]["A0FB389"]["LocationId"],
                         capability=TunnelCapabilities,
                         is_accepted=False, data=msg)
        netb.complete_edge_negotiation(en)
        self.assertEqual(ce.edge_state, EdgeState.PreAuth)
        print("passed: test_complete_edge_negotiation_reject_collision")
              
    def test_complete_edge_negotiation_reject(self):
        self.top.initialize()
        ce = ConnectionEdge("256", uuid.uuid4().hex, EdgeTypesOut.OnDemand)
        ce.edge_state = EdgeState.PreAuth
        netb = self.top._net_ovls["A0FB389"]["NetBuilder"]
        netb._adj_list.add_conn_edge(ce)
        en = EdgeNegotiate(overlay_id="A0FB389", edge_id=ce.edge_id, edge_type=ce.edge_type,
                         recipient_id=ce.peer_id, initiator_id=netb._adj_list.node_id,
                         location_id=self.top.config["Overlays"]["A0FB389"]["LocationId"],
                         capability=TunnelCapabilities,
                         is_accepted=False, data="E5 - Too many existing edges.")
        netb.complete_edge_negotiation(en)
        self.assertEqual(ce.edge_state, EdgeState.Deleting)
        print("passed: test_complete_edge_negotiation_reject")
                
    def test_initiate_remove_edge(self):
        self.top.initialize()
        netb = self.top._net_ovls["A0FB389"]["NetBuilder"]
        ce = ConnectionEdge("256", uuid.uuid4().hex, EdgeTypesOut.LongDistance)
        ce.connected_time = time.time() - (NetworkBuilder._EDGE_PROTECTION_AGE + 1)
        ce.edge_state = EdgeState.Connected
        netb._adj_list.add_conn_edge(ce)
        
        netb._initiate_remove_edge(ce)
        # self.assertEqual(len(netb._adj_list), 0)
        # self.assertFalse(netb._adj_list)
        print("passed: test_initiate_remove_edge")
        
###################################################################################################
# NetworkTransitions
###################################################################################################

    def test_network_transitions(self):
        '''Hand crafted test dataset to yeild predetermined results for asserts'''
        adjl1 = ConnEdgeAdjacenctList("A0FB389", "1234434323")
        adjl1.add_conn_edge(ConnectionEdge(
            peer_id="8", edge_id="e8", edge_type="CETypeLongDistance"))
        adjl1.add_conn_edge(ConnectionEdge(
            peer_id="1", edge_id="e1", edge_type="CETypeSuccessor"))
        adjl1.add_conn_edge(ConnectionEdge(
            peer_id="7", edge_id="e7", edge_type="CETypeLongDistance"))
        adjl1.add_conn_edge(ConnectionEdge(
            peer_id="2", edge_id="e2", edge_type="CETypeSuccessor"))
        adjl1.add_conn_edge(ConnectionEdge(
            peer_id="3", edge_id="e3", edge_type="CETypeLongDistance"))
        adjl1.add_conn_edge(ConnectionEdge(
            peer_id="6", edge_id="e6", edge_type="CETypeStatic"))
        self.assertEqual(len(adjl1), 6)
        nts = NetworkTransitions(ConnEdgeAdjacenctList(
            "A0FB389", "1234434323"), adjl1)
        self.assertTrue(nts[0].priority == UpdatePriority.AddStatic)
        self.assertTrue(nts[1].priority == UpdatePriority.AddSucc)
        self.assertTrue(nts[2].priority == UpdatePriority.AddSucc)
        self.assertTrue(nts[3].priority == UpdatePriority.AddLongDst)
        self.assertTrue(nts[4].priority == UpdatePriority.AddLongDst)
        self.assertTrue(nts[5].priority == UpdatePriority.AddLongDst)
        adjl2 = ConnEdgeAdjacenctList("A0FB389", "1234434323")
        adjl2.add_conn_edge(ConnectionEdge(
            peer_id="8", edge_id="e8", edge_type="CETypeLongDistance"))
        adjl2.add_conn_edge(ConnectionEdge(
            peer_id="1", edge_id="e1", edge_type="CETypeSuccessor"))
        adjl2.add_conn_edge(ConnectionEdge(
            peer_id="7", edge_id="e7", edge_type="CETypeLongDistance"))
        adjl2.add_conn_edge(ConnectionEdge(
            peer_id="3", edge_id="e3", edge_type="CETypeSuccessor"))
        adjl2.add_conn_edge(ConnectionEdge(
            peer_id="4", edge_id="e4", edge_type="CETypeLongDistance"))
        adjl2.add_conn_edge(ConnectionEdge(
            peer_id="9", edge_id="e9", edge_type="CETypeLongDistance"))
        adjl2.add_conn_edge(ConnectionEdge(
            peer_id="5", edge_id="e5", edge_type="CETypeOnDemand"))
        self.assertEqual(len(adjl2), 7)
        nts = NetworkTransitions(adjl1, adjl2)
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
        print("passed: test_netop_diff\n")


if __name__ == "__main__":
    # unittest.main()
    suite = unittest.TestSuite()
    # NetworkTransition
    suite.addTest(TopologyTest("test_network_transitions"))
    #NetworkBuilder
    suite.addTest(TopologyTest("test_initiate_negotiate_edge"))
    suite.addTest(TopologyTest("test_negotiate_incoming_edge_request"))
    suite.addTest(TopologyTest("test_complete_edge_negotiation"))
    suite.addTest(TopologyTest("test_complete_edge_negotiation_accept_collision"))
    suite.addTest(TopologyTest("test_complete_edge_negotiation_reject_collision"))
    suite.addTest(TopologyTest("test_complete_edge_negotiation_reject"))
    suite.addTest(TopologyTest("test_initiate_remove_edge"))
    # TopologyManager
    suite.addTest(TopologyTest("test_initialize"))
    suite.addTest(TopologyTest("test_process_cbt_request_no_action_match"))
    suite.addTest(TopologyTest("test_process_cbt_response_no_action_match"))
    suite.addTest(TopologyTest("test_req_handler_negotiate_edge"))
    suite.addTest(TopologyTest("test_update_overlay"))
    runner = unittest.TextTestRunner()
    runner.run(suite)    
