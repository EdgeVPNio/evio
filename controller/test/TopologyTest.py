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
import unittest
from unittest.mock import MagicMock, Mock, patch

from framework.CBT import CBT
from framework.CFxHandle import CFxHandle
from modules.NetworkOperations import NetworkTransitions
from modules.Topology import DiscoveredPeer
from modules.NetworkGraph import NetworkTransitions
from modules.NetworkGraph import ConnEdgeAdjacenctList
from modules.NetworkGraph import ConnectionEdge
from modules.NetworkGraph import EdgeState


class TopologyTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TopologyTest, self).__init__(*args, **kwargs)
    
    @classmethod
    def setUpClass(self):
        print("setUpClass")
        _logger = logging.getLogger()
        _logger.setLevel(logging.DEBUG)
        # Console Logger
        console_handler = logging.StreamHandler()
        console_log_formatter = logging.Formatter(
            "[%(asctime)s.%(msecs)03d] %(levelname)s:%(name)s: %(message)s",
            datefmt="%H:%M:%S")
        console_handler.setFormatter(console_log_formatter)
        _logger.addHandler(console_handler)
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
                        "EncryptionRequired": False
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
        self.top = module_class(cfx_handle, self.config["Topology"], "Topology")
        cfx_handle._cm_instance = self.top
        cfx_handle._cm_config = self.config["Topology"]

    def tearDown(self):
        self.top = None

    def test_initialize(self):
        self.top.initialize()
        self.assertTrue(self.top._net_ovls)
        print("passed: initialize")

    # def test_do_topo_change_post(self):
    #     # self.top._do_topo_change_post(overlay_id)
    #     pass
    
    # def test_trim_inactive_peers(self):
    #     # self.top._trim_inactive_peers(olid)
    #     pass

    def test_process_cbt_request_no_action_match(self):
        self.top.initialize()
        with self.assertLogs(level=logging.WARNING):
            cbt = CBT("NO_ONE", "Topology", "INVALID_REQ_CODE", {"OverlayId": "A0FB389", "NodeId": "1234434323"} )
            self.top.process_cbt(cbt)
        print("passed: process_cbt_request_no_action_match")
            
    def test_process_cbt_response_no_action_match(self):
        self.top.initialize()
        with self.assertLogs(level=logging.DEBUG):
            cbt = CBT("Topology", "Topology", "INVALID_REQ_CODE", {"OverlayId": "A0FB389", "NodeId": "1234434323"} )
            cbt.set_response({}, status=True)
            self.top.process_cbt(cbt)
        print("passed: cbt_response_no_action_match")
            
    def _create_peers(self):
        for olid in self.config["Topology"]["Overlays"]:
            for peer_id in range(1, 256):
                self.top._net_ovls[olid]["KnownPeers"][str(peer_id)] = DiscoveredPeer(str(peer_id))
    
    def test_update_overlay(self):
        self.top.initialize()
        self._create_peers()
        for olid in self.config["Topology"]["Overlays"]:
            self.assertTrue(self.top._net_ovls[olid]["NetBuilder"].is_ready)
            self.top._update_overlay(olid)
        print("passed: test_update_overlay")
                    
###########################################################################################################################
# NetworkOperations                
###########################################################################################################################

    def test_netop_diff(self):
        adjl1 = ConnEdgeAdjacenctList("A0FB389", "1234434323")
        adjl1.add_conn_edge(ConnectionEdge(peer_id="8", edge_id="e8", edge_type="CETypeLongDistance"))
        adjl1.add_conn_edge(ConnectionEdge(peer_id="1", edge_id="e1", edge_type="CETypeSuccessor"))
        adjl1.add_conn_edge(ConnectionEdge(peer_id="7", edge_id="e7", edge_type="CETypeLongDistance"))
        adjl1.add_conn_edge(ConnectionEdge(peer_id="2", edge_id="e2", edge_type="CETypeSuccessor"))
        adjl1.add_conn_edge(ConnectionEdge(peer_id="3", edge_id="e3", edge_type="CETypeLongDistance"))
        adjl1.add_conn_edge(ConnectionEdge(peer_id="6", edge_id="e6", edge_type="CETypeLongDistance"))
        self.assertEqual(len(adjl1), 6)
        nts = NetworkTransitions(ConnEdgeAdjacenctList("A0FB389", "1234434323"), adjl1)
        for tm in nts:
            print (tm)
        print("\n\n")

        adjl1["2"].connected_time = time.time() - 180    # min edge age before its considered for delete
        adjl1["2"].edge_state = EdgeState.Connected
        adjl2 = ConnEdgeAdjacenctList("A0FB389", "1234434323")
        adjl2.add_conn_edge(ConnectionEdge(peer_id="8", edge_id="e8", edge_type="CETypeLongDistance"))
        adjl2.add_conn_edge(ConnectionEdge(peer_id="1", edge_id="e1", edge_type="CETypeSuccessor"))
        adjl2.add_conn_edge(ConnectionEdge(peer_id="7", edge_id="e7", edge_type="CETypeLongDistance"))
        adjl2.add_conn_edge(ConnectionEdge(peer_id="3", edge_id="e3", edge_type="CETypeSuccessor"))
        adjl2.add_conn_edge(ConnectionEdge(peer_id="6", edge_id="e6", edge_type="CETypeLongDistance"))
        adjl2.add_conn_edge(ConnectionEdge(peer_id="4", edge_id="e4", edge_type="CETypeLongDistance"))
        adjl2.add_conn_edge(ConnectionEdge(peer_id="9", edge_id="e9", edge_type="CETypeLongDistance"))
        adjl2.add_conn_edge(ConnectionEdge(peer_id="5", edge_id="e5", edge_type="CETypeOnDemand"))
        self.assertEqual(len(adjl2), 8)
        nts = NetworkTransitions(adjl1, adjl2)
        #self.assertNotEqual(len(adjl2), len(nts))
        for tm in nts:
            print (tm)
        self.assertFalse(nts)                
        print("passed: test_netop_diff")

if __name__ == '__main__':
    unittest.main()
