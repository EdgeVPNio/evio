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

import unittest
import importlib
import warnings
import uuid
import logging

from framework.CBT import CBT
from unittest.mock import Mock, MagicMock
from pyroute2 import IPRoute

warnings.filterwarnings(action="ignore", message="unclosed", category=ResourceWarning)
from modules.Tunnel import TunnelStates
from modules.GeneveTunnel import GeneveTunnel

class GeneveTunnelTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(GeneveTunnelTest, self).__init__(*args, **kwargs)
        self.gen: GeneveTunnel = None
        
    @classmethod
    def setUpClass(self):
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
            "GeneveTunnel" : {
                "Overlays": {
                    "A0FB389": {
                        "TapNamePrefix": "gentun",
                        "EndPointAddress": "192.168.0.5"
                    }
                },
                "NodeId": "1234434323"
            }
        }

    @classmethod
    def tearDownClass(self):
        self.config = None

    def setUp(self):
        cfx_handle = Mock()
        self.ipr = IPRoute()
        module = importlib.import_module("modules.{0}"
                                         .format("GeneveTunnel"))
        module_class = getattr(module, "GeneveTunnel")

        self.gen = module_class(cfx_handle, self.config["GeneveTunnel"], "GeneveTunnel")
        cfx_handle._cm_instance = self.gen
        cfx_handle._cm_config = self.config["GeneveTunnel"]
        self.overlay_id = "A0FB389"
        tap_name_prefix = self.config["GeneveTunnel"]["Overlays"][self.overlay_id]["TapNamePrefix"]
        peer_id = self.config["GeneveTunnel"]["NodeId"]
        end_i = 15 - len(tap_name_prefix)
        self.tap_name = tap_name_prefix + str(peer_id[:end_i])
    
    def tearDown(self):
        if self.gen._is_tunnel_exist(self.tap_name):
            try:
                self.ipr.link("del", index=self.ipr.link_lookup(ifname=self.tap_name)[0])
            except:
                pass
        self.ipr.close()
        self.gen = None

    def test_req_handler_create_tunnel(self):
        self.gen.initialize()
        tnlid = uuid.uuid4().hex
        tns = self.gen._tunnels
        cbt = CBT()
        cbt.request.params = {
            "TapNamePrefix": self.config["GeneveTunnel"]["Overlays"][self.overlay_id]["TapNamePrefix"], 
            "TunnelId": tnlid, 
            "VNId": 1234,
            "EndPointAddress": self.config["GeneveTunnel"]["Overlays"][self.overlay_id]["EndPointAddress"],
            "OverlayId": self.overlay_id, 
            "PeerId": self.config["GeneveTunnel"]["NodeId"]}
        self.gen.req_handler_create_tunnel(cbt)
        self.assertIsNotNone(tns.get(tnlid))
        self.assertEqual(tns[tnlid].state, TunnelStates.AUTHORIZED)
        print("Passed : test_req_handler_create_tunnel")

    def test_req_handler_remove_tunnel(self):
        self.gen.initialize()
        cbt = CBT()
        cbt.request.params = {"TapNamePrefix": self.config["GeneveTunnel"]["Overlays"][self.overlay_id]["TapNamePrefix"], 
        "OverlayId": self.overlay_id, 
        "TunnelId": uuid.uuid4().hex,
        "PeerId": self.config["GeneveTunnel"]["NodeId"]
        }
        self.gen.req_handler_remove_tunnel(cbt)

        self.assertFalse(self.gen._is_tunnel_exist(self.tap_name)) 
        idx = self.ipr.link_lookup(ifname=self.tap_name)
        self.assertEqual(len(idx),0)
        print("Passed : test_req_handler_remove_tunnel")

    def test_req_handler_auth_tunnel(self):
        self.gen.initialize()
        node_id = self.config["GeneveTunnel"]["NodeId"]
        cbt = CBT()
        tun_id = uuid.uuid4().hex
        cbt.request.params = {"OverlayId": self.overlay_id, 
                            "PeerId": node_id, 
                            "TunnelId": tun_id}
        self.gen.req_handler_auth_tunnel(cbt)
        peers = self.gen._peers
        self.assertTrue(node_id, peers[self.overlay_id])
        self.assertTrue(self.gen._is_tunnel_authorized(tun_id))
        print("Passed: test_req_handler_auth_tunnel")

    def test_create_geneve_tunnel(self):
        vnid = 1234
        endpntAddr = self.config["GeneveTunnel"]["Overlays"][self.overlay_id]["EndPointAddress"]
        self.gen._create_geneve_tunnel(self.tap_name, vnid, endpntAddr)
        self.assertTrue(self.gen._is_tunnel_exist(self.tap_name))
        idx = self.ipr.link_lookup(ifname=self.tap_name)
        self.assertEqual(len(idx),1)
        print("Passed: test_create_geneve_tunnel")

    def test_req_handler_exchnge_endpt(self):
        pass

    def test_resp_handler_remote_action(self):
        self.gen.initialize()
        # sig_dict, signal = self.setup_vars_mocks()
        cbt = CBT()
        cbt.op_type = "Response"
        cbt.request.action = "SIG_REMOTE_ACTION"
        self.gen.resp_handler_remote_action = MagicMock()
        self.gen.process_cbt(cbt)
        self.gen.resp_handler_remote_action.assert_called_once()
        print("Passed : test_resp_handler_remote_action")

if __name__ == '__main__':
    # unittest.main()
    suite = unittest.TestSuite()
    suite.addTest(GeneveTunnelTest("test_req_handler_auth_tunnel"))
    suite.addTest(GeneveTunnelTest("test_req_handler_create_tunnel"))
    suite.addTest(GeneveTunnelTest("test_req_handler_remove_tunnel"))
    suite.addTest(GeneveTunnelTest("test_resp_handler_remote_action"))
    suite.addTest(GeneveTunnelTest("test_create_geneve_tunnel"))
    
    runner = unittest.TextTestRunner()
    runner.run(suite)        
