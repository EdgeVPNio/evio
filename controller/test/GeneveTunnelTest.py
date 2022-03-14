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

from framework.CBT import CBT
from unittest.mock import Mock
from pyroute2 import IPRoute

warnings.filterwarnings(action="ignore", message="unclosed", category=ResourceWarning)
from modules.GeneveTunnel import GeneveTunnel

class GeneveTunnelTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(GeneveTunnelTest, self).__init__(*args, **kwargs)

    @classmethod
    def setUpClass(self):
        self.config = {
            "GeneveTunnel" : {
                "Overlays": {
                    "A0FB389": {
                        "DevNamePrefix": "gentun", 
                        "NodeA": "192.168.0.5", 
                        "NodeB": "192.168.0.6",
                        "DestPort": None
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
        module = importlib.import_module("modules.{0}"
                                         .format("GeneveTunnel"))
        module_class = getattr(module, "GeneveTunnel")

        self.geneveTunnel = module_class(cfx_handle, self.config["GeneveTunnel"], "GeneveTunnel")
        cfx_handle._cm_instance = self.geneveTunnel
        cfx_handle._cm_config = self.config["GeneveTunnel"]
    
    def tearDown(self):
        self.genevetunnel = None

    def test_create_geneve_tunnel(self):
        """
        Test to check the creation of geneve tunnel.
        """
        cbt = CBT()
        cbt.request.params = {"DevNamePrefix": self.config["GeneveTunnel"]["Overlays"]["A0FB389"]["DevNamePrefix"], 
        "TunnelId": uuid.uuid4().hex, 
        "LocationId": 1234,
        "RemoteAddr": self.config["GeneveTunnel"]["Overlays"]["A0FB389"]["NodeA"], 
        "DstPort": self.config["GeneveTunnel"]["Overlays"]["A0FB389"]["DestPort"], 
        "OverlayId": self.config["GeneveTunnel"]["Overlays"], 
        "PeerId": self.config["GeneveTunnel"]["NodeId"]
        }
        self.geneveTunnel.req_handler_auth_tunnel(cbt)
        self.geneveTunnel.req_handler_create_tunnel(cbt)

        peer_id = self.config["GeneveTunnel"]["NodeId"]
        tap_name_prefix = self.config["GeneveTunnel"]["Overlays"]["A0FB389"]["DevNamePrefix"]
        end_i = 15 - len(tap_name_prefix)
        tap_name = tap_name_prefix + str(peer_id[:end_i])

        self.assertTrue(self.geneveTunnel._is_tunnel_exist(tap_name))
        ipr = IPRoute() 
        idx = ipr.link_lookup(ifname=tap_name)
        self.assertEqual(len(idx),1)
        print("Passed : test_req_handler_create_tunnel")

    def test_remove_geneve_tunnel(self):
        """
        Test to check the deletion of geneve tunnel.
        """
        cbt = CBT()
        cbt.request.params = {"DevNamePrefix": self.config["GeneveTunnel"]["Overlays"]["A0FB389"]["DevNamePrefix"], 
        "OverlayId": self.config["GeneveTunnel"]["Overlays"], 
        "PeerId": self.config["GeneveTunnel"]["NodeId"]
        }
        self.geneveTunnel.req_handler_remove_tunnel(cbt)
        tap_name_prefix = self.config["GeneveTunnel"]["Overlays"]["A0FB389"]["DevNamePrefix"]
        peer_id = self.config["GeneveTunnel"]["NodeId"]
        end_i = 15 - len(tap_name_prefix)
        tap_name = tap_name_prefix + str(peer_id[:end_i])

        self.assertFalse(self.geneveTunnel._is_tunnel_exist(tap_name))
        ipr = IPRoute() 
        idx = ipr.link_lookup(ifname=tap_name)
        self.assertEqual(len(idx),0)
        print("Passed : test_req_handler_remove_tunnel")

    def test_req_handler_auth_tunnel(self):
        """
        Test to check the authorization of geneve tunnel.
        """
        cbt = CBT()
        tun_id = uuid.uuid4().hex
        cbt.request.params = {"OverlayId": "A0FB389", 
                            "PeerId": self.config["GeneveTunnel"]["NodeId"], 
                            "TunnelId": tun_id}
        self.geneveTunnel.req_handler_auth_tunnel(cbt)
        self.assertTrue(self.geneveTunnel._is_tunnel_authorized(tun_id))
        print("Passed: test_req_handler_auth_tunnel")
       
if __name__ == '__main__':
    unittest.main()
