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
import logging
import importlib
import warnings
import uuid

from framework.CBT import CBT
from unittest.mock import MagicMock, Mock, patch
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
                        "DeviceName": "gentun", 
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

        # self.logger = logging.getLogger("GeneveTunnelTest console logger")
        # return self.config["GeneveTunnel"], self.geneveTunnel
    
    def tearDown(self):
        self.genevetunnel = None

    def test_create_geneve_tunnel(self):
        """
        Test to check the creation of geneve tunnel.
        """
        # self.config["GeneveTunnel"], geneveTunnel = self.setUp()
        cbt = CBT()
        cbt.request.params = {"DeviceName": self.config["GeneveTunnel"]["Overlays"]["A0FB389"]["DeviceName"], 
        "TunnelId": uuid.uuid4().hex, 
        "RemoteAddr": self.config["GeneveTunnel"]["Overlays"]["A0FB389"]["NodeA"], 
        "DstPort": self.config["GeneveTunnel"]["Overlays"]["A0FB389"]["DestPort"], 
        "OverlayId": self.config["GeneveTunnel"]["Overlays"], 
        "PeerId": self.config["GeneveTunnel"]["NodeId"]
        }
        self.geneveTunnel.req_handler_auth_tunnel(cbt)
        self.geneveTunnel.req_handler_create_tunnel(cbt)
        self.assertTrue(self.geneveTunnel._is_tunnel_exist(self.config["GeneveTunnel"]["Overlays"]["A0FB389"]["DeviceName"]))
        ipr = IPRoute() 
        idx = ipr.link_lookup(ifname=self.config["GeneveTunnel"]["Overlays"]["A0FB389"]["DeviceName"])
        self.assertEqual(len(idx),1)
        print("Passed : test_req_handler_create_tunnel")

    def test_remove_geneve_tunnel(self):
        """
        Test to check the deletion of geneve tunnel.
        """
        # self.config["GeneveTunnel"], geneveTunnel = self.setUp()
        cbt = CBT()
        cbt.request.params = {"DeviceName": self.config["GeneveTunnel"]["Overlays"]["A0FB389"]["DeviceName"]}
        self.geneveTunnel.req_handler_remove_tunnel(cbt)
        self.assertFalse(self.geneveTunnel._is_tunnel_exist(self.config["GeneveTunnel"]["Overlays"]["A0FB389"]["DeviceName"]))
        ipr = IPRoute() 
        idx = ipr.link_lookup(ifname=self.config["GeneveTunnel"]["Overlays"]["A0FB389"]["DeviceName"])
        self.assertEqual(len(idx),0)
        print("Passed : test_req_handler_remove_tunnel")

    def test_req_handler_auth_tunnel(self):
        """
        Test to check the authorization of geneve tunnel.
        """
        # self.config["GeneveTunnel"], geneveTunnel = self.setUp()
        cbt = CBT()
        cbt.request.params = {"OverlayId": "A0FB389", 
                            "PeerId": self.config["GeneveTunnel"]["NodeId"], 
                            "TunnelId": uuid.uuid4().hex}
        self.geneveTunnel.req_handler_auth_tunnel(cbt)
        self.assertTrue(self.geneveTunnel._is_tunnel_authorized(uuid.uuid4().hex))
        print("Passed: test_req_handler_auth_tunnel")
       
if __name__ == '__main__':
    unittest.main()
