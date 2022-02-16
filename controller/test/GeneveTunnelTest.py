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
from framework.CBT import CBT
from unittest.mock import MagicMock, Mock, patch

from modules.GeneveTunnel import GeneveTunnel

class GeneveTunnelTestCase(unittest.TestCase):
    def setup(self):
        logging.basicConfig(format="[%(asctime)s.%(msecs)03d] %(levelname)s: %(message)s",
                            datefmt="%H:%M:%S",
                            level=logging.DEBUG)
        cfx_handle = Mock()
        module = importlib.import_module("modules.{0}"
                                         .format("GeneveTunnel"))
        module_class = getattr(module, "GeneveTunnel")
        gen_dict = {
            "GeneveTunnel" : {
                "Overlays": {
                    "A0FB389": {
                        "dev_name": "gentun", 
                        "id": "1234", 
                        "node_a": "192.168.0.5", 
                        "node_b": "192.168.0.6",
                        "dst_port": None
                    }
                },
                "NodeId": "1234434323"
            }
        }

        geneveTunnel = module_class(cfx_handle, gen_dict, "GeneveTunnel")
        cfx_handle._cm_instance = geneveTunnel
        cfx_handle._cm_config = gen_dict
        geneveTunnel.initialize()
        self.logger = logging.getLogger("GeneveTunnelTest console logger")
        return gen_dict, geneveTunnel

    def test_create_geneve_tunnel(self):
        """
        Test to check the creation of geneve tunnel.
        """
        gen_dict, geneveTunnel = self.setup()
        
        geneveTunnel._create_geneve_tunnel(gen_dict["GeneveTunnel"]["dev_name"], gen_dict["id"], gen_dict["remote_addr"], gen_dict["dst_port"])
        # geneveTunnel._create_geneve_tunnel = MagicMock()
        # geneveTunnel._create_geneve_tunnel.assert_called_once()

    def test_request_create_geneve_tunnel(self):
        """
        Test to check the creation of geneve tunnel.
        """
        gen_dict, geneveTunnel = self.setup()
        cbt = CBT()
        cbt.request.params = {"dev_name": "gentun", "id": "1234", "remote_addr": "192.160.0.5", "dst_port": None}
        geneveTunnel.req_handler_create_tunnel(cbt)

        # tunnel.req_handler_create_tunnel = MagicMock()
        # tunnel.req_handler_create_tunnel.assert_called_once()

if __name__ == '__main__':
    unittest.main()