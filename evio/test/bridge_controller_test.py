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
import unittest
import warnings
from unittest.mock import MagicMock

from broker.cbt import CBT

warnings.filterwarnings(action="ignore", message="unclosed", category=ResourceWarning)
from evio.controllers.bridge_controller import BridgeController


class BridgeControllerTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.brctl: BridgeController = None

    @classmethod
    def setUpClass(self):
        _logger = logging.getLogger()
        _logger.setLevel(logging.DEBUG)
        # Console Logger
        console_handler = logging.StreamHandler()
        console_log_formatter = logging.Formatter(
            "[%(asctime)s.%(msecs)03d] %(levelname)s:%(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )
        console_handler.setFormatter(console_log_formatter)
        _logger.addHandler(console_handler)
        self.config = {
            "BridgeController": {
                "BoundedFlood": {"Overlays": {"A0FB389": {}}},
                "Overlays": {
                    "A0FB389": {
                        "NetDevice": {"AppBridge": {"IP4": "10.1.1.1", "PrefixLen": 24}}
                    }
                },
                "NodeId": "1234434323",
            }
        }

    @classmethod
    def tearDownClass(self):
        self.config = None

    def setUp(self):
        nexus = MagicMock()
        module = importlib.import_module("controllers.{0}".format("BridgeController"))
        module_class = getattr(module, "BridgeController")

        self.brctl = module_class(
            nexus, self.config["BridgeController"], "BridgeController"
        )
        nexus._cm_instance = self.brctl
        nexus._cm_config = self.config["BridgeController"]
        self.overlay_id = "A0FB389"

    def tearDown(self):
        self.brctl = None

    def test_initialize(self):
        self.brctl.initialize()
        print("Passed : test_initialize")


if __name__ == "__main__":
    suite = unittest.TestSuite()
    suite.addTest(BridgeControllerTest("test_initialize"))
    # suite.addTest(BridgeControllerTest("test_req_handler_"))
    # suite.addTest(BridgeControllerTest("test_req_handler_"))
    # suite.addTest(BridgeControllerTest("test_req_handler_"))
    # suite.addTest(BridgeControllerTest("test_resp_handler_"))

    runner = unittest.TextTestRunner()
    runner.run(suite)
