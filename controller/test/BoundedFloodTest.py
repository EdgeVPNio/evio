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

from queue import Queue
from time import sleep
import time
import unittest
# from unittest.mock import MagicMock, Mock, patch
import logging
import logging.handlers as lh

from evio.controller.modules.BoundedFlood import EvioPortal

class BoundedFloodTestCase(unittest.TestCase):

    def setUp(self):
        # Console logging
        logging.basicConfig(format="[%(asctime)s.%(msecs)03d] %(levelname)s: %(message)s",
                            datefmt="%H:%M:%S",
                            level=logging.DEBUG)
        self.logger = logging.getLogger("BoundedFloodTest console logger")
        self.config = {
                    "NodeId": "a100019ffffffffffffffffffffff019",
                    "LogDir": "/var/log/evio/",
                    "LogFilename": "bf.log",
                    "LogLevel": "DEBUG",
                    "MaxBytes": 10000000,
                    "BackupCount": 2,
                    "MonitorInterval": 60,
                    "ProxyListenAddress": "localhost",
                    "ProxyListenPort": 5802,
                    "evioT022221": {
                        "OverlayId": "T022221",
                        "DemandThreshold": "100M",
                        "FlowIdleTimeout": 60,
                        "FlowHardTimeout": 60,
                        "MulticastBroadcastInterval": 60,
                        "MaxOnDemandEdges": 3
                    },
                    "eviTB214": {
                        "OverlayId": "TB214",
                        "DemandThreshold": "1000M",
                        "FlowIdleTimeout": 60,
                        "FlowHardTimeout": 60,
                        "MulticastBroadcastInterval": 60,
                        "MaxOnDemandEdges": 5
                    },
                    "eviC03": {
                        "OverlayID": "C03",
                        "FlowIdleTimeout": 60,
                        "FlowHardTimeout": 60,
                        "MulticastBroadcastInterval": 60,
                        "MaxOnDemandEdges": 0
                    }
        }
                
    def tearDown(self):
        del self.logger
        self.logger = None
        del self.config
        self.config = None
        
    def setup_vars_mocks(self):
        """
        Setup the variables and the mocks required by the unit tests.
        :return: The EvioPortal object
        """
        svr_addr = (self.config["ProxyListenAddress"], self.config["ProxyListenPort"])
        ep = EvioPortal(svr_addr, self.logger)
        return ep

    def testevio_portal_send_recv(self):
        """
        Test to check the connect to server of the transport instance of the signal class.
        """
        evio_portal = self.setup_vars_mocks()
        req = dict(Request=dict(Action="GetTunnels", Params=dict(OverlayId=self.config["evioT022221"]["OverlayId"])))
        resp = evio_portal.send_recv(req)
        evio_portal.terminate()
        self.assertTrue((resp is not None) and (resp["Response"]["Status"] is True))
        #self.assert (not resp["Response"]["Data"] is None)
        print("Passed : testevio_portal_send_recv")


if __name__ == '__main__':
    unittest.main()
