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

try:
    import simplejson as json
except ImportError:
    import json

import threading
import time
import zlib
from collections import defaultdict
from datetime import datetime

import requests
from broker.controller_module import ControllerModule


class OverlayVisualizer(ControllerModule):
    def __init__(self, nexus, module_config):
        super().__init__(nexus, module_config)
        self._vis_ds_lock = threading.Lock()
        self._vis_req_publisher = None
        # Visualizer webservice URL
        self._vis_address = "http://" + self.config["WebServiceAddress"]
        self._req_url = "{}/EVIO/nodes/{}".format(self._vis_address, self.node_id)
        self._vis_ds: dict
        self._boot_time = str(datetime.fromtimestamp(time.time()))

    def initialize(self):
        # We're using the pub-sub model here to gather data for the visualizer
        # from other modules
        # Using this publisher, the OverlayVisualizer publishes events in the
        # timer_method() and all subscribing modules are expected to reply
        # with the data they want to forward to the visualiser
        self._vis_ds = self.init_viz_data()
        self._vis_req_publisher = self.publish_subscription("VIS_DATA_REQ")

        self.logger.info("Controller module loaded")
        self.post_viz_data(self.init_viz_data())

    def init_viz_data(self, boot_time=None):
        ds = dict(NodeId=self.node_id, VizData=defaultdict(dict))
        ds["BootTime"] = self._boot_time
        ds["Version"] = self.version
        for olid in self.registered_overlay_ids:
            ds["VizData"][olid] = defaultdict(dict, Tunnels=defaultdict(dict))
        if "NodeName" in self.config:
            ds["NodeName"] = self.config["NodeName"]
        if "GeoCoordinate" in self.config:
            ds["GeoCoordinate"] = self.config["GeoCoordinate"]
        return ds

    def process_cbt(self, cbt):
        if cbt.op_type == "Response":
            if cbt.request.action == "VIS_DATA_REQ":
                msg = cbt.response.data
                if cbt.response.status and msg:
                    with self._vis_ds_lock:
                        for mod_name in msg:
                            for olid in msg[mod_name]:
                                self._vis_ds["VizData"][olid][mod_name] = msg[mod_name][
                                    olid
                                ]
                self.free_cbt(cbt)
            else:
                self.req_handler_default(cbt)
        else:
            self.req_handler_default(cbt)

    def post_viz_data(self, viz_data):
        try:
            viz_data = json.dumps(viz_data).encode("utf-8")
            self.logger.debug("Posting viz data: %s", viz_data)
            resp = requests.put(
                self._req_url,
                data=zlib.compress(viz_data),
                headers={
                    "Content-Type": "application/json",
                    "Content-Encoding": "deflate",
                },
            )
            resp.raise_for_status()
        except requests.exceptions.RequestException as err:
            err_msg = (
                "Failed to send data to the collector webservice"
                " ({0}). Exception: {1}".format(self._req_url, str(err))
            )
            self.logger.warning(err_msg)

    def build_tunnel_data(self, ds):
        for olid in ds["VizData"]:
            if "Topology" in ds["VizData"][olid]:
                for tnlid in ds["VizData"][olid]["Topology"]:
                    ds["VizData"][olid]["Tunnels"][tnlid] = ds["VizData"][olid][
                        "Topology"
                    ][tnlid]
            if "LinkManager" in ds["VizData"][olid]:
                for tnlid in ds["VizData"][olid]["LinkManager"]:
                    ds["VizData"][olid]["Tunnels"][tnlid].update(
                        ds["VizData"][olid]["LinkManager"][tnlid]
                    )
            ds["VizData"][olid].pop("LinkManager", None)
            ds["VizData"][olid].pop("Topology", None)
        return ds

    def timer_method(self, is_exiting=False):
        if is_exiting:
            return
        viz_ds = None
        with self._vis_ds_lock:
            viz_ds = self._vis_ds
            self._vis_ds = self.init_viz_data()
        msg = self.build_tunnel_data(viz_ds)
        self.post_viz_data(msg)
        self._vis_req_publisher.post_update(None)

    def terminate(self):
        self.logger.info("Module Terminating")
