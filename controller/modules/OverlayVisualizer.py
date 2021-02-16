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
from collections import defaultdict
import requests
import zlib
from framework.ControllerModule import ControllerModule


class OverlayVisualizer(ControllerModule):
    def __init__(self, cfx_handle, module_config, module_name):
        super(OverlayVisualizer, self).__init__(cfx_handle,
                                                module_config, module_name)
        self._vis_ds_lock = threading.Lock()
        self._vis_req_publisher = None
        self._evio_version = self._cfx_handle.query_param("Version")
        self._vis_ds = dict(NodeId=self.node_id, VizData=defaultdict(dict))
        # Visualizer webservice URL
        self._vis_address = "http://" + self._cm_config["WebServiceAddress"]
        self._req_url = "{}/EVIO/nodes/{}".format(self._vis_address, self.node_id)

    def initialize(self):
        # We're using the pub-sub model here to gather data for the visualizer
        # from other modules
        # Using this publisher, the OverlayVisualizer publishes events in the
        # timer_method() and all subscribing modules are expected to reply
        # with the data they want to forward to the visualiser
        self._vis_req_publisher = \
            self._cfx_handle.publish_subscription("VIS_DATA_REQ")

        self.register_cbt("Logger", "LOG_INFO", "Module loaded")

    def process_cbt(self, cbt):
        if cbt.op_type == "Response":
            if cbt.request.action == "VIS_DATA_REQ":
                msg = cbt.response.data

                if cbt.response.status and msg:
                    with self._vis_ds_lock:
                        for mod_name in msg:
                            for ovrl_id in msg[mod_name]:
                                self._vis_ds["VizData"][ovrl_id][mod_name] = msg[mod_name][ovrl_id]
                else:
                    warn_msg = "Got no data in CBT response from module" \
                        " {}".format(cbt.request.recipient)
                    self.register_cbt("Logger", "LOG_WARNING", warn_msg)
                self.free_cbt(cbt)
            else:
                parent_cbt = cbt.parent
                cbt_data = cbt.response.data
                cbt_status = cbt.response.status
                self.free_cbt(cbt)
                if (parent_cbt is not None and parent_cbt.child_count == 1):
                    parent_cbt.set_response(cbt_data, cbt_status)
                    self.complete_cbt(parent_cbt)

        else:
            self.req_handler_default(cbt)

    def timer_method(self):
        collector_msg = None
        with self._vis_ds_lock:
            collector_msg = self._vis_ds
            # flush old data, next itr provides new data
            self._vis_ds = dict(NodeId=self.node_id,
                                VizData=defaultdict(dict))
        if "NodeName" in self._cm_config:
            collector_msg["NodeName"] = self._cm_config["NodeName"]
        if "GeoCoordinate" in self._cm_config:
            collector_msg["GeoCoordinate"] = self._cm_config["GeoCoordinate"]
        collector_msg["Version"] = self._evio_version
        data_log = "Submitting collector data {}".format(collector_msg)
        self.register_cbt("Logger", "LOG_DEBUG", data_log)
        try:
            resp = requests.put(self._req_url,
                                data=zlib.compress(json.dumps(collector_msg).encode('utf-8')),
                                headers={"Content-Type":
                                             "application/json",
                                         "Content-Encoding": "deflate"})
            resp.raise_for_status()
        except requests.exceptions.RequestException as err:
            err_msg = "Failed to send data to the collector webservice" \
                " ({0}). Exception: {1}" \
                .format(self._req_url, str(err))
            self.register_cbt("Logger", "LOG_WARNING", err_msg)

        # Now that all the accumulated data has been dealt with, we request more data
        self._vis_req_publisher.post_update(None)

    def terminate(self):
        pass
