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

import datetime
import hashlib
import threading
try:
    import simplejson as json
except ImportError:
    import json
import urllib.request as urllib2
from framework.ControllerModule import ControllerModule


class UsageReport(ControllerModule):
    def __init__(self, cfx_handle, module_config, module_name):
        super(UsageReport, self).__init__(cfx_handle, module_config, module_name)
        self._stat_data = None #{"ready": False, "pending_request": False}
        #self.submit_time = datetime.datetime(2015, 1, 1, 0, 0)
        self.lck = threading.Lock()
        self._report_id = 0

    def initialize(self):
        self.register_cbt("Logger", "LOG_INFO", "{0} Loaded".format(self._module_name))

    def process_cbt(self, cbt):
        if cbt.op_type == "Response":
            if cbt.request.action == "SIG_QUERY_REPORTING_DATA":
                if not cbt.response.status:
                    self.register_cbt("Logger", "LOG_WARNING",
                                      "CBT failed {0}".format(cbt.response.data))
                    self.free_cbt(cbt)
                else:
                    self.create_report(cbt)
            else:
                self.resp_handler_default(cbt)
        else:
            self.req_handler_default(cbt)

    def timer_method(self):
        cur_time = datetime.datetime.now()
        self.lck.acquire()
        if self._stat_data["ready"]:
            data = self._stat_data["data"]
            self._stat_data = {}
            self._stat_data["ready"] = False
            self._stat_data["pending_request"] = False
            self.lck.release()
            self.submit_report(data)
            self.submit_time = datetime.datetime.now()
        elif not self._stat_data["pending_request"] and cur_time > self.submit_time:
            self._stat_data["pending_request"] = True
            self.lck.release()
            self.request_report()

    def terminate(self):
        pass

    def request_report(self):
        self.register_cbt("Signal", "SIG_QUERY_REPORTING_DATA")

    def create_report(self, cbt):
        nid = self.node_id
        report_data = cbt.response.data
        for overlay_id in report_data:
            report_data[overlay_id] = {
                "xmpp_host": hashlib.sha1(report_data[overlay_id]["xmpp_host"].\
                                          encode("utf-8")).hexdigest(),
                "xmpp_username": hashlib.sha1(report_data[overlay_id]["xmpp_username"].\
                                              encode("utf-8")).hexdigest(),
            }
        stat = {
            "NodeId": hashlib.sha1(nid.encode("utf-8")).hexdigest(),
            "Time": str(datetime.datetime.now()),
            "Model": self._cfx_handle.query_param("Model"),
            "Version": self._cfx_handle.query_param("EvioVersion")
        }
        stat.update(report_data)
        self.lck.acquire()
        self._stat_data["data"] = stat
        self._stat_data["ready"] = True
        self._stat_data["pending_request"] = False
        self.lck.release()
        self.free_cbt(cbt)

    def submit_report(self, report_data):
        data = json.dumps(report_data).encode('utf8')
        self.register_cbt("Logger", "LOG_DEBUG", "Usage report data: {0}".format(data))
        url = None
        try:
            url = "http://" + self._cm_config["ServerAddress"] + ":" + \
                  str(self._cm_config["ServerPort"]) + "/api/submit"
            req = urllib2.Request(url=url, data=data)
            req.add_header("Content-Type", "application/json")
            res = urllib2.urlopen(req)
            if res.getcode() == 200:
                log = "Usage report successfully submitted to server {0}\n" \
                      "HTTP response code:{1}, msg:{2}" \
                    .format(url, res.getcode(), res.read())
                self.register_cbt("Logger", "LOG_INFO", log)
            else:
                self.register_cbt("Logger", "LOG_WARNING",
                                  "Usage report server indicated error "
                                  "code: {0}".format(res.getcode()))
        except (urllib2.HTTPError, urllib2.URLError) as error:
            log = "Usage report submission failed to server {0}. " \
                  "Error: {1}".format(url, error)
            self.register_cbt("Logger", "LOG_WARNING", log)
