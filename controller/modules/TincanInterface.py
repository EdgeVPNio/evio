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

import socket
import select
try:
    import simplejson as json
except ImportError:
    import json
from threading import Thread
import traceback
from distutils import spawn
import framework.Modlib as modlib
from framework.ControllerModule import ControllerModule
import framework.Version as ver

MaxReadSize = 65507,               # Max buffer size for Tincan Messages
SocketReadWaitTime = 15,           # Socket read wait time for Tincan Messages
RcvServiceAddress = "127.0.0.1",   # Controller server address
SndServiceAddress = "127.0.0.1",   # Tincan server address
CtrlRecvPort = 5801,               # Controller Listening Port
CtrlSendPort = 5800               # Tincan Listening Port

class TincanInterface(ControllerModule):
    def __init__(self, cfx_handle, module_config, module_name):
        super(TincanInterface, self).__init__(cfx_handle, module_config, module_name)
        self._tincan_listener_thread = None    # UDP listener thread object
        self._tci_publisher = None

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock_svr = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Controller UDP listening socket
        self._sock_svr.bind((self.config.get("RcvServiceAddress", RcvServiceAddress),
                             self.config.get("CtrlRecvPort", CtrlRecvPort)))
        # Controller UDP sending socket
        self._dest = (self.config.get("SndServiceAddress", SndServiceAddress), self.config.get("CtrlSendPort", CtrlSendPort))
        self._sock.bind(("", 0))
        self._sock_list = [self._sock_svr]
        self.iptool = spawn.find_executable("ip")

    def initialize(self):
        self._tincan_listener_thread = Thread(target=self.__tincan_listener)
        self._tincan_listener_thread.setDaemon(True)
        self._tincan_listener_thread.start()
        self.create_control_link()
        self._tci_publisher = self._cfx_handle.publish_subscription("TCI_TINCAN_MSG_NOTIFY")
        self.register_cbt("Logger", "LOG_QUERY_CONFIG")
        self.logger.info("Module loaded")

    def __tincan_listener(self):
        try:
            while True:
                socks, _, _ = select.select(self._sock_list, [], [],
                                            self.config.get("SocketReadWaitTime", SocketReadWaitTime))
                # Iterate across all socket list to obtain Tincan messages
                for sock in socks:
                    if sock == self._sock_svr:
                        data = sock.recvfrom(self.config.get("MaxReadSize", MaxReadSize))
                        ctl = json.loads(data[0].decode("utf-8"))
                        if ctl["EVIO"]["ProtocolVersion"] != ver.EVIO_VER_CTL:
                            raise ValueError("Invalid control version detected")
                        # Get the original CBT if this is the response
                        if ctl["EVIO"]["ControlType"] == "TincanResponse":
                            cbt = self._cfx_handle._pending_cbts[ctl["EVIO"]["TransactionId"]]
                            cbt.set_response(ctl["EVIO"]["Response"]["Message"],
                                             ctl["EVIO"]["Response"]["Success"])
                            self.complete_cbt(cbt)
                        else:
                            self._tci_publisher.post_update(ctl["EVIO"]["Request"])
        except Exception as err:
            self.logger.exception("Tincan Listener exception")

    def create_control_link(self,):
        self.logger.info("Creating Tincan control link")
        cbt = self.create_cbt(self._module_name, self._module_name, "TCI_CREATE_CTRL_LINK")
        ctl = modlib.CTL_CREATE_CTRL_LINK
        ctl["EVIO"]["TransactionId"] = cbt.tag
        ctl["EVIO"]["Request"]["Port"] = self.config.get("CtrlRecvPort", CtrlRecvPort)

        ctl["EVIO"]["Request"]["AddressFamily"] = "af_inet"
        ctl["EVIO"]["Request"]["IP"] = self.config.get("RcvServiceAddress", RcvServiceAddress)

        self._cfx_handle._pending_cbts[cbt.tag] = cbt
        self.send_control(json.dumps(ctl))

    def resp_handler_create_control_link(self, cbt):
        if cbt.response.status == "False":
            msg = "Failed to create Tincan response link: CBT={0}".format(cbt)
            raise RuntimeError(msg)

    def configure_tincan_logging(self, log_cfg, use_defaults=False):
        cbt = self.create_cbt(self._module_name, self._module_name, "TCI_CONFIGURE_LOGGING")
        ctl = modlib.CTL_CONFIGURE_LOGGING
        ctl["EVIO"]["TransactionId"] = cbt.tag
        if not use_defaults:
            ctl["EVIO"]["Request"] = log_cfg
        self._cfx_handle._pending_cbts[cbt.tag] = cbt
        self.send_control(json.dumps(ctl))

    def resp_handler_configure_tincan_logging(self, cbt):
        if cbt.response.status == "False":
            self.logger.warn("Failed to configure Tincan logging: CBT=%s", cbt)

    def req_handler_create_link(self, cbt):
        msg = cbt.request.params
        ctl = modlib.CTL_CREATE_LINK
        ctl["EVIO"]["TransactionId"] = cbt.tag
        req = ctl["EVIO"]["Request"]
        req["OverlayId"] = msg["OverlayId"]
        req["TunnelId"] = msg["TunnelId"]
        req["NodeId"] = msg.get("NodeId")
        req["LinkId"] = msg["LinkId"]
        req["PeerInfo"]["UID"] = msg["NodeData"].get("UID")
        req["PeerInfo"]["MAC"] = msg["NodeData"].get("MAC")
        req["PeerInfo"]["CAS"] = msg["NodeData"].get("CAS")
        req["PeerInfo"]["FPR"] = msg["NodeData"].get("FPR")
        # Optional overlay data to create overlay on demand
        req["StunServers"] = msg.get("StunServers")
        req["TurnServers"] = msg.get("TurnServers")
        req["TapName"] = msg.get("TapName")
        req["IgnoredNetInterfaces"] = msg.get("IgnoredNetInterfaces")
        self.send_control(json.dumps(ctl))

    def req_handler_create_tunnel(self, cbt):
        msg = cbt.request.params
        ctl = modlib.CTL_CREATE_TUNNEL
        ctl["EVIO"]["TransactionId"] = cbt.tag
        req = ctl["EVIO"]["Request"]
        req["StunServers"] = msg["StunServers"]
        req["TurnServers"] = msg.get("TurnServers")
        req["TapName"] = msg["TapName"]
        req["OverlayId"] = msg["OverlayId"]
        req["TunnelId"] = msg["TunnelId"]
        req["NodeId"] = msg.get("NodeId")
        req["IgnoredNetInterfaces"] = msg.get("IgnoredNetInterfaces")
        self.send_control(json.dumps(ctl))

    def req_handler_query_candidate_address_set(self, cbt):
        msg = cbt.request.params
        ctl = modlib.CTL_QUERY_CAS
        ctl["EVIO"]["TransactionId"] = cbt.tag
        req = ctl["EVIO"]["Request"]
        req["OverlayId"] = msg["OverlayId"]
        req["LinkId"] = msg["LinkId"]
        self.send_control(json.dumps(ctl))

    def req_handler_query_link_stats(self, cbt):
        msg = cbt.request.params
        ctl = modlib.CTL_QUERY_LINK_STATS
        ctl["EVIO"]["TransactionId"] = cbt.tag
        req = ctl["EVIO"]["Request"]
        req["TunnelIds"] = msg
        self.send_control(json.dumps(ctl))

    def req_handler_query_tunnel_info(self, cbt):
        msg = cbt.request.params
        ctl = modlib.CTL_QUERY_TUNNEL_INFO
        ctl["EVIO"]["TransactionId"] = cbt.tag
        req = ctl["EVIO"]["Request"]
        req["OverlayId"] = msg["OverlayId"]
        self.send_control(json.dumps(ctl))

    def req_handler_remove_tunnel(self, cbt):
        msg = cbt.request.params
        ctl = modlib.CTL_REMOVE_TUNNEL
        ctl["EVIO"]["TransactionId"] = cbt.tag
        req = ctl["EVIO"]["Request"]
        req["OverlayId"] = msg["OverlayId"]
        req["TunnelId"] = msg["TunnelId"]
        self.send_control(json.dumps(ctl))
        if "TapName" in msg and msg["TapName"]:
            modlib.runshell([self.iptool, "link", "del", "dev", msg["TapName"]])

    def req_handler_remove_link(self, cbt):
        msg = cbt.request.params
        ctl = modlib.CTL_REMOVE_LINK
        ctl["EVIO"]["TransactionId"] = cbt.tag
        req = ctl["EVIO"]["Request"]
        req["OverlayId"] = msg["OverlayId"]
        req["TunnelId"] = msg["TunnelId"]
        req["LinkId"] = msg["LinkId"]
        self.send_control(json.dumps(ctl))

    def process_cbt(self, cbt):
        if cbt.op_type == "Request":
            if cbt.request.action == "TCI_CREATE_LINK":
                self.req_handler_create_link(cbt)

            elif cbt.request.action == "TCI_REMOVE_LINK":
                self.req_handler_remove_link(cbt)

            elif cbt.request.action == "TCI_CREATE_TUNNEL":
                self.req_handler_create_tunnel(cbt)

            elif cbt.request.action == "TCI_QUERY_CAS":
                self.req_handler_query_candidate_address_set(cbt)

            elif cbt.request.action == "TCI_QUERY_LINK_STATS":
                self.req_handler_query_link_stats(cbt)

            elif cbt.request.action == "TCI_QUERY_TUNNEL_INFO":
                self.req_handler_query_tunnel_info(cbt)

            elif cbt.request.action == "TCI_REMOVE_TUNNEL":
                self.req_handler_remove_tunnel(cbt)

            else:
                self.req_handler_default(cbt)
        elif cbt.op_type == "Response":
            if cbt.request.action == "LOG_QUERY_CONFIG":
                self.configure_tincan_logging(cbt.response.data,
                                              not cbt.response.status)

            elif cbt.request.action == "TCI_CREATE_CTRL_LINK":
                self.resp_handler_create_control_link(cbt)

            elif cbt.request.action == "TCI_CONFIGURE_LOGGING":
                self.resp_handler_configure_tincan_logging(cbt)

            self.free_cbt(cbt)

    def send_control(self, msg):
        return self._sock.sendto(bytes(msg.encode("utf-8")), self._dest)

    def timer_method(self):
        pass

    def terminate(self):
        pass
