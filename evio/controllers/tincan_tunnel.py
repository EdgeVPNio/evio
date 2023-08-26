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

import signal
import subprocess
from threading import Event

import broker
from broker import TINCAN_CHK_INTERVAL, statement_false
from broker.cbt import CBT
from broker.controller_module import ControllerModule
from broker.process_proxy import ProxyMsg
from broker.version import EVIO_VER_CTL

# from pyroute2 import IPRoute


class TincanTunnel(ControllerModule):
    def __init__(self, nexus, module_config):
        super().__init__(nexus, module_config)
        self._echo_replies: int = 2
        self.exit_ev = Event()
        self._tci_publisher = None
        self._tc_pid = -1
        self._tc_proc = None
        self._tunnel_pid: dict[str, int] = {}
        self._ipc_id: int = -1
        self._use_log_defaults = False

    def initialize(self):
        self._register_abort_handlers()
        self._register_req_handlers()
        self._register_resp_handlers()
        self._tci_publisher = self.publish_subscription("TCI_TINCAN_MSG_NOTIFY")
        self._start_tincan()
        self.logger.info("Controller module loaded")

    def _register_abort_handlers(self):
        self._abort_handler_tbl = {
            "TCI_CONFIGURE_LOGGING": self.abort_handler_configure_tincan_logging,
            "_TCI_SEND_ECHO": self.abort_handler_send_echo,
            "TCI_TINCAN_MSG_NOTIFY": self.abort_handler_default,
        }

    def _register_req_handlers(self):
        self._req_handler_tbl = {
            "TCI_CREATE_LINK": self.req_handler_create_link,
            "TCI_REMOVE_LINK": self.req_handler_remove_link,
            "TCI_CREATE_TUNNEL": self.req_handler_create_tunnel,
            "TCI_QUERY_CAS": self.req_handler_query_candidate_address_set,
            "TCI_QUERY_LINK_STATS": self.req_handler_query_link_stats,
            "TCI_QUERY_TUNNEL_INFO": self.req_handler_query_tunnel_info,
            "TCI_REMOVE_TUNNEL": self.req_handler_remove_tunnel,
            "_TCI_SEND_ECHO": self.req_handler_send_send_echo,
            "TCI_CONFIGURE_LOGGING": self.req_handler_configure_tincan_logging,
        }

    def _register_resp_handlers(self):
        self._resp_handler_tbl = {
            "TCI_CONFIGURE_LOGGING": self.resp_handler_configure_tincan_logging,
            "_TCI_SEND_ECHO": self.resp_handler_send_echo,
        }

    def req_handler_configure_tincan_logging(self, cbt: CBT):
        ctl = broker.CTL_CONFIGURE_LOGGING
        ctl["TransactionId"] = cbt.tag
        if cbt.request.params and not self._use_log_defaults:
            ctl["Request"].update(cbt.request.params)
        self.send_control(json.dumps(ctl))

    def resp_handler_configure_tincan_logging(self, cbt: CBT):
        status = cbt.response.status
        self.free_cbt(cbt)
        if status == "False":
            self.logger.warning("Failed to configure Tincan logging: CBT=%s", cbt)
            self._use_log_defaults = True
            self._restart_tincan()
            return
        self._notify_tincan_ready()
        self.on_exp_chk_tincan()

    def req_handler_create_link(self, cbt: CBT):
        if not self._is_request_current(cbt):  # also sets the response to failed
            self.complete_cbt(cbt)
            return
        msg = cbt.request.params
        self._tunnel_pid[msg["TunnelId"]] = self._tc_pid
        ctl = broker.CTL_CREATE_LINK
        ctl["TransactionId"] = cbt.tag
        req = ctl["Request"]
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

    def req_handler_create_tunnel(self, cbt: CBT):
        if not self._is_request_current(cbt):
            self.complete_cbt(cbt)
            return
        msg = cbt.request.params
        self._tunnel_pid[msg["TunnelId"]] = self._tc_pid
        ctl = broker.CTL_CREATE_TUNNEL
        ctl["TransactionId"] = cbt.tag
        req = ctl["Request"]
        req["StunServers"] = msg["StunServers"]
        req["TurnServers"] = msg.get("TurnServers")
        req["TapName"] = msg["TapName"]
        req["OverlayId"] = msg["OverlayId"]
        req["TunnelId"] = msg["TunnelId"]
        req["NodeId"] = msg.get("NodeId")
        req["IgnoredNetInterfaces"] = msg.get("IgnoredNetInterfaces")
        self.send_control(json.dumps(ctl))

    def req_handler_query_candidate_address_set(self, cbt: CBT):
        if not self._is_request_current(cbt):
            self.complete_cbt(cbt)
            return
        msg = cbt.request.params
        ctl = broker.CTL_QUERY_CAS
        ctl["TransactionId"] = cbt.tag
        req = ctl["Request"]
        req["OverlayId"] = msg["OverlayId"]
        req["LinkId"] = msg["LinkId"]
        self.send_control(json.dumps(ctl))

    def req_handler_query_link_stats(self, cbt: CBT):
        # if not self._is_request_current(cbt):
        # Todo: TypeError - list indices must be integers or slices, not str
        #     self.complete_cbt(cbt)
        #     return
        msg = cbt.request.params
        ctl = broker.CTL_QUERY_LINK_STATS
        ctl["TransactionId"] = cbt.tag
        req = ctl["Request"]
        req["TunnelIds"] = msg
        self.send_control(json.dumps(ctl))

    def req_handler_query_tunnel_info(self, cbt: CBT):
        if not self._is_request_current(cbt):
            self.complete_cbt(cbt)
            return
        msg = cbt.request.params
        ctl = broker.CTL_QUERY_TUNNEL_INFO
        ctl["TransactionId"] = cbt.tag
        req = ctl["Request"]
        req["OverlayId"] = msg["OverlayId"]
        self.send_control(json.dumps(ctl))

    def req_handler_remove_tunnel(self, cbt: CBT):
        if not self._is_request_current(cbt):
            self.complete_cbt(cbt)
            return
        msg = cbt.request.params
        ctl = broker.CTL_REMOVE_TUNNEL
        ctl["TransactionId"] = cbt.tag
        req = ctl["Request"]
        req["OverlayId"] = msg["OverlayId"]
        req["TunnelId"] = msg["TunnelId"]
        self.send_control(json.dumps(ctl))
        # if "TapName" in msg and msg["TapName"]:
        #     try:
        #         with IPRoute() as ipr:
        #             idx = ipr.link_lookup(ifname=msg["TapName"])
        #             if len(idx) > 0:
        #                 idx = idx[0]
        #                 ipr.link("set", index=idx, state="down")
        #                 ipr.link("del", index=idx)
        #     except Exception:
        #         pass

    def req_handler_remove_link(self, cbt: CBT):
        if not self._is_request_current(cbt):
            self.complete_cbt(cbt)
            return
        msg = cbt.request.params
        ctl = broker.CTL_REMOVE_LINK
        ctl["TransactionId"] = cbt.tag
        req = ctl["Request"]
        req["OverlayId"] = msg["OverlayId"]
        req["TunnelId"] = msg["TunnelId"]
        req["LinkId"] = msg["LinkId"]
        self.send_control(json.dumps(ctl))

    def req_handler_send_send_echo(self, cbt: CBT):
        ctl = broker.CTL_ECHO
        ctl["TransactionId"] = cbt.tag
        if cbt.request.params:
            ctl["Request"]["Message"] = cbt.request.params
        self._echo_replies -= 1
        self.send_control(json.dumps(ctl))

    def resp_handler_send_echo(self, cbt: CBT):
        self._echo_replies += 1
        self.free_cbt(cbt)

    def abort_handler_configure_tincan_logging(self, cbt):
        self.free_cbt(cbt)
        self.logger.warning("Configure Tincan logging timeout: CBT=%s", cbt)
        self._restart_tincan()

    def abort_handler_send_echo(self, cbt):
        self.free_cbt(cbt)
        self.logger.warning("Echo test timeout")

    def on_timer_event(self):
        if self._echo_replies > 0:
            self.register_internal_cbt("_TCI_SEND_ECHO", "Tincan liveliness check")

    def on_exp_chk_tincan(self, *_):
        if self.exit_ev.is_set():
            return
        exit_code = None
        if self._tc_proc:
            exit_code = self._tc_proc.poll()
        if exit_code:
            if self._tc_pid == -1:
                self.logger.error(
                    "Tincan process has not called back to register the communication endpoint"
                )
                self._restart_tincan()
            elif self._tc_pid > 0:
                # tincan process crashed
                self.logger.warning("Tincan process exited with code, %s", exit_code)
                self._notify_tincan_terminated(self._tc_pid)
                self._start_tincan()
        elif self._echo_replies <= 0:
            # tincan process unresponsive
            self.logger.warning("No replies from Tincan echo check, resetting ...")
            self._restart_tincan()

        self.register_timed_transaction(
            self,
            statement_false,
            self.on_exp_chk_tincan,
            TINCAN_CHK_INTERVAL,
        )

    def terminate(self):
        self.exit_ev.set()
        self._stop_tincan()
        self.logger.info("Controller module terminating")

    def send_control(self, ctl: str):
        msg: ProxyMsg = ProxyMsg(self._ipc_id, payload=ctl.encode("utf-8"))
        self.send_ipc(msg)

    def _start_tincan(self):
        if self.exit_ev.is_set():
            return
        # self.logger.info(
        #     "start Tincan with ./tincan -s %s",
        #     self.process_proxy_address[1:].decode("utf-8"),
        # )
        self._tc_proc = subprocess.Popen(
            ["./tincan", "-s", self.process_proxy_address[1:]]
        )
        self._echo_replies = 2  # reset the echo counter
        self.logger.info("New Tincan session started %s", self._tc_proc.pid)

    def _stop_tincan(self):
        if self._tc_proc is None:
            return
        try:
            if self._tc_proc.poll() is not None:
                self._tc_proc.send_signal(signal.SIGTERM)
                self._tc_proc.wait(10.15)
        except subprocess.TimeoutExpired:
            if self._tc_proc is not None and self._tc_proc.poll() is not None:
                self.logger.info("Killing unresponsive Tincan: %s", self._tc_proc.pid)
                self._tc_proc.kill()
        finally:
            if not self.exit_ev.is_set():
                self._notify_tincan_terminated(self._tc_pid)
            self._tc_pid = 0
            self._tc_proc = None

    def _restart_tincan(self):
        self._stop_tincan()
        self._start_tincan()

    def _notify_tincan_ready(self):
        self._tc_pid = self._tc_proc.pid
        self._tci_publisher.post_update(
            {
                "Command": "TincanReady",
                "SessionId": self._tc_pid,
            }
        )

    def _notify_tincan_terminated(self, old_pid):
        self._tci_publisher.post_update(
            {
                "Command": "ResetTincanTunnels",
                "Reason": "Tincan process terminated",
                "SessionId": old_pid,
            }
        )

    def _is_request_current(self, cbt) -> bool:
        """There are 3 failure scenarios:
        1. No Tincan process currently exists
        2. The Tincan ID in the request does not match the one associated
            with the tunnel ID.
        3. The Tincan ID in the request does not match the current one.
        """
        is_current: bool = False
        tnlid = cbt.request.params["TunnelId"]
        tracked_sid = self._tunnel_pid.get(tnlid)
        try:
            msg = cbt.request.params
            if self._tc_pid <= 0:
                cbt.set_response(
                    {
                        "Message": "Tincan session not ready for request. Try again later.",
                        "NodeId": self.node_id,
                        "CurrentId": self._tc_pid,
                    },
                    False,
                )
            elif (tracked_sid and tracked_sid != msg["TincanId"]) or (
                msg["TincanId"] != self._tc_pid
            ):
                cbt.set_response(
                    {
                        "Message": "The requested Tincan session is invalid.",
                        "CurrentId": self._tc_pid,
                    },
                    False,
                )
            else:
                is_current = True
        except Exception as exc:
            self.logger.exception(exc)
            if cbt:
                cbt.set_response(
                    {
                        "Message": "The requested failed.",
                        "CurrentId": self._tc_pid,
                    },
                    False,
                )
        return is_current

    def handle_ipc(self, msg: ProxyMsg):
        try:
            ctl = msg.json
            self._ipc_id = msg.fileno
            if ctl["ProtocolVersion"] != EVIO_VER_CTL:
                raise ValueError("Invalid control version detected")
            # Get the original CBT if this is the response
            if ctl["ControlType"] == "Response":
                cbt = self.get_pending_cbt(ctl["TransactionId"])
                if cbt:
                    cbt.set_response(
                        ctl["Response"]["Message"],
                        ctl["Response"]["Success"],
                    )
                    self.complete_cbt(cbt)
            else:
                req = ctl["Request"]
                if req["Command"] == "RegisterDataplane":
                    self.logger.debug("Received Tincan dataplane registration")
                    self.register_internal_cbt("TCI_CONFIGURE_LOGGING", self.log_config)
                elif req["Command"] == "LinkStateChange":
                    self._tci_publisher.post_update(req)
                else:
                    self.loggger.warning(
                        "Invalid Tincan control command: %s", req["Command"]
                    )
        except ValueError as vr:
            self.logger.exception(str(vr))
