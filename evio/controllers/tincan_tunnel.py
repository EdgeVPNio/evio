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

import subprocess
import time
from copy import deepcopy
from threading import Event

import broker
from broker import TC_PRCS_CHK_INTERVAL, TC_REQUEST_TIMEOUT
from broker.cbt import CBT
from broker.controller_module import ControllerModule
from broker.process_proxy import ProxyMsg
from broker.version import EVIO_VER_CTL
from pyroute2 import IPRoute


class TincanProcess:
    _REFLECT: list[str] = ["ovlid", "tnlid", "ipc_id", "echo_replies", "tap_name"]

    def __init__(
        self,
        olid: str = "",
        tnlid: str = "",
        ipc_id: int = -1,
        proc: subprocess = None,
        do_chk: bool = False,
        echo_replies: int = broker.MAX_HEARTBEATS,
    ):
        self.ovlid = olid
        self.tnlid = tnlid
        self.ipc_id = ipc_id
        self.echo_replies = echo_replies
        self.do_chk = do_chk
        self.proc = proc
        self.tap_name: str = ""

    def __repr__(self):
        return broker.introspect(self)


class TincanTunnel(ControllerModule):
    _REFLECT: list[str] = ["_tc_proc_tbl", "_pids", "_tnl_cbts"]

    def __init__(self, nexus, module_config):
        super().__init__(nexus, module_config)
        self.exit_ev = Event()
        self._tci_publisher = None
        self._tc_proc_tbl: dict[str, TincanProcess] = {}
        self._pids: dict[int, str] = {}
        self._kill_times: list[float] = [
            0.0,
        ]
        self._tnl_cbts: dict[str, CBT] = {}

    def __repr__(self):
        return broker.introspect(self)

    def initialize(self):
        self._register_req_handlers()
        self._register_resp_handlers()
        self._register_abort_handlers()
        self._tci_publisher = self.publish_subscription("TCI_TUNNEL_EVENT")
        self.register_deferred_call(TC_PRCS_CHK_INTERVAL, self.on_expire_chk_tincan)
        self.logger.info("Controller module loaded")

    def _register_abort_handlers(self):
        self._abort_handler_tbl = {
            "_TCI_SEND_ECHO": self.abort_handler_send_echo,
            "_TCI_CHK_PROCESS": self.abort_handler_default,
            "TCI_TUNNEL_EVENT": self.abort_handler_default,
        }

    def _register_req_handlers(self):
        self._req_handler_tbl = {
            "TCI_CREATE_TUNNEL": self.req_handler_create_tunnel,
            "TCI_CREATE_LINK": self.req_handler_create_link,
            "TCI_QUERY_LINK_INFO": self.req_handler_query_link_stats,
            "TCI_REMOVE_TUNNEL": self.req_handler_remove_tunnel,
            "_TCI_SEND_ECHO": self.req_handler_send_echo,
            "_TCI_CHK_PROCESS": self.req_handler_check_process,
        }

    def _register_resp_handlers(self):
        self._resp_handler_tbl = {
            "_TCI_SEND_ECHO": self.resp_handler_send_echo,
            "_TCI_CHK_PROCESS": self.resp_handler_default,
            "TCI_QUERY_LINK_INFO": self.resp_handler_default,
            "TCI_TUNNEL_EVENT": self.resp_handler_default,
        }

    def req_handler_create_tunnel(self, cbt: CBT):
        try:
            msg = cbt.request.params
            olid = msg["OverlayId"]
            tnlid = msg["TunnelId"]
            if tnlid in self._tc_proc_tbl:
                cbt.set_response({"Message": "Tunnel already exists"}, False)
                self.complete_cbt(cbt)
                return
            if self._is_tap_exist(msg["TapName"]):
                self._remove_tap(msg["TapName"])
            cbt.add_context("OnRegister", self._create_tunnel)
            self._tnl_cbts[tnlid] = cbt
            self._start_tincan(tnlid)
            self._tc_proc_tbl[tnlid].ovlid = olid
            self._tc_proc_tbl[tnlid].tap_name = msg["TapName"]
        except Exception:
            self._tnl_cbts.pop(tnlid, None)
            cbt.set_response("Failed to create Tincan tunnel process", False)
            self.complete_cbt(cbt)

    def _create_tunnel(self, cbt: CBT):
        try:
            msg = cbt.request.params
            tnlid = msg["TunnelId"]
            ctl = deepcopy(broker.CTL_CREATE_TUNNEL)
            ctl["TransactionId"] = cbt.tag
            req = ctl["Request"]
            req["StunServers"] = msg["StunServers"]
            req["TurnServers"] = msg.get("TurnServers")
            req["TapName"] = msg["TapName"]
            req["TunnelId"] = tnlid
            req["NodeId"] = msg.get("NodeId")
            req["IgnoredNetInterfaces"] = msg.get("IgnoredNetInterfaces")
            tc_proc = self._tc_proc_tbl[tnlid]
            self._tnl_cbts[cbt.tag] = cbt
            self.register_deferred_call(
                TC_REQUEST_TIMEOUT,
                self.on_tc_req_expire,
                (cbt.tag,),
            )
            self.send_control(tc_proc.ipc_id, json.dumps(ctl))
        except Exception:
            self._tnl_cbts.pop(cbt.tag, None)
            cbt.set_response("Failed to create tunnel", False)
            self.complete_cbt(cbt)

    def req_handler_create_link(self, cbt: CBT):
        try:
            msg = cbt.request.params
            tnlid = msg["TunnelId"]
            if tnlid not in self._tc_proc_tbl:
                cbt.add_context("OnRegister", self._create_link)
                self._tnl_cbts[tnlid] = cbt
                self._start_tincan(tnlid)
                self._tc_proc_tbl[tnlid].ovlid = msg["OverlayId"]
                self._tc_proc_tbl[tnlid].tap_name = msg["TapName"]
            else:
                self._create_link(cbt)
        except Exception:
            self._tnl_cbts.pop(tnlid, None)
            cbt.set_response("Failed to create Tincan tunnel process", False)
            self.complete_cbt(cbt)

    def _create_link(self, cbt: CBT):
        try:
            msg = cbt.request.params
            tnlid = msg["TunnelId"]
            ctl = deepcopy(broker.CTL_CREATE_LINK)
            ctl["TransactionId"] = cbt.tag
            req = ctl["Request"]
            req["TunnelId"] = tnlid
            req["NodeId"] = msg.get("NodeId")
            req["LinkId"] = msg["LinkId"]
            req["PeerInfo"]["UID"] = msg["NodeData"].get("UID")
            req["PeerInfo"]["MAC"] = msg["NodeData"].get("MAC")
            req["PeerInfo"]["CAS"] = msg["NodeData"].get("CAS")
            req["PeerInfo"]["FPR"] = msg["NodeData"].get("FPR")
            # Optional overlay data to create overlay on demand
            req["StunServers"] = msg.get("StunServers", [])
            req["TurnServers"] = msg.get("TurnServers", [])
            req["TapName"] = msg.get("TapName")
            req["IgnoredNetInterfaces"] = msg.get("IgnoredNetInterfaces")
            tc_proc = self._tc_proc_tbl[tnlid]
            self._tnl_cbts[cbt.tag] = cbt
            self.register_deferred_call(
                TC_REQUEST_TIMEOUT,
                self.on_tc_req_expire,
                (cbt.tag,),
            )
            self.send_control(tc_proc.ipc_id, json.dumps(ctl))
        except Exception:
            self._tnl_cbts.pop(cbt.tag, None)
            cbt.set_response("Failed to create link", False)
            self.complete_cbt(cbt)

    def req_handler_query_candidate_address_set(self, cbt: CBT):
        try:
            msg = cbt.request.params
            tnlid = msg["TunnelId"]
            if tnlid not in self._tc_proc_tbl:
                err_msg = f"No tunnel exists for tunnel ID: {tnlid[:7]}"
                cbt.set_response(err_msg, False)
                return
            ctl = deepcopy(broker.CTL_QUERY_CAS)
            ctl["TransactionId"] = cbt.tag
            ctl["Request"]["TunnelId"] = tnlid
            tc_proc = self._tc_proc_tbl[tnlid]
            self._tnl_cbts[cbt.tag] = cbt
            self.register_deferred_call(
                TC_REQUEST_TIMEOUT,
                self.on_tc_req_expire,
                (cbt.tag,),
            )
            self.send_control(tc_proc.ipc_id, json.dumps(ctl))
        except Exception:
            self._tnl_cbts.pop(cbt.tag, None)
            cbt.set_response("Failed to retrieve local CAS", False)
            self.complete_cbt(cbt)

    def req_handler_query_link_stats(self, cbt: CBT):
        try:
            tnlid = cbt.request.params["TunnelId"]
            tc_proc = self._tc_proc_tbl.get(tnlid)
            if not tc_proc:
                err_msg = f"No tunnel exists for tunnel ID: {tnlid[:7]}"
                cbt.set_response(err_msg, False)
                self.complete_cbt(cbt)
                return
            ctl = deepcopy(broker.CTL_QUERY_LINK_STATS)
            ctl["TransactionId"] = cbt.tag
            ctl["Request"]["TunnelId"] = tnlid
            self._tnl_cbts[cbt.tag] = cbt
            self.register_deferred_call(
                TC_REQUEST_TIMEOUT,
                self.on_tc_req_expire,
                (cbt.tag,),
            )
            self.send_control(tc_proc.ipc_id, json.dumps(ctl))
        except Exception as excep:
            self.logger.warning("Query link stats failed: %s", excep)
            self._tnl_cbts.pop(cbt.tag, None)
            cbt.set_response("Failed to retrieve link stats", False)
            self.complete_cbt(cbt)

    def req_handler_remove_tunnel(self, cbt: CBT):
        try:
            msg = cbt.request.params
            tnlid = msg["TunnelId"]
            if tnlid not in self._tc_proc_tbl:
                err_msg = f"No tunnel exists for tunnel ID: {tnlid[:7]}"
                cbt.set_response(err_msg, True)
                self.complete_cbt(cbt)
                return
            self.logger.debug("Removing tunnel %s", tnlid[:7])
            tc_proc = self._tc_proc_tbl.pop(tnlid, None)
            self._pids.pop(tc_proc.proc.pid, None)
            self._stop_tincan(tc_proc)
            cbt.set_response("Tunnel removed", True)
            self.complete_cbt(cbt)
        except Exception:
            msg = f"Failed to remove tunnel {tnlid}"
            self.logger.error(msg)
            self._tnl_cbts.pop(cbt.tag, None)
            cbt.set_response(msg, False)
            self.complete_cbt(cbt)

    # def req_handler_remove_link(self, cbt: CBT):
    #     msg = cbt.request.params
    #     tnlid = msg["TunnelId"]
    #     if tnlid not in self._tc_proc_tbl:
    #         err_msg = f"No tunnel exists for tunnel ID: {tnlid[:7]}"
    #         cbt.set_response(err_msg, False)
    #         self.complete_cbt(cbt)
    #         return
    #     ctl = deepcopy(broker.CTL_REMOVE_LINK)
    #     ctl["TransactionId"] = cbt.tag
    #     req = ctl["Request"]
    #     req["TunnelId"] = tnlid
    #     req["LinkId"] = msg["LinkId"]
    #     tc_proc = self._tc_proc_tbl[tnlid]
    #     self._tnl_cbts[cbt.tag] = cbt
    #     self.send_control(tc_proc.ipc_id, json.dumps(ctl))

    def req_handler_send_echo(self, cbt: CBT):
        ctl = deepcopy(broker.CTL_ECHO)
        ctl["TransactionId"] = cbt.tag
        tnlid = cbt.request.params
        tc_proc = self._tc_proc_tbl.get(tnlid)
        if tc_proc and tc_proc.do_chk and tc_proc.echo_replies > 0:
            tc_proc.echo_replies -= 1
            ctl["Request"]["Message"] = tc_proc.tnlid
            self._tnl_cbts[cbt.tag] = cbt
            self.send_control(tc_proc.ipc_id, json.dumps(ctl))
        else:
            # if tc_proc:
            #     tc_proc.do_chk = False
            cbt.set_response(f"Cannot send echo to {tc_proc}", False)
            self.complete_cbt(cbt)

    def resp_handler_send_echo(self, cbt: CBT):
        tnlid = cbt.response.data
        if cbt.response.status and tnlid in self._tc_proc_tbl:
            self._tc_proc_tbl[tnlid].echo_replies = broker.MAX_HEARTBEATS
            # self.register_internal_cbt(
            #     "TCI_QUERY_LINK_INFO", {"TunnelId": tnlid}, lifespan=15
            # )
        else:
            self.logger.info(cbt.response.data)
        self.free_cbt(cbt)

    def abort_handler_send_echo(self, cbt: CBT):
        tnlid = cbt.request.params
        self._tnl_cbts.pop(cbt.tag, None)
        self.free_cbt(cbt)
        if tnlid in self._tc_proc_tbl:
            tc_proc = self._tc_proc_tbl[tnlid]
            if tc_proc.echo_replies > 0:
                self.logger.debug(
                    "Tunnel: %s health check timeout, countdown: %s",
                    tnlid,
                    tc_proc.echo_replies,
                )
            else:
                # tincan process unresponsive
                self.logger.warning(
                    "Tunnel: %s health check failed, terminating process: %s",
                    tnlid,
                    tc_proc,
                )
                self._pids.pop(tc_proc.proc.pid, None)
                self._tc_proc_tbl.pop(tnlid, None)
                self._stop_tincan(tc_proc)
                self._notify_tincan_terminated(tc_proc)

    def req_handler_check_process(self, cbt: CBT):
        exit_code = None
        rmv = []
        for tc_proc in self._tc_proc_tbl.values():
            exit_code = tc_proc.proc.poll()
            if exit_code:
                # tincan process crashed
                self.logger.warning(
                    "Tincan process %s exited unexpectedly with code %s",
                    tc_proc.proc.pid,
                    exit_code,
                )
                rmv.append(tc_proc)
        for tc_proc in rmv:
            self._pids.pop(tc_proc.proc.pid)
            self._tc_proc_tbl.pop(tc_proc.tnlid, None)
            self._remove_tap(tc_proc.tap_name)
            self._notify_tincan_terminated(tc_proc)
        cbt.set_response(rmv, True)
        self.complete_cbt(cbt)

    def on_tc_req_expire(self, tag: int, timeout: float = None):
        if self.is_tc_req_cmpl(tag):
            return
        self.logger.info("Tincan request expired %s", tag)
        cbt: CBT = self._tnl_cbts.pop(tag, None)
        if cbt and cbt.is_pending:
            cbt.set_response("The Tincan request expired", False)
            self.complete_cbt(cbt)

    def is_tc_req_cmpl(self, tag: int) -> bool:
        return bool(tag not in self._tnl_cbts)

    def on_timer_event(self):
        if self.exit_ev.is_set():
            return
        # send an echo health check every timer interval, eg., 30s
        for tnlid, tc_proc in self._tc_proc_tbl.items():
            if tc_proc.do_chk:
                self.register_internal_cbt("_TCI_SEND_ECHO", tnlid, lifespan=10)

    def on_expire_chk_tincan(self):
        if self.exit_ev.is_set():
            return
        if self._tc_proc_tbl:
            self.register_internal_cbt("_TCI_CHK_PROCESS")
        self.register_deferred_call(TC_PRCS_CHK_INTERVAL, self.on_expire_chk_tincan)

    def terminate(self):
        self.exit_ev.set()
        for tc_proc in self._tc_proc_tbl.values():
            self._stop_tincan(tc_proc, wt=1.5)
        self.logger.debug("avg tok = %s", self._kill_times[-1] / len(self._kill_times))
        self.logger.info("Controller module terminated")

    def send_control(self, ipc_id: int, ctl: str):
        msg: ProxyMsg = ProxyMsg(ipc_id, payload=ctl.encode("utf-8"))
        # self.logger.debug("Sending dataplane control %s", msg)
        self.send_ipc(msg)

    def _start_tincan(self, tnlid: str):
        if self.exit_ev.is_set():
            return
        if not tnlid:
            raise ValueError("Tunnel ID cannot be None")
        if tnlid in self._tc_proc_tbl:
            raise ValueError(
                "Tunnel ID %s is already assigned to active Tincan process %s",
                tnlid,
                self._tc_proc_tbl[tnlid],
            )
        lg_cfg = self.log_config
        lg_cfg.pop("Level", None)
        sub_proc = subprocess.Popen(
            [
                "./tincan",
                "-s",
                self.process_proxy_address[1:],
                "-t",
                tnlid,
                "-l",
                json.dumps(lg_cfg),
            ]
        )
        self._pids[sub_proc.pid] = tnlid
        self._tc_proc_tbl[tnlid] = TincanProcess(tnlid=tnlid, proc=sub_proc)
        self.logger.debug(
            "New Tincan process %d started for tunnel %s", sub_proc.pid, tnlid[:7]
        )

    def _stop_tincan(self, tc_proc: TincanProcess, wt: int = 5.15):
        if tc_proc is None:
            return
        try:
            exit_code = tc_proc.proc.poll()
            if exit_code is None:
                self.logger.debug(
                    "Terminating process %s - Tincan %s",
                    tc_proc.proc.pid,
                    tc_proc.tnlid,
                )
                ts = time.time()
                tc_proc.proc.terminate()
                tc_proc.proc.wait(wt)
                self._kill_times.append(self._kill_times[-1] + time.time() - ts)
            else:
                self.logger.debug(
                    "Process %s for tunnel %s has already exited with code %s",
                    tc_proc.proc.pid,
                    tc_proc.tnlid[:7],
                    exit_code,
                )
        except subprocess.TimeoutExpired:
            exit_code = tc_proc.proc.poll()
            if exit_code is None:
                self._remove_tap(tc_proc.tap_name)
                tc_proc.proc.kill()
            self._kill_times.append(self._kill_times[-1] + time.time() - ts)
            self.logger.debug("Killed unresponsive Tincan: %s", tc_proc.proc.pid)
        self.logger.info(
            "Process %s for tunnel %s terminated", tc_proc.proc.pid, tc_proc.tnlid[:7]
        )

    def _notify_tincan_terminated(self, tc_proc: TincanProcess):
        self._tci_publisher.post_update(
            {
                "Command": "TincanTunnelFailed",
                "Reason": "Tincan process terminated",
                "OverlayId": tc_proc.ovlid,
                "TunnelId": tc_proc.tnlid,
                "TapName": tc_proc.tap_name,
            }
        )

    def handle_ipc(self, msg: ProxyMsg):
        if self.exit_ev.is_set():
            return
        try:
            ctl = msg.json
            if ctl["ProtocolVersion"] != EVIO_VER_CTL:
                raise ValueError("Invalid control version detected")
            # Get the original CBT if this is the response
            if ctl["ControlType"] == "Response":
                # self.logger.debug("Tincan response: %s", ctl)
                cbt = self._tnl_cbts.pop(ctl["TransactionId"])
                cbt.set_response(
                    ctl["Response"]["Message"],
                    ctl["Response"]["Success"],
                )
                self.complete_cbt(cbt)
            else:
                req = ctl["Request"]
                if req["Command"] == "RegisterDataplane":
                    pid = req["SessionId"]
                    tnlid = self._pids[pid]
                    self.logger.info(
                        "Tincan process %d registered tunnel %s", pid, tnlid[:7]
                    )
                    self._tc_proc_tbl[tnlid].ipc_id = msg.fileno
                    cbt = self._tnl_cbts.pop(tnlid)
                    create_tnl = cbt.pop_context("OnRegister")
                    create_tnl(cbt)
                    self._tc_proc_tbl[tnlid].do_chk = True
                elif req["Command"] in ("LinkConnected", "LinkDisconnected"):
                    self._tci_publisher.post_update(req)
                else:
                    self.logger.warning(
                        "Invalid Tincan control command: %s", req["Command"]
                    )
        except Exception:
            self.logger.exception("Tincan IPC failure, ProxyMsg= %s", msg)

    def _is_tap_exist(self, tap_name: str) -> bool:
        with IPRoute() as ipr:
            idx = ipr.link_lookup(ifname=tap_name)
            if len(idx) == 1:
                return True
        return False

    def _remove_tap(self, tap_name: str):
        try:
            self.logger.info("Removing Tincan TAP device %s", tap_name)
            with IPRoute() as ipr:
                idx = ipr.link_lookup(ifname=tap_name)
                if len(idx) > 0:
                    idx = idx[0]
                    ipr.link("set", index=idx, state="down")
                    ipr.link("del", index=idx)
        except Exception as e:
            self.logger.warning(
                "Failed to remove Tincan TAP device %s, error code: %s", tap_name, e
            )
