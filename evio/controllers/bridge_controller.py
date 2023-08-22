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

import copy
import logging
import signal

# import socket
# import select
# import time
# import socketserver
import threading
from abc import ABCMeta, abstractmethod
from collections.abc import MutableMapping
from distutils import spawn
from typing import Any, Union

import broker
from broker import (
    BR_NAME_MAX_LENGTH,
    BRIDGE_AUTO_DELETE,
    DEFAULT_BRIDGE_PROVIDER,
    DEFAULT_SWITCH_PROTOCOL,
    MTU,
    NAME_PREFIX_APP_BR,
    NAME_PREFIX_EVI,
    SDN_CONTROLLER_PORT,
)
from broker.cbt import CBT
from broker.controller_module import ControllerModule
from broker.process_proxy import ProxyMsg
from pyroute2 import IPRoute

from .tunnel import DATAPLANE_TYPES, TUNNEL_EVENTS

# BR_NAME_MAX_LENGTH: Literal[15] = 15
# NAME_PREFIX_EVI: Literal["evi"] = "evi"
# NAME_PREFIX_APP_BR: Literal["app"] = "app"
# MTU: Literal[1410] = 1410
# BRIDGE_AUTO_DELETE: bool = True
# DEFAULT_BRIDGE_PROVIDER: Literal["OVS"] = "OVS"
# DEFAULT_SWITCH_PROTOCOL: Literal["BF"] = "BF"
# PROXY_LISTEN_ADDRESS: Literal["127.0.0.1"] = "127.0.0.1"
# PROXY_LISTEN_PORT: Literal[5802] = 5802
# SDN_CONTROLLER_PORT: Literal[6633] = 6633


class BridgeABC:
    __metaclass__ = ABCMeta

    bridge_type = NotImplemented

    def __init__(self, name, ip_addr, prefix_len, mtu):
        self.name: str = name
        self.ip_addr: str = ip_addr
        self.prefix_len: int = prefix_len
        self.mtu: int = mtu
        self.ports: set[str] = set()
        self.port_descriptors: dict[str, dict] = {}

    @abstractmethod
    def add_port(self, port_name, port_descr):
        pass

    @abstractmethod
    def del_port(self, port_name):
        pass

    @abstractmethod
    def del_br(self):
        pass

    def __repr__(self):
        """Return a representaion of a bridge object."""
        return f"{self.bridge_type}/{self.name}"

    def __str__(self):
        """Return a string of the bridge name."""
        return self.__repr__()

    def flush_ip_addresses(self, port_name):
        # try:
        #     broker.run_proc(["sysctl", f"net.ipv6.conf.{port_name}.disable_ipv6=1"])
        # except Exception:
        #     pass
        with IPRoute() as ipr:
            ipr.flush_addr(label=port_name)


###################################################################################################


class OvsBridge(BridgeABC):
    """Wrapper class for the OpenvSwitch Bridge"""

    brctl = spawn.find_executable("ovs-vsctl")
    bridge_type = "OVS"

    def __init__(
        self,
        name: str,
        ip_addr: str,
        prefix_len: int,
        mtu: int,
        sw_proto: str,
        sdn_ctrl_port: int,
        logger: logging.Logger,
    ):
        """Initialize an OpenvSwitch bridge object."""
        super().__init__(name, ip_addr, prefix_len, mtu)
        self.logger = logger
        if OvsBridge.brctl is None:
            raise RuntimeError("openvswitch-switch was not found")
        broker.run_proc([OvsBridge.brctl, "--may-exist", "add-br", self.name])

        if ip_addr and prefix_len:
            self.flush_ip_addresses(self.name)
            with IPRoute() as ipr:
                idx = ipr.link_lookup(ifname=self.name)[0]
                ipr.addr("add", index=idx, address=ip_addr, mask=prefix_len)
        else:
            self.flush_ip_addresses(self.name)
        try:
            broker.run_proc(
                [
                    OvsBridge.brctl,
                    "set",
                    "int",
                    self.name,
                    "mtu_request=" + str(self.mtu),
                ]
            )
        except RuntimeError as rte:
            self.logger.warning(
                "The following error occurred while setting MTU for OVS bridge: %s",
                rte,
                exc_info=True,
            )

        if sw_proto is not None and sw_proto.casefold() == "STP".casefold():
            self.stp(True)
        elif sw_proto is not None and sw_proto.casefold() == "BF".casefold():
            self.add_sdn_ctrl(sdn_ctrl_port)
        elif sw_proto is not None:
            raise RuntimeError(
                f"Invalid switch protocol '{sw_proto}' specified for bridge {name}."
            )
        with IPRoute() as ipr:
            idx = ipr.link_lookup(ifname=self.name)[0]
            ipr.link("set", index=idx, state="up")

    def add_sdn_ctrl(self, sdn_ctrl_port):
        ctrl_conn_str = f"tcp:127.0.0.1:{sdn_ctrl_port}"
        broker.run_proc([OvsBridge.brctl, "set-controller", self.name, ctrl_conn_str])

    def del_sdn_ctrl(self):
        broker.run_proc([OvsBridge.brctl, "del-controller", self.name])

    def del_br(self):
        self.del_sdn_ctrl()

        broker.run_proc([OvsBridge.brctl, "--if-exists", "del-br", self.name])

    def add_port(self, port_name, port_descr):
        self.flush_ip_addresses(self.name)
        with IPRoute() as ipr:
            idx = ipr.link_lookup(ifname=port_name)[0]
            ipr.link("set", index=idx, mtu=self.mtu)
        broker.run_proc(
            [OvsBridge.brctl, "--may-exist", "add-port", self.name, port_name]
        )
        self.ports.add(port_name)
        self.port_descriptors[port_name] = port_descr

    def del_port(self, port_name):
        broker.run_proc(
            [OvsBridge.brctl, "--if-exists", "del-port", self.name, port_name]
        )
        if port_name in self.ports:
            self.ports.remove(port_name)
        self.port_descriptors.pop(port_name, None)

    def stp(self, enable):
        """Enables spanning tree protocol on bridge, as opposed to BoundedFlood"""
        broker.run_proc(
            [
                OvsBridge.brctl,
                "set",
                "bridge",
                self.name,
                f"stp_enable={str(enable).lower()}",
            ]
        )

    def add_patch_port(self, peer_patch_port: str):
        broker.run_proc(
            [
                OvsBridge.brctl,
                "--may-exist",
                "add-port",
                self.name,
                self.patch_port_name,
                "--",
                "set",
                "interface",
                self.patch_port_name,
                "type=patch",
                f"options:peer={peer_patch_port}",
            ]
        )

    @property
    def patch_port_name(self) -> str:
        return f"pp-{self.name[:12]}"


###################################################################################################


class LinuxBridge(BridgeABC):
    """Wrapper class to manage a Linux Bridge"""

    bridge_type = "LXBR"

    def __init__(
        self,
        name: str,
        ip_addr: str,
        prefix_len: int,
        mtu: int,
        stp_enable: bool,
        logger: logging.Logger,
    ):
        """Initialize a Linux bridge object."""
        super().__init__(name, ip_addr, prefix_len, mtu)
        self.logger: logging.Logger = logger
        with IPRoute() as ipr:
            idx = ipr.link_lookup(ifname=self.name)
            if len(idx) == 1:
                return
            ipr.link("add", ifname=self.name, kind="bridge")
            idx = ipr.link_lookup(ifname=self.name)[0]
            if ip_addr and prefix_len:
                ipr.addr("add", index=idx, address=ip_addr, mask=prefix_len)
            self.stp(stp_enable)
            ipr.link("set", index=idx, state="up")

    def del_br(self):
        # Set the device down and delete the bridge
        with IPRoute() as ipr:
            idx = ipr.link_lookup(ifname=self.name)[0]
            ipr.link("set", index=idx, state="down")
            ipr.link("del", ifname=self.name, kind="bridge")

    def add_port(self, port_name, port_descr):
        with IPRoute() as ipr:
            idx = ipr.link_lookup(ifname=port_name)[0]
            ipr.link("set", index=idx, mtu=self.mtu)
            ipr.link("set", index=idx, master=ipr.link_lookup(ifname=self.name)[0])
        self.ports.add(port_name)
        self.port_descriptors[port_name] = port_descr

    def del_port(self, port_name):
        with IPRoute() as ipr:
            idx = ipr.link_lookup(ifname="port_name")[0]
            ipr.link("set", index=idx, state="down")
            ipr.link("set", index=idx, master=0)
            ipr.link("del", index=idx)
        if port_name in self.ports:
            self.ports.remove(port_name)
        self.port_descriptors.pop(port_name, None)

    def stp(self, val):
        """Turn STP protocol on/off. Recommended to be on for Linux Bridge in a fabric"""
        state = 0
        if val:
            state = 1
        with IPRoute() as ipr:
            idx = ipr.link_lookup(ifname=self.name)[0]
            ipr.link("set", index=idx, kind="bridge", stp_state=state)


###################################################################################################


class VNIC(BridgeABC):
    """Wrapper class for a TAP device"""

    brctl = None
    bridge_type = "VNIC"

    def __init__(self, ip_addr, prefix_len, mtu):
        super(VNIC, self).__init__("VirtNic", ip_addr, prefix_len, mtu)

    def del_br(self):
        pass

    def add_port(self, port_name):
        self.name = port_name
        with IPRoute() as ipr:
            idx = ipr.link_lookup(ifname=port_name)[0]
            ipr.link("set", index=idx, mtu=self.mtu)
            ipr.addr("add", index=idx, address=self.ip_addr, mask=self.prefix_len)
            ipr.link("set", index=idx, state="up")

    def del_port(self, port_name):
        with IPRoute() as ipr:
            idx = ipr.link_lookup(ifname="port_name")[0]
            ipr.link("set", index=idx, state="down")
            ipr.link("del", index=idx)


###################################################################################################


def get_evio_bridge_name(overlay_id: str, name_prefix: str) -> str:
    """Generates the appropriate bridge name from the overlay id and optional name prefix"""
    prefix = name_prefix[:3]
    end_i = BR_NAME_MAX_LENGTH - len(prefix)
    return prefix + overlay_id[:end_i]


def bridge_factory(
    overlay_id, dev_type, sw_proto, br_ctrl, **config
) -> Union[VNIC, LinuxBridge, OvsBridge, None]:
    """Creates an instance the appropriate network device as specified in the configuration.
    This is one of virtual network interface, Linux bridge, or Open-vSwitch"""
    net_dev: Union[VNIC, LinuxBridge, OvsBridge, None] = None
    if dev_type == VNIC.bridge_type:
        net_dev = VNIC(
            ip_addr=config.get("IP4", None),
            prefix_len=config.get("PrefixLen", None),
            mtu=config.get("MTU", MTU),
        )
    elif dev_type == LinuxBridge.bridge_type:
        br_name = get_evio_bridge_name(overlay_id, config["NamePrefix"])
        net_dev = LinuxBridge(
            name=br_name,
            ip_addr=config.get("IP4", None),
            prefix_len=config.get("PrefixLen", None),
            mtu=config.get("MTU", MTU),
            logger=br_ctrl.logger,
            stp_enable=bool(sw_proto.casefold() == "stp".casefold()),
        )
    elif dev_type == OvsBridge.bridge_type:
        br_name = get_evio_bridge_name(overlay_id, config["NamePrefix"])
        net_dev = OvsBridge(
            name=br_name,
            ip_addr=config.get("IP4", None),
            prefix_len=config.get("PrefixLen", None),
            mtu=config.get("MTU", MTU),
            sw_proto=sw_proto,
            sdn_ctrl_port=config.get("SDNControllerPort", SDN_CONTROLLER_PORT),
            logger=br_ctrl.logger,
        )
    return net_dev


###################################################################################################


class TunnelsLog(MutableMapping):
    def __init__(self, **kwargs) -> None:
        self._seq = int(kwargs.get("seq", 1))
        # maps a seqeunce number to a snapshot of the tunnel dataset
        self._journal: dict[int, dict[str, Any]] = {self._seq: {}}
        self._trim_point = self._seq - 1
        self._lock = threading.Lock()

    def __getitem__(self, port_name: str):
        with self._lock:
            return copy.deepcopy(self._journal[self._seq][port_name])

    def __delitem__(self, port_name: str):
        with self._lock:
            snap: dict[str, dict] = copy.copy(self._journal[self._seq])
            self._seq = self._seq + 1
            del snap[port_name]
            self._journal[self._seq] = snap

    def __setitem__(self, port_name: str, tunnel_descr: dict):
        with self._lock:
            snap: dict[str, dict] = copy.deepcopy(self._journal[self._seq])
            snap[port_name] = tunnel_descr
            self._seq = self._seq + 1
            self._journal[self._seq] = snap

    def __iter__(self):
        with self._lock:
            return iter(self._journal[self._seq])

    def __len__(self):
        with self._lock:
            return len(self._journal[self._seq])

    def __repr__(self):
        with self._lock:
            return broker.introspect(self)

    @property
    def sequence_number(self) -> int:
        with self._lock:
            return self._seq

    def snapshot(self) -> dict:
        with self._lock:
            snp = self._journal[self._seq]
            self._trim_point = self._seq - 1
            return {"seq": self._seq, "snapshot": copy.deepcopy(snp)}

    def trim(self):
        with self._lock:
            for seq in sorted(self._journal.keys()):
                if seq > self._trim_point:
                    break
                self._journal.pop(seq)


class BridgeController(ControllerModule):
    """Bridge Controller is responsible for creating, configuring and mananging
    the local network devices used in the Evio overlays"""

    _REFLECT: list[str] = ["_ovl_net", "_appbr", "_tunnels"]

    def __init__(self, nexus, module_config):
        super().__init__(nexus, module_config)
        # self._bfproxy = None
        # self._bfproxy_thread = None
        self._ovl_net: dict[str, Union[VNIC, LinuxBridge, OvsBridge]] = {}
        self._appbr: dict[str, Union[LinuxBridge, OvsBridge]] = {}
        # self._lock = threading.Lock()
        self._tunnels: dict[str, TunnelsLog] = {}

    def initialize(self):
        self._register_abort_handlers()
        self._register_req_handlers()
        self._register_resp_handlers()
        for _, net_ovl in self.config["Overlays"].items():
            if "NetDevice" not in net_ovl:
                net_ovl["NetDevice"] = {}
        # start the BF proxy if at least one overlay is configured for it
        if "BoundedFlood" in self.config:
            self._start_bf_proxy_server()
        # create and configure the bridge for each overlay
        _ = self._create_overlay_bridges()
        publishers = self.get_registered_publishers()
        if (
            "TincanTunnel" not in publishers
            or "TCI_TINCAN_MSG_NOTIFY"
            not in self.get_available_subscriptions("TincanTunnel")
        ):
            raise RuntimeError(
                "The TincanTunnel MESSAGE NOTIFY subscription is not available."
                "Link Manager cannot continue."
            )
        self.start_subscription("TincanTunnel", "TCI_TINCAN_MSG_NOTIFY")

        if (
            "LinkManager" not in publishers
            or "LNK_TUNNEL_EVENTS"
            not in self.get_available_subscriptions("LinkManager")
        ):
            raise RuntimeError(
                "The LinkManager subscription is not available."
                "BridgeController cannot continue."
            )
        self.start_subscription("LinkManager", "LNK_TUNNEL_EVENTS")

        if (
            "GeneveTunnel" in publishers
            and "GNV_TUNNEL_EVENTS" in self.get_available_subscriptions("GeneveTunnel")
        ):
            self.start_subscription("GeneveTunnel", "GNV_TUNNEL_EVENTS")
        else:
            self.logger.info("Geneve tunnel capability unavailable")
        self.logger.info("Controller module loaded")

    def _register_abort_handlers(self):
        self._abort_handler_tbl = {
            "LNK_ADD_IGN_INF": self.abort_handler_default,
            "TOP_REQUEST_OND_TUNNEL": self.abort_handler_default,
        }

    def _register_req_handlers(self):
        self._req_handler_tbl = {
            "GNV_TUNNEL_EVENTS": self.req_handler_manage_bridge,
            "LNK_TUNNEL_EVENTS": self.req_handler_manage_bridge,
            "VIS_DATA_REQ": self.req_handler_vis_data,
            "TCI_TINCAN_MSG_NOTIFY": self.req_handler_tincan_notify,
        }

    def _register_resp_handlers(self):
        self._resp_handler_tbl = {
            "LNK_ADD_IGN_INF": self.resp_handler_default,
            "TOP_REQUEST_OND_TUNNEL": self.resp_handler_default,
        }

    def _start_bf_proxy_server(self):
        bf_config = self.config["BoundedFlood"]
        bf_config["NodeId"] = self.node_id
        bf_ovls = bf_config.pop("Overlays")
        for olid in bf_ovls:
            net_ovl = self.overlays[olid]
            br_name = get_evio_bridge_name(
                olid,
                net_ovl["NetDevice"].get("NamePrefix", NAME_PREFIX_EVI),
            )
            bf_config[br_name] = bf_ovls[olid]
            bf_config[br_name]["OverlayId"] = olid
        # while True:
        #     try:
        #         self._bfproxy = BoundedFloodProxy(
        #             bf_config,
        #             self,
        #         )
        #         self._bfproxy_thread = threading.Thread(
        #             target=self._bfproxy.serve_forever, name="BFProxyServer"
        #         )
        #         break
        #     except socket.error as err:
        #         self.logger.warning(
        #             "Failed to start the BoundedFlood Proxy, will retry. Error msg= %s",
        #             err,
        #         )
        #         time.sleep(10)
        # self._server_thread.setDaemon(True)
        # self._bfproxy_thread.start()
        # start the BF RYU module
        # self._bfproxy.start_bf_client_module()
        self.start_bf_client_module(bf_config)

    def _create_overlay_bridges(self) -> dict:
        ign_br_names = {}
        for olid in self.overlays:
            self._tunnels[olid] = TunnelsLog()
            br_cfg = self.overlays[olid]
            ign_br_names[olid] = set()
            if "NamePrefix" not in br_cfg["NetDevice"]:
                br_cfg["NetDevice"]["NamePrefix"] = NAME_PREFIX_EVI
            self._ovl_net[olid] = bridge_factory(
                olid,
                br_cfg["NetDevice"].get("BridgeProvider", DEFAULT_BRIDGE_PROVIDER),
                br_cfg["NetDevice"].get("SwitchProtocol", DEFAULT_SWITCH_PROTOCOL),
                self,
                **br_cfg["NetDevice"],
            )
            if "AppBridge" in br_cfg["NetDevice"]:
                name = self._create_app_bridge(olid, br_cfg["NetDevice"]["AppBridge"])
                ign_br_names[olid].add(name)
            ign_br_names[olid].add(self._ovl_net[olid].name)
            self.register_cbt("LinkManager", "LNK_ADD_IGN_INF", ign_br_names)
        return ign_br_names

    def _add_tunnel_port(self, overlay_id: str, port_name: str, tnl_data: dict):
        try:
            bridge = self._ovl_net[overlay_id]
            mac = tnl_data["MAC"]
            peer_mac = tnl_data["PeerMac"]
            descr = {
                "PeerId": tnl_data["PeerId"],
                "TunnelId": tnl_data["TunnelId"],
                "ConnectedTimestamp": tnl_data["ConnectedTimestamp"],
                "TapName": port_name,
                "MAC": mac if ":" in mac else broker.delim_mac_str(mac),
                "PeerMac": peer_mac
                if ":" in peer_mac
                else broker.delim_mac_str(peer_mac),
                "Dataplane": tnl_data["Dataplane"],
            }
            self._tunnels[overlay_id][port_name] = descr
            bridge.add_port(port_name, descr)
            self.logger.info("Port %s added to bridge %s", port_name, str(bridge))
        except Exception as err:
            self._tunnels[overlay_id].pop(port_name, None)
            bridge.del_port(port_name)
            self.logger.info("Failed to add port %s. %s", tnl_data, err, exc_info=True)

    def req_handler_manage_bridge(self, cbt: CBT):
        try:
            olid = cbt.request.params["OverlayId"]
            bridge = self._ovl_net[olid]
            port_name = cbt.request.params.get("TapName")
            if cbt.request.params["UpdateType"] == TUNNEL_EVENTS.Connected:
                self._add_tunnel_port(olid, port_name, cbt.request.params)
            elif cbt.request.params["UpdateType"] == TUNNEL_EVENTS.Removed:
                self._tunnels[olid].pop(port_name, None)
                bridge.del_port(port_name)
                self.logger.info("Port %s removed from bridge %s", port_name, bridge)
        except Exception as err:
            self.logger.warning("Manage bridge error %s", err, exc_info=True)
        cbt.set_response(None, True)
        self.complete_cbt(cbt)

    def req_handler_tincan_notify(self, cbt: CBT):
        if cbt.request.params["Command"] == "ResetTincanTunnels":
            sid = cbt.request.params["SessionId"]
            for olid, br in self._ovl_net.items():
                self.logger.info("Clearing Tincan TAPs from %s for session %s", br, sid)
                for port_name in [*br.ports]:
                    if (
                        br.port_descriptors[port_name]["Dataplane"]
                        == DATAPLANE_TYPES.Tincan
                    ):
                        br.del_port(port_name)
                        self._tunnels[olid].pop(port_name, None)
                        self.logger.info(
                            "Port %s removed from bridge %s", port_name, br
                        )
        cbt.set_response(data=None, status=True)
        self.complete_cbt(cbt)

    def on_timer_event(self):
        for tnl in self._tunnels.values():
            tnl.trim()

    # def abort_handler(self, cbt: CBT):
    #     """Additional resouce clean here, eg., fail edge negotiate or create"""
    #     self.free_cbt(cbt)

    def process_cbt(self, cbt):
        if cbt.is_expired:
            self.abort_handler(cbt)
        elif cbt.is_pending:
            if cbt.request.action in ("LNK_TUNNEL_EVENTS", "GNV_TUNNEL_EVENTS"):
                self.req_handler_manage_bridge(cbt)
            elif cbt.request.action == "VIS_DATA_REQ":
                self.req_handler_vis_data(cbt)
            elif cbt.request.action == "TCI_TINCAN_MSG_NOTIFY":
                self.req_handler_tincan_notify(cbt)
            else:
                self.req_handler_default(cbt)
        elif cbt.is_completed:
            self.resp_handler_default(cbt)

    def terminate(self):
        try:
            # if self._bfproxy:
            #     self._bfproxy.stop_bf_module()
            #     self._bfproxy.server_close()
            #     self._bfproxy_thread.join()
            self.stop_bf_module()
            for olid, bridge in self._ovl_net.items():
                if self.overlays[olid]["NetDevice"].get(
                    "AutoDelete", BRIDGE_AUTO_DELETE
                ):
                    bridge.del_br()
                    if olid in self._appbr:
                        self._appbr[olid].del_br()
                else:
                    for port in [*bridge.ports]:
                        bridge.del_port(port)
        except RuntimeError as err:
            self.logger.warning("Terminate error %s", err, exc_info=True)
        self.logger.info("Controller module terminating")

    def req_handler_vis_data(self, cbt: CBT):
        br_data = {}
        is_data_available = False
        for olid in self.overlays:
            is_data_available = True
            br_data[olid] = {}
            br_data[olid]["BridgeProvider"] = self.overlays[olid]["NetDevice"].get(
                "BridgeProvider", DEFAULT_BRIDGE_PROVIDER
            )
            br_data[olid]["BridgeName"] = self.overlays[olid]["NetDevice"].get(
                "NamePrefix", NAME_PREFIX_EVI
            )
            if "IP4" in self.overlays[olid]["NetDevice"]:
                br_data[olid]["IP4"] = self.overlays[olid]["NetDevice"]["IP4"]
            if "PrefixLen" in self.overlays[olid]["NetDevice"]:
                br_data[olid]["PrefixLen"] = self.overlays[olid]["NetDevice"][
                    "PrefixLen"
                ]
            if "MTU" in self.overlays[olid]["NetDevice"]:
                br_data[olid]["MTU"] = self.overlays[olid]["NetDevice"]["MTU"]
            br_data[olid]["AutoDelete"] = self.overlays[olid]["NetDevice"].get(
                "AutoDelete", BRIDGE_AUTO_DELETE
            )
        cbt.set_response({"BridgeController": br_data}, is_data_available)
        self.complete_cbt(cbt)

    def _create_app_bridge(self, olid, abr_cfg):
        """If specified in the configuration, add an application bridge that is patched through
        to the Evio switch. Only supported when bridge type is OVS"""
        if "NamePrefix" not in abr_cfg:
            abr_cfg["NamePrefix"] = NAME_PREFIX_APP_BR
        gbr = bridge_factory(
            olid,
            abr_cfg.get("BridgeProvider", DEFAULT_BRIDGE_PROVIDER),
            None,
            self,
            **abr_cfg,
        )

        gbr.add_patch_port(self._ovl_net[olid].patch_port_name)
        self._ovl_net[olid].add_patch_port(gbr.patch_port_name)
        self._appbr[olid] = gbr
        return self._appbr[olid].name

    def get_tunnels(self) -> dict[TunnelsLog]:
        """Retrieves the next topology update log entry"""
        resp = {}
        try:
            for olid, tnls_log in self._tunnels.items():
                resp[olid] = tnls_log.snapshot()
        except Exception as err:
            self.logger.warning(
                "The operation get_tunnels failed, %s", err, exc_info=True
            )
            resp = {}
        return resp

    def tunnel_request(self, req_params: dict):
        """Forwards the on demand tunnel request to Topology controller"""
        self.register_cbt("Topology", "TOP_REQUEST_OND_TUNNEL", req_params)

    def handle_ipc(self, msg: ProxyMsg):
        task = msg.json
        # task structure
        # dict(Request=dict(Action=None, Params=None),
        #      Response=dict(Status=False, Data=None))
        if task["Request"]["Action"] == "GetTunnelData":
            topo = self.get_tunnels()
            task["Response"] = dict(Status=bool(topo), Data=topo)
            self.logger.debug("Task response: %s", task)
        elif task["Request"]["Action"] == "TunnelRquest":
            task["Response"] = dict(
                Status=True, Data=dict(StatusMsg="Request shall be considered")
            )
            self.logger.info("On-demand tunnel request recvd %s", task["Request"])
            self.tunnel_request(task["Request"]["Params"])  # op is ADD/REMOVE
        else:
            self.logger.warning("An unrecognized SDNI task was discarded %s", task)
            task["Response"] = dict(
                Status=False, Data=dict(ErrorMsg="Unsupported request")
            )
        msg.data = json.dumps(task).encode("utf-8")
        # resp = ProxyMsg(msg.fileno, json.dumps(task).encode("utf-8"))
        self.send_ipc(msg)

    def start_bf_client_module(self, bf_config):
        RyuManager = spawn.find_executable("ryu-manager")
        if RyuManager is None:
            raise RuntimeError("RyuManager was not found, is it installed?")
        bf_config["ProxyAddress"] = self.process_proxy_address
        cmd = [
            RyuManager,
            "--nouse-stderr",
            "--user-flags",
            "controllers/bfflags.py",
            "--bf-config-string",
            json.dumps(bf_config),
            "controllers/bounded_flood.py",
        ]
        self._bf_proc = broker.create_process(cmd)

    def stop_bf_module(self):
        if hasattr(self, "_bf_proc"):
            if self._bf_proc:
                self._bf_proc.send_signal(signal.SIGINT)
                self._bf_proc.wait()
