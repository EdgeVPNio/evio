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
import threading
import time
import socketserver
from abc import ABCMeta, abstractmethod
from collections.abc import MutableMapping
from distutils import spawn
from typing import Dict
from framework.ControllerModule import ControllerModule
import framework.Modlib as Modlib

NamePrefix = ""
MTU = 1410
class BridgeABC():
    __metaclass__ = ABCMeta

    bridge_type = NotImplemented
    iptool = spawn.find_executable("ip")

    def __init__(self, name, ip_addr, prefix_len, mtu, cm):
        self.name = name
        self.ip_addr = ip_addr
        self.prefix_len = prefix_len
        self.mtu = mtu
        self.ports = set()
        self.cm = cm

    @abstractmethod
    def add_port(self, port_name):
        pass

    @abstractmethod
    def del_port(self, port_name):
        pass

    @abstractmethod
    def del_br(self):
        pass

    @property
    @abstractmethod
    def brctl(self,):
        pass

    def __repr__(self):
        """ Return a representaion of a bridge object. """
        return "%s %s" % (self.bridge_type, self.name)

    def __str__(self):
        """ Return a string of the bridge name. """
        return self.__repr__()
###################################################################################################


class OvsBridge(BridgeABC):
    brctl = spawn.find_executable("ovs-vsctl")
    bridge_type = "OVS"

    def __init__(self, name, ip_addr, prefix_len, mtu, cm, sw_proto, sdn_ctrl_port):
        """ Initialize an OpenvSwitch bridge object. """
        super(OvsBridge, self).__init__(name, ip_addr, prefix_len, mtu, cm)
        if OvsBridge.brctl is None or OvsBridge.iptool is None:
            raise RuntimeError("openvswitch-switch was not found" if not OvsBridge.brctl else
                               "iproute2 was not found")
        self._patch_port = "pp-"+self.name[:12]
        Modlib.runshell([OvsBridge.brctl, "--may-exist", "add-br", self.name])

        if ip_addr and prefix_len:
            net = "{0}/{1}".format(ip_addr, prefix_len)
            Modlib.runshell([OvsBridge.iptool, "addr",
                            "flush", "dev", self.name])
            Modlib.runshell([OvsBridge.iptool, "addr",
                            "add", net, "dev", self.name])
        else:
            Modlib.runshell(
                ["sysctl", "net.ipv6.conf.{}.disable_ipv6=1".format(self.name)])
            Modlib.runshell([OvsBridge.iptool, "addr", "flush", self.name])
        try:
            Modlib.runshell([OvsBridge.brctl, "set", "int", self.name,
                             "mtu_request=" + str(self.mtu)])
        except RuntimeError as e:
            self.cm.log("LOG_WARNING",
                        "The following error occurred while setting MTU for OVS bridge: %s", e)

        if sw_proto.casefold() == "STP".casefold():
            self.stp(True)
        elif sw_proto.casefold() == "BF".casefold():
            self.add_sdn_ctrl(sdn_ctrl_port)
        else:
            raise RuntimeError("Invalid switch protocol specified in bridge configuration.")          
        Modlib.runshell([OvsBridge.iptool, "link",
                        "set", "dev", self.name, "up"])

    def add_sdn_ctrl(self, sdn_ctrl_port):
        ctrl_conn_str = f"tcp:127.0.0.1:{sdn_ctrl_port}"
        Modlib.runshell([OvsBridge.brctl,
                            "set-controller",
                            self.name,
                            ctrl_conn_str])

    def del_sdn_ctrl(self):
        Modlib.runshell([OvsBridge.brctl, "del-controller", self.name])

    def del_br(self):
        self.del_sdn_ctrl()

        Modlib.runshell([OvsBridge.brctl,
                         "--if-exists", "del-br", self.name])

    def add_port(self, port_name):
        Modlib.runshell([OvsBridge.iptool, "link", "set",
                        "dev", port_name, "mtu", str(self.mtu)])
        Modlib.runshell([OvsBridge.brctl,
                         "--may-exist", "add-port", self.name, port_name])
        self.ports.add(port_name)

    def del_port(self, port_name):
        Modlib.runshell([OvsBridge.brctl,
                         "--if-exists", "del-port", self.name, port_name])
        if port_name in self.ports:
            self.ports.remove(port_name)

    def stp(self, enable):
        Modlib.runshell([OvsBridge.brctl,
                         "set", "bridge", self.name, "stp_enable={0}"
                         .format("true" if enable else "false")])

    def add_patch_port(self, peer_patch_port):
        iface_opt = "options:peer={0}".format(peer_patch_port)
        Modlib.runshell([OvsBridge.brctl,
                         "--may-exist", "add-port", self.name, self._patch_port,
                         "--", "set", "interface", self._patch_port, "type=patch", iface_opt])

    def get_patch_port_name(self):
        return self._patch_port
###################################################################################################


class LinuxBridge(BridgeABC):
    brctl = spawn.find_executable("brctl")
    bridge_type = "LXBR"

    def __init__(self, name, ip_addr, prefix_len, mtu, cm, stp_enable):
        """ Initialize a Linux bridge object. """
        super(LinuxBridge, self).__init__(name, ip_addr, prefix_len, mtu, cm)
        if LinuxBridge.brctl is None or LinuxBridge.iptool is None:
            raise RuntimeError("bridge-utils was not found" if not LinuxBridge.brctl else
                               "iproute2 was not found")
        p = Modlib.runshell([LinuxBridge.brctl, "show"])
        wlist = map(str.split, p.stdout.decode("utf-8").splitlines()[1:])
        brwlist = filter(lambda x: len(x) != 1, wlist)
        brlist = map(lambda x: x[0], brwlist)
        for br in brlist:
            if br == name:
                return

        p = Modlib.runshell([LinuxBridge.brctl, "addbr", self.name])
        net = "{0}/{1}".format(ip_addr, prefix_len)
        if ip_addr and prefix_len:
            Modlib.runshell(
                [LinuxBridge.iptool, "addr", "add", net, "dev", name])
        self.stp(stp_enable)
        Modlib.runshell([LinuxBridge.iptool, "link", "set", "dev", name, "up"])

    def del_br(self):
        # Set the device down and delete the bridge
        Modlib.runshell([LinuxBridge.iptool, "link",
                        "set", "dev", self.name, "down"])
        Modlib.runshell([LinuxBridge.brctl, "delbr", self.name])

    def add_port(self, port_name):
        Modlib.runshell([LinuxBridge.iptool, "link", "set",
                        port_name, "mtu", str(self.mtu)])
        Modlib.runshell([LinuxBridge.brctl, "addif", self.name, port_name])
        self.ports.add(port_name)

    def del_port(self, port_name):
        p = Modlib.runshell([LinuxBridge.brctl, "show", self.name])
        wlist = map(str.split, p.stdout.decode("utf-8").splitlines()[1:])
        port_lines = filter(lambda x: len(x) == 4, wlist)
        ports = map(lambda x: x[-1], port_lines)
        for port in ports:
            if port == port_name:
                Modlib.runshell(
                    [LinuxBridge.brctl, "delif", self.name, port_name])
                if port_name in self.ports:
                    self.ports.remove(port_name)

    def stp(self, val=True):
        """ Turn STP protocol on/off. """
        if val:
            state = "on"
        else:
            state = "off"
        Modlib.runshell([LinuxBridge.brctl, "stp", self.name, state])

    def set_bridge_prio(self, prio):
        """ Set bridge priority value. """
        Modlib.runshell([LinuxBridge.brctl,
                         "setbridgeprio", self.name, str(prio)])

    def set_path_cost(self, port, cost):
        """ Set port path cost value for STP protocol. """
        Modlib.runshell([LinuxBridge.brctl,
                         "setpathcost", self.name, port, str(cost)])

    def set_port_prio(self, port, prio):
        """ Set port priority value. """
        Modlib.runshell([LinuxBridge.brctl,
                         "setportprio", self.name, port, str(prio)])
###################################################################################################


class BoundedFloodProxy(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """
    Starts the TCP proxy listener
    Starts the Ryu engine and module
    Supports interactions between BF Ryu module and evio controller
    """
    RyuManager = spawn.find_executable("ryu-manager")
    if RyuManager is None:
        raise RuntimeError("RyuManager was not found, is it installed?")

    def __init__(self, host_port_tuple, bf_config, streamhandler, netman):
        super().__init__(host_port_tuple, streamhandler)
        self.config = bf_config
        self.netman = netman
        self._bf_proc = None

    def start_bf_client_module(self):
        # with open("/etc/opt/evio/bf-config.json", "w", encoding="utf-8") as f:
        #     json.dump(self.config, f, ensure_ascii=False, indent=4)
        cmd = [
            BoundedFloodProxy.RyuManager,
            "--user-flags", "modules/BFFlags.py",
            "--nouse-stderr",
            "--bf-config-string", json.dumps(self.config),
            "modules/BoundedFlood.py"]
        self._bf_proc = Modlib.create_process(cmd)
        self.config = None

    def server_close(self):
        if self._bf_proc:
            self._bf_proc.kill()
            self._bf_proc.wait()
        socketserver.TCPServer.server_close(self)


class BFRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(65536)
        if not data:
            return
        task = json.loads(data.decode("utf-8"))
        task = self.process_task(task)
        self.request.sendall(bytes(json.dumps(task) + "\n", "utf-8"))

    def process_task(self, task):
        # task structure
        # dict(Request=dict(Action=None, Params=None),
        #      Response=dict(Status=False, Data=None))
        if task["Request"]["Action"] == "GetTunnelData":
            task = self._handle_get_tunnel_data(task)
        # elif task["Request"]["Action"] == "GetTunnels":
        #     task = self._handle_get_tunnels(task)
        # elif task["Request"]["Action"] == "GetSeqNum":
        #     task = self._handle_get_current_seq(task)
        elif task["Request"]["Action"] == "GetNodeId":
            task["Response"] = dict(Status=True,
                                    Data=dict(NodeId=str(self.server.netman.node_id)))
        elif task["Request"]["Action"] == "TunnelRquest":
            task["Response"] = dict(Status=True,
                                    Data=dict(StatusMsg="Request shall be considered"))
            self.server.netman.log(
                "LOG_INFO", "On-demand tunnel request recvd %s", task["Request"])
            self.server.netman.tunnel_request(
                task["Request"]["Params"])  # op is ADD/REMOVE
        else:
            self.server.netman.log("LOG_WARNING", "An unrecognized SDNI task was discarded %s",
                                   task)
            task["Response"] = dict(Status=False, Data=dict(
                ErrorMsg="Unsupported request"))
        return task

    # def _handle_get_tunnels(self, task):
    #     olid = task["Request"]["Params"]["OverlayId"]
    #     seq = task["Request"]["Params"]["DSeq"]
    #     topo = self.server.netman.get_overlay_tunnels(olid, seq)
    #     task["Response"] = dict(Status=bool(topo), Data=topo)
    #     return task

    def _handle_get_tunnel_data(self, task):
        topo = self.server.netman.get_tunnels()
        task["Response"] = dict(Status=bool(topo), Data=topo)
        return task
    
    # def _handle_get_current_seq(self, task):
    #     olid = task["Request"]["Params"]["OverlayId"]
    #     topo = self.server.netman.get_overlay_seq(olid)
    #     task["Response"] = dict(Status=bool(topo), Data=topo)
    #     return task

###################################################################################################


class VNIC(BridgeABC):
    brctl = None
    bridge_type = "VNIC"

    def __init__(self, ip_addr, prefix_len, mtu, cm):
        super(VNIC, self).__init__("VirtNic", ip_addr, prefix_len, mtu, cm)

    def del_br(self):
        pass

    def add_port(self, port_name):
        self.name = port_name
        net = "{0}/{1}".format(self.ip_addr, self.prefix_len)
        Modlib.runshell([VNIC.iptool, "addr", "add", net, "dev", self.name])
        Modlib.runshell([VNIC.iptool, "link", "set",
                        self.name, "mtu", str(self.mtu)])
        Modlib.runshell([VNIC.iptool, "link", "set", "dev", self.name, "up"])

    def del_port(self, port_name):
        pass

###################################################################################################


def get_br_name(overlay_id, config):
    BR_NAME_MAX_LENGTH = 15
    name_prefix = config.get("NamePrefix", NamePrefix)[:3]
    end_i = BR_NAME_MAX_LENGTH - len(name_prefix)
    return name_prefix + overlay_id[:end_i]


def BridgeFactory(overlay_id, dev_type, config, cm):

    br = None
    if dev_type == VNIC.bridge_type:
        br = VNIC(ip_addr=config.get("IP4", None),
                  prefix_len=config.get("PrefixLen", None),
                  mtu=config.get("MTU", MTU),
                  cm=cm)
    elif dev_type == LinuxBridge.bridge_type:
        br_name = get_br_name(overlay_id, config)
        br = LinuxBridge(name=br_name,
                         ip_addr=config.get("IP4", None),
                         prefix_len=config.get("PrefixLen", None),
                         mtu=config.get("MTU", MTU),
                         cm=cm,
                         stp_enable=(True if config.get("SwitchProtocol", "STP").casefold() == "stp" else False))
    elif dev_type == OvsBridge.bridge_type:
        br_name = get_br_name(overlay_id, config)
        br = OvsBridge(name=br_name,
                       ip_addr=config.get("IP4", None),
                       prefix_len=config.get("PrefixLen", None),
                       mtu=config.get("MTU", MTU),
                       cm=cm,
                       sw_proto=(config.get("SwitchProtocol", "")),
                       sdn_ctrl_port=config.get("SDNControllerPort", 6633))
    return br

###################################################################################################


class TunnelsLog(MutableMapping):
    def __init__(self,  **kwargs) -> None:
        self._seq = int(kwargs.get("seq", 1))
        # maps a seqeunce number to a snapshot of the tunnel dataset
        self._journal = {self._seq: dict()}
        self._trim_point = self._seq - 1
        # self.update(dict(**kwargs))
        self._lock = threading.Lock()

    def __getitem__(self, port_name):
        with self._lock:
            return copy.deepcopy(self._journal[self._seq][port_name])

    def __delitem__(self, port_name):
        with self._lock:
            ds = copy.copy(self._journal[self._seq])
            self._seq = self._seq + 1
            del ds[port_name]
            self._journal[self._seq] = ds

    def __setitem__(self, port_name, tunnel_descr):
        with self._lock:
            ds = copy.deepcopy(self._journal[self._seq])
            ds[port_name] = tunnel_descr
            self._seq = self._seq + 1
            self._journal[self._seq] = ds

    def __iter__(self):
        with self._lock:
            return iter(self._journal[self._seq])

    def __len__(self):
        with self._lock:
            return len(self._journal[self._seq])

    def __repr__(self):
        with self._lock:
            items = (f"\"{k}\": {v!r}" for k, v in self.__dict__.items())
        return "{{{}}}".format(", ".join(items))

    @property
    def sequence_number(self):
        with self._lock:
            return self._seq

    def snapshot(self):
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
    _REFLECT = set(["_tunnels"])

    def __init__(self, cfx_handle, module_config, module_name):
        super(BridgeController, self).__init__(
            cfx_handle, module_config, module_name)
        self._bfproxy = None
        self._server_thread = None
        self._ovl_net = dict()
        self._appbr = dict()
        self._lock = threading.Lock()
        self._tunnels = dict()

    def initialize(self):
        ign_br_names = dict()
        # start the BF proxy if at least one overlay is configured for it
        if "BoundedFlood" in self.config:
            proxy_listen_address = self.config["BoundedFlood"]["ProxyListenAddress"]
            proxy_listen_port = self.config["BoundedFlood"]["ProxyListenPort"]
            bf_config = self.config["BoundedFlood"]
            bf_config["NodeId"] = self.node_id
            bf_ovls = bf_config.pop("Overlays")
            for olid in bf_ovls:
                br_name = get_br_name(olid, self.overlays[olid]["NetDevice"])
                bf_config[br_name] = bf_ovls[olid]
                bf_config[br_name]["OverlayId"] = olid
            time.sleep(1)
            self._bfproxy = BoundedFloodProxy(
                (proxy_listen_address, proxy_listen_port), bf_config,
                BFRequestHandler, self)
            self._server_thread = threading.Thread(target=self._bfproxy.serve_forever,
                                                   name="BFProxyServer")
            self._server_thread.setDaemon(True)
            self._server_thread.start()
            # start the BF RYU module
            self._bfproxy.start_bf_client_module()
        # create each configure bridge type
        for olid in self.overlays:
            self._tunnels[olid] = TunnelsLog()
            br_cfg = self.overlays[olid]
            ign_br_names[olid] = set()
            self._ovl_net[olid] = BridgeFactory(olid, br_cfg["NetDevice"]["Type"],
                                                br_cfg["NetDevice"], self)
            if "AppBridge" in br_cfg["NetDevice"]:
                name = self._create_app_bridge(
                    olid, br_cfg["NetDevice"]["AppBridge"])
                ign_br_names[olid].add(name)
            ign_br_names[olid].add(self._ovl_net[olid].name)
            self.register_cbt("LinkManager", "LNK_ADD_IGN_INF", ign_br_names)
        self.logger.debug(f"ignored bridges={ign_br_names}")
        # self.log("LOG_DEBUG", "ignored bridges=%s", ign_br_names)
        # try:
        #    # Subscribe for data request notifications from OverlayVisualizer
        #    self._cfx_handle.start_subscription("OverlayVisualizer", "VIS_DATA_REQ")
        # except NameError as err:
        #    if "OverlayVisualizer" in str(err):
        #        self.register_cbt("Logger", "LOG_INFO",
        #                          "OverlayVisualizer module not loaded."
        #                          " Visualization data will not be sent.")

        self._cfx_handle.start_subscription("LinkManager", "LNK_TUNNEL_EVENTS")
        self.logger.info("Module Loaded")

    def req_handler_manage_bridge(self, cbt):
        try:
            olid = cbt.request.params["OverlayId"]
            br = self._ovl_net[olid]
            port_name = cbt.request.params.get("TapName")
            tnlid = cbt.request.params["TunnelId"]
            if cbt.request.params["UpdateType"] == "LnkEvCreated":
                # block external system components from attempting to configure our
                # tunnel as a source of traffic
                Modlib.runshell(
                    ["sysctl", "net.ipv6.conf.{}.disable_ipv6=1".format(port_name)])
                Modlib.runshell([OvsBridge.iptool, "addr", "flush", port_name])
            elif cbt.request.params["UpdateType"] == "LnkEvConnected":
                self._tunnels[olid][port_name] = {
                    "PeerId": cbt.request.params["PeerId"],
                    "TunnelId": tnlid,
                    "ConnectedTimestamp": cbt.request.params["ConnectedTimestamp"],
                    "TapName": port_name,
                    "MAC": Modlib.delim_mac_str(cbt.request.params["MAC"]),
                    "PeerMac": Modlib.delim_mac_str(cbt.request.params["PeerMac"])
                }
                br.add_port(port_name)
                self.log("LOG_INFO", "Port %s added to bridge %s",
                         port_name, str(br))
            elif cbt.request.params["UpdateType"] == "LnkEvRemoved":
                self._tunnels[olid].pop(port_name, None)
                if br.bridge_type == OvsBridge.bridge_type:
                    br.del_port(port_name)
                    self.log(
                        "LOG_INFO", "Port %s removed from bridge %s", port_name, str(br))
        except RuntimeError as err:
            self.log("LOG_WARNING", str(err))
        cbt.set_response(None, True)
        self.complete_cbt(cbt)

    def timer_method(self):
        self.trace_state()
        for olid in self._tunnels:
            self._tunnels[olid].trim()

    def process_cbt(self, cbt):
        if cbt.op_type == "Request":
            if cbt.request.action == "LNK_TUNNEL_EVENTS":
                self.req_handler_manage_bridge(cbt)
            elif cbt.request.action == "VIS_DATA_REQ":
                self.req_handler_vis_data(cbt)
            else:
                self.req_handler_default(cbt)
        elif cbt.op_type == "Response":
            parent_cbt = cbt.parent
            cbt_data = cbt.response.data
            cbt_status = cbt.response.status
            self.free_cbt(cbt)
            if (parent_cbt is not None and parent_cbt.child_count == 1):
                parent_cbt.set_response(cbt_data, cbt_status)
                self.complete_cbt(parent_cbt)

    def terminate(self):
        try:
            if self._bfproxy:
                self._bfproxy.server_close()
                self._bfproxy.shutdown()
            for olid in self._ovl_net:
                if olid in self._appbr and self.overlays[olid]["NetDevice"]["AppBridge"].get("AutoDelete", False):
                    self._appbr[olid].del_br()
                br = self._ovl_net[olid]
                if self.overlays[olid]["NetDevice"].get("AutoDelete", False):
                    br.del_br()
                else:
                    if br.bridge_type == OvsBridge.bridge_type:
                        for port in br.ports:
                            br.del_port(port)
        except RuntimeError as err:
            self.register_cbt("Logger", "LOG_WARNING", str(err))

    def req_handler_vis_data(self, cbt):
        br_data = dict()
        is_data_available = False
        for olid in self.overlays:
            is_data_available = True
            br_data[olid] = {}
            br_data[olid]["Type"] = self.overlays[olid]["NetDevice"]["Type"]
            br_data[olid]["BridgeName"] = self.overlays[olid]["NetDevice"].get("NamePrefix", NamePrefix)
            if "IP4" in self.overlays[olid]["NetDevice"]:
                br_data[olid]["IP4"] = self.overlays[olid]["NetDevice"]["IP4"]
            if "PrefixLen" in self.overlays[olid]["NetDevice"]:
                br_data[olid]["PrefixLen"] = self.overlays[olid]["NetDevice"]["PrefixLen"]
            if "MTU" in self.overlays[olid]["NetDevice"]:
                br_data[olid]["MTU"] = self.overlays[olid]["NetDevice"]["MTU"]
            br_data[olid]["AutoDelete"] = self.overlays[olid]["NetDevice"].get(
                "AutoDelete", False)
        cbt.set_response({"BridgeController": br_data}, is_data_available)
        self.complete_cbt(cbt)

    def _create_app_bridge(self, olid, abr_cfg):
        name_prefix = abr_cfg.get("NamePrefix", NamePrefix)[:3]
        end_i = 15 - len(name_prefix)
        name = name_prefix[:3] + olid[:end_i]
        gbr = BridgeFactory(olid, abr_cfg["Type"], abr_cfg, self)

        gbr.add_patch_port(self._ovl_net[olid].get_patch_port_name())
        self._ovl_net[olid].add_patch_port(gbr.get_patch_port_name())
        self._appbr[olid] = gbr
        return name

    def get_tunnels(self):
        resp = {}
        try:
            for olid in self._tunnels:
                resp[olid] = self._tunnels[olid].snapshot()
        except Exception as err:
            self.logger.exception("The operation get_tunnels failed")
            resp = None
        return resp

    def tunnel_request(self, req_params):
        self.register_cbt("Topology", "TOP_REQUEST_OND_TUNNEL", req_params)
