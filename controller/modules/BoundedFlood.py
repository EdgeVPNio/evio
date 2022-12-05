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


from collections import namedtuple
import json
from typing import List, Union
from eventlet.green import time
from eventlet.green import socket
from eventlet.green import Queue
from eventlet.green import subprocess
from datetime import datetime
import struct
import uuid
from distutils import spawn
import os
import logging
from collections.abc import MutableSet
import random
import math
import hashlib
import logging.handlers as lh
from collections.abc import MutableMapping
from collections.abc import MutableSet
from ryu import cfg
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import dpset
from ryu.ofproto import ofproto_v1_4
from ryu.lib.packet import packet_base
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib import hub
from ryu.lib import mac as mac_lib
from ryu.topology import event
from ryu.lib import addrconv
from ryu.lib.packet import packet_utils
import Tunnel

DataplaneTypes = Tunnel.DataplaneTypes
LogDir = "/var/log/evio/"
LogFilename = "bf.log"
LogLevel = "INFO"
DemandThreshold = "10M"
FlowIdleTimeout = 60
FlowHardTimeout = 60
LinkCheckInterval = 10
MaxOnDemandEdges = 3
TrafficAnalysisInterval = 10
StateLoggingInterval = 60
StateTracingEnabled = False
ProxyListenAddress = ""
ProxyListenPort = 5802
BackupCount = 2
MaxBytes = 10000000
CONF = cfg.CONF  # RYU environment
BF_COUNTER_DIGEST = hashlib.sha256("".encode("utf-8")).hexdigest()
BF_STATE_DIGEST = hashlib.sha256("".encode("utf-8")).hexdigest()
INTERNAL_PORT_NUM = 4294967294
KNOWN_LEAF_PORTS = {INTERNAL_PORT_NUM, 1}
NODE_TYPES = namedtuple("NODE_TYPES",
                        ["UNKNOWN", "LEAF", "EVIO_LEAF", "PEER"],
                        defaults=["ND_TYPE_UNKNOWN", "ND_TYPE_LEAF", "ND_TYPE_EVIO_LEAF", "ND_TYPE_PEER"])
NodeTypes = NODE_TYPES()

OPCODE = namedtuple("OPCODE",
                    ["UPDATE_TUNNELS", "OND_REQUEST"],
                    defaults=["UPDATE_TUNNELS", "OND_REQUEST"])
Opcode = OPCODE()


def runcmd(cmd):
    """ Run a shell command. if fails, raise an exception. """
    if cmd[0] is None:
        raise ValueError("No executable specified to run")
    p = subprocess.run(cmd, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, check=False)
    return p


def is_multiricepient(mac_addr):
    """
    :param addr: An IEEE EUI-48 (MAC) address in UNIX/WINDOWS string form.

    :return: ``True`` if MAC address string is multicast, ``False`` otherwise.
    """
    return bool(int(mac_addr.replace(":", ""), 16) & 1)


##########################################################################
class EvioOp():
    def __init__(self, code, dpid, olid, data=None):
        self.code = code
        self.dpid = dpid
        self.olid = olid
        self.data = data


class EvioPortal():
    MAX_ATTEMPTS = 3

    def __init__(self, svr_addr: tuple, logger):
        self._logger = logger
        self._svr_addr = svr_addr
        self._sock = None

    def connect(self):
        attempts = 0
        while attempts < self.MAX_ATTEMPTS:
            try:
                attempts += 1
                self._sock.connect(self._svr_addr)
                break
            except ConnectionRefusedError as err:
                if attempts < 3:
                    self._logger.warning(
                        "Attempt %i failed to connect to evio portal: %s", attempts, str(err))
                    hub.sleep(1)
                else:
                    self._logger.error(
                        "Aborting attempts to connect to evio portal. Error: %s", str(err))
                    raise err

    def send(self, req):
        send_data = json.dumps(req)
        self._sock.sendall(bytes(send_data + "\n", "utf-8"))

    def recv(self):
        recv_data = str(self._sock.recv(65536), "utf-8")
        if not recv_data:
            return {'Response': {'Status': False, 'Data': "No response from evio controller"}}

        return json.loads(recv_data)

    def send_recv(self, req):
        resp = None
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect()
        try:
            # self._logger.debug("EvioPortal send Request={}".format(req))
            self.send(req)
            resp = self.recv()
            # self._logger.debug("EvioPortal recv'd Response={}".format(resp))
        except Exception as err:
            self._logger.warning(f"A send recv failure occurred: {err}")
            resp = {'Response': {'Status': False,
                                 'Data': "The send/recv operation to the evio controller failed."}}
        finally:
            self._sock.close()
        return resp

    def terminate(self):
        self._sock.close()

###################################################################################################


class PeerData():
    def __init__(self, peer_id):
        self.node_id = peer_id
        self.hw_addr = None         # peer mac from evio controller
        self.leaf_macs = set()      # leaf devices managed by the peer switch
        self.hop_count = 0          # 1 -> an adjacent peer
        self.port_no = None         # valid only when a peer tunnel exists

    def __repr__(self):
        msg = {"hw_addr": self.hw_addr, "node_id": self.node_id,
               "hop_count": self.hop_count, "leaf_macs": list(self.leaf_macs), "port_no": self.port_no}
        return json.dumps(msg)

    def __str__(self):
        return self.__repr__()

    def update(self, peer_hw_addr=None, leaf_macs: list = None, hop_count=None, port_no=None):
        if peer_hw_addr:
            self.hw_addr = peer_hw_addr
        if leaf_macs:
            self.leaf_macs.update(leaf_macs)
        if hop_count:
            self.hop_count = hop_count
        if port_no:
            self.port_no = port_no

###################################################################################################


class PortDescriptor():

    def __init__(self, port_no: int, name: str, hw_addr: str):
        self.port_no = port_no              # port no for tunnel on the local switch
        self.name = name                    # interface (TAP/NIC) name
        self.hw_addr = hw_addr              # local side tunnel MAC
        # is the remote device a peer switch or leaf
        self.rmt_nd_type = NodeTypes.UNKNOWN
        self.peer_data = None               # valid if ND_TYPE_PEER
        self._dp_type = DataplaneTypes.Unknown
        self.is_activated = False
        self.last_active_time = time.time()

    def __repr__(self):
        msg = {"port_no": self.port_no, "name": self.name, "hw_addr": self.hw_addr,
               "rmt_nd_type": self.rmt_nd_type, "dp_type": self.dp_type,
               "last_active_time": str(datetime.fromtimestamp(self.last_active_time)),
               "is_activated": self.is_activated,
               "peer_data": self.peer_data.__dict__ if self.peer_data else None}
        return json.dumps(msg, default=lambda o: list(o) if isinstance(o, set) else o)

    def __str__(self):
        return self.__repr__()

    @property
    def peer(self):
        return self.peer_data

    @peer.setter
    def peer(self, data):
        if isinstance(data, PeerData):
            self.peer_data = data
        else:
            self.peer_data = PeerData(data)
            #raise ValueError("Unsupported type for peer data")

    @property
    def is_peer(self):
        return bool(self.rmt_nd_type == NodeTypes.PEER and self.peer_data is not None)

    @property
    def is_categorized(self):
        return bool(self.rmt_nd_type != NodeTypes.UNKNOWN)

    @property
    def dp_type(self):
        return self._dp_type

    @dp_type.setter
    def dp_type(self, tech):
        if tech == DataplaneTypes.Tincan:
            self.is_activated = True
        self._dp_type = tech

    @property
    def is_tincan_tunnel(self):
        return self._dp_type == DataplaneTypes.Tincan

    @property
    def is_geneve_tunnel(self):
        return self._dp_type == DataplaneTypes.Geneve

    @property
    def is_wireguard_tunnel(self):
        return self._dp_type == DataplaneTypes.WireGuard

###################################################################################################


class EvioSwitch(MutableMapping):
    def __init__(self, datapath, **kwargs) -> None:
        self._datapath = datapath
        self._overlay_id = kwargs["OverlayId"]
        self._node_id = kwargs["NodeId"]
        self.logger = kwargs["Logger"]
        self._leaf_prts = set()         # port_no of leaf tunnels
        self._link_prts = set()         # port_no of peer tunnels
        self._leaf_macs = set()         # hw addr of local leaf devices
        self._port_tbl = dict()         # port_no->PortDescriptor
        self._ingress_tbl = dict()      # hw_addr->ingress port number
        self._root_sw_tbl = dict()      # leaf_mac->PeerData
        self._peer_tbl = dict()         # node_id->PeerData

        self.max_on_demand_edges = kwargs.get(
            "MaxOnDemandEdges", FlowHardTimeout)
        self.traffic_analyzer = TrafficAnalyzer(
            self.logger, kwargs.get("DemandThreshold", DemandThreshold))
        self._is_tunnel_data_good = False
        self.idle_timeout = kwargs.get("FlowIdleTimeout", FlowIdleTimeout)
        self.hard_timeout = kwargs.get("FlowHardTimeout", FlowHardTimeout)
        self._topo_seq = 0
        self._uncategorized_ports = set()
        #self._lock = threading.RLock()
        self._max_hops = 0
        self._ond_ops = []

    def __repr__(self):
        msg = {"EvioSwitch": {
            "overlay_id": self._overlay_id, "node_id": self._node_id,
            "datapath_id": self._datapath.id, "leaf_ports": list(self._leaf_prts),
            "link_ports": list(self._link_prts), "leaf_macs": list(self._leaf_macs),
            "ingress_tbl": self._ingress_tbl, "port_tbl": self._port_tbl,
            "root_sw_tbl": self._root_sw_tbl, "peer_table": self._peer_tbl}}
        return str(msg)

    def __str__(self):
        return self.__repr__()

    def __getitem__(self, mac):
        # return the best egress to reach the given mac
        psw = self._root_sw_tbl.get(mac)
        if psw and psw.port_no:
            return psw.port_no
        return self._ingress_tbl[mac]

    def __setitem__(self, key_mac, value: Union[tuple, str]):
        if isinstance(value, tuple):
            self._learn(src_mac=key_mac, in_port=value[0], rnid=value[1])
        else:
            self._learn(key_mac, value)

    def __delitem__(self, mac):
        self._ingress_tbl.pop(mac, None)
        self._root_sw_tbl.pop(mac, None)

    def __iter__(self):
        return iter(self._ingress_tbl)

    def __len__(self):
        return len(self._ingress_tbl)

    def _register_peer(self, peer_id, in_port=None, peer_hw_addr=None, leaf_macs: list = None, hop_count=None) -> PeerData:
        if peer_id not in self._peer_tbl:
            self._peer_tbl[peer_id] = PeerData(peer_id)
        self._peer_tbl[peer_id].update(
            port_no=in_port, peer_hw_addr=peer_hw_addr, leaf_macs=leaf_macs, hop_count=hop_count)
        return self._peer_tbl[peer_id]

    def _deregister_peer(self, peer_id):
        """
        Clear port_no to indicate the tunnel is removed, ie., switch is no longer adjacent
        although it may be accessible via hops.
        """
        if peer_id and peer_id in self._peer_tbl:
            self._peer_tbl[peer_id].port_no = None

    @property
    def name(self) -> str:
        return self._port_tbl[INTERNAL_PORT_NUM].name

    @property
    def is_ond_enabled(self) -> bool:
        return self.max_on_demand_edges > 0

    @property
    def leaf_ports(self) -> list:
        # with self._lock:
        return list(self._leaf_prts)

    @property
    def link_ports(self) -> list:
        # with self._lock:
        return list(self._link_prts)

    @property
    def port_numbers(self) -> list:
        # with self._lock:
        return [*self._port_tbl.keys()]

    @property
    def node_id(self) -> str:
        return self._node_id

    @property
    def overlay_id(self) -> str:
        return self._overlay_id

    @property
    def peer_list(self) -> list:
        return [*self._peer_tbl.keys()]
        # pl = []
        # # with self._lock:
        # for port_no in self._link_prts:
        #     pl.append(self._port_tbl[port_no].peer_data.node_id)
        # return pl

    def peer(self, peer_id) -> PeerData:
        return self._peer_tbl[peer_id]

    def get_root_sw(self, leaf_mac) -> PeerData:
        # with self._lock:
        return self._root_sw_tbl.get(leaf_mac)

    def port_descriptor(self, port_no) -> PortDescriptor:
        # with self._lock:
        return self._port_tbl[port_no]

    def is_valid_port(self, port_no) -> bool:
        # with self._lock:
        return bool(port_no in self._datapath.ports)

    def is_port_categorized(self, port_no) -> bool:
        # with self._lock:
        return bool(self._port_tbl[port_no].is_categorized)

    def is_port_activated(self, port_no) -> bool:
        return self._port_tbl[port_no].is_activated

    def is_update_pending(self) -> bool:
        with self._lock:
            return bool(self._uncategorized_ports)

    def update_bridge_ports(self, port_set):
        # with self._lock:
        self._port_tbl.clear()
        self._root_sw_tbl.clear()
        self._peer_tbl.clear()
        self._uncategorized_ports.clear()
        for port_no, prt in port_set.items():
            pd = PortDescriptor(
                port_no, prt.name.decode("utf-8"), prt.hw_addr)
            if port_no == INTERNAL_PORT_NUM:
                pd.rmt_nd_type = NodeTypes.LEAF
                pd.dp_type = DataplaneTypes.Patch
            else:
                self._uncategorized_ports.add(port_no)
            self._port_tbl[port_no] = pd

    def _categorize_port(self,  port, rmt_nd_type, tnl_data=None):
        """
        Categorize a port in the local switch by setting the tunnel type,
        and optionally creating the PeerData entry in the peer table and port descriptor.
        """
        port.rmt_nd_type = rmt_nd_type
        self._port_tbl[port.port_no] = port
        if tnl_data:
            port.dp_type = tnl_data["Dataplane"]
            pd = self._register_peer(peer_id=tnl_data["PeerId"],
                                     peer_hw_addr=tnl_data["PeerMac"],
                                     in_port=port.port_no, hop_count=1)
            self._port_tbl[port.port_no].peer_data = pd
        else:
            port.dp_type = DataplaneTypes.Patch
        self.logger.info("Categorized port %s %s",
                         self.name, self._port_tbl[port.port_no])

    def activate_port(self, port_no):
        self._port_tbl[port_no].is_activated = True

    def add_port(self, ofpport):
        port = PortDescriptor(
            ofpport.port_no, ofpport.name.decode("utf-8"), ofpport.hw_addr)
        # with self._lock:
        self._port_tbl[port.port_no] = port
        self._uncategorized_ports.add(port.port_no)
        self.logger.debug("Added uncategorized port_no: %s/%i",
                          self.name, ofpport.port_no)

    def delete_port(self, port_no):
        # with self._lock:
        port = self._port_tbl.pop(port_no, None)
        if port:
            self.logger.debug("Removed %s:%s from _port_tbl",
                              self.name, port)
            if port.rmt_nd_type == "ND_TYPE_PEER":
                self._deregister_peer(port.peer_data.node_id)
                self._link_prts.remove(port_no)
                for mac in port.peer_data.leaf_macs:
                    self._ingress_tbl.pop(mac, None)
                    self._root_sw_tbl.pop(mac, None)
            elif port.rmt_nd_type == "ND_TYPE_LEAF":
                self._leaf_prts.remove(port_no)
            tbr = []  # build a list of all mac that ingress via this port
            for mac_key, port_val in self._ingress_tbl.items():
                if port_val == port_no:
                    tbr.append(mac_key)
            for mac_entry in tbr:  # remove these mac entries from the ingress table
                self._ingress_tbl.pop(mac_entry, None)

        if port_no in self._uncategorized_ports:
            self._uncategorized_ports.remove(port_no)

    def update_port_data(self, tnl_data, ports=None) -> list:
        updated = []
        if ports:
            self.update_bridge_ports(ports)
        # with self._lock:
        if not tnl_data or not "seq" in tnl_data:
            return
        if tnl_data["seq"] >= self._topo_seq:
            uncat = self._uncategorized_ports
            self._uncategorized_ports = set()
            for port_no in uncat:
                port = self._port_tbl[port_no]
                if port.name in tnl_data["snapshot"]:
                    self._categorize_port(
                        port, "ND_TYPE_PEER", tnl_data["snapshot"][port.name])
                    self._link_prts.add(port.port_no)
                    updated.append(port)
                elif port.port_no in KNOWN_LEAF_PORTS:
                    self._categorize_port(port, "ND_TYPE_LEAF")
                    self._leaf_prts.add(port.port_no)
                    updated.append(port)
                else:
                    self._uncategorized_ports.add(port_no)
            self._topo_seq = tnl_data["seq"]
            if (self._uncategorized_ports):
                self.logger.info("No data was available to categorize the "
                                 f"following ports {self._uncategorized_ports}")
        else:
            self.logger.info(
                f"The evio tunnel data for {self.name} "
                f"has not yet been updated beyond seq {self._topo_seq}")
        return updated

    def _learn(self, src_mac, in_port, rnid=None):
        """
        Associate the mac with the ingress port. If the RNID is provided it indicates the peer 
        switch that hosts the leaf mac.
        """
        self._ingress_tbl[src_mac] = in_port
        if rnid:
            pd = self._register_peer(peer_id=rnid, leaf_macs=[src_mac, ])
            self._root_sw_tbl[src_mac] = pd
            self.logger.debug(
                f"learn sw:{self.name}, leaf_mac:{src_mac}, ingress:{in_port}, peerid:{rnid}")
        elif in_port in self._leaf_prts:
            self._leaf_macs.add(src_mac)
            self.logger.debug(
                f"learn sw:{self.name}, leaf_mac:{src_mac}, ingress:{in_port}")
        # else:
        #     self.logger.debug("Unicast on link ingress, no leaf tracking attemped")

    @property
    def local_leaf_macs(self):
        return self._leaf_macs

    def leaf_macs(self, node_id):
        if node_id is None:
            return None
        return self._peer_tbl[node_id].leaf_macs

    def clear_leaf_macs(self, node_id):
        if node_id is None:
            self._leaf_macs.clear()
        else:
            self._peer_tbl[node_id].leaf_macs.clear()

    def add_leaf_mac(self, node_id, leaf_mac):
        if node_id is None:
            self._leaf_macs.add(leaf_mac)
        else:
            self._peer_tbl[node_id].leaf_macs.add(leaf_mac)

    def port_no(self, node_id):
        for prtno in self._link_prts:
            if self._port_tbl[prtno].peer_data.node_id == node_id:
                return prtno
        return None

    # def process_ond_tnl_updates(self, flow_metrics):
    #     #with self._lock:
    #     return self.traffic_analyzer.get_ond_tnl_ops(flow_metrics, self)

    @property
    def ond_tnl_ops(self):
        # with self._lock:
        tnl_ops = self._ond_ops
        self._ond_ops = []
        return tnl_ops

    def terminate(self):
        self._overlay_id = ""
        self._node_id = ""
        self.logger = None
        self._leaf_prts.clear()
        self._link_prts.clear()
        self._leaf_macs.clear()
        self._ingress_tbl.clear()
        self._port_tbl.clear()
        self._root_sw_tbl.clear()
        self._peer_tbl.clear()
        self.evio_portal = None
        self.counters = None

    @property
    def max_hops(self):
        # with self._lock:
        return self._max_hops

    @max_hops.setter
    def max_hops(self, num_hops):
        # with self._lock:
        if num_hops == 0:
            self._max_hops = 0
        elif (num_hops > self._max_hops):
            self._max_hops = num_hops

    def get_flooding_bounds(self, frb_type, prev_frb=None, exclude_ports=None) -> list:
        """
        FloodingBounds is used to dtermine which of its adjacent peers should be sent a frb to complete
        a system wide broadcast and bound should be used in the frb sent to said peer. FloodingBounds
        are typically calculated to flow clockwise to greater peer IDs and bounds and accommodates
        the wrap around of the ring. However, for the initial frb broadcast lesser peer IDs are used.
        This gives the local node the opportunity to discover the direct path associated with lesser
        peer IDs.        
        Creates a list of tuples in the format (egress, frb) which indicates the output port
        number that the frb should be sent.
        prev_frb - indicates that there is no incoming frb to be used to derive the next set
        of outgoing frb's; this is the case when the node is generating the initial one.
        exluded_ports - list the port numbers that should not be used for output; this is tyically
        the ingress of the prev_frb.
        """
        if not exclude_ports:
            exclude_ports = []
        out_bounds = []
        node_list = self.peer_list
        my_nid = self.node_id
        node_list.append(my_nid)
        node_list.sort()
        myi = node_list.index(my_nid)
        num_nodes = len(node_list)
        for i, peer1 in enumerate(node_list):
            # Preconditions:
            #  peer1 < peer2
            #  self < peer1 < peer2 || peer1 < peer2 <= self
            if i == myi:
                continue
            p2i = (i + 1) % num_nodes
            peer2 = node_list[p2i]
            if not (my_nid < peer1 or peer2 <= my_nid):
                self.logger.warning("Invalid node_id ordering self={0}, peer1={1}, peer2={2}"
                                    .format(my_nid, peer1, peer2))
                return out_bounds
            # base scenario when the local node is initiating the FRB
            hops = 1
            root_nid = my_nid
            bound_nid = my_nid
            if not prev_frb:
                bound_nid = peer2
                frb_hdr = FloodRouteBound(root_nid, bound_nid, hops, frb_type)
                if frb_hdr:
                    prtno = self.port_no(peer1)
                    if prtno and prtno not in exclude_ports:
                        out_bounds.append((prtno, frb_hdr))
            else:
                if prev_frb.bound_nid == my_nid:
                    self.logger.warning("This frb should not have reached this node my_nid={0} prev_frb={1}"
                                        .format(my_nid, prev_frb))
                    return out_bounds
                hops = prev_frb.hop_count + 1
                root_nid = prev_frb.root_nid
                if peer1 < my_nid:  # peer1 is a predecessor
                    if prev_frb.bound_nid > peer1 and prev_frb.bound_nid < my_nid:  # bcast to peer1
                        if peer2 < prev_frb.bound_nid:
                            bound_nid = peer2
                        else:
                            bound_nid = prev_frb.bound_nid
                    else:
                        continue
                else:  # peer1 is a successor
                    if prev_frb.bound_nid < my_nid:  # bcast to peer1
                        if peer2 < my_nid and peer2 > prev_frb.bound_nid:
                            bound_nid = prev_frb.bound_nid
                        elif (peer2 < my_nid and peer2 <= prev_frb.bound_nid) or \
                                peer2 > my_nid:
                            bound_nid = peer2
                    else:  # prev_frb.bound_nid > my_nid
                        if prev_frb.bound_nid <= peer1:
                            continue
                        if peer2 < my_nid or prev_frb.bound_nid < peer2:
                            bound_nid = prev_frb.bound_nid
                        else:
                            bound_nid = peer2
                frb_hdr = FloodRouteBound(root_nid, bound_nid, hops, frb_type)
                if frb_hdr:
                    prtno = self.port_no(peer1)
                    if prtno and prtno not in exclude_ports:
                        out_bounds.append((prtno, frb_hdr))
        return out_bounds

###################################################################################################


class LearningTable(MutableMapping):
    _REFLECT = set(
        ["_node_id", "_switch_tbl"])

    def __init__(self,  **kwargs) -> None:
        self._node_id = kwargs["NodeId"]
        self.logger = kwargs["Logger"]
        self._switch_tbl = dict()

    def __getitem__(self, dpid):
        return self._switch_tbl[dpid]

    def __delitem__(self, dpid):
        del self._switch_tbl[dpid]

    def __setitem__(self, dpid, evio_sw):
        self._switch_tbl[dpid] = evio_sw

    def __iter__(self):
        return iter(self._switch_tbl)

    def __len__(self):
        return len(self._switch_tbl)

    def __repr__(self):
        items = set()
        for k in LearningTable._REFLECT:
            items.add(f"\"{k}\": {self.__dict__[k]!r}")
        return "{{{}}}".format(", ".join(items))

    def register_datapath(self, datapath_id, evio_switch):
        self._switch_tbl[datapath_id] = evio_switch

    def deregister_datapath(self, datapath_id):
        self._switch_tbl.pop(datapath_id)

###################################################################################################


class BoundedFlood(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
    }
    OFCTL = spawn.find_executable("ovs-ofctl")
    if OFCTL is None:
        raise RuntimeError("Open vSwitch was not found, is it installed?")

    def __init__(self, *args, **kwargs):
        super(BoundedFlood, self).__init__(*args, **kwargs)
        ethernet.ethernet.register_packet_type(
            FloodRouteBound, FloodRouteBound.ETH_TYPE_BF)
        self._is_exit = False
        self._load_config()
        self._traffic_analysis_interval = self.config.get(
            "TrafficAnalysisInterval", TrafficAnalysisInterval)
        self._state_logging_interval = self.config.get(
            "StateLoggingInterval", StateLoggingInterval)
        self._link_check_interval = self.config.get(
            "LinkCheckInterval", LinkCheckInterval)
        self._setup_logger()
        self.evio_portal = EvioPortal(
            (self.config.get("ProxyListenAddress", ProxyListenAddress),
             self.config.get("ProxyListenPort", ProxyListenPort)), self.logger)
        self.dpset = kwargs['dpset']
        self._lt = LearningTable(NodeId=self.config["NodeId"],
                                 Logger=self.logger)
        self._ev_bh_update = Queue.Queue()
        hub.spawn(self.monitor_flow_traffic)
        hub.spawn(self.update_tunnels)
        hub.spawn(self.check_links)
        if self.config.get("StateTracingEnabled", StateTracingEnabled):
            hub.spawn(self.log_state)
        self.logger.info("BoundedFlood: Module loaded")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        try:
            while INTERNAL_PORT_NUM not in datapath.ports:
                hub.sleep(1)
            br_name = datapath.ports[INTERNAL_PORT_NUM].name.decode("utf-8")
            if datapath.id in self._lt:
                self.logger.warning(f"Datapath {datapath.id} is already in learning table, "
                                    "reinitializing")
                self._lt.pop(datapath.id)
            if br_name not in self.config:
                self.logger.warning(f"Bridge {br_name} is not specified in the BoundedFlood config, "
                                    f"skipping bridge registration. Config={self.config}")
                return

            overlay_id = self.config[br_name]["OverlayId"]
            self._lt[datapath.id] = EvioSwitch(datapath,
                                               OverlayId=overlay_id,
                                               NodeId=self.config["NodeId"],
                                               Logger=self.logger,
                                               MaxOnDemandEdges=self.config[br_name].get(
                                                   "MaxOnDemandEdges", FlowHardTimeout),
                                               DemandThreshold=self.config[br_name].get(
                                                   "DemandThreshold", DemandThreshold),
                                               FlowIdleTimeout=self.config[br_name].get(
                                                   "FlowIdleTimeout", FlowIdleTimeout),
                                               FlowHardTimeout=self.config[br_name].get("FlowHardTimeout", FlowHardTimeout))

            self.logger.info(
                f"Switch {br_name} added with overlay ID {overlay_id}")
            self._lt[datapath.id].update_bridge_ports(datapath.ports)
            self._reset_switch_flow_rules(datapath)
            self._ev_bh_update.put(
                EvioOp(Opcode.UPDATE_TUNNELS, datapath.id, overlay_id))
        except RuntimeError as wrn:
            self.logger.exception(
                f"An runtime error occurred while registering a switch {ev.msg}")
            if datapath.id in self._lt:
                self._lt.pop(datapath.id, None)
        except Exception as err:
            self.logger.exception("A failure occurred while registering a switch. "
                                  f"Event={ev.msg}")
            if datapath.id in self._lt:
                self._lt.pop(datapath.id, None)

    @set_ev_cls(event.EventSwitchLeave, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def handler_switch_leave(self, ev):
        try:
            dpid = ev.switch.dp.id
            if dpid in self._lt:
                br_name = self._lt[dpid].name
                self._lt[dpid].terminate()
                self._lt.pop(dpid, None)
            self.logger.info("Removed switch: %s", br_name)
        except Exception as err:
            self.logger.exception("An error occurred while attempting to remove switch "
                                  f"{ev.switch.dp.id}.")

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        port_no = msg.desc.port_no
        try:
            if msg.reason == ofp.OFPPR_ADD:
                self.logger.debug(
                    "OFPPortStatus: port ADDED desc=%s", msg.desc)
                self._lt[dp.id].add_port(msg.desc)
                self._ev_bh_update.put(
                    EvioOp(Opcode.UPDATE_TUNNELS, dp.id, self._lt[dp.id].overlay_id))
            elif msg.reason == ofp.OFPPR_DELETE:
                self.logger.debug(
                    "OFPPortStatus: port DELETED desc=%s", msg.desc)
                self._del_port_flow_rules(dp, port_no, tblid=0)
                self._lt[dp.id].delete_port(port_no)
            # elif msg.reason == ofp.OFPPR_MODIFY:
            #     self.logger.debug(
            #         "OFPPortStatus: port MODIFIED desc=%s", msg.desc)

        except Exception as err:
            self.logger.exception(f"An error occurred while responding to a port event. "
                                  f"Event={ev.msg}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.protocols[0]
        dpid = msg.datapath.id
        port: PortDescriptor = self._lt[dpid].port_descriptor(in_port)
        try:
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug(f"packet_in[{in_port}]<=={pkt}")

            if not self._lt[dpid].is_valid_port(in_port):
                if self.logger.isEnabledFor(logging.DEBUG):
                    self.logger.warning(
                        f"On removed port:{self._lt[dpid].name}/{in_port} bufferd frame: {pkt}")
                return
            if not port.is_categorized:
                self.logger.debug(f"Port {in_port} is not yet ready")
                return
            port.last_active_time = time.time()
            if eth.ethertype == FloodRouteBound.ETH_TYPE_BF:
                self.handle_bounded_flood_msg(msg.datapath, pkt, in_port, msg)
            elif eth.dst in self._lt[dpid]:
                ''' Vanilla Ethernet frame and forwarding data is available for its destination MAC'''
                self._forward_frame(msg.datapath, pkt, in_port, msg)
            else:
                ''' Vanilla Ethernet frame but the destination MAC is not in our LT. Currently, only broadcast
                    addresses originating from local leaf ports are broadcasted using FRB. Multiricepient frames
                    that ingress on a link port is protocol logic error, and flooding unicast frames which have
                    no LT info, prevents accumulating enough port data to ever create a flow rule'''
                if in_port in self._lt[dpid].leaf_ports and is_multiricepient(eth.dst):
                    self._broadcast_frame(msg.datapath, pkt, in_port, msg)
                else:
                    self.logger.debug(
                        f"No forwarding route to {eth.dst} in LT, discarding frame. "
                        f" ingress={self._lt[dpid].name}/{in_port}")
                return
        except Exception as err:
            self.logger.exception(f"An error occurred in the controller's packet handler. "
                                  f"Event={ev.msg}")

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        # self.logger.info('%s', json.dumps(ev.msg.to_jsondict()))
        try:
            dpid = ev.msg.datapath.id
            evi_sw = self._lt[dpid]
            ond_ops = evi_sw.traffic_analyzer.get_ond_tnl_ops(
                flow_metrics=ev.msg.body, evio_sw=evi_sw)
            if ond_ops:
                self._ev_bh_update.put(
                    EvioOp(Opcode.OND_REQUEST, dpid, evi_sw.overlay_id, ond_ops))
        except Exception as err:
            self.logger.exception(
                f"An error occurred in the flow stats handler. Event={ev.msg}")

    ##################################################################################
    ##################################################################################

    def monitor_flow_traffic(self):
        while not self._is_exit:
            try:
                while not self._is_exit:
                    for dpid in self._lt:
                        self._request_stats(self.dpset.dps[dpid])
                    hub.sleep(self._traffic_analysis_interval)
            except Exception:
                self.logger.exception(
                    "An exception occurred within the traffic monitor")
                hub.sleep(self._traffic_analysis_interval)

    def update_tunnels(self):
        while not self._is_exit:
            try:
                while not self._is_exit:
                    tnl_data = {}
                    op = self._ev_bh_update.get()
                    if op.code == Opcode.UPDATE_TUNNELS:
                        tnl_data = self._query_evio_tunnel_data(op.olid)
                        if op.olid in tnl_data:
                            updated_prts = \
                                self._lt[op.dpid].update_port_data(
                                    tnl_data[op.olid])
                            for port in updated_prts:
                                if port.is_peer:
                                    if port.is_tincan_tunnel:
                                        self._update_port_flow_rules(self.dpset.dps[op.dpid],
                                                                     port.peer.node_id,
                                                                     port.port_no)
                                    elif port.dp_type in (DataplaneTypes.Geneve, DataplaneTypes.WireGuard):
                                        self.do_link_check(
                                            self.dpset.dps[op.dpid], port)
                    elif op.code == Opcode.OND_REQUEST:
                        self._request_ond_tnl_ops(op.olid, op.data)
                    self._ev_bh_update.task_done()
            except Exception:
                self.logger.exception(
                    "An exception occurred while updating the tunnel data")

    def log_state(self):
        while not self._is_exit:
            try:
                while not self._is_exit:
                    counter_vals = {}
                    for dpid in self._lt:
                        self._collect_counters(dpid, counter_vals)
                    self._log_state()
                    self._log_counters(counter_vals)
                    hub.sleep(self._state_logging_interval)
            except Exception:
                self.logger.exception(
                    "An exception occurred within log state")
                hub.sleep(self._state_logging_interval)

    def check_links(self):
        """
        A link check is performed every LNK_CHK_INTERVAL. Receiving a LNK_CHK or
        LNK_ACK satifies the LNK_ACTIVE condition and resets the check interval
        """
        while not self._is_exit:
            try:
                while not self._is_exit:
                    for dpid, sw in self._lt.items():
                        tunnel_ops = []
                        for port_no in sw.port_numbers:
                            port = sw.port_descriptor(port_no)
                            if (port.is_geneve_tunnel or port.is_wireguard_tunnel):
                                now = time.time()
                                if now >= port.last_active_time + 3 * self._link_check_interval:
                                    # send req to remove tunnel to peer
                                    self.logger.debug(
                                        f"Requesting removal of inactive port {port}")
                                    tunnel_ops.append(
                                        (port.peer.node_id, "DISCONN"))
                                    sw.delete_port(port_no)
                                elif now >= port.last_active_time + self._link_check_interval:
                                    self.do_link_check(
                                        self.dpset.dps[dpid], port)
                        if tunnel_ops:
                            self._ev_bh_update.put(
                                EvioOp(Opcode.OND_REQUEST, dpid, sw.overlay_id, tunnel_ops))
                    hub.sleep(self._link_check_interval)
            except Exception:
                self.logger.exception(
                    "An exception occurred within check links")
                hub.sleep(self._link_check_interval)
    ##################################################################################
    ##################################################################################

    def _setup_logger(self):
        fqname = os.path.join(
            self.config.get("LogDir", LogDir), self.config.get("LogFilename", LogFilename))
        if os.path.isfile(fqname):
            os.remove(fqname)
        self.logger = logging.getLogger(self.name)
        level = getattr(logging, self.config.get("LogLevel", LogLevel))
        self.logger.setLevel(level)
        handler = lh.RotatingFileHandler(filename=fqname, maxBytes=self.config.get("MaxBytes", MaxBytes),
                                         backupCount=self.config.get("BackupCount", BackupCount))
        formatter = logging.Formatter(
            "[%(asctime)s.%(msecs)03d] %(levelname)s:%(message)s", datefmt="%Y%m%d %H:%M:%S")
        logging.Formatter.converter = time.localtime
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def _load_config(self):
        if CONF["bf"]["config_file"]:
            if not os.path.isfile(CONF["bf"]["config_file"]):
                raise RuntimeError("The specified configuration file was not found: {}"
                                   .format(CONF["bf"]["config_file"]))
            with open(CONF["bf"]["config_file"]) as f:
                self.config = json.load(f)
        elif CONF["bf"]["config_string"]:
            self.config = json.loads(CONF["bf"]["config_string"])
        else:
            raise RuntimeError("No valid configuration found")

    def _query_evio_tunnel_data(self, overlay_id=None):
        req = dict(Request=dict(Action="GetTunnelData",
                   Params=dict()))
        resp = self.evio_portal.send_recv(req)
        if not resp["Response"]["Status"]:
            self.logger.warning("Failed to update tunnel data")
            return {}
        # self._is_update_tunnel_data = False
        tnl_data = resp["Response"]["Data"]
        return resp["Response"]["Data"]

    def _request_ond_tnl_ops(self, overlay_id, ond_tnl_ops):
        reqs = []
        for ond_op in ond_tnl_ops:
            reqs.append({"OverlayId": overlay_id,
                        "PeerId": ond_op[0], "Operation": ond_op[1]})
        req = {"Request": {"Action": "TunnelRquest", "Params": reqs}}
        self.evio_portal.send_recv(req)

    def _log_state(self):
        global BF_STATE_DIGEST
        state = repr(self._lt)
        new_digest = hashlib.sha256(state.encode("utf-8")).hexdigest()
        if BF_STATE_DIGEST != new_digest:
            BF_STATE_DIGEST = new_digest
            self.logger.info(f"{{\"BF State\": {state}}}\n")

    def _collect_counters(self, dpid, counter_vals: dict):
        total_hops = 0
        num_nodes = len(self._lt[dpid]._peer_tbl) + 1
        pd: PeerData
        for pd in self._lt[dpid]._peer_tbl.values():
            total_hops += pd.hop_count
            self._lt[dpid].max_hops = pd.hop_count
        counter_vals[self._lt[dpid].name] = {"MaxHops": self._lt[dpid].max_hops,
                                             "TotalHops": total_hops,
                                             "NumNodes": num_nodes,
                                             "AvgHops": total_hops/num_nodes}

    def _log_counters(self, counter_vals: dict):
        global BF_COUNTER_DIGEST
        counter_s = str(counter_vals)
        new_digest = hashlib.sha256(counter_s.encode("utf-8")).hexdigest()
        if BF_COUNTER_DIGEST != new_digest:
            BF_COUNTER_DIGEST = new_digest
            self._last_count_time = time.time()
            self.logger.info(f"Counters: {counter_vals}")
        counter_vals.clear()

    def _request_stats(self, datapath, tblid=0):
        if not (self._lt[datapath.id].is_ond_enabled and bool(self._lt[datapath.id]._peer_tbl)):
            return
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath, table_id=tblid)
        resp = datapath.send_msg(req)
        if not resp:
            self.logger.warning(
                "Request stats operation failed, OFPFlowStatsRequest=%s", req)

    def _create_flow_rule(self, datapath, match, actions, priority=0, tblid=0, idle=0, hard_timeout=0):
        mod = None
        try:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            inst = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self.logger.debug(f"Adding flow rule {datapath.id}: {match}")
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, table_id=tblid,
                                    idle_timeout=idle, hard_timeout=hard_timeout, match=match, instructions=inst)
            resp = datapath.send_msg(mod)
            if not resp:
                self.logger.warning(
                    "Add flow operation failed, OFPFlowMod=%s", mod)
        except struct.error as err:
            self.logger.exception(
                f"Add flow operation failed, OFPFlowMod={mod}\n struct.")

    def _create_flow_rule_drop_multicast(self, datapath, priority=1, tblid=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            eth_dst=("33:33:00:00:00:00", "ff:ff:00:00:00:00"))
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                command=ofproto.OFPFC_ADD, instructions=inst, table_id=tblid)
        resp = datapath.send_msg(mod)
        if not resp:
            self.logger.warning(
                "Add flow (MC) operation failed, OFPFlowMod=%s", mod)
        match = parser.OFPMatch(
            eth_dst=("01:00:5e:00:00:00", "ff:ff:ff:ff:ff:00"))
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                command=ofproto.OFPFC_ADD, instructions=inst, table_id=tblid)
        resp = datapath.send_msg(mod)
        if not resp:
            self.logger.warning(
                "Add flow (MC) operation failed, OFPFlowMod=%s", mod)

    def _update_port_flow_rules(self, datapath, peer_id, in_port):
        '''Used when a new port is connected to the switch and we know the pendant MACs that anchored
           to the now adjacent peer switch. Flow rules involving those pendant MACs are updated or
           created to use the new port.'''
        dpid = datapath.id
        parser = datapath.ofproto_parser
        for mac in self._lt[dpid].leaf_macs(peer_id):
            self._update_inbound_flow_rules(datapath, mac, in_port, tblid=0)
            # create new outbound flow rule, old ones will expire
            for dst_mac in self._lt[dpid].local_leaf_macs:
                port_no = self._lt[dpid].get(dst_mac)
                if port_no:
                    actions = [parser.OFPActionOutput(port_no)]
                    match = parser.OFPMatch(
                        in_port=in_port, eth_dst=dst_mac, eth_src=mac)
                    self._create_flow_rule(datapath, match, actions, priority=1, tblid=0,
                                           idle=self._lt[dpid].idle_timeout)

    def _del_port_flow_rules(self, datapath, port_no, tblid=None):
        '''Used when a port is removed from the switch. Any flow rule with in_port or
           out_port that matches port_no is removed'''
        try:
            sw_name = self._lt[datapath.id].name
            ofproto = datapath.ofproto
            if tblid is None:
                tblid = ofproto.OFPTT_ALL
            parser = datapath.ofproto_parser
            cmd = ofproto.OFPFC_DELETE
            match = parser.OFPMatch()
            mod = parser.OFPFlowMod(datapath=datapath, table_id=tblid, match=match, command=cmd,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM, out_port=port_no,
                                    out_group=ofproto.OFPG_ANY, priority=1, idle_timeout=0,
                                    cookie=0, cookie_mask=0)
            datapath.send_msg(mod)
            match = parser.OFPMatch(in_port=port_no)
            mod = parser.OFPFlowMod(datapath=datapath, table_id=tblid, match=match, command=cmd,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM, out_port=ofproto.OFPP_ANY,
                                    out_group=ofproto.OFPG_ANY, priority=1, idle_timeout=0,
                                    cookie=0, cookie_mask=0)
            self.logger.debug(
                "Attempting to delete flow rules on port=%s/%s", sw_name, port_no)
            datapath.send_msg(mod)
            if self._is_flow_rule_exist(sw_name, port_no):
                self._reset_switch_flow_rules(datapath)
        except Exception as err:
            self.logger.exception(
                f"Failed to delete flows for port {sw_name}/{port_no}")

    def _del_port_flow_rules_ovs(self, datapath, port_no, tblid=None):
        '''Alternate approach to _del_flow_rules_for_port, uses ovs-ofctl cmd '''
        try:
            sw_name = self._lt[datapath.id].name
            self.logger.debug(
                "Attempting to delete flow rules on port=%s/%s", sw_name, port_no)
            runcmd([BoundedFlood.OFCTL, "del-flows", sw_name,
                    "out_port={0}".format(port_no)])
            runcmd([BoundedFlood.OFCTL, "del-flows", sw_name,
                    "in_port={0}".format(port_no)])
            if self._is_flow_rule_exist(sw_name, port_no):
                self._reset_switch_flow_rules(datapath)
        except Exception as err:
            self.logger.exception(
                f"Failed to delete flows for port {sw_name}/{port_no}")

    def _is_flow_rule_exist(self, switch, port_no):
        '''Uses ovs-ofctl to check if an outbound flow rule exists for this port_no'''
        chk = runcmd([BoundedFlood.OFCTL, "dump-flows", switch,
                      "out_port={0}".format(port_no)])
        chk.check_returncode()
        lines = chk.stdout.splitlines()
        if (len(lines) > 1):
            self.logger.debug("Flow rules for %s/%s: %s",
                              switch, port_no, chk.stdout)
            return True
        return False

    def _clear_switch_flow_rules(self, datapath):
        '''Due to intermittent failure of deleting flow rules on OVS clear all flow
           rules from sw'''
        self.logger.debug("Attempting to delete ALL flow rules for switch=%s",
                          self._lt[datapath.id].name)
        #runcmd([BoundedFlood.OFCTL, "del-flows", self._lt[datapath.id].name])
        ofproto = datapath.ofproto
        tblid = ofproto.OFPTT_ALL
        parser = datapath.ofproto_parser
        cmd = ofproto.OFPFC_DELETE
        match = parser.OFPMatch()
        mod = parser.OFPFlowMod(datapath=datapath, table_id=tblid, match=match, command=cmd,
                                flags=ofproto.OFPFF_SEND_FLOW_REM, out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY, priority=1, idle_timeout=0,
                                cookie=0, cookie_mask=0)
        datapath.send_msg(mod)

    def _create_switch_startup_flow_rules(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._create_flow_rule(datapath, match, actions)
        # deliver bounded flood frames to controller
        match = parser.OFPMatch(eth_type=FloodRouteBound.ETH_TYPE_BF)
        self._create_flow_rule(datapath, match, actions, priority=100)
        # drop multicast frames
        self._create_flow_rule_drop_multicast(datapath)

    def _reset_switch_flow_rules(self, datapath):
        '''Resets the switch flow rules by deleting all flow ruls and recreating the base
           rules to deliver unhandled frames to the controller'''
        self._clear_switch_flow_rules(datapath)
        self._create_switch_startup_flow_rules(datapath)

    def _update_inbound_flow_rules(self, datapath, dst_mac, new_egress, tblid=None):
        parser = datapath.ofproto_parser
        if tblid is None:
            tblid = datapath.ofproto.OFPTT_ALL
        cmd = datapath.ofproto.OFPFC_MODIFY
        acts = [parser.OFPActionOutput(new_egress, 1500)]
        inst = [parser.OFPInstructionActions(
            datapath.ofproto.OFPIT_APPLY_ACTIONS, acts)]
        mt = parser.OFPMatch(eth_dst=dst_mac)
        mod = parser.OFPFlowMod(datapath=datapath, table_id=tblid, match=mt, command=cmd,
                                instructions=inst, idle_timeout=self._lt[datapath.id].idle_timeout)
        self.logger.debug("Attempting to update all flows matching %s/%s",
                          self._lt[datapath.id].name, mt)
        datapath.send_msg(mod)

    def _update_leaf_macs(self, dpid, rnid, macs, num_items):
        self._lt[dpid].clear_leaf_macs(rnid)
        self._lt[dpid].peer(rnid).hop_count = 1
        mlen = num_items*6
        for mactup in struct.iter_unpack("!6s", macs[:mlen]):
            macstr = mac_lib.haddr_to_str(mactup[0])
            self.logger.debug(
                "Registering leaf mac %s/%s to peer %s", self._lt[dpid].name, macstr, rnid)
            self._lt[dpid].add_leaf_mac(rnid, macstr)

    def do_link_check(self, datapath, port):
        """
        Send a query to an adjacent peer to test transport connectivity. Peer is expected acknowlege
        sense request.        
        """
        sw: EvioSwitch = self._lt[datapath.id]
        nid = sw.node_id
        if port.is_peer:
            port_no = port.port_no
            peer_id = port.peer.node_id
            peer_mac = port.peer.hw_addr
            src_mac = port.hw_addr

            bf_hdr = FloodRouteBound(
                nid, nid, 0, FloodRouteBound.FRB_LNK_CHK)
            eth = ethernet.ethernet(dst=peer_mac, src=src_mac,
                                    ethertype=FloodRouteBound.ETH_TYPE_BF)
            p = packet.Packet()
            p.add_protocol(eth)
            p.add_protocol(bf_hdr)
            p.serialize()
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            acts = [parser.OFPActionOutput(port_no)]
            pkt_out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                          actions=acts, data=p.data, in_port=ofproto.OFPP_LOCAL)
            resp = datapath.send_msg(pkt_out)
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug("Sending link check %s/%s %s", self._lt[datapath.id].name, port_no, peer_id)
            if not resp:
                self.logger.warning(
                    "Failed to send link chk FRB, OFPPacketOut=%s", pkt_out)
        else:
            self.logger.info("Link CHK attempted but remote is not a peer")

    def _do_link_ack(self, datapath, port):

        sw: EvioSwitch = self._lt[datapath.id]
        nid = sw.node_id
        if port.is_peer:
            port_no = port.port_no
            peer_id = port.peer.node_id
            peer_mac = port.peer.hw_addr
            src_mac = port.hw_addr

            bf_hdr = FloodRouteBound(
                nid, nid, 0, FloodRouteBound.FRB_LNK_ACK)
            eth = ethernet.ethernet(dst=peer_mac, src=src_mac,
                                    ethertype=FloodRouteBound.ETH_TYPE_BF)
            p = packet.Packet()
            p.add_protocol(eth)
            p.add_protocol(bf_hdr)
            p.serialize()
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            acts = [parser.OFPActionOutput(port_no)]
            pkt_out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                          actions=acts, data=p.data, in_port=ofproto.OFPP_LOCAL)
            resp = datapath.send_msg(pkt_out)
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug("Sending link ack, %s/%s %s",
                                  self._lt[datapath.id].name, port_no, peer_id)
            if not resp:
                self.logger.warning(
                    "Failed to send link ack FRB, OFPPacketOut=%s", pkt_out)
        else:
            self.logger.info("Link ACK attempted but remote is not a peer")

    ###############################################################################################
    def do_bounded_flood(self, datapath, ingress, tx_bounds, src_mac, payload):
        """
        datapath is the local switch datapath object.
        ingress is the recv port number of the brdcast
        tx_bounds is a list of tuples, each describing the outgoing port number and the
        corresponding FRB associated with the transmission of 'payload' on that port.
        (out_port, frb)

        This method uses the custom EtherType 0xc0c0, an assumes it will not be used on the network
        for any other purpose.
        The source MAC is set to the original frame src mac for convenience.
        """
        eth = ethernet.ethernet(dst='ff:ff:ff:ff:ff:ff', src=src_mac,
                                ethertype=FloodRouteBound.ETH_TYPE_BF)
        for out_port, bf in tx_bounds:
            p = packet.Packet()
            p.add_protocol(eth)
            p.add_protocol(bf)
            p.add_protocol(payload)
            p.serialize()
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            actions = [parser.OFPActionOutput(out_port)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=ingress, actions=actions, data=p.data)
            resp = datapath.send_msg(out)
            if not resp:
                self.logger.warning(
                    "Send FRB operation failed, OFPPacketOut=%s", out)

    def do_bf_leaf_transfer(self, datapath, ports):
        sw: EvioSwitch = self._lt[datapath.id]
        nid = sw.node_id
        payload = bytearray(6*len(sw.local_leaf_macs))
        offset = 0
        for leaf_mac in sw.local_leaf_macs:
            bmac = mac_lib.haddr_to_bin(leaf_mac)
            struct.pack_into("!6s", payload, offset, bmac)
            offset += 6
        for port in ports:
            if not port.is_peer:
                continue
            port_no = port.port_no
            peer_id = port.peer.node_id
            peer_mac = port.peer.hw_addr
            src_mac = port.hw_addr

            bf_hdr = FloodRouteBound(
                nid, nid, 0, FloodRouteBound.FRB_LEAF_TX, offset//6)
            eth = ethernet.ethernet(dst=peer_mac, src=src_mac,
                                    ethertype=FloodRouteBound.ETH_TYPE_BF)
            p = packet.Packet()
            p.add_protocol(eth)
            p.add_protocol(bf_hdr)
            p.add_protocol(payload)
            p.serialize()
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            acts = [parser.OFPActionOutput(port_no)]
            pkt_out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                          actions=acts, data=p.data, in_port=ofproto.OFPP_LOCAL)
            resp = datapath.send_msg(pkt_out)
            if resp:
                self.logger.debug("FRB local leaf transfer completed, %s/%s %s %s",
                                  self._lt[datapath.id].name, port_no, peer_id, payload)
            else:
                self.logger.warning(
                    "FRB leaf exchange failed, OFPPacketOut=%s", pkt_out)

    def handle_bounded_flood_msg(self, datapath, pkt, in_port, msg):
        eth = pkt.protocols[0]
        src = eth.src
        dpid = datapath.id
        parser = datapath.ofproto_parser
        rcvd_frb = pkt.protocols[1]
        payload = None
        port: PortDescriptor
        if len(pkt.protocols) == 3:
            payload = pkt.protocols[2]
        if self._lt._node_id == rcvd_frb.root_nid:
            self.logger.warning(f"Discarded a FRB from self {rcvd_frb}")
            return
        if rcvd_frb.frb_type not in (FloodRouteBound.FRB_BRDCST,
                                     FloodRouteBound.FRB_LNK_CHK, FloodRouteBound.FRB_LNK_ACK):
            # discard these types
            self.logger.info(f"Discarded type {rcvd_frb.frb_type} FRB")
            return
        port = self._lt[dpid].port_descriptor(in_port)
        if rcvd_frb.frb_type == FloodRouteBound.FRB_LNK_CHK:
            self._do_link_ack(datapath, port)
            if not port.is_activated:
                port.is_activated = True
                self._update_port_flow_rules(datapath,
                                             port.peer.node_id,
                                             in_port)
            return
        if rcvd_frb.frb_type == FloodRouteBound.FRB_LNK_ACK:
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug("Received link ack %s/%s %s", self._lt[dpid].name, in_port, rcvd_frb)
            if not port.is_activated:
                port.is_activated = True
                self._update_port_flow_rules(datapath,
                                             port.peer.node_id,
                                             in_port)
            return
        self._lt[dpid][src] = (in_port, rcvd_frb.root_nid)
        self._lt[dpid].peer(
            rcvd_frb.root_nid).hop_count = rcvd_frb.hop_count
        self._lt[dpid].max_hops = rcvd_frb.hop_count
        # deliver the broadcast frame to leaf devices
        if payload:
            self.logger.debug("Sending FRB payload to leaf ports=%s/%s",
                              self._lt[dpid].name, self._lt[dpid].leaf_ports)
            for out_port in self._lt[dpid].leaf_ports:
                actions = [parser.OFPActionOutput(out_port)]
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=payload)
                datapath.send_msg(out)
        # continue the bounded flood as necessary
        out_bounds = self._lt[dpid].get_flooding_bounds(
            rcvd_frb.frb_type, rcvd_frb, [in_port])
        self.logger.debug("Derived FRB(s)=%s/%s",
                          self._lt[dpid].name, out_bounds)
        if out_bounds:
            self.do_bounded_flood(
                datapath, in_port, out_bounds, src, payload)

    def _forward_frame(self, datapath, pkt, in_port, msg):
        eth = pkt.protocols[0]
        dpid = datapath.id
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        out_port = self._lt[dpid][eth.dst]
        # learn a mac address
        self._lt[dpid][eth.src] = in_port
        # create new flow rule
        actions = [parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(
            in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
        self._create_flow_rule(datapath, match, actions, priority=1, tblid=0,
                               idle=self._lt[dpid].idle_timeout)
        # forward frame to destination
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _broadcast_frame(self, datapath, pkt, in_port, msg):
        eth = pkt.protocols[0]
        dpid = datapath.id
        # learn a mac address
        self._lt[dpid][eth.src] = in_port
        frb_type = FloodRouteBound.FRB_BRDCST
        if in_port not in self._lt[dpid].leaf_ports:
            # this node did not initiate the frame but it has no data on how to switch it
            # so it must brdcast with an FRB but let peers know we  are not the root sw
            frb_type = FloodRouteBound.FRB_FWD
        # perform bounded flood
        out_bounds = self._lt[dpid].get_flooding_bounds(
            frb_type, None, [in_port])
        self.logger.debug("Generated FRB(s)=%s/%s",
                          self._lt[dpid].name, out_bounds)
        # fwd frame on every port wrapped with an FRB
        if out_bounds:
            self.do_bounded_flood(
                datapath, in_port, out_bounds, eth.src, msg.data)

###################################################################################################
###################################################################################################


class FloodRouteBound(packet_base.PacketBase):
    """
    Flooding Route and Bound is an custom ethernet layer protocol used by EdgeVPNio SDN switching to
    perform link layer broadcasts in cyclic switched fabrics.
    bound_nid is the ascii UUID representation of the upper exclusive node id bound that limits the
    extent of the retransmission.
    hop_count is the number of switching hops to the destination, the initial switch sets this
    value to zero
    root_nid is the node id of the switch that initiated the bounded flood operation
    """
    _PACK_STR = '!16s16sBBB'
    _MIN_LEN = struct.calcsize(_PACK_STR)
    ETH_TYPE_BF = 0xc0c0
    FRB_BRDCST = 0
    FRB_LEAF_TX = 1
    FRB_FWD = 2
    FRB_LNK_CHK = 3
    FRB_LNK_ACK = 4

    def __init__(self, root_nid, bound_nid, hop_count, frb_type=0, pl_count=0):
        super(FloodRouteBound, self).__init__()
        self.root_nid = root_nid
        self.bound_nid = bound_nid
        self.hop_count = hop_count
        self.frb_type = frb_type
        self.pl_count = pl_count
        assert self.hop_count < (1 << 16), "hop_count exceeds max val"
        assert self.frb_type < (1 << 16), "frb_type exceeds max val"
        assert self.pl_count < (1 << 16), "pl_count exceeds max val"

    def __repr__(self):
        return str(f"frb(root_nid={self.root_nid},bound_nid={self.bound_nid},"
                   f"frb_type={self.frb_type} hop_count={self.hop_count})")

    @classmethod
    def parser(cls, buf):
        unpk_data = struct.unpack(cls._PACK_STR, buf[:cls._MIN_LEN])
        rid = uuid.UUID(bytes=unpk_data[0])
        bid = uuid.UUID(bytes=unpk_data[1])
        hops = unpk_data[2]
        ty = unpk_data[3]
        cnt = unpk_data[4]
        return cls(rid.hex, bid.hex, hops, ty, cnt), None, buf[cls._MIN_LEN:]

    def serialize(self, payload, prev):
        rid = uuid.UUID(hex=self.root_nid).bytes
        bid = uuid.UUID(hex=self.bound_nid).bytes
        # if self.hop_count == 0:
        #     self.frb_type = FloodRouteBound.FRB_LEAF_TX
        # if self.frb_type == FloodRouteBound.FRB_LEAF_TX:
        #     self.pl_count = len(payload) // 6
        return struct.pack(FloodRouteBound._PACK_STR, rid, bid, self.hop_count, self.frb_type,
                           self.pl_count)

###################################################################################################
###################################################################################################


class TrafficAnalyzer():
    """ A very simple traffic analyzer to trigger an on demand tunnel """
    _DEMAND_THRESHOLD = 1 << 20  # 1MB

    def __init__(self, logger, demand_threshold=None, max_ond_tuns=1):
        self._max_ond = max_ond_tuns
        val = TrafficAnalyzer._DEMAND_THRESHOLD
        if demand_threshold:
            if demand_threshold[-1] == "K":
                val = int(demand_threshold[:-1]) * 1 << 10
            if demand_threshold[-1] == "M":
                val = int(demand_threshold[:-1]) * 1 << 20
            if demand_threshold[-1] == "G":
                val = int(demand_threshold[:-1]) * 1 << 30
            self.demand_threshold = val
        self._ond = dict()
        self.logger = logger
        self._min_tnl_age = 180
        logger.info("Demand threshold set at %d bytes", self.demand_threshold)

    def get_ond_tnl_ops(self, flow_metrics, evio_sw: EvioSwitch) -> List:
        tunnel_reqs = []
        active_flows = set()
        for stat in flow_metrics:
            if "eth_src" not in stat.match or "eth_dst" not in stat.match:
                continue
            src_mac = stat.match["eth_src"]
            dst_mac = stat.match["eth_dst"]
            peer_sw: PeerData
            peer_sw = evio_sw.get_root_sw(src_mac)
            if not peer_sw:
                continue
            active_flows.add(peer_sw.node_id)
            if dst_mac not in evio_sw.local_leaf_macs:
                # only the leaf's managing sw should create an OND tunnel
                # so prevent every switch along path from req an OND to the initiator
                continue
            if peer_sw.port_no is not None:
                # already a direct tunnel to this switch
                continue
            if peer_sw.node_id not in self._ond and len(self._ond) < self._max_ond and \
                    stat.byte_count > self.demand_threshold:
                self.logger.debug(
                    "Creating a request for OND edge to %s", peer_sw.node_id)
                tunnel_reqs.append((peer_sw.node_id, "ADD"))
                self._ond[peer_sw.node_id] = time.time()
                active_flows.add(peer_sw.node_id)
        # if the flow has expired request the on demand tunnel be removed
        remove_list = []
        for rnid in self._ond:
            if (time.time() - self._ond[rnid]) < self._min_tnl_age:
                continue
            if rnid not in active_flows:
                self.logger.debug(
                    "Creating requesting for removal of OND edge to %s", rnid)
                tunnel_reqs.append((rnid, "REMOVE"))
                remove_list.append(rnid)
        for rnid in remove_list:
            del self._ond[rnid]
        return tunnel_reqs


###################################################################################################
###################################################################################################
DVMRP_TYPE = 0x13
DVMRP_CODE_GRAFT = 0x8


class DVMRP(packet_base.PacketBase):
    """
    __init__ takes the corresponding args in this order.

    =============== ====================================================
    Attribute       Description
    =============== ====================================================
    msgtype         Identifies the packet as DVMRP.
    code            Identifies type of DVMRP message - Graft, Graft_Ack etc
    csum            a check sum value. 0 means automatically-calculate
                    when encoding.
    src_address     src_address of the initiator of multicast transmission.
    grp_address     grp address for multicast transmission
    =============== ====================================================
    """
    _PACK_STR = '!BBH4s4s'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(self, msgtype=DVMRP_TYPE, code=DVMRP_CODE_GRAFT, csum=0,
                 src_address='0.0.0.0', grp_address='224.0.0.1'):
        super(DVMRP, self).__init__()
        self.msgtype = msgtype
        self.code = code
        self.csum = csum
        self.src_address = src_address
        self.grp_address = grp_address

    @classmethod
    def parser(cls, buf):
        assert cls._MIN_LEN <= len(buf)
        subclass = None
        instance = None
        rest = None
        (msgtype, ) = struct.unpack_from('!B', buf)
        if msgtype == DVMRP_TYPE:
            (msgtype, code, csum, src_address,
             grp_address) = struct.unpack_from(cls._PACK_STR, buf)
            instance = cls(msgtype, code, csum,
                           addrconv.ipv4.bin_to_text(src_address),
                           addrconv.ipv4.bin_to_text(grp_address),
                           )

            rest = buf[cls._MIN_LEN:]
        return instance, subclass, rest

    def serialize(self, payload, prev):
        hdr = bytearray(struct.pack(self._PACK_STR, self.msgtype,
                                    self.code, self.csum,
                                    addrconv.ipv4.text_to_bin(
                                        self.src_address),
                                    addrconv.ipv4.text_to_bin(self.grp_address)))

        if self.csum == 0:
            self.csum = packet_utils.checksum(hdr)
            struct.pack_into('!H', hdr, 2, self.csum)
        return hdr

    @property
    def min_len(self):
        return self._MIN_LEN

##########################################################################
#     Custom datastores supporting expiration of stale entries           #
##########################################################################


class timedSet(MutableSet):
    def __init__(self, **kwargs):
        self.store = set()
        self.ttl = kwargs['ttl']
        self.timeStore = dict()

    def __contains__(self, element):
        if self.store.__contains__(element):
            self.timeStore[element] = time.time()
            return True
        else:
            return False

    def add(self, element):
        self.timeStore[element] = time.time()
        self.store.add(element)

    def discard(self, element):
        self.timeStore.pop(element)
        self.store.discard(element)

    def get(self):
        return self.store

    def __iter__(self):
        return self.store.__iter__()

    def __len__(self):
        return self.store.__len__()

    def expire(self):
        toRemove = set()
        for k, v in self.timeStore.items():
            if time.time() - v >= self.ttl:
                toRemove.add(k)
        for k in toRemove:
            self.discard(k)

    def __repr__(self):
        reprList = []
        for k in self.store:
            reprList.append((k, self.timeStore[k]))
        return reprList.__repr__()


class container:
    def __init__(self, **kwargs):
        self.store = dict()
        self.ttl = kwargs['ttl']
        self.lastCleanup = None

    def containsKey(self, key):
        if self.lastCleanup is not None and time.time() - self.lastCleanup >= self.ttl:
            self.lastCleanup = time.time()
            self.expire()
        return key in self.store and len(self.store[key]) > 0

    def put(self, key, value):
        if self.lastCleanup is None:
            self.lastCleanup = time.time()
        if key not in self.store:
            self.store[key] = timedSet(ttl=self.ttl)
        self.store[key].add(value)

    def containsValue(self, key, value):
        if not self.containsKey(key):
            return False
        return self.store[key].__contains__(value)

    def removeValue(self, key, value):
        self.store[key].discard(value)

    # always call containsKey before calling get.
    def get(self, key):
        if key in self.store:
            return self.store[key].get()
        else:
            return None

    def cleanup(self, key):
        self.store[key].expire()
        if len(self.store[key]) == 0:
            self.store.pop(key)

    def expire(self):
        sampleCount = math.ceil(.25*self.store.__len__())
        clearKeys = random.sample(self.store.keys(), sampleCount)
        for k in clearKeys:
            self.cleanup(k)

    def __repr__(self):
        return self.store.__repr__()
