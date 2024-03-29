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


import hashlib
import json
import logging
import os
import queue
import struct
import sys
import uuid
from collections import namedtuple

# from collections.abc import MutableSet
from datetime import datetime
from distutils import spawn
from logging.handlers import QueueHandler, QueueListener, RotatingFileHandler
from typing import Optional, Set, Tuple, Union

import eventlet
from eventlet.green import Queue, socket, subprocess, time
from ryu import cfg
from ryu.base import app_manager
from ryu.controller import dpset, ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    DEAD_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from ryu.lib import addrconv, hub
from ryu.lib.packet import arp, ethernet, packet, packet_base, packet_utils
from ryu.ofproto import ofproto_v1_4
from ryu.topology import event

DataplaneTypes = namedtuple(
    "DATAPLANE_TYPES",
    ["Undefined", "Patch", "Tincan", "Geneve"],
    defaults=["DptUndefined", "DptPatch", "DptTincan", "DptGeneve"],
)

DATAPLANE_TYPES: DataplaneTypes = DataplaneTypes()
LOG_DIR = "/var/log/evio/"
LOG_FILENAME = "bounded_flood.log"
LOG_LEVEL = "WARNING"
DEMAND_THRESHOLD = "10M"
FLOW_IDLE_TIMEOUT = 60
FLOW_HARD_TIMEOUT = 0  # 360
LINK_CHECK_INTERVAL = 65
MAX_ONDEMAND_EDGES = 0
TRAFFIC_ANALYSIS_INTERVAL = 10
STATE_LOGGING_INTERVAL = 66
STATE_TRACING_ENABLED = False
BACKUP_COUNT = 2
MAX_FILE_SIZE_BYTES = 10000000
CONF = cfg.CONF  # RYU environment
BF_COUNTER_DIGEST = hashlib.sha256("".encode("utf-8")).hexdigest()
BF_STATE_DIGEST = hashlib.sha256("".encode("utf-8")).hexdigest()
INTERNAL_PORT_NUM = 4294967294
KNOWN_LEAF_PORTS = (INTERNAL_PORT_NUM, 1)

NODE_TYPES = namedtuple(
    "NODE_TYPES",
    ["UNKNOWN", "LEAF", "EVIO_LEAF", "PEER"],
    defaults=["ND_TYPE_UNKNOWN", "ND_TYPE_LEAF", "ND_TYPE_EVIO_LEAF", "ND_TYPE_PEER"],
)
NodeTypes = NODE_TYPES()

OPCODE = namedtuple(
    "OPCODE",
    ["UPDATE_TUNNELS", "OND_REQUEST"],
    defaults=["UPDATE_TUNNELS", "OND_REQUEST"],
)
Opcode = OPCODE()


def runcmd(cmd):
    """Run a shell command. if fails, raise an exception."""
    if cmd[0] is None:
        raise ValueError("No executable specified to run")
    resp = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    return resp


def is_multiricepient(mac_addr):
    """
    :param addr: An IEEE EUI-48 (MAC) address in UNIX/WINDOWS string form.

    :return: ``True`` if MAC address string is multicast, ``False`` otherwise.
    """
    return bool(int(mac_addr[:2], 16) & 1)


##########################################################################
class FloodRouteBound(packet_base.PacketBase):
    """
    Flooding Route and Bound is an custom ethernet layer protocol used by EdgeVPNio SDN switching to
    perform link layer broadcasts in cyclic switched fabrics.
    root_nid is the node id of the switch that initiated the bounded flood operation
    bound_nid is the ascii UUID representation of the upper exclusive node id bound that limits the
    extent of the retransmission.
    hop_count is the number of switching hops to the destination, the initial switch sets this
    value to zero
    """

    # _PACK_STR = "!16s16sBBB16s"
    _PACK_STR = "!16s16sBBB"
    _MIN_LEN = struct.calcsize(_PACK_STR)
    ETH_TYPE_BF = 0xC0C0
    FRB_BRDCST = 0
    FRB_LEAF_TX = 1
    FRB_FWD = 2
    FRB_LNK_CHK = 3
    FRB_LNK_ACK = 4
    MAX_BYTE_VAL = 1 << 8
    TYPE_DESCR: list[str] = ["BRDCAST", "LEAF_TX", "FWD", "LNL_CHK", "LNK_ACK"]

    def __init__(
        # self, root_nid, bound_nid, hop_count, frb_type=0, pl_count=0, path=None
        self,
        root_nid,
        bound_nid,
        hop_count,
        frb_type=0,
        pl_count=0,
    ):
        super().__init__()
        self.root_nid: uuid.UUID = root_nid
        self.bound_nid: uuid.UUID = bound_nid
        self.hop_count: int = hop_count
        self.frb_type: int = frb_type
        self.pl_count: int = pl_count
        # if path is None:
        #     self.path: bytearray = bytearray(16)
        # else:
        #     assert self.hop_count < 16, "hop_count exceeds max val"
        #     self.path = path
        # assert self.hop_count < self.MAX_BYTE_VAL, "hop_count exceeds max val"
        # assert self.frb_type < self.MAX_BYTE_VAL, "frb_type exceeds max val"
        # assert self.pl_count < self.MAX_BYTE_VAL, "pl_count exceeds max val"

    def __str__(self):
        state = {
            "root_nid": self.root_nid,
            "bound_nid": self.bound_nid,
            "frb_type": self.TYPE_DESCR[self.frb_type],
            "hop_count": self.hop_count,
            "pl_count": self.pl_count,
            # "path": self.path.hex(),
        }
        return str(state)

    @classmethod
    def parser(cls, buf):
        unpk_data = struct.unpack(cls._PACK_STR, buf[: cls._MIN_LEN])
        rid = uuid.UUID(bytes=unpk_data[0])
        bid = uuid.UUID(bytes=unpk_data[1])
        hops = unpk_data[2]
        ty = unpk_data[3]
        cnt = unpk_data[4]
        # pth = unpk_data[5]
        return (
            # cls(rid.hex, bid.hex, hops, ty, cnt, pth),
            cls(rid.hex, bid.hex, hops, ty, cnt),
            None,
            buf[cls._MIN_LEN :],
        )

    def serialize(self, payload, prev):
        rid = uuid.UUID(hex=self.root_nid).bytes
        bid = uuid.UUID(hex=self.bound_nid).bytes
        # if payload is None:
        #     self.pl_count = 0
        # else:
        #     self.pl_count = len(payload)
        return struct.pack(
            FloodRouteBound._PACK_STR,
            rid,
            bid,
            self.hop_count,
            self.frb_type,
            self.pl_count,
            # self.path,
        )


###################################################################################################
###################################################################################################
class EvioOp:
    def __init__(self, code, dpid, olid, data=None):
        self.code = code
        self.dpid = dpid
        self.olid = olid
        self.data = data


class EvioPortal:
    MAX_ATTEMPTS = 3

    def __init__(self, svr_addr: str, logger):
        self._logger = logger
        self._svr_addr: str = svr_addr
        self._sock = None
        self._is_shutdown: bool = False

    def connect(self, sock):
        attempts = 0
        self._sock = sock
        while attempts < self.MAX_ATTEMPTS:
            try:
                attempts += 1
                self._sock.connect(self._svr_addr)
                break
            except ConnectionRefusedError as err:
                if attempts < 3:
                    self._logger.warning(
                        "Attempt %d failed to connect to evio portal: %s",
                        attempts,
                        str(err),
                    )
                    self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                    hub.sleep(2)
                else:
                    self._logger.error(
                        "Aborting attempts to connect to evio portal. Error: %s",
                        str(err),
                    )
                    sys.exit(-1)
                    # raise err

    def send(self, req):
        send_data = json.dumps(req)
        self._sock.sendall(len(send_data).to_bytes(2, sys.byteorder))
        self._sock.sendall(bytes(send_data, "utf-8"))

    def recv(self):
        recv_len = int.from_bytes(self._sock.recv(2), sys.byteorder)
        recv_data = str(self._sock.recv(recv_len), "utf-8")
        if not recv_data:
            return {
                "Response": {
                    "Status": False,
                    "Data": "No response from evio controller",
                }
            }

        return json.loads(recv_data)

    def send_recv(self, req):
        resp = None
        if self._is_shutdown:
            return {
                "Response": {
                    "Status": False,
                    "Data": "Terminating",
                }
            }
        if self._sock is None:
            self.connect(socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET))
        try:
            self.send(req)
            resp = self.recv()
        except Exception as err:
            self._logger.warning("A send recv failure occurred: %s", err)
            resp = {
                "Response": {
                    "Status": False,
                    "Data": "The send/recv operation to the evio controller failed.",
                }
            }
            self._sock.close()
            self._sock = None
        return resp

    def terminate(self):
        self._is_shutdown = True
        if self._sock:
            self._sock.shutdown(socket.SHUT_RDWR)
            self._sock.close()


###################################################################################################


class PeerData:
    def __init__(self, peer_id: str):
        self.port_no: Optional[int] = None  # valid only when a peer tunnel exists
        self.node_id: str = peer_id
        self.hw_addr: Optional[str] = None  # peer mac from evio controller
        self.hop_count: int = 0  # 1 -> an adjacent peer
        self.leaf_macs: set = set()  # leaf devices managed by the peer switch

    def __repr__(self):
        state = {
            "node_id": self.node_id,
            "port_no": self.port_no,
            "hw_addr": self.hw_addr,
            "hop_count": self.hop_count,
            "leaf_macs": sorted(self.leaf_macs),
        }
        return json.dumps(state)

    def __iter__(self):
        if hasattr(self, "_REFLECT"):
            keys = self._REFLECT
        else:
            keys = self.__dict__.keys()
        for k in keys:
            yield ((k, getattr(self, k)))

    def __len__(self):
        return len(self._REFLECT) if hasattr(self, "_REFLECT") else len(self.__dict__)

    def update(
        self,
        peer_hw_addr=None,
        leaf_macs: Optional[list] = None,
        hop_count: Optional[int] = None,
        port_no: Optional[int] = None,
    ):
        if peer_hw_addr:
            self.hw_addr = peer_hw_addr
        if leaf_macs:
            self.leaf_macs.update(leaf_macs)
        if hop_count:
            self.hop_count = hop_count
        if port_no:
            self.port_no = port_no


###################################################################################################


class PortDescriptor:
    _REFLECT: list[str] = [
        "port_no",
        "name",
        "hw_addr",
        "rmt_nd_type",
        "_dp_type",
        "last_active_time",
        "is_activated",
        "peer_data",
    ]

    def __init__(self, port_no: int, name: str, hw_addr: str):
        self.port_no: int = port_no  # port no for tunnel on the local switch
        self.name: str = name  # interface (TAP/NIC) name
        self.hw_addr: str = hw_addr  # local side tunnel MAC
        self.rmt_nd_type: NodeTypes = (
            NodeTypes.UNKNOWN
        )  # is the remote device a peer switch or leaf
        self._dp_type: DataplaneTypes = DATAPLANE_TYPES.Undefined
        self.is_activated: bool = False
        self.last_active_time: float = time.time()
        self.peer_data: PeerData = None  # valid if ND_TYPE_PEER

    def __repr__(self):
        state = {
            "port_no": self.port_no,
            "name": self.name,
            "hw_addr": self.hw_addr,
            "rmt_nd_type": self.rmt_nd_type,
            "dataplane_type": self.dataplane_type,
            "last_active_time": str(datetime.fromtimestamp(self.last_active_time)),
            "is_activated": self.is_activated,
            "peer_data": dict(self.peer_data) if self.peer_data else None,
        }
        return json.dumps(
            state, default=lambda o: sorted(o) if isinstance(o, set) else o
        )

    def __iter__(self):
        if hasattr(self, "_REFLECT"):
            keys = self._REFLECT
        else:
            keys = self.__dict__.keys()
        for k in keys:
            if k == "peer_data":
                yield ((k, dict(self.peer_data)))
            elif k == "last_active_time":
                yield (
                    "last_active_time",
                    str(datetime.fromtimestamp(self.last_active_time)),
                )
            else:
                yield ((k, getattr(self, k)))

    def __len__(self):
        return len(self._REFLECT) if hasattr(self, "_REFLECT") else len(self.__dict__)

    @property
    def peer(self):
        return self.peer_data

    @peer.setter
    def peer(self, data):
        if isinstance(data, PeerData):
            self.peer_data = data
        else:
            self.peer_data = PeerData(data)

    @property
    def is_peer(self):
        return bool(self.rmt_nd_type == NodeTypes.PEER and self.peer_data is not None)

    @property
    def is_adjacent_peer(self):
        return bool(self.is_peer and self.peer_data.port_no is not None)

    @property
    def is_categorized(self):
        return bool(self.rmt_nd_type != NodeTypes.UNKNOWN)

    @property
    def dataplane_type(self):
        return self._dp_type

    @dataplane_type.setter
    def dataplane_type(self, tech):
        if tech == DATAPLANE_TYPES.Tincan:
            self.is_activated = True
        self._dp_type = tech

    @property
    def is_tincan_tunnel(self):
        return self._dp_type == DATAPLANE_TYPES.Tincan

    @property
    def is_geneve_tunnel(self):
        return self._dp_type == DATAPLANE_TYPES.Geneve


###################################################################################################


class EvioSwitch:
    _REFLECT: list[str] = [
        "_datapath",
        "_overlay_id",
        "_node_id",
        "_leaf_prts",
        "_link_prts",
        "_leaf_macs",
        "_ingress_tbl",
        "_port_tbl",
        "_root_sw_tbl",
        "_peer_tbl",
    ]

    def __init__(self, datapath, **kwargs) -> None:
        self._datapath = datapath
        self._overlay_id = kwargs["OverlayId"]
        self._node_id = kwargs["NodeId"]
        self.logger: logging.Logger = kwargs["Logger"]
        self._leaf_prts: Set[int] = set()  # port numbers of leaf tunnels
        self._link_prts: Set[int] = set()  # port numbers of peer tunnels
        self._leaf_macs: Set[str] = set()  # hw addr of local leaf devices
        self._port_tbl: dict[int, PortDescriptor] = dict()  # port_no->PortDescriptor
        self._ingress_tbl: dict[str, int] = dict()  # hw_addr->ingress port number
        self._root_sw_tbl: dict[str, PeerData] = dict()  # leaf_mac->PeerData
        self._peer_tbl: dict[str, PeerData] = dict()  # node_id->PeerData
        # self._flows: dict[tuple[int, str, str], int] = dict()

        self.max_on_demand_edges = kwargs.get("MaxOnDemandEdges", MAX_ONDEMAND_EDGES)
        self.traffic_analyzer = TrafficAnalyzer(
            self.logger, kwargs.get("DemandThreshold", DEMAND_THRESHOLD)
        )
        self._is_tunnel_data_good = False
        self.idle_timeout = kwargs.get("FlowIdleTimeout", FLOW_IDLE_TIMEOUT)
        self.hard_timeout = kwargs.get("FlowHardTimeout", FLOW_HARD_TIMEOUT)
        self._topo_seq = 0
        self._uncategorized_ports: Set[int] = set()
        self._max_hops = 0
        self._ond_ops: list = []

    def __repr__(self):
        state = {
            "EvioSwitch": {
                "overlay_id": self._overlay_id,
                "node_id": self._node_id,
                "datapath_id": self._datapath.id,
                "leaf_ports": list(self._leaf_prts),
                "link_ports": list(self._link_prts),
                "leaf_macs": list(self._leaf_macs),
                "ingress_tbl": self._ingress_tbl,
                "port_tbl": self._port_tbl,
                "root_sw_tbl": self._root_sw_tbl,
                "peer_table": self._peer_tbl,
            }
        }
        return str(state)

    def ingress_tbl_contains(self, mac) -> bool:
        return mac in self._ingress_tbl

    def get_ingress_port(self, mac) -> Optional[int]:
        # return the best egress to reach the given mac
        psw: Optional[PeerData] = self._root_sw_tbl.get(mac)
        if psw and psw.port_no:
            return psw.port_no
        return self._ingress_tbl.get(mac)

    def set_ingress_port(self, key_mac, value: Union[tuple, str]):
        if isinstance(value, tuple):
            self._learn(src_mac=key_mac, in_port=value[0], rnid=value[1])
        else:
            self._learn(key_mac, value)

    def remove_ingress_port(self, mac):
        self._ingress_tbl.pop(mac, None)
        self._root_sw_tbl.pop(mac, None)

    def __iter__(self):
        if hasattr(self, "_REFLECT"):
            keys = self._REFLECT
        else:
            keys = self.__dict__.keys()
        for k in keys:
            yield ((k, getattr(self, k)))

    def __len__(self):
        return (
            len(self._REFLECT)
            if hasattr(self, "_REFLECT")
            else len(self.__dict__.keys())
        )

    def _register_peer(
        self,
        peer_id,
        in_port=None,
        peer_hw_addr=None,
        leaf_macs: Optional[list] = None,
        hop_count=None,
    ) -> PeerData:
        if peer_id not in self._peer_tbl:
            self._peer_tbl[peer_id] = PeerData(peer_id)
        self._peer_tbl[peer_id].update(
            port_no=in_port,
            peer_hw_addr=peer_hw_addr,
            leaf_macs=leaf_macs,
            hop_count=hop_count,
        )
        return self._peer_tbl[peer_id]

    def _deregister_peer(self, peer: PeerData):
        """
        Clear port_no to indicate the tunnel is removed, ie., switch is no longer adjacent
        although it may be accessible via hops.
        """
        for mac in peer.leaf_macs:
            self.remove_ingress_port(mac)
        peer.port_no = None
        peer.leaf_macs.clear()

    @property
    def name(self) -> str:
        return self._port_tbl[INTERNAL_PORT_NUM].name

    @property
    def is_ond_enabled(self) -> bool:
        return self.max_on_demand_edges > 0

    @property
    def leaf_ports(self) -> list:
        return list(self._leaf_prts)

    @property
    def link_ports(self) -> list:
        return list(self._link_prts)

    @property
    def port_numbers(self) -> list:
        return [*self._port_tbl.keys()]

    @property
    def node_id(self) -> str:
        return self._node_id

    @property
    def overlay_id(self) -> str:
        return self._overlay_id

    @property
    def adjacent_peers(self) -> list:
        """The list of peers to which this node has a connected tunnel"""
        pl = []
        for port_no in self._link_prts:
            pl.append(self._port_tbl[port_no].peer_data.node_id)
        return pl

    def peer(self, peer_id) -> PeerData:
        return self._peer_tbl[peer_id]

    def get_root_sw(self, leaf_mac) -> Optional[PeerData]:
        return self._root_sw_tbl.get(leaf_mac)

    def port_descriptor(self, port_no) -> PortDescriptor:
        return self._port_tbl[port_no]

    def is_valid_port(self, port_no) -> bool:
        return bool(port_no in self._datapath.ports)

    def is_port_categorized(self, port_no) -> bool:
        return bool(self._port_tbl[port_no].is_categorized)

    def is_port_activated(self, port_no) -> bool:
        return self._port_tbl[port_no].is_activated

    def reset_port_data(self, port_set):
        self._port_tbl.clear()
        self._root_sw_tbl.clear()
        self._peer_tbl.clear()
        self._uncategorized_ports.clear()
        for port_no, prt in port_set.items():
            pd = PortDescriptor(port_no, prt.name.decode("utf-8"), prt.hw_addr)
            if port_no == INTERNAL_PORT_NUM:
                self._categorize_port(pd, NodeTypes.LEAF)
                self._leaf_prts.add(pd.port_no)
                # pd.rmt_nd_type = NodeTypes.LEAF
                # pd.dataplane_type = DATAPLANE_TYPES.Patch
            else:
                self._uncategorized_ports.add(port_no)
            self._port_tbl[port_no] = pd

    def _categorize_port(
        self,
        port: PortDescriptor,
        rmt_nd_type: NodeTypes,
        tnl_data: Optional[dict] = None,
    ):
        """
        Categorize a port in the local switch by setting the tunnel type, dataplane type,
        and optionally creating the PeerData entry in the peer table and port descriptor. The
        tnl_data comes from the evio controller.
        """
        port.rmt_nd_type = rmt_nd_type
        self._port_tbl[port.port_no] = port
        if tnl_data:
            port.dataplane_type = tnl_data["Dataplane"]
            pd = self._register_peer(
                peer_id=tnl_data["PeerId"],
                peer_hw_addr=tnl_data["PeerMac"],
                in_port=port.port_no,
                hop_count=1,
            )
            self._port_tbl[port.port_no].peer_data = pd
        else:
            port.dataplane_type = DATAPLANE_TYPES.Patch
        self.logger.info(
            "Categorized port %s:%s, port_no=%d, dp=%s",
            self.name,
            port.name,
            port.port_no,
            port.dataplane_type,
        )

    def activate_port(self, port_no):
        self._port_tbl[port_no].is_activated = True

    def add_port(self, ofpport):
        port = PortDescriptor(
            ofpport.port_no, ofpport.name.decode("utf-8"), ofpport.hw_addr
        )
        self._port_tbl[port.port_no] = port
        self._uncategorized_ports.add(port.port_no)
        self.logger.debug(
            "Added uncategorized port_no: %s:%s/%d", self.name, port.name, port.port_no
        )

    def delete_port(self, port_no):
        port = self._port_tbl.pop(port_no, None)
        if port:
            self.logger.info(
                "Removed port %s:%s/%d", self.name, port.name, port.port_no
            )
            if port.rmt_nd_type == NodeTypes.PEER:
                self._deregister_peer(port.peer_data)
                self._link_prts.remove(port_no)
            elif port.rmt_nd_type == NodeTypes.LEAF:
                self._leaf_prts.remove(port_no)
            tbr = []  # build a list of all mac that ingress via this port
            for mac_key, port_val in self._ingress_tbl.items():
                if port_val == port_no:
                    tbr.append(mac_key)
            for mac_entry in tbr:  # remove these mac entries from the ingress table
                self._ingress_tbl.pop(mac_entry, None)
        try:
            self._uncategorized_ports.remove(port_no)
        except KeyError:
            pass

    def update_port_data(self, tnl_data) -> list:
        updated: list = []
        if not tnl_data or "seq" not in tnl_data:
            return updated
        if tnl_data["seq"] >= self._topo_seq:
            uncat = self._uncategorized_ports
            self._uncategorized_ports = set()
            for port_no in uncat:
                port = self._port_tbl[port_no]
                if port.name in tnl_data["snapshot"]:
                    self._categorize_port(
                        port, NodeTypes.PEER, tnl_data["snapshot"][port.name]
                    )
                    self._link_prts.add(port.port_no)
                    updated.append(port)
                elif port.port_no in KNOWN_LEAF_PORTS:
                    self._categorize_port(port, NodeTypes.LEAF)
                    self._leaf_prts.add(port.port_no)
                    updated.append(port)
                else:
                    self._uncategorized_ports.add(port_no)
            self._topo_seq = tnl_data["seq"]
            if self._uncategorized_ports:
                self.logger.warning(
                    "No data was available to categorize the "
                    f"following ports {self._uncategorized_ports}"
                )
        else:
            self.logger.warning(
                f"The evio tunnel data for {self.name} "
                f"has not yet been updated beyond seq {self._topo_seq}"
            )
        return updated

    def _learn(self, src_mac, in_port, rnid=None):
        """
        Associate the mac with the ingress port. If the RNID is provided it indicates the peer
        switch that hosts the leaf mac.
        """
        self._ingress_tbl[src_mac] = in_port
        if rnid:
            pd = self._register_peer(
                peer_id=rnid,
                leaf_macs=[
                    src_mac,
                ],
            )
            self._root_sw_tbl[src_mac] = pd
            self.logger.debug(
                f"learn sw:{self.name}, leaf_mac:{src_mac}, rnid:{rnid[:7]}, via ingress:{in_port}"
            )
        elif in_port in self._leaf_prts:
            self._leaf_macs.add(src_mac)
        else:
            self.logger.debug(
                f"learn sw:{self.name}, leaf_mac:{src_mac}, ingress:{in_port}"
            )

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

    @property
    def ond_tnl_ops(self):
        tnl_ops = self._ond_ops
        self._ond_ops = []
        return tnl_ops

    def terminate(self):
        self._overlay_id = ""
        self._node_id = ""
        self._leaf_prts.clear()
        self._link_prts.clear()
        self._leaf_macs.clear()
        self._ingress_tbl.clear()
        self._port_tbl.clear()
        self._root_sw_tbl.clear()
        self._peer_tbl.clear()

    @property
    def max_hops(self):
        return self._max_hops

    @max_hops.setter
    def max_hops(self, num_hops):
        if num_hops == 0:
            self._max_hops = 0
        elif num_hops > self._max_hops:
            self._max_hops = num_hops

    def get_flooding_bounds(
        self, frb_type, prev_frb=None, exclude_ports=None
    ) -> list[Tuple[int, FloodRouteBound]]:
        """
        FloodingBounds is used to dtermine which of its adjacent peers should be sent a frb to
        complete a overlay wide broadcast and bound should be used in the frb sent to said peer.
        FloodingBounds are typically calculated to flow clockwise to greater peer IDs and bounds
        and accommodates the wrap around of the ring. However, for the initial frb broadcast
        lesser peer IDs are used. This gives the local node the opportunity to discover the direct
        path associated with lesser peer IDs.
        Creates a list of tuples in the format (egress, frb) which indicates the output port
        number that the frb should be sent.
        prev_frb - indicates that there is no incoming frb to be used to derive the next set
        of outgoing frb's; this is the case when the node is generating the initial one.
        exluded_ports - list the port numbers that should not be used for output; this is tyically
        the ingress of the prev_frb.
        """
        if not exclude_ports:
            exclude_ports = []
        out_bounds: list[Tuple[int, FloodRouteBound]] = []
        node_list = self.adjacent_peers
        my_nid = self.node_id
        node_list.append(my_nid)
        node_list.sort()
        myi = node_list.index(my_nid)
        num_nodes = len(node_list)
        for i, peer1 in enumerate(node_list):
            # Preconditions:
            #  peer1 < peer2
            #  self < peer1 < peer2 || peer1 < peer2 <= self
            # if i == myi or (prtno and prtno not in exclude_ports):
            if i == myi:
                continue
            p2i = (i + 1) % num_nodes
            peer2 = node_list[p2i]
            if not (my_nid < peer1 or peer2 <= my_nid):
                self.logger.warning(
                    f"Invalid node_id ordering self={my_nid}, peer1={peer1}, peer2={peer2}"
                )
                return out_bounds
            # base scenario when the local node is initiating the FRB
            hops = 1
            root_nid = my_nid
            bound_nid = my_nid
            if not prev_frb:
                bound_nid = peer2
                frb_hdr = FloodRouteBound(root_nid, bound_nid, hops, frb_type)
                if frb_hdr:
                    # frb_hdr.path[0] = int(frb_hdr.root_nid[5:7], 16)
                    prtno = self.port_no(peer1)
                    if prtno and prtno not in exclude_ports:
                        out_bounds.append((prtno, frb_hdr))
            else:
                if prev_frb.bound_nid == my_nid:
                    self.logger.warning(
                        f"This frb should not have reached this node "
                        f"my_nid={my_nid} prev_frb={prev_frb}"
                    )
                    return out_bounds
                hops = prev_frb.hop_count + 1
                root_nid = prev_frb.root_nid
                if peer1 < my_nid:  # peer1 is a predecessor
                    if (
                        prev_frb.bound_nid > peer1 and prev_frb.bound_nid < my_nid
                    ):  # bcast to peer1
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
                        elif (
                            peer2 < my_nid and peer2 <= prev_frb.bound_nid
                        ) or peer2 > my_nid:
                            bound_nid = peer2
                    else:  # prev_frb.bound_nid > my_nid
                        if prev_frb.bound_nid <= peer1:
                            continue
                        if peer2 < my_nid or prev_frb.bound_nid < peer2:
                            bound_nid = prev_frb.bound_nid
                        else:
                            bound_nid = peer2
                # ba = bytearray(prev_frb.path)
                # ba[hops] = int(my_nid[5:7], 16)
                # frb_hdr = FloodRouteBound(root_nid, bound_nid, hops, frb_type, path=ba)
                frb_hdr = FloodRouteBound(root_nid, bound_nid, hops, frb_type)
                if frb_hdr:
                    prtno = self.port_no(peer1)
                    if prtno and prtno not in exclude_ports:
                        # if peer1 == frb_hdr.bound_nid:
                        #     state = ", ".join(
                        #         (f'"{k}": {str(v)}' for k, v in self._lt.items())
                        #     )
                        #     self.logger.error(
                        #         "BoundID matches recipient %s, egress:%s, frb:%s. state:",
                        #         peer1,
                        #         prtno,
                        #         frb_hdr,
                        #         state,
                        #     )
                        out_bounds.append((prtno, frb_hdr))
        return out_bounds


###################################################################################################


class BoundedFlood(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]
    _CONTEXTS = {
        "dpset": dpset.DPSet,
    }
    LOGGER_NAME = "BoundedFlood"
    OFCTL = spawn.find_executable("ovs-ofctl")
    if OFCTL is None:
        raise RuntimeError("Open vSwitch was not found, is it installed?")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        ethernet.ethernet.register_packet_type(
            FloodRouteBound, FloodRouteBound.ETH_TYPE_BF
        )
        self._is_exit = eventlet.event.Event()
        self._load_config()
        self._traffic_analysis_interval = self.config.get(
            "TrafficAnalysisInterval", TRAFFIC_ANALYSIS_INTERVAL
        )
        self._state_logging_interval = self.config.get(
            "StateLoggingInterval", STATE_LOGGING_INTERVAL
        )
        self._link_check_interval = self.config.get(
            "LinkCheckInterval", LINK_CHECK_INTERVAL
        )
        self._setup_logger()
        self.evio_portal = EvioPortal(
            self.config.get("ProxyAddress"),
            self.logger,
        )
        self.dpset = kwargs["dpset"]
        self._lt: dict[int, EvioSwitch] = {}
        self._ev_bh_update = Queue.Queue()
        self._monitors = [
            hub.spawn(self.monitor_flow_traffic),
            hub.spawn(self.update_tunnels),
            hub.spawn(self.check_links),
        ]
        if self.config.get("StateTracingEnabled", STATE_TRACING_ENABLED):
            self._monitors.append(hub.spawn(self.log_state))
        self.logger.info("BoundedFlood: Module loaded")

    def close(self):
        self._is_exit.send(True)
        for evi in self._lt.values():
            evi.terminate()
        self._lt.clear()
        self.evio_portal.terminate()
        hub.joinall(self._monitors)
        self.logger.info("BoundedFlood terminated")
        self._que_listener.stop()
        logging.shutdown()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        try:
            while INTERNAL_PORT_NUM not in datapath.ports:
                hub.sleep(1)
            br_name = datapath.ports[INTERNAL_PORT_NUM].name.decode("utf-8")
            if datapath.id in self._lt:
                self.logger.warning(
                    "Datapath %s is already in learning table, reinitializing",
                    datapath.id,
                )
                self._lt.pop(datapath.id)
            if br_name not in self.config:
                self.logger.warning(
                    "Bridge %s is not specified in the BoundedFlood config, "
                    "skipping bridge registration. Config=%s",
                    br_name,
                    self.config,
                )
                return

            overlay_id = self.config[br_name]["OverlayId"]
            self._lt[datapath.id] = EvioSwitch(
                datapath,
                OverlayId=overlay_id,
                NodeId=self.config["NodeId"],
                Logger=self.logger,
                MaxOnDemandEdges=self.config[br_name].get(
                    "MaxOnDemandEdges", MAX_ONDEMAND_EDGES
                ),
                DemandThreshold=self.config[br_name].get(
                    "DemandThreshold", DEMAND_THRESHOLD
                ),
                FlowIdleTimeout=self.config[br_name].get(
                    "FlowIdleTimeout", FLOW_IDLE_TIMEOUT
                ),
                FlowHardTimeout=self.config[br_name].get(
                    "FlowHardTimeout", FLOW_HARD_TIMEOUT
                ),
            )

            self.logger.info("Switch %s added with overlay ID %s", br_name, overlay_id)
            self._lt[datapath.id].reset_port_data(datapath.ports)
            self._reset_switch_flow_rules(datapath)
            self._ev_bh_update.put(
                EvioOp(Opcode.UPDATE_TUNNELS, datapath.id, overlay_id)
            )
        except RuntimeError:
            self.logger.exception(
                "An runtime error occurred while registering a switch."
            )
            if datapath.id in self._lt:
                self._lt.pop(datapath.id, None)
        except Exception:
            self.logger.exception("A failure occurred while registering a switch.")
            if datapath.id in self._lt:
                self._lt.pop(datapath.id, None)

    @set_ev_cls(
        event.EventSwitchLeave, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER]
    )
    def handler_switch_leave(self, ev):
        try:
            dpid = ev.switch.dp.id
            if dpid in self._lt:
                sw: EvioSwitch = self._lt[dpid]
                br_name = sw.name
                sw.terminate()
                self._lt.pop(dpid, None)
            self.logger.info("Removed switch: %s", br_name)
        except Exception:
            self.logger.exception(
                "An error occurred while attempting to remove switch %s",
                ev.switch.dp.id,
            )

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        port_no = msg.desc.port_no
        try:
            if msg.reason == ofp.OFPPR_ADD:
                self.logger.debug("OFPPortStatus: port ADDED desc=%s", msg.desc)
                self._lt[dp.id].add_port(msg.desc)
                self._ev_bh_update.put(
                    EvioOp(Opcode.UPDATE_TUNNELS, dp.id, self._lt[dp.id].overlay_id)
                )
            elif msg.reason == ofp.OFPPR_DELETE:
                self.logger.debug("OFPPortStatus: port DELETED desc=%s", msg.desc)
                self._del_port_flow_rules(dp, port_no, tblid=0)
                self._lt[dp.id].delete_port(port_no)
            elif msg.reason == ofp.OFPPR_MODIFY:
                self.logger.debug("OFPPortStatus: port MODIFIED desc=%s", msg.desc)

        except Exception:
            self.logger.exception(
                "An error occurred while responding to port event %s.", ev.msg
            )

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        ev_msg = ev.msg
        in_port = ev_msg.match["in_port"]
        pkt = packet.Packet(ev_msg.data)
        eth = pkt.protocols[0]
        dpid = ev_msg.datapath.id
        sw: EvioSwitch = self._lt[dpid]
        port: PortDescriptor = sw.port_descriptor(in_port)

        try:
            # if self.logger.isEnabledFor(logging.DEBUG):
            #     self.logger.debug(f"packet_in[{in_port}]<=={pkt}")

            if not sw.is_valid_port(in_port):
                if self.logger.isEnabledFor(logging.DEBUG):
                    self.logger.warning(
                        f"Packet received on invalid port:{sw.name}/{in_port} bufferd frame: {pkt}"
                    )
                return
            if not port.is_categorized:
                self.logger.info(
                    f"Packet received, but port {in_port} is not yet ready"
                )
                return
            port.last_active_time = time.time()
            """Learn new ingress and attemp update of outgoing flow rules for the current eth src
            mac. An upcall to BF implies a possible change to the topo that can render existing
            rules invalid"""
            if eth.ethertype == FloodRouteBound.ETH_TYPE_BF:
                self.handle_bounded_flood_msg(ev_msg.datapath, in_port, ev_msg)
            elif is_multiricepient(eth.dst):
                """Currently, only broadcast addresses originating from local leaf ports are
                broadcasted using FRB"""
                if in_port in sw.leaf_ports:
                    self._broadcast_frame(ev_msg.datapath, in_port, ev_msg)
                else:
                    self.logger.info(
                        "Discarding ingressed multirecipient frame on peer port %s/%s",
                        sw.name,
                        in_port,
                    )  # can occur on newly added port before IP addresses are flushed
            elif sw.ingress_tbl_contains(eth.dst):
                """Unicast Ethernet frame and forwarding port data is available for its destination
                MAC"""
                # learn MAC address
                sw.set_ingress_port(eth.src, in_port)
                if eth.dst in sw.local_leaf_macs:
                    self._update_outbound_flow_rules(
                        ev_msg.datapath,
                        eth.src,
                        in_port,
                        reason="Packet for local pendant",
                    )
                elif eth.src in sw.local_leaf_macs:  # outgoing from local pendant
                    peer: PeerData = self._lt[dpid].get_root_sw(eth.dst)
                    if peer and peer.port_no:  # remote is adjacent
                        self.send_pendant_mac_to_adj_peer(
                            ev_msg.datapath, peer, eth.dst, eth.src
                        )
                # include frames where local pendant not involved
                self._add_flow_and_forward_frame(ev_msg.datapath, pkt, in_port, ev_msg)
            else:
                """Flooding unicast frames, prevents accumulating the port data to create a flow rule"""
                self.logger.info(
                    "No forwarding route to %s, discarding frame. Ingress=%s/%s",
                    eth.dst,
                    sw.name,
                    in_port,
                )  # some apps arp to an eth addr other than broadcast or the fwding port was recently removed
        except Exception:
            self.logger.exception(
                "An error occurred in the controller's packet handler. Event=%s", ev.msg
            )

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        try:
            dpid = ev.msg.datapath.id
            evi_sw = self._lt[dpid]
            ond_ops = evi_sw.traffic_analyzer.get_ond_tnl_ops(
                flow_metrics=ev.msg.body, evio_sw=evi_sw
            )
            if ond_ops:
                self._ev_bh_update.put(
                    EvioOp(Opcode.OND_REQUEST, dpid, evi_sw.overlay_id, ond_ops)
                )
        except Exception:
            self.logger.exception(
                "An error occurred in the flow stats handler. Event=%s", ev.msg
            )

    @set_ev_cls(ofp_event.EventOFPFlowMonitorReply, MAIN_DISPATCHER)
    def flow_monitor_reply_handler(self, ev):
        try:
            msg = ev.msg
            dp = msg.datapath
            ofp = dp.ofproto
            flow_updates = []
            for update in msg.body:
                update_str = f"length={update.length} event={update.event}"
                if (
                    update.event == ofp.OFPFME_INITIAL
                    or update.event == ofp.OFPFME_ADDED
                    or update.event == ofp.OFPFME_REMOVED
                    or update.event == ofp.OFPFME_MODIFIED
                ):
                    update_str += f"table_id={update.table_id} reason={update.reason} idle_timeout={update.idle_timeout} hard_timeout={update.hard_timeout} priority={update.priority} cookie={update.cookie} match={update.match} instructions={update.instructions}"
                elif update.event == ofp.OFPFME_ABBREV:
                    update_str += f"xid={update.xid}"
                flow_updates.append(update_str)
            self.logger.debug("FlowUpdates: %s", flow_updates)
        except Exception:
            self.logger.exception(
                "An error occurred in the controller's flow monitor reply handler. Event=%s",
                ev,
            )

    ##################################################################################
    ##################################################################################

    def monitor_flow_traffic(self):
        while not self._is_exit.wait(float(self._traffic_analysis_interval)):
            try:
                while not self._is_exit:
                    for dpid in self._lt:
                        self._request_stats(self.dpset.dps[dpid])
            except Exception:
                self.logger.exception(
                    "An exception occurred within the traffic monitor."
                )

    def update_tunnels(self):
        while not self._is_exit.ready():
            try:
                while not self._is_exit.ready():
                    tnl_data = {}
                    op = self._ev_bh_update.get()
                    if op is None:
                        return
                    if op.code == Opcode.UPDATE_TUNNELS:
                        tnl_data = self._query_evio_tunnel_data(op.olid)
                        if op.olid in tnl_data:
                            updated_prts = self._lt[op.dpid].update_port_data(
                                tnl_data[op.olid]
                            )
                            for port in updated_prts:
                                if port.is_adjacent_peer:
                                    if port.is_tincan_tunnel:
                                        self._update_flow_rules_to_peer(
                                            self.dpset.dps[op.dpid],
                                            port.peer,
                                            reason="Port categorized",
                                        )
                                    elif port.dataplane_type == DATAPLANE_TYPES.Geneve:
                                        self.do_link_check(
                                            self.dpset.dps[op.dpid], port
                                        )
                    elif op.code == Opcode.OND_REQUEST:
                        self._request_ond_tnl_ops(op.olid, op.data)
                    self._ev_bh_update.task_done()
            except Exception:
                self.logger.exception(
                    "An exception occurred while updating the tunnel data."
                )

    def log_state(self):
        while not self._is_exit.wait(float(self._state_logging_interval)):
            try:
                while not self._is_exit.wait(float(self._state_logging_interval)):
                    counter_vals = {}
                    for dpid in self._lt:
                        self._collect_counters(dpid, counter_vals)
                    self._log_state()
                    self._log_counters(counter_vals)
            except Exception:
                self.logger.exception("An exception occurred while logging BF state.")

    def check_links(self):
        """
        A link check is performed every LNK_CHK_INTERVAL. Receiving a LNK_CHK or
        LNK_ACK satifies the LNK_ACTIVE condition and resets the check interval
        """
        while not self._is_exit.wait(float(self._link_check_interval)):
            try:
                while not self._is_exit.wait(float(self._link_check_interval)):
                    for dpid, sw in self._lt.items():
                        tunnel_ops = []
                        for port_no in sw.port_numbers:
                            port = sw.port_descriptor(port_no)
                            if port.is_geneve_tunnel:
                                now = time.time()
                                if (
                                    now
                                    >= port.last_active_time
                                    + 3 * self._link_check_interval
                                ):
                                    # send req to remove tunnel to peer
                                    self.logger.info(
                                        f"Requesting removal of inactive port {port}"
                                    )
                                    tunnel_ops.append((port.peer.node_id, "DISCONN"))
                                    sw.delete_port(port_no)
                                elif (
                                    now
                                    >= port.last_active_time + self._link_check_interval
                                ):
                                    self.do_link_check(self.dpset.dps[dpid], port)
                        if tunnel_ops:
                            self._ev_bh_update.put(
                                EvioOp(
                                    Opcode.OND_REQUEST, dpid, sw.overlay_id, tunnel_ops
                                )
                            )
            except Exception:
                self.logger.exception("An exception occurred within check links.")

    ##################################################################################
    ##################################################################################

    def _setup_logger(self):
        cm_name = ("BoundedFlood", LOG_FILENAME)
        logname = os.path.join(self.config.get("LogDir", LOG_DIR), f"{cm_name[1]}")
        # if os.path.isfile(logname):
        #     os.remove(logname)
        level = self.config.get("LogLevel", LOG_LEVEL)
        file_handler = RotatingFileHandler(
            filename=logname,
            maxBytes=self.config.get("MaxBytes", MAX_FILE_SIZE_BYTES),
            backupCount=self.config.get("BackupCount", BACKUP_COUNT),
        )
        formatter = logging.Formatter(
            "[%(asctime)s.%(msecs)03d] %(levelname)s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(level)
        que = queue.Queue()
        que_handler = QueueHandler(que)
        self._que_listener = QueueListener(
            que, file_handler, respect_handler_level=True
        )
        self.logger = logging.getLogger(cm_name[0])
        self.logger.setLevel(level)
        self.logger.addHandler(que_handler)
        self._que_listener.start()

    def _load_config(self):
        if CONF["bf"]["config_file"]:
            if not os.path.isfile(CONF["bf"]["config_file"]):
                raise RuntimeError(
                    "The specified configuration file was not found: {}".format(
                        CONF["bf"]["config_file"]
                    )
                )
            with open(CONF["bf"]["config_file"]) as f:
                self.config = json.load(f)
        elif CONF["bf"]["config_string"]:
            self.config = json.loads(CONF["bf"]["config_string"])
        else:
            raise RuntimeError("No valid configuration found")

    def _query_evio_tunnel_data(self, overlay_id=None):
        req = {
            "Request": {
                "Recipient": "BridgeController",
                "Action": "GetTunnelData",
                "Params": {},
            }
        }
        resp = self.evio_portal.send_recv(req)
        if not resp["Response"]["Status"]:
            self.logger.warning("Failed to update tunnel data")
            return {}
        tnl_data = resp["Response"]["Data"]
        return tnl_data

    def _request_ond_tnl_ops(self, overlay_id, ond_tnl_ops):
        reqs = []
        for ond_op in ond_tnl_ops:
            reqs.append(
                {"OverlayId": overlay_id, "PeerId": ond_op[0], "Operation": ond_op[1]}
            )
        req = {
            "Request": {
                "Recipient": "BridgeController",
                "Action": "TunnelRquest",
                "Params": reqs,
            }
        }
        self.evio_portal.send_recv(req)

    def _log_state(self):
        global BF_STATE_DIGEST
        state = ", ".join((f'"{k}": {str(v)}' for k, v in self._lt.items()))
        new_digest = hashlib.sha256(state.encode("utf-8")).hexdigest()
        if BF_STATE_DIGEST != new_digest:
            BF_STATE_DIGEST = new_digest
            self.logger.info(f'{{"controller state": {{{state}}}}}\n')

    def _collect_counters(self, dpid, counter_vals: dict):
        total_hops = 0
        sw: EvioSwitch = self._lt[dpid]
        num_nodes = len(sw._peer_tbl) + 1
        pd: PeerData
        for pd in sw._peer_tbl.values():
            total_hops += pd.hop_count
            sw.max_hops = pd.hop_count
        counter_vals[sw.name] = {
            "MaxHops": sw.max_hops,
            "TotalHops": total_hops,
            "NumNodes": num_nodes,
            "AvgHops": total_hops / num_nodes,
        }

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
        if not (
            self._lt[datapath.id].is_ond_enabled
            and bool(self._lt[datapath.id]._peer_tbl)
        ):
            return
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath, table_id=tblid)
        resp = datapath.send_msg(req)
        if not resp:
            self.logger.warning(
                "Request stats operation failed, OFPFlowStatsRequest=%s", req
            )

    def _create_flow_rule(
        self,
        datapath,
        match,
        actions,
        priority=0,
        tblid=0,
        idle_timeout=0,
        hard_timeout=0,
    ):
        mod = None
        try:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            # self.logger.info(
            #     "Adding flow rule %s/%s to egress %s",
            #     self._lt[datapath.id].name,
            #     match,
            #     actions,
            # )
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                table_id=tblid,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout,
                match=match,
                instructions=inst,
            )
            resp = datapath.send_msg(mod)
            if not resp:
                self.logger.warning("Add flow operation failed, OFPFlowMod=%s", mod)
        except struct.error:
            self.logger.exception("Add flow operation failed, OFPFlowMod=%s.", mod)

    def _create_flow_rule_drop_multicast(self, datapath, priority=1, tblid=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_dst=("33:33:00:00:00:00", "ff:ff:00:00:00:00"))
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            command=ofproto.OFPFC_ADD,
            instructions=inst,
            table_id=tblid,
        )
        resp = datapath.send_msg(mod)
        if not resp:
            self.logger.warning("Add flow (MC) operation failed, OFPFlowMod=%s", mod)
        match = parser.OFPMatch(eth_dst=("01:00:5e:00:00:00", "ff:ff:ff:ff:ff:00"))
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            command=ofproto.OFPFC_ADD,
            instructions=inst,
            table_id=tblid,
        )
        resp = datapath.send_msg(mod)
        if not resp:
            self.logger.warning("Add flow (MC) operation failed, OFPFlowMod=%s", mod)

    def _create_inbound_flow_rules(
        self, datapath, eth_src: str, ingress: int, tblid: int = 0
    ):
        """Create new flow rules from eth_src to all local pendant macs. @param eth_src is always
        a remote pendant device and @param ingress is the associated port number"""
        sw: EvioSwitch = self._lt[datapath.id]
        parser = datapath.ofproto_parser
        for eth_dst in sw.local_leaf_macs:
            local_port_no = sw.get_ingress_port(eth_dst)
            actions = [parser.OFPActionOutput(local_port_no)]
            mt = parser.OFPMatch(in_port=ingress, eth_src=eth_src, eth_dst=eth_dst)
            self.logger.info(
                "Adding inflow rule %s/%s to egress %s",
                self._lt[datapath.id].name,
                f"in_port: {mt['in_port']}, eth_dst: {mt['eth_dst']}, eth_src:{mt['eth_src']}",
                local_port_no,
            )
            self._create_flow_rule(
                datapath,
                mt,
                actions,
                priority=1,
                tblid=tblid,
                idle_timeout=sw.idle_timeout,
                hard_timeout=sw.hard_timeout,
            )

    def _update_outbound_flow_rules(
        self, datapath, dst_mac, new_egress, tblid=None, reason=None
    ):
        """Updates existing flow rules from all local pendant eth src to @param dst_mac
        - a remote pendant device"""
        sw: EvioSwitch = self._lt[datapath.id]
        if dst_mac in sw.local_leaf_macs:
            self.logger.warning(
                "Invalid flow update request, the dst mac %s is a local pendant",
                dst_mac,
            )
            return
        parser = datapath.ofproto_parser
        if tblid is None:
            tblid = datapath.ofproto.OFPTT_ALL
        cmd = datapath.ofproto.OFPFC_MODIFY
        acts = [parser.OFPActionOutput(new_egress)]
        inst = [
            parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, acts)
        ]
        for src_mac in sw.local_leaf_macs:
            port_no = sw.get_ingress_port(src_mac)
            mt = parser.OFPMatch(in_port=port_no, eth_dst=dst_mac, eth_src=src_mac)
            mod = parser.OFPFlowMod(
                datapath=datapath,
                table_id=tblid,
                match=mt,
                command=cmd,
                instructions=inst,
                idle_timeout=sw.idle_timeout,
                hard_timeout=sw.hard_timeout,
            )
            self.logger.info(
                "Updating outflow matching %s/%s to egress %s. %s",
                sw.name,
                f"in_port: {mt['in_port']}, eth_dst: {mt['eth_dst']}, eth_src:{mt['eth_src']}",
                new_egress,
                reason,
            )
            datapath.send_msg(mod)

    def _update_flow_rules_to_peer(self, datapath, peer: PeerData, reason=None):
        """Used when a new port is connected to the switch and we know the pendant MACs that
        anchored to the now adjacent peer switch. Flow rules involving those pendant MACs are
        updated or created to use the new port.
        @param peer_id - peer id of adjacent switch
        @param port_no - port number associated with peer"""
        if peer.port_no is None:
            return
        dpid = datapath.id
        sw: EvioSwitch = self._lt[dpid]
        for mac in sw.leaf_macs(peer.node_id):
            # update existing flows going out to the remote peer
            self._update_outbound_flow_rules(
                datapath=datapath,
                dst_mac=mac,
                new_egress=peer.port_no,
                reason=reason,
            )
            self._create_inbound_flow_rules(
                datapath=datapath, eth_src=mac, ingress=peer.port_no
            )

    def _del_port_flow_rules(self, datapath, port_no, tblid=None):
        """Used when a port is removed from the switch. Any flow rule with in_port or
        out_port that matches port_no is removed"""
        try:
            sw_name = self._lt[datapath.id].name
            ofproto = datapath.ofproto
            if tblid is None:
                tblid = ofproto.OFPTT_ALL
            parser = datapath.ofproto_parser
            cmd = ofproto.OFPFC_DELETE
            match = parser.OFPMatch()
            mod = parser.OFPFlowMod(
                datapath=datapath,
                table_id=tblid,
                match=match,
                command=cmd,
                flags=ofproto.OFPFF_SEND_FLOW_REM,
                out_port=port_no,
                out_group=ofproto.OFPG_ANY,
                priority=1,
                idle_timeout=0,
                cookie=0,
                cookie_mask=0,
            )
            datapath.send_msg(mod)
            match = parser.OFPMatch(in_port=port_no)
            mod = parser.OFPFlowMod(
                datapath=datapath,
                table_id=tblid,
                match=match,
                command=cmd,
                flags=ofproto.OFPFF_SEND_FLOW_REM,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                priority=1,
                idle_timeout=0,
                cookie=0,
                cookie_mask=0,
            )
            self.logger.debug(
                "Attempting to delete flow rules on port=%s/%s", sw_name, port_no
            )
            datapath.send_msg(mod)
            if self._is_flow_rule_exist(sw_name, port_no):
                self._reset_switch_flow_rules(datapath)
        except Exception:
            self.logger.exception(
                "Failed to delete flows for port %s/%s.", sw_name, port_no
            )

    def _del_port_flow_rules_ovs(self, datapath, port_no, tblid=None):
        """Alternate approach to _del_flow_rules_for_port, uses ovs-ofctl cmd"""
        try:
            sw_name = self._lt[datapath.id].name
            self.logger.debug(
                "Attempting to delete flow rules on port=%s/%s", sw_name, port_no
            )
            runcmd(
                [
                    BoundedFlood.OFCTL,
                    "del-flows",
                    sw_name,
                    "out_port={0}".format(port_no),
                ]
            )
            runcmd(
                [
                    BoundedFlood.OFCTL,
                    "del-flows",
                    sw_name,
                    "in_port={0}".format(port_no),
                ]
            )
            if self._is_flow_rule_exist(sw_name, port_no):
                self._reset_switch_flow_rules(datapath)
        except Exception:
            self.logger.exception(
                "Failed to delete flows for port %s/%s.", sw_name, port_no
            )

    def _is_flow_rule_exist(self, switch, port_no):
        """Uses ovs-ofctl to check if an outbound flow rule exists for this port_no"""
        chk = runcmd(
            [BoundedFlood.OFCTL, "dump-flows", switch, "out_port={0}".format(port_no)]
        )
        chk.check_returncode()
        lines = chk.stdout.splitlines()
        if len(lines) > 1:
            self.logger.debug("Flow rules for %s/%s: %s", switch, port_no, chk.stdout)
            return True
        return False

    def _clear_switch_flow_rules(self, datapath):
        """Due to intermittent failure of deleting flow rules on OVS clear all flow
        rules from sw"""
        self.logger.debug(
            "Attempting to delete ALL flow rules for switch=%s",
            self._lt[datapath.id].name,
        )
        # runcmd([BoundedFlood.OFCTL, "del-flows", self._lt[datapath.id].name])
        ofproto = datapath.ofproto
        tblid = ofproto.OFPTT_ALL
        parser = datapath.ofproto_parser
        cmd = ofproto.OFPFC_DELETE
        match = parser.OFPMatch()
        mod = parser.OFPFlowMod(
            datapath=datapath,
            table_id=tblid,
            match=match,
            command=cmd,
            flags=ofproto.OFPFF_SEND_FLOW_REM,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            priority=1,
            idle_timeout=0,
            cookie=0,
            cookie_mask=0,
        )
        datapath.send_msg(mod)

    def _create_switch_startup_flow_rules(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self._create_flow_rule(datapath, match, actions)
        # deliver bounded flood frames to controller
        match = parser.OFPMatch(eth_type=FloodRouteBound.ETH_TYPE_BF)
        self._create_flow_rule(datapath, match, actions, priority=100)
        # drop multicast frames
        self._create_flow_rule_drop_multicast(datapath)

    def _reset_switch_flow_rules(self, datapath):
        """Resets the switch flow rules by deleting all flow ruls and recreating the base
        rules to deliver unhandled frames to the controller"""
        self._clear_switch_flow_rules(datapath)
        self._create_switch_startup_flow_rules(datapath)

    def do_link_check(self, datapath, port: PortDescriptor):
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

            bf_hdr = FloodRouteBound(nid, nid, 0, FloodRouteBound.FRB_LNK_CHK)
            eth = ethernet.ethernet(
                dst=peer_mac, src=src_mac, ethertype=FloodRouteBound.ETH_TYPE_BF
            )
            p = packet.Packet()
            p.add_protocol(eth)
            p.add_protocol(bf_hdr)
            p.serialize()
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            acts = [parser.OFPActionOutput(port_no)]
            pkt_out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                actions=acts,
                data=p.data,
                in_port=ofproto.OFPP_LOCAL,
            )
            resp = datapath.send_msg(pkt_out)
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug(
                    "Sending link check %s/%s %s", sw.name, port_no, peer_id
                )
            if not resp:
                self.logger.warning(
                    "Failed to send link chk FRB, OFPPacketOut=%s", pkt_out
                )
        else:
            raise RuntimeWarning(f"Link CHK requestd but remote is not a peer {port}")

    def _do_link_ack(self, datapath, port):
        sw: EvioSwitch = self._lt[datapath.id]
        nid = sw.node_id
        if port.is_peer:
            port_no = port.port_no
            peer_id = port.peer.node_id
            peer_mac = port.peer.hw_addr
            src_mac = port.hw_addr

            bf_hdr = FloodRouteBound(nid, nid, 0, FloodRouteBound.FRB_LNK_ACK)
            eth = ethernet.ethernet(
                dst=peer_mac, src=src_mac, ethertype=FloodRouteBound.ETH_TYPE_BF
            )
            p = packet.Packet()
            p.add_protocol(eth)
            p.add_protocol(bf_hdr)
            p.serialize()
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            acts = [parser.OFPActionOutput(port_no)]
            pkt_out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                actions=acts,
                data=p.data,
                in_port=ofproto.OFPP_LOCAL,
            )
            resp = datapath.send_msg(pkt_out)
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug(
                    "Sending link ack, %s/%s %s", sw.name, port_no, peer_id
                )
            if not resp:
                self.logger.warning(
                    "Failed to send link ack FRB, OFPPacketOut=%s", pkt_out
                )
        else:
            raise RuntimeWarning(f"Link ACK attempted but remote is not a peer {port}")

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
        eth = ethernet.ethernet(
            dst="ff:ff:ff:ff:ff:ff", src=src_mac, ethertype=FloodRouteBound.ETH_TYPE_BF
        )
        for out_port, bf in tx_bounds:
            p = packet.Packet()
            p.add_protocol(eth)
            p.add_protocol(bf)
            p.add_protocol(payload)
            p.serialize()
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            actions = [parser.OFPActionOutput(out_port)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ingress,
                actions=actions,
                data=p.data,
            )
            resp = datapath.send_msg(out)
            if not resp:
                self.logger.warning("Send FRB operation failed, OFPPacketOut=%s", out)

    def send_pendant_mac_to_adj_peer(
        self, datapath, peer: PeerData, eth_dest: str, pendant_mac: str
    ):
        # send an FRB via 'egress' to tell the adjacent node that the local node hosts pendant_mac
        egress: int = peer.port_no
        peer_id: str = peer.node_id
        sw: EvioSwitch = self._lt[datapath.id]
        nid = sw.node_id
        bf_hdr = FloodRouteBound(nid, nid, 0, FloodRouteBound.FRB_LEAF_TX)
        eth = ethernet.ethernet(
            dst=eth_dest, src=pendant_mac, ethertype=FloodRouteBound.ETH_TYPE_BF
        )
        p = packet.Packet()
        p.add_protocol(eth)
        p.add_protocol(bf_hdr)
        p.serialize()
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        acts = [parser.OFPActionOutput(egress)]
        pkt_out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            actions=acts,
            data=p.data,
            in_port=ofproto.OFPP_LOCAL,
        )
        resp = datapath.send_msg(pkt_out)
        if resp:
            self.logger.debug(
                "FRB leaf transfer sent to %s/%s (%s), peer:%s, local pendant:%s",
                sw.name,
                egress,
                sw._port_tbl[egress].name,
                peer_id,
                pendant_mac,
            )
        else:
            self.logger.warning("FRB leaf exchange failed, OFPPacketOut=%s", pkt_out)

    def handle_bounded_flood_msg(self, datapath, in_port, evmsg):
        pkt = packet.Packet(evmsg.data)
        eth = pkt.protocols[0]
        dpid = datapath.id
        parser = datapath.ofproto_parser
        rcvd_frb: FloodRouteBound = pkt.protocols[1]
        payload = None

        sw: EvioSwitch = self._lt[dpid]
        if len(pkt.protocols) == 3:
            payload = pkt.protocols[2]
        if sw.node_id == rcvd_frb.root_nid:
            self.logger.error(
                "Discarded a FRB from self - ingress: %s/%s (%s), FRB: %s",
                sw.name,
                in_port,
                sw._port_tbl[in_port].name,
                rcvd_frb,
            )
            return
        if rcvd_frb.frb_type not in (
            FloodRouteBound.FRB_BRDCST,
            FloodRouteBound.FRB_LNK_CHK,
            FloodRouteBound.FRB_LNK_ACK,
            FloodRouteBound.FRB_LEAF_TX,
        ):
            # discard these types
            self.logger.warning(
                "Discarded invalid FRB type - ingress: %s/%s, FRB: %s",
                sw.name,
                in_port,
                rcvd_frb,
            )
            return
        port: PortDescriptor = sw.port_descriptor(in_port)
        if rcvd_frb.frb_type == FloodRouteBound.FRB_LNK_CHK:
            self._do_link_ack(datapath, port)
            if not port.is_activated:
                port.is_activated = True
                self._update_flow_rules_to_peer(
                    datapath, port.peer, reason="GNV link chk"
                )
            return
        if rcvd_frb.frb_type == FloodRouteBound.FRB_LNK_ACK:
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug(
                    "Received link ack %s/%s %s", sw.name, in_port, rcvd_frb
                )
            if not port.is_activated:
                port.is_activated = True
                self._update_flow_rules_to_peer(
                    datapath, port.peer, reason="GNV link ack"
                )
            return
        if rcvd_frb.frb_type == FloodRouteBound.FRB_LEAF_TX:
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug(
                    "FRB leaf transfer recv from %s/%s (%s), rnid:%s, remote pendant:%s",
                    sw.name,
                    in_port,
                    sw._port_tbl[in_port].name,
                    rcvd_frb.root_nid,
                    eth.src,
                )
            # learn a mac address
            sw.set_ingress_port(eth.src, (in_port, rcvd_frb.root_nid))
            self._update_flow_rules_to_peer(
                datapath, port.peer, reason="Received pendant update"
            )
            return
        # case (rcvd_frb.frb_type == FloodRouteBound.FRB_BRDCST)
        inner_pkt = packet.Packet(payload)
        arp_pkt = inner_pkt.get_protocol(arp.arp)
        if arp_pkt and arp_pkt.opcode == arp.ARP_REQUEST:
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug(
                    "Received ARP %s",
                    str(arp_pkt),
                )
            # learn a mac address but only for ARPs - reduce the occurence of path flips
            sw.set_ingress_port(eth.src, (in_port, rcvd_frb.root_nid))
            sw.peer(rcvd_frb.root_nid).hop_count = rcvd_frb.hop_count
            sw.max_hops = rcvd_frb.hop_count
            self._update_outbound_flow_rules(
                datapath, eth.src, in_port, reason="ARP received"
            )
        # deliver the broadcast frame to leaf devices
        if payload:
            for out_port in sw.leaf_ports:
                actions = [parser.OFPActionOutput(out_port)]
                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=evmsg.buffer_id,
                    in_port=in_port,
                    actions=actions,
                    data=payload,
                )
                datapath.send_msg(out)
        # continue the bounded flood as necessary
        out_bounds = sw.get_flooding_bounds(rcvd_frb.frb_type, rcvd_frb, [in_port])
        if out_bounds:
            if self.logger.isEnabledFor(logging.DEBUG):
                in_frb = f"ingress:{in_port}-{sw._port_tbl[in_port].name} root:{rcvd_frb.root_nid[:7]} bound:{rcvd_frb.bound_nid[:7]}"
                log_msg = ""
                for egress, frb in out_bounds:
                    log_msg += f"\n\tegress:{egress}-{sw._port_tbl[egress].name} bound:{frb.bound_nid[:7]}"
                self.logger.debug(
                    "FRB(s) Derived from %s %s %s", sw.name, in_frb, log_msg
                )
            self.do_bounded_flood(datapath, in_port, out_bounds, eth.src, payload)

    def _add_flow_and_forward_frame(self, datapath, pkt, in_port, msg):
        eth = pkt.protocols[0]
        dpid = datapath.id
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        sw: EvioSwitch = self._lt[dpid]
        out_port = sw.get_ingress_port(eth.dst)
        if out_port:
            # create new flow rule
            actions = [parser.OFPActionOutput(out_port)]
            mt = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
            self.logger.info(
                "Adding flow & fwding %s/%s to egress %s",
                self._lt[datapath.id].name,
                f"in_port: {mt['in_port']}, eth_dst: {mt['eth_dst']}, eth_src:{mt['eth_src']}",
                out_port,
            )
            self._create_flow_rule(
                datapath,
                mt,
                actions,
                priority=1,
                tblid=0,
                idle_timeout=sw.idle_timeout,
                hard_timeout=sw.hard_timeout,
            )
            # forward frame to destination
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=data,
            )
            datapath.send_msg(out)
        else:
            self.logger.warning(
                "Failed to add flow and forward frame, no LT ingress exists for the eth dst. pkt=%s",
                str(pkt),
            )

    def _broadcast_frame(self, datapath, in_port, evmsg):
        """@param pkt is always an eth frame originating from a local pendant.
        The frame is broadcasted with an FRB."""
        pkt = packet.Packet(evmsg.data)
        eth = pkt.protocols[0]
        dpid = datapath.id
        sw: EvioSwitch = self._lt[dpid]
        # learn a mac address
        sw.set_ingress_port(eth.src, in_port)
        frb_type = FloodRouteBound.FRB_BRDCST
        # perform bounded flood
        out_bounds = sw.get_flooding_bounds(frb_type, None, [in_port])
        # fwd frame as an FRB on each peer port
        if out_bounds:
            if self.logger.isEnabledFor(logging.DEBUG):
                log_msg = ""
                for egress, frb in out_bounds:
                    log_msg += f"\n\tegress:{egress}-{sw._port_tbl[egress].name} bound:{frb.bound_nid[:7]}"
                self.logger.debug("Generated FRB(s) %s %s", sw.name, log_msg)
            self.do_bounded_flood(datapath, in_port, out_bounds, eth.src, evmsg.data)

    def send_arp_reply(self, datapath, src_mac, dst_mac, src_ip, dst_ip, in_port):
        self.send_arp(
            datapath, arp.ARP_REPLY, src_mac, src_ip, dst_mac, dst_ip, in_port
        )

    def send_arp_request(self, datapath, src_mac, src_ip, dst_ip):
        self.send_arp(datapath, arp.ARP_REQUEST, src_mac, src_ip, None, dst_ip, None)

    def send_arp(self, datapath, opcode, src_mac, src_ip, dst_mac, dst_ip, in_port):
        eth_dst_mac = dst_mac
        arp_dst_mac = dst_mac
        actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]
        # todo: wrap request with FRB before flooding
        if opcode == arp.ARP_REQUEST:
            eth_dst_mac = "ff:ff:ff:ff:ff:ff"
            arp_dst_mac = "00:00:00:00:00:00"
            actions = [
                datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)
            ]

        # Create Ethernet header
        eth = ethernet.ethernet(
            dst=eth_dst_mac, src=src_mac, ethertype=packet.ethernet.ether.ETH_TYPE_ARP
        )

        # Create ARP header
        arp_header = arp.arp(
            opcode=opcode,
            src_mac=src_mac,
            src_ip=src_ip,
            dst_mac=arp_dst_mac,
            dst_ip=dst_ip,
        )

        # Create packet and send it
        pkt = packet.Packet()
        pkt.add_protocol(eth)
        pkt.add_protocol(arp_header)

        pkt.serialize()
        datapath.send_packet_out(
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=pkt.data,
        )


###################################################################################################
###################################################################################################


class TrafficAnalyzer:
    """A very simple traffic analyzer to trigger an on demand tunnel"""

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

    def get_ond_tnl_ops(self, flow_metrics, evio_sw: EvioSwitch) -> list:
        tunnel_reqs = []
        active_flows = set()
        for stat in flow_metrics:
            if "eth_src" not in stat.match or "eth_dst" not in stat.match:
                continue
            src_mac = stat.match["eth_src"]
            dst_mac = stat.match["eth_dst"]
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
            if (
                peer_sw.node_id not in self._ond
                and len(self._ond) < self._max_ond
                and stat.byte_count > self.demand_threshold
            ):
                self.logger.debug(
                    "Creating a request for OND edge to %s", peer_sw.node_id
                )
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
                    "Creating requesting for removal of OND edge to %s", rnid
                )
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

    _PACK_STR = "!BBH4s4s"
    _MIN_LEN = struct.calcsize(_PACK_STR)

    def __init__(
        self,
        msgtype=DVMRP_TYPE,
        code=DVMRP_CODE_GRAFT,
        csum=0,
        src_address="0.0.0.0",
        grp_address="224.0.0.1",
    ):
        super().__init__()
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
        (msgtype,) = struct.unpack_from("!B", buf)
        if msgtype == DVMRP_TYPE:
            (msgtype, code, csum, src_address, grp_address) = struct.unpack_from(
                cls._PACK_STR, buf
            )
            instance = cls(
                msgtype,
                code,
                csum,
                addrconv.ipv4.bin_to_text(src_address),
                addrconv.ipv4.bin_to_text(grp_address),
            )

            rest = buf[cls._MIN_LEN :]
        return instance, subclass, rest

    def serialize(self, payload, prev):
        hdr = bytearray(
            struct.pack(
                self._PACK_STR,
                self.msgtype,
                self.code,
                self.csum,
                addrconv.ipv4.text_to_bin(self.src_address),
                addrconv.ipv4.text_to_bin(self.grp_address),
            )
        )

        if self.csum == 0:
            self.csum = packet_utils.checksum(hdr)
            struct.pack_into("!H", hdr, 2, self.csum)
        return hdr

    @property
    def min_len(self):
        return self._MIN_LEN

    ##########################################################################
    #     Custom datastores supporting expiration of stale entries           #
    ##########################################################################

    # class timedSet(MutableSet):
    #     def __init__(self, **kwargs):
    #         self.store = set()
    #         self.ttl = kwargs["ttl"]
    #         self.timeStore = dict()

    #     def __contains__(self, element):
    #         if self.store.__contains__(element):
    #             self.timeStore[element] = time.time()
    #             return True
    #         return False

    #     def add(self, value):
    #         self.timeStore[value] = time.time()
    #         self.store.add(value)

    #     def discard(self, value):
    #         self.timeStore.pop(value)
    #         self.store.discard(value)

    #     def get(self):
    #         return self.store

    #     def __iter__(self):
    #         return self.store.__iter__()

    #     def __len__(self):
    #         return self.store.__len__()

    #     def expire(self):
    #         toRemove = set()
    #         for k, v in self.timeStore.items():
    #             if time.time() - v >= self.ttl:
    #                 toRemove.add(k)
    #         for k in toRemove:
    #             self.discard(k)

    #     def __repr__(self):
    #         state = {
    #             "ttl": self.ttl,
    #             "store": sorted(self.store),
    #             "timeStore": self.timeStore,
    #         }
    #         return json.dumps(state)

    # class container:
    #     def __init__(self, **kwargs):
    #         self.store = dict()
    #         self.ttl = kwargs["ttl"]
    #         self.lastCleanup: Optional[float] = None

    #     def __repr__(self):
    #         state = {
    #             "ttl": self.ttl,
    #             "lastCleanup": self.lastCleanup,
    #             "store": self.store,
    #         }
    #         return json.dumps(state)

    #     def containsKey(self, key):
    #         if self.lastCleanup is not None and time.time() - self.lastCleanup >= self.ttl:
    #             self.lastCleanup = time.time()
    #             self.expire()
    #         return key in self.store and len(self.store[key]) > 0

    #     def put(self, key, value):
    #         if self.lastCleanup is None:
    #             self.lastCleanup = time.time()
    #         if key not in self.store:
    #             self.store[key] = timedSet(ttl=self.ttl)
    #         self.store[key].add(value)

    #     def containsValue(self, key, value):
    #         if not self.containsKey(key):
    #             return False
    #         return self.store[key].__contains__(value)

    #     def removeValue(self, key, value):
    #         self.store[key].discard(value)

    #     # always call containsKey before calling get.
    #     def get(self, key):
    #         if key in self.store:
    #             return self.store[key].get()
    #         return None

    #     def cleanup(self, key):
    #         self.store[key].expire()
    #         if len(self.store[key]) == 0:
    #             self.store.pop(key)

    #     def expire(self):
    #         sampleCount = math.ceil(0.25 * self.store.__len__())
    #         clearKeys = random.sample(self.store.keys(), sampleCount)
    #         for k in clearKeys:
    #             self.cleanup(k)
