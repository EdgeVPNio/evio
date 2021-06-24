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
import socket
import threading
import struct
import uuid
from distutils import spawn
import os
import subprocess
import logging
from collections.abc import MutableSet
import random
import time
import math
import sys
import logging.handlers as lh
from collections.abc import MutableMapping
from collections.abc import MutableSet
from ryu import cfg
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import dpset
from ryu.ofproto import ofproto_v1_4, inet, ether
from ryu.lib.packet import packet_base
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import igmp
from ryu.lib.packet import ipv4
from ryu.lib import hub
from ryu.lib import mac as mac_lib
from ryu.topology import event
from ryu.lib import addrconv
from ryu.lib.packet import packet_utils


CONF = cfg.CONF  # RYU environment

INTERNAL_PORT_NUM = 4294967294


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
##########################################################################


class EvioPortal():
    MAX_ATTEMPTS = 3

    def __init__(self, svr_addr: tuple, logger):
        self._logger = logger
        self._sseq = random.randint(1, sys.maxsize)
        self._rseq = 0
        self._svr_addr = svr_addr
        self._sock = None
        #req = dict(Request=dict(Action="sync", Params=None))
        #resp = self.send_recv(req)
        #self._rseq = resp["RSeq"]

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
                    time.sleep(1)
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
            req["SSeq"] = self._sseq
            self._logger.debug("EvioPortal send Request={}".format(req))
            self.send(req)
            self._sseq = self._sseq + 1
            resp = self.recv()
            self._logger.debug("EvioPortal recv'd Response={}".format(resp))
        except Exception as err:
            self._logger.warning(
                "send recv failure=%s, resp=%s", str(err), resp)
            resp = {'Response': {'Status': False,
                                 'Data': "No response from evio controller"}}
        finally:
            self._sock.close()
        return resp

    def terminate(self):
        self._sock.close()

###################################################################################################
###################################################################################################


class PeerData():
    def __init__(self, peer_id):
        self.node_id = peer_id
        self.hw_addr = None         # peer mac from evio controller
        self.leaf_macs = set()      # leaf devices managed by the peer switch
        self.hop_count = 0          # 1 -> an adjacent peer
        self.port_no = None         # valid only when a peer tunnel exists

    def __repr__(self):
        # msg = ("{{hw_addr: \'{0}\', node_id: {1}, hop_count: {2}, leaf_macs: {3}, port_no: {4}}}"
        #        .format(self.hw_addr, self.node_id, self.hop_count, self.leaf_macs, self.port_no))
        # return msg
        msg = {"hw_addr": self.hw_addr, "node_id": self.node_id,
               "hop_count": self.hop_count, "leaf_macs": [*self.leaf_macs], "port_no": self.port_no}
        return json.dumps(msg)

    def __str__(self):
        return "" #self.__repr__()
    
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
    TUNNEL_TYPES = ["TNL_TYPE_UNKNOWN", "TNL_TYPE_LEAF",
                    "TNL_TYPE_EVIO_LEAF", "TNL_TYPE_PEER"]

    def __init__(self, port_no: int, name: str, hw_addr: str):
        self.port_no = port_no              # port no for tunnel on the local switch
        self.name = name                    # interface (TAP/NIC) name
        self.hw_addr = hw_addr              # local side tunnel MAC
        self.tnl_type = "TNL_TYPE_UNKNOWN"  # is the remote device a peer switch or leaf
        self.peer_data = None               # valid if TNL_TYPE_PEER

    def __repr__(self):
        # msg = ("{{port_no: {0}, name: {1}, hw_addr: \'{2}\', tnl_type: {3}, peer_data: {4}}}"
        #        .format(self.port_no, self.name, self.hw_addr, self.tnl_type, self.peer_data))
        # return msg
        msg = {"port_no": self.port_no, "name": self.name, "hw_addr": self.hw_addr, "tnl_type": self.tnl_type, "peer_data": self.peer_data}
        return json.dumps(msg)

    def __str__(self):
        return self.__repr__()

    # @property
    # def tnl_type(self):
    #     return self.tnl_type

    # @tnl_type.setter
    # def tnl_type(self, ptype):
    #     assert self.tnl_type != 0, "Port {0} being reclassified to {1}".format(self.port_no, ptype)
    #     self.tnl_type = ptype

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
        return bool(self.tnl_type == "TNL_TYPE_PEER" and self.peer_data is not None)

###################################################################################################


class EvioSwitch(MutableMapping):
    def __init__(self, datapath_id, **kwargs) -> None:
        self._datapath_id = datapath_id
        #self.ryu = ryu_app
        #self.config = kwargs
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

        self.evio_portal = kwargs["EvioPortal"]  # ref to tcp send_recv socket
        self.counters = {}  # PerformanceCounters()
        self.max_on_demand_edges = kwargs["MaxOnDemandEdges"]
        self.traffic_analyzer = TrafficAnalyzer(
            self.logger, kwargs["DemandThreshold"])
        self._is_tunnel_data_good = False
        self._topo_seq = 0
        self.idle_timeout = kwargs["FlowIdleTimeout"]
        self.hard_timeout = kwargs["FlowHardTimeout"]
        # multicast
        # grp->[ports interested]
        # 24 hours timeout, leaf nodes don't refresh.
        #self.leaf_interest = container(ttl=24*60*self.kwargs["MulticastBroadcastInterval"])
        # (src,grp)-> port on which multicast transmission recvd
        #self.upstream_reception = container(ttl=self.kwargs["MulticastBroadcastInterval"]*4)
        # (src,grp)-> [downstream ports from which join for this transmission recvd]
        #self.downstream_interest = container(ttl=self.kwargs["MulticastBroadcastInterval"]*4)
        # grp -> [(src_1,grp),....,(src_n,grp)]
        #self.multicast_groups = container(ttl=self.kwargs["MulticastBroadcastInterval"]*4)
        # (src,mcast_dst)->time_in_secs_of_last_broadcast.
        #self.broadcast_timeout = {}

    def __repr__(self):
        msg = {"EvioSwitch": {"overlay_id": self._overlay_id, "node_id": self._overlay_id,
                              "datapath_id": self._datapath_id, "leaf_ports": [*self._leaf_prts],
                              "link_ports": [*self._link_prts], "leaf_macs": [*self._leaf_macs],
                              "ingress_tbl": self._ingress_tbl}}
        # msg = {"EvioSwitch": {"overlay_id": self._overlay_id, "node_id": self._overlay_id,
        #                       "datapath_id": self._datapath_id, "leaf_ports": [*self._leaf_prts],
        #                       "link_ports": [*self._link_prts], "leaf_macs": [*self._leaf_macs],
        #                       "ingress_tbl": self._ingress_tbl, #"port_tbl": self._port_tbl,
        #                       "root_sw_tbl": self._root_sw_tbl, "peer_table": self._peer_tbl}}
        return json.dumps(msg)

    def __str__(self):
        return self.__repr__()

    def __getitem__(self, mac):
        # return the best egress to reach the given mac
        psw = self._root_sw_tbl.get(mac)
        if psw and psw.port_no:
            return psw.port_no
        return self._ingress_tbl[mac]

    def __setitem__(self, key_mac, value):
        if isinstance(value, tuple):
            self.learn(src_mac=key_mac, in_port=value[0], rnid=value[1])
        else:
            self.learn(key_mac, value)

    def __delitem__(self, mac):
        del self._ingress_tbl[mac]
        nid = self._root_sw_tbl.pop(mac, None)
        # if nid and nid in self._leaf_macs_tbl and len(self._leaf_macs_tbl[nid] == 1):
        #     self._leaf_macs_tbl.pop(nid, None)

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
        if not self.is_br_ready:
            self.update()
        return list(self._leaf_prts)

    @property
    def link_ports(self) -> list:
        if not self.is_br_ready:
            self.update()
        return list(self._link_prts)

    @property
    def port_numbers(self) -> list:
        return [*self._port_tbl.keys()]

    @property
    def is_br_ready(self):
        return self._is_tunnel_data_good

    @property
    def node_id(self) -> str:
        return self._node_id

    @property
    def overlay_id(self) -> str:
        return self._overlay_id

    @property
    def peer_list(self) -> list:
        pl = []
        for port_no in self._link_prts:
            pl.append(self._port_tbl[port_no].peer_data.node_id)
        return pl

    def get_root_sw(self, leaf_mac) -> PeerData:
        return self._root_sw_tbl.get(leaf_mac, None)

    def port_descriptor(self, port_no) -> PortDescriptor:
        return self._port_tbl[port_no]

    def is_valid_port(self, port_no) -> bool:
        return bool(port_no in self._port_tbl)

    def query_evio_tunnels(self, tapn=None) -> dict:
        self._is_tunnel_data_good = False
        req = dict(Request=dict(Action="GetTunnels",
                   Params=dict(OverlayId=self._overlay_id)))
        resp = self.evio_portal.send_recv(req)
        if resp["Response"]["Status"]:
            self._is_tunnel_data_good = True
            if not resp["Response"]["Data"]:
                self.logger.info(
                    "evio controller reported no tunnels for %s", self.name)
                return {}
            tunnels = resp["Response"]["Data"]
            if self._topo_seq >= resp["Response"]["DSeq"]:
                self.logger.warning("The tunnel data reported by evio controller is unchanged "
                                    "or invalid since its previous update; dseq: %i, tunnel_data: %s",
                                    resp["Response"]["DSeq"], tunnels)
                return {}
            else:
                self.logger.debug("The evio tunnel data has been updated to dseq: %i, tunnel_data: %s",
                                  resp["Response"]["DSeq"], tunnels)
                self._topo_seq = resp["Response"]["DSeq"]
            if tapn:
                if not tapn in tunnels:
                    self.logger.debug("The queried TAP name (%s) was not available in the evio "
                                      "tunnel data. It will be treated as a leaf.", tapn)
                    return {}
                return tunnels[tapn]
            else:
                return tunnels
        else:
            self.logger.warning("- Failed to update tunnels for overlay:%s dpid:%s, response:%s",
                                self._overlay_id, self._datapath_id, resp["Response"])
            return {}

    def update_bridge_ports(self, port_set):
        # tries = 0
        # while not self.ryu.dpset.port_state and tries < 3:
        #     time.sleep(1)
        #     tries += 1
        # self.port_state = copy.deepcopy(self.ryu.dpset.port_state.get(
        #     self.datapath_id, None))
        self._port_tbl.clear()
        self._root_sw_tbl.clear()
        self._peer_tbl.clear()
        for port_no, prt in port_set.items():
            if port_no not in self._port_tbl:
                self._port_tbl[port_no] = PortDescriptor(
                    port_no, prt.name.decode("utf-8"), prt.hw_addr)

    def categorize_port(self,  port_no, tnl_type, tnl_data=None):
        """
        Categorize a newly added port to the local switch by setting the tunnel type,
        and optionally creating the PeerData entry in the peer table and port descriptor.
        """
        self._port_tbl[port_no].tnl_type = tnl_type
        if tnl_data:
            # assert tnl_data["MAC"] == self._port_tbl[port_no].hw_addr, \
            #     "hw_addr conflict between ryu/evio data."
            pd = self._register_peer(
                peer_id=tnl_data["PeerId"], peer_hw_addr=tnl_data["PeerMac"], in_port=port_no, hop_count=1)
            self._port_tbl[port_no].peer_data = pd
        self.logger.debug("Categorized port %s %s",
                          self.name, self._port_tbl[port_no])

    def add_port(self, ofpport):
        # assert ofpport.port_no not in self._port_tbl, \
        #     "Port {1}:{0} already exist".format(
        #         ofpport.port_no, self.name)
        port = PortDescriptor(
            ofpport.port_no, ofpport.name.decode("utf-8"), ofpport.hw_addr)
        self._port_tbl[ofpport.port_no] = port
        tnl_data = self.query_evio_tunnels(port.name)
        if not self.is_br_ready:
            return
        if tnl_data:
            self.categorize_port(ofpport.port_no, "TNL_TYPE_PEER", tnl_data)
            self._link_prts.add(ofpport.port_no)
        else:
            self.categorize_port(ofpport.port_no, "TNL_TYPE_LEAF")
            self._leaf_prts.add(ofpport.port_no)
        self.logger.debug("Added port_no: %s/%i to _port_tbl: %s",
                          self.name, ofpport.port_no, self._port_tbl)

    def delete_port(self, port_no):
        self.logger.debug("Deleting %s/%i from _port_tbl: %s",
                          self.name, port_no, self._port_tbl)
        port = self._port_tbl.pop(port_no, None)
        if port:
            self.logger.debug("Removed %s port: %s/%i",
                              port.tnl_type, self.name, port_no)
            if port.tnl_type == "TNL_TYPE_PEER":
                self._deregister_peer(port.peer_data.node_id)
                self._link_prts.remove(port_no)
            if port.tnl_type == "TNL_TYPE_LEAF":
                self._leaf_prts.remove(port_no)

    def update(self, ports=None):
        if ports:
            self.update_bridge_ports(ports)
        tnl_data = self.query_evio_tunnels()
        if not self.is_br_ready:
            return
        for port_no, port in self._port_tbl.items():
            if port.name in tnl_data:
                self.categorize_port(
                    port_no, "TNL_TYPE_PEER", tnl_data[port.name])
                self._link_prts.add(port_no)
            else:
                self.categorize_port(port_no, "TNL_TYPE_LEAF")
                self._leaf_prts.add(port_no)
        self.logger.debug("Updated _port_tbl: %s %s",
                          self.name, self._port_tbl)

    def learn(self, src_mac, in_port, rnid=None):
        """
        Associate the mac with the ingress port. If the RNID is provided it indicates the peer 
        switch that hosts the leaf mac.
        """
        self._ingress_tbl[src_mac] = in_port
        if in_port in self._leaf_prts:
            self._leaf_macs.add(src_mac)
            self.logger.debug(
                "learn sw:%s, leaf_mac:%s, ingress:%i", self.name, src_mac, in_port)
        elif rnid:
            pd = self._register_peer(rnid, leaf_macs=[src_mac, ])
            self._root_sw_tbl[src_mac] = pd
            self.logger.debug(
                "learn sw:%s, leaf_mac:%s, ingress:%i, peerid:%s", self.name, src_mac, in_port, rnid)

    @property
    def local_leaf_macs(self):
        return self._leaf_macs
        # return [*self._leaf_macs, ]

    def leaf_macs(self, node_id=None):
        if node_id is None:
            return self._leaf_macs
            # return [*self._leaf_macs, ]
        return self._peer_tbl[node_id].leaf_macs
        # return [*self._peer_tbl[node_id].leaf_macs, ]

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

    def handle_ond_tunnel_req(self, flow_metrics):
        tunnel_ops = self.traffic_analyzer.ond_recc(flow_metrics, self)
        for op in tunnel_ops:
            if op[1] == "ADD":
                # self.req_add_tunnel(op[0])
                self.logger.debug("req_add_tunnel: %s", op[0])
            elif op[1] == "REMOVE":
                # self.req_remove_tunnel(op[0])
                self.logger.debug("req_remove_tunnel: %s", op[0])

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

    def get_flooding_bounds(self, prev_frb=None, exclude_ports=None, frb_type=0) -> list:
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
            assert (my_nid < peer1 or peer2 <= my_nid),\
                "invalid node_id ordering self={0}, peer1={1}, peer2={2}".\
                format(my_nid, peer1, peer2)
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
                assert prev_frb.bound_nid != my_nid,\
                    "this frb should not have reached this node ny_nid={0} prev_frb={1}".\
                    format(my_nid, prev_frb)
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
    def __init__(self,  **kwargs) -> None:
        #self._lock = threading.Lock()
        self._node_id = kwargs["NodeId"]
        self.logger = kwargs["Logger"]
        self._switch_tbl = dict()
        # self.update(dict(**kwargs))

    def __getitem__(self, dpid):
       # with self._lock:
        return self._switch_tbl[dpid]

    def __delitem__(self, dpid):
       # with self._lock:
        del self._switch_tbl[dpid]

    def __setitem__(self, dpid, evio_sw):
        # with self._lock:
        self._switch_tbl[dpid] = evio_sw

    def __iter__(self):
        # with self._lock:
        return iter(self._switch_tbl)

    def __len__(self):
        # with self._lock:
        return len(self._switch_tbl)

    def __repr__(self):
        # with self._lock:
        return f"{type(self).__name__}({self._switch_tbl})"

    def register_datapath(self, datapath_id, evio_switch):
        # with self._lock:
        self._switch_tbl[datapath_id] = evio_switch

    def deregister_datapath(self, datapath_id):
        # with self._lock:
        self._switch_tbl.pop(datapath_id)


###################################################################################################
class PerformanceCounters():
    def __init__(self) -> None:
        pass

###################################################################################################
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

        # self._overlays = {}             # maps dpid to an evio bridge instance
        self._lock = threading.Lock()
        self.load_config()
        self.monitor_interval = self.config["MonitorInterval"]
        self._last_log_time = time.time()
        self._setup_logger()
        self.evio_portal = EvioPortal(
            (self.config["ProxyListenAddress"], self.config["ProxyListenPort"]), self.logger)
        # self.mcast_broadcast_period = self.config["MulticastBroadcastInterval"]
        self.dpset = kwargs['dpset']
        self._lt = LearningTable(NodeId=self.config["NodeId"],
                                 Logger=self.logger)
        self.monitor_thread = hub.spawn(self._monitor)
        self.logger.info("BoundedFlood module ready")

    def _setup_logger(self):
        fqname = os.path.join(
            self.config["LogDir"], self.config["LogFilename"])
        if os.path.isfile(fqname):
            os.remove(fqname)
        self.logger = logging.getLogger(__name__)
        level = getattr(logging, self.config["LogLevel"])
        self.logger.setLevel(level)
        handler = lh.RotatingFileHandler(filename=fqname, maxBytes=self.config["MaxBytes"],
                                         backupCount=self.config["BackupCount"])
        formatter = logging.Formatter(
            "[%(asctime)s.%(msecs)03d %(thread)d] %(levelname)s:%(message)s", datefmt="%Y%m%d %H:%M:%S")
        logging.Formatter.converter = time.localtime
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def load_config(self):
        with open("/home/kcratie/workspace/EdgeVPNio/bf-config.json", "r") as content:
            self.config = json.load(content)
        return
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

    # def _find_protocol(self, pkt, name):
    #     for p in pkt.protocols:
    #         if hasattr(p, 'protocol_name'):
    #             if p.protocol_name == name:
    #                 return p

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)  # pylint: disable=no-member
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        while INTERNAL_PORT_NUM not in datapath.ports:
            time.sleep(1)
        br_name = datapath.ports[INTERNAL_PORT_NUM].name.decode("utf-8")
        with self._lock:
            assert datapath.id not in self._lt, "Datapath ID {} is already in learning table".format(
                datapath.id)
            if br_name not in self.config:
                self.logger.warning("Bridge {} is not specified in the BoundedFlood config, skipping bridge registration"
                                    .format(br_name))
                return

            # install table-miss flow entry
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, match, actions)
            # deliver bounded flood frames to controller
            match = parser.OFPMatch(eth_type=FloodRouteBound.ETH_TYPE_BF)
            self.add_flow(datapath, match, actions, priority=100)
            # drop multicast frames
            self.add_flow_drop_multicast(datapath)

            overlay_id = self.config[br_name]["OverlayId"]
            self._lt[datapath.id] = EvioSwitch(datapath.id,
                                               OverlayId=overlay_id,
                                               NodeId=self.config["NodeId"],
                                               Logger=self.logger,
                                               EvioPortal=self.evio_portal,
                                               MaxOnDemandEdges=self.config[br_name]["MaxOnDemandEdges"],
                                               DemandThreshold=self.config[br_name]["DemandThreshold"],
                                               FlowIdleTimeout=self.config[br_name]["FlowIdleTimeout"],
                                               FlowHardTimeout=self.config[br_name]["FlowHardTimeout"])
            self.logger.info(
                "Switch %s added with overlay ID %s", br_name, overlay_id)
            self._lt[datapath.id].update(datapath.ports)
            for port_no in self._lt[datapath.id].link_ports:
                if self._lt[datapath.id].port_descriptor(port_no).is_peer:
                    self.do_bf_leaf_transfer(datapath, port_no)

    @set_ev_cls(event.EventSwitchLeave, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def handler_switch_leave(self, ev):
        with self._lock:
            dpid = ev.switch.dp.id
            br_name = self._lt[dpid].name
            self._lt[dpid].terminate()
            self._lt.pop(dpid, None)
        self.logger.info("Removed switch: %s", br_name)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)  # pylint: disable=no-member
    def port_status_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        port_no = msg.desc.port_no
        with self._lock:
            if msg.reason == ofp.OFPPR_ADD:
                # self.logger.info("OFPPortStatus: port ADDED desc=%s", msg.desc)
                self._lt[dp.id].add_port(msg.desc)
                if self._lt[dp.id].port_descriptor(port_no).is_peer:
                    self.do_bf_leaf_transfer(dp, port_no)
            elif msg.reason == ofp.OFPPR_DELETE:
                # self.logger.info(
                #    "OFPPortStatus: port DELETED desc=%s", msg.desc)
                self.del_flows_port(dp, port_no, tblid=0)
                self._lt[dp.id].delete_port(port_no)
            elif msg.reason == ofp.OFPPR_MODIFY:
                # self.logger.debug(
                #    "OFPPortStatus: port MODIFIED desc=%s", msg.desc)
                pass

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)  # pylint: disable=no-member
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        for p in pkt.protocols:
            if hasattr(p, 'protocol_name'):
                self.logger.debug("pkt proto=%s", p)
        eth = pkt.protocols[0]
        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        # req_igmp = pkt.get_protocol(igmp.igmp)
        # req_ip = pkt.get_protocol(ipv4.ipv4)
        # is_igmp = False
        # is_dvmrp = False
        # if req_ip and req_ip.proto == 200:
        #     is_dvmrp=True
        # if req_igmp:
        #     is_igmp = True
        #     self._handle_igmp(msg)
        # elif is_dvmrp:
        #     self._handle_dvmrp(msg)

        with self._lock:
            if not self._lt[dpid].is_valid_port(in_port):
                return
            if eth.ethertype == FloodRouteBound.ETH_TYPE_BF:
                self.handle_bounded_flood_msg(datapath, pkt, in_port, msg)
            elif dst in self._lt[dpid]:
                out_port = self._lt[dpid][dst]
                # learn a mac address
                self._lt[dpid][src] = in_port
                # create new flow rule
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(
                    in_port=in_port, eth_dst=dst, eth_src=src)
                self.add_flow(datapath, match, actions, priority=1, tblid=0,
                              idle=self._lt[dpid].idle_timeout)
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
            else:
                # this dst mac is not in our LT
                self.logger.debug(
                    "Default packet handler src:%s dst:%s ingress: %s/%s", src, dst, self._lt[dpid].name, in_port)
                if in_port not in self._lt[dpid].leaf_ports and is_multiricepient(dst):
                    # a broadcast or multicast frame was received on a peer sw link.
                    # This is invalid as these tunnel interfaces should not be used the src of a request.
                    self.logger.debug(
                        "Dropping multi/broadcast frame to %s on ingress %s/%s", dst, self._lt[dpid].name, in_port)
                    return
                # learn a mac address
                self._lt[dpid][src] = in_port
                frb_type = FloodRouteBound.FRB_BRDCST
                if in_port not in self._lt[dpid].leaf_ports:
                    # this node did not initiate the frame but it has no data on how to switch it
                    # so it must brdcast with an FRB but let peers know we  are not the root sw
                    frb_type = FloodRouteBound.FRB_FWD
                # check if this is a multicast frame
                # if eth.dst.split(':')[0] == '01':
                #     if self._handle_multicast_frame(msg,is_igmp,is_dvmrp):
                    # return
                # perform bounded flood same as leaf case
                out_bounds = self._lt[dpid].get_flooding_bounds(
                    None, [in_port], frb_type)
                self.logger.info("<--\nGenerated FRB(s)=%s/%s",
                                 self._lt[dpid].name, out_bounds)
                if out_bounds:
                    self.do_bounded_flood(
                        datapath, in_port, out_bounds, src, msg.data)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)  # pylint: disable=no-member
    def _flow_stats_reply_handler(self, ev):
        if self._lt[ev.msg.datapath.id].is_ond_enabled:
            self._lt[ev.msg.datapath.id].handle_ond_tunnel_req(ev.msg.body)
    ##################################################################################

    def _send_igmp_query(self, msg):
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        dpid = datapath.id
        node = self._lt[dpid]
        actions = []
        # igmp_query = self.frame_igmp_query()
        for leaf_port in node.leaf_prts:
            actions.append(parser.OFPActionOutput(leaf_port))
        if len(actions) != 0:
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=datapath.ofproto.OFPP_LOCAL,
                                      actions=actions, data=igmp_query.data)
            self.logger.info(
                "Sending IGMP QUERY {} to leaf ports".format(igmp_query))
            datapath.send_msg(out)

    def _handle_igmp(self, msg):
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        req_igmp = pkt.get_protocol(igmp.igmp)
        dpid = datapath.id
        node = self._lt[dpid]
        if req_igmp.msgtype == 34:
            self.logger.info("Received a IGMP_TYPE_REPORT_V3")
        if req_igmp.msgtype == igmp.IGMP_TYPE_REPORT_V3:
            if in_port in node.leaf_prts:
                self.logger.info("Received IGMP_TYPE_REPORT_V3 on LEAF PORT")
            else:
                self.logger.info("Received IGMP_TYPE_REPORT_V3 on PEER PORT")
            for record in req_igmp.records:
                if record.type_ == 3:
                    if in_port in node.leaf_prts:
                        self.logger.info(
                            "Leaving multicast group {}".format(record.address))
                        if node.leaf_interest.containsKey(record.address):
                            if node.leaf_interest.containsValue(record.address, in_port):
                                node.leaf_interest.removeValue(
                                    record.address, in_port)
                elif record.type_ == 4 or record.type_ == 2:
                    if in_port in node.leaf_ports:
                        self.logger.info(
                            "Joining/Reaffirming multicast group {}".format(record.address))
                        node.leaf_interest.put(record.address, in_port)
                    # Optimization: if need to update flows, find all transmissions corresponding this group
                    # address and update rules for them.
                    # need to send this IGMP join as DVMRP upstream to create tree.
                    if node.multicast_groups.containsKey(record.address):
                        for transmission in node.multicast_groups.get(record.address):
                            self.logger.info(
                                "Updating flow for {} on new IGMP join.".format(transmission))
                            actions = []
                            if node.downstream_interest.containsKey(transmission):
                                for outport in node.downstream_interest.get(transmission):
                                    actions.append(
                                        parser.OFPActionOutput(outport))
                            if node.leaf_interest.containsKey(record.address):
                                for outport in node.leaf_interest.get(record.address):
                                    actions.append(
                                        parser.OFPActionOutput(outport))
                            if in_port in node.leaf_ports:
                                self.hard_timeout = self.mcast_broadcast_period
                            ip_src, ip_dst = transmission
                            match = parser.OFPMatch(eth_type=0x800, ipv4_dst=ip_dst,
                                                    ipv4_src=ip_src)
                            self.add_flow(datapath, match, actions, priority=1, tblid=0,
                                          idle=self.idle_timeout, hard_timeout=self.hard_timeout)
                            # need to send this IGMP join as DVMRP upstream to create tree.
                            if node.upstream_reception.containsKey(transmission):
                                send_port = list(
                                    node.upstream_reception.get(transmission))[0]
                                if send_port not in node.leaf_ports:
                                    # send upstream
                                    self.logger.info("Sending a graft message upstream on IGMP join for src {} dst {}".
                                                     format(ip_src, ip_dst))
                                    graft_msg = self.frame_graft_msg(
                                        ip_src, ip_dst)
                                    actions = [parser.OFPActionOutput(in_port)]
                                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                                              in_port=datapath.ofproto.OFPP_LOCAL,
                                                              actions=actions,
                                                              data=graft_msg.data)
                                    datapath.send_msg(out)

    def _handle_dvmrp(self, msg):
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        dpid = datapath.id
        netnode = self._lt[dpid]
        (req_dvmrp, _, _) = DVMRP.parser(pkt.protocols[2])
        self.logger.info("Received a downstream DVMRP msg from port {} for {} {}".format(in_port,
                                                                                         req_dvmrp.src_address, req_dvmrp.grp_address))
        transmission = (req_dvmrp.src_address, req_dvmrp.grp_address)
        self.logger.info("Added {} to downstream interest for "
                         "transmission {}".format(in_port, transmission))
        if not netnode.downstream_interest.containsValue(transmission, in_port):
            netnode.downstream_interest.put(transmission, in_port)
            # Optimization: Modify flow for multicast as soon as downstream interest table
            # has changes, note that this optimization takes only updates to non-leaf
            # downstream ports into account and not leaf ports
            ip_src, ip_dst = transmission
            actions = []
            if netnode.downstream_interest.containsKey(transmission):
                self.logger.info(
                    "Updating flow for {} on new dvmrp join.".format(transmission))
                for outport in netnode.downstream_interest.get(transmission):
                    actions.append(parser.OFPActionOutput(outport))
                if netnode.leaf_interest.containsKey(ip_dst):
                    for outport in netnode.leaf_interest.get(ip_dst):
                        actions.append(parser.OFPActionOutput(outport))
            if in_port in netnode.leaf_ports:
                self.hard_timeout = self.mcast_broadcast_period
            match = parser.OFPMatch(eth_type=0x800, ipv4_dst=ip_dst,
                                    ipv4_src=ip_src)
            self.add_flow(datapath, match, actions, priority=1, tblid=0,
                          idle=self.idle_timeout, hard_timeout=self.hard_timeout)

            # need to send this join upstream to create tree, note that this also serves as reaffirming continued
            # interest in the multicast transmission.
            if netnode.multicast_groups.containsKey(req_dvmrp.grp_address):
                targetTransmission = (
                    req_dvmrp.src_address, req_dvmrp.grp_address)
                if netnode.upstream_reception.containsKey(targetTransmission):
                    send_port = list(
                        netnode.upstream_reception.get(targetTransmission))[0]
                    if send_port not in netnode.leaf_ports:
                        # send upstream
                        if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
                            data = msg.data
                        actions = [parser.OFPActionOutput(send_port)]
                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                                  in_port=in_port, actions=actions, data=data)
                        datapath.send_msg(out)
                        self.logger.info("Forwarded DVMRP upstream for {} on port {}".
                                         format((req_dvmrp.src_address, req_dvmrp.grp_address), send_port))

    def _handle_multicast_frame(self, msg, is_igmp, is_dvmrp):
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        dpid = datapath.id
        netnode = self._lt[dpid]
        eth = pkt.protocols[0]
        dst = eth.dst
        src = eth.src
        ip_load = pkt.get_protocol(ipv4.ipv4)
        ip_src = ip_load.src
        ip_dst = ip_load.dst
        if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            data = msg.data
        self.logger.info("Received a multicast packet with dst {} from {} on port {}".format(dst,
                                                                                             src, in_port))
        if is_igmp or is_dvmrp:
            self.logger.info("Not going to broadcast igmp or dvmrp")
            return True
        # make note only if it comes from leaf port or is broadcast.
        elif in_port in netnode.leaf_ports:
            netnode.upstream_reception.put((ip_src, ip_dst), in_port)
            netnode.multicast_groups.put(ip_dst, (ip_src, ip_dst))
            ''' To force refreshing of state of multicast tree have to revert to periodic broadcasts.
                timestamp is associated with  a multicast flow which is determined by combination of
                IP src and multicast DST address.
            '''
        # two kind of interested parties in this transmission, leaf nodes, downstream nodes.
        # need to maintains actions for each.
        actions_leaf = []
        actions_downstream = []
        # check if any leaf nodes are interested and in_port is not the same as interested port.
        if netnode.leaf_interest.containsKey(ip_dst):
            for outport in netnode.leaf_interest.get(ip_dst):
                if outport != in_port:
                    actions_leaf.append(parser.OFPActionOutput(outport))
        # check if I have any downstream interests, if so append to actions.
        if netnode.downstream_interest.containsKey((ip_src, ip_dst)):
            self.logger.info(
                "Found downstream for {}".format((ip_src, ip_dst)))
            for outport in netnode.downstream_interest.get((ip_src, ip_dst)):
                actions_downstream.append(parser.OFPActionOutput(outport))
        # check If it is time to broadcast.
        curr_time = time.time()
        ''' possible that this is first time this multicast is seen outside FRB broadcast'''
        if (ip_src, ip_dst) in netnode.broadcast_timeout.keys():
            prev_forced_broadcast = netnode.broadcast_timeout[(ip_src, ip_dst)]
        else:
            prev_forced_broadcast = None
        if prev_forced_broadcast is None or curr_time - prev_forced_broadcast > self.mcast_broadcast_period:
            self.logger.info(
                "Broadcast timeout for {}, will broadcast".format((ip_src, ip_dst)))
            netnode.broadcast_timeout[(ip_src, ip_dst)] = time.time()
            # still need to send packets to leaf nodes.
            actions = actions_leaf
            if len(actions) != 0:
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                self.logger.info(
                    "Sending mcast group pkt {} to leaf port".format(ip_dst))
                datapath.send_msg(out)
        else:
            actions = actions_leaf + actions_downstream
            # Install a flow rule, if the multicast transmission originates on a leaf node, hard timeout
            # has to be set to  a lower value to enable packets to come to controller to initiate periodic
            # broadcasts.
            if in_port in netnode.leaf_ports:
                self.hard_timeout = self.mcast_broadcast_period
            if len(actions) != 0:
                match = parser.OFPMatch(
                    eth_type=0x800, ipv4_dst=ip_dst, ipv4_src=ip_src)
                self.add_flow(datapath, match, actions, priority=1, tblid=0,
                              idle=self.idle_timeout, hard_timeout=self.hard_timeout)
                # Also send the packet out this time
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                self.logger.info(
                    "Sending mcast group pkt {} flow out".format(ip_dst))
                datapath.send_msg(out)
                return True  # no need to broadcast

        # Do not broadcast multicast packets received on non leaf ports on a regular channel.
        if in_port not in netnode.leaf_ports:
            return True
        # will have to broadcast
        return False
    ###################################################################################

    def _monitor(self):
        while True:
            msg = ""
            state_msg = ""
            self._lock.acquire()
            for dpid in self._lt:
                self._lt[dpid].counters["MaxFloodingHopCount"] = 0
                total_hc = 0
                num_rsw = 0
                rsw: PeerData
                for rsw in self._lt[dpid]._peer_tbl.values():
                    if rsw.hop_count > 0:
                        total_hc += rsw.hop_count
                        num_rsw += 1
                    if rsw.hop_count > self._lt[dpid].counters.get("MaxFloodingHopCount", 1):
                        self._lt[dpid].counters["MaxFloodingHopCount"] = rsw.hop_count
                if num_rsw == 0:
                    num_rsw = 1
                self._lt[dpid].counters["TotalHopCount"] = total_hc
                self._lt[dpid].counters["NumPeersCounted"] = num_rsw
                self._lt[dpid].counters["AvgFloodingHopCount"] = total_hc/num_rsw

                self.request_stats(self.dpset.dps[dpid])
                if self.logger.isEnabledFor(logging.DEBUG):
                    state_msg += "{0}\n".format(self._lt[dpid])
                    #state_msg += str(self._lt[dpid])
                msg += "{0}:Max_FHC={1},NPC={2},THC={3},AHC={4}\n".\
                    format(self._lt[dpid].name,
                           self._lt[dpid].counters.get(
                               "MaxFloodingHopCount", 1),
                           self._lt[dpid].counters.get("NumPeersCounted", 0),
                           self._lt[dpid].counters.get("TotalHopCount", 0),
                           self._lt[dpid].counters.get("AvgFloodingHopCount", 0))
            self._lock.release()
            if time.time() - self._last_log_time > self.monitor_interval:
                self._last_log_time = time.time()
                if msg:
                    self.logger.info("@@>\n%s", msg)
                if state_msg:
                    self.logger.debug("%s", state_msg)
            hub.sleep(self.monitor_interval)

    def request_stats(self, datapath, tblid=0):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath, table_id=tblid)
        resp = datapath.send_msg(req)
        if not resp:
            self.logger.warning(
                "Request stats operation failed, OFPFlowStatsRequest=%s", req)

    def add_flow(self, datapath, match, actions, priority=0, tblid=0, idle=0, hard_timeout=0):
        mod = None
        try:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            inst = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]
            log_string = "datapath.id={} priority={} table_id={} idle_timeout={} ".format(
                datapath.id, priority, tblid, idle)
            log_string += " hard_timeout={} {} {} ".format(
                hard_timeout, match, inst)
            self.logger.debug(log_string)
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, table_id=tblid,
                                    idle_timeout=idle, hard_timeout=hard_timeout, match=match, instructions=inst)
            resp = datapath.send_msg(mod)
            if not resp:
                self.logger.warning(
                    "Add flow operation failed, OFPFlowMod=%s", mod)
        except struct.error as err:
            self.logger.warning("Add flow operation failed, OFPFlowMod=%s\n struct.error=%s",
                                mod, err)

    def add_flow_drop_multicast(self, datapath, priority=1, tblid=0):
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

    def del_flows_port(self, datapath, port_no, tblid=None):
        # this is silently failing, no flows are deleted
        #ofproto = datapath.ofproto
        # if tblid is None:
        #    tblid = ofproto.OFPTT_ALL
        #parser = datapath.ofproto_parser
        #cmd = ofproto.OFPFC_DELETE
        #match = parser.OFPMatch()
        # mod = parser.OFPFlowMod(datapath=datapath, table_id=ofproto.OFPTT_ALL, match=match,
        #                        command=cmd, flags=ofproto.OFPFF_SEND_FLOW_REM, out_port=port_no,
        #                        idle_timeout=self.idle_timeout)
        #self.logger.info("Delete flow mod output, egress=%s, OFPFlowMod=%s", port_no, mod)
        #resp = datapath.send_msg(mod)
        # if not resp:
        #    self.logger.warning("Delete flow operation failed, egress=%s, OFPFlowMod=%s",
        #                        port_no, mod)
        #match = parser.OFPMatch(in_port=port_no)
        # mod = parser.OFPFlowMod(datapath=datapath, table_id=tblid, match=match, command=cmd,
        #                        flags=ofproto.OFPFF_SEND_FLOW_REM, idle_timeout=self.idle_timeout)
        #self.logger.info("Delete flow mod, egress=%s, OFPFlowMod=%s", port_no, mod)
        #resp = datapath.send_msg(mod)
        # if not resp:
        #    self.logger.warning("Delete flow operation failed, egress=%s, OFPFlowMod=%s",
        #                        port_no, mod)
        resp = runcmd([BoundedFlood.OFCTL, "del-flows", self._lt[datapath.id].name,
                       "in_port={0}".format(port_no)])
        self.logger.debug("Deleted flows with in_port=%s", port_no)
        resp = runcmd([BoundedFlood.OFCTL, "del-flows", self._lt[datapath.id].name,
                       "out_port={0}".format(port_no)])
        self.logger.debug("deleted flows with out_port=%s", port_no)

    def update_flow_match_dstmac(self, datapath, dst_mac, new_egress, tblid=None):
        self.logger.debug("Updating all flows matching dst mac %s-%s",
                          self._lt[datapath.id].name, dst_mac)
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
        resp = datapath.send_msg(mod)
        if not resp:
            self.logger.warning(
                "Update flow operation failed, OFPFlowMod=%s", mod)

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

    def do_bf_leaf_transfer(self, datapath, port_no):
        sw: EvioSwitch = self._lt[datapath.id]
        peer_id = sw._port_tbl[port_no].peer_data.node_id
        peer_mac = sw._port_tbl[port_no].peer_data.hw_addr
        src_mac = sw._port_tbl[port_no].hw_addr

        # if not self._lt.local_leaf_macs:
        #     return
        payload = bytearray(6*len(sw.local_leaf_macs))
        offset = 0
        for leaf_mac in sw.local_leaf_macs:
            bmac = mac_lib.haddr_to_bin(leaf_mac)
            struct.pack_into("!6s", payload, offset, bmac)
            offset += 6

        nid = sw.node_id
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
            self.logger.info("FRB leaf exchange completed, %s/%s %s %s %s", self._lt[datapath.id].name, port_no, peer_id,
                             peer_mac, payload)
        else:
            self.logger.warning(
                "FRB leaf exchange failed, OFPPacketOut=%s", pkt_out)

    # def frame_graft_msg(self,source_address, group_address):
    #     dvmrp = DVMRP(src_address=source_address,
    #                   grp_address=group_address)
    #     # src and dst MAC addresses do not matter.
    #     eth = ethernet.ethernet(dst='01:00:5E:0A:0A:0A',
    #                             src='00:00:00:00:00:00',
    #                             ethertype=ether.ETH_TYPE_IP)
    #     pkt = packet.Packet()
    #     total_length = 20 + dvmrp.min_len
    #     nw_proto = 200 # custom network protocol payload type
    #     nw_dst = '255.255.255.255'
    #     nw_src = '0.0.0.0'
    #     i = ipv4.ipv4(total_length=total_length,
    #                   src=nw_src,
    #                   dst=nw_dst,
    #                   proto=nw_proto)
    #     pkt.add_protocol(eth)
    #     pkt.add_protocol(i)
    #     pkt.add_protocol(dvmrp)
    #     pkt.serialize()
    #     return pkt

    # def frame_igmp_query(self):
    #     igmp_query = igmp.igmpv3_query(maxresp=igmp.QUERY_RESPONSE_INTERVAL * 10,
    #                       csum=0,
    #                       address='0.0.0.0')
    #     eth = ethernet.ethernet(dst=igmp.MULTICAST_MAC_ALL_HOST,
    #                             src='00:00:00:00:00:00',
    #                             ethertype=ether.ETH_TYPE_IP)
    #     ip = ipv4.ipv4(total_length=len(ipv4.ipv4()) + len(igmp_query),
    #                    proto=inet.IPPROTO_IGMP, ttl=1,
    #                    src='0.0.0.0',
    #                    dst=igmp.MULTICAST_IP_ALL_HOST)
    #     pkt = packet.Packet()
    #     pkt.add_protocol(eth)
    #     pkt.add_protocol(ip)
    #     pkt.add_protocol(igmp_query)
    #     pkt.serialize()
    #     return pkt

    def handle_bounded_flood_msg(self, datapath, pkt, in_port, msg):
        eth = pkt.protocols[0]
        src = eth.src
        dpid = datapath.id
        parser = datapath.ofproto_parser
        rcvd_frb = pkt.protocols[1]
        self.logger.info("-->\nReceived sw:%s FRB=%s",
                         self._lt[dpid].name, rcvd_frb)
        if len(pkt.protocols) < 2:
            return
        payload = pkt.protocols[2]
        # Check for a multicast payload.
        is_multicast = False
        payload_pkt = packet.Packet(payload)
        pload_eth = payload_pkt.protocols[0]
        eth_dst = None

        # if rcvd_frb.frb_type == FloodRouteBound.FRB_IDENT:
        #     self._lt[dpid].categorize_port(in_port, "TNL_TYPE_PEER", payload)
        #     self.logger.info("Update port=%d to peer type", in_port)
        #     return

        # if pload_eth and rcvd_frb.frb_type == FloodRouteBound.FRB_BRDCST:
        #     eth_dst = pload_eth.dst
        #     pload_ip = payload_pkt.get_protocol(ipv4.ipv4)
        # if eth_dst and eth_dst.split(':')[0] == '01':
        #     self.logger.info("Received a FRB multicast packet with dst {} from {} on port {}".format(eth_dst,
        #                      pload_eth.src, in_port))
        #     # self.logger.info("More details: ip dst {} ip src {}".format(pload_ip.dst, pload_ip.src))
        #     is_multicast = True
        #     netnode.upstream_reception.put((pload_ip.src, pload_ip.dst), in_port)
        #     netnode.multicast_groups.put(pload_ip.dst, (pload_ip.src, pload_ip.dst))
        #     # good time to send igmp queries to leaf ports
        #     self._send_igmp_query(msg)
        #     # check if any leaf nodes are interested and in_port is not the same as interested port.
        #     if netnode.leaf_interest.containsKey(pload_ip.dst):
        #         for outport in netnode.leaf_interest.get(pload_ip.dst):
        #             if outport != in_port:
        #                 actions = [parser.OFPActionOutput(outport)]
        #                 if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
        #                     data = msg.data
        #                 out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
        #                                           in_port=in_port, actions=actions, data=data)
        #                 datapath.send_msg(out)
        #                 # send out a graft message upstream (because leaf is interested.)
        #                 self.logger.info("Sending a graft message upstream for src {} dst {}".format(pload_ip.src,
        #                                                                                         pload_ip.dst))
        #                 graft_msg = self.frame_graft_msg(pload_ip.src, pload_ip.dst)
        #                 actions = [parser.OFPActionOutput(in_port)]
        #                 out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
        #                                           in_port=datapath.ofproto.OFPP_LOCAL,
        #                                           actions=actions, data=graft_msg.data)
        #                 datapath.send_msg(out)

        if rcvd_frb.frb_type == FloodRouteBound.FRB_LEAF_TX:
            self._lt[dpid].categorize_port(in_port, "TNL_TYPE_PEER", {
                                           "PeerId": rcvd_frb.root_nid, "PeerMac": src})
            self.update_leaf_macs_and_flows(datapath, rcvd_frb.root_nid, payload,
                                            rcvd_frb.pl_count, in_port)
        else:
            if rcvd_frb.frb_type == FloodRouteBound.FRB_BRDCST:
                # learn src mac and rnid only for frb_type == 1
                self._lt[dpid][src] = (in_port, rcvd_frb.root_nid)
                self._lt[dpid]._root_sw_tbl[src].hop_count = rcvd_frb.hop_count
            if rcvd_frb.hop_count > self._lt[dpid].counters.get("MaxFloodingHopCount", 1):
                self._lt[dpid].counters["MaxFloodingHopCount"] = rcvd_frb.hop_count
            # deliver the broadcast frame to leaf devices
            if not is_multicast:
                self.logger.info("Sending FRB payload to leaf ports=%s/%s",
                                 self._lt[dpid].name, self._lt[dpid].leaf_ports)
                for out_port in self._lt[dpid].leaf_ports:
                    if out_port == INTERNAL_PORT_NUM:
                        continue
                    actions = [parser.OFPActionOutput(out_port)]
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                              in_port=in_port, actions=actions, data=payload)
                    datapath.send_msg(out)
            # continue the bounded flood as necessary
            out_bounds = self._lt[dpid].get_flooding_bounds(rcvd_frb, [
                                                            in_port])
            self.logger.debug("Derived FRB(s)=%s/%s",
                              self._lt[dpid].name, out_bounds)
            if out_bounds:
                self.do_bounded_flood(
                    datapath, in_port, out_bounds, src, payload)

    def update_leaf_macs_and_flows(self, datapath, rnid, macs, num_items, ingress):
        self._lt[datapath.id].clear_leaf_macs(rnid)
        # self._lt[datapath.id][rnid].hop_count = 1 #TODO: hop count
        mlen = num_items*6
        for mactup in struct.iter_unpack("!6s", macs[:mlen]):
            macstr = mac_lib.haddr_to_str(mactup[0])
            self.logger.debug(
                "update_leaf_macs_and_flows: add leaf mac %s-%s", self._lt[datapath.id].name, macstr)
            self._lt[datapath.id].add_leaf_mac(rnid, macstr)
        for mac in self._lt[datapath.id].leaf_macs(rnid):
            if self._lt._node_id != rnid:
                self.update_flow_match_dstmac(datapath, mac, ingress, tblid=0)

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
        return str("frb<root_nid={0}, bound_nid={1}, hop_count={2}>"
                   .format(self.root_nid, self.bound_nid, self.hop_count))

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
###################################################################################################
###################################################################################################


class TrafficAnalyzer():
    """ A very simple traffic analyzer to trigger an on demand tunnel """
    _DEMAND_THRESHOLD = 1 << 30  # 1GB

    def __init__(self, logger, demand_threshold=None, max_ond_tuns=1):
        self.max_ond = max_ond_tuns
        val = TrafficAnalyzer._DEMAND_THRESHOLD
        if demand_threshold:
            if demand_threshold[-1] == "K":
                val = int(demand_threshold[:-1]) * 1 << 10
            if demand_threshold[-1] == "M":
                val = int(demand_threshold[:-1]) * 1 << 20
            if demand_threshold[-1] == "G":
                val = int(demand_threshold[:-1]) * 1 << 30
            self.demand_threshold = val
        self.ond = dict()
        self.logger = logger
        logger.info("Demand threshold set at %d bytes", self.demand_threshold)

    def ond_recc(self, flow_metrics, evio_sw: EvioSwitch):
        tunnel_reqs = []
        #self.logger.info("FLOW METRICS:%s", flow_metrics)
        active_flows = set()
        for stat in flow_metrics:
            if "eth_src" not in stat.match or "eth_dst" not in stat.match:
                continue
            src_mac = stat.match["eth_src"]
            dst_mac = stat.match["eth_dst"]
            # peer_sw:PeerData
            peer_sw = evio_sw.get_root_sw(src_mac)
            if not peer_sw:
                continue
            #assert bool(psw.rnid)
            active_flows.add(peer_sw.node_id)
            if dst_mac not in evio_sw.local_leaf_macs:
                # only the leaf's managing sw should create an OND tunnel
                # so prevent every switch along path from req an OND to the initiator
                continue
            if peer_sw.port_no is not None:
                # already a direct tunnel to this switch
                continue
            if peer_sw.node_id not in self.ond and len(self.ond) < self.max_ond and \
                    stat.byte_count > self.demand_threshold:
                self.logger.info(
                    "Requesting On-Demand edge to %s", peer_sw.node_id)
                tunnel_reqs.append((peer_sw.node_id, "ADD"))
                self.ond[peer_sw.node_id] = time.time()
                active_flows.add(peer_sw.node_id)
        # if the flow has expired request the on demand tunnel be removed
        remove_list = []
        for rnid in self.ond:
            if rnid not in active_flows and (time.time() - self.ond[rnid]) >= 60:
                self.logger.info("Requesting removal of OND edge to %s", rnid)
                tunnel_reqs.append((rnid, "REMOVE"))
                remove_list.append(rnid)
        for rnid in remove_list:
            del self.ond[rnid]
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
