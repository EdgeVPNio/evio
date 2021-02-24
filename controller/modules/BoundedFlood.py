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
import logging.handlers as lh
from collections.abc import MutableSet
import random
import time
import math
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

CONF = cfg.CONF # RYU environment



def runcmd(cmd):
    """ Run a shell command. if fails, raise an exception. """
    if cmd[0] is None:
        raise ValueError("No executable specified to run")
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    return p

def is_multicast(mac_addr):

    """
    :param addr: An IEEE EUI-48 (MAC) address in UNIX/WINDOWS string form.

    :return: ``True`` if MAC address string is multicast, ``False`` otherwise.
    """
    if not isinstance(mac_addr, (str, type(''.encode()))):
        return False
    return bool(int(mac_addr.split(":")[0], 16) & 1)
    
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
        return key in self.store and len(self.store[key])>0

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

class netNode():
    def __init__(self, datapath, ryu_app):
        self.datapath = datapath
        self.logger = ryu_app.logger
        self.config = ryu_app.config
        self.addr = (datapath.address[0], self.config["ProxyListenPort"])
        self.node_id = None
        self._leaf_prts = set()
        self.port_state = None
        self.links = {} # maps port no to tuple (local_mac, peer_mac, peer_id)
        self.mac_local_to_peer = {}
        self.counters = {}
        self.ryu = ryu_app
        self.traffic_analyzer = TrafficAnalyzer(self.logger, self.config["DemandThreshold"])
        self.update_node_id()
        # some additional maps for multicast
        # grp->[ports interested]
        # 24 hours timeout, leaf nodes don't refresh.
        self.leaf_interest = container(ttl=24*60*self.config["MulticastBroadcastInterval"])
        # (src,grp)-> port on which multicast transmission recvd
        self.upstream_reception = container(ttl=self.config["MulticastBroadcastInterval"]*4)
        # (src,grp)-> [downstream ports from which join for this transmission recvd]
        self.downstream_interest = container(ttl=self.config["MulticastBroadcastInterval"]*4)
        # grp -> [(src_1,grp),....,(src_n,grp)]
        self.multicast_groups = container(ttl=self.config["MulticastBroadcastInterval"]*4)
        # (src,mcast_dst)->time_in_secs_of_last_broadcast.
        self.broadcast_timeout = {}

    def __repr__(self):
        return ("node_id=%s, node_address=%s:%s, datapath_id=0x%016x, ports=%s" %
                (self.node_id[:7], self.addr[0], self.addr[1], self.datapath.id, self.port_state))

    def __str__(self):
        msg = ("netNode<{0}\nLink={1}, LeafPorts={2}>"
               .format(str(self.__repr__()), self.links, str(self.leaf_ports())))
        return msg

    @property
    def is_ond_enabled(self):
        return self.config["MaxOnDemandEdges"] > 0

    def leaf_ports(self):
        return self._leaf_prts

    def link_ports(self):
        return [*self.links.keys()]

    def update_node_id(self):
        req = dict(Request=dict(Action="GetNodeId", Params=None))
        resp = self._send_recv(self.addr, req)
        if resp and resp["Response"]["Status"]:
            self.node_id = resp["Response"]["Data"]["NodeId"]
            self.logger.debug("Updated node id %s", self.node_id)
        else:
            self.logger.warning("Get Node ID failed for {0}".format(self.datapath.id))

    def query_port_no(self, node_id):
        for prtno in self.links:
            if self.links[prtno][2] == node_id:
                return prtno
        return None

    def peer_id(self, port_no):
        link_item = self.links.get(port_no, (None, None, None))
        return link_item[2]

    @property
    def peer_list(self):
        pl = []
        for entry in self.links.values():
            pl.append(entry[2])
        return pl

    def update(self, tapn=None):
        if not self.node_id:
            self.update_node_id()
        self.logger.info("==Updating node %s==", self.node_id)
        self.update_evio_topology(tapn)
        self.update_links()
        self.update_leaf_ports()

    def update_switch_ports(self):
        tries = 0
        while not self.ryu.dpset.port_state and tries < 3:
            time.sleep(1)
            tries += 1
        self.logger.info("DPSet.port_state %s", self.ryu.dpset.port_state)
        self.port_state = copy.deepcopy(self.ryu.dpset.port_state.get(
            self.datapath.id, None))

    def update_evio_topology(self, tapn=None):
        olid = self.config["OverlayId"]
        if not olid:
            raise ValueError("No overlay ID specified")
        req = dict(Request=dict(Action="GetTunnels", Params={"OverlayId": olid}))
        resp = self._send_recv(self.addr, req)
        if resp and resp["Response"]["Status"]:
            topo = resp["Response"]["Data"]
            if not topo:
                self.logger.info("- No evio topology data available as yet")
                return
            if tapn:
                for tnlid, tnl in topo.items():
                    if tnl["TapName"] == tapn:
                        local = tnl["MAC"]
                        peer_mac = tnl["PeerMac"]
                        peer_id = tnl["PeerId"]
                        self.mac_local_to_peer[local] = (peer_mac, peer_id)
                        break
            else:
                self.mac_local_to_peer.clear()
                for tnlid in topo:
                    local = topo[tnlid]["MAC"]
                    peer_mac = topo[tnlid]["PeerMac"]
                    peer_id = topo[tnlid]["PeerId"]
                    self.mac_local_to_peer[local] = (peer_mac, peer_id)

            self.logger.info("+ Updated mac_local_to_peer %s", self.mac_local_to_peer)
        else:
            msg = "No response from evio controller"
            if resp:
                msg = resp["Response"]
            self.logger.warning("- Failed to update topo for node:%s dpid:%s, response:%s",
                                self.node_id, self.datapath.id, msg)
            raise RuntimeError("Failed to update topo for node:%s dpid:%s, response:%s",
                                self.node_id, self.datapath.id, msg)

    def update_links(self):
        self.links.clear()
        for prt in self.port_state.values():
            peer = self.mac_local_to_peer.get(prt.hw_addr, None)
            if peer:
                self.links[prt.port_no] = (prt.hw_addr, peer[0], peer[1])
        self.logger.info("+ Updated links %s", self.links)

    def update_leaf_ports(self):
        # self._leaf_prts = set(pno for pno in self.port_state if pno not in self.links)
        self._leaf_prts = {1} #, 4294967294}
        self.logger.info("+ Updated leaf ports: %s", str(self._leaf_prts))

    def add_port(self, ofpport):
        self.port_state[ofpport.port_no] = ofpport

    def delete_port(self, ofpport):
        port_no = ofpport.port_no
        try:
            self.port_state.pop(port_no)
        except ValueError as err:
            # RYU events are delivered inconsistently when using both the newer topo with the older
            # events. Ex. legacy:DEL port, DEL port ADD Port, topo: DEL port, ADD port, DEL port
            self.logger.warning("Port %s not found for removal!!. ValueError=%s", ofpport, str(err))
        td = self.links.get(port_no)
        if td:
            self.mac_local_to_peer.pop(td[0], None)
        self.links.pop(port_no, None)
        self.update_leaf_ports()
        self.logger.info("Deleted port %d, NetNode=%s", port_no, self)

    def req_add_tunnel(self, peer_id):
        olid = self.config["OverlayId"]
        req = dict(Request=dict(Action="TunnelRquest", Params=dict(OverlayId=olid,
                                                                   PeerId=peer_id,
                                                                   Operation="ADD")))
        resp = self._send_recv(self.addr, req)
        self.logger.info("ADD OnDemand tunnel Response={}".format(resp))

    def req_remove_tunnel(self, peer_id):
        olid = self.config["OverlayId"]
        req = dict(Request=dict(Action="TunnelRquest", Params=dict(OverlayId=olid,
                                                                   PeerId=peer_id,
                                                                   Operation="REMOVE")))
        resp = self._send_recv(self.addr, req)
        self.logger.info("REMOVE OnDemand tunnel Response={}".format(resp))

    def ond_tunnel(self, flow_metrics, learning_table):
        tunnel_ops = self.traffic_analyzer.ond_recc(flow_metrics, learning_table)
        for op in tunnel_ops:
            if op[1] == "ADD":
                self.req_add_tunnel(op[0])
            elif op[1] == "REMOVE":
                self.req_remove_tunnel(op[0])

    def _send_recv(self, host_addr, send_data):
        recv_data = None
        sd = json.dumps(send_data)
        attempts = 0
        while attempts < 3:
            try:
                attempts += 1
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(host_addr)
                sock.sendall(bytes(sd + "\n", "utf-8"))
                received = str(sock.recv(65536), "utf-8")
                if received:
                    recv_data = json.loads(received)
                    break
            except ConnectionRefusedError as err:
                self.logger.warning("Failed to do send recv: %s", str(err))
                if attempts < 2:
                    time.sleep(1)
            except json.errors.JSONDecodeError as err:
                self.logger.warning("JSON ERROR=%s, rcvd string=%s", str(err), received)
            finally:
                sock.close()
        return recv_data

###################################################################################################
###################################################################################################
class PeerSwitch():
    def __init__(self, rnid):
        self.rnid = rnid
        self.port_no = None
        self.leaf_macs = set()
        self.hop_count = 0

    def __repr__(self):
        return "PeerSwitch<rnid={0}, port_no={1}, hop_count={2}, leaf_macs={3}>".\
            format(self.rnid[:7], self.port_no, self.hop_count, self.leaf_macs)

class LearningTable():
    NoTrackMac = ["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:00",
                  "ff:ff:ff:ff:ff:00", "33:33:00:00:00:00", "ff:ff:00:00:00:00"]
    
    def __init__(self, ryu):
        self._dpid = None
        self._nid = None         # local node id
        self.ingress_tbl = {}    # the last observed ingress for the src mac (index)
        self._leaf_ports = set() # provided by net node
        self.peersw_tbl = {}     # table of peer switches (index: peer sw node id)
        self.rootsw_tbl = {}     # table of leaf mac to host root switch
        self.logger = ryu.logger
        self.config = ryu.config
        self._ts_tbl = {}        # used to expire old leaf entries

    def __contains__(self, key_mac):
        self._lazy_remove(key_mac)
        return key_mac in self.rootsw_tbl or key_mac in self.ingress_tbl

    def __repr__(self):
        state = "dpid={0}, nid={1}, ingress_tbl={2}, leaf_ports={3}, peersw_tbl={4}, " \
            "rootsw_tbl={5}".format(self._dpid, self._nid, self.ingress_tbl, self.leaf_ports,
                                    self.peersw_tbl, self.rootsw_tbl)
        return state

    def __str__(self):
        return str("LearningTable<{}>".format(self.__repr__()))

    def _lazy_remove(self, key_mac):
        # lazy removal of expired entries
        now = time.time()
        ts = self._ts_tbl.get(key_mac, None)
        if not ts:
            return
        if ts <= now - self.config["FlowIdleTimeout"]:
            self.ingress_tbl.pop(key_mac, None)
            rsw = self.rootsw_tbl.pop(key_mac, None)
            if rsw:
                rsw.leaf_macs.discard(key_mac)
                self.logger.info("Removed client mac {0} from rootsw_tbl {1}".format(key_mac, rsw))
            return
        self._ts_tbl[key_mac] = now

    def __getitem__(self, key_mac):
        self._lazy_remove(key_mac)
        # return the best egress to reach the given mac
        psw = self.rootsw_tbl.get(key_mac)
        if psw and psw.port_no:
            return psw.port_no
        return self.ingress_tbl.get(key_mac, None)

    def __setitem__(self, key_mac, value):
        if key_mac in self.NoTrackMac:
            self.logger.debug("Ignoring source mac {0} from {1}".format(key_mac, value))
            return
        self._ts_tbl[key_mac] = time.time()
        if isinstance(value, tuple):
            self.learn(src_mac=key_mac, in_port=value[0], rnid=value[1])
        else:
            self.learn(key_mac, value)

    def __delitem__(self, key_mac):
        """ Remove the MAC address """
        self.ingress_tbl.pop(key_mac, None)
        rsw = self.rootsw_tbl.pop(key_mac, None)
        if rsw:
            rsw.leaf_macs.discard(key_mac)

    @property
    def dpid(self):
        return self._dpid

    @dpid.setter
    def dpid(self, value):
        self._dpid = value

    @property
    def node_id(self):
        return self._nid

    @node_id.setter
    def node_id(self, nid):
        self._nid = nid
        self.peersw_tbl[nid] = PeerSwitch(nid)

    @property
    def local_leaf_macs(self):
        if not self._nid:
            return None
        return self.peersw_tbl[self._nid].leaf_macs

    @property
    def leaf_ports(self):
        return self._leaf_ports

    @leaf_ports.setter
    def leaf_ports(self, ports_set):
        self._leaf_ports = ports_set

    def learn(self, src_mac, in_port, rnid=None):
        """
        Associate the mac with the port. If the RNID is provided it indicates the peer switch that
        hosts the leaf mac.
        """
        self.ingress_tbl[src_mac] = in_port
        if in_port in self.leaf_ports:
            self.logger.debug("learn: add local leaf mac %s", src_mac)
            self.peersw_tbl[self._nid].leaf_macs.add(src_mac)
        elif rnid:
            if rnid not in self.peersw_tbl:
                self.peersw_tbl[rnid] = PeerSwitch(rnid)
            self.logger.debug("learn: peerid: %s, leaf_mac %s", rnid, src_mac)
            self.peersw_tbl[rnid].leaf_macs.add(src_mac)
            self.rootsw_tbl[src_mac] = self.peersw_tbl[rnid]

    def leaf_to_peersw(self, leaf_mac):
        return self.rootsw_tbl.get(leaf_mac)

    def forget(self):
        """ Removes learning table entries associated with port no """
        self.ingress_tbl.clear()
        self.rootsw_tbl.clear()

    def register_peer_switch(self, peer_id, in_port):
        """ Track the adjacent switch and the port no """
        if peer_id:
            if peer_id not in self.peersw_tbl:
                self.peersw_tbl[peer_id] = PeerSwitch(peer_id)
            self.peersw_tbl[peer_id].port_no = in_port

    def unregister_peer_switch(self, peer_id):
        """
        Clear port_no to indicate the tunnel is removed, ie., switch is no longer adjacent
        although it may be accessible via hops.
        """
        if peer_id and peer_id in self.peersw_tbl:
            self.peersw_tbl[peer_id].port_no = None

    def remote_leaf_macs(self, rnid):
        return self.peersw_tbl[rnid].leaf_macs

    def clear(self):
        self._dpid = None
        self._nid = None
        self.ingress_tbl.clear()
        self.leaf_ports.clear()
        self.peersw_tbl.clear()

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
        self.monitor_thread = hub.spawn(self._monitor)
        ethernet.ethernet.register_packet_type(FloodRouteBound, FloodRouteBound.ETH_TYPE_BF)
        self.load_config()
        self.lt = LearningTable(self)   # The local nodes learning table
        self.nodes = dict()             # net node instance for datapath
        self.flooding_bounds = dict()   # flooding bounds instance for datapath

        self.idle_timeout = self.config["FlowIdleTimeout"]
        self.hard_timeout = self.config["FlowHardTimeout"]
        self.mcast_broadcast_period = self.config["MulticastBroadcastInterval"]
        self.monitor_interval = self.config["MonitorInterval"]
        self._last_log_time = time.time()
        self._lock = threading.Lock()
        self._setup_logger()
        self.dpset = kwargs['dpset']
        self.logger.info("BoundedFlood module ready")

    def _setup_logger(self):
        fqname = os.path.join(self.config["LogDir"], self.config["LogFilename"])
        if os.path.isfile(fqname):
            os.remove(fqname)
        self.logger = logging.getLogger(__name__)
        level = getattr(logging, self.config["LogLevel"])
        self.logger.setLevel(level)
        handler = lh.RotatingFileHandler(filename=fqname, maxBytes=self.config["MaxBytes"],
                                         backupCount=self.config["BackupCount"])
        formatter = logging.Formatter(
            "%(asctime)s.%(msecs)03d %(levelname)s: %(message)s", datefmt="%m%d %H:%M:%S")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def load_config(self):
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

    def _find_protocol(self, pkt, name):
        for p in pkt.protocols:
            if hasattr(p, 'protocol_name'):
                if p.protocol_name == name:
                    return p

    def _find_protocol(self, pkt, name):
        for p in pkt.protocols:
            if hasattr(p, 'protocol_name'):
                if p.protocol_name == name:
                    return p

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER) # pylint: disable=no-member
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.logger.info('OFPSwitchFeatures received: msg.datapath_id=0x%016x n_buffers=%d '
                          'n_tables=%d auxiliary_id=%d capabilities=0x%08x', msg.datapath_id,
                          msg.n_buffers, msg.n_tables, msg.auxiliary_id, msg.capabilities)
        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, match, actions)
        # deliver bounded flood frames to controller
        match = parser.OFPMatch(eth_type=FloodRouteBound.ETH_TYPE_BF)
        self.add_flow(datapath, match, actions, priority=100)
        # drop multicast frames
        # self.add_flow_drop_multicast(datapath)
        self.lt.dpid = datapath.id

        node = self.nodes.get(datapath.id, None)
        if not node:
            node = netNode(datapath, self)
        self.nodes[datapath.id] = node
        node.update_switch_ports()
        if node.port_state:
            node.update() # necessary as the DP can sometimes have existing ports at this event
        self.lt.node_id = node.node_id
        self.lt.leaf_ports = node.leaf_ports()

    @set_ev_cls(event.EventSwitchLeave, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def handler_switch_leave(self, ev):
        dpid = ev.switch.dp.id
        self.logger.info("Switch leave event, removing entry: %s", str(ev))
        self.nodes.pop(dpid, None)
        self.lt.clear()

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER) # pylint: disable=no-member
    def port_status_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        port_no = msg.desc.port_no
        node = self.nodes[dp.id]
        with self._lock:
            if msg.reason == ofp.OFPPR_ADD:
                self.logger.info("OFPPortStatus: port ADDED desc=%s", msg.desc)
                self.net_node_add_port(dp, msg.desc)
                self.update_net_node(dp, msg.desc.name.decode("utf-8"))
                self.lt.leaf_ports = node.leaf_ports()
                self.lt.register_peer_switch(node.peer_id(port_no), port_no)
                self.do_bf_leaf_transfer(dp, msg.desc.port_no)
            elif msg.reason == ofp.OFPPR_DELETE:
                self.logger.info("OFPPortStatus: port DELETED desc=%s", msg.desc)
                self.del_flows_port(dp, port_no, tblid=0)
                self.lt.unregister_peer_switch(node.peer_id(port_no))
                self.net_node_del_port(dp, msg.desc)
                self.lt.leaf_ports = node.leaf_ports()
                self.lt.forget()
            elif msg.reason == ofp.OFPPR_MODIFY:
                self.logger.debug("OFPPortStatus: port MODIFIED desc=%s", msg.desc)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER) # pylint: disable=no-member
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        for p in pkt.protocols:
            if hasattr(p, 'protocol_name'):
                self.logger.info(p)
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
            if eth.ethertype == 0xc0c0:
                self.handle_bounded_flood_msg(datapath, pkt, in_port, msg)
            elif dst in self.lt:
                out_port = self.lt[dst]
                # learn a mac address
                self.lt[src] = in_port
                # create new flow rule
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                self.add_flow(datapath, match, actions, priority=1, tblid=0,
                                idle=self.idle_timeout)
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                            in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
            else:
                # this dst mac is not in our LT
                self.logger.debug("Default packet in dpid:%s src:%s dst:%s ingress:%s", dpid, src, dst, in_port)
                if in_port not in self.lt.leaf_ports and is_multicast(dst):
                    # a broadcast or multicast frame was received on a peer sw link.
                    # This is invalid as these tunnel interfaces should not be used the src of a request.
                    self.logger.debug("Dropping multi/broadcast frame to %s on ingress %s", dst, in_port)
                    return
                self.lt[src] = in_port
                frb_type=0    
                if in_port != 1:
                    frb_type=2      # this node did not initiate the frame but it has no data on how to switch it so it must brdcast with an FRB
                # check if this is a multicast frame
                # if eth.dst.split(':')[0] == '01':
                #     if self._handle_multicast_frame(msg,is_igmp,is_dvmrp):
                        # return
                #perform bounded flood same as leaf case
                fld = self.flooding_bounds.get(dpid, None)
                if not fld:
                    fld = FloodingBounds(self.nodes[dpid])
                    self.flooding_bounds[dpid] = fld
                out_bounds = fld.bounds(None, [in_port], frb_type)
                self.logger.info("<--\nGenerated FRB(s)=%s", out_bounds)
                if out_bounds:
                    self.do_bounded_flood(datapath, in_port, out_bounds, src, msg.data)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER) # pylint: disable=no-member
    def _flow_stats_reply_handler(self, ev):
        if self.nodes[ev.msg.datapath.id].is_ond_enabled:
            self.nodes[ev.msg.datapath.id].ond_tunnel(ev.msg.body, self.lt)
    ##################################################################################

    def _send_igmp_query(self, msg):
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        dpid = datapath.id
        netnode = self.nodes[dpid]
        actions = []
        igmp_query = self.frame_igmp_query()
        for leaf_port in netnode.leaf_ports():
            actions.append(parser.OFPActionOutput(leaf_port))
        if len(actions) != 0:
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=datapath.ofproto.OFPP_LOCAL,
                                      actions=actions, data=igmp_query.data)
            self.logger.info("Sending IGMP QUERY {} to leaf ports".format(igmp_query))
            datapath.send_msg(out)

    def _handle_igmp(self, msg):
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        req_igmp = pkt.get_protocol(igmp.igmp)
        dpid = datapath.id
        netnode = self.nodes[dpid]
        if req_igmp.msgtype == 34:
            self.logger.info("Received a IGMP_TYPE_REPORT_V3")
        if req_igmp.msgtype == igmp.IGMP_TYPE_REPORT_V3:
            if in_port in netnode.leaf_ports():
                self.logger.info("Received IGMP_TYPE_REPORT_V3 on LEAF PORT")
            else:
                self.logger.info("Received IGMP_TYPE_REPORT_V3 on PEER PORT")
            for record in req_igmp.records:
                if record.type_ == 3:
                    if in_port in netnode.leaf_ports():
                        self.logger.info("Leaving multicast group {}".format(record.address))
                        if netnode.leaf_interest.containsKey(record.address):
                            if netnode.leaf_interest.containsValue(record.address, in_port):
                                netnode.leaf_interest.removeValue(record.address, in_port)
                elif record.type_ == 4 or record.type_ == 2:
                    if in_port in netnode.leaf_ports():
                        self.logger.info("Joining/Reaffirming multicast group {}".format(record.address))
                        netnode.leaf_interest.put(record.address, in_port)
                    # Optimization: if need to update flows, find all transmissions corresponding this group
                    # address and update rules for them.
                    # need to send this IGMP join as DVMRP upstream to create tree.
                    if netnode.multicast_groups.containsKey(record.address):
                        for transmission in netnode.multicast_groups.get(record.address):
                            self.logger.info("Updating flow for {} on new IGMP join.".format(transmission))
                            actions = []
                            if netnode.downstream_interest.containsKey(transmission):
                                for outport in netnode.downstream_interest.get(transmission):
                                    actions.append(parser.OFPActionOutput(outport))
                            if netnode.leaf_interest.containsKey(record.address):
                                for outport in netnode.leaf_interest.get(record.address):
                                    actions.append(parser.OFPActionOutput(outport))
                            if in_port in netnode.leaf_ports():
                                self.hard_timeout = self.mcast_broadcast_period
                            ip_src, ip_dst = transmission
                            match = parser.OFPMatch(eth_type=0x800, ipv4_dst=ip_dst,
                                                    ipv4_src=ip_src)
                            self.add_flow(datapath, match, actions, priority=1, tblid=0,
                                          idle=self.idle_timeout, hard_timeout=self.hard_timeout)
                            # need to send this IGMP join as DVMRP upstream to create tree.
                            if netnode.upstream_reception.containsKey(transmission):
                                send_port = list(netnode.upstream_reception.get(transmission))[0]
                                if send_port not in netnode.leaf_ports():
                                    # send upstream
                                    self.logger.info("Sending a graft message upstream on IGMP join for src {} dst {}".
                                            format(ip_src, ip_dst))
                                    graft_msg = self.frame_graft_msg(ip_src, ip_dst)
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
        netnode = self.nodes[dpid]
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
                self.logger.info("Updating flow for {} on new dvmrp join.".format(transmission))
                for outport in netnode.downstream_interest.get(transmission):
                    actions.append(parser.OFPActionOutput(outport))
                if netnode.leaf_interest.containsKey(ip_dst):
                    for outport in netnode.leaf_interest.get(ip_dst):
                        actions.append(parser.OFPActionOutput(outport))
            if in_port in netnode.leaf_ports():
                self.hard_timeout = self.mcast_broadcast_period
            match = parser.OFPMatch(eth_type=0x800, ipv4_dst=ip_dst,
                                    ipv4_src=ip_src)
            self.add_flow(datapath, match, actions, priority=1, tblid=0,
                          idle=self.idle_timeout, hard_timeout=self.hard_timeout)

            # need to send this join upstream to create tree, note that this also serves as reaffirming continued
            # interest in the multicast transmission.
            if netnode.multicast_groups.containsKey(req_dvmrp.grp_address):
                targetTransmission = (req_dvmrp.src_address, req_dvmrp.grp_address)
                if netnode.upstream_reception.containsKey(targetTransmission):
                    send_port = list(netnode.upstream_reception.get(targetTransmission))[0]
                    if send_port not in netnode.leaf_ports():
                        # send upstream
                        if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
                            data = msg.data
                        actions = [parser.OFPActionOutput(send_port)]
                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                                  in_port=in_port, actions=actions, data=data)
                        datapath.send_msg(out)
                        self.logger.info("Forwarded DVMRP upstream for {} on port {}".
                                         format((req_dvmrp.src_address, req_dvmrp.grp_address), send_port))

    def _handle_multicast_frame(self,msg,is_igmp,is_dvmrp):
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        dpid = datapath.id
        netnode = self.nodes[dpid]
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
        elif in_port in netnode.leaf_ports():  # make note only if it comes from leaf port or is broadcast.
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
            self.logger.info("Found downstream for {}".format((ip_src, ip_dst)))
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
            self.logger.info("Broadcast timeout for {}, will broadcast".format((ip_src, ip_dst)))
            netnode.broadcast_timeout[(ip_src, ip_dst)] = time.time()
            # still need to send packets to leaf nodes.
            actions = actions_leaf
            if len(actions) != 0:
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                self.logger.info("Sending mcast group pkt {} to leaf port".format(ip_dst))
                datapath.send_msg(out)
        else:
            actions = actions_leaf + actions_downstream
            # Install a flow rule, if the multicast transmission originates on a leaf node, hard timeout
            # has to be set to  a lower value to enable packets to come to controller to initiate periodic
            # broadcasts.
            if in_port in netnode.leaf_ports():
                self.hard_timeout = self.mcast_broadcast_period
            if len(actions) != 0:
                match = parser.OFPMatch(eth_type=0x800, ipv4_dst=ip_dst, ipv4_src=ip_src)
                self.add_flow(datapath, match, actions, priority=1, tblid=0,
                              idle=self.idle_timeout, hard_timeout=self.hard_timeout)
                # Also send the packet out this time
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                self.logger.info("Sending mcast group pkt {} flow out".format(ip_dst))
                datapath.send_msg(out)
                return True  # no need to broadcast

        # Do not broadcast multicast packets received on non leaf ports on a regular channel.
        if in_port not in netnode.leaf_ports():
            return True
        # will have to broadcast
        return False
    ###################################################################################
    def _monitor(self):
        while True:
            msg = ""
            state_msg = ""
            for dpid in self.nodes:
                self.nodes[dpid].counters["MaxFloodingHopCount"] = 0
                total_hc = 0
                num_rsw = 0
                for rsw in self.lt.peersw_tbl.values():
                    if rsw.hop_count > 0:
                        total_hc += rsw.hop_count
                        num_rsw += 1
                    if rsw.hop_count > self.nodes[dpid].counters.get("MaxFloodingHopCount", 1):
                        self.nodes[dpid].counters["MaxFloodingHopCount"] = rsw.hop_count
                if num_rsw == 0:
                    num_rsw = 1
                self.nodes[dpid].counters["TotalHopCount"] = total_hc
                self.nodes[dpid].counters["NumPeersCounted"] = num_rsw
                self.nodes[dpid].counters["AvgFloodingHopCount"] = total_hc/num_rsw

                self.request_stats(self.nodes[dpid].datapath)
                if self.logger.isEnabledFor(logging.DEBUG):
                    state_msg += "{0}\n".format(self.nodes[dpid])
                    state_msg += "{0}\n".format(str(self.lt))
                msg += "Max_FHC={0},".\
                    format(self.nodes[dpid].counters.get("MaxFloodingHopCount", 1))
                msg += "NPC={0},THC={1},AHC={2}".\
                    format(self.nodes[dpid].counters.get("NumPeersCounted", 0),
                           self.nodes[dpid].counters.get("TotalHopCount", 0),
                           self.nodes[dpid].counters.get("AvgFloodingHopCount", 0))
            if time.time() - self._last_log_time > 60:
                self._last_log_time = time.time()
                if msg:
                    self.logger.info("@@>\n%s\n<@@", msg)
                if state_msg:
                    self.logger.debug("%s", state_msg)
            hub.sleep(self.monitor_interval)

    def request_stats(self, datapath, tblid=0):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath, table_id=tblid)
        resp = datapath.send_msg(req)
        if not resp:
            self.logger.warning("Request stats operation failed, OFPFlowStatsRequest=%s", req)

    def add_flow(self, datapath, match, actions, priority=0, tblid=0, idle=0,hard_timeout=0):
        try:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            log_string = "datapath {} priority {} table_id {} idle_timeout {} ".format(datapath, priority, tblid, idle)
            log_string += " hard_timeout {} match {} instructions {} ".format(hard_timeout, match, inst)
            self.logger.info(log_string)
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, table_id=tblid,
                                    idle_timeout=idle, hard_timeout=hard_timeout ,match=match, instructions=inst)
            resp = datapath.send_msg(mod)
            self.logger.info("Response received from add flow request is {}".format(resp))
            if not resp:
                self.logger.info("Add flow operation failed, OFPFlowMod=%s", mod)
        except struct.error as err:
            self.logger.info("Add flow operation failed, OFPFlowMod=%s\n struct.error=%s",
                              mod, err)

    def add_flow_drop_multicast(self, datapath, priority=1, tblid=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_dst=("33:33:00:00:00:00", "ff:ff:00:00:00:00"))
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                command=ofproto.OFPFC_ADD, instructions=inst, table_id=tblid)
        resp = datapath.send_msg(mod)
        if not resp:
            self.logger.warning("Add flow (MC) operation failed, OFPFlowMod=%s", mod)
        match = parser.OFPMatch(eth_dst=("01:00:5e:00:00:00", "ff:ff:ff:ff:ff:00"))
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                command=ofproto.OFPFC_ADD, instructions=inst, table_id=tblid)
        resp = datapath.send_msg(mod)
        if not resp:
            self.logger.warning("Add flow (MC) operation failed, OFPFlowMod=%s", mod)

    def del_flows_port(self, datapath, port_no, tblid=None):
        # this is silently failing, no flows are deleted
        #ofproto = datapath.ofproto
        #if tblid is None:
        #    tblid = ofproto.OFPTT_ALL
        #parser = datapath.ofproto_parser
        #cmd = ofproto.OFPFC_DELETE
        #match = parser.OFPMatch()
        #mod = parser.OFPFlowMod(datapath=datapath, table_id=ofproto.OFPTT_ALL, match=match,
        #                        command=cmd, flags=ofproto.OFPFF_SEND_FLOW_REM, out_port=port_no,
        #                        idle_timeout=self.idle_timeout)
        #self.logger.info("Delete flow mod output, egress=%s, OFPFlowMod=%s", port_no, mod)
        #resp = datapath.send_msg(mod)
        #if not resp:
        #    self.logger.warning("Delete flow operation failed, egress=%s, OFPFlowMod=%s",
        #                        port_no, mod)
        #match = parser.OFPMatch(in_port=port_no)
        #mod = parser.OFPFlowMod(datapath=datapath, table_id=tblid, match=match, command=cmd,
        #                        flags=ofproto.OFPFF_SEND_FLOW_REM, idle_timeout=self.idle_timeout)
        #self.logger.info("Delete flow mod, egress=%s, OFPFlowMod=%s", port_no, mod)
        #resp = datapath.send_msg(mod)
        #if not resp:
        #    self.logger.warning("Delete flow operation failed, egress=%s, OFPFlowMod=%s",
        #                        port_no, mod)
        resp = runcmd([BoundedFlood.OFCTL, "del-flows", self.config["BridgeName"],
                       "in_port={0}".format(port_no)])
        self.logger.debug("Deleted flows with in_port=%s", port_no)
        resp = runcmd([BoundedFlood.OFCTL, "del-flows", self.config["BridgeName"],
                       "out_port={0}".format(port_no)])
        self.logger.debug("deleted flows with out_port=%s", port_no)

    def update_flow_match_dstmac(self, datapath, dst_mac, new_egress, tblid=None):
        self.logger.debug("Updating all flows matching dst mac %s", dst_mac)
        parser = datapath.ofproto_parser
        if tblid is None:
            tblid = datapath.ofproto.OFPTT_ALL
        cmd = datapath.ofproto.OFPFC_MODIFY
        acts = [parser.OFPActionOutput(new_egress, 1500)]
        inst = [parser.OFPInstructionActions(
            datapath.ofproto.OFPIT_APPLY_ACTIONS, acts)]
        mt = parser.OFPMatch(eth_dst=dst_mac)
        mod = parser.OFPFlowMod(datapath=datapath, table_id=tblid, match=mt, command=cmd,
                                instructions=inst, idle_timeout=self.idle_timeout)
        resp = datapath.send_msg(mod)
        if not resp:
            self.logger.warning("Update flow operation failed, OFPFlowMod=%s", mod)

    ###############################################################################################

    def update_net_node(self, datapath, tap_name):
        dpid = datapath.id
        node = self.nodes.get(dpid, None)
        if not node:
            node = netNode(datapath, self)
        node.update(tap_name)
        self.nodes[dpid] = node
        return node

    def net_node_add_port(self, datapath, ofpport):
        dpid = datapath.id
        node = self.nodes[dpid]
        node.add_port(ofpport)

    def net_node_del_port(self, datapath, ofpport):
        dpid = datapath.id
        node = self.nodes[dpid]
        node.delete_port(ofpport)

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
                self.logger.warning("Send FRB operation failed, OFPPacketOut=%s", out)

    def do_bf_leaf_transfer(self, datapath, tunnel_port_no):
        node = self.nodes[datapath.id]
        tun_item = node.links.get(tunnel_port_no)
        if not tun_item:
            return
        peer_id = tun_item[2]
        peer_mac = tun_item[1]
        src_mac = tun_item[0]

        if not self.lt.local_leaf_macs:
            return
        payload = bytearray(6*len(self.lt.local_leaf_macs))
        offset = 0
        for leaf_mac in self.lt.local_leaf_macs:
            bmac = mac_lib.haddr_to_bin(leaf_mac)
            struct.pack_into("!6s", payload, offset, bmac)
            offset += 6

        nid = node.node_id
        bf_hdr = FloodRouteBound(nid, nid, 0, FloodRouteBound.FRB_LEAF_TX, offset//6)
        eth = ethernet.ethernet(dst=peer_mac, src=src_mac,
                                ethertype=FloodRouteBound.ETH_TYPE_BF)
        p = packet.Packet()
        p.add_protocol(eth)
        p.add_protocol(bf_hdr)
        p.add_protocol(payload)
        p.serialize()
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        acts = [parser.OFPActionOutput(tunnel_port_no)]
        pkt_out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                      actions=acts, data=p.data, in_port=ofproto.OFPP_LOCAL)
        resp = datapath.send_msg(pkt_out)
        if resp:
            self.logger.info("FRB leaf exchange completed, %s %s %s %s %s", datapath.id, peer_id,
                             peer_mac, tunnel_port_no, payload)
        else:
            self.logger.warning("FRB leaf exchange failed, OFPPacketOut=%s", pkt_out)

    def frame_graft_msg(self,source_address, group_address):
        dvmrp = DVMRP(src_address=source_address,
                      grp_address=group_address)
        # src and dst MAC addresses do not matter.
        eth = ethernet.ethernet(dst='01:00:5E:0A:0A:0A',
                                src='00:00:00:00:00:00',
                                ethertype=ether.ETH_TYPE_IP)
        pkt = packet.Packet()
        total_length = 20 + dvmrp.min_len
        nw_proto = 200 # custom network protocol payload type
        nw_dst = '255.255.255.255'
        nw_src = '0.0.0.0'
        i = ipv4.ipv4(total_length=total_length,
                      src=nw_src,
                      dst=nw_dst,
                      proto=nw_proto)
        pkt.add_protocol(eth)
        pkt.add_protocol(i)
        pkt.add_protocol(dvmrp)
        pkt.serialize()
        return pkt

    def frame_igmp_query(self):
        igmp_query = igmp.igmpv3_query(maxresp=igmp.QUERY_RESPONSE_INTERVAL * 10,
                          csum=0,
                          address='0.0.0.0')
        eth = ethernet.ethernet(dst=igmp.MULTICAST_MAC_ALL_HOST,
                                src='00:00:00:00:00:00',
                                ethertype=ether.ETH_TYPE_IP)
        ip = ipv4.ipv4(total_length=len(ipv4.ipv4()) + len(igmp_query),
                       proto=inet.IPPROTO_IGMP, ttl=1,
                       src='0.0.0.0',
                       dst=igmp.MULTICAST_IP_ALL_HOST)
        pkt = packet.Packet()
        pkt.add_protocol(eth)
        pkt.add_protocol(ip)
        pkt.add_protocol(igmp_query)
        pkt.serialize()
        return pkt


    def handle_bounded_flood_msg(self, datapath, pkt, in_port, msg):
        eth = pkt.protocols[0]
        src = eth.src
        dpid = datapath.id
        netnode = self.nodes[dpid]
        parser = datapath.ofproto_parser
        rcvd_frb = pkt.protocols[1]
        self.logger.info("-->\nReceived FRB=%s", rcvd_frb)
        if len(pkt.protocols) < 2:
            return
        payload = pkt.protocols[2]
        # Check for a multicast payload.
        is_multicast = False
        payload_pkt = packet.Packet(payload)
        pload_eth = payload_pkt.protocols[0]
        eth_dst = None
        if pload_eth and rcvd_frb.frb_type == FloodRouteBound.FRB_BRDCST:
            eth_dst = pload_eth.dst
            pload_ip = payload_pkt.get_protocol(ipv4.ipv4)
        if eth_dst and eth_dst.split(':')[0] == '01':
            self.logger.info("Received a FRB multicast packet with dst {} from {} on port {}".format(eth_dst,
                             pload_eth.src, in_port))
            # self.logger.info("More details: ip dst {} ip src {}".format(pload_ip.dst, pload_ip.src))
            is_multicast = True
            netnode.upstream_reception.put((pload_ip.src, pload_ip.dst), in_port)
            netnode.multicast_groups.put(pload_ip.dst, (pload_ip.src, pload_ip.dst))
            # good time to send igmp queries to leaf ports
            self._send_igmp_query(msg)
            # check if any leaf nodes are interested and in_port is not the same as interested port.
            if netnode.leaf_interest.containsKey(pload_ip.dst):
                for outport in netnode.leaf_interest.get(pload_ip.dst):
                    if outport != in_port:
                        actions = [parser.OFPActionOutput(outport)]
                        if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
                            data = msg.data
                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                                  in_port=in_port, actions=actions, data=data)
                        datapath.send_msg(out)
                        # send out a graft message upstream (because leaf is interested.)
                        self.logger.info("Sending a graft message upstream for src {} dst {}".format(pload_ip.src,
                                                                                                pload_ip.dst))
                        graft_msg = self.frame_graft_msg(pload_ip.src, pload_ip.dst)
                        actions = [parser.OFPActionOutput(in_port)]
                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                                  in_port=datapath.ofproto.OFPP_LOCAL,
                                                  actions=actions, data=graft_msg.data)
                        datapath.send_msg(out)

        if rcvd_frb.frb_type == FloodRouteBound.FRB_LEAF_TX:
            self.update_leaf_macs_and_flows(datapath, rcvd_frb.root_nid, payload,
                                            rcvd_frb.pl_count, in_port)
        else:
            if rcvd_frb.frb_type == FloodRouteBound.FRB_BRDCST:
                #learn src mac and rnid only for frb_type == 1
                self.lt[src] = (in_port, rcvd_frb.root_nid)                
            self.lt.peersw_tbl[rcvd_frb.root_nid].hop_count = rcvd_frb.hop_count
            if rcvd_frb.hop_count > self.nodes[dpid].counters.get("MaxFloodingHopCount", 1):
                self.nodes[dpid].counters["MaxFloodingHopCount"] = rcvd_frb.hop_count
            # deliver the broadcast frame to leaf devices
            if not is_multicast:
                self.logger.info("Sending FRB payload to leaf ports=%s",
                                 self.nodes[datapath.id].leaf_ports())
                for out_port in self.nodes[datapath.id].leaf_ports():
                    actions = [parser.OFPActionOutput(out_port)]
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                              in_port=in_port, actions=actions, data=payload)
                    datapath.send_msg(out)
            # continue the bounded flood as necessary
            fld = self.flooding_bounds.get(dpid, None)
            if not fld:
                fld = FloodingBounds(self.nodes[dpid])
                self.flooding_bounds[dpid] = fld
            out_bounds = fld.bounds(rcvd_frb, [in_port])
            self.logger.info("Derived FRB(s)=%s", out_bounds)
            if out_bounds:
                self.do_bounded_flood(datapath, in_port, out_bounds, src, payload)

    def update_leaf_macs_and_flows(self, datapath, rnid, macs, num_items, ingress):
        self.lt.peersw_tbl[rnid].leaf_macs.clear()
        self.lt.peersw_tbl[rnid].hop_count = 1
        mlen = num_items*6
        for mactup in struct.iter_unpack("!6s", macs[:mlen]):
            macstr = mac_lib.haddr_to_str(mactup[0])
            self.logger.debug("update_leaf_macs_and_flows: add leaf mac %s", macstr)
            self.lt.peersw_tbl[rnid].leaf_macs.add(macstr)
        for mac in self.lt.remote_leaf_macs(rnid):
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

    def __init__(self, root_nid, bound_nid, hop_count, frb_type=0, pl_count=0):
        super(FloodRouteBound, self).__init__()
        self.root_nid = root_nid
        self.bound_nid = bound_nid
        self.hop_count = hop_count
        self.frb_type = frb_type
        self.pl_count = pl_count
        assert self.hop_count < (1<<16), "hop_count exceeds max val"
        assert self.frb_type < (1<<16), "frb_type exceeds max val"
        assert self.pl_count < (1<<16), "pl_count exceeds max val"

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
        if self.hop_count == 0:
            self.frb_type = FloodRouteBound.FRB_LEAF_TX
        if self.frb_type == FloodRouteBound.FRB_LEAF_TX:
            self.pl_count = len(payload) // 6
        return struct.pack(FloodRouteBound._PACK_STR, rid, bid, self.hop_count, self.frb_type,
                           self.pl_count)

###################################################################################################
###################################################################################################
class FloodingBounds():
    """
    FloodingBounds is used to dtermine which of its adjacent peers should be sent a frb to complete
    a system wide broadcast and bound should be used in the frb sent to said peer. FloodingBounds
    are typically calculated to flow clockwise to greater peer IDs and bounds and accommodates
    the wrap around of the ring. However, for the initial frb broadcast lesser peer IDs are used.
    This gives the local node the opportunity to discover the direct path associated with lesser
    peer IDs.
    """
    def __init__(self, net_node):
        self._root_nid = None
        self._bound_nid = None
        self._hops = None
        self._net_node = net_node

    def bounds(self, prev_frb=None, exclude_ports=None, frb_type=0):
        """
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
        node_list = self._net_node.peer_list
        my_nid = self._net_node.node_id
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
                "invalid nid ordering self={0}, peer1={1}, peer2={2}".\
                format(my_nid, peer1, peer2)
            # base scenario when the local node is initiating the FRB
            hops = 1
            root_nid = my_nid
            bound_nid = my_nid
            if not prev_frb:
                bound_nid = peer2
                frb_hdr = FloodRouteBound(root_nid, bound_nid, hops, frb_type)
                if frb_hdr:
                    prtno = self._net_node.query_port_no(peer1)
                    if prtno and prtno not in exclude_ports:
                        out_bounds.append((prtno, frb_hdr))
            else:
                assert prev_frb.bound_nid != my_nid,\
                    "this frb should not have reached this node ny_nid={0} prev_frb={1}".\
                    format(my_nid, prev_frb)
                hops = prev_frb.hop_count + 1
                root_nid = prev_frb.root_nid
                if peer1 < my_nid: # peer1 is a predecessor
                    if prev_frb.bound_nid > peer1 and prev_frb.bound_nid < my_nid: # bcast to peer1
                        if peer2 < prev_frb.bound_nid:
                            bound_nid = peer2
                        else:
                            bound_nid = prev_frb.bound_nid
                    else:
                        continue
                else: # peer1 is a successor
                    if prev_frb.bound_nid < my_nid: # bcast to peer1
                        if peer2 < my_nid and peer2 > prev_frb.bound_nid:
                            bound_nid = prev_frb.bound_nid
                        elif (peer2 < my_nid and peer2 <= prev_frb.bound_nid) or \
                            peer2 > my_nid:
                            bound_nid = peer2
                    else: # prev_frb.bound_nid > my_nid
                        if prev_frb.bound_nid <= peer1:
                            continue
                        if peer2 < my_nid or prev_frb.bound_nid < peer2:
                            bound_nid = prev_frb.bound_nid
                        else:
                            bound_nid = peer2
                frb_hdr = FloodRouteBound(root_nid, bound_nid, hops, frb_type)
                if frb_hdr:
                    prtno = self._net_node.query_port_no(peer1)
                    if prtno and prtno not in exclude_ports:
                        out_bounds.append((prtno, frb_hdr))
        return out_bounds

###################################################################################################
###################################################################################################
class TrafficAnalyzer():
    """ A very simple traffic analyzer to trigger an on demand tunnel """
    _DEMAND_THRESHOLD = 1<<23 # 80MB
    def __init__(self, logger, demand_threshold=None, max_ond_tuns=1):
        self.max_ond = max_ond_tuns
        if demand_threshold:
            if demand_threshold[-1] == "K":
                val = int(demand_threshold[:-1]) * 1<<10
            if demand_threshold[-1] == "M":
                val = int(demand_threshold[:-1]) * 1<<20
            if demand_threshold[-1] == "G":
                val = int(demand_threshold[:-1]) * 1<<30
            self.demand_threshold = val
        else:
            self.demand_threshold = TrafficAnalyzer._DEMAND_THRESHOLD
        self.ond = dict()
        self.logger = logger
        logger.info("Demand threshold set at %d bytes", self.demand_threshold)

    def ond_recc(self, flow_metrics, learning_table):
        tunnel_reqs = []
        #self.logger.info("FLOW METRICS:%s", flow_metrics)
        active_flows = set()
        for stat in flow_metrics:
            if "eth_src" not in stat.match or "eth_dst" not in stat.match:
                continue
            src_mac = stat.match["eth_src"]
            dst_mac = stat.match["eth_dst"]
            psw = learning_table.leaf_to_peersw(src_mac)
            if not psw:
                continue
            #assert bool(psw.rnid)
            active_flows.add(psw.rnid)
            if dst_mac not in learning_table.local_leaf_macs:
                # only the leaf's managing sw should create an OND tunnel
                # so prevent every switch along path from req an OND to the initiator
                continue
            if psw.port_no is not None:
                # already a direct tunnel to this switch
                continue
            if psw.rnid not in self.ond and len(self.ond) < self.max_ond and \
                stat.byte_count > self.demand_threshold:
                self.logger.info("Requesting On-Demand edge to %s", psw.rnid)
                tunnel_reqs.append((psw.rnid, "ADD"))
                self.ond[psw.rnid] = time.time()
                active_flows.add(psw.rnid)
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
                 src_address='0.0.0.0',grp_address='224.0.0.1'):
        super(DVMRP, self).__init__()
        self.msgtype = msgtype
        self.code = code
        self.csum = csum
        self.src_address = src_address
        self.grp_address = grp_address

    @classmethod
    def parser(cls, buf):
        assert cls._MIN_LEN <= len(buf)
        (msgtype, ) = struct.unpack_from('!B', buf)
        if msgtype == DVMRP_TYPE:
            (msgtype, code, csum, src_address,
             grp_address) = struct.unpack_from(cls._PACK_STR, buf)
            instance = cls(msgtype, code, csum,
                           addrconv.ipv4.bin_to_text(src_address),
                           addrconv.ipv4.bin_to_text(grp_address),
                           )
            subclass = None
            rest = buf[cls._MIN_LEN:]
        return instance, subclass, rest

    def serialize(self, payload, prev):
        hdr = bytearray(struct.pack(self._PACK_STR, self.msgtype,
                                    self.code, self.csum,
                                    addrconv.ipv4.text_to_bin(self.src_address),
                                    addrconv.ipv4.text_to_bin(self.grp_address)))

        if self.csum == 0:
            self.csum = packet_utils.checksum(hdr)
            struct.pack_into('!H', hdr, 2, self.csum)
        return hdr

    @property
    def min_len(self):
        return self._MIN_LEN
