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

import asyncio
import ssl
import time
import threading
import os
from queue import Queue
try:
    import simplejson as json
except ImportError:
    import json
import random
import socket
import slixmpp
from slixmpp import ElementBase, register_stanza_plugin, Message, Callback, StanzaPath, JID
from framework.ControllerModule import ControllerModule

CacheExpiry = 30
PresenceInterval = 30

class EvioSignal(ElementBase):
    """Representation of SIGNAL's custom message stanza"""
    name = "evio"
    namespace = "signal"
    plugin_attrib = "evio"
    interfaces = set(("type", "payload"))


class JidCache:
    _REFLECT = set(
        ["_cache", "_expiry"])

    def __init__(self, cmod, expiry):
        self._lck = threading.Lock()
        self._cache = {}
        self._sig = cmod
        self._expiry = expiry
        
    def __repr__(self):
        items = set()
        for k in JidCache._REFLECT:
            items.add(f"\"{k}\": {self.__dict__[k]!r}")
        return "{{{}}}".format(", ".join(items))
      
    def add_entry(self, node_id, jid):
        ts = time.time()
        with self._lck:
            self._cache[node_id] = (jid, ts)
        return ts

    def scavenge(self,):
        with self._lck:
            curr_time = time.time()
            keys_to_be_deleted = \
                [key for key, value in self._cache.items() if curr_time - value[1] >= self._expiry]
            for key in keys_to_be_deleted:
                del self._cache[key]

    def lookup(self, node_id):
        jid = None
        with self._lck:
            entry = self._cache.get(node_id)
            if entry and (time.time() - entry[1] < self._expiry):
                jid = entry[0]
            elif entry:
                del self._cache[node_id]
        return jid


class XmppTransport(slixmpp.ClientXMPP):
    _REFLECT = set(
        ["_overlay_id", "_node_id", "_cbt_to_action_tag"])

    def __init__(self, jid, password, sasl_mech):
        slixmpp.ClientXMPP.__init__(self, jid, password, sasl_mech=sasl_mech)
        self._overlay_id = None
        self._sig = None
        self._node_id = None
        self._presence_publisher = None
        self._jid_cache = None
        self._outgoing_rem_acts = None
        self._cbt_to_action_tag = {}  # maps remote action tags to cbt tags
        self._host = None
        self._port = None
        # TLS enabled by default.
        self._enable_tls = True
        self._enable_ssl = False
        self.xmpp_thread = None
        self._init_event = threading.Event()

    def __repr__(self):
        items = set()
        for k in XmppTransport._REFLECT:
            items.add(f"\"{k}\": {self.__dict__[k]!r}")
        return "{{{}}}".format(", ".join(items))

    def host(self):
        return self._host

    @staticmethod
    def factory(overlay_id, overlay_descr, cm_mod, presence_publisher, jid_cache,
                outgoing_rem_acts):
        keyring = None
        try:
            import keyring
        except ImportError as err:
            cm_mod.log("LOG_INFO", "No keyring available")
        host = overlay_descr["HostAddress"]
        port = overlay_descr["Port"]
        user = overlay_descr.get("Username", None)
        pswd = overlay_descr.get("Password", None)
        auth_method = overlay_descr.get("AuthenticationMethod", "PASSWORD").casefold()
        if auth_method == "x509".casefold() and (user is not None or pswd is not None):
            er_log = "x509 Authentication is enbabled but credentials " \
                "exists in evio configuration file; x509 will be used."
            cm_mod.log("LOG_WARNING", er_log)
        if auth_method == "x509".casefold():
            transport = XmppTransport(None, None, sasl_mech="EXTERNAL")
            transport.ssl_version = ssl.PROTOCOL_TLSv1
            transport.certfile = os.path.join(overlay_descr["CertDirectory"], overlay_descr["CertFile"])
            transport.keyfile = os.path.join(overlay_descr["CertDirectory"], overlay_descr["KeyFile"])
            transport._enable_ssl = True
        elif auth_method == "PASSWORD".casefold():
            if user is None:
                raise RuntimeError("No username is provided in evio configuration file.")
            if pswd is None and not keyring is None:
                pswd = keyring.get_password("evio", overlay_descr["Username"])
            if pswd is None:
                print("{0} XMPP Password: ".format(user))
                pswd = str(input())
                if not keyring is None:
                    try:
                        keyring.set_password("evio", user, pswd)
                    except keyring.errors.PasswordSetError as err:
                        cm_mod.log("LOG_ERROR", "Failed to store password in keyring. %S", str(err))
                                       
            transport = XmppTransport(user, pswd, sasl_mech="PLAIN")
            del pswd
        else:
            raise RuntimeError("Invalid authentication method specified in configuration: {0}"
                               .format(auth_method))
        transport._host = host
        transport._port = port
        transport._overlay_id = overlay_id
        transport._sig = cm_mod
        transport._node_id = cm_mod.config["NodeId"]
        transport._presence_publisher = presence_publisher
        transport._jid_cache = jid_cache
        transport._outgoing_rem_acts = outgoing_rem_acts
        # register event handlers of interest
        transport.add_event_handler("session_start", transport.handle_start_event)
        transport.add_event_handler("failed_auth", transport.handle_failed_auth_event)      
        transport.add_event_handler("disconnected", transport.handle_disconnect_event)
        transport.add_event_handler("presence_available", transport.handle_presence_event)      
        return transport

    def handle_failed_auth_event(self, event):
        self._sig.logger.error("XMPP authentication failure. Verify credentials for overlay %s and restart EVIO", self._overlay_id)

    def handle_disconnect_event(self, reason):
        self._sig.logger.debug("XMPP disconnected, reason=%s.", reason)
        self.loop.stop()
        
    def handle_start_event(self, event):
        """Registers custom event handlers at the start of XMPP session"""
        self._sig.logger.debug("XMPP Signalling started for overlay: %s",
                      self._overlay_id)
        try:
           # Register evio message with the server
            register_stanza_plugin(Message, EvioSignal)
            self.register_handler(
                Callback("evio", StanzaPath("message/evio"),
                self.handle_message)
            )
            # Get the friends list for the user
            asyncio.ensure_future(self.get_roster(), loop=self.loop)
            # Send initial sign-on presence
            self.send_presence(pstatus="ident#" + self._node_id)
            self._init_event.set()
        except Exception as err:
            self._sig.logger.error("XmppTransport: Exception:%s Event:%s", err, event)

    def handle_presence_event(self, presence):
        """
        Handle peer presence event messages
        """
        try:
            presence_sender = presence["from"]
            presence_receiver_jid = JID(presence["to"])
            presence_receiver = str(presence_receiver_jid.user) + "@" \
                + str(presence_receiver_jid.domain)
            status = presence["status"]
            self._sig.logger.debug("Presence recv - Overlay:%s Local JID:%s Msg:%s",
                          self._overlay_id, self.boundjid, presence)
            if(presence_receiver == self.boundjid.bare and presence_sender != self.boundjid.full):
                if (status and "#" in status):
                    pstatus, peer_id = status.split("#")
                    if pstatus == "ident":
                        if peer_id == self._node_id:
                            return
                        # a notification of a peer's node id to jid mapping
                        pts = self._jid_cache.add_entry(node_id=peer_id, jid=presence_sender)
                        self._presence_publisher.post_update(
                            dict(PeerId=peer_id, OverlayId=self._overlay_id,
                                 PresenceTimestamp=pts))
                        self._sig.logger.debug("Resolved %s@%s->%s", 
                                      peer_id[:7], self._overlay_id, presence_sender)
                        payload = self.boundjid.full + "#" + self._node_id
                        self.send_msg(presence_sender, "announce", payload)
                    elif pstatus == "uid?":
                        # a request for our jid
                        if self._node_id == peer_id:
                            payload = self.boundjid.full + "#" + self._node_id
                            self.send_msg(presence_sender, "uid!", payload)
                    else:
                        self._sig.logger.warning("Unrecognized PSTATUS:%s on overlay:%s",
                                      pstatus, self._overlay_id)
        except Exception as err:
            self._sig.logger.error("XmppTransport:Exception:%s overlay:%s presence:%s",
                          err, self._overlay_id, presence)
            
    def handle_message(self, msg):
        """
        Listen for matched messages on the xmpp stream, extract the header
        and payload, and takes suitable action.
        """
        try:
            sender_jid = msg["from"]
            # discard the message if it was initiated by this node
            if sender_jid == self.boundjid.full:
                return
            # extract header and content
            msg_type = msg["evio"]["type"]
            msg_payload = msg["evio"]["payload"]
            if msg_type == "uid!":
                match_jid, matched_nid = msg_payload.split("#")
                # put the learned JID in cache
                self._jid_cache.add_entry(matched_nid, match_jid)
                # send the remote actions that are waiting on JID refresh
                rm_que = self._outgoing_rem_acts.get(matched_nid, Queue())
                while not rm_que.empty():
                    entry = rm_que.get()
                    msg_type, msg_data = entry[0], entry[1]
                    self.send_msg(match_jid, msg_type, json.dumps(msg_data))
                    self._sig.logger.debug("Sent buffered remote action: %s", msg_data)
            elif msg_type == "announce":
                peer_jid, peer_id = msg_payload.split("#")
                if peer_id == self._node_id:
                    self._sig.logger.debug("UID Announce msg returned to self msg=%s", msg)
                    return
                # a notification of a peers node id to jid mapping
                pts = self._jid_cache.add_entry(node_id=peer_id, jid=peer_jid)
                self._presence_publisher.post_update(
                    dict(PeerId=peer_id, OverlayId=self._overlay_id, PresenceTimestamp=pts))
            elif msg_type in ("invk", "cmpt"):
                rem_act = json.loads(msg_payload)
                self._sig.handle_remote_action(self._overlay_id, rem_act, msg_type)
            else:
                self._sig.logger.warning("Invalid message type received %s", str(msg))
        except Exception as err:
            self._sig.logger.error("XmppTransport:Exception:%s msg:%s", err, msg)

    def send_msg(self, peer_jid, msg_type, payload):
        """Send a message to Peer JID via XMPP server"""
        msg = self.Message()
        msg["to"] = peer_jid
        msg["from"] = self.boundjid.full
        msg["type"] = "chat"
        msg["evio"]["type"] = msg_type
        msg["evio"]["payload"] = payload
        self.loop.call_soon_threadsafe(msg.send)

    def wait_until_initialized(self):
        return self._init_event.wait(10.0)

    def _check_network(self):
        # handle boot time start where the network is not yet available
        res = []
        try:
            res = socket.getaddrinfo(self._host, self._port, 0, socket.SOCK_STREAM)
        except socket.gaierror as err:
                    self._sig.logger.error("Check network failed, unable to retrieve address info for %s:%s.", self._host, self._port)
        return bool(res)

    def run(self):
        if not self._check_network():
            self._init_event.set()
            return

        try:
            self.connect(address=(self._host, int(self._port)))
            self.process(forever=True)
            # Do not show `asyncio.CancelledError` exceptions during shutdown
            def shutdown_exception_handler(loop, context):
                if "exception" not in context \
                or not isinstance(context["exception"], asyncio.CancelledError):
                    loop.default_exception_handler(context)
            self.loop.set_exception_handler(shutdown_exception_handler)
            # Handle shutdown by waiting for all tasks to be cancelled
            tasks = asyncio.gather(*asyncio.all_tasks(loop=self.loop), loop=self.loop, return_exceptions=True)
            tasks.add_done_callback(lambda t: self.loop.stop())
            tasks.cancel()
            # Keep the event loop running, after stop is called run_forever loops only once
            while not tasks.done() and not self.loop.is_closed():
                self.loop.run_forever() 
        except Exception as err:
            self._sig.logger.error("XMPPTransport run exception %s", str(err))           
        finally:
            self.loop.run_until_complete(self.loop.shutdown_asyncgens())
            self.loop.close()
            self._sig.logger.debug("Event loop closed on XMPP overlay=%s", self._overlay_id)

    def shutdown(self,):
        self._sig.logger.debug("Initiating shutdown of XMPP overlay=%s", self._overlay_id)
        self.loop.call_soon_threadsafe(self.disconnect(reason="controller shutdown"))        

class Signal(ControllerModule):
    _REFLECT = set(["_circles", "_remote_acts", "request_timeout"])
    
    def __init__(self, cfx_handle, module_config, module_name):
        super(Signal, self).__init__(cfx_handle, module_config, module_name)
        self._presence_publisher = None
        self._circles = {}
        self._remote_acts = {}
        self._lock = threading.Lock()
        self._request_timeout = self._cfx_handle.query_param("RequestTimeout")
        #self._scavenge_timer = time.time()
   
    def _setup_transport_instance(self, overlay_id):
        '''
        The ClientXMPP object must be instantiated on its own thread. ClientXMPP->BaseXMPP->XMLStream->asyncio.queue 
        attempts to get the eventloop associate with this thread. This means an eventloop must be created
        and set for the current thread, if one does not  already exist, before instantiating ClientXMPP.
        '''
        asyncio.set_event_loop(asyncio.new_event_loop())
        xport = XmppTransport.factory(overlay_id, self.overlays[overlay_id],
                                      self, self._presence_publisher,
                                      self._circles[overlay_id]["JidCache"],
                                      self._circles[overlay_id]["OutgoingRemoteActs"])
        self._circles[overlay_id]["Transport"] = xport
        # waiting to release the lock here prevents other threads from attempting to use the transport object before its has been created.
        self._lock.release() 
        xport.run()

    def _setup_circle(self, overlay_id):
        self._circles[overlay_id] = {}
        self._circles[overlay_id]["Announce"] = time.time() + \
            (self.config.get("PresenceInterval", PresenceInterval) * random.randint(1, 3))
        self._circles[overlay_id]["JidCache"] = \
            JidCache(self, self.config.get("CacheExpiry", CacheExpiry))
        self._circles[overlay_id]["OutgoingRemoteActs"] = {}
        xmpp_thread = threading.Thread(target=self._setup_transport_instance, kwargs={"overlay_id":overlay_id}, daemon=True)
        self._circles[overlay_id]["TransportThread"] = xmpp_thread
        xmpp_thread.start()

    def initialize(self):
        self._presence_publisher = self.publish_subscription("SIG_PEER_PRESENCE_NOTIFY")
        self._lock.acquire()
        for overlay_id in self.overlays:
            self._setup_circle(overlay_id)
        self.log("LOG_INFO", "Module loaded")

    def req_handler_query_reporting_data(self, cbt):
        rpt = {}
        for overlay_id in self.overlays:
            rpt[overlay_id] = {
                "xmpp_host": self._circles[overlay_id]["Transport"].host(),
                "xmpp_username": self._circles[overlay_id]["Transport"].boundjid.full
            }
        cbt.set_response(rpt, True)
        self.complete_cbt(cbt)

    def handle_remote_action(self, overlay_id, rem_act, act_type):
        if not overlay_id == rem_act["overlay_id"]:
            self.log("LOG_WARNING", "The Overlay ID in the rcvd remote action conflicts "
                     "with the local configuration. It was discarded: %s", rem_act)
            return
        if act_type == "invk":
            self.invoke_remote_action_on_target(rem_act)
        elif act_type == "cmpt":
            self.complete_remote_action_on_initiator(rem_act)

    def invoke_remote_action_on_target(self, rem_act):
        """ Convert the received remote action into a CBT and invoke it locally """
        # if the intended recipient is offline the XMPP server broadcasts the msg to all
        # matching ejabber ids. Verify recipient using Node ID and discard if mismatch
        if rem_act["recipient_id"] != self.node_id:
            self.log("LOG_WARNING", "A mis-delivered remote action was discarded: %s",
                         rem_act)
            return
        n_cbt = self.create_cbt(self._module_name, rem_act["recipient_cm"],
                                rem_act["action"], rem_act["params"])
        # store the remote action for completion
        self._remote_acts[n_cbt.tag] = rem_act
        self.submit_cbt(n_cbt)
        return

    def complete_remote_action_on_initiator(self, rem_act):
        """ Convert the received remote action into a CBT and complete it locally """
        # if the intended recipient is offline the XMPP server broadcasts the msg to all
        # matching ejabber ids. Verify recipient using Node ID and discard if mismatch
        if rem_act["initiator_id"] != self.node_id:
            self.log("LOG_WARNING", "A mis-delivered remote action was discarded: %s",
                         rem_act)
            return
        tag = rem_act["action_tag"]
        cbt_status = rem_act["status"]
        pending_cbt = self._cfx_handle._pending_cbts.get(tag, None)
        if pending_cbt:
            pending_cbt.set_response(data=rem_act, status=cbt_status)
            self.complete_cbt(pending_cbt)

    def req_handler_initiate_remote_action(self, cbt):
        """
        Create a new remote action from the received CBT and transmit it to the recepient
        remote_act = dict(overlay_id="",
                          recipient_id="",
                          recipient_cm="",
                          action="",
                          params=json.dumps(opaque_msg),
                          # added by Signal
                          initiator_id="",
                          initiator_cm="",
                          action_tag="",
                          data="",
                          status="")
        """
        rem_act = cbt.request.params
        peer_id = rem_act["recipient_id"]
        overlay_id = rem_act["overlay_id"]
        if overlay_id not in self._circles:
            cbt.set_response("Overlay ID not found", False)
            self.complete_cbt(cbt)
            return
        rem_act["initiator_id"] = self.node_id
        rem_act["initiator_cm"] = cbt.request.initiator
        rem_act["action_tag"] = cbt.tag
        self.transmit_remote_act(rem_act, peer_id, "invk")

    def resp_handler_remote_action(self, cbt):
        """ Convert the response CBT to a remote action and return to the initiator """
        rem_act = self._remote_acts.pop(cbt.tag)
        peer_id = rem_act["initiator_id"]
        rem_act["data"] = cbt.response.data
        rem_act["status"] = cbt.response.status
        self.transmit_remote_act(rem_act, peer_id, "cmpt")
        self.free_cbt(cbt)

    def transmit_remote_act(self, rem_act, peer_id, act_type):
        """
        Transmit rem act to peer, if Peer JID is not cached queue the rem act and attempt to
        resolve the peer's JID
        """
        olid = rem_act["overlay_id"]
        target_jid = self._circles[olid]["JidCache"].lookup(peer_id)
        transport = self._circles[olid]["Transport"]
        if target_jid is None:
            out_rem_acts = self._circles[olid]["OutgoingRemoteActs"]
            if peer_id not in out_rem_acts.keys():
                out_rem_acts[peer_id] = Queue(maxsize=0)
            out_rem_acts[peer_id].put((act_type, rem_act, time.time()))
            transport.send_presence(pstatus="uid?#" + peer_id)
        else:
            payload = json.dumps(rem_act)
            transport.send_msg(str(target_jid), act_type, payload)
            self.log("LOG_DEBUG", "Sent remote act to peer ID: %s\n Payload: %s",
                         peer_id, payload)

    def process_cbt(self, cbt):
        with self._lock:
            if cbt.op_type == "Request":
                if cbt.request.action == "SIG_REMOTE_ACTION":
                    self.req_handler_initiate_remote_action(cbt)
                elif cbt.request.action == "SIG_QUERY_REPORTING_DATA":
                    self.req_handler_query_reporting_data(cbt)
                else:
                    self.req_handler_default(cbt)
            elif cbt.op_type == "Response":
                if cbt.tag in self._remote_acts:
                    self.resp_handler_remote_action(cbt)
                else:
                    self.resp_handler_default(cbt)

    def timer_method(self, is_exiting=False):
        if is_exiting:
            return
        with self._lock:
            for overlay_id in self._circles:
                if "Transport" not in self._circles[overlay_id]: 
                    self.logger.warning("Transport not yet available")
                    continue
                self._circles[overlay_id]["Transport"].wait_until_initialized()
                if not self._circles[overlay_id]["Transport"].is_connected():
                    self.log("LOG_WARNING", "ThreadId=%d, OverlayID %s is disconnected; "
                            "attempting to recreate session",
                            self._circles[overlay_id]["TransportThread"].ident, overlay_id)
                    self._circles[overlay_id]["TransportThread"].join()
                    self._setup_circle(overlay_id)
                    continue
                anc = self._circles[overlay_id]["Announce"]
                if time.time() >= anc:
                    self._circles[overlay_id]["Transport"].send_presence(pstatus="ident#" + self.node_id)
                    self._circles[overlay_id]["Announce"] = time.time() + \
                        (self.config.get("PresenceInterval", PresenceInterval) * random.randint(2, 20))
                self._circles[overlay_id]["JidCache"].scavenge()
                self.scavenge_expired_outgoing_rem_acts(self._circles[overlay_id]
                                                        ["OutgoingRemoteActs"])
            self.scavenge_pending_cbts()

    def terminate(self):
        for overlay_id in self._circles:
            self._circles[overlay_id]["Transport"].shutdown()
            self._circles[overlay_id]["TransportThread"].join(1.0)
        self.logger.info("Module Terminating")

    def scavenge_pending_cbts(self):
        scavenge_list = []
        for item in self._cfx_handle._pending_cbts.items():
            if time.time() - item[1].time_submit >= self._request_timeout:
                scavenge_list.append(item[0])
        for tag in scavenge_list:
            pending_cbt = self._cfx_handle._pending_cbts.pop(tag, None)
            if pending_cbt:
                pending_cbt.set_response("The request has expired", False)
                self.complete_cbt(pending_cbt)

    def scavenge_expired_outgoing_rem_acts(self, outgoing_rem_acts):
        # clear out the JID Refresh queue for a peer if the oldest entry age exceeds the limit
        peer_ids = []
        for peer_id in outgoing_rem_acts:
            peer_qlen = outgoing_rem_acts[peer_id].qsize()
            if not outgoing_rem_acts[peer_id].queue:
                continue
            remact_descr = outgoing_rem_acts[peer_id].queue[0] # peek at the first/oldest entry
            if time.time() - remact_descr[2] >= self._request_timeout:
                peer_ids.append(peer_id)
                self.log("LOG_DEBUG", "Remote acts scavenged for removal peer id %s qlength %d",
                             peer_id, peer_qlen)
        for peer_id in peer_ids:
            rem_act_que = outgoing_rem_acts.pop(peer_id, Queue())
            while not rem_act_que.empty():
                entry = rem_act_que.get()
                if entry[0] == "invk":
                    tag = entry[1]["action_tag"]
                    pending_cbt = self._cfx_handle._pending_cbts.get(tag, None)
                    if pending_cbt:
                        pending_cbt.set_response("The specified recipient was not found", False)
                        self.complete_cbt(pending_cbt)
