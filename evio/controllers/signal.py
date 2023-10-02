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
import logging
import os
import ssl
import threading
import time
from queue import Queue

try:
    import simplejson as json
except ImportError:
    import json

import functools
import random
import socket
from typing import Optional, Tuple, Union

import broker
import slixmpp
from broker import CACHE_EXPIRY_INTERVAL, PRESENCE_INTERVAL, statement_false
from broker.cbt import CBT
from broker.controller_module import ControllerModule
from broker.remote_action import RemoteAction
from broker.subscription import Subscription
from slixmpp import (
    JID,
    Callback,
    ElementBase,
    Message,
    StanzaPath,
    register_stanza_plugin,
)


class EvioSignal(ElementBase):
    """Representation of SIGNAL's custom message stanza"""

    name = "evio"
    namespace = "evio:signal"
    plugin_attrib = name
    interfaces = set(("type", "payload"))


class JidCache:
    _REFLECT: list[str] = ["_cache", "_expiry"]

    def __init__(self, expiry: float):
        self._lck = threading.Lock()
        self._cache: dict[str, Tuple[JID, float]] = {}
        self._expiry = expiry

    def __repr__(self):
        return broker.introspect(self)

    def add_entry(self, node_id: str, jid: JID) -> float:
        ts = time.time()
        with self._lck:
            self._cache[node_id] = (jid, ts)
        return ts

    def scavenge(
        self,
    ):
        with self._lck:
            curr_time = time.time()
            keys_to_be_deleted = [
                key
                for key, value in self._cache.items()
                if curr_time - value[1] >= self._expiry
            ]
            for key in keys_to_be_deleted:
                del self._cache[key]

    def lookup(self, node_id: str) -> Optional[JID]:
        jid = None
        with self._lck:
            entry = self._cache.get(node_id)
            if entry and (time.time() - entry[1] < self._expiry):
                jid = entry[0]
            elif entry:
                del self._cache[node_id]
        return jid


class XmppTransport(slixmpp.ClientXMPP):
    _REFLECT: list[str] = ["_overlay_id", "_node_id"]

    def __init__(
        self, jid: Union[str, JID], password: str, sasl_mech
    ):  # param for coressponding XmppCircle
        slixmpp.ClientXMPP.__init__(self, jid, password, sasl_mech=sasl_mech)
        self._overlay_id = None
        self._node_id = None
        self.logger = None
        self.on_presence = None
        self.on_remote_action = None
        self._jid_cache: JidCache = None
        self._host = None
        self._port = None
        # TLS enabled by default.
        self._enable_tls = True
        self._enable_ssl = False
        self.xmpp_thread: Optional[threading.Thread] = None
        self._init_event = threading.Event()
        self._thread_id: int = threading.get_ident()

    def __repr__(self):
        return broker.introspect(self)

    def host(self):
        return self._host

    @staticmethod
    def factory(node_id, overlay_id, ovl_config, jid_cache, **kwargs):
        logger = kwargs["logger"]
        keyring = None
        try:
            import keyring
        except ImportError:
            logger.info("Keyring unavailable - package not installed")
        host = ovl_config["HostAddress"]
        port = ovl_config["Port"]
        user = ovl_config.get("Username", None)
        pswd = ovl_config.get("Password", None)
        auth_method = ovl_config.get("AuthenticationMethod", "PASSWORD").casefold()
        if auth_method == "x509".casefold() and (user is not None or pswd is not None):
            er_log = (
                "x509 Authentication is enbabled but credentials "
                "exists in evio configuration file; x509 will be used."
            )
            logger.warning(er_log)
        if auth_method == "x509".casefold():
            xport = XmppTransport(None, None, sasl_mech="EXTERNAL")
            xport.ssl_version = ssl.PROTOCOL_TLSv1
            xport.certfile = os.path.join(
                ovl_config["CertDirectory"], ovl_config["CertFile"]
            )
            xport.keyfile = os.path.join(
                ovl_config["CertDirectory"], ovl_config["KeyFile"]
            )
            xport._enable_ssl = True
        elif auth_method == "PASSWORD".casefold():
            if user is None:
                raise RuntimeError(
                    "No username is provided in evio configuration file."
                )
            if pswd is None and keyring is not None:
                pswd = keyring.get_password("evio", ovl_config["Username"])
            if pswd is None:
                print("{0} XMPP Password: ".format(user))
                pswd = str(input())
                if keyring is not None:
                    try:
                        keyring.set_password("evio", user, pswd)
                    except keyring.errors.PasswordSetError as err:
                        logger.error("Failed to store password in keyring. %s", err)

            xport = XmppTransport(user, pswd, sasl_mech="PLAIN")
            del pswd
        else:
            raise RuntimeError(
                "Invalid authentication method specified in configuration: {0}".format(
                    auth_method
                )
            )
        xport._host = host
        xport._port = port
        xport._overlay_id = overlay_id
        xport._node_id = node_id
        xport._jid_cache = jid_cache
        xport.logger = logger
        xport.on_presence = kwargs["on_presence"]
        xport.on_remote_action = kwargs["on_remote_action"]
        xport.on_peer_jid_updated = kwargs["on_peer_jid_updated"]
        # register event handlers of interest
        xport.add_event_handler("session_start", xport.handle_start_event)
        xport.add_event_handler("failed_auth", xport.handle_failed_auth_event)
        xport.add_event_handler("disconnected", xport.handle_disconnect_event)
        xport.add_event_handler("presence_available", xport.handle_presence_event)
        return xport

    def handle_failed_auth_event(self, event):
        self.logger.error(
            "XMPP authentication failure. Verify credentials for overlay %s and restart EVIO",
            self._overlay_id,
        )

    def handle_disconnect_event(self, reason):
        self.logger.debug("XMPP disconnected, reason=%s.", reason)
        self.loop.stop()

    def handle_start_event(self, event):
        """Registers custom event handlers at the start of XMPP session"""
        self.logger.debug("XMPP Signalling started for overlay: %s", self._overlay_id)
        try:
            # Register evio message with the server
            register_stanza_plugin(Message, EvioSignal)
            self.register_handler(
                Callback("evio", StanzaPath("message/evio"), self.handle_message)
            )
            # Get the friends list for the user
            asyncio.ensure_future(self.get_roster(), loop=self.loop)
            # Send initial sign-on presence
            self.send_presence_safe(pstatus="ident#" + self._node_id)
            self._init_event.set()
        except Exception as err:
            self.logger.error("XmppTransport: Exception:%s Event:%s", err, event)

    def handle_presence_event(self, presence):
        """
        Handle peer presence event messages
        """
        try:
            sender_jid = JID(presence["from"])
            receiver_jid = JID(presence["to"])
            status = presence["status"]
            if sender_jid == self.boundjid:
                self.logger.debug(
                    "Discarding self-presence %s->%s", sender_jid, self.boundjid
                )
                return
            if status and "#" in status:
                pstatus, node_id = status.split("#")
                if pstatus == "ident":
                    if node_id == self._node_id:
                        return
                    # a notification of a peer's node id to jid mapping
                    pts = self._jid_cache.add_entry(node_id=node_id, jid=sender_jid)
                    self.on_peer_jid_updated(self._overlay_id, node_id, sender_jid)
                    self.on_presence(
                        msg=dict(
                            PeerId=node_id,
                            OverlayId=self._overlay_id,
                            PresenceTimestamp=pts,
                        )
                    )
                    self.logger.debug(
                        "Resolved from %s, %s@%s->%s",
                        pstatus,
                        node_id[:7],
                        self._overlay_id,
                        sender_jid,
                    )
                    payload = self.boundjid.full + "#" + self._node_id
                    self.send_msg(sender_jid, "announce", payload)
                elif pstatus == "uid?":
                    # a request for our jid
                    if receiver_jid == self.boundjid and self._node_id == node_id:
                        payload = self.boundjid.full + "#" + self._node_id
                        self.send_msg(sender_jid, "uid!", payload)
                        # should do this here as well but no nid info avilable to signal
                        # self.on_peer_jid_updated(self._overlay_id, peer_nid, peer_jid)
                else:
                    self.logger.warning(
                        "Unrecognized PSTATUS:%s on overlay:%s",
                        pstatus,
                        self._overlay_id,
                    )
        except Exception as err:
            self.logger.error(
                "XmppTransport Exception: %s OverlayId: %s Presence Message: %s",
                err,
                self._overlay_id,
                presence,
            )

    def handle_message(self, msg):
        """
        Listen for matched messages on the xmpp stream, extract the header
        and payload, and takes suitable action.
        """
        try:
            sender_jid = JID(msg["from"])
            receiver_jid = JID(msg["to"])
            # discard the message if it was initiated by this node
            if receiver_jid != self.boundjid or sender_jid == self.boundjid:
                return
            # extract header and content
            msg_type = msg["evio"]["type"]
            msg_payload = msg["evio"]["payload"]
            if msg_type in ("uid!", "announce"):
                peer_jid, peer_id = msg_payload.split("#")
                # a notification of a peers node id to jid mapping
                pts = self._jid_cache.add_entry(node_id=peer_id, jid=peer_jid)
                self.on_peer_jid_updated(self._overlay_id, peer_id, peer_jid)
                self.on_presence(
                    msg=dict(
                        PeerId=peer_id,
                        OverlayId=self._overlay_id,
                        PresenceTimestamp=pts,
                    )
                )
                self.logger.debug(
                    "Resolved from %s, %s@%s->%s",
                    msg_type,
                    peer_id[:7],
                    self._overlay_id,
                    sender_jid,
                )
            elif msg_type in ("invk", "cmpt"):
                # should do this here as well but no nid info avilable to signal
                # self.on_peer_jid_updated(self._overlay_id, peer_nid, peer_jid)
                rem_act = RemoteAction(**json.loads(msg_payload))
                if self._overlay_id != rem_act.overlay_id:
                    self.logger.warning(
                        "The remote action overlay ID is invalid and has been discarded: %s",
                        rem_act,
                    )
                    return
                self.on_remote_action(rem_act, msg_type)
            else:
                self.logger.warning("Invalid message type received %s", msg)
        except Exception as err:
            self.logger.error("XmppTransport Exception: %s Message: %s", err, msg)

    def send_msg(self, peer_jid: JID, msg_type: str, payload):
        """Send a message to Peer JID via XMPP server"""
        msg = self.Message()
        msg["to"] = str(peer_jid)
        msg["from"] = str(self.boundjid)
        msg["type"] = "chat"
        msg["evio"]["type"] = msg_type
        msg["evio"]["payload"] = payload
        thread_id = threading.get_ident()
        if thread_id == self._thread_id:
            self.loop.call_soon(msg.send)
        else:
            self.loop.call_soon_threadsafe(msg.send)

    def send_presence_safe(self, pstatus):
        if threading.get_ident() == self._thread_id:
            self.loop.call_soon(functools.partial(self.send_presence, pstatus=pstatus))
        else:
            self.loop.call_soon_threadsafe(
                functools.partial(self.send_presence, pstatus=pstatus)
            )

    def wait_until_initialized(self):
        return self._init_event.wait(10.0)

    def _check_network(self):
        # handle boot time start where the network is not yet available
        res = []
        try:
            res = socket.getaddrinfo(self._host, self._port, 0, socket.SOCK_STREAM)
        except socket.gaierror as err:
            self.logger.warning(
                "Check network failed, unable to retrieve address info for %s:%s. %s",
                self._host,
                self._port,
                err,
            )
        return bool(res)

    def run(self):
        tries: int = 0
        is_net_ready: bool = self._check_network()
        while not is_net_ready:
            if tries >= 5:
                self.logger.error("Failure to resolve XMPP server address")
                self._init_event.set()
                return
            time.sleep(4)
            is_net_ready = self._check_network()

        try:
            self.connect(address=(self._host, int(self._port)))
            self.process(forever=True)
            # Do not show `asyncio.CancelledError` exceptions during shutdown

            def shutdown_exception_handler(loop, context):
                if "exception" not in context or not isinstance(
                    context["exception"], asyncio.CancelledError
                ):
                    loop.default_exception_handler(context)

            self.loop.set_exception_handler(shutdown_exception_handler)
            # Handle shutdown by waiting for all tasks to be cancelled
            tasks = asyncio.gather(
                *asyncio.all_tasks(loop=self.loop),
                loop=self.loop,
                return_exceptions=True
            )
            tasks.add_done_callback(lambda t: self.loop.stop())
            tasks.cancel()
            # Keep the event loop running, after stop is called run_forever loops only once
            while not tasks.done() and not self.loop.is_closed():
                self.loop.run_forever()
        except Exception as err:
            self.logger.error("XMPPTransport run exception %s", err)
        finally:
            self.loop.run_until_complete(self.loop.shutdown_asyncgens())
            self.loop.close()
            self.logger.debug("Event loop closed on XMPP overlay=%s", self._overlay_id)

    def shutdown(
        self,
    ):
        self.logger.debug("Initiating shutdown of XMPP overlay=%s", self._overlay_id)
        self.loop.call_soon_threadsafe(self.disconnect(reason="controller shutdown"))
        self.logger.debug("Disconnect of XMPP overlay=%s", self._overlay_id)


class XmppCircle:
    def __init__(
        self, node_id: str, overlay_id: str, ovl_config: dict, **kwargs
    ) -> None:
        self.node_id: str = node_id
        self.overlay_id: str = overlay_id
        self.ovl_config = ovl_config
        self.logger: logging.Logger = kwargs["logger"]
        self.on_presence = kwargs["on_presence"]
        self.on_remote_action = kwargs["on_remote_action"]
        self.on_peer_jid_updated = kwargs["on_peer_jid_updated"]
        self._transmission_queue: dict[str, Queue] = {}
        self.jid_cache: JidCache = JidCache(
            ovl_config.get("CacheExpiry", CACHE_EXPIRY_INTERVAL)
        )
        self.xport: XmppTransport = None
        self._xport_thread = threading.Thread(
            target=self._setup_transport_instance,
            daemon=True,
            name="XMPP.Client",
        )

    @property
    def transmit_queue(self) -> dict[str, Queue]:
        return self._transmission_queue

    def peer_transmit_queue(self, peer_id) -> Queue:
        return self._transmission_queue[peer_id]

    def _setup_transport_instance(self):
        """
        The ClientXMPP object must be instantiated on its own thread.
        ClientXMPP->BaseXMPP->XMLStream->asyncio.queue attempts to get the eventloop associate with
        this thread. This means an eventloop must be created and set for the current thread, if one
        does not  already exist, before instantiating ClientXMPP.
        """
        asyncio.set_event_loop(asyncio.new_event_loop())
        self.xport = XmppTransport.factory(
            self.node_id,
            self.overlay_id,
            self.ovl_config,
            self.jid_cache,
            logger=self.logger,
            on_presence=self.on_presence,
            on_remote_action=self.on_remote_action,
            on_peer_jid_updated=self.on_peer_jid_updated,
        )
        self.xport.run()

    def start(self):
        self._xport_thread.start()

    def terminate(self):
        self.xport.shutdown()
        self._xport_thread.join()


class Signal(ControllerModule):
    _REFLECT: list[str] = [
        "_circles",
        "_in_remote_acts",
        "_cbts_pending_remote_resp",
        "_request_timeout",
    ]

    def __init__(self, nexus, module_config):
        super().__init__(nexus, module_config)
        self._presence_publisher: Subscription = None
        self._circles: dict[str, XmppCircle] = {}
        self._recv_remote_acts_invk_locally: dict[str, RemoteAction] = {}
        self._cbts_pending_remote_resp: dict[
            str, CBT
        ] = {}  # use to track the cbt to be completed when the rem act returns
        self._lck = threading.Lock()
        self._request_timeout = self._nexus.query_param("RequestTimeout")

    def initialize(self):
        self._presence_publisher = self.publish_subscription("SIG_PEER_PRESENCE_NOTIFY")
        for olid in self.overlays:
            xcir = XmppCircle(
                self.node_id,
                olid,
                self.overlays[olid],
                logger=self.logger,
                on_presence=self.on_presence,
                on_remote_action=self.on_remote_action,
                on_peer_jid_updated=self.on_peer_jid_updated,
            )
            self._circles[olid] = xcir
            xcir.start()
            self.register_timed_transaction(
                self,
                statement_false,
                self.on_exp_presence,
                PRESENCE_INTERVAL * random.randint(2, 5),
            )
        self.logger.info("Controller module loaded")

    def _next_anc_interval(self):
        return self.config.get("PresenceInterval", PRESENCE_INTERVAL) * random.randint(
            10, 20
        )

    def announce_presence(self):
        for circ in self._circles.values():
            if circ.xport and circ.xport.is_connected():
                circ.xport.send_presence_safe(pstatus="ident#" + self.node_id)
            self.register_timed_transaction(
                self,
                statement_false,
                self.on_exp_presence,
                self._next_anc_interval(),
            )

    def on_exp_presence(self, *_):
        self.announce_presence()

    def on_presence(self, msg):
        self._presence_publisher.post_update(msg)

    def req_handler_query_reporting_data(self, cbt: CBT) -> dict:
        rpt = {}
        for overlay_id in self.overlays:
            rpt[overlay_id] = {
                "xmpp_host": self._circles[overlay_id].xport.host(),
                "xmpp_username": self._circles[overlay_id].xport.boundjid.full,
            }
        cbt.set_response(rpt, True)
        self.complete_cbt(cbt)

    def on_remote_action(self, rem_act: RemoteAction, act_type: str):
        if act_type == "invk":
            self.invoke_remote_action_on_target(rem_act)
        elif act_type == "cmpt":
            self.complete_remote_action_on_initiator(rem_act)

    def invoke_remote_action_on_target(self, rem_act: RemoteAction):
        """Convert the received remote action into a CBT and invoke it locally"""
        # if the intended recipient is offline the XMPP server broadcasts the msg to all
        # matching ejabber ids. Verify recipient using Node ID and discard if mismatch

        if rem_act.recipient_id != self.node_id:
            self.logger.warning(
                "A mis-delivered remote action was discarded: %s", rem_act
            )
            return
        n_cbt = self.create_cbt(rem_act.recipient_cm, rem_act.action, rem_act.params)
        # store the remote action for completion
        with self._lck:
            self._recv_remote_acts_invk_locally[n_cbt.tag] = rem_act
        self.submit_cbt(n_cbt)
        return

    def complete_remote_action_on_initiator(self, rem_act: RemoteAction):
        """Convert the received remote action into a CBT and complete it locally"""
        # if the intended recipient is offline the XMPP server broadcasts the msg to all
        # matching ejabber ids.

        if rem_act.initiator_id != self.node_id:
            self.logger.warning(
                "A mis-delivered remote action was discarded: %s", rem_act
            )
            return
        tag = rem_act.action_tag
        cbt_status = rem_act.status
        with self._lck:
            cbt = self._cbts_pending_remote_resp.pop(tag, None)
        if cbt and cbt.is_pending:
            cbt.set_response(data=rem_act, status=cbt_status)
            self.complete_cbt(cbt)

    def req_handler_initiate_remote_action(self, cbt: CBT):
        """
        Create a new remote action from the received CBT and transmit it to the recepient
        """
        rem_act = cbt.request.params
        peer_id = rem_act.recipient_id
        overlay_id = rem_act.overlay_id
        if overlay_id not in self._circles:
            cbt.set_response("Overlay ID not found", False)
            self.complete_cbt(cbt)
            return
        rem_act.initiator_id = self.node_id
        rem_act.initiator_cm = cbt.request.initiator
        rem_act.action_tag = cbt.tag
        self._cbts_pending_remote_resp[cbt.tag] = cbt
        self.transmit_remote_act(rem_act, peer_id, "invk")

    def req_handler_send_waiting_remote_acts(self, cbt: CBT):
        overlay_id = cbt.request.params["OverlayId"]
        peer_id = cbt.request.params["PeerId"]
        peer_jid = cbt.request.params["PeerJid"]
        self._send_waiting_remote_acts(overlay_id, peer_id, peer_jid)
        cbt.set_response(None, True)
        self.complete_cbt(cbt)

    def resp_handler_remote_action(self, cbt: CBT):
        """Convert the response CBT to a remote action and return to the initiator to be completed there"""
        rem_act = self._recv_remote_acts_invk_locally.pop(cbt.tag)
        peer_id = rem_act.initiator_id
        rem_act.data = cbt.response.data
        rem_act.status = cbt.response.status
        self.transmit_remote_act(rem_act, peer_id, "cmpt")
        self.free_cbt(cbt)

    def _send_waiting_remote_acts(self, overlay_id, peer_id, peer_jid):
        # out_rem_acts = self._circles[overlay_id]["OutgoingRemoteActs"]
        out_rem_acts = self._circles[overlay_id].transmit_queue
        if peer_id in out_rem_acts:
            transport = self._circles[overlay_id].xport
            ra_que = out_rem_acts.get(peer_id)
            while not ra_que.qsize() > 0:
                entry = ra_que.get()
                msg_type, msg_data = entry[0], dict(entry[1])
                transport.send_msg(peer_jid, msg_type, json.dumps(msg_data))
                self.logger.debug("Sent queued remote action: %s", msg_data)

    def transmit_remote_act(self, rem_act: RemoteAction, peer_id, act_type):
        """
        Transmit rem act to peer, if Peer JID is not cached queue the rem act and
        attempt to resolve the peer's JID
        """
        olid = rem_act.overlay_id
        peer_jid = self._circles[olid].jid_cache.lookup(peer_id)
        transport = self._circles[olid].xport
        if peer_jid is None:
            out_rem_acts = self._circles[olid].transmit_queue
            if peer_id not in out_rem_acts:
                out_rem_acts[peer_id] = Queue(maxsize=0)
            out_rem_acts[peer_id].put((act_type, rem_act, time.time()))
            transport.send_presence_safe(pstatus="uid?#" + peer_id)
        else:
            # JID can be updated by a separate presence update,
            # send any waiting msgs in the outgoing remote act queue
            self._send_waiting_remote_acts(olid, peer_id, peer_jid)
            payload = json.dumps(dict(rem_act))
            transport.send_msg(str(peer_jid), act_type, payload)
            self.logger.debug("Sent remote act to %s\n Payload: %s", peer_id, payload)

    def on_peer_jid_updated(self, overlay_id, peer_id, peer_jid):
        self.register_internal_cbt(
            "_PEER_JID_UPDATED_",
            {"OverlayId": overlay_id, "PeerId": peer_id, "PeerJid": peer_jid},
        )

    def process_cbt(self, cbt: CBT):
        with self._lck:
            if cbt.is_expired:
                self.abort_handler(cbt)
            elif cbt.is_pending:
                if cbt.request.action == "SIG_REMOTE_ACTION":
                    self.req_handler_initiate_remote_action(cbt)
                elif cbt.request.action == "SIG_QUERY_REPORTING_DATA":
                    self.req_handler_query_reporting_data(cbt)
                elif cbt.request.action == "_PEER_JID_UPDATED_":
                    self.req_handler_send_waiting_remote_acts(cbt)
                else:
                    self.req_handler_default(cbt)
            elif cbt.is_completed:
                if cbt.tag in self._recv_remote_acts_invk_locally:
                    self.resp_handler_remote_action(cbt)
                else:
                    self.resp_handler_default(cbt)

    def on_timer_event(self):
        for overlay_id in self._circles:
            if not self._circles[overlay_id].xport:
                self.logger.warning("Transport not yet available")
                continue
            self._circles[overlay_id].xport.wait_until_initialized()
            if not self._circles[overlay_id].xport.is_connected():
                self.logger.warning(
                    "Attempting XMPP session connection for overlay %s on thread %s",
                    overlay_id,
                    self._circles[overlay_id]._xport_thread.ident,
                )
                self._circles[overlay_id]._xport_thread.join()
                self._setup_circle(overlay_id)
                continue
            self._circles[overlay_id].jid_cache.scavenge()
            with self._lck:
                self.scavenge_expired_outgoing_rem_acts(
                    self._circles[overlay_id].transmit_queue
                )

    def terminate(self):
        with self._lck:
            for overlay_id in self._circles:
                self._circles[overlay_id].terminate()
        self.logger.info("Controller module terminating")

    def abort_handler(self, cbt: CBT):
        """Additional resouce clean here, eg., fail edge negotiate or create"""
        self._recv_remote_acts_invk_locally.pop(cbt.tag, None)
        self.free_cbt(cbt)

    def scavenge_expired_outgoing_rem_acts(self, outgoing_rem_acts):
        # clear out the JID Refresh queue for a peer if the oldest entry age exceeds the limit
        peer_ids = []
        for peer_id in outgoing_rem_acts:
            peer_qlen = outgoing_rem_acts[peer_id].qsize()
            if not outgoing_rem_acts[peer_id].queue:
                continue
            remact_descr = outgoing_rem_acts[peer_id].queue[
                0
            ]  # peek at the first/oldest entry
            if time.time() - remact_descr[2] >= self._request_timeout:
                peer_ids.append(peer_id)
                self.logger.debug(
                    "Remote acts scavenged for removal peer id %s qlength %d",
                    peer_id,
                    peer_qlen,
                )
        for peer_id in peer_ids:
            rem_act_que = outgoing_rem_acts.pop(peer_id, Queue())
            while not rem_act_que.qsize() > 0:
                entry = rem_act_que.get()
                rem_act_que.task_done()
                self.logger.info("failed to send remote action response %s", entry)

    def _setup_circle(self, overlay_id):
        xcir = XmppCircle(
            self.node_id,
            overlay_id,
            self.overlays[overlay_id],
            logger=self.logger,
            on_presence=self.on_presence,
            on_remote_action=self.on_remote_action,
            on_peer_jid_updated=self.on_peer_jid_updated,
        )
        self._circles[overlay_id] = xcir
        xcir.start()
