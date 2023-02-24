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

import importlib
import time
import unittest
from queue import Queue
from time import sleep
from unittest.mock import MagicMock, Mock, patch

from broker.cbt import CBT
from broker.nexus import Nexus
from slixmpp import JID, Callback, Message, StanzaPath, register_stanza_plugin

from evio.controllers.signal import EvioSignal, JidCache, XmppTransport


class SignalTest(unittest.TestCase):
    def setup_vars_mocks(self):
        """
        Setup the variables and the mocks required by the unit tests.
        :return: The signal object and signal dictionary
        """
        nexus = Mock()
        module = importlib.import_module("controllers.{0}".format("Signal"))
        module_class = getattr(module, "Signal")
        sig_dict = {
            "Signal": {
                "Enabled": True,
                "PresenceInterval": 10,
                "CacheExpiry": 5,
                "Overlays": {
                    "A0FB389": {
                        "HostAddress": "1.1.1.1",
                        "Port": "5222",
                        "Username": "raj",
                        "Password": "raj",
                        "AuthenticationMethod": "PASSWORD",
                    }
                },
                "NodeId": "1234434323",
            }
        }
        signal = module_class(nexus, sig_dict["Signal"], "Signal")
        nexus._cm_instance = signal
        nexus._cm_config = sig_dict["Signal"]
        return sig_dict, signal

    def testtransport_start_event_handler(self):
        """
        Test to check the start of the event handler of the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        transport = XmppTransport.factory(
            1, sig_dict["Signal"]["Overlays"]["A0FB389"], signal, None, None, None
        )
        transport._sig.sig_log = MagicMock()
        transport.add_event_handler = MagicMock()
        transport.register_handler = MagicMock()
        transport.get_roster = MagicMock()
        transport.start_event_handler(event=None)
        transport.add_event_handler.assert_called_once()
        transport.get_roster.assert_called_once()
        print("Passed : testtransport_start_event_handler")

    def testtransport_connect_to_server(self):
        """
        Test to check the connect to server of the transport instance of the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        transport = XmppTransport.factory(
            1, sig_dict["Signal"]["Overlays"]["A0FB389"], signal, None, None, None
        )
        transport._sig.sig_log = MagicMock()
        transport.connect = MagicMock()
        XmppTransport.connect_to_server(transport)
        transport._sig.sig_log.assert_called_once()
        transport.connect.assert_called_once()
        print("Passed : testtransport_connect_to_server")

    def testtransport_start_process(self):
        """
        Test to check the start_process method of the transport instance of the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        transport = XmppTransport.factory(
            1, sig_dict["Signal"]["Overlays"]["A0FB389"], signal, None, None, None
        )
        transport.loop.run_forever = MagicMock()
        transport.start_process()
        transport.loop.run_forever.assert_called_once()
        print("Passed : testtransport_start_process")

    def testtransport_factory_with_password(self):
        """
        Test to check the factory method of the transport instance of the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        self.assertTrue(
            isinstance(
                XmppTransport.factory(
                    "1",
                    sig_dict["Signal"]["Overlays"]["A0FB389"],
                    signal,
                    signal._presence_publisher,
                    None,
                    None,
                ),
                XmppTransport,
            )
        )
        print("Passed : testtransport_factory_with_password")

    def testtransport_factory_with_x509(self):
        """
        Test to check the factory method of the transport instance with x509 auth_method of the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        sig_dict["Signal"]["Overlays"]["A0FB389"]["AuthenticationMethod"] = "x509"
        sig_dict["Signal"]["Overlays"]["A0FB389"]["TrustStore"] = {}
        sig_dict["Signal"]["Overlays"]["A0FB389"]["CertDirectory"] = "/home/cert"
        sig_dict["Signal"]["Overlays"]["A0FB389"]["CertFile"] = "file1"
        sig_dict["Signal"]["Overlays"]["A0FB389"]["KeyFile"] = "keyfile"
        transport = XmppTransport.factory(
            "1",
            sig_dict["Signal"]["Overlays"]["A0FB389"],
            signal,
            signal._presence_publisher,
            None,
            None,
        )
        self.assertTrue(isinstance(transport, XmppTransport))
        print(transport.certfile)
        print(transport.keyfile)
        assert transport.certfile == "/home/cert\\file1"
        assert transport.keyfile == "/home/cert\keyfile"
        print("Passed : testtransport_factory_with_x509")

    def testtransport_factory_without_password(self):
        """
        Test to check the factory method of the transport instance without the password of the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        sig_dict["Signal"]["Overlays"]["A0FB389"]["Password"] = None
        transport = XmppTransport.factory(
            "1",
            sig_dict["Signal"]["Overlays"]["A0FB389"],
            signal,
            signal._presence_publisher,
            None,
            None,
        )
        transport.add_event_handler = MagicMock()
        transport.register_handler = MagicMock()
        transport.get_roster = MagicMock()
        self.assertTrue(isinstance(transport, XmppTransport))
        print("Passed : testtransport_factory_without_password")

    def testtransport_factory_without_user(self):
        """
        Test to check the factory method of the transport instance without the username of the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        sig_dict["Signal"]["Overlays"]["A0FB389"]["Username"] = None
        with self.assertRaises(RuntimeError):
            transport = XmppTransport.factory(
                "1",
                sig_dict["Signal"]["Overlays"]["A0FB389"],
                signal,
                signal._presence_publisher,
                None,
                None,
            )
        print("Passed : testtransport_factory_without_user")

    def testtransport_presence_event_handler(self):
        """
        Test to check the presence method with ident of the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        transport = XmppTransport.factory(
            "1",
            sig_dict["Signal"]["Overlays"]["A0FB389"],
            signal,
            signal._presence_publisher,
            None,
            None,
        )
        presence = {"from": "raj", "to": "raj@ipop", "status": "ident#12344323"}
        transport.boundjid = JID("raj@ipop/ipop")
        transport.send_msg = MagicMock()
        jid_cache = Mock()
        presence_publisher = Mock()
        transport._presence_publisher = presence_publisher
        transport._presence_publisher.post_update = MagicMock()
        transport._jid_cache = jid_cache
        transport._jid_cache.add_entry = MagicMock()
        transport.presence_event_handler(presence)
        transport.send_msg.assert_called_once()
        print("Passed : testtransport_presence_event_handler")

    def testtransport_presence_event_handler_with_uid(self):
        """
        Test to check the presence method with uid of the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        transport = XmppTransport.factory(
            "1",
            sig_dict["Signal"]["Overlays"]["A0FB389"],
            signal,
            signal._presence_publisher,
            None,
            None,
        )
        presence = {"from": "raj", "to": "raj@ipop", "status": "uid?#1234434323"}
        transport.boundjid = JID("raj@ipop/ipop")
        transport.send_msg = MagicMock()
        jid_cache = Mock()
        presence_publisher = Mock()
        transport._presence_publisher = presence_publisher
        transport._presence_publisher.post_update = MagicMock()
        transport._jid_cache = jid_cache
        transport._jid_cache.add_entry = MagicMock()
        transport.presence_event_handler(presence)
        transport.send_msg.assert_called_once()
        print("Passed : testtransport_presence_event_handler_with_uid")

    def testtransport_presence_event_handler_with_no_status(self):
        """
        Test to check the presence method with no valid status of the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        transport = XmppTransport.factory(
            "1",
            sig_dict["Signal"]["Overlays"]["A0FB389"],
            signal,
            signal._presence_publisher,
            None,
            None,
        )
        presence = {"from": "raj", "to": "raj@ipop", "status": "ipop?#1234434323"}
        transport.boundjid = JID("raj@ipop/ipop")
        jid_cache = Mock()
        presence_publisher = Mock()
        transport._presence_publisher = presence_publisher
        transport._presence_publisher.post_update = MagicMock()
        transport._jid_cache = jid_cache
        transport._jid_cache.add_entry = MagicMock()
        transport._sig.sig_log = MagicMock()
        transport.presence_event_handler(presence)
        transport._sig.sig_log.assert_called_once()
        print("Passed : testtransport_presence_event_handler_with_uid")

    def testtransport_presence_event_handler_with_exception(self):
        """
        Test to check the presence method with an exception raised of the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        transport = XmppTransport.factory(
            "1",
            sig_dict["Signal"]["Overlays"]["A0FB389"],
            signal,
            signal._presence_publisher,
            None,
            None,
        )
        presence = {"from": "raj", "to": "raj@ipop", "status": "uid?#1234434323"}
        transport.boundjid = JID("raj@ipop/ipop")
        transport.send_msg = MagicMock()
        transport.send_msg.side_effect = Exception()
        jid_cache = Mock()
        presence_publisher = Mock()
        transport._presence_publisher = presence_publisher
        transport._presence_publisher.post_update = MagicMock()
        transport._jid_cache = jid_cache
        transport._jid_cache.add_entry = MagicMock()
        transport._sig.sig_log = MagicMock()
        transport.presence_event_handler(presence)
        transport.send_msg.assert_called_once()
        transport._sig.sig_log.assert_called_once()
        print("Passed : testtransport_presence_event_handler_with_uid")

    def testtransport_message_listener_with_uid(self):
        """
        Test to check the message_listener method with uid of the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        transport = XmppTransport.factory(
            "1",
            sig_dict["Signal"]["Overlays"]["A0FB389"],
            signal,
            signal._presence_publisher,
            None,
            None,
        )
        transport._jid_cache = JidCache(signal, 30)
        register_stanza_plugin(Message, EvioSignal)
        msg = Message()
        msg["from"] = "ipop"
        transport.boundjid.full = "edgevpn"
        msg["evio"]["type"] = "uid!"
        msg["evio"]["payload"] = "123#456"
        item = {0: "invk", 1: {"ActionTag": "1"}, 2: 5}
        q = Queue()
        q.put_nowait(item)
        outgoing_rem_acts = {"456": q}
        transport._outgoing_rem_acts = outgoing_rem_acts
        transport.send_msg = MagicMock()
        transport.message_listener(msg)
        assert transport._jid_cache.lookup("456") == "123"
        transport.send_msg.assert_called_once()
        print("Passed : testtransport_presence_event_handler_with_uid")

    def testtransport_message_listener_with_announce_to_same_node(self):
        """
        Test to check the message_listener method with announce to the same of the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        transport = XmppTransport.factory(
            "1",
            sig_dict["Signal"]["Overlays"]["A0FB389"],
            signal,
            signal._presence_publisher,
            None,
            None,
        )
        transport._jid_cache = JidCache(signal, 30)
        register_stanza_plugin(Message, EvioSignal)
        msg = Message()
        msg["from"] = "ipop"
        transport.boundjid.full = "edgevpn"
        msg["evio"]["type"] = "announce"
        msg["evio"]["payload"] = "123#456"
        sig_dict["Signal"]["NodeId"] = "456"
        transport.send_msg = MagicMock()
        transport._presence_publisher = Mock()
        transport._presence_publisher.post_update = MagicMock()
        transport.message_listener(msg)
        self.assertEqual(transport._jid_cache.lookup("456"), None)
        transport.send_msg.assert_not_called()
        transport._presence_publisher.post_update.assert_not_called()
        print("Passed : testtransport_message_listener_with_announce_to_same_node")

    def testtransport_message_listener_with_announce_to_different_node(self):
        """
        Test to check the message_listener method with announce to a different node of the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        transport = XmppTransport.factory(
            "1",
            sig_dict["Signal"]["Overlays"]["A0FB389"],
            signal,
            signal._presence_publisher,
            None,
            None,
        )
        transport._jid_cache = JidCache(signal, 30)
        register_stanza_plugin(Message, EvioSignal)
        msg = Message()
        msg["from"] = "ipop"
        transport.boundjid.full = "edgevpn"
        msg["evio"]["type"] = "announce"
        msg["evio"]["payload"] = "123#456"
        transport._presence_publisher = Mock()
        transport._presence_publisher.post_update = MagicMock()
        transport.message_listener(msg)
        self.assertEqual(transport._jid_cache.lookup("456"), "123")
        transport._presence_publisher.post_update.assert_called_once()
        print("Passed : testtransport_message_listener_with_announce_to_same_node")

    @patch("json.loads")
    def testtransport_message_listener_with_invk(self, mock_loads):
        """
        Test to check the message_listener method with invk to a different node of the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        mock_loads.return_value = MagicMock()
        transport = XmppTransport.factory(
            "1",
            sig_dict["Signal"]["Overlays"]["A0FB389"],
            signal,
            signal._presence_publisher,
            None,
            None,
        )
        transport._jid_cache = JidCache(signal, 30)
        register_stanza_plugin(Message, EvioSignal)
        msg = Message()
        msg["from"] = "ipop"
        transport.boundjid.full = "edgevpn"
        msg["evio"]["type"] = "invk"
        msg["evio"]["payload"] = {"Action": "announce"}
        transport._sig.handle_remote_action = MagicMock()
        transport.message_listener(msg)
        mock_loads.assert_called_once()
        transport._sig.handle_remote_action.assert_called_once()
        print("Passed : testtransport_message_listener_with_invk")

    def testsignal_initialize(self):
        """
        Test to check the initialize method of the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        signal._create_transport_instance = MagicMock()
        signal.initialize()
        signal._create_transport_instance.assert_called_once()
        print("Passed : testsignal_initialize")

    @patch("controllers.Signal.XmppTransport.factory")
    def testsignal_create_transport(self, mock_factory):
        """
        Test to check the create transport method of the signal class.
        """
        nexus = Mock()
        nexus.query_param.return_value = 30
        module = importlib.import_module("controllers.{0}".format("Signal"))
        module_class = getattr(module, "Signal")
        sig_dict = {
            "Signal": {
                "Enabled": True,
                "Overlays": {
                    "A0FB389": {
                        "HostAddress": "1.1.1.1",
                        "Port": "5222",
                        "Username": "raj",
                        "Password": "raj",
                        "AuthenticationMethod": "PASSWORD",
                    }
                },
                "NodeId": "1234434323",
            }
        }
        signal = module_class(nexus, sig_dict["Signal"], "Signal")
        nexus._cm_instance = signal
        nexus._cm_config = sig_dict
        transport = XmppTransport(
            sig_dict["Signal"]["Overlays"]["A0FB389"]["Username"],
            sig_dict["Signal"]["Overlays"]["A0FB389"]["Password"],
            sasl_mech="PLAIN",
        )
        mock_factory.return_value = transport
        transport.connect_to_server = MagicMock()
        assert (
            signal._create_transport_instance(
                "1", sig_dict["Signal"]["Overlays"]["A0FB389"], None, None
            )
            == transport
        )
        print("Passed : testsignal_create_transport")

    def testsignal_handle_remote_action_invoke(self):
        """
        Test to check the handling of remote action with action as invoke in the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        rem_act = {
            "RecipientCM": "1234434323",
            "Action": "Sleep",
            "Params": "None",
            "OverlayId": "A0FB389",
            "RecipientId": "1234434323",
        }
        signal.submit_cbt = MagicMock()
        signal.handle_remote_action("A0FB389", rem_act, "invk")
        signal.submit_cbt.assert_called_once()
        print("Passed : testsignal_handle_remote_action_invoke")

    def testsignal_handle_remote_action_complete(self):
        """
        Test to check the handling of remote action with action as complete in the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        rem_act = {
            "RecipientCM": "1234434323",
            "Action": "Sleep",
            "Params": "None",
            "OverlayId": "A0FB389",
            "InitiatorId": "1234434323",
            "ActionTag": "None",
            "Status": "Active",
        }
        signal.complete_cbt = MagicMock()
        signal.handle_remote_action("A0FB389", rem_act, "cmpt")
        signal.complete_cbt.assert_called_once()
        print("Passed : testsignal_handle_remote_action_complete")

    @patch("controllers.Signal.XmppTransport.Message")
    def testtransport_send_message(self, msg_mock):
        """
        Test to check the send message method of transport instance of the signal class.
        """
        register_stanza_plugin(Message, EvioSignal)
        sig_dict, signal = self.setup_vars_mocks()
        transport = XmppTransport.factory(
            "1",
            sig_dict["Signal"]["Overlays"]["A0FB389"],
            signal,
            signal._presence_publisher,
            None,
            None,
        )
        transport.loop.call_soon_threadsafe = MagicMock()
        transport.register_handler(
            Callback("ipop", StanzaPath("message/ipop"), transport.message_listener)
        )
        msg = transport.Message()
        msg_mock.return_value = msg
        msg.send = MagicMock()
        transport.send_msg("2", "invk", "Data")
        transport.loop.call_soon_threadsafe.assert_called_once()
        transport.loop.call_soon_threadsafe.assert_called_with(msg.send)
        print("Passed : testtransport_send_message")

    def testjid_cache_add_lookup_entry(self):
        """
        Test to check the lookup method of the jid-cache of the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        jid_cache = JidCache(signal, 30)
        jid_cache.add_entry("123", "2345")
        assert jid_cache.lookup("123") == "2345"
        print("Passed : testjid_cache_add_lookup_entry")

    def testjid_cache_scavenge(self):
        """
        Test to check the scavenge method of the jid-cache of the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        jid_cache = JidCache(signal, 5)
        jid_cache.add_entry("123", "2345")
        assert jid_cache.lookup("123") == "2345"
        sleep(5)
        jid_cache.scavenge()
        assert jid_cache.lookup("123") is None
        print("Passed : testjid_cache_scavenge")

    def testsignal_req_handler_initiate_remote_action(self):
        """
        Test to check the handling remote action method  with a request of the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        jid_cache = JidCache(signal, 5)
        jid_cache.add_entry("1", "2345")
        transport = XmppTransport.factory(
            "1",
            sig_dict["Signal"]["Overlays"]["A0FB389"],
            signal,
            signal._presence_publisher,
            None,
            None,
        )
        transport.send_msg = MagicMock()
        signal._circles = {"A0FB389": {"JidCache": jid_cache, "Transport": transport}}
        cbt = CBT()
        cbt.request.params = {"RecipientId": "1", "OverlayId": "A0FB389"}
        signal.req_handler_initiate_remote_action(cbt)
        transport.send_msg.assert_called_once()
        print("Passed : testsignal_req_handler_initiate_remote_action")

    def testsignal_resp_handler_remote_action(self):
        """
        Test to check the handling remote action method  with a response of the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        cbt = CBT()
        cbt.request.params = {"RecipientId": "1", "OverlayId": "A0FB389"}
        jid_cache = JidCache(signal, 5)
        jid_cache.add_entry("1", "2345")
        transport = XmppTransport.factory(
            "1",
            sig_dict["Signal"]["Overlays"]["A0FB389"],
            signal,
            signal._presence_publisher,
            None,
            None,
        )
        transport.send_msg = MagicMock()
        signal._circles = {"A0FB389": {"JidCache": jid_cache, "Transport": transport}}
        cbt.tag = "1"
        signal.submit_cbt(cbt)
        resp = CBT.Response()
        cbt.response = resp
        rem_act = {"InitiatorId": "1", "OverlayId": "A0FB389"}
        signal._remote_acts["1"] = rem_act
        signal.submit_cbt(cbt)
        signal.transmit_remote_act = MagicMock()
        signal.free_cbt = MagicMock()
        signal.resp_handler_remote_action(cbt)
        signal.transmit_remote_act.assert_called_once()
        signal.free_cbt.assert_called_once()
        print("Passed : testsignal_resp_handler_remote_action")

    def testsignal_req_handler_query_reporting_data(self):
        """
        Test to check the reporting of data method of the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        cbt = CBT()
        transport = XmppTransport.factory(
            "1",
            sig_dict["Signal"]["Overlays"]["A0FB389"],
            signal,
            signal._presence_publisher,
            None,
            None,
        )
        transport._host = "IPOP"
        transport.boundjid.full = "ipopuser"
        signal._circles = {"A0FB389": {"Transport": transport}}
        signal.complete_cbt = MagicMock()
        signal.req_handler_query_reporting_data(cbt)
        signal.complete_cbt.assert_called_once()
        print("Passed : testsignal_req_handler_query_reporting_data")

    def testtransmit_remote_act(self):
        """
        Test to check the transmit remote action method of the signal class.
        """
        rem_act = {"InitiatorId": "1", "OverlayId": "A0FB389"}
        sig_dict, signal = self.setup_vars_mocks()
        jid_cache = JidCache(signal, 5)
        jid_cache.add_entry("1", "2345")
        transport = XmppTransport.factory(
            "1",
            sig_dict["Signal"]["Overlays"]["A0FB389"],
            signal,
            signal._presence_publisher,
            None,
            None,
        )
        transport.send_msg = MagicMock()
        signal._circles = {"A0FB389": {"JidCache": jid_cache, "Transport": transport}}
        signal.transmit_remote_act(rem_act, "1", "invk")
        transport.send_msg.assert_called_once()
        print("Passed : testtransmit_remote_act")

    def testtransmit_remote_act_nopeer_jid(self):
        """
        Test to check the transmit remote action method with no peer jid of the signal class.
        """
        rem_act = {"InitiatorId": "1", "OverlayId": "A0FB389"}
        sig_dict, signal = self.setup_vars_mocks()
        jid_cache = JidCache(signal, 5)
        transport = XmppTransport.factory(
            "1",
            sig_dict["Signal"]["Overlays"]["A0FB389"],
            signal,
            signal._presence_publisher,
            None,
            None,
        )
        transport.send_presence = MagicMock()
        signal._circles = {
            "A0FB389": {
                "JidCache": jid_cache,
                "Transport": transport,
                "OutgoingRemoteActs": {},
            }
        }
        signal.transmit_remote_act(rem_act, "1", "invk")
        transport.send_presence.assert_called_once()
        print("Passed : testtransmit_remote_act_nopeer_jid")

    def testsignal_process_cbt_request_rem_act(self):
        """
        Test to check the process cbt method with a request to initiate a remote action of the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        cbt = CBT()
        cbt.op_type = "Request"
        cbt.request.action = "SIG_REMOTE_ACTION"
        signal.req_handler_initiate_remote_action = MagicMock()
        signal.process_cbt(cbt)
        signal.req_handler_initiate_remote_action.assert_called_once()
        print("Passed : testprocess_cbt_request_rem_act")

    def testsignal_process_cbt_request_rep_data(self):
        """
        Test to check the process cbt method with a request to report data of the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        cbt = CBT()
        cbt.op_type = "Request"
        cbt.request.action = "SIG_QUERY_REPORTING_DATA"
        signal.req_handler_query_reporting_data = MagicMock()
        signal.process_cbt(cbt)
        signal.req_handler_query_reporting_data.assert_called_once()
        print("Passed : testprocess_cbt_request_rep_data")

    def testsignal_process_cbt_resp_tag_present(self):
        """
        Test to check the process cbt method with a response with the cbt tag present.
        """
        sig_dict, signal = self.setup_vars_mocks()
        signal._remote_acts = {"1"}
        signal.resp_handler_remote_action = MagicMock()
        cbt = CBT()
        cbt.op_type = "Response"
        cbt.tag = "1"
        signal.process_cbt(cbt)
        signal.resp_handler_remote_action.assert_called_once()
        print("Passed : testprocess_cbt_resp_tag_present")

    def testsignal_process_cbt_resp_with_parent(self):
        """
        Test to check the process cbt method with a response with the parent present and no tag.
        """
        sig_dict, signal = self.setup_vars_mocks()
        cbt1 = CBT()
        cbt = CBT()
        cbt.op_type = "Response"
        cbt.parent = cbt1
        resp = CBT.Response()
        resp.data = "Data"
        cbt.response = resp
        cbt.response.status = "OK"
        cbt1.child_count = 1
        signal.free_cbt = MagicMock()
        signal.complete_cbt = MagicMock()
        signal.process_cbt(cbt)
        signal.free_cbt.assert_called_once()
        signal.complete_cbt.assert_called_once()
        print("Passed : test_process_cbt_resp_with_parent")

    def testsignal_process_cbt_resp_with_parent_more_children(self):
        """
        Test to check the process cbt method with a response with the parent present and no tag and more than 1 child.
        """
        sig_dict, signal = self.setup_vars_mocks()
        cbt1 = CBT()
        cbt = CBT()
        cbt.op_type = "Response"
        cbt.parent = cbt1
        resp = CBT.Response()
        resp.data = "Data"
        cbt.response = resp
        cbt.response.status = "OK"
        cbt1.child_count = 2
        signal.free_cbt = MagicMock()
        signal.complete_cbt = MagicMock()
        signal.process_cbt(cbt)
        signal.free_cbt.assert_called_once()
        signal.complete_cbt.assert_not_called()
        print("Passed : test_process_cbt_resp_with_parent")

    def testsignal_terminate(self):
        """
        Test to check the terminate method of signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        transport = XmppTransport.factory(
            "1",
            sig_dict["Signal"]["Overlays"]["A0FB389"],
            signal,
            signal._presence_publisher,
            None,
            None,
        )
        transport.shutdown = MagicMock()
        signal._circles = {
            "A0FB389": {"Transport": transport, "OutgoingRemoteActs": {}}
        }
        signal.terminate()
        transport.shutdown.assert_called_once()
        print("Passed : test_signal_terminate")

    def testsignal_scavenge_pending_cbts(self):
        """
        Test to check if scavenge of pending CBT works with one above the request timeout.
        """
        cfxObject = Mock()
        nexus = Nexus(cfxObject)
        module = importlib.import_module("controllers.{0}".format("Signal"))
        module_class = getattr(module, "Signal")
        sig_dict = {
            "Signal": {
                "Enabled": True,
                "Overlays": {
                    "A0FB389": {
                        "HostAddress": "1.1.1.1",
                        "Port": "5222",
                        "Username": "raj",
                        "Password": "raj",
                        "AuthenticationMethod": "PASSWORD",
                    }
                },
            },
            "NodeId": "1234434323",
        }
        signal = module_class(nexus, sig_dict, "Signal")
        nexus._controller_obj = signal
        nexus._cm_config = sig_dict
        cbt1 = CBT()
        cbt1.tag = "1"
        cbt1.time_submit = time.time() - 5
        signal._request_timeout = 5
        cbt2 = CBT()
        cbt2.tag = "2"
        cbt2.time_submit = time.time() - 1
        signal.complete_cbt = MagicMock()
        signal._nexus._pending_cbts.update({"0": cbt1})
        signal._nexus._pending_cbts.update({"1": cbt2})
        assert len(signal._nexus._pending_cbts.items()) == 2
        signal.scavenge_pending_cbts()
        assert len(signal._nexus._pending_cbts.items()) == 1
        items = {}
        items.update({"1": cbt2})
        assert signal._nexus._pending_cbts == items
        print("Passed : testsignal_scavenge_pending_cbts")

    def testsignal_scavenge_expired_outgoing_rem_acts_single_entry(self):
        """
        Test to check scavenge remote actions method with a single entry of the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        signal._request_timeout = 3
        item = {0: "invk", 1: {"ActionTag": "1"}, 2: 5}
        q = Queue()
        q.put_nowait(item)
        outgoing_rem_acts = {"1": q}
        signal.complete_cbt = MagicMock()
        signal.scavenge_expired_outgoing_rem_acts(outgoing_rem_acts)
        signal.complete_cbt.assert_called_once()
        print("Passed : testsignal_scavenge_expired_outgoing_rem_acts_single_entry")

    def testsignal_scavenge_expired_outgoing_rem_acts_multiple_entries(self):
        """
        Test to check scavenge remote actions method with multiple entries of the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        signal._request_timeout = 3
        item1 = {0: "invk", 1: {"ActionTag": "1"}, 2: 5}
        item2 = {0: "invk", 1: {"ActionTag": "2"}, 2: 6}
        q = Queue()
        q.put_nowait(item1)
        q.put_nowait(item2)
        outgoing_rem_acts = {"1": q}
        assert outgoing_rem_acts["1"].qsize() == 2
        signal.complete_cbt = MagicMock()
        signal.scavenge_expired_outgoing_rem_acts(outgoing_rem_acts)
        assert len(outgoing_rem_acts) == 0
        assert signal.complete_cbt.call_count == 2
        print("Passed : testsignal_scavenge_expired_outgoing_rem_acts_multiple_entries")

    def testsignal_timer_method(self):
        """
        Test to check the timer method of the signal class.
        """
        sig_dict, signal = self.setup_vars_mocks()
        transport = XmppTransport.factory(
            "1",
            sig_dict["Signal"]["Overlays"]["A0FB389"],
            signal,
            signal._presence_publisher,
            None,
            None,
        )
        rem_acts = {}
        jid_cache = JidCache(signal, 5)
        jid_cache.scavenge = MagicMock()
        signal.scavenge_pending_cbts = MagicMock()
        transport.event_loop = MagicMock()
        signal._circles = {
            "A0FB389": {
                "Announce": 0,
                "Transport": transport,
                "OutgoingRemoteActs": rem_acts,
                "JidCache": jid_cache,
            }
        }
        signal._circles["A0FB389"][
            "Transport"
        ].event_loop.call_soon_threadsafe = MagicMock()
        signal.timer_method()
        signal._circles["A0FB389"][
            "Transport"
        ].event_loop.call_soon_threadsafe.assert_called_once()
        jid_cache.scavenge.assert_called_once()
        signal.scavenge_pending_cbts.assert_called_once()
        print("Passed : testsignal_timer_method")


if __name__ == "__main__":
    unittest.main()
