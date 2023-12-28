# EdgeVPNio
# Copyright 2020, University of Florida
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copyify, merge, publish, distribute, sublicense, and/or sell
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
import logging
from abc import ABCMeta, abstractmethod
from typing import Callable

from . import introspect
from .cbt import CBT
from .nexus import Nexus
from .process_proxy import ProxyMsg

# abstract ControllerModule (CM) class
# all CM implementations must override the abstract methods declared here


class ControllerModule:
    __metaclass__ = ABCMeta

    def __init__(self, nexus: Nexus, ctrl_config: dict):
        self._nexus = nexus
        self._ctrl_config = ctrl_config
        self._state_digest = None
        self._abort_handler_tbl: dict[str, Callable[[CBT]]] = {}
        self._req_handler_tbl: dict[str, Callable[[CBT]]] = {}
        self._resp_handler_tbl: dict[str, Callable[[CBT]]] = {}
        self._setup_logger()

    def __repr__(self):
        return introspect(self)

    def _setup_logger(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        if "LogLevel" in self.config:
            self.logger.setLevel(self.config["LogLevel"])
        return

    @abstractmethod
    def initialize(self):
        pass

    def process_cbt(self, cbt: CBT):
        if cbt.is_expired:
            self.abort_handler(cbt)
        elif cbt.is_pending:
            self.req_handler(cbt)
        elif cbt.is_completed:
            self.resp_handler(cbt)
        else:
            raise RuntimeError("Unexpected CBT state")

    def abort_handler(self, cbt: CBT):
        handle = self._abort_handler_tbl.get(
            cbt.request.action, self.abort_handler_default
        )
        try:
            handle(cbt)
        except Exception:
            self.logger.exception("CBT abort handler failure")
            if cbt and not cbt.is_freed:
                self.free_cbt(cbt)

    def req_handler(self, cbt: CBT):
        handle = self._req_handler_tbl.get(cbt.request.action, self.req_handler_default)
        try:
            handle(cbt)
        except Exception:
            self.logger.exception()
            if cbt and not cbt.is_completed:
                cbt.set_response({"Message": "Failed"}, False)
                self.complete_cbt(cbt)

    def resp_handler(self, cbt: CBT):
        handle = self._resp_handler_tbl.get(
            cbt.request.action, self.resp_handler_default
        )
        try:
            handle(cbt)
        except Exception:
            self.logger.exception()
            if cbt and not cbt.is_freed:
                self.free_cbt(cbt)

    @abstractmethod
    def on_timer_event(self):
        pass

    @abstractmethod
    def terminate(self):
        pass

    @property
    def node_id(self) -> str:
        return self._nexus.query_param("NodeId")

    @property
    def overlays(self) -> dict[str, dict]:
        return self._ctrl_config["Overlays"]

    @property
    def config(self) -> dict:
        return self._ctrl_config

    @property
    def name(self):
        return self.__class__.__name__

    @property
    def version(self):
        return self._nexus.query_param("Version")

    @property
    def registered_overlay_ids(self):
        return self._nexus.query_param("Overlays")

    @property
    def log_config(self):
        return self._nexus.query_param("LogConfig")

    @property
    def process_proxy_address(self):
        return self._nexus.query_param("ProcessProxyAddress")

    def req_handler_default(self, cbt):
        self.logger.warning("Unsupported CBT action %s", cbt)
        cbt.set_response({"Message": "No request handler registered"}, False)
        self.complete_cbt(cbt)

    def resp_handler_default(self, cbt):
        self.logger.debug("CBT default response handler %s", cbt)
        parent_cbt = cbt.parent
        resp_data = cbt.response.data
        cbt_status = cbt.response.status
        self.free_cbt(cbt)
        if parent_cbt and parent_cbt.child_count == 0:
            parent_cbt.set_response(resp_data, cbt_status)
            self.complete_cbt(parent_cbt)

    def abort_handler_default(self, cbt: CBT):
        self.logger.debug("CBT default abort handler %s", cbt)
        self.free_cbt(cbt)

    def log_state(self):
        if self.config.get("StateTracingEnabled", False):
            state = str(self)
            new_digest = hashlib.sha256(state.encode("utf-8")).hexdigest()
            if self._state_digest != new_digest:
                self._state_digest = new_digest
                self.logger.info("controller state: %s", state)

    def register_cbt(
        self, _recipient, _action, _params=None, _parent_cbt=None, **kwargs
    ):
        cbt = self._nexus.create_cbt(
            initiator=self.name,
            recipient=_recipient,
            action=_action,
            params=_params,
            parent_cbt=_parent_cbt,
            **kwargs,
        )
        self._nexus.submit_req_cbt(cbt)

    def register_internal_cbt(self, _action, _params=None, parent_cbt=None, **kwargs):
        cbt = self._nexus.create_cbt(
            initiator=self.name,
            recipient=self.name,
            action=_action,
            params=_params,
            parent_cbt=parent_cbt,
            **kwargs,
        )
        self._nexus.submit_req_cbt(cbt)

    def create_cbt(
        self, _recipient, _action, _params=None, _parent_cbt=None, **kwargs
    ) -> CBT:
        return self._nexus.create_cbt(
            initiator=self.name,
            recipient=_recipient,
            action=_action,
            params=_params,
            parent_cbt=_parent_cbt,
            **kwargs,
        )

    def complete_cbt(self, cbt: CBT):
        if not cbt.is_response:
            raise RuntimeError("Invalid attempt to complete CBT without a response")
        if cbt.is_completed:
            raise RuntimeError("This CBT has been previously completed.")
        if cbt.is_expired:
            raise RuntimeError("Invalid Operation: Do not complete an expired CBT")
        if len(cbt.deps) != 0:
            raise RuntimeWarning(
                "Invalid attempt to complete a CBT with outstanding dependencies"
            )
        self._nexus.complete_cbt(cbt)

    def free_cbt(self, cbt: CBT):
        if cbt.is_freed:
            raise RuntimeError("This CBT has been previously freed.")
        if not (cbt.is_completed or cbt.is_expired):
            raise RuntimeError(
                "Attempting to free a CBT that is neither completed nor expired."
            )
        self._nexus.free_cbt(cbt)

    def submit_cbt(self, cbt: CBT):
        if cbt.request.initiator != self.name:
            raise ValueError(
                f"Invalid attempt to submit a CBT that is owned by {cbt.request.initiator}"
            )
        self._nexus.submit_req_cbt(cbt)

    # Caller is the subscription source
    def publish_subscription(self, subscription_name: str):
        return self._nexus.publish_subscription(self.name, subscription_name)

    def remove_subscription(self, sub):
        self._nexus.remove_subscription(sub)

    def get_registered_publishers(self) -> list:
        return self._nexus.get_registered_publishers()

    def get_available_subscriptions(self, publisher_name) -> list:
        return self._nexus.get_available_subscriptions(publisher_name)

    # Caller is the subscription sink
    def start_subscription(self, publisher_name, subscription_name):
        self._nexus.start_subscription(publisher_name, subscription_name)

    def end_subscription(self, publisher_name, subscription_name):
        self._nexus.end_subscription(publisher_name, subscription_name)

    def register_timed_transaction(self, obj, is_completed, on_expired, lifespan):
        if is_completed(obj):
            raise ValueError(f"Object already marked as completed {obj}")
        self._nexus.register_timed_transaction(obj, is_completed, on_expired, lifespan)

    def register_deferred_call(self, delay, call, params=()):
        self._nexus.register_deferred_call(delay, call, params)

    @abstractmethod
    def handle_ipc(self, msg: ProxyMsg):
        NotImplemented

    def send_ipc(self, msg: ProxyMsg):
        self._nexus.send_ipc(msg)
