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

from . import introspect
from .cbt import CBT
from .nexus import Nexus

# abstract ControllerModule (CM) class
# all CM implementations must override the abstract methods declared here


class ControllerModule:

    __metaclass__ = ABCMeta

    def __init__(self, nexus: Nexus, ctrl_config: dict):
        self._nexus = nexus
        self._ctrl_config = ctrl_config
        # self._module_name = self.__class__.__module__
        self._state_digest = None
        self.logger = logging.getLogger("Evio." + self.__class__.__name__)

    def __repr__(self):
        return introspect(self)

    @abstractmethod
    def initialize(self):
        pass

    @abstractmethod
    def process_cbt(self, cbt: CBT):
        pass

    @abstractmethod
    def timer_method(self, is_exiting=False):
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

    # @property
    # def module_name(self):
    # return full path name
    #     return self.__class__.__module__

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

    def req_handler_default(self, cbt):
        self.logger.warning("Unsupported CBT action %s", cbt)
        self.complete_cbt(cbt)

    def resp_handler_default(self, cbt):
        self.logger.debug("Using CBT default response handler %s", cbt)
        parent_cbt = cbt.parent
        cbt_data = cbt.response.data
        cbt_status = cbt.response.status
        self.free_cbt(cbt)
        if parent_cbt and parent_cbt.child_count == 0:
            parent_cbt.set_response(cbt_data, cbt_status)
            self.complete_cbt(parent_cbt)

    # def log(self, level, fmt, *args):
    #     if level == "LOG_DEBUG":
    #         self.logger.debug(fmt, *args)
    #     elif level == "LOG_INFO":
    #         self.logger.info(fmt, *args)
    #     elif level == "LOG_WARNING":
    #         self.logger.warning(fmt, *args)
    #     elif level == "LOG_ERROR":
    #         self.logger.error(fmt, *args)
    #     else:
    #         self.logger.debug(fmt, *args)

    def trace_state(self):
        if self.config.get("StateTracingEnabled", False):
            state = str(self)
            new_digest = hashlib.sha256(state.encode("utf-8")).hexdigest()
            if self._state_digest != new_digest:
                self._state_digest = new_digest
                self.logger.info("state trace: %s", state)

    def register_cbt(self, _recipient, _action, _params=None):
        cbt = self._nexus.create_cbt(
            initiator=self.name,
            recipient=_recipient,
            action=_action,
            params=_params,
        )
        self._nexus.submit_cbt(cbt)

    def register_internal_cbt(self, _action, _params=None):
        cbt = self._nexus.create_cbt(
            initiator=self.name,
            recipient=self.name,
            action=_action,
            params=_params,
        )
        self._nexus.submit_cbt(cbt)

    def create_cbt(self, initiator, recipient, action, params=None) -> CBT:
        return self._nexus.create_cbt(initiator, recipient, action, params)

    def create_linked_cbt(self, parent) -> CBT:
        return self._nexus.create_linked_cbt(parent)

    def complete_cbt(self, cbt: CBT):
        self._nexus.complete_cbt(cbt)

    def free_cbt(self, cbt: CBT):
        self._nexus.free_cbt(cbt)

    def submit_cbt(self, cbt: CBT):
        self._nexus.submit_cbt(cbt)

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
