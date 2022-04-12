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

from abc import ABCMeta, abstractmethod
import hashlib
import logging

# abstract ControllerModule (CM) class
# all CM implementations inherit the variables declared here
# all CM implementations must override the abstract methods declared here


class ControllerModule():

    __metaclass__ = ABCMeta

    def __init__(self, cfx_handle, module_config, module_name):
        self._cfx_handle = cfx_handle
        self._cm_config = module_config
        self._module_name = module_name
        self._state_digest = None
        self.logger = logging.getLogger(self._module_name)

    def __repr__(self):
        items = set()
        if hasattr(self, "_REFLECT"):
            for k in self._REFLECT:
                items.add(f"\"{k}\": {self.__dict__[k]!r}")
        return "{{{}}}".format(", ".join(items))

    @abstractmethod
    def initialize(self):
        pass

    @abstractmethod
    def process_cbt(self, cbt):
        pass

    @abstractmethod
    def timer_method(self):
        pass

    @abstractmethod
    def terminate(self):
        pass

    @property
    def node_id(self):
        return self._cm_config["NodeId"]

    @property
    def overlays(self):
        return self._cm_config["Overlays"]

    @property
    def config(self):
        return self._cm_config

    @property
    def module_name(self):
        return self._module_name

    @property
    def version(self):
        return self._cfx_handle.query_param("Version")

    @property
    def overlay_names(self):
        return self._cfx_handle.query_param("Overlays")

    def req_handler_default(self, cbt):
        self.logger.warning(f"Unsupported CBT action {cbt}")
        self.complete_cbt(cbt)

    def resp_handler_default(self, cbt):
        parent_cbt = cbt.parent
        cbt_data = cbt.response.data
        cbt_status = cbt.response.status
        self.free_cbt(cbt)
        if (parent_cbt is not None and parent_cbt.child_count == 1):
            parent_cbt.set_response(cbt_data, cbt_status)
            self.complete_cbt(parent_cbt)

    def log(self, level, fmt, *args):
        if level == "LOG_DEBUG":
            self.logger.debug(fmt, *args)
        elif level == "LOG_INFO":
            self.logger.info(fmt, *args)
        elif level == "LOG_WARNING":
            self.logger.warning(fmt, *args)
        elif level == "LOG_ERROR":
            self.logger.error(fmt, *args)
        else:
            self.logger.debug(fmt, *args)

    def trace_state(self):
        if self.config.get("StateTracingEnabled", False):
            state = str(self)
            new_digest = hashlib.sha256(state.encode("utf-8")).hexdigest()
            if self._state_digest != new_digest:
                self._state_digest = new_digest
                self.logger.info(state)

    def register_cbt(self, _recipient, _action, _params=None):
        cbt = self._cfx_handle.create_cbt(
            initiator=self._module_name,
            recipient=_recipient,
            action=_action,
            params=_params
        )
        self._cfx_handle.submit_cbt(cbt)
        return cbt

    def create_cbt(self, initiator, recipient, action, params=None):
        return self._cfx_handle.create_cbt(initiator, recipient, action, params)

    def create_linked_cbt(self, parent):
        return self._cfx_handle.create_linked_cbt(parent)

    def complete_cbt(self, cbt):
        self._cfx_handle.complete_cbt(cbt)

    def free_cbt(self, cbt):
        self._cfx_handle.free_cbt(cbt)

    def submit_cbt(self, cbt):
        self._cfx_handle.submit_cbt(cbt)

    # Caller is the subscription source
    def publish_subscription(self, subscription_name):
        return self._cfx_handle.publish_subscription(self.module_name,
                                                     subscription_name, self)

    def remove_subscription(self, sub):
        self._cfx_handle.remove_subscription(sub)

    def get_registered_publishers(self)->list:
        return  self._cfx_handle.get_registered_publishers()

    def get_available_subscriptions(self, publisher_name)->list:
        return self._cfx_handle.get_available_subscriptions(publisher_name)

    # Caller is the subscription sink
    def start_subscription(self, publisher_name, subscription_name):
        self._cfx_handle.start_subscription(
            publisher_name, subscription_name, self)

    def end_subscription(self, publisher_name, subscription_name):
        self._cfx_handle.end_subscription(publisher_name, subscription_name, self)
