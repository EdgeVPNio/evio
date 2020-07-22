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

import os
import json
import signal
import argparse
import threading
import time
import importlib
import uuid
import framework.Fxlib as fxlib
from .CFxHandle import CFxHandle
from .CFxSubscription import CFxSubscription

# pylint: disable=protected-access
class CFX():

    def __init__(self):
        self._config = dict()
        self.parse_config()
        """
        CFxHandleDict is a dict containing the references to CFxHandles of all
        CMs. The key is the module name and value as the CFxHandle reference
        """
        self._cfx_handle_dict = {}
        self.model = self._config["CFx"]["Model"]
        self._event = None
        self._subscriptions = {}
        self._node_id = self._set_node_id()
        self._load_order = []

    def submit_cbt(self, cbt):
        recipient = cbt.request.recipient
        if cbt.op_type == "Response":
            recipient = cbt.response.recipient
        self._cfx_handle_dict[recipient]._cm_queue.put(cbt)

    def initialize(self,):
        # check for circular dependencies in the configuration file
        dependency_graph = {}
        for key in self._config:
            if key != "CFx":
                if "Dependencies" in self._config[key]:
                    dependency_graph[key] = self._config[key]["Dependencies"]

        if CFX.detect_cyclic_dependency(dependency_graph):
            msg = "Circular dependency detected in config.json. Correct and restart the service"
            raise RuntimeError(msg)

        self.build_load_order()
        # iterate and load the modules specified in the configuration file
        for module_name in self._load_order:
            self.load_module(module_name)

        # intialize all the CFxHandles which in turn initialize the CMs
        for module_name in self._load_order:
            self._cfx_handle_dict[module_name].initialize()

        # start all the worker and timer threads
        for module_name in self._cfx_handle_dict:
            self._cfx_handle_dict[module_name]._cm_thread.start()
            if self._cfx_handle_dict[module_name]._timer_thread:
                self._cfx_handle_dict[module_name]._timer_thread.start()

    def load_module(self, module_name):
        """
        Dynamically load the modules specified in the config file. Allow model
        specific module implementations to override the default by attempting
        to load them first.
        """
        if self.model:
            if os.path.isfile("modules/{0}/{1}.py"
                              .format(self.model, module_name)):
                module = importlib.import_module("modules.{0}.{1}"
                                                 .format(self.model, module_name))
            else:
                module = importlib.import_module("modules.{0}"
                                                 .format(module_name))

        # get the class with name key from module
        module_class = getattr(module, module_name)

        # create a CFxHandle object for each module
        handle = CFxHandle(self)
        self._config[module_name]["NodeId"] = self._node_id
        instance = module_class(handle, self._config[module_name], module_name)

        handle._cm_instance = instance
        handle._cm_config = self._config[module_name]

        # store the CFxHandle object references in the
        # dict with module name as the key
        self._cfx_handle_dict[module_name] = handle

    def add_dependencies(self, module_name):
        dependencies = self._config[module_name].get("Dependencies", {})
        for dep in dependencies:
            if dep not in self._load_order:
                self.add_dependencies(dep)
        if module_name not in self._load_order:
            self._load_order.append(module_name)

    def build_load_order(self,):
        # creates a module load order based on how they are listed in the
        # config file and their dependency list
        try:
            for module_name in self._config:
                module_enabled = self._config[module_name].get("Enabled", True)
                if module_enabled and module_name != "CFx":
                    self.add_dependencies(module_name)
        except KeyError:
            pass

    @staticmethod
    def detect_cyclic_dependency(graph):
        # test if the directed graph g has a cycle
        path = set()
        def visit(vertex):
            path.add(vertex)
            for neighbour in graph.get(vertex, ()):
                if (neighbour in path) or visit(neighbour):
                    return True
            path.remove(vertex)
            return False

        return any(visit(v) for v in graph)

    @staticmethod
    def __handler(signum=None, frame=None):
        # pylint: disable=unused-argument
        print("Signal handler called with signal ", signum)

    def parse_config(self):
        self._config = fxlib.CONFIG
        self._set_nid_file_name()
        parser = argparse.ArgumentParser(description="Starts the EVIO Controller")
        parser.add_argument("-c", help="load configuration from a file",
                            dest="config_file", metavar="config_file")
        parser.add_argument("-s", help="configuration as json string"
                            " (overrides configuration from file)",
                            dest="config_string", metavar="config_string")
        # parser.add_argument("-p", help="load remote ip configuration file",
        #                     dest="ip_config", metavar="ip_config")
        args = parser.parse_args()
        if args.config_file:
            while not os.path.isfile(args.config_file):
                print("Waiting on config file {}".format(args.config_file))
                time.sleep(10)
            # load the configuration file
            with open(args.config_file) as f:
                cfg = json.load(f)
                for key in cfg:
                    if self._config.get(key, False):
                        self._config[key].update(cfg[key])
                    else:
                        self._config[key] = cfg[key]
        if args.config_string:
            cfg = json.loads(args.config_string)
            for key in cfg:
                if self._config.get(key, None):
                    self._config[key].update(cfg[key])
                else:
                    self._config[key] = cfg[key]

    def _set_node_id(self,):
        config = self._config["CFx"]
        # if NodeId is not specified in Config file, generate NodeId
        nodeid = config.get("NodeId", None)
        if nodeid is None or not nodeid:
            try:
                with open(config["NidFileName"], "r") as f:
                    nodeid = f.read().strip()
            except IOError:
                pass
        if nodeid is None or not nodeid:
            nodeid = str(uuid.uuid4().hex)
            path = os.path.dirname(config["NidFileName"])
            if not os.path.exists(path):
                os.makedirs(path, exist_ok=True)
            with open(config["NidFileName"], "w") as f:
                f.write(nodeid)
        return nodeid

    def _set_nid_file_name(self):
        NID_FILENAME = "nid"
        if os.name == "posix":
            DIRNAME_PREFIX = os.path.normpath("/var/opt/edge-vpnio")
        else:
            DIRNAME_PREFIX = "."
        self._config["CFx"]["NidFileName"] = os.path.join(DIRNAME_PREFIX, NID_FILENAME)

    def wait_for_shutdown_event(self):
        self._event = threading.Event()

        # Since signal.pause() is not avaialble on windows, use event.wait()
        # with a timeout to catch KeyboardInterrupt. Without timeout, it"s
        # not possible to catch KeyboardInterrupt because event.wait() is
        # a blocking call without timeout. The if condition checks if the os
        # is windows.
        if os.name == "nt":
            while True:
                try:
                    self._event.wait(1)
                except (KeyboardInterrupt, SystemExit) as e:
                    print("Controller shutdown event: {0}".format(str(e)))
                    break
        else:
            for sig in [signal.SIGINT, signal.SIGTERM]:
                signal.signal(sig, CFX.__handler)
            # sleeps until signal is received
            # pylint: disable=no-member
            signal.pause()

    def terminate(self):
        for module_name in self._cfx_handle_dict:
            if self._cfx_handle_dict[module_name]._timer_thread:
                self._cfx_handle_dict[module_name]._exit_event.set()
            self._cfx_handle_dict[module_name]._cm_queue.put(None)

        # wait for the threads to process their current CBTs and exit
        print("waiting for threads to exit ...")
        for module_name in self._cfx_handle_dict:
            self._cfx_handle_dict[module_name]._cm_thread.join()
            print("{0} exited".format(self._cfx_handle_dict[module_name]._cm_thread.name))
            if self._cfx_handle_dict[module_name]._timer_thread:
                self._cfx_handle_dict[module_name]._timer_thread.join()
                print("{0} exited".format(self._cfx_handle_dict[module_name]._timer_thread.name))

    def query_param(self, param_name=""):
        val = None
        try:
            if param_name == "EvioVersion":
                val = self._config["CFx"]["EvioVersion"]
            elif param_name == "NodeId":
                val = self._node_id
            elif param_name == "Overlays":
                val = self._config["CFx"]["Overlays"]
            elif param_name == "Model":
                val = self.model
            elif param_name == "DebugCBTs":
                val = self._config["CFx"].get("DebugCBTs", False)
            elif param_name == "RequestTimeout":
                val = self._config["CFx"]["RequestTimeout"]
        except KeyError as err:
            print("Exception occurred while querying paramater:{0}, key:{1}"
                  .format(param_name, str(err)))
        return val

    # Caller is the subscription source
    def publish_subscription(self, owner_name, subscription_name, owner):
        sub = CFxSubscription(owner_name, subscription_name)
        sub._owner = owner
        if sub._owner_name not in self._subscriptions:
            self._subscriptions[sub._owner_name] = []
        self._subscriptions[sub._owner_name].append(sub)
        return sub

    def remove_subscription(self, sub):
        sub.post_update("SUBSCRIPTION_SOURCE_TERMINATED")
        if sub._owner_name not in self._subscriptions:
            raise NameError("Failed to remove subscription source \"{}\"."
                            " No such provider name exists."
                            .format(sub._owner_name))
        self._subscriptions[sub._owner_name].remove(sub)

    def find_subscription(self, owner_name, subscription_name):
        sub = None
        if owner_name not in self._subscriptions:
            raise NameError("The specified subscription provider {} was not found."
                            .format(owner_name))
        for sub in self._subscriptions[owner_name]:
            if sub._subscription_name == subscription_name:
                return sub
        return None

    # Caller is the subscription sink
    def start_subscription(self, owner_name, subscription_name, Sink):
        sub = self.find_subscription(owner_name, subscription_name)
        if sub is not None:
            sub.add_subscriber(Sink)
        else:
            raise NameError("The specified subscription name was not found")

    def end_subscription(self, owner_name, subscription_name, sink):
        sub = self.find_subscription(owner_name, subscription_name)
        if sub is not None:
            sub.remove_subscriber(sink)


if __name__ == "__main__":
    cf = CFX()
    cf.initialize()
