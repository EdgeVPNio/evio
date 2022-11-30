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

from copy import deepcopy
import os
import json
import signal
import argparse
import threading
import time
import importlib
import uuid
import logging
import logging.handlers as lh
import queue
import framework.Fxlib as fxlib
from .CBT import CBT
from .CFxHandle import CFxHandle
from .CFxSubscription import CFxSubscription

RootLogLevel = "INFO"
LogLevel = "INFO"
Directory = "/var/log/evio/"
CFxLogFileName = "cfx.log"
CtrlLogFileName = "ctrl.log"
TincanLogFileName = "tincan_log"
MaxFileSize = 10000000   # 10MB sized log files
MaxArchives = 5
ConsoleLevel = None
Device = "File"

class CFX():
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
        print("Signal handler called with signal", signum)

    def __init__(self):
        self._config = dict()
        self.parse_config()
        self._setup_logging()
        """
        CFxHandleDict is a dict containing the references to CFxHandles of all
        CMs. The key is the module name and value as the CFxHandle reference
        """
        self._handle_lock = threading.Lock()
        self._cfx_handle_dict = {}
        self.model = self._config["CFx"]["Model"]
        self._event = None
        self._subscriptions: dict[str, CFxSubscription] = {}
        self._node_id = self._set_node_id()
        self._load_order = []

    def __enter__(self):
        self.initialize()
        return self
    
    def __exit__(self, type, value, traceback):
        return self.terminate()
        
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
                self.logger.info("Waiting on config file %s", args.config_file)
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

    def _setup_logging(self):
            # Extracts the filepath else sets logs to current working directory
            filepath = self._config["CFx"].get("Directory", Directory)
            fqname = os.path.join(filepath,
                                  self._config["CFx"].get("CFxLogFileName", "cfx.log"))
            if not os.path.exists(filepath):
                os.makedirs(filepath, exist_ok=True)
            if os.path.isfile(fqname):
                os.remove(fqname)
            # setup root logger
            formatter = logging.Formatter(
                "[%(asctime)s.%(msecs)03d] %(levelname)s:%(name)s: %(message)s", datefmt="%Y%m%d %H:%M:%S")
            root_handler = lh.RotatingFileHandler(filename=fqname,
                                             maxBytes=self._config["CFx"].get(
                                                 "MaxFileSize", MaxFileSize),
                                             backupCount=self._config["CFx"].get("MaxArchives", MaxArchives))
            root_handler.setFormatter(formatter)
            que = queue.Queue(-1)  # no limit on size
            queue_handler = lh.QueueHandler(que)            
            self._rlistener = lh.QueueListener(que, root_handler, respect_handler_level=True)
            self.logger = logging.getLogger()
            level = getattr(logging, self._config["CFx"].get("RootLogLevel", RootLogLevel))
            self.logger.setLevel(level)
            self.logger.addHandler(queue_handler)            
            self._rlistener.start()
            
            # setup CM logging, each module adds their own logger
            fqname = os.path.join(filepath,
                                  self._config["CFx"].get("CtrlLogFileName", CtrlLogFileName))
            if not os.path.exists(filepath):
                os.makedirs(filepath, exist_ok=True)
            if os.path.isfile(fqname):
                os.remove(fqname)
                            
            cm_logger = logging.getLogger("Evio")
           
            rf_handler = lh.RotatingFileHandler(filename=fqname,
                                             maxBytes=self._config["CFx"].get(
                                                 "MaxFileSize", MaxFileSize),
                                             backupCount=self._config["CFx"].get("MaxArchives", MaxArchives))
            # formatter = logging.Formatter(
            #     "[%(asctime)s.%(msecs)03d] %(levelname)s:%(name)s: %(message)s", datefmt="%Y%m%d %H:%M:%S")
            rf_handler.setFormatter(formatter)
            level = getattr(logging, self._config["CFx"].get("LogLevel", LogLevel))
            cm_logger.setLevel(level)
            # setup console logging to record errors in the system journal
            console_handler = logging.StreamHandler()
            console_log_formatter = logging.Formatter("%(levelname)s:%(name)s: %(message)s")
            console_handler.setFormatter(console_log_formatter)
            console_handler.setLevel(logging.ERROR)
            # use queue handler/listenter since AsyncIO is used in this process
            que = queue.Queue(-1)
            queue_handler = lh.QueueHandler(que)
            self._cm_listener = lh.QueueListener(que, console_handler, rf_handler, respect_handler_level=True)
            cm_logger.addHandler(queue_handler)
            self._cm_listener.start()            

    def initialize(self):
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
        with self._handle_lock:
            for module_name in self._load_order:
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
            DIRNAME_PREFIX = os.path.normpath("/var/opt/evio")
        else:
            DIRNAME_PREFIX = "."
        self._config["CFx"]["NidFileName"] = os.path.join(DIRNAME_PREFIX, NID_FILENAME)

    def run(self):
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
                    self.logger.info("Controller shutdown event: %s", str(e))
                    break
        else:
            for sig in [signal.SIGINT, signal.SIGTERM]:
                signal.signal(sig, CFX.__handler)
            # sleeps until signal is received
            signal.pause()

    def terminate(self):
        with self._handle_lock:
            for module_name in reversed(self._load_order):
                if self._cfx_handle_dict[module_name]._timer_thread:
                    tn = self._cfx_handle_dict[module_name]._timer_thread.name
                    self._cfx_handle_dict[module_name]._exit_event.set()
                    self._cfx_handle_dict[module_name]._timer_thread.join()
                    self.logger.info("%s exited", tn)
                    print("exited:", tn)
                wn =self._cfx_handle_dict[module_name]._cm_thread.name
                self._cfx_handle_dict[module_name]._cm_queue.put(None)
                self._cfx_handle_dict[module_name]._cm_thread.join()
                self.logger.info("%s exited", wn)
                print("exited:", wn)
        # self._rlistener.stop()
        # logging.shutdown()
        return True

    def query_param(self, param_name=""):
        val = None
        try:
            if param_name == "Version":
                val = self._config["CFx"]["Version"]
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
            elif param_name == "LogConfig":
                val = {
                        "Level": self._config["CFx"].get("LogLevel", LogLevel),
                        "Device": self._config["CFx"].get("Device", Device),
                        "Directory": self._config["CFx"].get("Directory", Directory),
                        "Filename": self._config["CFx"].get("TincanLogFileName", TincanLogFileName),
                        "MaxArchives": self._config["CFx"].get("MaxArchives", MaxArchives),
                        "MaxFileSize": self._config["CFx"].get("MaxFileSize", MaxFileSize),
                        "ConsoleLevel": self._config["CFx"].get("ConsoleLevel", ConsoleLevel)
                    }
        except KeyError as err:
            self.logger.warning("Exception occurred while querying paramater:%s, %s", param_name, str(err))
        return val

    def submit_cbt(self, cbt: CBT):
        recipient = cbt.request.recipient
        initiator = cbt.request.initiator
        if cbt.op_type == "Response":
            recipient = cbt.response.recipient
            initiator = cbt.response.initiator
        with self._handle_lock:
            self._cfx_handle_dict[recipient]._cm_queue.put(cbt)
        
    # Caller is the subscription source
    def publish_subscription(self, publisher_name, subscription_name, publisher):
        sub = CFxSubscription(publisher_name, subscription_name)
        sub._publisher = publisher
        if sub._publisher_name not in self._subscriptions:
            self._subscriptions[sub._publisher_name] = []
        self._subscriptions[sub._publisher_name].append(sub)
        return sub

    def remove_subscription(self, sub):
        sub.post_update("SUBSCRIPTION_SOURCE_TERMINATED")
        if sub._publisher_name not in self._subscriptions:
            raise NameError("Failed to remove subscription source \"{}\"."
                            " No such provider name exists."
                            .format(sub._publisher_name))
        self._subscriptions[sub._publisher_name].remove(sub)

    def find_subscription(self, publisher_name, subscription_name):
        sub = None
        if publisher_name not in self._subscriptions:
            raise NameError("The specified subscription provider {} was not found."
                            .format(publisher_name))
        for sub in self._subscriptions[publisher_name]:
            if sub._subscription_name == subscription_name:
                return sub
        return None

    def get_registered_publishers(self)->list:
        return [*self._subscriptions]

    def get_available_subscriptions(self, publisher_name)->list:
        return [s._subscription_name for s in self._subscriptions[publisher_name]]

    # Caller is the subscription sink
    def start_subscription(self, publisher_name, subscription_name, sink):
        sub = self.find_subscription(publisher_name, subscription_name)
        if sub is not None:
            sub.add_subscriber(sink)
        else:
            raise NameError("The specified subscription name was not found")

    def end_subscription(self, publisher_name, subscription_name, sink):
        sub = self.find_subscription(publisher_name, subscription_name)
        if sub is not None:
            sub.remove_subscriber(sink)

    # def inject_fault(self, module_name):
    #     if "InjectFaults" not in self._config["CFx"]:
    #         return
    #     if module_name in self._config["CFx"]["InjectFaults"]:
    #         fxlib.inject_fault(frequency=self._config["CFx"]["InjectFaults"][module_name])

if __name__ == "__main__":
    cf = CFX()
    cf.initialize()
