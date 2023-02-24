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

import argparse
import importlib
import json
import logging
import logging.handlers as lh
import os
import queue
import signal
import threading
import time
import uuid
from copy import deepcopy
from typing import Any  # Optional, Set, Tuple, Union

from . import CONFIG
from .cbt import CBT, REQUEST_TIMEOUT
from .controller_module import ControllerModule
from .nexus import Nexus
from .subscription import Subscription

ROOT_LOG_LEVEL = "INFO"
LOG_DIRECTORY = "/var/log/evio/"
BROKER_LOG_NAME = "broker.log"
CTRL_LOG_NAME = "ctrl.log"
TINCAN_LOG_NAME = "tincan_log"
MAX_FILE_SIZE = 10000000  # 10MB sized log files
MAX_ARCHIVES = 5
CONSOLE_LEVEL = None
DEVICE = "File"


class Broker:
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
        print(
            f"Signal handler called with {signal.Signals(signum).name} ({signum}) {frame}"
        )

    def __init__(self):
        self._config: dict = {}
        self.parse_config()
        self._setup_logging()
        self._handle_lock: threading.Lock = threading.Lock()
        self._nexus_map: dict[str, Any] = {}  # ctrl classname -> class instance
        self.model = self._config["Broker"].get("Model")
        self._subscriptions: dict[str, list[Subscription]] = {}
        self._node_id: str = self._set_node_id()
        self._load_order: list[str] = []

    def __enter__(self):
        self.initialize()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self.terminate()

    def parse_config(self):
        self._config = CONFIG
        self._set_nid_file_name()
        parser = argparse.ArgumentParser(description="Starts the EVIO Controller")
        parser.add_argument(
            "-c",
            help="load configuration from a file",
            dest="config_file",
            metavar="config_file",
        )
        parser.add_argument(
            "-s",
            help="configuration as json string" " (overrides configuration from file)",
            dest="config_string",
            metavar="config_string",
        )
        args = parser.parse_args()
        if args.config_file:
            while not os.path.isfile(args.config_file):
                self.logger.info("Waiting on config file %s", args.config_file)
                time.sleep(10)
            # load the configuration file
            with open(args.config_file, encoding="utf-8") as cfg_file:
                cfg = json.load(cfg_file)
            for key in cfg:
                if key in self._config:
                    if key == "Broker":
                        ctrls = deepcopy(self._config[key]["Controllers"])
                        ctrls.update(cfg[key].get("Controllers", {}))
                        self._config[key].update(cfg[key])
                        self._config[key]["Controllers"] = ctrls
                    else:
                        self._config[key].update(cfg[key])
                else:
                    self._config[key] = cfg[key]
        if args.config_string:
            cfg = json.loads(args.config_string)
            for key in cfg:
                if key in self._config:
                    if key == "Broker":
                        ctrls = deepcopy(self._config[key]["Controllers"])
                        ctrls.update(cfg[key].get("Controllers", {}))
                        self._config[key].update(cfg[key])
                        self._config[key]["Controllers"] = ctrls
                    else:
                        self._config[key].update(cfg[key])
                else:
                    self._config[key] = cfg[key]

    def _setup_logging(self):
        # Extracts the filepath else sets logs to current working directory
        filepath = self._config["Broker"].get("Directory", LOG_DIRECTORY)
        fqname = os.path.join(
            filepath, self._config["Broker"].get("BrokerLogName", BROKER_LOG_NAME)
        )
        if not os.path.exists(filepath):
            os.makedirs(filepath, exist_ok=True)
        if os.path.isfile(fqname):
            os.remove(fqname)
        # setup root logger
        formatter = logging.Formatter(
            "[%(asctime)s.%(msecs)03d] %(levelname)s:%(name)s: %(message)s",
            datefmt="%Y%m%d %H:%M:%S",
        )
        root_handler = lh.RotatingFileHandler(
            filename=fqname,
            maxBytes=self._config["Broker"].get("MaxFileSize", MAX_FILE_SIZE),
            backupCount=self._config["Broker"].get("MaxArchives", MAX_ARCHIVES),
        )
        root_handler.setFormatter(formatter)
        que = queue.Queue(-1)  # no limit on size
        queue_handler = lh.QueueHandler(que)
        self._rlistener = lh.QueueListener(
            que, root_handler, respect_handler_level=True
        )
        self.logger = logging.getLogger()
        root_log_level = self._config["Broker"].get("RootLogLevel", ROOT_LOG_LEVEL)
        level = getattr(logging, root_log_level)
        self.logger.setLevel(level)
        self.logger.addHandler(queue_handler)
        self._rlistener.start()

        # setup CM logging, each module adds their own logger
        fqname = os.path.join(
            filepath, self._config["Broker"].get("CtrlLogName", CTRL_LOG_NAME)
        )
        if not os.path.exists(filepath):
            os.makedirs(filepath, exist_ok=True)
        if os.path.isfile(fqname):
            os.remove(fqname)

        cm_logger = logging.getLogger("Evio")

        rf_handler = lh.RotatingFileHandler(
            filename=fqname,
            maxBytes=self._config["Broker"].get("MaxFileSize", MAX_FILE_SIZE),
            backupCount=self._config["Broker"].get("MaxArchives", MAX_ARCHIVES),
        )
        rf_handler.setFormatter(formatter)
        level = getattr(logging, self._config["Broker"].get("LogLevel", root_log_level))
        cm_logger.setLevel(level)
        # setup console logging to record errors in the system journal
        console_handler = logging.StreamHandler()
        console_log_formatter = logging.Formatter("%(levelname)s:%(name)s: %(message)s")
        console_handler.setFormatter(console_log_formatter)
        console_handler.setLevel(logging.ERROR)
        # use queue handler/listenter since AsyncIO is used in this process
        que = queue.Queue(-1)
        queue_handler = lh.QueueHandler(que)
        self._cm_listener = lh.QueueListener(
            que, console_handler, rf_handler, respect_handler_level=True
        )
        cm_logger.addHandler(queue_handler)
        self._cm_listener.start()

    @property
    def cfg_controllers(self) -> dict[str, dict]:
        return self._config["Broker"]["Controllers"]

    @property
    def cfg_overlays(self) -> list[str]:
        return self._config["Broker"]["Overlays"]

    def _controller_config(self, ctrl) -> dict:
        return self._config.get(ctrl, {})

    def initialize(self):
        # check for controller cyclic dependencies
        self._validate_controller_deps()

        # order and load the controllers
        self.build_load_order()
        for ctrl_name in self._load_order:
            self.load_module(ctrl_name)

        # intialize the the CMs via their respective nexus
        for ctrl_name in self._load_order:
            self._nexus_map[ctrl_name].initialize()

        # start all the worker and timer threads
        with self._handle_lock:
            for ctrl_name in self._load_order:
                self._nexus_map[ctrl_name].start_controller()
                if self._nexus_map[ctrl_name]._timer_thread:
                    self._nexus_map[ctrl_name]._timer_thread.start()

    def _validate_controller_deps(self):
        dependency_graph = {}
        controllers = self.cfg_controllers
        for ctrl, cfg in controllers.items():
            if "Dependencies" in cfg:
                dependency_graph[ctrl] = cfg["Dependencies"]
        if Broker.detect_cyclic_dependency(dependency_graph):
            msg = "Circular dependency detected in config.json. Correct and restart the service"
            raise RuntimeError(msg)

    def build_load_order(self):
        # creates an ordering for loading the controllers based on their dependencies
        controllers = self.cfg_controllers
        for ctrl, cfg in controllers.items():
            if cfg.get("Enabled", True):
                self.add_dependencies(ctrl)

    def add_dependencies(self, ctrl_cls_name: str):
        controllers = self.cfg_controllers
        dependencies = controllers[ctrl_cls_name].get("Dependencies", {})
        for dep in dependencies:
            if dep not in self._load_order:
                self.add_dependencies(dep)
        if ctrl_cls_name not in self._load_order:
            self._load_order.append(ctrl_cls_name)

    def load_module(self, ctrl_cls_name: str):
        """
        Load the controllers based on load_order. Allow model
        specific module implementations to override the default by attempting
        to load them first.
        """
        assert (
            ctrl_cls_name != "Broker"
        ), "Invalid attempt to load the Broker as a controller module"
        mod_name = self.cfg_controllers[ctrl_cls_name]["Module"]
        if self.model:
            fqn = f"modules/{self.model}/{mod_name}.py"
            if os.path.isfile(fqn):
                module = importlib.import_module(f"controllers.{self.model}.{mod_name}")
            else:
                raise RuntimeError(f"Failed to located the specified module {fqn}")
        else:
            module = importlib.import_module(f"controllers.{mod_name}")

        # get the controller class from the class name
        ctrl_class = getattr(module, ctrl_cls_name)
        timer_interval = self.cfg_controllers[ctrl_cls_name].get("TimerInterval", 0)
        nexus = Nexus(self, timer_interval=timer_interval)
        ctrl_config = self._config.get(ctrl_cls_name)
        if ctrl_config is None:
            ctrl_config = {"Overlays": {}}
        elif "Overlays" not in ctrl_config:
            ctrl_config["Overlays"] = {}
        for olid in self.cfg_overlays:
            if olid not in ctrl_config["Overlays"]:
                ctrl_config["Overlays"] = {olid: {}}
        self._config[ctrl_cls_name] = ctrl_config
        ctrl_obj = ctrl_class(nexus, self._config[ctrl_cls_name])
        nexus.controller = ctrl_obj
        # keep a map of controller name -> Nexus object
        self._nexus_map[ctrl_cls_name] = nexus

    def _set_node_id(self):
        config = self._config["Broker"]
        # if NodeId is not specified in Config file, generate NodeId
        nodeid = config.get("NodeId", None)
        if nodeid is None or not nodeid:
            try:
                with open(config["NidFileName"], "r", encoding="utf-8") as fnid:
                    nodeid = fnid.read().strip()
            except IOError:
                pass
        if nodeid is None or not nodeid:
            nodeid = str(uuid.uuid4().hex)
            path = os.path.dirname(config["NidFileName"])
            if not os.path.exists(path):
                os.makedirs(path, exist_ok=True)
            with open(config["NidFileName"], "w", encoding="utf-8") as fnid:
                fnid.write(nodeid)
        return nodeid

    def _set_nid_file_name(self):
        NID_FILENAME = "nid"
        if os.name == "posix":
            DIRNAME_PREFIX = os.path.normpath("/var/opt/evio")
        else:
            DIRNAME_PREFIX = "."
        self._config["Broker"]["NidFileName"] = os.path.join(
            DIRNAME_PREFIX, NID_FILENAME
        )

    def run(self):
        for sig in [signal.SIGINT, signal.SIGTERM]:
            signal.signal(sig, Broker.__handler)
        # sleeps until signal is received
        signal.pause()

    def terminate(self):
        with self._handle_lock:
            for ctrl_name in reversed(self._load_order):
                if self._nexus_map[ctrl_name]._timer_thread:
                    tn = self._nexus_map[ctrl_name]._timer_thread.name
                    self._nexus_map[ctrl_name]._exit_event.set()
                    self._nexus_map[ctrl_name]._timer_thread.join()
                    self.logger.info("%s exited", tn)
                    print("exited:", tn)
                wn = self._nexus_map[ctrl_name]._cm_thread.name
                self._nexus_map[ctrl_name].work_queue.put(None)
                self._nexus_map[ctrl_name]._cm_thread.join()
                self.logger.info("%s exited", wn)
                print("exited:", wn)
        # self._rlistener.stop()
        # logging.shutdown()
        return True

    def query_param(self, param_name=""):
        val = None
        try:
            if param_name == "Version":
                val = self._config["Broker"]["Version"]
            elif param_name == "NodeId":
                val = self._node_id
            elif param_name == "Overlays":
                val = self._config["Broker"]["Overlays"]
            elif param_name == "Model":
                val = self.model
            elif param_name == "DebugCBTs":
                val = self._config["Broker"].get("DebugCBTs", False)
            elif param_name == "RequestTimeout":
                val = self._config["Broker"].get("RequestTimeout", REQUEST_TIMEOUT)
            elif param_name == "LogConfig":
                root_log_level = self._config["Broker"].get(
                    "RootLogLevel", ROOT_LOG_LEVEL
                )
                val = {
                    "Level": self._config["Broker"].get("LogLevel", root_log_level),
                    "Device": self._config["Broker"].get("Device", DEVICE),
                    "Directory": self._config["Broker"].get("Directory", LOG_DIRECTORY),
                    "Filename": self._config["Broker"].get(
                        "TincanLogName", TINCAN_LOG_NAME
                    ),
                    "MaxArchives": self._config["Broker"].get(
                        "MaxArchives", MAX_ARCHIVES
                    ),
                    "MaxFileSize": self._config["Broker"].get(
                        "MaxFileSize", MAX_FILE_SIZE
                    ),
                    "ConsoleLevel": self._config["Broker"].get(
                        "ConsoleLevel", CONSOLE_LEVEL
                    ),
                }
        except KeyError as err:
            self.logger.warning(
                "Exception occurred while querying paramater:%s, %s",
                param_name,
                str(err),
            )
        return val

    def submit_cbt(self, cbt: CBT):
        recipient: str = cbt.request.recipient
        if cbt.op_type == "Response":
            recipient = cbt.response.recipient
        with self._handle_lock:
            self._nexus_map[recipient].work_queue.put(cbt)

    # Caller is the subscription source
    def publish_subscription(self, publisher_name, subscription_name, publisher):
        sub = Subscription(publisher_name, subscription_name)
        sub.publisher = publisher
        if sub.publisher_name not in self._subscriptions:
            self._subscriptions[sub.publisher_name] = []
        self._subscriptions[sub.publisher_name].append(sub)
        return sub

    def remove_subscription(self, sub):
        sub.post_update("SUBSCRIPTION_SOURCE_TERMINATED")
        if sub.publisher_name not in self._subscriptions:
            raise NameError(
                'Failed to remove subscription source "{}".'
                " No such provider name exists.".format(sub.publisher_name)
            )
        self._subscriptions[sub.publisher_name].remove(sub)

    def find_subscription(self, publisher_name, subscription_name):
        sub = None
        if publisher_name not in self._subscriptions:
            raise NameError(
                f"The specified subscription provider {publisher_name} was not found."
            )
        for sub in self._subscriptions[publisher_name]:
            if sub.subscription_name == subscription_name:
                return sub
        return None

    def get_registered_publishers(self) -> list[str]:
        return [*self._subscriptions]

    def get_available_subscriptions(self, publisher_name) -> list[str]:
        return [sub.subscription_name for sub in self._subscriptions[publisher_name]]

    # Caller is the subscription sink
    def start_subscription(
        self, publisher_name: str, subscription_name: str, sink: ControllerModule
    ):
        sub = self.find_subscription(publisher_name, subscription_name)
        if sub is not None:
            sub.add_subscriber(sink)
        else:
            raise NameError("The specified subscription name was not found")

    def end_subscription(
        self, publisher_name: str, subscription_name: str, sink: ControllerModule
    ):
        sub = self.find_subscription(publisher_name, subscription_name)
        if sub is not None:
            sub.remove_subscriber(sink)

    # def inject_fault(self, module_name):
    #     if "InjectFaults" not in self._config["Broker"]:
    #         return
    #     if module_name in self._config["Broker"]["InjectFaults"]:
    #         inject_fault(frequency=self._config["Broker"]["InjectFaults"][module_name])


if __name__ == "__main__":
    cf = Broker()
    cf.initialize()
