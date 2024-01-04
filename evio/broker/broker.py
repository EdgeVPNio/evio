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
import glob
import importlib
import json
import logging
import os
import queue
import signal
import sys
import threading
import time
import uuid
from copy import deepcopy
from logging.handlers import (
    QueueHandler,
    QueueListener,
    RotatingFileHandler,
    TimedRotatingFileHandler,
)
from typing import Any

from . import (
    BROKER_LOG_LEVEL,
    BROKER_LOG_NAME,
    CM_TIMER_EVENT_INTERVAL,
    CONFIG,
    CONSOLE_LEVEL,
    DEVICE,
    EVIO_VER_REL,
    JID_RESOLUTION_TIMEOUT,
    KEEP_LOGS_ON_START,
    LOG_DIRECTORY,
    LOG_LEVEL,
    MAX_ARCHIVES,
    MAX_FILE_SIZE,
    TINCAN_LOG_NAME,
    ConfigurationError,
)
from .cbt import CBT
from .controller_module import ControllerModule
from .nexus import Nexus
from .process_proxy import ProcessProxy, ProxyMsg
from .subscription import Subscription
from .timed_transactions import TimedTransactions, Transaction


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
        self._nexus_lock: threading.Lock = threading.Lock()
        self._nexus_map: dict[str, Any] = {}  # ctrl classname -> class instance
        self._config: dict = {}
        self._cm_qlisteners: list[QueueListener] = []
        self._setup_logging()
        self.model = self._config["Broker"].get("Model")
        self._subscriptions: dict[str, list[Subscription]] = {}
        self._node_id: str = self._set_node_id()
        self._load_order: list[str] = []
        self._timers = TimedTransactions()
        self._ipc = ProcessProxy(self.dispach_proxy_msg, self.logger)

    def __enter__(self):
        self.initialize()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        if exc_type or exc_val or exc_tb:
            self.logger.warning(
                "type: %s, value: %s, traceback: %s", exc_type, exc_val, exc_tb
            )
        return self.terminate()

    def _parse_config(self):
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
                print("Waiting on config file ", args.config_file, file=sys.stderr)
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
        self._parse_config()
        logging.getLogger("slixmpp").propagate = False
        handlers = []
        filepath = self._config["Broker"].get("Directory", LOG_DIRECTORY)
        bkr_logname = os.path.join(
            filepath, self._config["Broker"].get("BrokerLogName", BROKER_LOG_NAME)
        )
        if not os.path.exists(filepath):
            os.makedirs(filepath, exist_ok=True)
        elif not self._config["Broker"].get("KeepLogsOnStart", KEEP_LOGS_ON_START):
            logs = glob.glob(os.path.join(filepath, "*"))
            for f in logs:
                os.remove(f)
        # setup root logger
        file_handler = RotatingFileHandler(
            filename=bkr_logname,
            maxBytes=self._config["Broker"].get("MaxFileSize", MAX_FILE_SIZE),
            backupCount=self._config["Broker"].get("MaxArchives", MAX_ARCHIVES),
        )
        broker_log_level = self._config["Broker"].get(
            "BrokerLogLevel", BROKER_LOG_LEVEL
        )
        file_handler.setLevel(broker_log_level)
        file_handler.setFormatter(
            logging.Formatter(
                "[%(asctime)s.%(msecs)03d] %(levelname)s %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        handlers.append(file_handler)
        # console logging
        console_handler = logging.StreamHandler(stream=sys.stdout)
        console_handler.setFormatter(logging.Formatter("evio: %(message)s"))
        console_handler.setLevel(logging.ERROR)
        handlers.append(console_handler)
        que = queue.Queue()
        que_handler = QueueHandler(que)
        self._que_listener = QueueListener(que, *handlers, respect_handler_level=True)
        self.logger = logging.getLogger()
        self.logger.setLevel(broker_log_level)
        self.logger.addHandler(que_handler)
        self._que_listener.start()
        for k, v in self.cfg_controllers.items():
            ctr_lgl = self._config["Broker"].get("LogLevel", LOG_LEVEL)
            self._setup_controller_logger(
                (k, v["Module"]),
                logging.Formatter(
                    "[%(asctime)s.%(msecs)03d] %(levelname)s %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                ),
                ctr_lgl,
            )

    def _setup_controller_logger(
        self, cm_name: tuple[str, str], formatter: logging.Formatter, log_level: int
    ):
        logname = os.path.join(LOG_DIRECTORY, f"{cm_name[1]}.log")
        # if os.path.isfile(logname):
        #     os.remove(logname)
        file_handler = TimedRotatingFileHandler(
            filename=logname, when="midnight", backupCount=7, utc=True
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(log_level)
        que = queue.Queue()
        que_handler = QueueHandler(que)
        que_listener = QueueListener(que, file_handler, respect_handler_level=True)
        logger = logging.getLogger(cm_name[0])
        logger.setLevel(log_level)
        logger.addHandler(que_handler)
        que_listener.start()
        self._cm_qlisteners.append(que_listener)

    @property
    def cfg_controllers(self) -> dict[str, dict]:
        return self._config["Broker"]["Controllers"]

    @property
    def cfg_overlays(self) -> list[str]:
        return self._config["Broker"]["Overlays"]

    def _controller_config(self, ctrl: str) -> dict:
        return self._config.get(ctrl, {})

    def initialize(self):
        try:
            # check for controller cyclic dependencies
            self._validate_controller_deps()

            # order and load the controllers
            self.build_load_order()
            for ctrl_name in self._load_order:
                self.load_module(ctrl_name)

            self._timers.start()
            self._ipc.start()
            # intialize the the CMs via their respective nexus
            for ctrl_name in self._load_order:
                self._nexus_map[ctrl_name].initialize()

            # start all the worker and timer threads
            with self._nexus_lock:
                for ctrl_name in self._load_order:
                    self._nexus_map[ctrl_name].start_controller()
        except ConfigurationError:
            self.logger.exception()
            sys.exit(-1)
        self.logger.info("Version %s loaded", EVIO_VER_REL)

    def _validate_controller_deps(self):
        dependency_graph = {}
        controllers = self.cfg_controllers
        for ctrl, cfg in controllers.items():
            if "Dependencies" in cfg:
                dependency_graph[ctrl] = cfg["Dependencies"]
        if Broker.detect_cyclic_dependency(dependency_graph):
            raise ConfigurationError(
                "Circular dependency detected in controller dependencies"
            )

    def build_load_order(self):
        # create the controller load order based on their dependencies
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
        timer_interval = self.cfg_controllers[ctrl_cls_name].get(
            "TimerInterval", CM_TIMER_EVENT_INTERVAL
        )
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
        signo = signal.sigwait([signal.SIGINT, signal.SIGTERM])
        self.logger.debug("Received Signal: %s", signal.Signals(signo).name)

    def terminate(self):
        with self._nexus_lock:
            for ctrl_name in reversed(self._load_order):
                wn = self._nexus_map[ctrl_name]._cm_thread.name
                self._nexus_map[ctrl_name].work_queue.put(None)
            for ctrl_name in reversed(self._load_order):
                wn = self._nexus_map[ctrl_name]._cm_thread.name
                self._nexus_map[ctrl_name]._cm_thread.join()
                self.logger.info("%s exited", wn)
            self._ipc.terminate()
            self._timers.terminate()
            for ql in self._cm_qlisteners:
                ql.stop()
        self._que_listener.stop()
        logging.shutdown()
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
            elif param_name == "ProcessProxyAddress":
                val = self._ipc.address
            elif param_name == "Model":
                val = self.model
            elif param_name == "DebugCBTs":
                val = self._config["Broker"].get("DebugCBTs", False)
            elif param_name == "JidResolutionTimeout":
                val = self._config["Broker"].get(
                    "JidResolutionTimeout", JID_RESOLUTION_TIMEOUT
                )
            elif param_name == "LogConfig":
                broker_log_level = self._config["Broker"].get(
                    "BrokerLogLevel", BROKER_LOG_LEVEL
                )
                val = {
                    "Level": self._config["Broker"].get("LogLevel", broker_log_level),
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
                exc_info=True,
            )
        return val

    def submit_cbt(self, cbt: CBT):
        recipient: str = cbt.request.recipient
        if cbt.is_response:
            recipient = cbt.response.recipient

        def is_cmplt(x: CBT):
            return x.is_completed or x.is_expired

        with self._nexus_lock:
            nexus = self._nexus_map[recipient]
            nexus.work_queue.put(cbt)
            if cbt.is_pending:
                initiator = cbt.request.initiator
                owner = self._nexus_map[initiator]
                self._timers.register(
                    Transaction(cbt, is_cmplt, owner.on_cbt_expired, cbt.lifespan)
                )

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

    def register_timed_transaction(self, entry: Transaction):
        self._timers.register(entry)

    def register_dpc(self, delay, call, params=()):
        self._timers.register_dpc(delay, call, params)

    def dispach_proxy_msg(self, msg: ProxyMsg):
        # task structure
        # dict(Request=dict(Target=CM, Action=None, Params=None),
        #      Response=dict(Status=False, Data=None))
        task = msg.json
        if "Response" in task:
            tgt = task["Response"].get("Recipient")
        else:
            tgt = task["Request"].get("Recipient")
        if tgt is None:
            self.logger.warning("No recipient specified in IPC message %s", msg)
            return
        with self._nexus_lock:
            nexus = self._nexus_map[tgt]
            nexus._cm_queue.put(msg)

    def send_ipc(self, msg: ProxyMsg):
        self._ipc.tx_que.put(msg)


if __name__ == "__main__":
    cf = Broker()
    cf.initialize()
    cf.run()
    cf.terminate()
