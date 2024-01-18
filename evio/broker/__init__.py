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

import subprocess

from .performance_data import PerformanceData
from .version import (
    EVIO_VER_BLD,
    EVIO_VER_CTL,
    EVIO_VER_MJR,
    EVIO_VER_MNR,
    EVIO_VER_REV,
)

__all__ = [
    "EVIO_VER_REL",
    "LOG_DIRECTORY",
    "BROKER_LOG_LEVEL",
    "TINCAN_LOG_LEVEL",
    "LOG_LEVEL",
    "BROKER_LOG_NAME",
    "TINCAN_LOG_NAME",
    "PERFDATA_LOG_NAME",
    "TC_PRCS_CHK_INTERVAL",
    "MAX_FILE_SIZE",
    "MAX_ARCHIVES",
    "CONSOLE_LEVEL",
    "DEVICE",
    "KEEP_LOGS_ON_START",
    "TIMER_EVENT_PERIOD",
    "CBT_DFLT_TIMEOUT",
    "LINK_SETUP_TIMEOUT",
    "JID_RESOLUTION_TIMEOUT",
    "CM_TIMER_EVENT_INTERVAL",
    "CACHE_ENTRY_TIMEOUT",
    "PRESENCE_UPDATE_INTERVAL",
    "BR_NAME_MAX_LENGTH",
    "NAME_PREFIX_EVI",
    "NAME_PREFIX_APP_BR",
    "MTU",
    "BRIDGE_AUTO_DELETE",
    "DEFAULT_BRIDGE_PROVIDER",
    "DEFAULT_SWITCH_PROTOCOL",
    "SDN_CONTROLLER_PORT",
    "GENEVE_SETUP_TIMEOUT",
    "MIN_SUCCESSORS",
    "MAX_ON_DEMAND_EDGES",
    "PEER_EXCLUSION_INTERVAL",
    "MAX_SUCCESSIVE_FAILS",
    "TRIM_CHECK_INTERVAL",
    "MAX_CONCURRENT_OPS",
    "SUCCESSIVE_FAIL_INCR",
    "SUCCESSIVE_FAIL_DECR",
    "PEER_CHKIN_TIMEOUT",
    "MAX_HEARTBEATS",
    "perfd",
    "CONFIG",
    "CTL_CREATE_CTRL_LINK",
    "CTL_CONFIGURE_LOGGING",
    "CTL_ECHO",
    "CTL_QUERY_TUNNEL_INFO",
    "CTL_CREATE_TUNNEL",
    "CTL_CREATE_LINK",
    "CTL_REMOVE_TUNNEL",
    "CTL_REMOVE_LINK",
    "RESP",
    "CTL_QUERY_LINK_STATS",
    "CTL_QUERY_CAS",
    "run_proc",
    "runshell",
    "introspect",
    "delim_mac_str",
    "statement_false",
    "TC_REQUEST_TIMEOUT",
]
EVIO_VER_REL: str = f"{EVIO_VER_MJR}.{EVIO_VER_MNR}.{EVIO_VER_REV}.{EVIO_VER_BLD}"
LOG_DIRECTORY = "/var/log/evio/"
BROKER_LOG_LEVEL = "INFO"
LOG_LEVEL = "INFO"
TINCAN_LOG_LEVEL = "WARNING"
BROKER_LOG_NAME = "broker.log"
TINCAN_LOG_NAME = "tincan"
PERFDATA_LOG_NAME = "perf.data"
MAX_FILE_SIZE = 10000000  # 10MB sized log files
MAX_ARCHIVES = 5
CONSOLE_LEVEL = "ERROR"
DEVICE = "File"
KEEP_LOGS_ON_START = False
BR_NAME_MAX_LENGTH = 15
NAME_PREFIX_EVI = "evi"
NAME_PREFIX_APP_BR = "app"
MTU = 1410
BRIDGE_AUTO_DELETE = True
DEFAULT_BRIDGE_PROVIDER = "OVS"
DEFAULT_SWITCH_PROTOCOL = "BF"
SDN_CONTROLLER_PORT = 6633
MIN_SUCCESSORS = 2
MAX_ON_DEMAND_EDGES = 0
MAX_SUCCESSIVE_FAILS = 4
MAX_CONCURRENT_OPS = 1
SUCCESSIVE_FAIL_INCR = 1
SUCCESSIVE_FAIL_DECR = 2
MAX_HEARTBEATS = 3
TIMER_EVENT_PERIOD = 1
CM_TIMER_EVENT_INTERVAL = 30
PRESENCE_UPDATE_INTERVAL = 30
PEER_EXCLUSION_INTERVAL = 60
TRIM_CHECK_INTERVAL = 300
TC_PRCS_CHK_INTERVAL = 5  # tincan process checks
CACHE_ENTRY_TIMEOUT = 60
PEER_CHKIN_TIMEOUT = 7200  # 2 hrs
CBT_DFLT_TIMEOUT = 160
JID_RESOLUTION_TIMEOUT = 15
GENEVE_SETUP_TIMEOUT = 90
LINK_SETUP_TIMEOUT = 130
TC_REQUEST_TIMEOUT = 30  # exipry of a req to tincan

# perfd = None
perfd = PerformanceData()

CONFIG = {
    "Broker": {
        "Version": EVIO_VER_REL,
        "Controllers": {
            "Signal": {"Module": "signal"},
            "TincanTunnel": {"Module": "tincan_tunnel"},
            "LinkManager": {"Module": "link_manager", "Dependencies": ["TincanTunnel"]},
            "GeneveTunnel": {"Module": "geneve_tunnel"},
            "Topology": {
                "Module": "topology",
                "Dependencies": [
                    "Signal",
                    "TincanTunnel",
                    "LinkManager",
                    "GeneveTunnel",
                ],
            },
            "BridgeController": {
                "Module": "bridge_controller",
                "Dependencies": ["Topology", "LinkManager", "GeneveTunnel"],
            },
            "UsageReport": {
                "Module": "usage_report",
                "Dependencies": ["Topology"],
            },
        },
    },
    "UsageReport": {
        "TimerInterval": 3600,
        "WebService": "https://qdscz6pg37.execute-api.us-west-2.amazonaws.com/default/EvioUsageReport",
    },
}

CTL_CONFIGURE_LOGGING = {
    "ProtocolVersion": EVIO_VER_CTL,
    "TransactionId": 0,
    "ControlType": "Request",
    "Request": {
        "Command": "ConfigureLogging",
        "Level": "INFO",
        "Device": "All",
        "Directory": "./logs/",
        "Filename": "tincan_log",
        "MaxArchives": 10,
        "MaxFileSize": 1048576,
        "ConsoleLevel": "WARNING",
    },
}
CTL_ECHO = {
    "ProtocolVersion": EVIO_VER_CTL,
    "TransactionId": 0,
    "ControlType": "Request",
    "Request": {"Command": "Echo", "Message": "ECHO TEST"},
}

CTL_CREATE_TUNNEL = {
    "ProtocolVersion": EVIO_VER_CTL,
    "ControlType": "Request",
    "TransactionId": 0,
    "Request": {
        "Command": "CreateTunnel",
        "NodeId": "",
        "TunnelId": "",
        "TapName": "",
        "StunServers": [],
        "TurnServers": [],
    },
}
CTL_CREATE_LINK = {
    "ProtocolVersion": EVIO_VER_CTL,
    "TransactionId": 0,
    "ControlType": "Request",
    "Request": {
        "Command": "CreateLink",
        "TunnelId": "",
        "LinkId": "",
        "PeerInfo": {"UID": "", "MAC": "", "FPR": ""},
    },
}
CTL_REMOVE_LINK = {
    "ProtocolVersion": EVIO_VER_CTL,
    "TransactionId": 0,
    "ControlType": "Request",
    "Request": {"Command": "RemoveLink"},
}
CTL_QUERY_LINK_STATS = {
    "ProtocolVersion": EVIO_VER_CTL,
    "TransactionId": 0,
    "ControlType": "Request",
    "Request": {"Command": "QueryLinkStats"},
}
CTL_QUERY_CAS = {
    "ProtocolVersion": EVIO_VER_CTL,
    "TransactionId": 0,
    "ControlType": "Request",
    "Request": {"Command": "QueryCandidateAddressSet"},
}
RESP = {
    "ProtocolVersion": EVIO_VER_CTL,
    "TransactionId": 0,
    "ControlType": "Response",
    "Request": {},
    "Response": {"Success": True, "Message": "description"},
}


class ConfigurationError(ValueError):
    def __init__(self, message):
        super().__init__(message)
        self.msgfmt = message


def run_proc(cmd: list[str], check=True, timeout=30.0) -> subprocess.CompletedProcess:
    """Run a shell command"""
    # print(cmd)
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
        timeout=timeout,
    )


def runshell(cmd: str) -> tuple[int, str, str]:
    cmd = ["bash", "-c"].append(cmd)
    cp = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    return (
        int(cp.returncode),
        cp.stdout.decode("utf-8").strip(),
        cp.stderr.decode("utf-8").strip(),
    )


def create_process(cmdlist) -> subprocess.Popen:
    """Run a shell command"""
    return subprocess.Popen(cmdlist)


def introspect(obj):
    _keys = obj._REFLECT if hasattr(obj, "_REFLECT") else obj.__dict__.keys()
    return "{{{}}}".format(", ".join((f'"{k}": {getattr(obj,k)!r}' for k in _keys)))


def delim_mac_str(mac_str: str, delim=":"):
    if not mac_str or len(mac_str) != 12 or delim in mac_str:
        return None
    return str(
        mac_str[:2]
        + delim
        + mac_str[2:4]
        + delim
        + mac_str[4:6]
        + delim
        + mac_str[6:8]
        + delim
        + mac_str[8:10]
        + delim
        + mac_str[10:12]
    ).lower()


def statement_false(*_):
    return False
