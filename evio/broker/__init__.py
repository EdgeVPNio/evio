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
import subprocess
from typing import Literal

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
    "LOG_LEVEL",
    "BROKER_LOG_NAME",
    "TINCAN_LOG_NAME",
    "PERFDATA_LOG_NAME",
    "TINCAN_CHK_INTERVAL",
    "MAX_FILE_SIZE",
    "MAX_ARCHIVES",
    "CONSOLE_LEVEL",
    "DEVICE",
    "EVENT_PERIOD",
    "CBT_LIFESPAN",
    "LINK_SETUP_TIMEOUT",
    "JID_RESOLUTION_TIMEOUT",
    "CONTROLLER_TIMER_INTERVAL",
    "CACHE_EXPIRY_INTERVAL",
    "PRESENCE_INTERVAL",
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
    "EXCLUSION_BASE_INTERVAL",
    "MAX_SUCCESSIVE_FAILS",
    "TRIM_CHECK_INTERVAL",
    "MAX_CONCURRENT_OPS",
    "SUCCESSIVE_FAIL_INCR",
    "SUCCESSIVE_FAIL_DECR",
    "STALE_INTERVAL",
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
]
EVIO_VER_REL: str = f"{EVIO_VER_MJR}.{EVIO_VER_MNR}.{EVIO_VER_REV}.{EVIO_VER_BLD}"
LOG_DIRECTORY = "/var/log/evio/"
BROKER_LOG_LEVEL = "INFO"
LOG_LEVEL = "INFO"
BROKER_LOG_NAME = "broker.log"
TINCAN_LOG_NAME = "tincan"
TINCAN_CHK_INTERVAL: Literal[5] = 5
PERFDATA_LOG_NAME = "perf.data"
MAX_FILE_SIZE = 10000000  # 10MB sized log files
MAX_ARCHIVES = 5
CONSOLE_LEVEL = None
DEVICE = "File"
EVENT_PERIOD: Literal[1] = 1
CBT_LIFESPAN: Literal[180] = 180
JID_RESOLUTION_TIMEOUT: Literal[15] = 15
LINK_SETUP_TIMEOUT: Literal[180] = 180
CONTROLLER_TIMER_INTERVAL: Literal[30] = 30
CACHE_EXPIRY_INTERVAL: Literal[60] = 60
PRESENCE_INTERVAL: Literal[30] = 30
BR_NAME_MAX_LENGTH: Literal[15] = 15
NAME_PREFIX_EVI: Literal["evi"] = "evi"
NAME_PREFIX_APP_BR: Literal["app"] = "app"
MTU: Literal[1410] = 1410
BRIDGE_AUTO_DELETE: Literal[True] = True
DEFAULT_BRIDGE_PROVIDER: Literal["OVS"] = "OVS"
DEFAULT_SWITCH_PROTOCOL: Literal["BF"] = "BF"
SDN_CONTROLLER_PORT: Literal[6633] = 6633
GENEVE_SETUP_TIMEOUT: Literal[180] = 180
MIN_SUCCESSORS: Literal[2] = 2
MAX_ON_DEMAND_EDGES: Literal[3] = 3
EXCLUSION_BASE_INTERVAL: Literal[60] = 60
MAX_SUCCESSIVE_FAILS: Literal[4] = 4
TRIM_CHECK_INTERVAL: Literal[300] = 300
MAX_CONCURRENT_OPS: Literal[1] = 1
SUCCESSIVE_FAIL_INCR: Literal[1] = 1
SUCCESSIVE_FAIL_DECR: Literal[2] = 2
STALE_INTERVAL = float(2 * 3600)  # 2 hrs
MAX_HEARTBEATS: Literal[5] = 3

perfd = PerformanceData(LogFile=os.path.join(LOG_DIRECTORY, PERFDATA_LOG_NAME))

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
                "Enabled": False,
                "Module": "usage_report",
                "Dependencies": ["Topology"],
            },
        },
    },
    "UsageReport": {
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
CTL_REMOVE_TUNNEL = {
    "ProtocolVersion": EVIO_VER_CTL,
    "TransactionId": 0,
    "ControlType": "Request",
    "Request": {"Command": "RemoveTunnel", "TunnelId": ""},
}
CTL_REMOVE_LINK = {
    "ProtocolVersion": EVIO_VER_CTL,
    "TransactionId": 0,
    "ControlType": "Request",
    "Request": {"Command": "RemoveLink", "TunnelId": "", "LinkId": ""},
}
RESP = {
    "ProtocolVersion": EVIO_VER_CTL,
    "TransactionId": 0,
    "ControlType": "Response",
    "Request": {},
    "Response": {"Success": True, "Message": "description"},
}
CTL_QUERY_LINK_STATS = {
    "ProtocolVersion": EVIO_VER_CTL,
    "TransactionId": 0,
    "ControlType": "Request",
    "Request": {"Command": "QueryLinkStats", "TunnelId": ""},
}
CTL_QUERY_CAS = {
    "ProtocolVersion": EVIO_VER_CTL,
    "TransactionId": 0,
    "ControlType": "Request",
    "Request": {
        "Command": "QueryCandidateAddressSet",
        "LinkId": "",
    },
}


class ConfigurationError(ValueError):
    def __init__(self, message):
        super().__init__(message)
        self.msgfmt = message


def run_proc(cmd: list[str]) -> subprocess.CompletedProcess:
    """Run a shell command"""
    # print(cmd)
    return subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=30.0
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
