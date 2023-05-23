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
from typing import Literal

from .version import (
    EVIO_VER_BLD,
    EVIO_VER_CTL,
    EVIO_VER_MJR,
    EVIO_VER_MNR,
    EVIO_VER_REV,
)

EVIO_VER_REL: str = f"{EVIO_VER_MJR}.{EVIO_VER_MNR}.{EVIO_VER_REV}.{EVIO_VER_BLD}"
EVENT_PERIOD: Literal[1] = 1
CBT_LIFESPAN: Literal[180] = 180
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
PROXY_LISTEN_ADDRESS: Literal["127.0.0.1"] = "127.0.0.1"
PROXY_LISTEN_PORT: Literal[5802] = 5802
SDN_CONTROLLER_PORT: Literal[6633] = 6633
GENEVE_SETUP_TIMEOUT: Literal[180] = 180
MAX_READ_SIZE: Literal[6557] = 65507  # Max buffer size for Tincan Messages
SOCKET_READ_WAIT_TIME: Literal[5] = 5  # Socket read wait time for Tincan Messages
RCV_SERVICE_ADDRESS: Literal["127.0.0.1"] = "127.0.0.1"  # Controller server address
SND_SERVICE_ADDRESS: Literal["127.0.0.1"] = "127.0.0.1"  # Tincan server address
CTRL_RECV_PORT: Literal[5801] = 5801  # Controller Listening Port
CTRL_SEND_PORT: Literal[5800] = 5800  # Tincan Listening Port
MIN_SUCCESSORS: Literal[2] = 2
MAX_ON_DEMAND_EDGES: Literal[3] = 3
PEER_DISCOVERY_COALESCE: Literal[1] = 1
EXCLUSION_BASE_INTERVAL: Literal[60] = 60
MAX_SUCCESSIVE_FAILS: Literal[4] = 4
TRIM_CHECK_INTERVAL: Literal[300] = 300
MAX_CONCURRENT_OPS: Literal[1] = 1
SUCCESSIVE_FAIL_INCR: Literal[1] = 1
SUCCESSIVE_FAIL_DECR: Literal[2] = 2
STALE_INTERVAL = float(2 * 3600)  # 2 hrs

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
                "Dependencies": ["TincanTunnel", "LinkManager", "GeneveTunnel"],
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

CTL_CREATE_CTRL_LINK = {
    "EVIO": {
        "ProtocolVersion": EVIO_VER_CTL,
        "TransactionId": 0,
        "ControlType": "TincanRequest",
        "Request": {
            "Command": "CreateCtrlRespLink",
            "AddressFamily": "af_inetv6",
            "Protocol": "proto_datagram",
            "IP": "::1",
            "Port": 5801,
        },
    }
}
CTL_CONFIGURE_LOGGING = {
    "EVIO": {
        "ProtocolVersion": EVIO_VER_CTL,
        "TransactionId": 0,
        "ControlType": "TincanRequest",
        "Request": {
            "Command": "ConfigureLogging",
            "Level": "DEBUG",
            "Device": "All",
            "Directory": "./logs/",
            "Filename": "tincan_log",
            "MaxArchives": 10,
            "MaxFileSize": 1048576,
            "ConsoleLevel": "DEBUG",
        },
    }
}
CTL_ECHO = {
    "EVIO": {
        "ProtocolVersion": EVIO_VER_CTL,
        "TransactionId": 0,
        "ControlType": "TincanRequest",
        "Request": {"Command": "Echo", "Message": "ECHO TEST"},
    }
}
CTL_QUERY_TUNNEL_INFO = {
    "EVIO": {
        "ProtocolVersion": EVIO_VER_CTL,
        "TransactionId": 0,
        "ControlType": "TincanRequest",
        "Request": {"Command": "QueryOverlayInfo", "OverlayId": "", "TunnelId": ""},
    }
}
CTL_CREATE_TUNNEL = {
    "EVIO": {
        "ProtocolVersion": EVIO_VER_CTL,
        "ControlType": "TincanRequest",
        "TransactionId": 0,
        "Request": {
            "Command": "CreateTunnel",
            "OverlayId": "",
            "NodeId": "",
            "TunnelId": "",
            "TapName": "",
            "StunServers": [],
            "TurnServers": [],
            "Type": "",
        },
    }
}
CTL_CREATE_LINK = {
    "EVIO": {
        "ProtocolVersion": EVIO_VER_CTL,
        "TransactionId": 0,
        "ControlType": "TincanRequest",
        "Request": {
            "Command": "CreateLink",
            "OverlayId": "",
            "TunnelId": "",
            "LinkId": "",
            "PeerInfo": {"UID": "", "MAC": "", "FPR": ""},
        },
    }
}
CTL_REMOVE_TUNNEL = {
    "EVIO": {
        "ProtocolVersion": EVIO_VER_CTL,
        "TransactionId": 0,
        "ControlType": "TincanRequest",
        "Request": {"Command": "RemoveTunnel", "OverlayId": "", "TunnelId": ""},
    }
}
CTL_REMOVE_LINK = {
    "EVIO": {
        "ProtocolVersion": EVIO_VER_CTL,
        "TransactionId": 0,
        "ControlType": "TincanRequest",
        "Request": {"Command": "RemoveLink", "OverlayId": "", "LinkId": ""},
    }
}
RESP = {
    "EVIO": {
        "ProtocolVersion": EVIO_VER_CTL,
        "TransactionId": 0,
        "ControlType": "TincanResponse",
        "Request": {},
        "Response": {"Success": True, "Message": "description"},
    }
}
CTL_QUERY_LINK_STATS = {
    "EVIO": {
        "ProtocolVersion": EVIO_VER_CTL,
        "TransactionId": 0,
        "ControlType": "TincanRequest",
        "Request": {"Command": "QueryLinkStats", "TunnelIds": []},
    }
}
CTL_QUERY_CAS = {
    "EVIO": {
        "ProtocolVersion": EVIO_VER_CTL,
        "TransactionId": 0,
        "ControlType": "TincanRequest",
        "Request": {
            "Command": "QueryCandidateAddressSet",
            "OverlayId": "",
            "LinkId": "",
        },
    }
}


def run_proc(cmd: list[str]) -> subprocess.CompletedProcess:
    """Run a shell command"""
    # print(cmd)
    return subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=3.2
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
