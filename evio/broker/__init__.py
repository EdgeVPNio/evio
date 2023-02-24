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

from .version import (
    EVIO_VER_BLD,
    EVIO_VER_CTL,
    EVIO_VER_MJR,
    EVIO_VER_MNR,
    EVIO_VER_REV,
)

EVIO_VER_REL = f"{EVIO_VER_MJR}.{EVIO_VER_MNR}.{EVIO_VER_REV}.{EVIO_VER_BLD}"

CONFIG = {
    "Broker": {
        "Version": EVIO_VER_REL,
        "Controllers": {
            "Signal": {"Module": "signal", "TimerInterval": 30},
            "TincanTunnel": {"Module": "tincan_tunnel"},
            "LinkManager": {
                "Module": "link_manager",
                "Dependencies": ["TincanTunnel"],
                "TimerInterval": 30,
            },
            "GeneveTunnel": {
                "Module": "geneve_tunnel",
                "TimerInterval": 30,
            },
            "Topology": {
                "Module": "topology",
                "Dependencies": ["TincanTunnel", "LinkManager", "GeneveTunnel"],
                "TimerInterval": 30,
            },
            "BridgeController": {
                "Module": "bridge_controller",
                "Dependencies": ["LinkManager", "GeneveTunnel"],
                "TimerInterval": 30,
            },
            "UsageReport": {
                "Module": "usage_report",
                "Dependencies": ["Topology"],
                "TimerInterval": 3600,
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


def runshell(cmd):
    """Run a shell command"""
    # print(cmd)
    return subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )


def create_process(cmdlist):
    """Run a shell command"""
    return subprocess.Popen(cmdlist)


def introspect(obj):
    _keys = obj._REFLECT if hasattr(obj, "_REFLECT") else obj.__dict__.keys()
    return "{{{}}}".format(", ".join((f'"{k}": {obj.__dict__[k]!r}' for k in _keys)))


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
