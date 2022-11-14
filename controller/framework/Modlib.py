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
import framework.Version as ver

CTL_CREATE_CTRL_LINK = {
    "EVIO": {
        "ProtocolVersion": ver.EVIO_VER_CTL,
        "TransactionId": 0,
        "ControlType": "TincanRequest",
        "Request": {
            "Command": "CreateCtrlRespLink",
            "AddressFamily": "af_inetv6",
            "Protocol": "proto_datagram",
            "IP": "::1",
            "Port": 5801
        }
    }
}
CTL_CONFIGURE_LOGGING = {
    "EVIO": {
        "ProtocolVersion": ver.EVIO_VER_CTL,
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
            "ConsoleLevel": "DEBUG"
        }
    }
}
CTL_QUERY_TUNNEL_INFO = {
    "EVIO": {
        "ProtocolVersion": ver.EVIO_VER_CTL,
        "TransactionId": 0,
        "ControlType": "TincanRequest",
        "Request": {
            "Command": "QueryOverlayInfo",
            "OverlayId": "",
            "TunnelId": ""
        }
    }
}
CTL_CREATE_TUNNEL = {
    "EVIO": {
        "ProtocolVersion": ver.EVIO_VER_CTL,
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
        }
    }
}
CTL_CREATE_LINK = {
    "EVIO": {
        "ProtocolVersion": ver.EVIO_VER_CTL,
        "TransactionId": 0,
        "ControlType": "TincanRequest",
        "Request": {
            "Command": "CreateLink",
            "OverlayId": "",
            "TunnelId": "",
            "LinkId": "",
            "PeerInfo": {
                "UID": "",
                "MAC": "",
                "FPR": ""
            }
        }
    }
}
CTL_REMOVE_TUNNEL = {
    "EVIO": {
        "ProtocolVersion": ver.EVIO_VER_CTL,
        "TransactionId": 0,
        "ControlType": "TincanRequest",
        "Request": {
            "Command": "RemoveTunnel",
            "OverlayId": "",
            "TunnelId": ""
        }
    }
}
CTL_REMOVE_LINK = {
    "EVIO": {
        "ProtocolVersion": ver.EVIO_VER_CTL,
        "TransactionId": 0,
        "ControlType": "TincanRequest",
        "Request": {
            "Command": "RemoveLink",
            "OverlayId": "",
            "LinkId": ""
        }
    }
}
RESP = {
    "EVIO": {
        "ProtocolVersion": ver.EVIO_VER_CTL,
        "TransactionId": 0,
        "ControlType": "TincanResponse",
        "Request": {
        },
        "Response": {
            "Success": True,
            "Message": "description"
        }
    }
}
CTL_QUERY_LINK_STATS = {
    "EVIO": {
        "ProtocolVersion": ver.EVIO_VER_CTL,
        "TransactionId": 0,
        "ControlType": "TincanRequest",
        "Request": {
            "Command": "QueryLinkStats",
            "TunnelIds" : []
        }
    }
}
CTL_QUERY_CAS = {
    "EVIO": {
        "ProtocolVersion": ver.EVIO_VER_CTL,
        "TransactionId": 0,
        "ControlType": "TincanRequest",
        "Request": {
            "Command": "QueryCandidateAddressSet",
            "OverlayId": "",
            "LinkId": ""
        }
    }
}


def ip4_a2hex(ipstr):
    return "".join(hex(int(x, 10))[2:] for x in ipstr.split("."))


def ip6_a2b(str_ip6):
    return b"".join(int(x, 16).to_bytes(2, byteorder="big") for x in str_ip6.split(":"))

def ip6_b2a(bin_ip6):
    return "".join("%04x" % int.from_bytes(bin_ip6[i:i + 2], byteorder="big") + ":"
                   for i in range(0, 16, 2))[:-1]

def ip4_a2b(str_ip4):
    return b"".join(int(x, 10).to_bytes(1, byteorder="big") for x in str_ip4.split("."))

def ip4_b2a(bin_ip4):
    return "".join(str(int.from_bytes(bin_ip4[i:i + 1], byteorder="big")) + "."
                   for i in range(0, 4, 1))[:-1]

def mac_a2b(str_mac):
    return b"".join(int(x, 16).to_bytes(1, byteorder="big") for x in str_mac.split(":"))

def mac_b2a(bin_mac):
    return "".join("%02x" % int.from_bytes(bin_mac[i:i + 1], byteorder="big") + ":"
                   for i in range(0, 6, 1))[:-1]

def delim_mac_str(mac_str:str, delim=":"):
    if not mac_str or len(mac_str) != 12 or delim in mac_str:
        return None
    return str(mac_str[:2] + delim + mac_str[2:4] + delim + mac_str[4:6] + delim + mac_str[6:8] +
               delim + mac_str[8:10] + delim + mac_str[10:12]).lower()

def uid_a2b(str_uid):
    return int(str_uid, 16).to_bytes(20, byteorder="big")

def uid_b2a(bin_uid):
    return "%40x" % int.from_bytes(bin_uid, byteorder="big")

def hexstr2b(hexstr):
    return b"".join(int(hexstr[i:i + 2], 16).to_bytes(1, byteorder="big") \
        for i in range(0, len(hexstr), 2))

def b2hexstr(binary):
    return "".join("%02x" % int.from_bytes(binary[i:i + 1], byteorder="big") \
        for i in range(0, len(binary), 1))

def gen_ip4(uid, peer_map, ip4):
    try:
        return peer_map[uid]
    except KeyError as error:
        print("Exception Caught in Modlib: {0}".format(str(error)))
    ips = set(peer_map.values())
    prefix, _ = ip4.rsplit(".", 1)
    # we allocate *.101 - *254 ensuring a 3-digit suffix and avoiding the
    # broadcast address; *.100 is the IPv4 address of this node
    for i in range(101, 255):
        peer_map[uid] = "%s.%s" % (prefix, i)
        if peer_map[uid] not in ips:
            return peer_map[uid]
    del peer_map[uid]
    raise OverflowError("too many peers, out of IPv4 addresses")


# Function to add 2 hex data and return the result
def addhex(data1, data2):
    bindata1 = list(("{0:0" + str((len(data1)) * 4) + "b}").format(int(data1, 16)))
    bindata2 = list(("{0:0" + str((len(data2)) * 4) + "b}").format(int(data2, 16)))
    if len(bindata1) == len(bindata2):
        j = len(bindata1) - 1
    elif len(bindata1) > len(bindata2):
        j = len(bindata1) - 1
        bindata2 = [0] * (len(bindata1) - len(bindata2)) + bindata2
    else:
        j = len(bindata2) - 1
        bindata1 = [0] * (len(bindata2) - len(bindata1)) + bindata1

    carry = 0
    result = []
    while j > 0:
        summer = carry + int(bindata1[j]) + int(bindata2[j])
        result.insert(0, str(summer % 2))
        carry = summer / 2
        j -= 1
    return hex(int("".join(result), 2))


# Function to calculate checksum and return it in HEX format
def getchecksum(hexstr):
    result = "0000"
    for i in range(0, len(hexstr), 4):
        result = addhex(result, hexstr[i:i + 4])
    if len(result) != 4:
        result = addhex(result[0:len(result) - 4], result[len(result) - 4:])
    return hex(65535 ^ int(result, 16))

def runshell(cmd):
    """ Run a shell command """
    #print(cmd)
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)

def create_process(cmdlist):
    """ Run a shell command """
    return subprocess.Popen(cmdlist)

class RemoteAction():
    def __init__(self, overlay_id=None, recipient_id=None, recipient_cm=None,
                 action=None, params=None, **kwargs):
        self.overlay_id = kwargs.get("overlay_id", overlay_id)
        self.recipient_id = kwargs.get("recipient_id", recipient_id)
        self.recipient_cm = kwargs.get("recipient_cm", recipient_cm)
        self.action = kwargs.get("action", action)
        self.params = kwargs.get("params", params)
        self.initiator_id = kwargs.get("initiator_id")
        self.initiator_cm = kwargs.get("initiator_cm")
        self.action_tag = kwargs.get("action_tag")
        self.status = kwargs.get("status")
        self.data = kwargs.get("data")

    def __iter__(self):
        yield("overlay_id", self.overlay_id)
        yield("recipient_id", self.recipient_id)
        yield("recipient_cm", self.recipient_cm)
        yield("action", self.action)
        yield("params", self.params)
        if self.initiator_id:
            yield("initiator_id", self.initiator_id)
        if self.initiator_cm:
            yield("initiator_cm", self.initiator_cm)
        if self.action_tag:
            yield("action_tag", self.action_tag)
        if self.status:
            yield("status", self.status)
        if self.data:
            yield("data", self.data)

    def submit_remote_act(self, cm, parent_cbt=None):
        self.initiator_id = cm.node_id
        self.initiator_cm = cm.module_name
        ra_desc = dict(self)
        if parent_cbt is not None:
            cbt = cm.create_linked_cbt(parent_cbt)
            cbt.set_request(cm.module_name, "Signal", "SIG_REMOTE_ACTION", ra_desc)
        else:
            cbt = cm.create_cbt(cm.module_name, "Signal", "SIG_REMOTE_ACTION", ra_desc)
        self.action_tag = cbt.tag
        cm.submit_cbt(cbt)

    @classmethod
    def request(cls, cbt):
        return cls(**cbt.request.params)
    
    @classmethod
    def response(cls, cbt):
        return cls(**cbt.response.data)


