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

import framework.Version as ver

EVIO_VER_REL = "{0}.{1}.{2}.{3}".format(ver.EVIO_VER_MJR, ver.EVIO_VER_MNR, ver.EVIO_VER_REV, ver.EVIO_VER_BLD)

CONFIG = {
    "CFx": {
        "NodeId": "",  # Single unique node Id for all overlays
        "Version": EVIO_VER_REL,
        "Model": "Default",
        "RequestTimeout": 120,
    },
    "Logger": {
        "Enabled": True,
        "LogLevel": "ERROR",      # Types of messages to log, <ERROR>/<WARNING>/<INFO>/<DEBUG>
        "Device": "File",      # Send logging output to <File> or <Console>
        "Directory": "./logs/",
        "CtrlLogFileName": "ctrl.log",
        "TincanLogFileName": "tincan_log",
        "MaxFileSize": 1000000,   # 1MB sized log files
        "MaxArchives": 5,   # Keep up to 5 files of history
        "ConsoleLevel": None
    },
    "TincanInterface": {
        "Enabled": True,
        "MaxReadSize": 65507,               # Max buffer size for Tincan Messages
        "SocketReadWaitTime": 15,           # Socket read wait time for Tincan Messages
        "RcvServiceAddress": "127.0.0.1",   # Controller server address
        "SndServiceAddress": "127.0.0.1",   # Tincan server address
        "RcvServiceAddress6": "::1",
        "SndServiceAddress6": "::1",
        "CtrlRecvPort": 5801,               # Controller Listening Port
        "CtrlSendPort": 5800,               # Tincan Listening Port
        "Dependencies": ["Logger"]
    },
    "Signal": {
        "Enabled": True,
        "TimerInterval": 30,
        "CacheExpiry": 30,          # Min duration an entry remains in the JID cache in seconds
        "Dependencies": ["Logger"],
        "PresenceInterval": 30      # seconds between presence broadcast
    },
    "LinkManager": {
        "Enabled": True,
        "Dependencies": ["Logger", "TincanInterface", "Signal"],
        "TimerInterval": 30,        # Timer thread interval in sec
        "LinkSetupTimeout": 120
    },
    "Topology": {
        "Enabled": True,
        "TimerInterval": 30,
        "PeerDiscoveryCoalesce": 1,
        "ExclusionBaseInterval": 240,
        "Dependencies": ["Logger", "TincanInterface", "LinkManager"]
    },
    "BridgeController": {
        "Enabled": True,
        "Dependencies": ["Logger", "LinkManager"]
    }
}


def gen_ip6(uid, ip6=None):
    if ip6 is None:
        ip6 = CONFIG["TincanInterface"]["ip6_prefix"]
    for i in range(0, 16, 4):
        ip6 += ":" + uid[i:i + 4]
    return ip6
