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

EVIO_VER_REL = f"{ver.EVIO_VER_MJR}.{ver.EVIO_VER_MNR}.{ver.EVIO_VER_REV}.{ver.EVIO_VER_BLD}"

CONFIG = {
    "CFx": {
        "Version": EVIO_VER_REL,
        "Model": "Default",
        "RequestTimeout": 120,
    },
    "Logger": {
        "Enabled": True      # Send logging output to <File> or <Console>
    },
    "OverlayVisualizer": {
        "Enabled": False,
        "Dependencies": ["Logger"],
        "TimerInterval": 30
    },
    "TincanInterface": {
        "Enabled": True,
        "Dependencies": ["Logger"]
    },
    "Signal": {
        "Enabled": True,
        "Dependencies": ["Logger"],
        "TimerInterval": 30
    },
    "LinkManager": {
        "Enabled": True,
        "Dependencies": ["Logger", "TincanInterface", "Signal"],
        "TimerInterval": 30        # Timer thread interval in sec
    },
    "Topology": {
        "Enabled": True,
        "Dependencies": ["Logger", "TincanInterface", "LinkManager", "GeneveTunnel"],
        "TimerInterval": 30
    },
    "BridgeController": {
        "Enabled": True,
        "Dependencies": ["Logger", "LinkManager"],
        "TimerInterval": 30
    }
}


def gen_ip6(uid, ip6=None):
    if ip6 is None:
        ip6 = CONFIG["TincanInterface"]["ip6_prefix"]
    for i in range(0, 16, 4):
        ip6 += ":" + uid[i:i + 4]
    return ip6

def inject_fault(frequency=0, fault_type=RuntimeWarning):
    pass
    # Todo: WIP
    # if frequency == 3:
    #         raise fault_type("Contrived fault")