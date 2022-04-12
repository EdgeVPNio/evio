# EdgeVPNio
# Copyright 2022, University of Florida
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


from collections import namedtuple
import time

TUNNEL_EVENTS = namedtuple(
    "TUNNEL_EVENTS",
    ["Authorized", "AuthExpired", "Created", "Connected", "Disconnected", "Removed"],
    defaults=["LnkEvAuthorized", "LnkEvAuthExpired", "LnkEvCreated", "LnkEvConnected",
              "LnkEvDisconnected", "LnkEvRemoved"])
TunnelEvents = TUNNEL_EVENTS()

TUNNEL_STATES = namedtuple(
    "TUNNEL_STATES",
    ["AUTHORIZED", "CREATING", "QUERYING", "ONLINE", "OFFLINE"],
    defaults=["TNL_AUTHORIZED", "TNL_CREATING", "TNL_QUERYING", "TNL_ONLINE", "TNL_OFFLINE"])
TunnelStates = TUNNEL_STATES()

class Tunnel():
    def __init__(self, tnlid, overlay_id, peer_id, tnl_state, state_timeout):
        self.tnlid = tnlid
        self.overlay_id = overlay_id
        self.peer_id = peer_id
        self.tap_name = None
        self.mac = None
        self.fpr = None
        self.link = None
        self.peer_mac = None
        self._tunnel_state = tnl_state
        self.creation_start_time = time.time()
        self.timeout = time.time() + state_timeout  # timeout for current phase

    def __repr__(self):
        items = (f"\"{k}\": {v!r}" for k, v in self.__dict__.items())
        return "{{{}}}".format(", ".join(items))

    @property
    def tunnel_state(self):
        return self._tunnel_state

    @tunnel_state.setter
    def tunnel_state(self, new_state):
        "todo: implement transition checks"
        self._tunnel_state = new_state
