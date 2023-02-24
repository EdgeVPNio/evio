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

from collections import namedtuple
from typing import Optional

from broker import introspect

from .tunnel import DATAPLANE_TYPES

ROLES = namedtuple(
    "ROLES", ["Switch", "Pendant"], defaults=["RoleSwitch", "RolePendant"]
)
DEFAULT_ROLE: ROLES = ROLES().Switch
DEFAULT_DATAPLANE = DATAPLANE_TYPES.Tincan


class PeerProfile:
    def __init__(self, peer_id: Optional[str], overlay_id: Optional[str], **kwargs):
        self.peer_id: str = peer_id if peer_id else kwargs["PeerId"]
        self.overlay_id = overlay_id if overlay_id else kwargs["OverlayId"]
        self.role: str = kwargs.get("Role", DEFAULT_ROLE)
        self.supported_dataplanes: list[str] = kwargs.get(
            "Dataplanes", [DEFAULT_DATAPLANE]
        )

    def __repr__(self) -> str:
        return introspect(self)
