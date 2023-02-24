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

from . import introspect


class RemoteAction:
    def __init__(
        self,
        overlay_id=None,
        recipient_id=None,
        recipient_cm=None,
        action=None,
        params=None,
        **kwargs,
    ):
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

    def __repr__(self) -> str:
        return introspect(self)

    def __iter__(self):
        yield ("overlay_id", self.overlay_id)
        yield ("recipient_id", self.recipient_id)
        yield ("recipient_cm", self.recipient_cm)
        yield ("action", self.action)
        yield ("params", self.params)
        if self.initiator_id:
            yield ("initiator_id", self.initiator_id)
        if self.initiator_cm:
            yield ("initiator_cm", self.initiator_cm)
        if self.action_tag:
            yield ("action_tag", self.action_tag)
        if self.status:
            yield ("status", self.status)
        if self.data:
            yield ("data", self.data)

    def submit_remote_act(self, cm, parent_cbt=None):
        self.initiator_id = cm.node_id
        self.initiator_cm = cm.name
        if parent_cbt is not None:
            cbt = cm.create_linked_cbt(parent_cbt)
            cbt.set_request(cm.name, "Signal", "SIG_REMOTE_ACTION", self)
        else:
            cbt = cm.create_cbt(cm.name, "Signal", "SIG_REMOTE_ACTION", self)
        self.action_tag = cbt.tag
        cm.submit_cbt(cbt)
