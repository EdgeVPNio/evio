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

import uuid
from typing import Any, Optional

from . import introspect

REQUEST_TIMEOUT: int = 90


class CBT:
    tag_counter: int = int(uuid.uuid4().hex[:15], base=16)

    class Request:
        def __init__(
            self,
            initiator: Optional[str] = None,
            recipient: Optional[str] = None,
            action: Optional[str] = None,
            params: Optional[dict] = None,
        ):
            self.update(initiator, recipient, action, params)

        def __repr__(self):
            return introspect(self)

        def __itr__(self):
            yield ("initiator", self.initiator)
            yield ("recipient", self.recipient)
            yield ("action", self.action)
            yield ("params", self.params)

        def update(
            self,
            initiator: Optional[str] = None,
            recipient: Optional[str] = None,
            action: Optional[str] = None,
            params: Optional[dict] = None,
        ):
            self.initiator: str = initiator if initiator else str()
            self.recipient: str = recipient if recipient else str()
            self.action: str = action if action else str()
            self.params: dict = params if params else {}

    class Response:
        def __init__(self, initiator: str, recipient: str, data: Any, status: bool):
            self.status: bool = status
            self.initiator: str = initiator
            self.recipient: str = recipient
            self.data: Any = data

        def __repr__(self):
            return introspect(self)

        def __itr__(self):
            yield ("status", self.status)
            yield ("initiator", self.initiator)
            yield ("recipient", self.recipient)
            yield ("data", self.data)

        def update(self, data, status: bool):
            self.status = status
            self.data = data

    def __init__(
        self,
        initiator: Optional[str] = None,
        recipient: Optional[str] = None,
        action: Optional[str] = None,
        params: Optional[dict] = None,
    ):
        self.tag: int = CBT.tag_counter
        CBT.tag_counter = CBT.tag_counter + 1
        self.parent = None
        self.child_count: int = 0
        self.completed: bool = False
        self.op_type: str = str("Request")
        self.request = self.Request(initiator, recipient, action, params)
        self.response: Optional[CBT.Response] = None
        self.time_create: float = 0.0
        self.time_submit: float = 0.0
        self.time_complete: float = 0.0
        self.time_free: float = 0.0

    def __repr__(self) -> str:
        return introspect(self)

    def __itr__(self):
        yield ("tag", self.tag)
        yield ("parent", self.parent)
        yield ("child_count", self.child_count)
        yield ("completed", self.completed)
        yield ("op_type", self.op_type)
        yield ("request", self.request)
        yield ("response", self.response)
        yield ("time_create", self.time_create)
        yield ("time_submit", self.time_submit)
        yield ("time_complete", self.time_complete)
        yield ("time_free", self.time_free)

    def set_request(
        self,
        initiator: Optional[str] = None,
        recipient: Optional[str] = None,
        action: Optional[str] = None,
        params: Optional[dict] = None,
    ):
        self.request.update(initiator, recipient, action, params)

    def set_response(self, data: Any, status: bool):
        self.op_type = str("Response")
        self.response = self.Response(
            self.request.recipient, self.request.initiator, data, status
        )

    def set_as_parent(self, cbt):
        self.parent = cbt
        cbt.child_count = cbt.child_ount + 1
