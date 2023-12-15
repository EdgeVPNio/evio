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

import time
import uuid
from typing import Any, Optional

from . import CBT_DFLT_TIMEOUT, introspect


class CBT:
    _tag_counter: int = int(uuid.uuid4().hex[:15], base=16)
    _REFLECT: list[str] = [
        "tag",
        "parent",
        "child_count",
        "op_type",
        "request",
        "response",
        "time_created",
        "time_submited",
        "time_completed",
        "time_expired",
        "time_freed",
        "age",
    ]

    @classmethod
    def tag_counter(cls) -> int:
        cls._tag_counter += 1
        return cls._tag_counter

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
            yield ("initiator", self.initiator)
            yield ("recipient", self.recipient)
            yield ("status", self.status)
            yield ("data", self.data)

        def update(self, data, status: bool):
            self.status = status
            self.data = data

    def __init__(
        self,
        initiator: str,
        recipient: str,
        action: str,
        params: dict,
        parent=None,
        **kwargs
    ):
        self.tag: int = CBT.tag_counter()
        self.deps: set = set()
        self.set_parent(parent)
        self.op_type: str = str("Request")
        self.request = self.Request(initiator, recipient, action, params)
        self.response: Optional[CBT.Response] = None
        self.context: dict = {}
        for k, v in kwargs.items():
            if hasattr(self, k):
                self.k = v
            else:
                self.context[k] = v
        self.lifespan = CBT_DFLT_TIMEOUT
        self.time_created: float = 0.0
        self.time_submited: float = 0.0
        self.time_completed: float = 0.0
        self.time_expired: float = 0.0
        self.time_freed: float = 0.0

    def __repr__(self) -> str:
        return introspect(self)

    def __itr__(self):
        yield ("tag", self.tag)
        yield ("parent", self.parent)
        yield ("op_type", self.op_type)
        yield ("request", self.request)
        yield ("response", self.response)
        yield ("context", self.context)
        yield ("time_create", self.time_created)
        yield ("time_submit", self.time_submited)
        yield ("time_complete", self.time_completed)
        yield ("time_free", self.time_freed)

    def set_request(
        self,
        initiator: Optional[str] = None,
        recipient: Optional[str] = None,
        action: Optional[str] = None,
        params: Optional[dict] = None,
    ):
        if self.is_submitted:
            raise RuntimeWarning(
                "Updating CBT Request is not permissible after submission"
            )
        self.request.update(initiator, recipient, action, params)

    def set_response(self, data: Any, status: bool):
        if self.is_completed:
            raise RuntimeWarning(
                "Updating CBT Response is not permissible after completion"
            )
        self.op_type = str("Response")
        self.response = self.Response(
            self.request.recipient, self.request.initiator, data, status
        )

    def set_parent(self, parent_cbt):
        self.parent = parent_cbt
        if self.parent:
            parent_cbt.deps.add(self)

    def add_context(self, key, value):
        if key in self.context:
            raise RuntimeWarning(
                "Context key add exists, either pop it or use a different key name"
            )
        self.context[key] = value

    def pop_context(self, key):
        return self.context.pop(key, None)

    @property
    def child_count(self) -> int:
        return len(self.deps)

    @property
    def is_request(self) -> bool:
        return self.op_type == "Request"

    @property
    def is_response(self) -> bool:
        return self.op_type == "Response"

    @property
    def is_submited(self):
        return self.time_submited != 0.0

    @property
    def is_pending(self) -> bool:
        return (
            self.is_request
            and self.is_submited
            and not self.is_expired
            and not self.is_completed
        )

    # CBT will be either expired or completed. Both should should
    # not be set
    @property
    def is_expired(self) -> bool:
        return self.time_expired != 0.0

    @property
    def is_completed(self) -> bool:
        return self.time_completed != 0.0

    @property
    def is_freed(self) -> bool:
        return self.time_freed != 0.0

    @property
    def is_aborted(self) -> bool:
        return self.is_expired and self.is_freed

    @property
    def age(self) -> float:
        if self.is_expired:
            return self.time_expired - self.time_created
        elif self.is_completed:
            return self.time_completed - self.time_created
        elif self.is_freed:
            return self.time_freed - self.time_created
        return time.time() - self.time_created

    def __key__(self):
        return int(self.tag)

    def __eq__(self, other):
        return self.__key__() == other.__key__()

    def __ne__(self, other):
        return self.__key__() != other.__key__()

    def __lt__(self, other):
        return self.__key__() < other.__key__()

    def __le__(self, other):
        return self.__key__() <= other.__key__()

    def __gt__(self, other):
        return self.__key__() > other.__key__()

    def __ge__(self, other):
        return self.__key__() >= other.__key__()

    def __hash__(self):
        return hash(self.__key__())
