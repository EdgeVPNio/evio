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


class CBT():
    tag_counter = int(uuid.uuid4().hex[:15], base=16)
    class Request():
        def __init__(self, initiator="", recipient="", action="", params=None):
            self.initiator = initiator
            self.recipient = recipient
            self.action = action
            self.params = params

        def __repr__(self):
            msg = "Request<initiator=%s, recipient=%s, action=%s, params=%s>" % (
                self.initiator, self.recipient, self.action, str(self.params))
            return msg

        def __itr__(self):
            yield("initiator", self.initiator)
            yield("recipient", self.recipient)
            yield("action", self.action)
            yield("params", self.params)

    class Response():
        def __init__(self,):
            self.status = False
            self.initiator = None
            self.recipient = None
            self.data = None

        def __repr__(self):
            msg = "Response<status=%s, initiator=%s, recipient=%s, data=%s>" % (
                self.status, self.initiator, self.recipient, str(self.data))
            return msg

        def __itr__(self):
            yield("status", self.status)
            yield("initiator", self.initiator)
            yield("recipient", self.recipient)
            yield("data", self.data)

    def __init__(self, initiator="", recipient="", action="", params=""):
        self.tag = CBT.tag_counter
        CBT.tag_counter = CBT.tag_counter + 1
        self.parent = None
        self.child_count = 0
        self.completed = False
        self.op_type = "Request"
        self.request = self.Request(initiator, recipient, action, params)
        self.response = None
        self.time_create = None
        self.time_submit = None
        self.time_complete = None
        self.time_free = None

    def __repr__(self):
        msg = ("CBT<tag=%d, parent=%s, child_count=%d, completed=%r, op_type=%s, request=%r,"
               " response=%r>" % (self.tag, str(self.parent), self.child_count, self.completed,
                                  self.op_type, self.request, self.response))
        return msg

    def __itr__(self):
        yield("tag", self.tag)
        yield("parent", self.parent)
        yield("child_count", self.child_count)
        yield("completed", self.completed)
        yield("op_type", self.op_type)
        yield("request", self.request)
        yield("response", self.response)
        yield("time_create", self.time_create)
        yield("time_submit", self.time_submit)
        yield("time_complete", self.time_complete)
        yield("time_free", self.time_free)

    def set_request(self, initiator="", recipient="", action="", params=""):
        self.request.initiator = initiator
        self.request.recipient = recipient
        self.request.action = action
        self.request.params = params

    def set_response(self, data="", status=False):
        self.op_type = "Response"
        self.response = self.Response()
        self.response.initiator = self.request.recipient
        self.response.recipient = self.request.initiator
        self.response.status = status
        self.response.data = data

    def set_as_parent(self, cbt):
        self.parent = cbt
        cbt.child_count = cbt.child_ount + 1
