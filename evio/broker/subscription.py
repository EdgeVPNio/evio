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


from typing import Any, Optional

from . import introspect
from .controller_module import ControllerModule


class Subscription:
    """A mechanism for pushing a CBT to multiple interested parties"""

    _REFLECT: list[str] = [
        "publisher_name",
        "subscription_name",
        "subscribers",
    ]

    def __init__(self, publisher_name: str, subscription_name: str):
        self.publisher_name: str = publisher_name
        self.publisher: Optional[ControllerModule] = None
        self.subscription_name: str = subscription_name
        self.subscribers: list[ControllerModule] = []

    def __repr__(self):
        return introspect(self)

    def add_subscriber(self, sink: ControllerModule):
        self.subscribers.append(sink)

    def remove_subscriber(self, sink: ControllerModule):
        self.subscribers.remove(sink)

    def post_update(self, msg: Any):
        for sink in self.subscribers:
            self.publisher.register_cbt(sink.name, self.subscription_name, msg)
