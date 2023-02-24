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

import queue
import threading
import time
import traceback

from .cbt import CBT


class Nexus:
    """Links the Boker to a Controller"""

    def __init__(self, broker_object, **kwargs):
        self._cm_queue: queue.Queue[CBT] = queue.Queue()  # CBT work queue
        self._controller_obj = None
        self._cm_thread = None
        self._broker_obj = broker_object  # broker object reference
        self._exit_event = threading.Event()
        self._timer_thread = None
        self._timer_interval: int = kwargs.get("timer_interval", 0)
        self._timer_loop_cnt: int = 1
        self._pending_cbts: dict[int, CBT] = {}
        self._owned_cbts: dict[int, CBT] = {}

    @property
    def controller(self):
        return self._controller_obj

    @controller.setter
    def controller(self, ctrl_obj):
        self._controller_obj = ctrl_obj

    @property
    def work_queue(self) -> queue.Queue:
        return self._cm_queue

    def submit_cbt(self, cbt):
        # submit a CBT via the broker
        cbt.time_submit = time.time()
        self._broker_obj.submit_cbt(cbt)

    def create_cbt(self, initiator=None, recipient=None, action=None, params=None):
        # create and return a CBT with optional parameters
        cbt = CBT(initiator, recipient, action, params)
        self._owned_cbts[cbt.tag] = cbt
        cbt.time_create = time.time()
        return cbt

    def create_linked_cbt(self, parent):
        cbt = self.create_cbt()
        cbt.parent = parent
        parent.child_count = parent.child_count + 1
        cbt.time_create = time.time()
        return cbt

    def free_cbt(self, cbt):
        cbt.time_free = time.time()
        if not cbt.child_count == 0:
            raise RuntimeError("Invalid attempt to free a linked CBT")
        if cbt.parent is not None:
            cbt.parent.child_count = cbt.parent.child_count - 1
            cbt.parent = None
        # explicitly deallocate CBT
        self._owned_cbts.pop(cbt.tag, None)
        del cbt

    def complete_cbt(self, cbt):
        cbt.time_complete = time.time()
        cbt.completed = True
        self._pending_cbts.pop(cbt.tag, None)
        if not cbt.child_count == 0:
            raise RuntimeError(
                "Invalid attempt to complete a CBT with outstanding dependencies"
            )
        self._broker_obj.submit_cbt(cbt)

    def initialize(self):
        # intialize the Controller Module and start it's threads
        self._controller_obj.initialize()

        # create the worker thread, which is started by broker
        thread_name = self._controller_obj.name + ".worker"
        self._cm_thread = threading.Thread(
            target=self.__worker, name=thread_name, daemon=False
        )

        # enable the timer event if the timer_interval is specified
        if self._timer_interval > 0:
            # create the timer worker thread, which is started by boker
            thread_name = self._controller_obj.name + ".timer"
            self._timer_thread = threading.Thread(
                target=self.__timer_worker, name=thread_name, daemon=False
            )

    def update_timer_interval(self, interval):
        self._timer_interval = interval

    def start_controller(self):
        self._cm_thread.start()

    def __worker(self):
        # get CBT from the local queue and call process_cbt() of the
        # CBT recipient and passing the CBT as an argument
        while True:
            cbt = self._cm_queue.get()
            # Terminate when CBT is None
            if cbt is None:
                self._controller_obj.terminate()
                self._cm_queue.task_done()
                break
            else:
                try:
                    if not cbt.completed:
                        self._pending_cbts[cbt.tag] = cbt
                    self._controller_obj.process_cbt(cbt)
                except Exception as err:
                    self._controller_obj.logger.warning(
                        f"Process CBT exception:{err}\n{cbt}\n{traceback.format_exc()}"
                    )
                    if cbt.request.initiator == self._controller_obj.name:
                        self.free_cbt(cbt)
                    else:
                        cbt.set_response(None, False)
                        self.complete_cbt(cbt)
                finally:
                    self._cm_queue.task_done()

    def __timer_worker(self):
        # call the timer_method of each CM every timer_interval seconds
        while not self._exit_event.wait(self._timer_interval):
            try:
                self._controller_obj.trace_state()
                self._check_container_bounds()
                self._controller_obj.timer_method()
            except Exception as err:
                self._controller_obj.logger.warning(
                    f"Timer Method exception:{err}\n{traceback.format_exc()}"
                )
        self._controller_obj.timer_method(True)

    def query_param(self, param_name=""):
        return self._broker_obj.query_param(param_name)

    # Caller is the subscription source
    def publish_subscription(self, publisher_name, subscription_name):
        return self._broker_obj.publish_subscription(
            publisher_name, subscription_name, self._controller_obj
        )

    def remove_subscription(self, sub):
        self._broker_obj.remove_subscription(sub)

    def get_registered_publishers(self) -> list:
        return self._broker_obj.get_registered_publishers()

    def get_available_subscriptions(self, publisher_name) -> list:
        return self._broker_obj.get_available_subscriptions(publisher_name)

    # Caller is the subscription sink
    def start_subscription(self, publisher_name, subscription_name):
        self._broker_obj.start_subscription(
            publisher_name, subscription_name, self._controller_obj
        )

    def end_subscription(self, publisher_name, subscription_name):
        self._broker_obj.end_subscription(
            publisher_name, subscription_name, self._controller_obj
        )

    def _check_container_bounds(self):
        if self._timer_loop_cnt % 10 == 0:
            plen = len(self._pending_cbts)
            if plen >= 25:
                self._controller_obj.logger.warning("_pending_cbts length=%s", plen)
            olen = len(self._owned_cbts)
            if olen >= 25:
                self._controller_obj.logger.warning("_owned_cbts length=%s", olen)
        self._timer_loop_cnt = self._timer_loop_cnt + 1
