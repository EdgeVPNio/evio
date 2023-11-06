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

from . import CONTROLLER_TIMER_INTERVAL, EVENT_PERIOD
from .cbt import CBT
from .process_proxy import ProxyMsg
from .timed_transactions import Transaction


class Nexus:
    """Links the Broker to a Controller"""

    def __init__(self, broker_object, **kwargs):
        self._cm_queue: queue.Queue[CBT] = queue.Queue()  # CBT work queue
        self._ipc_queue: queue.Queue[CBT] = queue.Queue()
        self._controller = None
        self._cm_thread = None
        self._broker = broker_object  # broker object reference
        self._exit_event = threading.Event()
        self.update_timer_interval(
            kwargs.get("timer_interval", CONTROLLER_TIMER_INTERVAL)
        )
        self._timer_loop_cnt: int = 1
        self._pending_cbts: dict[int, CBT] = {}

    @property
    def controller(self):
        return self._controller

    @controller.setter
    def controller(self, ctrl_obj):
        self._controller = ctrl_obj

    @property
    def work_queue(self) -> queue.Queue:
        return self._cm_queue

    def submit_req_cbt(self, cbt):
        if cbt is None:
            self._controller.logger.warning(
                "None is not a permissible CBT value for submit_req_cbt"
            )
        if cbt.is_request and not cbt.is_submited:
            cbt.time_submited = time.time()
            self._broker.submit_cbt(cbt)
        else:
            raise RuntimeError(f"CBT request state is invalid for submission {cbt}")

    def create_cbt(
        self,
        initiator=None,
        recipient=None,
        action=None,
        params=None,
        parent_cbt=None,
        **kwargs,
    ):
        # create and return a CBT with optional parameters
        cbt = CBT(initiator, recipient, action, params, parent_cbt, **kwargs)
        cbt.time_created = time.time()
        return cbt

    def free_cbt(self, cbt: CBT):
        if "on_free" in cbt.context:
            cbt.context["on_free"]()
        if cbt.is_expired:
            for child in cbt.deps:
                child.parent = None  # parent is going away, avoid any further events from the child
            cbt.deps.clear()
        if cbt.parent:
            cbt.parent.deps.remove(cbt)
            cbt.parent = None
        cbt.time_freed = time.time()

    def complete_cbt(self, cbt):
        if cbt is None:
            self._controller.logger.warning(
                "None is not a permissible CBT value for complete_cbt"
            )
        self._pending_cbts.pop(cbt.tag, None)
        cbt.time_completed = time.time()
        self._broker.submit_cbt(cbt)

    def get_pending_cbt(self, tag: int) -> CBT:
        cbt = self._pending_cbts.get(tag)
        if cbt and not cbt.is_pending:
            self._pending_cbts.pop(tag)
            return None
        return cbt

    def initialize(self):
        # intialize the Controller Module and start it's threads
        self._controller.initialize()

        # create the worker thread, which is started by broker
        thread_name = self._controller.name + ".worker"
        self._cm_thread = threading.Thread(
            target=self.__worker, name=thread_name, daemon=False
        )

    def update_timer_interval(self, interval: int):
        self._timer_interval: int = interval
        if self._timer_interval < EVENT_PERIOD:
            self._timer_interval = EVENT_PERIOD

    def start_controller(self):
        self._cm_thread.start()
        self._broker.register_dpc(self._timer_interval, self.on_timer)

    def __worker(self):
        # get CBT from the local queue and call process_cbt() of the
        # recipient with the CBT as an argument
        while True:
            try:
                cbt = self._cm_queue.get()
                # Terminate when CBT is None
                if cbt is None:
                    self._controller.terminate()
                    break
                elif isinstance(cbt, CBT):
                    if not cbt.is_completed:
                        self._pending_cbts[cbt.tag] = cbt
                    self._controller.process_cbt(cbt)
                elif isinstance(cbt, ProxyMsg):
                    self._controller.handle_ipc(cbt)
            except RuntimeError as err:
                self._controller.logger.warning(
                    "Process CBT RuntimeError exception: %s\nCBT: %s",
                    err,
                    cbt,
                    exc_info=True,
                )
            except KeyError as kerr:
                self._controller.logger.warning(
                    "Process CBT KeyError exception: %s\nCBT: %s",
                    kerr,
                    cbt,
                    exc_info=True,
                )
            finally:
                self._cm_queue.task_done()

    def on_cbt_expired(self, cbt: CBT, time_expired: float):
        """Callback from the TimedTransaction to indicate a CBT has expired.
        The CBT must be in a pending state, ie., it has not already been expired or completed
        """
        if cbt.request.initiator != self._controller.name:
            raise RuntimeWarning(
                f"Invalid Operation: Attemptng to expire a CBT that is not own by this controller {self._controller.name} {cbt}"
            )
        if cbt.is_pending:
            cbt.time_expired = time_expired
            self.work_queue.put(cbt)
        else:
            self._controller.logger.info(
                f"Unexpected CBT state for expired event. {cbt}"
            )

    def on_timer(self):
        try:
            self._controller.log_state()
            self._controller.on_timer_event()
        except Exception as err:
            self._controller.logger.warning(
                "on_timer exception: %s", err, exc_info=True
            )
        self._broker.register_dpc(self._timer_interval, self.on_timer)

    def query_param(self, param_name=""):
        return self._broker.query_param(param_name)

    # Caller is the subscription source
    def publish_subscription(self, publisher_name, subscription_name):
        return self._broker.publish_subscription(
            publisher_name, subscription_name, self._controller
        )

    def remove_subscription(self, sub):
        self._broker.remove_subscription(sub)

    def get_registered_publishers(self) -> list:
        return self._broker.get_registered_publishers()

    def get_available_subscriptions(self, publisher_name) -> list:
        return self._broker.get_available_subscriptions(publisher_name)

    # Caller is the subscription sink
    def start_subscription(self, publisher_name, subscription_name):
        self._broker.start_subscription(
            publisher_name, subscription_name, self._controller
        )

    def end_subscription(self, publisher_name, subscription_name):
        self._broker.end_subscription(
            publisher_name, subscription_name, self._controller
        )

    def register_timed_transaction(self, obj, is_completed, on_expired, lifespan):
        self._broker.register_timed_transaction(
            Transaction(
                item=obj,
                is_completed=is_completed,
                on_expired=on_expired,
                lifespan=lifespan,
            )
        )

    def register_deferred_call(self, delay, call, params):
        self._broker.register_dpc(delay, call, params)

    def send_ipc(self, msg: ProxyMsg):
        self._broker.send_ipc(msg)
