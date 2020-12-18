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

import threading
import traceback
import queue as Queue
import time
from .CBT import CBT

class CFxHandle():
    def __init__(self, CFxObject):
        self._cm_queue = Queue.Queue()  # CBT queue
        self._cm_instance = None
        self._cm_thread = None  # CM worker thread
        self._cm_config = None
        self.__cfx_object = CFxObject  # CFx object reference
        self._exit_event = threading.Event()
        self._timer_thread = None
        self._timer_interval = 0
        self._timer_loop_cnt = 1
        self._pending_cbts = {}
        self._owned_cbts = {}

    def submit_cbt(self, cbt):
        # submit CBT to the CFx
        cbt.time_submit = time.time()
        self.__cfx_object.submit_cbt(cbt)

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
        if not cbt.parent is None:
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
            raise RuntimeError("Invalid attempt to complete a CBT with outstanding dependencies")
        self.__cfx_object.submit_cbt(cbt)

    def initialize(self):
        # intialize the Controller Module and start it's threads
        self._cm_instance.initialize()

        # create the worker thread, which is started by CFx
        thread_name = self._cm_instance.__class__.__name__ + "::__worker"
        self._cm_thread = threading.Thread(target=self.__worker, name=thread_name,
                                           daemon=False)

        # enable the timer event if the timer_interval is specified
        self._timer_interval = int(self._cm_config.get("TimerInterval", 0))
        if self._timer_interval > 0:
            # create the timer worker thread, which is started by CFx
            thread_name = self._cm_instance.__class__.__name__ + "::__timer"
            self._timer_thread = threading.Thread(target=self.__timer_worker,
                                                  name=thread_name, daemon=False)

    def update_timer_interval(self, interval):
        self._timer_interval = interval

    def __worker(self):
        # get CBT from the local queue and call process_cbt() of the
        # CBT recipient and passing the CBT as an argument
        while True:
            cbt = self._cm_queue.get()
            # Terminate when CBT is None
            if cbt is None:
                self._cm_queue.task_done()
                self._cm_instance.terminate()
                break
            else:
                try:
                    if not cbt.completed:
                        self._pending_cbts[cbt.tag] = cbt
                    self._cm_instance.process_cbt(cbt)
                except Exception as err:
                    log_cbt = self.create_cbt(
                        initiator=self._cm_instance.__class__.__name__,
                        recipient="Logger", action="LOG_WARNING",
                        params="Process CBT exception:{0}\n{1}\n{2}"
                        .format(err, cbt, traceback.format_exc()))
                    self.submit_cbt(log_cbt)
                    if cbt.request.initiator == self._cm_instance.__class__.__name__:
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
                self._check_container_bounds()
                self._cm_instance.timer_method()
            except Exception as err:
                log_cbt = self.create_cbt(
                    initiator=self._cm_instance.__class__.__name__,
                    recipient="Logger", action="LOG_WARNING",
                    params="Timer Method exception:{0}\n{1}"
                    .format(err, traceback.format_exc()))
                self.submit_cbt(log_cbt)

    def query_param(self, param_name=""):
        pv = self.__cfx_object.query_param(param_name)
        return pv

    # Caller is the subscription source
    def publish_subscription(self, subscription_name):
        return self.__cfx_object.publish_subscription(self._cm_instance.__class__.__name__,
                                                      subscription_name, self._cm_instance)

    def remove_subscription(self, sub):
        self.__cfx_object.RemoveSubscriptionPublisher(sub)

    # Caller is the subscription sink
    def start_subscription(self, owner_name, subscription_name):
        self.__cfx_object.start_subscription(owner_name, subscription_name, self._cm_instance)

    def end_subscription(self, owner_name, subscription_name):
        self.__cfx_object.end_subscription(owner_name, subscription_name, self._cm_instance)

    def _check_container_bounds(self):
        if self._timer_loop_cnt % 10 == 0:
            plen = len(self._pending_cbts)
            if plen >= 50:
                log_cbt = self.create_cbt(initiator=self._cm_instance.__class__.__name__,
                                          recipient="Logger", action="LOG_WARNING",
                                          params="_pending_cbts length={0}".format(plen))
                self.submit_cbt(log_cbt)
            olen = len(self._owned_cbts)
            if olen >= 50:
                log_cbt = self.create_cbt(initiator=self._cm_instance.__class__.__name__,
                                          recipient="Logger", action="LOG_WARNING",
                                          params="_owned_cbts length={0}".format(olen))
                self.submit_cbt(log_cbt)
        self._timer_loop_cnt = self._timer_loop_cnt + 1
