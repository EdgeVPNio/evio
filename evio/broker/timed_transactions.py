import logging
import sched
import threading

from . import TIMER_EVENT_PERIOD


class TimedTransactions:
    def __init__(self) -> None:
        self._exit_ev = threading.Event()
        thread_name = "TimedTransactions.event"
        self._event_thread = threading.Thread(
            target=self._run, name=thread_name, daemon=False
        )
        self._chk_interval = float(TIMER_EVENT_PERIOD)
        self._sched = sched.scheduler()

    def register_dpc(self, delay: float, call, params: tuple):
        if self._exit_ev.is_set():
            return
        self._sched.enter(delay, 15, call, params)

    def _run(self):
        while not self._exit_ev.wait(self._chk_interval):
            try:
                while not self._exit_ev.wait(self._chk_interval):
                    self._sched.run(blocking=False)
            except Exception:
                logging.getLogger().exception("TimedTransactions run failure")

    def start(self):
        self._event_thread.start()

    def terminate(self):
        self._exit_ev.set()
        self._event_thread.join()
