import logging
import sched
import threading
import time

from . import EVENT_PERIOD


class Transaction:
    def __init__(self, item, is_completed, on_expired, lifespan) -> None:
        self.item = item
        self._is_completed = is_completed
        self.lifespan = lifespan
        self.on_expired = on_expired
        self.priority: int = 10

    def is_completed(self):
        return self._is_completed(self.item)


class TimedTransactions:
    def __init__(self) -> None:
        self._exit_ev = threading.Event()
        thread_name = "TimedTransactions.event"
        self._event_thread = threading.Thread(
            target=self._run, name=thread_name, daemon=False
        )
        self._chk_interval = float(EVENT_PERIOD)
        self._sched = sched.scheduler()

    def register(self, entry: Transaction):
        if self._exit_ev.is_set():
            return
        self._sched.enter(entry.lifespan, entry.priority, self._get_expired, [entry])

    def _get_expired(self, entry):
        if not entry.is_completed():
            # entry.time_expired = time.time()
            entry.on_expired(entry.item, time.time())

    def _run(self):
        # while not self._exit_ev.wait(self._chk_interval):
        #     self._sched.run(blocking=False)
        while not self._exit_ev.wait(self._chk_interval):
            try:
                while not self._exit_ev.wait(self._chk_interval):
                    self._sched.run(blocking=False)
            except Exception as err:
                logging.getLogger().exception("%s", err)

    def start(self):
        self._event_thread.start()

    def terminate(self):
        self._exit_ev.set()
        self._event_thread.join()
