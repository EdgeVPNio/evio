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

import logging
import queue
from logging.handlers import QueueHandler, QueueListener, TimedRotatingFileHandler


class PerformanceData:
    def __init__(self, **kwargs) -> None:
        self._rec_id = 0

    def setup_logger(self, log_file, when, backup_count):
        self.logger = logging.getLogger(__name__)
        formatter = logging.Formatter("%(message)s")
        self.file_handler = TimedRotatingFileHandler(
            log_file, when=when, backupCount=backup_count, utc=True
        )
        self.file_handler.setFormatter(formatter)
        que = queue.Queue()
        que_handler = QueueHandler(que)
        self.que_listener = QueueListener(
            que, self.file_handler, respect_handler_level=True
        )

        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(que_handler)
        self.que_listener.start()

    def record(self, entry: dict):
        entry["ID"], self._rec_id = self._rec_id, self._rec_id + 1
        self.logger.info(entry)
