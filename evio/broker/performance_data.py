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
from logging.handlers import TimedRotatingFileHandler


class PerformanceData:
    def __init__(self, **kwargs) -> None:
        self._setup_logger(__name__, kwargs["LogFile"])
        self._rec_id = 0

    def _setup_logger(self, logger_name, log_file, level=logging.INFO):
        self.logger = logging.getLogger(logger_name)
        formatter = logging.Formatter("%(message)s")
        fileHandler = TimedRotatingFileHandler(
            log_file, when="midnight", backupCount=7, utc=True
        )
        fileHandler.setFormatter(formatter)

        self.logger.setLevel(level)
        self.logger.addHandler(fileHandler)

    def record(self, entry: dict):
        entry["ID"], self._rec_id = self._rec_id, self._rec_id + 1
        self.logger.info(entry)
