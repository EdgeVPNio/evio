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
import logging.handlers as lh
import os
from framework.ControllerModule import ControllerModule

LogLevel = "INFO"      # Types of messages to log, <ERROR>/<WARNING>/<INFO>/<DEBUG>
Directory = "./logs/"
CtrlLogFileName = "ctrl.log"
TincanLogFileName = "tincan_log"
MaxFileSize = 10000000   # 10MB sized log files
MaxArchives = 5   # Keep up to 5 files of history
ConsoleLevel = None
Device = "All"


class Logger(ControllerModule):
    def __init__(self, cfx_handle, module_config, module_name):
        super(Logger, self).__init__(cfx_handle, module_config, module_name)
        self._logger = None

    def initialize(self):
        # Extracts the controller Log Level from the evio config file,
        # If nothing is provided the default is INFO

        level = getattr(logging, self.config.get("LogLevel", LogLevel))

        # If the Logging is set to Console by the User
        if self.config["Device"] == "Console":
            # Console logging
            logging.basicConfig(format="[%(asctime)s.%(msecs)03d] %(levelname)s: %(message)s",
                                datefmt="%H:%M:%S",
                                level=level)
            self._logger = logging.getLogger()

        # If the Logging is set to File by the User
        elif self.config["Device"] == "File":
            # Extracts the filepath else sets logs to current working directory
            filepath = self.config.get("Directory", Directory)
            fqname = os.path.join(filepath,
                                  self.config.get("CtrlLogFileName", CtrlLogFileName))
            if not os.path.exists(filepath):
                os.makedirs(filepath, exist_ok=True)
            if os.path.isfile(fqname):
                os.remove(fqname)
            self._logger = logging.getLogger()
            self._logger.setLevel(level)
            # Creates rotating filehandler
            handler = lh.RotatingFileHandler(filename=fqname,
                                             maxBytes=self.config.get(
                                                 "MaxFileSize", MaxFileSize),
                                             backupCount=self.config.get("MaxArchives", MaxArchives))
            formatter = logging.Formatter(
                "[%(asctime)s.%(msecs)03d] %(levelname)s:%(name)s: %(message)s", datefmt="%Y%m%d %H:%M:%S")
            handler.setFormatter(formatter)
            # Adds the filehandler to the Python logger module
            self._logger.addHandler(handler)

         # If the Logging is set to All by the User
        else:
            self._logger = logging.getLogger()
            self._logger.setLevel(level)

            # Console Logger
            console_handler = logging.StreamHandler()
            console_log_formatter = logging.Formatter(
                "[%(asctime)s.%(msecs)03d] %(levelname)s: %(message)s",
                datefmt="%H:%M:%S")
            console_handler.setFormatter(console_log_formatter)
            self._logger.addHandler(console_handler)

            # Extracts the filepath else sets logs to current working directory
            filepath = self.config.get("Directory", Directory)
            fqname = os.path.join(filepath,
                                  self.config.get("CtrlLogFileName", CtrlLogFileName))
            if not os.path.exists(filepath):
                os.makedirs(filepath, exist_ok=True)
            if os.path.isfile(fqname):
                os.remove(fqname)

            # File Logger
            # Creates rotating filehandler
            file_handler = lh.RotatingFileHandler(filename=fqname)
            file_log_formatter = logging.Formatter(
                "[%(asctime)s.%(msecs)03d] %(levelname)s: %(message)s", datefmt="%Y%m%d %H:%M:%S")
            file_handler.setFormatter(file_log_formatter)
            self._logger.addHandler(file_handler)

        self._logger.info("Logger: Module loaded")

    def req_handler_tincan_log_config(self, cbt):
        cfg = {
            "Level": self.config.get("LogLevel", LogLevel),
            "Device": self.config.get("Device", Device),
            "Directory": self.config.get("Directory", Directory),
            "Filename": self.config.get("TincanLogFileName", TincanLogFileName),
            "MaxArchives": self.config.get("MaxArchives", MaxArchives),
            "MaxFileSize": self.config.get("MaxFileSize", MaxFileSize),
            "ConsoleLevel": self.config.get("ConsoleLevel", ConsoleLevel)
        }
        cbt.set_response(cfg, True)

    def process_cbt(self, cbt):
        if cbt.op_type == "Request":
            lvl = cbt.request.action
            mod = cbt.request.initiator
            if isinstance(cbt.request.params, tuple):
                fmt = "LOGGER MODULE DEPRECATD: %s: " + cbt.request.params[0]
                vals = cbt.request.params[1]
            else:
                fmt = "LOGGER MODULE DEPRECATD: %s: %s"
                vals = [cbt.request.params]

            if lvl == "LOG_DEBUG":
                self._logger.debug(fmt, mod, *vals)
                cbt.set_response(None, True)
            elif lvl == "LOG_INFO":
                self._logger.info(fmt, mod, *vals)
                cbt.set_response(None, True)
            elif lvl == "LOG_WARNING":
                self._logger.warning(fmt, mod, *vals)
                cbt.set_response(None, True)
            elif lvl == "LOG_ERROR":
                self._logger.error(fmt, mod, *vals)
                cbt.set_response(None, True)
            elif lvl == "LOG_QUERY_CONFIG":
                self.req_handler_tincan_log_config(cbt)
            else:
                self._logger.warning(
                    "%s: Unsupported CBT action %s", self._module_name, str(cbt))
                cbt.set_response("Unsupported CBT action", False)
            self.complete_cbt(cbt)

        elif cbt.op_type == "Response":
            self.free_cbt(cbt)

    def timer_method(self):
        pass

    def terminate(self):
        logging.shutdown()
