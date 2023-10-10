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


try:
    import simplejson as json
except ImportError:
    import json

import logging
import queue
import select
import socket
import sys
import threading
import time
from collections import deque

from . import introspect


class ProxyMsg:
    def __init__(self, fileno, rdsz=0, payload=None) -> None:
        self.fileno: int = fileno
        self.rdsz: int = rdsz
        self.payload = payload
        self._json = None
        self.ts = time.time()

    @property
    def data(self) -> bytearray:
        return self.payload

    @data.setter
    def data(self, payload: bytearray):
        self.ts = time.time()
        self._json = None
        if payload is None:
            return
        self.payload = payload

    def __repr__(self) -> str:
        return f"{self.fileno}:{self.payload.decode('utf-8')}"

    @property
    def json(self):
        if self._json is None:
            self._json = json.loads(self.payload.decode("utf-8"))
        return self._json


class ProxyNode:
    def __init__(self, connection: socket = None, event: int = select.EPOLLIN) -> None:
        self.skt: socket = connection
        self.tx_deque: deque = deque()
        self.event: int = event
        self.is_rdhup: bool = False

    def __repr__(self) -> str:
        return introspect(self)


class ProcessProxy:
    """
    Starts the Unix Domain Socket proxy listener to support interactions between
    the controller modules and external local processes.
    """

    def __init__(self, dispatch_msg_cb, logger: logging.Logger, create_svc_thread=True):
        self.logger = logger
        self.tx_que = queue.Queue()
        self.dispatch_msg = dispatch_msg_cb
        self._svr_thread = None
        if create_svc_thread:
            self._svr_thread = threading.Thread(
                target=self.serve, name="ProcessProxyServer", daemon=False
            )
        self._exit_ev = threading.Event()
        self._server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self._server_sock.setblocking(0)
        self._server_sock.bind("")
        self._server_sock.listen(1)
        self._epoll = select.epoll()
        self._epoll.register(self._server_sock.fileno(), select.EPOLLIN)

    @property
    def address(self) -> str:
        return self._server_sock.getsockname()

    def start(self):
        self._svr_thread.start()

    def serve(self):
        while not self._exit_ev.is_set():
            if self._server_sock is None:
                self._server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                self._server_sock.setblocking(0)
                self._server_sock.bind("")
                self._server_sock.listen(1)
                self._epoll = select.epoll()
                self._epoll.register(self._server_sock.fileno(), select.EPOLLIN)
            self.logger.debug("Starting IPC listener at %s", self.address)
            try:
                connections: dict[int, ProxyNode] = {}
                requests: dict[int, ProxyMsg] = {}
                while not self._exit_ev.is_set():
                    while self.tx_que.qsize() > 0:
                        msg: ProxyMsg = self.tx_que.get_nowait()
                        node = connections.get(msg.fileno, None)
                        if node is not None:
                            if not node.event & select.EPOLLOUT:
                                node.event |= select.EPOLLOUT
                                self._epoll.modify(msg.fileno, node.event)
                            node.tx_deque.append(
                                len(msg.data).to_bytes(2, sys.byteorder)
                            )
                            node.tx_deque.append(msg.data)
                        else:
                            self.logger.info("No connection, dropping msg %s", msg)
                        self.tx_que.task_done()
                    events = self._epoll.poll(1.0)
                    for fileno, event in events:
                        if fileno == self._server_sock.fileno():
                            skt, _ = self._server_sock.accept()
                            self.logger.debug("New IPC connection %s", skt.fileno())
                            skt.setblocking(0)
                            node = ProxyNode(skt, select.EPOLLIN)
                            connections[skt.fileno()] = node
                            self._epoll.register(node.skt.fileno(), node.event)
                        elif event & select.EPOLLRDHUP:
                            node = connections[fileno]
                            node.is_rdhup = True
                            node.event &= ~select.EPOLLIN
                            self._epoll.modify(fileno, node.event)
                            self.logger.warning(
                                "Node %s IPC read hangup", node.skt.fileno()
                            )
                            if not node.tx_deque:
                                self.close_client(node)
                        elif event & select.EPOLLHUP:
                            node = connections.pop(fileno)
                            self.close_client(node)
                        elif event & select.EPOLLIN:
                            req = requests.pop(fileno, None)
                            if req is None:
                                bufsz = int.from_bytes(
                                    connections[fileno].skt.recv(2), sys.byteorder
                                )
                                if bufsz <= 0:
                                    node = connections[fileno]
                                    node.skt.shutdown(socket.SHUT_WR)
                                elif bufsz > 65507:
                                    node = connections[fileno]
                                    connections.pop(fileno)
                                    self.close_client(node)
                                else:
                                    requests[fileno] = ProxyMsg(fileno, rdsz=bufsz)
                            else:
                                req.data = connections[fileno].skt.recv(req.rdsz)
                                self.dispatch_msg(req)

                        elif event & select.EPOLLOUT:
                            node = connections[fileno]
                            entry = node.tx_deque.popleft()
                            _ = node.skt.send(entry)
                            if not node.tx_deque:
                                if node.is_rdhup:
                                    connections.pop(fileno)
                                    self.close_client(node)
                                else:
                                    node.event = select.EPOLLIN
                                    self._epoll.modify(fileno, node.event)
            except BrokenPipeError as bperr:
                connections.pop(fileno)
                self.close_client(node)
                self.logger.exception(bperr)
            except Exception as ex:
                self.logger.exception("Process Proxy Server exception %s", ex)
                self.server_close()

    def close_client(self, node):
        self.logger.debug("Closing connection %s", node.skt.fileno())
        node.skt.shutdown(socket.SHUT_RDWR)
        self._epoll.unregister(node.skt.fileno())
        node.skt.close()
        del node

    def server_close(self):
        self._epoll.unregister(self._server_sock.fileno())
        self._epoll.close()
        self._epoll = None
        self._server_sock.close()
        self._server_sock = None

    def terminate(self):
        self._exit_ev.set()
        self._svr_thread.join()
