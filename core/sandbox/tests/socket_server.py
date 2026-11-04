"""Owned socket threads for captive test backends."""

from __future__ import annotations

import contextlib
import socket
import threading
from collections.abc import Callable


class SocketServer:
    """Own a listening socket and retire its connection handlers on close."""

    def __init__(self, listener: socket.socket, handler: Callable[[socket.socket], None]):
        self._listener = listener
        self._handler = handler
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._clients: set[socket.socket] = set()
        self._threads: list[threading.Thread] = []
        try:
            listener.settimeout(0.1)
            self._accept_thread = threading.Thread(target=self._accept, daemon=True)
            self._accept_thread.start()
        except BaseException:
            listener.close()
            raise

    def _accept(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            if self._stop.is_set():
                conn.close()
                return
            thread = None
            try:
                thread = threading.Thread(target=self._serve, args=(conn,), daemon=True)
                with self._lock:
                    self._clients.add(conn)
                    self._threads.append(thread)
                thread.start()
            except BaseException:
                conn.close()
                with self._lock:
                    self._clients.discard(conn)
                    if thread in self._threads:
                        self._threads.remove(thread)
                raise

    def _serve(self, conn):
        try:
            self._handler(conn)
        except OSError:
            if not self._stop.is_set():
                raise
        finally:
            conn.close()
            with self._lock:
                self._clients.discard(conn)

    def close(self):
        self._stop.set()
        with contextlib.suppress(OSError):
            self._listener.shutdown(socket.SHUT_RDWR)
        self._listener.close()
        self._accept_thread.join(timeout=2)
        with self._lock:
            clients = list(self._clients)
        for conn in clients:
            with contextlib.suppress(OSError):
                conn.shutdown(socket.SHUT_RDWR)
        for thread in self._threads:
            thread.join(timeout=2)
        for conn in clients:
            conn.close()
        alive = [t.name for t in (self._accept_thread, *self._threads) if t.is_alive()]
        if alive:
            raise RuntimeError(f"SocketServer threads did not stop: {alive}")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
