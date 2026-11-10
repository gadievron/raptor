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
        self._accept_thread = None
        try:
            self._stop = threading.Event()
            self._lock = threading.Lock()
            self._clients: set[socket.socket] = set()
            self._threads: list[threading.Thread] = []
            listener.settimeout(0.1)
            self._accept_thread = threading.Thread(target=self._accept, daemon=True)
            self._accept_thread.start()
        except BaseException:
            with contextlib.ExitStack() as cleanup:
                if self._accept_thread is not None and self._accept_thread.ident is not None:
                    cleanup.callback(self._accept_thread.join, timeout=2)
                cleanup.callback(listener.close)
                if hasattr(self, "_stop"):
                    self._stop.set()
                with contextlib.suppress(OSError):
                    listener.shutdown(socket.SHUT_RDWR)
            if (self._accept_thread is not None
                    and self._accept_thread.ident is not None
                    and self._accept_thread.is_alive()):
                raise RuntimeError("SocketServer acceptor did not stop after failed setup")
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
                # The accept loop exits on this failure; wake-up errors in its
                # partially started handler are teardown, not handler failures.
                self._stop.set()
                started = thread is not None and thread.ident is not None
                try:
                    with contextlib.ExitStack() as cleanup:
                        cleanup.callback(conn.close)
                        if started:
                            cleanup.callback(thread.join, timeout=2)
                        if started:
                            with contextlib.suppress(OSError):
                                conn.shutdown(socket.SHUT_RDWR)
                finally:
                    with self._lock:
                        self._clients.discard(conn)
                        if thread in self._threads and not thread.is_alive():
                            self._threads.remove(thread)
                if started and thread.is_alive():
                    raise RuntimeError("SocketServer handler did not stop after failed setup")
                raise

    def _serve(self, conn):
        try:
            self._handler(conn)
        except OSError:
            if not self._stop.is_set():
                raise
        finally:
            try:
                conn.close()
            finally:
                with self._lock:
                    self._clients.discard(conn)

    def close(self):
        errors = []

        def attempt(action, *args, **kwargs):
            # One failed close or interrupted join must not abandon the rest.
            try:
                action(*args, **kwargs)
            except BaseException as exc:
                errors.append(exc)

        attempt(self._stop.set)
        def shutdown_listener():
            with contextlib.suppress(OSError):
                self._listener.shutdown(socket.SHUT_RDWR)

        attempt(shutdown_listener)
        attempt(self._listener.close)
        attempt(self._accept_thread.join, timeout=2)
        with self._lock:
            clients = list(self._clients)
        for conn in clients:
            def shutdown(conn=conn):
                with contextlib.suppress(OSError):
                    conn.shutdown(socket.SHUT_RDWR)
            attempt(shutdown)
        for thread in self._threads:
            attempt(thread.join, timeout=2)
        for conn in clients:
            attempt(conn.close)
        alive = [t.name for t in (self._accept_thread, *self._threads) if t.is_alive()]
        if alive:
            raise RuntimeError(f"SocketServer threads did not stop: {alive}")
        if errors:
            raise errors[0]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
