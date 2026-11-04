"""Captive upstream teardown must retire all of its socket threads."""

from __future__ import annotations

import socket
import threading

import pytest

from core.llm.tests.mock_upstream import MockUpstream


def _assert_stopped(server):
    assert not server._accept_thread.is_alive()
    assert all(not t.is_alive() for t in server._threads)
    assert not server._clients


def test_shutdown_without_clients_is_idempotent():
    server = MockUpstream()
    try:
        server.shutdown()
        _assert_stopped(server)
        server.shutdown()
        _assert_stopped(server)
    finally:
        server.shutdown()


@pytest.mark.parametrize("payload", [
    b"",
    b"POST / HTTP/1.1\r\n",
    b"POST / HTTP/1.1\r\nContent-Length: 20\r\n\r\nx",
])
def test_shutdown_wakes_blocked_request_reader(monkeypatch, payload):
    server = MockUpstream()
    reading = threading.Event()
    original = server._read_request

    def read(conn):
        reading.set()
        return original(conn)

    monkeypatch.setattr(server, "_read_request", read)
    try:
        with socket.create_connection(("127.0.0.1", server.port), timeout=5) as client:
            if payload:
                client.sendall(payload)
            assert reading.wait(5), "upstream did not enter request reader"
            server.shutdown()
            _assert_stopped(server)
    finally:
        server.shutdown()


def test_shutdown_interrupts_response_delay(monkeypatch):
    server = MockUpstream(response_delay_s=60)
    handled = threading.Event()
    original = server._bump

    def bump(name):
        original(name)
        if name == "requests_processed":
            handled.set()

    monkeypatch.setattr(server, "_bump", bump)
    try:
        with socket.create_connection(("127.0.0.1", server.port), timeout=5) as client:
            client.sendall(b"GET / HTTP/1.1\r\n\r\n")
            assert handled.wait(5), "upstream did not process request"
            server.shutdown()
            _assert_stopped(server)
    finally:
        server.shutdown()


def test_shutdown_wakes_half_open_reader(monkeypatch):
    server = MockUpstream("half-open", idle_s=0.01)
    condemned = threading.Event()
    original = server._bump

    def bump(name):
        original(name)
        if name == "condemnations":
            condemned.set()

    monkeypatch.setattr(server, "_bump", bump)
    try:
        with socket.create_connection(("127.0.0.1", server.port), timeout=5):
            assert condemned.wait(5), "upstream did not reach half-open mode"
            server.shutdown()
            _assert_stopped(server)
    finally:
        server.shutdown()


@pytest.mark.parametrize("fault", ["bind", "listen", "thread-start"])
def test_failed_startup_closes_listener(monkeypatch, fault):
    from types import SimpleNamespace
    from core.llm.tests import mock_upstream

    listeners = []

    class Listener(socket.socket):
        def bind(self, address):
            if fault == "bind":
                raise OSError("injected bind failure")
            return super().bind(address)

        def listen(self, backlog):
            if fault == "listen":
                raise OSError("injected listen failure")
            return super().listen(backlog)

    def socket_factory(*args, **kwargs):
        listener = Listener(*args, **kwargs)
        listeners.append(listener)
        return listener

    class StartFailure(threading.Thread):
        def start(self):
            raise RuntimeError("injected thread-start failure")

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(mock_upstream, "socket", SimpleNamespace(
                socket=socket_factory, AF_INET=socket.AF_INET,
                SOCK_STREAM=socket.SOCK_STREAM, SOL_SOCKET=socket.SOL_SOCKET,
                SO_REUSEADDR=socket.SO_REUSEADDR,
            ))
            if fault == "thread-start":
                patcher.setattr(mock_upstream, "threading", SimpleNamespace(
                    Lock=threading.Lock, Event=threading.Event, Thread=StartFailure,
                ))
            with pytest.raises((OSError, RuntimeError), match="injected .* failure"):
                MockUpstream()
        assert len(listeners) == 1
        assert listeners[0].fileno() == -1, "failed startup left its listener open"
    finally:
        for listener in listeners:
            listener.close()


@pytest.mark.parametrize("fault", ["construction", "start"])
def test_failed_handler_start_releases_connection(monkeypatch, fault):
    from types import SimpleNamespace
    from core.llm.tests import mock_upstream

    finished = threading.Event()
    errors = []
    connections = []
    real_thread = threading.Thread

    class StartFailure(real_thread):
        def start(self):
            raise RuntimeError("injected handler start failure")

    def thread(*args, **kwargs):
        if "args" not in kwargs:
            return real_thread(*args, **kwargs)
        connections.append(kwargs["args"][0])
        if fault == "construction":
            raise RuntimeError("injected handler construction failure")
        return StartFailure(*args, **kwargs)

    class ObservedUpstream(MockUpstream):
        def _accept_loop(self):
            try:
                super()._accept_loop()
            except RuntimeError as error:
                errors.append(str(error))
            finally:
                finished.set()

    with monkeypatch.context() as patcher:
        patcher.setattr(mock_upstream, "threading", SimpleNamespace(
            Event=threading.Event, Lock=threading.Lock, Thread=thread,
        ))
        server = ObservedUpstream()
        try:
            with socket.create_connection(("127.0.0.1", server.port), timeout=5):
                assert finished.wait(5), "accept loop did not report injected failure"
                assert errors == [f"injected handler {fault} failure"]
                assert len(connections) == 1
                assert connections[0].fileno() == -1, "failed handler left its socket open"
                assert not server._clients
                assert not server._threads, "unstarted handler remained registered"
                server.shutdown()
                _assert_stopped(server)
        finally:
            # Contain the regression even when shutdown cannot join a failed handler.
            for conn in connections:
                conn.close()
            server._listener.close()
            server._accept_thread.join(timeout=5)
