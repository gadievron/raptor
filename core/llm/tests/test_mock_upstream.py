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
