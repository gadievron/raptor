"""Hermeticity guard for the web test suite.

Web tests run against loopback fixtures or mocked clients — nothing
here may touch the real network. The guard turns any non-loopback
connect attempt into an immediate error instead of a silent dependency
on outside reachability: the request-smuggling check's raw-socket probe
against mocked 'example.com' targets burned two 5-second connect
timeouts per scan()-driving test before this existed.

In-process only by design: subprocess children (real ffuf, nuclei,
Chromium) manage their own sockets and are pointed at loopback by
their fixtures.
"""

from __future__ import annotations

import socket

import pytest

_REAL_CONNECT = socket.socket.connect


def _loopback_only_connect(self, address):  # noqa: ANN001
    host = address[0] if isinstance(address, tuple) else address
    if isinstance(host, (bytes, bytearray)):
        host = host.decode("utf-8", "replace")
    if isinstance(host, str) and not (
        host.startswith("127.") or host in ("::1", "localhost")
        or host.startswith("/")  # unix sockets (pytest internals)
    ):
        msg = (
            f"test tried to reach non-loopback host {host!r} — web tests "
            "must use loopback fixtures or mocks"
        )
        raise OSError(msg)
    return _REAL_CONNECT(self, address)


@pytest.fixture(autouse=True)
def _no_external_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", _loopback_only_connect)
