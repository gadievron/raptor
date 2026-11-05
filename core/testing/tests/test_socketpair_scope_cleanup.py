"""Socketpair callers own both ends before timeout setup and teardown."""

from contextlib import nullcontext
import importlib
import socket
from types import SimpleNamespace

import pytest


CASES = {
    "warmup": ("core.sandbox.tests.test_seatbelt_audit_malformed", None),
    "keepalive": ("core.sandbox.tests.test_proxy_tcp_keepalive", None),
    "qualifying": ("core.sandbox.tests.test_pass_fds_socketpair", "TestQualifyingShape"),
    "datagram": ("core.sandbox.tests.test_pass_fds_socketpair", "TestRefusedShapes"),
}


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_first_close_failure_still_closes_peer(case, error, tmp_path, monkeypatch):
    _exercise(case, "close", error, tmp_path, monkeypatch)


@pytest.mark.parametrize("stage", ["reader_timeout", "writer_timeout"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_timeout_setup_failure_closes_pair(stage, error, tmp_path, monkeypatch):
    _exercise("warmup", stage, error, tmp_path, monkeypatch)


def _exercise(case, stage, error, tmp_path, monkeypatch):
    module_name, owner = CASES[case]
    module = importlib.import_module(module_name)
    real_pair = socket.socketpair
    retained = []

    class OwnedSocket:
        def __init__(self, sock, index):
            self.sock, self.index = sock, index

        def __getattr__(self, name):
            return getattr(self.sock, name)

        def close(self):
            self.sock.close()
            if self.index == 0 and stage == "close":
                raise error("injected socket scope failure")

        def settimeout(self, value):
            if stage == ("reader_timeout" if self.index == 0 else "writer_timeout"):
                raise error("injected socket scope failure")
            return self.sock.settimeout(value)

    def pair(*args, **kwargs):
        sockets = real_pair(*args, **kwargs)
        retained.extend(OwnedSocket(sock, index) for index, sock in enumerate(sockets))
        return tuple(retained)

    proxy = SimpleNamespace(**vars(socket))
    proxy.socketpair = pair
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "socket", proxy)
            if case == "qualifying":
                # Exercise ownership independently of Linux SO_PEERCRED.
                patcher.setattr(module, "_anon_socketpair_problem", lambda fd: None)
            expected = nullcontext() if stage == "none" else pytest.raises(
                error, match="injected socket scope failure"
            )
            with expected:
                if case == "warmup":
                    module.test_warmup_continues_after_malformed_entries(tmp_path, patcher, [])
                elif case == "keepalive":
                    module.test_unix_socket_leg_is_skipped()
                else:
                    instance = getattr(module, owner)()
                    if case == "qualifying":
                        instance.test_own_socketpair_half_qualifies()
                    else:
                        instance.test_datagram_pair_refused()
        assert len(retained) == 2
        assert all(item.fileno() == -1 for item in retained), "peer socket leaked"
    finally:
        for item in retained:
            item.sock.close()


@pytest.mark.parametrize("case", CASES)
def test_normal_socketpair_scope_closes_both_ends(case, tmp_path, monkeypatch):
    _exercise(case, "none", OSError, tmp_path, monkeypatch)


@pytest.mark.parametrize("stage", ["bind", "listen", "construct", "connect", "accept", "close"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_tcp_fixture_failure_releases_all_sockets(stage, error, monkeypatch):
    _tcp_fixture(stage, error, monkeypatch)


def test_tcp_fixture_abort_releases_all_sockets(monkeypatch):
    _tcp_fixture("none", OSError, monkeypatch)


def _tcp_fixture(stage, error, monkeypatch):
    from core.sandbox.tests import test_proxy_tcp_keepalive as module

    real_socket = socket.socket
    retained = []

    def fail():
        raise error("injected TCP fixture failure")

    class OwnedSocket:
        def __init__(self, sock):
            self.sock = sock
            retained.append(self)

        def __getattr__(self, name):
            if name == stage and stage in ("bind", "listen", "connect", "accept"):
                return lambda *a, **kw: fail()
            return getattr(self.sock, name)

        def accept(self):
            if stage == "accept":
                fail()
            accepted, address = self.sock.accept()
            return OwnedSocket(accepted), address

        def close(self):
            self.sock.close()
            if stage == "close" and self is retained[-1]:
                fail()

    def construct(*args, **kwargs):
        if stage == "construct" and retained:
            fail()
        return OwnedSocket(real_socket(*args, **kwargs))

    proxy = SimpleNamespace(**vars(socket))
    proxy.socket = construct
    fixture = None
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "socket", proxy)
            fixture = module.tcp_pair.__wrapped__()
            expected = nullcontext() if stage == "none" else pytest.raises(
                error, match="injected TCP fixture failure"
            )
            with expected:
                next(fixture)
                fixture.close()
        assert retained and all(item.fileno() == -1 for item in retained)
    finally:
        if fixture is not None:
            fixture.close()
        for item in retained:
            item.sock.close()
