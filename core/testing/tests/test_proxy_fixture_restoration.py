"""Aborted proxy fixtures release owned resources and restore process state."""

import importlib
import os
from types import SimpleNamespace

import pytest

from core.sandbox import proxy as proxy_mod
from core.sandbox.tests import test_proxy_sigterm as sigterm


CASES = [
    ("test_lane_isolation", None, "reset_proxy"),
    ("test_parser_jail", None, "reset_proxy"),
    ("test_proxy_audit", None, "reset_proxy"),
    ("test_proxy_dns_cache", None, "reset_proxy"),
    ("test_proxy_gate2_multirecord", None, "reset_proxy"),
    ("test_proxy_handshake_budget", None, "reset_proxy"),
    ("test_proxy_lanes", None, "reset_proxy"),
    ("test_proxy_live_escalation", None, "reset_proxy"),
    ("test_proxy_observability", None, "reset_proxy"),
    ("test_proxy_peer_uid", None, "reset_proxy"),
    ("test_proxy_perf", None, "reset_proxy"),
    ("test_proxy_port_gate", None, "reset_proxy"),
    ("test_proxy_record_unregister_race", None, "reset_proxy"),
    ("test_proxy_sni_gate", None, "reset_proxy"),
    ("test_proxy_sock_diag", "TestForcedMissChurnVerdicts", "reset_proxy"),
    ("test_proxy_sock_diag", "TestGateEndToEnd", "reset_proxy"),
    ("test_proxy_teardown", None, "reset_proxy"),
    ("test_proxy_upstream_errors", None, "reset_proxy"),
    ("test_proxy_upstream_gate2", None, "reset_proxy"),
    ("test_proxy_upstream_handshake_timeout", None, "reset_proxy"),
]


def _fixture(case):
    name, owner, function = case
    module = importlib.import_module("core.sandbox.tests." + name)
    if owner is None:
        return getattr(module, function).__wrapped__()
    instance = getattr(module, owner)()
    return getattr(type(instance), function).__wrapped__(instance)


class OwnedProxy:
    def __init__(self):
        self.fds = list(os.pipe())
        self.closed = False

    def stop(self, **kwargs):
        while self.fds:
            os.close(self.fds.pop())
        self.closed = True


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("failure", [OSError, KeyboardInterrupt, GeneratorExit, None])
def test_proxy_reset_fixture_releases_owned_proxy(case, failure, monkeypatch):
    owned = OwnedProxy()
    fixture = None
    try:
        with monkeypatch.context() as patcher:
            # Preserve any pre-existing singleton; only this test's resource
            # may be touched by the real reset function.
            patcher.setattr(proxy_mod, "_instance", None)
            fixture = _fixture(case)
            next(fixture)
            proxy_mod._instance = owned
            if failure is None:
                with pytest.raises(StopIteration):
                    next(fixture)
            elif failure is GeneratorExit:
                fixture.close()
            else:
                with pytest.raises(failure, match="injected fixture interruption"):
                    fixture.throw(failure("injected fixture interruption"))
            assert owned.closed, "aborted fixture left its proxy resource open"
            assert proxy_mod._instance is None
    finally:
        if fixture is not None:
            fixture.close()
        owned.stop()


@pytest.mark.parametrize("failure", [OSError, KeyboardInterrupt, GeneratorExit])
def test_sigterm_fixture_abort_restores_both_state_slots(failure, monkeypatch):
    previous, changed = object(), object()
    state = SimpleNamespace(handler=previous)
    signals = SimpleNamespace(SIGTERM=15, getsignal=lambda sig: state.handler)
    signals.signal = lambda sig, handler: setattr(state, "handler", handler)
    with monkeypatch.context() as patcher:
        patcher.setattr(sigterm, "signal", signals)
        patcher.setattr(proxy_mod, "_sigterm_hook_installed", True)
        fixture = sigterm.sigterm_state.__wrapped__()
        try:
            next(fixture)
            state.handler = changed
            if failure is GeneratorExit:
                fixture.close()
            else:
                with pytest.raises(
                    failure, match="injected signal fixture interruption"
                ):
                    fixture.throw(failure("injected signal fixture interruption"))
            assert state.handler is previous
            assert proxy_mod._sigterm_hook_installed is True
        finally:
            fixture.close()


@pytest.mark.parametrize("failure", [OSError, KeyboardInterrupt])
def test_sigterm_restore_failure_still_restores_install_flag(failure, monkeypatch):
    signals = SimpleNamespace(SIGTERM=15, getsignal=lambda sig: object())

    def restore(*args):
        raise failure("injected handler restoration failure")

    signals.signal = restore
    with monkeypatch.context() as patcher:
        patcher.setattr(sigterm, "signal", signals)
        patcher.setattr(proxy_mod, "_sigterm_hook_installed", True)
        fixture = sigterm.sigterm_state.__wrapped__()
        try:
            next(fixture)
            with pytest.raises(failure, match="injected handler restoration failure"):
                next(fixture)
            assert proxy_mod._sigterm_hook_installed is True
        finally:
            fixture.close()


@pytest.mark.parametrize("case", CASES)
def test_aborted_fixture_stops_real_local_proxy(case, monkeypatch):
    fixture = None
    owned = None
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(proxy_mod, "_instance", None)
            fixture = _fixture(case)
            next(fixture)
            owned = proxy_mod.EgressProxy(allowed_hosts={"unused.invalid"})
            proxy_mod._instance = owned
            fixture.close()
            assert proxy_mod._instance is None
            assert not owned._thread.is_alive(), (
                "fixture left real proxy thread running"
            )
    finally:
        if fixture is not None:
            fixture.close()
        if owned is not None:
            owned.stop(drain_timeout=0)


@pytest.mark.parametrize("failure", [OSError, KeyboardInterrupt, GeneratorExit])
def test_aborted_fixture_restores_real_signal_handler(failure, monkeypatch):
    import signal

    previous = signal.getsignal(signal.SIGTERM)
    fixture = None
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(proxy_mod, "_sigterm_hook_installed", True)
            fixture = sigterm.sigterm_state.__wrapped__()
            next(fixture)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            if failure is GeneratorExit:
                fixture.close()
            else:
                with pytest.raises(
                    failure, match="injected native fixture interruption"
                ):
                    fixture.throw(failure("injected native fixture interruption"))
            assert signal.getsignal(signal.SIGTERM) == previous
            assert proxy_mod._sigterm_hook_installed is True
    finally:
        try:
            if fixture is not None:
                fixture.close()
        finally:
            signal.signal(signal.SIGTERM, previous)
