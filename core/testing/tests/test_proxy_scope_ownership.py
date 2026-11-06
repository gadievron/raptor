"""Proxy fixtures keep borrowed real listeners and benign worker children alive.

Worker startup is replaced only for lifecycle fault injection. Native proxy
suites separately exercise the confined parser; these cases claim no isolation.
"""

import ast
import atexit
from contextlib import ExitStack
from pathlib import Path
import os
import shutil
import signal
import socket
import subprocess
import sys
from types import ModuleType
import unittest

import pytest

from core.sandbox import parser_jail, proxy
from core.testing import proxy_scope
from core.testing.processes import reap_on_exit

ROOT = Path(__file__).resolve().parents[3]
CASES = [['core/sandbox/tests/test_lane_isolation.py', None, 'reset_proxy'], ['core/sandbox/tests/test_parser_jail.py', None, 'reset_proxy'], ['core/sandbox/tests/test_proxy_audit.py', None, 'reset_proxy'], ['core/sandbox/tests/test_proxy_dns_cache.py', None, 'reset_proxy'], ['core/sandbox/tests/test_proxy_gate2_multirecord.py', None, 'reset_proxy'], ['core/sandbox/tests/test_proxy_handshake_budget.py', None, 'reset_proxy'], ['core/sandbox/tests/test_proxy_lanes.py', None, 'reset_proxy'], ['core/sandbox/tests/test_proxy_live_escalation.py', None, 'reset_proxy'], ['core/sandbox/tests/test_proxy_observability.py', None, 'reset_proxy'], ['core/sandbox/tests/test_proxy_peer_uid.py', None, 'reset_proxy'], ['core/sandbox/tests/test_proxy_perf.py', None, 'reset_proxy'], ['core/sandbox/tests/test_proxy_port_gate.py', None, 'reset_proxy'], ['core/sandbox/tests/test_proxy_record_unregister_race.py', None, 'reset_proxy'], ['core/sandbox/tests/test_proxy_sni_gate.py', None, 'reset_proxy'], ['core/sandbox/tests/test_proxy_sock_diag.py', 'TestForcedMissChurnVerdicts', 'reset_proxy'], ['core/sandbox/tests/test_proxy_sock_diag.py', 'TestGateEndToEnd', 'reset_proxy'], ['core/sandbox/tests/test_proxy_teardown.py', None, 'reset_proxy'], ['core/sandbox/tests/test_proxy_upstream_errors.py', None, 'reset_proxy'], ['core/sandbox/tests/test_proxy_upstream_gate2.py', None, 'reset_proxy'], ['core/sandbox/tests/test_proxy_upstream_handshake_timeout.py', None, 'reset_proxy'], ['core/sandbox/tests/test_e2e_sandbox.py', 'TestE2EEgressProxy', 'setUp'], ['core/sandbox/tests/test_proxy_target_pollution.py', 'TestProxyEventsTargetPollution', 'setUp']]


def _function(case):
    path, cls, name = case
    tree = ast.parse((ROOT / path).read_text())
    parent = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == cls) if cls else tree
    node = next(n for n in parent.body if isinstance(n, ast.FunctionDef) and n.name == name)
    node.decorator_list = []
    namespace = dict(proxy_mod=proxy, isolated_proxy_scope=proxy_scope.isolated_proxy_scope,
                     check_net_available=lambda: True, os=os, shutil=shutil)
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(ROOT / path), "exec"), namespace)
    return namespace[name]


@pytest.fixture
def lifecycle_workers(monkeypatch):
    """Attach owned benign children to real ParserJail objects."""
    with ExitStack() as resources:
        started = []
        def start(jail):
            started.append(jail)
            left, right = socket.socketpair()
            resources.callback(left.close)
            resources.callback(right.close)
            proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
            resources.enter_context(reap_on_exit(proc))
            jail._proc, jail._sock = proc, left
            return jail
        monkeypatch.setattr(parser_jail.ParserJail, "start", start)
        yield started


@pytest.mark.parametrize("case", CASES, ids=[str(i) for i in range(len(CASES))])
@pytest.mark.parametrize("finish", ["normal", "body_error", "interrupt"])
def test_proxy_fixture_preserves_live_borrowed_owners(case, finish, lifecycle_workers, monkeypatch):
    registered = set()
    exits = ModuleType("atexit")
    vars(exits).update(vars(atexit))
    def register(callback, *args, **kwargs):
        registered.add(callback)
        return atexit.register(callback, *args, **kwargs)
    def unregister(callback):
        registered.discard(callback)
        return atexit.unregister(callback)
    exits.register, exits.unregister = register, unregister
    for module in (proxy, parser_jail, proxy_scope):
        monkeypatch.setattr(module, "atexit", exits)
    real_proxy = proxy.EgressProxy
    real_stop = real_proxy.stop
    real_jail_stop = parser_jail.ParserJail.stop
    with ExitStack() as cleanup:
        prior = signal.getsignal(signal.SIGTERM)
        cleanup.callback(signal.signal, signal.SIGTERM, prior)
        monkeypatch.setattr(proxy, "_instance", None)
        monkeypatch.setattr(parser_jail, "_jail", None)
        borrowed = real_proxy(allowed_hosts=set())
        cleanup.callback(real_stop, borrowed, drain_timeout=0)
        jail = borrowed._parser_jail
        cleanup.callback(unregister, jail.stop)
        cleanup.callback(real_jail_stop, jail)
        child = jail._proc
        monkeypatch.setattr(proxy, "_instance", borrowed)
        monkeypatch.setattr(proxy, "_sigterm_hook_installed", True)
        before_callbacks = registered.copy()
        before_handler = signal.getsignal(signal.SIGTERM)
        function = _function(case)
        unit = unittest.TestCase()
        generator, owned, owned_jail, direct = None, None, None, None
        try:
            if case[2] == "setUp":
                function(unit)
            else:
                generator = function(unit) if case[1] else function()
                next(generator)
            owned = proxy.get_proxy(set())
            owned_jail = owned._parser_jail
            owned_child = owned_jail._proc
            direct = proxy.EgressProxy(allowed_hosts=set())
            if generator is not None:
                if finish == "normal":
                    generator.close()
                else:
                    error = RuntimeError if finish == "body_error" else KeyboardInterrupt
                    with pytest.raises(error):
                        generator.throw(error)
            else:
                try:
                    if finish != "normal":
                        raise RuntimeError if finish == "body_error" else KeyboardInterrupt
                except (RuntimeError, KeyboardInterrupt):
                    pass
                finally:
                    assert unit.doCleanups()
            assert proxy._instance is borrowed
            assert parser_jail._jail is jail
            assert borrowed.is_alive()
            assert child.poll() is None
            assert not owned.is_alive()
            assert not direct.is_alive()
            assert owned_child.poll() is not None
            assert signal.getsignal(signal.SIGTERM) is before_handler
            assert proxy._sigterm_hook_installed is True
            assert registered == before_callbacks
        finally:
            if generator is not None:
                generator.close()
            unit.doCleanups()
            for item in (owned, direct):
                if item is not None:
                    real_stop(item, drain_timeout=0)
                    unregister(item.stop)
            if owned_jail is not None and owned_jail is not jail:
                real_jail_stop(owned_jail)
                unregister(owned_jail.stop)


@pytest.mark.parametrize("fault", [
    "constructor_error", "constructor_interrupt", "registration_error",
    "stop_error", "stop_interrupt", "parser_stop_error", "parser_stop_interrupt",
    "publication_error", "signal_error",
])
def test_proxy_scope_unwinds_setup_and_teardown_faults(fault, lifecycle_workers, monkeypatch):
    class Failure(Exception):
        pass
    error = KeyboardInterrupt if fault.endswith("interrupt") else Failure
    before = (proxy._instance, parser_jail._jail, proxy.EgressProxy,
              proxy._sigterm_hook_installed, signal.getsignal(signal.SIGTERM),
              proxy.atexit, parser_jail.atexit)
    owners = []
    original_init = proxy.EgressProxy.__init__
    def initialize(owner, *args, **kwargs):
        owners.append(owner)
        original_init(owner, *args, **kwargs)
        if fault.startswith("constructor"):
            raise error
    monkeypatch.setattr(proxy.EgressProxy, "__init__", initialize)
    if fault == "registration_error":
        exits = ModuleType("atexit")
        vars(exits).update(vars(atexit))
        def fail_register(callback, *args, **kwargs):
            atexit.register(callback, *args, **kwargs)
            raise Failure
        exits.register = fail_register
        monkeypatch.setattr(proxy_scope, "atexit", exits)
    elif fault == "signal_error":
        original_hook = proxy._install_sigterm_cleanup
        def fail_signal():
            original_hook()
            raise Failure
        monkeypatch.setattr(proxy, "_install_sigterm_cleanup", fail_signal)
    elif fault == "publication_error":
        original_setattr = pytest.MonkeyPatch.setattr
        def fail_publish(patcher, obj, name, value, *args, **kwargs):
            original_setattr(patcher, obj, name, value, *args, **kwargs)
            if obj is proxy and name == "EgressProxy":
                raise Failure
        monkeypatch.setattr(pytest.MonkeyPatch, "setattr", fail_publish)
    with pytest.raises(error):
        with proxy_scope.isolated_proxy_scope():
            owner = proxy.get_proxy(set())
            if fault.startswith(("stop", "parser_stop")):
                def fail_stop(*args, **kwargs):
                    raise error
                monkeypatch.setattr(owner._parser_jail if fault.startswith("parser_stop") else owner, "stop", fail_stop)
    after = (proxy._instance, parser_jail._jail, proxy.EgressProxy,
             proxy._sigterm_hook_installed, signal.getsignal(signal.SIGTERM),
             proxy.atexit, parser_jail.atexit)
    assert all(a is b for a, b in zip(after, before))
    for owner in owners:
        thread = getattr(owner, "_thread", None)
        assert thread is None or not thread.is_alive()
    for jail in lifecycle_workers:
        assert jail._proc is None
