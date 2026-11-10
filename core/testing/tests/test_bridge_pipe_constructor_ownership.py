"""Bridge fixture setup retains untransferred native death pipes."""

import builtins
from contextlib import contextmanager
import errno
import os
from types import FunctionType, ModuleType, SimpleNamespace
import threading

import pytest
from core.sandbox.tests import test_proxy_bridge_multi as native
from core.sandbox import _proxy_bridge
from core.testing import pipes

CASES = [
    ("TestRunBridges", "test_two_bridges_relay_to_their_own_upstreams"),
    ("TestRunBridges", "test_single_bridge_wrapper_compatible"),
    ("TestRunBridges", "test_dead_upstream_closes_client_not_relay"),
    ("TestForwarderBounds", "test_pair_cap_refuses_excess_connections"),
    ("TestForwarderBounds", "test_idle_pairs_are_swept"),
    ("TestForwarderBounds", "test_stalled_peer_does_not_block_other_pairs"),
    ("TestForwarderBounds", "test_eof_with_pending_bytes_still_delivers_the_tail"),
]


def _view(module):
    private = ModuleType(module.__name__)
    vars(private).update(vars(module))
    return private


@pytest.mark.parametrize("case", CASES, ids=[item[1] for item in CASES])
@pytest.mark.parametrize("stage", ["constructor", "start"])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_refused_worker_retires_death_pipe(case, stage, error, tmp_path):
    allocations, closes = [], []
    failure = error("owned bridge worker refusal")
    local_os, local_threads = _view(os), _view(threading)
    bridge = _view(_proxy_bridge)
    sandbox = ModuleType("core.sandbox")
    sandbox._proxy_bridge = bridge

    def allocate():
        pair = os.pipe()
        allocations.append((pair, [os.fstat(fd) for fd in pair]))
        return pair

    def close(fd):
        closes.append(fd)
        return os.close(fd)

    class Worker:
        ident = None

        def start(self):
            raise failure

    def construct(*args, **kwargs):
        if stage == "constructor":
            raise failure
        return Worker()

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name == "core.sandbox" and fromlist:
            return sandbox
        return builtins.__import__(name, globals, locals, fromlist, level)

    local_os.pipe, local_os.close = allocate, close
    local_threads.Thread = construct
    generator = pipes.pipes_for_setup.__wrapped__
    setup = contextmanager(
        FunctionType(
            generator.__code__,
            dict(generator.__globals__, os=local_os),
            generator.__name__,
            generator.__defaults__,
            generator.__closure__,
        )
    )
    original = getattr(getattr(native, case[0]), case[1])
    backend = lambda *args, **kwargs: SimpleNamespace(close=lambda: None)
    namespace = dict(
        original.__globals__,
        os=local_os,
        threading=local_threads,
        pipes_for_setup=setup,
        _free_port=lambda: 0,
        _unix_echo_server=backend,
        _unix_hold_echo_server=backend,
        _unix_flood_server=backend,
        _unix_listener=backend,
        SocketServer=backend,
        __builtins__=dict(vars(builtins), __import__=import_local),
    )
    invoke = FunctionType(
        original.__code__,
        namespace,
        original.__name__,
        original.__defaults__,
        original.__closure__,
    )
    try:
        with pytest.MonkeyPatch.context() as scope:

            class LocalPatch:
                def setattr(self, target, *args):
                    if isinstance(target, str):
                        prefix, name = target.rsplit(".", 1)
                        assert prefix == "core.sandbox._proxy_bridge"
                        scope.setattr(bridge, name, args[0])
                    else:
                        assert target is bridge
                        scope.setattr(target, *args)

            kwargs = (
                {"monkeypatch": LocalPatch()}
                if "monkeypatch"
                in original.__code__.co_varnames[: original.__code__.co_argcount]
                else {}
            )
            with pytest.raises(error) as caught:
                invoke(None, tmp_path, **kwargs)
            assert caught.value is failure
        assert len(allocations) == 1
        for fd, identity in zip(*allocations[0]):
            assert closes.count(fd) == 1
            try:
                actual = os.fstat(fd)
            except OSError as exc:
                assert exc.errno == errno.EBADF
            else:
                assert (actual.st_dev, actual.st_ino) != (
                    identity.st_dev,
                    identity.st_ino,
                )
    finally:
        for pair, identities in allocations:
            for fd, identity in zip(pair, identities):
                try:
                    actual = os.fstat(fd)
                except OSError as exc:
                    assert exc.errno == errno.EBADF
                    continue
                if (actual.st_dev, actual.st_ino) == (identity.st_dev, identity.st_ino):
                    os.close(fd)
