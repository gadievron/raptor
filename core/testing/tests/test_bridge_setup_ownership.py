"""Native bridge and proxy setup failures retire their owned resources."""

import importlib
import inspect
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
from types import ModuleType

import pytest

BRIDGES = (
    ('halfclose', None),
    ('read_cap', 'test_small_buffer_cap_preserves_large_roundtrip'),
    ('setup_failure', 'test_upstream_socket_exhaustion_allows_later_connection'),
    ('connect_backlog', 'test_full_upstream_queue_does_not_block_other_bridge'),
)


@pytest.mark.parametrize('suffix,method', BRIDGES)
@pytest.mark.parametrize('stage', ['pipe', 'construct', 'before-start', 'after-start'])
@pytest.mark.parametrize('failure_type', [RuntimeError, KeyboardInterrupt])
def test_native_bridge_setup_failure_retires_resources(suffix, method, stage, failure_type, monkeypatch):
    native = importlib.import_module('core.sandbox.tests.test_proxy_bridge_' + suffix)
    servers, workers, descriptors = [], [], []
    failure = failure_type('injected bridge setup failure')
    original_server = native.SocketServer
    original_thread = native.threading.Thread
    original_pipe = native.os.pipe

    class TrackedServer(original_server):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            servers.append(self)

    class Worker(original_thread):
        def __init__(self, *args, **kwargs):
            if stage == 'construct':
                raise failure
            super().__init__(*args, **kwargs)
            workers.append(self)

        def start(self):
            if stage == 'before-start':
                raise failure
            super().start()
            raise failure

    def pipe():
        if stage == 'pipe':
            raise failure
        pair = original_pipe()
        descriptors.extend(pair)
        return pair

    def private(module, **overrides):
        copy = ModuleType(module.__name__)
        vars(copy).update(vars(module))
        vars(copy).update(overrides)
        return copy

    monkeypatch.setattr(native, 'SocketServer', TrackedServer)
    monkeypatch.setattr(native, 'threading', private(native.threading, Thread=Worker))
    monkeypatch.setattr(native, 'os', private(native.os, pipe=pipe))
    body = pytest.MonkeyPatch()
    owner = native._owned_backends.__wrapped__(body)
    next(owner)
    try:
        with TemporaryDirectory(prefix='rp-setup-', dir='/tmp') as directory:
            with pytest.raises(failure_type) as caught:
                if method is None:
                    with native.running_bridge(Path(directory), lambda conn: None):
                        pytest.fail('injected setup failure was not reached')
                else:
                    function = getattr(native, method)
                    kwargs = {'short_sock_dir': Path(directory), 'monkeypatch': body}
                    function(**{key: value for key, value in kwargs.items()
                                if key in inspect.signature(function).parameters})
            assert caught.value is failure
    finally:
        owner.close()
        stopped = [not worker.is_alive() for worker in workers]
        closed = []
        for fd in descriptors:
            try:
                os.fstat(fd)
            except OSError:
                closed.append(True)
            else:
                closed.append(False)
                # Safety net also contains the unchanged native negative control.
                os.close(fd)
        backends = [(server._listener.fileno(), server._accept_thread.is_alive())
                    for server in servers]
        for server in servers:
            server.close()
        for worker in workers:
            if worker.ident is not None:
                threading.Thread.join(worker, 5)
                assert not worker.is_alive(), 'bridge survived safety cleanup'
        body.undo()
    assert stopped == [True] * len(workers)
    assert closed == [True] * len(descriptors)
    assert backends == [(-1, False)]


@pytest.mark.parametrize('method', [
    'test_cap_recovers_immediately_after_close',
    'test_slot_released_exactly_once_under_mixed_churn',
    'test_stop_during_active_tunnel_releases_slot',
])
@pytest.mark.parametrize('failure_type', [OSError, RuntimeError, KeyboardInterrupt])
def test_native_proxy_startup_failure_closes_backend(method, failure_type, monkeypatch):
    from core.sandbox import proxy
    from core.sandbox.tests import test_proxy_teardown as native
    from core.testing.module_bindings import patch_module_attribute
    from core.testing.proxy_scope import isolated_proxy_scope

    servers = []
    original = native.SocketServer

    class TrackedServer(original):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            servers.append(self)

    monkeypatch.setattr(native, 'SocketServer', TrackedServer)
    failure = failure_type('injected parser startup failure')

    def unavailable():
        raise failure

    patch_module_attribute(monkeypatch, proxy, 'parser_jail', 'get_parser_jail', unavailable)
    body = pytest.MonkeyPatch()
    owner = native._owned_backends.__wrapped__(body)
    next(owner)
    try:
        with isolated_proxy_scope():
            with pytest.raises(failure_type) as caught:
                getattr(native.TestCapAccounting(), method)(reset_proxy=None, loopback_permitted=True)
            assert caught.value is failure
    finally:
        owner.close()
        observed = [(server._listener.fileno(), server._accept_thread.is_alive()) for server in servers]
        for server in servers:
            server.close()
        body.undo()
    assert observed == [(-1, False)]
