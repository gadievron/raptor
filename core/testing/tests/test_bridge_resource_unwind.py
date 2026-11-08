"""Native bridge resources survive setup faults and cleanup interruptions."""

from contextlib import contextmanager
import importlib
import inspect
import os
from pathlib import Path
import socket
import subprocess
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
FORWARDERS = (
    'test_forwarder_relays_data',
    'test_forwarder_concurrent_connections_with_churn',
    'test_forwarder_exits_on_death_pipe',
)
SPECS = BRIDGES + tuple(('forwarder', method) for method in FORWARDERS)
SOCKET_CASES = tuple((spec, position, operation)
                     for spec in SPECS for position, operation in [(1, 'bind'), (1, 'listen')]) + tuple(
    (BRIDGES[-1], position, operation)
    for position, operation in [(2, 'settimeout'), (2, 'connect'), (3, 'bind'), (3, 'listen')]
)
FORWARDER_CASES = tuple((method, stage) for method in FORWARDERS
                       for stage in ['pipe', 'spawn', 'wait']) + tuple(
    (method, 'connect') for method in FORWARDERS[:2]
)


def _private(module, **overrides):
    owned = ModuleType(module.__name__)
    vars(owned).update(vars(module))
    vars(owned).update(overrides)
    return owned


class _Resources:
    def __init__(self, native, patch, stage, failure_type, position=1):
        self.native = native
        self.failure = failure_type('injected native resource fault')
        self.sockets, self.servers, self.workers = [], [], []
        self.joined, self.events, self.descriptors, self.processes = [], [], [], []
        self.safety = False
        self.faulted = False
        owner = self
        original_server = native.SocketServer

        def fault():
            owner.faulted = True
            raise owner.failure

        class Socket(socket.socket):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                if self.family == socket.AF_UNIX:
                    owner.sockets.append(self)

            def operation(self, name, action, *args):
                if (stage == name and self.family == socket.AF_UNIX
                        and owner.sockets.index(self) + 1 == position):
                    fault()
                return action(*args)

            def bind(self, address):
                return self.operation('bind', super().bind, address)

            def listen(self, *args):
                return self.operation('listen', super().listen, *args)

            def settimeout(self, timeout):
                return self.operation('settimeout', super().settimeout, timeout)

            def connect(self, address):
                return self.operation('connect', super().connect, address)

        class Server(original_server):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                owner.servers.append(self)

        class Worker(threading.Thread):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                owner.workers.append(self)

            def start(self):
                super().start()
                if stage in ('close-writer', 'join'):
                    raise ValueError('exit the native body after starting the relay')

            def join(self, *args, **kwargs):
                super().join(*args, **kwargs)
                owner.joined.append(self)
                if stage == 'join' and not owner.faulted:
                    fault()

            def run(self):
                try:
                    super().run()
                except OSError:
                    if not owner.safety:
                        raise

        def event():
            value = threading.Event()
            owner.events.append(value)
            return value

        def pipe():
            if stage == 'pipe':
                fault()
            pair = os.pipe()
            owner.descriptors.extend(pair)
            return pair

        def close(fd):
            os.close(fd)
            if stage == 'close-writer' and fd == owner.descriptors[-1] and not owner.faulted:
                fault()

        patch.setattr(native, 'socket', _private(socket, socket=Socket))
        patch.setattr(native, 'os', _private(os, pipe=pipe, close=close))
        patch.setattr(native, 'threading', _private(threading, Thread=Worker, Event=event), raising=False)
        patch.setattr(native, 'SocketServer', Server)
        if stage == 'patch':
            patch.setattr(native, 'patch_module_attribute', lambda *args, **kwargs: fault())
        if hasattr(native, '_spawn_forwarder'):
            original_spawn = native._spawn_forwarder

            def spawn(*args):
                if stage == 'spawn':
                    fault()
                process = original_spawn(*args)
                owner.processes.append(process)
                if stage == 'wait':
                    wait = process.wait

                    def fail_first_wait(*args, **kwargs):
                        if not owner.faulted:
                            fault()
                        return wait(*args, **kwargs)

                    patch.setattr(process, 'wait', fail_first_wait)
                return process

            patch.setattr(native, '_spawn_forwarder', spawn)
            if stage == 'connect':
                patch.setattr(native, '_connect_with_retry', lambda *args: fault())

    def finish(self):
        # Observe before safety cleanup, so unchanged native negative controls
        # fail on their own leaks rather than being rescued by this harness.
        sockets_closed = all(sock.fileno() == -1 for sock in self.sockets)
        workers_retired = all(not worker.is_alive() and (worker.ident is None or worker in self.joined)
                              for worker in self.workers)
        backends_retired = all(server._listener.fileno() == -1 and not server._accept_thread.is_alive()
                               for server in self.servers)
        children_reaped = all(process.returncode is not None for process in self.processes)
        descriptors_closed = True
        self.safety = True
        for event in self.events:
            event.set()
        for fd in self.descriptors:
            try:
                os.fstat(fd)
            except OSError:
                continue
            descriptors_closed = False
            os.close(fd)
        for process in self.processes:
            if process.poll() is None:
                process.kill()
            subprocess.Popen.wait(process, timeout=5)
        for server in self.servers:
            server.close()
        for sock in self.sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        for worker in self.workers:
            if worker.ident is not None:
                threading.Thread.join(worker, 5)
                assert not worker.is_alive(), 'native worker survived safety cleanup'
        return sockets_closed, workers_retired, backends_retired, children_reaped, descriptors_closed


@contextmanager
def _native_resources(spec, stage, failure_type, monkeypatch, position=1):
    suffix, method = spec
    module = ('test_proxy_netns_enforcement' if suffix == 'forwarder'
              else 'test_proxy_bridge_' + suffix)
    native = importlib.import_module('core.sandbox.tests.' + module)
    resources = _Resources(native, monkeypatch, stage, failure_type, position)
    body = pytest.MonkeyPatch()
    backend_owner = None
    if hasattr(native, '_owned_backends'):
        backend_owner = native._owned_backends.__wrapped__(body)
        next(backend_owner)
    left, right = socket.socketpair()
    try:
        with left, right, TemporaryDirectory(prefix='rp-unwind-', dir='/tmp') as directory:
            def invoke():
                if suffix == 'forwarder':
                    instance = native.TestProxyBridge()
                    instance.tmp = Path(directory)
                    getattr(instance, method)()
                elif method is None:
                    with native.running_bridge(Path(directory), lambda conn: None):
                        pytest.fail('the injected failure was not reached')
                else:
                    function = getattr(native, method)
                    kwargs = {'short_sock_dir': Path(directory), 'monkeypatch': body}
                    function(**{key: value for key, value in kwargs.items()
                                if key in inspect.signature(function).parameters})
            try:
                yield resources, invoke
            finally:
                if backend_owner is not None:
                    backend_owner.close()
                observed = resources.finish()
                left.sendall(b'borrowed')
                assert right.recv(8) == b'borrowed'
                body.undo()
            assert resources.faulted
            assert all(observed), ('sockets, workers, backends, children, descriptors', observed)
    finally:
        if backend_owner is not None:
            backend_owner.close()
        body.undo()
        left.close()
        right.close()


@pytest.mark.parametrize('spec,position,operation', SOCKET_CASES)
@pytest.mark.parametrize('failure_type', [OSError, RuntimeError, KeyboardInterrupt])
def test_native_socket_setup_unwinds(spec, position, operation, failure_type, monkeypatch):
    with _native_resources(spec, operation, failure_type, monkeypatch, position) as (resources, invoke):
        with pytest.raises(failure_type) as caught:
            invoke()
        assert caught.value is resources.failure


@pytest.mark.parametrize('spec', BRIDGES)
@pytest.mark.parametrize('stage', ['close-writer', 'join'])
@pytest.mark.parametrize('failure_type', [OSError, RuntimeError, KeyboardInterrupt])
def test_native_relay_cleanup_attempts_every_resource(spec, stage, failure_type, monkeypatch):
    with _native_resources(spec, stage, failure_type, monkeypatch) as (resources, invoke):
        with pytest.raises(failure_type) as caught:
            invoke()
        assert caught.value is resources.failure


@pytest.mark.parametrize('spec', BRIDGES[1:3])
@pytest.mark.parametrize('failure_type', [OSError, RuntimeError, KeyboardInterrupt])
def test_native_patch_setup_closes_both_pipe_ends(spec, failure_type, monkeypatch):
    with _native_resources(spec, 'patch', failure_type, monkeypatch) as (resources, invoke):
        with pytest.raises(failure_type) as caught:
            invoke()
        assert caught.value is resources.failure


@pytest.mark.parametrize('method,stage', FORWARDER_CASES)
@pytest.mark.parametrize('failure_type', [OSError, RuntimeError, KeyboardInterrupt])
def test_native_forwarder_failure_reaps_child_and_backend(method, stage, failure_type, monkeypatch):
    with _native_resources(('forwarder', method), stage, failure_type, monkeypatch) as (resources, invoke):
        with pytest.raises(failure_type) as caught:
            invoke()
        assert caught.value is resources.failure
