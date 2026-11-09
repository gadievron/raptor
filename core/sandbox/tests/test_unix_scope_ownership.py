"""Unix-scope handoff and close ownership with real, exclusively owned IPC."""
import array
import ast
from contextlib import contextmanager
import errno
import os
from pathlib import Path
import socket
import sys
import threading
from types import ModuleType

import pytest

from core.sandbox import _spawn as spawn, _unix_scope as scope
from core.testing.module_bindings import patch_module_attribute
from core.testing.threads import retiring_threads

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux Unix-scope backend')


@pytest.fixture
def owned_fds():
    identities = {}

    def record(*fds):
        # Register the whole installed batch before any fstat can fail.
        for fd in fds:
            identities.setdefault(fd, set())
        for fd in fds:
            info = os.fstat(fd)
            identities[fd].add((info.st_dev, info.st_ino))
        return fds[0] if len(fds) == 1 else fds

    def pipe():
        reader, writer = os.pipe()
        identities[reader] = set()
        identities[writer] = set()
        return record(reader), record(writer)

    try:
        yield pipe, record, identities
    finally:
        for fd, allowed in identities.items():
            try:
                info = os.fstat(fd)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
                continue
            if not allowed or (info.st_dev, info.st_ino) in allowed:
                os.close(fd)


@contextmanager
def _socket_pair():
    left, right = socket.socketpair()
    try:
        yield left, right
    finally:
        left.close()
        right.close()


class _RecordingSocket:
    def __init__(self, sock, record, limit=None):
        self.socket = sock
        self.record = record
        self.limit = limit
        self.received = []
        self.inheritable_at_receipt = []
        self.closed = 0

    def settimeout(self, value):
        self.socket.settimeout(value)

    def recvmsg(self, size, ancillary, flags=0):
        result = self.socket.recvmsg(min(size, self.limit or size), ancillary, flags)
        for level, kind, data in result[1]:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                values = array.array('i')
                values.frombytes(data[:len(data) - len(data) % values.itemsize])
                self.received.extend(values)
                self.record(*values)
                for fd in values:
                    self.inheritable_at_receipt.append(os.get_inheritable(fd))
        return result

    def recv(self, size):
        return self.socket.recv(size)

    def close(self):
        self.closed += 1
        self.socket.close()


def _receiver(sock, factory, registry, *, os_module=os, block_network=True,
              inherit_netns=False, ports=(443,)):
    # Exercise the exact nested implementation and its close helper. Retain
    # real module dependencies rather than manually recreating their globals.
    tree = ast.parse(Path(spawn.__file__).read_text())
    nodes = []
    for name in ('_close_scope_socket', '_unix_scope_receiver'):
        found = [node for node in ast.walk(tree)
                 if isinstance(node, ast.FunctionDef) and node.name == name]
        assert len(found) == 1, name
        nodes.append(found[0])
    bindings = dict(vars(spawn))
    bindings.update(_socket_mod=socket, _unix_scope_parent_sock=sock,
                    _UnixScopeSupervisor=factory, _unix_scope_supervisor=registry,
                    proxy_unix_socket='/owned/proxy.socket',
                    extra_unix_bridges=[(9000, '/owned/bridge.socket')],
                    allowed_tcp_ports=ports, block_network=block_network,
                    inherit_netns=inherit_netns, child_pid=123, os=os_module)
    module = ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[]))
    exec(compile(module, spawn.__file__, 'exec'), bindings)
    return bindings['_unix_scope_receiver']


def _assert_closed(fds):
    for fd in fds:
        with pytest.raises(OSError) as caught:
            os.fstat(fd)
        assert caught.value.errno == errno.EBADF


@pytest.mark.parametrize('stage', ['cloexec', 'constructor', 'registration', 'service'])
@pytest.mark.parametrize('failure_type', [OSError, KeyboardInterrupt])
def test_receiver_failure_retires_received_descriptor(
    owned_fds, monkeypatch, stage, failure_type,
):
    pipe, record, _ = owned_fds
    reader, _ = pipe()
    failure = failure_type('owned receiver handoff failure')
    consumer = ModuleType('owned_receiver_consumer')
    consumer.os = os
    constructed = []

    def set_inheritable(fd, value):
        if stage == 'cloexec':
            raise failure
        os.set_inheritable(fd, value)
    patch_module_attribute(monkeypatch, consumer, 'os', 'set_inheritable', set_inheritable)

    class Registry(list):
        def append(self, supervisor):
            if stage == 'registration':
                raise failure
            super().append(supervisor)

    def factory(fd, **policy):
        if stage == 'constructor':
            raise failure
        supervisor = scope.UnixScopeSupervisor(fd, **policy)
        constructed.append(supervisor)

        def serve():
            if stage == 'service':
                raise failure
        supervisor.serve_forever = serve
        return supervisor

    with _socket_pair() as (sender, raw_receiver):
        receiver = _RecordingSocket(raw_receiver, record)
        sender.sendmsg([b'F2\x00'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                    array.array('i', [reader]))])
        run = _receiver(receiver, factory, Registry(), os_module=consumer.os)
        if failure_type is KeyboardInterrupt:
            with pytest.raises(KeyboardInterrupt) as caught:
                run()
            assert caught.value is failure
        else:
            run()
        assert len(receiver.received) == 1
        _assert_closed(receiver.received)
        assert receiver.closed == 1
        for supervisor in constructed:
            assert supervisor._closed.is_set()


@pytest.mark.parametrize('rights', [0, 2, 4], ids=['missing', 'extra', 'truncated'])
def test_receiver_rejects_invalid_rights_and_closes_every_installed_fd(owned_fds, rights):
    pipe, record, _ = owned_fds
    readers = [pipe()[0] for _ in range(rights)]
    factories = []

    def factory(*args, **kwargs):
        factories.append(True)
        raise AssertionError('invalid rights reached supervisor construction')

    with _socket_pair() as (sender, raw_receiver):
        receiver = _RecordingSocket(raw_receiver, record)
        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', readers))] if readers else []
        sender.sendmsg([b'F2\x00'], ancillary)
        _receiver(receiver, factory, [])()
        assert not factories
        itemsize = array.array('i').itemsize
        capacity = (socket.CMSG_SPACE(itemsize) - socket.CMSG_LEN(0)) // itemsize
        assert len(receiver.received) == min(rights, capacity)
        _assert_closed(receiver.received)
        assert receiver.closed == 1


@pytest.mark.parametrize('payload,limit,expected', [
    (b'F2\x02' + (11).to_bytes(8, 'little') + (22).to_bytes(8, 'little'), None, frozenset({11, 22})),
    (b'F2\x02' + (11).to_bytes(8, 'little') + (22).to_bytes(8, 'little'), 3, frozenset({11, 22})),
    (b'F2\x02' + (11).to_bytes(8, 'little'), 3, frozenset()),
], ids=['complete', 'fragmented', 'incomplete-pins'])
@pytest.mark.parametrize('block,inherit,isolated', [(True, False, True), (True, True, False), (False, False, False)])
@pytest.mark.parametrize('ports', [None, (443,), ()], ids=['unrestricted', 'restricted', 'empty'])
def test_receiver_preserves_policy_and_retires_successful_handoff(
    owned_fds, payload, limit, expected, block, inherit, isolated, ports,
):
    pipe, record, _ = owned_fds
    reader, _ = pipe()
    policies, supervisors, registry = [], [], []

    def factory(fd, **policy):
        policies.append(policy)
        supervisor = scope.UnixScopeSupervisor(fd, **policy)
        supervisor.serve_forever = lambda: None
        supervisors.append(supervisor)
        return supervisor

    with _socket_pair() as (sender, raw_receiver):
        receiver = _RecordingSocket(raw_receiver, record, limit)
        sender.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                   array.array('i', [reader]))])
        sender.shutdown(socket.SHUT_WR)
        _receiver(receiver, factory, registry, block_network=block,
                  inherit_netns=inherit, ports=ports)()
        assert len(policies) == 1 and registry == supervisors
        assert policies[0] == {
            'allowed_socket_paths': ['/owned/proxy.socket', '/owned/bridge.socket'],
            'label': 'spawn-123', 'allowed_tcp_ports': list(ports) if ports else None,
            'netns_isolated': isolated, 'private_tmpfs_devs': expected,
        }
        assert receiver.inheritable_at_receipt == [False]
        _assert_closed(receiver.received)
        assert receiver.closed == 1


def test_concurrent_close_cannot_close_a_recycled_descriptor(owned_fds, monkeypatch):
    pipe, _, identities = owned_fds
    notify, _ = pipe()
    replacement, _ = pipe()
    identities[notify].update(identities[replacement])
    supervisor = scope.UnixScopeSupervisor(notify, allowed_socket_paths=[], label='owned')
    closed = supervisor._closed
    barrier, start = threading.Barrier(2), threading.Event()
    lock = threading.Lock()
    workers, calls, errors = [], [], []

    class InterleavedEvent:
        def is_set(self):
            value = closed.is_set()
            if not value:
                barrier.wait(timeout=3)
            return value
        def set(self):
            closed.set()
    supervisor._closed = InterleavedEvent()

    def close(fd):
        assert fd == notify
        with lock:
            calls.append(fd)
            if len(calls) == 1:
                os.dup2(replacement, fd, inheritable=False)
            else:
                os.close(fd)
    patch_module_attribute(monkeypatch, scope, 'os', 'close', close)

    def run():
        try:
            assert start.wait(3)
            supervisor.close()
        except BaseException as error:
            errors.append(error)

    def release():
        start.set()
        barrier.abort()

    with retiring_threads(workers, release=release, timeout=5):
        for _ in range(2):
            worker = threading.Thread(target=run)
            workers.append(worker)
            worker.start()
        start.set()
        for worker in workers:
            worker.join(timeout=5)
            assert not worker.is_alive()
        assert not errors
        assert calls == [notify]
        info = os.fstat(notify)
        assert (info.st_dev, info.st_ino) in identities[replacement]
        assert closed.is_set()


@pytest.mark.parametrize('primary_type', [RuntimeError, KeyboardInterrupt])
@pytest.mark.parametrize('secondary_type', [None, OSError, KeyboardInterrupt])
def test_event_failure_still_closes_once_and_preserves_primary(
    owned_fds, monkeypatch, primary_type, secondary_type,
):
    pipe, _, identities = owned_fds
    notify, _ = pipe()
    replacement, _ = pipe()
    identities[notify].update(identities[replacement])
    supervisor = scope.UnixScopeSupervisor(notify, allowed_socket_paths=[], label='owned')
    primary = primary_type('owned stop-event failure')
    secondary = secondary_type('owned close acknowledgement failure') if secondary_type else None
    calls = []

    class BrokenEvent:
        def is_set(self):
            return False
        def set(self):
            raise primary
    supervisor._closed = BrokenEvent()

    def close(fd):
        calls.append(fd)
        os.dup2(replacement, fd, inheritable=False)
        if secondary is not None:
            raise secondary
    patch_module_attribute(monkeypatch, scope, 'os', 'close', close)
    with pytest.raises(primary_type) as caught:
        supervisor.close()
    assert caught.value is primary
    supervisor.close()
    assert calls == [notify]
    info = os.fstat(notify)
    assert (info.st_dev, info.st_ino) in identities[replacement]


def test_receiver_eof_closes_transport_without_constructing_supervisor(owned_fds):
    _, record, _ = owned_fds
    calls = []

    def factory(*args, **kwargs):
        calls.append(True)
        raise AssertionError('EOF reached supervisor construction')

    with _socket_pair() as (sender, raw_receiver):
        receiver = _RecordingSocket(raw_receiver, record)
        sender.close()
        _receiver(receiver, factory, [])()
        assert not calls
        assert receiver.received == []
        assert receiver.closed == 1
