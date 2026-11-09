"""Parent RPC deadlines and retirement with real owned pipes and threads."""

from contextlib import ExitStack
import errno
import json
import math
import os
import struct
import threading
from types import SimpleNamespace

import pytest

from core.sandbox import host as mod
from core.testing.module_bindings import patch_module_attribute
from core.testing.pipes import pipes_for_setup
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture
def peers(tmp_path):
    owned, workers, handles, releases = {}, [], [], []
    real_close, real_fstat = os.close, os.fstat
    def close_owned(fd):
        try:
            info = real_fstat(fd)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                return
            raise
        if (info.st_dev, info.st_ino) == owned[fd]:
            real_close(fd)
    def join(worker):
        if worker.ident is not None:
            worker.join(5)
            assert not worker.is_alive(), f"owned RPC thread survived: {worker.name}"
    def cleanup():
        for release in releases:
            release.set()
        with ExitStack() as finish:
            for fd in owned:
                finish.callback(close_owned, fd)
            for worker in workers:
                finish.callback(join, worker)
            for host in handles:
                if host._thread.ident is not None:
                    finish.callback(host.close)
    with ExitStack() as owner, pytest.MonkeyPatch.context() as patch:
        owner.callback(cleanup)
        pin_user_state_dirs(patch, tmp_path / 'state')
        def create(serve=None):
            release = threading.Event()
            releases.append(release)
            requests, errors = [], []
            with pipes_for_setup(2) as ((in_r, in_w), (out_r, out_w)):
                for fd in (in_r, in_w, out_r, out_w):
                    info = real_fstat(fd)
                    owned[fd] = (info.st_dev, info.st_ino)
                def exact(count):
                    data = bytearray()
                    while len(data) < count:
                        chunk = os.read(in_r, count - len(data))
                        if not chunk:
                            raise EOFError('owned request channel closed')
                        data.extend(chunk)
                    return bytes(data)
                def request():
                    size, = struct.unpack('!I', exact(4))
                    value = json.loads(exact(size))
                    requests.append(value)
                    return value
                def raw(data):
                    view = memoryview(data)
                    while view:
                        view = view[os.write(out_w, view):]
                def reply(value):
                    body = json.dumps(value).encode()
                    raw(struct.pack('!I', len(body)) + body)
                connection = SimpleNamespace(release=release, request=request, reply=reply,
                                             raw=raw, requests=requests, errors=errors,
                                             read_fd=in_r, write_fd=out_w)
                def echo():
                    while True:
                        value = request()
                        reply({'ok': True, 'rid': value['rid']})
                        if value['cmd'] == 'close':
                            return
                def worker():
                    try:
                        (serve(connection) if serve is not None else echo())
                    except (EOFError, BrokenPipeError):
                        pass
                    except BaseException as exc:
                        errors.append(exc)
                    finally:
                        close_owned(in_r)
                        close_owned(out_w)
                thread = threading.Thread(target=worker, name='owned-rpc-peer')
                workers.append(thread)
                host = mod.SandboxHost(_thread=thread, _write_fd=in_w, _read_fd=out_r,
                                       _daemon_fds=None, _lock=threading.Lock())
                handles.append(host)
            connection.host, connection.thread = host, thread
            thread.start()
            return connection
        def call(host, payload=None, timeout=5):
            done, values = threading.Event(), []
            def invoke():
                try:
                    values.append(host._rpc(payload or {'cmd': 'ping'}, timeout=timeout))
                except BaseException as exc:
                    values.append(exc)
                finally:
                    done.set()
            worker = threading.Thread(target=invoke, name='owned-rpc-caller')
            workers.append(worker)
            worker.start()
            return SimpleNamespace(done=done, values=values, thread=worker)
        yield SimpleNamespace(create=create, call=call, workers=workers)


def test_request_queue_has_a_deadline_and_does_not_retire_another_owner(peers):
    peer = peers.create()
    peer.host._lock.acquire()
    try:
        queued = peers.call(peer.host, timeout=0.02)
        assert queued.done.wait(2), 'queue wait ignored the caller deadline'
        assert isinstance(queued.values[0], mod.HostRPCError)
        assert not peer.requests
    finally:
        peer.host._lock.release()
    assert peer.host._rpc({'cmd': 'ping'}, timeout=5) == {'ok': True}
    assert not peer.errors


def test_full_request_pipe_obeys_deadline(peers):
    def silent(peer):
        assert peer.release.wait(10), 'owned silent peer not released'
    peer = peers.create(silent)
    caller = peers.call(peer.host, {'cmd': 'ping', 'padding': 'x' * 1048576}, timeout=0.02)
    assert caller.done.wait(2), 'blocked request write ignored the caller deadline'
    assert isinstance(caller.values[0], mod.HostRPCError)
    assert not peer.requests


@pytest.mark.parametrize('reply', [b'[]', b'bad JSON', b'{"ok":true}', b'{"ok":true,"rid":"wrong"}'],
                         ids=['nonobject', 'invalid-json', 'missing-id', 'wrong-id'])
def test_failed_transaction_cannot_reuse_the_channel(peers, reply):
    def malformed(peer):
        peer.request()
        peer.raw(struct.pack('!I', len(reply)) + reply)
        assert peer.release.wait(10)
    peer = peers.create(malformed)
    with pytest.raises(mod.HostRPCError):
        peer.host._rpc({'cmd': 'ping'}, timeout=5)
    result = peers.call(peer.host, timeout=0.02)
    assert result.done.wait(2)
    assert isinstance(result.values[0], mod.HostRPCError)
    assert 'retired' in str(result.values[0])
    assert len(peer.requests) == 1


@pytest.mark.parametrize('timeout', [0, -1, math.inf, -math.inf, math.nan, None, 'invalid'])
def test_invalid_deadlines_fail_before_touching_the_channel(peers, timeout):
    peer = peers.create()
    result = peers.call(peer.host, timeout=timeout)
    assert result.done.wait(2)
    assert isinstance(result.values[0], mod.HostRPCError)
    assert not peer.requests
    assert peer.host._rpc({'cmd': 'ping'}, timeout=5) == {'ok': True}


def test_serialization_and_transfer_do_not_reset_reply_deadline(peers, monkeypatch):
    peer = peers.create()
    clock = [100.0]
    real_write = os.write
    def write(fd, data):
        count = real_write(fd, data)
        if fd == peer.host._write_fd:
            clock[0] = 103.0
        return count
    patch_module_attribute(monkeypatch, mod, 'time', 'monotonic', lambda: clock[0])
    patch_module_attribute(monkeypatch, mod, 'os', 'write', write)
    deadlines = []
    read = peer.host._read_exact
    def exact(count, deadline):
        deadlines.append(deadline)
        return read(count, deadline)
    monkeypatch.setattr(peer.host, '_read_exact', exact)
    assert peer.host._rpc({'cmd': 'ping'}, timeout=5) == {'ok': True}
    assert deadlines == [105.0, 105.0]


def test_expiry_during_serialization_sends_nothing_and_keeps_channel(peers, monkeypatch):
    peer = peers.create()
    clock = [100.0]
    dumps = json.dumps
    def serialize(value):
        body = dumps(value)
        clock[0] += 6
        return body
    with monkeypatch.context() as patch:
        patch_module_attribute(patch, mod, 'time', 'monotonic', lambda: clock[0])
        patch_module_attribute(patch, mod, 'json', 'dumps', serialize)
        with pytest.raises(mod.HostRPCError):
            peer.host._rpc({'cmd': 'ping'}, timeout=5)
    assert not peer.requests
    assert peer.host._rpc({'cmd': 'ping'}, timeout=5) == {'ok': True}


@pytest.mark.parametrize('error', [RuntimeError, KeyboardInterrupt, OSError])
@pytest.mark.parametrize('phase', ['write', 'read'])
def test_interrupted_transaction_retires_channel_without_replacing_error(peers, monkeypatch, error, phase):
    peer = peers.create()
    failure = error('owned partial frame failure')
    original = os.write if phase == 'write' else os.read
    fd = peer.host._write_fd if phase == 'write' else peer.host._read_fd
    calls = []
    def fail(selected, data):
        if selected == fd and not calls:
            calls.append(selected)
            raise failure
        return original(selected, data)
    patch_module_attribute(monkeypatch, mod, 'os', phase, fail)
    with pytest.raises(mod.HostRPCError if error is OSError else error) as caught:
        peer.host._rpc({'cmd': 'ping'}, timeout=5)
    if error is not OSError:
        assert caught.value is failure
    subsequent = peers.call(peer.host, timeout=0.02)
    assert subsequent.done.wait(2)
    assert isinstance(subsequent.values[0], mod.HostRPCError)
    assert 'retired' in str(subsequent.values[0])


@pytest.mark.parametrize('phase', ['write', 'read'])
@pytest.mark.parametrize('error', [InterruptedError, BlockingIOError])
def test_transient_pipe_errors_retry_without_losing_the_frame(peers, monkeypatch, phase, error):
    peer = peers.create()
    original = os.write if phase == 'write' else os.read
    fd = peer.host._write_fd if phase == 'write' else peer.host._read_fd
    calls = []
    def transient(selected, data):
        if selected == fd and not calls:
            calls.append(selected)
            raise error(errno.EINTR if error is InterruptedError else errno.EAGAIN, 'owned transient')
        return original(selected, data)
    patch_module_attribute(monkeypatch, mod, 'os', phase, transient)
    assert peer.host._rpc({'cmd': 'ping'}, timeout=5) == {'ok': True}
    assert calls == [fd] and not peer.errors


@pytest.mark.parametrize('phase', ['write', 'read'])
def test_concurrent_close_is_observed_by_the_active_owner_and_preserves_reused_fds(peers, monkeypatch, phase):
    entered = threading.Event()
    def silent(peer):
        if phase == 'read':
            peer.request()
            entered.set()
        assert peer.release.wait(10)
    peer = peers.create(silent)
    parent = (peer.host._write_fd, peer.host._read_fd)
    real_write, real_close = os.write, os.close
    closes = []
    def write(fd, data):
        if fd == parent[0]:
            entered.set()
        return real_write(fd, data)
    def close(fd):
        if fd in parent:
            closes.append((fd, threading.get_ident()))
        real_close(fd)
        if fd in parent:
            peer.release.set()
    patch_module_attribute(monkeypatch, mod, 'os', 'write', write)
    patch_module_attribute(monkeypatch, mod, 'os', 'close', close)
    active = peers.call(peer.host, {'cmd': 'ping', 'padding': 'x' * (1048576 if phase == 'write' else 1)}, timeout=60)
    assert entered.wait(5), 'owned transaction did not reach its blocked phase'
    done, errors = threading.Event(), []
    def retire():
        try:
            peer.host.close()
        except BaseException as exc:
            errors.append(exc)
        finally:
            done.set()
    closer = threading.Thread(target=retire, name='owned-rpc-closer')
    peers.workers.append(closer)
    closer.start()
    assert done.wait(2), 'close did not interrupt the active transaction'
    assert active.done.wait(2)
    assert isinstance(active.values[0], mod.HostRPCError)
    assert not errors and not peer.thread.is_alive()
    assert sorted(closes) == sorted((fd, active.thread.ident) for fd in parent)
    with pipes_for_setup(1) as ((read_fd, write_fd),):
        identity = [(os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in (read_fd, write_fd)]
    try:
        peer.host.close()
        assert [(os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in (read_fd, write_fd)] == identity
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_oversized_request_is_rejected_before_transport_and_channel_still_works(peers, monkeypatch):
    peer = peers.create()
    with monkeypatch.context() as patch:
        patch.setattr(mod, '_DAEMON_REQUEST_CAP', 64, raising=False)
        with pytest.raises(mod.HostRPCError, match='request frame too large'):
            peer.host._rpc({'cmd': 'ping', 'padding': 'x'*128}, timeout=5)
    assert not peer.requests
    assert peer.host._rpc({'cmd': 'ping'}, timeout=5) == {'ok': True}


def test_oversized_spawn_stdin_is_rejected_before_hex_encoding(peers, monkeypatch):
    peer = peers.create()
    monkeypatch.setattr(mod, '_DAEMON_STDIN_CAP', 8, raising=False)

    class EncodingForbidden(bytes):
        def hex(self, *args, **kwargs):
            pytest.fail('oversized stdin was copied into a hexadecimal request')

    with pytest.raises(mod.HostRPCError, match='stdin_bytes=9 exceeds 8'):
        peer.host.spawn(['owned-command'], stdin_bytes=EncodingForbidden(b'x' * 9))
    assert not peer.requests
    assert peer.host._rpc({'cmd': 'ping'}, timeout=5) == {'ok': True}


def test_spawn_stdin_cap_counts_bytes_in_a_wide_memoryview(peers, monkeypatch):
    peer = peers.create()
    monkeypatch.setattr(mod, '_DAEMON_STDIN_CAP', 8)
    with memoryview(b'x' * 12).cast('I') as data:
        assert len(data) == 3 and data.nbytes == 12
        with pytest.raises(mod.HostRPCError, match='stdin_bytes=12 exceeds 8'):
            peer.host.spawn(['owned-command'], stdin_bytes=data)
    assert not peer.requests
    assert peer.host._rpc({'cmd': 'ping'}, timeout=5) == {'ok': True}


@pytest.mark.parametrize('data', [b'', b'\x00\xffowned!', bytearray(b'\x00\xffowned!'),
                                 memoryview(b'\x00\xffowned!').cast('I')],
                         ids=['empty', 'exact-cap-bytes', 'exact-cap-bytearray', 'exact-cap-view'])
def test_spawn_stdin_at_cap_retains_the_existing_wire_value(peers, monkeypatch, data):
    peer = peers.create()
    monkeypatch.setattr(mod, '_DAEMON_STDIN_CAP', 8, raising=False)
    result = peer.host.spawn(['owned-command'], stdin_bytes=data)
    assert result['stdout'] == result['stderr'] == b''
    request, = peer.requests
    assert request['cmd'] == 'spawn' and request['argv'] == ['owned-command']
    assert request['stdin_hex'] == bytes(data).hex()
    assert not peer.host._broken


def test_local_serialization_error_preserves_channel(peers):
    peer = peers.create()
    with pytest.raises(TypeError):
        peer.host._rpc({'cmd': 'ping', 'not-json': object()}, timeout=5)
    assert not peer.requests
    assert peer.host._rpc({'cmd': 'ping'}, timeout=5) == {'ok': True}


@pytest.mark.parametrize('endpoint', [0, 1], ids=['writer', 'reader'])
@pytest.mark.parametrize('cleanup_error', [OSError, KeyboardInterrupt])
@pytest.mark.parametrize('request_error', [False, True], ids=['close', 'request-failure'])
def test_cleanup_attempts_both_endpoints_and_preserves_request_error(peers, monkeypatch, endpoint, cleanup_error, request_error):
    peer = peers.create()
    parent = (peer.host._write_fd, peer.host._read_fd)
    real_close, real_write = os.close, os.write
    injected = []
    primary = RuntimeError('owned request failed')
    def close(fd):
        real_close(fd)
        if fd == parent[endpoint] and not injected:
            injected.append(fd)
            raise cleanup_error('owned close failed after consuming endpoint')
    def write(fd, data):
        if fd == parent[0]:
            raise primary
        return real_write(fd, data)
    with monkeypatch.context() as patch:
        patch_module_attribute(patch, mod, 'os', 'close', close)
        if request_error:
            patch_module_attribute(patch, mod, 'os', 'write', write)
            with pytest.raises(RuntimeError) as caught:
                peer.host._rpc({'cmd': 'ping'}, timeout=5)
            assert caught.value is primary
            if cleanup_error is KeyboardInterrupt:
                assert 'RPC endpoint cleanup: KeyboardInterrupt' in getattr(primary, '__notes__', ())
        elif cleanup_error is KeyboardInterrupt:
            with pytest.raises(KeyboardInterrupt):
                peer.host.close()
        else:
            peer.host.close()
        for fd in parent:
            with pytest.raises(OSError) as caught:
                os.fstat(fd)
            assert caught.value.errno == errno.EBADF
        assert injected == [parent[endpoint]]
    peer.host.close()
    assert not peer.thread.is_alive()


@pytest.mark.parametrize('partial', [b'', struct.pack('!I', 100), struct.pack('!I', 100) + b'{'],
                         ids=['silent', 'header-only', 'partial-body'])
def test_reply_timeout_retires_the_partial_frame(peers, partial):
    def silent(peer):
        peer.request()
        peer.raw(partial)
        assert peer.release.wait(10)
    peer = peers.create(silent)
    with pytest.raises(mod.HostRPCError):
        peer.host._rpc({'cmd': 'ping'}, timeout=0.02)
    next_call = peers.call(peer.host, timeout=0.02)
    assert next_call.done.wait(2)
    assert isinstance(next_call.values[0], mod.HostRPCError)
    assert 'retired' in str(next_call.values[0])
    assert len(peer.requests) == 1


@pytest.mark.parametrize('error', [RuntimeError, KeyboardInterrupt, OSError])
def test_request_id_failure_is_local_and_does_not_retire_channel(peers, monkeypatch, error):
    peer = peers.create()
    failure = error('owned random source failed')
    def fail(size):
        raise failure
    with monkeypatch.context() as patch:
        patch_module_attribute(patch, mod, 'os', 'urandom', fail)
        with pytest.raises(error) as caught:
            peer.host._rpc({'cmd': 'ping'}, timeout=5)
        assert caught.value is failure
    assert not peer.requests
    assert peer.host._rpc({'cmd': 'ping'}, timeout=5) == {'ok': True}


@pytest.mark.parametrize('timeout', [1e20, 1e300])
def test_large_finite_deadlines_do_not_overflow_native_waits(peers, timeout):
    peer = peers.create()
    assert peer.host._rpc({'cmd': 'ping'}, timeout=timeout) == {'ok': True}


def test_one_shot_uses_the_same_request_frame_ceiling(tmp_path, monkeypatch):
    import core.sandbox
    from core.sandbox import context
    from core.testing.state_isolation import pin_user_state_dirs
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setattr(context, '_require_userns_or_optin', lambda *a, **kw: False)
    monkeypatch.setattr(mod, '_DAEMON_REQUEST_CAP', 64, raising=False)
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(kwargs)
        raise AssertionError('oversized request reached backend')
    monkeypatch.setattr(core.sandbox, 'run', forbidden)
    target = tmp_path / 'target'
    target.mkdir()
    with pytest.raises(mod.HostRPCError, match='request frame too large'):
        mod.one_shot_call(cmd='ping', payload={'padding': 'x'*128}, target=target,
                          output=tmp_path / 'out')
    assert not calls


def test_close_shares_one_budget_between_rpc_and_worker_join(peers, monkeypatch):
    peer = peers.create()
    clock, joins = [100.0], []
    def close_rpc(payload, *, timeout):
        assert payload == {'cmd': 'close'} and timeout == 5
        clock[0] += 4
        return {'ok': True}
    join = peer.thread.join
    def finish(timeout=None):
        joins.append(timeout)
        return join(timeout)
    with monkeypatch.context() as patch:
        patch_module_attribute(patch, mod, 'time', 'monotonic', lambda: clock[0])
        patch.setattr(peer.host, '_rpc', close_rpc)
        patch.setattr(peer.thread, 'join', finish)
        peer.host.close()
    assert joins == [1.0]
    assert not peer.thread.is_alive()
