"""Owned RPC pipes cancel work without consuming queued requests.

These transport tests launch only test-authored programs; they do not claim
namespace or read confinement. Native containment has separate integration tests.
"""
from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import select
import signal
import struct
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from core.sandbox import _daemon as daemon
from core.testing.module_bindings import patch_module_attribute
from core.testing.standalone_cli import standalone_cli_env

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX RPC pipes")


def frame(payload):
    body = json.dumps(payload).encode()
    return struct.pack('!I', len(body)) + body


def ready(fd, mask=select.POLLIN, timeout=30000):
    poller = select.poll()
    poller.register(fd, mask)
    return poller.poll(timeout)


def read_reply(fd):
    def exact(size):
        data = bytearray()
        while len(data) < size:
            assert ready(fd), f"reply stalled after {len(data)} of {size} bytes"
            chunk = os.read(fd, min(size - len(data), 65536))
            assert chunk, f"reply EOF after {len(data)} of {size} bytes"
            data.extend(chunk)
        return data
    length, = struct.unpack('!I', exact(4))
    assert length <= 4 * 64 * 1024 * 1024 + 1024 * 1024
    return json.loads(exact(length))


@pytest.fixture
def channel(tmp_path):
    """Own physical handles independently of daemon state, even on setup failure."""
    with ExitStack() as owner:
        env = owner.enter_context(standalone_cli_env(env={"PATH": os.defpath}))
        endpoints = []
        processes = []
        targets = []

        def close(endpoint):
            if endpoint[0] is not None:
                fd, endpoint[0] = endpoint[0], None
                os.close(fd)

        def cleanup():
            # pidfds identify only recorded, live test targets, including if a
            # broken implementation failed to retire its child. Never signal a
            # numeric PID after it may have been reused.
            for fd in targets:
                if not ready(fd, timeout=0):
                    try:
                        signal.pidfd_send_signal(fd, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            for endpoint in endpoints:
                close(endpoint)
            for proc, terminate, kill, wait in processes:
                try:
                    wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # The fresh bootstrap owns target handles even when their
                    # readiness marker has not arrived. Unwind it before the
                    # last-resort hard kill of the daemon itself.
                    terminate()
                    try:
                        wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        kill()
                        wait(timeout=5)
            for fd in targets:
                os.close(fd)
        owner.callback(cleanup)

        def start(*, one_shot=False, observe=False, read_after=None, observe_wait=False, skip_retirement=False):
            ends = []
            for _ in range(2):
                pair = [[fd] for fd in os.pipe()]
                endpoints.extend(pair)
                ends.extend(pair)
            request_read, request_write, reply_read, reply_write = ends
            log = owner.enter_context((tmp_path / f"daemon-{len(processes)}.log").open('w+b'))
            # Observe a genuinely blocked target writer without changing its
            # readiness or consuming any bytes. This is a phase handshake.
            blocked = tmp_path / f"blocked-{len(processes)}"
            phase_marker = tmp_path / f"phase-{len(processes)}"
            phase = f"read:{read_after}" if read_after is not None else 'wait' if observe_wait else 'none'
            fallback = tmp_path / f"fallback-{len(processes)}"
            bootstrap = """
import os, runpy, signal, sys
namespace = runpy.run_path(sys.argv[1])
g = namespace['main'].__globals__
owned_targets = []
fallback_path = sys.argv[8]
original_spawn = g['_spawn_request_target']
def tracked_spawn(argv):
    proc = original_spawn(argv)
    owned_targets.append((proc, proc.kill, proc.wait, (proc.stdin, proc.stdout, proc.stderr)))
    return proc
g['_spawn_request_target'] = tracked_spawn
if sys.argv[9] == 'skip':
    g['_retire_request_target'] = lambda proc: None
def retire_bootstrap(signum, frame):
    raise SystemExit(121)
signal.signal(signal.SIGTERM, retire_bootstrap)
if sys.argv[2] != '-':
    old = g['_target_ready']
    blocked_path, rpc_out = sys.argv[2], int(sys.argv[4])
    def observe(readers, writers, remaining):
        for fd in writers:
            if fd != rpc_out:
                poller = g['select'].poll()
                poller.register(fd, g['select'].POLLOUT)
                if not poller.poll(0):
                    with open(blocked_path, 'w') as marker: marker.write('blocked')
        return old(readers, writers, remaining)
    g['_target_ready'] = observe
# Observe the phase itself, after the channel-entry probe. A readiness
# file alone would allow disconnect before the daemon reached the blocked I/O.
phase, phase_path = sys.argv[6], sys.argv[7]
if phase.startswith('read:'):
    import types
    native_os = g['os']
    local_os = types.ModuleType('observed_os')
    vars(local_os).update(vars(native_os))
    request_fd, threshold, consumed = int(sys.argv[3]), int(phase.split(':')[1]), 0
    def observed_read(fd, size):
        global consumed
        chunk = native_os.read(fd, size)
        if fd == request_fd:
            consumed += len(chunk)
            if consumed >= threshold:
                with open(phase_path, 'w') as marker: marker.write('partial frame consumed')
        return chunk
    local_os.read = observed_read
    g['os'] = local_os
elif phase == 'wait':
    tracked = g['_spawn_request_target']
    def observed_spawn(argv):
        proc = tracked(argv)
        native_wait, marked = proc.wait, False
        def observed_wait(*args, **kwargs):
            nonlocal marked
            if not marked:
                with open(phase_path, 'w') as marker: marker.write('process wait entered')
                marked = True
            return native_wait(*args, **kwargs)
        proc.wait = observed_wait
        return proc
    g['_spawn_request_target'] = observed_spawn
sys.argv = ['daemon', '--one-shot'] if sys.argv[5] == 'one' else [
    'daemon', '--rpc-in-fd', sys.argv[3], '--rpc-out-fd', sys.argv[4]]
try:
    result = g['main']()
finally:
    for proc, kill, wait, streams in owned_targets:
        if proc.poll() is None:
            # Visible intervention makes a broken production cleanup fail the
            # test. This safety net must not supply the asserted outcome.
            with open(fallback_path, 'w') as marker: marker.write('bootstrap target cleanup')
            kill()
        wait(timeout=5)
        for stream in streams:
            if stream is not None:
                stream.close()
raise SystemExit(result)
"""
            proc = subprocess.Popen(
                [os.path.realpath(sys.executable), '-I', '-S', '-B', '-c', bootstrap,
                 str(Path(daemon.__file__)), str(blocked) if observe else '-',
                 str(request_read[0]), str(reply_write[0]), 'one' if one_shot else 'persistent',
                 phase, str(phase_marker), str(fallback), 'skip' if skip_retirement else 'normal'],
                stdin=request_read[0] if one_shot else subprocess.DEVNULL,
                stdout=reply_write[0] if one_shot else subprocess.DEVNULL,
                stderr=log, pass_fds=(request_read[0], reply_write[0]),
                cwd=tmp_path, env=env)
            processes.append((proc, proc.terminate, proc.kill, proc.wait))
            close(request_read)
            close(reply_write)
            def wait(timeout):
                status = proc.wait(timeout=timeout)
                assert not fallback.exists(), "bootstrap target cleanup supplied production outcome"
                return status
            return SimpleNamespace(proc=proc, request=request_write, reply=reply_read,
                                   blocked=blocked, phase=phase_marker, log=log, close=close,
                                   wait=wait)

        def wait_marker(path, proc):
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if path.exists():
                    return path.read_text()
                assert proc.poll() is None, f"daemon exited {proc.returncode} before {path.name}"
                time.sleep(.01)
            pytest.fail(f"daemon never reached {path.name}")

        def own_target(marker, proc):
            pid = int(wait_marker(marker, proc))
            fd = os.pidfd_open(pid)
            targets.append(fd)
            assert not ready(fd, timeout=0), "target exited before channel retirement"
            return fd
        yield SimpleNamespace(start=start, marker=wait_marker, own_target=own_target)


@pytest.mark.slow
@pytest.mark.parametrize('partial', [b'\x00', struct.pack('!I', 20) + b'{'])
def test_partial_request_retires_when_reply_reader_disappears(channel, partial):
    rpc = channel.start(read_after=len(partial))
    os.write(rpc.request[0], partial)
    channel.marker(rpc.phase, rpc.proc)
    rpc.close(rpc.reply)
    assert rpc.wait(timeout=5) == 0


@pytest.mark.slow
def test_queued_requests_are_not_consumed_by_lifetime_watch(channel):
    rpc = channel.start()
    os.write(rpc.request[0], frame({'cmd': 'ping', 'rid': 1}) + frame({'cmd': 'ping', 'rid': 2}))
    assert read_reply(rpc.reply[0])['rid'] == 1
    assert read_reply(rpc.reply[0])['rid'] == 2
    os.write(rpc.request[0], frame({'cmd': 'close', 'rid': 3}))
    assert read_reply(rpc.reply[0]) == {'ok': True, 'closed': True, 'rid': 3}
    assert rpc.wait(timeout=5) == 0


@pytest.mark.slow
@pytest.mark.parametrize('cmd', ['ping', 'spawn', 'probe', 'conversation'])
def test_one_shot_accepts_complete_request_followed_by_eof(channel, cmd):
    rpc = channel.start(one_shot=True)
    argv = [os.path.realpath(sys.executable), '-I', '-S', '-B', '-c', "import os; os.write(1,b'ok')"]
    request = dict(cmd=cmd, rid=4, argv=argv, target_argv=argv,
                   steps=[{'recv_until': 2}], sends=[{'bytes_hex': '', 'then_recv_until': 2}],
                   timeout=30, per_recv_timeout=30, total_wait_seconds=30)
    os.write(rpc.request[0], frame(request))
    rpc.close(rpc.request)
    response = read_reply(rpc.reply[0])
    assert response['ok'] and response['rid'] == 4, response
    assert rpc.wait(timeout=5) == 0


def request_for(verb, phase, marker):
    program = ("import os,time\n"
               + ("os.close(0);os.close(1);os.close(2)\n" if phase == 'wait' else '')
               + f"with open({str(marker) + '.pending'!r},'w') as f: f.write(str(os.getpid()))\n"
               + f"os.replace({str(marker) + '.pending'!r},{str(marker)!r})\n"
               + "time.sleep(120)\n")
    argv = [os.path.realpath(sys.executable), '-I', '-S', '-B', '-c', program]
    send = '61' * 131072 if phase == 'send' else ''
    request = dict(cmd=verb, rid=7, argv=argv, target_argv=argv, stdin_hex=send,
                   timeout=120, per_recv_timeout=30, total_wait_seconds=30)
    request['steps'] = [{'send_hex': send, 'recv_until': 'timeout'}] if phase in {'recv', 'send'} else []
    request['sends'] = [{'bytes_hex': send, 'then_recv_until': 'timeout' if phase in {'recv', 'send'} else 0}]
    return request


@pytest.mark.slow
@pytest.mark.skipif(sys.platform != 'linux' or not hasattr(os, 'pidfd_open'), reason='Linux owned pidfd witness')
@pytest.mark.parametrize('endpoint', ['request', 'reply', 'both'])
@pytest.mark.parametrize('verb,phase', [('spawn', 'recv'), ('spawn', 'send'), ('spawn', 'wait'),
                                      ('probe', 'recv'), ('probe', 'send'), ('probe', 'drain'),
                                      ('probe', 'wait'), ('conversation', 'recv'),
                                      ('conversation', 'send'), ('conversation', 'drain'),
                                      ('conversation', 'wait')])
def test_lost_channel_retires_active_target(channel, tmp_path, endpoint, verb, phase):
    rpc = channel.start(observe=phase == 'send', observe_wait=phase == 'wait')
    marker = tmp_path / 'target-ready'
    os.write(rpc.request[0], frame(request_for(verb, phase, marker)))
    target = channel.own_target(marker, rpc.proc)
    if phase == 'send':
        channel.marker(rpc.blocked, rpc.proc)
    if phase == 'wait':
        channel.marker(rpc.phase, rpc.proc)
    if endpoint in {'request', 'both'}:
        rpc.close(rpc.request)
    if endpoint in {'reply', 'both'}:
        rpc.close(rpc.reply)
    assert rpc.wait(timeout=5) == 0
    assert ready(target, timeout=0), 'daemon exited without retiring its target'


@pytest.mark.slow
@pytest.mark.skipif(sys.platform != 'linux' or not hasattr(os, 'pidfd_open'), reason='Linux owned pidfd witness')
def test_one_shot_lost_output_retires_active_target(channel, tmp_path):
    rpc = channel.start(one_shot=True)
    marker = tmp_path / 'target-ready'
    os.write(rpc.request[0], frame(request_for('spawn', 'recv', marker)))
    target = channel.own_target(marker, rpc.proc)
    rpc.close(rpc.request)  # valid one-shot input EOF; target stays live
    assert not ready(target, timeout=0)
    rpc.close(rpc.reply)
    assert rpc.wait(timeout=5) == 0
    assert ready(target, timeout=0)


@pytest.mark.slow
def test_blocked_reply_retires_when_request_writer_disappears(channel):
    rpc = channel.start()
    argv = [os.path.realpath(sys.executable), '-I', '-S', '-B', '-c',
            "import os; data=b'x'*1048576\nwhile data: data=data[os.write(1,data):]"]
    os.write(rpc.request[0], frame(dict(cmd='spawn', argv=argv, timeout=30)))
    assert ready(rpc.reply[0]), 'daemon never began its oversized-for-pipe reply'
    header = bytearray()
    while len(header) < 4:
        assert ready(rpc.reply[0])
        chunk = os.read(rpc.reply[0], 4 - len(header))
        assert chunk, 'daemon closed before the backpressure frame header'
        header.extend(chunk)
    length, = struct.unpack('!I', header)
    assert length > 2 * 1048576, 'target did not produce the intended backpressured reply'
    rpc.close(rpc.request)  # keep reply reader open, but deliberately do not drain
    assert rpc.wait(timeout=5) == 0


@pytest.mark.slow
def test_real_bounded_reply_can_exceed_request_ceiling(channel):
    rpc = channel.start()
    size = 33 * 1024 * 1024
    argv = [os.path.realpath(sys.executable), '-I', '-S', '-B', '-c',
            f"import os\nfor _ in range({size // 65536}):\n data=b'x'*65536\n while data: data=data[os.write(1,data):]"]
    os.write(rpc.request[0], frame(dict(cmd='spawn', argv=argv, rid=91, timeout=30)))
    result = read_reply(rpc.reply[0])
    assert result['ok'] and result['rid'] == 91, result
    assert result['stdout_bytes_kept'] == size
    assert result['stdout_hex'] == '78' * size
    assert result['stderr_hex'] == ''
    assert not result['stdout_truncated'] and not result['stderr_truncated']
    assert not result['timed_out'] and result['returncode'] == 0
    os.write(rpc.request[0], frame({'cmd': 'close'}))
    assert read_reply(rpc.reply[0])['closed']
    assert rpc.wait(timeout=5) == 0


@pytest.fixture
def pipes():
    with ExitStack() as owner:
        def create():
            read, write = os.pipe()
            owner.callback(os.close, read)
            owner.callback(os.close, write)
            return read, write
        yield create


@pytest.mark.parametrize('failure', [None, ValueError, KeyboardInterrupt])
def test_channel_scope_restores_nested_state_by_identity(pipes, failure):
    read, write = pipes()
    before = daemon._REQUEST_CHANNEL_FDS
    with daemon._request_channel(out_fd=write):
        outer = daemon._REQUEST_CHANNEL_FDS
        try:
            with daemon._request_channel(in_fd=read):
                assert daemon._REQUEST_CHANNEL_FDS == (read,)
                if failure:
                    raise failure('scope')
        except BaseException as error:
            assert failure is not None and type(error) is failure
        assert daemon._REQUEST_CHANNEL_FDS is outer
    assert daemon._REQUEST_CHANNEL_FDS is before


def test_terminal_probe_preserves_queued_bytes(pipes):
    read, write = pipes()
    os.write(write, b'next request')
    with daemon._request_channel(in_fd=read):
        daemon._check_request_channel()
        assert os.read(read, 12) == b'next request'


@pytest.mark.parametrize('omit_invalid', [False, True], ids=['native-poll', 'omitted-invalid'])
@pytest.mark.parametrize('verb', ['recv', 'send', 'spawn'])
def test_abandonment_precedes_pushback_empty_send_and_spawn(pipes, monkeypatch, verb, omit_invalid):
    read, write = pipes()
    if omit_invalid:
        original = select.poll

        class Poll:
            def __init__(self):
                self.delegate = original()

            def register(self, *args):
                return self.delegate.register(*args)

            def poll(self, *args):
                return [(fd, events) for fd, events in self.delegate.poll(*args)
                        if not events & select.POLLNVAL]

        patch_module_attribute(monkeypatch, daemon, 'select', 'poll', Poll)
    # An invalid descriptor is a real terminal event, with no borrowed endpoint.
    invalid = os.dup(read)
    os.close(invalid)
    monkeypatch.setattr(daemon, '_REQUEST_CHANNEL_FDS', (invalid,))
    called = []
    patch_module_attribute(monkeypatch, daemon, 'subprocess', 'Popen', lambda *a, **k: called.append(a))
    pushback = bytearray(b'keep')
    with pytest.raises(daemon._RequestAbandoned):
        if verb == 'recv':
            daemon._recv_until(None, 1, 1, pushback=pushback)
        elif verb == 'send':
            daemon._send_capped(None, b'', 1, 1)
        else:
            daemon._spawn_request_target(['unused'])
    assert pushback == b'keep' and not called


@pytest.mark.parametrize('error', [OSError(errno.EIO, 'descriptor probe failed'), KeyboardInterrupt()])
def test_channel_descriptor_probe_preserves_unrelated_failures(pipes, monkeypatch, error):
    read, write = pipes()
    monkeypatch.setattr(daemon, '_REQUEST_CHANNEL_FDS', (read,))

    def fail(fd):
        assert fd == read
        raise error

    patch_module_attribute(monkeypatch, daemon, 'os', 'fstat', fail)
    with pytest.raises(type(error)) as caught:
        daemon._check_request_channel()
    assert caught.value is error


@pytest.mark.parametrize('blocking', [True, False])
@pytest.mark.parametrize('operation', ['read', 'write'])
@pytest.mark.parametrize('failure', [None, OSError, KeyboardInterrupt])
def test_frame_operations_restore_blocking_mode(pipes, monkeypatch, blocking, operation, failure):
    read, write = pipes()
    fd = read if operation == 'read' else write
    os.set_blocking(fd, blocking)
    payload = {'ok': True}
    if operation == 'read':
        os.write(write, frame(payload))
    if failure:
        def fail(*args):
            raise failure('frame fault')
        patch_module_attribute(monkeypatch, daemon, 'os', operation, fail)
    with daemon._request_channel(out_fd=write):
        if failure:
            with pytest.raises(failure, match='frame fault'):
                getattr(daemon, '_' + operation + '_frame')(fd, payload) if operation == 'write' else daemon._read_frame(fd)
        elif operation == 'read':
            assert daemon._read_frame(fd) == payload
        else:
            daemon._write_frame(fd, payload)
            assert read_reply(read) == payload
    assert os.get_blocking(fd) is blocking


@pytest.mark.parametrize('operation', ['read', 'write'])
def test_frame_io_retries_transient_faults(pipes, monkeypatch, operation):
    read, write = pipes()
    payload = {'ok': True}
    if operation == 'read':
        os.write(write, frame(payload))
    original = getattr(os, operation)
    faults = [InterruptedError(), BlockingIOError()]
    def transient(*args):
        if faults:
            raise faults.pop(0)
        return original(*args)
    patch_module_attribute(monkeypatch, daemon, 'os', operation, transient)
    with daemon._request_channel(out_fd=write):
        if operation == 'read':
            assert daemon._read_frame(read) == payload
        else:
            daemon._write_frame(write, payload)
            assert read_reply(read) == payload
    assert not faults


@pytest.mark.parametrize('operation', ['check', 'read', 'write'])
def test_channel_poll_retries_interrupted_wait(pipes, monkeypatch, operation):
    read, write = pipes()
    payload = {'ok': True}
    if operation == 'read':
        os.write(write, frame(payload))
    original = select.poll
    faults = [InterruptedError()]
    class Poll:
        def __init__(self):
            self.delegate = original()
        def register(self, *args):
            return self.delegate.register(*args)
        def poll(self, *args):
            if faults:
                raise faults.pop()
            return self.delegate.poll(*args)
    with daemon._request_channel(out_fd=write):
        patch_module_attribute(monkeypatch, daemon, 'select', 'poll', Poll)
        if operation == 'check':
            daemon._check_request_channel()
        elif operation == 'read':
            assert daemon._read_frame(read) == payload
        else:
            daemon._write_frame(write, payload)
            assert read_reply(read) == payload
    assert not faults


def test_one_shot_regular_files_preserve_descriptor_modes(tmp_path, monkeypatch):
    with (tmp_path / 'input').open('w+b') as source, (tmp_path / 'output').open('w+b') as target:
        source.write(frame({'cmd': 'ping', 'rid': 63}))
        source.seek(0)
        patch_module_attribute(monkeypatch, daemon, 'sys', 'stdin', source)
        patch_module_attribute(monkeypatch, daemon, 'sys', 'stdout', target)
        monkeypatch.setattr(daemon, '_set_non_dumpable', lambda: True)
        before = [os.get_blocking(s.fileno()) for s in (source, target)]
        assert daemon._run_one_shot() == 0
        assert [os.get_blocking(s.fileno()) for s in (source, target)] == before
        target.seek(0)
        result = read_reply(target.fileno())
        assert result['ok'] and result['rid'] == 63


@pytest.mark.parametrize('operation', ['read', 'write'])
def test_unwatched_nonblocking_frame_preserves_would_block_contract(pipes, monkeypatch, operation):
    read, write = pipes()
    error = BlockingIOError('unwatched')
    calls = []
    def fail(*args):
        calls.append(args)
        if len(calls) == 1:
            raise error
        raise AssertionError('unwatched I/O retried without a readiness wait')
    patch_module_attribute(monkeypatch, daemon, 'os', operation, fail)
    with pytest.raises(BlockingIOError) as caught:
        if operation == 'read':
            daemon._read_frame(read)
        else:
            daemon._write_frame(write, {'ok': True})
    assert caught.value is error and len(calls) == 1


@pytest.mark.parametrize('phase', ['enter', 'leave'])
@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt])
def test_descriptor_mode_faults_restore_mode_and_propagate(pipes, monkeypatch, phase, failure):
    read, write = pipes()
    original = os.set_blocking
    error = failure('mode transition')
    calls = []
    def transition(fd, blocking):
        original(fd, blocking)
        calls.append(blocking)
        if len(calls) == (1 if phase == 'enter' else 2):
            raise error
    patch_module_attribute(monkeypatch, daemon, 'os', 'set_blocking', transition)
    with daemon._request_channel(out_fd=write):
        with pytest.raises(failure) as caught:
            daemon._write_frame(write, {'ok': True})
    assert caught.value is error and calls == [False, True]
    assert os.get_blocking(write)


@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt])
@pytest.mark.parametrize('primary', [OSError, KeyboardInterrupt])
def test_descriptor_restore_fault_preserves_primary_error(pipes, monkeypatch, failure, primary):
    read, write = pipes()
    original = os.set_blocking
    error = primary('primary frame failure')
    def transition(fd, blocking):
        original(fd, blocking)
        if blocking:
            raise failure('secondary restoration failure')
    def fail_write(*args):
        raise error
    patch_module_attribute(monkeypatch, daemon, 'os', 'set_blocking', transition)
    patch_module_attribute(monkeypatch, daemon, 'os', 'write', fail_write)
    with daemon._request_channel(out_fd=write):
        with pytest.raises(primary) as caught:
            daemon._write_frame(write, {'ok': True})
    assert caught.value is error
    assert os.get_blocking(write)


@pytest.mark.slow
@pytest.mark.skipif(sys.platform != 'linux' or not hasattr(os, 'pidfd_open'), reason='Linux owned pidfd witness')
def test_bootstrap_cleanup_does_not_mask_missing_production_retirement(channel, tmp_path):
    rpc = channel.start(skip_retirement=True)
    marker = tmp_path / 'target-ready'
    os.write(rpc.request[0], frame(request_for('spawn', 'recv', marker)))
    target = channel.own_target(marker, rpc.proc)
    rpc.close(rpc.request)
    with pytest.raises(AssertionError, match='bootstrap target cleanup'):
        rpc.wait(timeout=5)
    assert ready(target, timeout=0), 'independent fixture cleanup failed'
