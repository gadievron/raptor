"""Persistent request I/O makes progress on both output pipes and owns cleanup."""

from contextlib import ExitStack
import errno
import fcntl
import os
import resource
import subprocess
import sys
from types import SimpleNamespace

import pytest

from core.sandbox import _daemon as daemon
from core.sandbox._pipe_poll import readable_fds
from core.testing.module_bindings import patch_module_attribute
from core.testing.state_isolation import pin_user_state_dirs

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux persistent daemon pipes")


@pytest.fixture
def target(tmp_path, monkeypatch):
    records, streams = [], []
    with ExitStack() as owner:
        def cleanup():
            with ExitStack() as finish:
                for stream in streams:
                    finish.callback(stream.close)
                for proc, kill, wait in records:
                    def retire(proc=proc, kill=kill, wait=wait):
                        try:
                            if proc.returncode is None:
                                kill()
                        finally:
                            wait(timeout=5)
                    finish.callback(retire)
        owner.callback(cleanup)
        pin_user_state_dirs(monkeypatch, tmp_path / "state")
        def create(code, **kwargs):
            options = dict(stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           start_new_session=True, env={"PATH": os.defpath}, cwd=tmp_path)
            options.update(kwargs)
            proc = subprocess.Popen([os.path.realpath(sys.executable), "-I", "-S", "-B", "-c", code], **options)
            records.append((proc, proc.kill, proc.wait))
            streams.extend(s for s in (proc.stdin, proc.stdout, proc.stderr) if s is not None)
            return proc
        yield SimpleNamespace(create=create, records=records, streams=streams, owner=owner)


FLOOD = "import os\nfor _ in range(32): os.write(2,b'e'*65536)\n"


@pytest.mark.parametrize("cap", [0, 1, 97, 8192])
@pytest.mark.parametrize("phase", ["send", "recv", "mixed"])
def test_stderr_pressure_does_not_block_interactive_progress(target, monkeypatch, cap, phase):
    monkeypatch.setattr(daemon, "_MAX_CAPTURE_BYTES", cap)
    payload = b'i' * 262144
    if phase == "recv":
        program = FLOOD + "os.write(1,b'READY')\n"
    else:
        program = FLOOD + f"data=b''\nwhile len(data)<{len(payload)}:\n data+=os.read(0,{len(payload)}-len(data))\nassert data==b'i'*{len(payload)}\nos.write(1,b'READY')\n"
    if phase == "mixed":
        program = program.replace("os.write(1,b'READY')", FLOOD + "os.write(1,b'READY')")
    proc = target.create(program)
    pushback = bytearray()
    if phase != "recv":
        drained, truncated, dropped = daemon._send_capped(proc, payload, 5, 5)
        assert dropped == 0, "stderr pressure prevented the target reading stdin"
        assert not truncated
        pushback.extend(drained)
    got = daemon._recv_until(proc, 5, 5, max_bytes=5, pushback=pushback)
    assert got == b'READY'
    out, err, ot, et, timed_out = daemon._drain_target(proc, 5, 5)
    assert out == b'' and not ot and not timed_out
    assert err == b'e' * cap and et
    assert proc.returncode == 0


@pytest.mark.parametrize("verb", ["spawn", "probe", "conversation"])
@pytest.mark.parametrize("cap", [97, 8192])
def test_handlers_preserve_early_stderr_and_close_all_owned_pipes(target, monkeypatch, verb, cap):
    monkeypatch.setattr(daemon, "_MAX_CAPTURE_BYTES", cap)
    def spawn(argv):
        return target.create(argv[0])
    monkeypatch.setattr(daemon, "_spawn_request_target", spawn)
    program = FLOOD + "os.write(1,b'ok')\n"
    payload = {"argv": [program], "target_argv": [program], "timeout": 5,
               "steps": [{"recv_until": 2}], "sends": [{"bytes_hex": "", "then_recv_until": 2}],
               "per_recv_timeout": 5, "total_wait_seconds": 5}
    result = getattr(daemon, '_handle_' + verb)(payload)
    assert result['ok'] and result['stderr_truncated'], result
    if verb == 'spawn':
        assert bytes.fromhex(result['stderr_hex']) == b'e' * cap
        assert bytes.fromhex(result['stdout_hex']) == b'ok'
    else:
        assert result['target_exit'] == 'clean'
        key = 'target_stderr_tail' if verb == 'probe' else 'target_stderr_text_tail'
        assert result[key] == 'e' * min(cap, 2000)
    assert all(s.closed for s in target.streams)
    assert target.records[0][0].returncode == 0


@pytest.mark.parametrize("phase", ["send", "recv", "communicate"])
def test_high_numbered_owned_pipes_work_in_every_target_phase(target, phase):
    proc = target.create("import os\nos.write(1,b'hello');os.write(2,b'diagnostic')\n")
    previous = resource.getrlimit(resource.RLIMIT_NOFILE)
    if previous[1] < 1200:
        pytest.skip('hard descriptor limit below high-fd test requirement')
    with ExitStack() as scope:
        scope.callback(resource.setrlimit, resource.RLIMIT_NOFILE, previous)
        if previous[0] < 1200:
            resource.setrlimit(resource.RLIMIT_NOFILE, (1200, previous[1]))
        for label in ('stdin', 'stdout', 'stderr'):
            stream = getattr(proc, label)
            fd = fcntl.fcntl(stream.fileno(), fcntl.F_DUPFD_CLOEXEC, 1100)
            try:
                replacement = os.fdopen(fd, 'wb' if label == 'stdin' else 'rb')
            except BaseException:
                os.close(fd)
                raise
            target.streams.append(replacement)
            setattr(proc, label, replacement)
            stream.close()
        pushback = bytearray()
        if phase == 'send':
            data, _, _ = daemon._send_capped(proc, b'x', 5, 64)
            pushback.extend(data)
        if phase != 'communicate':
            assert daemon._recv_until(proc, 5, 5, pushback=pushback) == b'hello'
        out, err, ot, et = daemon._communicate_capped(proc, b'', 5)
        assert out == (b'hello' if phase == 'communicate' else b'')
        assert err == b'diagnostic' and not ot and not et


@pytest.mark.parametrize('verb', ['spawn', 'probe', 'conversation'])
@pytest.mark.parametrize('failure', [RuntimeError, KeyboardInterrupt])
def test_handler_failure_retires_process_and_all_pipes(target, monkeypatch, verb, failure):
    proc = target.create('import time;time.sleep(60)')
    monkeypatch.setattr(daemon, '_spawn_request_target', lambda argv: proc)
    error = failure('owned request failure')
    def fail(*args, **kwargs):
        raise error
    monkeypatch.setattr(daemon, '_communicate_capped' if verb == 'spawn' else '_recv_until', fail)
    payload = {'argv': ['owned'], 'target_argv': ['owned'], 'steps': [{'recv_until': 1}],
               'sends': [{'bytes_hex': '', 'then_recv_until': 1}]}
    if verb == 'spawn' and failure is RuntimeError:
        assert not daemon._handle_spawn(payload)['ok']
    else:
        with pytest.raises(failure) as caught:
            getattr(daemon, '_handle_' + verb)(payload)
        assert caught.value is error
    assert proc.returncode is not None
    assert all(s.closed for s in target.streams)


@pytest.mark.parametrize('cap', [0, 5, 32])
def test_second_timeout_preserves_newly_drained_bytes_and_loss_flags(target, monkeypatch, cap):
    monkeypatch.setattr(daemon, '_MAX_CAPTURE_BYTES', cap)
    with ExitStack() as pipes:
        pairs = []
        for _ in range(3):
            r, w = os.pipe()
            pipes.callback(os.close, r)
            pipes.callback(os.close, w)
            pairs.append((r, w))
        (out_r, out_w), (err_r, err_w), (ready_r, ready_w) = pairs
        code = f"import os,time\nos.write(1,b'head');os.write(2,b'HEAD');os.write({ready_w},b'R');time.sleep(60)"
        proc = target.create(code, stdout=out_w, stderr=err_w, pass_fds=(ready_w,))
        for label, original in (('stdout', out_r), ('stderr', err_r)):
            duplicate = os.dup(original)
            try:
                stream = os.fdopen(duplicate, 'rb')
            except BaseException:
                os.close(duplicate)
                raise
            target.streams.append(stream)
            setattr(proc, label, stream)
        assert readable_fds([ready_r], 5), 'owned target did not signal readiness'
        assert os.read(ready_r, 1) == b'R'
        kill = daemon._kill_request_group
        def kill_then_tail(child):
            kill(child)
            os.write(out_w, b'tail')
            os.write(err_w, b'TAIL')
        monkeypatch.setattr(daemon, '_kill_request_group', kill_then_tail)
        out, err, ot, et, timeout = daemon._drain_target(proc, 0.02, cap)
        assert timeout
        assert out == b'headtail'[:cap] and err == b'HEADTAIL'[:cap]
        assert ot is (cap < 8) and et is (cap < 8)
        assert proc.returncode is not None


@pytest.mark.parametrize('phase', ['send', 'communicate'])
@pytest.mark.parametrize('fault', ['interrupt', 'would-block', 'zero', 'io'])
def test_stdin_transient_errors_retry_and_real_errors_remain_visible(target, monkeypatch, phase, fault):
    proc = target.create('import os\nassert os.read(0,1)==b"x"\nos.write(1,b"ok")')
    fd = proc.stdin.fileno()
    real_write = os.write
    calls = []
    def write(selected, data):
        if selected == fd and not calls:
            calls.append(selected)
            if fault == 'zero':
                return 0
            if fault == 'interrupt':
                raise InterruptedError(errno.EINTR, 'owned interrupted write')
            if fault == 'would-block':
                raise BlockingIOError(errno.EAGAIN, 'owned busy pipe')
            raise OSError(errno.EIO, 'owned failed write')
        return real_write(selected, data)
    patch_module_attribute(monkeypatch, daemon, 'os', 'write', write)
    def execute():
        if phase == 'send':
            return daemon._send_capped(proc, b'x', 5, 64)
        return daemon._communicate_capped(proc, b'x', 5)
    if fault in ('zero', 'io'):
        with pytest.raises(OSError) as caught:
            execute()
        assert caught.value.errno == errno.EIO
    else:
        result = execute()
        if phase == 'send':
            assert result[2] == 0
        else:
            assert result[:2] == (b'ok', b'')
    assert calls == [fd]


@pytest.mark.parametrize('phase', ['send', 'recv', 'communicate'])
@pytest.mark.parametrize('fault', ['interrupt', 'would-block'])
def test_output_transient_errors_do_not_look_like_eof(target, monkeypatch, phase, fault):
    proc = target.create('import os\nos.write(2,b"err");os.write(1,b"ok")')
    original = os.read
    selected = proc.stderr.fileno()
    injected = []
    def read(fd, size):
        if fd == selected and not injected:
            injected.append(fd)
            if fault == 'interrupt':
                raise InterruptedError(errno.EINTR, 'owned interrupted read')
            raise BlockingIOError(errno.EAGAIN, 'owned read readiness race')
        return original(fd, size)
    patch_module_attribute(monkeypatch, daemon, 'os', 'read', read)
    pushback = bytearray()
    if phase == 'send':
        data, _, _ = daemon._send_capped(proc, b'x'*65536, 5, 64)
        pushback.extend(data)
    if phase != 'communicate':
        assert daemon._recv_until(proc, 2, 5, pushback=pushback) == b'ok'
    out, err, _, _ = daemon._communicate_capped(proc, b'', 5)
    assert out == (b'ok' if phase == 'communicate' else b'')
    assert err == b'err'
    assert injected


@pytest.mark.parametrize('stream_index', [0, 1, 2])
@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt])
@pytest.mark.parametrize('primary_failure', [False, True], ids=['cleanup-primary', 'request-primary'])
def test_retirement_attempts_every_pipe_and_preserves_primary_failure(target, monkeypatch, stream_index, failure, primary_failure):
    proc = target.create('import time;time.sleep(60)')
    label = ('stdin', 'stdout', 'stderr')[stream_index]
    physical = getattr(proc, label)
    close_error = failure('owned close failed after retirement')
    def close():
        physical.close()
        raise close_error
    class PipeView:
        @property
        def closed(self):
            return physical.closed

        def close(self):
            close()

    monkeypatch.setattr(proc, label, PipeView())
    error = RuntimeError('request failed before cleanup')
    with pytest.raises(RuntimeError if primary_failure else failure) as caught:
        if primary_failure:
            try:
                raise error
            except RuntimeError:
                daemon._retire_request_target(proc)
                raise
        else:
            daemon._retire_request_target(proc)
    assert caught.value is (error if primary_failure else close_error)
    if primary_failure:
        assert 'target cleanup: ' + failure.__name__ in error.__notes__
    assert all(s.closed for s in target.streams)
    assert proc.returncode is not None
    assert not daemon._REQUEST_CLEANUP_FAILED


@pytest.mark.parametrize('phase', ['send', 'recv', 'communicate'])
def test_interrupted_readiness_keeps_the_original_deadline(target, monkeypatch, phase):
    proc = target.create('import os\nos.write(1,b"ok");os.write(2,b"err")')
    clock = [100.0]
    def monotonic():
        clock[0] += 0.1
        return clock[0]
    patch_module_attribute(monkeypatch, daemon, 'time', 'monotonic', monotonic)
    ready = daemon._target_ready
    waits = []
    def interrupted(readers, writers, remaining):
        waits.append(remaining)
        if len(waits) == 1:
            raise InterruptedError(errno.EINTR, 'owned interrupted readiness')
        return ready(readers, writers, remaining)
    monkeypatch.setattr(daemon, '_target_ready', interrupted)
    if phase == 'send':
        daemon._send_capped(proc, b'x' * 65536, 5, 64)
    elif phase == 'recv':
        assert daemon._recv_until(proc, 2, 5) == b'ok'
    else:
        assert daemon._communicate_capped(proc, b'', 5)[:2] == (b'ok', b'err')
    assert len(waits) >= 2 and 0 < waits[1] < waits[0] < 5
