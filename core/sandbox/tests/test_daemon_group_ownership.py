"""Request group retirement retains a leader until its final signal and reap."""

from contextlib import ExitStack
import errno
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from core.sandbox import _daemon as daemon
from core.testing.module_views import module_function_view
from core.testing.processes import reap_on_exit


pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "WNOWAIT"),
    reason="Linux non-reaping child ownership observation",
)


@pytest.fixture
def requests():
    with ExitStack() as owners:
        def create(code, module=daemon):
            proc = module._spawn_request_target(
                [sys.executable, "-I", "-S", "-B", "-c", code],
            )
            owners.enter_context(reap_on_exit(proc, process_group=True))
            return proc
        yield SimpleNamespace(create=create, owners=owners)


def test_retirement_does_not_signal_an_already_reaped_request(requests):
    signals = []
    local_os = SimpleNamespace(**vars(os))
    local_os.killpg = lambda pid, sig: signals.append((pid, sig))
    view = module_function_view(daemon, bindings={"os": local_os})
    proc = requests.create("pass", module=view)
    assert proc.wait(timeout=2) == 0
    with pytest.raises(view._RequestCleanupError, match="reaped before group retirement"):
        view._kill_request_group(proc)
    assert signals == []


def test_external_reap_prevents_numeric_group_signalling(requests):
    signals = []
    local_os = SimpleNamespace(**vars(os))
    local_os.killpg = lambda pid, sig: signals.append((pid, sig))
    view = module_function_view(daemon, bindings={"os": local_os})
    proc = requests.create("raise SystemExit(7)", module=view)
    _, status = os.waitpid(proc.pid, 0)
    try:
        assert proc.returncode is None
        with pytest.raises(view._RequestCleanupError, match="ownership lost"):
            view._kill_request_group(proc)
        assert signals == []
    finally:
        # The test performed the external reap; retire its cached owner too.
        proc.returncode = os.waitstatus_to_exitcode(status)


class BrokenSignalError(PermissionError):
    def __str__(self):
        raise AssertionError("cleanup must not format the signal failure")


@pytest.mark.parametrize("error", [PermissionError, BrokenSignalError])
def test_denied_group_signal_is_not_silent_success(requests, error):
    secondary = error(errno.EPERM, "owned group signal denial")

    def deny(*args):
        raise secondary

    local_os = SimpleNamespace(**vars(os))
    local_os.killpg = deny
    view = module_function_view(daemon, bindings={"os": local_os})
    proc = requests.create("import sys; sys.stdin.buffer.read()", module=view)
    with pytest.raises(view._RequestCleanupError, match="group signal") as caught:
        view._kill_request_group(proc)
    assert caught.value.__cause__ is secondary
    assert view._REQUEST_CLEANUP_FAILED
    assert proc.returncode is None


def test_unconfirmed_reap_is_reported_with_the_original_wait_budget(requests):
    local_os = SimpleNamespace(**vars(os))
    local_os.killpg = lambda *args: None  # Controlled undelivered signal.
    view = module_function_view(daemon, bindings={"os": local_os})
    proc = requests.create("import sys; sys.stdin.buffer.read()", module=view)
    with pytest.raises(view._RequestCleanupError, match="unreaped") as caught:
        view._kill_request_group(proc)
    assert isinstance(caught.value.__cause__, subprocess.TimeoutExpired)
    assert 0 <= caught.value.__cause__.timeout <= 1
    assert view._REQUEST_CLEANUP_FAILED and proc.returncode is None


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_ownership_probe_failure_is_not_treated_as_retirement(requests, error):
    primary = error("owned wait probe failure")
    signals = []

    def fail_probe(*args):
        raise primary

    local_os = SimpleNamespace(**vars(os))
    local_os.waitid = fail_probe
    local_os.killpg = lambda *args: signals.append(args)
    view = module_function_view(daemon, bindings={"os": local_os})
    proc = requests.create("import sys; sys.stdin.buffer.read()", module=view)
    with pytest.raises(error) as caught:
        view._kill_request_group(proc)
    assert caught.value is primary and view._REQUEST_CLEANUP_FAILED
    assert signals == []


@pytest.mark.parametrize("error", [PermissionError, KeyboardInterrupt])
def test_group_signal_failure_preserves_primary_error_and_closes_pipes(requests, error):
    primary = RuntimeError("owned request error")
    secondary = error("owned signal failure")

    def deny(*args):
        raise secondary

    local_os = SimpleNamespace(**vars(os))
    local_os.killpg = deny
    view = module_function_view(daemon, bindings={"os": local_os})
    proc = requests.create("import sys; sys.stdin.buffer.read()", module=view)
    with pytest.raises(RuntimeError) as caught:
        try:
            raise primary
        except RuntimeError:
            view._retire_request_target(proc)
            raise
    assert caught.value is primary
    assert all(stream.closed for stream in (proc.stdin, proc.stdout, proc.stderr))
    assert view._REQUEST_CLEANUP_FAILED
    assert primary.__notes__


def test_spawn_error_survives_cleanup_error_in_its_response(requests):
    primary = RuntimeError("owned original request error")

    def deny(*args):
        raise PermissionError(errno.EPERM, "owned signal denial")

    def fail_capture(*args, **kwargs):
        raise primary

    def create(argv):
        proc = daemon._spawn_request_target(argv)
        requests.owners.enter_context(reap_on_exit(proc, process_group=True))
        return proc

    local_os = SimpleNamespace(**vars(os))
    local_os.killpg = deny
    view = module_function_view(daemon, bindings={
        "os": local_os, "_spawn_request_target": create,
        "_communicate_capped": fail_capture,
    })
    response = view._handle_spawn({
        "argv": [sys.executable, "-I", "-S", "-B", "-c", "import sys; sys.stdin.buffer.read()"],
    })
    assert response == {"ok": False, "error": "RuntimeError: owned original request error"}
    assert view._REQUEST_CLEANUP_FAILED and primary.__notes__


def test_pipe_state_failure_cannot_skip_sibling_closes(requests):
    view = module_function_view(daemon)
    proc = requests.create("pass", module=view)
    assert view._wait_request_exit(proc, 2) == 0
    actual = proc.stdout
    requests.owners.callback(actual.close)
    primary = OSError("owned pipe close failure")

    class PipeView:
        @property
        def closed(self):
            raise KeyboardInterrupt("owned pipe state failure")

        def close(self):
            raise primary

    proc.stdout = PipeView()
    with pytest.raises(OSError) as caught:
        view._retire_request_target(proc)
    assert caught.value is primary
    assert proc.stdin.closed and proc.stderr.closed and not actual.closed
    assert view._REQUEST_CLEANUP_FAILED
    assert any("KeyboardInterrupt" in note for note in primary.__notes__)


def test_platform_without_nonreaping_wait_keeps_existing_wait_behaviour(requests):
    signals = []
    local_os = SimpleNamespace(**vars(os))
    local_os.killpg = lambda pid, sig: signals.append((pid, sig))
    view = module_function_view(daemon, bindings={
        "os": local_os, "_RETAIN_REQUEST_GROUP": False,
    })
    proc = requests.create("pass", module=view)
    assert view._communicate_capped(proc, b"", 2) == (b"", b"", False, False)
    assert proc.returncode == 0
    view._kill_request_group(proc)
    assert signals == [(proc.pid, signal.SIGKILL)]  # Recorded only; no signal sent.


def test_startup_marker_failure_retires_the_new_request(requests):
    primary = KeyboardInterrupt("owned request marker failure")
    created = []

    def create(*args, **kwargs):
        proc = subprocess.Popen(*args, **kwargs)
        created.append(proc)
        requests.owners.enter_context(reap_on_exit(proc, process_group=True))
        return proc

    def fail_marker(*args):
        raise primary

    local_subprocess = SimpleNamespace(**vars(subprocess))
    local_subprocess.Popen = create
    view = module_function_view(daemon, bindings={
        "subprocess": local_subprocess, "setattr": fail_marker,
    })
    with pytest.raises(KeyboardInterrupt) as raised:
        view._spawn_request_target([sys.executable, "-I", "-S", "-B", "-c", "pass"])
    assert raised.value is primary
    proc, = created
    assert proc.returncode is not None
    assert all(stream.closed for stream in (proc.stdin, proc.stdout, proc.stderr))


@pytest.mark.parametrize("code,expected", [
    ("pass", 0),
    ("raise SystemExit(7)", 7),
    ("import os,signal; os.kill(os.getpid(),signal.SIGTERM)", -signal.SIGTERM),
], ids=["clean", "nonzero", "signal"])
def test_request_exit_stays_unreaped_until_group_retirement(requests, code, expected):
    proc = requests.create(code)
    assert daemon._communicate_capped(proc, b"", 2) == (b"", b"", False, False)
    status = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    assert status is not None and status.si_pid == proc.pid
    assert proc.returncode is None
    assert daemon._request_returncode(proc) == expected
    daemon._retire_request_target(proc)
    assert proc.returncode == expected
    assert all(stream.closed for stream in (proc.stdin, proc.stdout, proc.stderr))
    with pytest.raises(ChildProcessError):
        os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)


def _quiescent(identity):
    try:
        fields = Path(f"/proc/{identity['pid']}/stat").read_text().rsplit(")", 1)[1].split()
    except (FileNotFoundError, ProcessLookupError):
        return True
    return fields[0] == "Z" or fields[19] != identity['start_ticks']


@pytest.mark.parametrize("verb", ["spawn", "probe", "conversation"])
def test_exited_leader_still_anchors_live_descendant_retirement(requests, tmp_path, verb):
    import json

    fifo = tmp_path / "park"
    metadata = tmp_path / "child.json"
    os.mkfifo(fifo)
    park = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
    signals = []

    def signal_group(pid, sig):
        status = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        assert status is not None and status.si_pid == pid
        assert status.si_code == os.CLD_EXITED and status.si_status == 7
        signals.append((pid, sig))
        os.killpg(pid, sig)

    def create(argv):
        proc = daemon._spawn_request_target(argv)
        requests.owners.enter_context(reap_on_exit(proc, process_group=True))
        return proc

    local_os = SimpleNamespace(**vars(os))
    local_os.killpg = signal_group
    view = module_function_view(daemon, bindings={
        "os": local_os, "_spawn_request_target": create,
    })
    # The parent-owned FIFO writer releases the descendant even if an
    # assertion fails before production cleanup. It owns no output pipes.
    program = f"""
import json, os
r, w = os.pipe()
child = os.fork()
if child == 0:
    os.close(r)
    with open({str(fifo)!r}, 'rb', buffering=0) as parked:
        with open('/proc/self/stat') as stat:
            fields = stat.read().rsplit(')', 1)[1].split()
        with open({str(metadata)!r}, 'w') as record:
            json.dump({{'pid': os.getpid(), 'start_ticks': fields[19]}}, record)
        for fd in (0, 1, 2):
            os.close(fd)
        os.write(w, b'R')
        os.close(w)
        parked.read(1)
    os._exit(0)
os.close(w)
assert os.read(r, 1) == b'R'
os.close(r)
raise SystemExit(7)
"""
    argv = [sys.executable, "-I", "-S", "-B", "-c", program]
    payload = {"argv": argv, "target_argv": argv, "steps": [], "sends": [],
               "timeout": 2, "total_wait_seconds": 2}
    if verb == "conversation":
        payload["sends"] = [{"bytes_hex": "", "then_recv_until": 0}]
    try:
        result = getattr(view, "_handle_" + verb)(payload)
        assert result["ok"], result
        if verb == "spawn":
            assert result["returncode"] == 7 and not result["timed_out"]
        else:
            assert result["target_exit"] == "exit:7"
        assert len(signals) == 1
        identity = json.loads(metadata.read_text())
        deadline = time.monotonic() + 5
        while not _quiescent(identity) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert _quiescent(identity), "owned descendant survived group retirement"
    finally:
        os.close(park)
        if metadata.exists():
            identity = json.loads(metadata.read_text())
            deadline = time.monotonic() + 5
            while not _quiescent(identity) and time.monotonic() < deadline:
                time.sleep(0.01)
            assert _quiescent(identity), "owned FIFO descendant failed to finish"
