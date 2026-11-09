"""Secondary diagnostic failures must not interrupt remaining owner cleanup."""

import os
import threading
import signal
import sys

import pytest

from core.sandbox import host, _daemon as daemon
from core.testing.module_bindings import patch_module_attribute
from core.testing.module_views import module_function_view
from core.testing.processes import reap_on_exit


@pytest.fixture
def rejecting_note():
    def make(primary_type, note_type):
        attempts = []
        problem = note_type("owned annotation failure")

        class Primary(primary_type):
            def add_note(self, text):
                attempts.append(text)
                raise problem

        return Primary("owned primary failure"), attempts
    return make


@pytest.mark.parametrize("primary_type", [RuntimeError, KeyboardInterrupt])
@pytest.mark.parametrize("note_type", [MemoryError, KeyboardInterrupt])
def test_close_annotation_failure_cannot_skip_worker_and_output_cleanup(
    tmp_path, rejecting_note, primary_type, note_type,
):
    primary, notes = rejecting_note(primary_type, note_type)
    secondary = OSError("owned endpoint cleanup failure")
    joined = []
    done = threading.Event()
    output = tmp_path / "owned-output"
    output.mkdir()
    (output / "marker").write_bytes(b"owned")

    class Worker(threading.Thread):
        def join(self, timeout=None):
            joined.append(True)
            return super().join(timeout)

    class Host(host.SandboxHost):
        def _rpc(self, payload, *, timeout):
            raise primary

        def _release_rpc_fds(self, failure=None):
            super()._release_rpc_fds(failure)
            raise secondary

    worker = Worker(target=done.set)
    worker.start()
    assert done.wait(2)
    read, write = os.pipe()
    identities = {fd: (os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in (read, write)}
    owner = Host(_thread=worker, _write_fd=write, _read_fd=read,
                 _daemon_fds=None, _lock=threading.Lock(), _owned_output=str(output))
    try:
        with pytest.raises(BaseException) as caught:
            owner.close()
        assert caught.value is primary
        assert notes and joined == [True]
        assert owner._write_fd is None and owner._read_fd is None
        assert owner._owned_output is None and not output.exists()
        assert not worker.is_alive()
    finally:
        threading.Thread.join(worker, timeout=2)
        # Safety cleanup consumes only the originally owned physical objects.
        for fd, identity in identities.items():
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == identity:
                os.close(fd)


@pytest.mark.parametrize("kind", ["daemon", "rpc"])
@pytest.mark.parametrize("note_type", [MemoryError, KeyboardInterrupt])
def test_endpoint_annotation_failure_preserves_first_error_and_consumes_all_owners(
    monkeypatch, rejecting_note, kind, note_type,
):
    primary, notes = rejecting_note(KeyboardInterrupt, note_type)
    secondary = RuntimeError("owned second endpoint close failure")
    read, write = os.pipe()
    native_close = os.close
    closed = []

    def close(fd):
        native_close(fd)
        closed.append(fd)
        raise primary if len(closed) == 1 else secondary

    patch_module_attribute(monkeypatch, host, "os", "close", close)
    owner = object.__new__(host.SandboxHost)
    owner._daemon_fds_lock = threading.Lock()
    owner._daemon_fds = (read, write)
    owner._read_fd, owner._write_fd = read, write
    with pytest.raises(BaseException) as caught:
        if kind == "daemon":
            owner._release_daemon_fds()
        else:
            owner._release_rpc_fds()
    assert caught.value is primary
    assert notes and len(closed) == 2
    assert set(closed) == {read, write}
    if kind == "daemon":
        assert owner._daemon_fds is None
    else:
        assert owner._read_fd is None and owner._write_fd is None


@pytest.mark.skipif(sys.platform != "linux" or not hasattr(os, "WNOWAIT"),
                    reason="Linux retained request leader ownership")
@pytest.mark.parametrize("primary_type", [RuntimeError, KeyboardInterrupt])
@pytest.mark.parametrize("note_type", [MemoryError, KeyboardInterrupt])
def test_target_annotation_failure_preserves_error_after_real_retirement(
    rejecting_note, primary_type, note_type,
):
    primary, notes = rejecting_note(primary_type, note_type)
    secondary = OSError("owned target pipe cleanup failure")
    view = module_function_view(daemon)
    proc = view._spawn_request_target(
        [sys.executable, "-I", "-S", "-B", "-c", "import sys; sys.stdin.buffer.read()"],
    )
    with reap_on_exit(proc, process_group=True):
        stream = proc.stdin

        class CloseFailure:
            failed = False

            @property
            def closed(self):
                return stream.closed

            def close(self):
                stream.close()
                if not self.failed:
                    self.failed = True
                    raise secondary

        proc.stdin = CloseFailure()
        with pytest.raises(BaseException) as caught:
            try:
                raise primary
            finally:
                view._retire_request_target(proc)
        assert caught.value is primary
        assert notes and proc.returncode == -signal.SIGKILL
        assert all(pipe.closed for pipe in (proc.stdin, proc.stdout, proc.stderr))
        assert not view._REQUEST_CLEANUP_FAILED  # All physical owners retired.
