"""Pipe ownership across failed child startup and readiness writes."""

from contextlib import contextmanager
import errno
import os
import subprocess
import sys

import pytest

_DRAINS = [
    "test_drain_survives_idle_gap_while_child_alive",
    "test_drain_does_not_reap_target",
    "test_drain_stops_when_child_exited_and_pipe_held_elsewhere",
    "test_drain_stops_when_grandchild_chatters_after_target_exit",
    "test_drain_detects_exit_when_deadline_shorter_than_poll_interval",
    "test_drain_respects_deadline",
    "test_drain_caps_per_fd_accumulation",
]


def _owned(fd, identity):
    try:
        stat = os.fstat(fd)
    except OSError as exc:
        if exc.errno == errno.EBADF:
            return False
        raise
    return (stat.st_dev, stat.st_ino) == identity


@contextmanager
def _pipes(monkeypatch, error, second_fails=False):
    descriptors, pairs = [], []
    real_pipe = os.pipe

    def pipe():
        if second_fails and pairs:
            raise error("injected pipe setup failure")
        pair = real_pipe()
        pairs.append(pair)
        for fd in pair:
            stat = os.fstat(fd)
            descriptors.append((fd, (stat.st_dev, stat.st_ino)))
        return pair

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(os, "pipe", pipe)
            yield pairs
        assert descriptors
        assert not any(_owned(fd, identity) for fd, identity in descriptors), (
            "test setup left its pipe descriptors open"
        )
    finally:
        for fd, identity in descriptors:
            if _owned(fd, identity):
                os.close(fd)


_DRAIN_FAULTS = [(name, "spawn") for name in _DRAINS]
_DRAIN_FAULTS += [(_DRAINS[0], "second-pipe")]


@pytest.mark.skipif(sys.platform != "linux", reason="owned Linux drain fixtures")
@pytest.mark.parametrize("name,fault", _DRAIN_FAULTS)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_drain_startup_failure_releases_pipes(name, fault, error, monkeypatch):
    from core.sandbox.tests import test_landlock_audit_drain as module

    def fail(*args, **kwargs):
        raise error("injected pipe setup failure")

    with _pipes(monkeypatch, error, fault == "second-pipe"):
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "_spawn_child", fail)
            kwargs = (
                {}
                if name
                == "test_drain_detects_exit_when_deadline_shorter_than_poll_interval"
                else {"monkeypatch": patcher}
            )
            with pytest.raises(error, match="injected pipe setup failure"):
                getattr(module, name)(**kwargs)


@pytest.mark.skipif(os.name != "posix", reason="owned ready-pipe fixtures")
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_failed_supervisor_start_releases_both_pipe_ends(error, tmp_path, monkeypatch):
    from packages.joern.tests import test_netns_forwarder_boot as module

    def fail(*args, **kwargs):
        raise error("injected pipe setup failure")

    with _pipes(monkeypatch, error):
        with monkeypatch.context() as patcher:
            patcher.setattr(module, "_spawn_supervisor", fail)
            with pytest.raises(error, match="injected pipe setup failure"):
                module.test_sigterm_at_ready_line_is_honoured(
                    str(tmp_path), str(tmp_path / "owned-marker")
                )


@pytest.mark.skipif(os.name != "posix", reason="owned readiness writer fixtures")
@pytest.mark.parametrize("close", [True, False])
@pytest.mark.parametrize("fault", ["write", "read", "none"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_tier_reader_closes_owned_pipe_ends(close, fault, error, monkeypatch):
    from packages.joern.tests import test_pidns_tier as module

    def fail(*args, **kwargs):
        raise error("injected pipe setup failure")

    with _pipes(monkeypatch, error):
        with monkeypatch.context() as patcher:
            if fault == "write":
                patcher.setattr(os, "write", fail)
            elif fault == "read":
                patcher.setattr(module.server_mod, "_read_achieved_tier", fail)
            invoke = lambda: module.TestReadAchievedTier()._read(
                b"supervision_tier=pidns\n", close=close, timeout_s=0.1
            )
            if fault == "none":
                assert invoke() == "pidns"
            else:
                with pytest.raises(error, match="injected pipe setup failure"):
                    invoke()


@pytest.mark.skipif(os.name != "posix", reason="descriptor reuse on readiness path")
def test_tier_reader_preserves_reused_writer_descriptor(tmp_path, monkeypatch):
    from packages.joern.tests import test_pidns_tier as module

    borrowed = []
    try:
        with _pipes(monkeypatch, OSError) as pairs:

            def read(*args, **kwargs):
                old_writer = pairs[0][1]
                # dup2 simulates a new owner reusing the closed writer number.
                fd = os.open(tmp_path / "other-owner", os.O_CREAT | os.O_WRONLY, 0o600)
                if fd != old_writer:
                    os.dup2(fd, old_writer)
                    os.close(fd)
                borrowed.append(old_writer)
                raise OSError("injected pipe setup failure")

            with monkeypatch.context() as patcher:
                patcher.setattr(module.server_mod, "_read_achieved_tier", read)
                with pytest.raises(OSError, match="injected pipe setup failure"):
                    module.TestReadAchievedTier()._read(b"ready", close=True)
            os.write(borrowed[0], b"still owned")
            assert (tmp_path / "other-owner").read_bytes() == b"still owned"
    finally:
        for fd in borrowed:
            os.close(fd)


@pytest.mark.skipif(os.name != "posix", reason="owned SIGTERM readiness child")
def test_ready_pipe_success_transfers_child_ownership(tmp_path, monkeypatch):
    from packages.joern.tests import test_netns_forwarder_boot as module

    children = []
    code = r"import os,signal,sys,time; signal.signal(signal.SIGTERM,lambda *args:sys.exit(143)); os.write(int(sys.argv[1]),b'supervision_tier=group\n'); time.sleep(60)"

    def spawn(directory, marker, *, ready_fd):
        process = subprocess.Popen(
            [sys.executable, "-I", "-c", code, str(ready_fd)], pass_fds=(ready_fd,)
        )
        children.append(process)
        return process, str(tmp_path / "absent.sock")

    try:
        with _pipes(monkeypatch, OSError):
            with monkeypatch.context() as patcher:
                patcher.setattr(module, "_spawn_supervisor", spawn)
                # The controlled child creates no descendants or native socket.
                patcher.setattr(module, "_sweep_stub_stragglers", lambda *args: None)
                module.test_sigterm_at_ready_line_is_honoured(
                    str(tmp_path), str(tmp_path / "owned-marker")
                )
            assert len(children) == 1 and children[0].returncode == 143
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
