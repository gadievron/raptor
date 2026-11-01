"""Capability probes may be reused only for a stable executable/context."""
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

import pytest

from core.run.toolprobe import ToolInfo
from packages.semgrep import runner


@pytest.fixture
def executable(tmp_path, monkeypatch):
    tool = tmp_path / "semgrep"
    tool.write_text("#!/bin/sh\nexit 0\n")
    tool.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.delenv("RAPTOR_SEMGREP_OFFLINE", raising=False)
    return tool


def _info(path, banner="1.177.0", rc=0):
    return ToolInfo(name="semgrep", path=str(path), stdout=banner, returncode=rc)


def test_capability_reused_but_explicit_diagnostics_stay_fresh(executable, monkeypatch):
    probe = Mock(return_value=_info(executable))
    monkeypatch.setattr(runner, "_version_probe", probe)
    assert runner.scope_isolation_available()
    assert runner.scope_isolation_available()
    assert probe.call_count == 1
    assert runner.version() == "1.177.0"
    assert runner.version() == "1.177.0"
    assert probe.call_count == 3


def test_parallel_workers_share_one_probe(executable, monkeypatch):
    from threading import Event
    entered, release = Event(), Event()

    def probe():
        entered.set()
        assert release.wait(5), "parent did not release probe"
        return _info(executable)

    mock = Mock(side_effect=probe)
    monkeypatch.setattr(runner, "_version_probe", mock)
    with ThreadPoolExecutor(max_workers=8) as pool:
        calls = [pool.submit(runner.scope_isolation_available) for _ in range(8)]
        try:
            assert entered.wait(5)
        finally:
            release.set()
        assert all(call.result(timeout=5) for call in calls)
    assert mock.call_count == 1


@pytest.mark.parametrize("first", [None, "failure", "unparsable"])
def test_failed_or_unparsable_probe_is_retried(executable, monkeypatch, first):
    bad = {None: None, "failure": _info(executable, rc=1),
           "unparsable": _info(executable, "unknown")}[first]
    probe = Mock(side_effect=[bad, _info(executable)])
    monkeypatch.setattr(runner, "_version_probe", probe)
    assert not runner.scope_isolation_available()
    assert runner.scope_isolation_available()
    assert runner.scope_isolation_available()
    assert probe.call_count == 2


def test_old_but_valid_version_can_be_reused(executable, monkeypatch):
    probe = Mock(return_value=_info(executable, "1.79.0"))
    monkeypatch.setattr(runner, "_version_probe", probe)
    assert not runner.scope_isolation_available()
    assert not runner.scope_isolation_available()
    assert probe.call_count == 1


@pytest.mark.parametrize("change", ["replace", "rewrite", "chmod", "delete"])
def test_installation_changes_invalidate(executable, monkeypatch, change):
    probe = Mock(return_value=_info(executable))
    monkeypatch.setattr(runner, "_version_probe", probe)
    assert runner.scope_isolation_available()
    if change == "replace":
        other = executable.with_name("new")
        other.write_text(executable.read_text())
        other.chmod(0o755)
        other.replace(executable)
    elif change == "rewrite":
        executable.write_text("#!/bin/sh\nexit 1\n")
    elif change == "chmod":
        executable.chmod(0o644)
    else:
        executable.unlink()
    probe.return_value = None
    assert not runner.scope_isolation_available()
    assert probe.call_count == 2


def test_same_size_rewrite_with_restored_mtime_is_invalidated(executable, monkeypatch):
    import os
    import time
    before = executable.stat()
    probe = Mock(return_value=_info(executable))
    monkeypatch.setattr(runner, "_version_probe", probe)
    assert runner.scope_isolation_available()
    # Some filesystems update timestamps on coarse clock ticks even though
    # stat exposes nanoseconds. Separate the rewrite from fixture creation.
    time.sleep(0.02)
    executable.write_text(executable.read_text().replace("exit 0", "exit 1"))
    os.utime(executable, ns=(before.st_atime_ns, before.st_mtime_ns))
    probe.return_value = _info(executable, "1.79.0")
    assert not runner.scope_isolation_available()
    assert probe.call_count == 2


def test_symlink_retarget_is_invalidated(executable, monkeypatch):
    second = executable.with_name("second")
    second.write_bytes(executable.read_bytes())
    second.chmod(0o755)
    alias = executable.with_name("alias")
    alias.symlink_to(executable)
    monkeypatch.setattr(runner, "_SEMGREP_BIN", str(alias))
    probe = Mock(return_value=_info(alias))
    monkeypatch.setattr(runner, "_version_probe", probe)
    assert runner.scope_isolation_available()
    alias.unlink()
    alias.symlink_to(second)
    probe.return_value = _info(alias, "1.79.0")
    assert not runner.scope_isolation_available()
    assert probe.call_count == 2


@pytest.mark.parametrize("change", ["path", "cwd", "offline"])
def test_dispatch_or_sandbox_context_changes_invalidate(executable, monkeypatch, change):
    probe = Mock(return_value=_info(executable))
    monkeypatch.setattr(runner, "_version_probe", probe)
    assert runner.scope_isolation_available()
    if change == "path":
        monkeypatch.setenv("PATH", str(executable.parent) + ":/usr/bin")
    elif change == "cwd":
        monkeypatch.chdir(executable.parent)
    else:
        monkeypatch.setenv("RAPTOR_SEMGREP_OFFLINE", "1")
    probe.return_value = _info(executable, "1.79.0")
    assert not runner.scope_isolation_available()
    assert probe.call_count == 2


def test_replacement_during_probe_is_not_published(executable, monkeypatch):
    def replaced():
        replacement = executable.with_name("replacement")
        replacement.write_text("#!/bin/sh\nexit 1\n")
        replacement.chmod(0o755)
        replacement.replace(executable)
        return _info(executable)
    probe = Mock(side_effect=replaced)
    monkeypatch.setattr(runner, "_version_probe", probe)
    assert not runner.scope_isolation_available()
    probe.side_effect = None
    probe.return_value = _info(executable, "1.79.0")
    assert not runner.scope_isolation_available()
    assert probe.call_count == 2


def test_answer_from_a_different_executable_is_not_reused(executable, monkeypatch):
    other = executable.with_name("other")
    other.write_bytes(executable.read_bytes())
    other.chmod(0o755)
    probe = Mock(return_value=_info(other))
    monkeypatch.setattr(runner, "_version_probe", probe)
    assert not runner.scope_isolation_available()
    assert not runner.scope_isolation_available()
    assert probe.call_count == 2


def test_child_reset_does_not_inherit_a_locked_cache(executable, monkeypatch):
    probe = Mock(return_value=_info(executable))
    monkeypatch.setattr(runner, "_version_probe", probe)
    assert runner.scope_isolation_available()
    parent_lock = runner._SCOPE_PROBE_LOCK
    parent_lock.acquire()
    try:
        runner._reset_scope_probe_cache()
        assert runner.scope_isolation_available()
    finally:
        parent_lock.release()
    assert probe.call_count == 2


def test_path_selects_another_installation(executable, monkeypatch):
    directory = executable.parent / "alternate"
    directory.mkdir()
    other = directory / "semgrep"
    other.write_bytes(executable.read_bytes())
    other.chmod(0o755)
    probe = Mock(return_value=_info(executable))
    monkeypatch.setattr(runner, "_version_probe", probe)
    assert runner.scope_isolation_available()
    monkeypatch.setenv("PATH", str(directory))
    probe.return_value = _info(other, "1.79.0")
    assert not runner.scope_isolation_available()
    assert probe.call_count == 2


def test_unstatable_identity_is_not_cached(executable, monkeypatch):
    probe = Mock(return_value=_info(executable))
    monkeypatch.setattr(runner, "_scope_probe_key", lambda: None)
    monkeypatch.setattr(runner, "_version_probe", probe)
    assert runner.scope_isolation_available()
    assert runner.scope_isolation_available()
    assert probe.call_count == 2


def test_forked_child_can_probe_while_parent_lock_is_held(executable, monkeypatch):
    import multiprocessing
    import os
    if not hasattr(os, "register_at_fork") or "fork" not in multiprocessing.get_all_start_methods():
        pytest.skip("requires fork hooks")
    probe = Mock(return_value=_info(executable))
    monkeypatch.setattr(runner, "_version_probe", probe)
    assert runner.scope_isolation_available()

    def child():
        assert runner.scope_isolation_available()
        assert probe.call_count == 2  # Child reprobes instead of inheriting capability state.

    process = multiprocessing.get_context("fork").Process(target=child)
    lock = runner._SCOPE_PROBE_LOCK
    lock.acquire()
    try:
        process.start()
        process.join(timeout=5)
        assert not process.is_alive(), "child inherited a locked capability mutex"
        assert process.exitcode == 0
    finally:
        lock.release()
        if process.is_alive():
            process.kill()
            process.join(timeout=5)
        process.close()


def test_probe_timeout_releases_lock_and_is_retried(executable, monkeypatch):
    from subprocess import TimeoutExpired
    probe = Mock(side_effect=[TimeoutExpired("semgrep", 15), _info(executable)])
    monkeypatch.setattr(runner, "_version_probe", probe)
    with pytest.raises(TimeoutExpired):
        runner.scope_isolation_available()
    assert runner.scope_isolation_available()
    assert probe.call_count == 2


def test_path_rewrite_during_probe_is_not_published(executable, monkeypatch):
    directory = executable.parent / "alternate"
    directory.mkdir()
    other = directory / "semgrep"
    other.write_bytes(executable.read_bytes())
    other.chmod(0o755)

    def switched():
        monkeypatch.setenv("PATH", str(directory))
        return _info(executable)

    probe = Mock(side_effect=switched)
    monkeypatch.setattr(runner, "_version_probe", probe)
    assert not runner.scope_isolation_available()
    probe.side_effect = None
    probe.return_value = _info(other)
    assert runner.scope_isolation_available()
    assert probe.call_count == 2


@pytest.mark.parametrize("failure", ["none", "timeout"])
def test_current_waiters_share_failure_but_later_calls_retry(executable, monkeypatch, failure):
    from concurrent.futures import Future
    from subprocess import TimeoutExpired
    from threading import Event, Lock
    entered, release, waiting = Event(), Event(), Event()
    count_lock = Lock()
    waiter_count = 0

    class ObservedFuture(Future):
        def result(self, timeout=None):
            nonlocal waiter_count
            with count_lock:
                waiter_count += 1
                if waiter_count == 7:
                    waiting.set()
            return super().result(timeout=timeout)

    def failed_probe():
        entered.set()
        assert release.wait(10)
        if failure == "timeout":
            raise TimeoutExpired("semgrep", 15)
        return None

    probe = Mock(side_effect=failed_probe)
    monkeypatch.setattr(runner, "Future", ObservedFuture)
    monkeypatch.setattr(runner, "_version_probe", probe)
    with ThreadPoolExecutor(max_workers=8) as pool:
        calls = [pool.submit(runner.scope_isolation_available) for _ in range(8)]
        try:
            assert entered.wait(10)
            assert waiting.wait(10), "workers did not join the in-flight probe"
        finally:
            release.set()
        for call in calls:
            if failure == "timeout":
                with pytest.raises(TimeoutExpired):
                    call.result(timeout=5)
            else:
                assert not call.result(timeout=5)
    assert probe.call_count == 1
    probe.side_effect = None
    probe.return_value = _info(executable)
    assert runner.scope_isolation_available()
    assert probe.call_count == 2


def test_waiter_revalidates_identity_after_receiving_answer(executable, monkeypatch):
    from concurrent.futures import Future
    from threading import Event
    entered, waiting, release = Event(), Event(), Event()

    class ReplacingFuture(Future):
        def result(self, timeout=None):
            waiting.set()
            answer = super().result(timeout=timeout)
            replacement = executable.with_name("replacement")
            replacement.write_text("#!/bin/sh\nexit 1\n")
            replacement.chmod(0o755)
            replacement.replace(executable)
            return answer

    def probe():
        entered.set()
        assert release.wait(10)
        return _info(executable)

    monkeypatch.setattr(runner, "Future", ReplacingFuture)
    monkeypatch.setattr(runner, "_version_probe", probe)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(runner.scope_isolation_available)
        try:
            assert entered.wait(10)
            second = pool.submit(runner.scope_isolation_available)
            assert waiting.wait(10)
        finally:
            release.set()
        assert first.result(timeout=5)
        assert not second.result(timeout=5)
