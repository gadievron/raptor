"""Per-call scanner scratch is reclaimed without touching caller output."""

import json
import os
import select
import signal
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.atomic_fs import rmtree_hardened
from core.run import scratch as scratch_mod
from packages.semgrep import runner


@pytest.fixture(autouse=True)
def isolated_scratch(tmp_path, monkeypatch):
    runner._reset_sandbox_scratch()
    original = runner.tempfile.mkdtemp
    monkeypatch.setattr(
        runner.tempfile,
        "mkdtemp",
        lambda prefix="", dir=None, **kw: original(
            prefix=prefix, dir=tmp_path if dir is None else dir, **kw
        ),
    )
    monkeypatch.setattr(runner, "is_available", lambda: True)
    monkeypatch.setattr(runner, "scope_isolation_available", lambda: True)
    monkeypatch.setattr("core.sandbox.python_paths.python_tool_paths", lambda *a: [])
    monkeypatch.setattr("core.config.RaptorConfig.SEMGREP_OFFLINE", False)
    yield
    runner._reset_sandbox_scratch()
    for path in tmp_path.glob("semgrep-sbx-*"):
        rmtree_hardened(path)


def result():
    return SimpleNamespace(
        returncode=0, stdout='{"version":"2.1.0","runs":[]}', stderr=""
    )


@pytest.mark.parametrize(
    "failure", [None, OSError, subprocess.TimeoutExpired, KeyboardInterrupt]
)
@pytest.mark.parametrize("entry", ["run_rule", "wrapper"])
def test_owned_invocation_scratch_is_removed_on_every_exit(
    tmp_path, monkeypatch, entry, failure
):
    seen = []

    def sandbox(cmd, **kwargs):
        path = Path(kwargs["output"])
        seen.append(path)
        (path / "cache").mkdir()
        (path / "cache" / "log").write_text("leftover log")
        if failure is subprocess.TimeoutExpired:
            raise failure(cmd, 1)
        if failure is not None:
            raise failure("scan failed")
        if "--json-output" in cmd:
            Path(cmd[cmd.index("--json-output") + 1]).write_text(
                '{"paths":{"scanned":[]},"errors":[]}'
            )
        return result()

    monkeypatch.setattr("core.sandbox.context.run", sandbox)

    def invoke():
        if entry == "run_rule":
            return runner.run_rule(tmp_path, "local-rule.yaml")
        return runner._default_sandbox_runner(tmp_path, "local-rule.yaml")(["semgrep"])

    if failure is KeyboardInterrupt or (entry == "wrapper" and failure is not None):
        with pytest.raises(failure):
            invoke()
    else:
        invoke()
    assert seen and all(not path.exists() for path in seen)
    assert list(Path(runner._sandbox_scratch_parent()).iterdir()) == []


@pytest.mark.parametrize("mode", [0o000, 0o500, 0o555])
def test_reclaims_restricted_per_call_cache(tmp_path, monkeypatch, mode):
    seen = []

    def sandbox(cmd, **kwargs):
        root = Path(kwargs["output"])
        seen.append(root)
        cache = root / "locked"
        cache.mkdir()
        (cache / "payload").write_text("cache")
        cache.chmod(mode)
        return result()

    monkeypatch.setattr("core.sandbox.context.run", sandbox)
    runner.run_rule(tmp_path, "local-rule.yaml")
    assert seen and not seen[0].exists()


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_sidecar_setup_failure_removes_invocation_scratch(tmp_path, monkeypatch, error):
    def fail(*args, **kwargs):
        raise error("sidecar creation failed")

    monkeypatch.setattr(runner, "NamedTemporaryFile", fail)
    with pytest.raises(error):
        runner.run_rule(tmp_path, "local-rule.yaml")
    assert list(Path(runner._sandbox_scratch_parent()).iterdir()) == []


def test_explicit_wrapper_output_remains_caller_owned(tmp_path, monkeypatch):
    output = tmp_path / "caller-output"
    output.mkdir()

    def sandbox(cmd, **kwargs):
        assert kwargs["output"] == output
        (output / "payload").write_text("keep")
        return result()

    monkeypatch.setattr("core.sandbox.context.run", sandbox)
    runner._default_sandbox_runner(tmp_path, "local-rule.yaml", output_dir=output)(
        ["semgrep"]
    )
    assert (output / "payload").read_text() == "keep"


def test_exported_json_survives_owned_scratch_cleanup(tmp_path, monkeypatch):
    destination = tmp_path / "metadata.json"
    seen = []

    def sandbox(cmd, **kwargs):
        seen.append(Path(kwargs["output"]))
        Path(cmd[cmd.index("--json-output") + 1]).write_text(
            '{"paths":{"scanned":["source.c"]},"errors":[]}'
        )
        return result()

    monkeypatch.setattr("core.sandbox.context.run", sandbox)
    scanned = runner.run_rule(tmp_path, "local-rule.yaml", json_output_path=destination)
    assert "source.c" in scanned.files_examined
    assert json.loads(destination.read_text())["paths"]["scanned"] == ["source.c"]
    assert not seen[0].exists()


def test_parent_has_live_keepalive_until_reset():
    parent = runner._sandbox_scratch_parent()
    assert parent in scratch_mod._keepalive_paths
    runner._reset_sandbox_scratch()
    assert parent not in scratch_mod._keepalive_paths
    assert not Path(parent).exists()


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_registration_failure_does_not_leave_allocated_parent(
    tmp_path, monkeypatch, error
):
    def fail(path):
        scratch_mod._keepalive_paths.add(str(path))
        raise error("registration failed")

    monkeypatch.setattr(runner, "keepalive_register", fail, raising=False)
    with pytest.raises(error):
        runner._sandbox_scratch_parent()
    assert list(tmp_path.glob("semgrep-sbx-*")) == []
    assert not any(str(tmp_path) in path for path in scratch_mod._keepalive_paths)


def test_failed_parent_cleanup_retains_tracking_for_retry(monkeypatch):
    parent = runner._sandbox_scratch_parent()
    with monkeypatch.context() as fault:
        fault.setattr(runner, "rmtree_hardened", lambda path: False, raising=False)
        runner._reset_sandbox_scratch()
    assert Path(parent).exists()
    runner._reset_sandbox_scratch()
    assert not Path(parent).exists()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork requires POSIX")
@pytest.mark.parametrize("locked", [False, True])
def test_forked_child_does_not_delete_parent_scratch_or_inherit_locked_mutex(locked):
    parent = Path(runner._sandbox_scratch_parent())
    (parent / "owner-data").write_text("keep")
    read_fd, write_fd = os.pipe()
    lock = runner._SCRATCH_LOCK
    if locked:
        lock.acquire()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(read_fd)
            runner._reset_sandbox_scratch()
            child = runner._sandbox_scratch_parent()
            good = parent.exists() and Path(child) != parent
            runner._reset_sandbox_scratch()
            os.write(write_fd, b"ok" if good else b"bad")
        finally:
            os._exit(0)
    try:
        os.close(write_fd)
        ready, _, _ = select.select([read_fd], [], [], 3)
        if not ready:
            os.kill(pid, signal.SIGKILL)
        _, status = os.waitpid(pid, 0)
        assert ready, "child inherited a locked scratch mutex"
        assert os.WIFEXITED(status)
        assert os.read(read_fd, 16) == b"ok"
        assert (parent / "owner-data").read_text() == "keep"
    finally:
        if locked:
            lock.release()
        os.close(read_fd)


def test_repeated_calls_do_not_accumulate_scratch(tmp_path, monkeypatch):
    seen = []

    def sandbox(cmd, **kwargs):
        root = Path(kwargs["output"])
        seen.append(root)
        (root / "log").write_bytes(b"x" * 1024)
        return result()

    monkeypatch.setattr("core.sandbox.context.run", sandbox)
    for _ in range(25):
        runner.run_rule(tmp_path, "local-rule.yaml")
        assert list(Path(runner._sandbox_scratch_parent()).iterdir()) == []
    assert len(set(seen)) == 25


def test_concurrent_calls_own_disjoint_live_scratch(tmp_path, monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    barrier = threading.Barrier(2)
    seen = []
    lock = threading.Lock()

    def sandbox(cmd, **kwargs):
        root = Path(kwargs["output"])
        (root / "payload").write_text("live")
        with lock:
            seen.append(root)
        barrier.wait(timeout=3)
        assert len(seen) == 2 and seen[0] != seen[1]
        assert all((path / "payload").exists() for path in seen)
        barrier.wait(timeout=3)
        return result()

    monkeypatch.setattr("core.sandbox.context.run", sandbox)
    with ThreadPoolExecutor(max_workers=2) as pool:
        calls = [
            pool.submit(runner.run_rule, tmp_path, "local-rule.yaml") for _ in range(2)
        ]
        for call in calls:
            call.result(timeout=5)
    assert all(not path.exists() for path in seen)


def test_parent_recreation_releases_old_keepalive():
    parent = runner._sandbox_scratch_parent()
    rmtree_hardened(parent)
    replacement = runner._sandbox_scratch_parent()
    assert replacement != parent
    assert parent not in scratch_mod._keepalive_paths
    assert replacement in scratch_mod._keepalive_paths


def test_foreign_owner_reset_never_removes_parent(monkeypatch):
    parent = runner._sandbox_scratch_parent()
    with monkeypatch.context() as child:
        child.setattr(runner, "_scratch_owner_pid", os.getpid() + 1, raising=False)
        runner._reset_sandbox_scratch()
    assert Path(parent).is_dir()


def test_parent_recreation_does_not_accumulate_atexit_callbacks(monkeypatch):
    registrations = []
    monkeypatch.setattr(
        runner.atexit, "register", lambda *a, **kw: registrations.append(a)
    )
    for _ in range(10):
        runner._sandbox_scratch_parent()
        runner._reset_sandbox_scratch()
    assert registrations == []


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_unregister_failure_still_reclaims_parent_and_preserves_error(
    monkeypatch, error
):
    parent = runner._sandbox_scratch_parent()
    sentinel = error("unregister failed")

    def fail(path):
        scratch_mod._keepalive_paths.discard(str(path))
        raise sentinel

    with monkeypatch.context() as fault:
        fault.setattr(runner, "keepalive_unregister", fail)
        with pytest.raises(error) as caught:
            runner._reset_sandbox_scratch()
    assert caught.value is sentinel
    assert not Path(parent).exists()
    assert runner._scratch_parent is None


def test_registration_error_is_not_masked_by_secondary_unregister_failure(
    tmp_path, monkeypatch
):
    first = OSError("registration failed")

    def register(path):
        raise first

    def unregister(path):
        raise RuntimeError("secondary cleanup error")

    monkeypatch.setattr(runner, "keepalive_register", register)
    monkeypatch.setattr(runner, "keepalive_unregister", unregister)
    with pytest.raises(OSError) as caught:
        runner._sandbox_scratch_parent()
    assert caught.value is first
    assert list(tmp_path.glob("semgrep-sbx-*")) == []


def test_sidecar_unlink_error_does_not_prevent_directory_cleanup(tmp_path, monkeypatch):
    seen = []

    def sandbox(cmd, **kwargs):
        seen.append(Path(kwargs["output"]))
        return result()

    def unlink(path):
        raise RuntimeError("unlink failed")

    monkeypatch.setattr("core.sandbox.context.run", sandbox)
    monkeypatch.setattr(runner, "_safe_unlink", unlink)
    with pytest.raises(RuntimeError):
        runner.run_rule(tmp_path, "local-rule.yaml")
    assert seen and not seen[0].exists()


@pytest.mark.parametrize("phase", ["build_cmd", "_default_sandbox_runner"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_command_and_runner_setup_failures_reclaim_scratch(
    tmp_path, monkeypatch, phase, error
):
    def fail(*args, **kwargs):
        raise error("setup failed")

    monkeypatch.setattr(runner, phase, fail)
    with pytest.raises(error):
        runner.run_rule(tmp_path, "local-rule.yaml")
    assert list(Path(runner._sandbox_scratch_parent()).iterdir()) == []


def test_unavailable_sandbox_refusal_reclaims_scratch(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "_default_sandbox_runner", lambda *a, **kw: None)
    scan = runner.run_rule(tmp_path, "local-rule.yaml")
    assert not scan.ok
    assert list(Path(runner._sandbox_scratch_parent()).iterdir()) == []


@pytest.mark.parametrize("mode", [0o000, 0o500, 0o555])
def test_parent_reset_reclaims_restricted_leftovers(mode):
    parent = Path(runner._sandbox_scratch_parent())
    locked = parent / "locked"
    locked.mkdir()
    (locked / "payload").write_text("cache")
    locked.chmod(mode)
    runner._reset_sandbox_scratch()
    assert not parent.exists()
