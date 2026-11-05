"""Sandbox scratch owners reclaim restricted trees and retain failed cleanup."""

from contextlib import ExitStack
from pathlib import Path
from argparse import Namespace
import threading

import pytest

from core.atomic_fs import rmtree_hardened
from core.sandbox import host, observe_cli


@pytest.fixture(autouse=True)
def _isolate_scratch_ownership(monkeypatch):
    """Filesystem tests track ownership without starting a process-wide ticker."""
    from core.run import scratch, tmp_reaper

    live = set()
    monkeypatch.setattr(tmp_reaper, "_RUNTIME_DIR_PREFIXES", set())
    monkeypatch.setattr(scratch, "keepalive_register", lambda p: live.add(str(p)))
    monkeypatch.setattr(scratch, "keepalive_unregister", lambda p: live.discard(str(p)))
    yield
    assert not live, f"scratch ownership not released: {sorted(live)}"


@pytest.mark.parametrize("mode", [0o000, 0o500, 0o555])
def test_observe_reclaims_restricted_output(tmp_path, monkeypatch, mode):
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    path = None
    try:
        with ExitStack() as stack:
            path, keep = observe_cli._resolve_run_dir(Namespace(out=None, keep=False), stack)
            nested = path / "locked" / "nested"
            nested.mkdir(parents=True)
            (nested / "output").write_bytes(b"output")
            (path / "locked").chmod(mode)
            assert not keep
        assert not path.exists()
    finally:
        if path is not None:
            rmtree_hardened(path)


def _host(path):
    return host.SandboxHost(_thread=threading.Thread(),
                            _write_fd=-1, _read_fd=-1, _daemon_fds=None,
                            _lock=threading.Lock(), _owned_output=str(path))


@pytest.mark.parametrize("mode", [0o000, 0o500, 0o555])
def test_host_reclaims_restricted_output(tmp_path, mode):
    path = tmp_path / "owned"
    nested = path / "locked" / "nested"
    nested.mkdir(parents=True)
    (nested / "output").write_bytes(b"output")
    (path / "locked").chmod(mode)
    instance = _host(path)
    try:
        instance._cleanup_owned_output()
        assert not path.exists()
        assert instance._owned_output is None
    finally:
        rmtree_hardened(path)


def test_closed_host_retries_failed_output_cleanup(tmp_path, monkeypatch):
    path = tmp_path / "owned"
    path.mkdir()
    instance = _host(path)
    instance._closed = True
    with monkeypatch.context() as fault:
        fault.setattr(host, "rmtree_hardened", lambda path: False, raising=False)
        instance.close()
        assert instance._owned_output == str(path)
        assert path.exists()
    instance.close()
    assert not path.exists()
    assert instance._owned_output is None


@pytest.mark.parametrize("raises", [False, True])
def test_host_retains_owner_after_failed_removal(tmp_path, monkeypatch, raises):
    path = tmp_path / "owned"
    path.mkdir()
    instance = _host(path)

    def fail_remove(path):
        if raises:
            raise OSError("removal failed")
        return False

    with monkeypatch.context() as fault:
        fault.setattr(host, "rmtree_hardened", fail_remove)
        instance._cleanup_owned_output()
        assert instance._owned_output == str(path)
        assert path.exists()
    instance._cleanup_owned_output()
    assert instance._owned_output is None
    assert not path.exists()


def test_closed_host_waits_for_live_backend_before_retry(tmp_path):
    path = tmp_path / "owned"
    path.mkdir()
    instance = _host(path)
    instance._closed = True
    entered, release = threading.Event(), threading.Event()

    def backend():
        entered.set()
        assert release.wait(3), "backend was not released"

    worker = threading.Thread(target=backend)
    instance._thread = worker
    try:
        worker.start()
        assert entered.wait(3), "backend did not start"
        instance.close()
        assert path.exists() and instance._owned_output == str(path)
    finally:
        release.set()
        if worker.ident is not None:
            worker.join(timeout=3)
    assert not worker.is_alive(), "backend did not exit"
    instance.close()
    assert not path.exists() and instance._owned_output is None


def test_host_never_traverses_replaced_output_root(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "keep"
    marker.write_text("external data")
    marker.chmod(0o400)
    path = tmp_path / "owned"
    path.symlink_to(outside, target_is_directory=True)
    instance = _host(path)
    instance._cleanup_owned_output()
    assert instance._owned_output == str(path)
    assert marker.read_text() == "external data"
    assert marker.stat().st_mode & 0o777 == 0o400
    assert path.is_symlink()


def test_concurrent_host_cleanup_removes_tree_once(tmp_path, monkeypatch):
    path = tmp_path / "owned"
    path.mkdir()
    instance = _host(path)
    entered, release = threading.Event(), threading.Event()
    calls = []

    def remove(candidate):
        calls.append(candidate)
        entered.set()
        assert release.wait(3)
        return rmtree_hardened(candidate)

    monkeypatch.setattr(host, "rmtree_hardened", remove)
    workers = [threading.Thread(target=instance._cleanup_owned_output) for _ in range(2)]
    try:
        workers[0].start()
        assert entered.wait(3)
        workers[1].start()
    finally:
        release.set()
        for worker in workers:
            if worker.ident is not None:
                worker.join(timeout=3)
    assert not any(worker.is_alive() for worker in workers)
    assert calls == [str(path)]
    assert instance._owned_output is None
    assert not path.exists()


@pytest.mark.parametrize("keep", [False, True])
def test_observe_keepalive_tracks_context_ownership(tmp_path, monkeypatch, keep):
    from core.run import scratch, tmp_reaper

    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(tmp_reaper, "_RUNTIME_DIR_PREFIXES", set())
    live = set()
    monkeypatch.setattr(scratch, "keepalive_register", lambda p: live.add(Path(p)))
    monkeypatch.setattr(scratch, "keepalive_unregister", lambda p: live.discard(Path(p)))
    with ExitStack() as stack:
        path, retained = observe_cli._resolve_run_dir(Namespace(out=None, keep=keep), stack)
        assert retained == keep
        assert (path in live) == (not keep)
        if keep:
            assert "raptor-observe-" not in tmp_reaper._RUNTIME_DIR_PREFIXES
    assert not live
    assert path.exists() == keep
    rmtree_hardened(path)


def test_observe_explicit_output_is_caller_owned(tmp_path):
    path = tmp_path / "explicit"
    path.mkdir()
    marker = path / "existing"
    marker.write_text("keep")
    with ExitStack() as stack:
        resolved, keep = observe_cli._resolve_run_dir(Namespace(out=str(path), keep=False), stack)
        assert resolved == path and keep
    assert marker.read_text() == "keep"


def test_executable_fallback_is_kept_alive_until_scope_ends(tmp_path, monkeypatch):
    from core.run import scratch
    from core.sandbox import exec_stage

    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(exec_stage, "exec_workdir", lambda: None)
    live = set()
    monkeypatch.setattr(scratch, "keepalive_register", lambda p: live.add(Path(p)))
    monkeypatch.setattr(scratch, "keepalive_unregister", lambda p: live.discard(Path(p)))
    source = tmp_path / "artifact"
    source.write_bytes(b"artifact")
    source.chmod(0o444)
    with exec_stage.executable_stage(source) as staged:
        assert staged.parent in live
        assert staged.read_bytes() == b"artifact"
    assert not live
    assert not staged.parent.exists()
    assert source.read_bytes() == b"artifact"


@pytest.mark.parametrize("cancel", [False, True])
def test_exec_cleanup_failure_preserves_probe_error(tmp_path, monkeypatch, cancel):
    import shutil
    from core.sandbox import exec_stage

    source = tmp_path / "artifact"
    source.write_bytes(b"artifact")
    source.chmod(0o444)
    monkeypatch.setattr(exec_stage, "exec_workdir", lambda: tmp_path)
    staged = None

    def fail_remove(*args, **kwargs):
        raise OSError("cleanup failed")

    try:
        with monkeypatch.context() as fault:
            fault.setattr(shutil, "rmtree", fail_remove)
            with pytest.raises(KeyboardInterrupt if cancel else ValueError):
                with exec_stage.executable_stage(source) as staged:
                    if cancel:
                        raise KeyboardInterrupt("probe cancelled")
                    raise ValueError("probe failed")
        assert source.read_bytes() == b"artifact"
        assert source.stat().st_mode & 0o777 == 0o444
    finally:
        if staged is not None:
            rmtree_hardened(staged.parent)


def test_exec_reclaims_restricted_side_output(tmp_path, monkeypatch):
    from core.sandbox import exec_stage

    source = tmp_path / "artifact"
    source.write_bytes(b"artifact")
    source.chmod(0o444)
    monkeypatch.setattr(exec_stage, "exec_workdir", lambda: tmp_path)
    with exec_stage.executable_stage(source) as staged:
        nested = staged.parent / "locked" / "nested"
        nested.mkdir(parents=True)
        (nested / "side-output").write_bytes(b"data")
        (staged.parent / "locked").chmod(0o000)
    assert not staged.parent.exists()
    assert source.read_bytes() == b"artifact"
