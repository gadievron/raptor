"""Joern must retain teardown ownership until disk cleanup succeeds."""

import os
from pathlib import Path
from unittest.mock import Mock

import pytest

from core.testing.restricted_tree import restricted_tree
from packages.joern import artifacts, server


import core.source.gated as _os_fault_consumer
from core.testing.module_bindings import patch_module_attribute


@pytest.mark.parametrize("mode", [0, 0o500, 0o555])
@pytest.mark.parametrize("spawned", [False, True])
def test_stop_reclaims_restricted_workspace_and_socket_tree(
    tmp_path, monkeypatch, mode, spawned
):
    worker = server.JoernServer(confined=True)
    with (
        restricted_tree(tmp_path / "workspace", mode) as workspace,
        restricted_tree(tmp_path / "uds", mode) as uds,
    ):
        worker._workdir, worker._uds_dir = str(workspace), str(uds)
        if spawned:
            worker._proc = Mock(pid=2_000_000_000, returncode=0)
            monkeypatch.setattr(server, "_signal_owned_group", lambda *args: None)
            monkeypatch.setattr(server, "_managed_group_stopped", lambda *args: True)
        assert worker.stop() is not False
        assert not workspace.exists()
        assert not uds.exists()
        assert worker._workdir is None and worker._uds_dir is None


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("stage", ["reservation", "flags", "capability"])
def test_startup_setup_failure_releases_owned_resources(
    tmp_path, monkeypatch, error, stage
):
    monkeypatch.setattr("packages.joern.client.runtime_base", lambda: tmp_path)
    monkeypatch.setattr(server, "_repl_bridge_path", lambda: "joern")
    monkeypatch.setattr(server, "_server_auth_supported", lambda binary: True)
    monkeypatch.setattr(server, "sweep_stale_workspaces", lambda **kwargs: [])
    reservation = Mock(granted_mb=64)
    monkeypatch.setattr(server, "reserve_heap_mb", lambda *args, **kwargs: reservation)
    failure = error("startup setup failed")

    def fail(*args, **kwargs):
        raise failure

    hook = {
        "reservation": "reserve_heap_mb",
        "flags": "_jvm_gc_flags",
        "capability": "_netns_isolation_available",
    }[stage]
    monkeypatch.setattr(server, hook, fail)
    worker = server.JoernServer(heap_mb=64)
    with pytest.raises(error) as caught:
        worker.start()
    assert caught.value is failure
    assert worker._workdir is None
    assert worker._heap_reservation is None
    assert not list(tmp_path.glob(server._WORKSPACE_PREFIX + "*"))
    assert reservation.release.call_count == (0 if stage == "reservation" else 1)


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_workspace_marker_failure_does_not_leak_allocation(
    tmp_path, monkeypatch, error
):
    monkeypatch.setattr("packages.joern.client.runtime_base", lambda: tmp_path)
    failure = error("marker failed")

    def fail(*args):
        raise failure

    monkeypatch.setattr(server, "write_owner_marker", fail)
    with pytest.raises(error) as caught:
        server._new_workspace()
    assert caught.value is failure
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("mode", [0, 0o500, 0o555])
def test_frozen_graph_close_reclaims_restricted_output(tmp_path, mode):
    source = tmp_path / "source.bin"
    source.write_bytes(b"graph")
    frozen = artifacts.FrozenGraph.copy(source, directory=tmp_path / "graphs")
    with restricted_tree(frozen.path.parent / "extra", mode):
        frozen.close()
        assert not frozen.path.parent.exists()
    assert source.read_bytes() == b"graph"


@pytest.mark.parametrize("error", [ValueError, KeyboardInterrupt, SystemExit])
def test_copy_cleanup_failure_preserves_primary_error(tmp_path, monkeypatch, error):
    from core.atomic_fs import rmtree_hardened

    source = tmp_path / "source.bin"
    source.write_bytes(b"graph")
    graphs = tmp_path / "graphs"
    failure = error("primary copy failure")

    class FailedGraph(artifacts.FrozenGraph):
        def __init__(self, *args):
            raise failure

    def cleanup_failed(*args, **kwargs):
        raise OSError("secondary cleanup failure")

    try:
        with monkeypatch.context() as fault:
            fault.setattr("shutil.rmtree", cleanup_failed)
            with pytest.raises(error) as caught:
                FailedGraph.copy(source, directory=graphs)
            assert caught.value is failure
    finally:
        rmtree_hardened(graphs)


@pytest.mark.parametrize("operation", ["digest", "copy"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_failed_stream_acquisition_closes_source_descriptor(
    tmp_path, monkeypatch, operation, error
):
    source = tmp_path / "source.bin"
    source.write_bytes(b"graph")
    opened = []
    real_open = os.open

    def track(path, *args, **kwargs):
        fd = real_open(path, *args, **kwargs)
        if Path(path) == source:
            opened.append(fd)
        return fd

    failure = error("fdopen failed")

    def fail(*args, **kwargs):
        raise failure

    try:
        with monkeypatch.context() as fault:
            patch_module_attribute(fault, _os_fault_consumer, "os", "open", track)
            patch_module_attribute(fault, _os_fault_consumer, "os", "fdopen", fail)
            with pytest.raises(error) as caught:
                if operation == "digest":
                    artifacts.graph_digest(source)
                else:
                    artifacts.FrozenGraph.copy(source, directory=tmp_path / "graphs")
            assert caught.value is failure
        assert opened
        for fd in opened:
            with pytest.raises(OSError):
                os.fstat(fd)
    finally:
        for fd in opened:
            try:
                os.close(fd)
            except OSError:
                pass


@pytest.mark.parametrize("blocked", ["_workdir", "_uds_dir"])
def test_incomplete_scratch_cleanup_keeps_only_failed_path_for_retry(
    tmp_path, monkeypatch, blocked
):
    worker = server.JoernServer()
    workspace, uds = tmp_path / "workspace", tmp_path / "uds"
    workspace.mkdir()
    uds.mkdir()
    worker._workdir, worker._uds_dir = str(workspace), str(uds)
    reservation = Mock()
    worker._heap_reservation = reservation
    remove = server.rmtree_hardened
    held = getattr(worker, blocked)
    with monkeypatch.context() as fault:
        fault.setattr(
            server,
            "rmtree_hardened",
            lambda path: False if path == held else remove(path),
        )
        assert worker.stop() is False
        assert getattr(worker, blocked) == held
        other = "_uds_dir" if blocked == "_workdir" else "_workdir"
        assert getattr(worker, other) is None
        assert worker._heap_reservation is None
    assert worker.stop() is not False
    assert worker._workdir is None and worker._uds_dir is None
    reservation.release.assert_called_once()


def test_start_cannot_forget_pending_scratch_from_previous_boot(tmp_path, monkeypatch):
    worker = server.JoernServer()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "keep").write_text("pending")
    worker._workdir = str(workspace)
    allocation = Mock(side_effect=AssertionError("must not allocate another workspace"))
    with monkeypatch.context() as fault:
        fault.setattr(server, "rmtree_hardened", lambda path: False)
        fault.setattr(server, "_new_workspace", allocation)
        with pytest.raises(RuntimeError, match="cleanup is incomplete"):
            worker.start()
        assert worker._workdir == str(workspace)
        assert (workspace / "keep").read_text() == "pending"
        allocation.assert_not_called()
    worker.stop()
    assert not workspace.exists()


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_failed_live_boot_retains_heap_and_scratch_until_death_is_verified(
    tmp_path, monkeypatch, error
):
    monkeypatch.setattr("packages.joern.client.runtime_base", lambda: tmp_path)
    monkeypatch.setattr(server, "_repl_bridge_path", lambda: "joern")
    monkeypatch.setattr(server, "_server_auth_supported", lambda binary: True)
    monkeypatch.setattr(server, "sweep_stale_workspaces", lambda **kwargs: [])
    monkeypatch.setattr(server, "_jvm_gc_flags", lambda: [])
    monkeypatch.setattr(server, "_netns_isolation_available", lambda: False)
    monkeypatch.setattr(server, "_find_free_port", lambda: 12345)
    monkeypatch.setattr(server, "_private_java_command", lambda *args: ["joern"])
    monkeypatch.setattr("packages.joern.prereqs.joern_tool_paths", lambda: [])
    process = Mock(pid=2_000_000_000, returncode=0)
    patch_module_attribute(monkeypatch, server, 'subprocess', "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(server, "_signal_owned_group", lambda *args: None)
    reservation = Mock(granted_mb=64, pass_fds=())
    monkeypatch.setattr(server, "reserve_heap_mb", lambda *args, **kwargs: reservation)
    dead = False
    monkeypatch.setattr(server, "_managed_group_stopped", lambda *args: dead)
    failure = error("readiness failed")
    worker = server.JoernServer(heap_mb=64, confined=True)

    def fail():
        raise failure

    monkeypatch.setattr(worker, "_wait_for_ready", fail)
    try:
        with pytest.raises(error) as caught:
            worker.start()
        assert caught.value is failure
        assert worker._proc is process
        assert worker._heap_reservation is reservation
        assert worker._workdir and Path(worker._workdir).exists()
        reservation.release.assert_not_called()
    finally:
        dead = True
        worker.stop()
    assert worker._workdir is None
    reservation.release.assert_called_once()
