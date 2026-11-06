"""Graph scratch is owned across setup, use, failure, and final teardown."""

import json
import logging
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace

import pytest

from core.atomic_fs import rmtree_hardened
from core.run import scratch, tmp_reaper
import packages.joern as joern
from packages.joern import artifacts, client, runner
from packages.joern.models import JoernCPG
from packages.joern.tunables import JoernTunables


def _graph_bytes(methods=1):
    return b"FLATGRAPH" + json.dumps({"version": 1, "nodes": [{"nodeLabel": "METHOD", "nnodes": methods}]}).encode()


@pytest.fixture
def owned(tmp_path, monkeypatch, caplog, _isolated_graph_keepalive):
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.c").write_text("int f(void) { return 0; }\n")
    source = tmp_path / "input.bin"
    source.write_bytes(_graph_bytes())
    monkeypatch.setenv("RAPTOR_REGISTRY_HOME", str(tmp_path / "state"))
    monkeypatch.setattr(client, "runtime_base", lambda: runtime)
    monkeypatch.setattr(runner, "_joern_parse_path", lambda: "joern-parse-owned")
    monkeypatch.setattr(runner, "_joern_path", lambda: "joern-owned")
    monkeypatch.setattr(runner, "joern_tool_paths", lambda: [])
    monkeypatch.setattr(runner, "_jvm_scratch_command", lambda command, directory: command)
    monkeypatch.setattr(artifacts, "toolchain_identity", lambda: "owned-tools")
    logger = logging.getLogger("test.graph-scratch-owned")
    monkeypatch.setattr(logger, "handlers", [caplog.handler])
    monkeypatch.setattr(logger, "propagate", False)
    monkeypatch.setattr(joern, "_logger", logger)
    for module in (runner, artifacts, scratch):
        monkeypatch.setattr(module, "logger", logger)
    allocated = []
    def allocate(**kwargs):
        path = Path(tempfile.mkdtemp(**kwargs))
        allocated.append(path)
        return str(path)
    monkeypatch.setattr(runner, "tempfile", SimpleNamespace(mkdtemp=allocate))
    state = {"error": None, "returncode": 0, "bytes": _graph_bytes(), "delete": False}
    def execute(command, **kwargs):
        root = Path(kwargs.get("output", kwargs.get("cwd")))
        locked = root / "workspace/locked"
        locked.mkdir(parents=True)
        (locked / "copy.bin").write_bytes(b"private JVM copy")
        locked.chmod(0)
        (root / "java-dump.hprof").write_bytes(b"JVM scratch")
        if "--output" in command:
            output = Path(command[command.index("--output") + 1])
            output.write_bytes(state["bytes"])
            if state["delete"]:
                output.unlink()
        if state["error"]:
            raise state["error"]
        return SimpleNamespace(returncode=state["returncode"], stdout="", stderr="")
    monkeypatch.setattr(runner, "_default_sandbox_runner", lambda: execute)
    try:
        yield SimpleNamespace(runtime=runtime, target=target, source=source, allocated=allocated,
                              pins=_isolated_graph_keepalive, state=state, execute=execute,
                              graph=JoernCPG(source, target), cache=tmp_path / "cache")
    finally:
        # Fault cases deliberately retain a tree for retry/identity assertions.
        assert rmtree_hardened(runtime)
        assert rmtree_hardened(tmp_path / "cache")


def _build(owned, **kwargs):
    return runner.build_cpg(owned.target, heap_mb=64, **kwargs)


def _query(owned, **kwargs):
    return runner.run_query(owned.graph, "cpg.method.l", heap_mb=64, **kwargs)


@pytest.mark.parametrize("phase", ["registration", "frontend", "command", "factory", "progress", "dispatch"])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_automatic_build_reclaims_setup_and_execution_failures(owned, monkeypatch, phase, error):
    failure = error("build stopped")
    def fail(*args, **kwargs):
        raise failure
    if phase == "registration":
        register = runner.keepalive_register
        def register_then_fail(path):
            register(path)
            raise failure
        monkeypatch.setattr(runner, "keepalive_register", register_then_fail)
    elif phase == "frontend":
        monkeypatch.setattr(runner, "discover_frontend_args", fail)
    elif phase == "command":
        monkeypatch.setattr(runner, "_jvm_scratch_command", fail)
    elif phase == "factory":
        monkeypatch.setattr(runner, "_default_sandbox_runner", fail)
    elif phase == "dispatch":
        owned.state["error"] = failure
    with pytest.raises(error) as caught:
        _build(owned, languages={"c"}, on_progress=fail if phase == "progress" else None)
    assert caught.value is failure
    assert owned.allocated
    assert not list(owned.runtime.iterdir())
    assert not owned.pins


@pytest.mark.parametrize("failure", ["timeout", "spawn", "nonzero", "empty", "missing"])
def test_automatic_failed_build_reclaims_all_jvm_scratch(owned, failure):
    if failure == "timeout":
        owned.state["error"] = subprocess.TimeoutExpired("joern-owned", 1)
    elif failure == "spawn":
        owned.state["error"] = OSError("spawn stopped")
    elif failure == "nonzero":
        owned.state["returncode"] = 1
    elif failure == "empty":
        owned.state["bytes"] = _graph_bytes(0)
    else:
        owned.state["delete"] = True
    graph = _build(owned)
    assert graph.build_failed or not graph.exists()
    assert graph.owned_dir is not None
    assert not graph.owned_dir.exists()
    assert graph.owned_dir_identity is None
    assert not owned.pins
    runner.cleanup_cpg(graph)


@pytest.mark.parametrize("missing", [False, True])
def test_successful_build_transfers_entire_tree_until_explicit_cleanup(owned, missing):
    graph = _build(owned)
    root = graph.path.parent
    assert graph.owned_dir == root and root.exists()
    assert owned.pins == {str(root)}
    if missing:
        graph.path.unlink()
    runner.cleanup_cpg(graph)
    assert not root.exists()
    assert not owned.pins
    runner.cleanup_cpg(graph)


def test_caller_output_directory_is_not_claimed(owned, tmp_path):
    output = tmp_path / "caller-output"
    output.mkdir()
    marker = output / "operator.txt"
    marker.write_text("operator data")
    graph = _build(owned, output_dir=output)
    assert graph.owned_dir is None
    runner.cleanup_cpg(graph)
    assert marker.read_text() == "operator data"
    assert (output / "java-dump.hprof").exists()
    assert not owned.pins
    assert rmtree_hardened(output)


@pytest.mark.parametrize("phase", ["registration", "pin", "wrapper", "write", "command", "factory", "dispatch"])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_query_setup_and_execution_always_release_private_graphs(owned, monkeypatch, phase, error):
    failure = error("query stopped")
    def fail(*args, **kwargs):
        raise failure
    if phase == "registration":
        register = runner.keepalive_register
        def register_then_fail(path):
            register(path)
            raise failure
        monkeypatch.setattr(runner, "keepalive_register", register_then_fail)
    elif phase == "pin":
        frozen = artifacts.FrozenGraph
        class FailAfterCopy(frozen):
            @classmethod
            def copy(cls, *args, **kwargs):
                super().copy(*args, **kwargs)
                raise failure
        monkeypatch.setattr(artifacts, "FrozenGraph", FailAfterCopy)
    elif phase == "wrapper":
        monkeypatch.setattr(runner, "_escape_scala_string", fail)
    elif phase == "write":
        class FailingPath(type(owned.runtime)):
            def write_text(self, *args, **kwargs):
                if self.name == "query.sc":
                    raise failure
                return super().write_text(*args, **kwargs)
        monkeypatch.setattr(runner, "Path", FailingPath)
    elif phase == "command":
        monkeypatch.setattr(runner, "_jvm_scratch_command", fail)
    elif phase == "factory":
        monkeypatch.setattr(runner, "_default_sandbox_runner", fail)
    else:
        owned.state["error"] = failure
    with pytest.raises(error) as caught:
        _query(owned)
    assert caught.value is failure
    assert not list(owned.runtime.iterdir())
    assert not owned.pins
    assert owned.source.read_bytes() == _graph_bytes()


@pytest.mark.parametrize("failure", ["timeout", "spawn", "nonzero", "success"])
def test_query_exit_removes_graph_workspace_and_jvm_scratch(owned, failure):
    if failure == "timeout":
        owned.state["error"] = subprocess.TimeoutExpired("joern-owned", 1)
    elif failure == "spawn":
        owned.state["error"] = OSError("spawn stopped")
    elif failure == "nonzero":
        owned.state["returncode"] = 1
    result = _query(owned)
    assert result.ok == (failure == "success")
    assert not list(owned.runtime.iterdir())
    assert not owned.pins


@pytest.mark.parametrize("operation", ["build", "query"])
@pytest.mark.parametrize("teardown", ["unregister", "remove"])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_secondary_cleanup_cancellation_preserves_primary_failure(owned, monkeypatch, operation, teardown, error):
    failure = error("primary failure")
    owned.state["error"] = failure
    unregister = runner.keepalive_unregister
    def drop(path):
        unregister(path)
        raise KeyboardInterrupt("secondary interruption")
    def remove(path):
        raise KeyboardInterrupt("secondary interruption")
    monkeypatch.setattr(runner, "keepalive_unregister" if teardown == "unregister" else "rmtree_hardened",
                        drop if teardown == "unregister" else remove)
    with pytest.raises(error) as caught:
        (_build if operation == "build" else _query)(owned)
    assert caught.value is failure
    assert not owned.pins
    if teardown == "unregister":
        assert not list(owned.runtime.iterdir())


def test_cleanup_retry_reclaims_owned_tree_even_when_graph_is_missing(owned, monkeypatch, caplog):
    graph = _build(owned)
    graph.path.unlink()
    with monkeypatch.context() as fault:
        fault.setattr(runner, "rmtree_hardened", lambda path: False)
        runner.cleanup_cpg(graph)
    assert graph.owned_dir.exists()
    assert "retained after failed removal" in caplog.text
    assert not owned.pins
    runner.cleanup_cpg(graph)
    assert not graph.owned_dir.exists()


@pytest.mark.parametrize("replacement", ["symlink", "directory"])
def test_replaced_owned_root_is_preserved(owned, tmp_path, replacement):
    graph = _build(owned)
    root = graph.owned_dir
    parked = owned.runtime / "parked"
    root.rename(parked)
    outside = tmp_path / "operator"
    outside.mkdir()
    (outside / "keep").write_text("operator data")
    if replacement == "symlink":
        root.symlink_to(outside, target_is_directory=True)
    else:
        root.mkdir()
        (root / "keep").write_text("replacement data")
    runner.cleanup_cpg(graph)
    assert not owned.pins
    assert (outside / "keep").read_text() == "operator data"
    if replacement == "directory":
        assert (root / "keep").read_text() == "replacement data"
    else:
        assert root.is_symlink()


def test_frozen_graph_teardown_interruption_does_not_mask_copy_error(owned, monkeypatch):
    failure = RuntimeError("construction failed")
    class FailedGraph(artifacts.FrozenGraph):
        def __init__(self, *args):
            raise failure
    def remove(path):
        raise KeyboardInterrupt("secondary copy cleanup interruption")
    monkeypatch.setattr(artifacts, "FrozenGraph", FailedGraph)
    monkeypatch.setattr(artifacts, "rmtree_hardened", remove)
    with pytest.raises(RuntimeError) as caught:
        _query(owned)
    assert caught.value is failure
    assert not list(owned.runtime.iterdir())
    assert not owned.pins


@pytest.mark.parametrize("kind", ["uncached", "cache-fallback", "cache-hit"])
@pytest.mark.parametrize("stop_failed", [False, True])
@pytest.mark.parametrize("body_error", [None, RuntimeError, KeyboardInterrupt])
def test_session_releases_disposable_graphs_even_if_worker_stop_fails(owned, monkeypatch, kind, stop_failed, body_error):
    if kind == "cache-hit":
        graph = runner.build_cpg_cached(owned.target, owned.cache, subprocess_runner=owned.execute, heap_mb=64)
        assert graph.owned_dir is None
    elif kind == "cache-fallback":
        owned.state["bytes"] = b"unrecognised graph format"
        graph = runner.build_cpg_cached(owned.target, owned.cache, subprocess_runner=owned.execute, heap_mb=64)
        assert graph.owned_dir is not None
    else:
        graph = _build(owned)
    monkeypatch.setattr(joern, "is_available", lambda: True)
    monkeypatch.setattr(joern, "build_cpg", lambda *args, **kwargs: graph)
    monkeypatch.setattr(joern, "build_cpg_cached", lambda *args, **kwargs: graph)
    monkeypatch.setattr(client.GraphClient, "bind_graph", lambda self, graph, **kwargs: True)
    stop = client.GraphClient.stop
    def stop_then_fail(self):
        stop(self)
        raise RuntimeError("worker stop failed")
    if stop_failed:
        monkeypatch.setattr(client.GraphClient, "stop", stop_then_fail)
    original = body_error("session body stopped") if body_error else None
    def session():
        with joern.joern_session(owned.target, cache_dir=None if kind == "uncached" else owned.cache,
                               tunables=JoernTunables(heap_mb=64), register_reach_audit=False) as worker:
            assert isinstance(worker, client.GraphClient)
            if original is not None:
                raise original
    if original is not None:
        with pytest.raises(body_error) as caught:
            session()
        assert caught.value is original
    elif stop_failed:
        with pytest.raises(RuntimeError, match="worker stop failed"):
            session()
    else:
        session()
    assert not owned.pins
    assert graph.exists() == (kind == "cache-hit")
    if kind != "cache-hit":
        assert not graph.owned_dir.exists()


def test_graph_client_import_releases_missing_graph_output(owned, monkeypatch):
    graph = _build(owned)
    graph.path.unlink()
    monkeypatch.setattr(runner, "build_cpg", lambda *args, **kwargs: graph)
    worker = client.GraphClient(tunables=JoernTunables(heap_mb=64), heap_mb=64)
    try:
        assert worker.import_code(owned.target) is False
    finally:
        worker.stop()
    assert not graph.owned_dir.exists()
    assert not owned.pins


def test_query_scratch_prefix_has_crash_reaping_and_live_keepalive(owned, monkeypatch):
    monkeypatch.setattr(tmp_reaper, "_sweep_roots", lambda: [(owned.runtime, False)])
    monkeypatch.setattr(tmp_reaper, "_live_cwds", lambda: set())
    monkeypatch.setenv("RAPTOR_TMP_REAP_MAX_AGE_H", "1")
    old = 1_000_000
    now = old + 7200
    def execute(command, **kwargs):
        root = Path(kwargs["output"])
        for path in [*root.rglob("*"), root]:
            os.utime(path, (old, old))
        assert str(root) in owned.pins
        # Refresh a live owner's mtime, then run a sweep confined to this test.
        scratch._keepalive_tick()
        assert tmp_reaper.reap_stale_tmp(now=now) == []
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    assert _query(owned, subprocess_runner=execute).ok
    orphan = owned.runtime / "raptor-query-abandoned"
    orphan.mkdir()
    (orphan / "copy.bin").write_bytes(b"dead owner graph")
    for path in (orphan / "copy.bin", orphan):
        os.utime(path, (old, old))
    assert tmp_reaper.reap_stale_tmp(now=now) == [orphan]
    assert not orphan.exists()


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_reach_registration_reset_failure_cannot_skip_worker_and_graph_cleanup(owned, monkeypatch, error):
    from core.analysis import reach_audit
    graph = _build(owned)
    monkeypatch.setattr(joern, "is_available", lambda: True)
    monkeypatch.setattr(joern, "build_cpg", lambda *args, **kwargs: graph)
    monkeypatch.setattr(client.GraphClient, "bind_graph", lambda *args, **kwargs: True)
    token = object()
    monkeypatch.setattr(reach_audit, "set_joern_server", lambda server: token)
    events = []
    failure = error("reach reset stopped")
    def reset(value):
        assert value is token
        events.append("reset")
        raise failure
    stop = client.GraphClient.stop
    def stop_worker(self):
        events.append("stop")
        stop(self)
    monkeypatch.setattr(reach_audit, "reset_joern_server", reset)
    monkeypatch.setattr(client.GraphClient, "stop", stop_worker)
    with pytest.raises(error) as caught:
        with joern.joern_session(owned.target, tunables=JoernTunables(heap_mb=64)):
            pass
    assert caught.value is failure
    assert events[:2] == ["reset", "stop"]
    assert not graph.owned_dir.exists()
    assert not owned.pins


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_client_bind_failure_releases_import_scratch(owned, monkeypatch, error):
    graph = _build(owned)
    monkeypatch.setattr(runner, "build_cpg", lambda *args, **kwargs: graph)
    failure = error("binding stopped")
    def bind(*args, **kwargs):
        raise failure
    monkeypatch.setattr(client.GraphClient, "bind_graph", bind)
    worker = client.GraphClient(tunables=JoernTunables(heap_mb=64), heap_mb=64)
    try:
        with pytest.raises(error) as caught:
            worker.import_code(owned.target)
        assert caught.value is failure
    finally:
        worker.stop()
    assert not graph.owned_dir.exists()
    assert not owned.pins



def test_repeated_cleanup_does_not_adopt_a_reused_path(owned):
    graph = _build(owned)
    root = graph.owned_dir
    runner.cleanup_cpg(graph)
    assert graph.owned_dir_identity is None
    root.mkdir()
    (root / "cpg.bin").write_bytes(b"replacement graph")
    runner.cleanup_cpg(graph)
    assert (root / "cpg.bin").read_bytes() == b"replacement graph"


def test_relative_cache_fallback_keeps_absolute_ownership_after_chdir(owned, monkeypatch, tmp_path):
    monkeypatch.chdir(owned.cache.parent)
    owned.state["bytes"] = b"unrecognised graph format"
    graph = runner.build_cpg_cached(owned.target, Path(owned.cache.name),
                                    subprocess_runner=owned.execute, heap_mb=64)
    try:
        assert graph.owned_dir.is_absolute()
        assert str(graph.owned_dir) in owned.pins
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)
    finally:
        runner.cleanup_cpg(graph)
    assert not graph.owned_dir.exists()
    assert not owned.pins
