"""Graph and workspace retention must actually reclaim their bytes."""

import contextlib
import logging
import os
import time
from pathlib import Path
from types import SimpleNamespace
import pytest
from core.testing.restricted_tree import restricted_tree
from packages.joern import runner, client
from packages.joern.models import JoernCPG


@pytest.mark.parametrize("mode", [0o000, 0o500, 0o555])
@pytest.mark.parametrize("kind", ["slot", "build", "workspace", "orphan-query"])
def test_graph_cleanup_reclaims_restricted_copies(tmp_path, monkeypatch, mode, kind):
    prefix = runner._CPG_SLOT_TARGET_PREFIX
    name = {
        "slot": prefix + "old",
        "build": runner._CPG_BUILD_DIR_PREFIX + "old",
        "workspace": "workspace",
        "orphan-query": "raptor-query-old",
    }[kind]
    with restricted_tree(tmp_path / name, mode) as tree:
        os.utime(tree, (time.time() - 60 * 86400,) * 2)
        if kind == "slot":
            monkeypatch.setattr(runner, "_CPG_SCOPED_SLOTS_KEEP", 1)
            active = tmp_path / (prefix + "active")
            active.mkdir()
            runner._prune_cpg_slot_pool(
                tmp_path, prefix=prefix, active_slot=active.name
            )
            assert active.exists()
        elif kind == "build":
            runner._sweep_stale_cpg_build_dirs(tmp_path)
        else:
            graph = tmp_path / "cpg.bin"
            graph.write_bytes(b"graph")
            runner.cleanup_cpg(JoernCPG(path=graph, target=tmp_path))
        assert not tree.exists()


@pytest.mark.parametrize(
    "prefix_attr", ["_CPG_SLOT_TARGET_PREFIX", "_CPG_SLOT_SCOPED_PREFIX"]
)
def test_old_active_slot_counts_towards_pool_budget(tmp_path, monkeypatch, prefix_attr):
    prefix = getattr(runner, prefix_attr)
    monkeypatch.setattr(runner, "_CPG_SCOPED_SLOTS_KEEP", 2)
    slots = []
    for i in range(4):
        slot = tmp_path / (prefix + str(i))
        slot.mkdir()
        os.utime(slot, (i + 1,) * 2)
        slots.append(slot)
    runner._prune_cpg_slot_pool(tmp_path, prefix=prefix, active_slot=slots[0].name)
    assert slots[0].exists() and slots[-1].exists()
    assert sum(path.exists() for path in slots) == 2


@pytest.mark.parametrize("kind", ["slot", "build"])
def test_failed_removal_does_not_log_success(tmp_path, monkeypatch, caplog, kind):
    tree = tmp_path / (
        runner._CPG_SLOT_TARGET_PREFIX + "old"
        if kind == "slot"
        else runner._CPG_BUILD_DIR_PREFIX + "old"
    )
    tree.mkdir()
    os.utime(tree, (time.time() - 60 * 86400,) * 2)
    monkeypatch.setattr("shutil.rmtree", lambda *args, **kw: None)
    monkeypatch.setattr(runner, "_CPG_SCOPED_SLOTS_KEEP", 0)
    with caplog.at_level(logging.INFO, logger=runner.__name__):
        if kind == "slot":
            runner._prune_cpg_slot_pool(
                tmp_path, prefix=runner._CPG_SLOT_TARGET_PREFIX, active_slot="absent"
            )
        else:
            runner._sweep_stale_cpg_build_dirs(tmp_path)
    assert tree.exists()
    assert not any(
        "pruned stale" in message or "removed stale" in message
        for message in caplog.messages
    )


@pytest.mark.parametrize("mode", [0o000, 0o555])
def test_query_teardown_removes_restricted_workspace(tmp_path, monkeypatch, mode):
    graph = tmp_path / "cpg.bin"
    graph.write_bytes(b"graph")
    outputs = []
    monkeypatch.setattr(client, "runtime_base", lambda: tmp_path)
    monkeypatch.setattr(
        runner, "_jvm_scratch_command", lambda command, directory: command
    )
    with contextlib.ExitStack() as cleanup:

        def run(command, **kwargs):
            out = Path(kwargs["output"])
            cleanup.enter_context(restricted_tree(out, mode))
            outputs.append(out)
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        result = runner._run_query_admitted(
            JoernCPG(path=graph, target=tmp_path),
            "cpg.method.l",
            subprocess_runner=run,
            heap_mb=256,
        )
        assert not result.errors
        assert outputs and all(not path.exists() for path in outputs)
        assert graph.read_bytes() == b"graph"
