"""Tests for the sound-tier barrier synthesis loop (stubbed proposer + runner)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.dataflow.barrier_synth import (
    BarrierProposal,
    assemble_barrier_query,
    run_synthesis_loop,
)

_GUARD = (
    "predicate proposedGuard(DataFlow::GuardNode g, ControlFlowNode node, boolean branch) {\n"
    '  exists(DataFlow::CallCfgNode c |\n'
    '    c.getFunction().asExpr().(Name).getId() = "host_is_allowed" and\n'
    "    g = c.asCfgNode() and node = c.getArg(0).asCfgNode() and branch = true) }"
)


def _proposer(_proposal) -> str:
    return _GUARD


def _stub_runner(counts_by_db: dict):
    """codeql stand-in: writes a SARIF with N results for the queried db."""
    def run(cmd, **kwargs):
        db = cmd[3]  # codeql database analyze <db> ...
        out = next(a.split("=", 1)[1] for a in cmd if a.startswith("--output="))
        n = counts_by_db[db]
        results = [{"ruleId": "x", "message": {"text": "m"}} for _ in range(n)]
        Path(out).write_text(json.dumps({"runs": [{"results": results}]}))
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    return run


def _proposal() -> BarrierProposal:
    return BarrierProposal(sink_class="cmdi", finding_id="F1",
                           sink_snippet="os.system(...)", source_context="...")


# --- assembly (pure) ---

def test_assemble_wires_guard_and_stock_source_sink():
    q = assemble_barrier_query(_GUARD, sink_class="cmdi", query_id="raptor/x")
    assert "CommandInjection::Source" in q
    assert "CommandInjection::Sink" in q
    assert "BarrierGuard<proposedGuard/3>" in q
    assert "proposedGuard" in q


def test_assemble_rejects_unknown_sink_class():
    with pytest.raises(ValueError):
        assemble_barrier_query(_GUARD, sink_class="nosuch", query_id="x")


def test_assemble_rejects_proposal_without_guard():
    with pytest.raises(ValueError):
        assemble_barrier_query("predicate other() { any() }", sink_class="cmdi", query_id="x")


# --- the loop (stubbed proposer + runner) ---

def test_loop_sound_when_fp_suppressed_and_tp_preserved(tmp_path: Path):
    after_db, before_db = tmp_path / "adb", tmp_path / "bdb"
    runner = _stub_runner({str(after_db): 0, str(before_db): 1})
    res = run_synthesis_loop(
        _proposal(), after_db, before_db,
        proposer=_proposer, work_dir=tmp_path / "work", runner=runner,
    )
    assert res.after_count == 0 and res.before_count == 1
    assert res.suppressed_fp and res.preserved_tp and res.is_sound
    assert "BarrierGuard<proposedGuard/3>" in res.query_ql


def test_loop_rejects_overbroad_barrier_that_kills_the_tp(tmp_path: Path):
    # Barrier suppresses BOTH dbs -> it also killed the real TP -> unsound.
    after_db, before_db = tmp_path / "adb", tmp_path / "bdb"
    runner = _stub_runner({str(after_db): 0, str(before_db): 0})
    res = run_synthesis_loop(
        _proposal(), after_db, before_db,
        proposer=_proposer, work_dir=tmp_path / "work", runner=runner,
    )
    assert res.suppressed_fp        # killed the FP
    assert not res.preserved_tp     # but also killed the TP
    assert not res.is_sound         # -> rejected by the soundness check


def test_loop_rejects_barrier_that_does_not_suppress(tmp_path: Path):
    # Barrier changes nothing -> FP still flagged -> not useful.
    after_db, before_db = tmp_path / "adb", tmp_path / "bdb"
    runner = _stub_runner({str(after_db): 1, str(before_db): 1})
    res = run_synthesis_loop(
        _proposal(), after_db, before_db,
        proposer=_proposer, work_dir=tmp_path / "work", runner=runner,
    )
    assert not res.suppressed_fp
    assert not res.is_sound
