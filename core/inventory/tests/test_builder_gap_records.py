"""Inventory builder plumbing for analysis-gap records."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.inventory import builder
from core.run import gaps


@pytest.fixture(autouse=True)
def _fresh_gap_state(monkeypatch):
    monkeypatch.setattr(gaps, "_gap_count", 0)
    monkeypatch.setattr(gaps, "_pending", [])


def test_worker_wrapper_carries_pending_gaps(monkeypatch, tmp_path):
    import core.sandbox.summary as summary
    monkeypatch.setattr(summary, "_active_run_dir", None)

    def fake_process(filepath: Path, *args):
        gaps.record_analysis_gap(
            file_path="src/evil.js", reason="parser budget exceeded",
            tool="tree-sitter",
        )
        return {"path": "src/evil.js", "items": []}

    monkeypatch.setattr(builder, "_process_single_file", fake_process)
    result = builder._process_one_with_gap_context(
        tmp_path / "src" / "evil.js", tmp_path,
    )
    assert result is not None
    carried = result["_analysis_gaps"]
    assert len(carried) == 1
    assert carried[0]["reason"] == "parser budget exceeded"


def test_worker_wrapper_sets_relative_parse_origin(monkeypatch, tmp_path):
    seen: dict[str, object] = {}

    def fake_process(filepath: Path, *args):
        seen["origin"] = gaps.current_parse_origin()
        return None

    monkeypatch.setattr(builder, "_process_single_file", fake_process)
    result = builder._process_one_with_gap_context(
        tmp_path / "pkg" / "a.js", tmp_path,
    )
    assert seen["origin"] == str(Path("pkg") / "a.js")
    # No gaps recorded: a None result stays None.
    assert result is None


def test_worker_wrapper_gaps_only_result(monkeypatch, tmp_path):
    import core.sandbox.summary as summary
    monkeypatch.setattr(summary, "_active_run_dir", None)

    def fake_process(filepath: Path, *args):
        gaps.record_analysis_gap(
            file_path="x.js", reason="parser budget exceeded",
            tool="tree-sitter",
        )
        return None

    monkeypatch.setattr(builder, "_process_single_file", fake_process)
    result = builder._process_one_with_gap_context(
        tmp_path / "x.js", tmp_path,
    )
    assert result is not None
    assert result["_gaps_only"] is True
    assert len(result["_analysis_gaps"]) == 1


def test_build_inventory_persists_hostile_file_gap(monkeypatch, tmp_path):
    """End-to-end: a tree salted with the crafted JS file yields a
    durable gap record in the active run dir — never a silent skip."""
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_javascript")
    import core.sandbox.summary as summary

    from .test_bounded_parse import HOSTILE_JS

    target = tmp_path / "repo"
    target.mkdir()
    (target / "ok.py").write_text("def fine():\n    return 1\n")
    (target / "evil.js").write_text(HOSTILE_JS)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    monkeypatch.setattr(summary, "_active_run_dir", run_dir)
    monkeypatch.setenv("RAPTOR_TS_PARSE_BUDGET_S", "0.5")

    out = tmp_path / "out"
    result = builder.build_inventory(
        str(target), output_dir=str(out), parallel=False,
    )
    assert result is not None
    records = gaps.load_gaps(run_dir)
    assert any(
        "evil.js" in r["file_path"]
        and r["reason"] == "parser budget exceeded"
        for r in records
    ), records
