"""orchestrate()-level wiring test for the opt-in ranking stage.

Drives the real orchestrate() far enough to cross the ranking
insertion point, then exits deterministically via the blocked-CC
path (block_cc_dispatch=True, llm_config=None) — no model, no
subprocess. This pins the wiring contract: the stage runs only when
rank_findings=True, and it receives the FULL pre-cap findings list
(rank-then-spend requires ranking before the max_findings cut, which
sits between the ranking call and the dispatch exit we use here).
"""

from __future__ import annotations

import json

from packages.llm_analysis.orchestrator import orchestrate


def _write_prep_report(tmp_path, n=4):
    findings = [
        {"finding_id": f"f{i}", "file_path": "src/a.c",
         "start_line": i + 1, "rule_id": f"rule-{i}", "tool": "semgrep"}
        for i in range(n)
    ]
    path = tmp_path / "autonomous_analysis_report.json"
    path.write_text(json.dumps({"mode": "prep_only", "results": findings}))
    return path


def _quiet_preseeds(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "packages.llm_analysis.source_intel_inject.prepare_source_intel",
        lambda *a, **k: None,
    )
    monkeypatch.setattr(
        "packages.llm_analysis.flow_context_inject.prepare_flow_context",
        lambda *a, **k: None,
    )
    # Hermeticity: the scorecard ETA estimate reads
    # $RAPTOR_DIR/out/llm_scorecard.json; point it at an empty tree.
    monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))


def test_rank_stage_receives_full_precap_findings(
    monkeypatch, tmp_path, capsys,
):
    calls = {}

    def fake_rank(findings, llm_config, query=None):
        calls["ids"] = [f["finding_id"] for f in findings]
        return list(reversed(findings)), 0.02, "rank-model"

    _quiet_preseeds(monkeypatch, tmp_path)
    monkeypatch.setattr(
        "packages.llm_analysis.rank_stage.rank_findings_for_analysis",
        fake_rank,
    )
    report = _write_prep_report(tmp_path, n=4)
    result = orchestrate(
        prep_report_path=report,
        repo_path=tmp_path,
        out_dir=tmp_path,
        max_findings=2,          # cap sits AFTER the ranking call
        llm_config=None,
        block_cc_dispatch=True,  # deterministic exit after the stage
        rank_findings=True,
    )
    assert result is None
    # Anchor: the run exited via the intended blocked-CC path — i.e.
    # it got PAST the ranking insertion point and the cap, not out of
    # an earlier report-parse/empty-findings return.
    assert "CC dispatch blocked" in capsys.readouterr().err
    # The stage saw every finding, in input order, before the cap.
    assert calls["ids"] == ["f0", "f1", "f2", "f3"]


def test_rank_stage_not_invoked_by_default(monkeypatch, tmp_path, capsys):
    def fail_rank(*args, **kwargs):
        raise AssertionError("ranking stage must not run without opt-in")

    _quiet_preseeds(monkeypatch, tmp_path)
    monkeypatch.setattr(
        "packages.llm_analysis.rank_stage.rank_findings_for_analysis",
        fail_rank,
    )
    report = _write_prep_report(tmp_path, n=4)
    result = orchestrate(
        prep_report_path=report,
        repo_path=tmp_path,
        out_dir=tmp_path,
        llm_config=None,
        block_cc_dispatch=True,
    )
    assert result is None
    # Anchor: the run crossed the (skipped) insertion point and died
    # on the blocked-CC exit, not on an earlier degenerate return —
    # otherwise this test proves nothing about the opt-in gate.
    assert "CC dispatch blocked" in capsys.readouterr().err
