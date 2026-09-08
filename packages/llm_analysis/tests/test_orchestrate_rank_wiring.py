"""orchestrate()-level wiring test for the opt-in ranking stage.

Drives the real orchestrate() far enough to cross the ranking insertion
point, then exits deterministically when the mocked external client is
constructed. This pins the wiring contract: the stage runs only when
rank_findings=True, and it receives the FULL pre-cap findings list.
"""

from __future__ import annotations

import json

import pytest

from core.llm.config import LLMConfig, ModelConfig
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


def _external_config():
    return LLMConfig(
        primary_model=ModelConfig(
            provider="anthropic",
            model_name="test-ranking-model",
            max_context=32_000,
        ),
        fallback_models=[],
        specialized_models={},
    )


def test_rank_stage_receives_full_precap_findings(
    monkeypatch, tmp_path,
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
    monkeypatch.setattr(
        "core.llm.client.LLMClient",
        lambda config: (_ for _ in ()).throw(
            RuntimeError("stop after ranking"),
        ),
    )
    report = _write_prep_report(tmp_path, n=4)
    with pytest.raises(RuntimeError, match="stop after ranking"):
        orchestrate(
            prep_report_path=report,
            repo_path=tmp_path,
            out_dir=tmp_path,
            max_findings=2,          # cap sits AFTER the ranking call
            llm_config=_external_config(),
            rank_findings=True,
        )
    # The stage saw every finding, in input order, before the cap.
    assert calls["ids"] == ["f0", "f1", "f2", "f3"]


def test_rank_stage_not_invoked_by_default(monkeypatch, tmp_path):
    def fail_rank(*args, **kwargs):
        raise AssertionError("ranking stage must not run without opt-in")

    _quiet_preseeds(monkeypatch, tmp_path)
    monkeypatch.setattr(
        "packages.llm_analysis.rank_stage.rank_findings_for_analysis",
        fail_rank,
    )
    monkeypatch.setattr(
        "core.llm.client.LLMClient",
        lambda config: (_ for _ in ()).throw(
            RuntimeError("stop after skipped ranking stage"),
        ),
    )
    report = _write_prep_report(tmp_path, n=4)
    with pytest.raises(RuntimeError, match="skipped ranking stage"):
        orchestrate(
            prep_report_path=report,
            repo_path=tmp_path,
            out_dir=tmp_path,
            llm_config=_external_config(),
        )
