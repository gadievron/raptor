"""Tests for OSS forensics walkthrough reader."""

from __future__ import annotations

import json
from pathlib import Path

from packages.studio.services.forensics_reader import (
    is_forensics_run_dir,
    load_forensics_bundle,
)


def test_empty_dir(tmp_path: Path):
    bundle = load_forensics_bundle(tmp_path)
    assert not bundle.has_any


def test_is_forensics_run_dir_detects_evidence_or_report(tmp_path: Path):
    assert not is_forensics_run_dir(tmp_path)
    (tmp_path / "forensic-report.md").write_text("# Report")
    assert is_forensics_run_dir(tmp_path)


def test_load_full_forensics_bundle(tmp_path: Path):
    (tmp_path / "evidence.json").write_text(json.dumps({
        "research_question": "Who pushed commit X on 2026-04-12?",
        "github_api":   [{"commit": "abc"}, {"commit": "def"}],
        "gh_archive":   [{"event": "PushEvent"}],
        "wayback":      [{"url": "https://web.archive.org/..."}],
    }))
    (tmp_path / "evidence-verification-report.md").write_text("# Verification\nVerified.")
    (tmp_path / "hypothesis-001.md").write_text("# Hypothesis 1\nAttacker pushed via compromised token.")
    (tmp_path / "hypothesis-002-confirmed.md").write_text("# Hypothesis 2\nToken was committed to repo.")
    (tmp_path / "forensic-report.md").write_text("# Final Report\n\n## Timeline\n- 2026-04-12 push\n")

    bundle = load_forensics_bundle(tmp_path)
    assert bundle.has_any
    assert bundle.evidence["research_question"] == "Who pushed commit X on 2026-04-12?"
    assert bundle.evidence_verification.startswith("# Verification")
    assert bundle.forensic_report.startswith("# Final Report")
    assert len(bundle.hypotheses) == 2
    assert bundle.hypotheses[0].order == 1
    assert bundle.hypotheses[1].order == 2
    assert bundle.hypotheses[1].status == "confirmed"
    assert bundle.research_question.startswith("Who pushed")


def test_evidence_summary_counts_sources(tmp_path: Path):
    (tmp_path / "evidence.json").write_text(json.dumps({
        "github_api": [1, 2, 3, 4],
        "wayback":    [1, 2],
        "gh_archive": {"PushEvent": 3, "ForkEvent": 1},
    }))
    bundle = load_forensics_bundle(tmp_path)
    summary = dict(bundle.evidence_summary)
    assert summary["github_api"] == 4
    assert summary["wayback"] == 2
    assert summary["gh_archive"] == 2  # dict count


def test_hypothesis_status_detection(tmp_path: Path):
    (tmp_path / "hypothesis-001-rebuttal.md").write_text("# Rejected\nToken theft unlikely.")
    (tmp_path / "hypothesis-002.md").write_text("# New angle")
    (tmp_path / "hypothesis-003-confirmed.md").write_text("# Final")
    bundle = load_forensics_bundle(tmp_path)
    statuses = [h.status for h in bundle.hypotheses]
    assert statuses == ["rejected", "unknown", "confirmed"]


def test_research_question_falls_back_to_first_hypothesis(tmp_path: Path):
    (tmp_path / "hypothesis-001.md").write_text("# Question\nDid attacker have repo write access?")
    bundle = load_forensics_bundle(tmp_path)
    assert bundle.research_question == "Did attacker have repo write access?"


def test_malformed_evidence_json_ignored(tmp_path: Path):
    (tmp_path / "evidence.json").write_text("{not valid")
    (tmp_path / "forensic-report.md").write_text("# Report")
    bundle = load_forensics_bundle(tmp_path)
    assert bundle.evidence is None
    assert bundle.forensic_report == "# Report"
    assert bundle.has_any  # still has the report
