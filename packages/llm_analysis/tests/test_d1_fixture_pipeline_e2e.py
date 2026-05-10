"""End-to-end tests for the D-1 fixture-detection wire-in across
both pipelines.

These tests drive the full process_findings flow with fixture-
detection-eligible findings and assert:

  * Pre-flight verdicts ride through to the synthetic
    ``vuln.analysis``.
  * The high-confidence ``true`` case skips ``analyze_vulnerability``
    (no LLM call, no exploit/patch attempts).
  * ``candidate`` and ``false`` outcomes don't skip — the LLM
    pass runs normally.
  * ``manual_override`` bypasses the pre-flight entirely.
  * Telemetry counts in ``autonomous_analysis_report.json``
    reflect the per-finding outcomes.
  * Annotations emitted by the pre-flight skip path land with
    ``status=clean`` (via the existing ``_derive_status`` mapping
    on ``is_true_positive: false``).

Cross-pipeline consistency is exercised by reusing the same
finding shape against /validate's helper prep (separate test
module already covers /validate-side correctness; this one
focuses on /agentic).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from core.annotations import read_annotation
from packages.llm_analysis.agent import (
    AutonomousSecurityAgentV2,
    VulnerabilityContext,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def repo(tmp_path):
    """Minimal repo with prod and test source files."""
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "tests").mkdir()
    (repo / "src" / "api.py").write_text(
        "def save_upload(req):\n    return open(req.path, 'wb')\n"
    )
    (repo / "tests" / "conftest.py").write_text(
        "def setup_user(req):\n    return {'token': 'fake'}\n"
    )
    return repo


@pytest.fixture
def agent(tmp_path, repo):
    """An agent in prep_only mode — no LLM dispatcher needed."""
    out = tmp_path / "out"
    return AutonomousSecurityAgentV2(
        repo_path=repo, out_dir=out, prep_only=True,
    )


@pytest.fixture
def checklist(repo):
    """Realistic inventory: production file calls a function in src/api.py;
    tests/conftest.py is also indexed but no production code calls
    setup_user."""
    return {
        "target_path": str(repo),
        "files": [
            {
                "path": "src/api.py",
                "items": [{
                    "name": "save_upload",
                    "line_start": 1, "line_end": 2,
                }],
            },
            {
                "path": "tests/conftest.py",
                "items": [{
                    "name": "setup_user",
                    "line_start": 1, "line_end": 2,
                }],
            },
        ],
    }


def _finding(file_path, function, fid="F-1", **extras):
    """Construct a SARIF-shaped finding for process_findings."""
    f = {
        "finding_id": fid,
        "rule_id": "py/path-traversal",
        "file": file_path,
        "file_path": file_path,
        "function": function,
        "startLine": 1,
        "endLine": 2,
        "snippet": "open(req.path, 'wb')",
        "message": "Path traversal in upload",
        "level": "warning",
        "cwe_id": "CWE-22",
        "tool": "semgrep",
        "has_dataflow": False,
    }
    f.update(extras)
    return f


# ---------------------------------------------------------------------------
# Pre-flight skip — high-confidence ``true`` case
# ---------------------------------------------------------------------------


class TestPreflightSkipsLLMOnTrueVerdict:
    def test_fixture_finding_skips_analyze_vulnerability(
        self, agent, checklist, repo, tmp_path,
    ):
        """A finding in tests/conftest.py with no production caller —
        pre-flight returns ``true``, agent skips analyze_vulnerability,
        synthesises a deterministic clean analysis, emits annotation."""
        finding = _finding("tests/conftest.py", "setup_user", fid="F-FIX")
        # findings.json input
        findings_in = tmp_path / "findings_in.json"
        findings_in.write_text(json.dumps([finding]))

        # Mock parse_sarif_findings to return our finding without
        # touching SARIF; mock analyze_vulnerability to ASSERT it
        # isn't called.
        with patch.object(
            AutonomousSecurityAgentV2,
            "_load_validated_findings",
            return_value=[finding],
        ), patch.object(
            AutonomousSecurityAgentV2,
            "analyze_vulnerability",
        ) as mock_analyze:
            mock_analyze.side_effect = AssertionError(
                "analyze_vulnerability should NOT have been called",
            )
            report = agent.process_findings(
                findings_path=str(findings_in),
                max_findings=10,
                checklist=checklist,
                emit_annotations=True,
            )

        # Telemetry fields populated.
        assert report["fixture_detection_metrics"]["skipped_llm_calls"] == 1
        assert report["fixture_detection_metrics"]["prep_outcomes"][
            "true"
        ] == 1
        # Annotation written with status=clean (via _derive_status
        # on synthetic is_true_positive=False).
        ann_dir = agent.out_dir / "annotations"
        ann = read_annotation(ann_dir, "tests/conftest.py", "setup_user")
        assert ann is not None
        assert ann.metadata.get("status") == "clean"
        # Body cites the harness reasoning.
        assert "Test-harness circularity" in ann.body


class TestPreflightDoesNotSkipOnFalseVerdict:
    def test_production_finding_runs_llm(
        self, agent, checklist, repo, tmp_path,
    ):
        """A finding in src/api.py — pre-flight returns ``false``,
        analyze_vulnerability is called normally."""
        finding = _finding("src/api.py", "save_upload", fid="F-PROD")
        findings_in = tmp_path / "findings_in.json"
        findings_in.write_text(json.dumps([finding]))

        with patch.object(
            AutonomousSecurityAgentV2,
            "_load_validated_findings",
            return_value=[finding],
        ), patch.object(
            AutonomousSecurityAgentV2,
            "analyze_vulnerability",
            return_value=False,  # LLM ran but ruled out
        ) as mock_analyze:
            report = agent.process_findings(
                findings_path=str(findings_in),
                max_findings=10,
                checklist=checklist,
                emit_annotations=False,
            )

        mock_analyze.assert_called_once()
        assert report["fixture_detection_metrics"]["skipped_llm_calls"] == 0
        assert report["fixture_detection_metrics"]["prep_outcomes"][
            "false"
        ] == 1


class TestPreflightDoesNotSkipOnCandidateVerdict:
    def test_candidate_verdict_runs_llm(
        self, agent, repo, tmp_path,
    ):
        """A fixture-path finding without inventory — pre-flight
        returns ``candidate``, LLM still runs (verifies the
        uncertain case)."""
        finding = _finding("tests/conftest.py", "setup_user", fid="F-CAND")
        findings_in = tmp_path / "findings_in.json"
        findings_in.write_text(json.dumps([finding]))

        with patch.object(
            AutonomousSecurityAgentV2,
            "_load_validated_findings",
            return_value=[finding],
        ), patch.object(
            AutonomousSecurityAgentV2,
            "analyze_vulnerability",
            return_value=False,
        ) as mock_analyze:
            # No checklist passed → fixture_detection falls to
            # ``candidate``.
            report = agent.process_findings(
                findings_path=str(findings_in),
                max_findings=10,
                checklist=None,
                emit_annotations=False,
            )

        # LLM was called (no skip on candidate).
        # process_findings short-circuits the pre-flight when
        # checklist=None, so prep_outcomes are all zero — the
        # finding still flows through to analyze_vulnerability.
        mock_analyze.assert_called_once()
        assert report["fixture_detection_metrics"]["skipped_llm_calls"] == 0


class TestManualOverrideBypassesPreflight:
    def test_manual_override_skips_fixture_detection_entirely(
        self, agent, checklist, repo, tmp_path,
    ):
        """manual_override=True on the finding bypasses the pre-
        flight; the LLM analysis runs normally even when path +
        reachability would have triggered ``true``."""
        finding = _finding(
            "tests/conftest.py", "setup_user",
            fid="F-OVERRIDE",
            manual_override=True,
            manual_override_reason=(
                "Operator: this fixture is also exposed via debug "
                "endpoint in prod under DEBUG=1"
            ),
        )
        findings_in = tmp_path / "findings_in.json"
        findings_in.write_text(json.dumps([finding]))

        with patch.object(
            AutonomousSecurityAgentV2,
            "_load_validated_findings",
            return_value=[finding],
        ), patch.object(
            AutonomousSecurityAgentV2,
            "analyze_vulnerability",
            return_value=False,
        ) as mock_analyze:
            report = agent.process_findings(
                findings_path=str(findings_in),
                max_findings=10,
                checklist=checklist,
                emit_annotations=False,
            )

        mock_analyze.assert_called_once()
        # Pre-flight did not record an outcome (it was bypassed).
        assert report["fixture_detection_metrics"]["skipped_llm_calls"] == 0


class TestMixedBatch:
    def test_mixed_batch_telemetry(
        self, agent, checklist, repo, tmp_path,
    ):
        """Three findings: fixture (skip), prod (run), fixture-with-
        override (run). Telemetry should reflect each path."""
        findings = [
            _finding("tests/conftest.py", "setup_user", fid="F-FIX"),
            _finding("src/api.py", "save_upload", fid="F-PROD"),
            _finding(
                "tests/conftest.py", "setup_user",
                fid="F-OVERRIDE", manual_override=True,
            ),
        ]
        findings_in = tmp_path / "findings_in.json"
        findings_in.write_text(json.dumps(findings))

        with patch.object(
            AutonomousSecurityAgentV2,
            "_load_validated_findings",
            return_value=findings,
        ), patch.object(
            AutonomousSecurityAgentV2,
            "analyze_vulnerability",
            return_value=False,
        ) as mock_analyze:
            report = agent.process_findings(
                findings_path=str(findings_in),
                max_findings=10,
                checklist=checklist,
                emit_annotations=True,
            )

        # Two LLM calls (prod + override-bypass).
        assert mock_analyze.call_count == 2
        # One LLM-skip (the fixture finding).
        assert report["fixture_detection_metrics"]["skipped_llm_calls"] == 1
        # Pre-flight outcomes: F-FIX → true, F-PROD → false,
        # F-OVERRIDE bypassed (no outcome recorded).
        outcomes = report["fixture_detection_metrics"]["prep_outcomes"]
        assert outcomes["true"] == 1
        assert outcomes["false"] == 1
        # F-OVERRIDE bypass means no outcome — counts stay at 0
        # for candidate.
        assert outcomes.get("candidate", 0) == 0
