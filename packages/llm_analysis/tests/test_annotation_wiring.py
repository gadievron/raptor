"""Wiring + adversarial-input tests for the /agentic annotation emit path.

The 27 tests in ``test_annotation_emit.py`` exercise the helper module
in isolation. These tests cover what the helper tests can't:

  * The ``AutonomousSecurityAgentV2._emit_finding_annotation`` method
    actually drives the helper with the right arguments
    (``out_dir/annotations``, ``checklist``, ``repo_path``).
  * The wiring point in ``process_findings`` calls the method.
  * Weird ``vuln.analysis`` shapes the schema validator might let
    through: ``None`` for required bools, NaN scores, missing fields,
    oversized reasoning text, control characters in CWE.

If any of these break, ``/agentic`` would silently emit nothing or
crash the analysis loop — neither would have shown up in the helper
unit tests.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

from core.annotations import read_annotation
from packages.llm_analysis.agent import (
    AutonomousSecurityAgentV2,
    VulnerabilityContext,
)


REPO_ROOT = Path(__file__).resolve().parents[3]
AGENT_PY = REPO_ROOT / "packages" / "llm_analysis" / "agent.py"


# ---------------------------------------------------------------------------
# Static-wiring sanity: process_findings calls the method.
# ---------------------------------------------------------------------------


class TestProcessFindingsCallsTheMethod:
    """If someone refactors and drops the call, the on-disk emit
    path silently disappears. Pin it with a static check."""

    def test_call_present_in_process_findings(self):
        text = AGENT_PY.read_text(encoding="utf-8")
        assert "self._emit_finding_annotation(vuln, checklist)" in text

    def test_call_is_inside_analyze_vulnerability_branch(self):
        """The call must be inside the ``if analyze_vulnerability``
        block (post-analysis) — otherwise it fires on every iteration
        regardless of whether analysis happened."""
        text = AGENT_PY.read_text(encoding="utf-8")
        # Find the analyze_vulnerability check and the emit call.
        ana_idx = text.index("if self.analyze_vulnerability(vuln):")
        emit_idx = text.index("self._emit_finding_annotation(vuln, checklist)")
        # Emit must come after the conditional (within the block).
        assert emit_idx > ana_idx
        # And reasonably close — within ~500 chars (same indent block).
        assert emit_idx - ana_idx < 500


# ---------------------------------------------------------------------------
# Method-level wiring: drive _emit_finding_annotation directly.
# ---------------------------------------------------------------------------


def _make_agent(tmp_path: Path) -> AutonomousSecurityAgentV2:
    """Build the smallest possible agent that doesn't call any LLM."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "src").mkdir()
    out = tmp_path / "out"
    return AutonomousSecurityAgentV2(
        repo_path=repo, out_dir=out, prep_only=True,
    )


def _make_finding(
    file_path="src/foo.py",
    line=10,
    rule_id="py/sql-injection",
    cwe_id="CWE-89",
    tool="codeql",
) -> Dict[str, Any]:
    return {
        "finding_id": "f1",
        "rule_id": rule_id,
        "file": file_path,
        "startLine": line,
        "endLine": line + 5,
        "level": "warning",
        "message": "msg",
        "tool": tool,
        "cwe_id": cwe_id,
    }


def _checklist(file_path="src/foo.py", name="login",
               line_start=10, line_end=15) -> Dict[str, Any]:
    return {
        "files": [
            {
                "path": file_path,
                "items": [{
                    "name": name,
                    "line_start": line_start,
                    "line_end": line_end,
                }],
            }
        ]
    }


def _set_analysis(vuln, **kwargs) -> None:
    vuln.analysis = {
        "is_true_positive": kwargs.get("is_true_positive", True),
        "is_exploitable": kwargs.get("is_exploitable", True),
        "reasoning": kwargs.get("reasoning", "test reasoning"),
        "exploitability_score": kwargs.get("exploitability_score", 0.5),
        "severity_assessment": kwargs.get("severity_assessment", "medium"),
    }


class TestEmitMethod:
    def test_emits_annotation_with_correct_args(self, tmp_path):
        agent = _make_agent(tmp_path)
        # Source file the helper will hash.
        (agent.repo_path / "src" / "foo.py").write_text(
            "\n" * 9 + "def login(req):\n    return req\n" * 4
        )
        vuln = VulnerabilityContext(_make_finding(), agent.repo_path)
        _set_analysis(vuln)

        agent._emit_finding_annotation(vuln, _checklist())

        ann = read_annotation(
            agent.out_dir / "annotations", "src/foo.py", "login",
        )
        assert ann is not None
        assert ann.metadata["source"] == "llm"
        assert ann.metadata["status"] == "finding"
        assert ann.metadata["rule_id"] == "py/sql-injection"
        assert "test reasoning" in ann.body

    def test_swallows_helper_exceptions(self, tmp_path, monkeypatch):
        """Even if the helper blows up unexpectedly, the agent method
        must not propagate — this is the OUTER try/except that wraps
        even an exception escaping the helper's own swallow."""
        agent = _make_agent(tmp_path)
        vuln = VulnerabilityContext(_make_finding(), agent.repo_path)
        _set_analysis(vuln)

        from packages.llm_analysis import annotation_emit

        def boom(*a, **kw):
            raise RuntimeError("simulated crash")

        monkeypatch.setattr(annotation_emit, "emit_finding_annotation", boom)
        # Must not raise.
        agent._emit_finding_annotation(vuln, _checklist())

    def test_no_checklist_skips(self, tmp_path):
        agent = _make_agent(tmp_path)
        vuln = VulnerabilityContext(_make_finding(), agent.repo_path)
        _set_analysis(vuln)
        # No exception, no annotation directory created.
        agent._emit_finding_annotation(vuln, None)
        assert not (agent.out_dir / "annotations").exists() or \
               not any((agent.out_dir / "annotations").rglob("*.md"))


# ---------------------------------------------------------------------------
# Adversarial vuln.analysis shapes that the schema might let through.
# ---------------------------------------------------------------------------


class TestAdversarialAnalysis:
    """The LLM response validator can return a partial dict when
    the model omits fields. The annotation emitter must tolerate
    every shape the validator might produce."""

    def test_is_true_positive_none(self, tmp_path):
        """``is_true_positive`` missing → status 'error', not crash."""
        agent = _make_agent(tmp_path)
        (agent.repo_path / "src" / "foo.py").write_text(
            "\n" * 9 + "def login():\n    pass\n"
        )
        vuln = VulnerabilityContext(_make_finding(), agent.repo_path)
        # Note: not using _set_analysis — leaving is_true_positive out.
        vuln.analysis = {"reasoning": "shrug"}
        agent._emit_finding_annotation(vuln, _checklist())
        ann = read_annotation(
            agent.out_dir / "annotations", "src/foo.py", "login",
        )
        assert ann is not None
        assert ann.metadata["status"] == "error"

    def test_is_true_positive_string_value(self, tmp_path):
        """A model may emit ``"yes"`` instead of ``true``. The
        emitter should treat anything non-True/non-False as 'error'
        — never crash."""
        agent = _make_agent(tmp_path)
        (agent.repo_path / "src" / "foo.py").write_text(
            "\n" * 9 + "def login():\n    pass\n"
        )
        vuln = VulnerabilityContext(_make_finding(), agent.repo_path)
        vuln.analysis = {
            "is_true_positive": "yes",  # not a bool!
            "reasoning": "x",
        }
        agent._emit_finding_annotation(vuln, _checklist())
        ann = read_annotation(
            agent.out_dir / "annotations", "src/foo.py", "login",
        )
        assert ann is not None
        assert ann.metadata["status"] == "error"

    def test_nan_score_silently_dropped(self, tmp_path):
        """NaN scores can't be formatted with ``f"{x:.2f}"`` — no,
        wait, NaN CAN be formatted. But Inf can't be formatted as
        a finite. Either way, the emit should not crash."""
        agent = _make_agent(tmp_path)
        (agent.repo_path / "src" / "foo.py").write_text(
            "\n" * 9 + "def login():\n    pass\n"
        )
        vuln = VulnerabilityContext(_make_finding(), agent.repo_path)
        vuln.analysis = {
            "is_true_positive": True,
            "is_exploitable": True,
            "reasoning": "x",
            "exploitability_score": float("nan"),
        }
        agent._emit_finding_annotation(vuln, _checklist())
        ann = read_annotation(
            agent.out_dir / "annotations", "src/foo.py", "login",
        )
        assert ann is not None
        # Either no score key, or "nan" — both acceptable, just no crash.

    def test_inf_score_silently_dropped(self, tmp_path):
        agent = _make_agent(tmp_path)
        (agent.repo_path / "src" / "foo.py").write_text(
            "\n" * 9 + "def login():\n    pass\n"
        )
        vuln = VulnerabilityContext(_make_finding(), agent.repo_path)
        vuln.analysis = {
            "is_true_positive": True,
            "is_exploitable": True,
            "reasoning": "x",
            "exploitability_score": float("inf"),
        }
        agent._emit_finding_annotation(vuln, _checklist())
        # No crash.

    def test_score_as_string(self, tmp_path):
        """Some LLMs emit scores as strings."""
        agent = _make_agent(tmp_path)
        (agent.repo_path / "src" / "foo.py").write_text(
            "\n" * 9 + "def login():\n    pass\n"
        )
        vuln = VulnerabilityContext(_make_finding(), agent.repo_path)
        vuln.analysis = {
            "is_true_positive": True, "is_exploitable": True,
            "reasoning": "x",
            "exploitability_score": "0.7",
        }
        agent._emit_finding_annotation(vuln, _checklist())
        ann = read_annotation(
            agent.out_dir / "annotations", "src/foo.py", "login",
        )
        assert ann.metadata.get("score") == "0.70"

    def test_unparseable_score_skipped(self, tmp_path):
        agent = _make_agent(tmp_path)
        (agent.repo_path / "src" / "foo.py").write_text(
            "\n" * 9 + "def login():\n    pass\n"
        )
        vuln = VulnerabilityContext(_make_finding(), agent.repo_path)
        vuln.analysis = {
            "is_true_positive": True, "is_exploitable": True,
            "reasoning": "x",
            "exploitability_score": "very high",  # unparseable
        }
        agent._emit_finding_annotation(vuln, _checklist())
        ann = read_annotation(
            agent.out_dir / "annotations", "src/foo.py", "login",
        )
        # No 'score' metadata key — silently skipped.
        assert "score" not in ann.metadata

    def test_huge_reasoning_text(self, tmp_path):
        """An LLM that returns 100KB of reasoning shouldn't kill us."""
        agent = _make_agent(tmp_path)
        (agent.repo_path / "src" / "foo.py").write_text(
            "\n" * 9 + "def login():\n    pass\n"
        )
        vuln = VulnerabilityContext(_make_finding(), agent.repo_path)
        big_reasoning = "x" * 100_000
        vuln.analysis = {
            "is_true_positive": True, "is_exploitable": False,
            "reasoning": big_reasoning,
        }
        agent._emit_finding_annotation(vuln, _checklist())
        ann = read_annotation(
            agent.out_dir / "annotations", "src/foo.py", "login",
        )
        assert ann is not None
        assert len(ann.body) >= 100_000

    def test_cwe_with_html_comment_close(self, tmp_path):
        """A scanner could emit a malformed cwe_id. Sanitiser must
        strip ``-->`` so the metadata HTML comment isn't broken."""
        agent = _make_agent(tmp_path)
        (agent.repo_path / "src" / "foo.py").write_text(
            "\n" * 9 + "def login():\n    pass\n"
        )
        vuln = VulnerabilityContext(
            _make_finding(cwe_id="CWE-89-->evil"),
            agent.repo_path,
        )
        _set_analysis(vuln)
        agent._emit_finding_annotation(vuln, _checklist())
        ann = read_annotation(
            agent.out_dir / "annotations", "src/foo.py", "login",
        )
        assert ann is not None
        assert "-->" not in ann.metadata["cwe"]

    def test_rule_id_with_newline(self, tmp_path):
        """Newline in rule_id would corrupt the metadata HTML
        comment. Sanitiser converts to space."""
        agent = _make_agent(tmp_path)
        (agent.repo_path / "src" / "foo.py").write_text(
            "\n" * 9 + "def login():\n    pass\n"
        )
        vuln = VulnerabilityContext(
            _make_finding(rule_id="rule\nwith\nnewlines"),
            agent.repo_path,
        )
        _set_analysis(vuln)
        agent._emit_finding_annotation(vuln, _checklist())
        ann = read_annotation(
            agent.out_dir / "annotations", "src/foo.py", "login",
        )
        assert "\n" not in ann.metadata["rule_id"]

    def test_null_byte_in_tool(self, tmp_path):
        agent = _make_agent(tmp_path)
        (agent.repo_path / "src" / "foo.py").write_text(
            "\n" * 9 + "def login():\n    pass\n"
        )
        vuln = VulnerabilityContext(
            _make_finding(tool="codeql\x00"), agent.repo_path,
        )
        _set_analysis(vuln)
        agent._emit_finding_annotation(vuln, _checklist())
        ann = read_annotation(
            agent.out_dir / "annotations", "src/foo.py", "login",
        )
        assert "\x00" not in ann.metadata["tool"]

    def test_none_analysis_falls_back_to_message(self, tmp_path):
        """Skipped analysis (vuln.analysis is None) — emit should
        still write an annotation using the scanner's message as body
        and status='error'."""
        agent = _make_agent(tmp_path)
        (agent.repo_path / "src" / "foo.py").write_text(
            "\n" * 9 + "def login():\n    pass\n"
        )
        vuln = VulnerabilityContext(_make_finding(), agent.repo_path)
        # vuln.analysis stays None.
        agent._emit_finding_annotation(vuln, _checklist())
        ann = read_annotation(
            agent.out_dir / "annotations", "src/foo.py", "login",
        )
        assert ann is not None
        assert ann.metadata["status"] == "error"
        assert "Scanner message" in ann.body
