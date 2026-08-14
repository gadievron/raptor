"""Wiring + adversarial-input tests for the /agentic journal emit path.

These tests cover:

  * The ``AutonomousSecurityAgentV2._emit_journal_entry`` method
    writes a ReviewJournalEntry via ``append_entry``.
  * The wiring point in ``process_findings`` calls the method.
  * Weird ``vuln.analysis`` shapes the schema validator might let
    through: ``None`` for required bools, NaN scores, missing fields,
    oversized reasoning text.

If any of these break, ``/agentic`` would silently emit nothing or
crash the analysis loop.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from core.coverage.journal import load_entries
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
    def test_call_present_in_process_findings(self):
        text = AGENT_PY.read_text(encoding="utf-8")
        assert "self._emit_journal_entry(vuln, checklist)" in text

    def test_call_is_inside_analyze_vulnerability_branch(self):
        text = AGENT_PY.read_text(encoding="utf-8")
        ana_idx = text.index("if self.analyze_vulnerability(vuln):")
        post_text = text[ana_idx:]
        emit_offset = post_text.index(
            "self._emit_journal_entry(vuln, checklist)"
        )
        assert 0 < emit_offset < 500


# ---------------------------------------------------------------------------
# Method-level wiring: drive _emit_journal_entry directly.
# ---------------------------------------------------------------------------


def _make_agent(tmp_path: Path) -> AutonomousSecurityAgentV2:
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


class TestTelemetry:
    def test_emit_method_returns_true_on_success(self, tmp_path):
        agent = _make_agent(tmp_path)
        (agent.repo_path / "src" / "foo.py").write_text(
            "\n" * 9 + "def login():\n    pass\n"
        )
        vuln = VulnerabilityContext(_make_finding(), agent.repo_path)
        _set_analysis(vuln)
        result = agent._emit_journal_entry(vuln, _checklist())
        assert result is True

    def test_emit_method_returns_false_on_skip(self, tmp_path):
        agent = _make_agent(tmp_path)
        vuln = VulnerabilityContext(_make_finding(), agent.repo_path)
        _set_analysis(vuln)
        result = agent._emit_journal_entry(vuln, None)
        assert result is False

    def test_emit_method_returns_false_on_exception(
        self, tmp_path, monkeypatch,
    ):
        agent = _make_agent(tmp_path)
        vuln = VulnerabilityContext(_make_finding(), agent.repo_path)
        _set_analysis(vuln)

        from core.coverage import journal

        def boom(*a, **kw):
            raise RuntimeError("crash")

        monkeypatch.setattr(journal, "append_entry", boom)
        result = agent._emit_journal_entry(vuln, _checklist())
        assert result is False


class TestEmitMethod:
    def test_emits_journal_entry_with_correct_fields(self, tmp_path):
        agent = _make_agent(tmp_path)
        (agent.repo_path / "src" / "foo.py").write_text(
            "\n" * 9 + "def login(req):\n    return req\n" * 4
        )
        vuln = VulnerabilityContext(_make_finding(), agent.repo_path)
        _set_analysis(vuln)

        agent._emit_journal_entry(vuln, _checklist())

        entries = load_entries(agent.out_dir)
        assert len(entries) == 1
        entry = entries[0]
        assert entry.file == "src/foo.py"
        assert entry.function == "login"
        assert entry.verdict == "finding"
        assert entry.cwe == "CWE-89"
        assert "test reasoning" in entry.body
        assert "unknown" not in entry.evidence_tools
        assert "codeql" in entry.evidence_tools

    def test_swallows_exceptions(self, tmp_path, monkeypatch):
        agent = _make_agent(tmp_path)
        vuln = VulnerabilityContext(_make_finding(), agent.repo_path)
        _set_analysis(vuln)

        from core.coverage import journal

        def boom(*a, **kw):
            raise RuntimeError("simulated crash")

        monkeypatch.setattr(journal, "append_entry", boom)
        agent._emit_journal_entry(vuln, _checklist())

    def test_no_checklist_skips(self, tmp_path):
        agent = _make_agent(tmp_path)
        vuln = VulnerabilityContext(_make_finding(), agent.repo_path)
        _set_analysis(vuln)
        agent._emit_journal_entry(vuln, None)
        entries = load_entries(agent.out_dir)
        assert len(entries) == 0


class TestNoJournalOptOut:
    def test_signature_has_emit_journal(self, tmp_path):
        agent = _make_agent(tmp_path)
        import inspect
        sig = inspect.signature(agent.process_findings)
        assert "emit_journal" in sig.parameters
        assert sig.parameters["emit_journal"].default is True

    def test_signature_documents_opt_out(self, tmp_path):
        from packages.llm_analysis.agent import AutonomousSecurityAgentV2
        doc = AutonomousSecurityAgentV2.process_findings.__doc__ or ""
        assert "emit_journal" in doc


# ---------------------------------------------------------------------------
# Verdict mapping (replaces _derive_status tests)
# ---------------------------------------------------------------------------


class TestDeriveVerdict:
    def test_tp_exploitable_is_finding(self):
        assert AutonomousSecurityAgentV2._derive_verdict(
            {"is_true_positive": True, "is_exploitable": True},
        ) == "finding"

    def test_tp_not_exploitable_is_suspicious(self):
        assert AutonomousSecurityAgentV2._derive_verdict(
            {"is_true_positive": True, "is_exploitable": False},
        ) == "suspicious"

    def test_not_tp_is_clean(self):
        assert AutonomousSecurityAgentV2._derive_verdict(
            {"is_true_positive": False},
        ) == "clean"

    def test_none_analysis_is_error(self):
        assert AutonomousSecurityAgentV2._derive_verdict(None) == "error"

    def test_missing_is_true_positive_is_error(self):
        assert AutonomousSecurityAgentV2._derive_verdict(
            {"reasoning": "shrug"},
        ) == "error"

    def test_string_is_true_positive_is_error(self):
        assert AutonomousSecurityAgentV2._derive_verdict(
            {"is_true_positive": "yes"},
        ) == "error"


# ---------------------------------------------------------------------------
# Adversarial vuln.analysis shapes
# ---------------------------------------------------------------------------


class TestAdversarialAnalysis:
    def test_is_true_positive_none(self, tmp_path):
        agent = _make_agent(tmp_path)
        (agent.repo_path / "src" / "foo.py").write_text(
            "\n" * 9 + "def login():\n    pass\n"
        )
        vuln = VulnerabilityContext(_make_finding(), agent.repo_path)
        vuln.analysis = {"reasoning": "shrug"}
        agent._emit_journal_entry(vuln, _checklist())
        entries = load_entries(agent.out_dir)
        assert len(entries) == 1
        assert entries[0].verdict == "error"

    def test_none_analysis_falls_back_to_message(self, tmp_path):
        agent = _make_agent(tmp_path)
        (agent.repo_path / "src" / "foo.py").write_text(
            "\n" * 9 + "def login():\n    pass\n"
        )
        vuln = VulnerabilityContext(_make_finding(), agent.repo_path)
        agent._emit_journal_entry(vuln, _checklist())
        entries = load_entries(agent.out_dir)
        assert len(entries) == 1
        assert entries[0].verdict == "error"
        assert "Scanner message" in entries[0].body

    def test_huge_reasoning_text(self, tmp_path):
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
        agent._emit_journal_entry(vuln, _checklist())
        entries = load_entries(agent.out_dir)
        assert len(entries) == 1
        assert len(entries[0].body) >= 100_000

    def test_journal_entry_is_valid_json(self, tmp_path):
        agent = _make_agent(tmp_path)
        (agent.repo_path / "src" / "foo.py").write_text(
            "\n" * 9 + "def login():\n    pass\n"
        )
        vuln = VulnerabilityContext(_make_finding(), agent.repo_path)
        _set_analysis(vuln)
        agent._emit_journal_entry(vuln, _checklist())
        journal_path = agent.out_dir / "review-journal.jsonl"
        assert journal_path.exists()
        lines = journal_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["file"] == "src/foo.py"
        assert data["function"] == "login"
        assert data["verdict"] == "finding"
