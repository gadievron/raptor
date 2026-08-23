"""Phase-4 orchestrated analyses reach the review journal.

The orchestrator has no journal writer of its own; the launcher calls
``journal_orchestrated_results`` on the merged report results after
``orchestrate()`` returns. Entries are finding-grade
(``producer="agentic"``), land at the run root, and only ANALYSED
records qualify — inconsistent/skipped/error records carry no
reviewable verdict.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.coverage.journal import is_function_grade, load_entries
from packages.llm_analysis.journal_emit import (
    build_journal_body,
    derive_verdict,
    journal_orchestrated_results,
)


def _checklist(target: Path) -> dict:
    return {
        "target_path": str(target),
        "files": [{
            "path": "src/foo.py",
            "items": [{
                "name": "login",
                "kind": "function",
                "line_start": 10,
                "line_end": 15,
            }],
        }],
    }


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "repo"
    (target / "src").mkdir(parents=True)
    (target / "src" / "foo.py").write_text(
        "\n" * 9 + "def login(req):\n    return req\n" * 3,
        encoding="utf-8",
    )
    return target


def _result(**kw) -> dict:
    base = {
        "finding_id": "f1",
        "file_path": "src/foo.py",
        "start_line": 11,
        "status": "analysed",
        "is_true_positive": True,
        "is_exploitable": True,
        "reasoning": "tainted req reaches eval",
        "severity_assessment": "high",
        "cwe_id": "CWE-95",
        "tool": "semgrep",
        "analysed_by": "test-model",
    }
    base.update(kw)
    return base


class TestJournalOrchestratedResults:
    def test_analysed_result_journaled_finding_grade(self, tmp_path):
        target = _target(tmp_path)
        out = tmp_path / "out"
        out.mkdir()

        emitted = journal_orchestrated_results(
            out, target, [_result()], checklist=_checklist(target),
        )

        assert emitted == 1
        entries = load_entries(out)
        assert len(entries) == 1
        entry = entries[0]
        assert entry.file == "src/foo.py"
        assert entry.function == "login"
        assert entry.verdict == "finding"
        assert entry.cwe == "CWE-95"
        assert entry.model == "test-model"
        assert "tainted req reaches eval" in entry.body
        assert entry.producer == "agentic"
        assert not is_function_grade(entry)
        assert entry.source_hash

    def test_verdict_mapping(self, tmp_path):
        target = _target(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        results = [
            _result(finding_id="f1", is_true_positive=False,
                    is_exploitable=False),
            _result(finding_id="f2", is_true_positive=True,
                    is_exploitable=False),
        ]
        assert journal_orchestrated_results(
            out, target, results, checklist=_checklist(target)) == 2
        verdicts = sorted(e.verdict for e in load_entries(out))
        assert verdicts == ["clean", "suspicious"]

    def test_non_analysed_statuses_skipped(self, tmp_path):
        target = _target(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        results = [
            _result(status="error"),
            _result(status="analysis_inconsistent"),
            _result(status="skipped_over_budget"),
            "junk",
        ]
        assert journal_orchestrated_results(
            out, target, results, checklist=_checklist(target)) == 0
        assert load_entries(out) == []

    def test_status_less_record_requires_boolean_verdict(self, tmp_path):
        target = _target(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        results = [
            _result(finding_id="f1", status=None, is_true_positive=None),
            _result(finding_id="f2", status=None),
        ]
        # Explicit None status → fall back to the schema-required bool.
        for r in results:
            del r["status"]
        assert journal_orchestrated_results(
            out, target, results, checklist=_checklist(target)) == 1

    def test_checklist_auto_loaded_from_out_dir(self, tmp_path):
        target = _target(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        (out / "checklist.json").write_text(
            json.dumps(_checklist(target)), encoding="utf-8")

        assert journal_orchestrated_results(out, target, [_result()]) == 1

    def test_no_checklist_is_a_noop(self, tmp_path):
        target = _target(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        assert journal_orchestrated_results(out, target, [_result()]) == 0


class TestVerdictAndBodyHelpers:
    def test_derive_verdict_enum(self):
        assert derive_verdict(None) == "error"
        assert derive_verdict({}) == "error"
        assert derive_verdict({"is_true_positive": "yes"}) == "error"
        assert derive_verdict({"is_true_positive": False}) == "clean"
        assert derive_verdict(
            {"is_true_positive": True, "is_exploitable": False},
        ) == "suspicious"
        assert derive_verdict(
            {"is_true_positive": True, "is_exploitable": True},
        ) == "finding"

    def test_body_falls_back_to_scanner_message(self):
        assert build_journal_body({}, message="msg") == "Scanner message: msg"

    def test_body_prefers_reasoning(self):
        body = build_journal_body(
            {"reasoning": "why", "severity_assessment": "low"},
            message="msg",
        )
        assert "why" in body
        assert "Severity: low" in body
        assert "Scanner message" not in body

    def test_dataflow_block_gated_on_has_dataflow(self):
        analysis = {
            "reasoning": "why",
            "dataflow_validation": {"false_positive": True},
        }
        assert "false_positive=True" not in build_journal_body(analysis)
        assert "false_positive=True" in build_journal_body(
            analysis, has_dataflow=True,
        )


class TestPanelJournaling:
    """Multi-model runs journal each panel member's own verdict."""

    def _panel_result(self):
        return _result(multi_model_analyses=[
            {"model": "test-model", "is_exploitable": True,
             "ruling": "validated", "reasoning": "primary says yes"},
            {"model": "second-model", "is_exploitable": False,
             "ruling": {"status": "false_positive"},
             "reasoning": "second says sanitized"},
            {"model": "third-model", "is_exploitable": False,
             "ruling": "validated", "reasoning": "real but unreachable"},
        ])

    def test_disagreeing_members_journaled_with_own_verdicts(
        self, tmp_path,
    ):
        target = _target(tmp_path)
        out = tmp_path / "out"
        out.mkdir()

        emitted = journal_orchestrated_results(
            out, target, [self._panel_result()],
            checklist=_checklist(target),
        )

        assert emitted == 3
        entries = load_entries(out)
        by_model = {e.model: e for e in entries}
        # Primary carries the merged post-pipeline verdict, not its
        # dispatch-time panel record.
        assert by_model["test-model"].verdict == "finding"
        assert by_model["second-model"].verdict == "clean"
        assert "sanitized" in by_model["second-model"].body
        assert by_model["third-model"].verdict == "suspicious"
        # Distinct index identities per model — merging preserves all.
        assert len({e.index_key for e in entries}) == 3
        assert all(e.producer == "agentic" for e in entries)

    def test_verdictless_member_skipped(self, tmp_path):
        target = _target(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        result = _result(multi_model_analyses=[
            {"model": "test-model", "is_exploitable": True,
             "reasoning": "yes"},
            {"model": "erroring-model", "is_exploitable": None,
             "reasoning": ""},
        ])
        emitted = journal_orchestrated_results(
            out, target, [result], checklist=_checklist(target),
        )
        assert emitted == 1

    def test_single_member_panel_not_double_journaled(self, tmp_path):
        target = _target(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        result = _result(multi_model_analyses=[
            {"model": "test-model", "is_exploitable": True,
             "reasoning": "yes"},
        ])
        emitted = journal_orchestrated_results(
            out, target, [result], checklist=_checklist(target),
        )
        assert emitted == 1
        assert len(load_entries(out)) == 1
