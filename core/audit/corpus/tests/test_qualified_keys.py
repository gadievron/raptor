"""Receiver-qualified keys end-to-end.

The v5 corpus run showed distinct methods collapsing onto one bare
key: seven ``Null*.Scan`` labels all printed and scored as
``sql.go:Scan`` (mixed verdicts under one name), and attribution
receipts never joined qualified label ids at all.  The qualified name
must ride from the inventory metadata through the gap, the review
outcome, the journal/audit-log rows, and back into corpus scoring and
attribution.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.audit.corpus.attribution import build_signal_index
from core.audit.corpus.run_corpus import _parse_audit_log_outcomes


def _write_log(path: Path, entries: list[dict[str, Any]]) -> Path:
    path.write_text(
        "\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8",
    )
    return path


class TestParseAuditLogOutcomes:
    def test_qualified_alias_resolves_label_id(self, tmp_path):
        log = _write_log(tmp_path / ".audit-log.jsonl", [
            {"action": "orchestrator_review",
             "key": "src/database/sql/sql.go:Scan:100",
             "function_qualified": "NullBool.Scan", "status": "clean"},
            {"action": "orchestrator_review",
             "key": "src/database/sql/sql.go:Scan:200",
             "function_qualified": "NullTime.Scan", "status": "suspicious"},
        ])
        outcomes, _bare = _parse_audit_log_outcomes(log)
        assert outcomes[
            "src/database/sql/sql.go:NullBool.Scan"
        ]["status"] == "clean"
        assert outcomes[
            "src/database/sql/sql.go:NullTime.Scan"
        ]["status"] == "suspicious"
        # Line-suffixed qualified aliases too.
        assert (
            outcomes["src/database/sql/sql.go:NullTime.Scan:200"]["status"]
            == "suspicious"
        )

    def test_rows_without_qualified_name_unchanged(self, tmp_path):
        log = _write_log(tmp_path / ".audit-log.jsonl", [
            {"action": "orchestrator_review", "key": "a.c:f:10",
             "status": "clean"},
        ])
        outcomes, _ = _parse_audit_log_outcomes(log)
        assert outcomes["a.c:f"]["status"] == "clean"
        assert "a.c:.f" not in outcomes

    def test_missing_log_is_empty(self, tmp_path):
        outcomes, bare = _parse_audit_log_outcomes(tmp_path / "absent.jsonl")
        assert outcomes == {} and bare == {}


class TestAttributionQualifiedJoin:
    def test_audit_log_receipts_join_qualified_ids(self, tmp_path):
        run = tmp_path / "run"
        run.mkdir()
        _write_log(run / ".audit-log.jsonl", [
            {"action": "orchestrator_review", "key": "sql.go:Scan:100",
             "function_qualified": "NullBool.Scan",
             "evidence_tool": "smt:check-overflow", "status": "suspicious"},
        ])
        index = build_signal_index([run])
        assert "smt:check-overflow" in index.tools.get(
            "sql.go:NullBool.Scan", set(),
        )
        # The bare key keeps working for unqualified labels.
        assert "smt:check-overflow" in index.tools.get("sql.go:Scan", set())

    def test_journal_receipts_join_qualified_ids(self, tmp_path):
        run = tmp_path / "run"
        run.mkdir()
        (run / "review-journal.jsonl").write_text(json.dumps({
            "file": "sql.go", "function": "Scan",
            "function_qualified": "NullTime.Scan",
            "evidence_tools": ["semgrep"],
        }) + "\n", encoding="utf-8")
        index = build_signal_index([run])
        assert "semgrep" in index.tools.get("sql.go:NullTime.Scan", set())


@dataclass
class _Outcome:
    file: str = "sql.go"
    function: str = "Scan"
    function_qualified: str = ""
    status: str = "clean"
    body: str = ""
    model: str = ""
    cost_usd: float = 0.0
    duration_s: float = 0.0
    line: int = 100
    hypothesis: str = ""
    hypotheses: list = field(default_factory=list)
    evidence_tool: str = ""
    review_result: dict | None = None
    tools_dispatched: set | None = None


class TestJournalCarriesQualifiedName:
    def test_gap_qualified_name_stamps_outcome_and_entry(self, tmp_path):
        from core.audit.collector import append_journal_for_outcome
        from core.coverage.journal import load_entries

        outcome = _Outcome()
        append_journal_for_outcome(
            out_dir=tmp_path,
            target_path=tmp_path,
            run_id="run-1",
            outcome=outcome,
            gap={"file": "sql.go", "name": "Scan", "line_start": 100,
                 "line_end": 120, "qualified_name": "NullBool.Scan"},
        )
        assert outcome.function_qualified == "NullBool.Scan"
        entries = load_entries(tmp_path)
        assert entries[0].function == "Scan"
        assert entries[0].function_qualified == "NullBool.Scan"

    def test_entry_without_qualified_name_round_trips(self, tmp_path):
        from core.audit.collector import append_journal_for_outcome
        from core.coverage.journal import load_entries

        append_journal_for_outcome(
            out_dir=tmp_path,
            target_path=tmp_path,
            run_id="run-1",
            outcome=_Outcome(),
            gap={"file": "sql.go", "name": "Scan", "line_start": 100},
        )
        entries = load_entries(tmp_path)
        assert entries[0].function_qualified is None


class TestGapQualifiedName:
    def test_compute_gaps_qualifies_from_class_name(self):
        from core.audit.gaps import compute_gaps

        checklist = {
            "target_path": "",
            "files": [{
                "path": "sql.go",
                "items": [
                    {"name": "Scan", "kind": "function", "line_start": 1,
                     "line_end": 10,
                     "metadata": {"class_name": "NullBool"}},
                    {"name": "free_fn", "kind": "function",
                     "line_start": 12, "line_end": 20},
                ],
            }],
        }
        gaps = compute_gaps(checklist, [])
        by_name = {g["name"]: g for g in gaps}
        assert by_name["Scan"]["qualified_name"] == "NullBool.Scan"
        assert "qualified_name" not in by_name["free_fn"]


class TestLearnedAliasCanonicalization:
    """An unqualified late row (post-loop re-review, promotion clone)
    must update the qualified alias learned from earlier rows —
    otherwise a real status flip is invisible to a qualified label."""

    def test_late_unqualified_row_updates_qualified_alias(self, tmp_path):
        import json

        from core.audit.corpus.run_corpus import (
            _parse_audit_log_outcomes,
        )
        log = tmp_path / ".audit-log.jsonl"
        rows = [
            {"action": "orchestrator_review", "key": "a/l.go:Ensure:24",
             "status": "clean", "function_qualified": "snap.Ensure"},
            {"action": "orchestrator_review", "key": "a/l.go:Ensure:24",
             "status": "suspicious"},
        ]
        log.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
        o, _ = _parse_audit_log_outcomes(log)
        assert o["a/l.go:snap.Ensure"]["status"] == "suspicious"
        assert o["a/l.go:snap.Ensure:24"]["status"] == "suspicious"
        assert o["a/l.go:Ensure"]["status"] == "suspicious"
