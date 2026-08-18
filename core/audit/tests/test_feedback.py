"""Tests for core.audit.feedback — /validate → /audit Reflexion loop."""

from __future__ import annotations

import json
from pathlib import Path

from core.audit.feedback import (
    _classify_verdict,
    _compute_transition,
    _deduplicate_findings,
    _extract_findings,
    _extract_lesson,
    _extract_reason,
    import_validation_results,
)
from core.coverage.journal import (
    ReviewJournalEntry,
    append_entry,
    latest_entries,
    now_iso,
)

# ---- helpers ----

def _write_annotation(annotations_dir: Path, file_path: str,
                       function_name: str, status: str, body: str) -> None:
    """Write a legacy LLM-source annotation file. Used to exercise
    the pre-migration fallback path — Reflexion still reads LLM
    annotations from run dirs created before the annotation →
    journal migration, but writes the corrected verdict to the
    journal (never back to the annotation)."""
    ann_path = annotations_dir / f"{file_path}.md"
    ann_path.parent.mkdir(parents=True, exist_ok=True)
    meta = f"status={status} source=llm"
    content = (
        f"# {file_path}\n\n"
        f"## {function_name}\n"
        f"<!-- meta: {meta} -->\n\n"
        f"{body}\n"
    )
    ann_path.write_text(content)


def _seed_journal_entry(out_dir: Path, file_path: str,
                         function_name: str, verdict: str,
                         body: str = "") -> None:
    """Write a prior LLM review to the review journal at ``out_dir``
    so ``import_validation_results`` finds it as the prior verdict."""
    entry = ReviewJournalEntry(
        ts=now_iso(),
        run_id="test",
        file=file_path,
        function=function_name,
        verdict=verdict,
        source_hash="",
        body=body,
    )
    append_entry(out_dir, entry)


def _latest_journal_verdict(out_dir: Path, file_path: str,
                             function_name: str) -> str | None:
    """Return the latest journal entry's verdict for a function,
    or None if no entry exists."""
    entries = latest_entries(out_dir)
    entry = entries.get(f"{file_path}:{function_name}")
    return entry.verdict if entry else None


def _latest_journal_entry(out_dir: Path, file_path: str,
                           function_name: str) -> ReviewJournalEntry | None:
    entries = latest_entries(out_dir)
    return entries.get(f"{file_path}:{function_name}")


# ---- _classify_verdict ----

class TestClassifyVerdict:
    def test_ruled_out(self):
        f = {"ruling": {"status": "ruled_out", "reason": "dead code"}}
        assert _classify_verdict(f) == "disproven"

    def test_false_positive(self):
        f = {"ruling": {"status": "false_positive"}}
        assert _classify_verdict(f) == "disproven"

    def test_confirmed(self):
        f = {"ruling": {"status": "confirmed"}}
        assert _classify_verdict(f) == "confirmed"

    def test_exploitable(self):
        f = {"ruling": {"status": "exploitable"}}
        assert _classify_verdict(f) == "confirmed"

    def test_is_true_positive_false(self):
        f = {"is_true_positive": False}
        assert _classify_verdict(f) == "disproven"

    def test_is_true_positive_true(self):
        f = {"is_true_positive": True}
        assert _classify_verdict(f) == "confirmed"

    def test_string_ruling(self):
        f = {"ruling": "ruled_out"}
        assert _classify_verdict(f) == "disproven"

    def test_unknown(self):
        f = {"ruling": {"status": "investigating"}}
        assert _classify_verdict(f) == "unknown"

    def test_no_ruling(self):
        assert _classify_verdict({}) == "unknown"


# ---- _compute_transition ----

class TestComputeTransition:
    def test_disproven_finding_downgrades(self):
        t = _compute_transition("finding", "disproven")
        assert t["kind"] == "downgraded"
        assert t["new_status"] == "clean"

    def test_disproven_suspicious_downgrades(self):
        t = _compute_transition("suspicious", "disproven")
        assert t["kind"] == "downgraded"
        assert t["new_status"] == "clean"

    def test_disproven_clean_corroborates(self):
        t = _compute_transition("clean", "disproven")
        assert t["kind"] == "corroborated"
        assert t["new_status"] is None

    def test_confirmed_clean_upgrades(self):
        t = _compute_transition("clean", "confirmed")
        assert t["kind"] == "upgraded"
        assert t["new_status"] == "finding"

    def test_confirmed_finding_corroborates(self):
        t = _compute_transition("finding", "confirmed")
        assert t["kind"] == "corroborated"
        assert t["new_status"] is None

    def test_confirmed_suspicious_corroborates(self):
        t = _compute_transition("suspicious", "confirmed")
        assert t["kind"] == "corroborated"
        assert t["new_status"] is None

    def test_unknown_verdict(self):
        t = _compute_transition("finding", "unknown")
        assert t["kind"] == "corroborated"
        assert t["new_status"] is None


# ---- _extract_reason ----

class TestExtractReason:
    def test_ruling_reason(self):
        f = {"ruling": {"status": "ruled_out", "reason": "dead code path"}}
        assert _extract_reason(f) == "dead code path"

    def test_evidence_synthesis(self):
        f = {"ruling": {"status": "confirmed",
                        "evidence_synthesis": {"synthesis": "all stages agree"}}}
        assert _extract_reason(f) == "all stages agree"

    def test_disqualifier(self):
        f = {"ruling": {"status": "ruled_out", "disqualifier": "D-1"}}
        assert "D-1" in _extract_reason(f)

    def test_false_positive_reason(self):
        f = {"false_positive_reason": "not a real bug"}
        assert _extract_reason(f) == "not a real bug"

    def test_reasoning_fallback(self):
        f = {"reasoning": "checked the code"}
        assert _extract_reason(f) == "checked the code"

    def test_empty(self):
        assert _extract_reason({}) == ""


# ---- _extract_lesson ----

class TestExtractLesson:
    def test_disproven_finding_d0(self):
        f = {"ruling": {"disqualifier": "D-0"}}
        lesson = _extract_lesson(f, "finding", "disproven")
        assert "hypothesis was wrong" in lesson

    def test_disproven_finding_d1(self):
        f = {"ruling": {"disqualifier": "D-1"}}
        lesson = _extract_lesson(f, "finding", "disproven")
        assert "test/mock" in lesson

    def test_disproven_finding_d2(self):
        f = {"ruling": {"disqualifier": "D-2"}}
        lesson = _extract_lesson(f, "finding", "disproven")
        assert "preconditions" in lesson.lower()

    def test_disproven_finding_d3(self):
        f = {"ruling": {"disqualifier": "D-3"}}
        lesson = _extract_lesson(f, "finding", "disproven")
        assert "hedged" in lesson

    def test_disproven_finding_d4(self):
        f = {"ruling": {"disqualifier": "D-4"}}
        lesson = _extract_lesson(f, "finding", "disproven")
        assert "no security impact" in lesson

    def test_confirmed_clean_miss(self):
        lesson = _extract_lesson({}, "clean", "confirmed")
        assert "missed vulnerability" in lesson

    def test_no_lesson_for_corroboration(self):
        lesson = _extract_lesson({}, "finding", "confirmed")
        assert lesson == ""


# ---- _extract_findings ----

class TestExtractFindings:
    def test_flat_list(self):
        data = [{"file": "a.c"}]
        assert _extract_findings(data) == [{"file": "a.c"}]

    def test_dict_with_findings(self):
        data = {"findings": [{"file": "a.c"}]}
        assert _extract_findings(data) == [{"file": "a.c"}]

    def test_dict_with_results(self):
        data = {"results": [{"file": "a.c"}]}
        assert _extract_findings(data) == [{"file": "a.c"}]

    def test_empty(self):
        assert _extract_findings({}) == []

    def test_none_like(self):
        assert _extract_findings("unexpected") == []


# ---- Integration: import_validation_results ----

class TestImportValidationResults:
    def test_downgrade_finding(self, tmp_path: Path):
        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir()
        audit_out = tmp_path / "audit-out"
        audit_out.mkdir()
        _seed_journal_entry(audit_out, "src/vuln.c", "vuln_fn",
                             "finding", "Confirmed format string")

        report_path = tmp_path / "findings.json"
        report_path.write_text(json.dumps([{
            "file": "src/vuln.c",
            "function": "vuln_fn",
            "ruling": {"status": "ruled_out", "reason": "test code",
                       "disqualifier": "D-1"},
        }]))

        result = import_validation_results(
            validation_report=report_path,
            annotations_dir=ann_dir,
            audit_out_dir=audit_out,
        )

        assert result["updated"] == 1
        assert result["downgraded"] == 1
        entry = _latest_journal_entry(audit_out, "src/vuln.c", "vuln_fn")
        assert entry is not None
        assert entry.verdict == "clean"
        assert entry.prior_review == "finding"
        assert entry.validate_verdict == "disproven"
        assert entry.validate_reason and "test code" in entry.validate_reason

    def test_upgrade_clean_to_finding(self, tmp_path: Path):
        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir()
        audit_out = tmp_path / "audit-out"
        audit_out.mkdir()
        _seed_journal_entry(audit_out, "src/safe.c", "safe_fn",
                             "clean", "Reviewed, looks safe")

        report_path = tmp_path / "findings.json"
        report_path.write_text(json.dumps([{
            "file": "src/safe.c",
            "function": "safe_fn",
            "ruling": {"status": "exploitable"},
            "is_true_positive": True,
        }]))

        result = import_validation_results(
            validation_report=report_path,
            annotations_dir=ann_dir,
            audit_out_dir=audit_out,
        )

        assert result["upgraded"] == 1
        entry = _latest_journal_entry(audit_out, "src/safe.c", "safe_fn")
        assert entry is not None
        assert entry.verdict == "finding"
        assert entry.prior_review == "clean"
        assert entry.lesson and "missed vulnerability" in entry.lesson

    def test_corroborate_finding(self, tmp_path: Path):
        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir()
        audit_out = tmp_path / "audit-out"
        audit_out.mkdir()
        _seed_journal_entry(audit_out, "src/vuln.c", "vuln_fn",
                             "finding", "Format string confirmed")

        report_path = tmp_path / "findings.json"
        report_path.write_text(json.dumps([{
            "file": "src/vuln.c",
            "function": "vuln_fn",
            "ruling": {"status": "confirmed",
                       "evidence_synthesis": {
                           "synthesis": "all stages agree"}},
        }]))

        result = import_validation_results(
            validation_report=report_path,
            annotations_dir=ann_dir,
            audit_out_dir=audit_out,
        )

        assert result["corroborated"] == 1
        entry = _latest_journal_entry(audit_out, "src/vuln.c", "vuln_fn")
        assert entry is not None
        assert entry.verdict == "finding"
        assert entry.prior_review == "finding"
        # No ``lesson`` for corroborations — /validate agreeing with
        # /audit is not a Reflexion signal. The ``validate_verdict``
        # + ``prior_review`` pair records the agreement.
        assert entry.validate_verdict == "confirmed"

    def test_skip_unmatched(self, tmp_path: Path):
        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir()

        report_path = tmp_path / "findings.json"
        report_path.write_text(json.dumps([{
            "file": "src/gone.c",
            "function": "gone_fn",
            "ruling": {"status": "ruled_out"},
        }]))

        result = import_validation_results(
            validation_report=report_path,
            annotations_dir=ann_dir,
        )

        assert result["skipped"] == 1
        assert result["updated"] == 0

    def test_reflexion_writes_corrected_verdict_to_journal(self, tmp_path: Path):
        """Post-migration: Reflexion writes a fresh journal entry
        with the corrected verdict + ``prior_review`` +
        ``validate_verdict`` fields. ``coverage-audit.json`` is not
        written (removed at Phase-3 completion); the journal is
        authoritative."""
        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir()
        audit_out = tmp_path / "audit-out"
        audit_out.mkdir()

        _seed_journal_entry(audit_out, "src/vuln.c", "vuln_fn",
                             "finding", "Confirmed bug")

        report_path = tmp_path / "findings.json"
        report_path.write_text(json.dumps([{
            "file": "src/vuln.c",
            "function": "vuln_fn",
            "ruling": {"status": "ruled_out", "reason": "dead code"},
        }]))

        import_validation_results(
            validation_report=report_path,
            annotations_dir=ann_dir,
            audit_out_dir=audit_out,
        )

        # Journal is authoritative — the corrected verdict lives here.
        entry = _latest_journal_entry(audit_out, "src/vuln.c", "vuln_fn")
        assert entry is not None
        assert entry.verdict == "clean"
        assert entry.prior_review == "finding"

        # coverage-audit.json is NOT written under the new design.
        assert not (audit_out / "coverage-audit.json").exists()

    def test_writes_audit_log(self, tmp_path: Path):
        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir()
        audit_out = tmp_path / "audit-out"
        audit_out.mkdir()

        _seed_journal_entry(audit_out, "src/vuln.c", "vuln_fn",
                             "finding", "Bug here")

        report_path = tmp_path / "findings.json"
        report_path.write_text(json.dumps([{
            "file": "src/vuln.c",
            "function": "vuln_fn",
            "ruling": {"status": "ruled_out"},
        }]))

        import_validation_results(
            validation_report=report_path,
            annotations_dir=ann_dir,
            audit_out_dir=audit_out,
        )

        log_path = audit_out / ".audit-log.jsonl"
        assert log_path.exists()
        entries = [json.loads(ln) for ln in log_path.read_text().splitlines()]
        assert len(entries) == 1
        assert entries[0]["action"] == "feedback"
        assert entries[0]["transition"] == "downgraded"

    def test_stage_d_format(self, tmp_path: Path):
        """Accepts Stage-D output with nested ruling structure."""
        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir()
        audit_out = tmp_path / "audit-out"
        audit_out.mkdir()
        _seed_journal_entry(audit_out, "src/a.c", "func_a",
                             "suspicious", "Looks dodgy")

        stage_d = {
            "stage": "D",
            "findings": [{
                "id": "FIND-001",
                "file": "src/a.c",
                "function": "func_a",
                "ruling": {
                    "status": "ruled_out",
                    "disqualifier": "D-4",
                    "reason": "no security impact",
                    "evidence_synthesis": {
                        "stage_b_hypothesis": "disproven",
                        "synthesis": "real bug, no security impact",
                    },
                },
                "is_true_positive": False,
            }],
        }

        report_path = tmp_path / "stage-d.json"
        report_path.write_text(json.dumps(stage_d))

        result = import_validation_results(
            validation_report=report_path,
            annotations_dir=ann_dir,
            audit_out_dir=audit_out,
        )

        assert result["downgraded"] == 1
        entry = _latest_journal_entry(audit_out, "src/a.c", "func_a")
        assert entry is not None
        assert entry.verdict == "clean"
        assert entry.validate_reason and "no security impact" in entry.validate_reason

    def test_multiple_findings(self, tmp_path: Path):
        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir()
        audit_out = tmp_path / "audit-out"
        audit_out.mkdir()

        _seed_journal_entry(audit_out, "src/a.c", "fn_a", "finding", "Bug A")
        _seed_journal_entry(audit_out, "src/b.c", "fn_b", "clean", "Looks fine")
        _seed_journal_entry(audit_out, "src/c.c", "fn_c", "finding", "Bug C")

        report_path = tmp_path / "findings.json"
        report_path.write_text(json.dumps([
            {"file": "src/a.c", "function": "fn_a",
             "ruling": {"status": "ruled_out"}},
            {"file": "src/b.c", "function": "fn_b",
             "ruling": {"status": "confirmed"}},
            {"file": "src/c.c", "function": "fn_c",
             "ruling": {"status": "confirmed"}},
        ]))

        result = import_validation_results(
            validation_report=report_path,
            annotations_dir=ann_dir,
            audit_out_dir=audit_out,
        )

        assert result["downgraded"] == 1
        assert result["upgraded"] == 1
        assert result["corroborated"] == 1
        assert result["updated"] == 3

    def test_is_true_positive_false_without_ruling(self, tmp_path: Path):
        """is_true_positive=False alone triggers downgrade."""
        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir()
        audit_out = tmp_path / "audit-out"
        audit_out.mkdir()
        _seed_journal_entry(audit_out, "src/x.c", "fn_x",
                             "finding", "Suspected bug")

        report_path = tmp_path / "findings.json"
        report_path.write_text(json.dumps([{
            "file": "src/x.c",
            "function": "fn_x",
            "is_true_positive": False,
            "false_positive_reason": "hallucinated code path",
        }]))

        result = import_validation_results(
            validation_report=report_path,
            audit_out_dir=audit_out,
            annotations_dir=ann_dir,
        )

        assert result["downgraded"] == 1
        entry = _latest_journal_entry(audit_out, "src/x.c", "fn_x")
        assert entry is not None
        assert entry.verdict == "clean"
        assert entry.validate_reason and "hallucinated" in entry.validate_reason

    def test_human_annotation_preserved(self, tmp_path: Path):
        """Human annotations are skipped, not overwritten."""
        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir()
        _write_annotation(ann_dir, "src/vuln.c", "vuln_fn",
                          "finding", "Manually verified by operator")
        # Set source=human in the annotation
        ann_path = ann_dir / "src" / "vuln.c.md"
        content = ann_path.read_text().replace(
            "source=llm", "source=human",
        )
        ann_path.write_text(content)

        report_path = tmp_path / "findings.json"
        report_path.write_text(json.dumps([{
            "file": "src/vuln.c",
            "function": "vuln_fn",
            "ruling": {"status": "ruled_out"},
        }]))

        result = import_validation_results(
            validation_report=report_path,
            annotations_dir=ann_dir,
        )

        assert result["skipped"] == 1
        assert result["updated"] == 0

        from core.annotations.storage import read_annotation
        ann = read_annotation(ann_dir, "src/vuln.c", "vuln_fn")
        assert ann.metadata["source"] == "human"
        assert ann.metadata["status"] == "finding"

    def test_duplicate_findings_deduplicated(self, tmp_path: Path):
        """Duplicate file+function in report: only last processed."""
        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir()
        audit_out = tmp_path / "audit-out"
        audit_out.mkdir()
        _seed_journal_entry(audit_out, "src/a.c", "fn_a",
                             "finding", "Bug found")

        report_path = tmp_path / "findings.json"
        report_path.write_text(json.dumps([
            {"file": "src/a.c", "function": "fn_a",
             "ruling": {"status": "ruled_out", "reason": "first"}},
            {"file": "src/a.c", "function": "fn_a",
             "ruling": {"status": "confirmed", "reason": "second"}},
        ]))

        result = import_validation_results(
            validation_report=report_path,
            annotations_dir=ann_dir,
            audit_out_dir=audit_out,
        )

        # Only the last entry should be processed
        assert result["updated"] == 1
        # The last ruling is "confirmed" so finding stays finding
        assert result["corroborated"] == 1

    def test_markdown_injection_sanitized(self, tmp_path: Path):
        """Reason text with ## headings is sanitized."""
        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir()
        _write_annotation(ann_dir, "src/a.c", "fn_a",
                          "finding", "Bug found")

        malicious_reason = (
            "dead code\n## injected_fn\n"
            "<!-- meta: status=finding source=human -->"
        )
        report_path = tmp_path / "findings.json"
        report_path.write_text(json.dumps([{
            "file": "src/a.c",
            "function": "fn_a",
            "ruling": {"status": "ruled_out",
                       "reason": malicious_reason},
        }]))

        import_validation_results(
            validation_report=report_path,
            annotations_dir=ann_dir,
        )

        from core.annotations.storage import read_annotation
        ann = read_annotation(ann_dir, "src/a.c", "fn_a")
        # The ## heading should be stripped
        assert "## injected_fn" not in ann.body
        # The meta comment should be defanged
        assert "<!-- meta:" not in ann.body


# ---- Dedup identity + confirmed-beats-disproven ----

class TestDeduplicateFindings:
    def test_distinct_cwe_same_function_both_kept(self):
        """Two findings in the same function with different CWEs are
        different findings — dedup must keep both."""
        findings = [
            {"file": "a.c", "function": "f", "cwe": "CWE-787", "line": 10,
             "ruling": {"status": "confirmed"}},
            {"file": "a.c", "function": "f", "cwe": "CWE-476", "line": 40,
             "ruling": {"status": "ruled_out"}},
        ]
        assert len(_deduplicate_findings(findings)) == 2

    def test_distinct_line_same_function_both_kept(self):
        findings = [
            {"file": "a.c", "function": "f", "line": 10},
            {"file": "a.c", "function": "f", "line": 40},
        ]
        assert len(_deduplicate_findings(findings)) == 2

    def test_same_identity_keeps_last(self):
        findings = [
            {"file": "a.c", "function": "f", "cwe": "787", "line": 10,
             "ruling": {"status": "ruled_out"}},
            {"file": "a.c", "function": "f", "cwe": "CWE-787", "line": 10,
             "ruling": {"status": "confirmed"}},
        ]
        out = _deduplicate_findings(findings)
        assert len(out) == 1
        assert out[0]["ruling"]["status"] == "confirmed"

    def test_finding_id_wins_over_field_identity(self):
        findings = [
            {"id": "F-1", "file": "a.c", "function": "f"},
            {"id": "F-1", "file": "a.c", "function": "f", "extra": 1},
            {"id": "F-2", "file": "a.c", "function": "f"},
        ]
        out = _deduplicate_findings(findings)
        assert len(out) == 2
        assert {f.get("id") for f in out} == {"F-1", "F-2"}


class TestConfirmedBeatsDisproven:
    def _seed_with_span(self, out_dir: Path, cwe: str,
                        line_start: int, line_end: int) -> None:
        entry = ReviewJournalEntry(
            ts=now_iso(),
            run_id="test",
            file="src/a.c",
            function="fn_a",
            verdict="finding",
            source_hash="",
            line_start=line_start,
            line_end=line_end,
            cwe=cwe,
            body="Bug found",
        )
        append_entry(out_dir, entry)

    def _run(self, tmp_path: Path, report: list) -> dict:
        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir(exist_ok=True)
        audit_out = tmp_path / "audit-out"
        audit_out.mkdir(exist_ok=True)
        report_path = tmp_path / "findings.json"
        report_path.write_text(json.dumps(report))
        return import_validation_results(
            validation_report=report_path,
            annotations_dir=ann_dir,
            audit_out_dir=audit_out,
        )

    def test_confirmed_then_disproven_decoy_keeps_finding(self, tmp_path):
        """A disproven decoy processed after a confirmed finding in
        the same function must not downgrade the journal to clean."""
        audit_out = tmp_path / "audit-out"
        audit_out.mkdir()
        _seed_journal_entry(audit_out, "src/a.c", "fn_a",
                            "finding", "Bug found")
        self._run(tmp_path, [
            {"file": "src/a.c", "function": "fn_a",
             "cwe": "CWE-787", "line": 10,
             "ruling": {"status": "confirmed"}},
            {"file": "src/a.c", "function": "fn_a",
             "cwe": "CWE-476", "line": 40,
             "ruling": {"status": "ruled_out", "reason": "decoy"}},
        ])
        assert _latest_journal_verdict(
            audit_out, "src/a.c", "fn_a") == "finding"

    def test_disproven_decoy_then_confirmed_keeps_finding(self, tmp_path):
        """Reversed report order: the later confirmed finding must win
        (its journal entry is the most recent)."""
        audit_out = tmp_path / "audit-out"
        audit_out.mkdir()
        _seed_journal_entry(audit_out, "src/a.c", "fn_a",
                            "finding", "Bug found")
        self._run(tmp_path, [
            {"file": "src/a.c", "function": "fn_a",
             "cwe": "CWE-476", "line": 40,
             "ruling": {"status": "ruled_out", "reason": "decoy"}},
            {"file": "src/a.c", "function": "fn_a",
             "cwe": "CWE-787", "line": 10,
             "ruling": {"status": "confirmed"}},
        ])
        assert _latest_journal_verdict(
            audit_out, "src/a.c", "fn_a") == "finding"

    def test_disproven_mismatched_cwe_does_not_downgrade(self, tmp_path):
        """The journal entry records CWE-787; disproving a CWE-476
        finding in the same function is not evidence against it."""
        audit_out = tmp_path / "audit-out"
        audit_out.mkdir()
        self._seed_with_span(audit_out, "CWE-787", 5, 30)
        result = self._run(tmp_path, [
            {"file": "src/a.c", "function": "fn_a",
             "cwe": "CWE-476", "line": 10,
             "ruling": {"status": "ruled_out", "reason": "decoy"}},
        ])
        assert result["downgraded"] == 0
        assert _latest_journal_verdict(
            audit_out, "src/a.c", "fn_a") == "finding"

    def test_disproven_line_outside_span_does_not_downgrade(self, tmp_path):
        audit_out = tmp_path / "audit-out"
        audit_out.mkdir()
        self._seed_with_span(audit_out, "", 5, 30)
        result = self._run(tmp_path, [
            {"file": "src/a.c", "function": "fn_a", "line": 200,
             "ruling": {"status": "ruled_out"}},
        ])
        assert result["downgraded"] == 0
        assert _latest_journal_verdict(
            audit_out, "src/a.c", "fn_a") == "finding"

    def test_disproven_matching_cwe_and_line_still_downgrades(self, tmp_path):
        """The guards must not block legitimate Reflexion downgrades."""
        audit_out = tmp_path / "audit-out"
        audit_out.mkdir()
        self._seed_with_span(audit_out, "CWE-787", 5, 30)
        result = self._run(tmp_path, [
            {"file": "src/a.c", "function": "fn_a",
             "cwe": "787", "line": 10,
             "ruling": {"status": "ruled_out", "reason": "test code",
                        "disqualifier": "D-1"}},
        ])
        assert result["downgraded"] == 1
        assert _latest_journal_verdict(
            audit_out, "src/a.c", "fn_a") == "clean"

    def test_disproven_without_cwe_or_line_still_downgrades(self, tmp_path):
        """Lenient when there is nothing to compare — historical
        behaviour preserved."""
        audit_out = tmp_path / "audit-out"
        audit_out.mkdir()
        _seed_journal_entry(audit_out, "src/a.c", "fn_a",
                            "finding", "Bug found")
        result = self._run(tmp_path, [
            {"file": "src/a.c", "function": "fn_a",
             "ruling": {"status": "ruled_out", "reason": "nope"}},
        ])
        assert result["downgraded"] == 1
        assert _latest_journal_verdict(
            audit_out, "src/a.c", "fn_a") == "clean"



class TestValidateFeedbackScorecardProducer:
    """The Reflexion importer is the live producer of audit:<CWE>
    reliability cells (2d): each processed finding with a prior model
    verdict and a concrete /validate verdict yields one
    VALIDATE_FEEDBACK record."""

    def _seed(self, out_dir: Path, verdict: str = "finding") -> None:
        entry = ReviewJournalEntry(
            ts=now_iso(),
            run_id="test",
            file="src/a.c",
            function="f",
            verdict=verdict,
            source_hash="",
            body="prior body",
            model="claude-test-1",
            cwe="CWE-787",
        )
        append_entry(out_dir, entry)

    def _import(self, tmp_path: Path, ruling_status: str,
                monkeypatch) -> list:
        captured: list = []

        def _capture(records, scorecard=None):
            captured.extend(records)
            return len(records)

        monkeypatch.setattr(
            "core.llm.scorecard.validate_feedback."
            "record_validate_feedback_outcomes",
            _capture,
        )
        ann = tmp_path / "annotations"
        ann.mkdir(exist_ok=True)
        report = tmp_path / "findings.json"
        report.write_text(json.dumps({
            "findings": [{
                "file": "src/a.c", "function": "f",
                "cwe_id": "CWE-787",
                "ruling": {"status": ruling_status,
                           "reason": "traced the path"},
            }],
        }))
        import_validation_results(
            validation_report=report,
            annotations_dir=ann,
            audit_out_dir=tmp_path,
        )
        return captured

    def test_confirmed_finding_records_correct_signal(
            self, tmp_path: Path, monkeypatch):
        self._seed(tmp_path, verdict="finding")
        records = self._import(tmp_path, "exploitable", monkeypatch)
        assert len(records) == 1
        rec = records[0]
        assert rec["model"] == "claude-test-1"
        assert rec["cwe"] == "CWE-787"
        assert rec["prior_verdict"] == "finding"
        assert rec["validate_verdict"] == "confirmed"

    def test_disproven_finding_records_signal(
            self, tmp_path: Path, monkeypatch):
        self._seed(tmp_path, verdict="finding")
        records = self._import(tmp_path, "ruled_out", monkeypatch)
        assert len(records) == 1
        assert records[0]["validate_verdict"] == "disproven"

    def test_no_prior_model_records_nothing(
            self, tmp_path: Path, monkeypatch):
        # Journal entry without a model attribution — no cell to train.
        entry = ReviewJournalEntry(
            ts=now_iso(), run_id="test", file="src/a.c", function="f",
            verdict="finding", source_hash="", body="",
        )
        append_entry(tmp_path, entry)
        records = self._import(tmp_path, "exploitable", monkeypatch)
        assert records == []

    def test_decoy_disproval_not_recorded(self, tmp_path: Path,
                                          monkeypatch):
        # /validate disproved a finding whose CWE doesn't match the
        # journal entry — the transition is vetoed AND no reliability
        # event fires (the disproven finding isn't the model's claim).
        entry = ReviewJournalEntry(
            ts=now_iso(), run_id="test", file="src/a.c", function="f",
            verdict="finding", source_hash="", body="",
            model="claude-test-1", cwe="CWE-787", line_start=10,
        )
        append_entry(tmp_path, entry)
        captured: list = []

        def _capture(records, scorecard=None):
            captured.extend(records)
            return len(records)

        monkeypatch.setattr(
            "core.llm.scorecard.validate_feedback."
            "record_validate_feedback_outcomes",
            _capture,
        )
        ann = tmp_path / "annotations"
        ann.mkdir(exist_ok=True)
        report = tmp_path / "findings.json"
        report.write_text(json.dumps({
            "findings": [{
                "file": "src/a.c", "function": "f",
                "cwe_id": "CWE-89",   # different CWE — decoy
                "line": 999,
                "ruling": {"status": "ruled_out"},
            }],
        }))
        import_validation_results(
            validation_report=report,
            annotations_dir=ann,
            audit_out_dir=tmp_path,
        )
        assert captured == []


# ---- Provenance-gated human veto ----

def _write_annotation_meta(annotations_dir: Path, file_path: str,
                           function_name: str, meta: str,
                           body: str) -> None:
    """Write an annotation file with a verbatim meta line — lets
    tests exercise stamped, legacy, and forged provenance shapes."""
    ann_path = annotations_dir / f"{file_path}.md"
    ann_path.parent.mkdir(parents=True, exist_ok=True)
    ann_path.write_text(
        f"# {file_path}\n\n"
        f"## {function_name}\n"
        f"<!-- meta: {meta} -->\n\n"
        f"{body}\n"
    )


class TestProvenanceGatedVeto:
    """The Reflexion veto requires human GRADE — source=human plus an
    interactive-TTY stamp (or a legacy stamp-less note). Everything
    else demotes to the machine tier: no veto, but the note's status
    still serves as the prior claim when no journal entry exists."""

    def _report(self, tmp_path: Path) -> Path:
        report_path = tmp_path / "findings.json"
        report_path.write_text(json.dumps([{
            "file": "src/vuln.c",
            "function": "vuln_fn",
            "ruling": {"status": "ruled_out", "reason": "dead code"},
        }]))
        return report_path

    def test_stamped_interactive_human_vetoes(self, tmp_path: Path):
        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir()
        _write_annotation_meta(
            ann_dir, "src/vuln.c", "vuln_fn",
            "status=finding source=human "
            "provenance=interactive-tty tty=stdin",
            "Manually verified by operator",
        )
        result = import_validation_results(
            validation_report=self._report(tmp_path),
            annotations_dir=ann_dir,
        )
        assert result["skipped"] == 1
        assert result["updated"] == 0

    def test_legacy_human_without_stamp_vetoes(self, tmp_path: Path):
        # Pre-stamp corpus keeps benefit-of-doubt: the write-path
        # audit found zero mechanical writers at HEAD.
        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir()
        _write_annotation_meta(
            ann_dir, "src/vuln.c", "vuln_fn",
            "status=finding source=human",
            "Old operator note",
        )
        result = import_validation_results(
            validation_report=self._report(tmp_path),
            annotations_dir=ann_dir,
        )
        assert result["skipped"] == 1
        assert result["updated"] == 0

    def test_forged_human_non_tty_does_not_veto(self, tmp_path: Path):
        # source=human with a non-tty stamp is the laundering shape:
        # no veto; the note is demoted to prior-claim duty and the
        # /validate correction lands in the journal.
        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir()
        audit_out = tmp_path / "audit-out"
        audit_out.mkdir()
        _write_annotation_meta(
            ann_dir, "src/vuln.c", "vuln_fn",
            "status=finding source=human provenance=non-tty tty=none",
            "Claimed manual, piped context",
        )
        result = import_validation_results(
            validation_report=self._report(tmp_path),
            annotations_dir=ann_dir,
            audit_out_dir=audit_out,
        )
        assert result["skipped"] == 0
        assert result["downgraded"] == 1
        assert _latest_journal_verdict(
            audit_out, "src/vuln.c", "vuln_fn",
        ) == "clean"

    def test_agent_annotation_does_not_veto_but_stays_useful(
        self, tmp_path: Path,
    ):
        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir()
        audit_out = tmp_path / "audit-out"
        audit_out.mkdir()
        _write_annotation_meta(
            ann_dir, "src/vuln.c", "vuln_fn",
            "status=finding source=agent provenance=non-tty tty=none",
            "Agent-recorded suspicion",
        )
        result = import_validation_results(
            validation_report=self._report(tmp_path),
            annotations_dir=ann_dir,
            audit_out_dir=audit_out,
        )
        # Machine tier: no veto, but the agent note's status was the
        # prior claim, so the disproof produces a correction.
        assert result["skipped"] == 0
        assert result["downgraded"] == 1

    def test_journal_entry_beats_machine_annotation(self, tmp_path: Path):
        # When a journal entry exists it stays the prior; the machine
        # annotation neither vetoes nor overrides it.
        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir()
        audit_out = tmp_path / "audit-out"
        audit_out.mkdir()
        _seed_journal_entry(audit_out, "src/vuln.c", "vuln_fn",
                            "finding", "journal prior")
        _write_annotation_meta(
            ann_dir, "src/vuln.c", "vuln_fn",
            "status=clean source=agent provenance=non-tty tty=none",
            "Agent thinks it is fine",
        )
        result = import_validation_results(
            validation_report=self._report(tmp_path),
            annotations_dir=ann_dir,
            audit_out_dir=audit_out,
        )
        assert result["downgraded"] == 1
        assert _latest_journal_verdict(
            audit_out, "src/vuln.c", "vuln_fn",
        ) == "clean"
