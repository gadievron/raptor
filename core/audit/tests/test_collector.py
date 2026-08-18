"""Tests for core.audit.collector.Collector."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.audit.collector import Collector


@dataclass
class _FakeOutcome:
    file: str = "src/auth.py"
    function: str = "check_pw"
    status: str = "finding"
    body: str = "SQL injection in query"
    model: str = "test-model"
    cost_usd: float = 0.01
    duration_s: float = 1.5
    hypothesis: str = ""
    hypotheses: list[str] = field(default_factory=list)
    evidence_tool: str = ""
    review_result: dict[str, Any] | None = None


def _make_gap(file: str = "src/auth.py", name: str = "check_pw") -> dict[str, Any]:
    return {"file": file, "name": name, "line_start": 10, "line_end": 30}


def _write_checklist(out_dir: Path, files: list[dict]) -> None:
    cl = {"files": files}
    (out_dir / "checklist.json").write_text(json.dumps(cl), encoding="utf-8")


class TestCollectorSubmitAndFlush:
    def test_journal_written_immediately_not_on_flush(self, tmp_path: Path) -> None:
        from core.coverage.journal import load_entries
        c = Collector(out_dir=tmp_path, target_path=tmp_path)
        c.submit(_FakeOutcome(function="check_pw"), _make_gap(name="check_pw"))
        c.submit(_FakeOutcome(function="login"), _make_gap(name="login"))

        entries = load_entries(tmp_path)
        assert len(entries) == 2
        assert entries[0].function == "check_pw"
        assert entries[1].function == "login"

        c.flush()
        entries_after = load_entries(tmp_path)
        assert len(entries_after) == 2

    def test_batches_audit_log_single_write(self, tmp_path: Path) -> None:
        c = Collector(out_dir=tmp_path, target_path=tmp_path)
        c.submit(_FakeOutcome(function="a"), _make_gap(name="a"))
        c.submit(_FakeOutcome(function="b"), _make_gap(name="b"))

        log_path = tmp_path / ".audit-log.jsonl"
        assert not log_path.exists()

        c.flush()

        lines = log_path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0])["key"] == "src/auth.py:a:10"
        assert json.loads(lines[1])["key"] == "src/auth.py:b:10"

    def test_flush_is_idempotent(self, tmp_path: Path) -> None:
        c = Collector(out_dir=tmp_path, target_path=tmp_path)
        c.submit(_FakeOutcome(), _make_gap())
        c.flush()
        c.flush()
        lines = (tmp_path / ".audit-log.jsonl").read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 1

    def test_error_status_not_marked_checked(self, tmp_path: Path) -> None:
        _write_checklist(tmp_path, [
            {"path": "src/auth.py", "items": [{"name": "check_pw"}]},
        ])
        c = Collector(out_dir=tmp_path, target_path=tmp_path)
        c.submit(_FakeOutcome(status="error"), _make_gap())
        c.flush()

        cl = json.loads((tmp_path / "checklist.json").read_text(encoding="utf-8"))
        assert "checked_by" not in cl["files"][0]["items"][0]

    def test_no_checklist_file_no_crash(self, tmp_path: Path) -> None:
        c = Collector(out_dir=tmp_path, target_path=tmp_path)
        c.submit(_FakeOutcome(), _make_gap())
        c.flush()

    def test_audit_log_entry_fields(self, tmp_path: Path) -> None:
        outcome = _FakeOutcome(
            hypothesis="tainted input",
            evidence_tool="joern",
        )
        outcome.review_result = {"preconditions": ["auth required"]}
        gap = _make_gap()
        gap["strategies"] = ["sql_injection"]

        c = Collector(out_dir=tmp_path, target_path=tmp_path)
        c.submit(outcome, gap)
        c.flush()

        entry = json.loads(
            (tmp_path / ".audit-log.jsonl").read_text(encoding="utf-8").strip(),
        )
        assert entry["hypothesis"] == "tainted input"
        assert entry["evidence_tool"] == "joern"
        assert entry["preconditions"] == ["auth required"]
        assert entry["strategies"] == ["sql_injection"]

    def test_checklist_not_mutated_by_collector(self, tmp_path: Path) -> None:
        """Post-migration: Collector doesn't stamp ``checked_by`` on
        the checklist. Journal is authoritative for LLM review
        existence; checklist is a pure inventory snapshot. Any
        pre-existing ``checked_by`` (from a prior tool run, e.g.
        ``scan``) is preserved untouched — but no fresh
        ``audit`` entry is added by the review path."""
        _write_checklist(tmp_path, [
            {"path": "src/auth.py", "items": [
                {"name": "check_pw", "checked_by": ["scan"]},
            ]},
        ])
        c = Collector(out_dir=tmp_path, target_path=tmp_path)
        c.submit(_FakeOutcome(), _make_gap())
        c.flush()

        cl = json.loads((tmp_path / "checklist.json").read_text(encoding="utf-8"))
        by = cl["files"][0]["items"][0].get("checked_by", [])
        assert "scan" in by
        assert "audit" not in by

    def test_multiple_submits_produce_multiple_journal_entries(self, tmp_path: Path) -> None:
        from core.coverage.journal import load_entries
        c = Collector(out_dir=tmp_path, target_path=tmp_path)
        c.submit(_FakeOutcome(model="model-a"), _make_gap())
        c.submit(_FakeOutcome(model="model-b"), _make_gap())
        c.flush()

        entries = load_entries(tmp_path)
        assert len(entries) == 2
        assert entries[0].model == "model-a"
        assert entries[1].model == "model-b"


class TestCollectorJournalDualWrite:
    """Verify each submit lands in the journal (the sole review store)."""

    def test_append_journal_without_checked_by(self, tmp_path: Path) -> None:
        """checked_by is vestigial — callers may omit it entirely."""
        from core.audit.collector import append_journal_for_outcome
        from core.coverage.journal import load_entries
        append_journal_for_outcome(
            out_dir=tmp_path,
            target_path=tmp_path,
            run_id="r1",
            outcome=_FakeOutcome(),
            gap=_make_gap(),
        )
        entries = load_entries(tmp_path)
        assert len(entries) == 1
        assert entries[0].model == "test-model"

    def test_submit_creates_journal_entry(self, tmp_path: Path) -> None:
        from core.coverage.journal import load_entries
        c = Collector(out_dir=tmp_path, target_path=tmp_path, run_id="test-run")
        c.submit(_FakeOutcome(), _make_gap())
        entries = load_entries(tmp_path)
        assert len(entries) == 1
        assert entries[0].file == "src/auth.py"
        assert entries[0].function == "check_pw"
        assert entries[0].verdict == "finding"
        assert entries[0].run_id == "test-run"
        assert entries[0].model == "test-model"

    def test_journal_entries_match_submits(self, tmp_path: Path) -> None:
        from core.coverage.journal import load_entries
        c = Collector(out_dir=tmp_path, target_path=tmp_path, run_id="r1")
        c.submit(_FakeOutcome(function="fn_a"), _make_gap(name="fn_a"))
        c.submit(_FakeOutcome(function="fn_b", status="clean"),
                 _make_gap(name="fn_b"))
        entries = load_entries(tmp_path)
        assert len(entries) == 2
        assert entries[0].function == "fn_a"
        assert entries[0].verdict == "finding"
        assert entries[1].function == "fn_b"
        assert entries[1].verdict == "clean"

    def test_journal_captures_strategies(self, tmp_path: Path) -> None:
        from core.coverage.journal import load_entries
        gap = _make_gap()
        gap["strategies"] = ["aliasing", "input_handling"]
        c = Collector(out_dir=tmp_path, target_path=tmp_path)
        c.submit(_FakeOutcome(), gap)
        entries = load_entries(tmp_path)
        assert entries[0].strategies == ["aliasing", "input_handling"]

    def test_journal_captures_hypotheses(self, tmp_path: Path) -> None:
        from core.coverage.journal import load_entries
        outcome = _FakeOutcome(
            hypotheses=[{"claim": "overflow", "status": "disproven"}],
        )
        c = Collector(out_dir=tmp_path, target_path=tmp_path)
        c.submit(outcome, _make_gap())
        entries = load_entries(tmp_path)
        assert entries[0].hypotheses == [{"claim": "overflow", "status": "disproven"}]

    def test_journal_captures_domain_model_hash(self, tmp_path: Path) -> None:
        from core.coverage.journal import load_entries
        dm = {"concepts": [{"id": "test"}]}
        (tmp_path / "domain-model.json").write_text(
            json.dumps(dm), encoding="utf-8",
        )
        c = Collector(out_dir=tmp_path, target_path=tmp_path)
        c.submit(_FakeOutcome(), _make_gap())
        entries = load_entries(tmp_path)
        assert entries[0].domain_model_hash is not None
        assert len(entries[0].domain_model_hash) == 8

    def test_invalidate_domain_model_cache(self, tmp_path: Path) -> None:
        from core.coverage.journal import load_entries
        c = Collector(out_dir=tmp_path, target_path=tmp_path)
        c.submit(_FakeOutcome(function="fn1"), _make_gap(name="fn1"))
        hash1 = load_entries(tmp_path)[0].domain_model_hash

        dm = {"concepts": [{"id": "new_concept"}]}
        (tmp_path / "domain-model.json").write_text(
            json.dumps(dm), encoding="utf-8",
        )
        c.invalidate_domain_model_cache()
        c.submit(_FakeOutcome(function="fn2"), _make_gap(name="fn2"))
        entries = load_entries(tmp_path)
        hash2 = entries[1].domain_model_hash
        assert hash2 is not None
        assert hash1 != hash2

    def test_error_status_still_journaled(self, tmp_path: Path) -> None:
        from core.coverage.journal import load_entries
        c = Collector(out_dir=tmp_path, target_path=tmp_path)
        c.submit(_FakeOutcome(status="error"), _make_gap())
        entries = load_entries(tmp_path)
        assert len(entries) == 1
        assert entries[0].verdict == "error"


class TestCollectorSageHypothesis:
    """Test SAGE hypothesis store wiring in Collector.submit()."""

    def test_stores_verdict_when_hash_present(self, tmp_path: Path) -> None:
        from unittest.mock import patch

        calls: list = []

        def capture(**kwargs):
            calls.append(kwargs)
            return True

        c = Collector(out_dir=tmp_path, target_path=tmp_path)
        outcome = _FakeOutcome(
            status="clean", hypothesis="unchecked return",
            evidence_tool="semgrep:ret-check",
        )
        gap = _make_gap()
        gap["_sage_source_hash"] = "abc123"

        with patch("core.sage.hooks.store_audit_hypothesis_verdict", side_effect=capture):
            c.submit(outcome, gap)

        assert len(calls) == 1
        assert calls[0]["file_path"] == "src/auth.py"
        assert calls[0]["function"] == "check_pw"
        assert calls[0]["hypothesis"] == "unchecked return"
        assert calls[0]["status"] == "clean"
        assert calls[0]["source_hash"] == "abc123"

    def test_skips_without_source_hash(self, tmp_path: Path) -> None:
        from unittest.mock import patch

        c = Collector(out_dir=tmp_path, target_path=tmp_path)
        outcome = _FakeOutcome(status="clean", hypothesis="test")
        gap = _make_gap()

        with patch("core.sage.hooks.store_audit_hypothesis_verdict") as mock:
            c.submit(outcome, gap)
            mock.assert_not_called()

    def test_skips_error_status(self, tmp_path: Path) -> None:
        from unittest.mock import patch

        c = Collector(out_dir=tmp_path, target_path=tmp_path)
        outcome = _FakeOutcome(status="error", hypothesis="test")
        gap = _make_gap()
        gap["_sage_source_hash"] = "h1"

        with patch("core.sage.hooks.store_audit_hypothesis_verdict") as mock:
            c.submit(outcome, gap)
            mock.assert_not_called()

    def test_skips_empty_hypothesis(self, tmp_path: Path) -> None:
        from unittest.mock import patch

        c = Collector(out_dir=tmp_path, target_path=tmp_path)
        outcome = _FakeOutcome(status="clean", hypothesis="")
        gap = _make_gap()
        gap["_sage_source_hash"] = "h1"

        with patch("core.sage.hooks.store_audit_hypothesis_verdict") as mock:
            c.submit(outcome, gap)
            mock.assert_not_called()

    def test_sage_error_does_not_break_submit(self, tmp_path: Path) -> None:
        from unittest.mock import patch

        c = Collector(out_dir=tmp_path, target_path=tmp_path)
        outcome = _FakeOutcome(status="clean", hypothesis="test hyp")
        gap = _make_gap()
        gap["_sage_source_hash"] = "h1"

        with patch("core.sage.hooks.store_audit_hypothesis_verdict", side_effect=RuntimeError("boom")):
            c.submit(outcome, gap)

        assert len(c._log_entries) == 1
