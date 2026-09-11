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
    # A legitimate finding carries a tool receipt — the journal-write
    # promotion gate demotes an evidence-less finding to suspicious
    # (that path is exercised in test_promotion_alarm.py).
    evidence_tool: str = "semgrep:sql-injection"
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


class TestEvidenceToolsSeparation:
    """Regression: journal evidence_tools must carry only the CONFIRMING
    receipt — never the tools_dispatched union. A dispatched-but-
    silent tool reading as a confirming receipt made false positives
    permanently undemotable via feedback's referee and corrupted
    per-channel survival/attribution telemetry."""

    def _submit(self, tmp_path, outcome):
        from core.coverage.journal import load_entries
        c = Collector(out_dir=tmp_path, target_path=tmp_path)
        c.submit(outcome, _make_gap())
        entries = load_entries(tmp_path)
        assert len(entries) == 1
        return entries[0]

    def test_dispatched_but_silent_tools_are_not_evidence(self, tmp_path):
        # The verifier PoC: semgrep dispatched, found nothing
        # (confirmed=set(), ran={'semgrep'}) — the journal row used to
        # show evidence_tools=['semgrep'] while outcome.evidence_tool
        # was empty.
        outcome = _FakeOutcome(
            status="suspicious", evidence_tool="",
        )
        outcome.tools_dispatched = {"semgrep", "joern"}
        entry = self._submit(tmp_path, outcome)
        assert entry.evidence_tools == []
        assert entry.tools_dispatched == ["joern", "semgrep"]

    def test_confirming_receipt_is_evidence(self, tmp_path):
        outcome = _FakeOutcome(
            status="finding", evidence_tool="smt:check-overflow",
        )
        outcome.tools_dispatched = {"smt", "semgrep"}
        entry = self._submit(tmp_path, outcome)
        assert entry.evidence_tools == ["smt:check-overflow"]
        assert entry.tools_dispatched == ["semgrep", "smt"]

    def test_referee_does_not_grade_dispatched_as_tool_evidence(
        self, tmp_path,
    ):
        # The verdict-affecting consumer from the PoC: feedback's
        # _prior_has_tool_evidence must come back False for a
        # dispatched-but-silent journal entry, so an LLM-only
        # /validate 'disproven' ruling can demote the claim.
        from core.audit.feedback import _prior_has_tool_evidence

        outcome = _FakeOutcome(status="suspicious", evidence_tool="")
        outcome.tools_dispatched = {"semgrep"}
        entry = self._submit(tmp_path, outcome)
        assert _prior_has_tool_evidence(entry) is False

    def test_round_trip_preserves_tools_dispatched(self, tmp_path):
        from core.coverage.journal import _entry_from_dict

        outcome = _FakeOutcome(status="suspicious", evidence_tool="")
        outcome.tools_dispatched = {"coccinelle"}
        entry = self._submit(tmp_path, outcome)
        raw = entry.to_dict()
        assert raw["tools_dispatched"] == ["coccinelle"]
        assert "evidence_tools" not in raw or raw["evidence_tools"] == []
        rebuilt = _entry_from_dict(raw)
        assert rebuilt.tools_dispatched == ["coccinelle"]


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


class TestCorrectiveStrategyInheritance:
    """Strategies-less corrective writes (deepen / post-loop re-review
    commit paths pass synthetic gaps without the field) inherit the
    strategy set the run's own journal already recorded for the site,
    so the corrective row keeps the review's briefing instead of
    shadowing it with ``strategies: []`` (which made cross-run verdict
    reuse refuse the function as strategy_changed forever)."""

    def _write(self, out_dir: Path, gap: dict, **outcome_over) -> None:
        from core.audit.collector import append_journal_for_outcome
        outcome = _FakeOutcome(**outcome_over)
        append_journal_for_outcome(
            out_dir=out_dir, target_path=out_dir, run_id="run-1",
            outcome=outcome, gap=gap,
        )

    def test_corrective_write_inherits_site_strategies(
        self, tmp_path: Path,
    ) -> None:
        from core.coverage.journal import load_entries
        self._write(
            tmp_path,
            {"line_start": 10, "line_end": 30,
             "strategies": ["general", "input_handling"]},
            status="suspicious",
        )
        self._write(tmp_path, {"line_start": 10}, status="clean",
                    body="[resolution] corrective")
        entries = load_entries(tmp_path)
        assert entries[-1].verdict == "clean"
        assert entries[-1].strategies == ["general", "input_handling"]

    def test_no_prior_row_keeps_empty_record(self, tmp_path: Path) -> None:
        from core.coverage.journal import load_entries
        self._write(tmp_path, {"line_start": 10}, status="clean")
        assert load_entries(tmp_path)[-1].strategies == []

    def test_other_site_never_donates(self, tmp_path: Path) -> None:
        # Same-named sibling at a different span must not donate its
        # briefing to this site's corrective row.
        from core.coverage.journal import load_entries
        self._write(
            tmp_path,
            {"line_start": 10, "line_end": 30, "strategies": ["auth"]},
            status="suspicious",
        )
        self._write(tmp_path, {"line_start": 99}, status="clean")
        assert load_entries(tmp_path)[-1].strategies == []

    def test_agentic_producer_never_inherits(self, tmp_path: Path) -> None:
        from core.audit.collector import append_journal_for_outcome
        from core.coverage.journal import load_entries
        self._write(
            tmp_path,
            {"line_start": 10, "line_end": 30, "strategies": ["auth"]},
            status="suspicious",
        )
        append_journal_for_outcome(
            out_dir=tmp_path, target_path=tmp_path, run_id="run-1",
            outcome=_FakeOutcome(status="clean"),
            gap={"line_start": 10}, producer="agentic",
        )
        assert load_entries(tmp_path)[-1].strategies == []

    def test_later_segment_row_found_after_snapshot(
        self, tmp_path: Path,
    ) -> None:
        # The per-run snapshot is built at the first strategies-less
        # write; a site journaled only AFTER that must still resolve
        # (miss-triggered refresh when the journal grew).
        from core.coverage.journal import load_entries
        self._write(tmp_path, {"line_start": 10}, status="clean")
        self._write(
            tmp_path,
            {"line_start": 50, "line_end": 70, "strategies": ["memory"]},
            status="suspicious", function="login",
        )
        self._write(tmp_path, {"line_start": 50}, status="clean",
                    function="login")
        assert load_entries(tmp_path)[-1].strategies == ["memory"]

    def test_mechanical_echo_never_donates(self, tmp_path: Path) -> None:
        # A post-loop mechanical echo row's ``post-loop-mechanical``
        # tag is a row-kind marker, not a review briefing — inheriting
        # it turns the corrective row itself into a mechanical echo
        # for every is_mechanical_echo consumer (dropped from reviewed
        # counts, refused by cross-run reuse as strategy_changed).
        from core.coverage.journal import is_mechanical_echo, load_entries
        self._write(
            tmp_path,
            {"line_start": 0, "strategies": ["post-loop-mechanical"]},
            status="suspicious", body="[mechanical] pattern hit",
        )
        self._write(tmp_path, {"line_start": 10}, status="clean",
                    body="[resolution] corrective")
        entry = load_entries(tmp_path)[-1]
        assert entry.strategies == []
        assert not is_mechanical_echo(entry)


class TestFlushDurability:
    """flush() is re-usable (post-loop passes submit AFTER the first
    flush), retains entries on write failure, and appends through the
    hardened JSONL writer (no symlink-follow)."""

    def test_flush_reusable_across_post_loop_submits(
        self, tmp_path: Path,
    ) -> None:
        c = Collector(out_dir=tmp_path, target_path=tmp_path)
        c.submit(_FakeOutcome(function="main_loop"), _make_gap(name="main_loop"))
        c.flush()
        # Post-loop pass (dark verify / IRIS telemetry) submits more —
        # a one-shot latch used to silently discard this.
        c.submit(_FakeOutcome(function="post_loop"), _make_gap(name="post_loop"))
        c.flush()
        lines = (tmp_path / ".audit-log.jsonl").read_text(
            encoding="utf-8",
        ).strip().split("\n")
        keys = [json.loads(ln)["key"] for ln in lines]
        assert keys == [
            "src/auth.py:main_loop:10", "src/auth.py:post_loop:10",
        ]

    def test_failed_write_retains_entries(
        self, tmp_path: Path, monkeypatch,
    ) -> None:
        import core.json as core_json

        c = Collector(out_dir=tmp_path, target_path=tmp_path)
        c.submit(_FakeOutcome(function="kept"), _make_gap(name="kept"))

        real = core_json.append_jsonl
        state = {"fail": True}

        def flaky(*args, **kwargs):
            if state["fail"]:
                raise OSError("disk full")
            return real(*args, **kwargs)

        monkeypatch.setattr(core_json, "append_jsonl", flaky)
        c.flush()  # must not raise, must not mark flushed
        assert not (tmp_path / ".audit-log.jsonl").exists()

        state["fail"] = False
        c.flush()
        lines = (tmp_path / ".audit-log.jsonl").read_text(
            encoding="utf-8",
        ).strip().split("\n")
        assert len(lines) == 1
        assert json.loads(lines[0])["key"] == "src/auth.py:kept:10"

    def test_symlinked_audit_log_refused(self, tmp_path: Path) -> None:
        # A symlink planted at the trail path in the target-writable
        # run dir must be refused (O_NOFOLLOW), never followed.
        out = tmp_path / "out"
        out.mkdir()
        victim = tmp_path / "victim.txt"
        victim.write_text("host file\n")
        (out / ".audit-log.jsonl").symlink_to(victim)

        c = Collector(out_dir=out, target_path=tmp_path)
        c.submit(_FakeOutcome(function="x"), _make_gap(name="x"))
        c.flush()  # swallows the OSError, retains the entry
        assert victim.read_text() == "host file\n"
        assert c._log_entries  # retained for a later flush


class TestSubmitVerificationTier:
    def test_submit_computes_verification_tier(self, tmp_path: Path) -> None:
        # Collector.submit must derive the tier like _commit_outcome
        # does — otherwise propagate_confidence's trusted_clean set is
        # empty on every standard (collector) run.
        from core.audit.orchestrator import ReviewOutcome

        c = Collector(out_dir=tmp_path, target_path=tmp_path)
        clean = ReviewOutcome(
            file="src/a.c", function="ok", status="clean",
            body="fine", tools_dispatched={"semgrep"},
        )
        c.submit(clean, _make_gap(name="ok"))
        assert clean.verification_tier == "tool_backed"

        spec = ReviewOutcome(
            file="src/a.c", function="guess", status="clean", body="fine",
        )
        c.submit(spec, _make_gap(name="guess"))
        assert spec.verification_tier == "speculative"

        c.flush()
        lines = (tmp_path / ".audit-log.jsonl").read_text(
            encoding="utf-8",
        ).strip().split("\n")
        tiers = {
            json.loads(ln)["key"]: json.loads(ln)["verification_tier"]
            for ln in lines
        }
        assert tiers["src/a.c:ok:10"] == "tool_backed"
        assert tiers["src/a.c:guess:10"] == "speculative"


class TestReusedVerdictChokepoint:
    """The journal-write promotion gate must not decay reused
    findings: a cross-run import re-asserts the origin run's already-
    gated verdict at the LLM_ONLY tier cap (verdict_reuse doctrine),
    it is not a fresh promotion."""

    def test_reused_finding_not_demoted_no_alarm(
        self, tmp_path: Path,
    ) -> None:
        from core.audit.orchestrator import ReviewOutcome
        from core.audit.promotion_alarm import load_alarms

        o = ReviewOutcome(
            file="src/a.c", function="fn", status="finding",
            body="[reused]", evidence_tool="journal:recall:run-1",
        )
        o.reused = True
        o.reused_from_run = "run-1"

        c = Collector(out_dir=tmp_path, target_path=tmp_path, run_id="run-2")
        c.submit(o, _make_gap(name="fn"))
        assert o.status == "finding"
        assert load_alarms(tmp_path) == []
        # ...and the tier cap still applies: no live receipt, LLM_ONLY.
        assert o.verification_tier == "llm_only"

    def test_fresh_evidence_less_finding_still_demoted(
        self, tmp_path: Path,
    ) -> None:
        from core.audit.orchestrator import ReviewOutcome
        from core.audit.promotion_alarm import load_alarms

        o = ReviewOutcome(
            file="src/a.c", function="fn", status="finding",
            body="claim", evidence_tool="",
        )
        c = Collector(out_dir=tmp_path, target_path=tmp_path, run_id="run-2")
        c.submit(o, _make_gap(name="fn"))
        assert o.status == "suspicious"
        alarms = load_alarms(tmp_path)
        assert len(alarms) == 1
        assert alarms[0]["blocked"] is True
