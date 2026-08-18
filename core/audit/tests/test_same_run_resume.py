"""Same-run resume plumbing: own-journal reuse fold, guard bypass,
prior-segment ledger booking. Zero LLM calls."""

from __future__ import annotations

from core.audit.cost_tracker import PRIOR_SEGMENTS_PHASE, PhaseCostLedger
from core.audit.gaps import compute_gaps
from core.audit.orchestrator import OrchestratorConfig, OrchestratorResult
from core.audit.strategy import strategies_from_item
from core.audit.verdict_reuse import import_reused_verdicts
from core.coverage.journal import (
    ReviewJournalEntry,
    append_entry,
    latest_entries,
    merge_into_index,
    now_iso,
)
from core.staleness import hash_span

_SOURCE = """\
int check_pw(const char *pw) {
    if (!pw)
        return -1;
    return strcmp(pw, stored) == 0;
}
"""

_ITEM = {
    "name": "check_pw",
    "kind": "function",
    "line_start": 1,
    "line_end": 5,
}


def _write_target(tmp_path):
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    (target / "auth.c").write_text(_SOURCE, encoding="utf-8")
    return target


def _checklist(target):
    return {
        "target_path": str(target),
        "files": [{
            "path": "auth.c",
            "language": "c",
            "items": [dict(_ITEM)],
        }],
    }


def _current_strategies():
    return sorted(strategies_from_item(dict(_ITEM), "auth.c"))


def _entry(target, **over):
    fields = {
        "ts": now_iso(),
        "run_id": "run1",
        "file": "auth.c",
        "function": "check_pw",
        "verdict": "clean",
        "source_hash": hash_span(target / "auth.c", 1, 5),
        "line_start": 1,
        "line_end": 5,
        "strategies": _current_strategies(),
        "model": "model-a",
        "body": "segment-1 review body",
    }
    fields.update(over)
    return ReviewJournalEntry(**fields)


def _run_dir(tmp_path, *entries):
    run_dir = tmp_path / "run1"
    run_dir.mkdir(exist_ok=True)
    for entry in entries:
        append_entry(run_dir, entry)
    return run_dir


def _gap_keys(gaps):
    return {f"{g['file']}:{g['name']}" for g in gaps}


class TestOwnRunReuseFold:
    def test_verified_own_entry_lands_in_sink(self, tmp_path):
        target = _write_target(tmp_path)
        run_dir = _run_dir(tmp_path, _entry(target))
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], out_dir=run_dir,
            reuse_sink=sink, own_run_reuse=True,
            current_model="model-a",
        )
        assert "auth.c:check_pw" not in _gap_keys(gaps)
        assert "auth.c:check_pw" in sink
        assert sink["auth.c:check_pw"].run_id == "run1"

    def test_drifted_own_entry_resurfaces_not_reused(self, tmp_path):
        target = _write_target(tmp_path)
        run_dir = _run_dir(tmp_path, _entry(target))
        # Source changed between the kill and the resume.
        (target / "auth.c").write_text(
            _SOURCE.replace("return -1", "return -2"), encoding="utf-8",
        )
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], out_dir=run_dir,
            reuse_sink=sink, own_run_reuse=True,
            current_model="model-a",
        )
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_error_verdict_resurfaces_on_resume(self, tmp_path):
        target = _write_target(tmp_path)
        run_dir = _run_dir(tmp_path, _entry(target, verdict="error"))
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], out_dir=run_dir,
            reuse_sink=sink, own_run_reuse=True,
            current_model="model-a",
        )
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_default_fold_unchanged_without_own_run_reuse(self, tmp_path):
        """own_run_reuse off: blanket suppression, nothing imported —
        the historical single-process behaviour."""
        target = _write_target(tmp_path)
        run_dir = _run_dir(tmp_path, _entry(target))
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], out_dir=run_dir,
            reuse_sink=sink, current_model="model-a",
        )
        assert "auth.c:check_pw" not in _gap_keys(gaps)
        assert sink == {}

    def test_own_run_candidate_wins_over_project_index(self, tmp_path):
        """The run's own latest verdict beats a prior run's for the
        same function (first fold writes the sink; setdefault)."""
        target = _write_target(tmp_path)
        own = _entry(target, verdict="suspicious", run_id="run1")
        run_dir = _run_dir(tmp_path, own)

        project = tmp_path / "project"
        prior_dir = project / "run0"
        prior_dir.mkdir(parents=True)
        append_entry(prior_dir, _entry(target, run_id="run0"))
        merge_into_index(project, prior_dir)

        sink: dict = {}
        compute_gaps(
            _checklist(target), [], out_dir=run_dir,
            project_dir=project, reuse_sink=sink,
            own_run_reuse=True, current_model="model-a",
        )
        assert sink["auth.c:check_pw"].run_id == "run1"
        assert sink["auth.c:check_pw"].verdict == "suspicious"


def _config(tmp_path, **over) -> OrchestratorConfig:
    defaults = {
        "target_path": tmp_path / "target",
        "out_dir": tmp_path / "run1",
        "sweep_validate_findings": False,
        "validate": False,
        "prefilter": False,
    }
    defaults.update(over)
    (tmp_path / "run1").mkdir(exist_ok=True)
    return OrchestratorConfig(**defaults)


class TestSameRunImportGuard:
    def test_same_run_bypasses_own_journal_guard(self, tmp_path, monkeypatch):
        import core.audit.orchestrator as orch
        monkeypatch.setattr(
            orch, "_proactive_validate", lambda outcome, *a, **k: outcome,
        )
        target = _write_target(tmp_path)
        entry = _entry(target)
        run_dir = _run_dir(tmp_path, entry)

        result = OrchestratorResult()
        n = import_reused_verdicts(
            {"auth.c:check_pw": entry},
            _config(tmp_path),
            result,
            same_run=True,
        )
        assert n == 1
        assert result.reused_from_prior == 1

        # A fresh reused=true row landed; latest_entries keeps ONE
        # verdict per function so counts stay coherent.
        latest = latest_entries(run_dir)
        assert len(latest) == 1
        resumed = latest["auth.c:check_pw"]
        assert resumed.reused is True
        assert resumed.reused_from_run == "run1"

    def test_default_guard_still_skips_own_journal(self, tmp_path, monkeypatch):
        import core.audit.orchestrator as orch
        monkeypatch.setattr(
            orch, "_proactive_validate", lambda outcome, *a, **k: outcome,
        )
        target = _write_target(tmp_path)
        entry = _entry(target)
        _run_dir(tmp_path, entry)

        result = OrchestratorResult()
        n = import_reused_verdicts(
            {"auth.c:check_pw": entry},
            _config(tmp_path),
            result,
        )
        assert n == 0
        assert result.reused_from_prior == 0


class TestPriorSegmentLedger:
    def test_book_prior_segments_and_totals(self):
        ledger = PhaseCostLedger()
        ledger.record_call("review", cost_usd=1.5)
        ledger.book_prior_segments(3.25, segment=2)

        assert ledger.prior_segments_spend_usd == 3.25
        # No client injection: tracked spend covers both segments.
        assert abs(ledger.total_spend_usd - 4.75) < 1e-9

        # With injection: this segment's client ledger + prior booked.
        ledger.set_total_spend(2.0)
        assert abs(ledger.total_spend_usd - 5.25) < 1e-9

        d = ledger.to_dict()
        assert d["segments"] == [
            {"segment": 2, "prior_spend_usd": 3.25},
        ]
        assert PRIOR_SEGMENTS_PHASE in d["phases"]
        assert d["phases"][PRIOR_SEGMENTS_PHASE]["cost_usd"] == 3.25
        assert d["phases"][PRIOR_SEGMENTS_PHASE]["calls"] == 0

    def test_no_segments_key_without_resume(self):
        ledger = PhaseCostLedger()
        ledger.record_call("review", cost_usd=1.0)
        assert "segments" not in ledger.to_dict()
