"""Cross-run verdict reuse: fold eligibility + $0 outcome import.

Zero LLM calls. The fold side reuses the hash-verification fixtures
from the gap-folding tests; the import side drives
``import_reused_verdicts`` with fake collectors and stubbed sweeps.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.audit.gaps import compute_gaps
from core.audit.orchestrator import OrchestratorConfig, OrchestratorResult
from core.audit.record import _compute_hash
from core.audit.strategy import strategies_from_item
from core.audit.verdict_reuse import import_reused_verdicts, outcome_from_entry
from core.coverage.journal import (
    ReviewJournalEntry,
    append_entry,
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
        "body": "prior review body",
    }
    fields.update(over)
    return ReviewJournalEntry(**fields)


def _project_with(tmp_path, entry):
    project = tmp_path / "project"
    run_dir = project / entry.run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    append_entry(run_dir, entry)
    merge_into_index(project, run_dir)
    return project


def _gap_keys(gaps):
    return {f"{g['file']}:{g['name']}" for g in gaps}


class TestFoldReuseEligibility:
    def test_eligible_entry_lands_in_sink_and_stays_covered(self, tmp_path):
        target = _write_target(tmp_path)
        project = _project_with(tmp_path, _entry(target))
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink, current_model="model-a",
        )
        assert "auth.c:check_pw" not in _gap_keys(gaps)
        assert "auth.c:check_pw" in sink
        assert sink["auth.c:check_pw"].verdict == "clean"

    def test_findings_are_reusable_too(self, tmp_path):
        target = _write_target(tmp_path)
        project = _project_with(
            tmp_path, _entry(target, verdict="finding"),
        )
        sink: dict = {}
        compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink, current_model="model-a",
        )
        assert sink["auth.c:check_pw"].verdict == "finding"

    def test_hash_mismatch_never_in_sink(self, tmp_path):
        target = _write_target(tmp_path)
        project = _project_with(
            tmp_path, _entry(target, source_hash="0" * 16),
        )
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink,
        )
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_legacy_entry_without_hash_suppressed_not_reused(self, tmp_path):
        # No hash evidence → historical silent suppression, no import.
        target = _write_target(tmp_path)
        project = _project_with(tmp_path, _entry(target, source_hash=""))
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink,
        )
        assert sink == {}
        assert "auth.c:check_pw" not in _gap_keys(gaps)

    def test_provisional_row_resurfaces_with_reuse_on(self, tmp_path):
        """A provisional (unfinalized cadence-tick) finding row is not
        a settled verdict: no import, no suppression."""
        target = _write_target(tmp_path)
        project = _project_with(
            tmp_path, _entry(target, verdict="finding", provisional=True),
        )
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink, current_model="model-a",
        )
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_provisional_row_gets_no_plain_fold_credit(self, tmp_path):
        """With verdict reuse OFF the fold must not credit a
        provisional row either — plain coverage credit would silently
        suppress the very re-review that settles it, leaving the
        journal's latest row provisional on a COMPLETED resumed run."""
        target = _write_target(tmp_path)
        project = _project_with(
            tmp_path, _entry(target, verdict="finding", provisional=True),
        )
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=None,
        )
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_provisional_skip_counted_in_reuse_stats(self, tmp_path):
        """The pre-hash provisional screen still feeds the run
        summary's not-reusable split (it went silent when the screen
        moved above the eligibility check)."""
        target = _write_target(tmp_path)
        project = _project_with(
            tmp_path, _entry(target, verdict="finding", provisional=True),
        )
        sink: dict = {}
        stats: dict = {}
        compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink, current_model="model-a", reuse_stats=stats,
        )
        assert stats == {"auth.c:check_pw": "provisional"}

    def test_context_reduced_verdict_resurfaces(self, tmp_path):
        target = _write_target(tmp_path)
        project = _project_with(
            tmp_path, _entry(target, context_reduced=True),
        )
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink,
        )
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps), (
            "a reduced-context verdict is lower-confidence — with "
            "reuse enabled it must re-review, not stay suppressed"
        )

    def test_error_verdict_never_reused(self, tmp_path):
        target = _write_target(tmp_path)
        project = _project_with(tmp_path, _entry(target, verdict="error"))
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink,
        )
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_model_change_resurfaces(self, tmp_path):
        target = _write_target(tmp_path)
        project = _project_with(tmp_path, _entry(target, model="model-a"))
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink, current_model="model-b",
        )
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_default_model_run_cannot_compare_and_reuses(self, tmp_path):
        # Current run on the default/session model: no stable name to
        # compare against — the model gate is skipped (documented).
        target = _write_target(tmp_path)
        project = _project_with(tmp_path, _entry(target, model="model-a"))
        sink: dict = {}
        compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink, current_model=None,
        )
        assert "auth.c:check_pw" in sink

    def test_strategy_change_resurfaces(self, tmp_path):
        target = _write_target(tmp_path)
        project = _project_with(
            tmp_path,
            _entry(target, strategies=["some_retired_strategy"]),
        )
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink, current_model="model-a",
        )
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_strategy_order_and_duplicates_do_not_block(self, tmp_path):
        # The recorded strategy ORDER (and any duplicate) is
        # presentation, not review context — the eligibility compare
        # is a set compare. Pre-fix, order/duplicate wobble at a
        # segment boundary read as "strategy set changed" and re-bought
        # the review.
        target = _write_target(tmp_path)
        recorded = list(reversed(_current_strategies()))
        if recorded:
            recorded.append(recorded[-1])  # duplicate
        project = _project_with(
            tmp_path, _entry(target, strategies=recorded),
        )
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink, current_model="model-a",
        )
        assert "auth.c:check_pw" in sink
        assert "auth.c:check_pw" not in _gap_keys(gaps)

    def test_reuse_disabled_keeps_plain_fold(self, tmp_path):
        # reuse_sink=None (--no-verdict-reuse): hash-verified entries
        # suppress silently, exactly the pre-reuse behaviour — even
        # ones reuse would have screened out (context_reduced).
        target = _write_target(tmp_path)
        project = _project_with(
            tmp_path, _entry(target, context_reduced=True),
        )
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
        )
        assert "auth.c:check_pw" not in _gap_keys(gaps)


class TestReuseBlockedStats:
    """Per-reason refusal map (function key → reason class) for
    hash-verified entries the eligibility screen refused — the
    aggregate 'not reusable' figure hid which driver mass-fired
    (observed live: 1,461 re-reviews at one segment start, reason
    split unknowable from the logs)."""

    def _stats_for(self, tmp_path, entry_over, current_model="model-a"):
        target = _write_target(tmp_path)
        project = _project_with(tmp_path, _entry(target, **entry_over))
        stats: dict = {}
        sink: dict = {}
        compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink, current_model=current_model,
            reuse_stats=stats,
        )
        return stats, sink

    def test_context_reduced_counted(self, tmp_path):
        stats, sink = self._stats_for(tmp_path, {"context_reduced": True})
        assert stats == {"auth.c:check_pw": "context_reduced"}
        assert sink == {}

    def test_model_changed_counted(self, tmp_path):
        stats, sink = self._stats_for(
            tmp_path, {"model": "model-b"}, current_model="model-a",
        )
        assert stats == {"auth.c:check_pw": "model_changed"}
        assert sink == {}

    def test_strategy_changed_counted(self, tmp_path):
        stats, sink = self._stats_for(
            tmp_path, {"strategies": ["some_retired_strategy"]},
        )
        assert stats == {"auth.c:check_pw": "strategy_changed"}
        assert sink == {}

    def test_eligible_entry_counts_nothing(self, tmp_path):
        stats, sink = self._stats_for(tmp_path, {})
        assert stats == {}
        assert "auth.c:check_pw" in sink

    def test_key_refused_in_both_folds_counts_once(self, tmp_path):
        # A resumed project run screens the same function in its OWN
        # journal fold AND the project-index fold. Refused twice, it
        # is re-reviewed ONCE — the stats (and the summary built from
        # them) must say once.
        from core.coverage.journal import append_entry, merge_into_index

        target = _write_target(tmp_path)
        entry = _entry(target, model="model-b")
        run_dir = tmp_path / "run1"
        run_dir.mkdir()
        append_entry(run_dir, entry)
        project = tmp_path / "project"
        prior_dir = project / "run0"
        prior_dir.mkdir(parents=True)
        append_entry(prior_dir, _entry(target, model="model-b",
                                       run_id="run0"))
        merge_into_index(project, prior_dir)

        stats: dict = {}
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], out_dir=run_dir,
            project_dir=project, reuse_sink=sink,
            own_run_reuse=True, current_model="model-a",
            reuse_stats=stats,
        )
        assert stats == {"auth.c:check_pw": "model_changed"}
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)


class TestCorrectiveStrategyBackfill:
    """Corrective re-journal rows (final-status corrections, deepen /
    post-loop re-reviews) historically journaled ``strategies: []``
    because their synthetic gap dicts never carried the field. Being
    the newest row for the site, the corrective shadowed the original
    review in the latest-per-site collapse and the eligibility screen
    refused every corrected function as strategy_changed on all later
    runs — on unchanged source (observed live as a mass re-buy). The
    fold now backfills the empty record from the shadowed sibling row
    (same site, same run or same source hash); the strict set-equality
    comparison itself is unchanged, so a genuine strategy-coverage
    regression still refuses."""

    def _project_with_history(self, tmp_path, *entries):
        project = tmp_path / "project"
        for entry in entries:
            run_dir = project / entry.run_id
            run_dir.mkdir(parents=True, exist_ok=True)
            append_entry(run_dir, entry)
        for run_id in {e.run_id for e in entries}:
            merge_into_index(project, project / run_id)
        return project

    def _corrective(self, target, **over):
        # The observed corrective shape: same site, empty strategies,
        # window source hash (the writer's minimal gap had no
        # line_end, so the stamp covers the fallback read window),
        # final verdict differing from the original.
        fields = {
            "verdict": "clean",
            "strategies": [],
            "line_end": None,
            "source_hash": _compute_hash(target, "auth.c", 1, None),
            "body": "[resolution] corrective entry",
        }
        fields.update(over)
        return _entry(target, **fields)

    def test_corrective_empty_row_reuses_via_same_run_sibling(
            self, tmp_path):
        target = _write_target(tmp_path)
        original = _entry(target, verdict="suspicious")
        corrective = self._corrective(target)   # later ts, same run
        project = self._project_with_history(
            tmp_path, original, corrective)
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink, current_model="model-a",
        )
        assert "auth.c:check_pw" not in _gap_keys(gaps)
        assert "auth.c:check_pw" in sink
        # The FINAL verdict (the corrective row's) is what reuses.
        assert sink["auth.c:check_pw"].verdict == "clean"

    def test_deepen_shape_reuses_via_same_hash_sibling(self, tmp_path):
        # Deepen-shaped corrective: full span + full-span hash, but a
        # different run than the populated sibling — donation matches
        # on the exact source hash instead.
        target = _write_target(tmp_path)
        original = _entry(target, run_id="run0", verdict="suspicious")
        corrective = _entry(
            target, verdict="clean", strategies=[],
            body="DEEPEN pass corrective",
        )
        project = self._project_with_history(
            tmp_path, original, corrective)
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink, current_model="model-a",
        )
        assert "auth.c:check_pw" in sink
        assert sink["auth.c:check_pw"].verdict == "clean"
        assert "auth.c:check_pw" not in _gap_keys(gaps)

    def test_strategy_regression_still_refused(self, tmp_path):
        # The sibling proves the review was briefed with a SUPERSET of
        # what current inference produces (a strategy was retired or
        # its inputs regressed): materially different briefing — the
        # backfilled comparison must still refuse.
        target = _write_target(tmp_path)
        original = _entry(
            target, verdict="suspicious",
            strategies=[*_current_strategies(), "some_retired_strategy"],
        )
        corrective = self._corrective(target)
        project = self._project_with_history(
            tmp_path, original, corrective)
        stats: dict = {}
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink, current_model="model-a",
            reuse_stats=stats,
        )
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)
        assert stats == {"auth.c:check_pw": "strategy_changed"}

    def test_empty_row_without_sibling_still_refused(self, tmp_path):
        # No populated sibling: the pre-backfill guard holds — an
        # empty record only matches a currently-empty inference.
        target = _write_target(tmp_path)
        project = self._project_with_history(
            tmp_path, self._corrective(target))
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink, current_model="model-a",
        )
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_unrelated_sibling_never_donates(self, tmp_path):
        # A populated row from another run AND another source snapshot
        # (different hash) is not evidence of this row's briefing.
        target = _write_target(tmp_path)
        original = _entry(
            target, run_id="run0", verdict="suspicious",
            source_hash="f" * 12,
        )
        corrective = self._corrective(target)
        project = self._project_with_history(
            tmp_path, original, corrective)
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink, current_model="model-a",
        )
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_mechanical_echo_sibling_never_donates(self, tmp_path):
        # When a post-loop pattern hit triggered the correction, the
        # newest populated row at the site is the mechanical echo —
        # its ``post-loop-mechanical`` tag is a row-kind marker, not
        # a briefing, and never matches a current inference. The
        # backfill must reach past it to the real review row, or the
        # corrected function is refused as strategy_changed forever.
        target = _write_target(tmp_path)
        original = _entry(target, verdict="suspicious")
        echo = _entry(
            target, verdict="suspicious",
            strategies=["post-loop-mechanical"],
            body="[mechanical] pattern hit", line_end=None,
        )
        corrective = self._corrective(target)
        project = self._project_with_history(
            tmp_path, original, echo, corrective)
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink, current_model="model-a",
        )
        assert "auth.c:check_pw" in sink
        assert sink["auth.c:check_pw"].verdict == "clean"
        assert "auth.c:check_pw" not in _gap_keys(gaps)


class TestOutcomeFromEntry:
    def test_fields(self, tmp_path):
        target = _write_target(tmp_path)
        entry = _entry(
            target, verdict="finding", cwe="CWE-787",
            hypotheses=[{"mechanism": "unchecked memcpy", "confidence": "high"}],
            evidence_tools=["semgrep:rule-x"],
        )
        outcome = outcome_from_entry(entry)
        assert outcome.status == "finding"
        assert outcome.reused is True
        assert outcome.reused_from_run == "run1"
        assert outcome.cost_usd == 0.0
        assert outcome.evidence_tool == "journal:recall:run1"
        assert outcome.hypothesis == "unchecked memcpy"
        assert outcome.review_result["reused"] is True
        assert outcome.review_result["cwe"] == "CWE-787"
        assert outcome.review_result["prior_evidence_tools"] == ["semgrep:rule-x"]
        assert "reused: verdict imported from run run1" in outcome.body
        assert "prior review body" in outcome.body

    def test_origin_propagates_through_reuse_chains(self, tmp_path):
        target = _write_target(tmp_path)
        entry = _entry(
            target, run_id="run3", reused=True, reused_from_run="run1",
        )
        outcome = outcome_from_entry(entry)
        assert outcome.reused_from_run == "run1", (
            "a reused entry re-imported later must keep pointing at "
            "the run that actually reviewed"
        )

    def test_index_stub_marker_points_at_the_producing_run(
        self, tmp_path,
    ):
        # Index write-boundary stub: EMPTY sidecar name, and no
        # sidecar file is ever written for it — the marker must point
        # at the producing run's journal, never at
        # review-journal-bodies.jsonl (a file the operator would hunt
        # and never find).
        target = _write_target(tmp_path)
        entry = _entry(
            target, body="", hypotheses=[],
            body_offload={
                "sidecar": "", "offset": 0, "bytes": 0,
                "sha256": "0" * 64, "fields": ["body", "hypotheses"],
            },
        )
        outcome = outcome_from_entry(entry)
        assert "offloaded at the index write boundary" in outcome.body
        assert "the journal of run run1" in outcome.body
        assert "review-journal-bodies.jsonl" not in outcome.body

    def test_compact_stub_marker_wording_unchanged(self, tmp_path):
        # Run-side slim stub (journal compact --slim-clean): a real
        # sidecar file exists, and the established marker names it.
        target = _write_target(tmp_path)
        entry = _entry(
            target, body="", hypotheses=[],
            body_offload={
                "sidecar": "review-journal-bodies.jsonl",
                "offset": 0, "bytes": 42,
                "sha256": "0" * 64, "fields": ["body", "hypotheses"],
            },
        )
        outcome = outcome_from_entry(entry)
        assert ("[body and hypotheses offloaded: "
                "review-journal-bodies.jsonl — journal compact "
                "--slim-clean]") in outcome.body

    def test_reused_finding_is_not_tool_backed(self, tmp_path):
        # No live tool receipt: tools_dispatched is empty and the
        # evidence is journal:recall — compute_tier must cap at
        # llm_only, never inherit TOOL_BACKED from the dead receipt.
        target = _write_target(tmp_path)
        entry = _entry(
            target, verdict="finding",
            evidence_tools=["semgrep:rule-x"],
            hypotheses=[{"mechanism": "m", "confidence": "high"}],
        )
        outcome = outcome_from_entry(entry)
        assert outcome.compute_tier() == "llm_only"


class _Collector:
    def __init__(self):
        self.submitted = []

    def submit(self, outcome, gap, **kwargs):
        self.submitted.append((outcome, gap))


def _config(tmp_path, **over) -> OrchestratorConfig:
    defaults = {
        "target_path": tmp_path / "target",
        "out_dir": tmp_path / "out",
        "sweep_validate_findings": False,
        "validate": False,
        "prefilter": False,
    }
    defaults.update(over)
    (tmp_path / "out").mkdir(exist_ok=True)
    return OrchestratorConfig(**defaults)


class TestImportReusedVerdicts:
    def test_imports_tally_and_journal(self, tmp_path, monkeypatch):
        import core.audit.orchestrator as orch
        monkeypatch.setattr(
            orch, "_proactive_validate",
            lambda outcome, *a, **k: outcome,
        )
        target = _write_target(tmp_path)
        clean = _entry(target)
        finding = _entry(
            target, function="other_fn", verdict="finding",
            hypotheses=[{"mechanism": "m", "confidence": "high"}],
        )
        collector = _Collector()
        result = OrchestratorResult()
        reviewed_outcomes: dict = {}

        n = import_reused_verdicts(
            {"auth.c:check_pw": clean, "auth.c:other_fn": finding},
            _config(tmp_path),
            result,
            collector=collector,
            reviewed_outcomes=reviewed_outcomes,
        )

        assert n == 2
        assert result.reused_from_prior == 2
        assert result.reviewed == 0, "imports are not reviews"
        assert result.clean == 1
        assert result.findings == 1
        assert result.total_cost_usd == 0.0
        assert len(result.outcomes) == 2
        assert len(collector.submitted) == 2
        assert reviewed_outcomes["auth.c:check_pw"].status == "clean"
        gap = collector.submitted[0][1]
        assert gap["line_start"] == 1
        assert gap["line_end"] == 5

    def test_reused_finding_reenters_sweeps(self, tmp_path, monkeypatch):
        import core.audit.orchestrator as orch

        swept = []

        def _fake_sweep(outcome, config, sarif_cache=None, **kwargs):
            swept.append(outcome.function)
            outcome.status = "suspicious"  # tools no longer confirm
            return outcome

        monkeypatch.setattr(orch, "_sweep_validate", _fake_sweep)
        monkeypatch.setattr(
            orch, "_proactive_validate",
            lambda outcome, *a, **k: outcome,
        )

        target = _write_target(tmp_path)
        finding = _entry(
            target, verdict="finding",
            hypotheses=[{"mechanism": "m", "confidence": "high"}],
        )
        result = OrchestratorResult()
        n = import_reused_verdicts(
            {"auth.c:check_pw": finding},
            _config(tmp_path, sweep_validate_findings=True),
            result,
            collector=_Collector(),
        )
        assert n == 1
        assert swept == ["check_pw"]
        assert result.sweep_demoted == 1
        assert result.findings == 0
        assert result.suspicious == 1

    def test_clean_does_not_enter_sweeps(self, tmp_path, monkeypatch):
        import core.audit.orchestrator as orch

        def _boom(*a, **k):
            raise AssertionError("sweep must not run for clean reuse")

        monkeypatch.setattr(orch, "_sweep_validate", _boom)
        target = _write_target(tmp_path)
        result = OrchestratorResult()
        n = import_reused_verdicts(
            {"auth.c:check_pw": _entry(target)},
            _config(tmp_path, sweep_validate_findings=True),
            result,
            collector=_Collector(),
        )
        assert n == 1
        assert result.clean == 1

    def test_journal_records_reuse_provenance(self, tmp_path, monkeypatch):
        import core.audit.orchestrator as orch
        monkeypatch.setattr(
            orch, "_proactive_validate",
            lambda outcome, *a, **k: outcome,
        )
        from core.audit.collector import Collector
        from core.coverage.journal import load_entries

        target = _write_target(tmp_path)
        out_dir = tmp_path / "out"
        out_dir.mkdir(exist_ok=True)
        collector = Collector(
            out_dir=out_dir, target_path=target, run_id="run9",
        )
        result = OrchestratorResult()
        import_reused_verdicts(
            {"auth.c:check_pw": _entry(target)},
            _config(tmp_path, target_path=target, out_dir=out_dir),
            result,
            collector=collector,
        )
        entries = load_entries(out_dir)
        assert len(entries) == 1
        e = entries[0]
        assert e.reused is True
        assert e.reused_from_run == "run1"
        assert e.run_id == "run9"
        assert e.verdict == "clean"
        assert e.cost_usd is None or e.cost_usd == 0.0

    def test_empty_candidates_noop(self, tmp_path):
        result = OrchestratorResult()
        assert import_reused_verdicts({}, _config(tmp_path), result) == 0
        assert result.reused_from_prior == 0


class TestContextReducedJournalled:
    def test_collector_records_context_reduced(self, tmp_path):
        from core.audit.collector import Collector
        from core.audit.orchestrator import ReviewOutcome
        from core.coverage.journal import load_entries

        target = _write_target(tmp_path)
        out_dir = tmp_path / "out"
        out_dir.mkdir(exist_ok=True)
        collector = Collector(
            out_dir=out_dir, target_path=target, run_id="runX",
        )
        outcome = ReviewOutcome(
            file="auth.c", function="check_pw", status="clean",
            body="ok", context_reduced=True,
        )
        collector.submit(outcome, {"line_start": 1, "line_end": 5})
        entry = load_entries(out_dir)[0]
        assert entry.context_reduced is True
        assert entry.reused is None


class TestFoldDriftFailClosed:
    """Deleted files and unverifiable spans are DRIFT, not coverage.

    Pre-fix: a deleted source file folded its entries to covered (the
    verdicts stood as coverage), and a span that no longer exists in
    the file (current hash "") slipped the prefix-compare so the
    stale verdict was reused as hash-verified at $0 — while
    compute_drift flags the identical cases as drift."""

    def test_deleted_file_resurfaces_as_gap(self, tmp_path):
        target = _write_target(tmp_path)
        entry = _entry(target)
        project = _project_with(tmp_path, entry)
        (target / "auth.c").unlink()
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink, current_model="model-a",
        )
        assert "auth.c:check_pw" in _gap_keys(gaps)
        assert "auth.c:check_pw" not in sink

    def test_out_of_range_span_resurfaces_as_gap(self, tmp_path):
        """The recorded span is beyond the current file's end — the
        current hash is '' and must read as drift, never verified."""
        target = _write_target(tmp_path)
        entry = _entry(target, line_start=100, line_end=120,
                       source_hash="abcdef123456")
        project = _project_with(tmp_path, entry)
        sink: dict = {}
        checklist = _checklist(target)
        checklist["files"][0]["items"][0]["line_start"] = 100
        checklist["files"][0]["items"][0]["line_end"] = 120
        gaps = compute_gaps(
            checklist, [], project_dir=project,
            reuse_sink=sink, current_model="model-a",
        )
        assert "auth.c:check_pw" in _gap_keys(gaps)
        assert "auth.c:check_pw" not in sink

    def test_intact_file_still_folds_covered(self, tmp_path):
        """Positive control: verification still passes when nothing
        drifted."""
        target = _write_target(tmp_path)
        project = _project_with(tmp_path, _entry(target))
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink, current_model="model-a",
        )
        assert "auth.c:check_pw" not in _gap_keys(gaps)


def _write_domain_model(project, concepts=None, invariants=None):
    import json
    cdir = project / "concepts"
    cdir.mkdir(parents=True, exist_ok=True)
    (cdir / "domain-model.json").write_text(json.dumps({
        "concepts": concepts or [],
        "invariants": invariants or [],
    }), encoding="utf-8")


_AUTH_CONCEPT = {
    "id": "cred_cache_rules",
    "description": "credential cache invalidation rules",
    "related_strategies": ["auth"],
}


class TestContextStaleness:
    """AR-7 domain-model context gate on fold eligibility.

    check_pw's current strategies include ``auth`` (path signal), so a
    new concept stamped ``related_strategies=["auth"]`` is relevant to
    it and one stamped ``["aliasing"]`` is not.
    """

    def _gaps(self, target, project, sink):
        return compute_gaps(
            _checklist(target), [], project_dir=project,
            out_dir=project / "run2",
            reuse_sink=sink, current_model="model-a",
        )

    def test_relevant_new_concept_resurfaces(self, tmp_path):
        target = _write_target(tmp_path)
        project = _project_with(
            tmp_path, _entry(target, domain_model_hash="00000000"))
        _write_domain_model(project, concepts=[_AUTH_CONCEPT])
        sink: dict = {}
        gaps = self._gaps(target, project, sink)
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_irrelevant_new_concept_stays_reused(self, tmp_path):
        target = _write_target(tmp_path)
        project = _project_with(
            tmp_path, _entry(target, domain_model_hash="00000000"))
        _write_domain_model(project, concepts=[{
            "id": "sg_page_ownership",
            "description": "scatterlist page ownership",
            "related_strategies": ["aliasing"],
        }])
        sink: dict = {}
        gaps = self._gaps(target, project, sink)
        assert "auth.c:check_pw" in sink
        assert "auth.c:check_pw" not in _gap_keys(gaps)

    def test_matching_hash_stays_reused(self, tmp_path):
        from core.coverage.journal import domain_model_context
        target = _write_target(tmp_path)
        project = tmp_path / "project"
        _write_domain_model(project, concepts=[_AUTH_CONCEPT])
        current = domain_model_context(project / "run2")["hash"]
        _project_with(
            tmp_path, _entry(target, domain_model_hash=current))
        sink: dict = {}
        gaps = self._gaps(target, project, sink)
        assert "auth.c:check_pw" in sink
        assert "auth.c:check_pw" not in _gap_keys(gaps)

    def test_legacy_entry_without_dm_hash_stays_reused(self, tmp_path):
        # No knowledge-state evidence → keep historical suppression
        # (same precedent as source_hash) — no storm on upgrade.
        target = _write_target(tmp_path)
        project = _project_with(tmp_path, _entry(target))
        _write_domain_model(project, concepts=[_AUTH_CONCEPT])
        sink: dict = {}
        gaps = self._gaps(target, project, sink)
        assert "auth.c:check_pw" in sink
        assert "auth.c:check_pw" not in _gap_keys(gaps)

    def test_concept_already_available_stays_reused(self, tmp_path):
        target = _write_target(tmp_path)
        project = _project_with(tmp_path, _entry(
            target, domain_model_hash="00000000",
            domain_concepts_available=["cred_cache_rules"],
        ))
        _write_domain_model(project, concepts=[_AUTH_CONCEPT])
        sink: dict = {}
        gaps = self._gaps(target, project, sink)
        assert "auth.c:check_pw" in sink
        assert "auth.c:check_pw" not in _gap_keys(gaps)

    def test_new_invariant_on_known_concept_resurfaces(self, tmp_path):
        # CopyFail shape: the concept was known at review time, but
        # the study loop later resolved a NEW invariant under it.
        target = _write_target(tmp_path)
        project = _project_with(tmp_path, _entry(
            target, domain_model_hash="00000000",
            domain_concepts_available=["cred_cache_rules"],
            invariants_available=[],
        ))
        _write_domain_model(
            project, concepts=[_AUTH_CONCEPT],
            invariants=[{"id": "inv_cred_ttl", "concept": "cred_cache_rules"}],
        )
        sink: dict = {}
        gaps = self._gaps(target, project, sink)
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_unstamped_concept_is_storm_safe(self, tmp_path):
        target = _write_target(tmp_path)
        project = _project_with(
            tmp_path, _entry(target, domain_model_hash="00000000"))
        _write_domain_model(project, concepts=[{
            "id": "legacy_concept", "description": "unstamped",
        }])
        sink: dict = {}
        gaps = self._gaps(target, project, sink)
        assert "auth.c:check_pw" in sink
        assert "auth.c:check_pw" not in _gap_keys(gaps)


class TestModelIdentityNormalisation:
    def test_route_prefixed_current_model_reuses_wire_form_entry(self, tmp_path):
        # Journal records the resolved wire name; the run pins the
        # bedrock/ override string. Same model — must reuse, not
        # re-review.
        target = _write_target(tmp_path)
        project = _project_with(
            tmp_path, _entry(target, model="anthropic.claude-opus-4-7"))
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink,
            current_model="bedrock/anthropic.claude-opus-4-7",
        )
        assert "auth.c:check_pw" in sink
        assert "auth.c:check_pw" not in _gap_keys(gaps)

    def test_genuinely_different_model_still_blocks(self, tmp_path):
        target = _write_target(tmp_path)
        project = _project_with(
            tmp_path, _entry(target, model="gemini-2.5-pro"))
        sink: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], project_dir=project,
            reuse_sink=sink,
            current_model="bedrock/anthropic.claude-opus-4-7",
        )
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)


class TestResweepReceiptCounting:
    """'Mechanically re-validated: N confirmed' may only count findings
    a tool actually re-confirmed (live receipt) — a sweep that raised
    or found nothing leaves the finding reused-but-unconfirmed at the
    LLM_ONLY tier cap, and reporting that as confirmed forged the run
    summary's receipt claim."""

    def _run(self, tmp_path, monkeypatch, caplog, fake_sweep):
        import core.audit.orchestrator as orch

        monkeypatch.setattr(orch, "_sweep_validate", fake_sweep)
        monkeypatch.setattr(
            orch, "_proactive_validate",
            lambda outcome, *a, **k: outcome,
        )
        target = _write_target(tmp_path)
        finding = _entry(
            target, verdict="finding",
            hypotheses=[{"mechanism": "m", "confidence": "high"}],
        )
        result = OrchestratorResult()
        with caplog.at_level("INFO", logger="core.audit.verdict_reuse"):
            import_reused_verdicts(
                {"auth.c:check_pw": finding},
                _config(tmp_path, sweep_validate_findings=True),
                result,
                collector=_Collector(),
            )
        return result, caplog.text

    def test_unconfirmed_survivor_not_counted_confirmed(
        self, tmp_path, monkeypatch, caplog,
    ):
        def _no_receipt_sweep(outcome, config, sarif_cache=None, **kw):
            return outcome  # status stays finding, no live stamp

        result, log = self._run(
            tmp_path, monkeypatch, caplog, _no_receipt_sweep,
        )
        assert result.findings == 1
        assert "0 confirmed" in log
        assert "1 reused without live re-confirmation" in log

    def test_live_receipt_counts_confirmed(
        self, tmp_path, monkeypatch, caplog,
    ):
        def _receipt_sweep(outcome, config, sarif_cache=None, **kw):
            outcome.evidence_tool = "semgrep:rule-1"
            return outcome

        result, log = self._run(
            tmp_path, monkeypatch, caplog, _receipt_sweep,
        )
        assert result.findings == 1
        assert "1 confirmed" in log
        assert "reused without live re-confirmation" not in log

    def test_sweep_exception_not_counted_confirmed(
        self, tmp_path, monkeypatch, caplog,
    ):
        def _raising_sweep(outcome, config, sarif_cache=None, **kw):
            raise RuntimeError("tool chain crashed")

        result, log = self._run(
            tmp_path, monkeypatch, caplog, _raising_sweep,
        )
        assert "0 confirmed" in log
        assert "1 reused without live re-confirmation" in log


class TestProvisionalFourPathMatrix:
    """Reviewer probe matrix: a provisional (unfinalized cadence-tick)
    finding row never suppresses and never imports on ANY fold path —
    cross-run and same-run resume, verdict reuse on and off — while a
    settled control row folds on every path (so a green matrix cannot
    come from a broken harness)."""

    def _fold(self, tmp_path, *, cross_run, reuse_on, **entry_over):
        from core.audit.gaps import _fold_journal_into_covered

        target = _write_target(tmp_path)
        entry = _entry(target, **entry_over)
        covered: set = set()
        sink: dict | None = {} if reuse_on else None
        spans = {"auth.c:check_pw": (1, 5)}
        if cross_run:
            project = _project_with(tmp_path, entry)
            _fold_journal_into_covered(
                covered, None, project,
                target_path=target, current_spans=spans,
                reuse_sink=sink,
            )
        else:
            run_dir = tmp_path / "run"
            run_dir.mkdir(exist_ok=True)
            append_entry(run_dir, entry)
            _fold_journal_into_covered(
                covered, run_dir, None,
                target_path=target, current_spans=spans,
                reuse_sink=sink, own_run_reuse=reuse_on,
            )
        return covered, sink

    @pytest.mark.parametrize(
        ("cross_run", "reuse_on"),
        [(False, False), (False, True), (True, False), (True, True)],
        ids=[
            "same-run-reuse-off", "same-run-reuse-on",
            "cross-run-reuse-off", "cross-run-reuse-on",
        ],
    )
    def test_provisional_never_suppresses(
        self, tmp_path, cross_run, reuse_on,
    ):
        covered, sink = self._fold(
            tmp_path, cross_run=cross_run, reuse_on=reuse_on,
            verdict="finding", provisional=True,
        )
        assert covered == set()
        if sink is not None:
            assert sink == {}

    @pytest.mark.parametrize(
        ("cross_run", "reuse_on"),
        [(False, False), (False, True), (True, False), (True, True)],
        ids=[
            "same-run-reuse-off", "same-run-reuse-on",
            "cross-run-reuse-off", "cross-run-reuse-on",
        ],
    )
    def test_settled_control_row_folds(self, tmp_path, cross_run, reuse_on):
        covered, _ = self._fold(
            tmp_path, cross_run=cross_run, reuse_on=reuse_on,
            verdict="finding",
        )
        assert "auth.c:check_pw" in covered


class TestCounterLockAccessor:
    def test_counter_lock_is_the_instance_lock(self):
        from core.audit.orchestrator import OrchestratorResult
        result = OrchestratorResult()
        lock = result.counter_lock()
        assert lock is result._lock
        with lock:
            pass  # acquirable

    def test_module_does_not_touch_the_private_lock(self):
        import inspect

        from core.audit import verdict_reuse
        src = inspect.getsource(verdict_reuse)
        assert "._lock" not in src


_SELECTED_CONCEPT = {
    # Selects into check_pw's prompt slice (direct name match) AND
    # intersects its current strategies — both the slice fingerprint
    # and the relevance diff see it.
    "id": "pw_compare_rules",
    "description": "check_pw comparison must run in constant time",
    "related_strategies": ["auth"],
}


class TestSliceStampReuse:
    """Per-function slice stamp on the AR-7 staleness gate.

    A whole-model regeneration re-bought every stamped verdict whose
    strategies the new concepts touched, even when the per-function
    prompt slice — what the review would actually be briefed with —
    was byte-identical. Entries stamped with ``domain_slice_hash``
    short-circuit fresh when the recompute reproduces the stamp;
    every failure mode (no stamp, mismatch, recompute error) falls
    back to the relevance diff, so the stamp only ever ADDS reuse.
    """

    def _gaps(self, target, project, sink):
        return compute_gaps(
            _checklist(target), [], project_dir=project,
            out_dir=project / "run2",
            reuse_sink=sink, current_model="model-a",
        )

    @staticmethod
    def _clear_model_cache():
        from core.concepts.audit_bridge import _load_cached
        _load_cached.cache_clear()

    def _stamp(self, project, target):
        """Record-time stamp — the same code path the fold recomputes
        through (core.audit.context.domain_slice_hash_for)."""
        from core.audit.context import domain_slice_hash_for
        self._clear_model_cache()
        return domain_slice_hash_for(
            project / "run2", target, "auth.c", "check_pw", 1, 5)

    def _regenerate_model(self, project, concepts):
        _write_domain_model(project, concepts=concepts)
        self._clear_model_cache()

    def test_unchanged_slice_survives_model_regeneration(self, tmp_path):
        target = _write_target(tmp_path)
        project = tmp_path / "project"
        _write_domain_model(project, concepts=[])
        stamp = self._stamp(project, target)
        assert stamp is not None
        _project_with(tmp_path, _entry(
            target, domain_model_hash="00000000",
            domain_slice_hash=stamp,
        ))
        # Regenerated engine output: the whole-model hash moves and
        # the new concept is strategy-relevant to check_pw — but it
        # never SELECTS into check_pw's slice, so the briefing this
        # function's review would receive is unchanged.
        self._regenerate_model(project, [_AUTH_CONCEPT])
        sink: dict = {}
        gaps = self._gaps(target, project, sink)
        assert "auth.c:check_pw" in sink
        assert "auth.c:check_pw" not in _gap_keys(gaps)

    def test_changed_slice_resurfaces(self, tmp_path):
        target = _write_target(tmp_path)
        project = tmp_path / "project"
        _write_domain_model(project, concepts=[])
        stamp = self._stamp(project, target)
        _project_with(tmp_path, _entry(
            target, domain_model_hash="00000000",
            domain_slice_hash=stamp,
        ))
        # The regenerated model now selects a concept INTO check_pw's
        # slice: the stamp mismatches and the relevance diff sees a
        # relevant new concept — re-review.
        self._regenerate_model(project, [_SELECTED_CONCEPT])
        sink: dict = {}
        gaps = self._gaps(target, project, sink)
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_missing_stamp_keeps_whole_model_behaviour(self, tmp_path):
        target = _write_target(tmp_path)
        project = _project_with(
            tmp_path, _entry(target, domain_model_hash="00000000"))
        _write_domain_model(project, concepts=[_AUTH_CONCEPT])
        self._clear_model_cache()
        sink: dict = {}
        gaps = self._gaps(target, project, sink)
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_mismatching_stamp_never_blocks_diff_granted_reuse(
        self, tmp_path,
    ):
        # Monotone pin: a stamp the recompute cannot reproduce (model
        # prose reworded, stamp truncated, foreign hash) falls back to
        # the relevance diff — it must never turn reuse the diff
        # grants into a refusal.
        target = _write_target(tmp_path)
        project = _project_with(tmp_path, _entry(
            target, domain_model_hash="00000000",
            domain_slice_hash="deadbeef" * 8,
        ))
        _write_domain_model(project, concepts=[{
            "id": "sg_page_ownership",
            "description": "scatterlist page ownership",
            "related_strategies": ["aliasing"],
        }])
        self._clear_model_cache()
        sink: dict = {}
        gaps = self._gaps(target, project, sink)
        assert "auth.c:check_pw" in sink
        assert "auth.c:check_pw" not in _gap_keys(gaps)

    # Selects into check_pw's slice ONLY via source tokens (three
    # id parts — stored/strcmp/return — appear in the function BODY;
    # the description never names check_pw): scored against the pad
    # lines a stale recorded-span recompute reads, it selects
    # nothing, so only a recompute at the function's real location
    # sees it. related_strategies intersects check_pw's current
    # strategies, so the relevance diff also flags it.
    _SOURCE_ONLY_CONCEPT = {
        "id": "stored_strcmp_return",
        "description": "comparisons of secrets must be constant time",
        "related_strategies": ["auth"],
    }

    @staticmethod
    def _moved_checklist(target):
        # check_pw moved down 10 lines: the checklist sees it at its
        # CURRENT span while journal rows recorded 1-5.
        item = dict(_ITEM, line_start=11, line_end=15)
        return {
            "target_path": str(target),
            "files": [{
                "path": "auth.c",
                "language": "c",
                "items": [item],
            }],
        }

    @staticmethod
    def _move_function_down(target):
        pad = "".join(f"/* pad {i} */\n" for i in range(1, 11))
        (target / "auth.c").write_text(pad + _SOURCE, encoding="utf-8")

    def _moved_gaps(self, target, project, sink):
        return compute_gaps(
            self._moved_checklist(target), [], project_dir=project,
            out_dir=project / "run2",
            reuse_sink=sink, current_model="model-a",
        )

    def test_moved_function_recomputes_slice_at_verified_span(
        self, tmp_path,
    ):
        """Span drift: check_pw moved down 10 lines, body unchanged,
        so the source hash verifies at the checklist's CURRENT span.
        The regenerated model gains a concept that selects into
        check_pw's slice at its real location. Recomputing the slice
        at the stale RECORDED span would read the inserted pad lines,
        select nothing, reproduce the empty-selection stamp
        byte-for-byte and falsely certify the slice "provably
        unchanged" — reusing a verdict whose re-review prompt would
        carry the new concept. The recompute must run at the span
        where source verification succeeded: the slice differs there,
        the relevance diff sees a relevant new concept, re-review."""
        target = _write_target(tmp_path)
        project = tmp_path / "project"
        _write_domain_model(project, concepts=[])
        stamp = self._stamp(project, target)
        assert stamp is not None
        _project_with(tmp_path, _entry(
            target, domain_model_hash="00000000",
            domain_slice_hash=stamp,
        ))
        self._move_function_down(target)
        self._regenerate_model(project, [self._SOURCE_ONLY_CONCEPT])
        sink: dict = {}
        gaps = self._moved_gaps(target, project, sink)
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_moved_function_with_unchanged_slice_still_reuses(
        self, tmp_path,
    ):
        """The reuse-preserving half of the verified-span semantics:
        a moved-but-unchanged function whose slice recomputed at its
        CURRENT span is still byte-identical (the new concept is
        strategy-relevant but never SELECTS into check_pw's slice)
        keeps its $0 reuse — the span fix must not turn every moved
        function into a re-review."""
        target = _write_target(tmp_path)
        project = tmp_path / "project"
        _write_domain_model(project, concepts=[])
        stamp = self._stamp(project, target)
        assert stamp is not None
        _project_with(tmp_path, _entry(
            target, domain_model_hash="00000000",
            domain_slice_hash=stamp,
        ))
        self._move_function_down(target)
        self._regenerate_model(project, [_AUTH_CONCEPT])
        sink: dict = {}
        gaps = self._moved_gaps(target, project, sink)
        assert "auth.c:check_pw" in sink
        assert "auth.c:check_pw" not in _gap_keys(gaps)

    @staticmethod
    def _none_end_item(line_start: int) -> dict:
        # A checklist item the inventory never measured an end line
        # for: line_end is absent, and every consumer reads the
        # fallback window — the source hash, the slice stamp, and the
        # review prompt all cover the same lines.
        item = dict(_ITEM, line_start=line_start)
        del item["line_end"]
        return item

    @classmethod
    def _none_end_checklist(cls, target: Path, line_start: int) -> dict:
        return {
            "target_path": str(target),
            "files": [{
                "path": "auth.c",
                "language": "c",
                "items": [cls._none_end_item(line_start)],
            }],
        }

    def _none_end_gaps(
        self, target: Path, project: Path, sink: dict, line_start: int,
    ) -> list:
        return compute_gaps(
            self._none_end_checklist(target, line_start), [],
            project_dir=project, out_dir=project / "run2",
            reuse_sink=sink, current_model="model-a",
        )

    def _none_end_stamp(
        self, project: Path, target: Path, line_start: int,
    ) -> str | None:
        from core.audit.context import domain_slice_hash_for
        self._clear_model_cache()
        return domain_slice_hash_for(
            project / "run2", target, "auth.c", "check_pw",
            line_start, None)

    def test_unmoved_row_without_line_end_keeps_reuse_via_raw_window(
        self, tmp_path,
    ):
        """Reuse-preserving half of the raw-window semantics: a row
        whose checklist item carries no line_end was stamped over the
        fallback read window (the raw None the writer hands the
        renderer), and its source hash covers that same window.
        When the function has NOT moved and the model
        gained nothing that selects into that window, the recompute
        must read the SAME fallback window — recomputing over the
        single normalised line would select nothing where the stamp's
        window selected the body-matching concept, mismatch the
        stamp, and re-buy a verdict whose briefing is unchanged."""
        target = _write_target(tmp_path)
        project = tmp_path / "project"
        # The concept selects into check_pw's slice via BODY tokens
        # only, and is present at BOTH stamp time and fold time: the
        # stamp encodes a non-empty selection, so it is only
        # reproducible by a recompute over the same read window.
        _write_domain_model(project, concepts=[self._SOURCE_ONLY_CONCEPT])
        stamp = self._none_end_stamp(project, target, 1)
        assert stamp is not None
        # Window-sensitivity precondition: the single normalised line
        # yields a DIFFERENT fingerprint (no body tokens on line 1),
        # so this test discriminates the raw window from the
        # normalised one rather than passing under either.
        from core.audit.context import domain_slice_hash_for
        assert domain_slice_hash_for(
            project / "run2", target, "auth.c", "check_pw", 1, 1,
        ) != stamp
        item = self._none_end_item(1)
        _project_with(tmp_path, _entry(
            target,
            source_hash=_compute_hash(target, "auth.c", 1, None),
            line_end=None,
            strategies=sorted(strategies_from_item(dict(item), "auth.c")),
            domain_model_hash="00000000",
            domain_slice_hash=stamp,
        ))
        self._clear_model_cache()
        sink: dict = {}
        gaps = self._none_end_gaps(target, project, sink, 1)
        assert "auth.c:check_pw" in sink
        assert "auth.c:check_pw" not in _gap_keys(gaps)

    def test_moved_function_without_line_end_recomputes_full_window(
        self, tmp_path,
    ):
        """A row without a line_end whose function MOVED: the source
        hash covers the review window (clamped here to the whole
        unchanged body), so it verifies at the checklist's current
        span even though the body now sits on different lines. The
        recompute must read the fallback window
        at the function's real location — the raw missing line_end,
        exactly what the re-review prompt reads there. Recomputing
        over the single normalised current line selects nothing and
        reproduces the empty-selection stamp byte-for-byte, falsely
        certifying "provably unchanged" while the prompt window would
        carry the newly selecting concept: stale verdict reused."""
        target = _write_target(tmp_path)
        project = tmp_path / "project"
        _write_domain_model(project, concepts=[])
        stamp = self._none_end_stamp(project, target, 1)
        assert stamp is not None
        item = self._none_end_item(11)
        _project_with(tmp_path, _entry(
            target,
            source_hash=_compute_hash(target, "auth.c", 1, None),
            line_end=None,
            strategies=sorted(strategies_from_item(dict(item), "auth.c")),
            domain_model_hash="00000000",
            domain_slice_hash=stamp,
        ))
        self._move_function_down(target)
        # The regenerated model gains a concept selecting via BODY
        # tokens at the function's new location — visible to the
        # fallback window there, invisible to its single header line.
        self._regenerate_model(project, [self._SOURCE_ONLY_CONCEPT])
        sink: dict = {}
        gaps = self._none_end_gaps(target, project, sink, 11)
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_sibling_row_without_line_end_keeps_reuse_at_recorded_site(
        self, tmp_path,
    ):
        """Same-named items (macro redefinitions, C++ overloads,
        prototype + definition) share one file:function key but live
        at different sites, and only the FIRST occurrence owns the
        key's current-span slot. A row for a LATER site verifies at
        its own recorded span, so the raw read window must come from
        the ENTRY (its line_end, None included), not from the
        first occurrence's slot: normalising the recorded span to a
        single line would select nothing where the stamp's fallback
        window selected the body-matching concept, mismatch the
        stamp, and re-buy an unchanged review."""
        target = _write_target(tmp_path)
        pad = "".join(f"/* pad {i} */\n" for i in range(1, 6))
        # Two same-named definitions: lines 1-5 and lines 11-15.
        (target / "auth.c").write_text(
            _SOURCE + pad + _SOURCE, encoding="utf-8")
        project = tmp_path / "project"
        _write_domain_model(project, concepts=[self._SOURCE_ONLY_CONCEPT])
        stamp = self._none_end_stamp(project, target, 11)
        assert stamp is not None
        from core.audit.context import domain_slice_hash_for
        assert domain_slice_hash_for(
            project / "run2", target, "auth.c", "check_pw", 11, 11,
        ) != stamp
        sibling = self._none_end_item(11)
        _project_with(tmp_path, _entry(
            target,
            source_hash=_compute_hash(target, "auth.c", 11, None),
            line_start=11,
            line_end=None,
            strategies=sorted(
                strategies_from_item(dict(sibling), "auth.c")),
            domain_model_hash="00000000",
            domain_slice_hash=stamp,
        ))
        self._clear_model_cache()
        checklist = {
            "target_path": str(target),
            "files": [{
                "path": "auth.c",
                "language": "c",
                # First occurrence (measured span) owns the key's
                # current-span slot; the reviewed sibling carries no
                # line_end.
                "items": [dict(_ITEM), sibling],
            }],
        }
        sink: dict = {}
        gaps = compute_gaps(
            checklist, [], project_dir=project,
            out_dir=project / "run2",
            reuse_sink=sink, current_model="model-a",
        )
        assert "auth.c:check_pw" in sink
        # The never-reviewed FIRST site surfaces as a gap (correct —
        # one row reviews one site); the reviewed sibling must not.
        assert 11 not in {g["line_start"] for g in gaps}

    # Selects ONLY via tokens on the neighbour lines directly after
    # check_pw's measured span (throttle/lockout/bruteforce, lines
    # 6-8 of _NEIGHBOUR_SOURCE): scored against any window ending at
    # line 5 it selects nothing, so only a recompute over the widened
    # fallback window sees it. related_strategies intersects
    # check_pw's current strategies, so the relevance diff also
    # flags it.
    _NEIGHBOUR_CONCEPT = {
        "id": "throttle_lockout_bruteforce",
        "description": "repeated failures must delay retries",
        "related_strategies": ["auth"],
    }

    @staticmethod
    def _neighbour_target(tmp_path: Path) -> Path:
        # check_pw (lines 1-5) followed by neighbour declarations
        # (lines 6-8): inside the fallback read window a missing
        # line_end produces, outside any window ending at line 5.
        target = tmp_path / "target"
        target.mkdir(exist_ok=True)
        (target / "auth.c").write_text(_SOURCE + (
            "static int throttle_ms = 200;\n"
            "/* lockout counter guards bruteforce attempts */\n"
            "static int lockout_after = 5;\n"
        ), encoding="utf-8")
        return target

    def test_stamped_line_dropped_from_checklist_resurfaces(
        self, tmp_path,
    ):
        """A row stamped with a measured line_end whose CURRENT
        checklist item dropped it: the source hash verifies at the
        entry's own recorded span, but a re-review prompt at that
        site now reads the fallback window (raw missing line_end),
        not the stamped line. Recomputing over the stamped single
        line is blind to a regenerated model whose new concept
        selects only inside the widened window — it reproduces the
        stamp byte-for-byte and falsely certifies the briefing
        unchanged while the prompt would carry the new concept. The
        recompute may only certify the stamp window when it IS the
        window the prompt reads at that site; here they differ, so
        the relevance diff decides — re-review."""
        target = _write_target(tmp_path)
        project = tmp_path / "project"
        _write_domain_model(project, concepts=[])
        from core.audit.context import domain_slice_hash_for
        self._clear_model_cache()
        stamp = domain_slice_hash_for(
            project / "run2", target, "auth.c", "check_pw", 1, 1)
        assert stamp is not None
        item = self._none_end_item(1)
        _project_with(tmp_path, _entry(
            target,
            source_hash=hash_span(target / "auth.c", 1, 1),
            line_end=1,
            strategies=sorted(strategies_from_item(dict(item), "auth.c")),
            domain_model_hash="00000000",
            domain_slice_hash=stamp,
        ))
        self._regenerate_model(project, [self._SOURCE_ONLY_CONCEPT])
        # Window-sensitivity preconditions: the new concept selects
        # via BODY tokens — invisible to the stamped single line,
        # visible to the fallback window the prompt reads — so this
        # test discriminates the two windows rather than passing
        # under either.
        assert domain_slice_hash_for(
            project / "run2", target, "auth.c", "check_pw", 1, 1,
        ) == stamp
        assert domain_slice_hash_for(
            project / "run2", target, "auth.c", "check_pw", 1, None,
        ) != stamp
        sink: dict = {}
        gaps = self._none_end_gaps(target, project, sink, 1)
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_measured_stamp_blind_to_widened_prompt_window_resurfaces(
        self, tmp_path,
    ):
        """Non-degenerate window drift: the row was stamped over an
        honestly measured window (lines 1-5) and the source hash
        verifies there, but the current checklist item dropped
        line_end, so a re-review prompt reads the fallback window —
        which also covers the neighbour lines after the function. A
        regenerated model gains a concept selecting only on that
        neighbour content: a recompute over the stamped window
        reproduces the stamp exactly and would reuse a verdict whose
        briefing the prompt no longer matches. Window mismatch →
        relevance diff → re-review."""
        target = self._neighbour_target(tmp_path)
        project = tmp_path / "project"
        _write_domain_model(project, concepts=[])
        stamp = self._stamp(project, target)
        assert stamp is not None
        item = self._none_end_item(1)
        _project_with(tmp_path, _entry(
            target,
            strategies=sorted(strategies_from_item(dict(item), "auth.c")),
            domain_model_hash="00000000",
            domain_slice_hash=stamp,
        ))
        self._regenerate_model(project, [self._NEIGHBOUR_CONCEPT])
        from core.audit.context import domain_slice_hash_for
        assert domain_slice_hash_for(
            project / "run2", target, "auth.c", "check_pw", 1, 5,
        ) == stamp
        assert domain_slice_hash_for(
            project / "run2", target, "auth.c", "check_pw", 1, None,
        ) != stamp
        sink: dict = {}
        gaps = self._none_end_gaps(target, project, sink, 1)
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_row_without_line_end_on_measured_item_still_re_reviews(
        self, tmp_path,
    ):
        """The other direction of the window rule: the row was
        stamped over the fallback read window (raw line_end None)
        while the current checklist item carries a measured
        line_end. The stamp window covered the neighbour lines the
        measured window excludes, and the regenerated model's new
        concept selects on that neighbour content — so no recompute
        may certify the CURRENT (narrower) window against the stamp:
        both select nothing there, reproducing the stamp for a
        window it never fingerprinted. The windows differ, so the
        relevance diff decides — re-review."""
        target = self._neighbour_target(tmp_path)
        project = tmp_path / "project"
        _write_domain_model(project, concepts=[])
        stamp = self._none_end_stamp(project, target, 1)
        assert stamp is not None
        _project_with(tmp_path, _entry(
            target,
            source_hash=hash_span(target / "auth.c", 1, 1),
            line_end=None,
            domain_model_hash="00000000",
            domain_slice_hash=stamp,
        ))
        self._regenerate_model(project, [self._NEIGHBOUR_CONCEPT])
        from core.audit.context import domain_slice_hash_for
        # A recompute pointed at the measured current window would
        # reproduce the stamp (both select nothing at lines 1-5);
        # only the stamp's own fallback window sees the new concept.
        assert domain_slice_hash_for(
            project / "run2", target, "auth.c", "check_pw", 1, 5,
        ) == stamp
        assert domain_slice_hash_for(
            project / "run2", target, "auth.c", "check_pw", 1, None,
        ) != stamp
        sink: dict = {}
        gaps = self._gaps(target, project, sink)
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_first_listed_same_named_item_never_speaks_for_the_site(
        self, tmp_path,
    ):
        """Per-site window comparison: the raw line_end a recorded
        site is checked against must come from the checklist item AT
        that site, never from the same-named occurrence that owns
        the key's first-occurrence slots. Here a measured same-named
        definition is listed FIRST while the reviewed site carries
        no line_end — comparing the entry's raw None against the
        decoy's measured end would refuse the short-circuit and
        re-buy an unchanged review that the per-site comparison
        keeps at $0."""
        target = tmp_path / "target"
        target.mkdir(exist_ok=True)
        pad = "".join(f"/* pad {i} */\n" for i in range(1, 6))
        # Two same-named definitions: lines 1-5 and lines 11-15.
        (target / "auth.c").write_text(
            _SOURCE + pad + _SOURCE, encoding="utf-8")
        project = tmp_path / "project"
        _write_domain_model(project, concepts=[self._SOURCE_ONLY_CONCEPT])
        stamp = self._none_end_stamp(project, target, 1)
        assert stamp is not None
        from core.audit.context import domain_slice_hash_for
        # Window-sensitivity precondition: the single normalised
        # line yields a different fingerprint, so only the raw
        # fallback window reproduces the stamp.
        assert domain_slice_hash_for(
            project / "run2", target, "auth.c", "check_pw", 1, 1,
        ) != stamp
        reviewed = self._none_end_item(1)
        decoy = dict(_ITEM, line_start=11, line_end=15)
        _project_with(tmp_path, _entry(
            target,
            source_hash=_compute_hash(target, "auth.c", 1, None),
            line_end=None,
            strategies=sorted(
                strategies_from_item(dict(reviewed), "auth.c")),
            domain_model_hash="00000000",
            domain_slice_hash=stamp,
        ))
        self._clear_model_cache()
        checklist = {
            "target_path": str(target),
            "files": [{
                "path": "auth.c",
                "language": "c",
                # The measured decoy is listed FIRST and owns the
                # key's first-occurrence slots; the reviewed site
                # carries no line_end.
                "items": [decoy, reviewed],
            }],
        }
        sink: dict = {}
        gaps = compute_gaps(
            checklist, [], project_dir=project,
            out_dir=project / "run2",
            reuse_sink=sink, current_model="model-a",
        )
        assert "auth.c:check_pw" in sink
        assert 1 not in {g["line_start"] for g in gaps}

    def test_truncated_stamp_prefix_never_short_circuits(self, tmp_path):
        """Full-string equality pin: a stamp that is a strict PREFIX
        of the recomputed slice hash must not short-circuit fresh.
        The whole-model hash deliberately uses a bidirectional prefix
        compare; the slice stamp deliberately does NOT — a prefix-
        tolerant compare here would accept a truncated (or attacker-
        chosen 1-char) stamp against the full recompute and grant
        reuse. Full equality mismatches, the relevance diff sees a
        relevant new concept, re-review."""
        target = _write_target(tmp_path)
        project = tmp_path / "project"
        _write_domain_model(project, concepts=[])
        full = self._stamp(project, target)
        assert full is not None
        _project_with(tmp_path, _entry(
            target, domain_model_hash="00000000",
            domain_slice_hash=full[:8],
        ))
        # Same regeneration as
        # test_unchanged_slice_survives_model_regeneration: the
        # recompute reproduces the FULL hash, of which the stored
        # stamp is a strict prefix.
        self._regenerate_model(project, [_AUTH_CONCEPT])
        sink: dict = {}
        gaps = self._gaps(target, project, sink)
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)

    def test_no_matched_span_skips_the_short_circuit(self):
        """Fail-closed default: a caller that cannot name the span
        where source verification succeeded gets no slice
        short-circuit at all — the recompute never runs and the
        relevance diff decides."""
        from core.audit.gaps import _context_staleness

        stamp = "cafe" * 16
        calls: list = []

        def _slice_fn(entry, span=None):
            # Reproduces the stamp on purpose: a regression that
            # calls the recompute WITHOUT a verified span would
            # short-circuit fresh here and hide from this test.
            calls.append(span)
            return stamp

        entry = ReviewJournalEntry(
            ts=now_iso(), run_id="r1", file="auth.c",
            function="check_pw", verdict="clean", source_hash="",
            line_start=1, line_end=5, strategies=["auth"],
            model="model-a", body="prior review body",
            domain_model_hash="00000000",
            domain_slice_hash=stamp,
        )
        ctx = {
            "hash": "11111111",
            "canonical": True,
            "concepts": {"cred_cache_rules": ["auth"]},
            "invariant_concept": {},
            "slice_hash_fn": _slice_fn,
        }
        stale = _context_staleness(
            entry, "auth.c:check_pw", ctx,
            lambda key, line_start: ["auth"],
        )
        assert calls == []
        assert stale is not None
        assert "cred_cache_rules" in stale

    def test_recompute_error_falls_back_to_re_review(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.context as context_mod
        target = _write_target(tmp_path)
        project = tmp_path / "project"
        _write_domain_model(project, concepts=[])
        stamp = self._stamp(project, target)
        _project_with(tmp_path, _entry(
            target, domain_model_hash="00000000",
            domain_slice_hash=stamp,
        ))
        self._regenerate_model(project, [_AUTH_CONCEPT])

        def _boom(*a, **kw):
            raise RuntimeError("slice recompute failure")

        monkeypatch.setattr(context_mod, "domain_slice_hash_for", _boom)
        # Identical setup reuses in
        # test_unchanged_slice_survives_model_regeneration — with the
        # recompute erroring, the slice cannot be PROVEN unchanged, so
        # the relevance diff decides and re-reviews.
        sink: dict = {}
        gaps = self._gaps(target, project, sink)
        assert sink == {}
        assert "auth.c:check_pw" in _gap_keys(gaps)
