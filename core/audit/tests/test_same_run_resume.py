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

    def test_two_segment_resume_strategy_set_stable(self, tmp_path):
        # Simulated multi-segment resume on an unchanged tree: strategy
        # inference is a pure function of the stable checklist/target
        # inputs, so a hash-verified segment-1 verdict must stay
        # reusable at EVERY later segment start — not flip to
        # "strategy set changed" once derived context wobbles (the
        # live 1,461-re-review storm's driver, fed by a flapping CPG
        # cache key).
        target = _write_target(tmp_path)
        run_dir = _run_dir(tmp_path, _entry(target))
        for segment in (2, 3):
            sink: dict = {}
            stats: dict = {}
            gaps = compute_gaps(
                _checklist(target), [], out_dir=run_dir,
                reuse_sink=sink, own_run_reuse=True,
                current_model="model-a", reuse_stats=stats,
            )
            assert "auth.c:check_pw" in sink, f"segment {segment}"
            assert "auth.c:check_pw" not in _gap_keys(gaps), (
                f"segment {segment}"
            )
            assert stats == {}, f"segment {segment}: {stats}"

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


class TestMultiResumeCostContinuity:
    """The cumulative ledger chain across resumed segments.

    Representation under test: each segment's rewritten
    cost-breakdown.json stores cumulative-so-far (a ``prior_segments``
    phase + a ``segments`` row + whole-run ``totals.total_spend_usd``),
    so readers never fold a chain. Each resume books the RESOLVED
    whole-run prior spend (``resolve_prior_spend``), not merely the
    immediately-prior segment's ledger — pre-fix a segment whose
    predecessor died unreconciled restarted the chain, and the final
    ledger under-reported the run by all earlier segments' spend
    (observed live: segment 4 booked $47.29 of a ~$4,534 run).
    """

    def _segment(self, tmp_path, segment, own_spend, *, reconcile=True):
        """Run one simulated segment through the production
        reconciliation path (`_reconcile_cost_ledgers`)."""
        from types import SimpleNamespace

        from core.audit.orchestrator import _reconcile_cost_ledgers
        from core.audit.resume import (
            load_prior_cost_breakdown,
            persist_spend_floor,
            resolve_prior_spend,
        )

        out_dir = tmp_path / "run1"
        prior_breakdown = None
        booked = 0.0
        if segment > 1:
            # What cmd_resume does at segment start.
            prior_breakdown = load_prior_cost_breakdown(out_dir)
            booked, _note = resolve_prior_spend(out_dir)
        config = _config(
            tmp_path,
            same_run_reuse=segment > 1,
            prior_cost_breakdown=prior_breakdown,
            prior_booked_spend_usd=booked,
            resume_segment=segment,
            llm_budget_client=SimpleNamespace(
                total_cost=own_spend, provider_spend_usd=0.0,
            ),
        )
        result = OrchestratorResult()
        result.cost_tracker.record_call("review", cost_usd=own_spend)
        if reconcile:
            _reconcile_cost_ledgers(config, result)
        else:
            # Hard kill (SIGKILL/OOM): no ledger write — only the
            # incremental spend floor the run persisted while alive.
            persist_spend_floor(out_dir, own_spend + booked,
                                segment=segment)
        return result

    def test_three_segments_final_ledger_is_whole_run(self, tmp_path):
        import json as _json

        from core.audit.resume import resolve_prior_spend

        self._segment(tmp_path, 1, 100.0)
        self._segment(tmp_path, 2, 50.0)
        self._segment(tmp_path, 3, 25.0)

        data = _json.loads(
            (tmp_path / "run1" / "cost-breakdown.json").read_text())
        assert abs(data["totals"]["total_spend_usd"] - 175.0) < 1e-6
        assert data["segments"] == [
            {"segment": 3, "prior_spend_usd": 150.0},
        ]
        booked, note = resolve_prior_spend(tmp_path / "run1")
        assert abs(booked - 175.0) < 1e-6
        assert note == "reconciled ledger"

    def test_unreconciled_predecessor_spend_survives(self, tmp_path):
        # Segment 1 dies hard: no cost-breakdown.json, only the
        # spend floor. Pre-fix, segment 2 booked $0 into its ledger
        # (no prior dict) and segment 3 then carried only segment 2's
        # own spend forward.
        import json as _json

        self._segment(tmp_path, 1, 100.0, reconcile=False)
        self._segment(tmp_path, 2, 50.0)
        self._segment(tmp_path, 3, 25.0)

        data = _json.loads(
            (tmp_path / "run1" / "cost-breakdown.json").read_text())
        assert abs(data["totals"]["total_spend_usd"] - 175.0) < 1e-6

    def test_old_own_spend_only_ledger_still_readable(self, tmp_path):
        # A pre-fix run dir whose ledger carries only the last
        # segment's own spend (no segments rows, no prior_segments
        # phase) must stay readable: the resolver returns its stated
        # figure without crashing.
        import json as _json

        from core.audit.resume import resolve_prior_spend

        out_dir = tmp_path / "run1"
        out_dir.mkdir(exist_ok=True)
        (out_dir / "cost-breakdown.json").write_text(_json.dumps({
            "phases": {"re_review": {"calls": 129, "cost_usd": 14.0}},
            "totals": {
                "cost_usd": 14.0072,
                "calls": 129,
                "failed_attempts_cost_usd": 0.0,
                "unattributed_cost_usd": 33.2853,
                "total_spend_usd": 47.2925,
            },
        }))
        booked, note = resolve_prior_spend(out_dir)
        assert abs(booked - 47.2925) < 1e-6
        assert note == "reconciled ledger"

    def test_journal_floor_rescues_legacy_broken_ledger(self, tmp_path):
        # A pre-fix own-segment-only ledger next to a journal whose
        # per-entry costs exceed it: the journal is the best surviving
        # evidence of the whole-run chain and must win the max().
        # Reused verdicts journal at cost_usd=0, so the journal floor
        # never double-counts a healthy cumulative ledger.
        import json as _json

        from core.audit.resume import resolve_prior_spend

        out_dir = tmp_path / "run1"
        out_dir.mkdir(exist_ok=True)
        (out_dir / "cost-breakdown.json").write_text(_json.dumps({
            "phases": {},
            "totals": {"cost_usd": 47.29, "total_spend_usd": 47.29},
        }))
        for i, cost in enumerate((150.0, 250.0)):
            append_entry(out_dir, ReviewJournalEntry(
                ts=now_iso(),
                run_id="run1",
                file="auth.c",
                function=f"fn_{i}",
                verdict="clean",
                source_hash="",
                cost_usd=cost,
            ))
        booked, note = resolve_prior_spend(out_dir)
        assert abs(booked - 400.0) < 1e-6
        assert note == "journal per-entry floor — exceeds the reconciled ledger"


_MACRO_SOURCE = """\
#define SSHINT(x) ((x) + 1)
int a;
#define SSHINT(x) ((x) + 2)
int b;
"""

_SITE_1 = {"name": "SSHINT", "kind": "macro", "line_start": 1, "line_end": 1}
_SITE_2 = {"name": "SSHINT", "kind": "macro", "line_start": 3, "line_end": 3}


def _macro_target(tmp_path):
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    (target / "conf.c").write_text(_MACRO_SOURCE, encoding="utf-8")
    return target


def _macro_checklist(target):
    return {
        "target_path": str(target),
        "files": [{
            "path": "conf.c",
            "language": "c",
            "items": [dict(_SITE_1), dict(_SITE_2)],
        }],
    }


def _site_entry(target, site, strategies):
    return ReviewJournalEntry(
        ts=now_iso(),
        run_id="run1",
        file="conf.c",
        function="SSHINT",
        verdict="clean",
        source_hash=hash_span(
            target / "conf.c", site["line_start"], site["line_end"]),
        line_start=site["line_start"],
        line_end=site["line_end"],
        strategies=strategies,
        model="model-a",
        body="segment-1 review body",
    )


class TestSameNamedSitesFold:
    """Same-named items at different spans (macro redefinitions, C++
    overloads) share one file:function key. The resume fold must
    credit each hash-verified SITE, or every sibling beyond the first
    is re-bought on every resume — the infinite re-review cycle."""

    def _strategies(self):
        return sorted(strategies_from_item(dict(_SITE_1), "conf.c"))

    def test_all_journaled_sites_stay_covered(self, tmp_path):
        target = _macro_target(tmp_path)
        strategies = self._strategies()
        run_dir = tmp_path / "run1"
        run_dir.mkdir(exist_ok=True)
        for site in (_SITE_1, _SITE_2):
            append_entry(run_dir, _site_entry(target, site, strategies))

        sink: dict = {}
        gaps = compute_gaps(
            _macro_checklist(target), [], out_dir=run_dir,
            reuse_sink=sink, own_run_reuse=True,
        )
        leftover = [g for g in gaps if g["name"] == "SSHINT"]
        assert leftover == [], (
            "both sites carry hash-verified reviews at their own spans "
            "— resurfacing either re-buys an already-paid review"
        )

    def test_unreviewed_same_named_site_still_surfaces(self, tmp_path):
        target = _macro_target(tmp_path)
        run_dir = tmp_path / "run1"
        run_dir.mkdir(exist_ok=True)
        append_entry(
            run_dir, _site_entry(target, _SITE_1, self._strategies()))

        gaps = compute_gaps(
            _macro_checklist(target), [], out_dir=run_dir,
            reuse_sink={}, own_run_reuse=True,
        )
        leftover = [g for g in gaps if g["name"] == "SSHINT"]
        assert len(leftover) == 1, (
            "one verified review must suppress exactly one same-named "
            "site; the unreviewed sibling stays a gap"
        )


class TestSpanBoundCredits:
    """A coverage credit belongs to the SITE that earned it. The
    checklist lists functions before same-named prototypes, so a
    count-based credit let an unreviewed 169-line body absorb its
    reviewed 1-line prototype's credit on every recomputation — a
    real vulnerability inside such a body was missed exactly this
    way."""

    _PROTO_SOURCE = "".join(
        ["char *fn(const char *p);\n"]           # line 1: prototype
        + [f"int filler_{i};\n" for i in range(2, 5)]
        + ["char *fn(const char *p)\n",           # line 5: body
           "{\n", "    return 0;\n", "}\n"]
    )

    def test_reviewed_prototype_does_not_cover_unreviewed_body(
            self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "r.c").write_text(self._PROTO_SOURCE, encoding="utf-8")
        checklist = {
            "target_path": str(target),
            "files": [{
                "path": "r.c",
                "language": "c",
                "items": [
                    # Function FIRST — the extraction's kind-grouped
                    # order, the exact trap.
                    {"name": "fn", "kind": "function",
                     "line_start": 5, "line_end": 8},
                    {"name": "fn", "kind": "global",
                     "line_start": 1, "line_end": 1},
                ],
            }],
        }
        run_dir = tmp_path / "run1"
        run_dir.mkdir()
        # The eligibility screen resolves strategies PER SITE, so the
        # journaled strategies must match the PROTOTYPE site's own
        # inference to be admitted — this test targets credit
        # binding, not eligibility.
        fn_item = checklist["files"][0]["items"][1]
        append_entry(run_dir, ReviewJournalEntry(
            ts=now_iso(), run_id="run1", file="r.c", function="fn",
            verdict="clean",
            source_hash=hash_span(target / "r.c", 1, 1),
            line_start=1, line_end=1,
            strategies=sorted(strategies_from_item(dict(fn_item), "r.c")),
        ))
        gaps = compute_gaps(
            checklist, [], out_dir=run_dir,
            reuse_sink={}, own_run_reuse=True,
        )
        leftover = [(g["name"], g["line_start"]) for g in gaps
                    if g["name"] == "fn"]
        assert leftover == [("fn", 5)], (
            "the unreviewed BODY must surface; pre-fix it absorbed "
            "the prototype's credit and vanished"
        )


_COLLISION_SOURCE = """\
int check_pw(const char *pw) {
    if (!pw)
        return -1;
    return strcmp(pw, stored) == 0;
}

int check_pw(const char *pw);
"""

# A function + declaration collision pair: same name, one
# file:function key, two sites whose strategy inference DIFFERS (the
# extern visibility on the declaration adds input_handling).
_FUNC_SITE = {
    "name": "check_pw", "kind": "function",
    "line_start": 1, "line_end": 5,
}
_PROTO_SITE = {
    "name": "check_pw", "kind": "function",
    "line_start": 7, "line_end": 7,
    "metadata": {"visibility": "extern"},
}


def _collision_target(tmp_path):
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    (target / "auth.c").write_text(_COLLISION_SOURCE, encoding="utf-8")
    return target


def _collision_checklist(target):
    return {
        "target_path": str(target),
        "files": [{
            "path": "auth.c",
            "language": "c",
            "items": [dict(_FUNC_SITE), dict(_PROTO_SITE)],
        }],
    }


def _site_strategies(site):
    return sorted(strategies_from_item(dict(site), "auth.c"))


def _collision_entry(target, site, **over):
    fields = {
        "ts": now_iso(),
        "run_id": "run1",
        "file": "auth.c",
        "function": "check_pw",
        "verdict": "clean",
        "source_hash": hash_span(
            target / "auth.c", site["line_start"], site["line_end"]),
        "line_start": site["line_start"],
        "line_end": site["line_end"],
        "strategies": _site_strategies(site),
        "model": "model-a",
        "body": "segment-1 review body",
    }
    fields.update(over)
    return ReviewJournalEntry(**fields)


class TestPerSiteEligibility:
    """The reuse-eligibility screen resolves CURRENT strategies at the
    entry's own SITE. Same-named collision pairs (function +
    prototype, macro redefinitions) share one file:function key but
    infer different strategy sets — comparing every entry against the
    first same-named item mispaired the check by construction,
    refusing valid reuse and re-buying paid reviews on every resume."""

    def test_prototype_entry_admitted_at_its_own_site(self, tmp_path):
        # The PROTOTYPE's journal entry carries the prototype-item
        # strategies. Pre-fix it was refused ("strategy set changed")
        # via mispairing with the FUNCTION item's inference.
        target = _collision_target(tmp_path)
        run_dir = tmp_path / "run1"
        run_dir.mkdir(exist_ok=True)
        append_entry(run_dir, _collision_entry(target, _PROTO_SITE))

        sink: dict = {}
        stats: dict = {}
        gaps = compute_gaps(
            _collision_checklist(target), [], out_dir=run_dir,
            reuse_sink=sink, own_run_reuse=True,
            current_model="model-a", reuse_stats=stats,
        )
        assert stats == {}, f"eligibility refused a valid entry: {stats}"
        assert "auth.c:check_pw" in sink
        assert sink["auth.c:check_pw"].line_start == 7
        leftover = [g for g in gaps if g["name"] == "check_pw"]
        assert len(leftover) == 1, (
            "the reviewed site's credit must suppress one occurrence; "
            "only the unreviewed sibling stays a gap"
        )

    def test_single_site_key_resolves_to_sole_item(self, tmp_path):
        # Single-site key (the overwhelming case): an entry whose
        # recorded span no longer matches any current site still
        # resolves to the key's sole item — identical to the legacy
        # first-item behaviour.
        target = _write_target(tmp_path)
        run_dir = _run_dir(
            tmp_path, _entry(target, line_start=2, line_end=6))
        sink: dict = {}
        stats: dict = {}
        gaps = compute_gaps(
            _checklist(target), [], out_dir=run_dir,
            reuse_sink=sink, own_run_reuse=True,
            current_model="model-a", reuse_stats=stats,
        )
        assert stats == {}
        assert "auth.c:check_pw" in sink
        assert "auth.c:check_pw" not in _gap_keys(gaps)

    def test_zero_line_start_falls_back_to_first_site(self, tmp_path):
        # A legacy entry with no recorded site (line_start 0) keeps
        # the historical first-site resolution: admitted with the
        # FIRST item's strategies, refused with a sibling's.
        target = _collision_target(tmp_path)

        run_dir = tmp_path / "run1"
        run_dir.mkdir(exist_ok=True)
        append_entry(run_dir, _collision_entry(
            target, _FUNC_SITE,
            source_hash=hash_span(target / "auth.c", 1, 5),
            line_start=0, line_end=0,
        ))
        sink: dict = {}
        stats: dict = {}
        compute_gaps(
            _collision_checklist(target), [], out_dir=run_dir,
            reuse_sink=sink, own_run_reuse=True,
            current_model="model-a", reuse_stats=stats,
        )
        assert stats == {}
        assert "auth.c:check_pw" in sink

        run2 = tmp_path / "run2"
        run2.mkdir(exist_ok=True)
        append_entry(run2, _collision_entry(
            target, _FUNC_SITE,
            source_hash=hash_span(target / "auth.c", 1, 5),
            line_start=0, line_end=0,
            strategies=_site_strategies(_PROTO_SITE),
        ))
        sink2: dict = {}
        stats2: dict = {}
        compute_gaps(
            _collision_checklist(target), [], out_dir=run2,
            reuse_sink=sink2, own_run_reuse=True,
            current_model="model-a", reuse_stats=stats2,
        )
        assert stats2 == {"auth.c:check_pw": "strategy_changed"}
        assert sink2 == {}
