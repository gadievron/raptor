"""Tests for the incremental-promotion cadence.

The mechanical promotion resolution runs mid-loop on the critique
cadence, journaling promotions immediately with ``provisional: true``;
the post-loop finalization confirms (mark dropped via a corrective
journal row) or the demotion paths retract. All hermetic: tool chains
are stubbed, no LLM, no external tools.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import core.audit.orchestrator as orch_mod
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _finalize_provisional_promotions,
    _incremental_promotion_tick,
    _rejournal_final_statuses,
    _run_critique,
)
from core.coverage.journal import load_entries


def _suspicious(fn: str = "f", file: str = "a.c") -> ReviewOutcome:
    return ReviewOutcome(
        file=file,
        function=fn,
        status="suspicious",
        body="maybe",
        hypothesis="unbounded memcpy overflow",
        line=3,
    )


def _config(tmp_path: Path, **kw) -> OrchestratorConfig:
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    return OrchestratorConfig(target_path=target, out_dir=out, **kw)


def _patch_confirming_chain(
    monkeypatch,
    receipts=("semgrep:unbounded",),
    patch_prefilter=True,
):
    """Stub every mechanical channel so the chain confirms *receipts*."""
    monkeypatch.setattr(
        orch_mod, "_hypothesis_to_tool_chain",
        lambda hyp, f, cwe="", language=None: ["fake-rule"],
    )
    monkeypatch.setattr(orch_mod, "_read_raw_source", lambda *a, **kw: "src")
    monkeypatch.setattr(
        orch_mod, "_run_tool_chain", lambda *a, **kw: list(receipts),
    )
    monkeypatch.setattr(orch_mod, "_is_detection_only", lambda t: False)
    monkeypatch.setattr(
        orch_mod, "_check_sink_guarded_cached", lambda *a, **kw: None,
    )
    if patch_prefilter:
        monkeypatch.setattr(
            orch_mod, "run_prefilter",
            lambda *a, **kw: SimpleNamespace(hits=[]),
        )



@pytest.fixture(autouse=True)
def _stub_mechanical_detectors(monkeypatch) -> None:
    """Stub the pre-loop mechanical-detector pass at its seam (the
    test_consistency_wiring / test_scorecard_events idiom) for every
    run_orchestrator driver in this file: the pass does real I/O —
    sandboxed coccinelle spawns where spatch is installed, plus the
    per-process detector-cache import-closure fingerprint on whichever
    test opens the cache first in a worker — seconds per run, entirely
    orthogonal to the promotion cadence under test, and enough to trip
    the default-tier duration guard on a contended runner. Module-wide
    (not per-class) on purpose: stubbing a single class only displaces
    the first-payer cost onto the file's next unstubbed orchestrated
    run."""
    monkeypatch.setattr(orch_mod, "_run_mechanical_detectors",
                        lambda *a, **k: ({}, set()))


class TestIncrementalTick:
    def test_promotes_and_journals_provisional(self, monkeypatch, tmp_path):
        """Evidence present at tick time → provisional finding is
        journal-visible immediately, not at end of run."""
        _patch_confirming_chain(monkeypatch)
        config = _config(tmp_path)
        result = OrchestratorResult(suspicious=1)
        result.outcomes = [_suspicious()]

        n = _incremental_promotion_tick(result, config)

        assert n == 1
        assert result.outcomes[0].status == "finding"
        assert result.outcomes[0].provisional is True
        assert result.findings == 1
        assert result.suspicious == 0
        assert result.sweep_promoted == 1
        assert result.provisional_promoted_keys == ["a.c:f"]

        # Journal row exists NOW, marked provisional.
        entries = load_entries(config.out_dir)
        rows = [e for e in entries if e.function == "f"]
        assert rows and rows[-1].verdict == "finding"
        assert rows[-1].provisional is True

        # findings.json rides along for mid-run/report visibility.
        data = json.loads((config.out_dir / "findings.json").read_text())
        findings = data["findings"] if isinstance(data, dict) else data
        assert findings and findings[0]["provisional"] is True

        # Audit-log record in the sweep-entry shape.
        log = (config.out_dir / ".audit-log.jsonl").read_text()
        actions = [json.loads(line) for line in log.splitlines()]
        incr = [a for a in actions if a["action"] == "incremental_promotion"]
        assert incr and incr[0]["provisional"] is True
        assert incr[0]["status"] == "finding"

    def test_window_advances_and_is_single_pass(self, monkeypatch, tmp_path):
        """A tick consumes only outcomes not yet offered to a tick."""
        _patch_confirming_chain(monkeypatch)
        config = _config(tmp_path)
        result = OrchestratorResult(suspicious=1)
        result.outcomes = [_suspicious("f1")]

        assert _incremental_promotion_tick(result, config) == 1
        # No new outcomes → nothing to do.
        assert _incremental_promotion_tick(result, config) == 0
        # New outcome arrives → next tick picks up only the new window.
        result.outcomes.append(_suspicious("f2"))
        assert _incremental_promotion_tick(result, config) == 1

    def test_window_survives_midloop_removals(self, monkeypatch, tmp_path):
        """Chain re-reviews remove() list entries mid-loop — the window
        is keyed on the outcome objects themselves, so index shifts
        neither rescan already-ticked items nor skip fresh ones."""
        _patch_confirming_chain(monkeypatch)
        config = _config(tmp_path)
        clean = ReviewOutcome(
            file="a.c", function="c0", status="clean", body="ok",
        )
        result = OrchestratorResult(suspicious=1, clean=1)
        result.outcomes = [clean, _suspicious("f1")]

        assert _incremental_promotion_tick(result, config) == 1
        promoted_f1 = result.outcomes[1]
        assert promoted_f1.status == "finding"

        # Mid-loop removal shifts every index; a fresh suspicious lands.
        result.outcomes.remove(clean)
        result.outcomes.append(_suspicious("f2"))
        result.suspicious += 1

        assert _incremental_promotion_tick(result, config) == 1
        # f1's replacement was not touched again (no rescan) …
        assert result.outcomes[0] is promoted_f1
        # … and exactly one provisional journal row exists per function.
        rows = load_entries(config.out_dir)
        assert sum(1 for e in rows if e.function == "f1") == 1
        assert sum(1 for e in rows if e.function == "f2") == 1

    def test_busy_tick_skips_without_claiming_window(
        self, monkeypatch, tmp_path,
    ):
        _patch_confirming_chain(monkeypatch)
        config = _config(tmp_path)
        result = OrchestratorResult(suspicious=1)
        result.outcomes = [_suspicious()]

        assert result._incremental_tick_lock.acquire(blocking=False)
        try:
            assert _incremental_promotion_tick(result, config) == 0
            assert result.outcomes[0]._incr_ticked is False
        finally:
            result._incremental_tick_lock.release()
        # The folded window is consumed by the next tick.
        assert _incremental_promotion_tick(result, config) == 1

    def test_no_llm_synthesis_on_the_cadence(self, monkeypatch, tmp_path):
        """Chain-less hypotheses are parked, never synthesized mid-loop —
        promotions on the cadence stay mechanical ($0 LLM). Recording
        stub, NOT a raising one: the tick swallows per-item exceptions,
        so a raising stub passes vacuously even when synthesis runs
        (a synthesis_queue=None mutation must fail this test)."""
        _patch_confirming_chain(monkeypatch)
        # No static channel binds the hypothesis.
        monkeypatch.setattr(
            orch_mod, "_hypothesis_to_tool_chain",
            lambda hyp, f, cwe="", language=None: [],
        )

        synth_calls: list = []
        monkeypatch.setattr(
            orch_mod, "_synthesize_unmapped_suspicious",
            lambda *a, **kw: synth_calls.append(a),
        )
        config = _config(tmp_path)
        result = OrchestratorResult(suspicious=1)
        result.outcomes = [_suspicious()]

        assert _incremental_promotion_tick(result, config) == 0
        assert synth_calls == []
        assert result.outcomes[0].status == "suspicious"
        assert not (config.out_dir / "findings.json").exists()

    def test_stale_slot_promotion_dropped(self, monkeypatch, tmp_path):
        """An outcome replaced (or removed) while the tick's tool chain
        ran must not be double-promoted or clobber the replacement."""
        config = _config(tmp_path)
        result = OrchestratorResult(suspicious=1)
        suspicious = _suspicious()
        result.outcomes = [suspicious]
        replacement = ReviewOutcome(
            file="a.c", function="f", status="finding",
            body="already promoted", evidence_tool="critique:semgrep:x",
        )

        def _chain_that_races(*a, **kw):
            # Simulate a concurrent worker replacing the outcome while
            # the chain runs.
            result.outcomes[0] = replacement
            return ["semgrep:unbounded"]

        _patch_confirming_chain(monkeypatch)
        monkeypatch.setattr(orch_mod, "_run_tool_chain", _chain_that_races)

        assert _incremental_promotion_tick(result, config) == 0
        assert result.outcomes[0] is replacement
        assert result.sweep_promoted == 0
        assert result.findings == 0


class TestCritiqueProvisionalJournal:
    def test_critique_promotion_journals_provisional(
        self, monkeypatch, tmp_path,
    ):
        _patch_confirming_chain(monkeypatch)
        config = _config(tmp_path)
        result = OrchestratorResult(suspicious=1)
        result.outcomes = [_suspicious()]

        _run_critique(result, config)

        assert result.outcomes[0].status == "finding"
        assert result.outcomes[0].provisional is True
        rows = load_entries(config.out_dir)
        assert rows and rows[-1].verdict == "finding"
        assert rows[-1].provisional is True

    def test_knob_off_restores_deferred_journal(self, monkeypatch, tmp_path):
        """incremental_promotion=False → exact pre-cadence behavior:
        the promotion happens, nothing is journaled mid-loop."""
        _patch_confirming_chain(monkeypatch)
        config = _config(tmp_path, incremental_promotion=False)
        result = OrchestratorResult(suspicious=1)
        result.outcomes = [_suspicious()]

        _run_critique(result, config)

        assert result.outcomes[0].status == "finding"
        assert result.outcomes[0].provisional is False
        assert load_entries(config.out_dir) == []
        assert result.provisional_promoted_keys == []


class TestFinalization:
    def _promoted_provisional(self, monkeypatch, tmp_path):
        _patch_confirming_chain(monkeypatch)
        config = _config(tmp_path)
        result = OrchestratorResult(suspicious=1)
        result.outcomes = [_suspicious()]
        assert _incremental_promotion_tick(result, config) == 1
        return config, result

    def test_confirmation_clears_mark_and_rejournals(
        self, monkeypatch, tmp_path,
    ):
        config, result = self._promoted_provisional(monkeypatch, tmp_path)

        assert _finalize_provisional_promotions(result, config) == 1
        assert result.outcomes[0].provisional is False
        assert _rejournal_final_statuses(result, config) == 1

        rows = [e for e in load_entries(config.out_dir) if e.function == "f"]
        assert len(rows) >= 2
        assert rows[-1].verdict == "finding"
        assert rows[-1].provisional is None  # confirming row, mark dropped

        log = (config.out_dir / ".audit-log.jsonl").read_text()
        resolved = [
            json.loads(line) for line in log.splitlines()
            if json.loads(line)["action"] == "provisional_promotion_resolved"
        ]
        assert resolved and resolved[0]["resolution"] == "confirmed"

    def test_retraction_reconciles_cleanly(self, monkeypatch, tmp_path):
        """A provisionally-promoted outcome later refuted retracts: the
        corrective journal row ships the demoted verdict, unmarked."""
        config, result = self._promoted_provisional(monkeypatch, tmp_path)

        # Existing demotion paths replace the outcome object (the
        # replacement never carries the mark) — model that directly.
        demoted = ReviewOutcome(
            file="a.c", function="f", status="clean",
            body="[refutation: guard proven]", line=3,
        )
        result.outcomes[0] = demoted
        result.findings -= 1
        result.clean += 1

        _finalize_provisional_promotions(result, config)
        assert _rejournal_final_statuses(result, config) == 1

        rows = [e for e in load_entries(config.out_dir) if e.function == "f"]
        assert rows[-1].verdict == "clean"
        assert rows[-1].provisional is None

        log = (config.out_dir / ".audit-log.jsonl").read_text()
        resolved = [
            json.loads(line) for line in log.splitlines()
            if json.loads(line)["action"] == "provisional_promotion_resolved"
        ]
        assert resolved and resolved[0]["resolution"] == "retracted"

    def test_interrupted_run_keeps_provisional_row(
        self, monkeypatch, tmp_path,
    ):
        """SIGTERM before finalization: the salvage re-journal pass
        must NOT strip the mark, and the durable journal keeps the
        provisional finding (the whole point of the cadence)."""
        config, result = self._promoted_provisional(monkeypatch, tmp_path)

        # Salvage path: re-journal WITHOUT finalization.
        assert _rejournal_final_statuses(result, config) == 0

        rows = [e for e in load_entries(config.out_dir) if e.function == "f"]
        assert rows[-1].verdict == "finding"
        assert rows[-1].provisional is True

    def test_provisional_row_refused_by_verdict_reuse(
        self, monkeypatch, tmp_path,
    ):
        from core.audit.gaps import _reuse_block_class, _reuse_ineligibility

        config, result = self._promoted_provisional(monkeypatch, tmp_path)
        rows = [e for e in load_entries(config.out_dir) if e.function == "f"]
        reason = _reuse_ineligibility(
            rows[-1], "a.c:f",
            current_strategies_fn=None, current_model=None,
        )
        assert reason == "provisional verdict"
        assert _reuse_block_class(reason) == "provisional"

    def test_report_notes_provisional_finding(self, monkeypatch, tmp_path):
        from core.audit.report import write_markdown_report

        config, result = self._promoted_provisional(monkeypatch, tmp_path)
        data = json.loads((config.out_dir / "findings.json").read_text())
        findings = data["findings"] if isinstance(data, dict) else data
        report = {
            "findings_count": len(findings),
            "findings": findings,
            "functions_analysed": [],
        }
        path = write_markdown_report(report, config.out_dir)
        assert "Provisional at time of writing" in Path(path).read_text()


class TestEndToEndCadence:
    def test_finding_journaled_at_tick_and_confirmed_at_end(
        self, monkeypatch, tmp_path,
    ):
        """Through run_orchestrator: the provisional row lands on the
        cadence (action logged), and the completed run's latest journal
        row for the function is a settled, unmarked finding."""
        _patch_confirming_chain(monkeypatch, patch_prefilter=False)
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        src_lines = []
        items = []
        line = 1
        for i in range(4):
            src_lines.append(
                f"void fn{i}(char *p, int n) "
                f"{{ char buf[8]; memcpy(buf, p, n); }}"
            )
            items.append({
                "name": f"fn{i}", "line_start": line,
                "line_end": line, "sloc": 1,
            })
            line += 1
        (target / "src" / "vuln.c").write_text("\n".join(src_lines) + "\n")
        out = tmp_path / "out"
        out.mkdir()
        (out / "checklist.json").write_text(json.dumps({
            "files": [{"path": "src/vuln.c", "items": items}],
            "metadata": {"total_items": len(items), "total_sloc": 4},
        }))

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"], function=ctx["function"],
                status="suspicious", body="unbounded copy",
                hypothesis="unbounded memcpy overflow",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            sweep_validate_findings=True, batch_sloc_threshold=0,
            critique_interval=2, triage=False,
            joern_overrides={"enabled": False},
        )
        result = orch_mod.run_orchestrator(config, review_fn)

        assert result.findings > 0
        log = (out / ".audit-log.jsonl").read_text()
        actions = [json.loads(line)["action"] for line in log.splitlines()]
        # Wired: promotions landed on the cadence, not (only) post-loop.
        assert (
            "incremental_promotion" in actions
            or any(e.provisional for e in load_entries(out))
        )
        assert "provisional_promotion_resolved" in actions

        # Completed run: latest row per promoted function is settled.
        latest: dict[str, object] = {}
        for e in load_entries(out):
            latest[e.function] = e
        settled = [
            e for e in latest.values()
            if e.verdict == "finding" and not e.provisional
        ]
        assert settled, "no confirmed finding row after finalization"
        # In-memory marks are cleared on the completed run.
        assert all(not o.provisional for o in result.outcomes)


class TestPromotionReReviewReconciliation:
    """Mid-loop promotion vs the chain re-review preamble.

    A tick/critique promotion REPLACES the outcome object; the
    executor's reviewed_outcomes map must follow it, and when it does
    not (concurrent swap), _supersede_prior_outcome must supersede the
    CURRENT object at the site — never un-tally a stale status while
    leaving the promoted object behind as an orphan finding.
    """

    def _promoted_with_stale_map(self, monkeypatch, tmp_path):
        _patch_confirming_chain(monkeypatch)
        config = _config(tmp_path)
        o_susp = _suspicious()
        result = OrchestratorResult(suspicious=1, reviewed=1)
        result.outcomes = [o_susp]
        reviewed_outcomes = {"a.c:f": o_susp}  # tracked pre-promotion
        # Tick WITHOUT the map — models a concurrent re-review racing
        # the tracking swap.
        assert _incremental_promotion_tick(result, config) == 1
        assert reviewed_outcomes["a.c:f"] is o_susp  # stale by design
        return config, result, reviewed_outcomes

    def test_tick_midrun_persist_stamps_tree_class(self, monkeypatch,
                                                   tmp_path):
        """The tick's ride-along findings.json write happens with no
        prep verdicts in scope — the provisional record must still
        carry the tree-class stamp (path-only fallback). Untagged
        tick-persisted findings were the mid-run half of the
        every-emission-path-stamps contract."""
        config, result, _ = self._promoted_with_stale_map(
            monkeypatch, tmp_path,
        )
        data = json.loads((config.out_dir / "findings.json").read_text())
        findings = data["findings"] if isinstance(data, dict) else data
        assert len(findings) == 1
        assert findings[0].get("provisional") is True
        assert findings[0]["tree_class"] == "production"

    def test_tick_updates_reviewed_outcomes(self, monkeypatch, tmp_path):
        _patch_confirming_chain(monkeypatch)
        config = _config(tmp_path)
        o_susp = _suspicious()
        result = OrchestratorResult(suspicious=1, reviewed=1)
        result.outcomes = [o_susp]
        reviewed_outcomes = {"a.c:f": o_susp}

        assert _incremental_promotion_tick(
            result, config, reviewed_outcomes=reviewed_outcomes,
        ) == 1
        assert reviewed_outcomes["a.c:f"] is result.outcomes[0]
        assert reviewed_outcomes["a.c:f"].status == "finding"

    def test_stale_map_supersedes_current_object(self, monkeypatch, tmp_path):
        from core.audit.orchestrator import _supersede_prior_outcome

        config, result, reviewed_outcomes = self._promoted_with_stale_map(
            monkeypatch, tmp_path,
        )
        removed = _supersede_prior_outcome(result, reviewed_outcomes, "a.c:f")

        # The PROMOTED replacement was removed and un-tallied with its
        # ACTUAL status — no orphan, no negative counters.
        assert removed is not None and removed.status == "finding"
        assert result.outcomes == []
        assert result.findings == 0
        assert result.suspicious == 0

    def test_vanished_outcome_untallies_nothing(self, tmp_path):
        from core.audit.orchestrator import _supersede_prior_outcome

        o = _suspicious()
        result = OrchestratorResult(suspicious=1, reviewed=1)
        result.outcomes = []  # already removed by another pass
        assert _supersede_prior_outcome(result, {"a.c:f": o}, "a.c:f") is None
        assert result.suspicious == 1  # untouched
        assert result.reviewed == 1

    def test_reused_outcome_untally_reverses_reused_counter(self):
        """Superseding a reused-imported outcome reverses
        ``reused_from_prior``, never ``reviewed`` — verdict-reuse
        imports tally with ``reused=True`` (which does not increment
        ``reviewed``), so decrementing ``reviewed`` on a re-review
        drifted it below truth, negative on reuse-heavy resume
        segments."""
        from core.audit.orchestrator import (
            _supersede_prior_outcome,
            _tally_outcome,
        )

        o = _suspicious()
        o.reused = True
        result = OrchestratorResult(reviewed=3)
        _tally_outcome(result, o, reused=True)
        assert result.reused_from_prior == 1
        assert result.reviewed == 3  # reused import never counts here

        removed = _supersede_prior_outcome(result, {"a.c:f": o}, "a.c:f")
        assert removed is o
        assert result.reused_from_prior == 0
        assert result.reviewed == 3  # fresh reviews only — no drift
        assert result.suspicious == 0

    def test_repro_end_to_end_no_orphan_finding(self, monkeypatch, tmp_path):
        """The adversarial-review repro: tick promotes, stale-map
        re-review concludes clean — findings.json must ship NO finding
        and every counter stays non-negative."""
        from core.audit.orchestrator import (
            _persist_findings,
            _supersede_prior_outcome,
            _tally_outcome,
        )

        config, result, reviewed_outcomes = self._promoted_with_stale_map(
            monkeypatch, tmp_path,
        )
        # Re-review preamble (as review_one_function runs it).
        _supersede_prior_outcome(result, reviewed_outcomes, "a.c:f")
        # Re-review concludes clean; loop tallies and tracks it.
        o_clean = ReviewOutcome(
            file="a.c", function="f", status="clean", body="ok",
        )
        _tally_outcome(result, o_clean)  # appends to result.outcomes
        reviewed_outcomes["a.c:f"] = o_clean

        assert [o.function for o in result.outcomes] == ["f"]
        assert result.findings == 0
        assert result.suspicious == 0
        assert result.clean == 1

        _finalize_provisional_promotions(result, config)
        _persist_findings(result, config)
        data = json.loads((config.out_dir / "findings.json").read_text())
        findings = data["findings"] if isinstance(data, dict) else data
        assert findings == []


class TestKnobGate:
    def test_knob_off_never_ticks_in_the_loop(self, monkeypatch, tmp_path):
        """review_one_function's cadence gate: incremental_promotion=False
        must keep the tick entirely out of the loop."""
        tick_calls: list = []
        monkeypatch.setattr(
            orch_mod, "_incremental_promotion_tick",
            lambda *a, **kw: tick_calls.append(a) or 0,
        )
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void fn0(char *p, int n) { char buf[8]; memcpy(buf, p, n); }\n"
            "void fn1(char *p, int n) { char buf[8]; memcpy(buf, p, n); }\n"
            "void fn2(char *p, int n) { char buf[8]; memcpy(buf, p, n); }\n"
        )
        out = tmp_path / "out"
        out.mkdir()
        (out / "checklist.json").write_text(json.dumps({
            "files": [{"path": "src/vuln.c", "items": [
                {"name": f"fn{i}", "line_start": i + 1,
                 "line_end": i + 1, "sloc": 1}
                for i in range(3)
            ]}],
            "metadata": {"total_items": 3, "total_sloc": 3},
        }))

        def review_fn(ctx, config):
            return ReviewOutcome(
                file=ctx["file"], function=ctx["function"],
                status="clean", body="ok",
            )

        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            sweep_validate_findings=True, batch_sloc_threshold=0,
            critique_interval=2, triage=False,
            incremental_promotion=False,
            joern_overrides={"enabled": False},
        )
        orch_mod.run_orchestrator(config, review_fn)
        assert tick_calls == []


class TestDeepenIncludesProvisional:
    def test_provisional_finding_gets_deepen_rereview(
        self, monkeypatch, tmp_path,
    ):
        """Pre-cadence, a tick-promoted item was still suspicious at
        deepen time and got the enriched-context refutation chance —
        provisional findings must keep it. Settled findings stay out."""
        import time as _time

        from core.audit.orchestrator import _deepen_suspicious

        monkeypatch.setattr(
            orch_mod, "_build_context",
            lambda cfg, gap, *a, **kw: {
                "file": gap["file"], "function": gap["name"],
            },
        )
        provisional = ReviewOutcome(
            file="a.c", function="pf", status="finding",
            body="[sweep promoted via semgrep:x]\n\nmaybe",
            hypothesis="h1", review_result={"body": "maybe"},
        )
        provisional.provisional = True
        settled = ReviewOutcome(
            file="a.c", function="sf", status="finding",
            body="found", hypothesis="h2",
            review_result={"body": "found"},
        )
        result = OrchestratorResult(findings=2, reviewed=2)
        result.outcomes = [provisional, settled]
        checklist = {"files": [{"path": "a.c", "functions": [
            {"name": "pf", "line_start": 1, "line_end": 100},
            {"name": "sf", "line_start": 1, "line_end": 100},
        ]}]}

        deepened: list[str] = []

        def review_fn(ctx, cfg):
            deepened.append(ctx["function"])
            return ReviewOutcome(
                file=ctx["file"], function=ctx["function"],
                status="clean", body="refuted",
                review_result={
                    "body": "refuted", "all_refuted_demotion": True,
                },
            )

        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path,
            sweep_validate_findings=False, deepen_suspicious=True,
        )
        _deepen_suspicious(
            result, config, review_fn, checklist,
            None, None, [], None, set(), _time.time(), None,
            max_workers=1,
        )

        assert deepened == ["pf"]  # provisional deepened; settled not
        assert result.findings == 1
        assert result.clean == 1
        # The deepen verdict superseded the provisional object entirely.
        assert all(
            not getattr(o, "provisional", False) for o in result.outcomes
        )
