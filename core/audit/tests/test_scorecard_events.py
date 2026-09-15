"""Tests for the audit scorecard producer (``core.audit.scorecard_events``).

Pin the emission contract the orchestrator wiring depends on:

* events carry the audit decision-class convention and the
  correct/incorrect grades of each adjudication shape;
* the reliability pool (``tool_evidence``) is receipt-only —
  unreceipted adversarial rulings land on consistency axes
  (``self_consistency`` / ``cross_family_consistency``), never
  ``judge_review``;
* attribution rules (self-consistency handle suffix stripped, the
  ``"default"`` placeholder never attributing on ANY path, lone
  configured model as fallback, no attribution → no event);
* hostile-input bounds (target-controlled keys capped before they
  reach the shared cross-run sidecar);
* flush reconciliation in both grade directions, outcome-aware dedup,
  and per-entry validation (one malformed dict never aborts the
  batch);
* fail-soft everywhere — a raising store or a broken outcome object
  must never propagate out of the emission path;
* the orchestrator wiring itself binds: a minimal orchestrated run
  buffers events and writes the sidecar, and a scorecard-disabled
  client config suppresses the write entirely.

No LLM calls, no network; sidecar writes go through the per-test
``RAPTOR_SCORECARD_PATH`` isolation fixture (directory conftest).
"""

from __future__ import annotations

import inspect
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from core.audit.scorecard_events import (
    buffer_confirmed_findings,
    buffer_event,
    flush_scorecard_events,
    lone_model,
    record_adversarial_outcome,
    record_mechanical_refutation,
    record_self_consistency_violation,
    resolve_scorecard_store,
)


def _outcome(**kw: Any) -> SimpleNamespace:
    base = {
        "file": "src/a.c",
        "function": "parse",
        "status": "finding",
        "model": "model-a",
        "hypothesis": "unchecked length reaches memcpy",
        "evidence_tool": "",
        "review_result": {"cwe_class": "CWE-787"},
        "body": "",
    }
    base.update(kw)
    return SimpleNamespace(**base)


class _RaisingStore:
    def record_events(self, events: list[dict]) -> None:
        raise OSError("sidecar unwritable")


class _CapturingStore:
    def __init__(self) -> None:
        self.batches: list[list[dict]] = []

    def record_events(self, events: list[dict]) -> None:
        self.batches.append(events)


# ---------------------------------------------------------------------------
# buffer_event / attribution
# ---------------------------------------------------------------------------


class TestBufferEvent:
    def test_builds_record_events_shape(self) -> None:
        events: list[dict] = []
        ok = buffer_event(
            events, model="m", cwe="CWE-79", event_type="tool_evidence",
            grade="incorrect", key="f.c:g", this_reasoning="x" * 1000,
            other_reasoning="gate: reason",
        )
        assert ok and len(events) == 1
        ev = events[0]
        assert ev["decision_class"] == "audit:CWE-79"
        assert ev["model"] == "m"
        assert ev["event_type"] == "tool_evidence"
        assert ev["outcome"] == "incorrect"
        assert ev["_key"] == "f.c:g"
        # Reasoning capped at the canonical producer limit.
        assert len(ev["sample"]["this_reasoning"]) == 500

    def test_correct_grade_carries_no_sample(self) -> None:
        events: list[dict] = []
        buffer_event(
            events, model="m", cwe="", event_type="tool_evidence",
            grade="correct", key="k",
        )
        assert events[0]["sample"] is None
        assert events[0]["decision_class"] == "audit:review"

    def test_skips_missing_model_and_bad_grade(self) -> None:
        events: list[dict] = []
        assert not buffer_event(
            events, model="", cwe="", event_type="tool_evidence",
            grade="incorrect", key="k",
        )
        assert not buffer_event(
            events, model="m", cwe="", event_type="tool_evidence",
            grade="maybe", key="k",
        )
        assert events == []

    def test_strips_self_consistency_handle_suffix(self) -> None:
        events: list[dict] = []
        buffer_event(
            events, model="model-a#sc2", cwe="", event_type="tool_evidence",
            grade="correct", key="k",
        )
        assert events[0]["model"] == "model-a"

    def test_default_placeholder_never_attributes(self) -> None:
        """The unconfigured sentinel reaches outcome.model verbatim via
        the panel-result fallback, so the primary path (not just the
        lone_model fallback) must reject it — bare and suffixed."""
        events: list[dict] = []
        assert not buffer_event(
            events, model="default", cwe="", event_type="tool_evidence",
            grade="correct", key="k",
        )
        assert not buffer_event(
            events, model="default#sc0", cwe="", event_type="tool_evidence",
            grade="correct", key="k",
        )
        assert not record_mechanical_refutation(
            events, _outcome(model="default"), gate="g", reason="r",
        )
        assert events == []

    def test_target_controlled_key_is_capped(self) -> None:
        """A hostile repo can mint megabyte function names; the key
        rides into the shared cross-run sidecar and must be bounded."""
        events: list[dict] = []
        huge = "src/a.c:" + "f" * (10 * 1024 * 1024)
        buffer_event(
            events, model="m", cwe="", event_type="tool_evidence",
            grade="incorrect", key=huge,
        )
        assert len(events[0]["_key"]) == 500
        assert len(events[0]["sample"]["function_id"]) == 500


class TestLoneModel:
    def test_single_model_attributes(self) -> None:
        assert lone_model(["model-a"]) == "model-a"

    def test_multi_model_and_placeholder_do_not(self) -> None:
        assert lone_model(["a", "b"]) == ""
        assert lone_model(["default"]) == ""
        assert lone_model(None) == ""
        assert lone_model([]) == ""


# ---------------------------------------------------------------------------
# Site helpers
# ---------------------------------------------------------------------------


class TestMechanicalRefutation:
    def test_records_tool_evidence_incorrect(self) -> None:
        events: list[dict] = []
        ok = record_mechanical_refutation(
            events, _outcome(), gate="refutation_gate",
            reason="bounds check dominates the sink",
        )
        assert ok
        ev = events[0]
        assert ev["event_type"] == "tool_evidence"
        assert ev["outcome"] == "incorrect"
        assert ev["decision_class"] == "audit:CWE-787"
        assert ev["_key"] == "src/a.c:parse"
        assert "refutation_gate" in ev["sample"]["other_reasoning"]

    def test_fallback_attribution_on_lone_model_run(self) -> None:
        events: list[dict] = []
        assert record_mechanical_refutation(
            events, _outcome(model=""), gate="g", reason="r",
            models=["model-b"],
        )
        assert events[0]["model"] == "model-b"

    def test_no_attribution_no_event(self) -> None:
        events: list[dict] = []
        assert not record_mechanical_refutation(
            events, _outcome(model=""), gate="g", reason="r",
            models=["a", "b"],
        )
        assert events == []

    def test_broken_outcome_never_raises(self) -> None:
        class _Broken:
            @property
            def model(self) -> str:
                raise RuntimeError("boom")

        assert not record_mechanical_refutation(
            [], _Broken(), gate="g", reason="r",
        )


class TestAdversarialOutcome:
    def test_unreceipted_cross_model_refuted_is_consistency_axis(self) -> None:
        """A 1-vs-1 refuter ruling is policy, not ground truth: it must
        never land in the reliability pool (judge_review/tool_evidence)
        — the registry's own judge producer refuses this shape."""
        events: list[dict] = []
        n = record_adversarial_outcome(
            events, _outcome(), producer_model="model-a",
            refuter_model="model-b", verdict="refuted",
            defeating_mechanism="the loop bound is clamped upstream",
        )
        assert n == 1
        ev = events[0]
        assert ev["event_type"] == "cross_family_consistency"
        assert ev["outcome"] == "incorrect"
        assert ev["model"] == "model-a"
        assert "model-b" in ev["sample"]["other_reasoning"]

    def test_unreceipted_cross_model_stands_is_consistency_axis(self) -> None:
        events: list[dict] = []
        record_adversarial_outcome(
            events, _outcome(), producer_model="model-a",
            refuter_model="model-b", verdict="stands",
        )
        assert events[0]["event_type"] == "cross_family_consistency"
        assert events[0]["outcome"] == "correct"

    def test_never_emits_reliability_pool_types_unreceipted(self) -> None:
        from core.audit.calibrated_merge import RELIABILITY_EVENT_TYPES

        events: list[dict] = []
        for refuter in ("model-b", "model-a", ""):
            for verdict in ("stands", "refuted"):
                record_adversarial_outcome(
                    events, _outcome(), producer_model="model-a",
                    refuter_model=refuter, verdict=verdict,
                )
        assert events, "expected consistency events"
        assert not [
            e for e in events
            if e["event_type"] in RELIABILITY_EVENT_TYPES
        ]

    def test_self_adversarial_uses_self_consistency(self) -> None:
        events: list[dict] = []
        record_adversarial_outcome(
            events, _outcome(), producer_model="model-a",
            refuter_model="model-a", verdict="refuted",
        )
        record_adversarial_outcome(
            events, _outcome(), producer_model="model-a",
            refuter_model="", verdict="stands",
        )
        assert [e["event_type"] for e in events] == [
            "self_consistency", "self_consistency",
        ]
        assert [e["outcome"] for e in events] == ["incorrect", "correct"]

    def test_overturned_grades_both_sides_on_the_receipt(self) -> None:
        events: list[dict] = []
        n = record_adversarial_outcome(
            events, _outcome(), producer_model="model-a",
            refuter_model="model-b", verdict="refuted",
            defeating_mechanism="claimed clamp",
            overturned_by="smt:overflow-check",
        )
        assert n == 2
        by_model = {e["model"]: e for e in events}
        assert by_model["model-a"]["event_type"] == "tool_evidence"
        assert by_model["model-a"]["outcome"] == "correct"
        assert by_model["model-b"]["event_type"] == "tool_evidence"
        assert by_model["model-b"]["outcome"] == "incorrect"
        assert by_model["model-b"]["_grades_refuter"] is True

    def test_ungraded_verdicts_emit_nothing(self) -> None:
        events: list[dict] = []
        assert record_adversarial_outcome(
            events, _outcome(), producer_model="model-a",
            refuter_model="model-b", verdict="needs_evidence",
        ) == 0
        assert events == []


class TestSelfConsistencyViolation:
    def test_records_incorrect(self) -> None:
        events: list[dict] = []
        assert record_self_consistency_violation(
            events, _outcome(status="suspicious"),
            detail="all 3 hypotheses marked refuted yet verdict suspicious",
        )
        assert events[0]["event_type"] == "self_consistency"
        assert events[0]["outcome"] == "incorrect"


class TestConfirmedFindings:
    def test_receipt_check_gates_the_grade(self) -> None:
        events: list[dict] = []
        outcomes = [
            _outcome(evidence_tool="smt:overflow-check"),
            # Below the injected receipt bar — no grade.
            _outcome(function="g", evidence_tool="consistency:x-majority"),
            # No hypothesis — nothing was confirmed.
            _outcome(function="h", evidence_tool="smt:overflow-check",
                     hypothesis=""),
            # Non-finding statuses carry no confirmed grade.
            _outcome(function="i", status="suspicious",
                     evidence_tool="smt:overflow-check"),
        ]
        n = buffer_confirmed_findings(
            events, outcomes,
            receipt_check=lambda s: s.startswith("smt:"),
        )
        assert n == 1
        assert events[0]["event_type"] == "tool_evidence"
        assert events[0]["outcome"] == "correct"
        assert events[0]["_key"] == "src/a.c:parse"

    def test_default_receipt_check_is_promotion_grade(
        self, monkeypatch,
    ) -> None:
        """Without an injected predicate the promotion-grade bar (the
        one the overturn and promotion sites use) decides — not bare
        is_tool_evidence, which admits detection-role stamps."""
        import core.audit.orchestrator as orch

        seen: list[str] = []

        def _fake(receipt: str) -> bool:
            seen.append(receipt)
            return False

        monkeypatch.setattr(orch, "_promotion_grade_receipt", _fake)
        events: list[dict] = []
        assert buffer_confirmed_findings(
            events, [_outcome(evidence_tool="semgrep:rule-1")],
        ) == 0
        assert seen == ["semgrep:rule-1"]
        assert events == []


# ---------------------------------------------------------------------------
# Flush: reconciliation, dedup, validation, fail-soft
# ---------------------------------------------------------------------------


class TestFlush:
    def test_rescued_finding_drops_buffered_refutation(self) -> None:
        events: list[dict] = []
        record_mechanical_refutation(events, _outcome(), gate="g", reason="r")
        store = _CapturingStore()
        n = flush_scorecard_events(
            events, finding_keys={"src/a.c:parse"}, scorecard=store,
        )
        assert n == 0
        assert store.batches == []

    def test_demoted_function_drops_buffered_confirmation(self) -> None:
        """Symmetric direction: a correct grade must not ship for a
        function whose final status contradicts it."""
        events: list[dict] = []
        record_adversarial_outcome(
            events, _outcome(), producer_model="model-a",
            refuter_model="model-b", verdict="refuted",
            overturned_by="smt:check",
        )
        store = _CapturingStore()
        # Function does NOT end the run as a finding: the producer's
        # correct grade drops; the refuter's receipt-settled incorrect
        # survives (exempt both ways).
        n = flush_scorecard_events(events, finding_keys=set(),
                                   scorecard=store)
        assert n == 1
        written = store.batches[0]
        assert written[0]["model"] == "model-b"
        assert written[0]["outcome"] == "incorrect"

    def test_refuter_grade_survives_finding_reconciliation(self) -> None:
        events: list[dict] = []
        record_adversarial_outcome(
            events, _outcome(), producer_model="model-a",
            refuter_model="model-b", verdict="refuted",
            overturned_by="smt:check",
        )
        store = _CapturingStore()
        n = flush_scorecard_events(
            events, finding_keys={"src/a.c:parse"}, scorecard=store,
        )
        assert n == 2
        written = store.batches[0]
        # Private bookkeeping keys never reach the store.
        assert all("_key" not in e and "_grades_refuter" not in e
                   for e in written)

    def test_consistency_events_are_not_reconciled(self) -> None:
        """A flip/dispute happened regardless of the final status — a
        later rescue does not un-happen it."""
        events: list[dict] = []
        record_self_consistency_violation(
            events, _outcome(status="suspicious"), detail="flip",
        )
        store = _CapturingStore()
        assert flush_scorecard_events(
            events, finding_keys={"src/a.c:parse"}, scorecard=store,
        ) == 1

    def test_dedup_one_miss_per_cell_per_function(self) -> None:
        events: list[dict] = []
        record_mechanical_refutation(events, _outcome(status="suspicious"),
                                     gate="g1", reason="r1")
        record_mechanical_refutation(events, _outcome(status="suspicious"),
                                     gate="g2", reason="r2")
        store = _CapturingStore()
        assert flush_scorecard_events(events, scorecard=store) == 1

    def test_dedup_is_outcome_aware(self) -> None:
        """A correct and an incorrect for the same cell/function are
        different observations — dedup must not let the first-buffered
        direction swallow the other; reconciliation arbitrates."""
        events: list[dict] = []
        buffer_event(events, model="m", cwe="", event_type="tool_evidence",
                     grade="correct", key="src/a.c:parse")
        buffer_event(events, model="m", cwe="", event_type="tool_evidence",
                     grade="incorrect", key="src/a.c:parse")
        store = _CapturingStore()
        # Final status finding: the incorrect drops, the correct ships.
        assert flush_scorecard_events(
            events, finding_keys={"src/a.c:parse"}, scorecard=store,
        ) == 1
        assert store.batches[0][0]["outcome"] == "correct"
        # Final status non-finding: the correct drops, the incorrect
        # ships.
        store2 = _CapturingStore()
        assert flush_scorecard_events(
            events, finding_keys=set(), scorecard=store2,
        ) == 1
        assert store2.batches[0][0]["outcome"] == "incorrect"

    def test_dedup_ships_both_directions_on_consistency_axes(self) -> None:
        """Consistency events are never reconciled, so ONLY the dedup
        tuple stands between an opposite-direction pair and silent
        swallowing: a clean-with-live-hypotheses contradiction
        (incorrect) followed by a self-adversarial upheld verdict
        (correct) for the same cell and function must both ship."""
        events: list[dict] = []
        record_self_consistency_violation(
            events, _outcome(status="clean"),
            detail="clean verdict despite live hypotheses",
        )
        record_adversarial_outcome(
            events, _outcome(), producer_model="model-a",
            refuter_model="model-a", verdict="stands",
        )
        assert [e["event_type"] for e in events] == [
            "self_consistency", "self_consistency",
        ]
        store = _CapturingStore()
        assert flush_scorecard_events(events, scorecard=store) == 2
        assert sorted(e["outcome"] for e in store.batches[0]) == [
            "correct", "incorrect",
        ]

    def test_long_keys_reconcile_via_the_shared_builder(self) -> None:
        """Events cap their keys at buffer time; the flush's finding
        set is built with the SAME helper (outcome_key), so functions
        whose file:function exceeds the cap still reconcile in both
        directions — a rescued finding's refutation drops and a
        confirmed finding's grade survives."""
        from core.audit.scorecard_events import outcome_key

        long_fn = _outcome(function="f" * 600)
        finding_keys = {outcome_key(long_fn)}

        # Rescued-finding direction: the refutation must drop.
        events: list[dict] = []
        record_mechanical_refutation(events, long_fn, gate="g", reason="r")
        store = _CapturingStore()
        assert flush_scorecard_events(
            events, finding_keys=finding_keys, scorecard=store,
        ) == 0

        # Confirmed-finding direction: the correct grade must survive
        # the symmetric reconciliation.
        events2: list[dict] = []
        assert buffer_confirmed_findings(
            events2, [long_fn], receipt_check=lambda s: True,
        ) == 1
        store2 = _CapturingStore()
        assert flush_scorecard_events(
            events2, finding_keys=finding_keys, scorecard=store2,
        ) == 1
        assert store2.batches[0][0]["outcome"] == "correct"

    def test_one_malformed_entry_does_not_abort_the_batch(self) -> None:
        """record_events validates pre-lock and raises on ANY invalid
        entry; the flush must filter per entry so one bad dict cannot
        cost the run's whole telemetry."""
        events: list[dict] = []
        record_mechanical_refutation(
            events, _outcome(status="suspicious"), gate="g", reason="r",
        )
        events.insert(0, {"event_type": "not-a-type",
                          "outcome": "incorrect", "model": "m",
                          "decision_class": "audit:review"})
        events.insert(0, {"nonsense": True})
        events.insert(0, "not-a-dict")  # type: ignore[arg-type]
        from core.llm.scorecard import ModelScorecard

        path = Path(os.environ["RAPTOR_SCORECARD_PATH"])
        assert flush_scorecard_events(
            events, scorecard=ModelScorecard(path),
        ) == 1
        assert path.exists()

    def test_raising_store_is_contained(self) -> None:
        events: list[dict] = []
        record_mechanical_refutation(events, _outcome(status="suspicious"),
                                     gate="g", reason="r")
        # Must not raise, must report zero written.
        assert flush_scorecard_events(events, scorecard=_RaisingStore()) == 0

    def test_empty_buffer_is_noop(self) -> None:
        assert flush_scorecard_events([], scorecard=_RaisingStore()) == 0

    def test_real_sidecar_roundtrip(self, tmp_path) -> None:
        """End-to-end through the real public API: events land in the
        sidecar under the audit decision class, on the right axes."""
        from core.llm.scorecard import ModelScorecard

        path = tmp_path / "llm_scorecard.json"
        events: list[dict] = []
        record_mechanical_refutation(
            events, _outcome(status="suspicious"), gate="refutation_gate",
            reason="dominating bounds check",
        )
        record_adversarial_outcome(
            events, _outcome(function="other"), producer_model="model-a",
            refuter_model="model-b", verdict="stands",
        )
        n = flush_scorecard_events(
            events, finding_keys=set(), scorecard=ModelScorecard(path),
        )
        assert n == 2
        stats = ModelScorecard(path).get_stats()
        cells = {(s.model, s.decision_class): s for s in stats}
        cell = cells[("model-a", "audit:CWE-787")]
        assert cell.events["tool_evidence"].incorrect == 1
        assert cell.events["cross_family_consistency"].correct == 1

    def test_default_path_resolution_honours_env_override(
        self, tmp_path, monkeypatch,
    ) -> None:
        monkeypatch.setenv(
            "RAPTOR_SCORECARD_PATH", str(tmp_path / "sc.json"),
        )
        events: list[dict] = []
        record_mechanical_refutation(
            events, _outcome(status="suspicious"), gate="g", reason="r",
        )
        assert flush_scorecard_events(events) == 1
        assert (tmp_path / "sc.json").exists()


class TestResolveStore:
    def test_property_style_client(self) -> None:
        store = object()
        client = SimpleNamespace(scorecard=store, config=None)
        assert resolve_scorecard_store(client) == (store, False)

    def test_method_style_client(self) -> None:
        store = object()
        client = SimpleNamespace(scorecard=lambda: store)
        assert resolve_scorecard_store(client) == (store, False)

    def test_disabled_config_blocks_default_fallback(self) -> None:
        client = SimpleNamespace(
            scorecard=None,
            config=SimpleNamespace(scorecard_enabled=False),
        )
        assert resolve_scorecard_store(client) == (None, True)

    def test_no_client_falls_through(self) -> None:
        assert resolve_scorecard_store(None) == (None, False)


# ---------------------------------------------------------------------------
# Orchestrator wiring: the emission path must never break a decision
# ---------------------------------------------------------------------------


class TestFailSoftWiring:
    def test_helpers_contain_a_raising_buffer(self, monkeypatch) -> None:
        """Even if the innermost append path breaks, every site helper
        the orchestrator calls returns instead of raising — the
        decision path (demotion/promotion bookkeeping) proceeds."""
        import core.audit.scorecard_events as mod

        def _boom(*a: Any, **k: Any) -> bool:
            raise RuntimeError("recorder broken")

        monkeypatch.setattr(mod, "buffer_event", _boom)
        o = _outcome()
        assert mod.record_mechanical_refutation(
            [], o, gate="g", reason="r",
        ) is False
        assert mod.record_self_consistency_violation(
            [], o, detail="d",
        ) is False
        assert mod.record_adversarial_outcome(
            [], o, producer_model="a", refuter_model="b", verdict="refuted",
        ) == 0
        assert mod.buffer_confirmed_findings(
            [], [_outcome(evidence_tool="smt:x")],
            receipt_check=lambda s: True,
        ) == 0

    def test_orchestrator_result_buffers_and_events_validate(self) -> None:
        """The orchestrator's buffer field exists and buffered entries
        pass the public API's pre-lock validation, so a batch can
        never abort on shape."""
        from core.audit.orchestrator import OrchestratorResult
        from core.llm.scorecard.scorecard import ModelScorecard

        result = OrchestratorResult()
        assert result.scorecard_events == []
        record_mechanical_refutation(
            result.scorecard_events, _outcome(), gate="g", reason="r",
        )
        for ev in result.scorecard_events:
            ModelScorecard._validate_event(
                ev.get("event_type"), ev.get("outcome"),
            )


class TestPostLoopPassEmission:
    """Functional binding of the callable post-loop emission sites."""

    def test_self_contradiction_demotion_buffers_event(self) -> None:
        from core.audit.orchestrator import (
            OrchestratorResult,
            ReviewOutcome,
            _demote_self_contradictions,
        )

        result = OrchestratorResult()
        result.outcomes.append(ReviewOutcome(
            file="src/a.c", function="parse", status="suspicious",
            body="verdict body", model="model-a",
            hypothesis="overflow via len",
            hypotheses=[{"mechanism": "m1", "confidence": "refuted"},
                        {"mechanism": "m2", "confidence": "refuted"}],
        ))
        result.suspicious = 1
        _demote_self_contradictions(result)
        assert result.outcomes[0].status == "clean"
        assert len(result.scorecard_events) == 1
        ev = result.scorecard_events[0]
        assert ev["event_type"] == "self_consistency"
        assert ev["outcome"] == "incorrect"
        assert ev["model"] == "model-a"

    def test_hypothesis_inconsistent_promotion_buffers_event(self) -> None:
        from core.audit.orchestrator import (
            OrchestratorResult,
            ReviewOutcome,
            _promote_hypothesis_inconsistent,
        )

        result = OrchestratorResult()
        result.outcomes.append(ReviewOutcome(
            file="src/a.c", function="parse", status="clean",
            body="verdict body", model="model-a",
            hypothesis="race on shared state",
            hypotheses=[{"mechanism": "race", "confidence": "high"}],
        ))
        result.clean = 1
        _promote_hypothesis_inconsistent(result)
        assert result.outcomes[0].status == "suspicious"
        assert len(result.scorecard_events) == 1
        assert result.scorecard_events[0]["event_type"] == "self_consistency"
        assert result.scorecard_events[0]["outcome"] == "incorrect"


class TestInlineSitePins:
    """Source-level pins for the emission sites that live inline in
    functions too large to drive hermetically. They bind the gating
    conditions the functional/e2e tests cannot reach: neutralizing a
    guard or moving the flush ahead of the exports fails here."""

    def test_refutation_gate_requires_proof_grade(self) -> None:
        from core.audit import orchestrator as orch

        src = inspect.getsource(orch.review_one_function)
        gate_idx = src.index('refuter_grade", "heuristic") == "proof"')
        emit_idx = src.index("_sc_record_refutation", gate_idx)
        # The emission is inside the proof-grade conditional.
        assert emit_idx - gate_idx < 400

    def test_sweep_site_grades_only_smt_disproof(self) -> None:
        from core.audit import orchestrator as orch

        src = inspect.getsource(orch.review_one_function)
        idx = src.index('_sweep_reason.startswith("[smt-disproof:")')
        assert "_sc_record_refutation" in src[idx:idx + 400]

    def test_post_deepen_routes_reasons_by_what_they_prove(self) -> None:
        from core.audit import orchestrator as orch

        src = inspect.getsource(orch._run_audit_body)
        idx = src.index('"[guarded-sink:"')
        segment = src[idx:idx + 1200]
        assert "_sc_record_refutation" in segment
        assert '"[self-contradiction:"' in segment
        assert "_sc_record_self_consistency" in segment
        # Reachability reasons must not reach either grading branch:
        # nothing between the routing head and the consistency call
        # names them, and there is no third emission branch.
        assert "unreachability" not in segment

    def test_dark_verify_grades_only_without_retained_stamp(self) -> None:
        from core.audit import orchestrator as orch

        src = inspect.getsource(orch._run_dark_verification)
        idx = src.index('_pe.startswith("llm-claimed:")')
        assert "_sc_record_refutation" in src[idx:idx + 500]

    def test_flush_runs_after_primary_artifacts(self) -> None:
        """The sidecar write takes a cross-process flock; a wedged
        holder may stall only the telemetry, never the findings
        persist / journal correction / graded export."""
        from core.audit import orchestrator as orch

        src = inspect.getsource(orch._run_audit_body)
        flush_idx = src.index("_flush_scorecard_events_now")
        assert src.index("_persist_findings", 0, flush_idx) > 0
        assert src.index("_rejournal_final_statuses", 0, flush_idx) > 0
        assert src.index("write_graded_findings", 0, flush_idx) > 0

    def test_flush_respects_disabled_store(self) -> None:
        from core.audit import orchestrator as orch

        src = inspect.getsource(orch._flush_scorecard_events_now)
        idx = src.index("_sc_resolve_store")
        segment = src[idx:]
        assert "if disabled:" in segment
        assert segment.index("if disabled:") < segment.index(
            "_sc_flush_events",
        )
        # finding_keys must be built with the SAME capped key builder
        # the events buffered with — a raw f-string comprehension
        # breaks reconciliation for over-cap file:function keys.
        assert "_sc_outcome_key(o)" in segment


class TestOrchestratedRunBinding:
    """Binding of the whole wiring on a real (tiny, LLM-free)
    orchestrated run: emission site → result buffer → flush → sidecar,
    and the scorecard-disabled suppression."""

    @staticmethod
    def _setup_target(tmp_path: Path):
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        body = (
            "int quux_step(int a) {\n"
            + "\n".join(f"  int v{i} = a + {i};" for i in range(12))
            + "\n  return a;\n}\n"
        )
        (target / "src" / "one.c").write_text(body)
        out = tmp_path / "out"
        out.mkdir()
        checklist = {"files": [{"path": "src/one.c", "items": [
            {"name": "quux_step", "line_start": 1,
             "line_end": body.count("\n")},
        ]}]}
        (out / "checklist.json").write_text(json.dumps(checklist))
        return target, out

    @staticmethod
    def _review_fn(ctx, config):
        from core.audit.orchestrator import ReviewOutcome

        # Suspicious verdict whose own hypotheses are all refuted →
        # the self-contradiction pass demotes it and buffers a
        # self_consistency event. Nonsense mechanism text keeps every
        # keyword-driven gate/tool-chain out of the way.
        return ReviewOutcome(
            file=ctx["file"], function=ctx["function"],
            status="suspicious",
            body="the frobnicator misaligns the quux lattice",
            hypothesis="the frobnicator misaligns the quux lattice",
            hypotheses=[
                {"mechanism": "quux lattice drift",
                 "confidence": "refuted"},
            ],
            model="test-model",
            review_result={"cwe_class": "CWE-000"},
        )

    def _config(self, target: Path, out: Path, **kw):
        from core.audit.orchestrator import OrchestratorConfig

        defaults: dict = {
            "target_path": target,
            "out_dir": out,
            "resume": False,
            "max_workers": 1,
            "batch_sloc_threshold": 0,
            "prefilter": False,
            "validate": False,
            "joern_overrides": {"enabled": False},
        }
        defaults.update(kw)
        return OrchestratorConfig(**defaults)

    def test_minimal_run_writes_sidecar(self, tmp_path) -> None:
        from core.audit.orchestrator import run_orchestrator
        from core.llm.scorecard import ModelScorecard

        target, out = self._setup_target(tmp_path)
        result = run_orchestrator(self._config(target, out),
                                  self._review_fn)
        assert result.errors == 0
        events = result.scorecard_events
        assert any(
            e["event_type"] == "self_consistency"
            and e["outcome"] == "incorrect"
            and e["model"] == "test-model"
            for e in events
        ), f"no self_consistency event buffered: {events}"

        sidecar = Path(os.environ["RAPTOR_SCORECARD_PATH"])
        assert sidecar.exists(), "flush did not write the sidecar"
        stats = ModelScorecard(sidecar).get_stats()
        cell = next(s for s in stats if s.model == "test-model")
        assert cell.events["self_consistency"].incorrect >= 1

    def test_disabled_scorecard_suppresses_the_write(self, tmp_path) -> None:
        from core.audit.orchestrator import run_orchestrator

        target, out = self._setup_target(tmp_path)
        disabled_client = SimpleNamespace(
            scorecard=None,
            config=SimpleNamespace(scorecard_enabled=False),
        )
        result = run_orchestrator(
            self._config(target, out, llm_client=disabled_client),
            self._review_fn,
        )
        # Events still buffer (cheap, in-memory) …
        assert result.scorecard_events
        # … but the disabled client config suppresses the sidecar
        # write entirely — no default-path fallback.
        assert not Path(os.environ["RAPTOR_SCORECARD_PATH"]).exists()


class TestCrossFlushDedup:
    """The per-call dedup cannot see across calls; the caller-owned
    ``seen`` set must."""

    def test_seen_set_blocks_rewrite_of_shipped_cell(self) -> None:
        seen: set = set()
        store = _CapturingStore()
        events: list[dict] = []
        record_self_consistency_violation(
            events, _outcome(status="suspicious"), detail="flip",
        )
        assert flush_scorecard_events(events, scorecard=store, seen=seen) == 1
        # A later event for the SAME cell/function/direction buffers
        # after the first flush shipped — it must not land twice.
        later: list[dict] = []
        record_self_consistency_violation(
            later, _outcome(status="suspicious"), detail="another flip",
        )
        assert flush_scorecard_events(later, scorecard=store, seen=seen) == 0
        assert len(store.batches) == 1

    def test_failed_write_does_not_poison_the_seen_set(self) -> None:
        seen: set = set()
        events: list[dict] = []
        record_self_consistency_violation(
            events, _outcome(status="suspicious"), detail="flip",
        )
        assert flush_scorecard_events(
            events, scorecard=_RaisingStore(), seen=seen,
        ) == 0
        # The write failed, so the cell stays retryable.
        assert seen == set()
        store = _CapturingStore()
        assert flush_scorecard_events(events, scorecard=store, seen=seen) == 1


class TestIsReconcilable:
    def test_only_non_refuter_tool_evidence_is_reconcilable(self) -> None:
        from core.audit.scorecard_events import is_reconcilable

        events: list[dict] = []
        record_mechanical_refutation(events, _outcome(), gate="g", reason="r")
        record_self_consistency_violation(events, _outcome(), detail="d")
        buffer_event(
            events, model="m", cwe="", event_type="cross_family_consistency",
            grade="incorrect", key="src/a.c:parse",
        )
        buffer_event(
            events, model="m", cwe="", event_type="tool_evidence",
            grade="incorrect", key="src/a.c:parse", grades_refuter=True,
        )
        assert [is_reconcilable(ev) for ev in events] == [
            True, False, False, False,
        ]


class TestIncrementalFlushSeam:
    """The budget-poll incremental flush (orchestrator seam): settled
    event kinds ship mid-run so a hard-killed segment loses at most an
    interval's worth; reconcilable ``tool_evidence`` grades hold for
    the final flush's finding-set reconciliation; nothing ever lands
    in the sidecar twice."""

    @staticmethod
    def _rig(tmp_path):
        from core.audit.orchestrator import (
            OrchestratorConfig,
            OrchestratorResult,
        )

        store = _CapturingStore()
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path,
            llm_client=SimpleNamespace(scorecard=store),
        )
        return config, OrchestratorResult(), store

    @staticmethod
    def _written(store) -> list[tuple]:
        return [
            (e["model"], e["event_type"], e["outcome"])
            for batch in store.batches for e in batch
        ]

    def test_incremental_ships_only_never_reconciled_kinds(self, tmp_path):
        from core.audit.orchestrator import (
            _flush_scorecard_events_incremental,
        )

        config, result, store = self._rig(tmp_path)
        record_self_consistency_violation(
            result.scorecard_events, _outcome(model="m1"), detail="flip",
        )
        buffer_event(
            result.scorecard_events, model="m2", cwe="",
            event_type="cross_family_consistency", grade="incorrect",
            key="src/a.c:parse",
        )
        buffer_event(
            result.scorecard_events, model="m3", cwe="",
            event_type="tool_evidence", grade="incorrect",
            key="src/a.c:parse", grades_refuter=True,
        )
        # Reconcilable: must be HELD for the final flush.
        record_mechanical_refutation(
            result.scorecard_events, _outcome(model="m4"),
            gate="g", reason="r",
        )
        _flush_scorecard_events_incremental(config, result, force=True)
        written = self._written(store)
        assert ("m1", "self_consistency", "incorrect") in written
        assert ("m2", "cross_family_consistency", "incorrect") in written
        assert ("m3", "tool_evidence", "incorrect") in written
        assert not any(m == "m4" for m, _, _ in written)

    def test_long_loop_flushes_land_every_event_exactly_once(self, tmp_path):
        from core.audit.orchestrator import (
            ReviewOutcome,
            _flush_scorecard_events_incremental,
            _flush_scorecard_events_now,
        )

        config, result, store = self._rig(tmp_path)
        # Loop tick 1 buffers a consistency event, poll flushes it.
        record_self_consistency_violation(
            result.scorecard_events, _outcome(model="m1"), detail="flip",
        )
        _flush_scorecard_events_incremental(config, result, force=True)
        # Loop tick 2 buffers another consistency event AND a
        # reconcilable confirmation; poll flushes again.
        record_self_consistency_violation(
            result.scorecard_events,
            _outcome(model="m2", function="other"), detail="flip",
        )
        record_adversarial_outcome(
            result.scorecard_events, _outcome(model="m1"),
            producer_model="model-a", refuter_model="model-b",
            verdict="refuted", overturned_by="smt:check",
        )
        _flush_scorecard_events_incremental(config, result, force=True)
        # End of run: the function ends as a finding, so the held
        # producer confirmation ships at the final flush.
        result.outcomes.append(ReviewOutcome(
            file="src/a.c", function="parse", status="finding", body="b",
        ))
        _flush_scorecard_events_now(config, result, final=True)
        written = self._written(store)
        assert len(written) == len(set(written)) == 4
        assert ("model-a", "tool_evidence", "correct") in written

    def test_reconcilable_events_still_reconciled_at_final(self, tmp_path):
        from core.audit.orchestrator import (
            ReviewOutcome,
            _flush_scorecard_events_incremental,
            _flush_scorecard_events_now,
        )

        config, result, store = self._rig(tmp_path)
        # Mid-run mechanical refutation of a function that a later
        # pass RESCUES: the final reconciliation must drop the grade —
        # which is exactly why it may not ship incrementally.
        record_mechanical_refutation(
            result.scorecard_events, _outcome(model="m1"),
            gate="g", reason="r",
        )
        _flush_scorecard_events_incremental(config, result, force=True)
        assert self._written(store) == []
        result.outcomes.append(ReviewOutcome(
            file="src/a.c", function="parse", status="finding", body="b",
        ))
        _flush_scorecard_events_now(config, result, final=True)
        assert self._written(store) == []

    def test_throttle_interval_and_force_flag(self, tmp_path):
        from core.audit.orchestrator import (
            _flush_scorecard_events_incremental,
        )

        config, result, store = self._rig(tmp_path)
        record_self_consistency_violation(
            result.scorecard_events, _outcome(model="m1"), detail="flip",
        )
        # First poll of the run: interval elapsed vs the epoch mark.
        _flush_scorecard_events_incremental(config, result)
        assert len(self._written(store)) == 1
        record_self_consistency_violation(
            result.scorecard_events,
            _outcome(model="m2", function="other"), detail="flip",
        )
        # Immediate re-poll: throttled.
        _flush_scorecard_events_incremental(config, result)
        assert len(self._written(store)) == 1
        # Forced (SIGTERM arm): bypasses the interval.
        _flush_scorecard_events_incremental(config, result, force=True)
        assert len(self._written(store)) == 2

    def test_final_flush_never_reships_incremental_events(self, tmp_path):
        from core.audit.orchestrator import (
            _flush_scorecard_events_incremental,
            _flush_scorecard_events_now,
        )

        config, result, store = self._rig(tmp_path)
        record_self_consistency_violation(
            result.scorecard_events, _outcome(model="m1"), detail="flip",
        )
        _flush_scorecard_events_incremental(config, result, force=True)
        # A duplicate observation for the same cell buffers afterwards
        # (a second pass re-detecting the same contradiction).
        record_self_consistency_violation(
            result.scorecard_events, _outcome(model="m1"), detail="again",
        )
        _flush_scorecard_events_now(config, result, final=True)
        assert self._written(store) == [
            ("m1", "self_consistency", "incorrect"),
        ]

    def test_disabled_store_claims_no_events(self, tmp_path):
        """A disabled scorecard writes nothing — and must also CLAIM
        nothing: stranded _flushed marks with no rollback would break
        the claim/rollback invariant if enablement ever became
        per-flush-dynamic."""
        from core.audit.orchestrator import (
            _flush_scorecard_events_incremental,
        )

        config, result, _store = self._rig(tmp_path)
        config.llm_client = SimpleNamespace(
            scorecard=None,
            config=SimpleNamespace(scorecard_enabled=False),
        )
        record_self_consistency_violation(
            result.scorecard_events, _outcome(model="m1"), detail="flip",
        )
        _flush_scorecard_events_incremental(config, result, force=True)
        assert not any(
            ev.get("_flushed") for ev in result.scorecard_events
        )

    def test_failed_incremental_write_stays_retryable(self, tmp_path):
        from core.audit.orchestrator import (
            _flush_scorecard_events_incremental,
            _flush_scorecard_events_now,
        )

        config, result, _store = self._rig(tmp_path)
        raising = _RaisingStore()
        config.llm_client = SimpleNamespace(scorecard=raising)
        record_self_consistency_violation(
            result.scorecard_events, _outcome(model="m1"), detail="flip",
        )
        _flush_scorecard_events_incremental(config, result, force=True)
        # Sidecar came back before the end of the run.
        store = _CapturingStore()
        config.llm_client = SimpleNamespace(scorecard=store)
        _flush_scorecard_events_now(config, result, final=True)
        assert self._written(store) == [
            ("m1", "self_consistency", "incorrect"),
        ]
