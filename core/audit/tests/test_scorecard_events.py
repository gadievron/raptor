"""Tests for the audit scorecard producer (``core.audit.scorecard_events``).

Pin the emission contract the orchestrator wiring depends on:

* events carry the audit decision-class convention and the
  correct/incorrect grades of each adjudication shape;
* attribution rules (self-consistency handle suffix stripped, lone
  configured model as fallback, ``"default"`` placeholder never
  attributes, no attribution → no event);
* flush reconciliation (rescued findings drop their buffered
  refutations, refuter grades survive, dedup);
* fail-soft everywhere — a raising store or a broken outcome object
  must never propagate out of the emission path.

No LLM calls, no network; the one real-sidecar test writes under a
tmp path (MAC keys are isolated by the directory conftest).
"""

from __future__ import annotations

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
    def test_cross_model_refuted_grades_judge_review(self) -> None:
        events: list[dict] = []
        n = record_adversarial_outcome(
            events, _outcome(), producer_model="model-a",
            refuter_model="model-b", verdict="refuted",
            defeating_mechanism="the loop bound is clamped upstream",
        )
        assert n == 1
        ev = events[0]
        assert ev["event_type"] == "judge_review"
        assert ev["outcome"] == "incorrect"
        assert ev["model"] == "model-a"
        assert "model-b" in ev["sample"]["other_reasoning"]

    def test_cross_model_stands_grades_upheld(self) -> None:
        events: list[dict] = []
        record_adversarial_outcome(
            events, _outcome(), producer_model="model-a",
            refuter_model="model-b", verdict="stands",
        )
        assert events[0]["event_type"] == "judge_review"
        assert events[0]["outcome"] == "correct"

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

    def test_overturned_grades_both_sides(self) -> None:
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
    def test_receipt_backed_findings_grade_correct(self) -> None:
        events: list[dict] = []
        outcomes = [
            _outcome(evidence_tool="semgrep:rule-1"),
            # llm-claimed stamp is not a receipt — no grade.
            _outcome(function="g", evidence_tool="llm-claimed:semgrep"),
            # No hypothesis — nothing was confirmed.
            _outcome(function="h", evidence_tool="semgrep:rule-1",
                     hypothesis=""),
            # Non-finding statuses carry no confirmed grade.
            _outcome(function="i", status="suspicious",
                     evidence_tool="semgrep:rule-1"),
        ]
        assert buffer_confirmed_findings(events, outcomes) == 1
        assert events[0]["event_type"] == "tool_evidence"
        assert events[0]["outcome"] == "correct"
        assert events[0]["_key"] == "src/a.c:parse"


# ---------------------------------------------------------------------------
# Flush: reconciliation, dedup, fail-soft
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

    def test_dedup_one_miss_per_cell_per_function(self) -> None:
        events: list[dict] = []
        record_mechanical_refutation(events, _outcome(status="suspicious"),
                                     gate="g1", reason="r1")
        record_mechanical_refutation(events, _outcome(status="suspicious"),
                                     gate="g2", reason="r2")
        store = _CapturingStore()
        assert flush_scorecard_events(events, scorecard=store) == 1

    def test_raising_store_is_contained(self) -> None:
        events: list[dict] = []
        record_mechanical_refutation(events, _outcome(), gate="g", reason="r")
        # Must not raise, must report zero written.
        assert flush_scorecard_events(events, scorecard=_RaisingStore()) == 0

    def test_empty_and_malformed_buffers_are_noops(self) -> None:
        assert flush_scorecard_events([], scorecard=_RaisingStore()) == 0
        # Malformed entries must not raise: the non-dict is skipped,
        # the shapeless dict passes through to the (fake) store.
        assert flush_scorecard_events(
            [{"nonsense": True}, "not-a-dict"],  # type: ignore[list-item]
            scorecard=_CapturingStore(),
        ) == 1

    def test_real_sidecar_roundtrip(self, tmp_path) -> None:
        """End-to-end through the real public API: events land in the
        sidecar under the audit decision class."""
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
        assert cell.events["judge_review"].correct == 1

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
            [], [_outcome(evidence_tool="semgrep:rule-1")],
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
