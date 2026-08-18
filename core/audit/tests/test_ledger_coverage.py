"""Every audit call class must ride the budget-governed client and
land in the unified ledger.

Observed field failure (openssl comparison run): telemetry $29.18 vs
summary ledger $24.10 — 17.4% divergence, $4.18 true cap overshoot.
Two isolated causes: (a) the second call of two-call reviews
(clean-check / refinement continuations) was never phase-booked
($8.93 unbooked); (b) iris / spec_inference / study / synthesis /
summary classes built private ``LLMClient()`` instances whose spend
never reached the run ledger and whose dispatch bypassed the per-call
reservation gate (a post-loop iris call ran 11 minutes after budget
exhaustion).

No real LLM calls — everything stubbed.
"""

from __future__ import annotations

import time
import types
from pathlib import Path

from core.audit.cost_tracker import PhaseCostLedger
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    StudyQueue,
    StudyRequest,
    _LockedOutcomes,
    _reconcile_cost_ledgers,
    _run_llm_client,
    _study_consumer_loop,
)
from core.llm import telemetry as llm_telemetry


class _StubBudgetClient:
    """Budget-client stand-in with the surfaces the audit code reads."""

    def __init__(self, cap: float = 25.0):
        self.total_cost = 0.0
        self.max_cost = cap
        self._call_cost_history: dict[str, tuple[int, float]] = {}
        self.generate_calls: list[dict] = []

    def is_budget_exhausted(self, estimated_cost: float = 0.1) -> bool:
        return self.total_cost + estimated_cost > self.max_cost

    def _note(self, call_class: str, cost: float) -> None:
        n, total = self._call_cost_history.get(call_class, (0, 0.0))
        self._call_cost_history[call_class] = (n + 1, total + cost)
        self.total_cost += cost

    def generate(self, prompt, **kwargs):
        cls = kwargs.get("call_class", "unclassified")
        if self.is_budget_exhausted():
            from core.llm.client import LLMBudgetExceededError

            raise LLMBudgetExceededError("budget exceeded")
        self.generate_calls.append({"call_class": cls})
        self._note(cls, 0.1)
        return types.SimpleNamespace(text="{}", content="{}")

    def generate_structured(self, prompt, schema=None, **kwargs):
        return self.generate(prompt, **kwargs)


class TestRunLlmClient:
    def test_prefers_budget_client(self):
        stub = _StubBudgetClient()
        config = OrchestratorConfig(
            target_path=Path("."), out_dir=None, llm_budget_client=stub,
        )
        assert _run_llm_client(config) is stub


class TestSpecInferenceClient:
    def test_uses_provided_client(self):
        from core.audit.spec_inference import infer_spec_with_llm_sync

        stub = _StubBudgetClient()
        gap = {
            "name": "f", "file": "a.c",
            "source": "int f(int x) { return x + 1; }",
        }
        infer_spec_with_llm_sync(gap, client=stub)
        assert stub.generate_calls, (
            "spec inference must dispatch through the provided "
            "budget-governed client"
        )
        assert stub.generate_calls[0]["call_class"] == "spec_inference"

    def test_budget_exhausted_client_blocks_the_call(self):
        from core.audit.spec_inference import infer_spec_with_llm_sync

        stub = _StubBudgetClient(cap=0.0)   # nothing fits
        gap = {
            "name": "f", "file": "a.c",
            "source": "int f(int x) { return x + 1; }",
        }
        spec = infer_spec_with_llm_sync(gap, client=stub)
        # Refused at the gate: no completed call, mechanical fallback.
        assert stub.generate_calls == []
        assert spec is None or not any(
            s.signal == "llm_inference" for s in spec.sources
        )


class TestSynthesisClient:
    def test_build_llm_callable_prefers_budget_client(self):
        from core.audit.checker_synthesis import _build_llm_callable

        stub = _StubBudgetClient()
        config = types.SimpleNamespace(
            llm_budget_client=stub, models=["default"],
        )
        pair = _build_llm_callable(config)
        assert pair is not None
        _call, client = pair
        assert client is stub


class TestStudySpendDelta:
    def test_books_class_delta_not_whole_ledger(
        self, monkeypatch, tmp_path,
    ):
        import core.audit.orchestrator as _orch

        stub = _StubBudgetClient()
        # The shared client already carries review spend when the
        # study batch runs — booking client.total_cost into the study
        # phase would attribute the whole run to study.
        stub._note("review", 15.17)

        def fake_prep(cmd, **kwargs):
            (tmp_path / "study-list.json").write_text("[]")
            return types.SimpleNamespace(returncode=0, stderr="")

        monkeypatch.setattr(_orch, "_run_study_prep", fake_prep)

        import core.concepts.study as _study_mod

        def fake_run_study(study_list, out_dir, client):
            client._note("study", 0.5)

        monkeypatch.setattr(_study_mod, "run_study", fake_run_study)

        q = StudyQueue()
        for i in range(2):
            q.enqueue(StudyRequest(
                question=f"what is c{i}?",
                source_file="a.c",
                source_function=f"fn{i}",
            ))
        q.signal_producer_done()

        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path,
            llm_budget_client=stub,
        )
        result = OrchestratorResult()
        shared = types.SimpleNamespace(domain_model=None)
        _study_consumer_loop(
            q, config, shared, lambda ctx, cfg: None,
            _LockedOutcomes(), result,
            checklist={"files": []},
            context_map=None,
            evidence_index={},
            sarif_cache=None,
            entry_points=set(),
            start_time=time.monotonic(),
            on_progress=None,
        )

        study_phase = result.cost_tracker.phases.get("study")
        assert study_phase is not None, "study spend must be booked"
        assert abs(study_phase.cost_usd - 0.5) < 1e-9, (
            f"study phase must book the class delta (0.5), "
            f"not the whole client ledger "
            f"(booked {study_phase.cost_usd})"
        )
        assert abs(result.total_cost_usd - 0.5) < 1e-9


class TestTelemetryReplayReconciliation:
    """Replay the observed run's call shape through the telemetry sink
    and the (post-fix) booking discipline; the two ledgers must agree
    within 1% and the divergence warning must stay silent."""

    # The midpoint run's review telemetry: 6 first calls + 3
    # continuation calls (clean-check / refinement follow-ups).
    FIRST_CALLS = (0.818, 2.766, 1.84, 4.602, 2.048, 3.097)
    CONTINUATIONS = (2.421, 2.435, 4.074)
    SPEC_CALLS = (0.15,) * 28
    IRIS_CALLS = (0.83,)

    def _record(self, sink, call_class, cost):
        sink.record({
            "event": "call",
            "disposition": "ok",
            "call_class": call_class,
            "cost_usd": cost,
            "duration_s": 1.0,
        })

    def test_reconciles_within_one_percent(self, tmp_path, monkeypatch):
        sink = llm_telemetry.TelemetrySink(tmp_path / "telemetry.jsonl")
        monkeypatch.setattr(llm_telemetry, "_sink", sink, raising=False)
        llm_telemetry.set_sink(sink)
        try:
            client = _StubBudgetClient(cap=40.0)
            tracker = PhaseCostLedger()

            # All classes flow through the shared client now.
            for c in self.FIRST_CALLS:
                self._record(sink, "review", c)
                client._note("review", c)
                tracker.record_call("review", cost_usd=c)
            for c in self.CONTINUATIONS:
                self._record(sink, "review", c)
                client._note("review", c)
                # Post-fix: continuations are phase-booked.
                tracker.record_call("clean_check", cost_usd=c)
            for c in self.SPEC_CALLS:
                self._record(sink, "spec_inference", c)
                client._note("spec_inference", c)
            for c in self.IRIS_CALLS:
                self._record(sink, "iris", c)
                client._note("iris", c)

            result = OrchestratorResult()
            result.cost_tracker = tracker
            config = OrchestratorConfig(
                target_path=tmp_path, out_dir=tmp_path,
                llm_budget_client=client,
            )

            warnings = []
            import core.audit.orchestrator as _orch

            def _warn(msg, *args, **kwargs):
                warnings.append(str(msg) % args if args else str(msg))

            monkeypatch.setattr(_orch.logger, "warning", _warn)

            _reconcile_cost_ledgers(config, result)

            tel = sink.total_cost_usd()
            booked = result.cost_tracker.total_spend_usd
            divergence = abs(tel - booked) / max(tel, booked)
            assert divergence <= 0.01, (
                f"telemetry ${tel:.2f} vs booked ${booked:.2f} "
                f"({divergence:.1%} divergence)"
            )
            assert not any("divergence" in w for w in warnings), warnings
            # Attribution closes: unattributed residual is negligible.
            assert result.cost_tracker.unattributed_cost_usd < 0.05
        finally:
            llm_telemetry.set_sink(None)

    def test_prefix_shape_would_have_warned(self, tmp_path, monkeypatch):
        """The pre-fix shape (private clients, unbooked continuations)
        must still trip the reconciliation warning — the warning is the
        canary that catches any future class escaping the ledger."""
        sink = llm_telemetry.TelemetrySink(tmp_path / "telemetry.jsonl")
        llm_telemetry.set_sink(sink)
        try:
            client = _StubBudgetClient(cap=40.0)
            tracker = PhaseCostLedger()
            for c in self.FIRST_CALLS:
                self._record(sink, "review", c)
                client._note("review", c)
                tracker.record_call("review", cost_usd=c)
            for c in self.CONTINUATIONS:
                self._record(sink, "review", c)
                client._note("review", c)   # client saw them…
                # …but no phase booking (pre-fix behaviour).
            for c in self.SPEC_CALLS + self.IRIS_CALLS:
                # Private clients: telemetry sees the spend, the
                # budget client never does.
                self._record(sink, "spec_inference", c)

            result = OrchestratorResult()
            result.cost_tracker = tracker
            config = OrchestratorConfig(
                target_path=tmp_path, out_dir=tmp_path,
                llm_budget_client=client,
            )

            warnings = []
            import core.audit.orchestrator as _orch

            def _warn(msg, *args, **kwargs):
                warnings.append(str(msg) % args if args else str(msg))

            monkeypatch.setattr(_orch.logger, "warning", _warn)

            _reconcile_cost_ledgers(config, result)
            assert any("divergence" in w for w in warnings), (
                "reconciliation must keep warning on unbooked spend"
            )
        finally:
            llm_telemetry.set_sink(None)


class TestGateEnforcement:
    """A real LLMClient refuses any call class once the reservation
    would breach the cap — the property that bounds true overshoot to
    one call's estimate globally now that every class shares the
    client."""

    def test_all_classes_share_one_gate(self):
        import pytest

        from core.llm.client import LLMBudgetExceededError, LLMClient
        from core.llm.config import LLMConfig, ModelConfig
        from core.llm.providers import LLMResponse

        class _Provider:
            def generate(self, prompt, system_prompt=None, **kwargs):
                return LLMResponse(
                    content="ok", model="stub-model",
                    provider="anthropic", tokens_used=10,
                    cost=4.0, finish_reason="complete",
                )

        config = LLMConfig(
            primary_model=ModelConfig(
                provider="anthropic", model_name="stub-model",
                api_key="k",
            ),
            enable_caching=False,
            enable_fallback=False,
            enable_cost_tracking=True,
            max_cost_per_scan=4.5,
            max_retries=1,
        )
        client = LLMClient(config)
        client._get_provider = lambda model_config: _Provider()

        client.generate("p", call_class="review")
        assert client.total_cost == 4.0

        # Any other class hitting the same client is now gated by the
        # same ledger: $4 spent + the next call's reservation would
        # breach the cap → refused before dispatch.
        with pytest.raises(LLMBudgetExceededError):
            client.generate("p", call_class="spec_inference")
