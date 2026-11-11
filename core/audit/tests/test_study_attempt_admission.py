"""Shared source packets retain admission and provenance across real retries."""
from contextlib import nullcontext
from hashlib import sha256
import json
from types import SimpleNamespace

import pytest

from core.audit import knowledge_study
from core.audit.knowledge_calls import observed_client, owned_call_scope, KnowledgeCallRefused
from core.audit.knowledge_requests import KnowledgeOrigin
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.orchestrator import OrchestratorConfig, OrchestratorResult, StudyQueue, _reconcile_cost_ledgers
from core.audit.refutation_source import capture_source_identity
from core.concepts import study
from core.concepts.model import StudyItem
from core.concepts.subject_study import SubjectDispatchRefused
from core.llm import telemetry
from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig
from core.llm.providers import StructuredResponse, _attach_billed_usage
from core.testing.module_bindings import patch_module_attribute
from core.testing.module_state import isolated_module_state


@pytest.mark.parametrize("failed", [True, False], ids=["paid-retry", "foreign-scope"])
def test_shared_packet_owns_each_attempt(tmp_path, monkeypatch, failed):
    import core.llm.client as consumer
    patch_module_attribute(monkeypatch, consumer, "time", "sleep", lambda _: None)
    primary = ModelConfig(provider="anthropic", model_name="study-primary-stub", api_key="inert")
    fallback = ModelConfig(provider="anthropic", model_name="study-fallback-stub", api_key="inert")
    client = LLMClient(LLMConfig(primary_model=primary, fallback_models=[fallback],
        enable_caching=False, enable_fallback=True, max_retries=3,
        max_calls_per_scan=20, max_cost_per_scan=10))
    provider = SimpleNamespace(total_cost=0.0, total_tokens=0, calls=0)
    def structured(*args, **kwargs):
        assert not any(key.startswith("accounting_") for key in kwargs)
        provider.calls += 1
        provider.total_cost += 0.1
        provider.total_tokens += 3
        if failed:
            error = ConnectionError("captured paid transport failure")
            _attach_billed_usage(error, cost_usd=0.1, tokens_in=2, tokens_out=1)
            raise error
        return StructuredResponse(result={"subject_answers": []}, raw='{"subject_answers":[]}',
            model="study-primary-stub", provider="anthropic", cost=0.1, tokens_used=3)
    provider.generate_structured = structured
    client.providers["scripted"] = provider
    monkeypatch.setattr(client, "_get_provider", lambda _: provider)
    source = "owned declaration"
    (tmp_path / "unit.txt").write_text(source)
    runtime = AuditKnowledgeRuntime(tmp_path, StudyQueue(), deadline=float("inf"), max_model_calls=1)
    result = OrchestratorResult()
    config = OrchestratorConfig(target_path=tmp_path, out_dir=None, llm_budget_client=client)
    sink = telemetry.TelemetrySink(tmp_path / "attempts.jsonl")
    refused, packets = [], []
    try:
        identity = capture_source_identity(tmp_path, "unit.txt")
        for function in ("first", "second"):
            origin = KnowledgeOrigin("pass-" + function, "unit.txt", function, 1, 1, identity)
            runtime._register(origin, {"file": "unit.txt", "function": function, "line_start": 1,
                "source": source}, {"reading_list": [{"subject": "Packet", "context": "type role",
                    "resolution": "identifier"}]})
        requests = tuple(runtime._requests.values())
        assert len(requests) == 2
        item = StudyItem("owned-item", "type", "Packet", "unit.txt", line=1, definition=source)
        plan = knowledge_study._SourcePlan([item],
            {r.request_id: frozenset({item.id}) for r in requests},
            {item.id: "target"}, {}, {}, {item.id: identity})
        monkeypatch.setattr(knowledge_study, "_prepare", lambda *args: plan)
        def dispatch(items, root, study_client, *, subjects, **kwargs):
            packet = subjects.prepare(items, [])
            packets.append(packet)
            assert len(packet.subjects) == 2 and packet.materials
            with subjects.dispatching(packet):
                try:
                    study_client.generate_structured("captured", {"type": "object"}, call_class="study")
                except SubjectDispatchRefused as error:
                    refused.append(str(error))
        monkeypatch.setattr(study, "run_phase2", dispatch)
        scope = nullcontext() if failed else owned_call_scope(
            lambda *args: False, work_id="foreign-unit", beneficiaries=("foreign-unit",))
        with isolated_module_state(telemetry, {"_sink": sink}, lock=telemetry._sink_lock), scope:
            knowledge_study.study_batch(requests, runtime, config, result,
                checklist={}, should_stop=lambda: False)
            if not failed:
                with pytest.raises(KnowledgeCallRefused):
                    observed_client(client).generate("denied")
            _reconcile_cost_ledgers(config, result)
        assert provider.calls == 1 and len(packets) == 1
        row, = sink.attempt_projection()["attempts"]
        packet_key = json.dumps(sorted({r.request_id for r in requests}), separators=(",", ":"))
        assert row["work_id"] == "study:" + sha256(packet_key.encode()).hexdigest()
        assert set(row["beneficiaries"]) == {r.origin.pass_id for r in requests}
        assert row["cost_usd"] == pytest.approx(0.1)
        assert client.provider_spend_usd == pytest.approx(0.1)
        assert result.llm_spend_usd == result.cost_tracker.total_spend_usd == pytest.approx(0.1)
        projected = result.cost_tracker.to_dict()["attempt_accounting"]
        assert projected["status"] == "projected"
        charged, = projected["attempts"]
        assert charged["attempt_id"] == row["attempt_id"]
        assert set(charged["beneficiaries"]) == {r.origin.pass_id for r in requests}
        if not failed:
            assert client.total_cost == pytest.approx(0.1)
            assert result.total_cost_usd == pytest.approx(0.1)
        assert len([e for e in runtime.events() if e["event"] == "study_attempt"]) == 1
        if failed:
            assert result.cost_tracker.total_failed_attempts_cost_usd == pytest.approx(0.1)
            assert refused and "source_study_admission_refused" in refused[0]
            assert any(e["event"] == "study_dispatch_refused" and e["reason"] == "model_call_limit"
                       for e in runtime.events())
        else:
            assert refused == []
    finally:
        runtime.close()
