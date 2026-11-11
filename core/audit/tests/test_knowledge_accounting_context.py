"""Pipeline-owned review and study identities reach actual client charges."""
from types import SimpleNamespace

import pytest

from core.audit.knowledge_calls import observed_client, owned_call_scope
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.orchestrator import OrchestratorConfig, ReviewOutcome, StudyQueue
from core.llm import telemetry
from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig
from core.llm.providers import LLMResponse, StructuredResponse
from core.testing.module_state import isolated_module_state


@pytest.fixture
def accounting(tmp_path, monkeypatch):
    client = LLMClient(LLMConfig(primary_model=ModelConfig(
        provider="anthropic", model_name="context-stub", api_key="inert"),
        enable_caching=False, enable_fallback=False, max_retries=1, max_cost_per_scan=5))
    provider = SimpleNamespace(total_cost=0.0, total_tokens=0, calls=0)
    def text(prompt, system_prompt=None, **kwargs):
        assert "accounting_work_id" not in kwargs and "accounting_beneficiaries" not in kwargs
        provider.calls += 1
        provider.total_cost += 0.25
        provider.total_tokens += 3
        return LLMResponse(content="captured", model="context-stub", provider="anthropic",
                           cost=0.25, tokens_used=3, finish_reason="complete")
    def structured(prompt, schema, system_prompt=None, **kwargs):
        response = text(prompt, system_prompt, **kwargs)
        return StructuredResponse(result={"subject_answers": []}, raw='{"subject_answers":[]}',
            model=response.model, provider=response.provider, cost=response.cost, tokens_used=3)
    provider.generate, provider.generate_structured = text, structured
    client.providers["scripted"] = provider
    monkeypatch.setattr(client, "_get_provider", lambda _: provider)
    sink = telemetry.TelemetrySink(tmp_path / "accounting.jsonl")
    with isolated_module_state(telemetry, {"_sink": sink}, lock=telemetry._sink_lock):
        yield client, provider, sink


def test_real_review_scope_forwards_pipeline_origin_before_dispatch(tmp_path, accounting):
    client, provider, sink = accounting
    source = "owned context line"
    (tmp_path / "unit.txt").write_text(source)
    runtime = AuditKnowledgeRuntime(tmp_path, StudyQueue(), deadline=float("inf"))
    def review(ctx, config):
        observed_client(client, purpose="review").generate("captured", call_class="review")
        return ReviewOutcome("unit.txt", "f", "clean", "captured", review_result={})
    review._knowledge_observed_client_contract = True
    try:
        runtime.wrap_review(review)({"file": "unit.txt", "function": "f", "line_start": 1,
                                    "source": source, "language": "text"},
                                   OrchestratorConfig(target_path=tmp_path, out_dir=None))
        event = next(e for e in runtime.events() if e["event"] == "review_attempt")
        row, = sink.attempt_projection()["attempts"]
        assert provider.calls == 1 and client.total_cost == pytest.approx(0.25)
        assert row["work_id"] == "review:" + event["origin"]["pass_id"]
        assert row["beneficiaries"] == [event["origin"]["pass_id"]]
        assert row["attempt_id"] != event["attempt_id"]
    finally:
        runtime.close()


def test_owned_metadata_survives_helper_thread_and_cannot_be_retargeted(accounting):
    from concurrent.futures import ThreadPoolExecutor
    from core.audit.knowledge_calls import KnowledgeCallRefused
    client, provider, sink = accounting
    beneficiaries = ["owned-unit"]
    admissions = []
    with owned_call_scope(lambda purpose, method: admissions.append((purpose, method)) or True,
                          work_id="owned-work", beneficiaries=beneficiaries):
        view = observed_client(client, purpose="review")
        beneficiaries.append("later-mutation")
        with ThreadPoolExecutor(max_workers=1) as pool:
            response = pool.submit(view.generate, "captured", call_class="review",
                accounting_work_id="forged", accounting_beneficiaries=("forged",)).result(timeout=10)
        assert response.content == "captured"
    with pytest.raises(KnowledgeCallRefused, match="scope_closed"):
        view.generate("captured")
    row, = sink.attempt_projection()["attempts"]
    assert provider.calls == 1 and admissions == [("review", "generate")]
    assert row["work_id"] == "owned-work" and row["beneficiaries"] == ["owned-unit"]


def test_unknown_custom_client_keeps_its_existing_signature():
    class Custom:
        def generate(self, prompt):
            return prompt
    with owned_call_scope(lambda *args: True, work_id="owned-work", beneficiaries=("unit",)):
        assert observed_client(Custom()).generate("captured") == "captured"


def test_scope_refusal_still_prevents_real_dispatch(accounting):
    from core.audit.knowledge_calls import KnowledgeCallRefused
    client, provider, sink = accounting
    with owned_call_scope(lambda *args: False, work_id="owned-work", beneficiaries=("unit",)):
        with pytest.raises(KnowledgeCallRefused, match="unit_admission"):
            observed_client(client).generate("captured")
    assert provider.calls == 0 and client.total_cost == 0
    assert sink.attempt_projection()["attempts"] == []


def test_accounting_context_does_not_split_transcript_replay_identity(tmp_path, accounting):
    from core.llm.transcript import TranscriptLLMClient, TranscriptRecorder, TranscriptReplayer
    client, provider, _ = accounting
    path = tmp_path / "captured-transcript.jsonl"
    captured = LLMResponse(content="captured", model="context-stub", provider="anthropic",
                          cost=0.25, tokens_used=3, finish_reason="complete")
    TranscriptRecorder(path).record_generate("captured", None, None, {"call_class": "review"}, captured)
    replay = TranscriptLLMClient(client.config, session=TranscriptReplayer(path))
    with owned_call_scope(lambda *args: True, work_id="new-owned-work", beneficiaries=("unit",)):
        result = observed_client(replay).generate("captured", call_class="review")
    assert result.content == "captured" and replay.total_cost == 0
    assert provider.calls == 0


def test_shared_study_packet_references_actual_request_beneficiaries(tmp_path, monkeypatch, accounting):
    from core.audit import knowledge_study
    from core.audit.knowledge_requests import KnowledgeOrigin
    from core.audit.orchestrator import OrchestratorResult
    from core.audit.refutation_source import capture_source_identity
    from core.concepts import study
    from core.concepts.model import StudyItem
    client, provider, sink = accounting
    source = "owned declaration"
    (tmp_path / "unit.txt").write_text(source)
    runtime = AuditKnowledgeRuntime(tmp_path, StudyQueue(), deadline=float("inf"))
    config = OrchestratorConfig(target_path=tmp_path, out_dir=None, llm_budget_client=client)
    result = OrchestratorResult()
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
        packets = []
        def dispatch(items, root, study_client, *, subjects, **kwargs):
            packet = subjects.prepare(items, [])
            packets.append(packet)
            assert len(packet.subjects) == 2 and packet.materials
            schema = {"type": "object", "properties": {"subject_answers": {"type": "array"}},
                      "required": ["subject_answers"], "additionalProperties": False}
            with subjects.dispatching(packet):
                study_client.generate_structured("captured", schema, call_class="study")
        monkeypatch.setattr(study, "run_phase2", dispatch)
        knowledge_study.study_batch(requests, runtime, config, result, checklist={}, should_stop=lambda: False)
        assert provider.calls == 1 and len(packets) == 1
        row, = sink.attempt_projection()["attempts"]
        assert row["work_id"].startswith("study:")
        assert set(row["beneficiaries"]) == {r.origin.pass_id for r in requests}
        assert client.total_cost == result.total_cost_usd == pytest.approx(0.25)
    finally:
        runtime.close()
