"""Opaque source-study adapters disclose incomplete beneficiary counts.

No live provider, SDK transport, compiler, solver or target campaign is used.
The real LLMClient calls an owned inert provider three times behind an opaque
adapter. Source admission, SubjectPacket binding and beneficiary routing are real.
"""
from hashlib import sha256
import json
from types import SimpleNamespace

import pytest

from core.audit import knowledge_study
from core.audit.knowledge_requests import KnowledgeOrigin
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.orchestrator import OrchestratorConfig, OrchestratorResult, StudyQueue
from core.audit.refutation_source import capture_source_identity
from core.concepts import study
from core.concepts.model import StudyItem
from core.llm import telemetry
from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig
from core.llm.providers import StructuredResponse
from core.testing.module_state import isolated_module_state


def test_opaque_shared_study_marks_each_beneficiary_count_unknown(tmp_path, monkeypatch):
    primary = ModelConfig(provider="anthropic", model_name="study-primary-stub", api_key="inert")
    client = LLMClient(LLMConfig(primary_model=primary, fallback_models=[],
        enable_caching=False, enable_fallback=False, max_retries=1,
        max_calls_per_scan=20, max_cost_per_scan=10))
    provider = SimpleNamespace(total_cost=0.0, total_tokens=0, calls=0)
    def structured(*args, **kwargs):
        assert not any(key.startswith("accounting_") for key in kwargs)
        provider.calls += 1
        provider.total_cost += 0.1
        provider.total_tokens += 3
        return StructuredResponse(result={"subject_answers": []}, raw='{"subject_answers":[]}',
            model="study-primary-stub", provider="anthropic", cost=0.1, tokens_used=3)
    provider.generate_structured = structured
    client.providers["scripted"] = provider
    monkeypatch.setattr(client, "_get_provider", lambda _: provider)

    class OpaqueClient:
        _attempt_admission_protocol = None
        def __getattr__(self, name):
            return getattr(client, name)
        def generate_structured(self, *args, **kwargs):
            for _ in range(3):
                response = client.generate_structured(*args, **kwargs)
            return response

    source = "owned declaration"
    (tmp_path / "unit.txt").write_text(source)
    runtime = AuditKnowledgeRuntime(tmp_path, StudyQueue(), deadline=float("inf"))
    result = OrchestratorResult()
    config = OrchestratorConfig(target_path=tmp_path, out_dir=None, llm_budget_client=OpaqueClient())
    sink = telemetry.TelemetrySink(tmp_path / "attempts.jsonl")
    packets = []
    try:
        identity = capture_source_identity(tmp_path, "unit.txt")
        assert identity is not None
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
                study_client.generate_structured("captured", {"type": "object"}, call_class="study")
        monkeypatch.setattr(study, "run_phase2", dispatch)
        with isolated_module_state(telemetry, {"_sink": sink}, lock=telemetry._sink_lock):
            knowledge_study.study_batch(requests, runtime, config, result,
                checklist={}, should_stop=lambda: False)
        assert provider.calls == client._governed_calls == 3 and len(packets) == 1
        rows = sink.attempt_projection()["attempts"]
        assert len(rows) == len({row["attempt_id"] for row in rows}) == 3
        packet_key = json.dumps(sorted({r.request_id for r in requests}), separators=(",", ":"))
        expected_work = "study:" + sha256(packet_key.encode()).hexdigest()
        for row in rows:
            assert row["work_id"] == expected_work
            assert set(row["beneficiaries"]) == {r.origin.pass_id for r in requests}
            assert row["cost_usd"] == pytest.approx(0.1)
        assert client.provider_spend_usd == pytest.approx(0.3)
        assert result.total_cost_usd == pytest.approx(0.3)
        keys = {("unit.txt", function, 1) for function in ("first", "second")}
        assert runtime._calls == {key: 1 for key in keys}
        assert len([e for e in runtime.events() if e["event"] == "study_attempt"]) == 1
        assert runtime._unknown_calls == keys, "opaque study attempts remained complete-looking"
        runtime.write_artifacts(tmp_path / "out")
        exported = json.loads((tmp_path / "out" / "knowledge-results.json").read_text())
        assert len(exported["units"]) == 2
        assert all(unit["all_model_calls"] is None and unit["owned_dispatch_attempts"] == 1
                   for unit in exported["units"])
        assert runtime.admit_source_attempt(requests) is False
        assert runtime.events()[-1]["event"] == "study_dispatch_refused"
        assert runtime.events()[-1]["reason"] == "model_call_count_unavailable"
    finally:
        runtime.close("test_complete")
