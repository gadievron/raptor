"""Unexecuted owned subject-context ACK controls; no SDK or binary backend."""
from functools import wraps
import hashlib
import json
from time import monotonic

import pytest

from core.audit import collector as collector_module, orchestrator as orch
from core.audit.binary_review_scope import capture_binary_input_identity
from core.audit.binary_subjects import BinarySubjectContext
from core.audit.collector import Collector
from core.audit.journal import load_entries
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.tests.test_binary_subjects import subject_case as subject_case
from core.audit.tests.test_binary_abi_prompt import binary_abi_case as binary_abi_case
from core.audit.tests.test_study_claim_retention import _owned_review_caches as _owned_review_caches
from core.json import dumps_canonical
from core.inventory import save_checklist
from core.inventory.binary_builder import build_binary_checklist
from core.llm.providers import StructuredResponse
from core.testing.audit_shutdown import isolated_audit_shutdown


@pytest.mark.parametrize("change", ["unchanged", "initial_type_after_ack"])
def test_binary_subject_actual_ack_rechecks_original_payload(subject_case, tmp_path, monkeypatch, change):
    build, target, database = subject_case
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    install = tmp_path / "owned-install"
    install.mkdir()
    monkeypatch.setenv("RAPTOR_DIR", str(install))
    initial, config = build(None)
    assert initial["type_definitions"] == []
    config.immediate_verify = False
    config.sweep_validate_findings = False
    config.enable_session_context = False
    checklist = build_binary_checklist(database, binary_path=target)
    save_checklist(config.out_dir, checklist)
    entry, = checklist["files"]
    item, = entry["items"]
    module_before = target.read_bytes()
    database_before = dumps_canonical(database.to_dict())
    prompts, contexts, outcomes = [], [], []

    class Client:
        _attempt_admission_protocol = 1

        def generate_structured(self, prompt, schema, **kwargs):
            assert kwargs.pop("accounting_attempt_admission")() is True
            prompts.append(prompt)
            payload = {
                "status": "clean" if len(prompts) == 1 else "suspicious",
                "body": "Initial independent assessment" if len(prompts) == 1 else "Recovered layout remains provisional",
                "reading_list": [{"subject": "Packet", "context": "field layout", "resolution": "identifier"}],
            }
            return StructuredResponse(result=payload, raw="", cost=.1, model="captured")

    review = make_review_fn(Client(), schema={"type": "object"}, escalate_clean=False, out_dir=config.out_dir)

    @wraps(review)
    def observed_review(ctx, cfg):
        contexts.append(ctx)
        outcome = review(ctx, cfg)
        outcomes.append(outcome)
        return outcome

    runtime = AuditKnowledgeRuntime(target, orch.StudyQueue(), deadline=float("inf"), window=0)
    acknowledgements, post_ack = [], []
    try:
        prior = runtime.wrap_review(observed_review)(initial, config)
        assert prior.status == "clean" and len(prompts) == 1
        origin = runtime._origin(initial)
        assert origin is not None
        gap = {**item, "file": entry["path"], "line_start": 0, "line_end": None}
        assert Collector(out_dir=config.out_dir, target_path=target, run_id=config.out_dir.name).submit(prior, gap)
        result = orch.OrchestratorResult(outcomes=[prior], reviewed=1, clean=1, total_cost_usd=prior.cost_usd)
        result.cost_tracker.record_call("review", cost_usd=prior.cost_usd, wall_time_s=prior.duration_s)
        reservation, = runtime.ready_continuations(admission=lambda: True)
        assert reservation.packet.external_context_ids

        def fresh_context(*args, **kwargs):
            fresh, _ = build(None)
            assert fresh["type_definitions"] == []
            return fresh

        monkeypatch.setattr(orch, "_build_context", fresh_context)
        original_append = collector_module.append_journal_for_outcome

        def append_then_observe(**kwargs):
            assert len(contexts) == len(outcomes) == len(prompts) == 2
            assert kwargs["outcome"] is outcomes[-1]
            assert result.outcomes[0] is prior
            fresh = contexts[-1]
            payload = fresh["binary_subject_context"]
            assert isinstance(payload, BinarySubjectContext) and payload.current(fresh)
            scope = outcomes[-1].binary_publication_scope
            assert scope is not None and scope.current(target)
            identity = capture_binary_input_identity(fresh, scope)
            acknowledgement = original_append(**kwargs)
            assert acknowledgement is not None
            acknowledgements.append(acknowledgement)
            assert result.outcomes[0] is prior
            if change == "initial_type_after_ack":
                fresh["type_definitions"].append({"name": "Packet", "kind": "struct"})
            post_ack.append({
                "subject_current": payload.current(fresh),
                "publication_scope_current": scope.current(target),
                "input_identity_unchanged": capture_binary_input_identity(fresh, scope) == identity,
                "runtime_publishable": runtime.can_publish(reservation),
            })
            return acknowledgement

        monkeypatch.setattr(collector_module, "append_journal_for_outcome", append_then_observe)
        with isolated_audit_shutdown(orch):
            orch._re_review_study_enriched(
                result, config, observed_review, {}, None, {}, None, set(),
                {(prior.file, prior.function, prior.line)}, monotonic(), None,
                max_workers=1, knowledge_runtime=runtime, knowledge_reservation=reservation,
            )
        assert len(prompts) == sum(runtime._calls.values()) == 2
        assert len(acknowledgements) == len(post_ack) == 1
        assert target.read_bytes() == module_before
        assert dumps_canonical(database.to_dict()) == database_before
        assert post_ack[0]["publication_scope_current"] is True
        assert post_ack[0]["input_identity_unchanged"] is True
        rows = load_entries(config.out_dir, fresh=True)
        assert len(rows) == 2
        completed = [event for event in runtime.events() if event["event"] == "continuation_completed"]
        observation = {"change": change, "post_ack": post_ack,
                       "canonical_is_prior": result.outcomes[0] is prior,
                       "canonical_status": result.outcomes[0].status,
                       "completed_count": len(completed), "charged_calls": sum(runtime._calls.values()),
                       "module_sha256": hashlib.sha256(module_before).hexdigest()}
        (tmp_path / "subject-post-ack-observation.json").write_text(json.dumps(observation, indent=2))
        if change == "initial_type_after_ack":
            assert post_ack[0]["subject_current"] is False
            assert result.outcomes[0] is prior, "invalid original subject payload was accepted after its actual journal ACK"
            assert not completed
        else:
            assert post_ack[0]["subject_current"] is True
            assert result.outcomes[0] is outcomes[-1] and result.outcomes[0].status == "suspicious"
            assert len(completed) == 1
        assert result.total_cost_usd == pytest.approx(.2)
    finally:
        runtime.close("test_complete")
