"""Actual review packets share ownership across study, references and late context."""

from contextlib import contextmanager
from time import monotonic
from types import SimpleNamespace

import pytest

from core.audit import llm_review, orchestrator as orch
from core.audit.continuation_context import context_version
from core.audit.knowledge_calls import KnowledgeCallRefused, observed_client
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.tests.test_knowledge_runtime import _consume_source_case
from core.llm.providers import StructuredResponse


class ScriptedClient:
    _call_cost_history = None

    def __init__(self, initial_status="suspicious"):
        self.initial_status = initial_status
        self.initial_outcome = None
        self.calls = []
        self.request_ids = []
        self.after_review = lambda prompt: None
        self.forged_id = "model-cannot-claim-delivery"

    def is_budget_exhausted(self):
        return False

    def generate_structured(self, prompt, schema, **kwargs):
        task = kwargs["task_type"]
        self.calls.append((task, prompt))
        if task == "study":
            assert schema["required"] == ["subject_answers"]
            assert "typedef struct" in prompt and "return item.length" in prompt
            return {
                "subject_answers": [
                    {
                        "request_id": self.request_ids[0],
                        "status": "partial",
                        "explanation": "The target type carries length; ownership is not established.",
                        "reason": "Other users are not supplied",
                        "material_ids": ["material-0"],
                    }
                ]
            }
        assert task == "audit"
        self.after_review(prompt)
        initial = sum(kind == "audit" for kind, _ in self.calls) == 1
        return StructuredResponse(
            result={
                "status": self.initial_status if initial else "suspicious",
                "body": "Scripted provisional assessment",
                "reading_list": [
                    {
                        "subject": "foo_t",
                        "resolution": "identifier",
                        "context": "role of the target type",
                    }
                ]
                if initial
                else [],
                "language_reference_requests": [
                    {
                        "topic": "integer arithmetic definedness",
                        "entry_id": "c.integer-definedness",
                    }
                ]
                if initial
                else [],
                "external_context_delivery": [
                    {"context_id": self.forged_id, "delivered": True}
                ],
            },
            raw="",
            cost=0,
            model="scripted",
        )


@contextmanager
def mixed_case(tmp_path, monkeypatch, *, initial_status="suspicious"):
    (tmp_path / "types.h").write_text("typedef struct { unsigned length; } foo_t;\n")
    source = '#include "types.h"\nunsigned f(foo_t item) { return item.length; }\n'
    (tmp_path / "owned.c").write_text(source)
    out = tmp_path / "out"
    out.mkdir()
    config = orch.OrchestratorConfig(
        target_path=tmp_path, out_dir=out, enable_session_context=False
    )
    queue = orch.StudyQueue()
    runtime = AuditKnowledgeRuntime(tmp_path, queue, deadline=float("inf"), window=0)
    client = ScriptedClient(initial_status)
    config.llm_budget_client = client
    monkeypatch.setattr(llm_review, "_prompt_budget", lambda *args: 0)
    review = runtime.wrap_review(make_review_fn(client, escalate_clean=False))
    ctx = {
        "file": "owned.c",
        "function": "f",
        "line_start": 2,
        "line_end": 2,
        "source": source.splitlines()[1],
        "language": "c",
    }
    try:
        client.initial_outcome = review(dict(ctx), config)
        requests = queue.dequeue_batch(timeout=0)
        assert len(requests) == 1
        client.request_ids.extend(request.request_id for request in requests)
        _consume_source_case(
            (orch, config, queue, runtime, review, requests, client.calls, client)
        )
        assert [kind for kind, _ in client.calls] == ["audit", "study"]
        yield runtime, client, review, config, ctx
    finally:
        runtime.close("owned_integration_finished")


def offer(runtime, ctx, evidence):
    ctx = {**ctx, "mechanical_evidence": evidence}
    version = context_version(evidence)
    assert runtime.offer_context_delta(ctx, kind="late_joern", version=version)
    return ctx, "context:late_joern:" + version


def reserve(runtime, ctx, context_id):
    return runtime.reserve_context_continuation(
        ctx,
        admission=lambda: True,
        required_context_id=context_id,
    )


def assert_prompt_receipt(runtime, packet, outcome, evidence, prompt):
    assert evidence in prompt
    rows = outcome.review_result["external_context_delivery"]
    assert len(rows) == 1 and rows[0]["delivered"] is True
    assert rows[0]["context_id"] in packet.packet.external_context_ids
    assert runtime.context_was_delivered(packet)
    assert rows[0]["reason"] == "complete_prompt_section"


def test_mixed_information_coalesces_and_inflight_arrival_waits(tmp_path, monkeypatch):
    with mixed_case(tmp_path, monkeypatch) as (runtime, client, review, config, base):
        first_ctx, first_id = offer(runtime, base, "Owned late evidence version one")
        first = reserve(runtime, first_ctx, first_id)
        assert first is not None
        assert first.packet.references and first.packet.explanations
        assert first.packet.external_context_ids == (first_id,)
        assert runtime.enrich_context(first_ctx, first)
        late = []

        def arrival(prompt):
            assert "The target type carries length" in prompt
            assert "ownership is not established" in prompt
            assert "c.integer-definedness v1:" in prompt
            next_ctx, next_id = offer(runtime, base, "Owned late evidence version two")
            late.append((next_ctx, next_id))
            assert reserve(runtime, next_ctx, next_id) is None
            assert runtime.ready_continuations(admission=lambda: True) == ()

        client.after_review = arrival
        first_outcome = review(first_ctx, config)
        first_prompt = client.calls[-1][1]
        assert_prompt_receipt(
            runtime,
            first,
            first_outcome,
            first_ctx["mechanical_evidence"],
            first_prompt,
        )
        assert "Owned late evidence version two" not in first_prompt
        assert runtime.complete(first, first_ctx)
        completed = [
            e for e in runtime.events() if e["event"] == "continuation_completed"
        ][-1]
        expected = {
            a.request_id for a in (*first.packet.references, *first.packet.explanations)
        } | {first_id}
        assert set(completed["delivered_request_ids"]) == expected
        assert late[0][1] not in completed["delivered_request_ids"]

        client.after_review = lambda prompt: None
        second_ctx, second_id = late[0]
        second = reserve(runtime, second_ctx, second_id)
        assert second is not None and second.packet.external_context_ids == (second_id,)
        assert runtime.enrich_context(second_ctx, second)
        second_outcome = review(second_ctx, config)
        assert_prompt_receipt(
            runtime,
            second,
            second_outcome,
            second_ctx["mechanical_evidence"],
            client.calls[-1][1],
        )
        assert runtime.complete(second, second_ctx)
        assert not runtime.offer_context_delta(
            second_ctx,
            kind="late_joern",
            version=context_version(second_ctx["mechanical_evidence"]),
        )
        third_ctx, third_id = offer(runtime, base, "Owned late evidence version three")
        assert reserve(runtime, third_ctx, third_id) is None
        assert runtime.ready_continuations(admission=lambda: True) == ()
        assert [kind for kind, _ in client.calls] == [
            "audit",
            "study",
            "audit",
            "audit",
        ]
        assert (
            len([e for e in runtime.events() if e["event"] == "continuation_reserved"])
            == 2
        )


def test_mixed_unit_six_call_cap_counts_actual_auxiliary_dispatches(
    tmp_path, monkeypatch
):
    with mixed_case(tmp_path, monkeypatch) as (runtime, client, review, config, base):
        ctx, context_id = offer(runtime, base, "Owned mixed call-cap evidence")
        packet = reserve(runtime, ctx, context_id)
        assert (
            packet is not None
            and packet.packet.explanations
            and packet.packet.references
        )
        assert runtime.enrich_context(ctx, packet)
        auxiliary = []

        class Auxiliary:
            def generate(self, prompt):
                auxiliary.append(prompt)
                return "owned auxiliary response"

        def consume_allowance(prompt):
            observed = observed_client(Auxiliary(), purpose="owned-auxiliary")
            for index in range(3):
                assert observed.generate(str(index)) == "owned auxiliary response"
            with pytest.raises(KnowledgeCallRefused):
                observed.generate("over-cap")

        client.after_review = consume_allowance
        outcome = review(ctx, config)
        assert_prompt_receipt(
            runtime, packet, outcome, ctx["mechanical_evidence"], client.calls[-1][1]
        )
        assert auxiliary == ["0", "1", "2"]
        assert runtime.complete(packet, ctx)
        next_ctx, next_id = offer(
            runtime, base, "Owned changed evidence after exhausted calls"
        )
        assert reserve(runtime, next_ctx, next_id) is None
        calls = [e for e in runtime.events() if e["event"] == "client_call_attempt"]
        assert (
            len(calls) == 5
        )  # Two reviewer calls plus three auxiliary calls; study is charged separately.
        assert [kind for kind, _ in client.calls] == ["audit", "study", "audit"]


@pytest.mark.parametrize("terminal", ["source-changed", "closed"])
def test_mixed_delivery_cannot_reopen_stale_or_closed_unit(
    tmp_path, monkeypatch, terminal
):
    with mixed_case(tmp_path, monkeypatch) as (runtime, client, review, config, base):
        ctx, context_id = offer(runtime, base, "Owned mixed terminal evidence")
        packet = reserve(runtime, ctx, context_id)
        assert packet is not None and runtime.enrich_context(ctx, packet)
        if terminal == "source-changed":
            client.after_review = lambda prompt: (tmp_path / "owned.c").write_text(
                "int changed(void) { return 0; }\n"
            )
        outcome = review(ctx, config)
        if terminal == "source-changed":
            assert not runtime.can_publish(packet)
            assert runtime.fail(packet, "source_changed", ctx)
        else:
            assert_prompt_receipt(
                runtime,
                packet,
                outcome,
                ctx["mechanical_evidence"],
                client.calls[-1][1],
            )
            assert runtime.complete(packet, ctx)
            runtime.close("owned_terminal")
            assert not runtime.offer_context_delta(
                ctx,
                kind="late_joern",
                version=context_version(ctx["mechanical_evidence"]),
            )
        assert reserve(runtime, ctx, context_id) is None
        assert runtime.ready_continuations(admission=lambda: True) == ()
        assert [kind for kind, _ in client.calls] == ["audit", "study", "audit"]
        assert any(e["event"] == "review_attempt" for e in runtime.events())


def test_mixed_postfit_omission_cannot_use_model_or_shared_context_receipts(
    tmp_path, monkeypatch
):
    with mixed_case(tmp_path, monkeypatch) as (runtime, client, review, config, base):
        ctx, context_id = offer(
            runtime, base, "Owned omitted evidence " * 10000 + "OWNED_UNDELIVERED_TAIL"
        )
        packet = reserve(runtime, ctx, context_id)
        assert (
            packet is not None
            and packet.packet.explanations
            and packet.packet.references
        )
        assert runtime.enrich_context(ctx, packet)
        client.forged_id = context_id
        ctx["external_context_delivery"] = [
            {"context_id": context_id, "delivered": True}
        ]
        monkeypatch.setattr(llm_review, "_prompt_budget", lambda *args: 100)
        outcome = review(ctx, config)
        assert "Owned omitted evidence" in client.calls[-1][1]
        assert "OWNED_UNDELIVERED_TAIL" not in client.calls[-1][1]
        assert ctx["mechanical_evidence"] not in client.calls[-1][1]
        assert not any(
            row["delivered"]
            for row in outcome.review_result["external_context_delivery"]
        )
        assert not runtime.context_was_delivered(packet)
        assert runtime.fail(packet, "context_not_delivered", ctx)
        prompt_event = [
            e for e in runtime.events() if e["event"] == "review_prompt_context"
        ][-1]
        external = [
            r
            for r in prompt_event["records"]
            if r["field"] == "external_context_delivery"
        ]
        assert external and all(not row["delivered"] for row in external)


@pytest.mark.parametrize("mode", ["admitted", "source-changed", "partial-fit"])
def test_mixed_late_orchestrator_publishes_only_delivered_current_packet(
    tmp_path, monkeypatch, mode
):
    with mixed_case(tmp_path, monkeypatch, initial_status="clean") as (
        runtime,
        client,
        _,
        config,
        base,
    ):
        prior = client.initial_outcome
        assert prior.status == "clean" and not prior.evidence_tool
        prior.line = 2
        config.sweep_validate_findings = False
        evidence = "Owned publisher evidence"
        if mode == "partial-fit":
            evidence = (evidence + " ") * 10000 + "OWNED_PUBLISHER_TAIL"
            monkeypatch.setattr(llm_review, "_prompt_budget", lambda *args: 100)
        ctx = {**base, "mechanical_evidence": evidence}
        context_id = "context:late_joern:" + context_version(evidence)
        client.forged_id = context_id
        ctx["external_context_delivery"] = [
            {"context_id": context_id, "delivered": True}
        ]

        def during_review(prompt):
            if mode != "partial-fit":
                assert "The target type carries length" in prompt
                assert "ownership is not established" in prompt
                assert "c.integer-definedness v1:" in prompt
                assert evidence in prompt
            if mode == "source-changed":
                (tmp_path / "owned.c").write_text("int changed(void) { return 0; }\n")

        client.after_review = during_review
        monkeypatch.setattr(orch, "_build_context", lambda *a, **kw: dict(ctx))
        committed = []
        monkeypatch.setattr(
            orch, "_commit_outcome", lambda cfg, outcome, gap: committed.append(outcome)
        )
        result = orch.OrchestratorResult(outcomes=[prior], clean=1, reviewed=1)
        record = SimpleNamespace(all_joern_flows=lambda: ["owned saved context"])
        gap = {"file": "owned.c", "name": "f", "line_start": 2, "line_end": 2}
        returned = orch._re_review_joern_enriched(
            result,
            config,
            make_review_fn(client, escalate_clean=False),
            checklist={"files": [{"path": "owned.c"}]},
            context_map=None,
            fuzz_coverage=None,
            evidence_index={"owned.c:f": record},
            sarif_cache=None,
            entry_points=set(),
            gaps_before_joern=[gap],
            start_time=monotonic(),
            on_progress=None,
            max_workers=1,
            knowledge_runtime=runtime,
        )
        assert returned is result
        assert [kind for kind, _ in client.calls] == ["audit", "study", "audit"]
        reservations = [
            e for e in runtime.events() if e["event"] == "continuation_reserved"
        ]
        assert len(reservations) == 1
        request_ids = {request.request_id for request in runtime.requests()}
        assert len(request_ids) == 2
        assert set(reservations[0]["delta_ids"]) == request_ids | {context_id}
        completed = [
            e for e in runtime.events() if e["event"] == "continuation_completed"
        ]
        failed = [e for e in runtime.events() if e["event"] == "continuation_failed"]
        if mode == "admitted":
            assert (
                result.outcomes[0] is not prior
                and result.outcomes[0].status == "suspicious"
            )
            assert committed == result.outcomes
            assert result.clean == 0 and result.suspicious == 1
            assert len(completed) == 1 and not failed
            assert set(completed[0]["delivered_request_ids"]) == request_ids | {
                context_id
            }
            assert completed[0]["published_status"] == "suspicious"
        else:
            assert result.outcomes == [prior] and result.outcomes[0] is prior
            assert result.clean == 1 and result.suspicious == 0 and not committed
            assert len(failed) == 1 and not completed
            if mode == "partial-fit":
                assert "Owned publisher evidence" in client.calls[-1][1]
                assert "OWNED_PUBLISHER_TAIL" not in client.calls[-1][1]
                prompt_event = [
                    e for e in runtime.events() if e["event"] == "review_prompt_context"
                ][-1]
                external = [
                    r
                    for r in prompt_event["records"]
                    if r["field"] == "external_context_delivery"
                ]
                assert external and all(not row["delivered"] for row in external)
        calls = [
            e
            for e in runtime.events()
            if e["event"] in ("client_call_attempt", "study_attempt")
        ]
        assert len(calls) == 3


def test_failed_mixed_pass_keeps_late_delta_and_consumes_its_round(
    tmp_path, monkeypatch
):
    with mixed_case(tmp_path, monkeypatch, initial_status="clean") as (
        runtime,
        client,
        _,
        config,
        base,
    ):
        prior = client.initial_outcome
        assert prior.status == "clean" and not prior.evidence_tool
        prior.line = 2
        config.sweep_validate_findings = False
        result = orch.OrchestratorResult(outcomes=[prior], clean=1, reviewed=1)
        committed = []
        monkeypatch.setattr(
            orch, "_commit_outcome", lambda cfg, outcome, gap: committed.append(outcome)
        )
        record = SimpleNamespace(all_joern_flows=lambda: ["owned saved context"])
        gap = {"file": "owned.c", "name": "f", "line_start": 2, "line_end": 2}

        def dispatch(ctx):
            monkeypatch.setattr(orch, "_build_context", lambda *a, **kw: dict(ctx))
            return orch._re_review_joern_enriched(
                result,
                config,
                make_review_fn(client, escalate_clean=False),
                checklist={"files": [{"path": "owned.c"}]},
                context_map=None,
                fuzz_coverage=None,
                evidence_index={"owned.c:f": record},
                sarif_cache=None,
                entry_points=set(),
                gaps_before_joern=[gap],
                start_time=monotonic(),
                on_progress=None,
                max_workers=1,
                knowledge_runtime=runtime,
            )

        first = {**base, "mechanical_evidence": "Owned failed-pass version one"}
        first_id = "context:late_joern:" + context_version(first["mechanical_evidence"])
        late = []
        failure = RuntimeError("owned mixed transport failed after dispatch")

        def fail_with_late_arrival(prompt):
            assert first["mechanical_evidence"] in prompt
            assert "The target type carries length" in prompt
            assert "c.integer-definedness v1:" in prompt
            next_ctx, next_id = offer(runtime, base, "Owned failed-pass version two")
            late.append((next_ctx, next_id))
            assert reserve(runtime, next_ctx, next_id) is None
            assert runtime.ready_continuations(admission=lambda: True) == ()
            raise failure

        client.after_review = fail_with_late_arrival
        assert dispatch(first) is result
        assert result.outcomes == [prior] and result.outcomes[0] is prior
        assert result.clean == 1 and result.suspicious == 0 and not committed
        failed = [e for e in runtime.events() if e["event"] == "continuation_failed"]
        assert len(failed) == 1 and failed[0]["published_status"] == ""
        assert not any(e["event"] == "continuation_completed" for e in runtime.events())
        failed_pass = failed[0]["pass_id"]
        assert any(
            e["event"] == "review_failed" and e["pass_id"] == failed_pass
            for e in runtime.events()
        )
        # The original version cannot consume the independently pending V2.
        assert reserve(runtime, first, first_id) is None
        before_retry = len(client.calls)
        assert dispatch(first) is result
        assert len(client.calls) == before_retry
        assert (
            len([e for e in runtime.events() if e["event"] == "continuation_reserved"])
            == 1
        )

        client.after_review = lambda prompt: None
        original_transport = client.generate_structured

        def clean_transport(prompt, schema, **kwargs):
            response = original_transport(prompt, schema, **kwargs)
            assert kwargs["task_type"] == "audit"
            response.result["status"] = "clean"
            return response

        monkeypatch.setattr(client, "generate_structured", clean_transport)
        second, second_id = late[0]
        assert dispatch(second) is result
        assert second["mechanical_evidence"] in client.calls[-1][1]
        assert result.outcomes == [prior] and result.outcomes[0] is prior
        assert result.clean == 1 and result.suspicious == 0 and not committed
        reservations = [
            e for e in runtime.events() if e["event"] == "continuation_reserved"
        ]
        completed = [
            e for e in runtime.events() if e["event"] == "continuation_completed"
        ]
        assert len(reservations) == 2 and len(completed) == 1
        assert set(reservations[1]["delta_ids"]) == {second_id}
        assert completed[0]["pass_id"] != failed_pass
        assert completed[0]["published_status"] == "clean"
        assert second_id in completed[0]["delivered_request_ids"]
        assert first_id not in completed[0]["delivered_request_ids"]

        third = {**base, "mechanical_evidence": "Owned failed-pass version three"}
        before_third = len(client.calls)
        assert dispatch(third) is result
        assert len(client.calls) == before_third
        assert (
            len([e for e in runtime.events() if e["event"] == "continuation_reserved"])
            == 2
        )
        assert [kind for kind, _ in client.calls] == [
            "audit",
            "study",
            "audit",
            "audit",
        ]
        assert (
            len([e for e in runtime.events() if e["event"] == "client_call_attempt"])
            == 3
        )
        assert len([e for e in runtime.events() if e["event"] == "study_attempt"]) == 1


def test_failed_study_stays_unavailable_when_other_information_is_published(
    tmp_path, monkeypatch
):
    from core.json import load_json

    original_transport = ScriptedClient.generate_structured
    failure = RuntimeError("owned unavailable source-study transport")

    def failed_study(self, prompt, schema, **kwargs):
        if kwargs["task_type"] == "study":
            self.calls.append(("study", prompt))
            assert self.request_ids[0] in prompt
            assert "typedef struct" in prompt
            raise failure
        return original_transport(self, prompt, schema, **kwargs)

    monkeypatch.setattr(ScriptedClient, "generate_structured", failed_study)
    with mixed_case(tmp_path, monkeypatch, initial_status="clean") as (
        runtime,
        client,
        _,
        config,
        base,
    ):
        prior = client.initial_outcome
        prior.line = 2
        assert prior.status == "clean" and not prior.evidence_tool
        config.sweep_validate_findings = False
        requests = runtime.requests()
        study = next(request for request in requests if request.kind == "target_study")
        reference = next(
            request for request in requests if request.kind == "language_reference"
        )
        answers = [
            e["answer"] for e in runtime.events() if e["event"] == "source_answer"
        ]
        assert len(answers) == 1 and answers[0]["request_id"] == study.request_id
        assert answers[0]["status"] == "unavailable"
        assert answers[0]["reason"] == "source_study_failed"
        assert not answers[0]["materials"] and not answers[0]["explanation"]
        evidence = "Owned useful context despite unavailable study"
        ctx = {**base, "mechanical_evidence": evidence}
        context_id = "context:late_joern:" + context_version(evidence)

        def actual_prompt(prompt):
            assert evidence in prompt and "c.integer-definedness v1:" in prompt
            assert "The target type carries length" not in prompt
            assert "Source-study explanation (untrusted context)" not in prompt

        client.after_review = actual_prompt
        monkeypatch.setattr(orch, "_build_context", lambda *a, **kw: dict(ctx))
        committed = []
        monkeypatch.setattr(
            orch, "_commit_outcome", lambda cfg, outcome, gap: committed.append(outcome)
        )
        result = orch.OrchestratorResult(outcomes=[prior], clean=1, reviewed=1)
        record = SimpleNamespace(all_joern_flows=lambda: ["owned saved context"])
        gap = {"file": "owned.c", "name": "f", "line_start": 2, "line_end": 2}
        assert (
            orch._re_review_joern_enriched(
                result,
                config,
                make_review_fn(client, escalate_clean=False),
                checklist={"files": [{"path": "owned.c"}]},
                context_map=None,
                fuzz_coverage=None,
                evidence_index={"owned.c:f": record},
                sarif_cache=None,
                entry_points=set(),
                gaps_before_joern=[gap],
                start_time=monotonic(),
                on_progress=None,
                max_workers=1,
                knowledge_runtime=runtime,
            )
            is result
        )
        assert committed == result.outcomes and len(committed) == 1
        outcome = result.outcomes[0]
        assert outcome is not prior and outcome.status == "suspicious"
        assert not outcome.evidence_tool and not outcome.review_result.get(
            "immediate_verified"
        )
        receipts = outcome.review_result["source_study_delivery"]
        assert len(receipts) == 1 and receipts[0]["request_id"] == study.request_id
        assert (
            receipts[0]["delivered"] is False
            and receipts[0]["reason"] == "answer_unavailable"
        )
        assert not receipts[0]["answer_statuses"] and not receipts[0]["binding_ids"]
        completed = [
            e for e in runtime.events() if e["event"] == "continuation_completed"
        ]
        assert len(completed) == 1
        assert set(completed[0]["delivered_request_ids"]) == {
            reference.request_id,
            context_id,
        }
        assert study.request_id not in completed[0]["delivered_request_ids"]
        reservation = next(
            e for e in runtime.events() if e["event"] == "continuation_reserved"
        )
        assert set(reservation["delta_ids"]) == {reference.request_id, context_id}
        assert [kind for kind, _ in client.calls] == ["audit", "study", "audit"]
        assert len([e for e in runtime.events() if e["event"] == "study_attempt"]) == 1
        assert (
            len([e for e in runtime.events() if e["event"] == "client_call_attempt"])
            == 2
        )
        runtime.write_artifacts(config.out_dir)
        recorded = load_json(config.out_dir / "knowledge-results.json")
        failed_request = next(
            row for row in recorded["requests"] if row["request_id"] == study.request_id
        )
        assert failed_request["processing"] == {
            "state": "unavailable",
            "answer_status": "unavailable",
            "reason": "source_study_failed",
        }
        assert recorded["role"] == "context_provenance_not_verification_evidence"
        assert recorded["units"][0]["all_model_calls"] == 3


def test_actual_runtime_stays_open_through_deepen_and_closes_afterward(
    tmp_path, monkeypatch
):
    import json
    import re

    from core.audit import capabilities
    from core.audit.continuation_context import context_spec
    from core.testing.audit_shutdown import isolated_audit_shutdown
    from core.testing.wallclock import wall_deadline

    target = tmp_path / "target"
    target.mkdir()
    (target / "types.h").write_text("typedef struct { unsigned length; } foo_t;\n")
    source = '#include "types.h"\nunsigned f(foo_t item) { return item.length; }\n'
    (target / "owned.c").write_text(source)
    out = tmp_path / "out"
    out.mkdir()
    (out / "checklist.json").write_text(
        json.dumps(
            {
                "files": [
                    {
                        "path": "owned.c",
                        "items": [{"name": "f", "line_start": 2, "line_end": 2}],
                    }
                ]
            }
        )
    )
    monkeypatch.setattr(orch, "_run_mechanical_detectors", lambda *a, **k: ({}, set()))
    monkeypatch.setattr(orch, "_proactive_validate", lambda outcome, *a, **k: outcome)
    monkeypatch.setattr(
        capabilities,
        "probe_capabilities",
        lambda *a, **k: capabilities.AuditCapabilities(),
    )
    instances = []
    timeline = []
    actual_wrap = AuditKnowledgeRuntime.wrap_review
    actual_close = AuditKnowledgeRuntime.close

    def wrap(self, fn):
        if not any(item is self for item in instances):
            instances.append(self)
        return actual_wrap(self, fn)

    def close(self, *args, **kwargs):
        timeline.append(
            ("close", args[0] if args else kwargs.get("reason", "audit_finished"))
        )
        return actual_close(self, *args, **kwargs)

    monkeypatch.setattr(AuditKnowledgeRuntime, "wrap_review", wrap)
    monkeypatch.setattr(AuditKnowledgeRuntime, "close", close)
    seen = []

    def deepen(result, *args, **kwargs):
        assert len(instances) == 1
        runtime = instances[0]
        ctx = {
            "file": "owned.c",
            "function": "f",
            "line_start": 2,
            "line_end": 2,
            "source": source.splitlines()[1],
            "language": "c",
            "mechanical_evidence": "Owned context at deepen entry",
        }
        version = context_version(ctx["mechanical_evidence"])
        assert context_spec(ctx, kind="late_joern", version=version) is not None
        admitted = runtime.offer_context_delta(ctx, kind="late_joern", version=version)
        timeline.append(("deepen", admitted))
        seen.append(admitted)
        return result

    monkeypatch.setattr(orch, "_deepen_suspicious", deepen)

    class Client(ScriptedClient):
        def generate_structured(self, prompt, schema, **kwargs):
            if kwargs["task_type"] == "study":
                self.request_ids[:] = [
                    re.search(r'"request_id"\s*:\s*"([^\"]+)"', prompt).group(1)
                ]
            return super().generate_structured(prompt, schema, **kwargs)

    client = Client()
    monkeypatch.setattr(orch, "_run_llm_client", lambda cfg: client)
    config = orch.OrchestratorConfig(
        target_path=target,
        out_dir=out,
        max_workers=1,
        resume=False,
        prefilter=False,
        validate=False,
        immediate_verify=False,
        sweep_validate_findings=False,
        max_refinements=0,
        deepen_suspicious=True,
        open_discovery=False,
        sage_recall=False,
        iris=False,
        enable_session_context=False,
        joern_overrides={"enabled": False},
        llm_budget_client=client,
    )
    with (
        isolated_audit_shutdown(orch),
        wall_deadline(
            30, code_bound_s=float("inf"), what="Runtime lifetime observation"
        ),
    ):
        result = orch.run_orchestrator(
            config, make_review_fn(client, escalate_clean=False)
        )
    assert len(result.outcomes) == 1
    assert [kind for kind, _ in client.calls] == ["audit", "study", "audit"]
    assert seen == [True]
    close_index = next(i for i, row in enumerate(timeline) if row[0] == "close")
    deepen_index = next(i for i, row in enumerate(timeline) if row[0] == "deepen")
    assert close_index > deepen_index
    final_ctx = {
        "file": "owned.c",
        "function": "f",
        "line_start": 2,
        "line_end": 2,
        "source": source.splitlines()[1],
        "language": "c",
        "mechanical_evidence": "Owned context after pipeline close",
    }
    assert not instances[0].offer_context_delta(
        final_ctx,
        kind="late_joern",
        version=context_version(final_ctx["mechanical_evidence"]),
    )
