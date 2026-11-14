"""Owned source/packet accounting controls, not a live study/build producer.

The private request/cycle registries below establish fixture-owned records with
real production shapes. They do not establish resolver, provider, target-build,
concurrency, or native execution authority. No worker is started by this file.
"""

from dataclasses import asdict, dataclass, replace
import json
from pathlib import Path

import pytest

from core.audit import knowledge_study
from core.audit.knowledge_calls import KnowledgeCallRefused, observed_client, owned_call_scope
from core.audit.knowledge_requests import KnowledgeBatch, KnowledgeOrigin, KnowledgeRequest
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.refutation_source import capture_source_identity
from core.audit.review_cycle import KnowledgeCycle
from core.audit.study_job_ledger import StudyJobDescriptor
from core.concepts.model import StudyItem
from core.concepts.subject_study import (
    StudySubject, StudySubjects, SubjectDispatchRefused, SubjectExplanation,
    SubjectMaterial, SubjectPacket,
)


@dataclass
class _Case:
    runtime: AuditKnowledgeRuntime
    requests: tuple[KnowledgeRequest, ...]
    packet: SubjectPacket
    jobs: tuple[StudyJobDescriptor, ...]
    root: Path

    @property
    def keys(self):
        return tuple(self.runtime._key(request.origin) for request in self.requests)

    def begin(self, *, packet=None, requests=None, jobs=None, owner="fixture-owner"):
        token, reason = self.runtime.begin_source_dispatch(
            requests=self.requests if requests is None else requests,
            packet=self.packet if packet is None else packet,
            jobs=self.jobs if jobs is None else jobs,
            owner_id=owner,
        )
        return token, reason

    def spent(self):
        return {row["lineage"]: row["spent"] for row in self.runtime._study_jobs.snapshot()["jobs"]}


@pytest.fixture
def owned_case(tmp_path):
    runtimes = []

    def create(*, limit=2, caps=(5,), required=1):
        root = tmp_path / f"case-{len(runtimes)}"
        root.mkdir()
        runtime = AuditKnowledgeRuntime(
            root, None, deadline=float("inf"), max_model_calls=max(caps),
            study_job_call_limit=limit, required_review_calls=required,
        )
        runtimes.append(runtime)
        requests = []
        for index, cap in enumerate(caps):
            file = f"caller-{index}.cpp"
            (root / file).write_text(f"int Caller{index}() {{ return {index}; }}\n")
            identity = capture_source_identity(root, file)
            assert identity is not None
            origin = KnowledgeOrigin(f"fixture-pass-{index}", file, f"Caller{index}", 1, 1, identity)
            request = KnowledgeRequest(f"fixture-request-{index}", origin, "target_study",
                                       "Decl", "owned source context", "normal", "identifier")
            runtime._requests[request.request_id] = request
            runtime._cycles[runtime._key(origin)] = KnowledgeCycle(
                origin, KnowledgeBatch((request,), ()), deadline=float("inf"),
                admit_study=runtime.bindings.admit, max_model_calls=cap,
            )
            runtime._pending_sources.add(request.request_id)
            requests.append(request)
        materials = []
        expected = {}
        for name in ("decl", "uncited"):
            file = f"{name}.cpp"
            text = f"int {name}() {{ return 1; }}\n"
            (root / file).write_text(text)
            identity = capture_source_identity(root, file)
            assert identity is not None
            expected[name] = identity
            materials.append(SubjectMaterial(name, file, 1, name, text, False,
                                             source_item_id=name))
        packet = SubjectPacket(tuple(StudySubject(
            request.request_id, request.subject, request.context,
            request.resolution, request.origin.file,
        ) for request in requests), tuple(materials))
        packet = runtime.bindings.bind(packet, expected=expected)
        assert len(packet.materials) == 2 and all(material.binding_id for material in packet.materials)
        return _Case(runtime, tuple(requests), packet,
                     (StudyJobDescriptor("decl-lineage", "decl-generation"),
                      StudyJobDescriptor("other-lineage", "other-generation")), root)

    yield create
    for runtime in reversed(runtimes):
        runtime.close("owned fixture teardown")


@pytest.mark.parametrize("policy", [None, True, 0, -1, "2"])
def test_absent_or_invalid_policy_retains_legacy_source_admission(owned_case, policy):
    case = owned_case(limit=policy, caps=(3,))
    assert case.runtime.study_jobs_enabled is False
    assert case.runtime.admit_source_attempt(case.requests) is True
    assert case.runtime._calls[case.keys[0]] == 1


def test_all_units_and_review_reserves_are_checked_before_any_debit(owned_case):
    case = owned_case(caps=(5, 5))
    case.runtime._calls[case.keys[1]] = 4
    token, reason = case.begin()
    assert token is not None and reason == ""
    assert not case.runtime.admit_source_attempt(case.requests, dispatch_lease=token)
    assert case.runtime._calls.get(case.keys[0], 0) == 0
    assert case.runtime._calls[case.keys[1]] == 4
    assert case.spent() == {"decl-lineage": 0, "other-lineage": 0}
    assert case.runtime.events()[-1]["reason"] == "review_call_reserve"


def test_freeze_rejects_job_allowance_above_one_participant_cap(owned_case):
    case = owned_case(limit=3, caps=(5, 2))
    token, reason = case.begin()
    assert token is None and reason == "study_job_allowance_exceeds_unit_cap"
    assert case.runtime._calls == {}
    assert case.runtime._study_jobs.snapshot()["jobs"] == []


def test_review_invocation_credit_is_not_released_again_by_identified_retry(owned_case):
    case = owned_case(caps=(6,), required=2)
    runtime, key = case.runtime, case.keys[0]
    assert runtime._study_reserved_calls(key) == 2
    assert runtime._admit_client_key(key, "review", "generate_structured", review_attempt_id="review-A")
    assert runtime._study_reserved_calls(key) == 1
    assert runtime._admit_client_key(key, "review", "generate_structured", review_attempt_id="review-A")
    assert runtime._study_reserved_calls(key) == 1
    assert runtime._calls[key] == 2
    # The original completion owner may release the first-review reservation;
    # the second provider admission was not a second renderer invocation.
    runtime._study_review_returned(key, "review-A", success=True)
    assert runtime._study_reserved_calls(key) == 0


def test_active_continuation_reservation_remains_until_its_review_admissions(owned_case):
    case = owned_case(caps=(6,))
    runtime, key = case.runtime, case.keys[0]
    runtime._study_review_finished.add(key)
    runtime._study_review_reservations[key] = (2, frozenset())
    runtime._calls[key] = 4
    token, _ = case.begin()
    assert token is not None
    assert not runtime.admit_source_attempt(case.requests, dispatch_lease=token)
    assert runtime._study_reserved_calls(key) == 2
    assert runtime._admit_client_key(key, "review", "generate_structured", review_attempt_id="continuation-A")
    assert runtime._study_reserved_calls(key) == 1
    assert not runtime.admit_source_attempt(case.requests, dispatch_lease=token)
    assert case.spent() == {"decl-lineage": 0, "other-lineage": 0}


def test_smaller_continuation_width_does_not_shrink_an_initial_review_reserve(owned_case):
    case = owned_case(caps=(5,), required=3)
    runtime, key = case.runtime, case.keys[0]
    runtime._calls[key] = 2
    # A busy initial reviewer is not a continuation candidate, but another
    # continuation poll still updates the runtime's scheduling width.
    runtime._busy[key] = 1
    try:
        assert runtime.ready_continuations(admission=lambda: True, required_calls=1) == ()
    finally:
        runtime._busy.pop(key)
    assert runtime._required_calls == 1
    assert runtime._study_reserved_calls(key) == 3
    token, _ = case.begin()
    assert token is not None
    assert not runtime.admit_source_attempt(case.requests, dispatch_lease=token)
    assert runtime._calls[key] == 2
    assert case.spent() == {"decl-lineage": 0, "other-lineage": 0}
    assert runtime.events()[-1]["reason"] == "review_call_reserve"


def test_charged_cap_one_first_provider_callback_remains_valid(owned_case):
    case = owned_case(limit=1, caps=(3,))
    runtime = case.runtime
    token, _ = case.begin()
    assert token is not None
    entries, callbacks = [], []

    class ScriptedClient:
        _attempt_admission_protocol = 1

        def generate_structured(self, *, accounting_attempt_admission):
            entries.append("one owned method body")
            callbacks.append(accounting_attempt_admission())
            assert runtime._calls[case.keys[0]] == 1
            return {"owned": True}

    def valid():
        assert runtime.source_dispatch_valid(token) is None
        return True

    try:
        with owned_call_scope(
            lambda purpose, method: runtime.admit_source_attempt(case.requests, dispatch_lease=token),
            validity=valid,
        ):
            assert observed_client(ScriptedClient(), purpose="study").generate_structured() == {"owned": True}
    finally:
        runtime.finish_source_dispatch(token)
    assert entries == ["one owned method body"] and callbacks == [True]
    assert case.spent() == {"decl-lineage": 1, "other-lineage": 1}


def test_identified_retries_charge_same_lease_without_reentering_scripted_body(owned_case):
    case = owned_case(limit=2, caps=(4,))
    runtime = case.runtime
    token, _ = case.begin()
    assert token is not None
    entries = []

    class ScriptedClient:
        _attempt_admission_protocol = 1

        def generate_structured(self, *, accounting_attempt_admission):
            entries.append("one high-level invocation")
            assert accounting_attempt_admission() is True
            assert accounting_attempt_admission() is True
            with pytest.raises(KnowledgeCallRefused, match="unit_admission"):
                accounting_attempt_admission()
            return {"owned": True}

    def valid():
        runtime.source_dispatch_valid(token)
        return True

    try:
        with owned_call_scope(
            lambda purpose, method: runtime.admit_source_attempt(case.requests, dispatch_lease=token),
            validity=valid,
        ):
            observed_client(ScriptedClient(), purpose="study").generate_structured()
    finally:
        runtime.finish_source_dispatch(token)
    assert entries == ["one high-level invocation"]
    assert runtime._calls[case.keys[0]] == 2
    assert case.spent() == {"decl-lineage": 2, "other-lineage": 2}


def test_opaque_accounting_blocks_replacement_even_after_actual_retirement(owned_case):
    case = owned_case(caps=(5,))
    runtime = case.runtime
    token, _ = case.begin()
    assert token is not None
    assert runtime.admit_source_attempt(case.requests, dispatch_lease=token)
    runtime.mark_source_dispatch_unknown(token)
    for request in case.requests:
        runtime.mark_call_count_unknown({"file": request.origin.file, "name": request.origin.function,
                                         "line_start": request.origin.line_start}, "opaque fixture")
    runtime.finish_source_dispatch(token)
    replacement, reason = case.begin()
    assert replacement is None and reason == "study_job_accounting_unknown"
    assert runtime._calls[case.keys[0]] == 1
    assert case.spent() == {"decl-lineage": 1, "other-lineage": 1}


def test_phase_completion_and_generation_change_do_not_retire_live_invocation(owned_case):
    case = owned_case(caps=(5,))
    runtime = case.runtime
    subjects = StudySubjects(case.packet.subjects)
    owner = runtime.source_job_owner(subjects)
    runtime.track_source_job(subjects)
    token, _ = case.begin(owner=owner)
    assert token is not None
    assert runtime.admit_source_attempt(case.requests, dispatch_lease=token)
    runtime.finish_source_job(subjects)
    assert runtime._study_jobs.snapshot()["leases"][0]["active"] is True
    replacement, reason = case.begin(jobs=tuple(replace(job, generation="new-generation") for job in case.jobs))
    assert replacement is None and reason == "study_job_dispatch_live"
    runtime.finish_source_dispatch(token)
    assert runtime._study_jobs.snapshot()["leases"][0]["active"] is False
    replacement, _ = case.begin(jobs=tuple(replace(job, generation="new-generation") for job in case.jobs))
    assert replacement is not None
    assert runtime.admit_source_attempt(case.requests, dispatch_lease=replacement)
    assert case.spent() == {"decl-lineage": 2, "other-lineage": 2}


def test_uncited_input_change_refuses_before_any_accounting_debit(owned_case):
    case = owned_case()
    token, _ = case.begin()
    assert token is not None
    (case.root / "uncited.cpp").write_text("int uncited() { return 99; }\n")
    assert not case.runtime.admit_source_attempt(case.requests, dispatch_lease=token)
    assert case.runtime._calls == {}
    assert case.spent() == {"decl-lineage": 0, "other-lineage": 0}
    assert case.runtime.events()[-1]["reason"] == "study_material_changed"


def test_duplicate_actual_completion_does_not_emit_another_retirement(owned_case):
    case = owned_case()
    token, _ = case.begin()
    assert token is not None
    assert case.runtime.admit_source_attempt(case.requests, dispatch_lease=token)
    case.runtime.finish_source_dispatch(token)
    before = case.runtime.events()
    case.runtime.finish_source_dispatch(token)
    assert case.runtime.events() == before


def test_answer_custody_keeps_original_requests_and_the_entire_input_packet(owned_case):
    case = owned_case()
    runtime = case.runtime
    token, _ = case.begin()
    assert token is not None
    assert runtime.admit_source_attempt(case.requests, dispatch_lease=token)
    runtime.finish_source_dispatch(token)
    request = case.requests[0]
    full = SubjectExplanation(request.request_id, "answered", "owned explanation", "",
                              case.packet.materials[:1], case.packet.materials)
    runtime.record_source_answers((full,))
    assert runtime._source_answers[request.request_id] == [full]
    late = replace(request, request_id="late-beneficiary")
    runtime._requests[late.request_id] = late
    runtime.record_source_answers((replace(full, request_id=late.request_id),))
    runtime.record_source_answers((replace(full, inputs=full.inputs[:1]),))
    assert late.request_id not in runtime._source_answers
    assert runtime._source_answers[request.request_id] == [full]


@pytest.mark.parametrize("alteration", ["omitted", "changed", "flag"])
def test_answer_custody_keeps_excluded_inputs_and_context_flag(owned_case, alteration):
    case = owned_case()
    excluded = SubjectMaterial("excluded", "missing.cpp", None, "Missing", "", False)
    packet = replace(case.packet, excluded_materials=(excluded,), extra_context_excluded=True)
    token, _ = case.begin(packet=packet)
    assert token is not None
    assert case.runtime.admit_source_attempt(case.requests, dispatch_lease=token)
    case.runtime.finish_source_dispatch(token)
    answer = SubjectExplanation(case.requests[0].request_id, "answered", "owned context", "",
                                packet.materials[:1], packet.materials,
                                excluded_inputs=packet.excluded_materials, extra_context_excluded=True)
    altered = {
        "omitted": replace(answer, excluded_inputs=()),
        "changed": replace(answer, excluded_inputs=(replace(excluded, file="other.cpp"),)),
        "flag": replace(answer, extra_context_excluded=False),
    }[alteration]
    case.runtime.record_source_answers((altered,))
    assert case.requests[0].request_id not in case.runtime._source_answers
    case.runtime.record_source_answers((answer,))
    assert case.runtime._source_answers[answer.request_id] == [answer]


@pytest.mark.parametrize("enabled", [False, True])
def test_artifacts_disclose_frozen_dispatch_scope_only_when_enabled(owned_case, enabled):
    case = owned_case(limit=2 if enabled else None)
    excluded = SubjectMaterial("excluded", "missing.cpp", None, "Missing", "", False)
    packet = replace(case.packet, excluded_materials=(excluded,), extra_context_excluded=True)
    token = None
    if enabled:
        token, _ = case.begin(packet=packet)
        assert token is not None
    from core.audit.knowledge_reporting import load_knowledge_processing

    for request in case.requests:
        case.runtime._request_status[request.request_id] = {"state": "pending"}
    out = case.root / "artifacts"
    out.mkdir()
    case.runtime.write_artifacts(out)
    payload = json.loads((out / "knowledge-results.json").read_text())
    assert payload["role"] == "context_provenance_not_verification_evidence"
    projection = load_knowledge_processing(out)
    assert projection is not None and projection["state"] == "recorded"
    assert projection["requests"] == len(case.requests)
    assert projection["delivered_requests"] == 0
    if not enabled:
        assert "shared_study_jobs" not in payload
    else:
        assert payload["shared_study_jobs"]["dispatch_scopes"] == [{
            "lease_id": token.lease_id,
            "subjects": [asdict(subject) for subject in packet.subjects],
            "input_binding_ids": [material.binding_id for material in packet.materials],
            "excluded_inputs": [asdict(excluded)],
            "extra_context_excluded": True,
        }]
@pytest.mark.parametrize("mode", ["known", "owner-finishes-before-callback", "opaque"])
def test_actual_studyclient_adapter_owns_first_callback_and_retirement(owned_case, monkeypatch, mode):
    # Imports are intentional profile resources, not an assertion that normal
    # orchestrator/study module import closure is native-free.
    from core.audit import orchestrator
    from core.concepts import study

    case = owned_case(limit=1, caps=(3,))
    runtime, request = case.runtime, case.requests[0]
    item = StudyItem("decl", "function", "Decl", "decl.cpp", line=1,
                     definition=(case.root / "decl.cpp").read_text())
    identity = capture_source_identity(case.root, "decl.cpp")
    assert identity is not None
    plan = knowledge_study._SourcePlan(
        [item], {request.request_id: frozenset((item.id,))}, {item.id: "target"}, {}, {},
        {item.id: identity},
    )
    plan.jobs = knowledge_study._job_descriptors(plan, case.requests, roots={"target": case.root})
    assert request.request_id in plan.jobs and item.id in plan.material_jobs
    holder, entries, callbacks = {}, [], []

    class ScriptedClient:
        _attempt_admission_protocol = None if mode == "opaque" else 1

        def generate_structured(self, **kwargs):
            entries.append("owned scripted body")
            if mode == "owner-finishes-before-callback":
                runtime.finish_source_job(holder["subjects"])
            if mode != "opaque":
                callbacks.append(kwargs["accounting_attempt_admission"]())
            return {"subject_answers": [{"request_id": request.request_id,
                    "status": "answered", "explanation": "owned declaration context",
                    "reason": "", "material_ids": [holder["packet"].materials[0].material_id]}]}

    def phase(items, target, client, *, subjects, **kwargs):
        holder["subjects"] = subjects
        packet = subjects.prepare(items, [])
        holder["packet"] = packet
        assert packet.subjects and packet.materials[0].binding_id
        with subjects.dispatching(packet):
            if mode == "owner-finishes-before-callback":
                with pytest.raises(SubjectDispatchRefused, match="study_job_owner_or_generation_closed"):
                    client.generate_structured()
            else:
                response = client.generate_structured()
                subjects.record(packet, response)

    monkeypatch.setattr(knowledge_study, "_prepare", lambda *args, **kwargs: plan)
    monkeypatch.setattr(orchestrator, "_run_llm_client", lambda config: ScriptedClient())
    monkeypatch.setattr(orchestrator, "_client_class_cost", lambda *args: 0.0)
    monkeypatch.setattr(study, "run_phase2", phase)
    config = orchestrator.OrchestratorConfig(case.root, case.root / "out")
    config.llm_budget_client = object()  # Availability sentinel; never called.
    knowledge_study.study_batch(case.requests, runtime, config, orchestrator.OrchestratorResult(),
                                checklist={}, should_stop=lambda: False)
    assert entries == ["owned scripted body"]
    assert callbacks == ([True] if mode == "known" else [])
    state = runtime._study_jobs.snapshot()
    assert state["leases"][0]["active"] is False
    assert state["jobs"][0]["spent"] == 1
    assert runtime._calls[case.keys[0]] == 1
    if mode == "known":
        assert runtime._source_answers[request.request_id][0].status == "answered"
    else:
        assert not any(answer.status == "answered"
                       for answer in runtime._source_answers.get(request.request_id, ()))
    if mode == "opaque":
        assert case.keys[0] in runtime._unknown_calls
        assert request.request_id not in runtime._pending_sources


@pytest.mark.parametrize("retirement", [
    "remaining", "remaining-final-sweep", "remaining-producer-done", "remaining-producer-done-consumer",
    "exhausted", "opaque",
    "exhausted-before-refusal-drain", "opaque-before-refusal-drain",
])
def test_late_beneficiary_waits_for_actual_retirement_and_keeps_its_packet(
        owned_case, monkeypatch, retirement):
    from core.audit import orchestrator
    from core.concepts import study

    case = owned_case(limit=1 if retirement.startswith("exhausted") else 2, caps=(5,))
    runtime, original = case.runtime, case.requests[0]
    queue = orchestrator.StudyQueue()
    runtime.study_queue = queue
    late = replace(original, request_id="late-original-B", context="B's distinct original learning context")
    runtime._requests[late.request_id] = late
    runtime._pending_sources.add(late.request_id)
    runtime._request_status[late.request_id] = {"state": "queued"}
    assert runtime._cycles[case.keys[0]].add_requests(KnowledgeBatch((late,), ()))
    item = StudyItem("decl", "function", "Decl", "decl.cpp", line=1,
                     definition=(case.root / "decl.cpp").read_text())
    identity = capture_source_identity(case.root, "decl.cpp")
    assert identity is not None
    plan = knowledge_study._SourcePlan(
        [item], {late.request_id: frozenset((item.id,))}, {item.id: "target"}, {}, {},
        {item.id: identity},
    )
    plan.jobs = knowledge_study._job_descriptors(plan, (late,), roots={"target": case.root})
    token, reason = case.begin(jobs=plan.jobs[late.request_id], owner="held-physical-A")
    assert token is not None and reason == ""
    assert runtime.admit_source_attempt(case.requests, dispatch_lease=token)
    first_packet, bodies, callbacks = [], [], []

    class ScriptedClient:
        _attempt_admission_protocol = 1

        def generate_structured(self, **kwargs):
            bodies.append("B's actual scripted body")
            callbacks.append(kwargs["accounting_attempt_admission"]())
            packet = first_packet[0]
            return {"subject_answers": [{"request_id": late.request_id,
                    "status": "answered", "explanation": "B's separately requested context",
                    "reason": "", "material_ids": [packet.materials[0].material_id]}]}

    def phase(items, target, client, *, subjects, **kwargs):
        packet = subjects.prepare(items, [])
        if not first_packet:
            packet = replace(packet, excluded_materials=(SubjectMaterial(
                "excluded-B", "unavailable.h", None, "Unavailable", "", False),),
                extra_context_excluded=True)
            first_packet.append(packet)
        else:
            assert packet == first_packet[0]
        assert packet.subjects[0].context == late.context
        with subjects.dispatching(packet):
            try:
                response = client.generate_structured()
            except SubjectDispatchRefused as error:
                assert error.reason == "study_job_dispatch_live"
                if retirement.endswith("before-refusal-drain"):
                    if retirement.startswith("opaque"):
                        runtime.mark_source_dispatch_unknown(token)
                        runtime.mark_call_count_unknown(
                            {"file": original.origin.file, "name": original.origin.function,
                             "line_start": original.origin.line_start}, reason="owned opaque A completion")
                    runtime.finish_source_dispatch(token)
                # Match the existing concepts consumer's refused-result branch
                # without starting its daemon worker or executing a provider.
                if retirement != "remaining-final-sweep":
                    subjects.unavailable(packet, error.reason)
            else:
                subjects.record(packet, response)

    monkeypatch.setattr(knowledge_study, "_prepare", lambda *args, **kwargs: plan)
    monkeypatch.setattr(orchestrator, "_run_llm_client", lambda config: ScriptedClient())
    monkeypatch.setattr(orchestrator, "_client_class_cost", lambda *args: 0.0)
    monkeypatch.setattr(study, "run_phase2", phase)
    config = orchestrator.OrchestratorConfig(case.root, case.root / "out")
    config.llm_budget_client = object()
    result = orchestrator.OrchestratorResult()
    knowledge_study.study_batch((late,), runtime, config, result,
                                checklist={}, should_stop=lambda: False)
    assert bodies == [] and callbacks == []
    if retirement.endswith("before-refusal-drain"):
        assert late.request_id not in runtime._pending_sources
        assert late.request_id not in runtime._source_answers
        assert runtime._request_status[late.request_id]["state"] == "deferred"
        assert runtime._request_status[late.request_id]["reason"] in {
            "study_job_call_limit", "study_job_accounting_unknown", "model_call_count_unavailable"}
        assert runtime._calls[case.keys[0]] == 1
        assert queue.dequeue_batch(timeout=0) == []
        return
    assert late.request_id in runtime._pending_sources
    assert late.request_id in runtime.transient_source_request_ids()
    assert late.request_id not in runtime._source_answers
    assert runtime._calls[case.keys[0]] == 1
    assert queue.dequeue_batch(timeout=0) == []
    if retirement.startswith("remaining-producer-done"):
        queue.signal_producer_done()
        assert queue.is_done()
    if retirement == "opaque":
        runtime.mark_source_dispatch_unknown(token)
        runtime.mark_call_count_unknown(
            {"file": original.origin.file, "name": original.origin.function,
             "line_start": original.origin.line_start}, reason="owned opaque A completion")
    consumer = retirement == "remaining-producer-done-consumer"
    if consumer:
        monkeypatch.setattr(knowledge_study, "_prepare", lambda *args, **kwargs: pytest.fail(
            "pending B must replay its frozen source plan, not resolve fresh material"))
        original_dequeue = queue.dequeue_batch
        loop_batches = []

        def retire_before_owned_dequeue(*args, **kwargs):
            assert kwargs.get("wait_for_pending") is True
            runtime.finish_source_dispatch(token)
            batch = original_dequeue(*args, **kwargs)
            loop_batches.append(batch)
            return batch

        monkeypatch.setattr(queue, "dequeue_batch", retire_before_owned_dequeue)
        monkeypatch.setattr(orchestrator, "_check_budget", lambda *args: False)
        # Call the existing consumer loop directly with an owned dequeue seam;
        # no consumer thread or Phase 2 worker is started by this control.
        orchestrator._study_consumer_loop(
            queue, config, orchestrator.SharedState(domain_model={"invariants": []}),
            lambda *args: pytest.fail("legacy review path must remain unused"),
            orchestrator._LockedOutcomes(), result, checklist={}, context_map=None, evidence_index={},
            sarif_cache=None, entry_points=set(), start_time=0, on_progress=None,
            knowledge_runtime=runtime,
        )
        monkeypatch.setattr(queue, "dequeue_batch", original_dequeue)
        assert loop_batches == [[late]]
        queued = loop_batches[0]
    else:
        runtime.finish_source_dispatch(token)
        queued = queue.dequeue_batch(timeout=0)
    if not retirement.startswith("remaining"):
        assert queued == [] and bodies == [] and callbacks == []
        assert late.request_id not in runtime._pending_sources
        assert late.request_id not in runtime._source_answers
        assert runtime._request_status[late.request_id]["state"] == "deferred"
        assert runtime._request_status[late.request_id]["reason"] in {
            "study_job_call_limit", "study_job_accounting_unknown", "model_call_count_unavailable"}
        assert runtime._calls[case.keys[0]] == 1
        return
    assert queued == [late] and queued[0] is late
    monkeypatch.setattr(knowledge_study, "_prepare", lambda *args, **kwargs: pytest.fail(
        "pending B must replay its frozen source plan, not resolve fresh material"))
    if not consumer:
        knowledge_study.study_batch(tuple(queued), runtime, config, result,
                                    checklist={}, should_stop=lambda: False)
    assert bodies == ["B's actual scripted body"] and callbacks == [True]
    answer, = runtime._source_answers[late.request_id]
    assert answer.request_id == late.request_id and answer.inputs == first_packet[0].materials
    assert answer.excluded_inputs == first_packet[0].excluded_materials
    assert answer.extra_context_excluded is True
    runtime.record_source_answers((SubjectExplanation(
        late.request_id, "unavailable", "", "study_job_dispatch_live", (), producer="pipeline"),))
    assert runtime._source_answers[late.request_id] == [answer]
    assert runtime._request_status[late.request_id]["state"] == "context_available"
    assert late.request_id not in runtime._pending_sources
    assert original.request_id not in runtime._source_answers
    assert runtime._calls[case.keys[0]] == 2
    assert runtime._study_jobs.snapshot()["jobs"][0]["spent"] == 2
    assert queue.dequeue_batch(timeout=0) == []
