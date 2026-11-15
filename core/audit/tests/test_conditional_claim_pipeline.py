"""UNEXECUTED integration controls: real issuer, local scripted review, no model.

Draft only. Independent review and separately pinned native-parser
qualification are required before applying or executing these controls.
"""
from copy import deepcopy
from types import SimpleNamespace
import json

import pytest

from core.audit import orchestrator as orch
from core.audit.conditional_claim_pipeline import REQUEST_FIELD, declarations
from core.audit.conditional_member_policy import POLICY_ID, POLICY_VERSION, STATEMENT
from core.audit.findings_export import write_graded_findings
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.prepared_claim_pipeline import PreparedClaimPipeline
from core.audit.record import load_verified_audit_log
from core.audit.tests.test_member_copy_observation import FIXTURES
from core.audit.tests.test_prepared_claim_context import case  # noqa: F401 -- maintained fixture
from core.audit.tests.test_prepared_claim_pipeline import pipeline_case  # noqa: F401 -- maintained fixture


def declaration(cwe="CWE-680"):
    return {"statement": STATEMENT, "mechanism_kind": "unsigned-member-narrow-alloc-wide-copy-v1",
            "declared_cwe": cwe, "policy_id": POLICY_ID, "policy_version": POLICY_VERSION}


@pytest.fixture
def live(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    root, out = tmp_path / "source", tmp_path / "run"
    out.mkdir()
    for name, source in FIXTURES.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    config = orch.OrchestratorConfig(root, out, immediate_verify=True)
    runtime = AuditKnowledgeRuntime(root, orch.StudyQueue(), deadline=float("inf"))
    source = "\n".join(FIXTURES["protocol/parser.c"].splitlines()[24:50])
    ctx = {"file": "protocol/parser.c", "function": "parse_header", "line_start": 25,
           "source": source, "language": "c"}
    def forbidden(*args, **kwargs):
        pytest.fail("conditional-only path reached legacy engine/provider/verdict work")
    for name in ("_get_llm_client", "_run_tool_chain", "_try_bound_ihv_synthesis",
                 "_aggregate_ihv_verdicts", "_gather_library_candidates"):
        monkeypatch.setattr(orch, name, forbidden)
    return SimpleNamespace(root=root, out=out, config=config, runtime=runtime,
                           ctx=ctx, source=source, last=None)


def review(c, requests, *, include_field=True):
    def scripted(ctx, config):
        result = {REQUEST_FIELD: deepcopy(requests)} if include_field else {}
        return orch.ReviewOutcome(file="protocol/parser.c", function="parse_header", line=25,
                                   status="suspicious", body="owned scripted review",
                                   review_result=result)
    c.last = c.runtime.wrap_review(scripted)(c.ctx, c.config)
    return c.last


def intake(c, outcome=None):
    value = outcome or c.last
    before = (value.status, value.evidence_tool, value.tools_dispatched, value.claim_refutations)
    returned = orch._verify_hypotheses_immediate(value, c.config, orch.OrchestratorResult(),
                                                source=c.source)
    assert returned is value
    assert (value.status, value.evidence_tool, value.tools_dispatched, value.claim_refutations) == before
    return returned


def publish(c):
    export = {"findings": []}
    write_graded_findings(export, c.out, prepared_claim_pipeline=c.config.prepared_claim_pipeline)
    assert export["findings"] == []
    value = json.loads((c.out / "claim-adjudication-shadow.json").read_text())
    assert value["authoritative"] is False and value["mode"] == "shadow"
    return value


def supported(shadow):
    return [claim for claim in shadow["claims"] if claim["supported_obligations"]]


def test_real_live_issuer_shadow_export_roundtrip_is_conditional_only(live):
    review(live, [declaration()])
    intake(live)
    observations = [row for row in load_verified_audit_log(live.out)
                    if row.get("action") == "ihv_claim_observations"]
    assert len(observations) == 1
    reference, = observations[0]["claim_revisions"]
    assert reference["parent_revision"] is None
    assert reference["pass_id"] == live.last.review_result["review_claims"]["review"]["origin"]["pass_id"]
    shadow = publish(live)
    row, = supported(shadow)
    assert row["revision_id"] == reference["revision_id"]
    assert row["supported_obligations"] == ["closed-conditional-pre-copy-size-relation"]
    assert not row["contradicted_obligations"]
    availability, = shadow["preparation_availability"]
    assert availability["issuer_cwe_verified"] is False
    assert availability["requested_conclusion"]["conclusion_kind"] == "conditional-size-mismatch"
    assert not supported(publish(live))  # consumed execution cannot re-export


@pytest.mark.parametrize("cwe", [None, "CWE-190 / CWE-680", ["CWE-190", "CWE-680"], "CWE-119"])
def test_explicit_class_is_not_selected_or_filled_from_headline(live, monkeypatch, cwe):
    from core.audit import conditional_member_copy
    def forbidden(*args, **kwargs):
        pytest.fail("invalid declaration reached source validator")
    monkeypatch.setattr(conditional_member_copy, "observe_member_copy", forbidden)
    row = declaration(cwe)
    review(live, [row])
    live.last.review_result["cwe_class"] = "CWE-680"
    intake(live)
    assert not supported(publish(live))


def test_legacy_only_review_never_initialises_conditional_adapter(live):
    review(live, [], include_field=False)
    intake(live)
    assert live.config.prepared_claim_pipeline._conditional_run is None


@pytest.mark.parametrize("replacement", ["empty", "missing", "disabled", "new-review"])
def test_new_intake_or_review_withdraws_previous_conditional_support(live, replacement):
    review(live, [declaration()])
    intake(live)
    if replacement == "new-review":
        review(live, [], include_field=False)  # withdraws even before next IHV
    elif replacement == "disabled":
        live.config.immediate_verify = False
        intake(live)
    else:
        live.last.review_result = {REQUEST_FIELD: []} if replacement == "empty" else {}
        intake(live)
    assert not supported(publish(live))


def test_history_and_copied_outcome_cannot_recreate_live_grant(live):
    original = review(live, [declaration()])
    copied = orch.ReviewOutcome(file=original.file, function=original.function, line=original.line,
                               status=original.status, body=original.body,
                               review_result=deepcopy(original.review_result))
    intake(live, copied)
    assert not supported(publish(live))


def test_separate_run_cannot_replay_retained_execution(live):
    review(live, [declaration()])
    intake(live)
    assert supported(publish(live))
    live.config.prepared_claim_pipeline = PreparedClaimPipeline(live.root, live.out)
    assert not supported(publish(live))


@pytest.mark.parametrize("change", ["declaration", "source", "retained-write"])
def test_publication_currentness_and_retention_faults_withdraw(live, monkeypatch, change):
    review(live, [declaration()])
    intake(live)
    if change == "declaration":
        live.last.review_result[REQUEST_FIELD][0]["declared_cwe"] = "CWE-195"
    elif change == "source":
        path = live.root / "protocol/message.h"
        path.write_bytes(path.read_bytes() + b"\n")
    else:
        from core.audit import conditional_member_copy
        def failed(*args, **kwargs):
            raise OSError("owned retention fault")
        monkeypatch.setattr(conditional_member_copy, "write_bytes_atomically", failed)
    assert not supported(publish(live))
    assert not supported(publish(live))


def test_cancelled_retention_propagates_without_reusable_handle(live, monkeypatch):
    from core.audit import conditional_member_copy
    review(live, [declaration()])
    intake(live)
    def cancelled(*args, **kwargs):
        raise KeyboardInterrupt
    with monkeypatch.context() as patch:
        patch.setattr(conditional_member_copy, "write_bytes_atomically", cancelled)
        with pytest.raises(KeyboardInterrupt):
            publish(live)
    assert not supported(publish(live))


def test_reentrant_export_does_not_issue_duplicate_fact(live, monkeypatch):
    from core.audit import conditional_member_copy
    review(live, [declaration()])
    intake(live)
    original = conditional_member_copy.write_bytes_atomically
    nested = []
    def reentrant(*args, **kwargs):
        nested.append(publish(live))
        return original(*args, **kwargs)
    monkeypatch.setattr(conditional_member_copy, "write_bytes_atomically", reentrant)
    outer = publish(live)
    assert len(nested) == 1 and not supported(nested[0])
    assert len(supported(outer)) == 1
    assert not supported(publish(live))


def test_source_change_during_later_retention_withdraws_prior_candidate(live, monkeypatch):
    from core.audit import conditional_member_copy
    review(live, [declaration("CWE-680"), declaration("CWE-190")])
    intake(live)
    original = conditional_member_copy.write_bytes_atomically
    calls = []
    def changed(*args, **kwargs):
        result = original(*args, **kwargs)
        calls.append(True)
        if len(calls) == 2:
            path = live.root / "protocol/message.c"
            path.write_bytes(path.read_bytes() + b"\n")
        return result
    monkeypatch.setattr(conditional_member_copy, "write_bytes_atomically", changed)
    assert not supported(publish(live))
    assert len(calls) == 2


def test_closed_schema_rejects_history_ids_conditions_and_duplicates():
    base = declaration()
    for field in ("claim_id", "revision_id", "conditions", "confidence", "is_primary"):
        altered = {**base, field: "not-authority"}
        assert declarations({REQUEST_FIELD: [altered]}) is None
    assert declarations({REQUEST_FIELD: [base, base]}) is None
    assert declarations({"cwe_class": "CWE-680"}) == ()


def test_noneligible_legacy_route_and_combined_class_stay_unchanged(live, monkeypatch):
    from core.audit.check_trace import record_claim_observations
    calls, legacy = [], []
    monkeypatch.setattr(orch, "_inventory_language_hint", lambda *args: "c")
    monkeypatch.setattr(orch, "_correlated_mech_detector_tool", lambda *args: None)
    monkeypatch.setattr(orch, "_get_llm_client", lambda *args: None)
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *args: [])
    def chain(*args, **kwargs):
        calls.append(args)
        return []
    monkeypatch.setattr(orch, "_hypothesis_to_tool_chain", chain)
    monkeypatch.setattr(orch, "_try_bound_ihv_synthesis", lambda *args, **kwargs: None)
    def aggregate(outcome, result, hypotheses, verifications, config, **kwargs):
        legacy.extend(verifications)
        record_claim_observations(config.out_dir, file=outcome.file, function=outcome.function,
                                  line_start=outcome.line, verifications=verifications)
        return outcome
    monkeypatch.setattr(orch, "_aggregate_ihv_verdicts", aggregate)
    review(live, [], include_field=False)
    live.last.hypothesis = "legacy descriptive narrowing concern"
    live.last.review_result["cwe_class"] = "CWE-190 / CWE-680"
    intake(live)
    assert len(calls) == len(legacy) == 1
    assert legacy[0].hypothesis["cwe"] == "CWE-190 / CWE-680"
    assert legacy[0].hypothesis["confidence"] == "high"
    assert legacy[0].hypothesis["is_primary"] is True
    assert live.config.prepared_claim_pipeline._conditional_run is None
    assert not supported(publish(live))


def test_concurrent_exports_consume_only_one_pending_execution(live):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from core.audit.check_trace import _admit_claim_events
    from core.audit.claim_observations import index_claim_observations

    review(live, [declaration()])
    intake(live)
    claim_events, _, _ = _admit_claim_events(load_verified_audit_log(live.out))
    index = index_claim_observations(claim_events, [])
    barrier = Barrier(2)
    def run():
        barrier.wait(timeout=5)
        return live.config.prepared_claim_pipeline.conditional_shadow_inputs(index)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(run) for _ in range(2)]
        results = [future.result(timeout=10) for future in futures]
    assert sum(len(result[1]) for result in results) == 1
    assert not live.config.prepared_claim_pipeline.conditional_shadow_inputs(index)[1]


def test_reentrant_empty_live_review_during_validation_withdraws(live, monkeypatch):
    from core.audit import conditional_member_copy
    review(live, [declaration()])
    first = live.last
    original = conditional_member_copy.observe_member_copy
    calls = []
    def reentrant(*args, **kwargs):
        calls.append(True)
        review(live, [], include_field=False)
        intake(live)
        return original(*args, **kwargs)
    monkeypatch.setattr(conditional_member_copy, "observe_member_copy", reentrant)
    intake(live, first)
    assert calls == [True]
    assert not supported(publish(live))


@pytest.mark.parametrize("fault", ["read-missing", "read-mismatch"])
def test_integration_readback_fault_does_not_leave_publishable_fact(live, monkeypatch, fault):
    from io import BytesIO
    from core.audit import conditional_member_copy
    review(live, [declaration()])
    intake(live)
    monkeypatch.setattr(conditional_member_copy, "open_regular_beneath",
                        lambda *args, **kwargs: None if fault == "read-missing"
                        else BytesIO(b"owned mismatch"))
    assert not supported(publish(live))
    assert not supported(publish(live))


def test_missing_adapter_refuses_without_changing_legacy_outcome(live, monkeypatch):
    import builtins
    review(live, [declaration()])
    original = builtins.__import__
    def absent(name, *args, **kwargs):
        if name == "conditional_member_copy":
            raise ImportError("owned missing conditional adapter")
        return original(name, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(builtins, "__import__", absent)
        intake(live)
    assert not supported(publish(live))


def test_real_review_schema_and_decoder_keep_explicit_request_to_issuer(live):
    from core.audit.llm_review import make_review_fn
    from core.audit.tests.test_llm_review import FakeStructuredResponse
    calls = []
    class ScriptedStructuredReview:
        def generate_structured(self, prompt, schema, **kwargs):
            calls.append(schema)
            assert REQUEST_FIELD in schema["properties"]
            assert REQUEST_FIELD not in schema.get("required", [])
            return FakeStructuredResponse(result={"status": "suspicious", "body": "owned response",
                "hypothesis": "", "hypotheses": [], REQUEST_FIELD: [declaration()]}, cost=0)
    reviewer = make_review_fn(ScriptedStructuredReview(), system_prompt="owned local review",
                              escalate_clean=False)
    live.last = live.runtime.wrap_review(reviewer)(live.ctx, live.config)
    assert declarations(live.last.review_result)
    # Real orchestration stamps the inventoried line after review returns.
    assert live.last.line == 0
    live.last.line = live.ctx["line_start"]
    intake(live)
    assert len(calls) == 1 and len(supported(publish(live))) == 1


def test_schema_exposure_is_bounded_and_never_source_admission(live):
    from core.audit.conditional_claim_pipeline import request_schema_for_context
    schema = request_schema_for_context(live.ctx)
    assert schema and schema["items"]["additionalProperties"] is False
    for key, value in (("file", "other.c"), ("function", "other"), ("line_start", 26),
                       ("language", "python"), ("source", "")):
        assert request_schema_for_context({**live.ctx, key: value}) is None
    assert not live.config.prepared_claim_pipeline._conditional_run


def authenticated_index(c):
    from core.audit.check_trace import _admit_claim_events
    from core.audit.claim_observations import index_claim_observations
    admitted, _, _ = _admit_claim_events(load_verified_audit_log(c.out))
    return index_claim_observations(admitted, [])


@pytest.mark.parametrize("change", ["material", "missing", "malformed", "duplicate"])
def test_exact_index_includes_canonical_hypothesis_material(live, change):
    from hashlib import sha256
    from core.json import dumps_canonical
    review(live, [declaration()])
    intake(live)
    index = authenticated_index(live)
    row, = index["claims"]
    if change == "material":
        row["definition_sha256"] = sha256(dumps_canonical({"definition": row["definition"],
            "hypothesis": {"mechanism": "different hypothesis", "cwe": "CWE-680"}}).encode()).hexdigest()
    elif change == "missing":
        row.pop("definition_sha256")
    elif change == "malformed":
        row["definition_sha256"] = "not-a-canonical-digest"
    else:
        index["claims"].append(deepcopy(row))
    assert not live.config.prepared_claim_pipeline.conditional_shadow_inputs(index)[1]


def test_concurrent_review_binder_cannot_remove_newer_grant(live, monkeypatch):
    from threading import Thread, Event, current_thread
    from core.testing.threads import retiring_threads
    review(live, [])  # initialise the run without a pending execution
    run = live.config.prepared_claim_pipeline._conditional_run
    original = run._withdraw
    older_ready, newer_done = Event(), Event()
    results, errors = {}, []
    def interleave(*args, **kwargs):
        epoch = original(*args, **kwargs)
        if current_thread().name == "older-review":
            older_ready.set()
            assert newer_done.wait(5), "new review did not finish"
        return epoch
    monkeypatch.setattr(run, "_withdraw", interleave)
    def invoke(name):
        try:
            results[name] = review(live, [declaration()])
        except BaseException as exc:
            errors.append(exc)
        finally:
            if name == "newer":
                newer_done.set()
    old = Thread(target=invoke, args=("older",), name="older-review")
    new = Thread(target=invoke, args=("newer",), name="newer-review")
    with retiring_threads([old, new], release=newer_done.set, timeout=10):
        old.start()
        assert older_ready.wait(5)
        new.start()
        new.join(5)
        old.join(5)
    assert not errors and len(results) == 2
    assert id(results["newer"]) in run._grants
    assert id(results["older"]) not in run._grants
    intake(live, results["older"])  # stale IHV cannot erase the newest grant
    assert id(results["newer"]) in run._grants
    intake(live, results["newer"])
    assert len(supported(publish(live))) == 1


@pytest.mark.parametrize("line", [0, 26])
def test_unstamped_or_wrong_stamped_factory_outcome_cannot_issue(live, line):
    from core.audit.llm_review import make_review_fn
    from core.audit.tests.test_llm_review import FakeStructuredResponse
    class Scripted:
        def generate_structured(self, *args, **kwargs):
            return FakeStructuredResponse(result={"status": "suspicious", "body": "owned",
                "hypothesis": "", REQUEST_FIELD: [declaration()]}, cost=0)
    live.last = live.runtime.wrap_review(make_review_fn(Scripted(),
                system_prompt="owned", escalate_clean=False))(live.ctx, live.config)
    live.last.line = line
    intake(live)
    assert not supported(publish(live))


@pytest.mark.parametrize("change", ["source", "declaration"])
def test_final_shared_currentness_barrier_withdraws_all_candidates(live, monkeypatch, change):
    from core.audit import conditional_claim_pipeline as module
    review(live, [declaration("CWE-680"), declaration("CWE-190")])
    intake(live)
    original, calls = module._units, []
    def final_change(root):
        calls.append(True)
        if len(calls) == 5:  # two pre/post pairs, then the common final barrier
            if change == "source":
                path = live.root / "protocol/message.h"
                path.write_bytes(path.read_bytes() + b"\n")
            else:
                live.last.review_result[REQUEST_FIELD] = []
        return original(root)
    monkeypatch.setattr(module, "_units", final_change)
    assert not supported(publish(live))
    assert len(calls) == 5
    assert not supported(publish(live))


@pytest.mark.parametrize("capacity", ["grants", "active", "occurrences"])
def test_capacity_refusal_is_bounded_and_does_not_run_checker(live, monkeypatch, capacity):
    from core.audit import conditional_claim_pipeline as module
    from core.audit import conditional_member_copy
    from core.audit.claims import ClaimRevision
    from core.audit.knowledge_requests import KnowledgeOrigin
    from core.audit.refutation_source import capture_source_identity
    review(live, [declaration()])
    intake(live)
    run = live.config.prepared_claim_pipeline._conditional_run
    origin = KnowledgeOrigin("owned-capacity", "protocol/parser.c", "parse_header", 25, 50,
                             capture_source_identity(live.root, "protocol/parser.c"))
    if capacity == "grants":
        # Grant bookkeeping contains live typed outcomes/origins, not proofs.
        run._grants = {i: (object(), KnowledgeOrigin("owned-capacity", f"owned-{i}.c",
            "unexecuted", 1, 1, origin.source_identity), "capacity", ()) for i in range(64)}
    elif capacity == "active":
        for i in range(63):
            occurrence = (f"owned-{i}.c", "unexecuted", 1)
            revision = ClaimRevision({"mechanism": STATEMENT, "mechanism_kind": module.MECHANISM,
                "cwe": "CWE-680"}, pass_id="owned-capacity", file=occurrence[0],
                function=occurrence[1], line_start=1)
            run._active[occurrence] = (module._Entry(revision, object(), (), "capacity", origin),)
    else:
        # A new occurrence, rather than a replacement, exercises the 128 bound.
        run = module.ConditionalClaimRun(live.root, live.out)
        live.config.prepared_claim_pipeline._conditional_run = run
        for i in range(128):
            run._withdraw((f"owned-{i}.c", "unexecuted", 1))
    def forbidden(*args, **kwargs):
        pytest.fail("capacity refusal reached checker execution")
    monkeypatch.setattr(conditional_member_copy.ConditionalMemberValidatorOwner, "validate", forbidden)
    requests = [declaration(), declaration("CWE-190"), declaration("CWE-195")]
    review(live, requests)
    intake(live)
    assert not run._pending
    assert not supported(publish(live))
    assert len(run._grants) <= 64 and len(run._epochs) <= 128
    # Inspect the explicit loss projection after the first export consumed none.
    availability = run.shadow_inputs({"claims": []})[3]
    assert any("budget" in row["reason"] or "grant-unavailable" in row["reason"]
               for row in availability)


@pytest.mark.parametrize("fault", ["serialize", "write"])
def test_shadow_write_failure_is_disclosed_and_cannot_reexport_consumed_fact(live, monkeypatch, fault):
    from core.audit import check_trace
    review(live, [declaration()])
    intake(live)
    export = {"findings": []}
    with monkeypatch.context() as patch:
        if fault == "serialize":
            from core.audit import claim_adjudication
            original_shadow = claim_adjudication.publication_shadow
            def circular(*args, **kwargs):
                value = original_shadow(*args, **kwargs)
                value["owned_serialization_cycle"] = value
                return value
            patch.setattr(claim_adjudication, "publication_shadow", circular)
        else:
            original = check_trace.save_json
            def failed(path, *args, **kwargs):
                if path.name == "claim-adjudication-shadow.json":
                    raise OSError("owned shadow write failure")
                return original(path, *args, **kwargs)
            patch.setattr(check_trace, "save_json", failed)
        write_graded_findings(export, live.out,
                             prepared_claim_pipeline=live.config.prepared_claim_pipeline)
    assert export["findings"] == []
    assert export["claim_adjudication_shadow"]["status"] == "export_error"
    assert not supported(publish(live))


def test_noneligible_actual_schema_and_export_parity(live):
    from core.audit.llm_review import make_review_fn
    from core.audit.tests.test_llm_review import FakeStructuredResponse
    schema = {"type": "object", "properties": {"status": {"type": "string"}}, "required": ["status"]}
    calls = []
    class Scripted:
        def generate_structured(self, prompt, actual, **kwargs):
            calls.append(deepcopy(actual))
            return FakeStructuredResponse(result={"status": "suspicious", "body": "owned",
                                                  "hypothesis": ""}, cost=0)
    reviewer = make_review_fn(Scripted(), schema=schema, blind_schema=schema,
                              system_prompt="owned", escalate_clean=False)
    ctx = {**live.ctx, "file": "other.c", "function": "other", "line_start": 1}
    outcome = reviewer(ctx, live.config)
    assert calls == [schema] and REQUEST_FIELD not in outcome.review_result
    review(live, [], include_field=False)
    intake(live)
    before = {"findings": []}
    write_graded_findings(before, live.out, prepared_claim_pipeline=None)
    after = {"findings": []}
    write_graded_findings(after, live.out, prepared_claim_pipeline=live.config.prepared_claim_pipeline)
    assert after == before


@pytest.mark.parametrize("raw", [[declaration()] * 9, [declaration(), declaration()], "not-an-array"])
def test_oversized_duplicate_malformed_requests_refuse_before_checker(live, monkeypatch, raw):
    from core.audit import conditional_member_copy
    def forbidden(*args, **kwargs):
        pytest.fail("malformed request reached checker")
    monkeypatch.setattr(conditional_member_copy.ConditionalMemberValidatorOwner, "validate", forbidden)
    review(live, raw)
    intake(live)
    assert not supported(publish(live))


def prepare_coexisting(concrete_case, monkeypatch):
    """Maintained concrete preparation fixture/API; no solver/tool dispatch.

    Its manifest is fixture-owned synthetic input, not a deployed build claim.
    The independent witness replay/retention are the real existing components.
    """
    from core.audit.check_trace import record_claim_observations
    c = concrete_case
    prepared = c.pipeline.prepare(c.record, integer_abi="ilp32")
    c.pipeline.observe(c.record, c.result, prepared=prepared, integer_abi="ilp32")
    record_claim_observations(c.out, file="unit.c", function="Read", line_start=1,
                              verifications=[c.record])
    for name, source in FIXTURES.items():
        path = c.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    source = "\n".join(FIXTURES["protocol/parser.c"].splitlines()[24:50])
    ctx = {"file": "protocol/parser.c", "function": "parse_header", "line_start": 25,
           "source": source, "language": "c"}
    runtime = AuditKnowledgeRuntime(c.root, orch.StudyQueue(), deadline=float("inf"))
    def scripted(ctx, config):
        return orch.ReviewOutcome(file=ctx["file"], function=ctx["function"], line=25,
            status="suspicious", body="owned", review_result={REQUEST_FIELD: [declaration()]})
    outcome = runtime.wrap_review(scripted)(ctx, c.config)
    c.config.immediate_verify = True
    orch._verify_hypotheses_immediate(outcome, c.config, orch.OrchestratorResult(), source=source)
    return c


def test_conditional_and_concrete_preparation_compose_without_namespace_loss(pipeline_case, monkeypatch):  # noqa: F811
    from core.audit.prepared_claim_context import OBLIGATION as concrete_obligation
    c = prepare_coexisting(pipeline_case, monkeypatch)
    export = {"findings": []}
    write_graded_findings(export, c.out, prepared_claim_pipeline=c.pipeline)
    shadow = json.loads((c.out / "claim-adjudication-shadow.json").read_text())
    obligations = {item for row in shadow["claims"] for item in row["supported_obligations"]}
    assert obligations == {concrete_obligation, "closed-conditional-pre-copy-size-relation"}
    assert len(shadow["preparation_availability"]) == 2
    concrete = [r for r in shadow["preparation_availability"] if r.get("prepared_target")]
    assert len(concrete) == 1
    assert concrete[0]["prepared_target"]["build_identity"] == c.target.build_identity
    assert not c.calls  # no SMT/tool dispatcher used
    assert export["findings"] == [] and shadow["authoritative"] is False


def test_contract_namespace_collision_is_explicit_export_error(pipeline_case, monkeypatch):  # noqa: F811
    from core.audit.prepared_claim_context import CONTRACT_ID as concrete_contract
    c = prepare_coexisting(pipeline_case, monkeypatch)
    original = c.pipeline.conditional_shadow_inputs
    def collision(index):
        contexts, events, contracts, availability = original(index)
        assert contracts
        return contexts, events, {**contracts, concrete_contract: next(iter(contracts.values()))}, availability
    monkeypatch.setattr(c.pipeline, "conditional_shadow_inputs", collision)
    export = {"findings": []}
    write_graded_findings(export, c.out, prepared_claim_pipeline=c.pipeline)
    assert export["findings"] == []
    assert export["claim_adjudication_shadow"]["status"] == "export_error"


def test_native_provider_wire_preserves_conditional_question_and_optional_refusal(live):
    from core.audit.conditional_claim_pipeline import request_schema_for_context
    from core.llm.providers import _dict_schema_to_pydantic
    question = request_schema_for_context(live.ctx)
    assert question is not None
    model = _dict_schema_to_pydantic({"type": "object", "properties": {REQUEST_FIELD: question},
                                     "required": []})
    assert model.model_json_schema()["properties"][REQUEST_FIELD]["description"] == question["description"]
    assert model.model_validate({}).model_dump()[REQUEST_FIELD] is None
    review(live, None)
    intake(live)
    assert not supported(publish(live))


@pytest.mark.parametrize("request_state", ["explicit", "omitted", "empty", "null"])
def test_normal_factory_provider_decode_real_caller_stamp_to_shadow(live, monkeypatch, request_state):
    from core.audit.llm_review import make_review_fn
    from core.audit.pipeline import ReviewMode
    from core.audit.shared_state import SharedState
    from core.audit.tests.test_llm_review import FakeStructuredResponse
    from core.llm.config import ModelConfig
    from core.llm.providers import _dict_schema_to_pydantic

    # Keep the actual context/factory/wrapper/caller/IHV/export path. Only
    # incidental legacy scheduling is neutral; the live fixture's engine
    # dispatch tripwires remain in force.
    live.config.prefilter = False
    live.config.max_refinements = 0
    live.config.sage_recall = False
    live.config.propagate_constraints = False
    live.config.sweep_validate_findings = False
    monkeypatch.setattr(orch, "_correlated_mech_detector_tool", lambda *a: None)
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *a: [])
    monkeypatch.setattr(orch, "_get_llm_client", lambda *a: None)
    monkeypatch.setattr(orch, "_proactive_validate", lambda outcome, *a, **kw: outcome)
    calls = []

    class ScriptedNativeDecode:
        config = SimpleNamespace(config_for_model=lambda name:
                                 ModelConfig(provider="anthropic", model_name=name))

        def supports_prompt_caching_for(self):
            return True

        def generate_structured(self, prompt, schema, **kwargs):
            assert REQUEST_FIELD in schema["properties"]
            model = _dict_schema_to_pydantic(schema)
            payload = {"status": "suspicious", "body": "Owned conditional-only scripted review",
                       "hypothesis": "", "hypotheses": [], "cwe": "",
                       "counter_hypothesis": "", "counter_direction": "refutes_vuln",
                       "verdict_rationale": "No active verdict proof asserted"}
            if request_state != "omitted":
                payload[REQUEST_FIELD] = ([declaration()] if request_state == "explicit"
                                          else [] if request_state == "empty" else None)
            parsed = model.model_validate(payload).model_dump()
            calls.append({"offered": REQUEST_FIELD in schema["properties"],
                          "decoded_null": parsed[REQUEST_FIELD] is None})
            return FakeStructuredResponse(result=parsed, cost=0)

    # These kwargs match the live pipeline factory; no custom system prompt,
    # custom schema or manual line assignment stands in for the producer.
    reviewer = make_review_fn(ScriptedNativeDecode(), task_type="audit",
                              model_name="scripted-local", mode=ReviewMode.SECURITY,
                              out_dir=live.out)
    item = {"kind": "function", "name": "parse_header", "line_start": 25,
            "line_end": 50, "sloc": 26}
    gap = {"file": "protocol/parser.c", **item, "pinned": True}
    shared = SharedState(checklist={"files": [{"path": "protocol/parser.c", "items": [item]}]})
    final = orch.review_one_function(gap, shared, live.config, reviewer, orch.OrchestratorResult(),
                                     knowledge_runtime=live.runtime)
    assert len(calls) == 1
    assert final.line == 25  # assigned by the real caller, never by the test
    assert bool(supported(publish(live))) is (request_state == "explicit")
    phases = [row for row in load_verified_audit_log(live.out)
              if row.get("action") == "conditional_phase_diagnostic"]
    returned = next(row for row in phases if row["phase"] == "review-return")
    checked = next(row for row in phases if row["phase"] == "intake")
    expected = {"explicit": "closed-valid", "omitted": "null", "empty": "empty", "null": "null"}
    assert returned["field_state"] == checked["field_state"] == expected[request_state]
    assert returned["line"] == 0 and checked["line"] == 25
    assert returned["schema_offered"] is True
    assert returned["grant_current"] is (request_state != "empty")
    assert checked["grant_current"] is False
    assert checked["pending_count"] == (1 if request_state == "explicit" else 0)
    for phase in phases:
        assert phase["role"] == "availability-only-not-authority"
        assert not {"body", "source", "request", "hypothesis", "fact_event"} & phase.keys()


def test_request_phase_diagnostics_are_bounded_and_model_spoofing_is_dropped():
    from core.audit.conditional_claim_pipeline import DELIVERY_FIELD, request_field_diagnostic
    from core.audit.evidence_grade import drop_pipeline_owned
    secret = "owned sentinel never retained"
    for request in [{"body": secret}, [secret] * 9, [{"declared_cwe": secret}], None]:
        diagnostic = request_field_diagnostic({REQUEST_FIELD: request})
        assert secret not in json.dumps(diagnostic)
        assert set(diagnostic) == {"field_state", "valid_count"}
        assert diagnostic["valid_count"] == 0
    assert request_field_diagnostic({})["field_state"] == "missing"
    assert DELIVERY_FIELD not in drop_pipeline_owned({DELIVERY_FIELD: {"schema_offered": True}})


def test_phase_diagnostic_io_failure_cannot_change_conditional_admission(live, monkeypatch):
    from core.audit import record
    append = record.append_audit_log
    failures = []

    def failed_diagnostic(out, event):
        if event.get("action") == "conditional_phase_diagnostic":
            failures.append(event["phase"])
            raise OSError("owned diagnostic-only write fault")
        return append(out, event)

    monkeypatch.setattr(record, "append_audit_log", failed_diagnostic)
    review(live, [declaration()])
    intake(live)
    assert supported(publish(live))
    assert failures == ["review-return", "intake"]
