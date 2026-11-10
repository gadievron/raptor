"""Withdrawal can reference only material delivered to this model invocation."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from threading import Barrier

import pytest

from core.audit import orchestrator as orch
from core.audit.claims import ClaimRevision
from core.audit.context import format_context_for_prompt
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.review_claims import begin_review, prepare_history_presentation, record_intake
from core.llm.providers import StructuredResponse


def case(tmp_path):
    source = "unsigned f(unsigned n) { return n; }\n"
    (tmp_path / "owned.c").write_text(source)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "run")
    runtime = AuditKnowledgeRuntime(tmp_path, orch.StudyQueue(), deadline=float("inf"))
    ctx = {"file": "owned.c", "function": "f", "line_start": 1, "source": source, "language": "c"}
    prior = orch.ReviewOutcome(file="owned.c", function="f", line=1, status="suspicious", body="prior",
        hypothesis="negative n reaches the return", review_result={"cwe": "CWE-195"})
    revisions = [ClaimRevision(h, pass_id="intake", file="owned.c", function="f", line_start=1)
                 for h in orch._extract_all_hypotheses(prior)]
    prior.review_result["review_claims"] = record_intake(begin_review(runtime._origin(ctx), "first"), revisions)
    ctx["prior_review_claims"] = prior.review_result["review_claims"]
    return config, runtime, ctx, prior


def test_presentation_quarantines_conflicts_even_when_one_variant_exceeds_prompt_cap(tmp_path):
    _, _, ctx, prior = case(tmp_path)
    value = deepcopy(prior.review_result["review_claims"])
    row = deepcopy(value["intakes"][0]["claims"][0])
    row["hypothesis"]["counter"] = "x" * 12000
    value["intakes"][0]["claims"].append(row)
    text, delivered = prepare_history_presentation(value, max_bytes=2048)
    assert delivered == []
    assert "invalid-or-conflicting-revision-definition" in text
    assert ctx["prior_review_claims"] != value


def test_budget_shedding_and_source_elision_cannot_deliver_claim_authority(tmp_path):
    _, _, ctx, _ = case(tmp_path)
    received = []
    prompt = format_context_for_prompt(ctx, budget_limit=100000, claim_delivery_sink=received.append)
    assert received[0]["claims"] and received[0]["source_fragment"]
    assert received[0]["source_fragment"]["fragment_id"] in prompt
    small = []
    format_context_for_prompt(ctx, budget_limit=100, claim_delivery_sink=small.append)
    assert small[0]["claims"] == []
    ctx["source"] = "\n".join("int repeated_source_line = 1;" for _ in range(500))
    elided = []
    format_context_for_prompt(ctx, budget_limit=100, claim_delivery_sink=elided.append)
    assert any(e["label"] == "source" for e in ctx["prompt_budget_event"]["elisions"])
    assert elided[0]["source_fragment"] is None


def test_glance_or_initial_review_has_no_claim_delivery(tmp_path):
    _, _, ctx, _ = case(tmp_path)
    received = []
    format_context_for_prompt({**ctx, "triage_bucket": "glance"}, claim_delivery_sink=received.append)
    assert received == []
    ctx.pop("prior_review_claims")
    format_context_for_prompt(ctx, claim_delivery_sink=received.append)
    assert received == []


def test_parser_freezes_its_own_delivery_before_model_mutates_context(tmp_path, monkeypatch):
    config, _, ctx, prior = case(tmp_path)
    reference = prior.review_result["review_claims"]["intakes"][0]["claims"][0]["reference"]
    monkeypatch.setattr("core.audit.llm_review._prompt_budget", lambda *_: 100000)
    schemas = []
    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            schemas.append(schema)
            assert reference["revision_id"] in prompt
            ctx["prior_review_claims"] = None
            ctx["source"] = "changed mutable context"
            return StructuredResponse(result={"status": "clean", "body": "review",
                "claim_review_delivery": {"role": "model-forged"}}, raw="", cost=0, model="scripted")
    outcome = make_review_fn(Client(), escalate_clean=False)(ctx, config)
    packet = outcome.review_result["claim_review_delivery"]
    assert packet["claims"][0]["reference"] == reference
    assert packet["source_fragment"]["source"] == "unsigned f(unsigned n) { return n; }\n"
    assert "claim_withdrawals" in schemas[0]["properties"]
    assert packet["role"] == "review-delivery-only"


def test_shared_context_panel_does_not_credit_another_members_larger_prompt(tmp_path, monkeypatch):
    config, _, ctx, _ = case(tmp_path)
    barrier = Barrier(2)
    monkeypatch.setattr("core.audit.llm_review._prompt_budget", lambda _ctx, system: 100 if system == "small" else 100000)
    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            barrier.wait(timeout=10)
            return StructuredResponse(result={"status": "clean", "body": "review"}, raw="", cost=0, model="scripted")
    small = make_review_fn(Client(), system_prompt="small", escalate_clean=False)
    large = make_review_fn(Client(), system_prompt="large", escalate_clean=False)
    with ThreadPoolExecutor(max_workers=2) as executor:
        a = executor.submit(small, ctx, config)
        b = executor.submit(large, ctx, config)
        first, second = a.result(timeout=15), b.result(timeout=15)
    assert first.review_result["claim_review_delivery"]["claims"] == []
    assert second.review_result["claim_review_delivery"]["claims"]


@pytest.mark.parametrize("fault", ["none", "mechanical_support", "source_drift", "missing_secondary", "remaining_unknowns", "unmapped_raw_variant", "duplicate_raw", "caller_context_pending"])
def test_model_judgment_admission_never_reconstructs_a_refutation(tmp_path, monkeypatch, fault):
    import re

    from core.audit.refutation_source import capture_source_identity

    config, runtime, ctx, prior = case(tmp_path)
    monkeypatch.setattr("core.audit.llm_review._prompt_budget", lambda *_: 100000)
    reference = prior.review_result["review_claims"]["intakes"][0]["claims"][0]["reference"]
    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            fragment_id = re.search(r"Source fragment:\*\* ([a-f0-9]{32})", prompt)[1]
            proposal = {**{k: reference[k] for k in ("claim_id", "revision_id")},
                "corrected_premise": "n is unsigned in the supplied declaration",
                "reason": "The stated negative-n theory used a signed parameter premise.",
                "source_anchors": [{"fragment_id": fragment_id, "line_start": 1, "line_end": 1}],
                "remaining_unknowns": ["caller behaviour"] if fault == "remaining_unknowns" else []}
            payload = {"status": "clean", "body": "Model corrected its premise.",
                       "hypothesis": "", "claim_withdrawals": [proposal]}
            if fault == "caller_context_pending":
                payload["caller_context_requests"] = [{"file": "caller.c", "function": "caller",
                    "line_start": 1, "reason": "Caller behaviour is still unknown"}]
            return StructuredResponse(result=payload, raw="", cost=0, model="scripted")
    fresh = runtime.wrap_review(make_review_fn(Client(), escalate_clean=False))(ctx, config)
    fresh.line = 1
    if fault == "mechanical_support":
        prior.evidence_tool = "frida:runtime"
    elif fault == "source_drift":
        (tmp_path / "owned.c").write_text("unsigned f(unsigned n) { return n + 1; }\n")
    elif fault == "missing_secondary":
        prior.hypotheses = [{"mechanism": "independent concern", "confidence": "high"}]
    elif fault == "duplicate_raw":
        original = deepcopy(prior.review_result["review_claims"]["intakes"][0]["claims"][0]["hypothesis"])
        prior.hypotheses = [original, {**original, "confidence": "medium", "counter": ""}]
    elif fault == "unmapped_raw_variant":
        original = deepcopy(prior.review_result["review_claims"]["intakes"][0]["claims"][0]["hypothesis"])
        # This second raw proposal had no intake identity after mechanism-only
        # normalisation. It must not disappear through the first proposal's ID.
        prior.hypotheses = [original, {**original, "assumed_property": "caller enforces a separate length bound",
                                       "counter_scope": "cross_function"}]
        assert len(orch._extract_all_hypotheses(prior)) == 1
    report = orch._model_withdrawal_assessment(config, prior, fresh,
                                             capture_source_identity(tmp_path, "owned.c"))
    assert report["admissible"] is (fault in ("none", "duplicate_raw"))
    assert fresh.claim_refutations == ()
    assert not fresh.evidence_tool
    if fault in ("none", "duplicate_raw"):
        assert report["accepted"][0]["adjudication"] == "model_withdrawn"
        assert fresh.review_result["review_claims"]["assessment_basis"] == "model_judgment_withdrawal"


def test_source_fragment_and_rendering_share_one_source_snapshot(tmp_path, monkeypatch):
    from core.audit import review_claims

    _, _, ctx, _ = case(tmp_path)
    original_source = ctx["source"]
    original = review_claims.source_fragment
    def mutate_after_snapshot(**kwargs):
        fragment = original(**kwargs)
        ctx["source"] = "int source_replaced_between_reads(void) { return -1; }"
        return fragment
    monkeypatch.setattr(review_claims, "source_fragment", mutate_after_snapshot)
    received = []
    prompt = format_context_for_prompt(ctx, claim_delivery_sink=received.append)
    assert received[0]["source_fragment"]["source"] == original_source
    assert original_source.rstrip() in prompt
    assert "source_replaced_between_reads" not in prompt


def test_first_pass_does_not_pay_for_withdrawal_schema_or_source_packet(tmp_path, monkeypatch):
    config, _, ctx, _ = case(tmp_path)
    ctx.pop("prior_review_claims")
    schemas = []
    monkeypatch.setattr("core.audit.llm_review._prompt_budget", lambda *_: 100000)
    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            schemas.append(schema)
            assert "Source fragment:" not in prompt
            return StructuredResponse(result={"status": "clean", "body": "review"}, raw="", cost=0, model="scripted")
    outcome = make_review_fn(Client(), escalate_clean=False)(ctx, config)
    assert "claim_withdrawals" not in schemas[0]["properties"]
    assert "claim_review_delivery" not in outcome.review_result


@pytest.mark.parametrize("same_label", [False, True], ids=["distinct-labels", "distinct-material"])
def test_scoped_negative_and_model_withdrawal_cover_distinct_prior_claims(tmp_path, monkeypatch, same_label):
    import re

    from core.audit.refutation_source import capture_source_identity
    from core.audit.verification_results import ClaimRefutation, ProbeOutcome

    config, runtime, ctx, prior = case(tmp_path)
    prior.hypotheses = [{"mechanism": "an independent later copy ignores allocation", "confidence": "high", "cwe": "CWE-787"}]
    hypotheses = orch._extract_all_hypotheses(prior)
    if same_label:
        # Exercise the negative-authority consumer with two complete intake
        # declarations; this does not claim production intake now preserves them.
        hypotheses[0].update(counter_scope="local", assumed_property="local declaration")
        hypotheses[1].update(mechanism=hypotheses[0]["mechanism"], cwe=hypotheses[0]["cwe"],
                             counter_scope="cross_function", assumed_property="caller declaration")
        prior.hypotheses = deepcopy(hypotheses)
        actual_extract = orch._extract_all_hypotheses
        monkeypatch.setattr(orch, "_extract_all_hypotheses",
                            lambda outcome: deepcopy(hypotheses) if outcome is prior else actual_extract(outcome))
    revisions = [ClaimRevision(h, pass_id="mixed-intake", file="owned.c", function="f", line_start=1) for h in hypotheses]
    prior.review_result["review_claims"] = record_intake(begin_review(runtime._origin(ctx), "mixed"), revisions)
    ctx["prior_review_claims"] = prior.review_result["review_claims"]
    reference = revisions[0].reference()
    monkeypatch.setattr("core.audit.llm_review._prompt_budget", lambda *_: 100000)
    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            fragment_id = re.search(r"Source fragment:\*\* ([a-f0-9]{32})", prompt)[1]
            return StructuredResponse(result={"status": "clean", "body": "Corrected premise.", "hypothesis": "",
                "claim_withdrawals": [{"claim_id": reference["claim_id"], "revision_id": reference["revision_id"],
                    "corrected_premise": "n is unsigned", "reason": "The signed parameter premise was wrong.",
                    "source_anchors": [{"fragment_id": fragment_id, "line_start": 1, "line_end": 1}],
                    "remaining_unknowns": []}]}, raw="", cost=0, model="scripted")
    fresh = runtime.wrap_review(make_review_fn(Client(), escalate_clean=False))(ctx, config)
    fresh.line = 1
    identity = capture_source_identity(tmp_path, "owned.c")
    # Model a channel's already admitted scoped negative; this control tests
    # the union policy, not native checker correctness or execution.
    fresh.claim_refutations = (ClaimRefutation("owned.c", "f", 1, hypotheses[1]["mechanism"],
        (ProbeOutcome("joern", "refuted", "owned-negative"),), identity),)
    report = orch._model_withdrawal_assessment(config, prior, fresh, identity)
    assert report["admissible"] is not same_label
    assert len(report["accepted"]) == 1
    assert report["accepted"][0]["reference"] == revisions[0].reference()
    assert report["accepted"][0]["adjudication"] == "model_withdrawn"
    if same_label:
        assert report["reason"] == "prior_claims_not_explicitly_withdrawn"
        assert "scoped_refuted_references" not in report
    else:
        assert report["scoped_refuted_references"] == [revisions[1].reference()]


def test_panel_merge_keeps_only_selected_responses_delivery_packet(tmp_path):
    from core.audit.multi_review import AuditVerdictAdapter

    _, _, ctx, _ = case(tmp_path)
    received = []
    format_context_for_prompt(ctx, claim_delivery_sink=received.append)
    full = received[0]
    absent = {"version": 1, "role": "review-delivery-only", "claims": [], "source_fragment": None}
    first = {"file": "owned.c", "function": "f", "status": "clean", "body": "first",
             "claim_review_delivery": absent,
             "caller_context_delivery": [{"request_id": "owned", "delivered": False}]}
    second = {"file": "owned.c", "function": "f", "status": "clean", "body": "second",
              "claim_review_delivery": full,
              "caller_context_delivery": [{"request_id": "owned", "delivered": True}]}
    merged, = AuditVerdictAdapter().merge({"first": [first], "second": [second]})
    assert merged["body"] == "first"
    assert merged["claim_review_delivery"] == absent
    assert merged["claim_review_delivery"] != full
    assert merged["caller_context_delivery"] == first["caller_context_delivery"]
