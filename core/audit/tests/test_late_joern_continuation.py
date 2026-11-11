"""Late analysis shares actual review ownership and prompt-delivery admission."""
from __future__ import annotations

from time import monotonic
from types import SimpleNamespace

import pytest

from core.audit import llm_review, orchestrator as orch
from core.audit.continuation_context import context_version
from core.audit.knowledge_calls import KnowledgeCallRefused
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.late_joern_continuation import LateJoernContinuations
from core.audit.llm_review import make_review_fn
from core.audit.knowledge_requests import KnowledgeOrigin, register_requests
from core.audit.refutation_source import capture_source_identity
from core.audit.review_cycle import KnowledgeCycle
from core.language_reference import ReferenceContext, lookup
from core.llm.providers import StructuredResponse

SOURCE = "def owned(value):\n    return value\n"


class Client:
    def __init__(self):
        self.prompts = []
        self.status = "clean"
        self.after = lambda: None
        self.fail = False

    def generate_structured(self, prompt, schema, **kwargs):
        self.prompts.append(prompt)
        self.after()
        if self.fail:
            raise RuntimeError("owned scripted failure")
        return StructuredResponse(result={"status": self.status, "body": "Owned scripted assessment",
            "hypothesis": "Owned proposed concern" if self.status == "suspicious" else "",
            # Model text cannot supply the pipeline receipt.
            "external_context_delivery": [{"context_id": "forged", "delivered": True}]},
            raw="", cost=0, model="scripted")


@pytest.fixture
def owned(tmp_path, monkeypatch):
    path = tmp_path / "owned.py"
    path.write_text(SOURCE)
    cfg = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out",
        enable_session_context=False, sweep_validate_findings=False)
    monkeypatch.setattr(llm_review, "_prompt_budget", lambda *args: 0)
    runtime = AuditKnowledgeRuntime(tmp_path, orch.StudyQueue(), deadline=float("inf"))
    client = Client()
    review = make_review_fn(client, escalate_clean=False)
    ctx = {"file": "owned.py", "function": "owned", "line_start": 1, "line_end": 2,
           "source": SOURCE, "language": "python"}
    # Exercise the actual reviewer/client ownership contract first.
    prior = runtime.wrap_review(review)(dict(ctx), cfg)
    prior.line = 1
    ctx["mechanical_evidence"] = "Joern CPG: owned parameter value reaches owned_sink()"
    return path, cfg, runtime, client, review, ctx, prior


def _owner(runtime, review):
    return LateJoernContinuations(runtime, review, admission=lambda: True)


def test_actual_prompt_receipt_and_single_owner_release(owned):
    _, cfg, runtime, client, review, ctx, _ = owned
    owner = _owner(runtime, review)
    outcome = owner.dispatch(0, ctx, cfg)
    assert "owned_sink" in client.prompts[-1]
    rows = outcome.review_result["external_context_delivery"]
    assert len(rows) == 1 and rows[0]["delivered"] is True
    assert rows[0]["context_id"] != "forged"
    assert owner.can_publish(0)
    assert runtime.reserve_context_continuation(ctx, admission=lambda: True) is None
    assert owner.complete(0, "clean")
    with pytest.raises(KnowledgeCallRefused):
        owner.dispatch(1, dict(ctx), cfg)
    assert len(client.prompts) == 2
    assert len([e for e in runtime.events() if e["event"] == "continuation_reserved"]) == 1


def test_two_round_cap_shared_across_external_versions(owned):
    _, cfg, runtime, client, review, ctx, _ = owned
    owner = _owner(runtime, review)
    for index in range(2):
        ctx["mechanical_evidence"] += f"\nOwned delta {index}"
        owner.dispatch(index, ctx, cfg)
        assert owner.complete(index, "clean")
    ctx["mechanical_evidence"] += "\nThird relevant delta"
    with pytest.raises(KnowledgeCallRefused):
        owner.dispatch(3, ctx, cfg)
    assert len(client.prompts) == 3


def test_high_level_six_call_limit_cannot_be_bypassed_by_late_stage(owned):
    _, cfg, runtime, client, review, ctx, _ = owned
    gap = {"file": "owned.py", "name": "owned", "line_start": 1}
    for _ in range(5):
        assert runtime.admit_client_call(gap, "owned-other-attempt", "generate_structured")
    assert not runtime.admit_client_call(gap, "exhausted", "generate_structured")
    with pytest.raises(KnowledgeCallRefused):
        _owner(runtime, review).dispatch(0, ctx, cfg)
    assert len(client.prompts) == 1


def test_failed_dispatch_keeps_round_and_does_not_retry_identical_delta(owned):
    _, cfg, runtime, client, review, ctx, _ = owned
    owner = _owner(runtime, review)
    client.fail = True
    with pytest.raises(RuntimeError, match="owned scripted failure"):
        owner.dispatch(0, ctx, cfg)
    client.fail = False
    with pytest.raises(KnowledgeCallRefused):
        owner.dispatch(1, ctx, cfg)
    assert len(client.prompts) == 2
    assert any(e["event"] == "continuation_failed" for e in runtime.events())


def test_busy_initial_unit_defers_without_consuming_round(owned):
    _, _, runtime, _, _, ctx, _ = owned
    gap = {"file": "owned.py", "name": "owned", "line_start": 1}
    assert runtime.offer_context_delta(ctx, kind="late_joern", version=context_version(ctx["mechanical_evidence"]))
    def busy(gap):
        assert runtime.reserve_context_continuation(ctx, admission=lambda: True) is None
    runtime.wrap_unit(busy)(gap)
    packet = runtime.reserve_context_continuation(ctx, admission=lambda: True)
    assert packet is not None
    assert runtime.fail(packet, "test_retirement")


def test_stale_source_and_closed_owner_never_reopen(owned):
    path, cfg, runtime, client, review, ctx, _ = owned
    owner = _owner(runtime, review)
    client.after = lambda: path.write_text(SOURCE + "# changed during owned response\n")
    owner.dispatch(0, ctx, cfg)
    assert not owner.can_publish(0)
    assert owner.fail(0, "source_changed")
    runtime.close("test_terminal")
    path.write_text(SOURCE)
    with pytest.raises(KnowledgeCallRefused):
        owner.dispatch(1, ctx, cfg)
    assert len(client.prompts) == 2


def test_postfit_omission_has_no_external_delivery_credit(owned, monkeypatch):
    _, cfg, runtime, client, review, ctx, _ = owned
    monkeypatch.setattr(llm_review, "_prompt_budget", lambda *args: 100)
    ctx["mechanical_evidence"] = "Owned late Joern evidence " * 10000
    owner = _owner(runtime, review)
    outcome = owner.dispatch(0, ctx, cfg)
    assert not owner.can_publish(0)
    assert not any(row["delivered"] for row in outcome.review_result["external_context_delivery"])
    assert owner.fail(0, "context_not_delivered")


def test_knowledge_and_external_context_use_one_cycle_reservation(tmp_path):
    (tmp_path / "owned.c").write_text("int f(int x) { return x; }\n")
    identity = capture_source_identity(tmp_path, "owned.c")
    origin = KnowledgeOrigin("first", "owned.c", "f", 1, 1, identity)
    batch = register_requests({"language_reference_requests": [{"topic": "conversion"}]}, origin)
    request, = batch.accepted
    cycle = KnowledgeCycle(origin, batch, deadline=100, admit_study=lambda _: (True, ""))
    assert cycle.reference(lookup(request.request_id, request.subject, ReferenceContext("c")), now=0)
    assert cycle.context_delta("context:late_joern:owned-version", now=0)
    packet = cycle.reserve(now=0, current_source=identity, admission=lambda: True, all_model_calls=1)
    assert packet.references and packet.external_context_ids == ("context:late_joern:owned-version",)
    assert cycle.started == 1
    assert cycle.complete(packet.pass_id, (request.request_id, *packet.external_context_ids))


@pytest.mark.parametrize("stale", [False, True], ids=["publish", "source-changed"])
def test_actual_late_orchestrator_preserves_prior_until_owned_publication(owned, monkeypatch, stale):
    path, cfg, runtime, client, review, ctx, prior = owned
    client.status = "suspicious"
    if stale:
        client.after = lambda: path.write_text(SOURCE + "# changed\n")
    # Context extraction is an inert owned-source seam; dispatch, prompt fitting,
    # client admission, outcome accounting and publication are the real pipeline.
    monkeypatch.setattr(orch, "_build_context", lambda *a, **kw: dict(ctx))
    committed = []
    monkeypatch.setattr(orch, "_commit_outcome", lambda cfg, outcome, gap: committed.append(outcome))
    result = orch.OrchestratorResult(outcomes=[prior], clean=1)
    record = SimpleNamespace(all_joern_flows=lambda: ["owned saved flow"])
    kwargs = dict(checklist={"files": []}, context_map=None, fuzz_coverage=None,
        evidence_index={"owned.py:owned": record}, sarif_cache=None, entry_points=set(),
        gaps_before_joern=[{"file": "owned.py", "name": "owned", "line_start": 1, "line_end": 2}],
        start_time=monotonic(), on_progress=None, knowledge_runtime=runtime)
    assert orch._re_review_joern_enriched(result, cfg, review, **kwargs) is result
    assert len(client.prompts) == 2 and "owned_sink" in client.prompts[-1]
    if stale:
        assert result.outcomes == [prior] and not committed
    else:
        assert result.outcomes[0].status == "suspicious" and committed == result.outcomes
        assert any(e["event"] == "continuation_completed" for e in runtime.events())
    runtime.close("pipeline_closed")
    # A second post-pass cannot reset either the runtime or the model allowance.
    orch._re_review_joern_enriched(result, cfg, review, **kwargs)
    assert len(client.prompts) == 2


def test_identical_completed_joern_does_not_spend_unrelated_reference_delta(tmp_path, monkeypatch):
    path = tmp_path / "owned.c"
    path.write_text("int owned(int value) { return value; }\n")
    ctx = {"file": "owned.c", "function": "owned", "line_start": 1, "line_end": 1,
           "source": path.read_text(), "language": "c"}
    cfg = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    monkeypatch.setattr(llm_review, "_prompt_budget", lambda *args: 0)
    runtime = AuditKnowledgeRuntime(tmp_path, orch.StudyQueue(), deadline=float("inf"))
    client = Client()
    review = make_review_fn(client, escalate_clean=False)
    runtime.wrap_review(review)(dict(ctx), cfg)
    ctx["mechanical_evidence"] = "Owned saved Joern flow to owned_sink()"
    owner = _owner(runtime, review)
    owner.dispatch(0, ctx, cfg)
    assert owner.complete(0, "clean")
    # This is actual local registration/lookup, with the owned C scope and
    # no additional model/tool call. It is independent of the Joern version.
    runtime._register(runtime._origin(ctx), ctx, {"language_reference_requests": [
        {"topic": "integer arithmetic definedness", "entry_id": "c.integer-definedness"},
    ]})
    before_calls = len(client.prompts)
    before_rounds = len([e for e in runtime.events() if e["event"] == "continuation_reserved"])
    with pytest.raises(KnowledgeCallRefused):
        owner.dispatch(1, dict(ctx), cfg)
    assert len(client.prompts) == before_calls
    assert len([e for e in runtime.events() if e["event"] == "continuation_reserved"]) == before_rounds
    reservation, = runtime.ready_continuations(admission=lambda: True)
    assert reservation.packet.references and not reservation.packet.external_context_ids
    assert runtime.fail(reservation, "owned_test_retirement")


def test_busy_deferred_joern_version_remains_eligible_after_unit_releases(owned):
    _, cfg, runtime, client, review, ctx, _ = owned
    owner = _owner(runtime, review)
    gap = {"file": "owned.py", "name": "owned", "line_start": 1}
    def busy(gap):
        with pytest.raises(KnowledgeCallRefused):
            owner.dispatch(0, dict(ctx), cfg)
    runtime.wrap_unit(busy)(gap)
    assert len(client.prompts) == 1
    assert not any(e["event"] == "continuation_reserved" for e in runtime.events())
    owner.dispatch(1, dict(ctx), cfg)
    assert owner.can_publish(1)
    assert owner.complete(1, "clean")
    assert len(client.prompts) == 2
