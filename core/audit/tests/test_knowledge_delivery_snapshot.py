"""Prompt fitting belongs to an invocation, never a shared panel dictionary."""

from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from threading import Barrier
from time import monotonic

import pytest

from core.audit.context import format_context_for_prompt
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import OrchestratorConfig
from core.audit.tests.test_knowledge_reference_delivery import _context as reference_context
from core.audit.tests.test_knowledge_study_delivery import _context as study_context
from core.audit.tests.test_knowledge_runtime_coordinator import _runtime
from core.audit.tests.test_knowledge_runtime import _source_study_case, _consume_source_case
from core.llm.providers import StructuredResponse


@pytest.mark.parametrize("factory,field", [
    (reference_context, "language_reference_delivery"),
    (study_context, "source_study_delivery"),
], ids=["reference", "study"])
@pytest.mark.parametrize("mode", ["full", "small", "glance"])
def test_renderer_snapshot_is_local_and_discloses_omissions(factory, field, mode):
    ctx, observed = factory(), []
    if mode == "glance":
        ctx["triage_bucket"] = "glance"
    format_context_for_prompt(ctx, budget_limit=100 if mode == "small" else 100000,
                              knowledge_delivery_sink=observed.append)
    snapshot, = observed
    assert set(snapshot) == {"language_reference_delivery", "source_study_delivery"}
    assert snapshot[field][0]["delivered"] is (mode == "full")
    if mode == "glance":
        assert snapshot[field][0]["reason"] == "glance_packet"
    ctx[field][0]["delivered"] = not snapshot[field][0]["delivered"]
    assert ctx[field] != snapshot[field]
    if mode == "full":
        format_context_for_prompt(ctx, budget_limit=100)
        assert snapshot[field][0]["delivered"] is True


@pytest.mark.parametrize("kind", ["reference", "study"])
@pytest.mark.parametrize("retain_prior", [False, True])
def test_completed_assessment_ignores_another_panel_members_shared_delivery(tmp_path, monkeypatch, kind, retain_prior):
    if kind == "reference":
        runtime, ctx = _runtime(tmp_path)
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    else:
        case = _source_study_case(tmp_path)
        _consume_source_case(case)
        _, config, _, runtime, _, _, _, _ = case
        ctx = {"file": "owned.c", "function": "f", "line_start": 2,
               "source": (tmp_path / "owned.c").read_text().splitlines()[1], "language": "c"}
    reservation, = runtime.ready_continuations(admission=lambda: True,
                                                now=monotonic() + 1, required_calls=2)
    assert runtime.enrich_context(ctx, reservation)
    field = "language_reference_delivery" if kind == "reference" else "source_study_delivery"
    request_id = (reservation.packet.references or reservation.packet.explanations)[0].request_id
    monkeypatch.setattr("core.audit.llm_review._prompt_budget",
                        lambda _ctx, system: 100 if system == "small" else 100000)
    barrier = Barrier(2)
    returned = []

    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            barrier.wait(timeout=10)
            return StructuredResponse(result={"status": "clean", "body": "Scripted assessment",
                # Neither response can mint its own fitting metadata.
                "language_reference_delivery": [{"request_id": request_id, "delivered": True}],
                "source_study_delivery": [{"request_id": request_id, "delivered": True}]},
                raw="", cost=0, model="scripted")

    small = make_review_fn(Client(), system_prompt="small", escalate_clean=False)
    large = make_review_fn(Client(), system_prompt="large", escalate_clean=False)

    def panel(shared, cfg):
        with ThreadPoolExecutor(max_workers=2) as pool:
            a = pool.submit(copy_context().run, small, shared, cfg)
            b = pool.submit(copy_context().run, large, shared, cfg)
            first, second = a.result(timeout=15), b.result(timeout=15)
        returned.extend((first, second))
        shared[field] = second.review_result[field]
        return first

    panel._knowledge_observed_client_contract = True
    selected = runtime.wrap_review(panel)(ctx, config)
    assert selected.review_result[field][0]["delivered"] is False
    assert returned[1].review_result[field][0]["delivered"] is True
    assert ctx[field][0]["delivered"] is True
    assert runtime.complete(reservation, ctx, published_status="suspicious" if retain_prior else selected.status,
                            reason="prior_retained" if retain_prior else "completed")
    completed = [event for event in runtime.events() if event["event"] == "continuation_completed"][-1]
    assert completed["delivered_request_ids"] == []
    recorded = [event for event in runtime.events() if event["event"] == "review_prompt_context"][-1]
    assert recorded["renderer_observed"]
    assert all(not row["delivered"] for row in recorded["records"] if row["field"] == field)
    assert not runtime._knowledge_deliveries


@pytest.mark.parametrize("failed", [False, True], ids=["completed", "failed"])
def test_shared_context_alone_cannot_claim_review_delivery(tmp_path, failed):
    runtime, ctx = _runtime(tmp_path)
    reservation, = runtime.ready_continuations(admission=lambda: True)
    assert runtime.enrich_context(ctx, reservation)
    request_id = reservation.packet.references[0].request_id
    ctx["language_reference_delivery"] = [{"request_id": request_id, "delivered": True}]
    if failed:
        assert runtime.fail(reservation, "review_did_not_return", ctx)
    else:
        assert runtime.complete(reservation, ctx)
    prompt = [event for event in runtime.events() if event["event"] == "review_prompt_context"][-1]
    assert prompt["records"] == [] and prompt["renderer_observed"] is False
    terminal = [event for event in runtime.events()
                if event["event"] in ("continuation_completed", "continuation_failed")][-1]
    if failed:
        assert "delivered_request_ids" not in terminal
        assert terminal["published_status"] == ""
    else:
        assert terminal["delivered_request_ids"] == []
