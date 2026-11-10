"""Exact reference requests retain fitting priority through owned continuations."""

from dataclasses import replace
from time import monotonic

import pytest

from core.audit.context import format_context_for_prompt
from core.audit.knowledge_context import reference_delivery, reference_sections
from core.audit.knowledge_requests import KnowledgeOrigin
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.orchestrator import StudyQueue
from core.audit.refutation_source import capture_source_identity
from core.language_reference import ReferenceAnswer, ReferenceContext, lookup
from core.llm.prompt_budget import fit_to_budget


@pytest.mark.parametrize("exact_first", [True, False])
def test_exact_id_priority_survives_owned_continuation(tmp_path, exact_first):
    source = 'int f(int a) { const char *padding="' + "x" * 17500 + '"; return a; }'
    (tmp_path / "unit.c").write_text(source)
    runtime = AuditKnowledgeRuntime(tmp_path, StudyQueue(), deadline=float("inf"))
    origin = KnowledgeOrigin("owned", "unit.c", "f", 1, 1,
                             capture_source_identity(tmp_path, "unit.c"))
    requests = [{"topic": "integer division", "entry_id": "c.integer-division"},
                {"topic": "scalar logical"}]
    if not exact_first:
        requests.reverse()
    ctx = {"file": "unit.c", "function": "f", "line_start": 1, "line_end": 1,
           "source": source, "language": "c"}
    try:
        runtime._register(origin, ctx, {"language_reference_requests": requests})
        accepted = runtime.requests()
        exact, = (r for r in accepted if r.entry_id is not None)
        topic, = (r for r in accepted if r.entry_id is None)
        reservation, = runtime.ready_continuations(admission=lambda: True, now=monotonic()+20)
        assert runtime.enrich_context(ctx, reservation)
        answers = ctx["language_reference_answers"]
        assert {a.request_id for a in answers} == {exact.request_id, topic.request_id}
        exact_answer, = (a for a in answers if a.request_id == exact.request_id)
        topic_answer, = (a for a in answers if a.request_id == topic.request_id)
        # This is an ordering control, not an incidental shared-content omission.
        assert {e.entry_id for e in exact_answer.entries}.isdisjoint(
            e.entry_id for e in topic_answer.entries)
        # Establish that the whole exact answer fits beside the same source.
        alone = {**ctx, "language_reference_answers": (exact_answer,)}
        single = format_context_for_prompt(alone, budget_limit=6000)
        assert alone["language_reference_delivery"][0]["delivered"]
        assert source in single
        prompt = format_context_for_prompt(ctx, budget_limit=6000)
        delivery = {row["request_id"]: row for row in ctx["language_reference_delivery"]}
        assert source in prompt
        assert delivery[exact.request_id]["delivered"]
        assert not delivery[topic.request_id]["delivered"]
        assert delivery[topic.request_id]["reason"] == "reference_too_large"
        assert all(entry.render_core() in prompt for entry in exact_answer.entries)
        assert runtime.can_publish(reservation)
    finally:
        runtime.close("test_complete_without_dispatch")


def test_lookup_request_kind_is_per_request_not_id_spelling_or_cached_template():
    context = ReferenceContext("c")
    exact = lookup("topic-looking-name", "", context, entry_id="c.integer-conversion")
    cached_exact = lookup("another-name", "", context, entry_id="c.integer-conversion")
    topic = lookup("entry:c.integer-conversion", "integer conversion", context)
    assert exact.selection_kind == cached_exact.selection_kind == "entry_id"
    assert topic.selection_kind == "topic"
    assert exact.request_id != cached_exact.request_id
    assert exact.entries == cached_exact.entries == topic.entries
    assert exact.status == topic.status == "needs_target_facts"
    assert exact.missing_facts == topic.missing_facts == ("language edition",)


@pytest.mark.parametrize("exact_first", [True, False])
def test_identical_answer_group_inherits_exact_request_priority(exact_first):
    context = ReferenceContext("c")
    exact = lookup("opaque-one", "", context, entry_id="c.integer-conversion")
    topic = lookup("opaque-two", "integer conversion", context)
    other = lookup("other-topic", "integer division", context)
    pair = (exact, topic) if exact_first else (topic, exact)
    answers = (*pair, other)
    sections = reference_sections(answers)
    assert len(sections) == 2
    assert sections[0].priority < sections[1].priority
    kept, _ = fit_to_budget(sections, budget_tokens=sections[0].token_estimate)
    delivery = {r["request_id"]: r for r in reference_delivery(answers, kept)}
    assert delivery[exact.request_id]["delivered"]
    assert delivery[topic.request_id]["delivered"]
    assert not delivery[other.request_id]["delivered"]
    assert len(kept) == 1


def test_unavailable_exact_id_does_not_outrank_useful_topic_or_initial():
    context = ReferenceContext("c")
    exact = lookup("owned", "", context, entry_id="c.integer-division")
    topic = lookup("topic", "integer conversion", context)
    initial = replace(exact, request_id="initial", selection_origin="initial")
    missing = lookup("missing", "", context, entry_id="c.does-not-exist")
    sections = reference_sections((missing, initial, topic))
    assert sections[2].priority < sections[1].priority < sections[0].priority
    unavailable_default = ReferenceAnswer("legacy", "unsupported")
    assert reference_sections((unavailable_default,))[0].priority == sections[0].priority


def test_lookup_kind_cannot_change_content_identity_or_renew_delivery_credit():
    from core.audit.reference_inputs import (
        reference_answer_already_delivered, reference_inputs_digest,
        reference_inputs_from_delivery,
    )
    exact = lookup("owned", "", ReferenceContext("c"), entry_id="c.integer-conversion")
    topic = replace(exact, selection_kind="topic")
    exact_delivery = reference_delivery((exact,), reference_sections((exact,)))
    topic_delivery = reference_delivery((topic,), reference_sections((topic,)))
    assert exact_delivery == topic_delivery
    exact_inputs = reference_inputs_from_delivery(exact_delivery, (exact,))
    topic_inputs = reference_inputs_from_delivery(topic_delivery, (topic,))
    assert exact_inputs == topic_inputs
    assert reference_inputs_digest(exact_inputs) == reference_inputs_digest(topic_inputs)
    assert reference_answer_already_delivered(exact, topic_inputs)
    assert reference_answer_already_delivered(topic, exact_inputs)
    omitted_inputs = reference_inputs_from_delivery(reference_delivery((topic,), []), (topic,))
    assert omitted_inputs is None
    assert not reference_answer_already_delivered(exact, omitted_inputs)
