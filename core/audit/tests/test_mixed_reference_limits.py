"""Unavailable reference notes accompany useful work without buying a pass."""

from dataclasses import replace

import pytest

from core.audit.context import format_context_for_prompt
from core.audit.knowledge_requests import register_requests
from core.audit.reference_inputs import reference_inputs_from_delivery
from core.audit.tests.test_review_cycle import SOURCE, _cycle, _reserve
from core.language_reference import ReferenceAnswer
from core.llm.prompt_budget import fit_to_budget
from core.audit.knowledge_context import reference_delivery, reference_sections


def test_unavailable_reference_accompanies_useful_packet_without_material_credit(tmp_path):
    cycle, identity, useful, explanation = _cycle(tmp_path)
    batch = register_requests({"language_reference_requests": [
        {"topic": "unreviewed topic", "entry_id": "c.unreviewed"}]}, cycle.origin)
    assert len(batch.accepted) == 1 and cycle.add_requests(batch)
    missing = ReferenceAnswer(batch.accepted[0].request_id, "unsupported",
                              reason="No reviewed entry covers this topic.")
    assert cycle.reference(useful, now=0)
    assert cycle.reference(missing, now=0)
    cycle.finished(explanation.request_id)
    packet = _reserve(cycle, identity, 1)
    assert packet is not None and cycle.started == 1
    assert packet.references == (useful, missing)
    assert packet.delta_ids == (useful.request_id,)

    ctx = {"file": "owned.c", "function": "f", "line_start": 1, "line_end": 2,
           "source": SOURCE, "language_reference_answers": packet.references}
    prompt = format_context_for_prompt(ctx, budget_limit=100_000)
    assert missing.reason in prompt
    assert useful.entries[0].render_core() in prompt
    records = {row["request_id"]: row for row in ctx["language_reference_delivery"]}
    assert records[useful.request_id]["delivered"]
    assert not records[missing.request_id]["delivered"]
    assert records[missing.request_id]["limitation_delivered"]
    manifest = reference_inputs_from_delivery(ctx["language_reference_delivery"], packet.references)
    assert manifest["complete"]
    assert {row["id"] for row in manifest["entries"]} == {entry.entry_id for entry in useful.entries}
    assert not cycle.complete(packet.pass_id, (useful.request_id, missing.request_id))
    assert cycle.complete(packet.pass_id, (useful.request_id,))
    assert _reserve(cycle, identity, 2, calls=2) is None


def test_only_unavailable_reference_never_buys_a_continuation(tmp_path):
    cycle, identity, useful, explanation = _cycle(tmp_path)
    missing = ReferenceAnswer(useful.request_id, "unsupported", reason="No reviewed entry.")
    cycle.reference(missing, now=0)
    cycle.finished(explanation.request_id)
    assert _reserve(cycle, identity, 1) is None
    assert cycle.started == 0


@pytest.mark.parametrize("origin", ["requested", "initial"])
def test_limitation_note_is_shed_before_available_reference_material(origin):
    from core.language_reference import ReferenceContext, lookup
    useful = lookup("useful", "", ReferenceContext("c"), entry_id="c.integer-conversion")
    useful = replace(useful, selection_origin=origin)
    missing = ReferenceAnswer("missing", "unsupported", reason="No reviewed entry.")
    sections = reference_sections((useful, missing))
    assert len(sections) == 2
    useful_section = sections[0]
    kept, _ = fit_to_budget(sections, useful_section.token_estimate)
    rows = reference_delivery((useful, missing), kept)
    assert rows[0]["delivered"]
    assert not rows[1]["delivered"] and not rows[1]["limitation_delivered"]


def test_withdrawn_useful_answer_does_not_leave_an_empty_dispatch_delta(tmp_path):
    cycle, identity, useful, explanation = _cycle(tmp_path)
    cycle.reference(useful, now=0)
    cycle.reference(ReferenceAnswer(useful.request_id, "unsupported", reason="Entry unavailable now."), now=1)
    cycle.finished(explanation.request_id)
    assert _reserve(cycle, identity, 2) is None
    assert cycle.started == 0
