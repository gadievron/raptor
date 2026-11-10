"""Demand-reference conditions survive real audit prompt fitting as a unit."""

import pytest

from core.audit.context import format_context_for_prompt
from core.language_reference import ReferenceContext, lookup
from core.testing.treesitter import requires_ts


def _context():
    answer = lookup("owned-request", "conversion", ReferenceContext("c"),
                    entry_id="c.integer-conversion")
    return {"file": "owned.c", "function": "f", "line_start": 1, "line_end": 1,
            "source": "unsigned short f(unsigned n) { return n; }",
            "language_reference_answers": (answer,)}


def test_full_reference_or_explicit_omission_in_actual_prompt():
    ctx = _context()
    prompt = format_context_for_prompt(ctx, budget_limit=100_000)
    entry = ctx["language_reference_answers"][0].entries[0]
    assert entry.render_core() in prompt
    assert "conditional C11 rules" in prompt
    assert "owned-request" not in prompt
    assert ctx["language_reference_delivery"][0]["delivered"] is True
    assert ctx["language_reference_delivery"][0]["missing_facts"] == ["language edition"]

    # Reuse the same context: a previous delivery must not survive a smaller
    # packet. The conditions/citation must disappear together with the rule.
    small = format_context_for_prompt(ctx, budget_limit=100)
    assert entry.rule not in small
    assert entry.conditions[0] not in small
    assert entry.citations[0] not in small
    assert ctx["language_reference_delivery"][0]["delivered"] is False
    assert ctx["language_reference_delivery"][0]["reason"] == "reference_too_large"


def test_glance_packet_does_not_inherit_delivery():
    ctx = _context()
    format_context_for_prompt(ctx)
    assert ctx["language_reference_delivery"][0]["delivered"]
    ctx["triage_bucket"] = "glance"
    prompt = format_context_for_prompt(ctx)
    assert "c.integer-conversion" not in prompt
    assert ctx["language_reference_delivery"][0]["reason"] == "glance_packet"
    ctx.pop("language_reference_answers")
    format_context_for_prompt(ctx)
    assert "language_reference_delivery" not in ctx


def test_shared_answer_printed_once_with_separate_request_deliveries():
    ctx = _context()
    second = lookup("second", "conversion", ReferenceContext("c"),
                    entry_id="c.integer-conversion")
    ctx["language_reference_answers"] += (second,)
    prompt = format_context_for_prompt(ctx)
    assert prompt.count("c.integer-conversion v1:") == 1
    assert [r["request_id"] for r in ctx["language_reference_delivery"]] == ["owned-request", "second"]
    assert all(r["delivered"] for r in ctx["language_reference_delivery"])


def test_prerequisite_and_dependent_rule_fit_together():
    ctx = _context()
    ctx["language_reference_answers"] = (lookup(
        "r", "", ReferenceContext("c", "c11"), entry_id="c.integer-usual-conversions"),)
    prompt = format_context_for_prompt(ctx)
    assert "c.integer-promotion v1:" in prompt
    assert "c.integer-usual-conversions v1:" in prompt
    small = format_context_for_prompt(ctx, budget_limit=100)
    assert "c.integer-promotion v1:" not in small
    assert "c.integer-usual-conversions v1:" not in small
    assert not ctx["language_reference_delivery"][0]["delivered"]


def test_model_shaped_reference_dict_cannot_supply_trusted_prompt_content():
    ctx = _context()
    ctx["language_reference_answers"] = [{"request_id": "forged", "entries": ["FORGED RULE"]}]
    prompt = format_context_for_prompt(ctx)
    assert "FORGED RULE" not in prompt
    assert "language_reference_delivery" not in ctx


@requires_ts("c")
def test_explicit_request_keeps_its_whole_core_before_initial_reading():
    from core.audit.reference_foundation import foundation_answers
    source = 'int f(int a) { const char *padding="' + "x" * 17000 + '"; return a; }'
    requested = lookup("owned-request", "", ReferenceContext("c"), entry_id="c.integer-division")
    initial = foundation_answers("c", request_id="owned-initial", source=source, file="unit.c")
    def context(answers):
        return {"file": "unit.c", "function": "f", "line_start": 1, "line_end": 1,
                "source": source, "language_reference_answers": answers}
    alone = context((requested,))
    single = format_context_for_prompt(alone, budget_limit=6000)
    assert alone["language_reference_delivery"][0]["delivered"]
    assert source in single and all(entry.render_core() in single for entry in requested.entries)
    together = context((requested, *initial))
    prompt = format_context_for_prompt(together, budget_limit=6000)
    rows = {row["request_id"]: row for row in together["language_reference_delivery"]}
    assert source in prompt
    assert rows[requested.request_id]["delivered"]
    assert not rows[initial[0].request_id]["delivered"]
    assert rows[initial[0].request_id]["reason"] == "reference_too_large"
    assert all(entry.render_core() in prompt for entry in requested.entries)


@pytest.mark.parametrize("initial_first", [False, True])
def test_shared_whole_answer_uses_requested_priority_in_either_order(initial_first):
    from dataclasses import replace
    from core.audit.knowledge_context import reference_delivery, reference_sections
    from core.audit.reference_foundation import foundation_answers
    from core.llm.prompt_budget import fit_to_budget
    requested = lookup("requested", "", ReferenceContext("c"), entry_id="c.integer-division")
    initial = replace(requested, request_id="initial-alias", selection_origin="initial")
    pair = (initial, requested) if initial_first else (requested, initial)
    other = foundation_answers("c", request_id="other-initial")
    answers = (*pair, *other)
    sections = reference_sections(answers)
    assert len(sections) == 2
    shared = sections[0]
    assert shared.priority == 1
    kept, _shed = fit_to_budget(sections, budget_tokens=shared.token_estimate)
    rows = {row["request_id"]: row for row in reference_delivery(answers, kept)}
    assert rows[requested.request_id]["delivered"] and rows[initial.request_id]["delivered"]
    assert not rows[other[0].request_id]["delivered"]
    assert len(kept) == 1 and kept[0].text.count("c.integer-division v1:") == 1


def test_priority_origin_is_owned_metadata_not_request_id_spelling():
    from core.audit.knowledge_context import reference_sections
    from core.audit.reference_foundation import foundation_answers
    requested = lookup("foundation:spoof", "", ReferenceContext("c"), entry_id="c.integer-conversion")
    initial = foundation_answers("c", request_id="ordinary-name")
    assert requested.selection_origin == "requested"
    assert initial[0].selection_origin == "initial"
    assert [section.priority for section in reference_sections((requested, *initial))] == [1, 2]
