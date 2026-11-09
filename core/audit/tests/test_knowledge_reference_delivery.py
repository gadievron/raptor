"""Demand-reference conditions survive real audit prompt fitting as a unit."""

from core.audit.context import format_context_for_prompt
from core.language_reference import ReferenceContext, lookup


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
