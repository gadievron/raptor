"""Selection limitations survive actual prompt fitting and delivery records."""

from dataclasses import replace

import pytest

from core.audit.context import format_context_for_prompt
from core.audit.reference_foundation import foundation_answers
from core.testing.treesitter import requires_ts


_SOURCE = "int f(int a, int b) { return a + b; }"


def _ctx(answers):
    return {"file": "unit.c", "function": "f", "line_start": 1, "line_end": 1,
            "source": _SOURCE, "language_reference_answers": answers}


def test_parser_unavailable_is_visible_separately_from_successful_delivery(monkeypatch):
    monkeypatch.setattr("core.audit.ts_extract._parse_file", lambda *args: None)
    answers = foundation_answers("c", request_id="owned", source=_SOURCE, file="unit.c")
    ctx = _ctx(answers)
    prompt = format_context_for_prompt(ctx, budget_limit=100_000)
    delivery, = ctx["language_reference_delivery"]
    assert delivery["delivered"] and delivery["reason"] == "delivered"
    assert "parser unavailable" in delivery["resolution_reason"]
    assert "parser unavailable" in prompt
    assert "fixed foundation only" in prompt
    assert "c.integer-promotion v1:" in prompt

    small = format_context_for_prompt(ctx, budget_limit=100)
    omitted, = ctx["language_reference_delivery"]
    assert not omitted["delivered"] and omitted["reason"] == "reference_too_large"
    assert omitted["resolution_reason"] == delivery["resolution_reason"]
    assert "c.integer-promotion v1:" not in small


@requires_ts("c")
@pytest.mark.parametrize("source,reason", [
    pytest.param("int f( { a +", "parse errors", id="syntax-error"),
    pytest.param(" " * (256 * 1024 + 1), "source limit", id="source-limit"),
    pytest.param("int f(int a) { a + 1;" + "a;" * 3000 + "}", "traversal limit", id="node-limit"),
])
def test_selection_limits_are_recorded_without_losing_fixed_rules(source, reason):
    answers = foundation_answers("c", request_id="owned", source=source, file="unit.c")
    ctx = _ctx(answers)
    format_context_for_prompt(ctx, budget_limit=100_000)
    delivery, = ctx["language_reference_delivery"]
    assert reason in delivery["resolution_reason"]
    assert {entry["id"] for entry in delivery["entries"]} == {
        "c.integer-promotion", "c.integer-conversion"}


def test_different_limitations_on_identical_entries_are_not_silently_coalesced():
    base, = foundation_answers("c", request_id="one")
    other = replace(base, request_id="two", reason="A separately recorded limitation.")
    ctx = _ctx((base, other))
    prompt = format_context_for_prompt(ctx, budget_limit=100_000)
    assert base.reason in prompt
    assert other.reason in prompt
    assert len(ctx["language_reference_delivery"]) == 2
    assert all(row["delivered"] for row in ctx["language_reference_delivery"])
