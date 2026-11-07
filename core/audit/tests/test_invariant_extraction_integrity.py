"""Invariant discovery must not solve a supported fragment of another predicate."""

import pytest

from core.audit.invariant_smt import extract_invariants


@pytest.mark.parametrize("text", [
    "Count <= 0xff", "Count <= 0XFF", "Count <= 10U", "Count <= 10ULL",
    "Count <= 1e3", "Count <= 1.5", "Count <= 1.", "Count <= 1_000", "Count <= 1'000",
    "!(Count <= Limit)", "!((Count <= Limit))", "~(Count <= Limit)",
    "check(Count <= Limit)", "(Count <= Limit) == 0", "(Count <= Limit) != 0",
    "Count <= Limit == 0", "Count <= Limit != 0", "0 == Count <= Limit",
    "Count <= Limit ? Left : Right", "Flag ? Count <= Limit : Other",
    "Flag ? Other : Count <= Limit", "(Count <= Limit)",
    "Count <= Limit, Other", "Other, Count <= Limit",
    "Count <= Limit" + " " * 200 + "|| Other > 0",
    "Flag ? Other" + " " * 200 + ": Count <= Limit",
    "A" * 200 + " <= Limit", "Count <= " + "A" * 200,
    "prose " * 2000 + "Count <= Limit",
    "!(\nCount <= Limit\n)", "!(\n\nCount <= Limit\n\n)",
    "Flag ?\nCount <= Limit\n: Other", "Count <= Limit\n== 0",
    "Count <= Limit\n|| Other > 0", "Count <= Limit\n+ Offset",
    "Count <= State.\nLimit", "Count <= State\n.Limit",
])
def test_unsupported_predicates_or_truncated_tokens_do_not_mint_candidates(text):
    assert extract_invariants(text) == []


@pytest.mark.parametrize("text,expected", [
    ("the invariant Count <= Limit holds", "Count <= Limit"),
    ("Count <= Limit.", "Count <= Limit"),
    ("copy length is clamped: n <= min(avail, sizeof(Data))", "n <= min(avail, sizeof(Data))"),
    ("State->Count <= State->Limit always", "State->Count <= State->Limit"),
    ("Count <= 100 holds", "Count <= 100"),
    ("the invariant:\nCount <= Limit", "Count <= Limit"),
])
def test_complete_supported_comparisons_keep_prose_and_member_identity(text, expected):
    assert extract_invariants(text) == [expected]


def test_independent_statements_keep_order_and_deduplicate():
    assert extract_invariants("Count <= Limit; Used <= Capacity\nCount <= Limit", "Used <= Capacity") == [
        "Count <= Limit", "Used <= Capacity",
    ]


@pytest.mark.parametrize("text", ["!(Count <= Limit)", "Count <= 0xff", "Count <= Limit == 0",
                                "Count <= Limit; Used <= Capacity"])
def test_orchestrator_does_not_schedule_a_different_invariant(text):
    from core.audit.orchestrator import _hypothesis_to_tool_chain

    chain = _hypothesis_to_tool_chain(text, "unit.c")
    assert not any(step["type"] == "smt_invariant" for step in chain)


@pytest.mark.parametrize("text", ["!(largest_acked_pkt <= highest_sent)", "largest_acked_pkt <= 0xff",
                                "largest_acked_pkt <= highest_sent; lowest_state <= highest_state"])
def test_protocol_classifier_does_not_adopt_a_changed_comparison(text):
    from core.audit.protocol_state import classify_protocol_state_hypothesis

    _fires, invariant = classify_protocol_state_hypothesis(text)
    assert invariant is None


def test_standing_prepass_does_not_select_one_part_of_an_ambiguous_statement(monkeypatch):
    from core.audit import protocol_state

    monkeypatch.setattr(protocol_state, "build_state_field_index", lambda *a, **k: {"fields": {}, "tier": "fixture"})
    monkeypatch.setattr(protocol_state, "_invariant_receipt", lambda *a, **k: {"verified": True})

    def forbidden(*args, **kwargs):
        pytest.fail("ambiguous invariant reached the solver consumer")

    monkeypatch.setattr(protocol_state, "_adjudicate_invariant", forbidden)
    result = protocol_state.run_protocol_state_prepass({}, domain_model={"invariants": [
        {"statement": "Count <= Limit; Used <= Capacity"},
    ]})
    assert result["telemetry"]["invariants_checked"] == 0
