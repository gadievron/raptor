"""A source guard and a census transition must describe the same write."""

import pytest

from core.audit import protocol_state as protocol

pytestmark = pytest.mark.usefixtures("invariant_unit_worker")


@pytest.fixture(autouse=True)
def native_grammar():
    pytest.importorskip("z3")
    pytest.importorskip("tree_sitter_c")


def solve(source_body, census_code):
    source = "void Read(struct S *State,struct S *Other){\n" + source_body + "\n}"
    line = next(n for n, text in enumerate(source.splitlines(), 1) if "State->Count" in text and ";" in text)
    site = dict(file="unit.c", function="Read", line=line, code=census_code)
    return protocol.check_invariant_multi_site(
        "Count <= Limit", {"fields": {"Count": {"writes": [site]}}}, {"unit.c": source},
    )


@pytest.mark.parametrize("source_body,census_code", [
    ("State->Count++;", "State->Count=State->Limit;"),
    ("State->Count--;", "State->Count++;"),
    ("State->Count=Other->Value;", "State->Count=State->Limit;"),
    ("State->Count++;", "Other->Count++;"),
    ("State->Count++;", "if(State->Count<State->Limit){State->Count++;}"),
    ("State->Count++;", "if(0){State->Count++;}"),
    ("State->Count=State->Limit; touch(State);", "State->Count=State->Limit;"),
])
def test_stale_or_strengthened_census_does_not_reach_solver(monkeypatch, source_body, census_code):
    from core.audit import invariant_smt

    monkeypatch.setattr(invariant_smt, "check_site_batch", lambda *a, **k: pytest.fail("unbound census reached solver"))
    result = solve(source_body, census_code)
    assert result["outcome"] == "inconclusive", result
    assert result["guard_leg"] is False
    assert result["sites"][0]["verdict"] == "out_of_scope"
    assert result["sites"][0]["guards_applied"] == []


@pytest.mark.parametrize("source_body,census_code,outcome", [
    ("State->Count++;", "++(State -> Count);", "violable"),
    ("State->Count=State->Limit;", "State -> Count = (State -> Limit);", "preserved"),
    ("if(State->Count<State->Limit){\nState->Count++;\n}", "State->Count++;", "preserved"),
    ("if(State->Count<State->Limit){State->Count++;}", "if(State->Count<State->Limit){State->Count++;}", "preserved"),
    ("if(State->Count>=State->Limit){}else{State->Count++;}", "if(State->Count>=State->Limit){}else{State->Count++;}", "preserved"),
])
def test_matching_transitions_keep_the_source_guard_frame(source_body, census_code, outcome):
    result = solve(source_body, census_code)
    assert result["outcome"] == outcome, result
    assert result["guard_leg"] is True
