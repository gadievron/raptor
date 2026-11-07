"""Protocol SMT guards retain source polarity and the complete conjunction."""

import pytest

from core.audit import protocol_state as protocol

pytestmark = pytest.mark.usefixtures("invariant_unit_worker")


@pytest.fixture(autouse=True)
def native_grammar():
    pytest.importorskip("z3")
    pytest.importorskip("tree_sitter_c")


def solve(body):
    source = "void Read(struct S *State,int Flag){\n" + body + "\n}"
    line = next(n for n, text in enumerate(source.splitlines(), 1) if "State->Count++;" in text)
    site = dict(file="unit.c", function="Read", line=line, code="State->Count++;")
    result = protocol.check_invariant_multi_site(
        "Count <= Limit", {"fields": {"Count": {"writes": [site]}}}, {"unit.c": source},
    )
    return source, line, result


@pytest.mark.parametrize("condition", ["Flag < Flag", "Flag != Flag", "Flag > Flag"])
def test_unrelated_impossible_guard_excludes_the_mutation(condition):
    _source, _line, result = solve(f"if({condition}){{\nState->Count++;\n}}")
    assert result["outcome"] == "preserved", result
    assert result["sites"][0]["guards_applied"] == [condition]
    assert result["sites"][0].get("model", {}) == {}


def test_unrelated_feasible_guard_is_present_in_the_replayed_counterexample():
    _source, _line, result = solve("if(Flag == 7){\nState->Count++;\n}")
    assert result["outcome"] == "violable", result
    site = result["sites"][0]
    assert site["guards_applied"] == ["Flag == 7"]
    assert site["model"]["Flag"] == 7


@pytest.mark.parametrize("condition,expected", [
    ("State->Count < State->Count", "violable"),
    ("State->Count >= State->Count", "preserved"),
])
def test_empty_then_branch_does_not_invert_the_else_guard(condition, expected):
    source, line, result = solve(f"if({condition}){{\n}} else {{\nState->Count++;\n}}")
    assert result["outcome"] == expected, result
    guards = protocol._branch_guards(source, "Read", line)
    assert guards == (["State->Count >= State->Count"] if expected == "violable" else ["State->Count < State->Count"])


@pytest.mark.parametrize("condition", [
    "Flag == Flag || State->Count > State->Limit",
    "!(Flag != Flag) || State->Count > State->Limit",
])
def test_false_compound_guard_retains_every_negated_atom(condition):
    _source, _line, result = solve(f"if({condition}){{\n}} else {{\nState->Count++;\n}}")
    assert result["outcome"] == "preserved", result
    guards = result["sites"][0]["guards_applied"]
    assert "Flag != Flag" in guards
    assert "Count <= Limit" in guards


def test_unavailable_guard_binding_never_dispatches_a_weakened_obligation(monkeypatch):
    from core.audit import invariant_smt

    monkeypatch.setattr(protocol, "_branch_guards", lambda *a: None)
    monkeypatch.setattr(invariant_smt, "check_site_batch", lambda *a, **k: pytest.fail("missing guards reached solver"))
    _source, _line, result = solve("State->Count++;")
    assert result["outcome"] == "inconclusive"
    assert result["guard_leg"] is False
    assert result["sites"][0]["verdict"] == "out_of_scope"


def test_source_guard_mapping_requires_a_bound_write_site():
    source = "void Read(int Flag){\n if(Flag > 0){\n  sink(Flag);\n }\n}"
    assert protocol._branch_guards(source, "Read", 3) is None


def test_same_line_mutations_do_not_choose_an_arbitrary_guard_frame():
    source = "void Read(struct S *State,int Flag){\n if(Flag > 0){State->Count++;} else {State->Count++;}\n}"
    assert protocol._branch_guards(source, "Read", 2) is None
