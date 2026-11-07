"""Protocol invariant normalization must not merge distinct object values."""

import pytest

from core.audit.protocol_state import check_invariant_multi_site

pytestmark = pytest.mark.usefixtures("invariant_unit_worker")


@pytest.fixture(autouse=True)
def grammar():
    pytest.importorskip("tree_sitter_c")
    pytest.importorskip("z3")


def run_site(body, statement):
    code = "void Read(struct S *State,struct S *Other,int Count){\n" + body + "\n}"
    line = next(i for i, text in enumerate(code.splitlines(), 1) if statement in text)
    site = dict(file="a.c", function="Read", line=line, code=statement)
    return check_invariant_multi_site(
        "Count <= Limit", {"fields": {"Count": {"writes": [site]}}}, {"a.c": code}
    )


@pytest.mark.parametrize(
    "body,statement",
    [
        ("if(Other->Count<State->Limit){\nState->Count++;\n}", "State->Count++;"),
        ("if(Count<State->Limit){\nState->Count++;\n}", "State->Count++;"),
        ("State->Count=Other->Count;", "State->Count=Other->Count;"),
        ("State->Count=Count;", "State->Count=Count;"),
        (
            "if(State->Count<State->Limit){\nOther->Count=State->Limit;\nState->Count++;\n}",
            "State->Count++;",
        ),
    ],
    ids=["foreign-guard", "scalar-guard", "foreign-rhs", "scalar-rhs", "alias-write"],
)
def test_ambiguous_object_bindings_cannot_claim_preservation(body, statement):
    result = run_site(body, statement)
    assert result["outcome"] != "preserved", result
    assert result["guard_leg"] is False, result
    if "Other->Count=State->Limit" not in body:
        assert result["sites"][0]["verdict"] == "out_of_scope", result
        assert result["sites"][0]["guards_applied"] == [], result


@pytest.mark.parametrize(
    "body,statement,outcome",
    [
        (
            "if(State->Count<State->Limit){\nState->Count++;\n}",
            "State->Count++;",
            "preserved",
        ),
        ("State->Count=State->Count;", "State->Count=State->Count;", "preserved"),
        ("State->Count=Other->Value;", "State->Count=Other->Value;", "violable"),
        (
            "if(State->Count<State->Limit){\nCount=0;\nState->Count++;\n}",
            "State->Count++;",
            "preserved",
        ),
    ],
    ids=[
        "same-owner-guard",
        "same-owner-rhs",
        "distinct-field-symbol",
        "unrelated-scalar-write",
    ],
)
def test_unambiguous_bindings_keep_their_arithmetic_result(body, statement, outcome):
    result = run_site(body, statement)
    assert result["outcome"] == outcome, result
    assert result["guard_leg"] is True, result


def test_refused_sites_keep_receipt_order_and_never_enter_the_solver_batch(monkeypatch):
    from core.audit import invariant_smt

    real_batch = invariant_smt.check_site_batch
    dispatched = []

    def batch(invariant, sites, **kwargs):
        dispatched.extend(sites)
        return real_batch(invariant, sites, **kwargs)

    monkeypatch.setattr(invariant_smt, "check_site_batch", batch)
    statements = [
        "State->Count=0;",
        "State->Count=Other->Count;",
        "State->Count=State->Count;",
    ]
    writes = [
        dict(file="a.c", function="", line=i, code=code)
        for i, code in enumerate(statements, 1)
    ]
    result = check_invariant_multi_site(
        "Count <= Limit", {"fields": {"Count": {"writes": writes}}}, {}
    )
    assert [site["line"] for site in result["sites"]] == [1, 2, 3]
    assert result["sites"][1]["verdict"] == "out_of_scope"
    assert [site["line"] for site in dispatched] == [1, 3]
    assert len(result["sites"]) == 3 and result["guard_leg"] is False


@pytest.mark.parametrize("part", ["source", "guard", "guard-count"])
def test_projection_limits_are_checked_before_native_parsing(monkeypatch, part):
    from core.audit import protocol_invariant_bindings as bindings

    def unexpected_parse(*args):
        pytest.fail("oversized projection reached the source parser")

    monkeypatch.setattr(bindings, "source_mutations", unexpected_parse)
    code = "x" * (bindings._MAX_SOURCE + 1) if part == "source" else "Count++;"
    guards = (
        ["x" * (bindings._MAX_TEXT + 1)]
        if part == "guard"
        else ["Count<Limit"] * (65 if part == "guard-count" else 0)
    )
    assert "budget" in bindings.projection_refusal(code, guards, {"Count", "Limit"})


def test_a_misattributed_census_write_never_becomes_vacuous_preservation():
    result = run_site("State->Other=0;", "State->Other=0;")
    assert result["outcome"] == "inconclusive", result
    assert result["sites"][0]["verdict"] == "out_of_scope"
    assert "does not bind" in result["sites"][0]["reason"]
