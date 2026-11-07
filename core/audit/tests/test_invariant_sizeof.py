"""Opaque sizes require stable operands and must not invent positivity."""

import pytest

from core.audit import invariant_smt as inv
from core.audit.invariant_expression import (
    ParseError,
    parse_expr,
    validate_counterexample,
)

pytestmark = pytest.mark.usefixtures("invariant_unit_worker")


@pytest.fixture(autouse=True)
def grammar():
    pytest.importorskip("tree_sitter_c")
    pytest.importorskip("z3")


@pytest.mark.parametrize(
    "operand", ["int[Count]", "char[0]", "char[4]", "", "Data;Other"]
)
def test_unmodeled_sizeof_operands_never_become_frozen_constants(operand):
    with pytest.raises(ParseError):
        parse_expr(f"sizeof({operand})")


def test_mutating_an_array_extent_cannot_be_vacuous_preservation():
    result = inv.check_invariant_preservation(
        "sizeof(char[Count]) <= Limit", "Count++;"
    )
    assert result.outcome == "inconclusive", result.to_dict()


def test_opaque_size_zero_prevents_a_strict_positivity_proof():
    result = inv.check_invariant_preservation("Count < sizeof(Data)", "Count=0;")
    assert result.outcome == "inconclusive", result.to_dict()
    site = result.sites[0]
    assert site.verdict == "preserved_nonneg"
    assert site.model["sizeof(Data)"] == 0
    assert site.model["Count"] < 0 == site.model["Count'"]


def test_an_explicit_size_guard_can_establish_strict_positivity():
    result = inv.check_invariant_preservation(
        "Count < sizeof(Data)", "if(sizeof(Data)>0)Count=0;"
    )
    assert result.outcome == "preserved", result.to_dict()


@pytest.mark.parametrize(
    "symbol", ["sizeof(char[Count])", "sizeof()", "sizeof( Data )"]
)
def test_forged_size_nodes_cannot_bypass_operand_or_identity_validation(symbol):
    assert not validate_counterexample(
        ("var", "Count"),
        "<=",
        ("sizeof", symbol),
        ("add", ("var", "Count"), ("int", 1)),
        "Count",
        [],
        {"Count": 0, symbol: 0, "Count'": 1},
    )


def test_protocol_consumer_cannot_refute_from_opaque_size_positivity():
    from core.audit.protocol_state import run_protocol_state_check

    result = run_protocol_state_check(
        ".",
        "a.c",
        "Reset",
        "Count < sizeof(Data)",
        invariant="Count < sizeof(Data)",
        source_texts={"a.c": "void Reset(struct S *State){\nState->Count=0;\n}"},
    )
    assert result.outcome == "inconclusive", result.to_dict()
    assert result.invariant["per_site"][0]["model"]["sizeof(Data)"] == 0


@pytest.mark.parametrize(
    "bound,rhs,outcome",
    [
        ("sizeof(Data)", "sizeof(Other->Data)", "violable"),
        ("sizeof(State->Data)", "sizeof(State->Data)", "preserved"),
    ],
    ids=["distinct-size-objects", "same-size-object"],
)
def test_protocol_projection_keeps_sizeof_operand_identity(bound, rhs, outcome):
    from core.audit.protocol_state import check_invariant_multi_site

    site = dict(file="a.c", function="", line=1, code=f"State->Count={rhs};")
    result = check_invariant_multi_site(
        f"Count <= {bound}", {"fields": {"Count": {"writes": [site]}}}, {}
    )
    assert result["outcome"] == outcome, result
    assert result["sites"][0]["code"] == f"Count={rhs};"


@pytest.mark.parametrize(
    "spelling,canonical",
    [
        ("sizeof ( Data )", "sizeof(Data)"),
        ("sizeof(State -> Count)", "sizeof(State->Count)"),
        ("sizeof(unsigned  char *)", "sizeof(unsigned char*)"),
    ],
    ids=["object", "member", "pointer-type"],
)
def test_sizeof_identity_ignores_lexically_irrelevant_whitespace(spelling, canonical):
    assert parse_expr(spelling) == ("sizeof", canonical)
    result = inv.check_invariant_preservation(
        f"Count <= {canonical}", f"Count={spelling};"
    )
    assert result.outcome == "preserved", result.to_dict()


@pytest.mark.slow
@pytest.mark.parametrize("case", ["zero", "runtime-array", "whitespace"])
def test_native_sizeof_model_contract(case):
    if case == "zero":
        result = inv.check_invariant_preservation(
            "Count < sizeof(Data)", "Count=0;", timeout_ms=30_000
        )
        assert result.outcome == "inconclusive", result.to_dict()
        assert result.sites[0].model["sizeof(Data)"] == 0
    elif case == "runtime-array":
        result = inv.check_invariant_preservation(
            "sizeof(char[Count]) <= Limit", "Count++;", timeout_ms=30_000
        )
        assert result.outcome == "inconclusive", result.to_dict()
    else:
        result = inv.check_invariant_preservation(
            "Count <= sizeof(Data)", "Count=sizeof( Data );", timeout_ms=30_000
        )
        assert result.outcome == "preserved", result.to_dict()
