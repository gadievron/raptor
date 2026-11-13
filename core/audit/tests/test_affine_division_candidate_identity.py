"""Affine division discovery preserves the verifier's occurrence identity."""

import pytest

from core.audit.integer_affine_division import affine_division_candidates


def discover(body, language="c"):
    pytest.importorskip("tree_sitter_" + language)
    source = "unsigned Read(unsigned Value,unsigned Other,unsigned Count){" + body + "}"
    return [row[1:] for row in affine_division_candidates(source, language=language, integer_abi="lp64")]


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("second", [
    "return Value/(Count-1);",
    "return (Value)/((Count-1));",
    "return Value/(Count-0x1);",
    "{void *Value=0;return Value/(Count-1);}",
], ids=["duplicate", "parenthesized", "numeric-offset", "type-refused"])
def test_ambiguous_affine_division_has_no_discovery_objective(second, language):
    assert discover("if(Value==0)return Value/(Count-1);" + second, language) == []


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_unevaluated_duplicate_does_not_obscure_one_runtime_site(language):
    assert discover("if(Value==0)return Value/(Count-1);return sizeof(Value/(Count-1));", language) == [
        ("Value", "Count", "-", 1, "/", "zero-divisor"),
    ]


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("second,expected", [
    ("return Other/(Count-1);", ("Other", "Count", "-", 1, "/", "zero-divisor")),
    ("return Value%(Count-1);", ("Value", "Count", "-", 1, "%", "zero-divisor")),
    ("return Value/(Count-2);", ("Value", "Count", "-", 2, "/", "zero-divisor")),
], ids=["other-numerator", "remainder", "other-offset"])
def test_distinct_affine_division_objectives_survive(second, expected, language):
    assert discover("if(Value==0)return Value/(Count-1);" + second, language) == [
        ("Value", "Count", "-", 1, "/", "zero-divisor"), expected,
    ]


def test_affine_division_counts_ambiguity_beyond_the_candidate_cap():
    pytest.importorskip("tree_sitter_c")
    parameters = ",".join(["unsigned Value", *(f"unsigned Count{i}" for i in range(17))])
    body = "".join(f"if(Value=={i})return Value/(Count{i}-1);" for i in range(16))
    body += "if(Value==16)return Value/(Count0-1);return Value/(Count16-1);"
    source = f"unsigned Read({parameters}){{{body}}}"
    rows = affine_division_candidates(source, language="c", integer_abi="lp64")
    assert [row[2] for row in rows] == [f"Count{i}" for i in range(1, 17)]
