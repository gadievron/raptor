"""Bounds leads must query the operands actually named in the claim."""

import pytest

from core.audit import sweep

SOURCE = "unsigned Read(unsigned Index, unsigned Capacity) { if(Index < Capacity) return Index; return 0; }"


@pytest.mark.parametrize("hypothesis", [
    "`Index` is used as an array index into buffer of size `Capacity`",
    "`Index` is an array index into buffer of size `Capacity`",
    "Index is an index into array of size Capacity",
    "Index used as an index into buffer size Capacity",
    "Index as an array index into array size Capacity",
    "'Index' is an index into buffer of size 'Capacity'",
    '"Index" is an index into buffer of size "Capacity"',
    "`Index` IS USED AS AN ARRAY INDEX into BUFFER OF SIZE `Capacity`",
    "`Index` is an index; array size `Capacity`; `Index` is an index; buffer size `Capacity`",
    "Claim: `Index` is an index into buffer of size `Capacity`.",
], ids=["array-phrase", "array-role", "unquoted", "used-as", "as", "single-quotes", "double-quotes", "keyword-case", "repeated-same-roles", "prose-punctuation"])
def test_explicit_roles_preserve_identifier_case(hypothesis):
    assert sweep._extract_oob_operands(hypothesis, SOURCE) == ("Index", "Capacity")


@pytest.mark.parametrize("hypothesis,expected", [
    pytest.param("`Index` is an array index", ("Index", None), id="missing-capacity"),
    pytest.param("`Index` is an array index into buffer", ("Index", None), id="no-capacity-name-guess"),
    pytest.param("array index into buffer of size `Capacity`", (None, "Capacity"), id="prose-is-not-index"),
    pytest.param("`index` is an index into buffer of size `Capacity`", (None, "Capacity"), id="wrong-index-case"),
    pytest.param("`Index` is an index into buffer of size `capacity`", ("Index", None), id="wrong-capacity-case"),
    pytest.param("`Ghost` is an index into buffer of size `Capacity`", (None, "Capacity"), id="missing-index"),
    pytest.param("`Index` is an index into buffer of size `Ghost`", ("Index", None), id="missing-capacity-identifier"),
    pytest.param("`Index` is an index into buffer of size `Capacity + 1`", ("Index", None), id="quoted-compound-capacity"),
    pytest.param("`Index + 1` is an index into buffer of size `Capacity`", (None, "Capacity"), id="quoted-compound-index"),
    pytest.param("`Index` is an index into buffer of size Capacity + 1", ("Index", None), id="compound-capacity"),
    pytest.param("`Index` is an index into buffer of size Capacity->field", ("Index", None), id="field-capacity"),
    pytest.param("ctx->Index is an index into buffer of size `Capacity`", (None, "Capacity"), id="field-index"),
    pytest.param("`Index` is an index into buffer of size Capacity[0]", ("Index", None), id="subscript-capacity"),
    pytest.param("`Index` is an index into buffer of size Capacity()", ("Index", None), id="call-capacity"),
    pytest.param("`Index` is an index into buffer of size `Capacity`; array size `Other`", ("Index", None), id="ambiguous-capacity"),
    pytest.param("`Index` is an index; `Other` is an index; buffer size `Capacity`", (None, "Capacity"), id="ambiguous-index"),
])
def test_missing_unsupported_and_conflicting_roles_decline(hypothesis, expected):
    source = SOURCE.replace("unsigned Capacity", "unsigned Capacity, unsigned Other")
    assert sweep._extract_oob_operands(hypothesis, source) == expected


@pytest.mark.parametrize("source", [
    'unsigned Read(unsigned Index) { /* Capacity */ return Index; }',
    'unsigned Read(unsigned Index) { const char *s = "Capacity"; return Index; }',
    'unsigned Read(unsigned Index, unsigned CapacityOther) { return Index; }',
    'unsigned Read(unsigned Index, unsigned ΩCapacity) { return Index; }',
], ids=["comment", "string", "identifier-suffix", "unicode-prefix"])
def test_comment_string_and_partial_identifier_cannot_supply_capacity(source):
    assert sweep._extract_oob_operands("`Index` is an array index into buffer of size `Capacity`", source) == ("Index", None)


@pytest.fixture
def c_parser():
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_c")


@pytest.mark.parametrize("comparison,feasible", [("<", False), ("<=", True)])
def test_real_model_uses_the_named_case_sensitive_bound(c_parser, comparison, feasible):
    pytest.importorskip("z3")
    source = SOURCE.replace("Index < Capacity", f"Index {comparison} Capacity")
    result = sweep._run_smt_verb_inner(
        file_path="record.c", function_name="Read", verb="check-oob", source=source,
        hypothesis="`Index` is an array index into buffer of size `Capacity`",
    )
    assert result.outcome == ("confirmed" if feasible else "inconclusive")
    assert result.details["feasible"] is feasible
    assert result.details["oracle_scope"] == "inferred-arithmetic-model"


@pytest.mark.parametrize("hypothesis", [
    "`Index` is an array index", "`index` is an index into buffer of size `Capacity`",
    "`Index` is an index into buffer of size `Ghost`",
])
def test_unbound_operands_stop_before_solver(c_parser, monkeypatch, hypothesis):
    from packages.exploit_feasibility import smt_verbs

    def forbidden(*args, **kwargs):
        pytest.fail("unbound operands should not start a bounds solve")

    monkeypatch.setattr(smt_verbs, "check_oob", forbidden)
    result = sweep._run_smt_verb_inner(file_path="record.c", function_name="Read", verb="check-oob",
                                     source=SOURCE, hypothesis=hypothesis)
    assert result.outcome == "inconclusive"
    assert not result.errors


@pytest.mark.parametrize("prefix", ["ctx . ", "ctx -> ", "namespace :: ", "Other + "])
def test_compound_prefix_cannot_borrow_an_atomic_index(prefix):
    hypothesis = prefix + "Index is an index into buffer of size Capacity"
    assert sweep._extract_oob_operands(hypothesis, SOURCE) == (None, "Capacity")
