"""Candidate objectives retain the exact occurrence identity of their checkers."""

import pytest

from core.audit import integer_conjunction as subject


SPECS = {
    "and": ("conjunction_candidates", "&&", (("Value", "<", "Limit"), ("Value", ">", "Limit"))),
    "or": ("disjunction_candidates", "||", (("Value", "<", "Limit"), ("Value", ">=", "Limit"))),
    "range-and": ("range_condition_candidates", "&&", (("Value", "<", "10"), ("Value", ">", "20"))),
    "range-or": ("range_condition_candidates", "||", (("Value", "<", "20"), ("Value", ">", "10"))),
}


def _expression(leaves, operator):
    return f" {operator} ".join(" ".join(leaf) for leaf in leaves)


def _discover(family, body, language):
    function, operator, _ = SPECS[family]
    source = "int Read(int Value,int Other,int Limit){" + body + "}"
    rows = getattr(subject, function)(source, language=language, integer_abi="lp64")
    if function == "range_condition_candidates":
        return [(row[1], row[2]) for row in rows]
    return [(operator, row[1]) for row in rows]


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("family", SPECS)
@pytest.mark.parametrize("context", [
    "duplicate", "parenthesized", "distinct-operand", "leaf-order", "other-operator",
    "return-excluded", "later-type-refusal",
])
def test_boolean_discovery_uses_the_exact_checker_identity(family, context, language):
    pytest.importorskip("tree_sitter_" + language)
    function, operator, leaves = SPECS[family]
    expression = _expression(leaves, operator)
    first = f"if({expression})return 1;"
    expected = []
    if context == "duplicate":
        body = first + f"if({expression})return 2;return 0;"
    elif context == "parenthesized":
        grouped = f"({' '.join(leaves[0])}) {operator} ({' '.join(leaves[1])})"
        body = first + f"if(({grouped}))return 2;return 0;"
    elif context == "distinct-operand":
        other = tuple(("Other", op, right) for _, op, right in leaves)
        body = first + f"if({_expression(other, operator)})return 2;return 0;"
        expected = [(operator, leaves), (operator, other)]
    elif context == "leaf-order":
        reversed_leaves = tuple(reversed(leaves))
        body = first + f"if({_expression(reversed_leaves, operator)})return 2;return 0;"
        expected = [(operator, leaves), (operator, reversed_leaves)]
    elif context == "other-operator":
        other_operator = "||" if operator == "&&" else "&&"
        body = first + f"if({_expression(leaves, other_operator)})return 2;return 0;"
        expected = [(operator, leaves)]
    elif context == "return-excluded":
        body = first + f"return {expression};"
        expected = [(operator, leaves)]
    else:
        body = first + f"{{void *Value=0;if({expression})return 2;}}return 0;"
    assert _discover(family, body, language) == expected


@pytest.mark.parametrize("family", ["range-and", "range-or"])
@pytest.mark.parametrize("language", ["c", "cpp"])
def test_range_discovery_keeps_literal_spelling_in_its_identity(family, language):
    pytest.importorskip("tree_sitter_" + language)
    _, operator, leaves = SPECS[family]
    other = tuple((name, op, hex(int(right))) for name, op, right in leaves)
    body = f"if({_expression(leaves, operator)})return 1;if({_expression(other, operator)})return 2;return 0;"
    assert _discover(family, body, language) == [(operator, leaves), (operator, other)]


@pytest.mark.parametrize("family", SPECS)
def test_boolean_discovery_counts_ambiguity_beyond_the_candidate_cap(family):
    pytest.importorskip("tree_sitter_c")
    function, operator, leaves = SPECS[family]
    parameters = ",".join([*(f"int Value{i}" for i in range(17)), "int Limit"])

    def occurrence(index):
        selected = tuple((f"Value{index}", op, right) for _, op, right in leaves)
        return f"if({_expression(selected, operator)})return 1;"

    body = "".join(occurrence(i) for i in range(16)) + occurrence(0) + occurrence(16)
    source = f"int Read({parameters}){{{body}return 0;}}"
    rows = getattr(subject, function)(source, language="c", integer_abi="lp64")
    selected = [row[2] if function == "range_condition_candidates" else row[1] for row in rows]
    assert [key[0][0] for key in selected] == [f"Value{i}" for i in range(1, 17)]
