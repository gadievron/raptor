"""Bounded parsing and solver-independent replay of invariant counterexamples."""

from itertools import product
import operator

import pytest

from core.audit import invariant_smt as inv
from core.audit.invariant_expression import (
    MAX_DEPTH,
    MAX_INTEGER_DIGITS,
    MAX_TOKENS,
    ParseError,
    parse_expr,
    validate_counterexample,
)

pytestmark = pytest.mark.usefixtures("invariant_unit_worker")


@pytest.mark.parametrize(
    "name",
    ["minimum", "maximum", "min_count", "max_size", "min", "max", "max_state.Count"],
)
def test_function_names_do_not_consume_identifier_prefixes(name):
    assert parse_expr(name) == ("var", name)
    result = inv.check_site_preservation(f"{name} <= Limit", name + "++;")
    assert result.verdict == "violable", result.to_dict()
    assert result.model[name + "'"] == result.model[name] + 1 > result.model["Limit"]


@pytest.mark.parametrize(
    "text,expected",
    [
        ("min(Count,Limit)", ("min", ("var", "Count"), ("var", "Limit"))),
        ("max(Count,Limit)", ("max", ("var", "Count"), ("var", "Limit"))),
    ],
)
def test_actual_minmax_calls_keep_their_mathematical_meaning(text, expected):
    assert parse_expr(text) == expected


@pytest.mark.parametrize(
    "source",
    [
        "(" * (MAX_DEPTH + 1) + "Count" + ")" * (MAX_DEPTH + 1),
        "-" * (MAX_DEPTH + 1) + "Count",
        "+".join(["Count"] * (MAX_DEPTH + 2)),
        "+".join(["Count"] * (MAX_TOKENS + 1)),
        "9" * (MAX_INTEGER_DIGITS + 1),
        "Count" + " " * 8192,
    ],
    ids=["parentheses", "unary", "left-deep-tree", "tokens", "digits", "text"],
)
def test_parser_limits_are_explicit_refusals(source):
    with pytest.raises(ParseError, match="budget"):
        parse_expr(source)


def test_exact_supported_depth_and_integer_digit_limits():
    assert parse_expr("(" * MAX_DEPTH + "Count" + ")" * MAX_DEPTH) == ("var", "Count")
    assert parse_expr("9" * MAX_INTEGER_DIGITS) == (
        "int",
        int("9" * MAX_INTEGER_DIGITS),
    )


@pytest.mark.parametrize(
    "op,compare",
    [
        ("<", operator.lt),
        ("<=", operator.le),
        (">", operator.gt),
        (">=", operator.ge),
        ("==", operator.eq),
        ("!=", operator.ne),
    ],
)
@pytest.mark.parametrize(
    "expression,evaluate",
    [
        ("Count+Step", operator.add),
        ("Count-Step", operator.sub),
        ("min(Count,Step)", min),
        ("max(Count,Step)", max),
    ],
)
def test_replay_matches_an_independent_exhaustive_integer_reference(
    op, compare, expression, evaluate
):
    lhs, rhs, new = parse_expr("Count"), parse_expr("Limit"), parse_expr(expression)
    condition = [(parse_expr("Step"), ">=", parse_expr("0"))]
    for count, limit, step in product(range(-2, 3), repeat=3):
        post = evaluate(count, step)
        model = {"Count": count, "Limit": limit, "Step": step, "Count'": post}
        expected = compare(count, limit) and step >= 0 and not compare(post, limit)
        assert (
            validate_counterexample(lhs, op, rhs, new, "Count", condition, model)
            is expected
        )
        nonnegative = expected and min(count, limit, step) >= 0
        assert (
            validate_counterexample(
                lhs, op, rhs, new, "Count", condition, model, nonnegative=True
            )
            is nonnegative
        )


def model_args():
    return (
        parse_expr("Count"),
        "<=",
        parse_expr("Limit"),
        parse_expr("Count+Step"),
        "Count",
        [],
        {"Count": 0, "Limit": 0, "Step": 1, "Count'": 1},
    )


@pytest.mark.parametrize(
    "case",
    [
        "missing",
        "extra",
        "bool",
        "transition",
        "pre-invariant",
        "safe-post",
        "nonnegative",
        "guard",
    ],
)
def test_invalid_counterexamples_are_not_repaired(case):
    lhs, op, rhs, new, var, conditions, model = model_args()
    nonnegative = False
    if case == "missing":
        del model["Step"]
    elif case == "extra":
        model["Other"] = 0
    elif case == "bool":
        model["Count"] = False
    elif case == "transition":
        model["Count'"] = 2
    elif case == "pre-invariant":
        model.update(Count=1, Limit=0)
        model["Count'"] = 2
    elif case == "safe-post":
        model.update(Step=0)
        model["Count'"] = 0
    elif case == "nonnegative":
        model.update(Count=-1, Limit=-1)
        model["Count'"] = 0
        nonnegative = True
    else:
        conditions = [(parse_expr("Step"), "<", parse_expr("0"))]
    assert not validate_counterexample(
        lhs, op, rhs, new, var, conditions, model, nonnegative=nonnegative
    )


@pytest.mark.parametrize(
    "size,expected", [(0, True), (-1, False), (1, True), (2, True)]
)
def test_opaque_sizes_are_nonnegative_and_stable_during_replay(size, expected):
    model = {"Count": size, "sizeof(Data)": size, "Count'": size + 1}
    assert (
        validate_counterexample(
            parse_expr("Count"),
            "<=",
            parse_expr("sizeof(Data)"),
            parse_expr("Count+1"),
            "Count",
            [],
            model,
        )
        is expected
    )


def test_corrupt_native_model_cannot_confirm_a_violation(monkeypatch):
    z3 = pytest.importorskip("z3")
    original = inv.new_solver
    checks = []

    def construct(*args):
        solver = original(*args)
        native = solver.check

        def check():
            checks.append(1)
            return native()

        class CorruptModel:
            def eval(self, *args, **kwargs):
                return z3.IntVal(0)

        monkeypatch.setattr(solver, "check", check)
        monkeypatch.setattr(solver, "model", lambda: CorruptModel())
        return solver

    monkeypatch.setattr(inv, "new_solver", construct)
    result = inv.check_site_preservation("Count <= Limit", "Count++;")
    assert result.verdict == "unknown" and result.model == {}
    assert "replay failed" in result.reason and checks == [1]


def test_nonnegative_query_model_is_independently_replayed(monkeypatch):
    z3 = pytest.importorskip("z3")
    original = inv.new_solver

    def construct(*args):
        solver = original(*args)
        native_model = solver.model
        calls = []

        class CorruptModel:
            def eval(self, *args, **kwargs):
                return z3.IntVal(0)

        def model():
            calls.append(1)
            return native_model() if len(calls) == 1 else CorruptModel()

        monkeypatch.setattr(solver, "model", model)
        return solver

    monkeypatch.setattr(inv, "new_solver", construct)
    result = inv.check_site_preservation("Count <= Limit", "Count++;")
    assert result.verdict == "unknown" and result.model == {}
    assert "non-negative counterexample replay failed" in result.reason


def test_over_budget_site_does_not_poison_the_rest_of_a_batch():
    results = inv.check_site_batch(
        "Count <= Limit",
        [
            dict(
                code="Count=" + "9" * (MAX_INTEGER_DIGITS + 1) + ";",
                line=1,
                pre_conditions=[],
            ),
            dict(code="Count++;", line=2, pre_conditions=[]),
        ],
    )
    assert [result.verdict for result in results] == ["out_of_scope", "violable"]
    assert "digit budget" in results[0].reason


@pytest.mark.parametrize("mode", ["site", "batch"])
def test_pre_replay_worker_contract_is_not_accepted(monkeypatch, mode):
    from core.audit import condition_smt

    def dispatch(tag, args, **kwargs):
        reply = condition_smt._z3_dispatch_json({"tag": tag, "args": args})
        reply["binding"]["query_contract"] = (
            "mathematical-invariant-worker-v1"
            if mode == "site"
            else "mathematical-invariant-site-batch-v1"
        )
        return reply

    monkeypatch.setattr(condition_smt, "_run_z3_child", dispatch)
    if mode == "site":
        assert (
            inv.check_site_preservation("Count <= Limit", "Count++;").verdict
            == "unknown"
        )
    else:
        assert (
            inv.check_site_batch(
                "Count <= Limit", [dict(code="Count++;", line=1, pre_conditions=[])]
            )
            is None
        )


@pytest.mark.slow
@pytest.mark.parametrize("case", ["identifier", "mixed-batch"])
def test_native_worker_uses_bounded_parser_and_replayed_witness(case):
    pytest.importorskip("z3")
    if case == "identifier":
        result = inv.check_site_preservation("max_size <= Limit", "max_size++;", timeout_ms=30_000)
        assert result.verdict == "violable", result.to_dict()
        assert result.model["max_size'"] > result.model["Limit"]
    else:
        results = inv.check_site_batch(
            "Count <= Limit",
            [
                dict(
                    code="Count=" + "9" * (MAX_INTEGER_DIGITS + 1) + ";",
                    line=1,
                    pre_conditions=[],
                ),
                dict(code="Count++;", line=2, pre_conditions=[]),
            ],
            timeout_ms=30_000,
        )
        assert results is not None, "native invariant batch returned no complete reply"
        assert [result.verdict for result in results] == ["out_of_scope", "violable"], [result.to_dict() for result in results]


def test_a_nonnegative_witness_blocks_a_contradictory_preservation_verdict(monkeypatch):
    z3 = pytest.importorskip("z3")
    original = inv.new_solver
    calls = []

    def construct(*args):
        solver = original(*args)
        native = solver.check

        def check():
            calls.append(1)
            return native() if len(calls) == 1 else z3.unsat

        monkeypatch.setattr(solver, "check", check)
        return solver

    monkeypatch.setattr(inv, "new_solver", construct)
    result = inv.check_site_preservation(
        "Count <= Limit", "Count++;", pre_conditions=("Count >= 0", "Limit >= 0")
    )
    assert result.verdict == "unknown" and result.model == {}
    assert "contradicts preservation" in result.reason and calls == [1, 1]


def test_replayed_prefix_identifiers_reach_the_protocol_consumer():
    from core.audit.protocol_state import check_invariant_multi_site

    site = dict(file="a.c", function="", line=1, code="max_size++;")
    result = check_invariant_multi_site(
        "max_size <= Limit", {"fields": {"max_size": {"writes": [site]}}}, {}
    )
    assert result["outcome"] == "violable"
    model = result["sites"][0]["model"]
    assert model["max_size'"] == model["max_size"] + 1 > model["Limit"]
