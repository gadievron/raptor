"""Legacy integer bridge must not change predicates or invent solver verdicts."""

import pytest

from core.audit import condition_smt as bridge
from core.audit.condition_extraction import GuardCondition
from core.audit.guard_integer_constraints import integer_conjunction


def guard(text, **kwargs):
    return GuardCondition(text=text, category="bounds", polarity="required", line=1,
                          concrete_values=kwargs)


@pytest.mark.parametrize("text", [
    "x < 10 + 20", "left + x < 10", "x == 010", "x < 10U",
    "x < 1e3", "x < 10.5", "x < 0x10suffix", "object->x < 10",
    "(int)x < 10", "f(x < 10)", "x < 10 && check(x)",
    "x < 10 || x > 20", "!(x < 10)", "x < 10 ? y < 1 : z < 2",
    "(x < 10", "x < 10)", "x < 10 &&", "x < 10 y > 1",
    "0 < x < 10", "x < 10 /* comment */", "x < 10 == 0",
])
def test_unsupported_complete_predicates_never_contribute_fragments(text):
    assert integer_conjunction(text) is None
    assert bridge.extract_bounds_constraints(guard(text)) == []
    assert bridge.constraints_for_guard(guard(text)) is None
    assert bridge._constraints_from_guard_text(text) is None


@pytest.mark.parametrize("text,expected", [
    ("x == 0X10", [("x", "==", 16)]),
    ("(0x10 > x) && (x >= 0)", [("x", "<", 16), ("x", ">=", 0)]),
    ("((x > 0) and (object.size < 16))", [("x", ">", 0), ("object.size", "<", 16)]),
    ("x != 0", [("x", "!=", 0)]),
])
def test_complete_supported_predicates_keep_exact_meaning(text, expected):
    assert integer_conjunction(text) == expected
    atoms = bridge.extract_bounds_constraints(guard(text))
    assert [(c.variable, c.operator, c.bound_value) for c in atoms] == expected


@pytest.mark.parametrize("value", ["10 + 20", "10U", "010", "replacement", "1 && y < 2"])
def test_constant_resolution_cannot_insert_replacement_expressions(value):
    assert bridge.constraints_for_guard(guard("x < LIMIT", LIMIT=value)) is None


def test_numeric_constants_and_reversed_comparisons_still_resolve():
    assert integer_conjunction("LIMIT > x", {"LIMIT": "0X10"}) == [("x", "<", 16)]


@pytest.mark.parametrize("text", ["(" * 100 + "x < 1" + ")" * 100,
                                  " && ".join(["x < 1"] * 200), "x" * 8193])
def test_grammar_budgets_decline_without_truncating(text):
    assert integer_conjunction(text) is None


@pytest.mark.parametrize("unmodeled", ["x < 10 || x > 20", "check(x)", "x < 10 + 20"])
def test_skipped_guard_prevents_partial_sat_in_both_backends(monkeypatch, unmodeled):
    guards = [guard("x == 0"), guard(unmodeled)]
    monkeypatch.setattr(bridge, "_try_z3_path_feasibility", lambda *args: None)
    result = bridge.check_path_feasibility(guards)
    assert result.feasible is None
    assert result.witness == {"x": 0}
    monkeypatch.setattr(bridge, "_try_z3_path_feasibility", lambda *args: (True, "SAT", {"x": 0}))
    result = bridge.check_path_feasibility(guards)
    assert result.feasible is None
    assert result.witness == {"x": 0}


def test_unmodeled_guard_does_not_discard_an_independent_contradiction(monkeypatch):
    monkeypatch.setattr(bridge, "_try_z3_path_feasibility", lambda *args: None)
    result = bridge.check_path_feasibility([guard("x == 0"), guard("x == 1"), guard("check(x)")])
    assert result.feasible is False


@pytest.mark.parametrize("name", ["path", "copy", "allocation"])
def test_native_unknown_is_neither_sat_nor_unsat(monkeypatch, name):
    z3 = pytest.importorskip("z3")
    solver = z3.Solver()
    monkeypatch.setattr(solver, "check", lambda: z3.unknown)
    monkeypatch.setattr(solver, "model", lambda: pytest.fail("unknown has no certified model"))
    monkeypatch.setattr(z3, "Solver", lambda: solver)
    monkeypatch.setattr("core.smt_solver.session.new_solver", lambda *args, **kwargs: solver)
    constraints = [bridge.BoundsConstraint("x", ">=", 0), bridge.BoundsConstraint("y", ">=", 0)]
    if name == "path":
        result = bridge._z3_path_feasibility_check(constraints)
    elif name == "copy":
        result = bridge._z3_overflow_check(constraints, 16)
    else:
        result = bridge._z3_alloc_overflow_check(constraints)
    assert result[0] is None
    assert result[2] is None
    assert "inconclusive" in result[1]


def test_inconclusive_worker_verdict_survives_public_path_adapter(monkeypatch):
    monkeypatch.setattr(bridge, "_z3_importable", lambda: True)
    monkeypatch.setattr(bridge, "_run_z3_child", lambda *args: [None, "solver unknown", None])
    monkeypatch.setattr(bridge, "_arithmetic_path_feasibility",
                        lambda *args: pytest.fail("unknown must not become an unavailable-worker fallback"))
    result = bridge.check_path_feasibility([guard("x < 10")])
    assert result.feasible is None
    assert result.witness is None


@pytest.mark.parametrize("bound", [1 << 63, 1 << 64, -(1 << 63) - 1, True])
@pytest.mark.parametrize("name", ["copy", "allocation"])
def test_bitvector_bridge_cannot_wrap_out_of_range_guard_bounds(bound, name):
    pytest.importorskip("z3")
    constraints = [bridge.BoundsConstraint("x", ">=", 0),
                   bridge.BoundsConstraint("x", "<", bound),
                   bridge.BoundsConstraint("y", ">=", 0)]
    result = (bridge._z3_overflow_check(constraints, 16) if name == "copy"
              else bridge._z3_alloc_overflow_check(constraints))
    assert result[0] is None
    assert "guard bounds" in result[1]
    assert result[2] is None


@pytest.mark.parametrize("size", [-1, 1 << 64, True])
def test_bitvector_bridge_cannot_wrap_buffer_sizes(size):
    pytest.importorskip("z3")
    result = bridge._z3_overflow_check([bridge.BoundsConstraint("x", ">=", 0)], size)
    assert result[0] is None
    assert "buffer size" in result[1]


@pytest.mark.parametrize("text,size,expected", [
    ("x >= 0 && x <= 10 && y >= 0 && y <= 1000", 16, True),
    ("x >= 0 && x <= 10 && y >= 0 && y <= 12", 16, False),
    ("x <= 10 && x == 5", 16, False),
    ("x <= 10 && x != -1", 16, True),
    ("x > 20 && x < 10", 16, False),
    ("x >= -10 && x <= -1", (1 << 64) - 1, False),
    ("x == -2", (1 << 64) - 2, False),
    ("x == -1", (1 << 64) - 2, True),
    ("x == 0", 0, False),
])
def test_copy_fallback_agrees_with_native_model_and_replays_witness(text, size, expected):
    pytest.importorskip("z3")
    condition = guard(text)
    constraints = bridge.constraints_for_guard(condition)
    fallback = bridge._arithmetic_check(constraints, condition, size, "memcpy")
    native = bridge._z3_overflow_check(constraints, size)
    assert fallback.feasible is expected
    assert native[0] is expected
    if expected:
        import operator
        comparisons = {"<": operator.lt, "<=": operator.le, ">": operator.gt,
                       ">=": operator.ge, "==": operator.eq, "!=": operator.ne}
        assert all(comparisons[c.operator](fallback.witness[c.variable], c.bound_value) for c in constraints)
        assert any(value % (1 << 64) > size for value in fallback.witness.values())


@pytest.mark.parametrize("api", ["malloc", "calloc", "unknown", "object.unknown"])
def test_copy_fallback_cannot_certify_an_unsupported_sink(api):
    condition = guard("x >= 0 && x < 10")
    result = bridge._arithmetic_check(bridge.constraints_for_guard(condition), condition, 16, api)
    assert result.feasible is None
    assert result.guard_sufficient is None


def test_public_sufficiency_adapter_keeps_variables_independent_without_z3(monkeypatch):
    from core.audit.condition_extraction import SinkGuard
    monkeypatch.setattr(bridge, "_try_z3_check", lambda *args: None)
    condition = guard("x >= 0 && x <= LIMIT && y >= 0 && y <= 1000", LIMIT="10")
    condition.resolvable = True
    sink = SinkGuard(sink_file="owned.c", sink_line=1, sink_function="copy",
                     sink_api="memcpy", guards=[condition], unconditional=False)
    results = bridge.check_guard_sufficiency(sink, buffer_size=16)
    assert len(results) == 1
    assert results[0].feasible is True
    assert results[0].guard_sufficient is False
    assert results[0].witness["y"] > 16


@pytest.mark.parametrize("text,expected", [("x == 0X10", True), ("x < 10 + 20", None),
                                          ("offset + x < 10", None), ("x == 020", None)])
def test_public_adapter_cannot_refute_through_changed_numeric_expressions(monkeypatch, text, expected):
    monkeypatch.setattr(bridge, "_try_z3_path_feasibility", lambda *args: None)
    result = bridge.check_path_feasibility([guard("x == 16"), guard(text)])
    assert result.feasible is expected
    assert result.witness == {"x": 16}
