"""Legacy guard diagnostics require explicit semantics and complete witnesses."""

import operator

import pytest

from core.audit import condition_smt as bridge
from core.audit.condition_extraction import GuardCondition, SinkGuard

pytestmark = pytest.mark.usefixtures("owned_smt_subprocess")


def guard(text, polarity="required", **values):
    return GuardCondition(text=text, category="bounds", polarity=polarity, line=1,
                          resolvable=True, concrete_values=values)


def replay(text, witness):
    comparisons = {"<": operator.lt, "<=": operator.le, ">": operator.gt,
                   ">=": operator.ge, "==": operator.eq, "!=": operator.ne}
    constraints = bridge.constraints_for_guard(guard(text))
    assert set(witness) == {c.variable for c in constraints}
    assert all(comparisons[c.operator](witness[c.variable], c.bound_value) for c in constraints)


@pytest.mark.parametrize("semantics", [None, False, 1, "signed"])
def test_unsigned_declaration_cannot_establish_signed_comparison(semantics, monkeypatch):
    monkeypatch.setattr(bridge, "_try_z3_signed_mismatch", lambda *a: pytest.fail("unbound comparison reached solver"))
    result = bridge.check_signed_mismatch(guard("size < 16"), source="void copy(unsigned int size);",
                                          comparison_is_signed=semantics)
    assert not result.mismatch and result.witness is None


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize("text,expected", [
    ("size < 16 && size >= 0", False),
    ("size < 16 && size == 4", False),
    ("size < 16 && size < -1 && size != -2 && other == 3", True),
    ("size <= 16 && size > 20", False),
    ("size < 16 && size != -1", True),
])
def test_signed_model_uses_complete_guard_and_valid_witness(monkeypatch, native, text, expected):
    if native:
        pytest.importorskip("z3")
        monkeypatch.setattr(bridge, "_try_z3_signed_mismatch",
                            lambda var, op, bound, width, cs: bridge._z3_signed_mismatch_check(var, op, bound, width, cs))
    else:
        monkeypatch.setattr(bridge, "_try_z3_signed_mismatch", lambda *a: None)
    result = bridge.check_signed_mismatch(guard(text), var_is_unsigned=True,
                                          comparison_is_signed=True, bit_width=8)
    assert result.mismatch is expected
    if expected:
        replay(text, result.witness)
        assert result.witness["size"] < 0
        assert result.witness["size"] % 256 > 16
    else:
        assert result.witness is None


def test_signed_model_respects_guard_polarity(monkeypatch):
    monkeypatch.setattr(bridge, "_try_z3_signed_mismatch", lambda *a: None)
    result = bridge.check_signed_mismatch(guard("size < 16", polarity="excluded"),
                                          var_is_unsigned=True, comparison_is_signed=True, bit_width=8)
    assert not result.mismatch and result.witness is None


@pytest.mark.parametrize("width", [0, -1, True, 1.5, "32", 1000000])
def test_invalid_width_cannot_select_a_comparison_model(width):
    result = bridge.check_signed_mismatch(guard("size < 16"), var_is_unsigned=True,
                                          comparison_is_signed=True, bit_width=width)
    assert not result.mismatch and result.witness is None


@pytest.mark.parametrize("width,bound", [(8, 128), (8, 256), (32, 1 << 32), (True, 16)])
def test_native_bound_and_width_cannot_silently_wrap(width, bound):
    pytest.importorskip("z3")
    result = bridge._z3_signed_mismatch_check("size", "<", bound, width)
    assert not result.mismatch and result.witness is None
    assert "inconclusive" in result.reasoning


def test_native_unknown_is_not_a_safety_proof(monkeypatch):
    z3 = pytest.importorskip("z3")
    solver = z3.Solver()
    monkeypatch.setattr(solver, "check", lambda: z3.unknown)
    monkeypatch.setattr("core.smt_solver.session.new_solver", lambda *a: solver)
    result = bridge._z3_signed_mismatch_check("size", "<", 16, 8)
    assert not result.mismatch and result.witness is None
    assert "inconclusive" in result.reasoning and "safe" not in result.reasoning


def test_model_failure_cannot_fabricate_a_sentinel(monkeypatch):
    pytest.importorskip("z3")
    def unavailable(*args, **kwargs):
        raise ValueError("owned model extraction failure")
    monkeypatch.setattr("core.smt_solver.witness.format_vars", unavailable)
    result = bridge._z3_signed_mismatch_check("size", "<", 16, 8)
    assert not result.mismatch and result.witness is None


def test_replayed_worker_result_cannot_discard_guard_constraints(monkeypatch):
    monkeypatch.setattr(bridge, "_try_z3_signed_mismatch",
                        lambda *a: bridge.SignedMismatchResult(mismatch=True, variable="size", witness={"size": -1}))
    result = bridge.check_signed_mismatch(guard("size < 16 && size >= 0"), var_is_unsigned=True,
                                          comparison_is_signed=True, bit_width=8)
    assert not result.mismatch and result.witness is None
    assert "replay" in result.reasoning


@pytest.mark.parametrize("others", ["len < 10", "len != 16", "len > 20", "unknown(len)"])
@pytest.mark.parametrize("same_guard", [False, True])
def test_off_by_one_boundary_must_satisfy_every_guard(others, same_guard):
    guards = ([guard(f"len <= LIMIT && {others}", LIMIT="16")] if same_guard
              else [guard("len <= LIMIT", LIMIT="16"), guard(others)])
    sink = SinkGuard("owned.c", 1, "copy", "strncat", guards)
    assert bridge.check_off_by_one(sink, buffer_size=16) == []


def test_off_by_one_assignment_includes_other_guard_variables():
    guards = [guard("len <= LIMIT", LIMIT="16"), guard("len >= 0 && mode == 3")]
    result = bridge.check_off_by_one(SinkGuard("owned.c", 1, "copy", "strncat", guards), buffer_size=16)
    assert len(result) == 1
    assert result[0].witness == {"len": 16, "mode": 3}
    replay("len <= 16 && len >= 0 && mode == 3", result[0].witness)


@pytest.mark.parametrize("size", [-1, True, 16.0])
def test_off_by_one_rejects_invalid_capacity(size):
    sink = SinkGuard("owned.c", 1, "copy", "strncat", [guard("len <= LIMIT", LIMIT="16")])
    assert bridge.check_off_by_one(sink, buffer_size=size) == []


@pytest.mark.parametrize("mismatch,variable", [(1, "size"), (True, "other")])
def test_worker_cannot_change_verdict_type_or_variable_identity(monkeypatch, mismatch, variable):
    monkeypatch.setattr(bridge, "_try_z3_signed_mismatch", lambda *a:
                        bridge.SignedMismatchResult(mismatch=mismatch, variable=variable, witness={"size": -1}))
    result = bridge.check_signed_mismatch(guard("size < 16"), var_is_unsigned=True,
                                          comparison_is_signed=True, bit_width=8)
    assert result.mismatch is False and result.witness is None


def test_full_guard_model_survives_json_worker_transport(monkeypatch):
    pytest.importorskip("z3")
    calls = []
    def child(tag, args):
        calls.append((tag, args))
        return bridge._z3_dispatch_json({"tag": tag, "args": args})
    monkeypatch.setattr(bridge, "_z3_importable", lambda: True)
    monkeypatch.setattr(bridge, "_run_z3_child", child)
    text = "size < 16 && size < -1 && mode == 3"
    result = bridge.check_signed_mismatch(guard(text), var_is_unsigned=True,
                                          comparison_is_signed=True, bit_width=8)
    assert result.mismatch is True
    replay(text, result.witness)
    assert calls[0][0] == "signed_mismatch"
    assert len(calls[0][1]["constraints"]) == 3


def test_consistency_consumer_does_not_infer_signed_conversion_from_unsigned_declaration():
    from types import SimpleNamespace
    from core.audit.consistency_verify import _signedness_mismatch_smt
    deviation = SimpleNamespace(file="owned.c", enclosing_function="copy", tested_var="size", relop="<", bound_expr="16", line=1)
    result = _signedness_mismatch_smt(deviation, {"owned.c": "int copy(unsigned size) { return size < 16; }"})
    assert result.feasible is None
    assert result.witness is None
    assert "semantics not established" in result.reasoning
