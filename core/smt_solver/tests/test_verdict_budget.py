"""Verdict-only queries retain obligations while avoiding optional solver work."""

import pytest

from core.smt_solver import BV_C_INT8, BV_C_UINT8
from core.smt_solver import path_feasibility as paths


def conditions(*texts):
    return [paths.PathCondition(text, n) for n, text in enumerate(texts)]


@pytest.fixture(autouse=True)
def z3_required():
    pytest.importorskip("z3")


@pytest.fixture
def no_reduction(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("verdict-only queries must not run optional reduction")
    monkeypatch.setattr(paths, "_extract_wp", forbidden)


@pytest.mark.parametrize("reduce,expected_checks,expected_solvers", [(True, 5, 3), (False, 1, 1)])
def test_bounded_solver_work(monkeypatch, reduce, expected_checks, expected_solvers):
    factory = paths._new_solver
    counts = {"solvers": 0, "checks": 0}

    def counted_solver(*args, **kwargs):
        solver = factory(*args, **kwargs)
        check = solver.check
        counts["solvers"] += 1

        def counted_check(*args, **kwargs):
            counts["checks"] += 1
            return check(*args, **kwargs)
        monkeypatch.setattr(solver, "check", counted_check)
        return solver

    monkeypatch.setattr(paths, "_new_solver", counted_solver)
    result = paths.check_path_feasibility(conditions("Value > 0", "Value < 10"),
                                          profile=BV_C_UINT8, reduce_constraints=reduce)
    assert result.feasible is True
    assert 0 < result.model["Value"] < 10
    assert counts == {"solvers": expected_solvers, "checks": expected_checks}
    assert result.wp_complete is reduce
    assert (result.wp_predicate is not None) is reduce
    if not reduce:
        assert result.wp_conjuncts == [] and result.satisfied == []


@pytest.mark.parametrize("texts,expected", [
    (("Value > 0", "Value < 10"), True),
    (("Value > 10", "Value < 5"), False),
    (("Value == Value",), True),
    (("Value == 1", "Value == 2"), False),
    ((), True),
], ids=["bounded-sat", "contradiction", "tautology", "equalities", "empty"])
def test_full_obligation_and_conflicts(no_reduction, texts, expected):
    result = paths.check_path_feasibility(conditions(*texts), profile=BV_C_UINT8, reduce_constraints=False)
    assert result.feasible is expected
    assert result.wp_predicate is None and result.wp_conjuncts == [] and result.wp_complete is False
    assert not result.unknown
    if not expected:
        assert result.unsatisfied


def test_call_summary_axioms_remain_asserted(no_reduction):
    result = paths.check_path_feasibility(conditions("strlen(Data) < 0"),
                                          profile=BV_C_INT8, reduce_constraints=False)
    assert result.feasible is False, result
    assert result.summary_axioms and result.unsatisfied


def test_unparsed_conditions_remain_visible(no_reduction):
    result = paths.check_path_feasibility(conditions("Value == 3", "unrecognized prose"),
                                          profile=BV_C_UINT8, reduce_constraints=False)
    assert result.feasible is None and result.model["Value"] == 3
    assert result.unknown == ["unrecognized prose"] and result.unknown_reasons
    assert result.wp_complete is False


@pytest.mark.parametrize("direction,expected", [("min", -5), ("max", 7)])
def test_extremal_witness_still_obeys_all_guards(no_reduction, direction, expected):
    result = paths.check_path_feasibility(conditions("Value >= -5", "Value <= 7"),
                                          profile=BV_C_INT8, prefer_witness=("Value", direction),
                                          reduce_constraints=False)
    assert result.feasible is True and result.model["Value"] == expected


def test_dual_keeps_required_contradiction_probes(no_reduction, monkeypatch):
    original = paths.check_path_feasibility
    calls = []

    def observe(*args, **kwargs):
        calls.append(kwargs["reduce_constraints"])
        return original(*args, **kwargs)
    monkeypatch.setattr(paths, "check_path_feasibility", observe)
    result = paths.check_path_feasibility_dual(conditions("Value == 1", "Value == 2"),
                                               profile=BV_C_UINT8, reduce_constraints=False)
    assert result.feasible is False
    assert len(calls) >= 4 and not any(calls)


def test_dual_public_result_preserves_sibling_timeout_and_deduplicates_rejections(monkeypatch):
    from core.smt_solver.rejection import RejectionKind
    from core.smt_solver.session import query_budget
    from packages.exploit_feasibility.smt_path import validate_path

    original = paths.check_path_feasibility
    legs = []

    def observe(*args, **kwargs):
        if legs:
            with query_budget(0):
                result = original(*args, **kwargs)
        else:
            result = original(*args, **kwargs)
        legs.append(result)
        return result

    monkeypatch.setattr(paths, 'check_path_feasibility', observe)
    for extra in [[], ['unrecognized @ syntax']]:
        legs.clear()
        result = validate_path(['Value < 0', *extra], reduce_constraints=False)
        assert len(legs) == 2
        assert legs[0].feasible is False and legs[1].feasible is None
        assert any(reason.kind is RejectionKind.SOLVER_TIMEOUT for reason in legs[1].unknown_reasons)
        assert result['feasible'] is None and result['model'] == {}
        assert result['wp_complete'] is False
        assert result['unknown'] == [*extra, 'Value < 0']
        reasons = result['unknown_reasons']
        assert len(reasons) == 1 + len(extra)
        assert sum(reason['kind'] == 'solver_timeout' for reason in reasons) == 1


def test_dual_rejection_disclosure_keeps_successful_fallback_and_primary_unknown(monkeypatch):
    from core.smt_solver.session import query_budget

    fallback = paths.check_path_feasibility_dual(conditions('Value < 0'), profile=BV_C_UINT8,
                                                reduce_constraints=False)
    assert fallback.feasible is True and fallback.model['Value'] < 0
    assert fallback.unknown == [] and fallback.unknown_reasons == []
    original = paths.check_path_feasibility
    calls = []

    def expired(*args, **kwargs):
        calls.append(kwargs['profile'])
        with query_budget(0):
            return original(*args, **kwargs)

    monkeypatch.setattr(paths, 'check_path_feasibility', expired)
    result = paths.check_path_feasibility_dual(conditions('Value < 0'), profile=BV_C_UINT8,
                                              reduce_constraints=False)
    assert len(calls) == 1 and result.feasible is None
    assert result.unknown == ['Value < 0'] and len(result.unknown_reasons) == 1


def test_dual_ambiguous_unsat_keeps_shared_parser_rejection_once():
    result = paths.check_path_feasibility_dual(
        conditions('Low < 0', 'High > 127', 'unrecognized @ syntax'),
        profile=BV_C_UINT8, reduce_constraints=False)
    assert result.feasible is None and result.model == {}
    assert result.unknown == ['unrecognized @ syntax']
    assert len(result.unknown_reasons) == 1


def test_dual_public_result_preserves_contradiction_probe_timeout(monkeypatch):
    from core.smt_solver.session import query_budget
    from packages.exploit_feasibility.smt_path import validate_path

    original = paths.check_path_feasibility
    queries = []

    def observe(*args, **kwargs):
        if len(queries) >= 2:
            with query_budget(0):
                result = original(*args, **kwargs)
        else:
            result = original(*args, **kwargs)
        queries.append(result)
        return result

    monkeypatch.setattr(paths, 'check_path_feasibility', observe)
    result = validate_path(['Value == 1', 'Value == 2'], reduce_constraints=False)
    assert [query.feasible for query in queries] == [False, False, None]
    assert result['feasible'] is None and result['model'] == {} and result['wp_complete'] is False
    assert result['unknown'] == ['Value == 1', 'Value == 2']
    assert len(result['unknown_reasons']) == 2
    assert all(reason['kind'] == 'solver_timeout' for reason in result['unknown_reasons'])


@pytest.mark.parametrize("entry", [paths.check_path_feasibility, paths.check_path_feasibility_dual])
@pytest.mark.parametrize("bad", [None, 0, 1, "false"])
def test_strict_option_before_native_work(monkeypatch, entry, bad):
    def forbidden(*args, **kwargs):
        pytest.fail("invalid option must not create native solvers")
    monkeypatch.setattr(paths, "_new_solver", forbidden)
    with pytest.raises(ValueError, match="reduce_constraints"):
        entry(conditions("Value > 0"), reduce_constraints=bad)


def test_no_z3_does_not_claim_a_summary(monkeypatch):
    monkeypatch.setattr(paths, "_z3_available", lambda: False)
    result = paths.check_path_feasibility(conditions("Value > 0"), reduce_constraints=False)
    assert result.feasible is None and result.smt_available is False and result.wp_complete is False


def test_budget_refusal_does_not_discard_guards(no_reduction):
    guards = conditions(*[f"Value == {n}" for n in range(65)])
    result = paths.check_path_feasibility(guards, reduce_constraints=False)
    assert result.feasible is None and len(result.unknown) == 65 and result.wp_complete is False
