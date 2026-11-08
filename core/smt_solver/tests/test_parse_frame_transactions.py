"""Rejected parse attempts cannot establish scalar identity for later guards."""

import pytest

from core.smt_solver import BVProfile
from core.smt_solver import path_feasibility as paths
from core.smt_solver.rejection import Rejection

PROFILE = BVProfile(32, True)


@pytest.fixture(autouse=True)
def native_solver():
    pytest.importorskip("z3")


def guards(*texts):
    return [paths.PathCondition(text, n) for n, text in enumerate(texts)]


def verb_query(conditions, **kwargs):
    return paths.check_verb_feasibility([], conditions, {}, **kwargs)


@pytest.mark.parametrize("entry", [paths.check_path_feasibility, paths.check_path_feasibility_dual, verb_query])
@pytest.mark.parametrize("reduce", [False, True])
@pytest.mark.parametrize("lead", ["Alias + == 0", "abs((Alias)Value) == 0", "max((Alias)Value,0) == 0"])
def test_a_failed_parse_cannot_make_a_later_cast_into_scalar_arithmetic(entry, reduce, lead):
    # With typedef unsigned short Alias and Value=65536, the two casts
    # both produce zero. Failed parsing must not invent a scalar Alias.
    cast = "(Alias)+Value == (Alias)-Value"
    result = entry(guards(lead, "Value == 65536", cast), profile=PROFILE, reduce_constraints=reduce)
    assert result.feasible is None, result
    assert cast in result.unknown
    assert "Alias" not in result.model and result.wp_complete is False


@pytest.mark.parametrize("parser", [paths._parse_expr, paths._parse_typed_expr])
def test_an_expression_rejection_preserves_existing_and_lazy_registry_entries(parser):
    from core.smt_solver import z3

    keep = z3.BitVec("existing", 32)
    registry = {"Keep": keep, "Fresh": None}
    result = parser("Warm + Fresh +", registry, profile=PROFILE)
    assert isinstance(result, Rejection)
    assert set(registry) == {"Keep", "Fresh"}
    assert registry["Keep"] is keep and registry["Fresh"] is None


@pytest.mark.parametrize("callee,args,has_summary", [
    ("min", "Warm,(Alias)Value", False),
    ("max", "Warm,(Alias)Value", False),
    ("abs", "(Alias)Value", True),
])
def test_incomplete_summary_arguments_do_not_publish_partial_scalar_bindings(callee, args, has_summary):
    from core.smt_solver import z3

    registry = {"Warm": None}
    result = paths._summarise_call(callee, args, f"{callee}({args})", z3.BitVec("result", 32), registry, profile=PROFILE)
    assert (result is not None) is has_summary
    assert registry == {"Warm": None}


def test_a_rejected_condition_does_not_publish_call_labels_axioms_or_scalar_bindings():
    from core.smt_solver import z3

    keep = z3.BitVec("existing", 32)
    previous = ("existing axiom", keep == 0)
    registry, calls, axioms = {"Keep": keep, "Bound": None}, {"Keep": "earlier()"}, [previous]
    result = paths._parse_condition("strlen(Data) == Bound +", registry, profile=PROFILE, anon_map=calls, axiom_sink=axioms)
    assert isinstance(result, Rejection)
    assert set(registry) == {"Keep", "Bound"} and registry["Keep"] is keep and registry["Bound"] is None
    assert calls == {"Keep": "earlier()"} and len(axioms) == 1 and axioms[0] is previous
    result = paths._parse_condition("strlen(Data) == 1", registry, profile=PROFILE, anon_map=calls, axiom_sink=axioms)
    assert not isinstance(result, Rejection)
    assert calls == {"Keep": "earlier()", "_anon_0": "strlen(Data)"}
    assert len(axioms) == 2 and axioms[0] is previous


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_native_errors_and_interrupts_do_not_leave_partial_condition_frames(monkeypatch, error):
    from core.smt_solver import z3

    keep = z3.BitVec("existing", 32)
    registry, calls, axioms = {"Keep": keep}, {}, []
    original = paths._mk_var

    def construct(name, width):
        if name == "Bomb":
            raise error("native allocation failed")
        return original(name, width)

    monkeypatch.setattr(paths, "_mk_var", construct)
    with pytest.raises(error):
        paths._parse_condition("strlen(Data) == Bomb", registry, profile=PROFILE, anon_map=calls, axiom_sink=axioms)
    assert set(registry) == {"Keep"} and registry["Keep"] is keep
    assert calls == {} and axioms == []


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_failed_call_operand_summaries_do_not_publish_an_orphan_occurrence(monkeypatch, error):
    from core.smt_solver import z3

    keep = z3.BitVec("existing", 32)
    registry = {"Keep": keep}
    model = paths.CallOperandModel()

    def fail(var, arguments, variables, profile):
        paths.make_var("Ghost", variables, profile=profile)
        raise error("summary failed")

    monkeypatch.setitem(paths._CALL_SUMMARIES, "min", (2, fail))
    with pytest.raises(error):
        paths.make_call_operand("min(Value,4)", registry, profile=PROFILE, model=model)
    assert set(registry) == {"Keep"} and registry["Keep"] is keep
    assert model.anon_var_map == {} and model.axioms == []


def test_a_completed_condition_still_binds_scalar_grouping_for_later_guards():
    result = paths.check_path_feasibility(guards("Alias == 0", "Value == 7", "(Alias)+Value == Value"),
                                           profile=PROFILE, reduce_constraints=False)
    assert result.feasible is True and result.unknown == []
    assert result.model["Alias"] == 0 and result.model["Value"] == 7


@pytest.mark.parametrize("parser", [paths._parse_expr, paths._parse_typed_expr])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_expression_errors_do_not_publish_names_parsed_before_the_failure(monkeypatch, parser, error):
    from core.smt_solver import z3

    keep = z3.BitVec("existing", 32)
    registry = {"Keep": keep}
    original = paths._mk_var

    def construct(name, width):
        if name == "Bomb":
            raise error("native allocation failed")
        return original(name, width)

    monkeypatch.setattr(paths, "_mk_var", construct)
    with pytest.raises(error):
        parser("Warm + Bomb", registry, profile=PROFILE)
    assert set(registry) == {"Keep"} and registry["Keep"] is keep


@pytest.mark.parametrize("direction", ["min", "max"])
def test_failed_conditions_do_not_create_phantom_witness_objectives(direction):
    result = paths.check_path_feasibility(guards("Alias + == 0", "Value == 3"), profile=PROFILE,
                                           prefer_witness=("Alias", direction), reduce_constraints=False)
    assert result.feasible is None
    assert result.model == {"Value": 3}
    assert result.unknown == ["Alias + == 0"]
