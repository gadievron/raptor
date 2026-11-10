"""Unnormalised C-family digraphs cannot conceal call structure or effects."""

import pytest

from core.smt_solver import BVProfile
from core.smt_solver.call_arguments import find_call_end, mask_non_code, split_call_arguments
from core.smt_solver import path_feasibility as paths


def test_braced_digraph_cannot_preserve_scalar_state():
    pytest.importorskip("z3")
    call = "Updater<% &Value %>.result() == 0"
    conditions = [paths.PathCondition(text, i) for i, text in enumerate(["Value == 0", call, "Value == 1"])]
    result = paths.check_path_feasibility(conditions, profile=BVProfile(8, False), reduce_constraints=False)
    assert result.feasible is None
    assert result.model == {} and result.wp_complete is False
    assert result.unknown_reasons[0].kind.value == "unmodeled_state_effect"


@pytest.mark.parametrize("arguments", ["Array<:Index:>", "Object<%Value%>", "%:Directive"])
def test_code_digraphs_decline_opaque_argument_admission(arguments):
    assert mask_non_code(arguments)[1] is False
    assert split_call_arguments(arguments) is None
    assert find_call_end("probe(" + arguments + ")", 5) is None


@pytest.mark.parametrize("arguments", [
    '"<% %> <: :> %:"', "'<%'", 'R"tag(<% <: %:)tag"',
    "Value /* <% <: %: */", "Value // <% <: %:",
])
def test_digraph_data_in_literals_and_comments_stays_opaque(arguments):
    assert mask_non_code(arguments)[1] is True
    assert split_call_arguments(arguments) == (arguments,)
    # A line comment needs a real LF before the closing call delimiter.
    suffix = "\n)" if "//" in arguments else ")"
    call = "probe(" + arguments + suffix
    assert find_call_end(call, 5) == len(call)


def test_digraph_operand_refuses_before_native_allocation(monkeypatch):
    pytest.importorskip("z3")

    def forbidden(*args, **kwargs):
        pytest.fail("Unnormalised operand reached native allocation")

    monkeypatch.setattr(paths, "make_anon_call_var", forbidden)
    registry, model = {}, paths.CallOperandModel()
    with pytest.raises(ValueError, match="state effects"):
        paths.make_call_operand("probe(Array<:Index:>)", registry,
                                profile=BVProfile(8, False), model=model)
    assert registry == {} and model.anon_var_map == {} and model.axioms == []
