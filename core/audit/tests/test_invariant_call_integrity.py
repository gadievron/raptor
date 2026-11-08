"""Source call names do not establish mathematical semantics or purity."""

import pytest

from core.audit import invariant_smt as inv
from core.audit.invariant_source import source_mutations

pytestmark = pytest.mark.usefixtures("invariant_unit_worker")


@pytest.mark.parametrize("callee", ["min", "max"])
def test_a_standalone_call_cannot_establish_vacuous_preservation(callee):
    result = inv.check_invariant_preservation("Count <= Limit", callee + "();")
    assert result.outcome == "inconclusive", result.to_dict()
    assert any(site.verdict == "out_of_scope" for site in result.sites)


@pytest.mark.parametrize("callee", ["min", "max"])
def test_an_assignment_call_cannot_invent_a_source_transition(callee):
    result = inv.check_invariant_preservation("Count <= Limit", f"Count={callee}(Value,Limit);")
    assert result.outcome == "inconclusive", result.to_dict()
    assert all(site.verdict == "out_of_scope" and not site.model for site in result.sites)
    site = inv.check_site_preservation("Count <= Limit", f"Count={callee}(Value,Limit);")
    assert site.verdict == "out_of_scope" and not site.model


@pytest.mark.parametrize("callee", ["min", "max"])
def test_a_guard_call_cannot_borrow_a_mathematical_callee_contract(callee):
    source = (f"void Read(int (*{callee})(int,int),int Count,int Limit,int Value)"
              + f"{{if(Count<{callee}(Limit,Value))Count++;}}")
    result = inv.check_invariant_preservation("Count <= Limit", source)
    assert result.outcome == "inconclusive", result.to_dict()
    assert all(site.verdict == "out_of_scope" and not site.model for site in result.sites)


@pytest.mark.parametrize("callee", ["min", "max"])
def test_a_source_snapshot_with_an_evaluated_guard_call_is_unavailable(callee):
    sites, effects, refusal = source_mutations(f"if(Count<{callee}(Limit,Value))Count++;")
    assert not refusal and effects
    assert len(sites) == 1 and sites[0].reason


@pytest.mark.parametrize("callee", ["min", "max"])
def test_calls_in_an_unevaluated_sizeof_operand_do_not_execute(callee):
    result = inv.check_invariant_preservation("Count <= Limit", f"sizeof({callee}());")
    assert result.outcome == "preserved", result.to_dict()


def test_an_independent_admitted_site_can_still_show_a_violation():
    result = inv.check_invariant_preservation("Count <= Limit", "min();\nCount++;")
    assert result.outcome == "violable", result.to_dict()
    assert any(site.verdict == "violable" and site.model for site in result.sites)
    assert any(site.verdict == "out_of_scope" for site in result.sites)


def test_mathematical_minimum_remains_available_in_a_supplied_invariant():
    result = inv.check_site_preservation("Count <= min(Limit,Value)", "Count-=1;")
    assert result.verdict == "preserved", result.to_dict()


@pytest.mark.parametrize("transition", [
    "if(State->Count<min(State->Limit,Value)){\nState->Count++;\n}",
    "State->Count=max(Value,State->Limit);",
], ids=["guard-call", "assignment-call"])
def test_protocol_census_cannot_crop_an_unmodelled_source_call(transition):
    from core.audit.protocol_invariant_bindings import census_source_refusal

    source = "void Read(struct State *State,int Value){\n" + transition + "\n}"
    line = next(i for i, text in enumerate(source.splitlines(), 1)
                if "Count++" in text or "Count=max" in text)
    code = "State->Count++;" if "Count++" in source else "State->Count=max(Value,State->Limit);"
    assert census_source_refusal(source, "Read", line, code)


def test_an_explicit_mathematical_premise_still_constrains_a_site():
    result = inv.check_site_preservation("Count <= Limit", "Count++;",
                                         pre_conditions=("Count < min(Limit,Value)",))
    assert result.verdict == "preserved", result.to_dict()


@pytest.mark.parametrize("callee", ["min", "max"])
def test_an_audit_consumer_does_not_refute_a_claim_using_an_unbound_call(tmp_path, callee):
    from core.audit.orchestrator import OrchestratorConfig, TierCounters, _run_tool_chain

    source = f"Count={callee}(Value,Limit);\n"
    (tmp_path / "unit.c").write_text(source)
    counters = {"smt_invariant": TierCounters()}
    confirmed = _run_tool_chain(
        [{"type": "smt_invariant", "config": {"invariant": "Count <= Limit"}}],
        config=OrchestratorConfig(target_path=tmp_path, out_dir=None),
        file_path="unit.c", function_name="Read", source=source,
        hypothesis="Count can exceed Limit", tier_counters=counters,
    )
    assert confirmed == []
    assert counters["smt_invariant"].refuted == 0
    assert counters["smt_invariant"].confirmed == 0
