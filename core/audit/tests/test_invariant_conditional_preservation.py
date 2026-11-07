"""A proof under extra nonnegative assumptions is not unconditional safety."""

import pytest

from core.audit import invariant_smt as inv
from core.audit.protocol_state import (
    check_invariant_multi_site,
    run_protocol_state_check,
)

pytestmark = pytest.mark.usefixtures("invariant_unit_worker")


@pytest.fixture(autouse=True)
def grammar():
    pytest.importorskip("tree_sitter_c")
    pytest.importorskip("z3")


def test_function_preservation_keeps_negative_counterexample_without_claiming_safety():
    result = inv.check_invariant_preservation("Count <= Limit", "Count=0;")
    assert result.outcome == "inconclusive", result.to_dict()
    site = result.sites[0]
    assert site.verdict == "preserved_nonneg" and site.model
    assert site.model["Count"] <= site.model["Limit"] < site.model["Count'"] == 0
    assert "non-negative" in result.reason


def test_protocol_aggregate_keeps_conditional_preservation_inconclusive():
    site = dict(file="a.c", function="", line=1, code="State->Count=0;")
    result = check_invariant_multi_site(
        "Count <= Limit", {"fields": {"Count": {"writes": [site]}}}, {}
    )
    assert result["outcome"] == "inconclusive", result
    assert result["sites"][0]["verdict"] == "preserved_nonneg"
    assert "non-negative" in result["reason"]


def test_protocol_adjudicator_never_refutes_on_assumed_nonnegative_inputs():
    result = run_protocol_state_check(
        ".",
        "a.c",
        "Reset",
        "Count <= Limit",
        invariant="Count <= Limit",
        source_texts={"a.c": "void Reset(struct S *State){\nState->Count=0;\n}"},
    )
    assert result.outcome == "inconclusive", result.to_dict()
    assert result.invariant["per_site"][0]["verdict"] == "preserved_nonneg"


@pytest.mark.parametrize(
    "body",
    ["if(Limit>=0)Count=0;", "if(Count>=0)Count=0;", "Count=Limit;"],
    ids=["guarded-bound", "guarded-prestate", "unconditional-assignment"],
)
def test_source_bound_assumptions_still_allow_preservation(body):
    result = inv.check_invariant_preservation("Count <= Limit", body)
    assert result.outcome == "preserved", result.to_dict()
    assert all(site.verdict == "preserved" for site in result.sites)


def test_real_violation_is_not_hidden_by_a_conditional_site():
    result = inv.check_invariant_preservation("Count <= Limit", "Count=0;Count++;")
    assert result.outcome == "violable", result.to_dict()
    assert {site.verdict for site in result.sites} == {"preserved_nonneg", "violable"}


def test_worker_cannot_upgrade_a_conditional_receipt_to_preserved(monkeypatch):
    from core.audit import condition_smt

    def dispatch(tag, args, **kwargs):
        reply = condition_smt._z3_dispatch_json({"tag": tag, "args": args})
        assert reply["result"]["outcome"] == "inconclusive"
        reply["result"]["outcome"] = "preserved"
        return reply

    monkeypatch.setattr(condition_smt, "_run_z3_child", dispatch)
    result = inv.check_invariant_preservation("Count <= Limit", "Count=0;")
    assert result.outcome == "inconclusive"
    assert "inconsistent" in result.reason


def test_batch_keeps_conditional_and_established_assumptions_distinct():
    results = inv.check_site_batch(
        "Count <= Limit",
        [
            dict(code="Count=0;", line=1, pre_conditions=[]),
            dict(code="Count=0;", line=2, pre_conditions=["Limit>=0"]),
        ],
    )
    assert [site.verdict for site in results] == ["preserved_nonneg", "preserved"]
    assert results[0].model and results[1].model == {}


def test_audit_tool_chain_books_conditional_preservation_as_inconclusive(tmp_path):
    from core.audit.orchestrator import OrchestratorConfig, _run_tool_chain

    target = tmp_path / "target"
    target.mkdir()
    code = "void Reset(int Count,int Limit){Count=0;}"
    (target / "a.c").write_text(code)
    config = OrchestratorConfig(target_path=target, out_dir=tmp_path / "out")
    inconclusive = set()
    result = _run_tool_chain(
        [{"type": "smt_invariant", "config": {"invariant": "Count <= Limit"}}],
        config=config,
        file_path="a.c",
        function_name="Reset",
        source=code,
        hypothesis="Count <= Limit can be violated",
        line_start=1,
        inconclusive_types=inconclusive,
    )
    assert result == []
    assert inconclusive == {"smt_invariant"}
    assert [outcome.verdict for outcome in result.outcomes] == ["inconclusive"]
    assert (
        result.refutation(
            file="a.c",
            function="Reset",
            line_start=1,
            hypothesis="Count <= Limit can be violated",
        )
        is None
    )


@pytest.mark.slow
@pytest.mark.parametrize(
    "guarded", [False, True], ids=["conditional", "established-guard"]
)
def test_native_worker_keeps_conditional_preservation_scoped(guarded):
    code = "if(Limit>=0)Count=0;" if guarded else "Count=0;"
    result = inv.check_invariant_preservation("Count <= Limit", code)
    assert result.outcome == ("preserved" if guarded else "inconclusive"), (
        result.to_dict()
    )
    assert result.sites[0].verdict == ("preserved" if guarded else "preserved_nonneg")
