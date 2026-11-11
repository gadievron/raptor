"""Grouping observations carry an entry witness, never an intent verdict."""

import pytest

from core.audit import sweep

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_c")
pytest.importorskip("z3")

SOURCE = "int Test(unsigned int Flags) { if(Flags & 4 == 4) return 1; return 0; }"
CLAIM = "Condition grouping changes truth in `Flags & 4 == 4`."
VERB = "check-integer-comparison"


def test_source_dispatch_reports_only_the_two_replayed_truths():
    result = sweep._run_smt_verb_inner(file_path="unit.c", function_name="Test", verb=VERB,
                                     source=SOURCE, hypothesis=CLAIM, integer_abi="lp64")
    assert result.outcome == "confirmed", result.details
    assert result.details["actual_truth"] != result.details["grouped_truth"]
    assert result.details["entry_witness_validated"]
    assert "constant_truth" not in result.details


def test_grouping_observations_never_gain_verification_or_refutation_credit():
    from core.audit import evidence_grade
    from core.audit.smt_evidence import is_diagnostic_smt_rule, is_non_refuting_smt_rule
    from core.audit.hypothesis_mapping import hypothesis_to_smt_verb

    assert hypothesis_to_smt_verb(CLAIM) == VERB
    for suffix in ("", ":witness", ":model"):
        rule = "smt:" + VERB + suffix
        assert is_diagnostic_smt_rule(rule) and is_non_refuting_smt_rule(rule)
        assert not evidence_grade.is_verification_evidence(rule)


def test_quality_grouping_discovery_is_pure_and_idempotent(monkeypatch):
    from core.audit import arithmetic_seeds, integer_grouping

    def forbidden(*args, **kwargs):
        raise AssertionError("discovery entered the grouping proof")
    monkeypatch.setattr(integer_grouping, "new_solver", forbidden)
    monkeypatch.setattr(integer_grouping, "guards_for_operation", forbidden)
    gap = dict(file="unit.c", name="Test", line_start=1, line_end=1)
    assert arithmetic_seeds.seed_arithmetic_hypotheses([gap], {"unit.c": SOURCE}, mode="quality", integer_abi="lp64") == 1
    row = gap["injected_hypotheses"][0]
    assert row["mechanism"] == CLAIM and row["arithmetic_site"]["claim_kind"] == "grouping-truth-difference"
    assert row["arithmetic_site"]["binding_status"] == "candidate"
    assert arithmetic_seeds.seed_arithmetic_hypotheses([gap], {"unit.c": SOURCE}, mode="quality", integer_abi="lp64") == 0
    other = dict(file="unit.c", name="Test", line_start=1, line_end=1)
    assert arithmetic_seeds.seed_arithmetic_hypotheses([other], {"unit.c": SOURCE}, mode="security", integer_abi="lp64") == 0


@pytest.mark.slow
def test_real_confined_grouping_receipt():
    result = sweep.run_smt_verb_direct(file_path="unit.c", function_name="Test", verb=VERB,
                                       source=SOURCE, hypothesis=CLAIM, integer_abi="lp64")
    assert result.outcome == "confirmed", result.errors
    assert result.details["source_scope"]["query_contract"] == "source-integer-comparison-v10"
    assert result.details["actual_truth"] != result.details["grouped_truth"]
    assert result.details["entry_witness_validated"] and "constant_truth" not in result.details


@pytest.mark.parametrize("field", ["sha256", "hypothesis_sha256", "query_contract", "integer_abi"])
def test_parent_rejects_grouping_receipts_bound_to_different_inputs(field):
    import builtins
    from copy import deepcopy
    from dataclasses import asdict
    from types import SimpleNamespace
    from core.testing.module_views import module_function_view

    reply = asdict(sweep._run_smt_verb_inner(file_path="unit.c", function_name="Test", verb=VERB,
                                           source=SOURCE, hypothesis=CLAIM, integer_abi="lp64"))
    assert reply["outcome"] == "confirmed"
    reply = deepcopy(reply)
    reply["details"]["source_scope"][field] = "changed"

    def importer(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "subproc_json" and level == 1:
            return SimpleNamespace(run_json_child=lambda *args, **kwargs: reply)
        return builtins.__import__(name, globals, locals, fromlist, level)
    view = module_function_view(sweep, import_hook=importer)
    result = view._smt_verb_in_subprocess(file_path="unit.c", function_name="Test", verb=VERB,
                                          source=SOURCE, hypothesis=CLAIM, integer_abi="lp64")
    assert result.outcome == "inconclusive" and not result.matches
