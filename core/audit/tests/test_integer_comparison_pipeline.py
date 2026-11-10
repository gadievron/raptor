"""A proved predicate observation remains distinct from a proved defect."""

import builtins
from dataclasses import asdict
from types import SimpleNamespace

import pytest

from core.audit import sweep
from core.audit.hypothesis_mapping import hypothesis_to_smt_verb
from core.audit.probe_function_scope import source_binding
from core.audit.smt_evidence import is_diagnostic_smt_rule, is_non_refuting_smt_rule
from core.testing.module_views import module_function_view

SOURCE = "int Read(unsigned Value){if(Value<0)return 1;return 0;}"
CLAIM = "comparison is always false: `Value < 0`"


def test_native_worker_preserves_source_abi_and_diagnostic_scope():
    result = sweep._run_smt_verb_inner(file_path="unit.c", function_name="Read", verb="check-integer-comparison",
                                      source=SOURCE, hypothesis=CLAIM, integer_abi="lp64")
    assert result.outcome == "confirmed", result.details
    assert result.details["entry_witness_validated"] is True
    binding = result.details["source_scope"]
    assert binding == source_binding(SOURCE, "Read", verb="check-integer-comparison", integer_abi="lp64", hypothesis=CLAIM)
    assert binding["query_contract"] == "source-integer-comparison-v7"
    assert binding["hypothesis_sha256"]
    assert binding["integer_abi"]["name"] == "lp64"
    assert is_diagnostic_smt_rule(result.rule_id)
    assert is_non_refuting_smt_rule(result.rule_id)
    assert sweep.get_smt_verb_role("check-integer-comparison") == "detection"
    assert hypothesis_to_smt_verb(CLAIM) == "check-integer-comparison"


def test_opposite_subject_and_missing_abi_never_clear_a_function():
    for abi, claim in [(None, CLAIM), ("lp64", CLAIM.replace("false", "true"))]:
        result = sweep._run_smt_verb_inner(file_path="unit.c", function_name="Read", verb="check-integer-comparison",
                                          source=SOURCE, hypothesis=claim, integer_abi=abi)
        assert result.outcome == "inconclusive"
        assert result.matches == []


@pytest.mark.parametrize("changed", [None, "hypothesis_sha256", "integer_abi", "query_contract", "sha256"])
def test_parent_rejects_a_comparison_proof_for_different_inputs(changed):
    worker = sweep._run_smt_verb_inner(file_path="unit.c", function_name="Read", verb="check-integer-comparison",
                                      source=SOURCE, hypothesis=CLAIM, integer_abi="lp64")
    data = asdict(worker)
    if changed:
        data["details"]["source_scope"][changed] = "other"

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "subproc_json" and level == 1:
            return SimpleNamespace(run_json_child=lambda *a, **kw: data)
        return builtins.__import__(name, globals, locals, fromlist, level)

    view = module_function_view(sweep, import_hook=import_local)
    result = view._smt_verb_in_subprocess(file_path="unit.c", function_name="Read", verb="check-integer-comparison",
                                        source=SOURCE, hypothesis=CLAIM, integer_abi="lp64")
    assert result.outcome == ("inconclusive" if changed else "confirmed")
    assert bool(result.matches) is (changed is None)


@pytest.mark.slow
def test_real_confined_comparison_worker_retains_diagnostic_scope():
    result = sweep.run_smt_verb_direct(file_path="unit.c", function_name="Read", verb="check-integer-comparison",
                                      source=SOURCE, hypothesis=CLAIM, integer_abi="lp64")
    assert result.outcome == "confirmed", result.errors
    assert result.details["oracle_scope"] == "source-integer-comparison"
    assert result.details["constant_truth"] is False
    assert result.details["entry_witness_validated"] is True


def test_mask_observation_uses_the_versioned_diagnostic_comparison_channel():
    source = 'int Read(unsigned Flags){if((Flags & 5)==2)return 1;return 0;}'
    claim = 'Comparison is always false in `(Flags & 5) == 2`.'
    result = sweep._run_smt_verb_inner(file_path='unit.c', function_name='Read', verb='check-integer-comparison',
                                      source=source, hypothesis=claim, integer_abi='lp64')
    assert result.outcome == 'confirmed', result.details
    assert result.details['source_scope'] == source_binding(source, 'Read', verb='check-integer-comparison',
                                                            hypothesis=claim, integer_abi='lp64')
    assert result.details['source_scope']['query_contract'] == 'source-integer-comparison-v7'
    assert result.details['checked_property'] == 'constant-mask-comparison'
    assert is_diagnostic_smt_rule(result.rule_id) and is_non_refuting_smt_rule(result.rule_id)
    assert sweep.get_smt_verb_role('check-integer-comparison') == 'detection'


@pytest.mark.slow
def test_real_confined_mask_comparison_worker_retains_diagnostic_scope():
    result = sweep.run_smt_verb_direct(file_path='unit.c', function_name='Read', verb='check-integer-comparison',
                                      source='int Read(unsigned Flags){if((Flags & 5)==2)return 1;return 0;}',
                                      hypothesis='Comparison is always false in `(Flags & 5) == 2`.', integer_abi='lp64')
    assert result.outcome == 'confirmed', result.errors
    assert result.details['oracle_scope'] == 'source-integer-comparison'
    assert result.details['constant_truth'] is False and result.details['entry_witness_validated']
    assert result.details['source_scope']['query_contract'] == 'source-integer-comparison-v7'
