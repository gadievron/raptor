"""Shift-count receipts bind source, target ABI and independent operand types."""

import builtins
from dataclasses import asdict
from types import SimpleNamespace

import pytest

from core.audit import evidence_grade as grade, sweep
from core.audit.hypothesis_mapping import hypothesis_to_smt_verb
from core.audit.refutation_source import SourceIdentity
from core.audit.verification_results import ClaimRefutation, ProbeOutcome
from core.testing.module_views import module_function_view

SOURCE = 'unsigned Read(unsigned Value,unsigned long Count){if(Count==32)return Value<<Count;return 0;}'
CLAIM = 'invalid shift count in `Value << Count`'
VERB = 'check-shift-count'


@pytest.fixture(autouse=True)
def native_dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


@pytest.mark.parametrize('safe', [False, True])
def test_source_worker_keeps_only_positive_count_proofs(safe):
    source = SOURCE.replace('Count==32', 'Count<32') if safe else SOURCE
    result = sweep._run_smt_verb_inner(file_path='record.c',function_name='Read',verb=VERB,
                                      source=source,hypothesis=CLAIM,integer_abi='lp64')
    assert result.outcome == ('inconclusive' if safe else 'confirmed')
    assert result.details['oracle_scope'] == 'integer-shift-count'
    assert result.details['source_scope']['query_contract'] == 'independent-shift-count-v1'
    assert bool(result.matches) is (not safe)
    if not safe:
        assert result.details['count_value'] == 32
        assert result.details['source_operation']['left_promoted_width'] == 32
        assert result.details['source_operation']['count_promoted_width'] == 64


@pytest.mark.parametrize('suffix', ['', ':witness', ':guessed'])
def test_exact_positive_receipt_is_verified_but_cannot_refute_a_function(suffix):
    rule = 'smt:' + VERB + suffix
    assert grade.is_verification_evidence(rule) is (not suffix)
    identity = SourceIdentity('source',(1,2,3))
    scope = dict(file='record.c',function='Read',line_start=1,hypothesis=CLAIM)
    negative = ClaimRefutation(**scope,source_identity=identity,checks=(ProbeOutcome('smt','refuted',rule),))
    assert not negative.matches(**scope,source_identity=identity)


@pytest.mark.parametrize('changed', [None, 'integer_abi', 'hypothesis_sha256', 'query_contract', 'sha256'])
def test_parent_rejects_mismatched_worker_inputs(changed):
    worker = sweep._run_smt_verb_inner(file_path='record.c',function_name='Read',verb=VERB,
                                      source=SOURCE,hypothesis=CLAIM,integer_abi='lp64')
    data = asdict(worker)
    if changed:
        data['details']['source_scope'][changed] = 'other'

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'subproc_json' and level == 1:
            return SimpleNamespace(run_json_child=lambda *a, **kw: data)
        return builtins.__import__(name, globals, locals, fromlist, level)

    view = module_function_view(sweep, import_hook=import_local)
    result = view._smt_verb_in_subprocess(file_path='record.c',function_name='Read',verb=VERB,
                                        source=SOURCE,hypothesis=CLAIM,integer_abi='lp64')
    assert result.outcome == ('inconclusive' if changed else 'confirmed')
    assert bool(result.matches) is (changed is None)


def test_hypothesis_dispatch_uses_the_count_oracle_only():
    assert hypothesis_to_smt_verb(CLAIM) == VERB
    assert hypothesis_to_smt_verb('negative shift count at `Value >> Count`') == VERB
    assert sweep.get_smt_verb_role(VERB) == 'verification'
    result = sweep._run_smt_verb_inner(file_path='record.c',function_name='Read',verb=VERB,
                                      source=SOURCE,hypothesis=CLAIM,integer_abi=None)
    assert result.outcome == 'inconclusive' and result.details['integer_abi_status'] == 'unavailable'


@pytest.mark.slow
def test_real_confined_worker_preserves_independent_shift_widths():
    result = sweep.run_smt_verb_direct(file_path='record.c',function_name='Read',verb=VERB,
                                      source=SOURCE,hypothesis=CLAIM,integer_abi='lp64')
    assert result.outcome == 'confirmed', result.errors
    assert result.details['model']['Count'] == 32
    assert result.details['source_operation']['left_promoted_width'] == 32
    assert result.details['source_operation']['count_promoted_width'] == 64
    assert result.details['source_scope']['integer_abi']['name'] == 'lp64'
