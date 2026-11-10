"""Division receipts retain source scope and never authorise negative claims."""

from dataclasses import asdict
import builtins
from types import SimpleNamespace

import pytest

from core.audit import evidence_grade as grade, sweep
from core.audit.hypothesis_mapping import hypothesis_to_smt_verb
from core.audit.refutation_source import SourceIdentity
from core.audit.verification_results import ClaimRefutation, ProbeOutcome
from core.testing.module_views import module_function_view

SOURCE = 'int Read(int Left,int Right){return Left/Right;}'
CLAIM = 'division by zero in `Left / Right`'
VERB = 'check-integer-division'


@pytest.fixture(autouse=True)
def native_dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


@pytest.mark.parametrize('safe', [False, True])
def test_worker_routes_only_a_real_fault_to_a_scoped_positive_receipt(safe):
    source = SOURCE.replace('return Left/Right;', 'if(Right<=0)return 0;return Left/Right;') if safe else SOURCE
    result = sweep._run_smt_verb_inner(file_path='record.c', function_name='Read', verb=VERB,
                                      source=source, hypothesis=CLAIM, integer_abi='ilp32')
    assert result.outcome == ('inconclusive' if safe else 'confirmed')
    assert result.rule_id == 'smt:' + VERB
    assert result.details['source_scope']['function'] == 'Read'
    assert result.details['source_scope']['query_contract'] == 'source-integer-division-v4'
    assert result.details['oracle_scope'] == 'integer-division-fault'
    assert bool(result.matches) is not safe


@pytest.mark.parametrize('suffix', ['', ':witness', ':guessed'])
def test_only_exact_positive_receipt_is_verified_and_no_variant_can_refute(suffix):
    rule = 'smt:' + VERB + suffix
    assert grade.is_verification_evidence(rule) is (not suffix)
    scope = dict(file='record.c',function='Read',line_start=1,hypothesis=CLAIM)
    identity = SourceIdentity('source',(1,2,3))
    negative = ClaimRefutation(**scope, source_identity=identity, checks=(ProbeOutcome('smt','refuted',rule),))
    assert not negative.matches(**scope, source_identity=identity)


@pytest.mark.parametrize('changed', [None, 'hypothesis_sha256', 'integer_abi', 'query_contract', 'sha256'])
def test_parent_checks_the_exact_source_binding_before_accepting_worker_proof(changed):
    worker = sweep._run_smt_verb_inner(file_path='record.c',function_name='Read',verb=VERB,
                                      source=SOURCE,hypothesis=CLAIM,integer_abi='ilp32')
    data = asdict(worker)
    if changed:
        data['details']['source_scope'][changed] = 'other'

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'subproc_json' and level == 1:
            return SimpleNamespace(run_json_child=lambda *a, **kw: data)
        return builtins.__import__(name, globals, locals, fromlist, level)

    view = module_function_view(sweep, import_hook=import_local)
    result = view._smt_verb_in_subprocess(file_path='record.c',function_name='Read',verb=VERB,
                                        source=SOURCE,hypothesis=CLAIM,integer_abi='ilp32')
    assert result.outcome == ('inconclusive' if changed else 'confirmed')
    assert bool(result.matches) is (changed is None)


def test_hypothesis_and_cwe_dispatch_reach_the_mathematical_checker():
    from core.audit.cwe_dispatch import smt_verb_for_cwe
    assert hypothesis_to_smt_verb(CLAIM) == VERB
    assert hypothesis_to_smt_verb('remainder by zero at `Left % Right`') == VERB
    assert hypothesis_to_smt_verb('division overflow at `Left / Right`') == VERB
    assert smt_verb_for_cwe('CWE-369') == VERB
    assert sweep.get_smt_verb_role(VERB) == 'verification'


@pytest.mark.slow
def test_real_confined_worker_returns_a_source_bound_zero_divisor():
    result = sweep.run_smt_verb_direct(file_path='record.c',function_name='Read',verb=VERB,
                                      source=SOURCE,hypothesis=CLAIM,integer_abi='ilp32')
    assert result.outcome == 'confirmed', result.errors
    assert result.details['witness_validated'] is True
    assert result.details['model']['Right'] == 0
    assert result.details['source_scope']['integer_abi']['name'] == 'ilp32'


@pytest.mark.slow
def test_real_confined_worker_preserves_a_negative_literal_fault_subject():
    source = 'int Read(int Value){return Value/-1;}'
    claim = 'division overflow in `Value / -1`'
    result = sweep.run_smt_verb_direct(file_path='record.c', function_name='Read', verb=VERB,
                                      source=source, hypothesis=claim, integer_abi='lp64')
    assert result.outcome == 'confirmed', result.errors
    assert result.details['fault_kind'] == 'signed-division-overflow'
    assert result.details['model']['Value'] == -(1 << 31)
    assert result.details['witness_validated'] is True
    assert result.details['source_scope']['query_contract'] == 'source-integer-division-v4'
