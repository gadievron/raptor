"""Bounds verification consumes proven scalar prefixes without inventing values."""

from dataclasses import asdict

import pytest

from core.audit.array_bounds import check_array_bounds, bind_array_access
from core.audit.probe_function_scope import source_binding, source_for_function
from core.audit import sweep


@pytest.fixture(autouse=True)
def dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter')
    pytest.importorskip('tree_sitter_c')


def source(prefix, extra='unsigned Extra', guard='Index>=0 && Index<=4'):
    return ('int Read(int Index,' + extra + '){int Data[4]={0};' + prefix
            + 'if(' + guard + '){return Data[Index];}return 0;}')


@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('prefix,extra', [
    ('unsigned Local=Extra+1;', 'unsigned Extra'),
    ('unsigned Local=Extra-1;', 'unsigned Extra'),
    ('unsigned Local=Extra*2;', 'unsigned Extra'),
    ('unsigned Local=Extra/2;', 'unsigned Extra'),
    ('unsigned Local=Extra%3;', 'unsigned Extra'),
    ('unsigned Local=Extra<<31;', 'unsigned Extra'),
    ('unsigned Local=Extra>>1;', 'unsigned Extra'),
    ('int Local=Extra<<1;', 'unsigned char Extra'),
    ('int Local=Extra*2;', 'unsigned char Extra'),
])
def test_array_source_verifier_consumes_proven_arithmetic_prefixes(prefix, extra, language):
    if language == 'cpp':
        pytest.importorskip('tree_sitter_cpp')
    result = check_array_bounds(source(prefix, extra), 'out-of-bounds read at Data[Index]', language=language, integer_abi='ilp32')
    assert result['array_bounds_status'] == 'checked', result
    assert result['violation'] is True and result['witness_index'] == 4
    assert set(result['model']) == {'Index', 'Extra'}
    assert all(name != 'Local' for name, _ in result['source_access']['types'])


@pytest.mark.parametrize('prefix,extra', [
    ('int Local=Extra+1;', 'int Extra'),
    ('int Local=Extra*2;', 'int Extra'),
    ('int Local=Extra<<1;', 'int Extra'),
    ('unsigned Local=Extra<<32;', 'unsigned Extra'),
    ('unsigned Local=Index/Extra;', 'unsigned Extra'),
    ('unsigned Local=Local;', 'unsigned Extra'),
    ('int Other[4]={0};', 'unsigned Extra'),
    ('unsigned Local;', 'unsigned Extra'),
])
def test_undefined_or_unsupported_prefix_cannot_certify_an_array_read(prefix, extra):
    result = check_array_bounds(source(prefix, extra), 'out-of-bounds read at Data[Index]', language='c', integer_abi='ilp32')
    assert result['array_bounds_status'] == 'unavailable' and result['violation'] is None


def test_local_values_do_not_become_free_inputs_for_array_guards():
    text = source('int Local=0;', guard='Index==Local')
    result = bind_array_access(text, 'out-of-bounds read at Data[Index]', language='c', integer_abi='ilp32')
    assert result.status == 'unavailable'


def test_a_safe_access_stays_a_site_result_with_a_defined_prefix():
    result = check_array_bounds(source('unsigned Local=Extra<<1;', guard='Index>=0 && Index<4'),
                                'out-of-bounds read at Data[Index]', language='c', integer_abi='ilp32')
    assert result['array_bounds_status'] == 'checked' and result['violation'] is False
    assert 'model' not in result


def test_real_audit_dispatch_keeps_the_bound_array_witness():
    result = sweep._run_smt_verb_inner(file_path='record.c', function_name='Read', verb='check-array-bounds',
                                     source=source('unsigned Local=Extra<<1;'),
                                     hypothesis='out-of-bounds read at Data[Index]', integer_abi='ilp32')
    assert result.outcome == 'confirmed' and result.matches
    assert result.details['witness_index'] == 4


@pytest.mark.parametrize('outcome', ['confirmed', 'refuted'])
def test_previous_array_contract_cannot_reuse_old_prefix_semantics(monkeypatch, outcome):
    text = source('unsigned Local=Extra<<1;')
    _, selected = source_for_function(text, 'record.c', 'Read')
    hypothesis = 'out-of-bounds read at Data[Index]'
    binding = source_binding(selected, 'Read', verb='check-array-bounds', integer_abi='ilp32', hypothesis=hypothesis)
    binding['query_contract'] = 'common-width-array-guards-v4'
    old = sweep.SweepResult(tool='smt', file_path='record.c', function_name='Read', rule_id='smt:check-array-bounds',
                            outcome=outcome, details={'source_scope': binding}, matches=[{'model': {}}])
    monkeypatch.setattr('core.audit.subproc_json.run_json_child', lambda *a, **kw: asdict(old))
    result = sweep._smt_verb_in_subprocess(file_path='record.c', function_name='Read', verb='check-array-bounds',
                                         source=text, hypothesis=hypothesis, integer_abi='ilp32')
    assert result.outcome == 'inconclusive' and result.matches == []
    assert result.details['source_scope_status'] == 'unbound-worker-result'


@pytest.mark.parametrize('requested', ['check-oob', 'check-array-bounds'])
def test_audit_tool_chain_keeps_the_verification_receipt_after_a_defined_prefix(tmp_path, monkeypatch, requested):
    from core.audit import orchestrator as orch, evidence_grade
    text = source('int Local=Extra<<1;', 'unsigned char Extra')
    (tmp_path / 'record.c').write_text(text)
    calls = []

    def worker(**request):
        calls.append(request['verb'])
        return sweep._run_smt_verb_inner(**request)

    monkeypatch.setattr(sweep, '_smt_verb_in_subprocess', worker)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / 'out', integer_abi='ilp32')
    result = orch._run_tool_chain([{'type': 'smt', 'config': {'verb': requested}}], config=config,
                                 file_path='record.c', function_name='Read', line_start=1, source=text,
                                 hypothesis='out-of-bounds read at Data[Index]')
    assert calls == ['check-array-bounds']
    assert result == ['smt:check-array-bounds']
    assert evidence_grade.is_verification_evidence(result[0])
