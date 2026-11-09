"""Literal-caller verification shares ordinary function admission with producers."""

from copy import deepcopy

import pytest

from core.audit import condition_smt
from core.audit.literal_call import check_literal_calls
from core.audit.smt_promotion_gate import evaluate_caller_gate

CLAIM = 'integer overflow in `Value * Step`'


@pytest.fixture(autouse=True)
def grammar():
    pytest.importorskip('tree_sitter')
    pytest.importorskip('tree_sitter_c')


def source(*, location='both', specification='noexcept', constexpr=False, arguments='65536,65536', void=False):
    qualifier = 'constexpr ' if constexpr else ''
    callee_spec = ' ' + specification if location in {'callee', 'both'} else ''
    caller_spec = ' ' + specification if location in {'caller', 'both'} else ''
    callee = (qualifier + 'unsigned Read(unsigned Value,unsigned Step)' + callee_spec
              + '{if(Value>0 && Step>0){return Value*Step;}return 0;}')
    caller = qualifier + ('void' if void else 'unsigned') + ' Drive()' + caller_spec
    statement = 'Read(' + arguments + ');' if void else 'return Read(' + arguments + ');'
    return callee + '\n' + caller + '{' + statement + '}\n'


def dispatch(monkeypatch):
    requests = []

    def worker(tag, args, **kwargs):
        requests.append(tag)
        return condition_smt._z3_dispatch_json({'tag': tag, 'args': args})

    monkeypatch.setattr(condition_smt, '_run_z3_child', worker)
    return requests


@pytest.mark.parametrize('location', ['callee', 'caller', 'both'])
@pytest.mark.parametrize('specification', ['noexcept', 'noexcept(false)'])
@pytest.mark.parametrize('constexpr', [False, True])
def test_supported_cpp_qualifiers_retain_a_complete_literal_tuple(location, specification, constexpr):
    pytest.importorskip('tree_sitter_cpp')
    text = source(location=location, specification=specification, constexpr=constexpr)
    reply = check_literal_calls(text, 'Read', 'check-overflow', CLAIM, 'ilp32', [2], 'cpp')
    assert reply['status'] == 'checked' and len(reply['calls']) == 1, reply
    assert reply['calls'][0]['arguments'] == {'Value': 65536, 'Step': 65536}
    assert reply['calls'][0]['verdict'] == 'violation'
    assert reply['binding']['query_contract'] == 'common-width-literal-frame-v11'


@pytest.mark.parametrize('void', [False, True])
@pytest.mark.parametrize('arguments,action', [('65536,65536', 'promote'), ('4,16', 'hold'), ('0,65536', 'hold')])
def test_qualified_wrappers_flow_through_the_real_caller_gate(tmp_path, monkeypatch, void, arguments, action):
    pytest.importorskip('tree_sitter_cpp')
    pytest.importorskip('z3')
    text = source(constexpr=True, void=void, arguments=arguments)
    (tmp_path / 'record.cpp').write_text(text)
    requests = dispatch(monkeypatch)
    result = evaluate_caller_gate(tmp_path, 'record.cpp', 'Read', 'check-overflow', CLAIM,
                                  source=text, def_span=(1, 1), integer_abi='ilp32')
    assert result.action == action, result.reason
    assert requests == ['literal_call']
    assert result.details['proof_scope'] == 'caller-entry-source-model'
    if action == 'promote':
        assert result.details['calls'][0]['mathematical_result'] == 1 << 32
        assert 'Drive entry' in result.citation
    else:
        assert result.channel_outcome == 'inconclusive'


@pytest.mark.parametrize('callee,caller', [
    ('const int Read(int Index)', 'const int Drive(void)'),
    ('static inline int Read(int Index)', 'static inline const int Drive(void)'),
])
def test_c_qualifiers_retain_the_array_caller_proof(tmp_path, monkeypatch, callee, caller):
    pytest.importorskip('z3')
    text = (callee + '{int Data[4]={0};if(Index>=0 && Index<=4){return Data[Index];}return 0;}\n'
            + caller + '{return Read(4);}\n')
    (tmp_path / 'record.c').write_text(text)
    requests = dispatch(monkeypatch)
    result = evaluate_caller_gate(tmp_path, 'record.c', 'Read', 'check-array-bounds',
                                  'out-of-bounds read at Data[Index]', source=text, def_span=(1, 1), integer_abi='ilp32')
    assert result.action == 'promote', result.reason
    assert requests == ['literal_call']
    assert result.details['calls'][0]['witness_index'] == 4


@pytest.mark.parametrize('head', [
    '__attribute__((noinline)) unsigned Drive()',
    'unsigned Drive() __attribute__((noinline))',
    'consteval unsigned Drive()',
    'unsigned Drive() const',
    'unsigned Drive() &',
    'unsigned Drive(unsigned Read)',
    'unsigned Drive(unsigned Count,unsigned Extra[Count])',
])
def test_added_qualifier_support_does_not_admit_unknown_or_shadowed_wrapper_frames(head):
    pytest.importorskip('tree_sitter_cpp')
    text = source(location='callee').splitlines()[0] + '\n' + head + '{return Read(65536,65536);}\n'
    reply = check_literal_calls(text, 'Read', 'check-overflow', CLAIM, 'ilp32', [2], 'cpp')
    assert reply['calls'] == []


def test_utf8_comment_does_not_shift_the_raw_signature_or_call_line():
    pytest.importorskip('tree_sitter_cpp')
    text = '// π: typed arithmetic\n' + source(constexpr=True)
    reply = check_literal_calls(text, 'Read', 'check-overflow', CLAIM, 'ilp32', [3], 'cpp')
    assert reply['status'] == 'checked' and reply['calls'][0]['line'] == 3
    assert reply['calls'][0]['verdict'] == 'violation'


def test_worker_from_before_shared_frame_admission_cannot_promote(tmp_path, monkeypatch):
    pytest.importorskip('tree_sitter_cpp')
    pytest.importorskip('z3')
    text = source(constexpr=True)
    (tmp_path / 'record.cpp').write_text(text)
    reply = check_literal_calls(text, 'Read', 'check-overflow', CLAIM, 'ilp32', [2], 'cpp')
    assert reply['calls'][0]['verdict'] == 'violation'
    reply['binding']['query_contract'] = 'common-width-literal-frame-v10'
    monkeypatch.setattr(condition_smt, '_run_z3_child', lambda *a, **kw: deepcopy(reply))
    result = evaluate_caller_gate(tmp_path, 'record.cpp', 'Read', 'check-overflow', CLAIM,
                                  source=text, def_span=(1, 1), integer_abi='ilp32')
    assert result.action == 'hold' and 'binding mismatched' in result.reason


def test_literal_caller_requires_non_narrowing_callee_list_initialisation():
    pytest.importorskip('tree_sitter_cpp')
    pytest.importorskip('z3')
    for kind, expected in [('unsigned char', 'unavailable'), ('unsigned', 'checked')]:
        text = source().replace('return Value*Step;', kind + ' Total{Value*Step};return 0;')
        reply = check_literal_calls(text, 'Read', 'check-overflow', CLAIM, 'ilp32', [2], 'cpp')
        assert reply['status'] == expected, reply
        if expected == 'checked':
            assert reply['calls'][0]['verdict'] == 'violation'
        else:
            assert reply['calls'] == []


@pytest.mark.parametrize('arguments,expected', [('65536,65536', 'finding'), ('4,16', 'suspicious')])
def test_orchestrator_uses_the_qualified_caller_proof_for_promotion(tmp_path, monkeypatch, arguments, expected):
    pytest.importorskip('tree_sitter_cpp')
    pytest.importorskip('z3')
    from core.audit import orchestrator as orch, sweep
    text = source(constexpr=True, arguments=arguments)
    (tmp_path / 'record.cpp').write_text(text)
    dispatch(monkeypatch)
    calls = []

    def worker(**request):
        calls.append(request['verb'])
        return sweep._run_smt_verb_inner(**request)

    monkeypatch.setattr(sweep, '_smt_verb_in_subprocess', worker)
    monkeypatch.setattr(orch, '_hypothesis_to_tool_chain', lambda *a, **kw: [{'type': 'smt', 'config': {'verb': 'check-overflow'}}])
    out = tmp_path / 'out'
    out.mkdir()
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=out, integer_abi='ilp32')
    hypothesis = {'mechanism': CLAIM, 'confidence': 'refuted'}
    reviewed = orch.ReviewOutcome(file='record.cpp', function='Read', status='clean', body='clean', line=1,
                                  hypotheses=[hypothesis], review_result={'hypotheses': [hypothesis], 'cwe': 'CWE-190'})
    result = orch.OrchestratorResult(outcomes=[reviewed], clean=1)
    checklist = {'files': [{'path': 'record.cpp', 'items': [{'name': 'Read', 'line_start': 1, 'line_end': 1}]}]}
    orch._promote_clean_refuted(result, config, checklist=checklist)
    assert calls == ['check-overflow']
    assert result.outcomes[0].status == expected, result.outcomes[0].body


@pytest.mark.slow
@pytest.mark.parametrize('arguments,action', [('65536,65536', 'promote'), ('4,16', 'hold')])
def test_native_qualified_literal_caller_receipt(tmp_path, arguments, action):
    pytest.importorskip('tree_sitter_cpp')
    pytest.importorskip('z3')
    text = source(constexpr=True, arguments=arguments)
    (tmp_path / 'record.cpp').write_text(text)
    result = evaluate_caller_gate(tmp_path, 'record.cpp', 'Read', 'check-overflow', CLAIM,
                                  source=text, def_span=(1, 1), integer_abi='ilp32')
    assert result.action == action, result.reason
    assert result.details['binding']['query_contract'] == 'common-width-literal-frame-v11'
    assert result.details['proof_scope'] == 'caller-entry-source-model'
