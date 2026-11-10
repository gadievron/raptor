"""Integer fault witnesses need real source types, paths and defined prefixes."""

import pytest

from core.audit.integer_division import check_integer_division


@pytest.fixture(autouse=True)
def native_dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


def check(body='return Left/Right;', spelling='int', abi='ilp32'):
    return check_integer_division(
        f'int Read({spelling} Left,{spelling} Right){{{body}}}',
        'undefined integer division in `Left / Right`', language='c', integer_abi=abi,
    )


@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('operator', ['/', '%'])
def test_zero_divisor_has_an_independently_checked_source_witness(language, operator):
    if language == 'cpp':
        pytest.importorskip('tree_sitter_cpp')
    result = check_integer_division(
        f'int Read(int Left,int Right){{return Left{operator}Right;}}',
        f'division by zero at `Left {operator} Right`', language=language, integer_abi='ilp32')
    assert result['violation'] is True and result['witness_validated'] is True
    assert result['model']['Right'] == 0
    assert result['fault_kind'] == 'zero-divisor'
    assert result['proof_scope'] == 'function-entry-source-model'


@pytest.mark.parametrize('operator', ['/', '%'])
def test_nonzero_guard_still_allows_signed_minimum_divided_by_minus_one(operator):
    result = check_integer_division(
        f'int Read(int Left,int Right){{if(Right==0)return 0;return Left{operator}Right;}}',
        f'division overflow in `Left {operator} Right`', language='c', integer_abi='ilp32')
    assert result['violation'] is True and result['witness_validated'] is True
    assert result['model'] == {'Left': -(1 << 31), 'Right': -1}
    assert result['fault_kind'] == 'signed-division-overflow'


@pytest.mark.parametrize('spelling,abi,expected', [('unsigned','ilp32',False), ('short','ilp32',False), ('short','i16',True)])
def test_promotions_and_original_storage_domains_select_the_fault(spelling, abi, expected):
    result = check('if(Right==0)return 0;return Left/Right;', spelling, abi)
    assert result['violation'] is expected
    assert result['witness_validated'] is expected


def test_guarded_safe_site_does_not_claim_whole_function_safety():
    result = check('if(Right==0 || Right==-1)return 0;return Left/Right;')
    assert result['violation'] is False and result['witness_validated'] is False
    assert 'model' not in result


@pytest.mark.parametrize('source,hypothesis,abi', [
    ('int Read(int Left,int Right){return Left/Right;}', 'undefined integer division in `Left / Right`', None),
    ('int Read(int Left,unsigned Right){return Left/Right;}', 'undefined integer division in `Left / Right`', 'ilp32'),
    ('int Read(int Left,int Right){return (Left+1)/Right;}', 'undefined integer division in `Left / Right`', 'ilp32'),
    ('int Read(int Left,int Right){int X=1/0;return Left/Right;}', 'undefined integer division in `Left / Right`', 'ilp32'),
    ('int Read(int Left,int Right){if(Right!=0){Right=0;return Left/Right;}return 0;}', 'undefined integer division in `Left / Right`', 'ilp32'),
    ('int Read(int Left,int Right){int X=Left/Right;return Left/Right;}', 'undefined integer division in `Left / Right`', 'ilp32'),
])
def test_unbound_or_undefined_prefixes_have_no_fault_authority(source, hypothesis, abi):
    result = check_integer_division(source, hypothesis, language='c', integer_abi=abi)
    assert result['violation'] is None and result['witness_validated'] is False


@pytest.mark.parametrize('hypothesis', ['division in Left/Right', 'division in `(Left+1)/Right`',
                                      'division in `Left / Right` and `Right / Left`'])
def test_claim_does_not_guess_an_expression_or_select_a_compound_prefix(hypothesis):
    result = check_integer_division('int Read(int Left,int Right){return Left/Right;}', hypothesis,
                                    language='c', integer_abi='ilp32')
    assert result['division_status'] == 'unavailable' and result['violation'] is None


@pytest.mark.parametrize('partial', [False, True])
def test_native_result_alone_cannot_manufacture_a_fault(monkeypatch, partial):
    from core.audit import integer_division
    from core.smt_solver.path_feasibility import PathSMTResult
    fake = PathSMTResult(feasible=None if partial else True, satisfied=[], unsatisfied=[],
                        unknown=['dropped'] if partial else [], model={'Left':1,'Right':1},
                        smt_available=True, reasoning='conditional')
    monkeypatch.setattr(integer_division, 'check_verb_feasibility', lambda *a, **kw: fake)
    result = check()
    assert result['violation'] is None and result['witness_validated'] is False
    assert 'model' not in result


@pytest.mark.parametrize('subject,body,expected', [
    ('division by zero', 'if(Right==0)return 0;return Left/Right;', False),
    ('division-by-zero', 'if(Right==0)return 0;return Left/Right;', False),
    ('division by 0', 'if(Right==0)return 0;return Left/Right;', False),
    ('zero divisor', 'if(Right==0)return 0;return Left/Right;', False),
    ('division overflow', 'if(Right!=-1)return 0;return Left/Right;', True),
    ('division overflow', 'if(Right!=0)return 0;return Left/Right;', False),
])
def test_exact_fault_claim_cannot_be_confirmed_by_another_fault(subject, body, expected):
    result = check_integer_division(f'int Read(int Left,int Right){{{body}}}',
                                    subject + ' at `Left / Right`', language='c', integer_abi='ilp32')
    assert result['violation'] is expected
    assert result['witness_validated'] is expected
    if expected:
        assert result['fault_kind'] == 'signed-division-overflow'


@pytest.mark.parametrize('subject', ['division by 1', 'division by 0x100', 'division by 0.5',
                                    'arithmetic issue', 'division by zero and division overflow'])
def test_unrecognised_or_combined_subject_cannot_select_an_arbitrary_fault(monkeypatch, subject):
    from core.audit import integer_division
    monkeypatch.setattr(integer_division, 'bind_arithmetic_operation',
                        lambda *a, **kw: pytest.fail('unsupported subject reached source query'))
    result = check_integer_division('int Read(int Left,int Right){return Left/Right;}',
                                    subject + ' in `Left / Right`', language='c', integer_abi='ilp32')
    assert result['division_status'] == 'unavailable' and result['violation'] is None
