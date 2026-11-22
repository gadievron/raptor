"""Counted-loop progressions confirm with re-executed witnesses; wrap risks never refute."""

from dataclasses import asdict

import pytest

from core.audit.loop_bounds import (LoopAccess, _execute_loop, _witness_violation,
                                    bind_loop_access, check_loop_bounds)

SOURCE = 'void F(unsigned n){int a[4];if(n > 4)return;for(unsigned i = 0; i <= n; i++)a[i] = 0;}'
CLAIM = 'Potential out-of-bounds write at `a[i]`.'


@pytest.fixture(autouse=True)
def prerequisites():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('abi', ['lp64', 'llp64', 'i16'])
def test_inclusive_bound_confirms_at_the_extent(language, abi):
    pytest.importorskip('tree_sitter_' + language)
    result = check_loop_bounds(SOURCE, CLAIM, language=language, integer_abi=abi)
    assert result['violation'] is True, result
    assert result['witness_index'] == result['witness_bound'] == 4
    assert result['model']['n'] == 4
    assert result['obligation'] == '4 <= n'
    access = result['source_access']
    assert access['extent'] == 4 and access['start'] == 0 and access['step'] == 1
    assert access['comparison'] == '<=' and access['first_violating_index'] == 4
    assert access['bound_kind'] == 'parameter' and access['bound'] == 'n'


def test_a_strict_guarded_bound_is_a_modeled_safe_exit():
    result = check_loop_bounds(SOURCE.replace('i <= n', 'i < n'), CLAIM,
                               language='c', integer_abi='lp64')
    assert result['loop_bounds_status'] == 'checked', result
    assert result['violation'] is False
    assert result['source_access']['safe_exit_modeled'] is True


def test_a_possible_counter_wrap_never_claims_safety():
    # The guards exclude the first out-of-bounds index 65535 (a multiple of
    # 3), but the exit increment 65534 + 3 leaves the 16-bit counter, so
    # the wrapped progression is unmodeled and no safety verdict exists.
    source = ('void F(unsigned short n){int a[65534];if(n > 65533)return;'
              'for(unsigned short i = 0; i <= n; i += 3)a[i] = 0;}')
    result = check_loop_bounds(source, CLAIM, language='c', integer_abi='lp64')
    assert result['loop_bounds_status'] == 'checked', result
    assert result['violation'] is None and result['violation'] is not False
    assert 'no safety claim' in result['reason']
    assert result['source_access']['safe_exit_modeled'] is False


def test_literal_bounds_are_decided_by_direct_execution():
    oob = check_loop_bounds('void F(void){int a[4];for(int i = 0; i <= 4; i++)a[i] = 0;}',
                            CLAIM, language='c', integer_abi='lp64')
    assert oob['violation'] is True and oob['witness_index'] == 4 and oob['witness_bound'] == 4
    safe = check_loop_bounds('void F(void){int a[4];for(int i = 0; i < 4; i++)a[i] = 0;}',
                             CLAIM, language='c', integer_abi='lp64')
    assert safe['loop_bounds_status'] == 'checked' and safe['violation'] is False


def test_the_progression_lattice_selects_the_first_violating_index():
    result = check_loop_bounds('void F(void){int a[4];for(int i = 0; i < 9; i += 5)a[i] = 0;}',
                               CLAIM, language='c', integer_abi='lp64')
    assert result['violation'] is True, result
    assert result['witness_index'] == 5 == result['source_access']['first_violating_index']
    stepped = check_loop_bounds('void F(unsigned n){int a[5];for(unsigned i = 1; i < n; i += 2)a[i] = 0;}',
                                CLAIM, language='c', integer_abi='lp64')
    assert stepped['violation'] is True and stepped['witness_index'] == 5


def test_an_unguarded_parameter_bound_confirms():
    result = check_loop_bounds(SOURCE.replace('if(n > 4)return;', ''), CLAIM,
                               language='c', integer_abi='lp64')
    assert result['violation'] is True, result
    assert result['witness_index'] == 4 <= result['witness_bound']


def test_signed_bounds_confirm_and_refute_within_the_frame():
    confirmed = check_loop_bounds(SOURCE.replace('unsigned', 'int'), CLAIM,
                                  language='c', integer_abi='lp64')
    assert confirmed['violation'] is True and confirmed['witness_index'] == 4
    safe = check_loop_bounds('void F(int n){int a[4];if(n >= 4)return;for(int i = 0; i < n; i++)a[i] = 0;}',
                             CLAIM, language='c', integer_abi='lp64')
    assert safe['loop_bounds_status'] == 'checked' and safe['violation'] is False


@pytest.mark.parametrize('spelling', ['++i', 'i += 1'])
def test_update_spellings_bind(spelling):
    result = check_loop_bounds(SOURCE.replace('i++', spelling), CLAIM,
                               language='c', integer_abi='lp64')
    assert result['violation'] is True, result


def test_a_braced_single_store_body_binds():
    result = check_loop_bounds(SOURCE.replace('a[i] = 0;}', '{a[i] = 0;}}'), CLAIM,
                               language='c', integer_abi='lp64')
    assert result['violation'] is True, result


def test_a_start_past_the_extent_confirms_the_first_iteration():
    result = check_loop_bounds('void F(unsigned n){int a[4];for(unsigned i = 10; i < n; i++)a[i] = 0;}',
                               CLAIM, language='c', integer_abi='lp64')
    assert result['violation'] is True and result['witness_index'] == 10


@pytest.mark.parametrize('source, claim', [
    # An exit-on-equality condition is not an upper bound.
    (SOURCE.replace('i <= n', 'i != n'), CLAIM),
    # A shrinking counter has a different progression.
    (SOURCE.replace('i++', 'i--'), CLAIM),
    # Unstructured exits leave the closed progression.
    (SOURCE.replace('a[i] = 0;', '{a[i] = 0;break;}'), CLAIM),
    # A second body statement is another effect.
    (SOURCE.replace('a[i] = 0;', '{a[i] = 0;a[i] = 1;}'), CLAIM),
    # Only the counted for-loop shape is modeled.
    ('void F(unsigned n){int a[4];unsigned i = 0;while(i <= n){a[i] = 0;i++;}}', CLAIM),
    # Storing the counter is a second counter use.
    (SOURCE.replace('a[i] = 0', 'a[i] = i'), CLAIM),
    # An initialized array needs an initialization model.
    (SOURCE.replace('int a[4];', 'int a[4] = {0};'), CLAIM),
    # Entry guards on a literal bound would need their own reachability model.
    (SOURCE.replace('i <= n', 'i <= 4'), CLAIM),
    # The bound must be an immutable entry parameter, not a local value.
    ('void F(void){int a[4];unsigned n = 9;for(unsigned i = 0; i < n; i++)a[i] = 0;}', CLAIM),
    # Mixed counter/bound declared types change the C comparison.
    (SOURCE.replace('unsigned n', 'unsigned long n'), CLAIM),
    # A negative start is below the object before any progression fact.
    ('void F(unsigned n){int a[4];for(int i = -1; i < 4; i++)a[i] = 0;}', CLAIM),
    # An adjusted claim must never bind the bare source index.
    (SOURCE, 'Potential out-of-bounds write at `a[i + 1]`.'),
    # Read wording never binds this write-only frame.
    (SOURCE, 'Potential out-of-bounds read at `a[i]`.'),
    # Value-bearing returns are other effects.
    ('int F(unsigned n){int a[4];for(unsigned i = 0; i <= n; i++)a[i] = 0;return 1;}', CLAIM),
])
def test_frame_and_claim_refusals(source, claim):
    result = check_loop_bounds(source, claim, language='c', integer_abi='lp64')
    assert result['loop_bounds_status'] == 'unavailable', result
    assert result['violation'] is None


def test_statement_targets_return_entry_premises_only():
    from core.audit.arithmetic_guards import guards_for_operation
    from core.audit.condition_extraction import _get_parser
    data = SOURCE.encode('utf-8')
    root = _get_parser('c').parse(data).root_node
    stack, nodes = [root], []
    while stack:
        item = stack.pop()
        nodes.append(item)
        stack.extend(item.named_children)
    body = [node for node in nodes if node.type == 'function_definition'][0].child_by_field_name('body')
    loop = [node for node in nodes if node.type == 'for_statement'][0]
    subscript = [node for node in nodes if node.type == 'subscript_expression'][0]
    bound = guards_for_operation(body, loop, data, ['n'], language='c', integer_abi='lp64')
    assert bound.status == 'bound' and bound.premises == ('n <= 4',)
    # An expression target inside the loop keeps the pre-existing decline:
    # only a direct statement child is admitted as a statement target.
    inner = guards_for_operation(body, subscript, data, ['i', 'n'], language='c', integer_abi='lp64')
    assert inner.status == 'unavailable'


def test_witness_replay_re_executes_the_loop():
    access = bind_loop_access(SOURCE, CLAIM, language='c', integer_abi='lp64')
    assert access.status == 'bound'
    assert _witness_violation(access, {'n': 'four'}, 'lp64') == (None, None, None)
    # A guard-violating assignment is never a witness.
    assert _witness_violation(access, {'n': 9}, 'lp64') == (None, None, None)
    assert _witness_violation(access, {'n': 4}, 'lp64') == (4, 4, True)
    assert _witness_violation(access, {'n': 3}, 'lp64') == (None, 3, False)
    # An omitted parameter completes to zero only as a checked safe run,
    # which the caller's confirm gate can never promote to a violation.
    assert _witness_violation(access, {}, 'lp64') == (None, 0, False)


def test_direct_execution_never_outruns_the_counter_storage():
    access = bind_loop_access(SOURCE, CLAIM, language='c', integer_abi='lp64')
    assert access.status == 'bound'
    tight = LoopAccess(**{**asdict(access), 'extent': 65536, 'index_width': 16,
                          'index_signed': False, 'first_violating_index': 65536})
    # The counter exhausts its 16-bit storage before reaching the extent:
    # execution must report no verdict, never a safe exit.
    assert _execute_loop(tight, 70000) == (None, None)


def test_receipts_are_verification_grade_but_never_refute():
    from core.audit.smt_evidence import (is_diagnostic_smt_rule, is_non_refuting_smt_rule,
                                         scope_smt_observation)
    from core.audit.sweep import _SMT_DIRECT_ONLY_VERBS, get_smt_verb_role
    assert 'check-loop-bounds' in _SMT_DIRECT_ONLY_VERBS
    assert get_smt_verb_role('check-loop-bounds') == 'verification'
    assert not is_diagnostic_smt_rule('smt:check-loop-bounds')
    assert is_diagnostic_smt_rule('smt:check-loop-bounds:witness')
    assert is_non_refuting_smt_rule('smt:check-loop-bounds')
    outcome, details = scope_smt_observation('check-loop-bounds', 'refuted', {'violation': False})
    assert outcome == 'inconclusive'
    assert details['oracle_scope'] == 'counted-loop-write'


def test_bound_record_round_trips():
    access = bind_loop_access(SOURCE, CLAIM, language='c', integer_abi='lp64')
    assert access.status == 'bound'
    assert LoopAccess(**asdict(access)) == access


@pytest.mark.slow
def test_real_confined_worker_reroutes_write_claims_to_the_loop_oracle():
    from core.audit import sweep
    for verb in ('check-array-bounds', 'check-oob', 'check-loop-bounds'):
        result = sweep.run_smt_verb_direct(file_path='unit.c', function_name='F', verb=verb,
                                           source=SOURCE, hypothesis=CLAIM, target_path=None,
                                           integer_abi='lp64', include_callers=False)
        assert result.rule_id == 'smt:check-loop-bounds', (verb, result)
        assert result.outcome == 'confirmed'
        details = result.details or {}
        assert details['oracle_scope'] == 'counted-loop-write'
        assert details['violation'] is True
        assert details['witness_index'] == details['witness_bound'] == 4
        assert details['source_scope']['query_contract'] == 'bounded-loop-progression-v1'
