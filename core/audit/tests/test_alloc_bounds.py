"""Symbolic-extent allocation bounds confirm with witnesses and never mint safety."""

from dataclasses import asdict

import pytest

from core.audit.alloc_bounds import (AllocAccess, _witness_violation, bind_alloc_access,
                                     check_alloc_bounds)

SOURCE = 'int Read(unsigned n, unsigned i){int *p = malloc(n * sizeof(int));if(!p)return 0;if(i <= n)return p[i];return 0;}'
CLAIM = 'Potential out-of-bounds read at `p[i]`.'


@pytest.fixture(autouse=True)
def prerequisites():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('abi', ['lp64', 'llp64', 'i16'])
def test_off_by_one_guard_confirms_with_a_boundary_witness(language, abi):
    pytest.importorskip('tree_sitter_' + language)
    result = check_alloc_bounds(SOURCE, CLAIM, language=language, integer_abi=abi)
    assert result['violation'] is True, result
    assert result['model']['i'] == result['model']['n']
    assert result['witness_index'] == result['witness_count'] == result['model']['i']
    assert result['obligation'] == 'i < 0 OR (n >= 0 AND i >= n)'
    access = result['source_access']
    assert access['count'] == 'n' and access['size_form'] == 'count-times-sizeof'
    assert access['element_type'] == 'int'
    assert access['element_size'] == (2 if abi == 'i16' else 4)


def test_strict_guard_claims_nothing_instead_of_safety():
    # size_t conversion and multiplication wrap are unmodeled, so an unsat
    # obligation must never surface as violation=False (a safety verdict).
    result = check_alloc_bounds(SOURCE.replace('i <= n', 'i < n'), CLAIM,
                                language='c', integer_abi='lp64')
    assert result['alloc_bounds_status'] == 'checked', result
    assert result['violation'] is None and result['violation'] is not False
    assert 'no safety claim' in result['reason']


def test_a_negative_count_alone_never_confirms():
    # The guards force n < 0, where the size_t conversion of n*sizeof(int)
    # requests an enormous allocation whose usable extent is unmodeled:
    # `i >= n` is satisfiable but proves nothing. A naive
    # `i < 0 OR i >= n` obligation would mint a false positive here.
    source = ('int Read(int n, int i){int *p = malloc(n * sizeof(int));if(!p)return 0;'
              'if(i == 0 && n < i)return p[i];return 0;}')
    result = check_alloc_bounds(source, CLAIM, language='c', integer_abi='lp64')
    assert result['alloc_bounds_status'] == 'checked', result
    assert result['violation'] is None


def test_signed_operands_confirm_only_with_a_non_negative_count():
    source = ('int Read(int n, int i){int *p = malloc(n * sizeof(int));if(!p)return 0;'
              'if(i >= 0 && i <= n)return p[i];return 0;}')
    result = check_alloc_bounds(source, CLAIM, language='c', integer_abi='lp64')
    assert result['violation'] is True, result
    assert result['model']['n'] >= 0 and result['model']['i'] == result['model']['n']


def test_reading_the_count_element_is_always_past_the_end():
    source = 'int Read(unsigned n){int *p = malloc(n * sizeof(int));if(!p)return 0;return p[n];}'
    result = check_alloc_bounds(source, 'Potential out-of-bounds read at `p[n]`.',
                                language='c', integer_abi='lp64')
    assert result['violation'] is True, result
    assert result['witness_index'] == result['witness_count']


def test_byte_counts_bind_only_one_byte_elements():
    byte_source = SOURCE.replace('int *p', 'char *p').replace(' * sizeof(int)', '').replace('int Read', 'char Read')
    result = check_alloc_bounds(byte_source, CLAIM, language='c', integer_abi='lp64')
    assert result['violation'] is True, result
    assert result['source_access']['size_form'] == 'count'
    for broken in (SOURCE.replace(' * sizeof(int)', ''),
                   SOURCE.replace('sizeof(int)', 'sizeof(char)')):
        declined = check_alloc_bounds(broken, CLAIM, language='c', integer_abi='lp64')
        assert declined['alloc_bounds_status'] == 'unavailable', declined
        assert 'byte discipline' in declined['reason']


def test_commuted_sizeof_carries_the_same_discipline():
    result = check_alloc_bounds(SOURCE.replace('n * sizeof(int)', 'sizeof(int) * n'),
                                CLAIM, language='c', integer_abi='lp64')
    assert result['violation'] is True, result


@pytest.mark.parametrize('check', ['if(!p)return 0;', 'if(p == 0)return 0;', 'if(!p){return 0;}'])
def test_exact_null_check_spellings_bind(check):
    result = check_alloc_bounds(SOURCE.replace('if(!p)return 0;', check),
                                CLAIM, language='c', integer_abi='lp64')
    assert result['violation'] is True, result


@pytest.mark.parametrize('source, claim', [
    # No null check: a failed allocation is a different defect.
    (SOURCE.replace('if(!p)return 0;', ''), CLAIM),
    # A value-bearing null-check exit is not the admitted pure exit.
    (SOURCE.replace('if(!p)return 0;', 'if(!p)return 1;'), CLAIM),
    # Only malloc is modeled; other allocators have other contracts.
    (SOURCE.replace('malloc(n * sizeof(int))', 'calloc(n, sizeof(int))'), CLAIM),
    # A second call could free, realloc, or alias the object.
    (SOURCE.replace('if(!p)return 0;', 'if(!p)return 0;free(p);'), CLAIM),
    (SOURCE.replace('if(!p)return 0;', 'if(!p)return 0;int *q = malloc(n * sizeof(int));'), CLAIM),
    # The count must be an immutable entry parameter, not a local value.
    ('int Read(unsigned i){unsigned n = 8;int *p = malloc(n * sizeof(int));if(!p)return 0;if(i <= n)return p[i];return 0;}', CLAIM),
    # Literal sizes belong to the fixed-extent oracle, not this one.
    ('int Read(unsigned i){int *p = malloc(8);if(!p)return 0;if(i <= 2)return p[i];return 0;}', CLAIM),
    # Another subscript could require its own safety obligation.
    (SOURCE.replace('return p[i];', 'return p[i] + p[0];'), CLAIM),
    # Mixed signedness changes the C comparison; decline, never guess.
    (SOURCE.replace('unsigned i', 'int i'), CLAIM),
    # An adjusted claim must never bind the bare source index.
    (SOURCE, 'Potential out-of-bounds read at `p[i + 1]`.'),
    # Write wording never binds this read-only frame.
    (SOURCE, 'Out-of-bounds write at `p[i]`.'),
    # A pointer parameter is not a visible local allocation.
    ('int Read(int *p, unsigned n, unsigned i){if(i <= n)return p[i];return 0;}', CLAIM),
])
def test_frame_and_claim_refusals(source, claim):
    result = check_alloc_bounds(source, claim, language='c', integer_abi='lp64')
    assert result['alloc_bounds_status'] == 'unavailable', result
    assert result['violation'] is None


def test_mixed_width_same_signedness_counts_bind_exactly():
    result = check_alloc_bounds(SOURCE.replace('unsigned n', 'unsigned long n'),
                                CLAIM, language='c', integer_abi='lp64')
    assert result['violation'] is True, result
    # The witness index equals the count inside the narrower index domain,
    # so the 64-bit common-frame comparison replays value-preservingly.
    assert result['witness_index'] == result['witness_count'] <= (1 << 32) - 1


def test_admitted_statements_are_opt_in_for_guard_collection():
    from core.audit.arithmetic_guards import guards_for_operation
    from core.audit.condition_extraction import _get_parser
    data = SOURCE.encode('utf-8')
    root = _get_parser('c').parse(data).root_node
    function = [node for node in root.named_children if node.type == 'function_definition'][0]
    body = function.child_by_field_name('body')
    stack, nodes = [body], []
    while stack:
        item = stack.pop()
        nodes.append(item)
        stack.extend(item.named_children)
    target = [node for node in nodes if node.type == 'subscript_expression'][0]
    statements = [child for child in body.named_children if child.type != 'comment']
    declaration, null_check = statements[0], statements[1]
    # Default behavior is unchanged: the allocation call and the pointer
    # null check decline guard credit unless a caller admits them under
    # the documented frame contract.
    default = guards_for_operation(body, target, data, ['i', 'n'], language='c', integer_abi='lp64')
    assert default.status == 'unavailable'
    bound = guards_for_operation(body, target, data, ['i', 'n'], language='c', integer_abi='lp64',
                                 admitted=(declaration, null_check))
    assert bound.status == 'bound' and bound.premises == ('i <= n',)


def test_incomplete_witness_values_replay_nothing():
    access = bind_alloc_access(SOURCE, CLAIM, language='c', integer_abi='lp64')
    assert access.status == 'bound'
    assert _witness_violation(access, {'i': 5}, 'lp64') == (None, None, None)
    assert _witness_violation(access, {'i': 5, 'n': 'five'}, 'lp64') == (None, None, None)
    assert _witness_violation(access, {'i': 5, 'n': 5}, 'lp64') == (5, 5, True)
    assert _witness_violation(access, {'i': 4, 'n': 5}, 'lp64') == (4, 5, False)


def test_confirmations_name_their_allocation_assumptions():
    result = check_alloc_bounds(SOURCE, CLAIM, language='c', integer_abi='lp64')
    assert result['violation'] is True
    assert 'a non-null allocation provides at most the requested storage' in result['assumptions']
    assert any('successful (non-null) allocation' in line for line in result['assumptions'])


def test_receipts_are_verification_grade_but_never_refute():
    from core.audit.smt_evidence import (is_diagnostic_smt_rule, is_non_refuting_smt_rule,
                                         scope_smt_observation)
    from core.audit.sweep import _SMT_DIRECT_ONLY_VERBS, get_smt_verb_role
    assert 'check-alloc-bounds' in _SMT_DIRECT_ONLY_VERBS
    assert get_smt_verb_role('check-alloc-bounds') == 'verification'
    assert not is_diagnostic_smt_rule('smt:check-alloc-bounds')
    assert is_diagnostic_smt_rule('smt:check-alloc-bounds:witness')
    assert is_non_refuting_smt_rule('smt:check-alloc-bounds')
    outcome, details = scope_smt_observation('check-alloc-bounds', 'refuted', {'violation': None})
    assert outcome == 'inconclusive'
    assert details['oracle_scope'] == 'allocated-extent-access'


def test_bound_record_round_trips():
    access = bind_alloc_access(SOURCE, CLAIM, language='c', integer_abi='lp64')
    assert access.status == 'bound'
    assert AllocAccess(**asdict(access)) == access


@pytest.mark.slow
def test_real_confined_worker_reroutes_subscript_claims_to_the_allocation_oracle():
    from core.audit import sweep
    for verb in ('check-array-bounds', 'check-oob'):
        result = sweep.run_smt_verb_direct(file_path='unit.c', function_name='Read', verb=verb,
                                           source=SOURCE, hypothesis=CLAIM, target_path=None,
                                           integer_abi='lp64', include_callers=False)
        assert result.rule_id == 'smt:check-alloc-bounds', (verb, result)
        assert result.outcome == 'confirmed'
        details = result.details or {}
        assert details['oracle_scope'] == 'allocated-extent-access'
        assert details['violation'] is True
        assert details['witness_index'] == details['witness_count']
        assert details['source_scope']['query_contract'] == 'symbolic-allocation-guards-v1'
