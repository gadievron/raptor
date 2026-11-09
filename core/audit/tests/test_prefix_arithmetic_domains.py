"""Existing overflow predicates now guard source-prefix arithmetic too."""

from collections import Counter

import pytest

from core.audit import sweep, arithmetic_prefix
from core.audit.arithmetic_prefix import PrefixIntegerModel
from core.audit.condition_extraction import _get_parser
from core.audit.integer_abi import resolve_integer_abi
from core.testing.module_views import scoped_function_imports


@pytest.fixture(autouse=True)
def dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter')
    pytest.importorskip('tree_sitter_c')


@pytest.fixture
def semantic_prefix_budget(monkeypatch):
    from core.audit import arithmetic_prefix_obligations

    # Proof semantics are independent of the production soft deadline.
    # Deadline, query-cap and non-proof controls keep their default budget.
    monkeypatch.setattr(arithmetic_prefix_obligations, '_BUDGET_MS', 5000)


def source(prefix, extra='unsigned Extra'):
    return ('unsigned Read(unsigned Value,unsigned Step,' + extra + '){' + prefix
            + 'if(Value<10 && Step<10){return Value+Step;}return 0;}')


@pytest.mark.usefixtures('semantic_prefix_budget')
def test_known_boolean_divisors_preserve_native_overflow_witnesses():
    for language, boolean in [('c', '_Bool'), ('cpp', 'bool')]:
        if language == 'cpp':
            pytest.importorskip('tree_sitter_cpp')
        divisors = [f'({boolean})2', '!0', '!!2', '!!-2']
        if language == 'cpp':
            # The pinned C grammar parses these _Bool casts as subtraction
            # or calls; those ambiguous forms retain their existing refusal.
            divisors += [f'({boolean})-2', f'({boolean})(Extra+1)']
        for divisor in divisors:
            text = ('unsigned Read(unsigned Value,unsigned Step,unsigned char Extra){int Local=10/(' + divisor
                    + ');if(Value>0 && Step>0)return Value*Step;return 0;}')
            result = sweep._run_smt_verb_inner(
                file_path='record.' + language, function_name='Read', verb='check-overflow',
                source=text, hypothesis='integer overflow in `Value * Step`', integer_abi='ilp32')
            assert result.outcome == 'confirmed', (divisor, result.details)
            assert result.details['witness_validated'] is True
            assert result.details['mathematical_result'] > 4294967295


def test_boolean_divisors_that_may_be_zero_never_get_prefix_credit():
    for language, boolean in [('c', '_Bool'), ('cpp', 'bool')]:
        if language == 'cpp':
            pytest.importorskip('tree_sitter_cpp')
        for divisor in [f'({boolean})0', f'({boolean})Extra', '!2', '!Extra', '(unsigned char)256',
                        f'({boolean})(1/0)', '!(-Extra)']:
            result = sweep._run_smt_verb_inner(
                file_path='record.' + language, function_name='Read', verb='check-overflow',
                source=source('int Local=10/(' + divisor + ');', extra='int Extra'),
                hypothesis='integer overflow in `Value + Step`', integer_abi='ilp32')
            assert result.outcome == 'inconclusive', (divisor, result.details)
            assert result.matches == []


@pytest.mark.usefixtures('semantic_prefix_budget')
def test_boolean_prefix_domains_preserve_array_witness_admission():
    from core.audit.array_bounds import check_array_bounds

    # Array access frames admit logical negation, but deliberately exclude casts.
    for divisor, expected in [('!0', True), ('!!2', True), ('!2', None), ('!!0', None)]:
        text = ('int Read(unsigned Index){int Data[4]={0};int Local=10/(' + divisor
                + ');return Data[Index];}')
        result = check_array_bounds(text, 'Data[Index]', language='c', integer_abi='ilp32')
        assert result['violation'] is expected, result
        if expected is True:
            assert result['witness_index'] >= 4
        else:
            assert result['array_bounds_status'] == 'unavailable'


@pytest.fixture
def overflow_leaf():
    from packages.exploit_feasibility import smt_verbs

    with scoped_function_imports(
        sweep, ('_run_smt_verb_inner',),
        {'packages.exploit_feasibility.smt_verbs': smt_verbs},
    ) as imports:
        yield getattr(imports, 'packages.exploit_feasibility.smt_verbs')


@pytest.mark.usefixtures('semantic_prefix_budget')
@pytest.mark.parametrize('abi,maximum', [('i16', 65535), ('ilp32', 4294967295)], ids=['int16', 'int32'])
def test_local_const_literal_divisors_keep_native_source_verdicts(monkeypatch, abi, maximum, overflow_leaf):
    actual = overflow_leaf.check_overflow
    calls = []

    def observe(*args, **kwargs):
        calls.append((args, kwargs))
        return actual(*args, **kwargs)

    monkeypatch.setattr(overflow_leaf, 'check_overflow', observe)
    prefixes = ['const int Divisor=1;', 'const int Divisor=-1;',
                'const unsigned char Divisor=255;', 'const long Divisor=1;',
                'const int Unused=1,Divisor=2;',
                'const int Divisor=1; {const int Divisor=0;}']
    for language in ['c', 'cpp']:
        if language == 'cpp':
            pytest.importorskip('tree_sitter_cpp')
        for prefix in prefixes:
            for guard, expected in [('Value<10 && Step<10', 'refuted'), ('Value>0 && Step>0', 'confirmed')]:
                text = source(prefix + 'int Local=10/Divisor;').replace('Value<10 && Step<10', guard)
                before = len(calls)
                result = sweep._run_smt_verb_inner(
                    file_path='record.' + language, function_name='Read', verb='check-overflow', source=text,
                    hypothesis='integer overflow in `Value + Step`', integer_abi=abi)
                assert result.outcome == expected, (language, prefix, result.details)
                assert len(calls) == before + 1
                assert result.details['source_operation']['profile'] == ('uint16' if abi == 'i16' else 'uint32')
                if expected == 'confirmed':
                    assert result.details['witness_validated'] is True
                    assert result.details['mathematical_result'] > maximum


@pytest.mark.usefixtures('semantic_prefix_budget')
def test_local_const_literal_inference_cannot_guess_mutable_or_converted_values(monkeypatch, overflow_leaf):
    def forbidden(*args, **kwargs):
        pytest.fail('unsupported prefix reached the overflow solver')

    monkeypatch.setattr(overflow_leaf, 'check_overflow', forbidden)
    cases = [
        ('const int Divisor=0; int Local=10/Divisor;', 'unsigned Extra', ''),
        ('int Divisor=1; int Local=10/Divisor;', 'unsigned Extra', ''),
        ('int Local=10/Divisor;', 'const int Divisor', ''),
        ('const unsigned char Divisor=256; int Local=10/Divisor;', 'unsigned Extra', ''),
        ('static const int Divisor=1; int Local=10/Divisor;', 'unsigned Extra', ''),
        ('const int Divisor=1; const int Copy=Divisor; int Local=10/Copy;', 'unsigned Extra', ''),
        ('const int Divisor=1; {const int Divisor=0; int Local=10/Divisor;', 'unsigned Extra', '}'),
        ('const int Divisor=Divisor; int Local=10/Divisor;', 'unsigned Extra', ''),
    ]
    for language in ['c', 'cpp']:
        if language == 'cpp':
            pytest.importorskip('tree_sitter_cpp')
        for prefix, extra, suffix in cases:
            text = ('unsigned Read(unsigned Value,unsigned Step,' + extra + '){' + prefix
                    + 'if(Value<10 && Step<10)return Value+Step;' + suffix + 'return 0;}')
            result = sweep._run_smt_verb_inner(
                file_path='record.' + language, function_name='Read', verb='check-overflow', source=text,
                hypothesis='integer overflow in `Value + Step`', integer_abi='ilp32')
            assert result.outcome == 'inconclusive' and result.matches == [], (prefix, result.details)
        for declaration in ['const int Divisor=1;', 'extern const int Divisor=1;']:
            text = declaration + source('int Local=10/Divisor;')
            result = sweep._run_smt_verb_inner(
                file_path='record.' + language, function_name='Read', verb='check-overflow', source=text,
                hypothesis='integer overflow in `Value + Step`', integer_abi='ilp32')
            assert result.outcome == 'inconclusive' and result.matches == []
            assert result.details['arithmetic_guard_status'] == 'unavailable'
        text = ('unsigned Read(unsigned Value){const unsigned Step=1;'
                'if(Value<10)return Value+Step;return 0;}')
        result = sweep._run_smt_verb_inner(
            file_path='record.' + language, function_name='Read', verb='check-overflow', source=text,
            hypothesis='integer overflow in `Value + Step`', integer_abi='ilp32')
        assert result.outcome == 'inconclusive' and result.matches == []
        assert result.details['arithmetic_type_status'] == 'unavailable'
        if language == 'cpp':
            text = source('const bool Divisor=2; int Local=1/(Divisor-1);')
            result = sweep._run_smt_verb_inner(
                file_path='record.cpp', function_name='Read', verb='check-overflow', source=text,
                hypothesis='integer overflow in `Value + Step`', integer_abi='ilp32')
            assert result.outcome == 'inconclusive' and result.matches == []


@pytest.mark.usefixtures('semantic_prefix_budget')
def test_local_const_literals_are_checked_in_literal_callee_prefixes():
    from core.audit.literal_call import check_literal_calls

    for language in ['c', 'cpp']:
        if language == 'cpp':
            pytest.importorskip('tree_sitter_cpp')
        for divisor, expected in [('1', 'checked'), ('0', 'unavailable')]:
            text = ('unsigned Read(unsigned Value,unsigned Step){const int Divisor=' + divisor
                    + ';int Local=10/Divisor;if(Value>0&&Step>0)return Value*Step;return 0;}\n'
                    'unsigned Drive(){return Read(65536,65536);}\n')
            result = check_literal_calls(text, 'Read', 'check-overflow',
                                        'integer overflow in `Value * Step`', 'ilp32', [2], language)
            assert result['status'] == expected, result
            if expected == 'checked':
                assert result['calls'][0]['verdict'] == 'violation'
                assert result['calls'][0]['mathematical_result'] == 4294967296
            else:
                assert result['calls'] == []


def test_const_prefix_refinement_keeps_array_frame_admission_closed():
    from core.audit.array_bounds import check_array_bounds

    for language in ['c', 'cpp']:
        if language == 'cpp':
            pytest.importorskip('tree_sitter_cpp')
        for divisor in ['1', '0']:
            text = ('int Read(unsigned Index){int Data[4]={0};const int Divisor=' + divisor
                    + ';int Local=10/Divisor;return Data[Index];}')
            result = check_array_bounds(text, 'Data[Index]', language=language, integer_abi='ilp32')
            assert result['violation'] is None, result
            assert result['array_bounds_status'] == 'unavailable'
            assert result['reason'] == 'frame syntax or effects are unsupported'



def _prefix_value_reads(text, language):
    if language == 'cpp':
        pytest.importorskip('tree_sitter_cpp')
    data = text.encode()
    root = _get_parser(language).parse(data).root_node
    assert not root.has_error
    pending, reads = [root], []
    while pending:
        node = pending.pop()
        if (node.type == 'identifier' and data[node.start_byte:node.end_byte] == b'Value'
                and node.parent.child_by_field_name('declarator') != node):
            reads.append(node)
        pending.extend(node.named_children)
    return data, sorted(reads, key=lambda node: node.start_byte)


@pytest.mark.parametrize('language', ['c', 'cpp'])
def test_prefix_binding_lookup_work_is_owned_by_each_source_read(monkeypatch, language):
    original = arithmetic_prefix.visible_declarations
    calls = []

    def observed(node, *args, **kwargs):
        calls.append((node.start_byte, node.end_byte))
        return original(node, *args, **kwargs)

    monkeypatch.setattr(arithmetic_prefix, 'visible_declarations', observed)
    data, reads = _prefix_value_reads(
        'int Read(void){const int Value=3;{const int Value=0;int Inner=Value;}return Value;}', language)
    assert len(reads) == 2
    model = PrefixIntegerModel(data, language, resolve_integer_abi('ilp32'))
    for node, expected in zip(reads, [0, 3]):
        assert model.kind_for_name(node).width == 32
        assert model.value_domain(node) == (expected, expected)
        assert model.value_domain(node) == (expected, expected)
    assert all(count <= 1 for count in Counter(calls).values()), calls
    assert model.proofs.checks == 0

    # Distinct trees deliberately put different storage types at the same
    # offsets. Source records and inferred types must never leak between models.
    previous_span = None
    cases = [
        ('const int   Value=1;', 'i16', 16, (1, 1)),
        ('const long  Value=9;', 'i16', 32, (9, 9)),
        ('const int   Value=1;', 'ilp32', 32, (1, 1)),
        ('', 'ilp32', None, None),
    ]
    for declaration, abi, width, domain in cases:
        data, reads = _prefix_value_reads('int Read(void){' + declaration + 'return Value;}', language)
        assert len(reads) == 1
        node = reads[0]
        if declaration:
            span = node.start_byte, node.end_byte
            assert previous_span is None or span == previous_span
            previous_span = span
        model = PrefixIntegerModel(data, language, resolve_integer_abi(abi))
        calls.clear()
        kind = model.kind_for_name(node)
        assert (kind.width if kind is not None else None) == width
        assert model.value_domain(node) == domain
        assert model.value_domain(node) == domain
        assert all(count <= 1 for count in Counter(calls).values()), calls
        assert model.proofs.checks == 0


@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('declaration', ['volatile int Value=1;', 'int Value=Value;'],
                         ids=['volatile', 'self-initialiser'])
def test_prefix_binding_cache_preserves_type_only_read_modes(language, declaration, monkeypatch):
    data, reads = _prefix_value_reads('int Read(void){' + declaration + 'return Value;}', language)
    node = reads[0]
    calls = []
    original = arithmetic_prefix.visible_declarations

    def observed(node, *args, **kwargs):
        calls.append((node.start_byte, node.end_byte))
        return original(node, *args, **kwargs)

    monkeypatch.setattr(arithmetic_prefix, 'visible_declarations', observed)
    model = PrefixIntegerModel(data, language, resolve_integer_abi('ilp32'))
    assert model.kind_for_name(node, read=False).width == 32
    assert model.kind_for_name(node) is None
    assert model.value_domain(node) is None
    assert model.kind_for_name(node, read=False).width == 32
    assert len(calls) <= 1, calls
    assert model.proofs.checks == 0


@pytest.mark.parametrize('language', ['c', 'cpp'])
@pytest.mark.parametrize('prefix,extra', [
    ('unsigned Local=Extra+1;', 'unsigned Extra'),
    ('unsigned Local=Extra-1;', 'unsigned Extra'),
    ('unsigned Local=Extra*2;', 'unsigned Extra'),
    ('int Local=Extra+0;', 'int Extra'),
    ('int Local=Extra-0;', 'int Extra'),
    ('int Local=Extra*1;', 'int Extra'),
    ('int Local=Extra*0;', 'int Extra'),
    ('int Local=Extra*2;', 'unsigned char Extra'),
    ('int Local=Extra+1;', 'unsigned short Extra'),
    ('int Local=Extra-1;', 'unsigned char Extra'),
])
@pytest.mark.usefixtures("semantic_prefix_budget")
def test_mechanically_defined_arithmetic_reaches_audit_verification(prefix, extra, language):
    if language == 'cpp':
        pytest.importorskip('tree_sitter_cpp')
    result = sweep._run_smt_verb_inner(file_path='record.' + language, function_name='Read', verb='check-overflow',
                                     source=source(prefix, extra), hypothesis='integer overflow in `Value + Step`',
                                     integer_abi='ilp32')
    assert result.outcome == 'refuted', result.details


@pytest.mark.parametrize('prefix,extra', [
    ('int Local=Extra+1;', 'int Extra'),
    ('int Local=Extra-1;', 'int Extra'),
    ('int Local=Extra*2;', 'int Extra'),
    ('int Local=Extra*-1;', 'int Extra'),
    ('int Local=Extra+1;', 'unsigned Extra'),
    ('signed char Local=Extra*2;', 'unsigned char Extra'),
])
def test_possible_signed_overflow_or_narrowing_never_gets_prefix_credit(prefix, extra):
    result = sweep._run_smt_verb_inner(file_path='record.c', function_name='Read', verb='check-overflow',
                                     source=source(prefix, extra), hypothesis='integer overflow in `Value + Step`',
                                     integer_abi='ilp32')
    assert result.outcome == 'inconclusive' and result.matches == []


@pytest.mark.parametrize('abi', ['i16', 'ilp32'])
@pytest.mark.parametrize('spelling', ['signed char', 'unsigned char', 'unsigned'])
@pytest.mark.parametrize('operator,operand', [('+', 1), ('-', 1), ('*', 2), ('<<', 1), ('<<', 8), ('<<', 15)])
def test_prefix_result_domains_match_independent_integer_ranges(abi, spelling, operator, operand, monkeypatch):
    from core.audit.arithmetic_types import integer_type
    from core.audit import arithmetic_prefix_obligations
    # This oracle tests arithmetic intervals, not the production deadline.
    # Expiry and query caps have separate conservative-refusal tests.
    monkeypatch.setattr(arithmetic_prefix_obligations, '_BUDGET_MS', 5000)
    integer_abi = resolve_integer_abi(abi)
    data = f'int Read({spelling} Extra){{return Extra {operator} {operand};}}'.encode()
    pending = [_get_parser('c').parse(data).root_node]
    while pending:
        node = pending.pop()
        if node.type == 'binary_expression':
            break
        pending.extend(node.named_children)
    else:
        pytest.fail('arithmetic fixture did not parse')
    storage = integer_type(spelling, integer_abi)
    low = -(1 << (storage.width - 1)) if storage.signed else 0
    high = (1 << (storage.width - (1 if storage.signed else 0))) - 1
    operation_width, signed = storage.promoted_width, storage.promoted_signed

    def calculate(value):
        if operator == '+':
            return value + operand
        if operator == '-':
            return value - operand
        if operator == '*':
            return value * operand
        return value * (2 ** operand)

    minimum, maximum = (-(1 << (operation_width - 1)), (1 << (operation_width - 1)) - 1) if signed else (0, (1 << operation_width) - 1)
    valid = operator != '<<' or (operand < operation_width and (not signed or low >= 0))
    if signed:
        valid = valid and minimum <= calculate(low) <= calculate(high) <= maximum
    domain = PrefixIntegerModel(data, 'c', integer_abi).value_domain(node)
    assert (domain is not None) is valid, (abi, spelling, operator, operand, domain)
    if domain is None:
        return
    values = range(low, high + 1) if storage.width == 8 else (low, low + 1, high // 2, high - 1, high)
    for value in values:
        result = calculate(value)
        if not signed:
            result %= 1 << operation_width
        assert domain[0] <= result <= domain[1], (abi, spelling, operator, operand, value, domain)
