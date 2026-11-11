"""Related-code packets bind current source without granting proof scope."""
from dataclasses import FrozenInstanceError, replace

import pytest

from core.audit import caller_review_context as adapter
from core.audit.knowledge_requests import KnowledgeOrigin
from core.audit.refutation_source import capture_source_identity


def _case(tmp_path, *, caller_source='def caller(x):\n    return callee(x)\n', same_file=False):
    root = tmp_path / 'root'
    root.mkdir()
    callee = 'def callee(x):\n    return x + 1\n'
    if same_file:
        file = 'callee.py'
        source = callee + '\n' + caller_source
        (root / file).write_text(source)
        lo = 4
    else:
        file = 'caller.py'
        (root / 'callee.py').write_text(callee)
        (root / file).write_text(caller_source)
        lo = 1
    identity = capture_source_identity(root, 'callee.py', excerpt=callee, line_start=1)
    assert identity is not None
    origin = KnowledgeOrigin('owned-pass', 'callee.py', 'callee', 1, 2, identity)
    count = len(caller_source.rstrip('\n').split('\n'))
    inventory = {'files': [{'path': file, 'items': [
        {'name': 'caller', 'kind': 'function', 'line_start': lo, 'line_end': lo + count - 1},
    ]}]}
    request = adapter.CallerContextRequest('owned-request', origin, file, 'caller', lo,
                                           'Does this caller enforce the bound?')
    return root, request, inventory


@pytest.mark.parametrize('same_file', [False, True])
def test_resolves_current_definition_and_revalidates_both_sources(tmp_path, same_file):
    root, request, inventory = _case(tmp_path, same_file=same_file)
    answer = adapter.resolve_caller_context(request, root, inventory)
    assert answer.status == 'ready'
    assert answer.origin is request.origin and answer.request_id == request.request_id
    assert answer.material is not None
    assert answer.material.source == 'def caller(x):\n    return callee(x)'
    assert answer.material.line_start == request.caller_line
    assert answer.material.line_end == request.caller_line + 1
    assert not answer.material.truncated
    assert adapter.validate_caller_context(answer, root) == (True, '')


def test_registered_requests_have_owned_identity_and_keep_question_as_reason(tmp_path):
    _root, request, _inventory = _case(tmp_path)
    row = {'file': 'caller.py', 'function': 'caller', 'line_start': 1,
           'reason': 'Does this caller enforce the bound?', 'request_id': 'forged', 'origin': 'forged'}
    batch = adapter.register_caller_context_requests({'caller_context_requests': [row]}, request.origin)
    assert not batch.rejected and len(batch.accepted) == 1
    accepted = batch.accepted[0]
    assert accepted.request_id != 'forged' and accepted.origin is request.origin
    assert accepted.reason == row['reason']
    row['file'] = 'replacement.py'
    assert accepted.caller_file == 'caller.py'
    with pytest.raises(FrozenInstanceError):
        accepted.caller_file = 'other.py'


@pytest.mark.parametrize('row', [None, {}, {'file': 'a.py'},
    {'file': 'a.py', 'function': 'f', 'line_start': True, 'reason': 'needed'},
    {'file': 'a.py', 'function': 'f', 'line_start': 0, 'reason': 'needed'},
    {'file': 'a.py', 'function': 'f', 'line_start': 1, 'reason': 'x' * 1001},
    {'file': 'a.py\nother', 'function': 'f', 'line_start': 1, 'reason': 'needed'},
])
def test_malformed_request_rows_are_visible(tmp_path, row):
    _root, request, _inventory = _case(tmp_path)
    batch = adapter.register_caller_context_requests({'caller_context_requests': [row]}, request.origin)
    assert not batch.accepted and batch.rejected[0].index == 0


def test_request_shape_caps_and_deduplication_are_visible(tmp_path):
    _root, request, _inventory = _case(tmp_path)
    invalid = adapter.register_caller_context_requests({'caller_context_requests': {}}, request.origin)
    assert invalid.rejected[0].reason == 'expected_array'
    row = {'file': 'caller.py', 'function': 'caller', 'line_start': 1, 'reason': 'need caller'}
    duplicate = adapter.register_caller_context_requests({'caller_context_requests': [row, row]}, request.origin)
    assert len(duplicate.accepted) == 1 and duplicate.rejected[0].reason == 'duplicate_request'
    rows = [{**row, 'reason': f'need caller {index}'} for index in range(7)]
    capped = adapter.register_caller_context_requests({'caller_context_requests': rows}, request.origin)
    assert len(capped.accepted) == 4
    assert capped.rejected[0].reason == 'request_limit' and capped.rejected[0].count == 3


@pytest.mark.parametrize('replacement', ['def renamed(x):\n    return callee(x)\n',
                                          '# moved\ndef caller(x):\n    return callee(x)\n'])
def test_stale_inventory_cannot_label_a_different_current_definition(tmp_path, replacement):
    root, request, inventory = _case(tmp_path)
    (root / request.caller_file).write_text(replacement)
    answer = adapter.resolve_caller_context(request, root, inventory)
    assert answer.material is None and answer.reason == 'caller_definition_changed'


def test_ambiguous_inventory_refuses_instead_of_first_name_match(tmp_path):
    root, request, inventory = _case(tmp_path)
    inventory['files'][0]['items'].append(dict(inventory['files'][0]['items'][0]))
    answer = adapter.resolve_caller_context(request, root, inventory)
    assert answer.status == 'ambiguous' and answer.material is None


def test_same_named_definitions_are_selected_by_current_line(tmp_path):
    root, request, _inventory = _case(tmp_path, caller_source=(
        'def caller(x):\n    return 0\n\ndef caller(x):\n    return callee(x)\n'))
    request = replace(request, caller_line=4)
    inventory = {'files': [{'path': 'caller.py', 'functions': [
        {'name': 'caller', 'line_start': 1, 'line_end': 2},
        {'name': 'caller', 'line_start': 4, 'line_end': 5},
    ]}]}
    answer = adapter.resolve_caller_context(request, root, inventory)
    assert answer.status == 'ready' and answer.material is not None
    assert answer.material.line_start == 4 and 'return callee' in answer.material.source


@pytest.mark.parametrize('field,value', [('line_end', None), ('line_end', 99), ('kind', 'class')])
def test_invalid_or_nonfunction_inventory_span_is_not_admitted(tmp_path, field, value):
    root, request, inventory = _case(tmp_path)
    inventory['files'][0]['items'][0][field] = value
    assert adapter.resolve_caller_context(request, root, inventory).material is None


@pytest.mark.parametrize('which,remove', [('origin', False), ('caller', False), ('origin', True), ('caller', True)])
def test_endpoint_change_or_loss_invalidates_a_packet(tmp_path, which, remove):
    root, request, inventory = _case(tmp_path)
    answer = adapter.resolve_caller_context(request, root, inventory)
    assert answer.status == 'ready'
    path = root / (request.origin.file if which == 'origin' else request.caller_file)
    if remove:
        path.unlink()
    else:
        path.write_text(path.read_text() + '# changed\n')
    assert not adapter.validate_caller_context(answer, root)[0]


@pytest.mark.parametrize('which', ['origin', 'caller'])
def test_change_during_related_source_read_is_not_admitted(tmp_path, monkeypatch, which):
    root, request, inventory = _case(tmp_path)
    real_read = adapter.read_contained

    def changing_read(*args, **kwargs):
        value = real_read(*args, **kwargs)
        path = root / (request.origin.file if which == 'origin' else request.caller_file)
        path.write_text(path.read_text() + '# changed during read\n')
        return value

    monkeypatch.setattr(adapter, 'read_contained', changing_read)
    answer = adapter.resolve_caller_context(request, root, inventory)
    assert answer.status == 'deferred' and answer.material is None


def test_cached_or_fabricated_reader_excerpt_cannot_acquire_fresh_identity(tmp_path, monkeypatch):
    root, request, inventory = _case(tmp_path)
    monkeypatch.setattr(adapter, 'read_contained', lambda *args, **kwargs: 'def caller(x):\n    return 999\n')
    answer = adapter.resolve_caller_context(request, root, inventory)
    assert answer.status == 'deferred' and answer.reason == 'caller_source_changed'


def test_full_file_excerpt_cannot_bypass_displayed_coordinate_check(tmp_path):
    root, request, inventory = _case(tmp_path)
    answer = adapter.resolve_caller_context(request, root, inventory)
    assert answer.material is not None
    shifted = replace(answer, material=replace(answer.material, line_start=2, line_end=3))
    assert adapter.validate_caller_context(shifted, root) == (False, 'caller_excerpt_changed')


def test_outside_root_hint_never_reaches_related_source_reader(tmp_path, monkeypatch):
    root, request, _inventory = _case(tmp_path)
    (tmp_path / 'outside.py').write_text('def caller(x):\n    return x\n')
    request = replace(request, caller_file='../outside.py')
    inventory = {'files': [{'path': '../outside.py', 'items': [
        {'name': 'caller', 'line_start': 1, 'line_end': 2},
    ]}]}
    calls = []
    monkeypatch.setattr(adapter, 'read_contained', lambda *args, **kwargs: calls.append(args))
    answer = adapter.resolve_caller_context(request, root, inventory)
    assert answer.material is None and not calls


@pytest.mark.parametrize('newline', ['\n', '\r\n'])
def test_lf_and_crlf_have_the_same_displayed_source_coordinates(tmp_path, newline):
    root, request, inventory = _case(tmp_path)
    (root / request.caller_file).write_bytes(('def caller(x):\n    return callee(x)\n').replace('\n', newline).encode())
    answer = adapter.resolve_caller_context(request, root, inventory)
    assert answer.status == 'ready' and answer.material is not None
    assert answer.material.line_end == 2 and '\r' not in answer.material.source


def test_bare_cr_coordinates_are_explicitly_unavailable(tmp_path):
    root, request, inventory = _case(tmp_path)
    (root / request.caller_file).write_bytes(b'def caller(x):\r    return callee(x)\r')
    answer = adapter.resolve_caller_context(request, root, inventory)
    assert answer.reason == 'source_line_model_unavailable' and answer.material is None


def test_unicode_separator_inside_a_comment_is_not_a_source_line(tmp_path):
    source = 'def caller(x):\n    # Unicode separator \u2028 remains in line\n    return callee(x)\n'
    root, request, inventory = _case(tmp_path, caller_source=source)
    answer = adapter.resolve_caller_context(request, root, inventory)
    assert answer.status == 'ready' and answer.material is not None
    assert answer.material.line_end == 3 and '\u2028' in answer.material.source


def test_large_body_is_a_line_aligned_partial_packet(tmp_path):
    source = 'def caller(x):\n' + ('    # ' + 'x' * 100 + '\n') * 220 + '    return callee(x)\n'
    root, request, inventory = _case(tmp_path, caller_source=source)
    answer = adapter.resolve_caller_context(request, root, inventory)
    assert answer.status == 'partial' and answer.material is not None
    assert answer.material.truncated and len(answer.material.source) <= 16_000
    assert answer.material.line_end < inventory['files'][0]['items'][0]['line_end']
    assert adapter.validate_caller_context(answer, root) == (True, '')


def test_oversized_first_line_is_unavailable(tmp_path):
    source = "def caller(x='" + 'x' * 17_000 + "'):\n    return x\n"
    root, request, inventory = _case(tmp_path, caller_source=source)
    answer = adapter.resolve_caller_context(request, root, inventory)
    assert answer.material is None and answer.reason == 'caller_line_exceeds_context_cap'


@pytest.mark.parametrize('endpoint', ['origin', 'caller'])
def test_binary_endpoints_require_a_separate_binding_adapter(tmp_path, endpoint):
    root, request, inventory = _case(tmp_path)
    if endpoint == 'origin':
        request = replace(request, origin=replace(request.origin, file='binary:program'))
    else:
        request = replace(request, caller_file='binary:program')
    answer = adapter.resolve_caller_context(request, root, inventory)
    assert answer.status == 'deferred' and answer.reason == 'binary_context_binding_unavailable'


def test_origin_without_identity_does_not_admit_related_code(tmp_path):
    root, request, inventory = _case(tmp_path)
    request = replace(request, origin=replace(request.origin, source_identity=None))
    answer = adapter.resolve_caller_context(request, root, inventory)
    assert answer.material is None and answer.reason == 'origin_source_unavailable'


def test_python_parse_failure_cannot_fall_back_to_regex_definition_scope(tmp_path):
    root, request, inventory = _case(tmp_path)
    (root / request.caller_file).write_text('def caller(x):\n    return (\n')
    answer = adapter.resolve_caller_context(request, root, inventory)
    assert answer.material is None and answer.reason == 'caller_definition_parser_unavailable'


def test_missing_nonpython_grammar_is_explicit(tmp_path, monkeypatch):
    root, request, _inventory = _case(tmp_path)
    (root / 'caller.c').write_text('int caller(int x) {\n    return x;\n}\n')
    request = replace(request, caller_file='caller.c')
    inventory = {'files': [{'path': 'caller.c', 'items': [
        {'name': 'caller', 'line_start': 1, 'line_end': 3},
    ]}]}

    class MissingGrammar:
        def __init__(self, language):
            raise RuntimeError('grammar unavailable')

    monkeypatch.setattr('core.inventory.extractors.TreeSitterExtractor', MissingGrammar)
    answer = adapter.resolve_caller_context(request, root, inventory)
    assert answer.material is None and answer.reason == 'caller_definition_parser_unavailable'


@pytest.mark.parametrize('field', ['file', 'function', 'reason'])
@pytest.mark.parametrize('invalid', [chr(0xD800), chr(0xDFFF)])
def test_non_utf8_request_text_is_rejected(tmp_path, field, invalid):
    _root, request, _inventory = _case(tmp_path)
    row = {'file': 'caller.py', 'function': 'caller', 'line_start': 1, 'reason': 'needed'}
    row[field] += invalid
    batch = adapter.register_caller_context_requests({'caller_context_requests': [row]}, request.origin)
    assert batch.accepted == ()
    assert batch.rejected == (adapter.CallerContextRejection(0, 'invalid_request_fields'),)
