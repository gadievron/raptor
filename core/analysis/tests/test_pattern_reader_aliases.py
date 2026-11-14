"""Local container projections retain the fixed owned descriptor reader."""
import ast
import html

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _function_reflective_readers, build_taint_summaries
from core.analysis.tests.test_adjacent_getter_frame_effects import SOURCE as GETTER_SOURCE
from core.analysis.tests.test_adjacent_hasattr_frame_effects import SOURCE as CHECK_SOURCE


class Marker(str):
    pass


@pytest.mark.parametrize('reader,template', [('getattr', GETTER_SOURCE), ('hasattr', CHECK_SOURCE)],
                         ids=['getattr', 'hasattr'])
@pytest.mark.parametrize('binding', [
    'match ({reader},):\n    case [first]:\n        pass\nread_attribute = first',
    'match ({reader},):\n    case [*retained]:\n        pass\nread_attribute = retained[0]',
    'match {{"read": {reader}}}:\n    case {{"read": first}}:\n        pass\nread_attribute = first',
    'match {{"read": {reader}}}:\n    case {{**retained}}:\n        pass\nread_attribute = retained["read"]',
    'match {reader}:\n    case read_attribute:\n        pass',
    'match ({reader},):\n    case [first] | (first,):\n        pass\nread_attribute = first',
], ids=['sequence-chain', 'star', 'mapping', 'mapping-rest', 'capture', 'or'])
@pytest.mark.parametrize('nested', [False, True], ids=['direct', 'nested'])
def test_pattern_reader_cannot_certify_clean_flow(reader, template, binding, nested):
    prefix = template[:template.index('def helper(raw):')]
    indent = '        ' if nested else '    '
    assignments = ''.join(indent + line + '\n' for line in binding.format(reader=reader).splitlines())
    if reader == 'hasattr':
        consumer = (indent + 'read_attribute(witness, "value")\n'
                    + indent + 'return observed[-1]\n')
    else:
        consumer = indent + 'return read_attribute(witness, "value")\n'
    if nested:
        body = '    def nested():\n' + assignments + consumer + '    return nested()\n'
    else:
        body = assignments + consumer
    source = prefix + 'def helper(raw):\n' + body + (
        'def handle(raw):\n    return html.escape(raw) + helper(raw)\n'
    )
    graph = build_python_module_callgraph(source)
    assert graph is not None
    assert not graph.namespace_unprovable
    summaries = build_taint_summaries(graph, source)
    namespace = {'__name__': 'owned_local_container_reader_fixture'}
    exec(compile(source, '<owned-local-container-reader>', 'exec', dont_inherit=True), namespace)
    marker = Marker('<owned-local-container-reader>')
    assert namespace['helper'](marker) is marker
    assert str(marker) in namespace['handle'](marker)
    assert html.escape(marker) != marker
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})
    assert summaries['helper'].summary_unknown


def summaries_for(source):
    graph = build_python_module_callgraph(source)
    assert graph is not None
    assert not graph.namespace_unprovable
    return build_taint_summaries(graph, source)


def test_existing_capture_refusal_and_sibling_isolation_are_preserved():
    summaries = summaries_for('import html\ndef helper(raw):\n'
                              '    match getattr:\n        case read:\n            pass\n    return html.escape(raw)\n'
                              'def sibling(raw):\n    return html.escape(raw)\n')
    assert summaries['helper'].summary_unknown_reason == 'pattern capture value transfer is not modelled'
    assert not summaries['sibling'].summary_unknown
    assert _param_cleanly_sanitized(summaries['sibling'], 0, {'html.escape'})


def test_unused_nested_pattern_does_not_seed_outer_alias():
    summaries = summaries_for('def helper(obj, field):\n'
                              '    read = lambda obj, field: "owned"\n'
                              '    def unused():\n        match getattr:\n            case read:\n                pass\n'
                              '    return read(obj, field)\n')
    assert not summaries['helper'].summary_unknown


def test_guard_expression_scopes_are_not_pattern_capture_bindings():
    function = ast.parse('def helper():\n'
                         '    match getattr:\n'
                         '        case read if (lambda: [leaked for leaked in ()])():\n'
                         '            pass\n').body[0]
    readers = _function_reflective_readers(function, frozenset({'getattr', 'hasattr'}))
    assert 'read' in readers
    assert 'leaked' not in readers


@pytest.mark.parametrize('body', [
    'return read(obj, field, **mapping)',
    'global external\n    return read(obj, field)',
])
def test_existing_pattern_capture_refusal_keeps_priority(body):
    summaries = summaries_for('def helper(obj, field, mapping):\n'
                              '    match getattr:\n        case read:\n            pass\n    ' + body + '\n')
    assert summaries['helper'].summary_unknown_reason == 'pattern capture value transfer is not modelled'


def test_subject_lambda_masks_its_owned_reader_spelling():
    function = ast.parse('def helper():\n'
                         '    match (lambda getattr: getattr)(0):\n'
                         '        case read:\n            pass\n').body[0]
    readers = _function_reflective_readers(function, frozenset({'getattr', 'hasattr'}))
    assert 'read' not in readers


def test_wildcard_pattern_has_no_capture_binding():
    function = ast.parse('def helper():\n'
                         '    match getattr:\n        case _:\n            pass\n').body[0]
    readers = _function_reflective_readers(function, frozenset({'getattr', 'hasattr'}))
    assert readers == frozenset({'getattr', 'hasattr'})
