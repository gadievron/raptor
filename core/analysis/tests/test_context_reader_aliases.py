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
    'with contextlib.nullcontext({reader}) as first:\n    pass\nread_attribute = first',
    'with contextlib.nullcontext(({reader},)) as [read_attribute]:\n    pass',
    'with contextlib.nullcontext({reader}) as first, contextlib.nullcontext(first) as read_attribute:\n    pass',
], ids=['bare-chain', 'unpacked', 'multiple-items'])
@pytest.mark.parametrize('nested', [False, True], ids=['direct', 'nested'])
def test_context_reader_cannot_certify_clean_flow(reader, template, binding, nested):
    prefix = 'import contextlib\n' + template[:template.index('def helper(raw):')]
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


def test_unused_context_keeps_precision_and_sibling_isolation():
    summaries = summaries_for('import html\nimport contextlib\ndef helper(raw):\n'
                              '    with contextlib.nullcontext(getattr) as read:\n        pass\n    return html.escape(raw)\n'
                              'def sibling(raw):\n    return html.escape(raw)\n')
    for name in ('helper', 'sibling'):
        assert not summaries[name].summary_unknown
        assert _param_cleanly_sanitized(summaries[name], 0, {'html.escape'})


def test_unused_nested_context_does_not_seed_outer_alias():
    summaries = summaries_for('def helper(obj, field):\n'
                              '    read = lambda obj, field: "owned"\n'
                              '    def unused():\n        with contextlib.nullcontext(getattr) as read:\n            pass\n'
                              '    return read(obj, field)\n')
    assert not summaries['helper'].summary_unknown


def test_target_address_comprehension_bindings_are_not_context_locals():
    function = ast.parse('def helper(slots):\n'
                         '    with contextlib.nullcontext(getattr) as slots[(lambda: [read for read in ()])()]:\n        pass\n').body[0]
    readers = _function_reflective_readers(function, frozenset({'getattr', 'hasattr'}))
    assert 'read' not in readers
    assert 'slots' not in readers


@pytest.mark.parametrize('body,reason', [
    ('return read(obj, field, **mapping)', 'forwards **kwargs'),
    ('global external\n    return read(obj, field)', 'declares global external'),
])
def test_context_reader_preserves_reason_priority(body, reason):
    summaries = summaries_for('def helper(obj, field, mapping):\n'
                              '    with contextlib.nullcontext(getattr) as read:\n        pass\n    ' + body + '\n')
    assert summaries['helper'].summary_unknown_reason == reason


def test_async_context_iterable_preserves_negative_reader_origin_without_execution():
    function = ast.parse('async def helper():\n'
                         '    async with contextlib.nullcontext(getattr) as read:\n        pass\n').body[0]
    readers = _function_reflective_readers(function, frozenset({'getattr', 'hasattr'}))
    assert 'read' in readers


def test_async_context_iterable_lambda_masks_owned_reader_spelling():
    function = ast.parse('async def helper():\n'
                         '    async with (lambda getattr: getattr)([]) as read:\n        pass\n').body[0]
    readers = _function_reflective_readers(function, frozenset({'getattr', 'hasattr'}))
    assert 'read' not in readers


def test_context_without_optional_binding_does_not_seed_unrelated_name():
    function = ast.parse('def helper():\n'
                         '    with contextlib.nullcontext(getattr):\n        pass\n').body[0]
    readers = _function_reflective_readers(function, frozenset({'getattr', 'hasattr'}))
    assert readers == frozenset({'getattr', 'hasattr'})
