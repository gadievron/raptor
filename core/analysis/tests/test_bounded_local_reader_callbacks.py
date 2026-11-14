"""Bounded callback reads withhold certification without effect/return proofs."""
import ast
import html

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import (
    _bounded_body_expression_loads,
    _detect_summary_unknown,
    _function_comprehension_retains_reflective_reader,
    _function_local_callable_candidates,
    build_taint_summaries,
)
from core.analysis.tests.test_adjacent_getter_frame_effects import SOURCE as GETTER_SOURCE
from core.analysis.tests.test_adjacent_hasattr_frame_effects import SOURCE as CHECK_SOURCE


class Marker(str):
    pass


@pytest.mark.parametrize('reader,template', [('getattr', GETTER_SOURCE), ('hasattr', CHECK_SOURCE)],
                         ids=['getattr', 'hasattr'])
@pytest.mark.parametrize('body', [
    '{prelude}\nreturn {value}',
    'if True:\n    {prelude}\nreturn {value}',
    'for ignored in (0,):\n    {prelude}\nreturn {value}',
    'try:\n    {prelude}\nfinally:\n    pass\nreturn {value}',
    'try:\n    {prelude}\nexcept AttributeError:\n    pass\nreturn {value}',
    'with contextlib.nullcontext():\n    {prelude}\nreturn {value}',
    'pass\n{prelude}\nreturn {value}',
    '{prelude}\nassert True\nreturn {value}',
    'alias = read\n{aliased_prelude}\nreturn {value}',
], ids=['linear', 'branch', 'loop', 'finally', 'unnamed-handler', 'context', 'pass', 'assert', 'local-alias'])
@pytest.mark.parametrize('nested', [False, True], ids=['direct', 'adjacent'])
def test_bounded_reader_callback_cannot_certify_clean_flow(reader, template, body, nested):
    prefix = 'import contextlib\n' + template[:template.index('def helper(raw):')]
    invocation = 'read(witness, "value")'
    prelude = 'result = ' + invocation if reader == 'getattr' else invocation
    statements = body.format(prelude=prelude, aliased_prelude=prelude.replace('read(', 'alias('),
                             value='result' if reader == 'getattr' else 'observed[-1]')
    definition = 'def consume(read):\n' + ''.join('    ' + line + '\n' for line in statements.splitlines())
    indent = '        ' if nested else '    '
    outer = ''.join(indent + line + '\n' for line in definition.splitlines())
    outer += indent + 'return consume(' + reader + ')\n'
    if nested:
        outer = '    def nested():\n' + outer + '    return nested()\n'
    source = prefix + 'def helper(raw):\n' + outer + (
        'def handle(raw):\n    return html.escape(raw) + helper(raw)\n'
    )
    graph = build_python_module_callgraph(source)
    assert graph is not None
    assert not graph.namespace_unprovable
    summaries = build_taint_summaries(graph, source)
    namespace = {'__name__': 'owned_bounded_reader_callback_fixture'}
    exec(compile(source, '<owned-bounded-reader-callback>', 'exec', dont_inherit=True), namespace)
    marker = Marker('<owned-bounded-reader-callback>')
    assert namespace['helper'](marker) is marker
    assert str(marker) in namespace['handle'](marker)
    assert html.escape(marker) != marker
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})
    assert summaries['helper'].summary_unknown


def function(source):
    return ast.parse(source).body[0]


def test_pass_and_return_are_now_supported_negative_body_reads():
    fn = function('def helper():\n    def consume(read):\n        pass\n        return read(obj, field)\n'
                  '    return consume(getattr)\n')
    assert 'consume' in _function_local_callable_candidates(fn)
    assert _detect_summary_unknown(fn) == 'local function call retains an unmodelled reflective reader'


@pytest.mark.parametrize('body', [
    'raise read(obj, field)',
    'try:\n    read(obj, field)\nexcept Exception:\n    return 0',
    'import owned_unexecuted\nread(obj, field)\nreturn 0',
])
def test_existing_lexical_reads_do_not_grant_raise_try_or_import_effect_authority(body):
    definition = '    def consume(read):\n' + ''.join('        ' + line + '\n' for line in body.splitlines())
    fn = function('def helper():\n' + definition + '    return consume(getattr)\n')
    assert _function_comprehension_retains_reflective_reader(
        fn, frozenset({'getattr', 'hasattr'}), local_functions=True,
    )


def test_named_exception_handler_remains_outside_existing_body_grammar():
    fn = function('def helper():\n    def consume(read):\n'
                  '        try:\n            return read(obj, field)\n'
                  '        except Exception as caught:\n            return caught\n')
    prototype = fn.body[0]
    assert _bounded_body_expression_loads(prototype.body) is None
    assert 'consume' not in _function_local_callable_candidates(fn)


def test_unused_parameter_in_bounded_body_keeps_existing_precision():
    fn = function('def helper():\n    def consume(read):\n        pass\n        return 0\n'
                  '    return consume(getattr)\n')
    assert _detect_summary_unknown(fn) is None


def test_own_local_bindings_mask_definition_frame_reader_aliases():
    fn = function('def helper():\n    alias = getattr\n    def consume(unused):\n'
                  '        alias = lambda obj, field: "owned"\n        return alias(obj, field)\n'
                  '    return consume(0)\n')
    assert not _function_comprehension_retains_reflective_reader(
        fn, frozenset({'getattr', 'hasattr'}), local_functions=True,
    )
    assert _detect_summary_unknown(fn) == 'returned local call may have unmodelled reflective effects'


def test_bounded_prototypes_do_not_leak_to_sibling():
    source = ('import html\ndef helper(raw):\n    def consume(read):\n'
              '        read(obj, field)\n        return 0\n    return consume(getattr)\n'
              'def sibling(raw):\n    def consume(read):\n        pass\n        return "owned"\n'
              '    return html.escape(raw) + consume(getattr)\n')
    graph = build_python_module_callgraph(source)
    assert graph is not None
    summaries = build_taint_summaries(graph, source)
    assert summaries['helper'].summary_unknown
    assert not summaries['sibling'].summary_unknown
    assert _param_cleanly_sanitized(summaries['sibling'], 0, {'html.escape'})


def test_saved_defaults_keep_defining_frame_with_bounded_body():
    fn = function('def helper(safe):\n    def consume(read=getattr):\n'
                  '        pass\n        return read(obj, field)\n'
                  '    return [consume() for getattr in (safe,)]\n')
    assert _function_comprehension_retains_reflective_reader(
        fn, frozenset({'getattr', 'hasattr'}), local_functions=True,
    )


def test_comprehension_callback_binder_masks_bounded_source_candidate():
    fn = function('def helper(safe):\n    def consume(read):\n'
                  '        pass\n        return read(obj, field)\n'
                  '    return [consume(getattr) for consume in (safe,)]\n')
    assert _detect_summary_unknown(fn) is None


def test_bounded_body_and_source_nodes_are_not_mutated():
    fn = function('def helper():\n    def consume(read):\n'
                  '        unused = 0\n        return read(obj, field)\n'
                  '    return consume(getattr)\n')
    before = ast.dump(fn, include_attributes=True)
    identities = tuple(id(node) for node in ast.walk(fn))
    assert _detect_summary_unknown(fn) == 'local function call retains an unmodelled reflective reader'
    assert ast.dump(fn, include_attributes=True) == before
    assert tuple(id(node) for node in ast.walk(fn)) == identities


@pytest.mark.parametrize('body,expected', [
    ('return consume(**mapping)', 'forwards **kwargs'),
    ('global external\n    return consume(getattr)', 'declares global external'),
])
def test_existing_reason_priority_is_preserved(body, expected):
    fn = function('def helper(mapping):\n    def consume(read):\n'
                  '        pass\n        return read(obj, field)\n    ' + body + '\n')
    assert _detect_summary_unknown(fn) == expected


def test_unused_free_reader_acquisition_is_not_a_bounded_call_effect():
    fn = function('def helper():\n    def consume():\n'
                  '        unused = getattr\n        return 0\n    return consume()\n')
    assert _detect_summary_unknown(fn) is None
