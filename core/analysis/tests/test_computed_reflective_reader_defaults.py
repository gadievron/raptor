"""Computed defaults cannot hide the existing owned descriptor reader."""

import html

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import build_taint_summaries
from core.analysis.tests.test_adjacent_getter_frame_effects import SOURCE as GETTER_SOURCE
from core.analysis.tests.test_adjacent_hasattr_frame_effects import SOURCE as CHECK_SOURCE


class Marker(str):
    pass


def summaries_for(source):
    graph = build_python_module_callgraph(source)
    assert graph is not None
    assert not graph.namespace_unprovable
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize('reader,template', [('getattr', GETTER_SOURCE), ('hasattr', CHECK_SOURCE)],
                         ids=['getattr', 'hasattr'])
@pytest.mark.parametrize('wrapper', ['({reader},)[0]', '[{reader}][0]', '{{"read": {reader}}}["read"]'],
                         ids=['tuple', 'list', 'dictionary'])
@pytest.mark.parametrize('keyword', [False, True], ids=['positional', 'keyword-only'])
def test_computed_default_getter_cannot_certify_clean_flow(reader, template, wrapper, keyword):
    default = wrapper.format(reader=reader)
    header = f'*, read_attribute={default}' if keyword else f'read_attribute={default}'
    source = template.replace('def nested():', f'def nested({header}):')
    source = source.replace(f'{reader}(witness, "value")', 'read_attribute(witness, "value")')
    summaries = summaries_for(source)
    namespace = {'__name__': 'owned_computed_default_reader_fixture'}
    exec(compile(source, '<owned-computed-reader-default>', 'exec', dont_inherit=True), namespace)
    marker = Marker('<owned-computed-reader-default>')
    assert namespace['helper'](marker) is marker
    assert str(marker) in namespace['handle'](marker)
    assert html.escape(marker) != marker
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})
    assert summaries['helper'].summary_unknown


def test_direct_function_computed_default_keeps_raw_flow():
    source = GETTER_SOURCE[:GETTER_SOURCE.index('def helper(raw):')] + (
        'def helper(raw, read_attribute=(getattr,)[0]):\n'
        '    return read_attribute(witness, "value")\n'
        'def handle(raw):\n    return html.escape(raw) + helper(raw)\n'
    )
    summaries = summaries_for(source)
    namespace = {'__name__': 'owned_direct_computed_default_fixture'}
    exec(compile(source, '<owned-direct-computed-default>', 'exec', dont_inherit=True), namespace)
    marker = Marker('<owned-direct-computed-default>')
    assert namespace['helper'](marker) is marker
    assert str(marker) in namespace['handle'](marker)
    assert summaries['helper'].summary_unknown_reason == 'calls read_attribute'
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})


def test_unused_computed_reader_default_keeps_precision():
    summaries = summaries_for('import html\ndef helper(raw, unused=(getattr,)[0]):\n'
                              '    return html.escape(raw)\n')
    assert not summaries['helper'].summary_unknown
    assert _param_cleanly_sanitized(summaries['helper'], 0, {'html.escape'})


def test_lambda_owned_getter_spelling_is_not_a_retained_reader():
    source = GETTER_SOURCE[:GETTER_SOURCE.index('def helper(raw):')] + (
        'def helper(raw, read_attribute=lambda getattr, field: getattr and "owned"):\n'
        '    return read_attribute(witness, "value")\n'
    )
    summaries = summaries_for(source)
    namespace = {'__name__': 'owned_shadowed_computed_default_fixture'}
    exec(compile(source, '<owned-shadowed-computed-default>', 'exec', dont_inherit=True), namespace)
    assert namespace['helper']('<owned-input>') == 'owned'
    assert not summaries['helper'].summary_unknown


def test_function_body_cannot_retroactively_define_computed_default_origin():
    source = GETTER_SOURCE[:GETTER_SOURCE.index('def helper(raw):')] + (
        'fallback = lambda obj, field: "owned"\n'
        'def helper(raw, read_attribute=(fallback,)[0]):\n'
        '    fallback = getattr\n'
        '    return read_attribute(witness, "value")\n'
    )
    summaries = summaries_for(source)
    namespace = {'__name__': 'owned_defining_frame_default_fixture'}
    exec(compile(source, '<owned-defining-frame-default>', 'exec', dont_inherit=True), namespace)
    assert namespace['helper']('<owned-input>') == 'owned'
    assert not summaries['helper'].summary_unknown


@pytest.mark.parametrize('body,reason', [
    ('return read_attribute(obj, field, **mapping)', 'forwards **kwargs'),
    ('global external\n    return read_attribute(obj, field)', 'declares global external'),
])
def test_computed_reader_does_not_preempt_existing_reason(body, reason):
    summaries = summaries_for('def helper(raw, mapping, read_attribute=(getattr,)[0]):\n    '
                              + body + '\n')
    assert summaries['helper'].summary_unknown_reason == reason
