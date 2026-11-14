"""Local container projections retain the fixed owned descriptor reader."""
import html

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import build_taint_summaries
from core.analysis.tests.test_adjacent_getter_frame_effects import SOURCE


class Marker(str):
    pass


@pytest.mark.parametrize('wrapper', ['(getattr,)[0]', '[getattr][0]', '{"read": getattr}["read"]'],
                         ids=['tuple', 'list', 'dictionary'])
@pytest.mark.parametrize('nested', [False, True], ids=['direct', 'nested'])
def test_local_container_reader_cannot_certify_clean_flow(wrapper, nested):
    prefix = SOURCE[:SOURCE.index('def helper(raw):')]
    if nested:
        body = ('    def nested():\n'
                f'        first = {wrapper}\n'
                '        read_attribute = first\n'
                '        return read_attribute(witness, "value")\n'
                '    return nested()\n')
    else:
        body = (f'    first = {wrapper}\n'
                '    read_attribute = first\n'
                '    return read_attribute(witness, "value")\n')
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


def test_unused_computed_reader_keeps_precision_and_sibling_isolation():
    summaries = summaries_for('import html\ndef helper(raw):\n'
                              '    read = (getattr,)[0]\n    return html.escape(raw)\n'
                              'def sibling(raw):\n    return html.escape(raw)\n')
    for name in ('helper', 'sibling'):
        assert not summaries[name].summary_unknown
        assert _param_cleanly_sanitized(summaries[name], 0, {'html.escape'})


def test_lambda_owned_name_does_not_seed_reader_alias():
    summaries = summaries_for('def helper(obj, field):\n'
                              '    read = lambda getattr, field: getattr\n'
                              '    return read(obj, field)\n')
    assert not summaries['helper'].summary_unknown


def test_unused_nested_scope_does_not_seed_outer_alias():
    summaries = summaries_for('def helper(obj, field):\n'
                              '    read = lambda obj, field: "owned"\n'
                              '    def unused():\n        read = (getattr,)[0]\n'
                              '    return read(obj, field)\n')
    assert not summaries['helper'].summary_unknown


@pytest.mark.parametrize('body,reason', [
    ('return read(obj, field, **mapping)', 'forwards **kwargs'),
    ('global external\n    return read(obj, field)', 'declares global external'),
])
def test_computed_local_reader_preserves_reason_priority(body, reason):
    summaries = summaries_for('def helper(obj, field, mapping):\n'
                              '    read = (getattr,)[0]\n    ' + body + '\n')
    assert summaries['helper'].summary_unknown_reason == reason
