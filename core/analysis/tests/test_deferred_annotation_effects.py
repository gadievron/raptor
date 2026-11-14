"""Deferred annotation metadata cannot certify a clean sanitizer path."""
import ast
import html
import sys

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _detect_summary_unknown, build_taint_summaries

HEADERS = {
    'direct': 'witness.value',
    'reflective': '(lambda:0).__globals__["witness"].value',
    'generator-frame': '(0 for item in ()).gi_frame.f_globals["witness"].value',
}
TEMPLATE = 'import sys\nimport html\nobserved = []\nclass Witness:\n    @property\n    def value(self):\n        current = sys._getframe()\n        try:\n            for _ in range(8):\n                if current is None:\n                    break\n                if current.f_code is helper.__code__:\n                    observed.append("owned-helper")\n                    return current.f_locals["raw"]\n                current = current.f_back\n            raise AssertionError("owned helper frame not present")\n        finally:\n            del current\nwitness = Witness()\ndef helper(raw):\n    def nested():\n        def leaf(value: ANNOTATION):\n            return 0\n        FORCE_LINE\n        return leaf\n    return nested()\ndef handle(raw):\n    return html.escape(raw) + helper(raw).__annotations__["value"]\n'


def fixture_source(kind, *, future=False, force=True, protocol='annotations'):
    source = TEMPLATE.replace('ANNOTATION', HEADERS[kind])
    if protocol == 'callable':
        source = source.replace('import html\n', 'import html\nimport annotationlib\n')
        force_line = 'leaf.saved = leaf.__annotate__(annotationlib.Format.VALUE)'
        source = source.replace('helper(raw).__annotations__["value"]', 'helper(raw).saved["value"]')
    else:
        force_line = 'leaf.__annotations__'
    source = source.replace('FORCE_LINE', force_line if force else 'pass')
    return ('from __future__ import annotations\n' if future else '') + source


def summaries_for(source):
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


def owned_namespace(source):
    # Execute only this fixed owned fixture. The descriptor reads a local only
    # after matching the exact owned helper code object, within an 8-frame walk.
    namespace = {'__name__': 'owned_annotation_effect_fixture'}
    exec(compile(source, '<owned-annotation-effect-fixture>', 'exec', dont_inherit=True), namespace)
    return namespace


class Marker(str):
    pass


@pytest.mark.parametrize('kind', list(HEADERS))
@pytest.mark.parametrize('protocol', ['annotations', 'callable'])
def test_forced_annotation_does_not_forge_a_clean_path(kind, protocol):
    if protocol == 'callable' and sys.version_info < (3, 14):
        pytest.skip('__annotate__ requires Python 3.14')
    source = fixture_source(kind, protocol=protocol)
    summaries = summaries_for(source)
    namespace = owned_namespace(source)
    marker = Marker('<owned-annotation-marker>')
    leaf = namespace['helper'](marker)
    retained = leaf.saved['value'] if protocol == 'callable' else leaf.__annotations__['value']
    assert retained is marker
    assert str(marker) in namespace['handle'](marker)
    assert html.escape(marker) != marker
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})
    # A zero-argument nested consumer must also poison its enclosing helper.
    assert summaries['helper'].summary_unknown


@pytest.mark.skipif(sys.version_info < (3, 14), reason='Deferred ordinary annotations require Python 3.14')
@pytest.mark.parametrize('kind', list(HEADERS))
def test_unforced_ordinary_annotation_is_lazy_on_this_runtime(kind):
    namespace = owned_namespace(fixture_source(kind, force=False))
    namespace['helper'](Marker('<owned-unforced-marker>'))
    assert namespace['observed'] == []


@pytest.mark.parametrize('kind', list(HEADERS))
@pytest.mark.parametrize('protocol', ['annotations', 'callable'])
def test_future_annotation_keeps_text_without_descriptor_effects(kind, protocol):
    if protocol == 'callable' and sys.version_info < (3, 14):
        pytest.skip('__annotate__ requires Python 3.14')
    namespace = owned_namespace(fixture_source(kind, future=True, protocol=protocol))
    marker = Marker('<owned-future-marker>')
    leaf = namespace['helper'](marker)
    retained = leaf.saved['value'] if protocol == 'callable' else leaf.__annotations__['value']
    assert isinstance(retained, str)
    assert str(marker) not in namespace['handle'](marker)
    assert namespace['observed'] == []


@pytest.mark.parametrize('field', ['__annotations__', '__annotate__'])
def test_protocol_names_as_data_keep_clean_paths(field):
    source = ('import html\ndef helper(raw):\n'
              + '    return html.escape(raw) + {' + repr(field) + ': "constant"}[' + repr(field) + ']\n')
    summary = summaries_for(source)['helper']
    assert not summary.summary_unknown
    assert _param_cleanly_sanitized(summary, 0, {'html.escape'})


@pytest.mark.parametrize('statement', ['value.__annotations__ = {}', 'del value.__annotations__',
                                     'value.__annotate__ = None', 'del value.__annotate__'])
def test_only_reads_consume_the_annotation_protocol(statement):
    # This checks the read guard's scope, not arbitrary setter/deleter effects.
    function = ast.parse('def helper(value):\n    ' + statement + '\n    return 0\n').body[0]
    assert _detect_summary_unknown(function) is None


@pytest.mark.parametrize('statement,reason', [('return eval("0")', 'calls eval'),
                                            ('global external', 'declares global external')])
def test_existing_unknown_reasons_keep_priority(statement, reason):
    source = 'def helper(value):\n    value.__annotations__\n    ' + statement + '\n'
    assert _detect_summary_unknown(ast.parse(source).body[0]) == reason


def test_existing_cell_reason_keeps_priority():
    source = ('def helper(raw):\n    def nested():\n        raw.__annotations__\n'
              '        return raw\n    return nested\n')
    assert _detect_summary_unknown(ast.parse(source).body[0]) == 'returned function retains an unmodelled enclosing cell'


def test_safe_projections_and_existing_capture_guard_are_preserved():
    source = fixture_source('reflective', force=False).replace(HEADERS['reflective'], '(1+2j).real')
    assert not summaries_for(source)['helper'].summary_unknown
    captured = fixture_source('reflective', force=False).replace('            return 0', '            return raw')
    summary = summaries_for(captured)['helper']
    assert summary.summary_unknown
    assert 'cell' in summary.summary_unknown_reason
