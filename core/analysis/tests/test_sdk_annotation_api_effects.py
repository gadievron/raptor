"""Fixed owned SDK annotation API probe; no external source execution."""
import ast
import html
import sys
import pytest
from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import build_taint_summaries
TEMPLATE = 'import sys\nimport html\nobserved = []\nclass Witness:\n    @property\n    def value(self):\n        current = sys._getframe()\n        try:\n            for _ in range(8):\n                if current is None:\n                    break\n                if current.f_code is helper.__code__:\n                    observed.append("owned-helper")\n                    return current.f_locals["raw"]\n                current = current.f_back\n            raise AssertionError("owned helper frame not present")\n        finally:\n            del current\nwitness = Witness()\ndef helper(raw):\n    def nested():\n        def leaf(value: ANNOTATION):\n            return 0\n        FORCE_LINE\n        return leaf\n    return nested()\ndef handle(raw):\n    return html.escape(raw) + helper(raw).__annotations__["value"]\n'
APIS = {
    'annotationlib': ('import annotationlib', 'annotationlib.get_annotations(leaf)'),
    'inspect': ('import inspect', 'inspect.get_annotations(leaf)'),
    'annotationlib-alias': ('from annotationlib import get_annotations as read_annotations', 'read_annotations(leaf)'),
    'inspect-alias': ('from inspect import get_annotations as read_annotations', 'read_annotations(leaf)'),
}
class Marker(str):
    pass

@pytest.mark.skipif(sys.version_info < (3, 14), reason='Deferred annotations require Python 3.14')
@pytest.mark.parametrize('kind', list(APIS))
def test_sdk_annotation_api_does_not_forge_clean_path(kind):
    imported, call = APIS[kind]
    source = TEMPLATE.replace('import html\n', 'import html\n' + imported + '\n')
    source = source.replace('ANNOTATION', 'witness.value').replace('FORCE_LINE', 'leaf.saved = ' + call)
    source = source.replace('helper(raw).__annotations__["value"]', 'helper(raw).saved["value"]')
    assert not any(isinstance(n, ast.Attribute) and n.attr in {'__annotations__', '__annotate__'}
                   for n in ast.walk(ast.parse(source)))
    graph = build_python_module_callgraph(source)
    assert graph is not None
    summaries = build_taint_summaries(graph, source)
    namespace = {'__name__': 'owned_sdk_annotation_api_fixture'}
    exec(compile(source, '<owned-sdk-annotation-api>', 'exec', dont_inherit=True), namespace)
    marker = Marker('<owned-sdk-annotation-marker>')
    leaf = namespace['helper'](marker)
    assert leaf.saved['value'] is marker
    assert str(marker) in namespace['handle'](marker)
    assert html.escape(marker) != marker
    clean = _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})
    assert not clean
    assert summaries["helper"].summary_unknown


@pytest.mark.parametrize('imported,call', [
    ('import annotationlib as annotations', 'annotations.get_annotations(value)'),
    ('from inspect import get_annotations as read', 'read(value)'),
    ('from annotationlib import get_annotations as read', 'read(value)'),
])
def test_nested_local_import_candidates_poison_enclosing_helper(imported, call):
    source = ('def helper(value):\n    def nested():\n        ' + imported
              + '\n        return ' + call + '\n    return nested()\n')
    graph = build_python_module_callgraph(source)
    assert graph is not None
    assert build_taint_summaries(graph, source)['helper'].summary_unknown


def test_api_name_as_data_does_not_consume_annotations():
    source = 'def helper(value):\n    return {"get_annotations": "annotationlib.get_annotations"}\n'
    graph = build_python_module_callgraph(source)
    assert graph is not None
    assert not build_taint_summaries(graph, source)['helper'].summary_unknown


def test_shadowing_does_not_grant_api_identity_authority():
    source = ('import annotationlib as annotations\n'
              'def helper(annotations, value):\n'
              '    return annotations.get_annotations(value)\n')
    graph = build_python_module_callgraph(source)
    assert graph is not None
    assert build_taint_summaries(graph, source)['helper'].summary_unknown


def test_existing_dynamic_call_reason_keeps_priority():
    source = ('import annotationlib\ndef helper(value):\n'
              '    annotationlib.get_annotations(value)\n    return eval("0")\n')
    graph = build_python_module_callgraph(source)
    assert graph is not None
    summary = build_taint_summaries(graph, source)['helper']
    assert summary.summary_unknown_reason == 'calls eval'
