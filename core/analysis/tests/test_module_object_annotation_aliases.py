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
    'module-object': ('import annotationlib\nannotations = annotationlib\nread_annotations = annotations.get_annotations', 'read_annotations(leaf)'),
    'module-chain': ('import inspect\nfirst = inspect\nsecond = first\nread_annotations = second.get_annotations', 'read_annotations(leaf)'),
}

class Marker(str):
    pass

@pytest.mark.skipif(sys.version_info < (3, 14), reason='Deferred annotations require Python 3.14')
@pytest.mark.parametrize('kind', list(APIS))
def test_module_object_alias_does_not_forge_clean_path(kind):
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


@pytest.mark.parametrize('bindings,expected', [
    ('import annotationlib\nannotations: object = annotationlib\n', {'annotations.get_annotations'}),
    ('import inspect as annotations\nannotations = None\n', {'annotations.get_annotations'}),
    ('if flag:\n    import inspect as annotations\nelse:\n    annotations = None\n', {'annotations.get_annotations'}),
    ('import annotationlib\nfirst = second = annotationlib\n', {'first.get_annotations', 'second.get_annotations'}),
    ('from . import annotationlib as annotations\ncopy = annotations\n', set()),
    ('annotations = "annotationlib"\n', set()),
])
def test_module_candidates_are_negative_only(bindings, expected):
    from core.analysis.python_module_callgraph import module_import_map
    source = bindings + '\ndef unrelated(value):\n    return value\n'
    graph = build_python_module_callgraph(source)
    assert graph is not None
    assert graph.annotation_evaluator_aliases == frozenset(expected)
    assert graph.import_map == module_import_map(ast.parse(source))
    assert not build_taint_summaries(graph, source)['unrelated'].summary_unknown
