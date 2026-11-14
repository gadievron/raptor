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
    'stored-annotationlib': ('import annotationlib\nread_annotations = annotationlib.get_annotations', 'read_annotations(leaf)'),
    'stored-inspect': ('import inspect\nread_annotations = inspect.get_annotations', 'read_annotations(leaf)'),
    'transitive': ('from annotationlib import get_annotations as read\nread_annotations = read', 'read_annotations(leaf)'),
}

class Marker(str):
    pass

@pytest.mark.skipif(sys.version_info < (3, 14), reason='Deferred annotations require Python 3.14')
@pytest.mark.parametrize('kind', list(APIS))
def test_module_evaluator_alias_does_not_forge_clean_path(kind):
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
    ('import annotationlib as annotations\nsaved = annotations.get_annotations\n', {'saved', 'annotations.get_annotations'}),
    ('from inspect import get_annotations as read\nsaved: object = read\n', {'read', 'saved'}),
    ('import inspect\nfirst = second = inspect.get_annotations\nlast = second\n', {'first', 'second', 'last'}),
    ('if flag:\n    from inspect import get_annotations as read\nelse:\n    read = None\nsaved = read\n', {'read', 'saved'}),
    ('from annotationlib import get_annotations as read\nread = None\n', {'read'}),
    ('from .annotationlib import get_annotations as read\nsaved = read\n', set()),
    ('saved = "annotationlib.get_annotations"\n', set()),
    ('saved: object\n', set()),
    ('def make():\n    import inspect\n    saved = inspect.get_annotations\n', set()),
])
def test_negative_alias_candidates_preserve_import_identity_contract(bindings, expected):
    from core.analysis.python_module_callgraph import module_import_map
    source = bindings + '\ndef unrelated(value):\n    return value\n'
    graph = build_python_module_callgraph(source)
    assert graph is not None
    assert graph.annotation_evaluator_aliases == frozenset(expected)
    assert graph.import_map == module_import_map(ast.parse(source))
    summaries = build_taint_summaries(graph, source)
    assert not summaries['unrelated'].summary_unknown


def test_shadowing_an_evaluator_alias_does_not_grant_safety_authority():
    source = ('import annotationlib\nsaved = annotationlib.get_annotations\n'
              'def helper(saved, value):\n    return saved(value)\n')
    graph = build_python_module_callgraph(source)
    assert graph is not None
    assert build_taint_summaries(graph, source)['helper'].summary_unknown
