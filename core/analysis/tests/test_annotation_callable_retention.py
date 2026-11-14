"""Fixed owned SDK annotation API probe; no external source execution."""
import ast
import html
import sys
import pytest
from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _detect_summary_unknown, build_taint_summaries
TEMPLATE = 'import sys\nimport html\nobserved = []\nclass Witness:\n    @property\n    def value(self):\n        current = sys._getframe()\n        try:\n            for _ in range(8):\n                if current is None:\n                    break\n                if current.f_code is helper.__code__:\n                    observed.append("owned-helper")\n                    return current.f_locals["raw"]\n                current = current.f_back\n            raise AssertionError("owned helper frame not present")\n        finally:\n            del current\nwitness = Witness()\ndef helper(raw):\n    def nested():\n        def leaf(value: ANNOTATION):\n            return 0\n        FORCE_LINE\n        return leaf\n    return nested()\ndef handle(raw):\n    return html.escape(raw) + helper(raw).__annotations__["value"]\n'
APIS = {
    'lambda-default': ('import annotationlib', '(lambda read=annotationlib.get_annotations: read(leaf))()'),
    'bare-default': ('from inspect import get_annotations as read_annotations', '(lambda read=read_annotations: read(leaf))()'),
}

class Marker(str):
    pass

@pytest.mark.skipif(sys.version_info < (3, 14), reason='Deferred annotations require Python 3.14')
@pytest.mark.parametrize('kind', list(APIS))
def test_retained_annotation_callable_does_not_forge_clean_path(kind):
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


@pytest.mark.parametrize('statement', ['saved = annotationlib.get_annotations',
                                     'return annotationlib.get_annotations'])
def test_benign_callable_acquisition_is_conservatively_unknown(statement):
    source = 'import annotationlib\ndef helper(value):\n    ' + statement + '\n'
    graph = build_python_module_callgraph(source)
    assert graph is not None
    assert build_taint_summaries(graph, source)['helper'].summary_unknown


@pytest.mark.parametrize('statement', ['annotationlib.get_annotations = None',
                                     'del annotationlib.get_annotations'])
def test_store_and_delete_are_not_callable_acquisition(statement):
    # This pins only the acquisition guard, not arbitrary setter safety.
    source = 'import annotationlib\ndef helper(value):\n    ' + statement + '\n'
    graph = build_python_module_callgraph(source)
    assert graph is not None
    assert _detect_summary_unknown(ast.parse(source).body[1], {'annotationlib': 'annotationlib'}) is None
    # The independent module-namespace mutation guard must still refuse.
    assert build_taint_summaries(graph, source)['helper'].summary_unknown


def test_nested_assignment_alias_poison_enclosing_helper():
    source = ('import annotationlib\ndef helper(value):\n'
              '    def nested():\n        read = annotationlib.get_annotations\n'
              '        return read(value)\n    return nested()\n')
    graph = build_python_module_callgraph(source)
    assert graph is not None
    assert build_taint_summaries(graph, source)['helper'].summary_unknown
