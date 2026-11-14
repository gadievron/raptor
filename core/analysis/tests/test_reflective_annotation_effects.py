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
    'metadata-getter': ('', 'getattr(leaf, "__annotations__")'),
    'callable-getter': ('import annotationlib', 'getattr(leaf, "__annotate__")(annotationlib.Format.VALUE)'),
}

class Marker(str):
    pass

@pytest.mark.skipif(sys.version_info < (3, 14), reason='Deferred annotations require Python 3.14')
@pytest.mark.parametrize('kind', list(APIS))
def test_literal_reflective_metadata_does_not_forge_clean_path(kind):
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


@pytest.mark.parametrize('expression,unknown', [
    ('getattr(value, "__annotations__")', True),
    ('getattr(value, "__annotate__", None)', True),
    ('getattr(value, "__annotations__", *defaults)', True),
    ('getattr(*value, "__annotations__")', False),
    ('getattr(value, field)', False),
    ('getattr(value, "other")', False),
    ('{"__annotations__": "getattr"}', False),
])
def test_only_stable_literal_metadata_getters_poison_enclosing_summary(expression, unknown):
    # This pins the metadata guard, not safety of arbitrary reflective calls.
    source = ('def helper():\n    def nested(value, field, defaults):\n        '
              + expression + '\n        return 0\n    return 0\n')
    reason = _detect_summary_unknown(ast.parse(source).body[0])
    assert (reason is not None) is unknown


def test_shadowed_getter_is_not_granted_trusted_identity():
    source = ('def helper(getattr):\n    def nested(value):\n'
              '        getattr(value, "__annotations__")\n        return 0\n    return 0\n')
    assert _detect_summary_unknown(ast.parse(source).body[0]) is not None


def test_existing_direct_getter_reason_keeps_priority():
    source = 'def helper(value):\n    return getattr(value, "__annotations__")\n'
    assert _detect_summary_unknown(ast.parse(source).body[0]) == 'calls getattr'
