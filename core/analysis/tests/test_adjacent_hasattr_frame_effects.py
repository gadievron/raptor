"""Fixed owned nested getter frame-effect probe; no external source execution."""
import ast
import html
from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _detect_summary_unknown, build_taint_summaries
SOURCE = 'import sys\nimport html\nobserved = []\nclass Witness:\n    @property\n    def value(self):\n        current = sys._getframe()\n        try:\n            for _ in range(8):\n                if current is None:\n                    break\n                if current.f_code is helper.__code__:\n                    observed.append(current.f_locals["raw"])\n                    return current.f_locals["raw"]\n                current = current.f_back\n            raise AssertionError("owned helper frame not present")\n        finally:\n            del current\nwitness = Witness()\ndef helper(raw):\n    def nested():\n        hasattr(witness, "value")\n        return observed[-1]\n    return nested()\ndef handle(raw):\n    return html.escape(raw) + helper(raw)\n'
class Marker(str):
    pass

def test_adjacent_hasattr_effect_cannot_forge_clean_path():
    assert not any(isinstance(n, ast.Attribute) and n.attr in {"__annotations__", "__annotate__"} for n in ast.walk(ast.parse(SOURCE)))
    graph = build_python_module_callgraph(SOURCE)
    assert graph is not None
    summaries = build_taint_summaries(graph, SOURCE)
    namespace = {"__name__": "owned_nested_getter_fixture"}
    exec(compile(SOURCE, "<owned-nested-getter>", "exec", dont_inherit=True), namespace)
    marker = Marker("<owned-getter-marker>")
    assert namespace["helper"](marker) is marker
    assert str(marker) in namespace["handle"](marker)
    assert html.escape(marker) != marker
    clean = _param_cleanly_sanitized(summaries["handle"], 0, {"html.escape"})
    assert not clean
    assert summaries["helper"].summary_unknown


def test_unused_nested_hasattr_keeps_existing_precision():
    source = ('def helper(value):\n    def nested(obj, field):\n'
              '        return hasattr(obj, field)\n    return value\n')
    assert _detect_summary_unknown(ast.parse(source).body[0]) is None


def test_direct_hasattr_reason_keeps_priority():
    source = 'def helper(value):\n    return hasattr(value, "field")\n'
    assert _detect_summary_unknown(ast.parse(source).body[0]) == 'calls hasattr'


def test_false_hasattr_can_still_retain_the_owned_marker():
    source = SOURCE.replace('return current.f_locals["raw"]', 'raise AttributeError("owned absent value")')
    graph = build_python_module_callgraph(source)
    assert graph is not None
    summaries = build_taint_summaries(graph, source)
    namespace = {'__name__': 'owned_false_hasattr_fixture'}
    exec(compile(source, '<owned-false-hasattr>', 'exec', dont_inherit=True), namespace)
    marker = Marker('<owned-false-hasattr-marker>')
    assert namespace['helper'](marker) is marker
    assert str(marker) in namespace['handle'](marker)
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})
    assert summaries['helper'].summary_unknown
