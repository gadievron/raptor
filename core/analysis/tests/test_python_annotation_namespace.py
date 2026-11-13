"""Unevaluated local annotations cannot mutate module namespaces."""

import ast

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.sanitizer_cut import evaluate_finding


def namespace(source):
    return module_dynamic_namespace(ast.parse(source))


def test_local_annotation_does_not_poison_the_module_namespace():
    source = ('import werkzeug\ndef handle(raw):\n'
              '    tmp: globals()\n'
              '    tmp=werkzeug.utils.secure_filename(raw)\n'
              '    open(tmp)\n')
    assert namespace(source) == (False, frozenset())
    cfg = build_python_cfg(source, "handle")
    assert cfg is not None
    assert cfg.namespace_unprovable is False
    sink = next(node for node in cfg.nodes() if "open" in node.calls)
    assert evaluate_finding(cfg, [cfg.entry], sink, cwe="CWE-22", language="python",
                            source_symbols={"raw"}, sink_arg="tmp").suppress is True


@pytest.mark.parametrize("annotation", [
    '__builtins__', 'exec("werkzeug=replacement",globals())',
    'tuple[str, globals()]', 'sys.modules',
])
def test_local_annotation_namespace_spellings_are_not_exposures(annotation):
    source = 'import sys\ndef handle():\n    value: ' + annotation + '\n'
    assert namespace(source) == (False, frozenset())


def test_nested_method_annotation_is_still_local():
    assert namespace('class C:\n    def method(self):\n        value: globals()\n') == (False, frozenset())


def test_rhs_namespace_access_still_poisons():
    assert namespace('def handle():\n    value: str = globals()\n')[0] is True


def test_target_namespace_access_is_not_skipped():
    assert namespace('def handle():\n    globals()["werkzeug"]: str\n')[1] == frozenset({"werkzeug"})


@pytest.mark.parametrize("source", [
    'value: globals()\n',
    'class C:\n    value: globals()\n',
    'def outer():\n    class C:\n        value: globals()\n',
])
def test_module_and_class_annotation_behavior_is_retained(source):
    assert namespace(source)[0] is True


def test_async_function_annotation_is_also_unevaluated():
    assert namespace('async def handle():\n    value: globals()\n') == (False, frozenset())
