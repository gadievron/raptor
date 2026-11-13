"""Dynamic import exposes process-wide modules outside ordinary import roots."""

import ast

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.sanitizer_cut import evaluate_finding


def test_dynamic_import_mutation_cannot_preserve_catalog_callable_identity():
    source = ('import werkzeug.utils\ndef handle(raw,replacement):\n'
              '    __import__("werkzeug").utils.secure_filename=replacement\n'
              '    tmp=werkzeug.utils.secure_filename(raw)\n    open(tmp)\n')
    cfg = build_python_cfg(source, 'handle')
    assert cfg is not None
    sink = next(node for node in cfg.nodes() if 'open' in node.calls)
    assert evaluate_finding(cfg, [cfg.entry], sink, cwe='CWE-22', language='python',
                            source_symbols={'raw'}, sink_arg='tmp').suppress is False
    assert module_dynamic_namespace(ast.parse(source))[0] is True


@pytest.mark.parametrize('source', [
    '__import__("module")',
    'saved=__import__',
    'from builtins import __import__ as load\nsaved=load',
    'def handle():\n    from builtins import __import__ as load\n    load("module")',
])
def test_dynamic_import_callable_exposure_loses_namespace_trust(source):
    assert module_dynamic_namespace(ast.parse(source))[0] is True


@pytest.mark.parametrize('source', [
    'import werkzeug.utils',
    'from builtins import len as size\nsize("value")',
    'from builtins import __import__ as load',
    'text="__import__"',
    'def handle():\n    value: __import__("module")',
])
def test_ordinary_imports_unrelated_builtins_and_inert_annotations_are_retained(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
