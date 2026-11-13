"""Importlib loader exposure invalidates shared callable namespace identity."""

import ast

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.sanitizer_cut import evaluate_finding


def test_importlib_mutation_cannot_preserve_catalog_callable_identity():
    source = ('import werkzeug.utils\nimport importlib as loader\ndef handle(raw,replacement):\n'
              '    loader.import_module("werkzeug").utils.secure_filename=replacement\n'
              '    tmp=werkzeug.utils.secure_filename(raw)\n    open(tmp)\n')
    cfg = build_python_cfg(source, 'handle')
    assert cfg is not None
    sink = next(node for node in cfg.nodes() if 'open' in node.calls)
    assert evaluate_finding(cfg, [cfg.entry], sink, cwe='CWE-22', language='python',
                            source_symbols={'raw'}, sink_arg='tmp').suppress is False
    assert module_dynamic_namespace(ast.parse(source))[0] is True


@pytest.mark.parametrize('source', [
    'import importlib\nimportlib.import_module("module")',
    'from importlib import import_module as load\nsaved=load',
    'from importlib import reload as refresh\nrefresh(module)',
    'def handle():\n    import importlib as loader\n    loader.import_module("module")',
    'def handle():\n    from importlib import import_module as load\n    load("module")',
    'import importlib.util as util\nsaved=util',
    'from importlib.util import find_spec\nfind_spec("module")',
])
def test_loader_and_module_alias_exposures_remove_namespace_trust(source):
    assert module_dynamic_namespace(ast.parse(source))[0] is True


@pytest.mark.parametrize('source', [
    'import importlib',
    'from importlib import import_module as load',
    'import importlib_metadata\nimportlib_metadata.version("package")',
    'from .importlib import import_module as load\nload("module")',
    'text="importlib.import_module"',
    'import importlib\ndef handle():\n    value: importlib.import_module("module")',
])
def test_unused_imports_unrelated_names_and_inert_annotations_keep_existing_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
