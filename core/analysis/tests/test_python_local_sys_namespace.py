"""Function-local sys.modules aliases expose the same mutable namespace."""

import ast

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.sanitizer_cut import evaluate_finding


def source_for(import_line, access):
    return ('import werkzeug\ndef handle(raw, replacement):\n    ' + import_line + '\n    '
            + access + '[__name__].werkzeug=replacement\n'
            '    tmp=werkzeug.utils.secure_filename(raw)\n    open(tmp)\n')


def test_local_sys_alias_cannot_preserve_a_replaced_catalogue_identity():
    source = source_for('import sys as local_sys', 'local_sys.modules')
    assert module_dynamic_namespace(ast.parse(source))[0] is True
    cfg = build_python_cfg(source, "handle")
    assert cfg is not None
    sink = next(node for node in cfg.nodes() if "open" in node.calls)
    assert evaluate_finding(cfg, [cfg.entry], sink, cwe="CWE-22", language="python",
                            source_symbols={"raw"}, sink_arg="tmp").suppress is False


@pytest.mark.parametrize("import_line,access", [
    ('import sys', 'sys.modules'),
    ('from sys import modules', 'modules'),
    ('from sys import modules as registry', 'registry'),
])
def test_local_namespace_import_spellings_are_conservatively_exposed(import_line, access):
    assert module_dynamic_namespace(ast.parse(source_for(import_line, access)))[0] is True


def test_local_sys_import_without_module_namespace_access_does_not_poison():
    source = 'def handle():\n    import sys as local_sys\n    return local_sys.version\n'
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())


def test_unrelated_module_with_modules_attribute_is_not_sys_by_spelling():
    source = 'def handle(local_sys):\n    return local_sys.modules\n'
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())


def test_local_annotation_namespace_reference_remains_unevaluated():
    source = 'def handle():\n    import sys as local_sys\n    value: local_sys.modules\n'
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
