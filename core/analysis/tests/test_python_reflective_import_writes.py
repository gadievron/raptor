"""Reflective writes to imported objects invalidate callable identity."""

import ast

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.sanitizer_cut import evaluate_finding


def test_setattr_cannot_preserve_replaced_catalogue_identity():
    source = ('import werkzeug\ndef handle(raw,replacement):\n'
              '    setattr(werkzeug.utils,"secure_filename",replacement)\n'
              '    tmp=werkzeug.utils.secure_filename(raw)\n    open(tmp)\n')
    cfg = build_python_cfg(source, "handle")
    assert cfg is not None
    sink = next(node for node in cfg.nodes() if "open" in node.calls)
    assert evaluate_finding(cfg, [cfg.entry], sink, cwe="CWE-22", language="python",
                            source_symbols={"raw"}, sink_arg="tmp").suppress is False
    assert module_dynamic_namespace(ast.parse(source))[0] is True


@pytest.mark.parametrize("source", [
    'import werkzeug as w\nsetattr(w.utils,"secure_filename",replacement)',
    'from werkzeug import utils as tools\ndelattr(tools,"secure_filename")',
    'def handle():\n    import werkzeug as w\n    setattr(w.utils,name,replacement)',
    'def handle():\n    from werkzeug import utils\n    delattr(utils,name)',
])
def test_import_alias_and_nested_import_receiver_writes_refuse(source):
    assert module_dynamic_namespace(ast.parse(source))[0] is True


@pytest.mark.parametrize("source", [
    'def handle(value):\n    setattr(value,"field",replacement)',
    'import werkzeug\ngetattr(werkzeug.utils,"secure_filename")',
    'import werkzeug\ndef handle():\n    value: setattr(werkzeug.utils,"secure_filename",replacement)',
])
def test_unrelated_objects_reads_and_unevaluated_annotations_are_retained(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
