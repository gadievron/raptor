"""Ordinary stores through imported objects invalidate callable identity."""

import ast

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.sanitizer_cut import evaluate_finding


def test_import_alias_attribute_write_cannot_preserve_canonical_call_identity():
    source = ('import werkzeug\nimport werkzeug as w\ndef handle(raw,replacement):\n'
              '    w.utils.secure_filename=replacement\n'
              '    tmp=werkzeug.utils.secure_filename(raw)\n    open(tmp)\n')
    cfg = build_python_cfg(source, "handle")
    assert cfg is not None
    sink = next(node for node in cfg.nodes() if "open" in node.calls)
    assert evaluate_finding(cfg, [cfg.entry], sink, cwe="CWE-22", language="python",
                            source_symbols={"raw"}, sink_arg="tmp").suppress is False
    assert module_dynamic_namespace(ast.parse(source))[0] is True


@pytest.mark.parametrize("source", [
    'import werkzeug\nwerkzeug.utils.secure_filename=replacement',
    'import werkzeug\ndel werkzeug.utils.secure_filename',
    'from werkzeug import utils\nutils.secure_filename+=replacement',
    'import werkzeug\nwerkzeug.__dict__["utils"]=replacement',
    'import werkzeug as w\nw.__dict__["utils"].secure_filename=replacement',
    'import werkzeug\nwerkzeug.utils.secure_filename: object = replacement',
    'def handle():\n    import werkzeug as w\n    w.utils.secure_filename=replacement',
])
def test_direct_imported_receiver_store_forms_are_uncertain(source):
    assert module_dynamic_namespace(ast.parse(source))[0] is True


@pytest.mark.parametrize("source", [
    'import werkzeug\nsaved=werkzeug.utils.secure_filename',
    'def handle(value):\n    value.field=replacement',
    'import werkzeug\ndef handle():\n    werkzeug.utils.secure_filename: annotation_only()',
])
def test_reads_unrelated_objects_and_annotation_only_targets_stay_unpoisoned(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
