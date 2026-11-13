"""Direct dictionary mutation of imported namespaces invalidates identity."""

import ast

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.sanitizer_cut import evaluate_finding


def test_imported_namespace_dict_update_cannot_preserve_callable_identity():
    source = ('import werkzeug\nimport werkzeug as w\ndef handle(raw,replacement):\n'
              '    w.utils.__dict__.update({"secure_filename":replacement})\n'
              '    tmp=werkzeug.utils.secure_filename(raw)\n    open(tmp)\n')
    cfg = build_python_cfg(source, "handle")
    assert cfg is not None
    sink = next(node for node in cfg.nodes() if "open" in node.calls)
    assert evaluate_finding(cfg, [cfg.entry], sink, cwe="CWE-22", language="python",
                            source_symbols={"raw"}, sink_arg="tmp").suppress is False
    assert module_dynamic_namespace(ast.parse(source))[0] is True


@pytest.mark.parametrize("statement", [
    'w.utils.__dict__.update({"secure_filename":replacement})',
    'w.utils.__dict__.clear()',
    'w.utils.__dict__.pop("secure_filename")',
    'w.utils.__dict__.popitem()',
    'w.utils.__dict__.setdefault("secure_filename",replacement)',
    'w.utils.__dict__.__setitem__("secure_filename",replacement)',
    'w.utils.__dict__.__delitem__("secure_filename")',
    'w.__dict__["utils"].__dict__.update(replacement)',
])
def test_imported_dictionary_mutator_forms_are_uncertain(statement):
    assert module_dynamic_namespace(ast.parse('import werkzeug as w\n' + statement))[0] is True


def test_local_import_dictionary_update_is_uncertain():
    source = ('def handle(replacement):\n    import werkzeug as w\n'
              '    w.utils.__dict__.update(replacement)')
    assert module_dynamic_namespace(ast.parse(source))[0] is True


@pytest.mark.parametrize("source", [
    'import werkzeug as w\nsaved=w.utils.__dict__',
    'import werkzeug as w\nw.utils.__dict__.get("secure_filename")',
    'import werkzeug as w\nw.utils.__dict__.copy()',
    'import werkzeug as w\nother[w].__dict__.update(replacement)',
    'import werkzeug as w\nw.utils.update(replacement)',
    'def handle(value):\n    value.__dict__.update(replacement)',
    'import werkzeug as w\ndef handle():\n    value: w.__dict__.clear()',
])
def test_dictionary_reads_unrelated_receivers_and_annotations_keep_existing_behavior(source):
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset())
