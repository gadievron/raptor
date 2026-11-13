"""Dictionary mutations of namespace lookup values lose callable trust."""

import ast

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.python_module_callgraph import module_dynamic_namespace
from core.analysis.sanitizer_cut import evaluate_finding


def test_lookup_namespace_dictionary_update_cannot_preserve_callable_identity():
    source = ('import werkzeug\ndef handle(raw,replacement):\n'
              '    globals()["werkzeug"].utils.__dict__.update({"secure_filename":replacement})\n'
              '    tmp=werkzeug.utils.secure_filename(raw)\n    open(tmp)\n')
    cfg = build_python_cfg(source, "handle")
    assert cfg is not None
    sink = next(node for node in cfg.nodes() if "open" in node.calls)
    assert evaluate_finding(cfg, [cfg.entry], sink, cwe="CWE-22", language="python",
                            source_symbols={"raw"}, sink_arg="tmp").suppress is False
    assert module_dynamic_namespace(ast.parse(source)) == (False, frozenset({"werkzeug"}))


@pytest.mark.parametrize("source,expected", [
    ('globals()["root"].__dict__.clear()', (False, frozenset({"root"}))),
    ('vars()["root"].items[0].__dict__.pop("field")', (False, frozenset({"root"}))),
    ('locals()["root"].__dict__.setdefault("field",replacement)', (False, frozenset({"root"}))),
    ('globals()[key].__dict__.update(replacement)', (True, frozenset())),
    ('vars(obj)["root"].__dict__.update(replacement)', (True, frozenset())),
    ('other[globals()["root"]].__dict__.update(replacement)', (False, frozenset())),
    ('factory(globals()["root"]).__dict__.update(replacement)', (False, frozenset())),
    ('globals()["root"].__dict__.copy()', (False, frozenset())),
    ('globals()["root"].__dict__.get("field")', (False, frozenset())),
    ('globals()["root"].update(replacement)', (False, frozenset())),
    ('def handle():\n    locals()["root"].__dict__.update(replacement)', (False, frozenset())),
    ('def handle():\n    value: globals()["root"].__dict__.clear()', (False, frozenset())),
])
def test_lookup_dictionary_receiver_and_scope_limits(source, expected):
    assert module_dynamic_namespace(ast.parse(source)) == expected
