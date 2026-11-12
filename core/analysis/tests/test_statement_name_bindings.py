"""String-named Python statements bind locals without Name(Store) children."""

import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.dataflow import reaching_defs


def build(statement):
    indented = statement.replace("\n", "\n    ")
    source = f"def handle(raw):\n    tmp = raw\n    {indented}\n    consume(tmp)\n"
    cfg = build_python_cfg(source, "handle")
    assert cfg is not None
    statements = [node for node in cfg.nodes() if node.kind == "stmt"]
    binding = next(node for node in statements if node.lineno == 3)
    use = next(node for node in statements if "consume" in node.calls)
    original = next(node for node in statements if node.lineno == 2)
    return cfg, binding, use, original


def test_nested_function_definition_rebinds_its_name_in_the_enclosing_frame():
    cfg, binding, use, _original = build("def tmp():\n    return raw")
    assert binding.defs == frozenset({"tmp"})
    assert reaching_defs(cfg).at(use, "tmp") == frozenset({binding})
    assert not binding.calls and not binding.call_sites


@pytest.mark.parametrize("statement,expected", [
    ("async def tmp():\n    return raw", {"tmp"}),
    ("class tmp:\n    pass", {"tmp"}),
    ("import pkg as tmp", {"tmp"}),
    ("import tmp.part", {"tmp"}),
    ("from pkg import value as tmp", {"tmp"}),
    ("from pkg import tmp", {"tmp"}),
    ("import first as tmp, second as other", {"tmp", "other"}),
    ("from pkg import first as tmp, second as other", {"tmp", "other"}),
], ids=["async-definition", "class", "import-alias", "import-root", "from-alias", "from-name",
        "multiple-import", "multiple-from"])
def test_other_string_named_bindings_replace_the_prior_local(statement, expected):
    cfg, binding, use, _original = build(statement)
    assert binding.defs == frozenset(expected)
    assert reaching_defs(cfg).at(use, "tmp") == frozenset({binding})
    assert not binding.calls and not binding.call_sites


@pytest.mark.parametrize("statement,name", [
    ("def helper():\n    tmp = raw", "helper"),
    ("class Wrapper:\n    tmp = raw", "Wrapper"),
    ("import pkg.part", "pkg"),
    ("from pkg import other", "other"),
])
def test_other_bindings_do_not_kill_the_local_or_leak_nested_names(statement, name):
    cfg, binding, use, original = build(statement)
    assert binding.defs == frozenset({name})
    assert reaching_defs(cfg).at(use, "tmp") == frozenset({original})


def test_definition_default_calls_do_not_gain_output_assignment_identity():
    _cfg, binding, _use, _original = build("def tmp(value=prepare(raw)):\n    return value")
    assert binding.defs == frozenset({"tmp"})
    assert binding.calls == frozenset({"prepare"})
    assert all(not site.assigned_names for site in binding.call_sites)


def test_definition_rebinding_removes_the_stale_sanitizer_value_binding():
    from core.analysis.sanitizer_cut import evaluate_finding

    source = (
        "import html\ndef handle(raw):\n    tmp = html.escape(raw)\n"
        "    def tmp():\n        return raw\n    render(tmp)\n"
    )
    cfg = build_python_cfg(source, "handle")
    assert cfg is not None
    sink = next(node for node in cfg.nodes() if "render" in node.calls)
    result = evaluate_finding(cfg, [cfg.entry], sink, cwe="CWE-79", language="python",
                              source_symbols={"raw"}, sink_arg="tmp")
    assert result.all_matched_bindings
    assert not result.value_bound_bindings
    assert result.suppress is False
