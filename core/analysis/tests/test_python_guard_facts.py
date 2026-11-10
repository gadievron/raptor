"""Python guard evidence follows selected boolean branches, not labels."""
import pytest

from core.analysis.cfg_builder import build_python_cfg
from core.analysis.dominators import build_dom_tree
from core.analysis.lifecycle_collector import GuardEpochUnavailable, collect_guards_at_site


def _guards(source, marker="consume()"):
    cfg = build_python_cfg(source, "handle")
    assert cfg is not None
    line = next(i for i, text in enumerate(source.splitlines(), 1) if marker in text)
    return collect_guards_at_site(cfg, build_dom_tree(cfg), line, "owned.py")


def test_reconverged_python_condition_is_not_a_later_guard():
    source = "def handle(count, flag):\n    if count < 4:\n        record()\n    if flag:\n        consume()\n"
    assert {guard.condition for guard in _guards(source)} == {"flag"}


def test_python_false_arm_keeps_polarity():
    source = "def handle(flag):\n    if flag:\n        return\n    consume()\n"
    guard, = _guards(source)
    assert (guard.condition, guard.polarity) == ("flag", False)


def test_python_value_rebinding_cannot_preserve_a_guard():
    source = "def handle(count, raw):\n    if count < 4:\n        count = raw\n        consume()\n"
    with pytest.raises(GuardEpochUnavailable):
        _guards(source)


def test_for_iteration_is_not_a_boolean_membership_test():
    source = "def handle(values):\n    for value in values:\n        consume()\n"
    assert not _guards(source)


def test_while_break_does_not_establish_false_exit_premise():
    source = "def handle(flag):\n    while flag:\n        if ready:\n            break\n    consume()\n"
    assert not _guards(source)


def test_while_else_requires_false_exit():
    source = "def handle(flag):\n    while flag:\n        if ready:\n            break\n    else:\n        consume()\n"
    guard, = _guards(source)
    assert (guard.condition, guard.polarity) == ("flag", False)


def test_python_condition_keeps_literal_case_spacing_and_utf8_offsets():
    source = 'def handle(role):\n    note = "π"; marker = "x"\n    if role == "A  B":\n        consume()\n'
    guard, = _guards(source)
    assert guard.condition == 'role == "A  B"'


def test_direct_ast_builder_retains_full_condition_facts():
    import ast
    from core.analysis.cfg_builder import _PythonCFGBuilder

    source = "def handle(flag):\n    if flag:\n        consume()\n"
    cfg = _PythonCFGBuilder("handle", "owned.py").build(ast.parse(source).body[0])
    guard, = collect_guards_at_site(cfg, build_dom_tree(cfg), 3, "owned.py")
    assert (guard.condition, guard.polarity) == ("flag", True)


def test_multiline_unicode_condition_uses_exact_source_span():
    source = 'def handle(role, ready):\n    if (\n        role == "π  Ω"\n        and ready\n    ):\n        consume()\n'
    guard, = _guards(source)
    assert guard.condition == 'role == "π  Ω"\n        and ready'


def test_long_python_condition_is_not_the_display_label():
    name = "long_flag_" + "x" * 150
    source = f"def handle({name}):\n    if {name}:\n        consume()\n"
    guard, = _guards(source)
    assert guard.condition == name


def test_synthetic_branch_identities_are_unique():
    source = "def handle(left, right):\n    if left:\n        pass\n    if right:\n        consume()\n"
    cfg = build_python_cfg(source, "handle")
    assert cfg is not None
    branches = [node for node in cfg.nodes() if node.kind == "branch"]
    assert len(branches) == len(set(branches)) == 4
    assert all(node.lineno < 0 and not node.calls and not node.defs and not node.uses for node in branches)
