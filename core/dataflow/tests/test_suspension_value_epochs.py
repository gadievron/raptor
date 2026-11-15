"""Suspension does not freeze global or enclosing-function name slots."""
import ast

import pytest

from core.dataflow import smt_barrier as sb

GUARD = ' if not re.fullmatch(r"[a-z]+", value): return'


@pytest.fixture(autouse=True)
def native():
    pytest.importorskip("z3")


def query(tmp_path, lines, sink="value"):
    header = 'def handle():' if any('yield from' in line for line in lines) else 'async def handle():'
    text = '\n'.join(['import re', 'value = "abc"', header, *lines,
                      ' consume(' + sink + ')']) + '\n'
    (tmp_path / "app.py").write_text(text)
    return sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
                       sink_uri="app.py", sink_line=len(text.splitlines()), sink_class="xss")


@pytest.mark.parametrize("suspension", [
    ' await checkpoint()', ' yield None', ' yield from checkpoint()',
    ' async for other in stream:\n  pass', ' async with context:\n  pass',
    ' other = [item async for item in stream]',
], ids=["await", "yield", "yield-from", "async-for", "async-with", "async-comprehension"])
@pytest.mark.parametrize("declaration", [[], [' global value']], ids=["implicit-global", "declared-global"])
def test_external_name_epoch_ends_at_suspension(tmp_path, suspension, declaration):
    result = query(tmp_path, [*declaration, GUARD, *suspension.splitlines()])
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert result.artifact is None


@pytest.mark.parametrize("capture_before", [False, True], ids=["late-alias", "captured-alias"])
def test_local_alias_is_a_snapshot_not_a_later_global_lookup(tmp_path, capture_before):
    lines = [GUARD]
    if capture_before:
        lines.append(' alias = value')
    lines.append(' await checkpoint()')
    if not capture_before:
        lines.append(' alias = value')
    result = query(tmp_path, lines, sink="alias")
    assert result.status is (sb.Tier0Status.SOUND if capture_before else sb.Tier0Status.NOT_APPLICABLE), result.reasoning


def test_local_value_slot_survives_suspension(tmp_path):
    result = query(tmp_path, [' value = "abc"', GUARD, ' await checkpoint()'])
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


def test_local_parameter_survives_suspension():
    text = 'async def handle(value):\n' + GUARD + '\n await checkpoint()\n consume(value)\n'
    assert sb._python_chain_reaches_sink(ast.parse(text), "value", 2, 4, ' consume(value)')


@pytest.mark.parametrize("middle", [' await checkpoint()', ' yield None'])
def test_substitution_dominance_also_loses_external_epoch(middle):
    text = 'import re\nasync def handle():\n global value\n value = re.sub(r"[ ]+", "", value)\n' + middle + '\n consume(value)\n'
    assert not sb.substitution_dominates_sink(text, 4, 6, "value")
    assert sb.substitution_dominates_sink(text.replace(' global value\n', ' value = "abc"\n'), 4, 6, "value")


def test_nested_suspension_body_is_not_executed_inline(tmp_path):
    result = query(tmp_path, [GUARD, ' async def later():', '  await checkpoint()'])
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


def test_nonlocal_slot_is_not_owned_by_the_suspended_function():
    text = ('def outer():\n value = "abc"\n async def handle():\n  nonlocal value\n'
            '  if not re.fullmatch(r"[a-z]+", value): return\n  await checkpoint()\n  consume(value)\n')
    assert not sb._python_chain_reaches_sink(ast.parse(text), "value", 5, 7, '  consume(value)')


def test_function_default_binding_does_not_create_a_local_slot():
    text = 'async def handle(arg=(value := "abc")):\n' + GUARD + '\n await checkpoint()\n consume(value)\n'
    assert not sb._python_chain_reaches_sink(ast.parse(text), "value", 2, 4, ' consume(value)')


def test_validation_after_suspension_starts_a_new_external_epoch(tmp_path):
    result = query(tmp_path, [' await checkpoint()', GUARD])
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


def test_definition_name_release_external_slot(tmp_path):
    import platform

    if platform.python_implementation() != "CPython":
        pytest.skip("owned last-reference timing control requires CPython")
    guard = '    if not re.fullmatch(r"[a-z]+", safe): return'
    for shared, asynchronous, external_target in (
        (shared, asynchronous, external_target)
        for shared in (False, True) for asynchronous in (False, True)
        for external_target in (False, True)
    ):
        definition = "    async def trigger(): pass" if asynchronous else "    def trigger(): pass"
        source = ("import re\nsafe = 'abc'\nclass Trigger:\n    def __del__(self):\n        global safe\n        safe = '<raw marker>'\n        events.append('finalized')\n"
                  + ("trigger = Trigger()\n" if external_target else "")
                  + "def process():\n"
                  + ("    global safe\n" if shared else "    safe = 'abc'\n")
                  + ("    global trigger\n" if external_target else "    trigger = Trigger()\n") + guard + "\n" + definition + "\n    sink(safe)\n")
        seen, events = [], []
        namespace = {"sink": seen.append, "events": events}
        exec(compile(source, "owned-definition.py", "exec"), namespace)
        namespace["process"]()
        assert events == ["finalized"]
        assert seen == (["<raw marker>"] if shared else ["abc"])
        (tmp_path / "app.py").write_text(source)
        result = sb.try_tier0(fix_diff="+" + guard + "\n", repo_root=tmp_path,
                              sink_uri="app.py", sink_line=len(source.splitlines()), sink_class="xss")
        assert result.status is (sb.Tier0Status.NOT_APPLICABLE if shared else sb.Tier0Status.SOUND), (shared, seen, events, result)


def test_exception_target_release_external_slot(tmp_path):
    import platform

    if platform.python_implementation() != "CPython":
        pytest.skip("owned last-reference timing control requires CPython")
    guard = '    if not re.fullmatch(r"[a-z]+", safe): return'
    for shared, capture, grouped in (
        (shared, capture, grouped) for shared in (False, True)
        for capture in ("direct", "before", "after") for grouped in (False, True)
    ):
        handler = "except* NameError" if grouped else "except NameError"
        source = ("import re\nsafe = 'abc'\nclass Trigger:\n    def __del__(self):\n        global safe\n        safe = '<raw marker>'\n        events.append('finalized')\ndef process():\n"
                  + ("    global safe\n" if shared else "    safe = 'abc'\n")
                  + "    trigger = Trigger()\n" + guard
                  + ("\n    alias = safe" if capture == "before" else "")
                  + "\n    try:\n        owned_missing_name\n    " + handler + " as trigger:\n        pass\n"
                  + ("    alias = safe\n" if capture == "after" else "")
                  + "    sink(" + ("safe" if capture == "direct" else "alias") + ")\n")
        seen, events = [], []
        namespace = {"sink": seen.append, "events": events}
        exec(compile(source, "owned-exception-target.py", "exec"), namespace)
        namespace["process"]()
        assert events == ["finalized"]
        assert seen == (["<raw marker>"] if shared and capture != "before" else ["abc"])
        (tmp_path / "app.py").write_text(source)
        result = sb.try_tier0(fix_diff="+" + guard + "\n", repo_root=tmp_path,
                              sink_uri="app.py", sink_line=len(source.splitlines()), sink_class="xss")
        assert result.status is (sb.Tier0Status.NOT_APPLICABLE if shared and capture != "before" else sb.Tier0Status.SOUND), (shared, seen, events, result)


def test_identity_capture_release_external_slot(tmp_path):
    import platform

    if platform.python_implementation() != "CPython":
        pytest.skip("owned last-reference timing control requires CPython")
    guard = '    if not re.fullmatch(r"[a-z]+", safe): return'
    for shared, capture, inline in (
        (shared, capture, inline) for shared in (False, True)
        for capture in ("direct", "before", "after") for inline in (False, True)
        if not (capture == "after" and inline)
    ):
        target = "safe" if capture == "direct" else "alias"
        source = ("import re\nsafe = 'abc'\nclass Trigger:\n    def __del__(self):\n        global safe\n        safe = '<raw marker>'\n        events.append('finalized')\ndef process():\n"
                  + ("    global safe\n" if shared else "    safe = 'abc'\n")
                  + "    trigger = Trigger()\n" + guard + "\n"
                  + ("    alias = safe\n" if capture == "before" else "")
                  + "    match None:\n")
        if inline:
            source += "        case trigger: sink(" + target + ")\n"
        else:
            source += ("        case trigger:\n            pass\n"
                       + ("    alias = safe\n" if capture == "after" else "")
                       + "    sink(" + target + ")\n")
        seen, events = [], []
        namespace = {"sink": seen.append, "events": events}
        exec(compile(source, "owned-capture-target.py", "exec"), namespace)
        namespace["process"]()
        assert events == ["finalized"]
        unsafe = shared and capture != "before"
        assert seen == (["<raw marker>"] if unsafe else ["abc"])
        (tmp_path / "app.py").write_text(source)
        result = sb.try_tier0(fix_diff="+" + guard + "\n", repo_root=tmp_path,
                              sink_uri="app.py", sink_line=len(source.splitlines()), sink_class="xss")
        assert result.status is (sb.Tier0Status.NOT_APPLICABLE if unsafe else sb.Tier0Status.SOUND), (shared, capture, inline, result)
