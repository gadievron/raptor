"""An outer shared-slot guard cannot survive opaque loop backedges."""
import ast

import pytest

from core.dataflow import smt_barrier as sb


@pytest.fixture(autouse=True)
def native():
    pytest.importorskip("z3")


@pytest.mark.parametrize("case", ["outer-guard", "fresh-guard", "parameter", "snapshot", "linear", "sink-only"])
def test_python_call_backedge_uses_slot_ownership(tmp_path, case):
    prefix = 'import re\nvalue = "abc"\ndef mutate():\n global value\n value = " "\n'
    header = 'def handle(value):' if case == 'parameter' else 'def handle():'
    guard = ' if not re.fullmatch(r"[a-z]+", value): return'
    lines = [*prefix.splitlines(), header]
    if case == 'fresh-guard':
        lines += [' while True:', ' ' + guard]
    else:
        lines.append(guard)
        if case == 'snapshot':
            lines.append(' alias = value')
        if case != 'linear':
            lines.append(' while True:')
    sink = 'alias' if case == 'snapshot' else 'value'
    indent = ' ' if case == 'linear' else '  '
    lines.append(indent + 'consume(' + sink + ')')
    sink_line = len(lines)
    if case != 'sink-only':
        lines.append(indent + 'mutate()')
    text = '\n'.join(lines) + '\n'
    (tmp_path / 'app.py').write_text(text)
    actual_guard = ' ' + guard if case == 'fresh-guard' else guard
    result = sb.try_tier0(fix_diff='+' + actual_guard + '\n', repo_root=tmp_path,
                          sink_uri='app.py', sink_line=sink_line, sink_class='xss')
    expected = sb.Tier0Status.NOT_APPLICABLE if case in {'outer-guard', 'sink-only', 'fresh-guard'} else sb.Tier0Status.SOUND
    assert result.status is expected, result.reasoning
    if case == 'fresh-guard':
        # Preserve the pre-existing public loop-dominance refusal. The new
        # opaque-call branch itself does not expire an in-loop guard.
        assert 'does not dominate' in result.reasoning
        guard_line = lines.index(actual_guard) + 1
        assert not sb._rebound_in_loop_containing_sink(ast.parse(text), 'value', guard_line, sink_line)


@pytest.mark.parametrize("language", ['javascript', 'typescript'])
@pytest.mark.parametrize("case", ["outer-guard", "fresh-guard", "parameter", "snapshot", "linear", "sink-only"])
def test_native_call_backedge_uses_slot_ownership(tmp_path, language, case):
    pytest.importorskip('tree_sitter_javascript' if language == 'javascript' else 'tree_sitter_typescript')
    from core.analysis import validator_control_scope

    lines = ['let value = "abc";', 'let shared = "abc";',
             'function mutate() { value = " "; shared = " "; }',
             'function handle(value) {' if case == 'parameter' else 'function handle() {']
    if case == 'snapshot':
        lines.append(' const value = shared;')
    guard = ' if (!/^[a-z]+$/.test(value)) return;'
    if case == 'fresh-guard':
        lines += [' while (true) {', ' ' + guard]
    else:
        lines.append(guard)
        if case != 'linear':
            lines.append(' while (true) {')
    indent = ' ' if case == 'linear' else '  '
    lines.append(indent + 'consume(value);')
    sink_line = len(lines)
    if case != 'sink-only':
        lines.append(indent + 'mutate();')
    if case != 'linear':
        lines.append(' }')
    lines.append('}')
    text = '\n'.join(lines) + '\n'
    assert validator_control_scope._native_source_tree(text, language) is not None
    name = 'app.js' if language == 'javascript' else 'app.ts'
    (tmp_path / name).write_text(text)
    actual_guard = ' ' + guard if case == 'fresh-guard' else guard
    result = sb.try_tier0(fix_diff='+' + actual_guard + '\n', repo_root=tmp_path,
                          sink_uri=name, sink_line=sink_line, sink_class='xss', language=language)
    expected = sb.Tier0Status.NOT_APPLICABLE if case in {'outer-guard', 'sink-only'} else sb.Tier0Status.SOUND
    assert result.status is expected, result.reasoning
