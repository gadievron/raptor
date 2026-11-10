"""A validator outside a native loop cannot certify a later value epoch."""

import pytest

from core.analysis.validator_control_scope import _native_source_tree
from core.dataflow import smt_barrier as sb

GUARD = " if (!/^[a-z]+$/.test(value)) return;"


def check(tmp_path, lines):
    pytest.importorskip("z3")
    pytest.importorskip("tree_sitter_javascript")
    text = "\n".join(lines) + "\n"
    assert _native_source_tree(text, "javascript") is not None
    (tmp_path / "app.js").write_text(text)
    return sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                        sink_uri="app.js", sink_line=lines.index(" consume(value);") + 1,
                        sink_class="xss", language="javascript")


@pytest.mark.parametrize("write", [" value = ' ';", " [value] = [' '];", r" val\u0075e = ' ';"],
                         ids=["bare-name", "pattern", "escaped-name"])
def test_loop_backedge_cannot_reuse_an_outer_guard(tmp_path, write):
    result = check(tmp_path, ["function handle() {", " var value = 'abc';", GUARD,
                              " for (let i=0; i<2; i++) {", " consume(value);", write, " }", "}"])
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert result.artifact is None


@pytest.mark.parametrize("refresh", [False, True], ids=["unrelated-write", "fresh-inner-guard"])
def test_unrelated_backedge_and_refreshed_guard_remain_eligible(tmp_path, refresh):
    lines = ["function handle() {", " var value = 'abc';", " var other = 'abc';"]
    if not refresh:
        lines.append(GUARD)
    lines.append(" for (let i=0; i<2; i++) {")
    if refresh:
        lines.append(GUARD)
    lines += [" consume(value);", " value = ' ';" if refresh else " other = ' ';", " }", "}"]
    result = check(tmp_path, lines)
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


@pytest.mark.parametrize("refresh", [False, True], ids=["outer-guard", "fresh-inner-guard"])
def test_java_backedge_respects_guard_refresh(tmp_path, refresh):
    pytest.importorskip("z3")
    pytest.importorskip("tree_sitter_java")
    guard = ' if (!value.matches("[a-z]+")) return;'
    lines = ["class App {", " void handle() {", ' String value = "abc";']
    if not refresh:
        lines.append(guard)
    lines.append(" for (int i=0; i<2; i++) {")
    if refresh:
        lines.append(guard)
    lines += [" consume(value);", ' value = " ";', " }", " }", "}"]
    text = "\n".join(lines) + "\n"
    assert _native_source_tree(text, "java") is not None
    (tmp_path / "App.java").write_text(text)
    result = sb.try_tier0(fix_diff="+" + guard + "\n", repo_root=tmp_path,
                         sink_uri="App.java", sink_line=lines.index(" consume(value);") + 1,
                         sink_class="xss", language="java")
    expected = sb.Tier0Status.SOUND if refresh else sb.Tier0Status.NOT_APPLICABLE
    assert result.status is expected, result.reasoning
