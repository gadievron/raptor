"""Composite native write targets cannot retain an earlier validator epoch."""

import json

import pytest

from core.analysis import validator_control_scope as syntax
from core.dataflow import injection_prescreen, smt_barrier as sb, tier1_llm

GUARD = " if (!/^[a-z]+$/.test(value)) return;"


@pytest.mark.parametrize("change", [
    r"val\u0075e = ' ';",
    r"val\u{75}e = ' ';",
    r"[val\u0075e] = values;",
    r"var val\u0075e = ' ';",
], ids=["escaped-name", "codepoint-name", "escaped-pattern", "escaped-declaration"])
def test_escaped_write_targets_cannot_preserve_an_epoch(native, tmp_path, change):
    text = source(change)
    (tmp_path / "app.js").write_text(text)
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                         sink_uri="app.js", sink_line=8, sink_class="xss", language="javascript")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert result.artifact is None


@pytest.fixture
def native():
    pytest.importorskip("z3")
    pytest.importorskip("tree_sitter_javascript")


def source(change, initial="'abc'"):
    text = ("function handle() {\n var value = " + initial
            + ";\n var other = 'abc';\n const values = [' '];\n"
              " const record = {item: ' ', value: ' '};\n"
            + GUARD + "\n " + change + "\n consume(value);\n}\n")
    assert syntax._native_source_tree(text, "javascript") is not None
    return text


@pytest.mark.parametrize("change,initial", [
    ("[value] = values;", "'abc'"),
    ("[...value] = values;", "'abc'"),
    ("({item: value} = record);", "'abc'"),
    ("({value} = record);", "'abc'"),
    ("(value) = ' ';", "'abc'"),
    ("var [value] = values;", "'abc'"),
    ("var {item: value} = record;", "'abc'"),
    ("value.current = ' ';", "{current: 'abc', toString() { return this.current; }}"),
    ("value[0] = ' ';", "['abc']"),
], ids=["array", "rest", "object-alias", "object-shorthand", "grouped-name",
        "array-declaration", "object-declaration", "member-write", "element-write"])
def test_composite_writes_cannot_reuse_a_validator_epoch(native, tmp_path, change, initial):
    text = source(change, initial)
    (tmp_path / "app.js").write_text(text)
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                         sink_uri="app.js", sink_line=8, sink_class="xss", language="javascript")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert result.artifact is None
    assert "no chain member reaches" in result.reasoning


@pytest.mark.parametrize("change", [
    "[other] = values;", "({value: other} = record);", "other = value;", "value = ((value));",
], ids=["unrelated-array", "property-name-only", "unrelated-assignment", "self-assignment"])
def test_unrelated_targets_and_bare_self_assignment_keep_the_epoch(native, tmp_path, change):
    text = source(change)
    (tmp_path / "app.js").write_text(text)
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                         sink_uri="app.js", sink_line=8, sink_class="xss", language="javascript")
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


def test_composite_write_refusal_reaches_tier1_and_prescreen(native, tmp_path):
    text = source("[value] = values;")
    (tmp_path / "app.js").write_text(text)
    reply = json.dumps({"kind": "charset", "validator_source_line": GUARD.strip(),
                        "variable_name": "value", "charset": "a-z", "forbidden": "", "library_call": ""})
    result = tier1_llm.try_tier1b(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                                 sink_uri="app.js", sink_line=8, sink_class="xss", language="javascript",
                                 complete=lambda *_args: reply)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    spec = sb.extract_validator_from_line(GUARD, "javascript")
    assert spec is not None
    refuted, reason, _ = injection_prescreen._step_refutes_path(
        spec=spec, step_file="app.js", step_line=6, sink_file="app.js", sink_line=8,
        source_text=text, language="javascript", sink_classes=frozenset({"xss"}),
    )
    assert refuted is False
    assert "value chain" in reason
