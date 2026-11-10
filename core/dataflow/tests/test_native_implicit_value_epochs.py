"""Implicit native writes must not inherit an earlier validator certificate."""
import pytest

from core.dataflow import smt_barrier as sb
from core.smt_solver import z3_available

pytestmark = pytest.mark.skipif(not z3_available(), reason="requires native Z3")
GUARD = ' if (!/^[a-z]+$/.test(value)) return;'


@pytest.mark.parametrize("body", [
    ' for (value of others) {\n  consume(value);\n }',
    ' for (value in others) {\n  consume(value);\n }',
    ' for (const value of others) {\n  consume(value);\n }',
    ' value++;\n consume(value);',
    ' --value;\n consume(value);',
], ids=["for-of", "for-in", "shadowed-target", "postfix", "prefix"])
def test_implicit_write_cannot_reuse_the_validated_epoch(tmp_path, body):
    pytest.importorskip("tree_sitter_javascript")
    source = 'function handle(value, others) {\n' + GUARD + '\n' + body + '\n}\n'
    (tmp_path / "app.js").write_bytes(source.encode())
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
        sink_uri="app.js", sink_line=4, sink_class="xss", language="javascript")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert "no chain member reaches" in result.reasoning


@pytest.mark.parametrize("header", ['for (other of others)', 'for (const other of others)'],
                         ids=["unrelated-target", "unrelated-declaration"])
def test_unrelated_iteration_target_keeps_direct_validated_value(tmp_path, header):
    pytest.importorskip("tree_sitter_javascript")
    source = ('function handle(value, others, other) {\n' + GUARD + '\n '
              + header + ' {\n  consume(value);\n }\n}\n')
    (tmp_path / "app.js").write_bytes(source.encode())
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
        sink_uri="app.js", sink_line=4, sink_class="xss", language="javascript")
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


@pytest.mark.parametrize("target", ["value", "other"], ids=["rebound", "independent"])
def test_java_enhanced_for_target_changes_only_its_named_epoch(tmp_path, target):
    pytest.importorskip("tree_sitter_java")
    guard = ' if (!value.matches("[a-z]+")) return;'
    source = ('class App { String value;\n void handle(String[] others) {\n' + guard
              + '\n for (String ' + target + ' : others) {\n  consume(value);\n }\n }\n}\n')
    (tmp_path / "App.java").write_bytes(source.encode())
    result = sb.try_tier0(fix_diff="+" + guard + "\n", repo_root=tmp_path,
        sink_uri="App.java", sink_line=5, sink_class="xss", language="java")
    expected = sb.Tier0Status.NOT_APPLICABLE if target == "value" else sb.Tier0Status.SOUND
    assert result.status is expected, result.reasoning


def test_implicit_epoch_veto_is_wired_to_tier1_and_prescreen(tmp_path):
    import json
    from core.dataflow import injection_prescreen, tier1_llm

    pytest.importorskip("tree_sitter_javascript")
    source = ('function handle(value, others) {\n' + GUARD
              + '\n for (value of others) {\n  consume(value);\n }\n}\n')
    (tmp_path / "app.js").write_bytes(source.encode())
    reply = json.dumps({"kind": "charset", "validator_source_line": GUARD.strip(),
                        "variable_name": "value", "charset": "a-z", "forbidden": "", "library_call": ""})
    result = tier1_llm.try_tier1b(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
        sink_uri="app.js", sink_line=4, sink_class="xss", language="javascript",
        complete=lambda *_args: reply)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert "does not reach sink" in result.reasoning
    spec = sb.extract_validator_from_line(GUARD, "javascript")
    assert spec is not None
    refuted, reason, _ = injection_prescreen._step_refutes_path(
        spec=spec, step_file="app.js", step_line=2, sink_file="app.js", sink_line=4,
        source_text=source, language="javascript", sink_classes=frozenset({"xss"}),
    )
    assert refuted is False
    assert "value chain" in reason
