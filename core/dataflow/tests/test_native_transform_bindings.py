"""Native returned-call binding must identify the complete RHS value."""
import json

import pytest

from core.dataflow import tier1_llm
from core.dataflow.smt_barrier import Tier0Status


def _run(tmp_path, line):
    source = 'function handle(value, other, strict) {\n' + line + '\n consume(safe);\n}\n'
    (tmp_path / "app.js").write_bytes(source.encode())
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": line.strip(),
                        "variable_name": "value", "charset": "", "forbidden": "",
                        "library_call": "validator.escape"})
    return tier1_llm.try_tier1b(fix_diff="+" + line + "\n", repo_root=tmp_path,
                               sink_uri="app.js", sink_line=3, sink_class="xss", language="javascript",
                               complete=lambda *_args: reply)


@pytest.mark.parametrize("line", [
    ' let safe = validator.escape(value) + other;',
    ' let safe = strict ? validator.escape(value) : other;',
    ' let ignored = validator.escape(value); let safe = evil.escape(value);',
], ids=["mixed-rhs", "conditional-rhs", "other-callee"])
def test_partial_or_unrelated_calls_do_not_certify_the_binding(tmp_path, line):
    pytest.importorskip("tree_sitter_javascript")
    result = _run(tmp_path, line)
    assert result.status is Tier0Status.NOT_APPLICABLE, result.reasoning
    assert result.artifact is None
    expected = "does not reach the sink line" if "evil.escape" in line else "not bound to a variable"
    assert expected in result.reasoning



@pytest.mark.parametrize("line", [
    ' let safe = validator.escape(value);',
    ' let safe = ((validator.escape(value)));',
    ' let raw = value, safe = validator.escape(value);',
    ' let raw = value; let safe = validator.escape(value);',
], ids=["direct", "parenthesized", "multi-declarator", "same-row-prefix"])
def test_direct_call_results_stay_bound_to_their_own_targets(tmp_path, line):
    pytest.importorskip("tree_sitter_javascript")
    result = _run(tmp_path, line)
    assert result.status is Tier0Status.SOUND, result.reasoning


@pytest.mark.parametrize("line", [
    ' let safe = [validator.escape(value), other][strict ? 0 : 1];',
    ' let safe = wrap(validator.escape(value));',
], ids=["selected-container", "unknown-wrapper"])
def test_nested_call_presence_is_not_a_complete_value_binding(tmp_path, line):
    pytest.importorskip("tree_sitter_javascript")
    result = _run(tmp_path, line)
    assert result.status is Tier0Status.NOT_APPLICABLE
    assert "not bound to a variable" in result.reasoning


def test_typescript_direct_typed_binding_retains_the_call_value(tmp_path):
    pytest.importorskip("tree_sitter_typescript")
    line = ' const safe: string = validator.escape(value);'
    source = 'function handle(value: string) {\n' + line + '\n consume(safe);\n}\n'
    (tmp_path / "app.ts").write_bytes(source.encode())
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": line.strip(),
                        "variable_name": "value", "charset": "", "forbidden": "",
                        "library_call": "validator.escape"})
    result = tier1_llm.try_tier1b(fix_diff="+" + line + "\n", repo_root=tmp_path,
                                 sink_uri="app.ts", sink_line=3, sink_class="xss", language="typescript",
                                 complete=lambda *_args: reply)
    assert result.status is Tier0Status.SOUND, result.reasoning


@pytest.mark.parametrize("mixed", [False, True], ids=["direct", "mixed"])
def test_java_direct_return_binding_does_not_credit_mixed_rhs(tmp_path, mixed):
    pytest.importorskip("tree_sitter_java")
    rhs = 'Encode.forHtml(value)' + (' + other' if mixed else '')
    line = ' String safe = ' + rhs + ';'
    source = ('import org.owasp.encoder.Encode;\nclass App {\n void handle(String value, String other) {\n'
              + line + '\n consume(safe);\n }\n}\n')
    (tmp_path / "App.java").write_bytes(source.encode())
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": line.strip(),
                        "variable_name": "value", "charset": "", "forbidden": "",
                        "library_call": "org.owasp.encoder.Encode.forHtml"})
    result = tier1_llm.try_tier1b(fix_diff="+" + line + "\n", repo_root=tmp_path,
                                 sink_uri="App.java", sink_line=5, sink_class="xss", language="java",
                                 complete=lambda *_args: reply)
    if mixed:
        assert result.status is Tier0Status.NOT_APPLICABLE
        assert "not bound to a variable" in result.reasoning
    else:
        assert result.status is Tier0Status.SOUND, result.reasoning
