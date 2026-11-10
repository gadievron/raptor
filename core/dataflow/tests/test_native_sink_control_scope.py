"""Unsupported sink-side control cannot inherit an outer guard certificate."""
import pytest

from core.dataflow import smt_barrier as sb
from core.smt_solver import z3_available

pytestmark = pytest.mark.skipif(not z3_available(), reason="requires native Z3")
GUARD = ' if (!/^[a-z]+$/.test(value)) return;'


@pytest.mark.parametrize("wrapper", [
    ' try { throw other; } catch (value) {\n  consume(value);\n }',
    ' try {\n  consume(value);\n } catch (other) {}',
    ' try { throw other; } catch (other) {\n  consume(value);\n }',
    ' switch (other) { case 1:\n  consume(value);\n }',
    ' label: {\n  consume(value);\n }',
], ids=["catch-shadow", "try-body", "independent-catch", "switch", "label"])
def test_sink_only_unsupported_control_remains_unverified(tmp_path, wrapper):
    pytest.importorskip("tree_sitter_javascript")
    source = 'function handle(value, other) {\n' + GUARD + '\n' + wrapper + '\n}\n'
    (tmp_path / "app.js").write_bytes(source.encode())
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
        sink_uri="app.js", sink_line=4, sink_class="xss", language="javascript")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning


def test_completed_unrelated_try_does_not_wrap_the_sink(tmp_path):
    pytest.importorskip("tree_sitter_javascript")
    source = ('function handle(value, other) {\n' + GUARD
              + '\n try { throw other; } catch (other) {}\n consume(value);\n}\n')
    (tmp_path / "app.js").write_bytes(source.encode())
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
        sink_uri="app.js", sink_line=4, sink_class="xss", language="javascript")
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


def test_java_sink_only_catch_cannot_inherit_field_guard(tmp_path):
    pytest.importorskip("tree_sitter_java")
    guard = ' if (!value.matches("[a-z]+")) return;'
    source = ('class App { String value;\n void handle(Exception other) {\n' + guard
              + '\n try { throw other; } catch (Exception value) {\n  consume(value);\n }\n }\n}\n')
    (tmp_path / "App.java").write_bytes(source.encode())
    result = sb.try_tier0(fix_diff="+" + guard + "\n", repo_root=tmp_path,
        sink_uri="App.java", sink_line=5, sink_class="xss", language="java")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning


def test_sink_control_veto_reaches_tier1_and_prescreen(tmp_path):
    import json
    from core.dataflow import injection_prescreen, tier1_llm

    pytest.importorskip("tree_sitter_javascript")
    source = ('function handle(value, other) {\n' + GUARD
              + '\n try { throw other; } catch (value) {\n  consume(value);\n }\n}\n')
    (tmp_path / "app.js").write_bytes(source.encode())
    reply = json.dumps({"kind": "charset", "validator_source_line": GUARD.strip(),
                        "variable_name": "value", "charset": "a-z", "forbidden": "", "library_call": ""})
    result = tier1_llm.try_tier1b(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
        sink_uri="app.js", sink_line=4, sink_class="xss", language="javascript",
        complete=lambda *_args: reply)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    spec = sb.extract_validator_from_line(GUARD, "javascript")
    assert spec is not None
    refuted, reason, _ = injection_prescreen._step_refutes_path(
        spec=spec, step_file="app.js", step_line=2, sink_file="app.js", sink_line=4,
        source_text=source, language="javascript", sink_classes=frozenset({"xss"}),
    )
    assert refuted is False, reason
