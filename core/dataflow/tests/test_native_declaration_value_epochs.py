"""New native declarations must not inherit another declaration's guard."""
import pytest

from core.analysis import validator_value_scope as epochs
from core.dataflow import smt_barrier as sb
from core.smt_solver import z3_available

pytestmark = pytest.mark.skipif(not z3_available(), reason="requires native Z3")
GUARD = ' if (!/^[a-z]+$/.test(value)) return;'


@pytest.mark.parametrize("declaration", [
    'let value;', 'function value() {}', 'function* value() {}', 'class value {}',
], ids=["uninitialised-let", "function", "generator", "class"])
def test_block_declaration_does_not_inherit_outer_value_proof(tmp_path, declaration):
    pytest.importorskip("tree_sitter_javascript")
    source = ('function handle(value) {\n' + GUARD + '\n {\n  '
              + declaration + '\n  consume(value);\n }\n}\n')
    (tmp_path / "app.js").write_bytes(source.encode())
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
        sink_uri="app.js", sink_line=5, sink_class="xss", language="javascript")
    assert epochs.native_value_epoch_unverified(source, "value", 2, 5, language="javascript")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    if declaration.startswith("function"):
        assert "does not dominate" in result.reasoning
    else:
        assert "no chain member reaches" in result.reasoning


@pytest.mark.parametrize("declaration", ['let other;', 'var value;', 'function other() {}', 'class other {}'],
                         ids=["independent-let", "same-function-var", "independent-function", "independent-class"])
def test_non_replacing_declarations_keep_the_direct_validated_value(tmp_path, declaration):
    pytest.importorskip("tree_sitter_javascript")
    source = ('function handle(value) {\n' + GUARD + '\n {\n  '
              + declaration + '\n  consume(value);\n }\n}\n')
    (tmp_path / "app.js").write_bytes(source.encode())
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
        sink_uri="app.js", sink_line=5, sink_class="xss", language="javascript")
    assert not epochs.native_value_epoch_unverified(source, "value", 2, 5, language="javascript")
    if declaration.startswith("function"):
        # The existing lexical function-boundary profile independently refuses.
        assert result.status is sb.Tier0Status.NOT_APPLICABLE
        assert "does not dominate" in result.reasoning
    else:
        assert result.status is sb.Tier0Status.SOUND, result.reasoning


@pytest.mark.parametrize("declaration", ['function value() {}', 'class value {}'], ids=["function", "class"])
def test_declaration_on_the_guard_row_also_changes_binding(tmp_path, declaration):
    pytest.importorskip("tree_sitter_javascript")
    source = ('function handle(value) {\n' + GUARD + ' { ' + declaration
              + '\n consume(value);\n }\n}\n')
    (tmp_path / "app.js").write_bytes(source.encode())
    result = sb.try_tier0(fix_diff="+" + source.split("\n")[1] + "\n", repo_root=tmp_path,
        sink_uri="app.js", sink_line=3, sink_class="xss", language="javascript")
    assert epochs.validator_row_epoch_unverified(source, "value", 2, language="javascript")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning


def test_typescript_enum_declaration_is_a_new_runtime_binding(tmp_path):
    pytest.importorskip("tree_sitter_typescript")
    source = ('function handle(value: string) {\n' + GUARD
              + '\n {\n enum value { A }\n consume(value);\n }\n}\n')
    (tmp_path / "app.ts").write_bytes(source.encode())
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
        sink_uri="app.ts", sink_line=5, sink_class="xss", language="typescript")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning


def test_declaration_epoch_veto_reaches_tier1_and_prescreen(tmp_path):
    import json
    from core.dataflow import injection_prescreen, tier1_llm

    pytest.importorskip("tree_sitter_javascript")
    source = ('function handle(value) {\n' + GUARD
              + '\n {\n let value;\n consume(value);\n }\n}\n')
    (tmp_path / "app.js").write_bytes(source.encode())
    reply = json.dumps({"kind": "charset", "validator_source_line": GUARD.strip(),
                        "variable_name": "value", "charset": "a-z", "forbidden": "", "library_call": ""})
    result = tier1_llm.try_tier1b(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
        sink_uri="app.js", sink_line=5, sink_class="xss", language="javascript",
        complete=lambda *_args: reply)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert "does not reach sink" in result.reasoning
    spec = sb.extract_validator_from_line(GUARD, "javascript")
    assert spec is not None
    refuted, reason, _ = injection_prescreen._step_refutes_path(
        spec=spec, step_file="app.js", step_line=2, sink_file="app.js", sink_line=5,
        source_text=source, language="javascript", sink_classes=frozenset({"xss"}),
    )
    assert refuted is False, reason
    assert "value chain" in reason
