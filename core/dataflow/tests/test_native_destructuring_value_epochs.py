"""Native destructuring writes cannot inherit earlier guard constraints."""
import pytest

from core.dataflow import smt_barrier as sb
from core.smt_solver import z3_available

pytestmark = pytest.mark.skipif(not z3_available(), reason="requires native Z3")
GUARD = ' if (!/^[a-z]+$/.test(value)) return;'


@pytest.mark.parametrize("write", [
    '[value] = others;',
    '({field: value} = other);',
    '({value} = other);',
    '[[value]] = others;',
    'var [value] = others;',
    'var {field: value} = other;',
    '[...value] = others;',
], ids=["array", "renamed-object", "shorthand", "nested", "array-declaration", "object-declaration", "rest"])
def test_pattern_target_replaces_the_validated_epoch(tmp_path, write):
    pytest.importorskip("tree_sitter_javascript")
    source = ('function handle(value, others, other) {\n' + GUARD + '\n '
              + write + '\n consume(value);\n}\n')
    (tmp_path / "app.js").write_bytes(source.encode())
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
        sink_uri="app.js", sink_line=4, sink_class="xss", language="javascript")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert "no chain member reaches" in result.reasoning


@pytest.mark.parametrize("write", ['[other] = others;', '({value: other} = others);'],
                         ids=["unrelated-array", "property-key-decoy"])
def test_unrelated_pattern_targets_preserve_the_direct_value(tmp_path, write):
    pytest.importorskip("tree_sitter_javascript")
    source = ('function handle(value, others, other) {\n' + GUARD + '\n '
              + write + '\n consume(value);\n}\n')
    (tmp_path / "app.js").write_bytes(source.encode())
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
        sink_uri="app.js", sink_line=4, sink_class="xss", language="javascript")
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


def test_pattern_epoch_veto_reaches_tier1_and_prescreen(tmp_path):
    import json
    from core.dataflow import injection_prescreen, tier1_llm

    pytest.importorskip("tree_sitter_javascript")
    source = ('function handle(value, others) {\n' + GUARD
              + '\n [value] = others;\n consume(value);\n}\n')
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
