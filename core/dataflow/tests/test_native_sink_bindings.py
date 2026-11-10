"""A validator certificate must reach a consumed value, not a name decoy."""
import pytest

from core.dataflow import smt_barrier
from core.smt_solver import z3_available

GUARD = ' if (!/^[a-z]+$/.test(value)) return;'


def _source(sink):
    return 'function handle(value, other) {\n' + GUARD + '\n ' + sink + '\n}\n'


@pytest.mark.skipif(not z3_available(), reason="requires native Z3")
@pytest.mark.parametrize("sink", ['consume({value: other});', 'writer.value(other);'],
                         ids=["property-key", "method-name"])
def test_names_outside_consumed_values_cannot_receive_the_proof(tmp_path, sink):
    pytest.importorskip("tree_sitter_javascript")
    (tmp_path / "app.js").write_bytes(_source(sink).encode())
    result = smt_barrier.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                                  sink_uri="app.js", sink_line=3, sink_class="xss", language="javascript")
    assert result.status is smt_barrier.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert "no chain member reaches" in result.reasoning



@pytest.mark.skipif(not z3_available(), reason="requires native Z3")
@pytest.mark.parametrize("sink", ['consume(value);', 'return consume((value));',
                                  'const result = consume(value);', 'return value;'],
                         ids=["direct", "parenthesized", "assigned-call", "return-name"])
def test_direct_consumed_values_remain_eligible(tmp_path, sink):
    pytest.importorskip("tree_sitter_javascript")
    (tmp_path / "app.js").write_bytes(_source(sink).encode())
    result = smt_barrier.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                                  sink_uri="app.js", sink_line=3, sink_class="xss", language="javascript")
    assert result.status is smt_barrier.Tier0Status.SOUND, result.reasoning


@pytest.mark.skipif(not z3_available(), reason="requires native Z3")
@pytest.mark.parametrize("sink", ['consume(value + other);', 'consume(value, other);',
                                  'consume(transform(value));', 'consume(value); consume(other);',
                                  'consume("prefix" + value);'],
                         ids=["mixed-value", "extra-argument", "unverified-transfer", "ambiguous-row", "literal-prefix"])
def test_uncontracted_sink_expressions_remain_unverified(tmp_path, sink):
    pytest.importorskip("tree_sitter_javascript")
    (tmp_path / "app.js").write_bytes(_source(sink).encode())
    result = smt_barrier.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                                  sink_uri="app.js", sink_line=3, sink_class="xss", language="javascript")
    assert result.status is smt_barrier.Tier0Status.NOT_APPLICABLE
    assert "no chain member reaches" in result.reasoning


@pytest.mark.skipif(not z3_available(), reason="requires native Z3")
@pytest.mark.parametrize("direct", [False, True], ids=["field-name-decoy", "direct-value"])
def test_java_native_sink_argument_is_distinct_from_callee_name(tmp_path, direct):
    pytest.importorskip("tree_sitter_java")
    guard = ' if (!value.matches("[a-z]+")) return;'
    sink = ' consume(value);' if direct else ' writer.value(other);'
    source = 'class App {\n void handle(String value, String other) {\n' + guard + '\n' + sink + '\n }\n}\n'
    (tmp_path / "App.java").write_bytes(source.encode())
    result = smt_barrier.try_tier0(fix_diff="+" + guard + "\n", repo_root=tmp_path,
                                  sink_uri="App.java", sink_line=4, sink_class="xss", language="java")
    assert result.status is (smt_barrier.Tier0Status.SOUND if direct else smt_barrier.Tier0Status.NOT_APPLICABLE), result.reasoning


@pytest.mark.skipif(not z3_available(), reason="requires native Z3")
def test_typescript_direct_typed_sink_expression_keeps_its_value(tmp_path):
    pytest.importorskip("tree_sitter_typescript")
    source = 'function handle(value: string, other: string) {\n' + GUARD + '\n consume(value);\n}\n'
    (tmp_path / "app.ts").write_bytes(source.encode())
    result = smt_barrier.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                                  sink_uri="app.ts", sink_line=3, sink_class="xss", language="typescript")
    assert result.status is smt_barrier.Tier0Status.SOUND, result.reasoning


def test_sink_shape_veto_is_wired_to_both_other_consumers(tmp_path):
    import json
    from core.dataflow import injection_prescreen, tier1_llm

    pytest.importorskip("tree_sitter_javascript")
    source = _source('writer.value(other);')
    (tmp_path / "app.js").write_bytes(source.encode())
    reply = json.dumps({"kind": "charset", "validator_source_line": GUARD.strip(),
                        "variable_name": "value", "charset": "a-z", "forbidden": "", "library_call": ""})
    result = tier1_llm.try_tier1b(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                                 sink_uri="app.js", sink_line=3, sink_class="xss", language="javascript",
                                 complete=lambda *_args: reply)
    assert result.status is smt_barrier.Tier0Status.NOT_APPLICABLE
    assert "does not reach sink" in result.reasoning
    spec = smt_barrier.extract_validator_from_line(GUARD, "javascript")
    assert spec is not None
    refuted, reason, _ = injection_prescreen._step_refutes_path(
        spec=spec, step_file="app.js", step_line=2, sink_file="app.js", sink_line=3,
        source_text=source, language="javascript", sink_classes=frozenset({"xss"}),
    )
    assert refuted is False
    assert "value chain" in reason


@pytest.mark.skipif(not z3_available(), reason="requires native Z3")
def test_multiline_statement_tail_cannot_share_the_sink_row(tmp_path):
    pytest.importorskip("tree_sitter_javascript")
    source = ('function handle(value, other) {\n' + GUARD + '\n'
              ' consume(\n other); consume(value);\n}\n')
    (tmp_path / "app.js").write_bytes(source.encode())
    result = smt_barrier.try_tier0(
        fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
        sink_uri="app.js", sink_line=4, sink_class="xss", language="javascript",
    )
    assert result.status is smt_barrier.Tier0Status.NOT_APPLICABLE
    assert "no chain member reaches" in result.reasoning
