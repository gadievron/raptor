"""A source validator constrains one value epoch, not its later mixes."""
import pytest

from core.dataflow import smt_barrier as sb
from core.smt_solver import z3_available

GUARD = '  if (!/^[a-z]+$/.test(value)) return;'


def _source(change):
    return 'function handle(value, other) {\n' + GUARD + '\n  ' + change + '\n  consume(value);\n}\n'


@pytest.mark.skipif(not z3_available(), reason="requires native Z3")
@pytest.mark.parametrize("change", ['value = value + other;', 'value += "<";'],
                         ids=["self-mix", "compound-literal"])
def test_guard_cannot_certify_a_changed_value_epoch(tmp_path, change):
    pytest.importorskip("tree_sitter_javascript")
    (tmp_path / "app.js").write_bytes(_source(change).encode())
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                         sink_uri="app.js", sink_line=4, sink_class="xss", language="javascript")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert "no chain member reaches" in result.reasoning



@pytest.mark.skipif(not z3_available(), reason="requires native Z3")
@pytest.mark.parametrize("change", ['value = value;', 'value = ((value));', '// value += other;'],
                         ids=["identity", "parenthesized-identity", "comment-decoy"])
def test_identity_epoch_and_comment_decoys_remain_eligible(tmp_path, change):
    pytest.importorskip("tree_sitter_javascript")
    (tmp_path / "app.js").write_bytes(_source(change).encode())
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                         sink_uri="app.js", sink_line=4, sink_class="xss", language="javascript")
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


@pytest.mark.skipif(not z3_available(), reason="requires native Z3")
def test_java_plain_self_mix_does_not_reuse_the_guard(tmp_path):
    pytest.importorskip("tree_sitter_java")
    guard = ' if (!value.matches("[a-z]+")) return;'
    source = ('class App {\n void handle(String value, String other) {\n' + guard +
              '\n value = value + other;\n consume(value);\n }\n}\n')
    (tmp_path / "App.java").write_bytes(source.encode())
    result = sb.try_tier0(fix_diff="+" + guard + "\n", repo_root=tmp_path,
                         sink_uri="App.java", sink_line=5, sink_class="xss", language="java")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert "no chain member reaches" in result.reasoning


def test_llm_guard_and_prescreen_cannot_reuse_a_mixed_epoch(tmp_path):
    import json
    from core.dataflow import injection_prescreen, tier1_llm

    pytest.importorskip("tree_sitter_javascript")
    source = _source('value = value + other;')
    (tmp_path / "app.js").write_bytes(source.encode())
    reply = json.dumps({"kind": "charset", "validator_source_line": GUARD.strip(),
                        "variable_name": "value", "charset": "a-z", "forbidden": "", "library_call": ""})
    result = tier1_llm.try_tier1b(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                                 sink_uri="app.js", sink_line=4, sink_class="xss", language="javascript",
                                 complete=lambda *_args: reply)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert "value" in result.reasoning
    spec = sb.extract_validator_from_line(GUARD, "javascript")
    assert spec is not None
    refuted, reason, _ = injection_prescreen._step_refutes_path(
        spec=spec, step_file="app.js", step_line=2, sink_file="app.js", sink_line=4,
        source_text=source, language="javascript", sink_classes=frozenset({"xss"}),
    )
    assert refuted is False
    assert "value chain" in reason



@pytest.mark.skipif(not z3_available(), reason="requires native Z3")
def test_reassignment_on_the_sink_row_invalidates_the_guard(tmp_path):
    pytest.importorskip("tree_sitter_javascript")
    source = 'function handle(value, other) {\n' + GUARD + '\n value = other; consume(value);\n}\n'
    (tmp_path / "app.js").write_bytes(source.encode())
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                         sink_uri="app.js", sink_line=3, sink_class="xss", language="javascript")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert "no chain member reaches" in result.reasoning



@pytest.mark.skipif(not z3_available(), reason="requires native Z3")
def test_unrelated_write_preserves_epoch_but_sink_row_is_ambiguous(tmp_path):
    pytest.importorskip("tree_sitter_javascript")
    source = 'function handle(value, other) {\n' + GUARD + '\n other = "marker"; consume(value);\n}\n'
    (tmp_path / "app.js").write_bytes(source.encode())
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                         sink_uri="app.js", sink_line=3, sink_class="xss", language="javascript")
    views = sb.code_view_lines(source, "javascript")
    assert sb._lexical_epoch_preserved("value", views, 2, 3)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert "no chain member reaches" in result.reasoning


@pytest.mark.skipif(not z3_available(), reason="requires native Z3")
def test_java_sink_row_reassignment_cannot_reuse_the_guard(tmp_path):
    pytest.importorskip("tree_sitter_java")
    guard = ' if (!value.matches("[a-z]+")) return;'
    source = ('class App {\n void handle(String value, String other) {\n' + guard +
              '\n value = other; consume(value);\n }\n}\n')
    (tmp_path / "App.java").write_bytes(source.encode())
    result = sb.try_tier0(fix_diff="+" + guard + "\n", repo_root=tmp_path,
                         sink_uri="App.java", sink_line=4, sink_class="xss", language="java")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert "no chain member reaches" in result.reasoning


def test_sink_row_reassignment_reaches_both_other_value_consumers(tmp_path):
    import json
    from core.dataflow import injection_prescreen, tier1_llm

    pytest.importorskip("tree_sitter_javascript")
    source = 'function handle(value, other) {\n' + GUARD + '\n value = other; consume(value);\n}\n'
    (tmp_path / "app.js").write_bytes(source.encode())
    reply = json.dumps({"kind": "charset", "validator_source_line": GUARD.strip(),
                        "variable_name": "value", "charset": "a-z", "forbidden": "", "library_call": ""})
    result = tier1_llm.try_tier1b(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                                 sink_uri="app.js", sink_line=3, sink_class="xss", language="javascript",
                                 complete=lambda *_args: reply)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert "does not reach sink" in result.reasoning
    spec = sb.extract_validator_from_line(GUARD, "javascript")
    assert spec is not None
    refuted, reason, _ = injection_prescreen._step_refutes_path(
        spec=spec, step_file="app.js", step_line=2, sink_file="app.js", sink_line=3,
        source_text=source, language="javascript", sink_classes=frozenset({"xss"}),
    )
    assert refuted is False
    assert "value chain" in reason
