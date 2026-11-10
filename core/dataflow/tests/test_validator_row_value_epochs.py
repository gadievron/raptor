"""Validator-row writes cannot inherit the earlier guard's language."""
import pytest

from core.dataflow import smt_barrier as sb
from core.smt_solver import z3_available

GUARD = '  if (!/^[a-z]+$/.test(value)) return;'


def _source(tail):
    return 'function handle(value, other) {\n' + GUARD + ' ' + tail + '\n consume(value);\n}\n'


@pytest.mark.skipif(not z3_available(), reason="requires native Z3")
def test_trailing_guard_row_rebind_invalidates_the_certificate(tmp_path):
    pytest.importorskip("tree_sitter_javascript")
    tail = 'value = other;'
    (tmp_path / "app.js").write_bytes(_source(tail).encode())
    result = sb.try_tier0(fix_diff="+" + GUARD + " " + tail + "\n", repo_root=tmp_path,
                         sink_uri="app.js", sink_line=3, sink_class="xss", language="javascript")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert "no chain member reaches" in result.reasoning



def test_safe_call_own_row_rebind_cannot_inherit_its_certificate(tmp_path):
    import json
    from core.dataflow import tier1_llm

    pytest.importorskip("tree_sitter_javascript")
    line = ' let safe = validator.escape(value); safe = other;'
    source = 'function handle(value, other) {\n' + line + '\n consume(safe);\n}\n'
    (tmp_path / "app.js").write_bytes(source.encode())
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": line.strip(),
                        "variable_name": "value", "charset": "", "forbidden": "",
                        "library_call": "validator.escape"})
    result = tier1_llm.try_tier1b(fix_diff="+" + line + "\n", repo_root=tmp_path,
                                 sink_uri="app.js", sink_line=3, sink_class="xss", language="javascript",
                                 complete=lambda *_args: reply)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert "does not reach the sink line" in result.reasoning



@pytest.mark.skipif(not z3_available(), reason="requires native Z3")
@pytest.mark.parametrize("placement", ["unrelated", "prefix", "failure-arm"])
def test_fresh_guard_epochs_keep_unrelated_and_exiting_writes(tmp_path, placement):
    pytest.importorskip("tree_sitter_javascript")
    if placement == "unrelated":
        line = GUARD + ' other = "marker";'
    elif placement == "prefix":
        line = ' value = other; ' + GUARD
    else:
        line = GUARD.replace("return;", "return (value = other);")
    source = 'function handle(value, other) {\n' + line + '\n consume(value);\n}\n'
    (tmp_path / "app.js").write_bytes(source.encode())
    result = sb.try_tier0(fix_diff="+" + line + "\n", repo_root=tmp_path,
                         sink_uri="app.js", sink_line=3, sink_class="xss", language="javascript")
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


@pytest.mark.parametrize("tail", ["", ' other = "marker";'], ids=["own-binding", "unrelated-binding"])
def test_returned_validator_own_assignment_is_retained(tmp_path, tail):
    import json
    from core.dataflow import tier1_llm

    pytest.importorskip("tree_sitter_javascript")
    line = ' let safe = validator.escape(value);' + tail
    source = 'function handle(value, other) {\n' + line + '\n consume(safe);\n}\n'
    (tmp_path / "app.js").write_bytes(source.encode())
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": line.strip(),
                        "variable_name": "value", "charset": "", "forbidden": "",
                        "library_call": "validator.escape"})
    result = tier1_llm.try_tier1b(fix_diff="+" + line + "\n", repo_root=tmp_path,
                                 sink_uri="app.js", sink_line=3, sink_class="xss", language="javascript",
                                 complete=lambda *_args: reply)
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


def test_native_row_check_distinguishes_guard_arms():
    pytest.importorskip("tree_sitter_javascript")
    from core.analysis.validator_value_scope import validator_row_epoch_unverified as refused

    passing_write = GUARD + ' else value = other;'
    source = 'function handle(value, other) {\n' + passing_write + '\n consume(value);\n}\n'
    assert refused(source, "value", 2, language="javascript")
    assert refused(_source('value++;'), "value", 2, language="javascript")
    assert not refused(_source('other++;'), "value", 2, language="javascript")


@pytest.mark.skipif(not z3_available(), reason="requires native Z3")
def test_java_guard_row_reassignment_invalidates_the_epoch(tmp_path):
    pytest.importorskip("tree_sitter_java")
    line = ' if (!value.matches("[a-z]+")) return; value = other;'
    source = ('class App {\n void handle(String value, String other) {\n' + line +
              '\n consume(value);\n }\n}\n')
    (tmp_path / "App.java").write_bytes(source.encode())
    result = sb.try_tier0(fix_diff="+" + line + "\n", repo_root=tmp_path,
                         sink_uri="App.java", sink_line=4, sink_class="xss", language="java")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert "no chain member reaches" in result.reasoning


def test_guard_row_write_reaches_llm_and_prescreen_consumers(tmp_path):
    import json
    from core.dataflow import injection_prescreen, tier1_llm

    pytest.importorskip("tree_sitter_javascript")
    line = GUARD + ' value = other;'
    source = _source('value = other;')
    (tmp_path / "app.js").write_bytes(source.encode())
    reply = json.dumps({"kind": "charset", "validator_source_line": line.strip(),
                        "variable_name": "value", "charset": "a-z", "forbidden": "", "library_call": ""})
    result = tier1_llm.try_tier1b(fix_diff="+" + line + "\n", repo_root=tmp_path,
                                 sink_uri="app.js", sink_line=3, sink_class="xss", language="javascript",
                                 complete=lambda *_args: reply)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert "does not reach sink" in result.reasoning
    spec = sb.extract_validator_from_line(line, "javascript")
    assert spec is not None
    refuted, reason, _ = injection_prescreen._step_refutes_path(
        spec=spec, step_file="app.js", step_line=2, sink_file="app.js", sink_line=3,
        source_text=source, language="javascript", sink_classes=frozenset({"xss"}),
    )
    assert refuted is False
    assert "value chain" in reason
