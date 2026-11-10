"""Line-only sink proofs cannot select among separate explicit calls."""
import pytest

from core.dataflow import smt_barrier as sb
from core.smt_solver import z3_available


@pytest.mark.skipif(not z3_available(), reason="requires native Z3")
@pytest.mark.parametrize("sink", [
    "slots[render(raw)] = value",
    "factory(raw)(value)",
    "factory(raw).send(value)",
], ids=["assignment-target", "nested-callee", "receiver-call"])
def test_python_other_calls_cannot_borrow_rhs_proof(tmp_path, sink):
    guard = '    if not re.fullmatch(r"[a-z]+", value):'
    source = 'import re\ndef handle(value, raw):\n' + guard + '\n        return\n    ' + sink + '\n'
    (tmp_path / "app.py").write_text(source)
    result = sb.try_tier0(fix_diff="+" + guard + "\n", repo_root=tmp_path,
                          sink_uri="app.py", sink_line=5, sink_class="xss")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert "no chain member reaches" in result.reasoning


@pytest.mark.skipif(not z3_available(), reason="requires native Z3")
@pytest.mark.parametrize("sink", ["render(value)", "writer.send(value)", "out = render(value)",
                                  "slots[key] = value", "writer.value = value", "return value"])
def test_python_single_value_controls_remain_eligible(tmp_path, sink):
    guard = '    if not re.fullmatch(r"[a-z]+", value):'
    (tmp_path / "app.py").write_text('import re\ndef handle(value):\n' + guard + '\n        return\n    ' + sink + '\n')
    result = sb.try_tier0(fix_diff="+" + guard + "\n", repo_root=tmp_path,
                          sink_uri="app.py", sink_line=5, sink_class="xss")
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


@pytest.mark.skipif(not z3_available(), reason="requires native Z3")
@pytest.mark.parametrize("sink", ["slots[render(raw)] = value;", "factory(raw)(value);",
                                  "factory(raw).send(value);", "new Writer(raw).send(value);"],
                         ids=["assignment-target", "nested-callee", "receiver-call", "constructor-receiver"])
def test_javascript_other_calls_cannot_borrow_rhs_proof(tmp_path, sink):
    pytest.importorskip("tree_sitter_javascript")
    guard = ' if (!/^[a-z]+$/.test(value)) return;'
    (tmp_path / "app.js").write_text('function handle(value, raw) {\n' + guard + '\n ' + sink + '\n}\n')
    result = sb.try_tier0(fix_diff="+" + guard + "\n", repo_root=tmp_path,
                          sink_uri="app.js", sink_line=3, sink_class="xss", language="javascript")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert "no chain member reaches" in result.reasoning


@pytest.mark.skipif(not z3_available(), reason="requires native Z3")
@pytest.mark.parametrize("sink", ["writer.send(value);", "out = render(value);", "slots[key] = value;",
                                  "writer.value = value;", "return value;"])
def test_javascript_single_value_controls_remain_eligible(tmp_path, sink):
    pytest.importorskip("tree_sitter_javascript")
    guard = ' if (!/^[a-z]+$/.test(value)) return;'
    (tmp_path / "app.js").write_text('function handle(value) {\n' + guard + '\n ' + sink + '\n}\n')
    result = sb.try_tier0(fix_diff="+" + guard + "\n", repo_root=tmp_path,
                          sink_uri="app.js", sink_line=3, sink_class="xss", language="javascript")
    assert result.status is sb.Tier0Status.SOUND, result.reasoning
