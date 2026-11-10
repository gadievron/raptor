"""A nested regex occurrence cannot supply the outer guard's property."""

import json
import re

import pytest

from core.dataflow import injection_prescreen, smt_barrier as sb, tier1_llm


@pytest.fixture(autouse=True)
def native():
    pytest.importorskip("z3")


INNER = 'obj.re.fullmatch(r"[a-z]+", value)'


def source(guard):
    return "import re\ndef handle(value, obj):\n " + guard + "\n consume(value)\n"


@pytest.mark.parametrize("call", [
    're.fullmatch(r"[a-z ]+", value, 0 * int(bool(' + INNER + ')))',
    're.fullmatch(r"[a-z ]+", value, flags=0 * int(bool(' + INNER + ')))',
    're.fullmatch(r"[A-Za-z]+", str(' + INNER + '))',
], ids=["positional-flags", "keyword-flags", "transformed-input"])
def test_inner_qualified_match_cannot_certify_the_outer_guard(tmp_path, call):
    guard = "if not " + call + ": return"
    text = source(guard)
    (tmp_path / "app.py").write_text(text)
    # Extraction really found the nested narrow class, not the outer one.
    spec = sb.extract_validator_from_line(guard, "python")
    assert spec is not None and spec.charset == "a-z"
    result = sb.try_tier0(fix_diff="+" + guard + "\n", repo_root=tmp_path,
                         sink_uri="app.py", sink_line=4, sink_class="xss", language="python")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert result.artifact is None


@pytest.mark.parametrize("kind", ["match", "fullmatch"])
def test_direct_literal_pattern_and_bare_input_remain_eligible(tmp_path, kind):
    guard = 'if not re.' + kind + '(r"^[a-z]+$", value): return'
    (tmp_path / "app.py").write_text(source(guard))
    result = sb.try_tier0(fix_diff="+" + guard + "\n", repo_root=tmp_path,
                         sink_uri="app.py", sink_line=4, sink_class="xss", language="python")
    # Python match/$ permits a final LF, unlike fullmatch.
    expected = sb.Tier0Status.SOUND if kind == "fullmatch" else sb.Tier0Status.DECLINED
    assert result.status is expected, result.reasoning


def test_nested_call_refusal_reaches_tier1_and_prescreen(tmp_path):
    guard = 'if not re.fullmatch(r"[a-z ]+", value, 0 * int(bool(' + INNER + '))): return'
    text = source(guard)
    (tmp_path / "app.py").write_text(text)
    assert re.fullmatch(r"[a-z ]+", " ", 0) is not None
    reply = json.dumps({"kind": "charset", "validator_source_line": guard,
                        "variable_name": "value", "charset": "a-z", "forbidden": "", "library_call": ""})
    result = tier1_llm.try_tier1b(fix_diff="+" + guard + "\n", repo_root=tmp_path,
                                 sink_uri="app.py", sink_line=4, sink_class="xss", language="python",
                                 complete=lambda *_args: reply)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    spec = sb.extract_validator_from_line(guard, "python")
    assert spec is not None
    refuted, _, _ = injection_prescreen._step_refutes_path(
        spec=spec, step_file="app.py", step_line=3, sink_file="app.py", sink_line=4,
        source_text=text, language="python", sink_classes=frozenset({"xss"}),
    )
    assert refuted is False
