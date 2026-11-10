"""Raw Java Unicode translation cannot be treated as a source proof."""
import pytest

from core.dataflow import smt_barrier as sb
from core.smt_solver import z3_available

GUARD = '    if (!value.matches("[a-z]+")) return;'
PREFIX = chr(92) + "u000a"
REASON = "java_unicode_translation_unverified"


def _source():
    return ("class App {\n void handle(String value, String other) {\n" + GUARD + "\n"
            "    // " + PREFIX + " value = other;\n    consume(value);\n }\n}\n")


@pytest.mark.skipif(not z3_available(), reason="requires native Z3")
def test_tier0_cannot_certify_a_raw_java_unicode_source(tmp_path):
    (tmp_path / "App.java").write_text(_source())
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                         sink_uri="App.java", sink_line=5, sink_class="xss", language="java")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert REASON in result.reasoning
    assert result.artifact is None


@pytest.mark.skipif(not z3_available(), reason="requires native Z3")
def test_ordinary_java_guard_remains_eligible(tmp_path):
    (tmp_path / "App.java").write_text(_source().replace(PREFIX, "ordinary comment"))
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                         sink_uri="App.java", sink_line=5, sink_class="xss", language="java")
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


@pytest.mark.parametrize("kind", ["charset", "known_safe_call"])
def test_llm_claim_cannot_discharge_the_source_translation_profile(tmp_path, kind):
    import json
    from core.dataflow import tier1_llm

    line = GUARD if kind == "charset" else "    String safe = org.owasp.encoder.Encode.forHtml(value);"
    source = (_source() if kind == "charset" else
              "class App {\n void handle(String value, String other) {\n" + line + "\n"
              "    // " + PREFIX + " safe = other;\n    consume(safe);\n }\n}\n")
    (tmp_path / "App.java").write_text(source)
    reply = json.dumps({"kind": kind, "validator_source_line": line.strip(),
                        "variable_name": "value", "charset": "a-z" if kind == "charset" else "",
                        "forbidden": "", "library_call": "org.owasp.encoder.Encode.forHtml"})
    result = tier1_llm.try_tier1b(fix_diff="+" + line + "\n", repo_root=tmp_path,
                                 sink_uri="App.java", sink_line=5, sink_class="xss", language="java",
                                 complete=lambda *_args: reply)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert result.extras["unverified_source_profile"] == REASON
    assert result.artifact is None


def test_prescreen_refuses_before_requesting_a_language_proof(monkeypatch):
    from core.dataflow import injection_prescreen as prescreen

    spec = sb.extract_validator_from_line(GUARD, "java")
    assert spec is not None

    def unexpected(*_args, **_kwargs):
        pytest.fail("unverified Java source reached the proof stage")

    monkeypatch.setattr(prescreen, "_spec_neutralizes_all", unexpected)
    refuted, reason, elapsed = prescreen._step_refutes_path(
        spec=spec, step_file="App.java", step_line=3, sink_file="App.java", sink_line=5,
        source_text=_source(), language="java", sink_classes=frozenset({"xss"}),
    )
    assert refuted is False
    assert REASON in reason
    assert elapsed == 0.0


def test_lexical_guard_helpers_preserve_unknown_translation():
    from core.dataflow.tier1_llm import _find_best_validator_line

    source = _source()
    spec = sb.extract_validator_from_line(GUARD, "java")
    assert spec is not None
    assert sb.find_validator_line(source, spec, language="java", sink_line=5) is None
    assert _find_best_validator_line(source, GUARD, 5, "java") is None
    assert sb._lexical_validator_in_branch(source, 3, 5, guard_shaped=True, language="java") is True
    assert sb._lexical_var_reaches_sink("value", source, 3, 5, "consume(value);", language="java") is False
    assert sb.validator_dominates_sink(source, 3, 5, language="java") is False
    assert sb.substitution_dominates_sink(source, 3, 5, "value", language="java") is False
