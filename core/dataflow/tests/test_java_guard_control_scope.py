"""Java source control ownership must precede a validator certificate."""
import pytest

from core.dataflow import smt_barrier as sb
from core.smt_solver import z3_available

pytest.importorskip("tree_sitter_java")
GUARD = ' if (!value.matches("[a-z]+")) return;'
SOURCE = ('class App {\n void handle(String value, boolean strict) {\n'
          ' if (\n strict\n )\n' + GUARD + '\n consume(value);\n }\n}\n')


@pytest.mark.skipif(not z3_available(), reason="requires native Z3")
def test_multiline_braceless_parent_cannot_certify_a_guard(tmp_path):
    (tmp_path / "App.java").write_bytes(SOURCE.encode())
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                         sink_uri="App.java", sink_line=7, sink_class="xss", language="java")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert "does not dominate" in result.reasoning



def test_guard_and_sink_must_share_the_same_native_arm():
    from core.analysis.java_guard_scope import java_guard_scope_unverified

    ordinary = ('class App {\n void handle(String value) {\n' + GUARD +
                '\n consume(value);\n }\n}\n')
    assert not java_guard_scope_unverified(ordinary, 3, 4, guard_shaped=True)
    shared = ('class App {\n void handle(String value, boolean strict) {\n if (strict) {\n'
              + GUARD + '\n consume(value);\n }\n }\n}\n')
    assert not java_guard_scope_unverified(shared, 4, 5, guard_shaped=True)
    sibling = ('class App {\n void handle(String value, boolean strict) {\n if (strict) {\n'
               + GUARD + '\n } else\n consume(value);\n }\n}\n')
    assert java_guard_scope_unverified(sibling, 4, 6, guard_shaped=True)


def test_unavailable_or_erroneous_java_syntax_cannot_authorise_scope(monkeypatch):
    from core.analysis import cfg_builder_java
    from core.analysis.java_guard_scope import java_guard_scope_unverified

    assert java_guard_scope_unverified(SOURCE + "}", 6, 7, guard_shaped=True)
    monkeypatch.setattr(cfg_builder_java, "_get_parser", lambda: None)
    assert java_guard_scope_unverified(SOURCE, 6, 7, guard_shaped=True)


def test_llm_guard_claim_cannot_override_the_multiline_parent(tmp_path):
    import json
    from core.dataflow import tier1_llm

    (tmp_path / "App.java").write_bytes(SOURCE.encode())
    reply = json.dumps({"kind": "charset", "validator_source_line": GUARD.strip(),
                        "variable_name": "value", "charset": "a-z", "forbidden": "", "library_call": ""})
    result = tier1_llm.try_tier1b(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                                 sink_uri="App.java", sink_line=7, sink_class="xss", language="java",
                                 complete=lambda *_args: reply)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert "not proven to execute unconditionally" in result.reasoning


def test_prescreen_keeps_the_bypassing_java_path():
    from core.dataflow import injection_prescreen

    spec = sb.extract_validator_from_line(GUARD, "java")
    assert spec is not None
    refuted, reason, _ = injection_prescreen._step_refutes_path(
        spec=spec, step_file="App.java", step_line=6, sink_file="App.java", sink_line=7,
        source_text=SOURCE, language="java", sink_classes=frozenset({"xss"}),
    )
    assert refuted is False
    assert reason == "validator does not dominate the sink"



def test_known_safe_call_claim_cannot_skip_the_multiline_parent(tmp_path):
    import json
    from core.dataflow import tier1_llm

    line = " safe = org.owasp.encoder.Encode.forHtml(value);"
    source = ('class App {\n void handle(String value, boolean strict) {\n'
              ' String safe = value;\n if (\n strict\n )\n' + line +
              '\n consume(safe);\n }\n}\n')
    (tmp_path / "App.java").write_bytes(source.encode())
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": line.strip(),
                        "variable_name": "safe", "charset": "", "forbidden": "",
                        "library_call": "org.owasp.encoder.Encode.forHtml"})
    result = tier1_llm.try_tier1b(fix_diff="+" + line + "\n", repo_root=tmp_path,
                                 sink_uri="App.java", sink_line=8, sink_class="xss", language="java",
                                 complete=lambda *_args: reply)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert "not proven to execute unconditionally" in result.reasoning
