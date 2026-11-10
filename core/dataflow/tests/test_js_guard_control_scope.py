"""JS-family multiline control ownership precedes source certificates."""
import pytest

from core.dataflow import smt_barrier as sb
from core.smt_solver import z3_available

GUARD = '  if (!/^[a-z]+$/.test(value)) return;'
SOURCE = 'function handle(value, strict) {\n if (\n strict\n )\n' + GUARD + '\n consume(value);\n}\n'


@pytest.mark.skipif(not z3_available(), reason="requires native Z3")
@pytest.mark.parametrize("language,suffix", [("javascript", "js"), ("typescript", "ts")])
def test_multiline_conditional_cannot_skip_a_js_family_guard(tmp_path, language, suffix):
    pytest.importorskip("tree_sitter_javascript" if language == "javascript" else "tree_sitter_typescript")
    name = "app." + suffix
    (tmp_path / name).write_bytes(SOURCE.encode())
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                         sink_uri=name, sink_line=6, sink_class="xss", language=language)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert "does not dominate" in result.reasoning



@pytest.mark.skipif(not z3_available(), reason="requires native Z3")
@pytest.mark.parametrize("language,suffix", [("javascript", "js"), ("typescript", "ts")])
def test_ordinary_js_family_guard_stays_eligible(tmp_path, language, suffix):
    pytest.importorskip("tree_sitter_javascript" if language == "javascript" else "tree_sitter_typescript")
    signature = "function handle(value) {" if language == "javascript" else "function handle(value: string) {"
    source = signature + "\n" + GUARD + "\n consume(value);\n}\n"
    name = "app." + suffix
    (tmp_path / name).write_bytes(source.encode())
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                         sink_uri=name, sink_line=3, sink_class="xss", language=language)
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


@pytest.mark.parametrize("language", ["javascript", "typescript"])
def test_native_js_arms_and_function_owners_are_distinct(language):
    pytest.importorskip("tree_sitter_javascript" if language == "javascript" else "tree_sitter_typescript")
    from core.analysis.validator_control_scope import validator_control_scope_unverified as refused

    shared = 'function handle(value, strict) {\n if (strict) {\n' + GUARD + '\n consume(value);\n }\n}\n'
    assert not refused(shared, 3, 4, guard_shaped=True, language=language)
    sibling = 'function handle(value, strict) {\n if (strict) {\n' + GUARD + '\n } else\n consume(value);\n}\n'
    assert refused(sibling, 3, 5, guard_shaped=True, language=language)
    other_function = 'function guard(value) {\n' + GUARD + '\n}\nfunction consumeIt(value) {\n consume(value);\n}\n'
    assert refused(other_function, 2, 5, guard_shaped=True, language=language)


def test_js_missing_grammar_and_bad_syntax_decline(monkeypatch):
    from core.analysis.validator_control_scope import validator_control_scope_unverified as refused
    from core.inventory import lexical_view

    assert refused(SOURCE + "}", 5, 6, guard_shaped=True, language="javascript")
    monkeypatch.setattr(lexical_view, "_parser_for", lambda language: None)
    assert refused(SOURCE, 5, 6, guard_shaped=True, language="javascript")


def test_llm_js_guard_claim_cannot_override_control_ownership(tmp_path):
    import json
    from core.dataflow import tier1_llm

    pytest.importorskip("tree_sitter_javascript")
    (tmp_path / "app.js").write_bytes(SOURCE.encode())
    reply = json.dumps({"kind": "charset", "validator_source_line": GUARD.strip(),
                        "variable_name": "value", "charset": "a-z", "forbidden": "", "library_call": ""})
    result = tier1_llm.try_tier1b(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
                                 sink_uri="app.js", sink_line=6, sink_class="xss", language="javascript",
                                 complete=lambda *_args: reply)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert "not proven to execute unconditionally" in result.reasoning


def test_js_prescreen_keeps_the_bypassing_path():
    from core.dataflow import injection_prescreen

    pytest.importorskip("tree_sitter_javascript")
    spec = sb.extract_validator_from_line(GUARD, "javascript")
    assert spec is not None
    refuted, reason, _ = injection_prescreen._step_refutes_path(
        spec=spec, step_file="app.js", step_line=5, sink_file="app.js", sink_line=6,
        source_text=SOURCE, language="javascript", sink_classes=frozenset({"xss"}),
    )
    assert refuted is False
    assert reason == "validator does not dominate the sink"



def test_same_row_statements_must_share_control_ownership():
    pytest.importorskip("tree_sitter_javascript")
    from core.analysis.validator_control_scope import validator_control_scope_unverified as refused

    same = 'function handle(value) {\n var raw = value; var safe = validator.escape(value);\n consume(safe);\n}\n'
    assert not refused(same, 2, 3, guard_shaped=False, language="javascript")
    mixed = 'function handle(value, strict) {\n if (strict) value = validator.escape(value); consumeOther(value);\n consume(value);\n}\n'
    assert refused(mixed, 2, 3, guard_shaped=False, language="javascript")
