"""A coercible object is not the primitive string in the regex model."""
import pytest

from core.dataflow import smt_barrier as sb
from core.smt_solver import z3_available

pytestmark = pytest.mark.skipif(not z3_available(), reason="requires native Z3")
GUARD = ' if (!/^[a-z]+$/.test(value)) return;'


@pytest.mark.parametrize("binding", [
    'const value = { toString() { return "abc"; } };',
    'const value = ["abc"];',
    'const value = () => "abc";',
    'const value = function() { return "abc"; };',
    'const value = new String("abc");',
    'const value = /abc/;',
    'const value = ({ toString() { return "abc"; } });',
], ids=["object", "array", "arrow", "function", "boxed-string", "regex", "parenthesized"])
def test_known_object_bindings_require_a_coercion_contract(tmp_path, binding):
    pytest.importorskip("tree_sitter_javascript")
    source = 'function handle() {\n ' + binding + '\n' + GUARD + '\n consume(value);\n}\n'
    (tmp_path / "app.js").write_bytes(source.encode())
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
        sink_uri="app.js", sink_line=4, sink_class="xss", language="javascript")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert "no chain member reaches" in result.reasoning


@pytest.mark.parametrize("binding", ['const value = "abc";', 'const other = {}; const value = "abc";'],
                         ids=["primitive-string", "unrelated-object"])
def test_primitive_literal_keeps_its_direct_guard_path(tmp_path, binding):
    pytest.importorskip("tree_sitter_javascript")
    source = 'function handle() {\n ' + binding + '\n' + GUARD + '\n consume(value);\n}\n'
    (tmp_path / "app.js").write_bytes(source.encode())
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
        sink_uri="app.js", sink_line=4, sink_class="xss", language="javascript")
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


def test_stateful_object_input_veto_reaches_all_three_consumers(tmp_path):
    import json
    from core.dataflow import injection_prescreen, tier1_llm

    pytest.importorskip("tree_sitter_javascript")
    source = ('function handle() {\n'
              ' let count = 0; const value = { toString() { return count++ ? "<" : "abc"; } };\n'
              + GUARD + '\n consume(value);\n}\n')
    (tmp_path / "app.js").write_bytes(source.encode())
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
        sink_uri="app.js", sink_line=4, sink_class="xss", language="javascript")
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    reply = json.dumps({"kind": "charset", "validator_source_line": GUARD.strip(),
                        "variable_name": "value", "charset": "a-z", "forbidden": "", "library_call": ""})
    llm_result = tier1_llm.try_tier1b(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
        sink_uri="app.js", sink_line=4, sink_class="xss", language="javascript",
        complete=lambda *_args: reply)
    assert llm_result.status is sb.Tier0Status.NOT_APPLICABLE
    assert "does not reach sink" in llm_result.reasoning
    spec = sb.extract_validator_from_line(GUARD, "javascript")
    assert spec is not None
    refuted, reason, _ = injection_prescreen._step_refutes_path(
        spec=spec, step_file="app.js", step_line=3, sink_file="app.js", sink_line=4,
        source_text=source, language="javascript", sink_classes=frozenset({"xss"}),
    )
    assert refuted is False, reason
    assert "value chain" in reason


@pytest.mark.parametrize("language,filename", [("typescript", "app.ts"), ("tsx", "app.tsx")], ids=["typescript", "tsx"])
def test_typed_source_profiles_do_not_make_objects_primitive(tmp_path, language, filename):
    pytest.importorskip("tree_sitter_typescript")
    source = ('function handle() {\n const value = { toString() { return "abc"; } };\n'
              + GUARD + '\n consume(value);\n}\n')
    (tmp_path / filename).write_bytes(source.encode())
    result = sb.try_tier0(fix_diff="+" + GUARD + "\n", repo_root=tmp_path,
        sink_uri=filename, sink_line=4, sink_class="xss", language=language)
    from core.analysis.validator_value_scope import native_object_input_unverified

    assert native_object_input_unverified(source, "value", 3, language=language)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    if language == "tsx":
        # The pre-existing mechanical extractor does not admit TSX guards.
        assert "no recognised charset/regex validator" in result.reasoning
    else:
        assert "no chain member reaches" in result.reasoning
