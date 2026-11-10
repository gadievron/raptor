"""C library spelling must not override negative source identity facts."""
import pytest

from core.analysis.cfg_builder_cpp import build_cpp_intraproc_cfg
from core.analysis.sanitizer_cut import VERDICT_SUPPRESS, evaluate_finding

pytest.importorskip("tree_sitter_c")
pytest.importorskip("tree_sitter_cpp")

BASE = "extern char *g_shell_quote(const char *);\nextern char *replacement(const char *);\nextern void consume(const char *);\n"


def _check(prefix="", before="", params="", expression="g_shell_quote(raw)", language="c", nested=False):
    body = (f"void handle(char *raw{params}) {{\n" + before +
            f"    char *safe = {expression};\n    consume(safe);\n}}\n")
    source = BASE + prefix + ("namespace own {\n" + body + "}\n" if nested else body)
    graph = build_cpp_intraproc_cfg(source, "handle", language=language)
    assert graph is not None
    sink = next(node for node in graph.nodes() if "consume" in node.calls)
    result = evaluate_finding(graph, [graph.entry_node], sink, cwe="CWE-78", language=language,
                              source_symbols={"raw"}, sink_arg="safe")
    return graph, result


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("prefix,before,params", [
    ("char *g_shell_quote(const char *raw) { return (char *)raw; }\n", "", ""),
    ("#define g_shell_quote(x) (x)\n", "", ""),
    ("#define g_shell_quote replacement\n", "", ""),
    ("", "", ", char *(*g_shell_quote)(const char *)"),
    ("", "    char *(*g_shell_quote)(const char *) = replacement;\n", ""),
    ("", "    static char *(*g_shell_quote)(const char *) = replacement;\n", ""),
], ids=["source-body", "function-macro", "object-macro", "parameter", "local-pointer", "static-pointer"])
def test_conflicting_source_identity_cannot_suppress(language, prefix, before, params):
    graph, result = _check(prefix, before, params, language=language)
    assert any(name == "g_shell_quote" for name, _line in graph.untrusted_call_sites)
    assert not result.suppress
    assert result.verdict != VERDICT_SUPPRESS


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("prefix,before", [
    ("", ""),
    ("", "    extern char *g_shell_quote(const char *);\n"),
    ("void sibling(void) { char *(*g_shell_quote)(const char *) = replacement; }\n", ""),
    ("", "    { char *(*g_shell_quote)(const char *) = replacement; }\n"),
], ids=["extern-prototype", "block-prototype", "sibling-local", "expired-local"])
def test_unrelated_declarations_do_not_poison_library_identity(language, prefix, before):
    graph, result = _check(prefix, before, language=language)
    assert not any(name == "g_shell_quote" for name, _line in graph.untrusted_call_sites)
    assert result.suppress and result.verdict == VERDICT_SUPPRESS


def test_unrelated_namespace_body_does_not_shadow_global_library():
    prefix = "namespace other { char *g_shell_quote(const char *raw) { return (char *)raw; } }\n"
    _, result = _check(prefix, language="cpp")
    assert result.suppress


def test_qualified_call_retains_qualification_instead_of_library_leaf():
    prefix = "namespace other { char *g_shell_quote(const char *raw) { return (char *)raw; } }\n"
    graph, result = _check(prefix, expression="other::g_shell_quote(raw)", language="cpp")
    calls = {site.name for node in graph.nodes() for site in node.call_sites}
    assert "other::g_shell_quote" in calls
    assert not result.suppress


def test_namespaced_target_does_not_assume_unqualified_global_origin():
    _, result = _check(language="cpp", nested=True)
    assert not result.suppress


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_prototype_parameter_names_do_not_bind_in_target_scope(language):
    graph, result = _check(before="    extern void declaration_only(char *(*g_shell_quote)(const char *));\n",
                           language=language)
    assert not any(name == "g_shell_quote" for name, _line in graph.untrusted_call_sites)
    assert result.suppress


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_prototype_parameter_cannot_vouch_a_later_global_store(language):
    source = (BASE + "char *saved;\nvoid handle(char *raw) {\n"
              "    void declaration_only(char *saved);\n"
              "    saved = g_shell_quote(raw);\n    consume(saved);\n}\n")
    graph = build_cpp_intraproc_cfg(source, "handle", language=language)
    assert graph is not None
    store = next(node for node in graph.nodes() if "saved" in node.defs)
    assert store.may_escape
