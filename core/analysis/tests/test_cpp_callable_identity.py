"""C library spelling must not override negative source identity facts."""
import pytest

from core.analysis.cfg_builder_cpp import build_cpp_intraproc_cfg
from core.analysis.sanitizer_cut import VERDICT_SUPPRESS, evaluate_finding

pytest.importorskip("tree_sitter_c")
pytest.importorskip("tree_sitter_cpp")

BASE = "extern char *g_shell_quote(const char *);\nextern char *replacement(const char *);\nextern void consume(const char *);\n"


def _check(prefix="", before="", params="", expression="g_shell_quote(raw)", language="c", nested=False, base=BASE, after="", between=""):
    body = (f"void handle(char *raw{params}) {{\n" + before +
            f"    char *safe = {expression};\n" + between + "    consume(safe);\n}\n")
    source = base + prefix + ("namespace own {\n" + body + "}\n" if nested else body) + after
    graph = build_cpp_intraproc_cfg(source, "handle", language=language)
    assert graph is not None
    sink = next(node for node in graph.nodes() if "consume" in node.calls)
    result = evaluate_finding(graph, [graph.entry_node], sink, cwe="CWE-78", language=language,
                              source_symbols={"raw"}, sink_arg="safe")
    return graph, result


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("prefix,before,params", [
    ("char *g_shell_quote(const char *raw) { return (char *)raw; }\n", "", ""),
    ("", "", ", char *(*g_shell_quote)(const char *)"),
    ("", "    char *(*g_shell_quote)(const char *) = replacement;\n", ""),
    ("", "    static char *(*g_shell_quote)(const char *) = replacement;\n", ""),
], ids=["source-body", "parameter", "local-pointer", "static-pointer"])
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


NO_LIBRARY_PROTOTYPE = "extern char *replacement(const char *);\nextern void consume(const char *);\n"
OWN_NAMESPACE = "namespace own { char *g_shell_quote(const char *raw) { return (char *)raw; } }\n"


@pytest.mark.parametrize("prefix", [
    OWN_NAMESPACE + "using own::g_shell_quote;\n",
    OWN_NAMESPACE + "using namespace own;\n",
    OWN_NAMESPACE + "namespace alias = own; using namespace alias;\n",
    "using g_shell_quote = char *;\n",
    "typedef char *g_shell_quote;\n",
    "typedef char *Other, *g_shell_quote;\n",
    "struct g_shell_quote { g_shell_quote(char *); operator char *() const; };\n",
], ids=["using-declaration", "using-namespace", "namespace-alias", "type-alias", "typedef", "multi-typedef", "constructor-type"])
def test_global_imports_and_aliases_do_not_establish_library_identity(prefix):
    graph, result = _check(prefix, language="cpp", base=NO_LIBRARY_PROTOTYPE)
    assert any(name == "g_shell_quote" for name, _line in graph.untrusted_call_sites)
    assert not result.suppress


@pytest.mark.parametrize("before", [
    "    using own::g_shell_quote;\n", "    using namespace own;\n",
    "    using g_shell_quote = char *;\n", "    typedef char *g_shell_quote;\n",
], ids=["using-declaration", "using-namespace", "type-alias", "typedef"])
def test_local_imports_and_aliases_are_positionally_untrusted(before):
    graph, result = _check(OWN_NAMESPACE, before, language="cpp", base=NO_LIBRARY_PROTOTYPE)
    assert any(name == "g_shell_quote" for name, _line in graph.untrusted_call_sites)
    assert not result.suppress


@pytest.mark.parametrize("before", [
    "    { using namespace own; }\n", "    { using own::g_shell_quote; }\n",
    "    { using g_shell_quote = char *; }\n", "    { typedef char *g_shell_quote; }\n",
    "    using ::g_shell_quote;\n",
], ids=["expired-namespace", "expired-using", "expired-type-alias", "expired-typedef", "global-qualification"])
def test_expired_or_global_identity_aliases_preserve_library_control(before):
    _, result = _check(OWN_NAMESPACE, before, language="cpp")
    assert result.suppress


def test_unrelated_using_declaration_does_not_poison_library_call():
    prefix = "namespace own { void helper(void); } using own::helper;\n"
    _, result = _check(prefix, language="cpp")
    assert result.suppress


def test_sibling_namespace_import_does_not_escape_its_function():
    prefix = OWN_NAMESPACE + "void sibling(void) { using namespace own; }\n"
    _, result = _check(prefix, language="cpp")
    assert result.suppress


@pytest.mark.parametrize("before", [
    "    typedef char *Other, *g_shell_quote;\n",
    "    struct g_shell_quote { g_shell_quote(char *); operator char *() const; };\n",
], ids=["multi-typedef", "constructor-type"])
def test_additional_local_alias_shapes_are_not_library_functions(before):
    graph, result = _check(before=before, language="cpp", base=NO_LIBRARY_PROTOTYPE)
    assert any(name == "g_shell_quote" for name, _line in graph.untrusted_call_sites)
    assert not result.suppress


def test_later_global_namespace_import_does_not_rewrite_earlier_lookup():
    _, result = _check(OWN_NAMESPACE, language="cpp", after="using namespace own;\n")
    assert result.suppress


def test_later_local_namespace_import_does_not_rewrite_allocating_call():
    _, result = _check(OWN_NAMESPACE, language="cpp", between="    using namespace own;\n")
    assert result.suppress


def test_unrelated_class_method_name_does_not_shadow_global_function():
    prefix = "struct Other { char *g_shell_quote(const char *); };\n"
    _, result = _check(prefix, language="cpp")
    assert result.suppress


@pytest.mark.parametrize("nested,before", [
    (True, "    using ::g_shell_quote;\n"),
    (False, "    using namespace own;\n    using ::g_shell_quote;\n"),
], ids=["namespaced-target", "namespace-directive"])
def test_explicit_block_global_selection_can_clear_lookup_uncertainty(nested, before):
    graph, result = _check(OWN_NAMESPACE, before, language="cpp", nested=nested)
    assert result.suppress and result.verdict == VERDICT_SUPPRESS
    assert not any(name == "g_shell_quote" for name, _line in graph.untrusted_call_sites)


@pytest.mark.parametrize("prefix", [
    "char *g_shell_quote(const char *raw) { return (char *)raw; }\n",
    "char *::g_shell_quote(const char *raw) { return (char *)raw; }\n",
], ids=["global-source-body", "qualified-global-body"])
def test_explicit_global_selection_cannot_override_known_source_conflicts(prefix):
    graph, result = _check(prefix, before="    using ::g_shell_quote;\n", language="cpp", nested=True)
    assert any(name == "g_shell_quote" for name, _line in graph.untrusted_call_sites)
    assert not result.suppress


def test_expired_global_selection_cannot_clear_namespaced_lookup():
    _, result = _check(OWN_NAMESPACE, before="    { using ::g_shell_quote; }\n",
                       language="cpp", nested=True)
    assert not result.suppress


def test_later_global_selection_cannot_rewrite_earlier_call():
    _, result = _check(OWN_NAMESPACE, between="    using ::g_shell_quote;\n",
                       language="cpp", nested=True)
    assert not result.suppress


@pytest.mark.parametrize("nested,before,params", [
    (False, "", ""), (True, "", ""),
    (False, "", ", char *(*g_shell_quote)(const char *)"),
    (False, "    char *(*g_shell_quote)(const char *) = replacement;\n", ""),
], ids=["global", "namespace", "parameter-shadow", "local-shadow"])
def test_direct_global_selection_can_use_existing_structural_profile(nested, before, params):
    expression = "::g_shell_quote(raw)"
    graph, result = _check(OWN_NAMESPACE, before, params, expression=expression, language="cpp", nested=nested)
    assert result.suppress and result.value_bound_bindings
    assert {binding.callable for binding in result.value_bound_bindings} == {"g_shell_quote"}
    assert not any(name == "g_shell_quote" for name, _line in graph.untrusted_call_sites)


@pytest.mark.parametrize("prefix", [
    "char *g_shell_quote(const char *raw) { return (char *)raw; }\n",
    "using g_shell_quote = char *;\n",
    "struct g_shell_quote { g_shell_quote(char *); operator char *() const; };\n",
    "extern char *(*g_shell_quote)(const char *);\n",
], ids=["source-body", "type-alias", "constructor", "global-pointer-object"])
def test_global_prefix_cannot_forge_library_identity(prefix):
    graph, result = _check(prefix, expression="::g_shell_quote(raw)", language="cpp", base=NO_LIBRARY_PROTOTYPE)
    assert any(name == "g_shell_quote" for name, _line in graph.untrusted_call_sites)
    assert not result.suppress


@pytest.mark.parametrize("expression", [
    "((char *(*)(const char *))::g_shell_quote)(raw)",
    "reinterpret_cast<char *(*)(const char *)>(::g_shell_quote)(raw)",
])
def test_cast_callees_do_not_inherit_the_direct_global_profile(expression):
    _, result = _check(expression=expression, language="cpp")
    assert not result.suppress


@pytest.mark.parametrize("expression", ["g_shell_quote<char *>(raw)", "::g_shell_quote<char *>(raw)"])
def test_template_callees_keep_their_distinct_identity(expression):
    prefix = "template <class T> char *g_shell_quote(T);\n"
    graph, result = _check(prefix, expression=expression, language="cpp", base=NO_LIBRARY_PROTOTYPE)
    calls = {site.name for node in graph.nodes() for site in node.call_sites}
    assert "g_shell_quote" not in calls
    assert not result.suppress


@pytest.mark.parametrize("nested,before,params", [
    (False, "", ""), (True, "", ""),
    (False, "", ", char *(*g_shell_quote)(const char *)"),
    (False, "    char *(*g_shell_quote)(const char *) = replacement;\n", ""),
], ids=["global", "namespace", "parameter-shadow", "local-shadow"])
def test_parser_ambiguous_parenthesised_callee_does_not_earn_a_profile(nested, before, params):
    # Without semantic type resolution the grammar represents this as a cast.
    # Do not reinterpret that representation as a proven library call.
    _, result = _check(OWN_NAMESPACE, before, params, expression="(::g_shell_quote)(raw)",
                       language="cpp", nested=nested)
    assert not result.suppress
