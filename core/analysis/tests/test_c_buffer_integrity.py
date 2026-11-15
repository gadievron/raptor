"""Unknown C helper effects cannot preserve a buffer certificate."""
import pytest
from core.analysis.cfg_builder_cpp import build_cpp_intraproc_cfg
from core.analysis.sanitizer_cut import VERDICT_CANDIDATE_ONLY, evaluate_finding

pytest.importorskip("tree_sitter_c")
pytest.importorskip("tree_sitter_cpp")


def _graph(middle, language="c", before="", sink_expression="consume(safe)"):
    source = ("extern char *g_shell_quote(const char *);\n"
              "extern void consume(const char *);\n"
              "extern void rewrite(char *);\n"
              "extern void inspect_raw(const char *);\n"
              "extern void inspect_flag(int);\n"
              "extern char *observe(char *);\n"
              "void handle(char *raw, int flag) {\n" + before +
              "    char *safe = g_shell_quote(raw);\n" + middle + "    " + sink_expression + ";\n}\n")
    graph = build_cpp_intraproc_cfg(source, "handle", language=language)
    assert graph is not None
    sink = next(node for node in graph.nodes() if "consume" in node.calls)
    return graph, sink


def _evaluate(middle, language="c", before="", value_context=True):
    graph, sink = _graph(middle, language, before)
    kwargs = {"source_symbols": {"raw"}, "sink_arg": "safe"} if value_context else {}
    return evaluate_finding(graph, [graph.entry_node], sink, cwe="CWE-78", language=language, **kwargs)


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("middle", ["    rewrite(safe);\n", "    char *alias = safe;\n    rewrite(alias);\n"], ids=["direct", "alias"])
def test_helper_effects_on_returned_buffers_are_unproven(language, middle):
    result = _evaluate(middle, language)
    assert result.verdict == VERDICT_CANDIDATE_ONLY and not result.suppress
    assert result.value_bound_bindings


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_clean_structural_buffer_control_keeps_binding(language):
    result = _evaluate("", language)
    _assert_context_binding(result)


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_existing_indirect_write_refusal_remains(language):
    result = _evaluate("    safe[0] = raw[0];\n", language)
    assert result.verdict == VERDICT_CANDIDATE_ONLY and not result.suppress


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_helper_before_fresh_allocation_cannot_mutate_new_buffer(language):
    result = _evaluate("", language, before="    inspect_raw(raw);\n")
    _assert_context_binding(result)


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_unknown_call_outside_sink_paths_does_not_block_clean_path(language):
    result = _evaluate("    if (flag) { rewrite(safe); return; }\n", language)
    _assert_context_binding(result)


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_unknown_scalar_helper_after_cleaning_is_conservatively_unmodelled(language):
    # The current graph does not export callee effects or pointer/value types.
    # This is a disclosed limitation, not a claim that inspect mutates safe.
    result = _evaluate("    inspect_flag(flag);\n", language)
    assert result.verdict == VERDICT_CANDIDATE_ONLY and not result.suppress


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("middle,before,sink_expression,has_effect", [
    ("", "", "consume(safe)", False),
    ("", "    inspect_raw(raw);\n", "consume(safe)", False),
    ("    rewrite(safe);\n", "", "consume(safe)", True),
    ("    char *alias = safe;\n    rewrite(alias);\n", "", "consume(safe)", True),
    ("    safe[0] = raw[0];\n", "", "consume(safe)", True),
    ("    inspect_flag(flag);\n", "", "consume(safe)", True),
    ("    if (flag) { rewrite(safe); return; }\n", "", "consume(safe)", False),
    ("", "", "consume(observe(safe))", True),
], ids=("clean", "prior-call", "direct-call", "alias-call", "indirect-write", "scalar-call", "exiting-branch", "nested-sink-call"))
def test_buffer_effect_structure_is_independent_of_context_contracts(language, middle, before, sink_expression, has_effect):
    from core.analysis.sanitizer_cut import _c_buffer_call_effect_nodes, _may_escape_nodes_on_path
    from core.dataflow.sanitizer_catalog import match_sanitizers_in_cfg

    graph, sink = _graph(middle, language, before, sink_expression)
    bindings = match_sanitizers_in_cfg(graph, "CWE-78", language)
    assert bindings
    assert all(b.unverified_source_contracts == frozenset({"posix_shell_argument_sink_context"}) for b in bindings)
    # Preserve actual requirements. Supplying the matched definitions answers
    # only the conditional effect question, never whether they may certify.
    effects = _c_buffer_call_effect_nodes(graph, bindings, sink, {b.callable for b in bindings})
    on_path = _may_escape_nodes_on_path(graph, {graph.entry_node}, sink, excluded=set(), additional_nodes=effects)
    assert bool(on_path) is has_effect
    if "return;" in middle:
        assert any("rewrite" in n.calls for n in effects)
        assert not on_path


def _assert_context_binding(result):
    assert not result.suppress and result.verdict == "candidate_only"
    binding, = result.value_bound_bindings
    assert binding.callable == "g_shell_quote"
    assert binding.input_symbols == frozenset({"raw"})
    assert binding.output_symbols == frozenset({"safe"})
    assert binding.unverified_source_contracts == frozenset({"posix_shell_argument_sink_context"})
