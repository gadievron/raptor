"""Unknown C helper effects cannot preserve a buffer certificate."""
import pytest
from core.analysis.cfg_builder_cpp import build_cpp_intraproc_cfg
from core.analysis.sanitizer_cut import VERDICT_CANDIDATE_ONLY, VERDICT_SUPPRESS, evaluate_finding

pytest.importorskip("tree_sitter_c")
pytest.importorskip("tree_sitter_cpp")


def _evaluate(middle, language="c", before="", value_context=True):
    source = ("extern char *g_shell_quote(const char *);\n"
              "extern void consume(const char *);\n"
              "extern void rewrite(char *);\n"
              "extern void inspect_raw(const char *);\n"
              "extern void inspect_flag(int);\n"
              "void handle(char *raw, int flag) {\n" + before +
              "    char *safe = g_shell_quote(raw);\n" + middle + "    consume(safe);\n}\n")
    graph = build_cpp_intraproc_cfg(source, "handle", language=language)
    assert graph is not None
    sink = next(node for node in graph.nodes() if "consume" in node.calls)
    kwargs = {"source_symbols": {"raw"}, "sink_arg": "safe"} if value_context else {}
    return evaluate_finding(graph, [graph.entry_node], sink, cwe="CWE-78", language=language, **kwargs)


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("middle", ["    rewrite(safe);\n", "    char *alias = safe;\n    rewrite(alias);\n"], ids=["direct", "alias"])
def test_helper_effects_on_returned_buffers_are_unproven(language, middle):
    result = _evaluate(middle, language)
    assert result.verdict == VERDICT_CANDIDATE_ONLY and not result.suppress
    assert result.value_bound_bindings


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_clean_structural_buffer_control_remains_admitted(language):
    result = _evaluate("", language)
    assert result.verdict == VERDICT_SUPPRESS and result.suppress


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_existing_indirect_write_refusal_remains(language):
    result = _evaluate("    safe[0] = raw[0];\n", language)
    assert result.verdict == VERDICT_CANDIDATE_ONLY and not result.suppress


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_helper_before_fresh_allocation_cannot_mutate_new_buffer(language):
    result = _evaluate("", language, before="    inspect_raw(raw);\n")
    assert result.verdict == VERDICT_SUPPRESS and result.suppress


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_unknown_call_outside_sink_paths_does_not_block_clean_path(language):
    result = _evaluate("    if (flag) { rewrite(safe); return; }\n", language)
    assert result.verdict == VERDICT_SUPPRESS and result.suppress


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_unknown_scalar_helper_after_cleaning_is_conservatively_unmodelled(language):
    # The current graph does not export callee effects or pointer/value types.
    # This is a disclosed limitation, not a claim that inspect mutates safe.
    result = _evaluate("    inspect_flag(flag);\n", language)
    assert result.verdict == VERDICT_CANDIDATE_ONLY and not result.suppress
