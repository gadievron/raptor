"""Java encoder context requirements survive distinct proof consumers."""
import json

import pytest

from core.analysis import validator_control_scope
from core.dataflow import known_safe_calls as ksc, smt_barrier as sb, tier1_llm
from core.dataflow.sanitizer_catalog import sanitizer_callables_for_cwe, source_contracts_for_callable

ESAPI = "org.owasp.esapi.ESAPI.encoder().encodeForHTML"
SPRING = "org.springframework.web.util.HtmlUtils.htmlEscape"
CASES = [(ESAPI, ksc.HTML_TEXT_CONTENT_CONTEXT), (SPRING, ksc.HTML_OUTPUT_POLICY)]


def _source(library, prefix='<a href="', suffix='">link</a>'):
    line = '  String safe = ' + library + '(raw);'
    source = ('class App {\n void handle(String raw, java.io.Writer out) throws Exception {\n'
              '  out.write(' + json.dumps(prefix) + ');\n' + line + '\n  out.write(safe);\n'
              '  out.write(' + json.dumps(suffix) + ');\n }\n}\n')
    tree = validator_control_scope._native_source_tree(source, "java")
    assert tree is not None and not tree.root_node.has_error
    return source, line


@pytest.mark.parametrize("library,requirement", CASES, ids=("esapi", "spring"))
@pytest.mark.parametrize("prefix,suffix", [("<p>", "</p>"), ('<a title="', '">link</a>'),
                                          ('<a href="', '">link</a>'), ('<a onclick="', '">link</a>')],
                         ids=("text", "text-attribute", "url-attribute", "event-attribute"))
def test_tier1_context_and_chain_refusals_remain_distinct(tmp_path, library, requirement, prefix, suffix):
    pytest.importorskip("tree_sitter_java")
    source, line = _source(library, prefix, suffix)
    (tmp_path / "App.java").write_bytes(source.encode())
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": line,
                        "variable_name": "raw", "charset": "", "forbidden": "",
                        "library_call": library, "html_context": "text", "url_validated": True})
    result = tier1_llm.try_tier1b(
        fix_diff="+" + line + "\n", repo_root=tmp_path, sink_uri="App.java", sink_line=5,
        sink_class="xss", language="java", complete=lambda *_: reply,
    )
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert result.artifact is None
    if library == ESAPI:
        assert "not bound to a variable" in result.reasoning
        assert "unverified_source_contracts" not in result.extras
    else:
        assert result.extras["unverified_source_contracts"] == [requirement]


@pytest.mark.parametrize("library,requirement", CASES, ids=("esapi", "spring"))
def test_graph_preserves_context_requirements_and_value_roles(library, requirement):
    pytest.importorskip("tree_sitter_java")
    from core.analysis.cfg_builder_java import build_java_intraproc_cfg
    from core.analysis.sanitizer_cut import VERDICT_CANDIDATE_ONLY, evaluate_finding

    source, _ = _source(library)
    graph = build_java_intraproc_cfg(source, "handle")
    assert graph is not None
    sink = next(n for n in graph.nodes() if "out.write" in n.calls and n.lineno == 5)
    result = evaluate_finding(graph, [graph.entry], sink, cwe="CWE-79", language="java",
                              source_symbols={"raw"}, sink_arg="safe", java_source_text=source)
    assert result.verdict == VERDICT_CANDIDATE_ONLY and not result.suppress
    binding, = result.value_bound_bindings
    assert binding.callable == library
    assert binding.input_symbols == frozenset({"raw"})
    assert binding.output_symbols == frozenset({"safe"})
    assert binding.unverified_source_contracts == frozenset({requirement})


@pytest.mark.parametrize("library,requirement", CASES, ids=("esapi", "spring"))
def test_encoder_requirements_remain_scoped(library, requirement):
    assert library in sanitizer_callables_for_cwe("CWE-79", "java")
    assert source_contracts_for_callable(library, "CWE-79", "java") == frozenset({requirement})
    assert source_contracts_for_callable(library, "CWE-89", "java") == frozenset()
    assert source_contracts_for_callable(library, "CWE-79", "python") == frozenset()


@pytest.mark.parametrize("depth", (1, 2), ids=("one-hop", "two-hop"))
def test_spring_wrapper_retains_underlying_encoder_context(depth):
    pytest.importorskip("tree_sitter_java")
    from core.analysis.cfg_builder_java import build_java_intraproc_cfg
    from core.analysis.java_wrapper_summaries import synthetic_wrapper_bindings_java
    from core.analysis.sanitizer_cut import VERDICT_CANDIDATE_ONLY, evaluate_finding
    from core.analysis.tests.test_java_wrapper_summaries import _hint, _src

    helpers = '    private static String esc(String s) { return HtmlUtils.htmlEscape(s); }\n'
    call = "esc"
    if depth == 2:
        helpers += '    private static String wrap(String s) { return esc(s); }\n'
        call = "wrap"
    source = _src(helpers, '        String y = ' + call + '(x);\n        out.println(y);\n')
    source = source.replace('import org.owasp.encoder.Encode;', 'import org.springframework.web.util.HtmlUtils;')
    cfg = build_java_intraproc_cfg(source, "handle")
    assert cfg is not None
    bindings = synthetic_wrapper_bindings_java(cfg, source, _hint(source), "CWE-79", "java")
    binding, = bindings
    assert binding.input_symbols == frozenset({"x"})
    assert binding.output_symbols == frozenset({"y"})
    assert binding.unverified_source_contracts == frozenset({ksc.HTML_OUTPUT_POLICY})
    sink = next(n for n in cfg.nodes() if "out.println" in n.calls)
    result = evaluate_finding(cfg, [cfg.entry], sink, cwe="CWE-79", language="java",
                              source_symbols={"x"}, sink_arg="y", java_source_text=source,
                              extra_bindings=bindings)
    assert result.verdict == VERDICT_CANDIDATE_ONLY and not result.suppress
    assert result.value_bound_bindings
