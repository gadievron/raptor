"""HTML encoding needs a source-bound output context and attribute policy."""
import json

import pytest

from core.analysis import validator_control_scope
from core.dataflow import known_safe_calls as ksc, smt_barrier as sb, tier1_llm
from core.dataflow.sanitizer_catalog import sanitizer_callables_for_cwe, source_contracts_for_callable


@pytest.mark.parametrize("prefix,suffix", [("<p>", "</p>"), ('<a title="', '">link</a>'),
                                           ('<a href="', '">link</a>'), ('<a title=', '>link</a>')],
                         ids=("text", "text-attribute", "url-attribute", "unquoted-attribute"))
def test_html_encoder_needs_verified_output_context(tmp_path, prefix, suffix):
    pytest.importorskip("tree_sitter_java")
    line = "  String safe = org.apache.commons.lang3.StringEscapeUtils.escapeHtml4(raw);"
    source = ('class App {\n void handle(String raw, java.io.Writer out) throws Exception {\n'
              '  out.write(' + json.dumps(prefix) + ');\n' + line + '\n'
              '  out.write(safe);\n  out.write(' + json.dumps(suffix) + ');\n }\n}\n')
    tree = validator_control_scope._native_source_tree(source, "java")
    assert tree is not None and not tree.root_node.has_error
    (tmp_path / "App.java").write_bytes(source.encode())
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": line,
                        "variable_name": "raw", "charset": "", "forbidden": "",
                        "library_call": "org.apache.commons.lang3.StringEscapeUtils.escapeHtml4",
                        "html_context": "text", "url_validated": True})
    result = tier1_llm.try_tier1b(fix_diff="+" + line + "\n", repo_root=tmp_path,
                                 sink_uri="App.java", sink_line=5, sink_class="xss", language="java",
                                 complete=lambda *_: reply)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert result.artifact is None
    assert result.extras["unverified_source_contracts"] == [ksc.HTML_OUTPUT_POLICY]


def test_commons_html_encoder_remains_a_conditional_candidate():
    library = "org.apache.commons.lang3.StringEscapeUtils.escapeHtml4"
    assert library in sanitizer_callables_for_cwe("CWE-79", "java")
    assert source_contracts_for_callable(library, "CWE-79", "java") == frozenset({ksc.HTML_OUTPUT_POLICY})
    assert source_contracts_for_callable(library, "CWE-89", "java") == frozenset()
    assert source_contracts_for_callable(library, "CWE-79", "python") == frozenset()
    entry = ksc.find(library, "xss", "java")
    assert entry is not None and entry.input_arg_kind == "transform"


@pytest.mark.parametrize("depth", (1, 2), ids=("one-hop", "two-hop"))
def test_wrapper_retains_underlying_encoder_context(depth):
    pytest.importorskip("tree_sitter_java")
    from core.analysis.cfg_builder_java import build_java_intraproc_cfg
    from core.analysis.java_wrapper_summaries import synthetic_wrapper_bindings_java
    from core.analysis.sanitizer_cut import VERDICT_CANDIDATE_ONLY, evaluate_finding
    from core.analysis.tests.test_java_wrapper_summaries import _hint, _src

    helpers = '    private static String esc(String s) { return StringEscapeUtils.escapeHtml4(s); }\n'
    call = "esc"
    if depth == 2:
        helpers += '    private static String wrap(String s) { return esc(s); }\n'
        call = "wrap"
    source = _src(helpers, '        String y = ' + call + '(x);\n        out.println(y);\n')
    source = source.replace('import org.owasp.encoder.Encode;', 'import org.apache.commons.lang3.StringEscapeUtils;')
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
