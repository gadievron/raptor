"""Content-only encoding needs evidence of its HTML output context."""
import json

import pytest

from core.analysis import validator_control_scope
from core.dataflow import known_safe_calls as ksc, smt_barrier as sb, tier1_llm
from core.dataflow.sanitizer_catalog import sanitizer_callables_for_cwe, source_contracts_for_callable


@pytest.mark.parametrize("prefix,suffix", [("<p>", "</p>"), ('<input title="', '">')],
                         ids=("text-candidate", "attribute-mismatch"))
def test_content_encoder_cannot_claim_an_unverified_sink_context(tmp_path, prefix, suffix):
    pytest.importorskip("tree_sitter_java")
    line = "  String safe = org.owasp.encoder.Encode.forHtmlContent(raw);"
    source = ('class App {\n void handle(String raw, java.io.Writer out) throws Exception {\n'
              '  out.write(' + json.dumps(prefix) + ');\n' + line + '\n'
              '  out.write(safe);\n  out.write(' + json.dumps(suffix) + ');\n }\n}\n')
    tree = validator_control_scope._native_source_tree(source, "java")
    assert tree is not None and not tree.root_node.has_error
    (tmp_path / "App.java").write_bytes(source.encode())
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": line,
                        "variable_name": "raw", "charset": "", "forbidden": "",
                        "library_call": "org.owasp.encoder.Encode.forHtmlContent",
                        "html_context": "text"})
    result = tier1_llm.try_tier1b(fix_diff="+" + line + "\n", repo_root=tmp_path,
                                 sink_uri="App.java", sink_line=5, sink_class="xss", language="java",
                                 complete=lambda *_: reply)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert result.artifact is None
    assert result.extras["unverified_source_contracts"] == [ksc.HTML_TEXT_CONTENT_CONTEXT]


def test_content_encoder_remains_a_candidate_with_its_context_requirement():
    library = "org.owasp.encoder.Encode.forHtmlContent"
    assert library in sanitizer_callables_for_cwe("CWE-79", "java")
    assert source_contracts_for_callable(library, "CWE-79", "java") == frozenset({ksc.HTML_TEXT_CONTENT_CONTEXT})
    assert source_contracts_for_callable(library, "CWE-89", "java") == frozenset()
    assert source_contracts_for_callable(library, "CWE-79", "python") == frozenset()
    entry = ksc.find(library, "xss", "java")
    assert entry is not None and entry.input_arg_kind == "transform"
