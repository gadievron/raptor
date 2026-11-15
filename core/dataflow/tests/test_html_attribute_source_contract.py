"""Attribute encoding alone cannot establish URL or script policy."""
import json

import pytest

from core.analysis import validator_control_scope
from core.dataflow import known_safe_calls as ksc, smt_barrier as sb, tier1_llm
from core.dataflow.sanitizer_catalog import sanitizer_callables_for_cwe, source_contracts_for_callable


@pytest.mark.parametrize("attribute", ("title", "href", "onclick"))
def test_attribute_encoder_needs_source_context_and_policy(tmp_path, attribute):
    pytest.importorskip("tree_sitter_java")
    line = "  String safe = org.owasp.encoder.Encode.forHtmlAttribute(raw);"
    source = ('class App {\n void handle(String raw, java.io.Writer out) throws Exception {\n'
              '  out.write(' + json.dumps('<a ' + attribute + '="') + ');\n' + line + '\n'
              '  out.write(safe);\n  out.write(' + json.dumps('">link</a>') + ');\n }\n}\n')
    tree = validator_control_scope._native_source_tree(source, "java")
    assert tree is not None and not tree.root_node.has_error
    (tmp_path / "App.java").write_bytes(source.encode())
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": line,
                        "variable_name": "raw", "charset": "", "forbidden": "",
                        "library_call": "org.owasp.encoder.Encode.forHtmlAttribute",
                        "html_context": "quoted_attribute", "url_validated": True})
    result = tier1_llm.try_tier1b(fix_diff="+" + line + "\n", repo_root=tmp_path,
                                 sink_uri="App.java", sink_line=5, sink_class="xss", language="java",
                                 complete=lambda *_: reply)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert result.artifact is None
    assert result.extras["unverified_source_contracts"] == [ksc.HTML_ATTRIBUTE_POLICY]


def test_attribute_encoder_candidate_retains_attribute_policy():
    library = "org.owasp.encoder.Encode.forHtmlAttribute"
    assert library in sanitizer_callables_for_cwe("CWE-79", "java")
    assert source_contracts_for_callable(library, "CWE-79", "java") == frozenset({ksc.HTML_ATTRIBUTE_POLICY})
    assert source_contracts_for_callable(library, "CWE-22", "java") == frozenset()
    assert source_contracts_for_callable(library, "CWE-79", "python") == frozenset()
    entry = ksc.find(library, "xss", "java")
    assert entry is not None and entry.input_arg_kind == "transform"
