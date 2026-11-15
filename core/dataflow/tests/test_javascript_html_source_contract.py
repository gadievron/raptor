"""Character encoding does not establish JavaScript HTML output policy."""
import json

import pytest

from core.analysis import validator_control_scope
from core.dataflow import known_safe_calls as ksc, smt_barrier as sb, tier1_llm
from core.dataflow.sanitizer_catalog import sanitizer_callables_for_cwe, source_contracts_for_callable


@pytest.mark.parametrize("language,ext", [("javascript", "js"), ("typescript", "ts")])
@pytest.mark.parametrize("prefix,suffix", [("<p>", "</p>"), ('<a title="', '">link</a>'),
                                          ('<a href="', '">link</a>'), ('<a onclick="', '">link</a>')],
                         ids=("text", "text-attribute", "url-attribute", "event-attribute"))
def test_encoder_requires_verified_output_context(tmp_path, language, ext, prefix, suffix):
    pytest.importorskip("tree_sitter_" + language)
    line = " const safe = validator.escape(raw);"
    source = ("function handle(raw, out) {\n"
              " out.write(" + json.dumps(prefix) + ");\n" + line + "\n"
              " out.write(safe);\n out.write(" + json.dumps(suffix) + ");\n}\n")
    tree = validator_control_scope._native_source_tree(source, language)
    assert tree is not None and not tree.root_node.has_error
    uri = "app." + ext
    (tmp_path / uri).write_bytes(source.encode())
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": line,
                        "variable_name": "raw", "charset": "", "forbidden": "",
                        "library_call": "validator.escape", "html_context": "text", "url_validated": True})
    result = tier1_llm.try_tier1b(
        fix_diff="+" + line + "\n", repo_root=tmp_path, sink_uri=uri, sink_line=4,
        sink_class="xss", language=language, complete=lambda *_: reply,
    )
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert result.artifact is None
    assert result.extras["unverified_source_contracts"] == [ksc.HTML_OUTPUT_POLICY]


@pytest.mark.parametrize("language", ["javascript", "typescript"])
def test_encoder_keeps_scoped_conditional_candidate(language):
    assert "validator.escape" in sanitizer_callables_for_cwe("CWE-79", language)
    assert source_contracts_for_callable("validator.escape", "CWE-79", language) == frozenset({ksc.HTML_OUTPUT_POLICY})
    assert source_contracts_for_callable("validator.escape", "CWE-89", language) == frozenset()
    assert source_contracts_for_callable("validator.escape", "CWE-79", "python") == frozenset()
