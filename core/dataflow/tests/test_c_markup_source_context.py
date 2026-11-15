import json
import pytest
from core.analysis.cfg_builder_cpp import _get_parser
from core.analysis.finding_resolver import ResolvedFinding, resolve_finding
from core.analysis.sanitizer_cut import evaluate_finding

@pytest.mark.parametrize("language,ext", [("c", "c"), ("cpp", "cpp")])
def test_markup_href_context(tmp_path, language, ext):
    pytest.importorskip("tree_sitter_" + language)
    source = ('extern char *g_markup_escape_text(const char *, long);\n'
              'extern void render(const char *);\nvoid handle(const char *raw) {\n'
              ' render(' + json.dumps('<a href="') + ');\n'
              ' const char *safe = g_markup_escape_text(raw, -1);\n'
              ' render(safe);\n render(' + json.dumps('">link</a>') + ');\n}\n')
    parser = _get_parser(language)
    assert parser is not None
    tree = parser.parse(source.encode())
    assert tree is not None and not tree.root_node.has_error
    path = tmp_path / ('app.' + ext)
    path.write_bytes(source.encode())
    resolved = resolve_finding({'cwe':'CWE-79','file_path':str(path),'source_line':3,
                                'sink_line':6,'language':language},target_root=tmp_path)
    assert isinstance(resolved, ResolvedFinding), resolved
    assert resolved.sink_arg == 'safe'
    result = evaluate_finding(resolved.cfg,[resolved.source_node],resolved.sink_node,
                              cwe=resolved.cwe,language=resolved.language,
                              source_symbols=resolved.source_symbols,sink_arg=resolved.sink_arg)
    assert not result.suppress and result.verdict == "candidate_only"
    binding, = result.value_bound_bindings
    assert binding.callable == "g_markup_escape_text"
    assert binding.input_symbols == frozenset({"raw"})
    assert binding.output_symbols == frozenset({"safe"})
    assert binding.unverified_source_contracts == frozenset({"html_text_or_quoted_attribute_sink_context_and_policy"})

    from core.analysis.sanitizer_cut import record_sanitizer_cut_suppression
    record_sanitizer_cut_suppression(tmp_path, {"file_path": path.name, "line": 6, "sink_line": 6, "cwe": "CWE-79"}, result, enforce=True)
    record, = [json.loads(row) for row in (tmp_path / "suppressions.jsonl").read_text().splitlines()]
    assert record["dropped"] is False and record["enforced"] is False
    assert record["catalog_matches"][0]["unverified_source_contracts"] == ["html_text_or_quoted_attribute_sink_context_and_policy"]
