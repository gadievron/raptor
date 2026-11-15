"""C shell quoting needs a separate source-bound argument context."""
import json

import pytest
from core.analysis.cfg_builder_cpp import _get_parser
from core.analysis.finding_resolver import resolve_finding, ResolvedFinding
from core.analysis.sanitizer_cut import evaluate_finding

@pytest.mark.parametrize("language,ext", [("c", "c"), ("cpp", "cpp")])
def test_existing_quote_context(tmp_path, language, ext):
    pytest.importorskip("tree_sitter_" + language)
    lines = ['typedef struct stream FILE;', 'extern FILE *popen(const char *, const char *);',
             'extern int fputs(const char *, FILE *);', 'extern char *g_shell_quote(const char *);',
             'void handle(const char *raw) {', ' FILE *pipe = popen("/bin/sh", "w");',
             ' fputs(' + json.dumps('printf "%s" "') + ', pipe);',
             ' char *safe = g_shell_quote(raw);', ' fputs(safe, pipe);',
             ' fputs(' + json.dumps('"\n') + ', pipe);', '}']
    source = '\n'.join(lines) + '\n'
    parser = _get_parser(language)
    assert parser is not None
    tree = parser.parse(source.encode())
    assert not tree.root_node.has_error
    path = tmp_path / ('app.' + ext)
    path.write_bytes(source.encode())
    resolved = resolve_finding({'cwe':'CWE-78','file_path':str(path),'source_line':5,
                                'sink_line':9,'language':language,'sink_arg':'safe'},target_root=tmp_path)
    assert isinstance(resolved, ResolvedFinding), resolved
    assert resolved.sink_arg == 'safe'
    result = evaluate_finding(resolved.cfg,[resolved.source_node],resolved.sink_node,
                              cwe=resolved.cwe,language=resolved.language,
                              source_symbols=resolved.source_symbols,sink_arg=resolved.sink_arg)
    assert not result.suppress and result.verdict == "candidate_only"
    binding, = result.value_bound_bindings
    assert binding.callable == "g_shell_quote"
    assert binding.input_symbols == frozenset({"raw"})
    assert binding.output_symbols == frozenset({"safe"})
    assert binding.unverified_source_contracts == frozenset({"posix_shell_argument_sink_context"})
    from core.analysis.sanitizer_cut import record_sanitizer_cut_suppression

    record_sanitizer_cut_suppression(tmp_path, {"file_path": path.name, "line": 9, "sink_line": 9, "cwe": "CWE-78"}, result, enforce=True)
    record, = [json.loads(row) for row in (tmp_path / "suppressions.jsonl").read_text().splitlines()]
    assert record["dropped"] is False and record["enforced"] is False
    assert record["catalog_matches"][0]["unverified_source_contracts"] == ["posix_shell_argument_sink_context"]


def test_shell_quote_context_is_scoped_to_shell_command_class():
    from core.dataflow import known_safe_calls as ksc
    from core.dataflow.sanitizer_catalog import source_contracts_for_callable

    for language in ("c", "cpp"):
        assert source_contracts_for_callable("g_shell_quote", "CWE-78", language) == frozenset({ksc.POSIX_SHELL_ARGUMENT_CONTEXT})
        assert source_contracts_for_callable("g_shell_quote", "CWE-88", language) == frozenset()
    assert source_contracts_for_callable("g_shell_quote", "CWE-78", "python") == frozenset()
