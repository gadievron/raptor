"""Lexical name flow cannot establish mutable C buffer integrity."""
import json
from pathlib import Path

import pytest
from core.dataflow import tier1_llm as t1


@pytest.mark.parametrize("language,suffix", [("c", "c"), ("cpp", "cpp")])
@pytest.mark.parametrize("library,arguments,sink_class", [("g_shell_quote", "raw", "cmdi"),
    ("g_markup_escape_text", "raw, -1", "xss")])
@pytest.mark.parametrize("middle", ["", "    safe[0] = raw[0];\n", "    rewrite(safe);\n"], ids=["clean", "index-write", "helper-call"])
def test_c_buffer_calls_need_an_integrity_receipt(tmp_path: Path, language, suffix, middle, library, arguments, sink_class):
    line = f"    safe = {library}({arguments});"
    source = ("extern char *g_shell_quote(const char *);\n"
              "extern char *g_markup_escape_text(const char *, long);\n"
              "extern void consume(const char *);\nextern void rewrite(char *);\n"
              "void handle(char *raw) {\n    char *safe;\n") + line + "\n" + middle + "    consume(safe);\n}\n"
    (tmp_path / f"app.{suffix}").write_text(source)
    sink_line = next(i for i, text in enumerate(source.splitlines(), 1) if "consume(safe)" in text)
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": line,
                        "variable_name": "raw", "charset": "", "forbidden": "",
                        "library_call": library, "buffer_unchanged": True})
    result = t1.try_tier1b(fix_diff="+" + line + "\n", repo_root=tmp_path,
                          sink_uri=f"app.{suffix}", sink_line=sink_line, sink_class=sink_class,
                          language=language, complete=lambda _system, _user: reply)
    assert result.status is t1.Tier0Status.NOT_APPLICABLE
    assert result.artifact is None
    assert result.extras["unverified_source_contracts"] == ["mutable_buffer_integrity_to_sink"]
