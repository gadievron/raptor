"""HTML escaping does not establish the surrounding output policy."""
import io
import json
from html.parser import HTMLParser

import pytest

from core.dataflow import known_safe_calls as ksc, smt_barrier as sb, tier1_llm
from core.dataflow.sanitizer_catalog import source_contracts_for_callable


@pytest.mark.parametrize("prefix,suffix,payload", [
    ("<p>", "</p>", "<script>"),
    ('<a title="', '">link</a>', '"title'),
    ('<a href="', '">link</a>', "javascript:alert(1)"),
    ('<a onclick="', '">link</a>', "alert(1)"),
], ids=("text", "text-attribute", "url-attribute", "event-attribute"))
def test_stdlib_escape_requires_output_policy(tmp_path, prefix, suffix, payload):
    line = "    safe = html.escape(raw)"
    source = ("import html\ndef process(raw, out):\n"
              f"    out.write({prefix!r})\n"
              "    if type(raw) is not str: return\n" + line + "\n"
              "    out.write(safe)\n" + f"    out.write({suffix!r})\n")
    namespace = {}
    exec(compile(source, "owned-html.py", "exec"), namespace)
    output = io.StringIO()
    namespace["process"](payload, output)

    class Observe(HTMLParser):
        def handle_starttag(self, tag, attrs):
            self.attrs = dict(attrs)

    parsed = Observe()
    parsed.feed(output.getvalue())
    if prefix.startswith("<a"):
        assert next(iter(parsed.attrs.values())) == payload
    (tmp_path / "app.py").write_bytes(source.encode())
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": line,
                        "variable_name": "raw", "charset": "", "forbidden": "",
                        "library_call": "html.escape", "html_context": "text", "url_validated": True})
    result = tier1_llm.try_tier1b(
        fix_diff="+" + line + "\n", repo_root=tmp_path, sink_uri="app.py", sink_line=6,
        sink_class="xss", language="python", complete=lambda *_: reply,
    )
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert result.artifact is None
    assert result.extras["unverified_source_contracts"] == [ksc.HTML_OUTPUT_POLICY]


def test_stdlib_html_retains_type_and_context_requirements():
    assert source_contracts_for_callable("html.escape", "CWE-79", "python") == frozenset({
        ksc.EXACT_STR_DEFAULT_CALL, ksc.HTML_OUTPUT_POLICY,
    })
    assert source_contracts_for_callable("html.escape", "CWE-89", "python") == frozenset()
