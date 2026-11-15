"""HTML-fragment cleaning cannot certify an arbitrary output context."""
import json

import pytest

from core.dataflow import known_safe_calls as ksc, smt_barrier as sb, tier1_llm
from core.dataflow.sanitizer_catalog import sanitizer_callables_for_cwe, source_contracts_for_callable


@pytest.mark.parametrize("prefix,suffix", [("<p>", "</p>"), ('<a title="', '">link</a>'),
                                          ('<a href="', '">link</a>'), ('<a onclick="', '">link</a>')],
                         ids=("fragment", "text-attribute", "url-attribute", "event-attribute"))
def test_cleaner_requires_verified_fragment_context(tmp_path, prefix, suffix):
    line = "    safe = bleach.clean(raw)"
    source = ("import bleach\ndef handle(raw, out):\n"
              f"    out.write({prefix!r})\n" + line + "\n"
              "    out.write(safe)\n" + f"    out.write({suffix!r})\n")
    compile(source, "owned-fragment.py", "exec")
    (tmp_path / "app.py").write_bytes(source.encode())
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": line,
                        "variable_name": "raw", "charset": "", "forbidden": "",
                        "library_call": "bleach.clean", "uses_defaults": True, "html_context": "fragment"})
    result = tier1_llm.try_tier1b(
        fix_diff="+" + line + "\n", repo_root=tmp_path, sink_uri="app.py", sink_line=5,
        sink_class="xss", language="python", complete=lambda *_: reply,
    )
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert result.artifact is None
    assert result.extras["unverified_source_contracts"] == [ksc.HTML_TEXT_CONTENT_CONTEXT]


def test_cleaner_keeps_configuration_and_context_contracts_scoped():
    assert "bleach.clean" in sanitizer_callables_for_cwe("CWE-79", "python")
    assert source_contracts_for_callable("bleach.clean", "CWE-79", "python") == frozenset({
        ksc.DEFAULT_POSITIONAL_CALL, ksc.HTML_TEXT_CONTENT_CONTEXT,
    })
    assert source_contracts_for_callable("bleach.clean", "CWE-89", "python") == frozenset()
    assert source_contracts_for_callable("bleach.clean", "CWE-79", "java") == frozenset()
