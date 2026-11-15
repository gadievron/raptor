"""HTML character encoding needs a separately verified output context."""
import json

import pytest

from core.dataflow import known_safe_calls as ksc, smt_barrier as sb, tier1_llm
from core.dataflow.sanitizer_catalog import sanitizer_callables_for_cwe, source_contracts_for_callable


@pytest.mark.parametrize("library", ["markupsafe.escape", "django.utils.html.escape"])
@pytest.mark.parametrize("prefix,suffix", [("<p>", "</p>"), ('<a title="', '">link</a>'),
                                          ('<a href="', '">link</a>'), ('<a onclick="', '">link</a>')],
                         ids=("text", "text-attribute", "url-attribute", "event-attribute"))
def test_html_wrapper_requires_source_bound_context(tmp_path, library, prefix, suffix):
    module = library.rsplit(".", 1)[0]
    line = f"    safe = {library}(raw)"
    source = (f"import {module}\ndef handle(raw, out):\n"
              f"    out.write({prefix!r})\n"
              "    if type(raw) is not str: return\n" + line + "\n"
              "    out.write(safe)\n" + f"    out.write({suffix!r})\n")
    compile(source, "owned-html.py", "exec")
    (tmp_path / "app.py").write_bytes(source.encode())
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": line,
                        "variable_name": "raw", "charset": "", "forbidden": "",
                        "library_call": library, "html_context": "text", "url_validated": True})
    result = tier1_llm.try_tier1b(
        fix_diff="+" + line + "\n", repo_root=tmp_path, sink_uri="app.py", sink_line=6,
        sink_class="xss", language="python", complete=lambda *_: reply,
    )
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert result.artifact is None
    assert result.extras["unverified_source_contracts"] == [ksc.HTML_OUTPUT_POLICY]


@pytest.mark.parametrize("library", ["markupsafe.escape", "django.utils.html.escape"])
def test_html_wrapper_retains_scoped_conditional_candidate(library):
    assert library in sanitizer_callables_for_cwe("CWE-79", "python")
    assert source_contracts_for_callable(library, "CWE-79", "python") == frozenset({
        ksc.EXACT_STR_DEFAULT_CALL, ksc.HTML_OUTPUT_POLICY,
    })
    assert source_contracts_for_callable(library, "CWE-89", "python") == frozenset()
    assert source_contracts_for_callable(library, "CWE-79", "java") == frozenset()
