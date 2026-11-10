"""Call syntax cannot certify mutable or stateful DOMPurify profiles."""
import json
from pathlib import Path

import pytest

from core.dataflow import tier1_llm as t1
from core.dataflow.sanitizer_catalog import sanitizer_callables_for_cwe, source_contracts_for_callable

REQUIREMENT = "dompurify_instance_config_and_immutable_output"


@pytest.mark.parametrize("language,suffix", [("javascript", "js"), ("typescript", "ts")])
@pytest.mark.parametrize("prefix,arguments,tail", [
    ("", "raw, {RETURN_DOM: true}", ""),
    ("", "raw, {RETURN_DOM_FRAGMENT: true}", ""),
    ("  DOMPurify.setConfig({RETURN_DOM: true});\n", "raw", ""),
    ("", "raw, options", "  const alias = safe;\n  alias.extra = raw;\n"),
    # TrustedHTML is a distinct output mode, not asserted to be mutable DOM.
    ("", "raw, {RETURN_TRUSTED_TYPE: true}", ""),
    ("", "raw", ""),
], ids=["dom", "fragment", "persistent-config", "alias-mutation", "trusted-output", "default-candidate"])
def test_unverified_instance_profile_cannot_earn_an_immutable_certificate(
    tmp_path: Path, language, suffix, prefix, arguments, tail,
):
    line = f"  const safe = DOMPurify.sanitize({arguments});"
    source = "function handle(raw, options) {\n" + prefix + line + "\n" + tail + "  consume(safe);\n}\n"
    (tmp_path / f"app.{suffix}").write_text(source)
    sink_line = next(i for i, text in enumerate(source.splitlines(), 1) if "consume(safe)" in text)
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": line,
                        "variable_name": "raw", "charset": "", "forbidden": "",
                        "library_call": "DOMPurify.sanitize", "immutable_output": True})
    result = t1.try_tier1b(fix_diff="+" + line + "\n", repo_root=tmp_path,
                          sink_uri=f"app.{suffix}", sink_line=sink_line, sink_class="xss",
                          language=language, complete=lambda _system, _user: reply)
    assert result.status is t1.Tier0Status.NOT_APPLICABLE
    assert result.artifact is None
    assert result.extras["unverified_source_contracts"] == [REQUIREMENT]


@pytest.mark.parametrize("language", ["javascript", "typescript"])
def test_profile_requirement_preserves_catalogue_candidates(language):
    assert "DOMPurify.sanitize" in sanitizer_callables_for_cwe("CWE-79", language)
    assert source_contracts_for_callable("DOMPurify.sanitize", "CWE-79", language) == frozenset({REQUIREMENT})
