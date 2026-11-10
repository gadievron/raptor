"""SQL escape candidates need driver, value, mode and context premises."""
import json
from pathlib import Path

import pytest

from core.dataflow import tier1_llm as t1
from core.dataflow.sanitizer_catalog import sanitizer_callables_for_cwe, source_contracts_for_callable

REQUIREMENT = "sql_escape_driver_input_mode_and_literal_context"


@pytest.mark.parametrize("library", ["connection.escape", "conn.escape"])
@pytest.mark.parametrize("language,suffix", [("javascript", "js"), ("typescript", "ts")])
@pytest.mark.parametrize("argument,guard", [("raw", ""), ("[raw]", ""),
    ("raw", '  if (typeof raw !== "string") { return; }\n')],
    ids=["unknown-input", "array-shape", "primitive-guard-only"])
def test_escape_name_or_type_guard_does_not_establish_sql_profile(
    tmp_path: Path, library, language, suffix, argument, guard,
):
    line = f"  const safe = {library}({argument});"
    source = "function handle(raw) {\n" + guard + line + "\n  consume(safe);\n}\n"
    (tmp_path / f"app.{suffix}").write_text(source)
    sink_line = next(i for i, text in enumerate(source.splitlines(), 1) if "consume(safe)" in text)
    reply = json.dumps({"kind": "known_safe_call", "validator_source_line": line,
                        "variable_name": "raw", "charset": "", "forbidden": "",
                        "library_call": library, "primitive_input": True,
                        "driver": "mysql", "sql_mode_verified": True})
    result = t1.try_tier1b(fix_diff="+" + line + "\n", repo_root=tmp_path,
                          sink_uri=f"app.{suffix}", sink_line=sink_line, sink_class="sqli",
                          language=language, complete=lambda _system, _user: reply)
    assert result.status is t1.Tier0Status.NOT_APPLICABLE
    assert result.artifact is None
    assert result.extras["unverified_source_contracts"] == [REQUIREMENT]


@pytest.mark.parametrize("library", ["connection.escape", "conn.escape"])
@pytest.mark.parametrize("language", ["javascript", "typescript"])
def test_sql_escape_profiles_preserve_candidate_names(library, language):
    assert library in sanitizer_callables_for_cwe("CWE-89", language)
    assert source_contracts_for_callable(library, "CWE-89", language) == frozenset({REQUIREMENT})
