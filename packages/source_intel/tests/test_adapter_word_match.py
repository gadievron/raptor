"""Attribute-evidence matching must be word-bounded, not substring.

Pre-fix the adapter's attribute loop used ``ev.function_name not in
snippet`` — an annotated function named ``free`` matched a snippet
mentioning ``freelist`` and fired EXPLOITABLE on a prefix collision.
"""

from __future__ import annotations

from unittest.mock import patch

from core.dataflow.finding import Finding, Step
from core.dataflow.validator import ValidatorVerdict
from packages.source_intel.adapter import SourceIntelValidator
from packages.source_intel.analyze import (
    KIND_NONNULL,
    AttributeEvidence,
    SourceIntelResult,
)


def _finding(file_path: str, snippet: str) -> Finding:
    return Finding(
        finding_id="test_finding",
        producer="codeql",
        rule_id="cpp/null-dereference",
        message="test",
        source=Step(file_path=file_path, line=1, column=1,
                    snippet=snippet, label="source"),
        sink=Step(file_path=file_path, line=2, column=1,
                  snippet="", label="sink"),
        intermediate_steps=(),
        raw={},
    )


def _result_with_annotated(function_name: str) -> SourceIntelResult:
    return SourceIntelResult(
        attributes=(AttributeEvidence(
            kind=KIND_NONNULL,
            function_name=function_name,
            location=("test.c", 1),
            match_source="literal",
            raw_match="__attribute__((nonnull))",
        ),),
    )


def _validate(tmp_path, snippet: str, function_name: str) -> ValidatorVerdict:
    (tmp_path / "test.c").write_text("int free(void*);\n")
    finding = _finding(str(tmp_path / "test.c"), snippet)
    with patch(
        "packages.source_intel.adapter.analyze",
        return_value=_result_with_annotated(function_name),
    ):
        return SourceIntelValidator(repo_root=tmp_path).validate(finding)


def test_substring_collision_does_not_fire(tmp_path):
    # `free` annotated; snippet only mentions `freelist` — no evidence.
    verdict = _validate(tmp_path, "q = freelist->next;", "free")
    assert verdict == ValidatorVerdict.UNCERTAIN


def test_suffix_collision_does_not_fire(tmp_path):
    verdict = _validate(tmp_path, "pfree(ctx);", "free")
    assert verdict == ValidatorVerdict.UNCERTAIN


def test_word_bounded_reference_still_fires(tmp_path):
    verdict = _validate(tmp_path, "free(p); *p = 1;", "free")
    assert verdict == ValidatorVerdict.EXPLOITABLE
