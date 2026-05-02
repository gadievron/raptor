"""Root-cause analyzer tests — mock LLM, cover parsing + validation."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from cve_diff.analysis.analyzer import (
    AnalysisError,
    RootCauseAnalyzer,
    _normalize_cwe,
    _parse_json_payload,
)
from cve_diff.core.models import CommitSha, DiffBundle, RepoRef
from cve_diff.llm.client import LLMResponse


def _bundle() -> DiffBundle:
    ref = RepoRef(
        repository_url="https://github.com/curl/curl",
        fix_commit=CommitSha("a" * 40),
        introduced=CommitSha("b" * 40),
        canonical_score=100,
    )
    return DiffBundle(
        cve_id="CVE-2023-38545",
        repo_ref=ref,
        commit_before=CommitSha("b" * 40),
        commit_after=CommitSha("a" * 40),
        diff_text="--- a/foo.c\n+++ b/foo.c\n@@\n-bad\n+good\n",
        files_changed=1,
        bytes_size=42,
    )


# --- JSON payload parser ---------------------------------------------------

def test_parses_bare_json():
    data = _parse_json_payload('{"cwe_id":"CWE-787","x":1}')
    assert data == {"cwe_id": "CWE-787", "x": 1}


def test_parses_fenced_code_block():
    data = _parse_json_payload('```json\n{"cwe_id":"CWE-787"}\n```')
    assert data["cwe_id"] == "CWE-787"


def test_parses_plain_fence_without_language():
    data = _parse_json_payload('```\n{"a":1}\n```')
    assert data == {"a": 1}


def test_extracts_json_from_surrounding_prose():
    """Some models still wrap JSON in prose despite instructions."""
    text = 'Sure! Here is the analysis: {"cwe_id":"CWE-119"} Hope that helps!'
    data = _parse_json_payload(text)
    assert data == {"cwe_id": "CWE-119"}


def test_raises_on_non_json():
    with pytest.raises(AnalysisError):
        _parse_json_payload("I cannot comply with that request.")


# --- CWE normalization -----------------------------------------------------

@pytest.mark.parametrize(
    "raw,expected",
    [
        ("CWE-787", "CWE-787"),
        ("cwe-787", "CWE-787"),
        ("CWE_787", "CWE-787"),
        ("CWE 787", "CWE-787"),
        ("Weakness: CWE-125 (out-of-bounds read)", "CWE-125"),
    ],
)
def test_normalize_cwe_various_shapes(raw, expected):
    assert _normalize_cwe(raw) == expected


def test_normalize_cwe_rejects_garbage():
    with pytest.raises(AnalysisError):
        _normalize_cwe("not-a-cwe")


# --- End-to-end with stubbed client ----------------------------------------

def _stub_client(text: str) -> MagicMock:
    stub = MagicMock()
    stub.complete.return_value = LLMResponse(
        text=text,
        model_id="claude-opus-4-7",
        input_tokens=123,
        output_tokens=45,
        retries=0,
        cost_usd=0.005,
    )
    return stub


def test_analyze_returns_rootcause_from_valid_json():
    analyzer = RootCauseAnalyzer(
        client=_stub_client(
            '{"cwe_id":"CWE-787","vulnerability_type":"Heap overflow",'
            '"summary":"The fix bounds-checks the copy.",'
            '"why_chain":["attacker controls length","memcpy unchecked","overflow"],'
            '"affected_functions":["tool_getparam"],'
            '"confidence":0.9}'
        )
    )
    rc = analyzer.analyze(_bundle())
    assert rc.cwe_id == "CWE-787"
    assert rc.vulnerability_type == "Heap overflow"
    assert rc.why_chain == (
        "attacker controls length",
        "memcpy unchecked",
        "overflow",
    )
    assert rc.affected_functions == ("tool_getparam",)
    assert rc.confidence == 0.9
    assert rc.input_tokens == 123
    assert rc.output_tokens == 45


def test_analyze_truncates_oversize_diff(monkeypatch):
    big = "+" * 50_000
    ref = RepoRef(
        repository_url="https://github.com/x/y",
        fix_commit=CommitSha("a" * 40),
        introduced=CommitSha("b" * 40),
        canonical_score=100,
    )
    bundle = DiffBundle(
        cve_id="CVE-X",
        repo_ref=ref,
        commit_before=CommitSha("b" * 40),
        commit_after=CommitSha("a" * 40),
        diff_text=big,
        files_changed=1,
        bytes_size=len(big),
    )
    stub = _stub_client('{"cwe_id":"CWE-119","vulnerability_type":"x","summary":"s"}')
    analyzer = RootCauseAnalyzer(client=stub, diff_limit=1000)
    analyzer.analyze(bundle)
    rendered_prompt = stub.complete.call_args.kwargs["prompt"]
    assert "[...truncated...]" in rendered_prompt
    # prompt must be smaller than the original 50k diff
    assert len(rendered_prompt) < 50_000


def test_analyze_raises_when_missing_required_field():
    analyzer = RootCauseAnalyzer(client=_stub_client('{"cwe_id":"CWE-787"}'))
    with pytest.raises(AnalysisError):
        analyzer.analyze(_bundle())


def test_analyze_raises_when_cwe_is_garbage():
    analyzer = RootCauseAnalyzer(
        client=_stub_client(
            '{"cwe_id":"unknown","vulnerability_type":"x","summary":"s"}'
        )
    )
    with pytest.raises(AnalysisError):
        analyzer.analyze(_bundle())
