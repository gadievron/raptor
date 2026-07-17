"""LabeledAttempt schema tests — round-trip + validation."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# parents[3] = repo root
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from core.labeled_attempts.types import (  # noqa: E402
    CodeQLEvidence,
    LabeledAttempt,
    SandboxEvidence,
    WebEvidence,
    compute_finding_signature,
)


# --------------------------------------------------------------------------
# Validation — exactly-one-oracle constraint
# --------------------------------------------------------------------------


def _sandbox_evidence() -> SandboxEvidence:
    return SandboxEvidence(
        bytes_hash="0" * 64,
        bytes_len=128,
        observed_outcome="sanitizer_report",
        outcome_detail={"sanitizer": "address"},
        target_binary_hash="b" * 64,
        commit_sha="abc1234",
        mitigations_active=["canary", "NX"],
        arch="x86_64",
        exploit_code="int main() { return 0; }",
        exploit_language="c",
    )


def _codeql_evidence() -> CodeQLEvidence:
    return CodeQLEvidence(
        query_ql="import python\nfrom DataFlow::Node n select n",
        before_count=2,
        after_count=0,
        is_sound=True,
        sink_class="SQL",
    )


def _web_evidence() -> WebEvidence:
    return WebEvidence(
        target_url="http://target.example/api/exec",
        http_request={"method": "POST", "path": "/api/exec", "body": "{{7*7}}"},
        response_evidence={"status": 200, "body_excerpt": "49"},
        evidence_type="ssti",
        timestamp_iso="2026-06-03T14:05:32Z",
    )


def _attempt(**overrides) -> LabeledAttempt:
    base = dict(
        finding_id="FND-001",
        finding_signature="abcd" * 8,
        cwe="CWE-787",
        outcome="success",
        sandbox_evidence=_sandbox_evidence(),
        producing_model="claude-haiku-4-5",
        prompt_version="v3",
        tools_used=("find_symbol", "disassemble"),
        iterations=8,
        cost_usd=0.12,
        reproducible=True,
        timestamp="2026-06-03T14:05:32+00:00",
    )
    base.update(overrides)
    return LabeledAttempt(**base)


def test_attempt_requires_exactly_one_oracle():
    with pytest.raises(ValueError, match="exactly one oracle evidence"):
        LabeledAttempt(
            finding_id="FND-001",
            finding_signature="abcd" * 8,
            cwe="CWE-787",
            outcome="success",
            sandbox_evidence=None,
            codeql_evidence=None,
            web_evidence=None,
        )


def test_attempt_rejects_two_oracles():
    with pytest.raises(ValueError, match="exactly one oracle evidence"):
        LabeledAttempt(
            finding_id="FND-001",
            finding_signature="abcd" * 8,
            cwe="CWE-787",
            outcome="success",
            sandbox_evidence=_sandbox_evidence(),
            codeql_evidence=_codeql_evidence(),
        )


def test_attempt_accepts_each_oracle():
    a = _attempt()
    assert a.oracle == "sandbox"

    b = _attempt(sandbox_evidence=None, codeql_evidence=_codeql_evidence())
    assert b.oracle == "codeql"

    c = _attempt(
        sandbox_evidence=None,
        web_evidence=_web_evidence(),
        reproducible=False,
    )
    assert c.oracle == "web"


def test_attempt_rejects_bad_outcome():
    with pytest.raises(ValueError, match="unknown outcome"):
        _attempt(outcome="totally-broken")


def test_attempt_requires_spine_fields():
    with pytest.raises(ValueError, match="finding_id is required"):
        _attempt(finding_id="")
    with pytest.raises(ValueError, match="finding_signature is required"):
        _attempt(finding_signature="")
    with pytest.raises(ValueError, match="cwe is required"):
        _attempt(cwe="")


def test_attempt_auto_populates_timestamp():
    a = _attempt(timestamp="")
    assert a.timestamp  # ISO format with timezone
    assert "T" in a.timestamp


# --------------------------------------------------------------------------
# Round-trip serialisation
# --------------------------------------------------------------------------


def test_sandbox_round_trip():
    original = _attempt()
    blob = original.to_dict()
    restored = LabeledAttempt.from_dict(blob)
    assert restored == original


def test_codeql_round_trip():
    original = _attempt(
        sandbox_evidence=None,
        codeql_evidence=_codeql_evidence(),
        cwe="CWE-89",
    )
    blob = original.to_dict()
    restored = LabeledAttempt.from_dict(blob)
    assert restored == original


def test_web_round_trip():
    original = _attempt(
        sandbox_evidence=None,
        web_evidence=_web_evidence(),
        cwe="CWE-1336",
        reproducible=False,
    )
    blob = original.to_dict()
    restored = LabeledAttempt.from_dict(blob)
    assert restored == original


def test_unknown_keys_ignored_on_load():
    """Future schema additions don't break old reads."""
    original = _attempt()
    blob = original.to_dict()
    blob["future_field"] = "some unknown future value"
    blob["sandbox_evidence"]["future_subfield"] = 42
    # The unknown sandbox field would actually cause SandboxEvidence
    # construction to fail — that's expected for a frozen dataclass.
    # The top-level future field should be ignored cleanly.
    del blob["sandbox_evidence"]["future_subfield"]
    restored = LabeledAttempt.from_dict(blob)
    assert restored == original  # extra top-level field tolerated


def test_tools_used_round_trips_as_tuple():
    """JSON serialises tuples as lists; ensure we restore the tuple
    on load (frozen dataclass requires hashable fields)."""
    original = _attempt(tools_used=("a", "b", "c"))
    blob = original.to_dict()
    assert isinstance(blob["tools_used"], list)
    restored = LabeledAttempt.from_dict(blob)
    assert isinstance(restored.tools_used, tuple)
    assert restored.tools_used == ("a", "b", "c")


# --------------------------------------------------------------------------
# finding_signature helper
# --------------------------------------------------------------------------


def test_compute_finding_signature_stable():
    """Same inputs → same signature."""
    a = compute_finding_signature(
        cwe="CWE-787", file_path="src/foo.c",
        function="parse", line=42,
    )
    b = compute_finding_signature(
        cwe="CWE-787", file_path="src/foo.c",
        function="parse", line=42,
    )
    assert a == b


def test_compute_finding_signature_trusts_caller_cwe_spelling():
    """Signature hashes the caller-supplied CWE spelling verbatim
    (whitespace stripped). Callers who want dedup across spellings
    (``"cwe-787"`` vs ``"CWE-787"``) must canonicalise upstream
    before calling. Signature-level canonicalisation would silently
    invalidate every existing on-disk
    ``<project>/labeled_attempts/<signature>/`` directory written
    under a different spelling."""
    a = compute_finding_signature(
        cwe="cwe-787", file_path="src/foo.c",
        function="parse", line=42,
    )
    b = compute_finding_signature(
        cwe="CWE-787", file_path="src/foo.c",
        function="parse", line=42,
    )
    assert a != b


def test_compute_finding_signature_distinct_for_distinct_inputs():
    sig_a = compute_finding_signature(
        cwe="CWE-787", file_path="src/foo.c",
        function="parse", line=42,
    )
    sig_b = compute_finding_signature(
        cwe="CWE-416", file_path="src/foo.c",   # different CWE
        function="parse", line=42,
    )
    sig_c = compute_finding_signature(
        cwe="CWE-787", file_path="src/foo.c",
        function="parse", line=43,              # different line
    )
    assert sig_a != sig_b
    assert sig_a != sig_c
    assert sig_b != sig_c


# --------------------------------------------------------------------------
# Adversarial-input validation (from session adversarial review 2026-06-03)
# --------------------------------------------------------------------------


def test_path_traversal_signature_rejected():
    """A finding_signature with path-traversal sequences cannot escape
    the finding-signature-keyed directory on disk."""
    with pytest.raises(ValueError, match="hex chars"):
        _attempt(finding_signature="../../../etc/escape")


def test_signature_with_slash_rejected():
    """Plain forward-slash also rejected (not just `..` sequences)."""
    with pytest.raises(ValueError, match="hex chars"):
        _attempt(finding_signature="aaaa/bbbb")


def test_signature_with_backslash_rejected():
    """Backslash rejected too (Windows path-style attack)."""
    with pytest.raises(ValueError, match="hex chars"):
        _attempt(finding_signature="aaaa\\bbbb")


def test_signature_with_unicode_rejected():
    """Non-ASCII characters rejected."""
    with pytest.raises(ValueError, match="hex chars"):
        _attempt(finding_signature="‮evil")  # RTL override


def test_signature_with_nul_rejected():
    """NUL bytes can confuse filesystem APIs; rejected."""
    with pytest.raises(ValueError, match="hex chars"):
        _attempt(finding_signature="aaaa\x00bbbb")


def test_signature_too_short_rejected():
    """Below the 8-char minimum rejected."""
    with pytest.raises(ValueError, match="hex chars"):
        _attempt(finding_signature="abc")


def test_signature_too_long_rejected():
    """Above the 64-char maximum rejected (filesystem name limits)."""
    with pytest.raises(ValueError, match="hex chars"):
        _attempt(finding_signature="a" * 65)


def test_signature_compute_helper_output_accepted():
    """The output of compute_finding_signature is by construction
    valid — sanity-check."""
    sig = compute_finding_signature(
        cwe="CWE-787", file_path="src/foo.c", function="f", line=1,
    )
    # Should not raise
    _attempt(finding_signature=sig)


# --------------------------------------------------------------------------
# Timestamp normalisation
# --------------------------------------------------------------------------


def test_malformed_timestamp_rejected():
    """A non-ISO-parseable timestamp is rejected at construction —
    not silently mismatched with the on-disk filename later."""
    with pytest.raises(ValueError, match="ISO-8601 parseable"):
        _attempt(timestamp="not-a-timestamp")


def test_timestamp_empty_falls_back_to_now():
    """Empty timestamp defaults to now() — convenience for callers
    that haven't seen a real wall-clock yet."""
    a = _attempt(timestamp="")
    assert a.timestamp  # populated
    assert "T" in a.timestamp


def test_exemplars_used_round_trips_as_tuple():
    """The new exemplars_used field carries the L3 exemplar_ids that
    were in the prompt at attempt time (Phase B unit #4). JSON
    serialises tuples as lists; ensure we restore the tuple."""
    original = _attempt(exemplars_used=("e1", "e2", "e3"))
    blob = original.to_dict()
    assert isinstance(blob["exemplars_used"], list)
    restored = LabeledAttempt.from_dict(blob)
    assert isinstance(restored.exemplars_used, tuple)
    assert restored.exemplars_used == ("e1", "e2", "e3")


def test_exemplars_used_default_empty():
    """Records produced before unit #4 (and tests that don't set it)
    must continue to work; default = empty tuple."""
    a = _attempt()
    assert a.exemplars_used == ()


def test_timestamp_preserved_when_valid():
    """Valid ISO timestamps pass through unchanged."""
    a = _attempt(timestamp="2026-06-03T14:05:32+00:00")
    assert a.timestamp == "2026-06-03T14:05:32+00:00"


# --------------------------------------------------------------------------
# SandboxEvidence — size + format guards (deferred items from review)
# --------------------------------------------------------------------------


def test_negative_bytes_len_rejected():
    with pytest.raises(ValueError, match="bytes_len must be >= 0"):
        SandboxEvidence(
            bytes_hash="0" * 64,
            bytes_len=-1,
            observed_outcome="not_run",
        )


def test_bytes_len_above_cap_rejected():
    with pytest.raises(ValueError, match="soft cap"):
        SandboxEvidence(
            bytes_hash="0" * 64,
            bytes_len=10**9,           # 1 GB
            observed_outcome="not_run",
        )


def test_bytes_hash_wrong_length_rejected():
    """Non-empty bytes_hash must be 64-char hex (SHA-256)."""
    with pytest.raises(ValueError, match="64-char hex"):
        SandboxEvidence(
            bytes_hash="abc",           # too short
            bytes_len=8,
            observed_outcome="not_run",
        )


def test_bytes_hash_non_hex_rejected():
    with pytest.raises(ValueError, match="64-char hex"):
        SandboxEvidence(
            bytes_hash="z" * 64,         # 'z' not in [0-9a-f]
            bytes_len=8,
            observed_outcome="not_run",
        )


def test_bytes_hash_empty_allowed():
    """Empty bytes_hash means 'no bytes recorded' — rare but valid."""
    e = SandboxEvidence(
        bytes_hash="",
        bytes_len=0,
        observed_outcome="not_run",
    )
    assert e.bytes_hash == ""


def test_exploit_code_oversized_rejected():
    huge = "a" * (2 * 1024 * 1024)
    with pytest.raises(ValueError, match="exploit_code length"):
        SandboxEvidence(
            bytes_hash="0" * 64,
            bytes_len=8,
            observed_outcome="not_run",
            exploit_code=huge,
        )


def test_outcome_detail_non_json_serialisable_rejected():
    """A producer that puts a set / datetime in outcome_detail gets a
    clear error at construction, not a confusing trace at write."""
    with pytest.raises(ValueError, match="JSON-serialisable"):
        SandboxEvidence(
            bytes_hash="0" * 64,
            bytes_len=8,
            observed_outcome="not_run",
            outcome_detail={"bad": {1, 2, 3}},  # set is not JSON
        )


# --------------------------------------------------------------------------
# from_dict — error UX (deferred item from review)
# --------------------------------------------------------------------------


def test_from_dict_names_offending_subrecord():
    """A malformed sandbox_evidence block surfaces with the subrecord
    name + the underlying cause — not a bare TypeError on nested
    construction."""
    original = _attempt()
    blob = original.to_dict()
    blob["sandbox_evidence"]["bytes_len"] = -42
    with pytest.raises(ValueError, match="SandboxEvidence.*sandbox_evidence"):
        LabeledAttempt.from_dict(blob)


def test_from_dict_names_finding_id_on_spine_error():
    """A malformed top-level field (not in a sub-record) surfaces with
    the finding_id so the operator knows which on-disk record is bad."""
    blob = _attempt().to_dict()
    blob["outcome"] = "nonsense-value"
    with pytest.raises(ValueError, match="finding_id='FND-001'"):
        LabeledAttempt.from_dict(blob)
