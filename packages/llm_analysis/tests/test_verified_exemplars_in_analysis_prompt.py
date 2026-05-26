"""Tests for the verified-outcome exemplar wire-in to
``build_analysis_prompt_bundle`` (Tier-3 retrieval).

When the caller supplies a corpus of VerifiedOutcomes and one ranks against
the finding, a "RAPTOR-verified exemplars" block appears in the system
message. Default (no corpus) leaves the prompt unchanged — so a first run
with no prior outcomes is byte-for-byte as before.
"""

from __future__ import annotations

from datetime import datetime, timezone

from core.verified_outcome import Oracle, OutcomeStatus, VerifiedOutcome
from packages.llm_analysis.prompts.analysis import build_analysis_prompt_bundle


def _system_message(bundle):
    return next(m.content for m in bundle.messages if m.role == "system")


def _user_message(bundle):
    return next(m.content for m in bundle.messages if m.role == "user")


def _outcome(file="src/x.c", cwe="CWE-787", fid="F-1"):
    return VerifiedOutcome(
        finding_id=fid, oracle=Oracle.SANDBOX, status=OutcomeStatus.VERIFIED,
        reproducible=True, evidence={"observed_outcome": "sanitizer_report"},
        cwe_id=cwe, file=file,
        timestamp=datetime(2026, 5, 25, tzinfo=timezone.utc),
    )


def _bundle(**kw):
    base = dict(
        rule_id="cpp/oob", level="warning", file_path="src/x.c",
        start_line=1, end_line=9, message="oob write", cwe_id="CWE-787",
    )
    base.update(kw)
    return build_analysis_prompt_bundle(**base)


def _all_text(bundle):
    return "\n".join(m.content for m in bundle.messages)


def test_no_corpus_leaves_prompt_unchanged():
    assert "RAPTOR-verified exemplars" not in _all_text(_bundle())


def test_matching_outcome_renders_block_in_untrusted_envelope():
    bundle = _bundle(verified_outcomes=[_outcome()])
    user = _user_message(bundle)
    system = _system_message(bundle)
    # The block carries scanned-repo data, so it rides the UNTRUSTED user
    # envelope, NOT the trusted system prompt (the standard posture).
    assert "## RAPTOR-verified exemplars" in user
    assert "F-1" in user and "CWE-787" in user and "`sandbox`" in user
    assert "RAPTOR-verified exemplars" not in system
    # Lands inside an untrusted-block envelope (nonce-tagged).
    assert "verified-exemplars" in user


def test_non_matching_outcome_no_block():
    # Different file + cwe -> score 0 -> no block anywhere.
    other = _outcome(file="other.c", cwe="CWE-22", fid="F-9")
    assert "RAPTOR-verified exemplars" not in _all_text(
        _bundle(verified_outcomes=[other]),
    )


def test_inconclusive_outcome_excluded():
    o = _outcome()
    o.status = OutcomeStatus.INCONCLUSIVE
    assert "RAPTOR-verified exemplars" not in _all_text(
        _bundle(verified_outcomes=[o]),
    )
