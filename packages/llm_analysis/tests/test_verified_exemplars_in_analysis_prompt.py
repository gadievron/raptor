"""Tests for the verified-outcome exemplar wire-in to
``build_analysis_prompt_bundle`` (Tier-3 retrieval).

When the caller supplies a corpus of VerifiedOutcomes, the exemplar slot
is served L3-retrieval-first (recency / dedup / diversity ranked records
from the labeled-attempt pool), with the supplied corpus rendered as the
fallback. Default (no corpus) leaves the prompt unchanged — so a first
run with no prior outcomes is byte-for-byte as before.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from core.labeled_attempts import RetrievedExemplar
from core.labeled_attempts.view import Oracle, OutcomeStatus, VerifiedOutcome
from packages.llm_analysis.prompts.analysis import build_analysis_prompt_bundle


@pytest.fixture(autouse=True)
def _empty_l3_pool(monkeypatch):
    """The exemplar slot tries L3 retrieval before the supplied corpus;
    pin the pool empty (and active-project discovery off) so these
    tests only see the state they construct. Retrieval-path tests
    re-patch inside."""
    monkeypatch.setattr(
        "core.labeled_attempts.retrieval.retrieve_exemplars",
        lambda **kw: [],
    )
    monkeypatch.setattr(
        "core.run.output._resolve_active_project", lambda: None,
    )


def _retrieved_exemplar(exemplar_id="abcd1234-2026-06-03T14:05:32+00:00"):
    return RetrievedExemplar(
        exemplar_id=exemplar_id,
        cwe="CWE-787",
        finding_summary="CWE-787 · finding=FND-1",
        exploit_code="abort();",
        evidence="observed=sanitizer_report",
        environment="x86_64",
        timestamp="2026-06-03T14:05:32+00:00",
    )


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


# ---------------------------------------------------------------------------
# L3-retrieval-first slot + exemplar-id feedback
# ---------------------------------------------------------------------------


def test_retrieval_serves_slot_ahead_of_corpus(monkeypatch):
    """When the labeled-attempt pool has entries for the finding's CWE,
    the retrieved exemplars serve the slot (still inside the untrusted
    user envelope, never the system prompt)."""
    ex = _retrieved_exemplar()
    monkeypatch.setattr(
        "core.labeled_attempts.retrieval.retrieve_exemplars",
        lambda **kw: [ex],
    )
    bundle = _bundle(verified_outcomes=[_outcome()])
    user = _user_message(bundle)
    assert "## RAPTOR-verified exemplars" in user
    assert ex.exemplar_id in user
    assert "RAPTOR-verified exemplars" not in _system_message(bundle)


def test_exemplar_usage_records_retrieved_ids(monkeypatch):
    """Which L3 exemplars landed in the prompt travels back through the
    caller-supplied ``exemplar_usage`` dict (PromptBundle is frozen) —
    same shape as ``LabeledAttempt.exemplars_used``."""
    ex = _retrieved_exemplar()
    monkeypatch.setattr(
        "core.labeled_attempts.retrieval.retrieve_exemplars",
        lambda **kw: [ex],
    )
    usage: dict = {}
    _bundle(verified_outcomes=[_outcome()], exemplar_usage=usage)
    assert usage["exemplars_used"] == [ex.exemplar_id]


def test_exemplar_usage_untouched_on_legacy_fallback():
    """The fallback VerifiedOutcome corpus has no exemplar ids — the
    usage dict stays empty so nothing false is persisted."""
    usage: dict = {}
    bundle = _bundle(verified_outcomes=[_outcome()], exemplar_usage=usage)
    assert "exemplars_used" not in usage
    # Fallback block still rendered from the supplied corpus.
    assert "## RAPTOR-verified exemplars" in _user_message(bundle)


def test_retrieval_gated_off_without_corpus(monkeypatch):
    """No supplied corpus means the exemplar slot stays off even when
    the pool has entries — the caller's opt-in gate is preserved."""
    monkeypatch.setattr(
        "core.labeled_attempts.retrieval.retrieve_exemplars",
        lambda **kw: [_retrieved_exemplar()],
    )
    assert "RAPTOR-verified exemplars" not in _all_text(_bundle())
