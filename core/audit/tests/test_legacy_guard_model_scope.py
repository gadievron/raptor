"""Legacy guard assignments cannot verify defects or survive as old proofs."""

import pytest

from core.audit import evidence_grade as grade
from core.audit.orchestrator import ReviewOutcome, _promotion_grade_receipt
from core.audit.smt_evidence import LEGACY_GUARD_MODEL_NAMESPACES
from core.audit.gaps import _reuse_block_class, _reuse_ineligibility
from core.audit.tests.test_verdict_reuse import _entry, _write_target


@pytest.mark.parametrize("name", sorted(LEGACY_GUARD_MODEL_NAMESPACES))
@pytest.mark.parametrize("suffix", ["", ":witness", ":unrecognized-proof"])
@pytest.mark.parametrize("wrapper", ["", "clean-refuted:"])
@pytest.mark.parametrize("fallback", [False, True])
def test_guard_models_never_gain_verification_authority(monkeypatch, name, suffix, wrapper, fallback):
    if fallback:
        monkeypatch.setattr(grade, "_channel_detection_classifier", lambda *args: None)
    receipt = wrapper + name + suffix
    assert not grade.is_tool_evidence(receipt)
    assert not grade.is_verification_evidence(receipt)
    assert not _promotion_grade_receipt(receipt)
    outcome = ReviewOutcome(file="owned.c", function="copy", status="finding", body="model only",
                            evidence_tool=receipt, tools_dispatched={"smt"})
    assert outcome.compute_tier() == "llm_only"
    assert grade.is_verification_evidence(receipt + "+lifecycle")


@pytest.mark.parametrize("name", sorted(LEGACY_GUARD_MODEL_NAMESPACES))
@pytest.mark.parametrize("verdict", ["clean", "finding", "suspicious", "dormant"])
@pytest.mark.parametrize("wrapper", ["", "clean-refuted:"])
def test_stored_guard_model_verdicts_need_revalidation(tmp_path, name, verdict, wrapper):
    target = _write_target(tmp_path)
    entry = _entry(target, verdict=verdict, evidence_tools=["semgrep:owned+" + wrapper + name + ":witness"])
    reason = _reuse_ineligibility(entry, "auth.c:check_pw", current_strategies_fn=None, current_model=None)
    assert reason == "legacy guard-model receipt requires fresh review"
    assert _reuse_block_class(reason) == "legacy_guard_model"


def test_independent_receipts_keep_existing_reuse_policy(tmp_path):
    target = _write_target(tmp_path)
    entry = _entry(target, verdict="finding", evidence_tools=["semgrep:owned"])
    assert _reuse_ineligibility(entry, "auth.c:check_pw", current_strategies_fn=None, current_model=None) is None
