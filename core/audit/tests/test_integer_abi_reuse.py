"""A source hash alone cannot reauthorize a target-dependent integer disproof."""

import pytest

from core.audit.gaps import _reuse_block_class, _reuse_ineligibility
from core.audit.tests.test_verdict_reuse import _entry, _write_target


@pytest.mark.parametrize("receipts,body", [
    pytest.param(["smt:disproof:unsat"], "review", id="disproof-receipt"),
    pytest.param(["smt:check-overflow"], "review", id="overflow-receipt"),
    pytest.param([], "[smt-disproof: integer overflow impossible (Z3 UNSAT)]\nreview", id="legacy-body-marker"),
])
def test_integer_clean_requires_fresh_target_context(tmp_path, receipts, body):
    target = _write_target(tmp_path)
    entry = _entry(target, evidence_tools=receipts, body=body, clean_basis="verdict")
    reason = _reuse_ineligibility(entry, "auth.c:check_pw", current_strategies_fn=None, current_model=None)
    assert reason == "integer disproof requires target ABI revalidation"
    assert _reuse_block_class(reason) == "integer_abi_unbound"


def test_other_clean_verdicts_keep_existing_reuse_policy(tmp_path):
    target = _write_target(tmp_path)
    entry = _entry(target, evidence_tools=[], body="review", clean_basis="verdict")
    assert _reuse_ineligibility(entry, "auth.c:check_pw", current_strategies_fn=None, current_model=None) is None
