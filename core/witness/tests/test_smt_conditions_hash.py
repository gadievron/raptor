"""Width and fail-direction of the SMT-feasibility condition binding.

The verifier equates record and path by string equality of
``smt_conditions_hash`` — a suppression-direction binding whose both
sides are attacker-influenceable (path_conditions are LLM-extracted
over a hostile target). A truncated 64-bit prefix left a ~2^32-work
offline birthday collision as the transplant margin, so the binding
carries the full digest; legacy truncated records must fail CLOSED
(demote to unverified), never verify.
"""

from core.witness.provenance import (
    PROVENANCE_KEY,
    smt_conditions_hash,
    stamp_smt_feasibility,
    verify_smt_feasibility,
)


def test_hash_is_full_width():
    digest = smt_conditions_hash(["x > 0", "x < 10"])
    assert len(digest) == 64
    int(digest, 16)  # plain hex


def test_sentinel_unchanged():
    assert smt_conditions_hash([]) == "<no-conditions>"
    assert smt_conditions_hash(None) == "<no-conditions>"


def _stamped_path(tmp_path, conditions_hash):
    conditions = ["x > 0"]
    path = {"finding_id": "F-1", "path_conditions": list(conditions)}
    record = {"feasible": False, "conditions_hash": conditions_hash}
    stamp_smt_feasibility(path, record, tmp_path)
    path["smt_feasibility"] = record
    return path


def test_fresh_record_verifies(tmp_path):
    full = smt_conditions_hash(["x > 0"])
    path = _stamped_path(tmp_path, full)
    if path["smt_feasibility"].get(PROVENANCE_KEY) is None:
        import pytest

        pytest.skip("no provenance key available in this environment")
    assert verify_smt_feasibility(path, tmp_path)


def test_truncated_legacy_record_fails_closed(tmp_path):
    full = smt_conditions_hash(["x > 0"])
    path = _stamped_path(tmp_path, full[:16])
    if path["smt_feasibility"].get(PROVENANCE_KEY) is None:
        import pytest

        pytest.skip("no provenance key available in this environment")
    # The MAC itself is genuine (it covers the truncated value), but
    # the path binding recomputes at full width — the record demotes
    # to unverified instead of suppressing on a 64-bit margin.
    assert not verify_smt_feasibility(path, tmp_path)
