"""S29 Phase C — `_map_status` decision-tree truth-table lock.

`_map_status` (src/cve_env/agent/loop.py:279-356) maps the SDK's
``stop_reason`` plus mid-run signals (refusal latch, verify_passed,
give_up_reason, launched_ok, verify_attempted) to one of the canonical
``OutcomeStatus`` literals. The function gathered branches from many
historical phases (44.1, 46.1, 52, 57, I3) and any future refactor must
keep the whole table consistent.

This test parametrizes the 11 semantically distinct branches. Each row
exercises ONE branch deterministically. Re-running this file is faster
than ``rg`` over the audit corpus when classifier behavior is suspected.

If a row goes RED, classify the failure:
- Branch logic genuinely changed (intended) → update the row
- Branch logic accidentally changed (regression) → fix the source
"""

from __future__ import annotations

from typing import Any

import pytest
pytest.importorskip("claude_agent_sdk")

from cve_env.agent.loop import _map_status, _StreamState, _terminal_status_for_result
from cve_env.models import OutcomeStatus


def _state(
    *,
    refusal_seen: bool = False,
    refusal_turn: int | None = None,
    verify_passed: bool = False,
    verify_passed_turn: int | None = None,
    give_up_reason: str = "",
    launched_ok: bool = False,
    verify_attempted: bool = False,
    has_version: bool = False,
    has_smoke: bool = False,
) -> _StreamState:
    """Build a `_StreamState` with only the fields `_map_status` reads."""
    s = _StreamState()
    s.refusal_stop_reason_seen = refusal_seen
    s.refusal_stop_reason_turn = refusal_turn
    s.verify_passed = verify_passed
    s.verify_passed_turn = verify_passed_turn
    s.give_up_reason = give_up_reason
    s.launched_ok = launched_ok
    s.verify_attempted = verify_attempted
    s.passing_verify_has_version_assertion = has_version
    s.passing_verify_has_functional_smoke = has_smoke
    return s


@pytest.mark.parametrize(
    ("stop_reason", "state_kwargs", "expected_status"),
    [
        # 1. Current stop_reason is refusal → incomplete (Phase 44.1).
        pytest.param(
            "refusal",
            {},
            "interrupted",
            id="refusal_current_stop_reason",
        ),
        # 2. SDK error message containing 'usage policy' → incomplete.
        pytest.param(
            "API Error 400 usage policy violation",
            {},
            "interrupted",
            id="usage_policy_in_stop_reason",
        ),
        # 3. Mid-run refusal latched, NO recovery (verify never passed) →
        # incomplete (Phase 46.1).
        pytest.param(
            "end_turn",
            {"refusal_seen": True, "refusal_turn": 3},
            "interrupted",
            id="refusal_seen_no_recovery",
        ),
        # 4. Mid-run refusal latched, recovery happened (verify passed AFTER
        # refusal turn) → success (I3 fix 2026-05-02).
        pytest.param(
            "end_turn",
            {
                "refusal_seen": True,
                "refusal_turn": 3,
                "verify_passed": True,
                "verify_passed_turn": 5,
                "has_version": True,
                "has_smoke": True,
            },
            "success",
            id="refusal_then_recovery_full_success",
        ),
        # 5. Verify passed, version + smoke both present → success.
        pytest.param(
            "end_turn",
            {
                "verify_passed": True,
                "has_version": True,
                "has_smoke": True,
            },
            "success",
            id="verify_passed_full",
        ),
        # 6. Verify passed but missing version+smoke → success_partial.
        pytest.param(
            "end_turn",
            {"verify_passed": True},
            "verified_partial",
            id="verify_passed_partial",
        ),
        # 7. give_up_reason set, no verify pass → unresolvable.
        pytest.param(
            "end_turn",
            {"give_up_reason": "no_image"},
            "unresolvable",
            id="give_up_unresolvable",
        ),
        # 8. launched_ok but never called verify → launched_unverified
        # (Phase 57 anti-pattern).
        pytest.param(
            "end_turn",
            {"launched_ok": True, "verify_attempted": False},
            "launched_no_verify",
            id="launched_unverified_phase57",
        ),
        # 9. Plain end_turn, no launch, no verify, no give_up → no_verify_pass.
        pytest.param(
            "end_turn",
            {},
            "verify_failed",
            id="end_turn_no_progress",
        ),
        # 10. SDK budget cap → budget_exhausted.
        pytest.param(
            "budget_exceeded",
            {},
            "budget_exhausted",
            id="budget_exhausted",
        ),
        # 11. SDK turn cap → turn_cap.
        pytest.param(
            "max_turns",
            {},
            "turn_cap",
            id="turn_cap_max_turns",
        ),
        # 12. BUG-007: refusal latched mid-run BUT terminal stop_reason is
        # a budget cap → budget_exhausted, NOT incomplete. Cap signal in the
        # CURRENT stop_reason represents the SDK's terminal cause and must
        # win over the latched refusal-mid-run flag. Forensic:
        # CVE-2022-25760 in bench50-20260508-085427 (cost=$3.05, cap=$1.80,
        # refusal at turn 80, stop_reason='budget_exceeded') was misclassified
        # as 'incomplete' under the pre-fix priority.
        pytest.param(
            "budget_exceeded",
            {"refusal_seen": True, "refusal_turn": 80},
            "budget_exhausted",
            id="bug007_refusal_seen_then_budget_cap",
        ),
        # 13. BUG-007 sibling: refusal latched mid-run + terminal turn cap
        # → turn_cap, NOT incomplete (same precedence rule as 12).
        pytest.param(
            "max_turns",
            {"refusal_seen": True, "refusal_turn": 80},
            "turn_cap",
            id="bug007_refusal_seen_then_turn_cap",
        ),
        # 14. BUG-007 regression-lock: refusal latched mid-run + terminal
        # end_turn (no cap, no verify pass) MUST stay 'incomplete'. The
        # priority change is narrow — only cap signals override; ordinary
        # end_turn does not. Locks current Phase 46.1 behavior so the fix
        # doesn't widen the override.
        pytest.param(
            "end_turn",
            {"refusal_seen": True, "refusal_turn": 80, "verify_passed": False},
            "interrupted",
            id="bug007_refusal_seen_end_turn_stays_incomplete",
        ),
        # 15. BUG-008: terminal stop_reason=budget_exceeded + verify_passed=True
        # (NO refusal latch) → budget_exhausted, NOT success/success_partial.
        # Cap signal in the CURRENT stop_reason wins over the verify-passed
        # branch. Forensic: CVE-2022-30352 (cost=$1.85, status=success_partial,
        # verify_passed=true, stop_reason=budget_exceeded) and CVE-2022-31531
        # (cost=$1.91, same shape) in bench50-20260507-021212. Pre-fix, the
        # verify_passed branch at loop.py:557 short-circuits BEFORE the
        # budget check at loop.py:626 — same family as BUG-007 but in a
        # different branch.
        pytest.param(
            "budget_exceeded",
            {"verify_passed": True, "has_version": True, "has_smoke": True},
            "budget_exhausted",
            id="bug008_verify_passed_then_budget_cap",
        ),
        # 16. BUG-008 sibling: same shape with terminal turn cap.
        pytest.param(
            "max_turns_reached",
            {"verify_passed": True, "has_version": True, "has_smoke": True},
            "turn_cap",
            id="bug008_verify_passed_then_turn_cap",
        ),
        # 17. BUG-008 minimal-state variant: verify_passed=True without full
        # version/smoke markers (Phase 52 demote → success_partial pre-budget)
        # + budget_exceeded → budget_exhausted. This is the EXACT shape of
        # the 2 forensic CVEs (Phase 52.1 demoted to success_partial; cap
        # then breached).
        pytest.param(
            "budget_exceeded",
            {"verify_passed": True},
            "budget_exhausted",
            id="bug008_verify_passed_minimal_then_budget_cap",
        ),
        # 18. BUG-008 regression-lock: verify_passed=True + ordinary end_turn
        # (no cap signal) MUST stay verify-driven (success/success_partial).
        # Locks the priority change to NARROW — only cap signals override
        # the verify_passed branch; ordinary end_turn does not.
        pytest.param(
            "end_turn",
            {"verify_passed": True, "has_version": True, "has_smoke": True},
            "success",
            id="bug008_verify_passed_end_turn_stays_success",
        ),
    ],
)
def test_map_status_truth_table(
    stop_reason: str,
    state_kwargs: dict[str, Any],
    expected_status: OutcomeStatus,
) -> None:
    state = _state(**state_kwargs)
    status, reason = _map_status(stop_reason, state)
    assert status == expected_status, (
        f"_map_status({stop_reason!r}, {state_kwargs!r}) returned "
        f"{status!r}, expected {expected_status!r}. reason={reason!r}"
    )


def test_map_status_unknown_stop_reason_falls_through_to_error() -> None:
    """Defensive: a stop_reason we don't recognize and don't have signals
    for should classify as 'error', not silently as success/incomplete.
    Lock the fallthrough so future stop_reason additions don't accidentally
    swallow unknowns."""
    status, reason = _map_status("transport_disconnected", _state())
    assert status == "error", (
        f"unknown stop_reason should fall through to 'error', "
        f"got {status!r} with reason={reason!r}"
    )
    assert "transport_disconnected" in reason


def test_map_status_empty_stop_reason_classified_as_error() -> None:
    """Defensive: empty stop_reason with no other signals → 'error'
    (with reason='unknown'). Locks the final-fallthrough branch."""
    status, reason = _map_status("", _state())
    assert status == "error"
    assert reason == "unknown"


# =============================================================================
# _terminal_status_for_result — sibling of _map_status (audit terminal status)
# =============================================================================


def test_terminal_status_verify_passed_then_budget_is_budget_exhausted() -> None:
    """BUG-008 sibling fix: _terminal_status_for_result must NOT report
    'final_success' for runs that hit the budget cap, even if verify
    passed mid-run. Cap signal in stop_reason wins. Forensic: same 2 CVEs
    as the _map_status fix (CVE-2022-30352, CVE-2022-31531) — the audit
    log was misclassifying the terminal entry as 'final_success' while
    the Outcome correctly classifies as budget_exhausted (post-fix).
    AuditStatus has 'budget_exhausted' available; emit it here."""
    result = _terminal_status_for_result(
        _state(verify_passed=True, has_version=True, has_smoke=True),
        "budget_exceeded",
    )
    assert result == "budget_exhausted", (
        f"verify_passed=True + stop_reason=budget_exceeded must map to "
        f"AuditStatus 'budget_exhausted', got {result!r}"
    )


def test_terminal_status_verify_passed_then_max_turns_is_final_turn_cap() -> None:
    """BUG-008 sibling fix: same shape with terminal turn cap → 'final_turn_cap'."""
    result = _terminal_status_for_result(
        _state(verify_passed=True, has_version=True, has_smoke=True),
        "max_turns_reached",
    )
    assert result == "final_turn_cap", (
        f"verify_passed=True + stop_reason=max_turns_reached must map to "
        f"AuditStatus 'final_turn_cap', got {result!r}"
    )


def test_terminal_status_verify_passed_end_turn_stays_final_success() -> None:
    """Regression-lock: verify_passed=True + ordinary end_turn (no cap)
    MUST stay 'final_success'. The priority change is narrow — only cap
    signals override; ordinary end_turn does not."""
    result = _terminal_status_for_result(
        _state(verify_passed=True, has_version=True, has_smoke=True),
        "end_turn",
    )
    assert result == "final_success", (
        f"verify_passed=True + end_turn must stay 'final_success', got {result!r}"
    )


def test_terminal_status_no_verify_budget_is_budget_exhausted() -> None:
    """Cap-only path (no verify pass): stop_reason=budget_exceeded must
    map to 'budget_exhausted' regardless of verify state. Locks the new
    branch's behavior on the simpler shape."""
    result = _terminal_status_for_result(_state(), "budget_exceeded")
    assert result == "budget_exhausted"
