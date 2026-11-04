"""Per-PID output caps include records retained through sampling."""

import pytest

from core.sandbox import audit_budget as audit


@pytest.mark.parametrize("mode", ["category", "global"])
@pytest.mark.parametrize("pid_cap", [1, 3])
def test_sampled_keeps_use_pid_allowance_without_suppressing_other_pids(mode, pid_cap):
    budget = audit.AuditBudget(
        global_cap=8, pid_cap=pid_cap,
        category_caps={"network": 1 if mode == "category" else 100, "setup": 100},
        refill_rates={"network": 0, "setup": 0},
        sampling_rates={"network": 1},
        categorise=lambda action: action, clock=lambda: 0,
    )
    warmup = 0
    if mode == "global":
        for pid in range(100, 108):
            assert budget.evaluate("setup", pid)[0] == audit.KEEP
            warmup += 1
    for pid in (1, 2):
        decisions = [budget.evaluate("network", pid) for _ in range(10)]
        assert sum(action == audit.KEEP for action, _ in decisions) == pid_cap
        pid_markers = [
            marker for _, marker in decisions
            if marker and marker["type"] == "pid_budget_exceeded"
        ]
        assert len(pid_markers) == 1
        assert pid_markers[0]["pid"] == pid
        assert budget.pid_counts[pid] == pid_cap
    assert budget.total_records_emitted == warmup + 2 * pid_cap
    assert sum(budget.pid_counts.values()) == budget.total_records_emitted
    assert sum(budget.dropped_by_category.values()) == 20 - 2 * pid_cap
    assert budget.total_records <= budget.global_cap


def test_sampled_only_pids_share_bounded_tracker_and_marker_eviction():
    budget = audit.AuditBudget(
        global_cap=20, pid_cap=1,
        category_caps={"network": 0}, refill_rates={"network": 0},
        sampling_rates={"network": 1}, clock=lambda: 0,
    )
    budget._pid_dict_cap = 2
    assert budget.evaluate("network", 1)[0] == audit.KEEP
    assert budget.evaluate("network", 1)[1]["type"] == "pid_budget_exceeded"
    assert budget.evaluate("network", 2)[0] == audit.KEEP
    assert budget.evaluate("network", 3)[0] == audit.KEEP
    assert budget.pid_counts == {2: 1, 3: 1}
    assert 1 not in budget._pid_marker_emitted
    # The documented eviction carve-out applies equally to sampled PIDs:
    # a forgotten PID may rejoin and emit its cap marker again.
    assert budget.evaluate("network", 1)[0] == audit.KEEP
    assert budget.evaluate("network", 1)[1]["type"] == "pid_budget_exceeded"
    for pid in range(4, 100):
        budget.evaluate("network", pid)
    assert len(budget.pid_counts) <= 2
    assert budget._pid_marker_emitted <= budget.pid_counts.keys()
    assert budget.total_records == 0
    assert budget.total_records_emitted == budget.global_cap
