"""Drop-all PID budgets must not create unbounded marker state."""

import pytest

from core.sandbox import audit_budget as audit


@pytest.mark.parametrize("pid_cap", [0, -1])
@pytest.mark.parametrize("tracking_cap", [0, 3])
def test_marker_only_pid_flood_is_bounded_and_all_drops_are_counted(pid_cap, tracking_cap):
    budget = audit.AuditBudget(global_cap=10, pid_cap=pid_cap, clock=lambda: 0)
    budget._pid_dict_cap = tracking_cap
    markers = []
    for pid in range(1000):
        category = "network" if pid % 2 else "file-write"
        action, marker = budget.evaluate(category, pid)
        assert action == audit.DROP
        if marker is not None:
            markers.append(marker)
    assert len(markers) == tracking_cap
    assert all(marker["type"] == "pid_budget_exceeded" for marker in markers)
    assert len(budget._pid_marker_emitted) == tracking_cap
    assert budget.pid_counts == {}
    assert budget.total_records_emitted == 0
    assert budget.dropped_by_category == {"network": 500, "file-write": 500}
    summary = budget.summary_record()
    assert summary["pid_budget_markers_truncated"] is True
    assert sum(summary["dropped_by_category"].values()) == 1000


def test_normal_pid_eviction_still_allows_one_notice_per_tracking_lifetime():
    budget = audit.AuditBudget(
        global_cap=10, pid_cap=1,
        category_caps={"network": 10}, refill_rates={"network": 0},
        sampling_rates={}, clock=lambda: 0,
    )
    budget._pid_dict_cap = 2
    markers = []
    for pid in (1, 2, 3, 1):
        assert budget.evaluate("network", pid)[0] == audit.KEEP
        action, marker = budget.evaluate("network", pid)
        assert action == audit.DROP
        assert marker["type"] == "pid_budget_exceeded"
        markers.append(marker["pid"])
    assert markers == [1, 2, 3, 1]
    assert len(budget._pid_marker_emitted) == 2
    assert "pid_budget_markers_truncated" not in budget.summary_record()


def test_repeated_marker_calls_do_not_consume_more_tracking_space():
    budget = audit.AuditBudget(global_cap=10, pid_cap=0, clock=lambda: 0)
    budget._pid_dict_cap = 1
    assert budget.evaluate("network", 1)[1] is not None
    for _ in range(10):
        assert budget.evaluate("network", 1) == (audit.DROP, None)
    assert "pid_budget_markers_truncated" not in budget.summary_record()
    assert budget.evaluate("network", 2) == (audit.DROP, None)
    assert budget.summary_record()["pid_budget_markers_truncated"] is True
    assert budget.dropped_by_category == {"network": 12}
    assert budget._pid_marker_emitted == {1}
