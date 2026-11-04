"""Sampling decisions and summary accounting must agree."""

import pytest

from core.sandbox import audit_budget


@pytest.mark.parametrize("global_cap", [1, 3, 10])
@pytest.mark.parametrize("category_cap", [0, 1, 4])
@pytest.mark.parametrize("sample_n", [0, 1, 3])
def test_every_event_is_either_emitted_or_dropped(global_cap, category_cap, sample_n):
    budget = audit_budget.AuditBudget(
        global_cap=global_cap,
        category_caps={"network": category_cap},
        pid_cap=1000,
        refill_rates={"network": 0},
        sampling_rates={"network": sample_n},
        clock=lambda: 0,
    )
    actions = [budget.evaluate("network", pid=1)[0] for _ in range(40)]
    kept = actions.count(audit_budget.KEEP)
    dropped = actions.count(audit_budget.DROP)
    assert budget.total_records_emitted == kept
    assert budget.dropped_by_category.get("network", 0) == dropped
    summary = budget.summary_record()
    assert summary["total_records"] + summary["sampled_keeps"] + sum(
        summary["dropped_by_category"].values()
    ) == len(actions)


def test_global_sampling_does_not_exhaust_an_unused_category():
    budget = audit_budget.AuditBudget(
        global_cap=4,
        category_caps={"network": 1, "file-write": 4},
        pid_cap=100,
        refill_rates={"network": 0, "file-write": 0},
        sampling_rates={"network": 1},
        clock=lambda: 0,
    )
    for _ in range(4):
        assert budget.evaluate("file-write", pid=1)[0] == audit_budget.KEEP
    # Global-cap samples must not exhaust a category that never used
    # any counted allowance or produce a false category-exhaust marker.
    for _ in range(4):
        action, marker = budget.evaluate("network", pid=1)
        assert action == audit_budget.KEEP
        assert marker is None
    action, marker = budget.evaluate("network", pid=1)
    assert action == audit_budget.DROP
    assert marker["type"] == "sampling_budget_exceeded"
    assert budget.dropped_by_category == {"network": 1}
    assert budget.category_counts == {"file-write": 4}
    assert budget.pop_global_cap_notice() is True
    assert budget.pop_global_cap_notice() is False
