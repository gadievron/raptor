"""Control-plane accounting stays distinct from enforcement and preserves loss."""

from copy import deepcopy

import pytest

from core.sandbox.audit_control import (
    AUDIT_CONTROL_TYPES, audit_capture_digest, capture_loss_status,
    partition_audit_records, valid_audit_capture,
)


@pytest.mark.parametrize("kind", sorted(AUDIT_CONTROL_TYPES))
def test_known_control_types_are_metadata(kind):
    events, capture = partition_audit_records([{"type": kind}])
    assert events == []
    assert capture["records"] == 1 and capture["by_type"] == {kind: 1}
    assert capture["summaries"] == int(kind == "audit_summary")
    assert valid_audit_capture(capture)


def test_event_order_identity_and_input_records_are_preserved():
    first = {"type": "read", "path": "/owned/one"}
    second = {"type": "future-event", "path": "/owned/two"}
    rows = [first, {"type": "audit_summary"}, second]
    before = deepcopy(rows)
    events, capture = partition_audit_records(rows)
    assert events == [first, second] and events[0] is first and events[1] is second
    assert rows == before and capture["records"] == 1
    assert partition_audit_records([first, second]) == ([first, second], None)


@pytest.mark.parametrize("kind", ["global_budget_exceeded", "category_budget_exceeded_sampling",
                                 "credential_keep_cap_exceeded"])
def test_notices_do_not_invent_dropped_records(kind):
    _, capture = partition_audit_records([{"type": kind}, {"type": "audit_summary"}])
    assert capture["budget_truncated"] is False
    assert capture["capture_incomplete"] is False
    assert valid_audit_capture(capture)


@pytest.mark.parametrize("kind", ["pid_budget_exceeded", "category_budget_exceeded", "sampling_budget_exceeded"])
def test_drop_markers_retain_loss_even_without_counts(kind):
    _, capture = partition_audit_records([{"type": kind}, {"type": "audit_summary"}])
    assert capture["budget_truncated"] is True
    assert capture["capture_incomplete"] is False
    assert valid_audit_capture(capture)


def test_summary_loss_and_reported_counts_accumulate():
    rows = [{"type": "audit_summary", "reader_drained": False,
             "dropped_by_category": {"read": 2}},
            {"type": "audit_summary", "reader_drained": True,
             "dropped_by_category": {"read": 3, "write": 0}}]
    _, capture = partition_audit_records(rows)
    assert capture["capture_incomplete"] and capture["budget_truncated"]
    assert capture["dropped_by_category"] == {"read": 5}
    assert capture["summaries"] == 2 and valid_audit_capture(capture)


def test_malformed_control_retains_usable_drop_counts():
    _, capture = partition_audit_records([{"type": "audit_summary", "reader_drained": "true",
                                          "dropped_by_category": {"read": 3, "write": True}}])
    assert capture["capture_incomplete"] and capture["malformed_records"] == 1
    assert capture["dropped_by_category"] == {"read": 3}
    assert valid_audit_capture(capture)


@pytest.mark.parametrize("field,value", [("reader_drained", False), ("reader_failed", True),
                                         ("lineage_failed", True), ("stdout_closed", False),
                                         ("append_failures", 2), ("append_failures", -1)])
def test_shared_loss_status_is_conservative(field, value):
    incomplete, malformed = capture_loss_status({field: value})
    assert incomplete
    assert malformed is (field == "append_failures" and value < 0)


@pytest.mark.parametrize("field,value", [
    ("version", True), ("version", 2), ("records", True), ("records", 0),
    ("summaries", 2), ("by_type", {"audit_summary": 0}), ("by_type", {"future": 1}),
    ("capture_incomplete", 0), ("budget_truncated", 1),
    ("malformed_records", 2), ("malformed_records", 1),
    ("dropped_by_category", {"read": -1}), ("dropped_by_category", {"read": True}),
    ("dropped_by_category", {"read": 1}),
])
def test_aggregate_shape_and_consistency_are_checked(field, value):
    _, capture = partition_audit_records([{"type": "audit_summary"}])
    capture[field] = value
    assert not valid_audit_capture(capture)


def test_digest_is_canonical_and_handles_escaped_unicode():
    _, capture = partition_audit_records([{"type": "audit_summary",
                                          "dropped_by_category": {"misc-\udcff": 1}}])
    assert valid_audit_capture(capture)
    reordered = dict(reversed(list(capture.items())))
    assert audit_capture_digest(capture) == audit_capture_digest(reordered)
    assert len(audit_capture_digest(capture)) == 64


@pytest.mark.parametrize("sampled", [0, 1, -1, True, "1"])
def test_sampled_observations_cannot_prove_complete_absence(sampled):
    events, capture = partition_audit_records([
        {"type": "audit_summary", "reader_drained": True, "sampled_keeps": sampled},
    ])
    assert events == []
    assert capture["capture_incomplete"] is (type(sampled) is not int or sampled != 0)
    assert capture["budget_truncated"] is False
    assert valid_audit_capture(capture)
