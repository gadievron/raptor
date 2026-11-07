"""Persisted capture completion includes every owned resource, with exact types."""

import json

import pytest

from core.sandbox import evidence, observe_profile as observe


@pytest.mark.parametrize("field", ["producer_reaped", "lineage_stopped", "stdout_closed"])
@pytest.mark.parametrize("value", [False, None, 0, 1, "false", [], {}],
                         ids=["false", "null", "zero", "one", "text", "list", "object"])
def test_resource_failure_or_malformed_status_is_incomplete(tmp_path, field, value):
    audit = tmp_path / evidence.AUDIT_SUBDIR
    audit.mkdir()
    tail = {"type": "audit_summary", "nonce": "owned", field: value}
    (audit / ".sandbox-observe.jsonl").write_text(json.dumps(tail) + "\n")
    profile = observe.parse_observe_log(tmp_path, expected_nonce="owned")
    assert profile.capture_incomplete is True


@pytest.mark.parametrize("field", ["producer_reaped", "lineage_stopped", "stdout_closed"])
def test_healthy_optional_status_is_compatible(tmp_path, field):
    audit = tmp_path / evidence.AUDIT_SUBDIR
    audit.mkdir()
    tail = {"type": "audit_summary", "nonce": "owned", field: True}
    (audit / ".sandbox-observe.jsonl").write_text(json.dumps(tail) + "\n")
    assert observe.parse_observe_log(tmp_path, expected_nonce="owned").capture_incomplete is False


def test_later_clean_tail_does_not_erase_failed_resource_status(tmp_path):
    audit = tmp_path / evidence.AUDIT_SUBDIR
    audit.mkdir()
    rows = [{"type": "audit_summary", "nonce": "owned", "producer_reaped": False},
            {"type": "audit_summary", "nonce": "owned", "producer_reaped": True}]
    (audit / ".sandbox-observe.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
    assert observe.parse_observe_log(tmp_path, expected_nonce="owned").capture_incomplete is True


def test_foreign_resource_failure_does_not_poison_owned_capture(tmp_path):
    audit = tmp_path / evidence.AUDIT_SUBDIR
    audit.mkdir()
    rows = [{"type": "audit_summary", "nonce": "other", "producer_reaped": False},
            {"type": "audit_summary", "nonce": "owned"}]
    (audit / ".sandbox-observe.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
    assert observe.parse_observe_log(tmp_path, expected_nonce="owned").capture_incomplete is False


@pytest.mark.parametrize("value", [True, None, 0, 1, "false", [], {}],
                         ids=["true", "null", "zero", "one", "text", "list", "object"])
def test_lineage_failure_or_malformed_status_is_incomplete(tmp_path, value):
    audit = tmp_path / evidence.AUDIT_SUBDIR
    audit.mkdir()
    tail = {"type": "audit_summary", "nonce": "owned", "lineage_failed": value}
    (audit / ".sandbox-observe.jsonl").write_text(json.dumps(tail) + "\n")
    assert observe.parse_observe_log(tmp_path, expected_nonce="owned").capture_incomplete is True


def test_healthy_lineage_failure_flag_is_compatible(tmp_path):
    audit = tmp_path / evidence.AUDIT_SUBDIR
    audit.mkdir()
    tail = {"type": "audit_summary", "nonce": "owned", "lineage_failed": False}
    (audit / ".sandbox-observe.jsonl").write_text(json.dumps(tail) + "\n")
    assert observe.parse_observe_log(tmp_path, expected_nonce="owned").capture_incomplete is False
