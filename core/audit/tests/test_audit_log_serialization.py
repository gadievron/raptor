"""Encoding once must preserve the audit trail's exact on-disk bytes."""

import json

import pytest

from core.audit import record


@pytest.mark.parametrize("row", [
    {"action": "context", "file": "é/🙂.c", "body": "\r\n\x00"},
    {"action": "sweep", "nested": {"values": [None, True, 1.25, -2]}},
    {"action": "record", "body": "x" * 10000},
])
def test_identical_bytes_with_one_encoding(tmp_path, monkeypatch, row):
    # Pin the stamp so the expected line is independent of key creation
    # and cryptographic serialization; the existing authority/tamper
    # suites exercise the real stamping path.
    stamped = {**row, "integrity": "fixed-stamp"}
    monkeypatch.setattr(record, "stamp_audit_log_row", lambda *_: stamped)
    expected = (json.dumps(stamped, separators=(",", ":"),
                           allow_nan=False) + "\n").encode("utf-8")
    original = json.dumps
    encoded = []

    def counted(value, *args, **kwargs):
        encoded.append(value)
        return original(value, *args, **kwargs)

    monkeypatch.setattr(json, "dumps", counted)
    record.append_audit_log(tmp_path, row)
    assert (tmp_path / record.AUDIT_LOG_FILENAME).read_bytes() == expected
    assert encoded == [stamped]


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), object()])
def test_serialization_failure_writes_nothing(tmp_path, monkeypatch, bad):
    monkeypatch.setattr(record, "stamp_audit_log_row", lambda row, _: row)
    with pytest.raises((ValueError, TypeError)):
        record.append_audit_log(tmp_path, {"bad": bad})
    assert not (tmp_path / record.AUDIT_LOG_FILENAME).exists()
