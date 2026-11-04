"""Rejected evidence records leave the writer usable for later events."""

import json
import logging
import sys

import pytest

from core.sandbox import evidence


@pytest.mark.parametrize("kind", ["deep", "circular", "nonfinite"])
def test_serialization_failure_does_not_break_later_appends(
    tmp_path, caplog, monkeypatch, kind,
):
    record = {}
    if kind == "deep":
        # Python versions differ in the C encoder's depth handling.
        # Exercise the supported stdlib Python encoder deterministically.
        monkeypatch.setattr(json.encoder, "c_make_encoder", None)
        nested = record
        for _ in range(sys.getrecursionlimit() + 10):
            child = {}
            nested["child"] = child
            nested = child
    elif kind == "circular":
        record["self"] = record
    else:
        record["value"] = float("nan")

    handle = evidence.EvidenceFile.open(tmp_path, "events.jsonl")
    try:
        with caplog.at_level(logging.WARNING, logger=evidence.__name__):
            assert handle.write_record(record) is False
        assert "evidence record not serialisable" in caplog.text
        assert handle.path.read_bytes() == b""
        assert handle.write_record({"event": "later denial"}) is True
        assert json.loads(handle.path.read_text()) == {"event": "later denial"}
    finally:
        handle.close()
