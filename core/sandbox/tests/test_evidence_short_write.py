"""Incomplete evidence appends must never be reported as successful."""

import logging
import os

import pytest

from core.sandbox import evidence


@pytest.mark.parametrize("written", [0, 1, 5])
@pytest.mark.parametrize("record", [False, True])
def test_short_append_reports_failure(tmp_path, monkeypatch, caplog, written, record):
    handle = evidence.EvidenceFile.open(tmp_path, "events.jsonl")
    real_write = os.write
    calls = []

    def short_write(fd, data):
        assert fd == handle.fd
        calls.append(data)
        return real_write(fd, data[:written])

    try:
        with monkeypatch.context() as patch:
            patch.setattr(os, "write", short_write)
            with caplog.at_level(logging.WARNING, logger=evidence.__name__):
                if record:
                    result = handle.write_record({"event": "denied"})
                else:
                    result = handle.write_line('{"event":"denied"}\n')
        assert result is False
        assert len(calls) == 1
        assert handle.path.read_bytes() == calls[0][:written]
        assert f"wrote {written} of {len(calls[0])} bytes" in caplog.text
    finally:
        handle.close()


def test_full_append_counts_encoded_bytes(tmp_path, caplog):
    handle = evidence.EvidenceFile.open(tmp_path, "events.jsonl")
    line = '{"event":"拒否"}\n'
    try:
        with caplog.at_level(logging.WARNING, logger=evidence.__name__):
            assert handle.write_line(line) is True
        assert handle.path.read_bytes() == line.encode("utf-8")
        assert not caplog.records
    finally:
        handle.close()
