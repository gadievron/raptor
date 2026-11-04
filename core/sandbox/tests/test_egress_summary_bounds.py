"""Egress summaries have finite input and JSON-record budgets."""

import errno
import json
import os
from unittest.mock import Mock

import pytest

from core.sandbox import egress_summary as summary
from core.security import capped_read


def event():
    return {"host": "example.test", "port": 443, "result": "allowed"}


def test_oversized_file_is_refused_before_parsing(tmp_path, monkeypatch):
    monkeypatch.setattr(summary, "_MAX_INPUT_BYTES", 64)
    (tmp_path / "proxy-events.jsonl").write_bytes(b"x" * 65)
    loads = Mock(side_effect=AssertionError("must not parse oversized input"))
    monkeypatch.setattr(summary.json, "loads", loads)
    assert summary.summarise_egress(tmp_path) is None
    loads.assert_not_called()


def test_oversized_line_does_not_hide_valid_neighbors(tmp_path, monkeypatch):
    good = json.dumps(event())
    huge = json.dumps({**event(), "padding": "x" * 500})
    (tmp_path / "proxy-events.jsonl").write_text(good + "\n" + huge + "\n" + good + "\n")
    monkeypatch.setattr(summary, "_MAX_LINE_CHARS", 128)
    real_loads = json.loads
    decoded = []

    def decode(line):
        decoded.append(line)
        return real_loads(line)

    monkeypatch.setattr(summary.json, "loads", decode)
    result = summary.summarise_egress(tmp_path)
    assert result["total_connections"] == 2
    assert len(decoded) == 2


@pytest.mark.parametrize("newline", ["\n", "\r", "\r\n"])
def test_newline_variants_and_final_unterminated_record(tmp_path, newline):
    line = json.dumps(event(), ensure_ascii=False)
    (tmp_path / "proxy-events.jsonl").write_bytes((line + newline + line).encode())
    assert summary.summarise_egress(tmp_path)["total_connections"] == 2


def test_existing_line_count_limit_is_preserved(tmp_path, monkeypatch):
    line = json.dumps(event())
    (tmp_path / "proxy-events.jsonl").write_text("\n".join([line] * 5))
    monkeypatch.setattr(summary, "_MAX_LINES", 2)
    assert summary.summarise_egress(tmp_path)["total_connections"] == 2


def test_stat_failure_closes_descriptor_and_returns_no_summary(tmp_path, monkeypatch):
    (tmp_path / "proxy-events.jsonl").write_text(json.dumps(event()))
    opened = []
    real_open = os.open

    def open_fd(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    with monkeypatch.context() as patch:
        patch.setattr(capped_read.os, "open", open_fd)
        patch.setattr(capped_read.os, "fstat", Mock(side_effect=OSError("stat failed")))
        assert summary.summarise_egress(tmp_path) is None
    assert len(opened) == 1
    with pytest.raises(OSError) as exc:
        os.fstat(opened[0])
    assert exc.value.errno == errno.EBADF


def test_growth_past_cap_is_not_accepted_as_a_partial_log(tmp_path, monkeypatch):
    path = tmp_path / "proxy-events.jsonl"
    path.write_text(json.dumps(event()) + "\n")
    monkeypatch.setattr(summary, "_MAX_INPUT_BYTES", path.stat().st_size)
    real_fstat = os.fstat

    def grow(fd):
        metadata = real_fstat(fd)
        with path.open("ab") as output:
            output.write(json.dumps(event()).encode() + b"\n")
        return metadata

    monkeypatch.setattr(capped_read.os, "fstat", grow)
    assert summary.summarise_egress(tmp_path) is None
