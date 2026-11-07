"""Observation byte limits apply to the bytes read, not only initial stat."""

import json
import os
from unittest.mock import Mock

import pytest

from core.testing.module_bindings import patch_module_attribute

from core.sandbox import observe_profile as observe
from core.security import capped_read


def line(path):
    return json.dumps({
        "syscall": "openat", "path": path,
        "args": [-100, 0, 0], "observe": True,
    }).encode()


def test_growth_past_cap_refuses_the_entire_log(tmp_path, monkeypatch, caplog):
    path = tmp_path / observe.OBSERVE_FILENAME
    original = line("/first") + b"\n"
    path.write_bytes(original)
    monkeypatch.setattr(observe, "_MAX_OBSERVE_BYTES", len(original))
    real_fstat = os.fstat

    def grow(fd):
        metadata = real_fstat(fd)
        with path.open("ab") as output:
            output.write(line("/last") + b"\n")
        return metadata

    patch_module_attribute(monkeypatch, capped_read, 'os', "fstat", grow)
    assert observe.parse_observe_log(tmp_path).paths_read == []
    assert "growing artifact" in caplog.text


@pytest.mark.parametrize("terminator", [b"", b"\n", b"\r\n"])
def test_record_boundary_preserves_terminator_accounting(tmp_path, monkeypatch, terminator):
    raw = line("/exact-limit")
    path = tmp_path / observe.OBSERVE_FILENAME
    path.write_bytes(raw + terminator)
    # Previous records counted CR but excluded LF from their byte cap.
    record_size = len(raw) + (1 if terminator == b"\r\n" else 0)
    monkeypatch.setattr(observe, "_MAX_RECORD_BYTES", record_size)
    monkeypatch.setattr(observe, "_MAX_OBSERVE_BYTES", len(raw + terminator))
    assert observe.parse_observe_log(tmp_path).paths_read == ["/exact-limit"]


def test_large_record_is_skipped_without_hiding_neighbors(tmp_path, monkeypatch):
    first, last = line("/first"), line("/last")
    too_large = line("/" + "x" * 2000)
    (tmp_path / observe.OBSERVE_FILENAME).write_bytes(
        first + b"\n" + too_large + b"\n" + last,
    )
    monkeypatch.setattr(observe, "_MAX_RECORD_BYTES", 256)
    assert observe.parse_observe_log(tmp_path).paths_read == ["/first", "/last"]


def test_oversized_log_is_refused_before_json_decoding(tmp_path, monkeypatch):
    monkeypatch.setattr(observe, "_MAX_OBSERVE_BYTES", 64)
    (tmp_path / observe.OBSERVE_FILENAME).write_bytes(b"x" * 65)
    loads = Mock(side_effect=AssertionError("oversized input must not be parsed"))
    patch_module_attribute(monkeypatch, observe, 'json', "loads", loads)
    assert observe.parse_observe_log(tmp_path).paths_read == []
    loads.assert_not_called()
