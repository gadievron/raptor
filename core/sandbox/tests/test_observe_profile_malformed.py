"""One malformed observation must not discard neighboring observations."""

import errno
import json
import os
from unittest.mock import Mock

import pytest

from core.sandbox import observe_profile as observe


def record(path_value, **fields):
    return {
        "syscall": "openat", "path": path_value, "observe": True,
        "args": [-100, 0, 0], **fields,
    }


def write_log(tmp_path, records):
    path = tmp_path / observe.OBSERVE_FILENAME
    path.write_text("\n".join(json.dumps(rec) for rec in records) + "\n")
    return path


@pytest.mark.parametrize("field,value", [
    ("syscall", []), ("syscall", {}), ("syscall", 7), ("syscall", True),
    ("path", []), ("path", {}), ("path", 7), ("path", True),
])
def test_invalid_record_fields_do_not_hide_neighbors(tmp_path, field, value):
    write_log(tmp_path, [
        record("/first"), record("/bad", **{field: value}), record("/last"),
    ])
    profile = observe.parse_observe_log(tmp_path)
    assert profile.paths_read == ["/first", "/last"]
    assert profile.paths_written == []


@pytest.mark.parametrize("args", [
    True, 42, {"a": 1, "b": 2, "c": 3}, [0, 0, True], "invalid",
])
def test_unusable_open_flags_keep_conservative_read_classification(tmp_path, args):
    write_log(tmp_path, [record("/unknown-flags", args=args), record("/last")])
    profile = observe.parse_observe_log(tmp_path)
    assert profile.paths_read == ["/unknown-flags", "/last"]
    assert profile.paths_written == []


def test_malformed_budget_counts_do_not_abort_profile(tmp_path):
    write_log(tmp_path, [
        record("/first"),
        {"type": "audit_summary", "dropped_by_category": {
            "valid": 3, "zero": 0, "negative": -1, "boolean": True,
            "nan": float("nan"), "infinity": float("inf"),
            "float": 1.5, "string": "3", "object": {},
        }},
        record("/last"),
    ])
    profile = observe.parse_observe_log(tmp_path)
    assert profile.paths_read == ["/first", "/last"]
    assert profile.dropped_by_category == {"valid": 3, "zero": 0}
    assert profile.budget_truncated is True


@pytest.mark.parametrize("syscall", ["connect", "network-outbound"])
@pytest.mark.parametrize("path", [[], {}, 42, True])
def test_invalid_connect_paths_are_skipped(tmp_path, syscall, path):
    write_log(tmp_path, [record("/first"), record(path, syscall=syscall), record("/last")])
    profile = observe.parse_observe_log(tmp_path)
    assert profile.paths_read == ["/first", "/last"]
    assert profile.connect_targets == []
    assert observe._parse_connect_path({"syscall": syscall, "path": path}) is None


def test_json_recursion_error_does_not_end_reading(tmp_path, monkeypatch):
    write_log(tmp_path, [record("/first"), record("/bad"), record("/last")])
    real_loads = json.loads
    calls = []

    def decode(line):
        calls.append(line)
        if len(calls) == 2:
            raise RecursionError("deep JSON")
        return real_loads(line)

    monkeypatch.setattr(observe.json, "loads", decode)
    assert observe.parse_observe_log(tmp_path).paths_read == ["/first", "/last"]


def test_stat_failure_closes_descriptor_and_returns_no_records(tmp_path, monkeypatch):
    path = write_log(tmp_path, [record("/first")])
    real_open = os.open
    opened = []

    def open_fd(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", open_fd)
        patch.setattr(os, "fstat", Mock(side_effect=OSError("stat failed")))
        assert list(observe._iter_records(path)) == []
    assert len(opened) == 1
    with pytest.raises(OSError) as exc:
        os.fstat(opened[0])
    assert exc.value.errno == errno.EBADF
