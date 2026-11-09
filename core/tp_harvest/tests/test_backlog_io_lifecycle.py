"""Backlog serialization precedes descriptor allocation and keeps accounting."""

import errno
import json
import os

import pytest

from core.json import load_json
from core.json import jsonl
from core.tp_harvest import labels
from core.tp_harvest.harvest import backlog_path, harvest_run
from core.tp_harvest.records import HarvestRecord
from core.testing.module_bindings import patch_module_attribute
from core.testing.module_views import module_function_view


@pytest.fixture
def record():
    return HarvestRecord(
        harvest_id="owned-harvest", finding_id="owned-finding", status="confirmed",
        rule_id="metadata", cwe="CWE-0", vuln_type="metadata", message="owned metadata",
        file="owned.py", function="owned", line=1, span_sha="0" * 64,
    )


@pytest.mark.parametrize("error_type", [MemoryError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_projection_failure_allocates_no_backlog_descriptor(record, tmp_path, monkeypatch, error_type):
    path = tmp_path / "backlog" / "pointer.jsonl"
    error = error_type("pointer projection failed")
    retained = []
    real_open = os.open
    # Own the producer's globals while tracking both legacy and shared IO.
    view = module_function_view(labels, bindings={"os": os})

    def opened(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        info = os.fstat(fd)
        retained.append((fd, (info.st_dev, info.st_ino)))
        return fd

    def fail(*args):
        raise error

    monkeypatch.setattr(view, "backlog_pointer", fail)
    patch_module_attribute(monkeypatch, view, "os", "open", opened)
    patch_module_attribute(monkeypatch, jsonl, "os", "open", opened)
    try:
        with pytest.raises(error_type) as caught:
            view.append_backlog_pointer(path, record)
        assert caught.value is error
        for fd, _ in retained:
            with pytest.raises(OSError) as gone:
                os.fstat(fd)
            assert gone.value.errno == errno.EBADF
        assert retained == []
        assert not path.exists()
    finally:
        for fd, identity in retained:
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == identity:
                os.close(fd)


def test_backlog_uses_nonblocking_regular_append_without_truncation(record, tmp_path, monkeypatch):
    path = tmp_path / "pointer.jsonl"
    path.write_text('{"previous": true}\n')
    real_open = os.open
    reached = []

    def opened(name, flags, *args, **kwargs):
        reached.append(flags)
        assert flags & os.O_NONBLOCK and flags & os.O_NOFOLLOW
        assert flags & os.O_APPEND and not flags & os.O_TRUNC
        return real_open(name, flags, *args, **kwargs)

    patch_module_attribute(monkeypatch, jsonl, "os", "open", opened)
    labels.append_backlog_pointer(path, record)
    assert reached
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert rows[0] == {"previous": True}
    assert rows[1]["harvest_id"] == record.harvest_id
    assert "message" not in rows[1] and "evidence" not in rows[1]


def test_backlog_write_failure_keeps_harvest_totals_and_continues(run_dir, monkeypatch):
    rows = [
        {"id": name, "file": "src/copy.c", "function": function, "line": line,
         "status": "confirmed", "final_status": "confirmed", "cwe_id": "CWE-0",
         "vuln_type": name, "rule_id": "metadata", "message": "owned metadata"}
        for name, function, line in [("first", "copy_name", 4), ("second", "main", 9)]
    ]
    (run_dir / "findings.json").write_text(json.dumps({"findings": rows}))
    real_write = os.write
    calls = []

    def write(fd, data):
        calls.append(fd)
        if len(calls) == 1:
            raise OSError(errno.ENOSPC, "controlled backlog write failure")
        return real_write(fd, data)

    patch_module_attribute(monkeypatch, jsonl, "os", "write", write)
    summary = harvest_run(run_dir, with_candidates=False)
    assert len(calls) == 2
    assert summary["findings_total"] == 2
    assert len(summary["harvested"]) == 1
    assert summary["skipped"] == {"finding_malformed": 1}
    assert len(summary["harvested"]) + sum(summary["skipped"].values()) == summary["findings_total"]
    manifest = load_json(summary["manifest"], strict=True)
    assert manifest["last_run"]["skipped"] == summary["skipped"]
    pointers = [json.loads(line) for line in backlog_path(run_dir).read_text().splitlines()]
    assert [row["harvest_id"] for row in pointers] == summary["harvested"]
