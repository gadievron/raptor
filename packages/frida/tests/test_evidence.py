"""Tests for frida evidence discovery."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from packages.frida.evidence import (
    discover_evidence,
    match_target,
)


def _write_metadata(run_dir: Path, metadata: dict) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "metadata.json").write_text(
        json.dumps(metadata), encoding="utf-8",
    )


def _sample_metadata(binary: str = "/tmp/build/myapp", ok: bool = True) -> dict:
    return {
        "ok": ok,
        "error": None,
        "target": {
            "raw": binary,
            "kind": "binary",
            "pid": None,
            "name": None,
            "binary": binary,
        },
        "script_origin": "template:api-trace",
        "duration_requested_sec": 60.0,
        "duration_actual_sec": 5.0,
        "events_captured": 10,
        "device": {"id": "local", "host": None, "usb": False},
        "host": {"system": "Linux", "arch": "x86_64", "frida_version": "16.0.0",
                 "frida_bin": "/usr/bin/frida", "sip_status": None,
                 "ptrace_scope": 0},
        "spawn": True,
        "unsafe_attach": False,
        "resolved_pid": 1234,
    }


def test_discover_finds_valid_run(tmp_path):
    run_dir = tmp_path / "frida-run-1"
    _write_metadata(run_dir, _sample_metadata())
    (run_dir / "events.jsonl").write_text('{"ts":1,"type":"send"}\n', encoding="utf-8")
    (run_dir / "coverage.drcov").write_bytes(b"DRCOV VERSION: 2\n")

    results = discover_evidence([tmp_path])
    assert len(results) == 1
    ev = results[0]
    assert ev.run_dir == run_dir
    assert ev.has_drcov is True
    assert ev.has_events is True
    assert ev.target_binary == "/tmp/build/myapp"


def test_discover_skips_corrupt_metadata(tmp_path):
    run_dir = tmp_path / "bad-run"
    run_dir.mkdir()
    (run_dir / "metadata.json").write_text("NOT JSON{{{", encoding="utf-8")

    results = discover_evidence([tmp_path])
    assert results == []


def test_discover_skips_wrong_target(tmp_path):
    run_dir = tmp_path / "run-other"
    _write_metadata(run_dir, _sample_metadata(binary="/opt/other-app"))

    results = discover_evidence([tmp_path], target_path="/home/user/myapp")
    assert results == []


def test_discover_empty_dir(tmp_path):
    results = discover_evidence([tmp_path])
    assert results == []


def test_match_target_exact():
    meta = _sample_metadata(binary="/home/user/src/myapp")
    assert match_target(meta, "/home/user/src/myapp") is True


def test_match_target_basename_no_false_positive():
    """Basename alone must NOT match -- avoids cross-project pollution."""
    meta = _sample_metadata(binary="/tmp/build/myapp")
    assert match_target(meta, "/home/user/src/myapp") is False


def test_match_target_realpath(tmp_path):
    real = tmp_path / "real_binary"
    real.write_bytes(b"ELF")
    link = tmp_path / "link_binary"
    link.symlink_to(real)
    meta = _sample_metadata(binary=str(real))
    assert match_target(meta, str(link)) is True


def test_match_target_by_name():
    """Attach-by-name: target.name matches basename of target_path."""
    meta = _sample_metadata(binary="")
    meta["target"]["binary"] = None
    meta["target"]["raw"] = ""
    meta["target"]["name"] = "my_daemon"
    assert match_target(meta, "/usr/sbin/my_daemon") is True
    assert match_target(meta, "/other/path/my_daemon") is True
    assert match_target(meta, "/other/path/wrong_name") is False


def test_discover_sorts_newest_first(tmp_path):
    run1 = tmp_path / "run-old"
    _write_metadata(run1, _sample_metadata())
    # Force older mtime
    old_time = time.time() - 100
    os.utime(run1 / "metadata.json", (old_time, old_time))

    run2 = tmp_path / "run-new"
    _write_metadata(run2, _sample_metadata())

    results = discover_evidence([tmp_path])
    assert len(results) == 2
    assert results[0].run_dir == run2
    assert results[1].run_dir == run1


def test_available_false_still_discovers(tmp_path):
    """Evidence discovery works on files, not the frida runtime."""
    run_dir = tmp_path / "run-1"
    _write_metadata(run_dir, _sample_metadata())
    (run_dir / "events.jsonl").write_text('{"ts":1}\n', encoding="utf-8")

    results = discover_evidence([tmp_path])
    assert len(results) == 1


def test_match_target_malformed_types():
    """Non-string metadata fields must not crash match_target."""
    meta_int = {"target": {"binary": 12345, "raw": None, "name": None}}
    assert match_target(meta_int, "/usr/bin/app") is False

    meta_list = {"target": {"binary": ["/usr/bin/app"], "raw": "", "name": ""}}
    assert match_target(meta_list, "/usr/bin/app") is False

    meta_str_target = {"target": "not a dict"}
    assert match_target(meta_str_target, "/usr/bin/app") is False


def test_discover_malformed_binary_field(tmp_path):
    """Non-string binary in metadata produces target_binary=None, not a crash."""
    run_dir = tmp_path / "bad-binary-type"
    meta = _sample_metadata()
    meta["target"]["binary"] = 99999
    _write_metadata(run_dir, meta)

    results = discover_evidence([tmp_path])
    assert len(results) == 1
    assert results[0].target_binary is None
