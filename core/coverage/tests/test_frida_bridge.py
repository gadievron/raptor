"""Tests for the frida coverage bridge."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from core.coverage.frida_bridge import import_frida_coverage
from core.coverage.store import CoverageStore

_C_CHECKLIST: Dict[str, Any] = {"files": [
    {"path": "prog.c", "lines": 12, "items": [
        {"name": "main", "kind": "function", "line_start": 1, "line_end": 12}]},
]}


def _store(tmp_path: Path) -> CoverageStore:
    return CoverageStore(tmp_path / "coverage.json", target="zip:x")


def _sample_metadata(binary: str = "/tmp/build/prog") -> dict:
    return {
        "ok": True,
        "error": None,
        "target": {"raw": binary, "kind": "binary", "pid": None,
                   "name": None, "binary": binary},
        "script_origin": "template:bb-coverage",
        "duration_requested_sec": 60.0,
        "duration_actual_sec": 5.0,
        "events_captured": 1,
        "device": {"id": "local", "host": None, "usb": False},
        "host": {"system": "Linux", "arch": "x86_64"},
        "spawn": True,
        "unsafe_attach": False,
        "resolved_pid": 1234,
    }


def _write_frida_run(run_dir: Path, binary: str = "/tmp/build/prog") -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "metadata.json").write_text(
        json.dumps(_sample_metadata(binary)), encoding="utf-8",
    )
    (run_dir / "coverage.drcov").write_bytes(b"DRCOV VERSION: 2\n")
    (run_dir / "events.jsonl").write_text('{"ts":1}\n', encoding="utf-8")


def test_import_frida_coverage_with_drcov(tmp_path, monkeypatch):
    """Synthetic drcov + binary -> store gets marks."""
    import core.coverage.collect as collect_mod
    monkeypatch.setattr(
        collect_mod, "collect_drcov",
        lambda *a, **k: {"prog.c": {1, 2, 5}},
    )

    run_dir = tmp_path / "frida-run"
    _write_frida_run(run_dir, binary="/tmp/build/prog")

    s = _store(tmp_path)
    s.import_inventory_meta(_C_CHECKLIST)
    n = import_frida_coverage(
        s, _C_CHECKLIST, [tmp_path],
        target_binary="/tmp/build/prog",
    )
    assert n >= 1
    assert s.who_checked("prog.c", 1) == ["frida"]


def test_import_frida_coverage_no_evidence(tmp_path):
    """No frida runs -> returns 0, no crash."""
    s = _store(tmp_path)
    s.import_inventory_meta(_C_CHECKLIST)
    n = import_frida_coverage(s, _C_CHECKLIST, [tmp_path])
    assert n == 0


def test_import_frida_coverage_no_binary(tmp_path):
    """drcov exists but no binary for addr2line -> returns 0."""
    run_dir = tmp_path / "frida-run"
    run_dir.mkdir(parents=True, exist_ok=True)
    # metadata with no binary field
    meta = _sample_metadata()
    meta["target"]["binary"] = None
    (run_dir / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")
    (run_dir / "coverage.drcov").write_bytes(b"DRCOV VERSION: 2\n")

    s = _store(tmp_path)
    s.import_inventory_meta(_C_CHECKLIST)
    n = import_frida_coverage(s, _C_CHECKLIST, [tmp_path])
    assert n == 0


def test_import_frida_coverage_target_mismatch(tmp_path):
    """drcov exists but target doesn't match -> returns 0."""
    run_dir = tmp_path / "frida-run"
    _write_frida_run(run_dir, binary="/opt/other-binary")

    s = _store(tmp_path)
    s.import_inventory_meta(_C_CHECKLIST)
    n = import_frida_coverage(
        s, _C_CHECKLIST, [tmp_path],
        target_binary="/opt/other-binary",
        target_path="/home/user/totally-different",
    )
    assert n == 0
