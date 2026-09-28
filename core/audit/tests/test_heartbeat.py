"""Heartbeat writer: atomic replace, throttle in both directions,
warn-once-then-disable on write failure, no-op without a run dir, and
the detail bound in both directions. Hermetic — tmp_path only."""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path

import pytest

import core.audit.heartbeat as hb_mod
from core.audit.heartbeat import (
    HEARTBEAT_FILENAME,
    HEARTBEAT_INTERVAL_S,
    Heartbeat,
    _MAX_DETAIL_CHARS,
)


def _read(run_dir: Path) -> dict:
    return json.loads((run_dir / HEARTBEAT_FILENAME).read_text())


def test_first_beat_writes_payload_fields(tmp_path: Path) -> None:
    hb = Heartbeat(tmp_path, "cocci_sweep")
    hb.beat(done=3, total=10, detail="src/x.c")
    payload = _read(tmp_path)
    assert payload["phase"] == "cocci_sweep"
    assert payload["pid"] == os.getpid()
    assert payload["done"] == 3
    assert payload["total"] == 10
    assert payload["detail"] == "src/x.c"
    # ISO-8601 UTC with an explicit offset.
    assert payload["timestamp"].endswith("+00:00")


def test_none_run_dir_is_a_noop(tmp_path: Path) -> None:
    for run_dir in (None, ""):
        hb = Heartbeat(run_dir, "cocci_sweep")
        hb.beat(done=1, total=2)  # must not raise, must not write
    assert list(tmp_path.iterdir()) == []


def test_throttle_two_directions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [1000.0]
    monkeypatch.setattr(hb_mod.time, "monotonic", lambda: clock[0])
    hb = Heartbeat(tmp_path, "cocci_sweep")
    hb.beat(done=1)
    # Under the interval: suppressed (old payload survives).
    clock[0] += HEARTBEAT_INTERVAL_S - 0.5
    hb.beat(done=2)
    assert _read(tmp_path)["done"] == 1
    # At/over the interval: written.
    clock[0] += 0.5
    hb.beat(done=3)
    assert _read(tmp_path)["done"] == 3


def test_write_is_atomic_replace_no_tempfile_residue(
    tmp_path: Path,
) -> None:
    hb = Heartbeat(tmp_path, "cocci_sweep", interval_s=0.0)
    for i in range(5):
        hb.beat(done=i)
    assert _read(tmp_path)["done"] == 4
    leftovers = [
        p.name for p in tmp_path.iterdir()
        if p.name != HEARTBEAT_FILENAME
    ]
    assert leftovers == []  # every temp file was renamed or unlinked


def test_write_failure_warns_once_and_disables(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    run_dir = tmp_path / "gone"
    run_dir.mkdir()
    hb = Heartbeat(run_dir, "cocci_sweep", interval_s=0.0)
    hb.beat(done=1)
    run_dir.joinpath(HEARTBEAT_FILENAME).unlink()
    os.rmdir(run_dir)  # mkstemp now fails
    with caplog.at_level(logging.WARNING, logger=hb_mod.__name__):
        hb.beat(done=2)  # fails → one warning, instance disables
        hb.beat(done=3)  # silent no-op
    warnings = [
        r for r in caplog.records
        if "heartbeat write" in r.getMessage()
    ]
    assert len(warnings) == 1
    assert hb._failed is True


def test_detail_bound_two_directions(tmp_path: Path) -> None:
    hb = Heartbeat(tmp_path, "cocci_sweep", interval_s=0.0)
    fits = "y" * _MAX_DETAIL_CHARS
    hb.beat(detail=fits)
    assert _read(tmp_path)["detail"] == fits  # kept whole at the bound
    hb.beat(detail="x" * (_MAX_DETAIL_CHARS + 50))
    assert _read(tmp_path)["detail"] == "x" * _MAX_DETAIL_CHARS


def test_optional_counters_omitted_when_absent(tmp_path: Path) -> None:
    hb = Heartbeat(tmp_path, "joern_presweep")
    hb.beat(detail="importing CPG")
    payload = _read(tmp_path)
    assert "done" not in payload and "total" not in payload
    assert payload["detail"] == "importing CPG"


def test_concurrent_beats_never_tear(tmp_path: Path) -> None:
    """Parallel sweep workers share one instance; a reader must always
    see one whole JSON document (os.replace, never in-place write)."""
    hb = Heartbeat(tmp_path, "cocci_sweep", interval_s=0.0)
    n = 16
    barrier = threading.Barrier(n)
    stop = threading.Event()
    torn: list[str] = []

    def _writer(i: int) -> None:
        barrier.wait()
        for j in range(50):
            hb.beat(done=i * 50 + j, total=n * 50)

    def _reader() -> None:
        target = tmp_path / HEARTBEAT_FILENAME
        while not stop.is_set():
            try:
                json.loads(target.read_text())
            except FileNotFoundError:
                continue
            except ValueError:
                torn.append("torn read")
                return

    reader = threading.Thread(target=_reader)
    reader.start()
    writers = [
        threading.Thread(target=_writer, args=(i,)) for i in range(n)
    ]
    for t in writers:
        t.start()
    for t in writers:
        t.join()
    stop.set()
    reader.join()
    assert torn == []
    json.loads((tmp_path / HEARTBEAT_FILENAME).read_text())
