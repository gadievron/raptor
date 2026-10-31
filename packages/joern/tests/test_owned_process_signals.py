"""A reaped Popen handle cannot authorize signalling its old numeric group."""

from pathlib import Path
import subprocess
import sys
from unittest.mock import Mock

from packages.joern import server


def test_reaped_worker_keeps_files_and_never_signals_a_recycled_group(tmp_path, monkeypatch):
    process = subprocess.Popen([sys.executable, "-c", "pass"], start_new_session=True)
    process.wait(timeout=5)
    worker = server.JoernServer(confined=True)
    worker._proc = process
    worker._pgid = process.pid
    worker._workdir = str(tmp_path / "workspace")
    Path(worker._workdir).mkdir()
    sentinel = Path(worker._workdir) / "retained"
    sentinel.write_text("keep")
    reservation = Mock()
    worker._heap_reservation = reservation
    signal_group = Mock()
    monkeypatch.setattr(server.os, "killpg", signal_group)
    monkeypatch.setattr(server, "_pgid_alive", lambda pgid: True)
    monkeypatch.setattr(server, "_GROUP_KILL_GRACE_S", 0.001)
    try:
        worker.interrupt()
        assert worker.stop() is False
        signal_group.assert_not_called()
        reservation.release.assert_not_called()
        assert sentinel.read_text() == "keep"
    finally:
        worker._proc = None
        worker._workdir = None
        worker._heap_reservation = None


def test_reaped_parser_never_signals_a_recycled_group(monkeypatch):
    from packages.joern.runner import _kill_build_group
    process = subprocess.Popen([sys.executable, "-c", "pass"], start_new_session=True)
    process.wait(timeout=5)
    signal_group = Mock()
    monkeypatch.setattr(server.os, "killpg", signal_group)
    assert not _kill_build_group(process)
    signal_group.assert_not_called()
