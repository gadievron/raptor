"""export() source-side copy discipline — no JVM required.

The worker holds the write grant on its own work dir, so the parent's
copy-out of ``export.json`` must not trust a by-name check: a racing
worker can swap the file for a symlink between an ``is_file()`` probe
and a separate ``open()``. The copy therefore routes through
``core.source.open_regular`` (O_NOFOLLOW + fstat regularity on the
opened fd) — these tests pin that routing and the refusal shapes it
buys (symlink and FIFO plants refused atomically, FIFO without a
blocking open).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

import packages.ghidra.server as server_mod

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX file-type semantics")


def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
            plant) -> "server_mod.GhidraServer":
    """Offline server whose _request 'export' op runs *plant* to
    materialise (or sabotage) the worker output path."""
    monkeypatch.setattr(server_mod, "pyghidra_available", lambda: True)
    gpr = tmp_path / "p.gpr"
    gpr.write_text("")
    srv = server_mod.GhidraServer(gpr)
    srv._work_dir = tmp_path / "work"
    srv._work_dir.mkdir()

    def _fake_request(payload: dict) -> dict:
        assert payload["op"] == "export"
        plant(Path(payload["out"]))
        return {"functions": 7}

    monkeypatch.setattr(srv, "_request", _fake_request)
    return srv


class TestExportCopyHardening:

    def test_regular_export_copies_through_open_regular(
            self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Happy path: bytes copied faithfully, AND the source open is
        pinned to the hardened helper (a regression back to a raw
        open() would pass a pure byte-comparison test)."""
        calls: list[str] = []
        real_open_regular = server_mod.open_regular

        def _spy(path, mode, **kwargs):
            calls.append(str(path))
            return real_open_regular(path, mode, **kwargs)

        monkeypatch.setattr(server_mod, "open_regular", _spy)
        srv = _server(tmp_path, monkeypatch,
                      lambda p: p.write_bytes(b'{"functions": []}'))
        dst = tmp_path / "out" / "export.json"
        assert srv.export(dst) == 7
        assert dst.read_bytes() == b'{"functions": []}'
        assert calls == [str(srv._work_dir / "export.json")]

    def test_symlink_at_worker_out_refused(
            self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A symlink where export.json should be (the swap a racing
        worker would plant) is refused — never followed."""
        victim = tmp_path / "victim.json"
        victim.write_bytes(b'{"secret": true}')
        srv = _server(tmp_path, monkeypatch,
                      lambda p: os.symlink(str(victim), str(p)))
        dst = tmp_path / "out" / "export.json"
        with pytest.raises(server_mod.GhidraServerError,
                           match="regular export file"):
            srv.export(dst)
        assert not dst.exists()

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs mkfifo")
    def test_fifo_at_worker_out_refused_without_hang(
            self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A reader-less FIFO at the worker output path must refuse,
        not block the parent forever (open_regular opens O_NONBLOCK)."""
        srv = _server(tmp_path, monkeypatch,
                      lambda p: os.mkfifo(str(p)))
        dst = tmp_path / "out" / "export.json"
        with pytest.raises(server_mod.GhidraServerError,
                           match="regular export file"):
            srv.export(dst)

    def test_missing_worker_out_refused(
            self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        srv = _server(tmp_path, monkeypatch, lambda p: None)
        with pytest.raises(server_mod.GhidraServerError,
                           match="regular export file"):
            srv.export(tmp_path / "out" / "export.json")

    def test_refusal_leaves_existing_destination_intact(
            self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """The source gate runs BEFORE destination preparation — a
        refused export must not have unlinked a prior good artifact."""
        victim = tmp_path / "victim.json"
        victim.write_bytes(b"x")
        srv = _server(tmp_path, monkeypatch,
                      lambda p: os.symlink(str(victim), str(p)))
        dst = tmp_path / "out" / "export.json"
        dst.parent.mkdir(parents=True)
        dst.write_bytes(b'{"prior": "good"}')
        with pytest.raises(server_mod.GhidraServerError):
            srv.export(dst)
        assert dst.read_bytes() == b'{"prior": "good"}'
