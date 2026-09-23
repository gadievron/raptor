"""_zip_members must bound work BEFORE parsing: ZipFile(path)
materialises the whole central directory at open, so a post-parse
namelist slice bounds nothing against a crafted many-entry archive."""

from __future__ import annotations

import zipfile
from pathlib import Path

import packages.binary_analysis.manifest as manifest_mod
from packages.binary_analysis.manifest import (
    _zip_central_directory_bounds,
    _zip_members,
)


def _make_zip(path: Path, entries: int) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        for i in range(entries):
            zf.writestr(f"member-{i}.txt", "")


def test_benign_zip_members_listed(tmp_path):
    zp = tmp_path / "small.zip"
    _make_zip(zp, 3)
    assert _zip_members(zp) == {
        "member-0.txt", "member-1.txt", "member-2.txt"}


def test_eocd_bounds_read_without_parsing(tmp_path):
    zp = tmp_path / "counted.zip"
    _make_zip(zp, 42)
    bounds = _zip_central_directory_bounds(zp)
    assert bounds is not None
    total, cd_size = bounds
    assert total == 42
    assert 0 < cd_size < zp.stat().st_size


def test_over_cap_archive_refused_before_parse(tmp_path, monkeypatch):
    zp = tmp_path / "dense.zip"
    _make_zip(zp, 150)
    monkeypatch.setattr(manifest_mod, "_MAX_ZIP_MEMBERS", 100)

    def boom(*args, **kwargs):
        raise AssertionError(
            "ZipFile opened an archive the EOCD gate must refuse")

    monkeypatch.setattr(manifest_mod.zipfile, "ZipFile", boom)
    assert _zip_members(zp) == set()


def test_oversized_central_directory_refused(tmp_path, monkeypatch):
    zp = tmp_path / "widecd.zip"
    _make_zip(zp, 5)
    monkeypatch.setattr(manifest_mod, "_MAX_ZIP_CDIR_BYTES", 8)
    assert _zip_members(zp) == set()


def test_non_zip_returns_empty(tmp_path):
    p = tmp_path / "not-a-zip.bin"
    p.write_bytes(b"\x7fELF" + b"\x00" * 64)
    assert _zip_members(p) == set()
