"""Tests for the airgap pack-cache tool's bounded registry fetch."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_TOOL_PATH = Path(__file__).resolve().parents[1] / "tools" / "cache-packs.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("cache_packs", _TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class _FakeResponse:
    """urlopen() stand-in whose read() honours the amount argument."""

    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self, amt: int | None = None) -> bytes:
        if amt is None:
            return self._payload
        return self._payload[:amt]


def test_fetch_pack_normal_response_normalised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mod = _load_tool()
    payload = b'{"rules": [{"id": "r1"}]}'
    monkeypatch.setattr(
        mod, "urlopen", lambda req, timeout: _FakeResponse(payload),
    )
    out = mod.fetch_pack("security-audit")
    assert out == b'{"rules":[{"id":"r1"}]}'


def test_fetch_pack_oversize_response_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A response past the cap is refused at the socket read — only
    cap+1 bytes are ever buffered, and the failure names the cap."""
    mod = _load_tool()
    buffered: list[int] = []

    class _Huge:
        def read(self, amt: int | None = None) -> bytes:
            assert amt is not None, "unbounded read() reintroduced"
            buffered.append(amt)
            return b"x" * amt

    monkeypatch.setattr(mod, "urlopen", lambda req, timeout: _Huge())
    with pytest.raises(SystemExit, match=rf"{mod.MAX_PACK_BYTES}-byte cap"):
        mod.fetch_pack("security-audit")
    assert buffered == [mod.MAX_PACK_BYTES + 1]


# --- cmd_import hardening ---------------------------------------------------


import argparse
import io
import zipfile


def _make_bundle(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _run_import(tmp_path: Path, mod, members: dict[str, bytes]):
    bundle = tmp_path / "bundle.zip"
    bundle.write_bytes(_make_bundle(members))
    mod.CACHE_DIR = tmp_path / "cache"
    mod.cmd_import(argparse.Namespace(zipfile=str(bundle)))


def test_import_rejects_traversal_shaped_names(tmp_path: Path) -> None:
    """Separator / '..' member names are skipped (flat-namespace
    contract) — never joined onto the cache dir, never a crash."""
    mod = _load_tool()
    # Stepping-stone dir that made the escape land outside CACHE_DIR.
    (tmp_path / "cache" / "c.p.sub").mkdir(parents=True)
    _run_import(tmp_path, mod, {
        "c.p.sub/../../escaped.json": b"{}",
        "c.p.sub/../evil.json": b"{}",
        "c.p..dotdot..json": b"{}",  # '..' anywhere is rejected
        "c.p.good.json": b'{"rules": []}',
    })
    assert (tmp_path / "cache" / "c.p.good.json").exists()
    assert not (tmp_path / "escaped.json").exists()
    assert not (tmp_path / "cache" / "evil.json").exists()
    # Only the good member landed as a file.
    files = [p for p in (tmp_path / "cache").rglob("*") if p.is_file()]
    assert files == [tmp_path / "cache" / "c.p.good.json"]


def test_import_caps_member_decompressed_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A member inflating past MAX_PACK_BYTES is skipped, bounding
    memory — the fetch-side cap previously had no import-side twin."""
    mod = _load_tool()
    monkeypatch.setattr(mod, "MAX_PACK_BYTES", 1024)
    big = b'{"pad": "' + b"a" * 4096 + b'"}'
    _run_import(tmp_path, mod, {
        "c.p.big.json": big,
        "c.p.small.json": b'{"rules": []}',
    })
    assert not (tmp_path / "cache" / "c.p.big.json").exists()
    assert (tmp_path / "cache" / "c.p.small.json").exists()


def test_import_valid_members_unchanged(tmp_path: Path) -> None:
    """Two-direction: a normal bundle still imports every pack."""
    mod = _load_tool()
    _run_import(tmp_path, mod, {
        "c.p.security-audit.json": b'{"rules": [{"id": "r1"}]}',
        "c.p.secrets.json": b'{"rules": []}',
        "manifest.json": b'{"fetched_utc": "2026-01-01"}',
    })
    cache = tmp_path / "cache"
    assert (cache / "c.p.security-audit.json").read_bytes() == b'{"rules": [{"id": "r1"}]}'
    assert (cache / "c.p.secrets.json").exists()
    assert not (cache / "manifest.json").exists()
