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
