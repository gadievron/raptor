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


def test_fetch_pack_socket_error_reported_per_pack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A socket-level error from read() (timeout, reset) is the same
    per-pack failure as a URLError — a FAILED line, not a traceback."""
    mod = _load_tool()

    class _Resets:
        def read(self, amt: int | None = None) -> bytes:
            raise TimeoutError("timed out")

    monkeypatch.setattr(mod, "urlopen", lambda req, timeout: _Resets())
    with pytest.raises(SystemExit, match=r"FAILED: security-audit"):
        mod.fetch_pack("security-audit")


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


# --- pack-id validation (the direct update/fetch side) ----------------------


def test_parse_pack_ids_rejects_separator_shaped_ids() -> None:
    """The pack id is spliced into both the registry URL and the cache
    filename — a separator or '..'-leading id must die at parse, never
    reach `CACHE_DIR / cache_filename(pid)`."""
    mod = _load_tool()
    for hostile in (
        "../../x", "a/b", "a\\b", "..", ".hidden", "-flag",
        "UPPER", "sp ace", "",
    ):
        with pytest.raises(SystemExit, match="invalid pack id"):
            mod.parse_pack_ids(hostile)


def test_parse_pack_ids_accepts_registry_names() -> None:
    mod = _load_tool()
    assert mod.parse_pack_ids("security-audit,p/owasp-top-ten, jwt") == [
        "security-audit", "owasp-top-ten", "jwt",
    ]
    # Interior dots stay within the flat cache namespace
    # (c.p.<pid>.json has no separators to escape with).
    assert mod.parse_pack_ids("r2c.internal") == ["r2c.internal"]


def test_cmd_update_refuses_hostile_pack_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: a traversal-shaped --packs id aborts update before
    any fetch or filesystem write."""
    mod = _load_tool()
    mod.CACHE_DIR = tmp_path / "cache"

    def _no_fetch(pid):  # pragma: no cover - must not be reached
        raise AssertionError("fetch_pack reached with unvalidated id")

    monkeypatch.setattr(mod, "fetch_pack", _no_fetch)
    with pytest.raises(SystemExit, match="invalid pack id"):
        mod.cmd_update(argparse.Namespace(packs="../../etc/passwd"))
    assert not (tmp_path / "cache").exists()


# --- DEFAULT_PACKS stays in sync with every pack-requesting layer -----------


def test_default_packs_match_every_pack_source() -> None:
    """DEFAULT_PACKS is intentionally duplicated so the tool stays
    standalone on the connected machine; this is the sync oracle the
    duplication comment promises, over EVERY layer that can request a
    registry pack at scan time: RaptorConfig's baseline and
    policy-group maps, plus the target-type catalog's semgrep_packs
    lists (a matched catalog entry's default packs REPLACE the config
    baseline in the scanner's resolver, so a catalog-only pack missing
    from the bundle is a coverage loss on exactly those target types).
    Drift in the harmful direction — any layer gains a pack the airgap
    bundle lacks — fails here instead of surfacing as a missing pack
    on the airgapped side."""
    pytest.importorskip("yaml")
    from core.config import RaptorConfig
    from core.run import target_types

    mod = _load_tool()
    expected = {
        pack.removeprefix("p/")
        for _, pack in RaptorConfig.BASELINE_SEMGREP_PACKS
    } | {
        pack.removeprefix("p/")
        for _, pack in RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK.values()
    }
    for entry in target_types.all_entries():
        # Optional packs are cached too: they are catalog-declared
        # requestables, and a bundle that lacks one degrades the run
        # that opts in.
        for pack in (*entry.semgrep_packs_default,
                     *entry.semgrep_packs_optional):
            expected.add(pack.removeprefix("p/"))
    assert len(expected) >= 8, "pack-source derivation looks broken"
    assert set(mod.DEFAULT_PACKS) == expected
    # Every default id must satisfy the tool's own grammar.
    assert mod.parse_pack_ids(",".join(mod.DEFAULT_PACKS)) == list(
        mod.DEFAULT_PACKS,
    )


# --- YAML→JSON normalisation stays inside the per-pack contract -------------


def test_fetch_pack_yaml_date_scalar_normalised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """yaml.safe_load turns unquoted ISO dates (routine in semgrep rule
    metadata:) into datetime.date; the JSON normalisation must render
    them as strings — the shape a JSON registry response carries —
    instead of letting a serialisation TypeError escape fetch_pack and
    abort the whole fetch/update on pack 1 of N."""
    pytest.importorskip("yaml")
    mod = _load_tool()
    payload = (
        b"rules:\n- id: r1\n  metadata:\n    updated: 2024-01-01\n"
    )
    monkeypatch.setattr(
        mod, "urlopen", lambda req, timeout: _FakeResponse(payload),
    )
    out = mod.fetch_pack("security-audit")
    assert b'"updated":"2024-01-01"' in out


def test_fetch_pack_unserialisable_yaml_fails_per_pack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A YAML shape json.dumps cannot serialise even with default=str
    (a non-string mapping KEY) is that one pack's failure — the FAILED
    line, never an escaping traceback (per-pack contract)."""
    pytest.importorskip("yaml")
    mod = _load_tool()
    payload = b"rules:\n- id: r1\n  metadata:\n    2024-01-01: seen\n"
    monkeypatch.setattr(
        mod, "urlopen", lambda req, timeout: _FakeResponse(payload),
    )
    with pytest.raises(SystemExit, match=r"FAILED: security-audit"):
        mod.fetch_pack("security-audit")


# --- incomplete update/fetch exit non-zero ----------------------------------


def test_update_all_failed_exits_nonzero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    """An update that wrote 0/N packs must not exit 0 — operators and
    CI key off the exit code, and a silent zero leaves the cache
    stale."""
    mod = _load_tool()
    mod.CACHE_DIR = tmp_path / "cache"

    def _down(req, timeout):
        raise OSError("registry unreachable")

    monkeypatch.setattr(mod, "urlopen", _down)
    with pytest.raises(SystemExit) as ei:
        mod.cmd_update(argparse.Namespace(packs="security-audit,jwt"))
    assert ei.value.code == 1
    assert "0/2" in capsys.readouterr().out


def test_update_complete_exits_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    mod = _load_tool()
    mod.CACHE_DIR = tmp_path / "cache"
    monkeypatch.setattr(
        mod, "urlopen",
        lambda req, timeout: _FakeResponse(b'{"rules": []}'),
    )
    # No SystemExit: both packs written.
    mod.cmd_update(argparse.Namespace(packs="security-audit,jwt"))
    assert (tmp_path / "cache" / "c.p.jwt.json").exists()


def test_fetch_partial_failure_writes_bundle_but_exits_nonzero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    """A partial fetch still writes the bundle (the fetched packs are
    useful) but must exit non-zero and say the bundle is incomplete —
    an airgap build that silently lacks packs is a coverage loss on
    the far side."""
    mod = _load_tool()

    def _flaky(req, timeout):
        if "jwt" in req.full_url:
            raise OSError("registry reset")
        return _FakeResponse(b'{"rules": []}')

    monkeypatch.setattr(mod, "urlopen", _flaky)
    out_zip = tmp_path / "bundle.zip"
    with pytest.raises(SystemExit) as ei:
        mod.cmd_fetch(argparse.Namespace(
            packs="security-audit,jwt", output=str(out_zip),
        ))
    assert ei.value.code == 1
    assert out_zip.exists()
    with zipfile.ZipFile(out_zip) as zf:
        assert "c.p.security-audit.json" in zf.namelist()
        assert "c.p.jwt.json" not in zf.namelist()
    assert "INCOMPLETE" in capsys.readouterr().out
