"""Tests for ``packages.sca.supply_chain.binary_in_package``."""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca.models import Confidence, Dependency, Manifest, PinStyle
from packages.sca.supply_chain.binary_in_package import scan_target


def _manifest(tmp_path: Path, name: str = "pkg",
              extra: dict | None = None) -> Manifest:
    payload = {"name": name}
    if extra:
        payload.update(extra)
    p = tmp_path / "package.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return Manifest(path=p, ecosystem="npm", is_lockfile=False)


def _dep(manifest: Manifest, name: str = "pkg",
         version: str = "1.0.0") -> Dependency:
    return Dependency(
        ecosystem="npm", name=name, version=version,
        declared_in=manifest.path,
        scope="main", is_lockfile=False,
        pin_style=PinStyle.EXACT, direct=True,
        purl=f"pkg:npm/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
    )


# ---------------------------------------------------------------------------
# Detection — Iron Worm shape
# ---------------------------------------------------------------------------

def test_elf_at_tools_setup_is_flagged(tmp_path: Path) -> None:
    """The literal Iron Worm path: ``tools/setup`` ELF."""
    m = _manifest(tmp_path)
    d = _dep(m)
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "setup").write_bytes(b"\x7fELF" + b"\x00" * 16)
    hits = scan_target(tmp_path, [m], [d])
    assert len(hits) == 1
    assert hits[0].relpath == "tools/setup"
    assert hits[0].family == "elf"


def test_pe_at_repo_root_is_flagged(tmp_path: Path) -> None:
    m = _manifest(tmp_path)
    (tmp_path / "agent.exe").write_bytes(b"MZ" + b"\x00" * 64)
    hits = scan_target(tmp_path, [m], [_dep(m)])
    assert len(hits) == 1 and hits[0].family == "pe"


def test_macho_at_bin_dir_is_flagged(tmp_path: Path) -> None:
    m = _manifest(tmp_path)
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "agent").write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00")
    hits = scan_target(tmp_path, [m], [_dep(m)])
    assert len(hits) == 1 and hits[0].family == "macho"


# ---------------------------------------------------------------------------
# Allowlist — legitimate locations must suppress
# ---------------------------------------------------------------------------

def test_prebuilds_binary_suppressed(tmp_path: Path) -> None:
    """``prebuilds/linux-x64/foo.node`` — prebuildify standard
    layout.  Must NOT fire."""
    m = _manifest(tmp_path)
    (tmp_path / "prebuilds" / "linux-x64").mkdir(parents=True)
    (tmp_path / "prebuilds" / "linux-x64" / "foo.node").write_bytes(
        b"\x7fELF" + b"\x00" * 16,
    )
    hits = scan_target(tmp_path, [m], [_dep(m)])
    assert hits == []


def test_wasm_with_correct_magic_suppressed(tmp_path: Path) -> None:
    """``foo.wasm`` with WASM magic — legitimate WebAssembly."""
    m = _manifest(tmp_path)
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "foo.wasm").write_bytes(b"\x00asm\x01\x00\x00\x00")
    hits = scan_target(tmp_path, [m], [_dep(m)])
    assert hits == []


def test_wasm_extension_with_elf_payload_still_flagged(
    tmp_path: Path,
) -> None:
    """``.wasm`` extension wearing ELF bytes — magic_required
    forbids the suppression.  Must fire."""
    m = _manifest(tmp_path)
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "evil.wasm").write_bytes(b"\x7fELF" + b"\x00")
    hits = scan_target(tmp_path, [m], [_dep(m)])
    assert len(hits) == 1
    assert hits[0].family == "elf"


def test_test_fixture_binary_suppressed(tmp_path: Path) -> None:
    """``tests/fixtures/sample.elf`` — explicit test corpus."""
    m = _manifest(tmp_path)
    (tmp_path / "tests" / "fixtures").mkdir(parents=True)
    (tmp_path / "tests" / "fixtures" / "sample.elf").write_bytes(
        b"\x7fELF" + b"\x00",
    )
    hits = scan_target(tmp_path, [m], [_dep(m)])
    assert hits == []


def test_vendored_dep_binary_suppressed(tmp_path: Path) -> None:
    m = _manifest(tmp_path)
    (tmp_path / "vendor" / "foo").mkdir(parents=True)
    (tmp_path / "vendor" / "foo" / "agent").write_bytes(
        b"\x7fELF" + b"\x00",
    )
    hits = scan_target(tmp_path, [m], [_dep(m)])
    assert hits == []


# ---------------------------------------------------------------------------
# Per-package opt-in — manifest declarations
# ---------------------------------------------------------------------------

def test_manifest_with_binary_field_suppresses_walk(tmp_path: Path) -> None:
    """``package.json:binary`` declares native binary opt-in.  We
    skip the walk entirely for fully-opt-in projects."""
    m = _manifest(tmp_path, extra={"binary": {"module_name": "foo"}})
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "setup").write_bytes(b"\x7fELF" + b"\x00")
    hits = scan_target(tmp_path, [m], [_dep(m)])
    assert hits == []


# ---------------------------------------------------------------------------
# Per-platform binary package name convention
# ---------------------------------------------------------------------------

def test_per_platform_package_name_suppresses(tmp_path: Path) -> None:
    """``@esbuild/linux-x64`` — name explicitly encodes platform.
    These packages exist to ship binaries; we don't flag them."""
    m = _manifest(tmp_path, name="@esbuild/linux-x64")
    d = _dep(m, name="@esbuild/linux-x64")
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "esbuild").write_bytes(b"\x7fELF" + b"\x00")
    hits = scan_target(tmp_path, [m], [d])
    assert hits == []


# ---------------------------------------------------------------------------
# Adversarial: symlinks, traversal, oversize files
# ---------------------------------------------------------------------------

def test_symlink_not_followed(tmp_path: Path) -> None:
    """Symlink in tree pointing to host binary must NOT be
    classified."""
    import os
    m = _manifest(tmp_path)
    outside = tmp_path.parent / "outside-binary"
    outside.write_bytes(b"\x7fELF" + b"\x00")
    (tmp_path / "tools").mkdir()
    link = tmp_path / "tools" / "setup"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        import pytest
        pytest.skip("symlinks unavailable")
    hits = scan_target(tmp_path, [m], [_dep(m)])
    assert hits == []


def test_text_file_with_elf_extension_not_flagged(tmp_path: Path) -> None:
    """File ending in ``.elf`` whose CONTENT is text doesn't fire —
    we classify on magic bytes, not extension."""
    m = _manifest(tmp_path)
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "notes.elf").write_text(
        "this is a text file\n", encoding="utf-8",
    )
    hits = scan_target(tmp_path, [m], [_dep(m)])
    assert hits == []


def test_only_first_bytes_read_on_giant_file(tmp_path: Path) -> None:
    """Multi-MB ELF: we classify from first 256 bytes — don't read
    the whole file."""
    m = _manifest(tmp_path)
    (tmp_path / "tools").mkdir()
    big = tmp_path / "tools" / "setup"
    big.write_bytes(b"\x7fELF" + b"\x00" * (2 * 1024 * 1024))
    hits = scan_target(tmp_path, [m], [_dep(m)])
    assert len(hits) == 1


def test_excluded_dir_skipped(tmp_path: Path) -> None:
    """``.git/objects/...`` style files in excluded dirs must not
    be walked."""
    m = _manifest(tmp_path)
    (tmp_path / ".git" / "objects").mkdir(parents=True)
    (tmp_path / ".git" / "objects" / "pack").write_bytes(
        b"\x7fELF" + b"\x00",
    )
    hits = scan_target(tmp_path, [m], [_dep(m)])
    assert hits == []


def test_empty_target_dir_no_findings(tmp_path: Path) -> None:
    m = _manifest(tmp_path)
    assert scan_target(tmp_path, [m], [_dep(m)]) == []
