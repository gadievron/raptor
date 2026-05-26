"""Tests for the Cargo (Rust) parser."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import PinStyle
from packages.sca.parsers.cargo import parse_lockfile, parse_manifest


def _write(tmp_path: Path, body: str, name: str) -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Cargo.toml — manifest
# ---------------------------------------------------------------------------

def test_basic_dependencies(tmp_path: Path) -> None:
    body = """\
[package]
name = "myapp"
version = "0.1.0"

[dependencies]
serde = "1.0.190"
tokio = "1.20"
"""
    p = _write(tmp_path, body, "Cargo.toml")
    deps = parse_manifest(p)
    by_name = {d.name: d for d in deps}
    # Bare strings are caret in Cargo. The ``serde`` spec ``"1.0.190"``
    # is implicitly ``^1.0.190``.
    assert by_name["serde"].version == "1.0.190"
    assert by_name["serde"].pin_style is PinStyle.CARET
    assert by_name["tokio"].pin_style is PinStyle.CARET
    assert by_name["serde"].purl == "pkg:cargo/serde@1.0.190"


def test_explicit_caret_tilde_eq_range(tmp_path: Path) -> None:
    body = """\
[dependencies]
exact = "=1.0.0"
caret = "^1.0.0"
tilde = "~1.0.0"
greater = ">=1.0.0"
range = ">=1.0, <2.0"
star = "*"
"""
    p = _write(tmp_path, body, "Cargo.toml")
    deps = {d.name: d for d in parse_manifest(p)}
    assert deps["exact"].pin_style is PinStyle.EXACT
    assert deps["caret"].pin_style is PinStyle.CARET
    assert deps["tilde"].pin_style is PinStyle.TILDE
    assert deps["greater"].pin_style is PinStyle.RANGE
    assert deps["range"].pin_style is PinStyle.RANGE
    assert deps["star"].pin_style is PinStyle.WILDCARD


def test_table_form_dependency(tmp_path: Path) -> None:
    body = """\
[dependencies]
tokio = { version = "1.20", features = ["full"] }
"""
    p = _write(tmp_path, body, "Cargo.toml")
    deps = parse_manifest(p)
    assert len(deps) == 1
    assert deps[0].name == "tokio"
    assert deps[0].version == "1.20"
    assert deps[0].pin_style is PinStyle.CARET


def test_git_dependency(tmp_path: Path) -> None:
    body = """\
[dependencies]
my-fork = { git = "https://github.com/me/my-fork", tag = "v1.0" }
"""
    p = _write(tmp_path, body, "Cargo.toml")
    deps = parse_manifest(p)
    assert len(deps) == 1
    assert deps[0].name == "my-fork"
    assert deps[0].pin_style is PinStyle.GIT
    assert deps[0].version is None


def test_path_dependency(tmp_path: Path) -> None:
    body = """\
[dependencies]
local = { path = "../other" }
"""
    p = _write(tmp_path, body, "Cargo.toml")
    deps = parse_manifest(p)
    assert len(deps) == 1
    assert deps[0].pin_style is PinStyle.PATH


def test_workspace_inherit(tmp_path: Path) -> None:
    body = """\
[dependencies]
shared = { workspace = true }
"""
    p = _write(tmp_path, body, "Cargo.toml")
    deps = parse_manifest(p)
    assert len(deps) == 1
    assert deps[0].name == "shared"
    assert deps[0].version is None
    assert deps[0].pin_style is PinStyle.UNKNOWN


def test_dev_and_build_deps_distinguished(tmp_path: Path) -> None:
    body = """\
[dependencies]
serde = "1.0"

[dev-dependencies]
criterion = "0.5"

[build-dependencies]
cc = "1.0"
"""
    p = _write(tmp_path, body, "Cargo.toml")
    by_name = {d.name: d for d in parse_manifest(p)}
    assert by_name["serde"].scope == "main"
    assert by_name["criterion"].scope == "dev"
    assert by_name["cc"].scope == "build"


def test_target_dependencies(tmp_path: Path) -> None:
    """``[target.'cfg(unix)'.dependencies]`` deps still surface as main."""
    body = """\
[target.'cfg(unix)'.dependencies]
nix = "0.27"

[target.'cfg(windows)'.dependencies]
winapi = "0.3"
"""
    p = _write(tmp_path, body, "Cargo.toml")
    by_name = {d.name: d for d in parse_manifest(p)}
    assert "nix" in by_name and "winapi" in by_name
    assert by_name["nix"].scope == "main"


def test_malformed_toml_returns_empty(tmp_path: Path) -> None:
    p = _write(tmp_path, "this is = not [valid toml", "Cargo.toml")
    assert parse_manifest(p) == []


# ---------------------------------------------------------------------------
# Cargo.lock — lockfile
# ---------------------------------------------------------------------------

def test_lockfile_basic(tmp_path: Path) -> None:
    body = """\
version = 3

[[package]]
name = "serde"
version = "1.0.190"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc123"

[[package]]
name = "tokio"
version = "1.32.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""
    p = _write(tmp_path, body, "Cargo.lock")
    deps = parse_lockfile(p)
    by_name = {d.name: d for d in deps}
    assert by_name["serde"].version == "1.0.190"
    assert by_name["serde"].pin_style is PinStyle.EXACT
    assert by_name["serde"].is_lockfile is True


def test_lockfile_git_source(tmp_path: Path) -> None:
    body = """\
[[package]]
name = "my-fork"
version = "0.1.0"
source = "git+https://github.com/me/my-fork#abcdef"
"""
    p = _write(tmp_path, body, "Cargo.lock")
    deps = parse_lockfile(p)
    assert len(deps) == 1
    assert deps[0].pin_style is PinStyle.GIT


def test_lockfile_workspace_member(tmp_path: Path) -> None:
    """Workspace-member entries lack a ``source`` field; treat as path."""
    body = """\
[[package]]
name = "myapp"
version = "0.1.0"
"""
    p = _write(tmp_path, body, "Cargo.lock")
    deps = parse_lockfile(p)
    assert len(deps) == 1
    assert deps[0].pin_style is PinStyle.PATH


def test_lockfile_dedup(tmp_path: Path) -> None:
    """Same (name, version) pair appearing twice (workspace + dep) → 1."""
    body = """\
[[package]]
name = "serde"
version = "1.0.190"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "serde"
version = "1.0.190"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""
    p = _write(tmp_path, body, "Cargo.lock")
    deps = parse_lockfile(p)
    assert len(deps) == 1


def test_lockfile_skips_malformed_entries(tmp_path: Path) -> None:
    body = """\
[[package]]
name = "serde"
version = "1.0.190"

[[package]]
# missing version
name = "bad"
"""
    p = _write(tmp_path, body, "Cargo.lock")
    deps = parse_lockfile(p)
    assert len(deps) == 1
    assert deps[0].name == "serde"


# ---------------------------------------------------------------------------
# Discovery → parser dispatch
# ---------------------------------------------------------------------------

def test_dispatch_via_discovery(tmp_path: Path) -> None:
    from packages.sca.discovery import find_manifests
    from packages.sca.parsers import parse_manifest as dispatch

    repo = tmp_path / "rust-proj"
    repo.mkdir()
    (repo / "Cargo.toml").write_text(
        '[dependencies]\nserde = "1.0"\n', encoding="utf-8")

    manifests = find_manifests(repo)
    cargo = next(m for m in manifests if m.path.name == "Cargo.toml")
    assert cargo.ecosystem == "Cargo"
    deps = dispatch(cargo)
    assert deps and deps[0].name == "serde"
