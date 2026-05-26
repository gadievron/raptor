"""Tests for the Go module parser (go.mod + go.sum)."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import PinStyle
from packages.sca.parsers.gomod import parse_lockfile, parse_manifest


def _write(tmp_path: Path, body: str, name: str) -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# go.mod — manifest
# ---------------------------------------------------------------------------

def test_block_require(tmp_path: Path) -> None:
    body = """\
module github.com/me/myapp

go 1.22

require (
    github.com/foo/bar v1.2.3
    github.com/baz/qux v0.5.0
)
"""
    p = _write(tmp_path, body, "go.mod")
    by_name = {d.name: d for d in parse_manifest(p)}
    assert by_name["github.com/foo/bar"].version == "v1.2.3"
    assert by_name["github.com/foo/bar"].pin_style is PinStyle.EXACT
    assert by_name["github.com/foo/bar"].direct is True
    assert by_name["github.com/baz/qux"].version == "v0.5.0"


def test_indirect_marks_transitive(tmp_path: Path) -> None:
    body = """\
require (
    github.com/foo/bar v1.2.3
    github.com/baz/qux v0.5.0 // indirect
)
"""
    p = _write(tmp_path, body, "go.mod")
    by_name = {d.name: d for d in parse_manifest(p)}
    assert by_name["github.com/foo/bar"].direct is True
    assert by_name["github.com/baz/qux"].direct is False


def test_single_line_require(tmp_path: Path) -> None:
    body = """\
require github.com/single/dep v1.0.0
"""
    p = _write(tmp_path, body, "go.mod")
    deps = parse_manifest(p)
    assert len(deps) == 1
    assert deps[0].name == "github.com/single/dep"
    assert deps[0].version == "v1.0.0"


def test_pseudo_version_classified_as_git(tmp_path: Path) -> None:
    """``v0.0.0-20210101120000-abcdef123456`` — pseudo-version pins to a
    specific commit; treat as GIT pin."""
    body = """\
require github.com/foo/bar v0.0.0-20210101120000-abcdef123456
"""
    p = _write(tmp_path, body, "go.mod")
    deps = parse_manifest(p)
    assert len(deps) == 1
    assert deps[0].pin_style is PinStyle.GIT


def test_replace_to_other_module(tmp_path: Path) -> None:
    body = """\
require github.com/foo/bar v1.2.3

replace github.com/foo/bar => github.com/me/forked v1.2.3-mine
"""
    p = _write(tmp_path, body, "go.mod")
    deps = parse_manifest(p)
    assert len(deps) == 1
    # Original is dropped; replacement is the surfaced dep.
    assert deps[0].name == "github.com/me/forked"
    assert deps[0].version == "v1.2.3-mine"


def test_replace_to_local_path(tmp_path: Path) -> None:
    body = """\
require github.com/foo/bar v1.2.3

replace github.com/foo/bar => ../local
"""
    p = _write(tmp_path, body, "go.mod")
    deps = parse_manifest(p)
    assert len(deps) == 1
    assert deps[0].pin_style is PinStyle.PATH
    assert deps[0].version is None


def test_block_replace(tmp_path: Path) -> None:
    body = """\
require github.com/foo/bar v1.2.3

replace (
    github.com/foo/bar => github.com/me/forked v1.2.3-mine
)
"""
    p = _write(tmp_path, body, "go.mod")
    deps = parse_manifest(p)
    assert len(deps) == 1
    assert deps[0].name == "github.com/me/forked"


def test_empty_or_malformed_returns_empty(tmp_path: Path) -> None:
    p = _write(tmp_path, "", "go.mod")
    assert parse_manifest(p) == []


# ---------------------------------------------------------------------------
# go.sum — lockfile
# ---------------------------------------------------------------------------

def test_lockfile_basic(tmp_path: Path) -> None:
    body = """\
github.com/foo/bar v1.2.3 h1:abc123
github.com/foo/bar v1.2.3/go.mod h1:def456
github.com/baz/qux v0.5.0 h1:ghi789
github.com/baz/qux v0.5.0/go.mod h1:jkl012
"""
    p = _write(tmp_path, body, "go.sum")
    deps = parse_lockfile(p)
    by_name = {d.name: d for d in deps}
    # Two distinct modules; ``/go.mod`` lines deduped.
    assert len(deps) == 2
    assert by_name["github.com/foo/bar"].version == "v1.2.3"
    assert by_name["github.com/foo/bar"].is_lockfile is True


def test_lockfile_skips_malformed(tmp_path: Path) -> None:
    body = """\
github.com/foo/bar v1.2.3 h1:abc

malformed line
github.com/baz/qux v0.5.0 h1:def
"""
    p = _write(tmp_path, body, "go.sum")
    deps = parse_lockfile(p)
    assert len(deps) == 2


# ---------------------------------------------------------------------------
# Discovery → parser dispatch
# ---------------------------------------------------------------------------

def test_dispatch_via_discovery(tmp_path: Path) -> None:
    from packages.sca.discovery import find_manifests
    from packages.sca.parsers import parse_manifest as dispatch

    repo = tmp_path / "go-proj"
    repo.mkdir()
    (repo / "go.mod").write_text(
        "module example\n\nrequire github.com/foo/bar v1.0.0\n",
        encoding="utf-8",
    )
    manifests = find_manifests(repo)
    gm = next(m for m in manifests if m.path.name == "go.mod")
    assert gm.ecosystem == "Go"
    deps = dispatch(gm)
    assert deps and deps[0].name == "github.com/foo/bar"
