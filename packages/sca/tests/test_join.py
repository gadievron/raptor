"""Tests for ``packages.sca.join``."""

from __future__ import annotations

from pathlib import Path

from packages.sca.join import join
from packages.sca.models import Confidence, Dependency, PinStyle


def _manifest(
    name: str,
    *,
    ecosystem: str = "npm",
    version: str | None = "1.0.0",
    path: Path,
    pin_style: PinStyle = PinStyle.CARET,
    scope: str = "main",
    direct: bool = True,
    confidence: Confidence | None = None,
) -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=path,
        scope=scope,
        is_lockfile=False,
        pin_style=pin_style,
        direct=direct,
        purl=f"pkg:{ecosystem.lower()}/{name}@{version}",
        parser_confidence=confidence
        or Confidence("high", reason="manifest"),
    )


def _lockfile(
    name: str,
    *,
    ecosystem: str = "npm",
    version: str | None = "1.0.4",
    path: Path,
    pin_style: PinStyle = PinStyle.EXACT,
    scope: str = "main",
    direct: bool = False,
    confidence: Confidence | None = None,
) -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=path,
        scope=scope,
        is_lockfile=True,
        pin_style=pin_style,
        direct=direct,
        purl=f"pkg:{ecosystem.lower()}/{name}@{version}",
        parser_confidence=confidence
        or Confidence("high", reason="lockfile resolved entry"),
    )


# ---------------------------------------------------------------------------
# Direct-flag promotion
# ---------------------------------------------------------------------------

def test_same_dir_lockfile_inherits_direct(tmp_path: Path) -> None:
    pkg = tmp_path / "package.json"
    lock = tmp_path / "package-lock.json"
    deps = [
        _manifest("lodash", path=pkg),
        _lockfile("lodash", path=lock),
        _lockfile("ms", path=lock),  # transitive — no manifest entry
    ]
    out = {d.name: d for d in join(deps) if d.is_lockfile}
    assert out["lodash"].direct is True
    assert out["ms"].direct is False


def test_pin_style_propagates_from_manifest(tmp_path: Path) -> None:
    pkg = tmp_path / "package.json"
    lock = tmp_path / "package-lock.json"
    deps = [
        _manifest("lodash", path=pkg, pin_style=PinStyle.CARET),
        _lockfile("lodash", path=lock, pin_style=PinStyle.EXACT),
    ]
    out = {d.name: d for d in join(deps) if d.is_lockfile}
    # Manifest's caret intent is now visible on the lockfile row.
    assert out["lodash"].pin_style is PinStyle.CARET


def test_no_match_when_ecosystems_differ(tmp_path: Path) -> None:
    pkg = tmp_path / "package.json"
    lock = tmp_path / "Pipfile.lock"
    deps = [
        _manifest("lodash", ecosystem="npm", path=pkg),
        _lockfile("lodash", ecosystem="PyPI", path=lock),
    ]
    out = {d.name: d for d in join(deps) if d.is_lockfile}
    assert out["lodash"].direct is False


# ---------------------------------------------------------------------------
# Workspace / ancestor walk
# ---------------------------------------------------------------------------

def test_lockfile_in_subdir_resolves_via_ancestor(tmp_path: Path) -> None:
    """A leaf-package lockfile finds the leaf manifest in the same dir."""
    leaf = tmp_path / "frontend"
    leaf.mkdir()
    pkg = leaf / "package.json"
    lock = leaf / "package-lock.json"
    deps = [_manifest("react", path=pkg), _lockfile("react", path=lock)]
    out = [d for d in join(deps) if d.is_lockfile]
    assert out[0].direct is True


def test_root_manifest_promotes_subdir_lockfile(tmp_path: Path) -> None:
    """Manifest at the root, lockfile in a subdirectory: lockfile walks up."""
    leaf = tmp_path / "leaf"
    leaf.mkdir()
    root_pkg = tmp_path / "package.json"
    leaf_lock = leaf / "package-lock.json"
    deps = [_manifest("react", path=root_pkg), _lockfile("react", path=leaf_lock)]
    out = [d for d in join(deps) if d.is_lockfile]
    assert out[0].direct is True


def test_sibling_leaves_do_not_cross_pollinate(tmp_path: Path) -> None:
    """Manifest in /a, lockfile in /b: should *not* match.

    The ancestor walk goes up from the lockfile to root, but a sibling
    directory is never an ancestor — so the manifest is invisible.
    """
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    deps = [
        _manifest("react", path=a / "package.json"),
        _lockfile("react", path=b / "package-lock.json"),
    ]
    out = [d for d in join(deps) if d.is_lockfile]
    assert out[0].direct is False


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_manifest_only_dep_unchanged(tmp_path: Path) -> None:
    """A dep that exists only in the manifest must pass through verbatim."""
    pkg = tmp_path / "package.json"
    deps = [_manifest("solo", path=pkg)]
    out = join(deps)
    assert out == deps


def test_lockfile_already_direct_is_not_churned(tmp_path: Path) -> None:
    """When the lockfile parser already marked direct=True (e.g.,
    package-lock v3 root deps) and pin_style matches what we'd promote,
    we leave the row alone — including its parser_confidence reason."""
    pkg = tmp_path / "package.json"
    lock = tmp_path / "package-lock.json"
    deps = [
        _manifest("lodash", path=pkg, pin_style=PinStyle.CARET),
        _lockfile("lodash", path=lock, pin_style=PinStyle.CARET, direct=True,
                  confidence=Confidence("high", reason="root entry")),
    ]
    out = [d for d in join(deps) if d.is_lockfile][0]
    assert out.direct is True
    assert out.parser_confidence.reason == "root entry"


def test_combined_confidence_reflects_manifest_lockfile_agreement(
    tmp_path: Path,
) -> None:
    """When both sides are high, combined reason names the agreement."""
    pkg = tmp_path / "package.json"
    lock = tmp_path / "package-lock.json"
    deps = [
        _manifest("lodash", path=pkg, pin_style=PinStyle.CARET),
        _lockfile("lodash", path=lock, pin_style=PinStyle.EXACT),
    ]
    out = [d for d in join(deps) if d.is_lockfile][0]
    assert out.parser_confidence.level == "high"
    assert "manifest+lockfile" in out.parser_confidence.reason


def test_combined_confidence_takes_weaker_side(tmp_path: Path) -> None:
    """If either side is low, the combined level matches the weaker side."""
    pkg = tmp_path / "package.json"
    lock = tmp_path / "package-lock.json"
    deps = [
        _manifest(
            "lodash",
            path=pkg,
            pin_style=PinStyle.UNKNOWN,
            confidence=Confidence("low", reason="bad spec"),
        ),
        _lockfile("lodash", path=lock, pin_style=PinStyle.EXACT),
    ]
    out = [d for d in join(deps) if d.is_lockfile][0]
    assert out.parser_confidence.level == "low"


def test_input_list_is_not_mutated(tmp_path: Path) -> None:
    """``join`` must return new objects, not mutate the input."""
    pkg = tmp_path / "package.json"
    lock = tmp_path / "package-lock.json"
    locked = _lockfile("lodash", path=lock, direct=False)
    deps = [_manifest("lodash", path=pkg), locked]
    join(deps)
    # Original lockfile dep still has direct=False.
    assert locked.direct is False


def test_empty_input_returns_empty() -> None:
    assert join([]) == []
