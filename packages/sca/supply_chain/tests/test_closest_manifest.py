"""Tests for the shared closest-manifest placeholder-dep builder
(``packages.sca.supply_chain._closest_manifest``) used by the
artefacts / exfil / gha-drift / python-imports walkers."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import Manifest, PinStyle
from packages.sca.supply_chain._closest_manifest import (
    closest_manifest,
    project_host_dep,
    rel_to_target,
)


def _manifest(path: Path, ecosystem: str = "npm",
              is_lockfile: bool = False) -> Manifest:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}", encoding="utf-8")
    return Manifest(path=path, ecosystem=ecosystem, is_lockfile=is_lockfile)


def test_nested_manifest_wins_over_root(tmp_path: Path) -> None:
    root = _manifest(tmp_path / "package.json")
    leaf = _manifest(tmp_path / "packages" / "leaf" / "package.json")
    flagged = tmp_path / "packages" / "leaf" / "src" / "x.js"
    best = closest_manifest([root, leaf], flagged)
    assert best is leaf
    # Order-independence: same answer with the candidates reversed.
    assert closest_manifest([leaf, root], flagged) is leaf


def test_lockfiles_are_skipped(tmp_path: Path) -> None:
    lock = _manifest(tmp_path / "sub" / "package-lock.json",
                     is_lockfile=True)
    root = _manifest(tmp_path / "package.json")
    flagged = tmp_path / "sub" / "payload"
    assert closest_manifest([lock, root], flagged) is root


def test_no_usable_manifest_returns_none(tmp_path: Path) -> None:
    assert closest_manifest([], tmp_path / "x") is None


def test_placeholder_dep_anchors_to_closest_manifest(
    tmp_path: Path,
) -> None:
    root = _manifest(tmp_path / "package.json", ecosystem="npm")
    dep = project_host_dep(
        [root], tmp_path / "src" / "x.js", tmp_path,
        reason="placeholder for test finding host",
    )
    assert dep.declared_in == root.path
    assert dep.ecosystem == "npm"
    assert dep.name == "<project>"
    assert dep.scope == "main"
    assert dep.pin_style is PinStyle.UNKNOWN
    assert dep.parser_confidence.reason == "placeholder for test finding host"


def test_placeholder_dep_fallback_without_manifests(
    tmp_path: Path,
) -> None:
    dep = project_host_dep(
        [], tmp_path / "src" / "x.js", tmp_path,
        reason="r",
    )
    assert dep.declared_in == tmp_path
    assert dep.ecosystem == "Project"


def test_placeholder_dep_name_and_scope_parameterised(
    tmp_path: Path,
) -> None:
    """gha_drift's variant: workflow findings carry a distinct name
    and a ``build`` scope."""
    dep = project_host_dep(
        [], tmp_path / ".github" / "workflows" / "ci.yml", tmp_path,
        name="<github-actions>", scope="build", reason="r",
    )
    assert dep.name == "<github-actions>"
    assert dep.scope == "build"


def test_rel_to_target_inside_and_outside(tmp_path: Path) -> None:
    inside = tmp_path / "a" / "b.py"
    assert rel_to_target(inside, tmp_path) == Path("a/b.py")
    outside = Path("/somewhere/else/b.py")
    assert rel_to_target(outside, tmp_path) == outside
