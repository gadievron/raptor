"""npm package-lock.json parser — handles lockfileVersion 1, 2, and 3.

Three on-disk shapes share one filename:

- **v1** (npm <7): a recursive ``"dependencies"`` tree where each node
  holds ``version``, ``resolved``, ``integrity``, ``dev``, ``optional``,
  and a child ``"dependencies"`` for transitive deps.

- **v2** (npm 7-8): keeps the v1 ``"dependencies"`` tree for backward
  compatibility *and* adds a flat ``"packages"`` map keyed by the
  install path (``""`` is the project root, ``"node_modules/foo"`` is a
  dep). Both views describe the same set of deps; we read ``packages``
  because it carries dev/peer/optional flags directly per-row.

- **v3** (npm 9+): ``"packages"`` is the only canonical view; the legacy
  ``"dependencies"`` tree is gone.

Strategy: prefer ``"packages"`` whenever present; fall back to the v1
tree only if ``"packages"`` is absent.

Direct vs transitive: the root entry (``""``) lists which top-level deps
the user declared via ``dependencies`` / ``devDependencies`` /
``peerDependencies`` / ``optionalDependencies``. We use that to flip
``direct=True`` for matching node_modules entries.
"""

from __future__ import annotations

import json as _json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ..models import Confidence, Dependency, PinStyle
from . import register

logger = logging.getLogger(__name__)

ECOSYSTEM = "npm"

# Root-package keys → scope.
_ROOT_KEY_SCOPE: Tuple[Tuple[str, str], ...] = (
    ("dependencies", "main"),
    ("devDependencies", "dev"),
    ("peerDependencies", "peer"),
    ("optionalDependencies", "optional"),
)


def parse(path: Path) -> List[Dependency]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("sca.parsers.package_lock: read failed for %s: %s", path, e)
        return []
    try:
        data = _json.loads(text)
    except _json.JSONDecodeError as e:
        logger.warning(
            "sca.parsers.package_lock: JSON parse failed for %s: %s", path, e
        )
        return []
    if not isinstance(data, dict):
        return []

    if isinstance(data.get("packages"), dict):
        return _parse_v2_or_v3(data, path)
    if isinstance(data.get("dependencies"), dict):
        return _parse_v1(data, path)
    return []


# ---------------------------------------------------------------------------
# v2 / v3 — flat "packages" map
# ---------------------------------------------------------------------------

def _parse_v2_or_v3(data: Dict[str, Any], path: Path) -> List[Dependency]:
    packages = data["packages"]
    direct_names = _direct_names_from_root(packages.get("", {}))

    deps: List[Dependency] = []
    for key, entry in packages.items():
        if key == "":
            # Project root — already harvested for direct-name set.
            continue
        if not isinstance(entry, dict):
            continue
        # ``link: true`` entries are workspace symlinks; the actual
        # package row is reachable via ``resolved`` and recorded
        # elsewhere — skip.
        if entry.get("link") is True:
            continue
        name = _name_from_packages_key(key, entry)
        if name is None:
            continue
        version = entry.get("version") if isinstance(entry.get("version"), str) else None
        scope = _scope_from_packages_entry(entry)

        pin_style, version_for_record = _classify_packages_entry(entry, version)
        is_direct = name in direct_names

        deps.append(Dependency(
            ecosystem=ECOSYSTEM,
            name=name,
            version=version_for_record,
            declared_in=path,
            scope=scope,
            is_lockfile=True,
            pin_style=pin_style,
            direct=is_direct,
            purl=_build_purl(name, version_for_record),
            parser_confidence=_confidence(pin_style, version_for_record),
        ))
    return deps


def _direct_names_from_root(root_entry: Dict[str, Any]) -> Set[str]:
    names: Set[str] = set()
    for key, _scope in _ROOT_KEY_SCOPE:
        block = root_entry.get(key)
        if isinstance(block, dict):
            names.update(k for k in block.keys() if isinstance(k, str))
    return names


def _name_from_packages_key(key: str, entry: Dict[str, Any]) -> Optional[str]:
    """Extract the package name from a packages-map key.

    npm uses install-path keys like ``"node_modules/foo"`` or
    ``"node_modules/@scope/bar"``. Nested ``node_modules`` (a deep
    transitive copy) yields keys like ``"node_modules/a/node_modules/b"``;
    the relevant name is the rightmost ``node_modules/...`` segment.
    """
    explicit = entry.get("name")
    if isinstance(explicit, str) and explicit:
        return explicit
    marker = "node_modules/"
    idx = key.rfind(marker)
    if idx == -1:
        return None
    return key[idx + len(marker):]


def _scope_from_packages_entry(entry: Dict[str, Any]) -> str:
    if entry.get("dev") is True:
        return "dev"
    if entry.get("peer") is True:
        return "peer"
    if entry.get("optional") is True:
        return "optional"
    if entry.get("devOptional") is True:
        # Both dev-only on one path and optional on another — most
        # conservative bucket is "dev" so it doesn't appear in main scans.
        return "dev"
    return "main"


def _classify_packages_entry(
    entry: Dict[str, Any], version: Optional[str]
) -> Tuple[PinStyle, Optional[str]]:
    """Classify pin style for a v2/v3 entry."""
    resolved = entry.get("resolved")
    if isinstance(resolved, str):
        if resolved.startswith(("git+", "git:", "git@")):
            return PinStyle.GIT, version
        if resolved.startswith("file:"):
            return PinStyle.PATH, version
        if resolved.startswith(("http://", "https://")):
            # HTTP tarball — version field is still authoritative.
            return PinStyle.EXACT if version else PinStyle.PATH, version
    if version is None:
        return PinStyle.WILDCARD, None
    return PinStyle.EXACT, version


# ---------------------------------------------------------------------------
# v1 — recursive "dependencies" tree
# ---------------------------------------------------------------------------

def _parse_v1(data: Dict[str, Any], path: Path) -> List[Dependency]:
    out: List[Dependency] = []
    direct_names: Set[str] = set()

    # The v1 root carries "dependencies" only — no separate dev/peer
    # arrays. Per-entry "dev" / "optional" flags drive scope.
    root_deps = data.get("dependencies", {})
    if isinstance(root_deps, dict):
        for name in root_deps.keys():
            if isinstance(name, str):
                direct_names.add(name)
        _walk_v1(root_deps, path, depth=0, direct_names=direct_names, out=out)
    return out


def _walk_v1(
    deps_block: Dict[str, Any],
    path: Path,
    *,
    depth: int,
    direct_names: Set[str],
    out: List[Dependency],
) -> None:
    if depth > 64:
        # Pathological depth; npm-real trees rarely exceed 30. Stop
        # recursion to bound work.
        return
    for name, entry in deps_block.items():
        if not isinstance(name, str) or not isinstance(entry, dict):
            continue
        version = entry.get("version") if isinstance(entry.get("version"), str) else None
        scope = "main"
        if entry.get("dev") is True:
            scope = "dev"
        elif entry.get("optional") is True:
            scope = "optional"

        pin_style: PinStyle
        if isinstance(entry.get("resolved"), str):
            r = entry["resolved"]
            if r.startswith(("git+", "git:", "git@")):
                pin_style = PinStyle.GIT
            elif r.startswith("file:"):
                pin_style = PinStyle.PATH
            else:
                pin_style = PinStyle.EXACT if version else PinStyle.WILDCARD
        else:
            pin_style = PinStyle.EXACT if version else PinStyle.WILDCARD

        out.append(Dependency(
            ecosystem=ECOSYSTEM,
            name=name,
            version=version,
            declared_in=path,
            scope=scope,
            is_lockfile=True,
            pin_style=pin_style,
            direct=(depth == 0 and name in direct_names),
            purl=_build_purl(name, version),
            parser_confidence=_confidence(pin_style, version),
        ))

        nested = entry.get("dependencies")
        if isinstance(nested, dict):
            _walk_v1(
                nested, path,
                depth=depth + 1,
                direct_names=direct_names,
                out=out,
            )


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _build_purl(name: str, version: Optional[str]) -> str:
    base = f"pkg:npm/{name}"
    if version:
        return f"{base}@{version}"
    return base


def _confidence(pin_style: PinStyle, version: Optional[str]) -> Confidence:
    if pin_style is PinStyle.GIT:
        return Confidence("medium", reason="package-lock.json git source")
    if pin_style is PinStyle.PATH:
        return Confidence("medium", reason="package-lock.json file/url source")
    if version is None:
        return Confidence("low", reason="package-lock.json entry without version")
    return Confidence("high", reason="package-lock.json resolved entry")


register(filenames=["package-lock.json", "shrinkwrap.json"])(parse)
