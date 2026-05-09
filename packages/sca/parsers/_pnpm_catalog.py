"""pnpm-workspace.yaml catalog resolution.

pnpm 9 added the ``catalog:`` mechanism: a workspace can declare
shared version pins in ``pnpm-workspace.yaml`` and reference them
from each member ``package.json`` as ``"react": "catalog:"`` or
``"react": "catalog:react17"``.

Without resolving the catalog, the spec ``"catalog:"`` is opaque:
SCA can't classify the pin style, can't query OSV, can't emit a
useful purl.

This module discovers the project's ``pnpm-workspace.yaml`` (by
walking up from a given ``package.json`` path), parses its
``catalog`` (default) and ``catalogs.<name>`` sections, and exposes
a tiny resolver that maps a ``catalog:[<name>]`` spec to its
declared version range.

YAML parsing degrades gracefully when ``yaml`` (PyYAML) isn't
available — returns an empty resolver, the spec stays unresolved
in the consumer, the operator sees an UNKNOWN-pin row in their
report.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)


# Per-root cache: ``{repo_root: {catalog_name_or_default:
# {package: version_spec}}}``. ``""`` is the default catalog.
# Consulted across parser invocations within the same process so
# every package.json in a workspace pays the YAML parse once.
_CATALOG_CACHE: Dict[Path, Dict[str, Dict[str, str]]] = {}


def find_workspace_root(start: Path) -> Optional[Path]:
    """Walk up from ``start`` looking for ``pnpm-workspace.yaml``.

    ``start`` is typically the directory containing a member
    ``package.json``. Returns the directory containing the YAML, or
    None if no such ancestor exists. Stops at the filesystem root.
    """
    cur = start.resolve()
    if cur.is_file():
        cur = cur.parent
    while True:
        if (cur / "pnpm-workspace.yaml").is_file():
            return cur
        if cur.parent == cur:
            return None
        cur = cur.parent


def get_catalogs(root: Path) -> Dict[str, Dict[str, str]]:
    """Return ``{catalog_name: {package: version_spec}}`` for the
    workspace rooted at ``root``. Empty dict on missing or
    malformed YAML.
    """
    root = root.resolve()
    cached = _CATALOG_CACHE.get(root)
    if cached is not None:
        return cached
    catalogs = _parse_catalogs(root / "pnpm-workspace.yaml")
    _CATALOG_CACHE[root] = catalogs
    return catalogs


def resolve_catalog_spec(
    spec: str, package_name: str, catalogs: Dict[str, Dict[str, str]],
) -> Optional[str]:
    """Resolve a ``catalog:[<name>]`` spec to its declared version.

    ``spec`` is the full string, e.g. ``"catalog:"`` (default
    catalog) or ``"catalog:react17"`` (named catalog).
    ``package_name`` is the dependency's name — pnpm catalogs are
    keyed by package name within each catalog.

    Returns the version-spec string from the catalog (e.g.
    ``"^18.2.0"``), or None if the catalog or package isn't
    declared.
    """
    if not spec.startswith("catalog:"):
        return None
    name = spec[len("catalog:"):].strip()
    cat_key = name or ""              # default catalog uses empty key
    return (catalogs.get(cat_key) or {}).get(package_name)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _parse_catalogs(path: Path) -> Dict[str, Dict[str, str]]:
    """Read the YAML and return the catalog map.

    Schema (pnpm 9):

      .. code-block:: yaml

         catalog:
           react: ^18.2.0
           lodash: 4.17.21
         catalogs:
           react17:
             react: ^17.0.0
             react-dom: ^17.0.0

    Either of ``catalog`` (default) or ``catalogs`` (named) may be
    absent. The default catalog is keyed under ``""`` in the
    returned dict; named catalogs use their declared name.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}

    try:
        import yaml  # type: ignore[import-untyped]
        from .._yaml_fast import safe_load
    except ImportError:
        logger.debug(
            "sca.parsers._pnpm_catalog: PyYAML not installed; "
            "catalog references stay unresolved",
        )
        return {}

    try:
        data = safe_load(text)
    except yaml.YAMLError as e:
        logger.warning(
            "sca.parsers._pnpm_catalog: parse failed for %s: %s",
            path, e,
        )
        return {}

    if not isinstance(data, dict):
        return {}

    out: Dict[str, Dict[str, str]] = {}
    default = data.get("catalog")
    if isinstance(default, dict):
        out[""] = {
            k: v for k, v in default.items()
            if isinstance(k, str) and isinstance(v, str)
        }
    named = data.get("catalogs")
    if isinstance(named, dict):
        for cat_name, entries in named.items():
            if not isinstance(cat_name, str) or not isinstance(entries, dict):
                continue
            out[cat_name] = {
                k: v for k, v in entries.items()
                if isinstance(k, str) and isinstance(v, str)
            }
    return out


def _clear_cache() -> None:
    """Test helper — clear the per-root catalog cache."""
    _CATALOG_CACHE.clear()


# ---------------------------------------------------------------------------
# npm / Yarn workspaces — ``workspaces`` field detection
# ---------------------------------------------------------------------------
#
# npm 7+, Yarn classic, and Yarn Berry all use the same shape: a top-
# level ``package.json`` declares ``"workspaces": ["packages/*"]``
# (array form) or ``"workspaces": {"packages": ["packages/*"]}`` (Yarn
# nohoist form). Each entry is a glob — usually ``packages/*`` or
# ``apps/*`` — that resolves to one or more directories each containing
# their own ``package.json``.
#
# This is distinct from pnpm's ``pnpm-workspace.yaml``: same conceptual
# model, different declaration mechanism. The two coexist in some
# projects (pnpm + an npm-shaped ``workspaces`` field for tooling
# compat).
#
# Why we care: a workspace member's ``Dependency`` rows should carry
# ``workspace_root`` pointing at the monorepo root, so hygiene checks
# (divergent versions across workspaces, cross-workspace dep
# coordination) cluster correctly. Without this, ``hygiene.py``'s
# divergent-version grouping uses ``declared_in.parent`` which fragments
# nested monorepos.


def find_npm_workspace_root(start: Path) -> Optional[Path]:
    """Walk up from ``start`` looking for an ancestor ``package.json``
    with a ``workspaces`` field whose globs match the directory
    containing ``start``.

    ``start`` is typically the path to a member ``package.json``.
    Returns the directory containing the ROOT ``package.json`` (i.e.
    the monorepo root), or ``None`` if no ancestor declares this path
    as a workspace member.

    Stops at the filesystem root. Defensive against unreadable / non-
    JSON / non-object package.json files (treats them as "no
    workspaces declared here, keep walking").

    Returns ``None`` for a package.json that IS the workspace root —
    callers wanting to distinguish "this is a member" from "this is
    the root" check ``find_npm_workspace_root(p) != p.parent.resolve()``.
    """
    cur = start.resolve()
    if cur.is_file():
        cur = cur.parent

    target = cur
    walk = cur.parent
    while True:
        parent_pkg = walk / "package.json"
        if parent_pkg.is_file():
            patterns = _read_workspaces_field(parent_pkg)
            if patterns and _target_matches_any(target, walk, patterns):
                return walk
        if walk.parent == walk:
            return None
        walk = walk.parent


def _read_workspaces_field(pkg_json: Path) -> Optional[list]:
    """Return the ``workspaces`` list from a package.json, normalising
    the Yarn nohoist object form. ``None`` on missing field /
    unreadable / non-JSON / wrong-type."""
    import json as _json
    try:
        text = pkg_json.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    try:
        data = _json.loads(text)
    except (_json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    raw = data.get("workspaces")
    if isinstance(raw, list):
        return [p for p in raw if isinstance(p, str)]
    if isinstance(raw, dict):
        # Yarn nohoist form: ``{"packages": [...], "nohoist": [...]}``.
        # Only the ``packages`` list contributes member globs; nohoist
        # patterns gate hoisting behaviour and aren't workspace
        # declarations.
        pkgs = raw.get("packages")
        if isinstance(pkgs, list):
            return [p for p in pkgs if isinstance(p, str)]
    return None


def _target_matches_any(
    target: Path, root: Path, patterns: list,
) -> bool:
    """Return True iff ``target`` (a directory) matches any of
    ``patterns`` interpreted as workspace globs relative to ``root``.

    Supports the workspace-glob shapes npm / Yarn accept:
      * ``packages/foo`` — exact directory
      * ``packages/*`` — single-level glob
      * ``packages/**`` — recursive glob (Yarn Berry; some npm
        versions)
      * ``!packages/legacy`` — negation (skipped: anything matching
        a negation is NOT a member)

    Negations are processed AFTER inclusions: a target included by an
    earlier pattern can be excluded by a later ``!`` pattern. Same
    semantics as npm / Yarn's resolution.
    """
    try:
        rel = target.resolve().relative_to(root.resolve())
    except ValueError:
        # target isn't under root — not a workspace member.
        return False
    rel_str = rel.as_posix()
    if not rel_str or rel_str == ".":
        # Root package.json's directory itself isn't a "member" of
        # its own workspaces.
        return False

    matched = False
    for pat in patterns:
        if not isinstance(pat, str) or not pat:
            continue
        if pat.startswith("!"):
            negation = pat[1:]
            if _glob_match(rel_str, negation):
                matched = False
        else:
            if _glob_match(rel_str, pat):
                matched = True
    return matched


def _glob_match(rel: str, pattern: str) -> bool:
    """Lightweight glob matcher tailored to npm/Yarn workspace
    patterns. ``fnmatch`` doesn't quite fit because npm globs are
    path-aware (``packages/*`` matches ``packages/foo`` but NOT
    ``packages/foo/bar``).
    """
    import fnmatch
    # Strip trailing slash; npm allows ``packages/*/`` as a synonym.
    pattern = pattern.rstrip("/")
    rel = rel.rstrip("/")
    if "**" in pattern:
        # ``a/**/b`` matches any depth between a and b. Translate to
        # an fnmatch-friendly regex via ``**`` → ``*``-wildcard ×
        # any-dirs.
        return fnmatch.fnmatch(rel, pattern.replace("**", "*"))
    # Single-level glob: ``packages/*`` matches ``packages/foo`` but
    # not ``packages/foo/bar``. Count the slashes: pattern's slash
    # count must equal rel's slash count.
    if pattern.count("/") != rel.count("/"):
        return False
    return fnmatch.fnmatchcase(rel, pattern)


__all__ = [
    "find_npm_workspace_root",
    "find_workspace_root",
    "get_catalogs",
    "resolve_catalog_spec",
]
