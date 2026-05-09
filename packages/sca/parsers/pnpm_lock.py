"""pnpm-lock.yaml parser — pnpm's lockfile (YAML).

Two on-disk shapes share one filename:

- **lockfileVersion <6** (pnpm 7-): top-level ``dependencies`` /
  ``devDependencies`` / ``optionalDependencies`` blocks; ``packages`` keys
  are slash-separated: ``/lodash/4.17.21`` or ``/@scope/name/1.0``.

- **lockfileVersion 6+** (pnpm 8+): an ``importers`` map with one entry
  per workspace path (``.`` for the root); each importer has ``dependencies``
  / ``devDependencies`` / ``peerDependencies`` / ``optionalDependencies``
  with ``{specifier, version}`` records. ``packages`` keys are
  ``/name@version`` (or ``/@scope/name@version``).

Direct vs transitive: a name listed under any importer's dependency
buckets is direct in that workspace. The ``packages`` map is the union
of every workspace's resolved tree.

Pin style: lockfile rows are resolved → EXACT, unless ``resolution.tarball``
or ``resolution.repo`` indicate a git/url source.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ..models import Confidence, Dependency, PinStyle
from . import register

logger = logging.getLogger(__name__)

ECOSYSTEM = "npm"

try:
    import yaml as _yaml                  # type: ignore[import-untyped]
    from .._yaml_fast import safe_load as _safe_load
    _AVAILABLE = True
except ImportError:                       # pragma: no cover — env-dependent
    _yaml = None                          # type: ignore[assignment]
    _safe_load = None                     # type: ignore[assignment]
    _AVAILABLE = False
    logger.warning(
        "sca.parsers.pnpm_lock: 'PyYAML' not installed — pnpm-lock.yaml "
        "files will be skipped. `pip install PyYAML` to enable."
    )


def parse(path: Path) -> List[Dependency]:
    if not _AVAILABLE:
        logger.warning(
            "sca.parsers.pnpm_lock: skipping %s — 'PyYAML' not installed", path,
        )
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("sca.parsers.pnpm_lock: read failed for %s: %s", path, e)
        return []
    try:
        data = _safe_load(text)           # type: ignore[misc]
    except _yaml.YAMLError as e:          # type: ignore[union-attr]
        logger.warning(
            "sca.parsers.pnpm_lock: YAML parse failed for %s: %s", path, e
        )
        return []
    if not isinstance(data, dict):
        return []

    direct_names = _collect_direct_names(data)
    packages = data.get("packages")
    if not isinstance(packages, dict):
        return []

    deps: List[Dependency] = []
    for key, entry in packages.items():
        if not isinstance(key, str):
            continue
        name, version = _split_packages_key(key)
        if name is None:
            continue
        if not isinstance(entry, dict):
            entry = {}
        scope = _scope_from_entry(entry)
        pin_style, version_for_record = _classify_packages_entry(entry, version)

        deps.append(Dependency(
            ecosystem=ECOSYSTEM,
            name=name,
            version=version_for_record,
            declared_in=path,
            scope=scope,
            is_lockfile=True,
            pin_style=pin_style,
            direct=name in direct_names,
            purl=_build_purl(name, version_for_record),
            parser_confidence=_confidence(pin_style, version_for_record),
        ))
    return deps


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _collect_direct_names(data: Dict[str, Any]) -> Set[str]:
    """Names listed under any importer's direct-dep buckets."""
    names: Set[str] = set()
    importers = data.get("importers")
    if isinstance(importers, dict):
        for imp in importers.values():
            if isinstance(imp, dict):
                names.update(_extract_direct_keys(imp))
    # v5 shape — direct deps live at the top level.
    names.update(_extract_direct_keys(data))
    return names


def _extract_direct_keys(scope_holder: Dict[str, Any]) -> Set[str]:
    keys: Set[str] = set()
    for bucket in (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ):
        block = scope_holder.get(bucket)
        if isinstance(block, dict):
            keys.update(k for k in block.keys() if isinstance(k, str))
    return keys


# Match v6 (/name@version, /@scope/name@version) and v5 (/name/version,
# /@scope/name/version). The ``@`` form is preferred — most modern files.
# The name segment forbids ``@`` so a ``(peer@x)`` suffix in the version
# doesn't get glued into the name by greedy matching.
_KEY_V6 = re.compile(r"^/(?P<name>(?:@[^/]+/)?[^/@]+)@(?P<version>.+)$")
_KEY_V5 = re.compile(r"^/(?P<name>(?:@[^/]+/)?[^/]+)/(?P<version>.+)$")


def _split_packages_key(key: str) -> Tuple[Optional[str], Optional[str]]:
    """Recover (name, version) from a ``packages`` map key."""
    # The v6 ``@`` form is anchored at the rightmost ``@`` *after* the
    # name segment; scoped packages contain a leading ``@`` too. Match
    # v6 first, then fall back to v5 slash form.
    m = _KEY_V6.match(key)
    if m:
        version = _strip_version_suffix(m.group("version"))
        return m.group("name"), version
    m = _KEY_V5.match(key)
    if m:
        version = _strip_version_suffix(m.group("version"))
        return m.group("name"), version
    return None, None


def _strip_version_suffix(version: str) -> str:
    """Drop pnpm's trailing ``(peer-key)`` annotations from a version.

    pnpm sometimes encodes peer-dep resolution into the lockfile key
    like ``29.0.3(typescript@5.0)``. The OSV-relevant version is just
    the leading version; the parenthesised tail is metadata.
    """
    paren = version.find("(")
    if paren > 0:
        return version[:paren]
    return version


def _scope_from_entry(entry: Dict[str, Any]) -> str:
    if entry.get("dev") is True:
        return "dev"
    if entry.get("peer") is True:
        return "peer"
    if entry.get("optional") is True:
        return "optional"
    return "main"


def _classify_packages_entry(
    entry: Dict[str, Any], version: Optional[str]
) -> Tuple[PinStyle, Optional[str]]:
    resolution = entry.get("resolution")
    if isinstance(resolution, dict):
        if "repo" in resolution or "commit" in resolution:
            return PinStyle.GIT, version
        tarball = resolution.get("tarball")
        if isinstance(tarball, str) and tarball.startswith("file:"):
            return PinStyle.PATH, version
    if version is None:
        return PinStyle.WILDCARD, None
    return PinStyle.EXACT, version


def _build_purl(name: str, version: Optional[str]) -> str:
    base = f"pkg:npm/{name}"
    if version:
        return f"{base}@{version}"
    return base


def _confidence(pin_style: PinStyle, version: Optional[str]) -> Confidence:
    if pin_style is PinStyle.GIT:
        return Confidence("medium", reason="pnpm-lock.yaml git source")
    if pin_style is PinStyle.PATH:
        return Confidence("medium", reason="pnpm-lock.yaml file source")
    if version is None:
        return Confidence("low", reason="pnpm-lock.yaml entry without version")
    return Confidence("high", reason="pnpm-lock.yaml resolved entry")


register(filenames=["pnpm-lock.yaml"])(parse)
