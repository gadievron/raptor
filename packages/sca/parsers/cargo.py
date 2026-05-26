"""Cargo (Rust) parser.

Handles ``Cargo.toml`` (manifest) and ``Cargo.lock`` (resolved versions).

Cargo manifests are TOML; lockfiles are TOML too. Cargo's version
grammar is semver with caret as the default — ``"1.0"`` means
``^1.0``, not ``=1.0``. Pin-style classification reflects this:

  - ``"=1.2.3"``                       → EXACT
  - ``"^1.2.3"``, ``"1.2.3"``          → CARET (default)
  - ``"~1.2.3"``                       → TILDE
  - ``">=1.2, <2.0"``                  → RANGE
  - ``"*"``                            → WILDCARD
  - ``{ git = "..." }``                → GIT
  - ``{ path = "..." }``               → PATH
  - ``{ workspace = true }``           → unknown (skipped — workspace
                                         inheritance handled at parse time)

Scopes:
  - ``[dependencies]``                  → "main"
  - ``[dev-dependencies]``              → "dev"
  - ``[build-dependencies]``            → "build"
  - ``[target.<cfg>.dependencies]``     → "main" (cfg qualifier dropped;
                                         the dep is still in the tree
                                         on matching platforms)
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, List, Optional, Tuple

from ..models import Confidence, Dependency, PinStyle
from . import register

try:
    import tomllib                # Python 3.11+
except ImportError:               # pragma: no cover
    import tomli as tomllib       # type: ignore[no-redef]

logger = logging.getLogger(__name__)


ECOSYSTEM = "Cargo"
_PURL_TYPE = "cargo"

# Maps the TOML scope key → SCA scope value.
_SCOPE_MAP = {
    "dependencies": "main",
    "dev-dependencies": "dev",
    "build-dependencies": "build",
}


@register(filenames=["Cargo.toml"])
def parse_manifest(path: Path) -> List[Dependency]:
    """Parse a ``Cargo.toml`` and emit one Dependency per declared dep.

    Workspace-only manifests (``[workspace]`` section without
    ``[package]``) emit no deps from the manifest itself; their member
    crates are discovered separately. ``workspace = true`` inheritances
    are emitted with version=None and pin_style=UNKNOWN — the resolved
    version comes from the lockfile.
    """
    try:
        data = _load_toml(path)
    except Exception as e:                   # noqa: BLE001
        logger.warning("sca.parsers.cargo: %s: %s", path, e)
        return []

    out: List[Dependency] = []
    seen_keys: set = set()

    # Top-level dep tables.
    for scope_key, scope in _SCOPE_MAP.items():
        block = data.get(scope_key) or {}
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            dep = _build_dep(name, spec, scope=scope, declared_in=path)
            if dep is None or dep.key() in seen_keys:
                continue
            seen_keys.add(dep.key())
            out.append(dep)

    # ``[target.'cfg(...)'.dependencies]`` etc.
    targets = data.get("target") or {}
    if isinstance(targets, dict):
        for _cfg, target_block in targets.items():
            if not isinstance(target_block, dict):
                continue
            for scope_key, scope in _SCOPE_MAP.items():
                inner = target_block.get(scope_key) or {}
                if not isinstance(inner, dict):
                    continue
                for name, spec in inner.items():
                    dep = _build_dep(
                        name, spec, scope=scope, declared_in=path)
                    if dep is None or dep.key() in seen_keys:
                        continue
                    seen_keys.add(dep.key())
                    out.append(dep)

    return out


@register(filenames=["Cargo.lock"])
def parse_lockfile(path: Path) -> List[Dependency]:
    """Parse a ``Cargo.lock`` and emit one Dependency per resolved entry.

    The lockfile is the source of truth for resolved versions; the
    direct-vs-transitive distinction comes from cross-referencing the
    lockfile's dependency graph with the manifest's direct deps.
    Cargo.lock alone can't tell us "direct" — we set ``direct=False``
    here and let the join layer (``packages/sca/join.py``) flip the bit
    when a manifest entry is found for the same name.
    """
    try:
        data = _load_toml(path)
    except Exception as e:                   # noqa: BLE001
        logger.warning("sca.parsers.cargo: %s: %s", path, e)
        return []

    packages = data.get("package") or []
    if not isinstance(packages, list):
        return []

    out: List[Dependency] = []
    seen_keys: set = set()
    for entry in packages:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        version = entry.get("version")
        if not (isinstance(name, str) and isinstance(version, str)):
            continue
        source = entry.get("source") if isinstance(
            entry.get("source"), str) else None
        pin_style = _lockfile_pin_style(source)
        purl = _build_purl(name, version)
        dep = Dependency(
            ecosystem=ECOSYSTEM,
            name=name,
            version=version,
            declared_in=path,
            scope="main",
            is_lockfile=True,
            pin_style=pin_style,
            direct=False,                    # join layer flips when matched
            purl=purl,
            parser_confidence=Confidence(
                "high",
                reason="Cargo.lock TOML — deterministic structure",
            ),
            source_kind="lockfile",
        )
        if dep.key() in seen_keys:
            continue
        seen_keys.add(dep.key())
        out.append(dep)
    return out


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _load_toml(path: Path) -> dict:
    with path.open("rb") as f:
        return tomllib.load(f)


def _build_dep(
    name: str,
    spec: Any,
    *,
    scope: str,
    declared_in: Path,
) -> Optional[Dependency]:
    """Translate a Cargo dep spec — string OR table — into a Dependency."""
    version: Optional[str] = None
    pin_style = PinStyle.UNKNOWN
    git_url: Optional[str] = None
    path_ref: Optional[str] = None
    is_workspace_inherit = False
    # Feature-flag awareness: ``optional = true`` + ``features = [...]``.
    # An ``optional = true`` dep is feature-gated — operators only get
    # it installed if a ``[features]`` entry references it. CVEs in
    # such deps may not apply unless the gating feature is active.
    is_optional = False
    declared_features: Optional[list] = None

    git_url: Optional[str] = None
    path_ref: Optional[str] = None
    if isinstance(spec, str):
        version = spec
        pin_style, normalised = _classify_version_spec(spec)
        if normalised is not None:
            version = normalised
    elif isinstance(spec, dict):
        if spec.get("workspace") is True:
            is_workspace_inherit = True
            pin_style = PinStyle.UNKNOWN
        elif "git" in spec:
            raw_git = spec.get("git")
            if isinstance(raw_git, str):
                git_url = raw_git
            pin_style = PinStyle.GIT
        elif "path" in spec:
            raw_path = spec.get("path")
            if isinstance(raw_path, str):
                path_ref = raw_path
            pin_style = PinStyle.PATH
        else:
            v = spec.get("version")
            if isinstance(v, str):
                version = v
                pin_style, normalised = _classify_version_spec(v)
                if normalised is not None:
                    version = normalised
        if spec.get("optional") is True:
            is_optional = True
        feats = spec.get("features")
        if isinstance(feats, list):
            declared_features = list(feats)
    else:
        return None

    # Carry git / path source coordinates into ``source_extra`` so
    # downstream consumers (SBOM, finding context, reachability)
    # know the dep's origin. Parallels the
    # ``cargo_optional`` / ``cargo_features`` pattern already here;
    # previously these locals were captured and dropped on the floor.
    source_extra = None
    if (is_optional or declared_features is not None
            or git_url or path_ref):
        source_extra = {}
        if is_optional:
            source_extra["cargo_optional"] = True
        if declared_features is not None:
            source_extra["cargo_features"] = declared_features
        if git_url:
            source_extra["cargo_git"] = git_url
        if path_ref:
            source_extra["cargo_path"] = path_ref

    purl = _build_purl(name, version)
    return Dependency(
        ecosystem=ECOSYSTEM,
        name=name,
        version=version,
        declared_in=declared_in,
        scope=scope,
        is_lockfile=False,
        pin_style=pin_style,
        direct=True,
        purl=purl,
        parser_confidence=Confidence(
            "high",
            reason=("Cargo.toml TOML — deterministic; "
                    "workspace-inherit"
                    if is_workspace_inherit
                    else "Cargo.toml TOML — deterministic"),
        ),
        source_kind="manifest",
        source_extra=source_extra,
    )


# Cargo version-spec parser. Cargo treats a bare ``"1.2"`` as ``^1.2``.
# We track the operator and the *bare* version so downstream OSV matching
# has something to compare against.
_VERSION_SPEC_OP_RE = re.compile(
    r"^\s*(=|\^|~|>=?|<=?)\s*(\d[^\s,]*)\s*$",
)


def _classify_version_spec(spec: str) -> Tuple[PinStyle, Optional[str]]:
    """Return (pin_style, bare_version) for a Cargo version spec.

    Returns the bare version stripped of operator characters when one is
    present; for ranges and wildcards returns the version-or-None as
    appropriate so the join layer / OSV matching has a value to use.
    """
    s = spec.strip()
    if not s:
        return PinStyle.UNKNOWN, None
    if s == "*":
        return PinStyle.WILDCARD, None
    # Compound (comma-separated) → range.
    if "," in s:
        return PinStyle.RANGE, None
    m = _VERSION_SPEC_OP_RE.match(s)
    if m:
        op, ver = m.group(1), m.group(2)
        if op == "=":
            return PinStyle.EXACT, ver
        if op == "^":
            return PinStyle.CARET, ver
        if op == "~":
            return PinStyle.TILDE, ver
        return PinStyle.RANGE, ver
    # Bare ``1.2.3`` is implicit caret in Cargo.
    if re.match(r"^\d[\w.\-+]*$", s):
        return PinStyle.CARET, s
    return PinStyle.UNKNOWN, None


def _lockfile_pin_style(source: Optional[str]) -> PinStyle:
    """Resolved entries in Cargo.lock are exact versions; the *source*
    field tells us whether it came from registry / git / path."""
    if not source:
        # Local path or workspace member — no source URL.
        return PinStyle.PATH
    if source.startswith("git+"):
        return PinStyle.GIT
    return PinStyle.EXACT


def _build_purl(name: str, version: Optional[str]) -> str:
    base = f"pkg:{_PURL_TYPE}/{name}"
    if version:
        return f"{base}@{version}"
    return base


__all__ = ["parse_manifest", "parse_lockfile"]
