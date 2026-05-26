"""npm package.json parser.

Handles ``dependencies``, ``devDependencies``, ``peerDependencies``,
``optionalDependencies`` (and ``bundleDependencies``, treated as direct
deps with main scope). Lockfiles (``package-lock.json``, ``yarn.lock``,
``pnpm-lock.yaml``) are parsed elsewhere; this module is the manifest-
only view.

Scope mapping:
- ``dependencies``        → main
- ``devDependencies``     → dev
- ``peerDependencies``    → peer
- ``optionalDependencies``→ optional
- ``bundleDependencies``  → main (legacy; lists names that ``dependencies``
                            already declares)

Pin-style classification covers npm's range grammar; anything we can't
classify drops to ``unknown`` rather than guessing.

Modern monorepo / workspace specs:

- ``workspace:^1.0.0``, ``workspace:*``, ``workspace:~`` (pnpm /
  Yarn Berry) — the dep is an internal workspace package, not a
  registry entry. Recorded with ``pin_style=PATH`` and
  ``version=None`` so OSV doesn't query it.
- ``catalog:`` and ``catalog:<name>`` (pnpm 9) — references a
  shared version pin in ``pnpm-workspace.yaml``. The parser walks
  up to find that file (cached per-root), resolves the catalog
  entry, and substitutes the actual version spec before
  classification. Unresolved catalogs (no YAML, no entry, PyYAML
  unavailable) are recorded with ``pin_style=UNKNOWN`` and a
  diagnostic ``parser_confidence`` reason.

Project-wide pins (``resolutions``, ``overrides``):

- ``resolutions`` (Yarn classic + Berry) — pin a transitive dep
  to a specific version, project-wide. The pin overrides whatever
  the dep tree would otherwise resolve to.
- ``overrides`` (npm 7+) — same mechanism, npm's name for it.

Both fields are read and emitted as Dependency rows with
``source_kind="override"``, ``direct=True``, and a high parser
confidence — operators care about these because they're explicit
security pins. CVE matching against the pinned version means
operators see whether their pin actually clears the advisory.

Nested ``overrides`` (``"overrides": {"foo": {"bar": "1.0"}}``,
which means "pin bar to 1.0 within foo's tree") are flattened
naively: each leaf produces one row. The rows lose the "only
within X's tree" qualifier, but for advisory-matching purposes
this over-reports rather than under-reports — the operator sees
all pins.

Lifecycle scripts (``preinstall``, ``install``, ``postinstall``,
``prepare``, ``prepublish``) are not recorded as Dependency rows here.
The supply-chain heuristic layer reads the same file directly to flag
suspicious lifecycle hooks; recording them twice would make dedup harder.
"""

from __future__ import annotations

import json as _json
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..models import Confidence, Dependency, PinStyle
from ..versions import semver
from . import register

logger = logging.getLogger(__name__)

ECOSYSTEM = "npm"

# (package.json key, scope value)
_DEP_BUCKETS = (
    ("dependencies", "main"),
    ("devDependencies", "dev"),
    ("peerDependencies", "peer"),
    ("optionalDependencies", "optional"),
)

# Comparator characters that indicate a multi-bound range, e.g.
# ">=1.0.0 <2.0.0" or "1.0.0 - 2.0.0". Used after ruling out caret/tilde.
_RANGE_CHARS = set("<>=|") | {" - "}
_HEX_SHA = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)


def parse(path: Path) -> List[Dependency]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("sca.parsers.package_json: read failed for %s: %s", path, e)
        return []

    try:
        data = _json.loads(text)
    except _json.JSONDecodeError as e:
        logger.warning(
            "sca.parsers.package_json: JSON parse failed for %s: %s", path, e
        )
        return []
    if not isinstance(data, dict):
        logger.warning(
            "sca.parsers.package_json: top-level not an object in %s", path
        )
        return []

    project_license = _extract_license(data)

    deps: List[Dependency] = []
    for key, scope in _DEP_BUCKETS:
        block = data.get(key)
        if not isinstance(block, dict):
            continue
        for name, raw_spec in block.items():
            d = _build_dep(name, raw_spec, scope, path)
            if d is not None:
                # Manifest-level license describes the project itself,
                # not its deps. We attach it as ``declared_license`` only
                # on rows that *are* the project (no manifests do that
                # by default; keep slot for SBOM use anyway).
                if project_license:
                    d.declared_license = project_license
                deps.append(d)

    # bundleDependencies / bundledDependencies — array of names already
    # declared in `dependencies`; just record them flagged as bundled.
    for key in ("bundleDependencies", "bundledDependencies"):
        bundle = data.get(key)
        if isinstance(bundle, list):
            for name in bundle:
                if not isinstance(name, str):
                    continue
                d = _build_dep(name, "*", "main", path)
                if d is not None:
                    # Mark explicitly so a downstream consumer can spot
                    # bundling without re-reading the manifest.
                    d.parser_confidence = Confidence(
                        "high",
                        reason="bundleDependencies entry; version unspecified",
                    )
                    deps.append(d)

    # ``resolutions`` (Yarn classic + Berry) and ``overrides`` (npm 7+) —
    # project-wide pins of transitive deps. Both fields are emitted as
    # ``source_kind="override"`` so the report can group them, and
    # advisory matching fires against the pinned version (operators
    # care: "did my pin actually clear the CVE?").
    for key in ("overrides", "resolutions"):
        block = data.get(key)
        if isinstance(block, dict):
            for name, spec in _flatten_overrides(block):
                d = _build_dep(name, spec, "main", path)
                if d is not None:
                    d.source_kind = "override"
                    deps.append(d)

    # ``workspaces`` linkage. If this package.json is the ROOT of an
    # npm/Yarn workspace, stamp ``workspace_root`` on every dep with
    # the root dir. If this package.json is a MEMBER of a workspace
    # declared by an ancestor, stamp ``workspace_root`` with that
    # ancestor's dir. Either way, the substrate downstream
    # (hygiene checks, divergent-version detection) gets a stable
    # identity for grouping.
    #
    # pnpm-workspace.yaml takes precedence when both exist (rare
    # but legal — projects migrating between tooling sometimes carry
    # both for compat). The pnpm root is the canonical workspace
    # root for that toolchain; the npm-shaped ``workspaces`` field
    # is usually present for ecosystem-tool compatibility, not for
    # an actual second workspace structure.
    if deps:
        from ._pnpm_catalog import (
            find_npm_workspace_root,
            find_workspace_root as find_pnpm_workspace_root,
        )
        ws_root = (
            find_pnpm_workspace_root(path)
            or find_npm_workspace_root(path)
        )
        if ws_root is None:
            # Maybe this IS the root: it has its own ``workspaces``
            # field declaring members under itself. Stamp with
            # ``path.parent`` so its deps cluster with the
            # workspace's other members.
            ws_field = data.get("workspaces")
            has_ws_field = (
                isinstance(ws_field, list)
                or (isinstance(ws_field, dict)
                    and isinstance(ws_field.get("packages"), list))
            )
            if has_ws_field:
                ws_root = path.parent.resolve()
        if ws_root is not None:
            for d in deps:
                d.workspace_root = ws_root

    return deps


def _flatten_overrides(
    block: Dict[str, object],
    parent_chain: Tuple[str, ...] = (),
) -> List[Tuple[str, str]]:
    """Walk an ``overrides`` / ``resolutions`` block and yield
    ``(package_name, version_spec)`` pairs.

    Both flat (``"foo": "1.0"``) and nested (``"foo": {"bar": "1.0"}``,
    "pin bar to 1.0 within foo's tree") shapes are supported.
    Nested entries lose their tree-scoping context — every leaf
    becomes one row. This over-reports rather than under-reports
    for advisory-matching purposes; the operator sees all pins.

    Yarn Berry's ``"foo@npm:^1.0": "1.0.5"`` descriptor-keyed shape
    is normalised by stripping everything after the first ``@``
    that comes after position 0 (``foo@npm:^1.0`` → ``foo``).
    Scoped packages (``@scope/pkg@npm:^1.0``) keep the leading
    ``@``.
    """
    out: List[Tuple[str, str]] = []
    for raw_name, value in block.items():
        if not isinstance(raw_name, str):
            continue
        name = _strip_descriptor(raw_name)
        if not name:
            continue
        if isinstance(value, str):
            out.append((name, value))
        elif isinstance(value, dict):
            # Yarn Berry's "." key inside a nested override is the
            # tree-root version pin (most common case).
            root_pin = value.get(".")
            if isinstance(root_pin, str):
                out.append((name, root_pin))
            out.extend(_flatten_overrides(
                {k: v for k, v in value.items() if k != "."},
                parent_chain=parent_chain + (name,),
            ))
    return out


def _strip_descriptor(spec_key: str) -> str:
    """Normalise an ``overrides`` / ``resolutions`` key into a plain
    package name.

    ``foo`` → ``foo``
    ``foo@npm:^1.0`` → ``foo``
    ``@scope/pkg`` → ``@scope/pkg``
    ``@scope/pkg@npm:^1.0`` → ``@scope/pkg``

    Yarn's parent/child resolution shape: ``parent/child`` (no
    leading ``@``) means "pin ``child`` only when ``parent``
    transitively pulls it in". The package name to record is the
    CHILD — the parent is only a position filter. Surfaced by the
    May 2026 200-project sweep when Grafana's package.json had
    ``"ngtemplate-loader/loader-utils": "^2.0.0"`` and the parser
    used the whole ``parent/child`` string as the package name,
    producing a URL-encoded ``parent%2Fchild`` registry lookup
    that npm returned 405 on.

    ``ngtemplate-loader/loader-utils`` → ``loader-utils``
    """
    if spec_key.startswith("@"):
        # Scoped: keep the leading @ and the first @ after the slash
        # is the descriptor separator.
        slash = spec_key.find("/")
        if slash == -1:
            return spec_key
        rest = spec_key[slash:]
        sep = rest.find("@")
        if sep == -1:
            return spec_key
        return spec_key[:slash] + rest[:sep]
    # Unscoped: handle yarn's ``parent/child`` resolution before
    # ``name@selector`` because a ``parent/child@selector`` key
    # has both shapes and the parent's position is what gets
    # stripped first (we want the child's name, then the child's
    # name with selector stripped).
    if "/" in spec_key:
        spec_key = spec_key.split("/", 1)[1]
    sep = spec_key.find("@")
    if sep <= 0:
        return spec_key
    return spec_key[:sep]


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _extract_license(data: Dict[str, object]) -> Optional[str]:
    """Read the ``license`` / ``licenses`` field from a package.json.

    Handles all three shapes seen in real-world manifests:
    - ``"license": "MIT"``                              (SPDX string, current)
    - ``"license": {"type": "MIT", ...}``               (legacy single-object)
    - ``"licenses": [{"type": "MIT"}, {"type": "ISC"}]`` (deprecated array)
    """
    raw = data.get("license")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    if isinstance(raw, dict):
        t = raw.get("type") or raw.get("name")
        if isinstance(t, str) and t.strip():
            return t.strip()
    arr = data.get("licenses")
    if isinstance(arr, list):
        names = []
        for item in arr:
            if isinstance(item, dict):
                t = item.get("type") or item.get("name")
                if isinstance(t, str) and t.strip():
                    names.append(t.strip())
            elif isinstance(item, str) and item.strip():
                names.append(item.strip())
        if names:
            # Multiple licenses: surface the lot as a SPDX-OR expression
            # so downstream consumers don't lose information.
            return " OR ".join(names) if len(names) > 1 else names[0]
    return None


def _build_dep(
    name: str,
    raw_spec: object,
    scope: str,
    path: Path,
) -> Optional[Dependency]:
    if not isinstance(name, str) or not name:
        return None
    if not isinstance(raw_spec, str):
        # Some lockfile-merged manifests inline objects; we treat those
        # as opaque and skip rather than emit a half-row.
        return None
    spec = raw_spec.strip()

    # ``catalog:`` reference (pnpm 9). Resolve via pnpm-workspace.yaml
    # if findable; otherwise emit an UNKNOWN-pin row so the operator
    # at least sees the dep name.
    catalog_unresolved = False
    if spec.startswith("catalog:"):
        from ._pnpm_catalog import (
            find_workspace_root,
            get_catalogs,
            resolve_catalog_spec,
        )
        root = find_workspace_root(path)
        if root is not None:
            catalogs = get_catalogs(root)
            resolved = resolve_catalog_spec(spec, name, catalogs)
            if resolved is not None:
                spec = resolved.strip()
            else:
                catalog_unresolved = True
        else:
            catalog_unresolved = True
        if catalog_unresolved:
            return Dependency(
                ecosystem=ECOSYSTEM,
                name=name, version=None, declared_in=path, scope=scope,
                is_lockfile=False, pin_style=PinStyle.UNKNOWN,
                direct=True,
                purl=_build_purl(name, None),
                parser_confidence=Confidence(
                    "low",
                    reason=(
                        f"pnpm catalog reference {raw_spec!r} could "
                        f"not be resolved (no pnpm-workspace.yaml or "
                        f"no matching catalog entry)"
                    ),
                ),
            )

    pin_style, version, npm_alias_target = _classify(spec)
    purl_name = npm_alias_target or name
    # Record the semver corridor (caret/tilde/range -> floor & ceiling) so
    # harden can place a ranged dep relative to its floor and keep a bump
    # inside the ceiling. Exact / git / alias specs yield (None, None).
    version_floor, version_ceiling = semver.bounds(spec)

    return Dependency(
        ecosystem=ECOSYSTEM,
        name=name,
        version=version,
        declared_in=path,
        scope=scope,
        is_lockfile=False,
        pin_style=pin_style,
        direct=True,
        purl=_build_purl(purl_name, version),
        parser_confidence=_confidence(pin_style, version),
        version_floor=version_floor,
        version_ceiling=version_ceiling,
    )


def _classify(spec: str) -> Tuple[PinStyle, Optional[str], Optional[str]]:
    """Return (pin_style, version_for_record, npm_alias_target_or_None).

    For an alias like ``"npm:lodash@^4.17.0"``, the alias target is
    returned so the purl reflects the actual installed package; the spec
    governing the pin style is the right-hand side.
    """
    if not spec:
        return PinStyle.WILDCARD, None, None

    # npm: alias → recurse on the right-hand side.
    if spec.startswith("npm:"):
        rest = spec[len("npm:"):]
        if "@" in rest[1:]:
            sep = rest.rindex("@")
            target = rest[:sep] if sep > 0 else rest
            inner_spec = rest[sep + 1:] if sep > 0 else ""
        else:
            target = rest
            inner_spec = ""
        pin, ver, _ = _classify(inner_spec)
        return pin, ver, target or None

    # ``workspace:`` references (pnpm + Yarn Berry) — internal
    # workspace package, not a registry entry. Marked as PATH so OSV
    # lookups skip it. Forms: ``workspace:^1.0``, ``workspace:*``,
    # ``workspace:~``, ``workspace:./pkgs/foo``.
    if spec.startswith("workspace:"):
        return PinStyle.PATH, None, None

    # Wildcards.
    if spec in ("*", "x", "X", "latest", ""):
        return PinStyle.WILDCARD, None, None

    # Git references (git+https://, git+ssh://, git://, github:owner/repo,
    # bitbucket:..., gitlab:..., gist:...).
    if (
        spec.startswith(("git+", "git:", "git@"))
        or spec.startswith(("github:", "bitbucket:", "gitlab:", "gist:"))
        or "://" in spec and spec.split("://", 1)[0].endswith("git")
    ):
        # Try to extract a #ref or #semver: spec for the version field.
        version: Optional[str] = None
        if "#" in spec:
            tag = spec.split("#", 1)[1]
            if tag.startswith("semver:"):
                version = tag[len("semver:"):]
            else:
                version = tag
        return PinStyle.GIT, version, None

    # Local paths.
    if spec.startswith(("file:", "./", "../", "/", "~/")):
        return PinStyle.PATH, None, None

    # Tarball URLs.
    if spec.startswith(("http://", "https://")):
        # Tarball; treat as path-like for pinning purposes (resolved by
        # URL, not by version range).
        return PinStyle.PATH, None, None

    # Caret / tilde.
    if spec.startswith("^"):
        return PinStyle.CARET, spec[1:].strip() or None, None
    if spec.startswith("~"):
        return PinStyle.TILDE, spec[1:].strip() or None, None

    # Multi-bound or comparator-based range.
    if any(ch in spec for ch in _RANGE_CHARS) or " - " in spec:
        return PinStyle.RANGE, spec, None

    # Bare version: treat as exact unless it's a SHA (which npm allows
    # for resolved git installs without a prefix — rare in package.json).
    if _HEX_SHA.match(spec):
        return PinStyle.GIT, spec, None

    return PinStyle.EXACT, spec, None


def _confidence(pin_style: PinStyle, version: Optional[str]) -> Confidence:
    if pin_style is PinStyle.UNKNOWN:
        return Confidence("low", reason="package.json spec unrecognised")
    if pin_style in (PinStyle.GIT, PinStyle.PATH):
        return Confidence(
            "medium",
            reason="package.json points to git/path source; version best-effort",
        )
    if version is None:
        return Confidence("medium", reason="package.json wildcard version")
    return Confidence("high", reason="package.json structured field")


def _build_purl(name: str, version: Optional[str]) -> str:
    """Build an npm purl. Scoped packages keep the leading ``@``."""
    base = f"pkg:npm/{name}"
    if version:
        return f"{base}@{version}"
    return base


register(filenames=["package.json"])(parse)
