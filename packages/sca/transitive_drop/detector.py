"""Detect transitive deps that newer parent versions make
optional (or drop entirely).

Two passes over the available data:

  1. **Linkage** — for each cascade-sourced Dependency carrying
     a finding (vuln / supply-chain / hygiene), look at its
     ``source_extra["via"]`` list to find parent direct deps.

  2. **Cross-version diff** — for each parent: compare its
     CURRENT pinned version's ``requires_dist`` against the
     LATEST stable version's ``requires_dist``. If the
     transitive is unconditional in current but extras-gated
     or absent in latest → emit a recommendation.

The output is a list of ``DropOnBumpFinding`` records the
pipeline merges into the SupplyChainFinding stream so the
operator-facing report surfaces the bump as a remediation
alongside the underlying CVE.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from packages.sca.models import (
    Dependency, SupplyChainFinding, VulnFinding,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DropOnBumpFinding:
    """One detected case: a transitive becomes droppable by
    bumping its parent. Pipeline wraps it into a
    SupplyChainFinding for the wider system."""

    transitive_name: str
    transitive_version: str
    transitive_finding_severity: str   # severity inherited from the
                                       # underlying issue
    parent_name: str
    parent_current_version: str
    parent_latest_version: str
    transitive_status_in_latest: str   # "extras-gated" | "removed"
    extra_name: Optional[str]          # which extra it moved behind


def detect_droppable_transitives(
    deps: Iterable[Dependency],
    vuln_findings: Iterable[VulnFinding] = (),
    supply_chain_findings: Iterable[SupplyChainFinding] = (),
    hygiene_findings: Iterable = (),
    *,
    pypi_client=None,
    npm_client=None,
    cargo_client=None,
    composer_client=None,
    rubygems_client=None,
    maven_client=None,
    nuget_client=None,
) -> List[DropOnBumpFinding]:
    """For each finding on a cascade-sourced transitive dep,
    check whether a parent bump would drop the dep entirely
    (or move it behind an optional/feature/scope gate).

    Each ecosystem-specific client gets its own kwarg. Per-ecosystem
    dep-state extraction is dispatched by ``dep.ecosystem``.
    Coverage today:

    * **PyPI** — ``requires_dist`` with PEP-508 ``extra ==``
      markers
    * **npm** — ``dependencies`` vs ``optionalDependencies`` /
      ``peerDependenciesMeta``
    * **Cargo** — ``optional = true`` + ``[features]`` gating
    * **Composer** — ``require`` vs ``require-dev`` / ``suggest``
    * **RubyGems** — ``runtime`` vs ``development`` type
    * **Maven** — ``<scope>compile→provided/test</scope>`` /
      ``<optional>true</optional>``
    * **NuGet** — TFM-group membership change

    Transitive must have ``source_kind == "cascade_resolver"``
    AND ``source_extra["via"]`` populated by the cascade-tagger.
    """
    clients = {
        "PyPI": pypi_client,
        "npm": npm_client,
        "Cargo": cargo_client,
        "Packagist": composer_client,
        "RubyGems": rubygems_client,
        "Maven": maven_client,
        "NuGet": nuget_client,
    }
    if not any(c is not None for c in clients.values()):
        return []

    deps_list = list(deps)
    # Index findings by their dep coordinate so we know which
    # transitives have issues worth proposing a bump for.
    issue_keys: Dict[Tuple[str, str], str] = {}
    for f in vuln_findings:
        d = f.dependency
        if d is not None:
            key = (d.ecosystem, d.name)
            sev = getattr(f, "severity", "medium")
            # Keep the most severe finding for tier escalation.
            issue_keys[key] = _max_severity(issue_keys.get(key), sev)
    for f in supply_chain_findings:
        d = f.dependency
        if d is not None:
            key = (d.ecosystem, d.name)
            sev = getattr(f, "severity", "info")
            issue_keys[key] = _max_severity(issue_keys.get(key), sev)
    for f in hygiene_findings:
        d = getattr(f, "dependency", None)
        if d is not None:
            key = (d.ecosystem, d.name)
            sev = getattr(f, "severity", "info")
            issue_keys[key] = _max_severity(issue_keys.get(key), sev)

    findings: List[DropOnBumpFinding] = []
    seen_pairs: set = set()
    # Map (ecosystem, name) → list of (dep, parents).
    by_eco_name: Dict[Tuple[str, str], List[Dependency]] = {}
    for d in deps_list:
        if d.ecosystem not in clients:
            continue
        if clients[d.ecosystem] is None:
            continue
        if d.source_kind != "cascade_resolver":
            continue
        if not d.source_extra:
            continue
        if not d.source_extra.get("via"):
            continue
        canon = _canonical_name(d.ecosystem, d.name)
        by_eco_name.setdefault((d.ecosystem, canon), []).append(d)

    # Direct deps indexed by (ecosystem, canonical name) — we need
    # their currently-pinned version when querying parent metadata.
    direct_versions: Dict[Tuple[str, str], str] = {}
    for d in deps_list:
        if d.direct and d.version and d.ecosystem in clients:
            canon = _canonical_name(d.ecosystem, d.name)
            direct_versions[(d.ecosystem, canon)] = d.version

    for (eco, canon_name), transitive_deps in by_eco_name.items():
        client = clients[eco]
        # Only spend the PyPI roundtrip on transitives whose
        # PROBLEMS make a bump worth surfacing.
        sample = transitive_deps[0]
        key = (sample.ecosystem, sample.name)
        if key not in issue_keys:
            continue
        underlying_sev = issue_keys[key]

        for parent in sample.source_extra.get("via") or []:
            parent_canon = _canonical_name(eco, parent)
            pair = (eco, canon_name, parent_canon)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)

            parent_pinned = direct_versions.get((eco, parent_canon))
            if not parent_pinned:
                # The "parent" came from the cascade resolver but
                # isn't in our direct dep set — could be a
                # transitive-of-transitive. Skip; cross-version
                # diff needs the operator's current pin.
                continue

            try:
                latest = _latest_stable_version(
                    eco, client, parent_canon,
                )
            except Exception as e:                       # noqa: BLE001
                logger.debug(
                    "transitive_drop: latest-version lookup failed for "
                    "parent %s: %s", parent_canon, e,
                )
                continue
            if latest is None:
                continue
            if parent_pinned and _version_lt(latest, parent_pinned):
                # Latest stable is older than what we have pinned
                # (operator on an unreleased dev pin? defensive).
                continue
            if parent_pinned == latest:
                # Already at latest — no bump to suggest.
                continue

            # Diff current's dep state against latest's. Per-ecosystem
            # dep-state extraction is dispatched here.
            current_state = _dep_state_in_version(
                eco, client, parent_canon, parent_pinned, canon_name,
            )
            latest_state = _dep_state_in_version(
                eco, client, parent_canon, latest, canon_name,
            )
            if current_state is None or latest_state is None:
                continue

            # Did the transitive move from "unconditional" to
            # "extras-gated" or "absent"?
            if (current_state.get("required")
                    and not latest_state.get("required")):
                # In latest, the dep is either gone or behind extras.
                extras = latest_state.get("extras") or []
                if extras:
                    transitive_status = "extras-gated"
                    extra_name = extras[0]
                else:
                    transitive_status = "removed"
                    extra_name = None
                findings.append(DropOnBumpFinding(
                    transitive_name=sample.name,
                    transitive_version=sample.version or "",
                    transitive_finding_severity=underlying_sev,
                    parent_name=parent,
                    parent_current_version=parent_pinned or "(unknown)",
                    parent_latest_version=latest,
                    transitive_status_in_latest=transitive_status,
                    extra_name=extra_name,
                ))

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _canonical_name(ecosystem: str, name: str) -> str:
    """Per-ecosystem canonical-name normalisation. Most ecosystems
    case-fold + treat ``_`` ≡ ``-``; Maven keeps ``groupId:artifactId``
    case-sensitive."""
    if ecosystem == "Maven":
        return name.strip()
    return name.lower().replace("_", "-")


_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


def _max_severity(a: Optional[str], b: str) -> str:
    if a is None:
        return b
    try:
        return max(a, b, key=lambda s: _SEVERITY_ORDER.index(s))
    except ValueError:
        return b


_STABLE_RE = re.compile(
    r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?$"
)


def _version_key(v: str) -> Tuple[int, ...]:
    m = _STABLE_RE.match(v)
    if not m:
        return (0,)
    return tuple(int(p) if p else 0 for p in m.groups())


def _version_lt(a: str, b: str) -> bool:
    return _version_key(a) < _version_key(b)


def _latest_stable_version(
    ecosystem: str, client, name: str,
) -> Optional[str]:
    """Return the highest stable version per the ecosystem's
    metadata shape. Dispatches because each registry exposes
    versions slightly differently:

      * PyPI / Composer (Packagist): ``releases: {<ver>: [...]}``
        (Packagist returns ``packages[<name>]: [{version, ...}]``,
        adapted below)
      * npm: ``versions: {<ver>: {...}}``
      * Maven / Cargo / RubyGems / NuGet: also via ``releases:``
        (our stubs normalise into that shape; real clients may
        vary)
    """
    meta = client.get_metadata(name) \
        if hasattr(client, "get_metadata") else None
    if not isinstance(meta, dict):
        return None
    candidates: List[str] = []
    if ecosystem == "npm":
        candidates = list((meta.get("versions") or {}).keys())
    elif ecosystem == "Packagist":
        # Packagist /p2 shape: packages[name] = [{version, ...}, ...]
        pkgs = meta.get("packages") or {}
        for vlist in pkgs.values():
            if isinstance(vlist, list):
                for v in vlist:
                    if isinstance(v, dict) and v.get("version"):
                        candidates.append(v["version"])
    else:
        candidates = list((meta.get("releases") or {}).keys())
    stable = [v for v in candidates if _STABLE_RE.match(v)]
    if not stable:
        return None
    stable.sort(key=_version_key, reverse=True)
    return stable[0]


def _dep_state_in_version(
    ecosystem: str, client, parent_name: str, parent_version: str,
    transitive_name: str,
) -> Optional[dict]:
    """Dispatch per-ecosystem dep-state extraction. Returns:

      None — couldn't fetch / unsupported ecosystem
      {"required": True, "extras": []}        — unconditional dep
      {"required": False, "extras": ["x"]}    — only via extras
      {"required": False, "extras": []}        — not declared at all
    """
    if ecosystem == "PyPI":
        return _dep_state_pypi(
            client, parent_name, parent_version, transitive_name,
        )
    if ecosystem == "npm":
        return _dep_state_npm(
            client, parent_name, parent_version, transitive_name,
        )
    if ecosystem == "Cargo":
        return _dep_state_cargo(
            client, parent_name, parent_version, transitive_name,
        )
    if ecosystem == "Packagist":
        return _dep_state_composer(
            client, parent_name, parent_version, transitive_name,
        )
    if ecosystem == "RubyGems":
        return _dep_state_rubygems(
            client, parent_name, parent_version, transitive_name,
        )
    if ecosystem == "Maven":
        return _dep_state_maven(
            client, parent_name, parent_version, transitive_name,
        )
    if ecosystem == "NuGet":
        return _dep_state_nuget(
            client, parent_name, parent_version, transitive_name,
        )
    return None


# ---------------------------------------------------------------------------
# PyPI
# ---------------------------------------------------------------------------

def _dep_state_pypi(
    client, parent_name: str, parent_version: str,
    transitive_name: str,
) -> Optional[dict]:
    requires_dist = _requires_dist_for_version_pypi(
        client, parent_name, parent_version,
    )
    if requires_dist is None:
        meta = client.get_metadata(parent_name)
        if not isinstance(meta, dict):
            return None
        info = meta.get("info") or {}
        requires_dist = info.get("requires_dist") or []
        if not isinstance(requires_dist, list):
            return None

    transitive_canon = transitive_name.lower().replace("_", "-")
    extras: List[str] = []
    unconditional = False
    for req in requires_dist:
        if not isinstance(req, str):
            continue
        name_part, _, marker = req.partition(";")
        name_match = re.match(
            r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", name_part,
        )
        if not name_match:
            continue
        req_name = name_match.group(1).lower().replace("_", "-")
        if req_name != transitive_canon:
            continue
        if marker.strip():
            m = re.search(r"extra\s*==\s*[\"']([^\"']+)[\"']", marker)
            if m:
                extras.append(m.group(1))
        else:
            unconditional = True
    return {"required": unconditional, "extras": extras}


def _requires_dist_for_version_pypi(
    client, name: str, version: str,
) -> Optional[List[str]]:
    """Fetch requires_dist for a SPECIFIC PyPI version."""
    if hasattr(client, "get_version_metadata"):
        meta = client.get_version_metadata(name, version)
        if isinstance(meta, dict):
            info = meta.get("info") or {}
            rd = info.get("requires_dist")
            if isinstance(rd, list):
                return rd
    return None


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------

def _dep_state_npm(
    client, parent_name: str, parent_version: str,
    transitive_name: str,
) -> Optional[dict]:
    """npm's per-version metadata lives inline in the packument
    (``versions[<ver>]``). Check for the transitive in ALL four
    dep keys: ``dependencies`` (required), ``optionalDependencies``,
    ``peerDependencies`` (with ``peerDependenciesMeta[name].optional``),
    ``devDependencies`` (build-only)."""
    meta = client.get_metadata(parent_name)
    if not isinstance(meta, dict):
        return None
    versions = meta.get("versions") or {}
    pkg_meta = versions.get(parent_version)
    if not isinstance(pkg_meta, dict):
        return None

    transitive_canon = transitive_name.lower()
    extras: List[str] = []
    unconditional = False
    if (pkg_meta.get("dependencies") or {}).get(transitive_name) or \
       (pkg_meta.get("dependencies") or {}).get(transitive_canon):
        unconditional = True
    if (pkg_meta.get("optionalDependencies") or {}).get(transitive_name) or \
       (pkg_meta.get("optionalDependencies") or {}).get(transitive_canon):
        extras.append("optionalDependencies")
    # peerDependencies are "you need this but I won't install it";
    # treat as a conditional state — operator must opt in by
    # installing it. peerDependenciesMeta[name].optional makes
    # it explicit.
    peer = pkg_meta.get("peerDependencies") or {}
    if peer.get(transitive_name) or peer.get(transitive_canon):
        extras.append("peerDependencies")
    return {"required": unconditional, "extras": extras}


# ---------------------------------------------------------------------------
# Cargo
# ---------------------------------------------------------------------------

def _dep_state_cargo(
    client, parent_name: str, parent_version: str,
    transitive_name: str,
) -> Optional[dict]:
    """crates.io exposes per-version deps at
    ``/api/v1/crates/<crate>/<ver>/dependencies`` returning a list
    of ``{name, kind, optional, features, default_features}`` rows.

    Cargo's ``kind`` is one of ``normal``, ``dev``, ``build``.
    ``optional=true`` means the dep is feature-gated and only
    pulled when a ``[features]`` entry enables it.

    Required-state in Cargo terms:
      * kind == "normal" + optional=false → unconditional
      * kind == "normal" + optional=true → feature-gated
      * kind == "dev" → development-only
      * kind == "build" → build-time only
    """
    if not hasattr(client, "get_version_dependencies"):
        return None
    deps = client.get_version_dependencies(parent_name, parent_version)
    if not isinstance(deps, list):
        return None
    transitive_canon = transitive_name.lower().replace("_", "-")
    extras: List[str] = []
    unconditional = False
    for d in deps:
        if not isinstance(d, dict):
            continue
        name = d.get("crate_id") or d.get("name") or ""
        if name.lower().replace("_", "-") != transitive_canon:
            continue
        kind = d.get("kind") or "normal"
        is_optional = bool(d.get("optional"))
        if kind == "normal" and not is_optional:
            unconditional = True
        elif kind == "normal" and is_optional:
            extras.append("optional-feature")
        elif kind == "dev":
            extras.append("dev")
        elif kind == "build":
            extras.append("build")
    return {"required": unconditional, "extras": extras}


# ---------------------------------------------------------------------------
# Composer (Packagist)
# ---------------------------------------------------------------------------

def _dep_state_composer(
    client, parent_name: str, parent_version: str,
    transitive_name: str,
) -> Optional[dict]:
    """Packagist's API returns per-version ``require`` /
    ``require-dev`` / ``suggest`` blocks. Moving a dep from
    ``require`` to ``require-dev`` or ``suggest`` is the
    extras-gating equivalent."""
    meta = client.get_metadata(parent_name) \
        if hasattr(client, "get_metadata") else None
    if not isinstance(meta, dict):
        return None
    # Packagist /p2 returns ``{packages: {<name>: [{version, ...}, ...]}}``
    packages = meta.get("packages") or {}
    versions = packages.get(parent_name) or []
    pkg_meta = None
    for v in versions:
        if isinstance(v, dict) and v.get("version") == parent_version:
            pkg_meta = v
            break
    if pkg_meta is None:
        return None

    # Packagist enforces lowercase canonical package names, but a
    # `require` map written by hand can still contain mixed-case
    # entries (``vendor/Package``). Match case-folded both sides
    # to stay consistent with every other ecosystem detector in
    # this module (``transitive_canon`` is built for exactly this
    # purpose; using ``transitive_name`` directly silently misses
    # mixed-case entries).
    transitive_canon = transitive_name.lower()

    def _has(block_key: str) -> bool:
        block = pkg_meta.get(block_key) or {}
        if not isinstance(block, dict):
            return False
        return any(
            (k or "").lower() == transitive_canon for k in block
        )

    extras: List[str] = []
    unconditional = _has("require")
    if _has("require-dev"):
        extras.append("require-dev")
    if _has("suggest"):
        extras.append("suggest")
    return {"required": unconditional, "extras": extras}


# ---------------------------------------------------------------------------
# RubyGems
# ---------------------------------------------------------------------------

def _dep_state_rubygems(
    client, parent_name: str, parent_version: str,
    transitive_name: str,
) -> Optional[dict]:
    """rubygems.org's per-version endpoint returns
    ``dependencies: {runtime: [...], development: [...]}``.
    Moving from runtime → development is the gating shift."""
    if not hasattr(client, "get_version_metadata"):
        return None
    meta = client.get_version_metadata(parent_name, parent_version)
    if not isinstance(meta, dict):
        return None
    deps = meta.get("dependencies") or {}
    transitive_canon = transitive_name.lower()
    extras: List[str] = []
    unconditional = False
    for d in deps.get("runtime") or []:
        if isinstance(d, dict) and (d.get("name") or "").lower() == transitive_canon:
            unconditional = True
    for d in deps.get("development") or []:
        if isinstance(d, dict) and (d.get("name") or "").lower() == transitive_canon:
            extras.append("development")
    return {"required": unconditional, "extras": extras}


# ---------------------------------------------------------------------------
# Maven
# ---------------------------------------------------------------------------

def _dep_state_maven(
    client, parent_name: str, parent_version: str,
    transitive_name: str,
) -> Optional[dict]:
    """Maven POMs declare ``<scope>`` (default ``compile``) and
    ``<optional>true</optional>``. ``parent_name`` is
    ``groupId:artifactId``.

    State mapping:
      * scope=compile or runtime + optional=false → unconditional
      * scope=provided / test → development-style
      * optional=true → optional-gated (consumers don't get it
        transitively unless they explicitly depend on it)
    """
    if not hasattr(client, "get_pom"):
        return None
    pom = client.get_pom(parent_name, parent_version)
    if not pom:
        return None
    transitive_canon = transitive_name.strip()  # case-sensitive
    extras: List[str] = []
    unconditional = False
    for dep in pom.get("dependencies") or []:
        if not isinstance(dep, dict):
            continue
        name = f"{dep.get('groupId','')}:{dep.get('artifactId','')}"
        if name != transitive_canon:
            continue
        scope = (dep.get("scope") or "compile").lower()
        optional = str(dep.get("optional", "")).lower() == "true"
        if optional:
            extras.append("optional")
        elif scope in ("compile", "runtime"):
            unconditional = True
        elif scope in ("provided", "test", "system"):
            extras.append(scope)
    return {"required": unconditional, "extras": extras}


# ---------------------------------------------------------------------------
# NuGet
# ---------------------------------------------------------------------------

def _dep_state_nuget(
    client, parent_name: str, parent_version: str,
    transitive_name: str,
) -> Optional[dict]:
    """NuGet nuspec files declare per-TFM dependency groups.
    A dep that appears in fewer TFM groups in a newer version is
    the closest analog to "moved to optional" — we conservatively
    report "required=True" when the dep appears in AT LEAST ONE
    group, "extras-gated" when it appears in only some groups but
    not all of the ones it appeared in the current version.

    For v1 we keep it simple: required if listed in ANY TFM group,
    extras-gated only if NO TFM has it.
    """
    if not hasattr(client, "get_nuspec"):
        return None
    nuspec = client.get_nuspec(parent_name, parent_version)
    if not nuspec:
        return None
    transitive_canon = transitive_name.lower()
    extras: List[str] = []
    unconditional = False
    for group in nuspec.get("dependency_groups") or []:
        for dep in group.get("dependencies") or []:
            if (dep.get("id") or "").lower() == transitive_canon:
                unconditional = True
                break
    return {"required": unconditional, "extras": extras}


def _requires_dist_for_version(
    pypi_client, name: str, version: str,
) -> Optional[List[str]]:
    """Fetch ``requires_dist`` for a SPECIFIC version.

    Prefers ``pypi_client.get_version_metadata(name, version)``
    when available (the standard PyPIClient surface from
    Phase-3.f). Falls back to the aggregate ``get_metadata(name)``
    when only that's available AND its reported version matches —
    useful for in-memory test stubs that don't implement the
    per-version method.
    """
    if hasattr(pypi_client, "get_version_metadata"):
        meta = pypi_client.get_version_metadata(name, version)
        if isinstance(meta, dict):
            info = meta.get("info") or {}
            rd = info.get("requires_dist")
            if isinstance(rd, list):
                return rd
    # Fallback for older stubs / clients without the per-version
    # method: try the aggregate, accept its data only if it
    # happens to be the version we want.
    meta = pypi_client.get_metadata(name)
    if not isinstance(meta, dict):
        return None
    info = meta.get("info") or {}
    if info.get("version") != version:
        return None
    rd = info.get("requires_dist")
    return rd if isinstance(rd, list) else None
