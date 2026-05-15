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
    Confidence, Dependency, SupplyChainFinding, VulnFinding,
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
    pypi_client,
) -> List[DropOnBumpFinding]:
    """For each finding on a cascade-sourced PyPI dep, check
    whether a parent bump would drop the dep entirely.

    ``pypi_client`` must expose ``get_metadata(name)`` and
    ``list_versions(name)`` (the standard PyPIClient surface).
    Returns one entry per (transitive, parent) where the bump
    would drop the transitive.

    Coverage: PyPI ecosystem only; transitive must have
    ``source_kind == "cascade_resolver"`` AND
    ``source_extra["via"]`` populated.
    """
    if pypi_client is None:
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
    # Map name → list of (dep, parents).
    by_name: Dict[str, List[Dependency]] = {}
    for d in deps_list:
        if d.ecosystem != "PyPI":
            continue
        if d.source_kind != "cascade_resolver":
            continue
        if not d.source_extra:
            continue
        if not d.source_extra.get("via"):
            continue
        by_name.setdefault(d.name.lower().replace("_", "-"), []).append(d)

    # Direct PyPI deps indexed by canonical name — we need their
    # currently-pinned version when querying parent metadata.
    direct_versions: Dict[str, str] = {}
    for d in deps_list:
        if d.ecosystem == "PyPI" and d.direct and d.version:
            canon = d.name.lower().replace("_", "-")
            direct_versions[canon] = d.version

    for canon_name, transitive_deps in by_name.items():
        # Only spend the PyPI roundtrip on transitives whose
        # PROBLEMS make a bump worth surfacing.
        sample = transitive_deps[0]
        key = (sample.ecosystem, sample.name)
        if key not in issue_keys:
            continue
        underlying_sev = issue_keys[key]

        for parent in sample.source_extra.get("via") or []:
            parent_canon = parent.lower().replace("_", "-")
            pair = (canon_name, parent_canon)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)

            parent_pinned = direct_versions.get(parent_canon)
            if not parent_pinned:
                # The "parent" came from pip-compile's ``# via``
                # but isn't in our direct dep set — could be a
                # transitive-of-transitive. We can still try the
                # diff against latest but skip the current-version
                # comparison.
                pass

            try:
                latest = _latest_stable_version(pypi_client, parent_canon)
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

            # Diff current's requires_dist against latest's.
            current_state = _dep_state_in_version(
                pypi_client, parent_canon,
                parent_pinned or latest, canon_name,
            )
            latest_state = _dep_state_in_version(
                pypi_client, parent_canon, latest, canon_name,
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


def _latest_stable_version(pypi_client, name: str) -> Optional[str]:
    """Walk PyPI release map; return the highest stable version
    (regex matches our parse_stable contract)."""
    meta = pypi_client.get_metadata(name)
    if not isinstance(meta, dict):
        return None
    releases = meta.get("releases") or {}
    stable = [v for v in releases.keys() if _STABLE_RE.match(v)]
    if not stable:
        return None
    stable.sort(key=_version_key, reverse=True)
    return stable[0]


def _dep_state_in_version(
    pypi_client, parent_name: str, parent_version: str,
    transitive_name: str,
) -> Optional[dict]:
    """Inspect parent_name==parent_version's requires_dist; return
    info about how it declares ``transitive_name``.

    Returns:
      None — couldn't fetch the version metadata
      {"required": True}                     — unconditional dep
      {"required": False, "extras": ["x"]}    — only via extras
      {"required": False, "extras": []}        — not declared at all
    """
    meta = pypi_client.get_metadata(parent_name)
    if not isinstance(meta, dict):
        return None
    # PyPI's /<name>/json returns aggregated metadata where
    # ``info.requires_dist`` reflects the LATEST version. For
    # historical versions we'd need /<name>/<ver>/json. Fetch
    # version-specific metadata when possible.
    requires_dist = _requires_dist_for_version(
        pypi_client, parent_name, parent_version,
    )
    if requires_dist is None:
        # Couldn't get version-specific; fall back to ``info``.
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
        # Get the package name + any extra marker.
        name_part, _, marker = req.partition(";")
        # First token of name_part is the package name (possibly
        # with extras-of-its-own like ``foo[extra]`` or
        # version-spec like ``foo>=1.0`` — split on first non-name
        # char).
        name_match = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", name_part)
        if not name_match:
            continue
        req_name = name_match.group(1).lower().replace("_", "-")
        if req_name != transitive_canon:
            continue

        # Is there an ``extra == "x"`` in the marker?
        if marker.strip():
            m = re.search(r"extra\s*==\s*[\"']([^\"']+)[\"']", marker)
            if m:
                extras.append(m.group(1))
            else:
                # Has marker but not extras (e.g. platform_python_impl)
                # → still treat as conditional for safety.
                pass
        else:
            unconditional = True

    return {
        "required": unconditional,
        "extras": extras,
    }


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
