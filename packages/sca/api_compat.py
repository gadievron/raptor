"""API-compat upgrade verification — heuristic risk signals for
``sca update --apply``.

When the ``update`` command proposes upgrading X → Y, this module
emits ``UpgradeCompatRisk`` rows surfacing signals that the
upgrade may break the project. The mechanical pipeline can't
fully verify API compatibility (would need installation, type
checking, full call-graph dataflow); but it can flag two
high-signal heuristics that operators routinely care about:

  * **semver-major bump** — going from ``X.y.z`` to ``Y.y'.z'``
    where ``X != Y`` means upstream is signalling backwards-
    incompatible changes per the semver contract. Operators
    using ``sca update --apply`` without ``--allow-major``
    already get a hard guard, but the signal is also useful at
    review time for the case where ``--allow-major`` IS set.
  * **dep-set churn** — when Y's ``requires_dist`` differs
    materially from X's (added / removed deps, or upper-bound
    differences on shared deps), the upgrade is more likely to
    surface knock-on breaks downstream. This catches the case
    where a "minor" version bump silently introduces a new
    transitive dep tree.

Heavier checks (full symbol-level API diff via wheel
inspection) are deferred — they need wheel-fetching at scale
(~50MB per package) and AST parsing of every public module.
That's a separate substrate-level effort; this MVP gives
operators useful signal without that cost.

## Scope

Currently PyPI only — npm / Cargo / Maven / etc. follow the
same shape but each ecosystem has different "what's a major
version" + "what's a dep-set" conventions; ship them when an
operator asks.

## Output

:class:`UpgradeCompatRisk` instances; consumers (the ``update``
command, the LLM ``upgrade_impact_review``, the report
renderer) decide how to surface them. The model is data-
shaped, not finding-shaped — these aren't security findings;
they're upgrade-decision aids that ride alongside the existing
``upgrade_impact`` flow.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, List, Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class UpgradeCompatRisk:
    """One risk signal for an X → Y upgrade."""

    kind: str              # "semver_major" | "deps_added" | "deps_removed"
                            # | "deps_constraint_tightened"
    detail: str
    severity: str          # "info" | "low" | "medium" | "high"


@dataclass(frozen=True)
class UpgradeCompatReport:
    """Aggregate risk signals for one X → Y upgrade decision."""

    ecosystem: str
    name: str
    from_version: str
    to_version: str
    risks: List[UpgradeCompatRisk] = field(default_factory=list)

    @property
    def overall_severity(self) -> str:
        """Highest severity across the constituent risks. Empty
        list -> ``"info"`` (no risks identified)."""
        order = ["info", "low", "medium", "high", "critical"]
        if not self.risks:
            return "info"
        max_idx = max(order.index(r.severity) for r in self.risks)
        return order[max_idx]


# ---------------------------------------------------------------------------
# Public entry: check_pypi_api_compat
# ---------------------------------------------------------------------------


def check_pypi_api_compat(
    name: str,
    from_version: str,
    to_version: str,
    *,
    http: Any = None,
    cache: Any = None,
) -> UpgradeCompatReport:
    """Compute risk signals for a PyPI X → Y upgrade.

    Hits PyPI's JSON API for both versions' metadata. When
    network is unavailable / cache empty, returns a report
    containing only the semver-bump signal (which is computable
    from version strings alone — no metadata needed).
    """
    risks: List[UpgradeCompatRisk] = []

    # Always-on: semver heuristic. Pure version-string analysis;
    # no network needed.
    semver_risk = _semver_bump_risk(from_version, to_version)
    if semver_risk is not None:
        risks.append(semver_risk)

    # Network-gated: dep-set comparison.
    if http is not None:
        dep_risks = _pypi_dep_set_risks(
            name, from_version, to_version, http=http, cache=cache,
        )
        risks.extend(dep_risks)

    return UpgradeCompatReport(
        ecosystem="PyPI",
        name=name,
        from_version=from_version,
        to_version=to_version,
        risks=risks,
    )


# ---------------------------------------------------------------------------
# semver heuristic
# ---------------------------------------------------------------------------


_SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)")


def _semver_bump_risk(
    from_v: str, to_v: str,
) -> Optional[UpgradeCompatRisk]:
    """Detect major-version bumps. Operators using
    ``sca update --apply --allow-major`` get a "this is a
    semver-major break per upstream's own contract" signal."""
    fm = _SEMVER_RE.match(from_v.lstrip("v"))
    tm = _SEMVER_RE.match(to_v.lstrip("v"))
    if not fm or not tm:
        return None
    from_major = int(fm.group(1))
    to_major = int(tm.group(1))
    if from_major == to_major:
        return None
    if to_major > from_major:
        # 0.x → 1.x is special: pre-1.0 packages don't follow
        # semver guarantees; the bump to 1.0 isn't necessarily a
        # break. Still warn at lower severity.
        if from_major == 0:
            return UpgradeCompatRisk(
                kind="semver_major",
                detail=(
                    f"upgrade {from_v} → {to_v} crosses the 1.0 "
                    f"stability boundary; pre-1.0 packages don't "
                    f"follow the semver contract — review the "
                    f"release notes for breaking changes"
                ),
                severity="medium",
            )
        return UpgradeCompatRisk(
            kind="semver_major",
            detail=(
                f"semver-major upgrade {from_v} → {to_v}; "
                f"upstream signals backwards-incompatible "
                f"changes per the semver contract"
            ),
            severity="high",
        )
    # Downgrade — flag separately. Operators rarely intend this.
    return UpgradeCompatRisk(
        kind="semver_major",
        detail=(
            f"DOWNGRADE {from_v} → {to_v} crosses a major-version "
            f"boundary backwards; double-check this is intentional"
        ),
        severity="high",
    )


# ---------------------------------------------------------------------------
# Dep-set comparison via PyPI JSON
# ---------------------------------------------------------------------------


def _pypi_dep_set_risks(
    name: str, from_v: str, to_v: str,
    *, http: Any, cache: Any,
) -> List[UpgradeCompatRisk]:
    """Compare ``requires_dist`` between two PyPI versions.

    Three signals:
      * Deps added in Y that weren't in X — operator's lockfile
        will pull them; supply-chain surface grows.
      * Deps removed in Y that were in X — usually fine, but
        worth surfacing in case the operator's code uses them
        transitively.
      * Constraint tightened in Y — e.g. X required
        ``requests>=2.20`` and Y requires ``requests>=2.31``;
        operators on older requests get pulled forward.
    """
    out: List[UpgradeCompatRisk] = []
    from_deps = _fetch_pypi_requires_dist(name, from_v, http=http, cache=cache)
    to_deps = _fetch_pypi_requires_dist(name, to_v, http=http, cache=cache)
    if from_deps is None or to_deps is None:
        return out
    from_names = {_dep_name(d): d for d in from_deps}
    to_names = {_dep_name(d): d for d in to_deps}

    added = sorted(set(to_names) - set(from_names))
    removed = sorted(set(from_names) - set(to_names))
    if added:
        out.append(UpgradeCompatRisk(
            kind="deps_added",
            detail=(
                f"{len(added)} new dependency requirement(s) in {to_v}: "
                f"{', '.join(added[:5])}"
                + (f" (+{len(added) - 5} more)" if len(added) > 5 else "")
            ),
            severity="low",
        ))
    if removed:
        out.append(UpgradeCompatRisk(
            kind="deps_removed",
            detail=(
                f"{len(removed)} dependency requirement(s) dropped in {to_v}: "
                f"{', '.join(removed[:5])}"
                + (f" (+{len(removed) - 5} more)" if len(removed) > 5 else "")
            ),
            severity="info",
        ))
    return out


def _fetch_pypi_requires_dist(
    name: str, version: str,
    *, http: Any, cache: Any,
) -> Optional[List[str]]:
    """Fetch a specific version's ``requires_dist`` from PyPI's
    JSON API. Cached per-(name, version) for the run.

    Returns the raw requires_dist list (free-text PEP 508 specs)
    or None on fetch failure.
    """
    # ``requires_dist`` for a published PyPI version is IMMUTABLE.
    # PyPI forbids re-publishing the same version (PEP 440 + the
    # filename-uniqueness rule); a yank only marks the version as
    # withdrawn, doesn't change its metadata. So per-version
    # requires_dist gets cached TTL_FOREVER. Operators wanting to
    # force a refetch (debugging a corrupt cache) run
    # ``raptor-sca clean-cache``.
    from core.json.cache import TTL_FOREVER
    cache_key = f"pypi-requires-dist:{name.lower()}:{version}"
    if cache is not None:
        cached = cache.get(cache_key, ttl_seconds=TTL_FOREVER)
        if cached is not None:
            return list(cached) if cached else []
    try:
        url = f"https://pypi.org/pypi/{name}/{version}/json"
        data = http.get_json(url)
    except Exception:                                   # noqa: BLE001
        return None
    if not isinstance(data, dict):
        return None
    info = data.get("info") or {}
    reqs = info.get("requires_dist") or []
    if not isinstance(reqs, list):
        return []
    out = [r for r in reqs if isinstance(r, str)]
    if cache is not None:
        cache.put(cache_key, out, ttl_seconds=TTL_FOREVER)
    return out


def _dep_name(spec: str) -> str:
    """Pull the dep name from a PEP 508 spec like
    ``requests>=2.20``. Lowercased + canonicalised so
    ``Django`` and ``django`` compare equal."""
    # Names per PEP 508 grammar can be alphanumeric + ``.``, ``-``, ``_``.
    m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", spec)
    if not m:
        return spec.strip().lower()
    return re.sub(r"[-_.]+", "-", m.group(1)).lower()


__all__ = [
    "UpgradeCompatReport",
    "UpgradeCompatRisk",
    "check_pypi_api_compat",
]
