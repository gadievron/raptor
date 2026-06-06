"""Composite supply-chain scoring at the ``evaluate`` chokepoint.

Each individual detector in ``supply_chain/`` aims for low FP rate in
isolation; the composite scorer here adds a second axis: when MULTIPLE
distinct detector families fire on the *same* (ecosystem, package,
version), the conjunction itself is the signal — and severity is
promoted accordingly.

The principle mirrors the dataflow validator's chokepoint approach:
cheap individual signals at honest confidence, combined into a
high-confidence verdict at one place.  Per-detector FP tuning is
endless and brittle; composite scoring is finite and resilient.

# Adversarial model

What this layer must defend against:

  * **Composite-evasion by package fragmentation** — an attacker who
    knows we look for multi-family signals would try to spread the
    attack across different versions so each version trips only one
    family.  Defence: grouping key is
    ``(ecosystem, name, version)`` — different versions are different
    groups.  An attacker still gains nothing because any single
    malicious version still trips the per-detector signals; we just
    don't help them by combining unrelated versions.

  * **Family-map gaps used to slip findings past the chokepoint** —
    a finding kind we don't classify gets no family and no
    contribution to a composite.  Defence: enumerate all
    ``SupplyChainKind`` values; unknown kinds are logged but never
    silently lost.  Reviewers add new kinds to ``_FAMILY`` when they
    land detectors.

  * **Severity downgrade by polluted findings** — an attacker who can
    seed an extra low-severity finding on a victim package might try
    to force a downgrade.  Defence: composite is a one-way ratchet —
    it can only PROMOTE a finding's severity, never demote.  The
    original severity is preserved in the ``composite_score`` evidence
    field so audit trails stay honest.

  * **Order-dependent results** — if the composite calculation were
    sensitive to detector firing order, an attacker could try to
    interleave findings to suppress promotion.  Defence: the family
    set per dep is a ``frozenset``; promotion is computed from set
    membership alone, not iteration order.  Deterministic by
    construction.

  * **Co-firing on UNRELATED deps inflating severity** — two
    legitimate findings on two different deps must NOT combine.
    Defence: grouping key is per-dep; cross-dep aggregation is
    explicitly out of scope.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import replace
from typing import Dict, FrozenSet, List, Mapping, Optional, Tuple

from ..models import (
    Dependency,
    Severity,
    SupplyChainFinding,
    SupplyChainKind,
)

logger = logging.getLogger(__name__)


# Map each finding ``kind`` to a coarse-grained "family" that names
# the SHAPE of attack signal it carries.  Families are what compose
# at the chokepoint; individual ``kind`` values are too granular for
# meaningful conjunction reasoning.
#
# Adding a new detector? Add its kinds here.  An unmapped kind
# contributes nothing to composite scoring (no harm, just no lift).
_FAMILY: Mapping[SupplyChainKind, str] = {
    # HOOK — code-execution surface attached to install / build /
    # import.  Single most important family because every supply-
    # chain attack must run code somewhere; that "somewhere" is
    # almost always a hook.
    "install_hook_suspicious":          "HOOK",
    "python_import_time_execution":     "HOOK",
    # BINARY — anomalous payload-shaped file in a source-distribution
    # tarball.  Includes native binaries, obfuscated source, and
    # files-pretending-to-be-other-files.
    "binary_in_tests":                  "BINARY",
    "binary_in_package":                "BINARY",
    "binary_capability_delta":          "BINARY",
    "image_capability_drift":           "BINARY",
    "large_obfuscated_artefact":        "BINARY",
    "disguised_filename":               "BINARY",
    "python_pth_file":                  "BINARY",
    "payload_size_spike":               "BINARY",
    # EGRESS — runtime / install-time exfil destination references.
    "known_exfil_destination":          "EGRESS",
    # GHA — GitHub Actions workflow hygiene + flow.
    "gha_action_ref_drift":             "GHA",
    "gha_secret_flow":                  "GHA",
    "gha_action_sunset":                "GHA",
    "gha_action_outdated":              "GHA",
    "workflow_unsigned_commit":         "GHA",
    "branch_protection_missing_signed_commits": "GHA",
    # REGISTRY — registry-side hygiene: ownership / publishing /
    # recency anomalies.  Often the FIRST signal a package was
    # taken over.
    "recent_publish":                   "REGISTRY",
    "version_publish":                  "REGISTRY",
    "maintainer_change":                "REGISTRY",
    "maintainer_account_change":        "REGISTRY",
    "low_bus_factor":                   "REGISTRY",
    "version_diff_anomaly":             "REGISTRY",
    "platform_compat_regression":       "REGISTRY",
    "platform_compat_improvement":      "REGISTRY",
    "transitive_now_optional":          "REGISTRY",
    # PIN — source-pin drift (git tag mutability, orphan commits,
    # forged-identity manifest commits).
    "git_tag_drift":                    "PIN",
    "orphan_commit_dep":                "PIN",
    "commit_provenance_drift":          "PIN",
    # SQUAT — name-based attacks.
    "typosquat_candidate":              "SQUAT",
    "typosquat_domain":                 "SQUAT",
    "slopsquat_suspect":                "SQUAT",
    # SENTINEL — explicit curated known-bad.  Always a strong
    # standalone signal; pairs with anything for critical escalation.
    "sentinel_match":                   "SENTINEL",
}


# Hard-pair conjunctions — when both families fire on the same dep,
# the resulting severity is ``critical`` regardless of the individual
# findings' base severities.  These are the structural archetypes
# RAPTOR considers "supply-chain attack shaped" — co-occurrence is
# the signal even when each individual rule fires informationally.
#
# Sets are matched as SUBSETS (``pair <= families``) so the pair is
# detected even when additional families also fire on the same dep.
_HARD_PAIRS: FrozenSet[FrozenSet[str]] = frozenset({
    # Iron Worm shape: lifecycle hook executes a payload that ships
    # in the package's own tree.
    frozenset({"HOOK", "BINARY"}),
    # Generic exfil-worm shape: install-time code execution + a
    # destination known for credential exfil.
    frozenset({"HOOK", "EGRESS"}),
    # CI-level explicit known-bad: a curated denylist hit on a
    # workflow-touching dep means the attack is shipping CI-side.
    frozenset({"GHA", "SENTINEL"}),
    # Curated known-bad + name-based deception is the
    # account-takeover-via-typosquat archetype.
    frozenset({"SENTINEL", "SQUAT"}),
})


# Severity rank for ordered comparisons.  Mirrors the order in
# :data:`packages.sca.models.Severity` (``Literal``); kept hand-coded
# rather than ``Literal.__args__``-derived because the literal's
# order is the source of truth for displayed severity but the
# RANKING is a separate semantic decision.
_SEVERITY_ORDER: Tuple[Severity, ...] = (
    "info", "low", "medium", "high", "critical",
)
_RANK: Mapping[Severity, int] = {s: i for i, s in enumerate(_SEVERITY_ORDER)}


def _dep_key(dep: Dependency) -> Tuple[str, str, str]:
    """Per-version grouping key.  An attacker who spreads payload
    across multiple versions deliberately fragments the composite
    signal; that's their choice — we don't help them combine across
    versions either."""
    return (dep.ecosystem, dep.name, dep.version)


def _families_per_dep(
    findings: List[SupplyChainFinding],
) -> Dict[Tuple[str, str, str], FrozenSet[str]]:
    """Bucket findings by per-version dep key, project to family set."""
    by_dep: Dict[Tuple[str, str, str], set] = defaultdict(set)
    for f in findings:
        family = _FAMILY.get(f.kind)
        if family is None:
            # Unknown kind — diagnostic, never silent loss.  When a
            # new detector ships, its kind should be added to
            # ``_FAMILY`` so the chokepoint sees it.
            logger.debug(
                "sca.composite: kind %r has no family mapping; "
                "skipping composite contribution",
                f.kind,
            )
            continue
        by_dep[_dep_key(f.dependency)].add(family)
    return {k: frozenset(v) for k, v in by_dep.items()}


def _promotion_target(families: FrozenSet[str]) -> Optional[Severity]:
    """Return the severity FLOOR the composite signal earns, or None
    when no promotion applies.

    Rules:
      * Any hard-pair subset → ``critical`` regardless of base.
      * 2 distinct families → floor ``medium``.
      * 3 distinct families → floor ``high``.
      * 4+ distinct families → floor ``critical``.

    The promotion is a FLOOR — the finding's severity is bumped TO
    this rank only if its current rank is lower.  Floor is never
    used to demote.
    """
    for pair in _HARD_PAIRS:
        if pair <= families:
            return "critical"
    n = len(families)
    if n >= 4:
        return "critical"
    if n == 3:
        return "high"
    if n == 2:
        return "medium"
    return None


def _promoted(
    finding: SupplyChainFinding,
    new_floor: Severity,
    families: FrozenSet[str],
) -> SupplyChainFinding:
    """Return a NEW finding with severity raised to ``new_floor``
    and a ``composite_score`` evidence stamp.

    Severity is the MAX of the current and the new floor — composite
    NEVER demotes.  Original severity is preserved in evidence for
    audit / explainability.
    """
    if _RANK[new_floor] <= _RANK[finding.severity]:
        # Floor doesn't lift this finding; still stamp evidence so
        # operators can see WHY this finding is in a composite-eligible
        # group even when no promotion was needed for THIS row.
        evidence = dict(finding.evidence)
        evidence["composite_score"] = {
            "families": sorted(families),
            "promotion": "no-op (already at or above floor)",
            "floor": new_floor,
            "original_severity": finding.severity,
        }
        return replace(finding, evidence=evidence)
    evidence = dict(finding.evidence)
    evidence["composite_score"] = {
        "families": sorted(families),
        "promotion": (
            "hard-pair → critical"
            if new_floor == "critical" and any(
                pair <= families for pair in _HARD_PAIRS
            )
            else f"{len(families)} families → {new_floor}"
        ),
        "floor": new_floor,
        "original_severity": finding.severity,
    }
    return replace(finding, severity=new_floor, evidence=evidence)


def apply(findings: List[SupplyChainFinding]) -> List[SupplyChainFinding]:
    """Apply composite scoring across ``findings``.

    Returns a NEW list.  Findings that participate in a multi-family
    composite get a ``composite_score`` evidence stamp and (when the
    floor exceeds their original severity) a raised severity.
    Findings on deps where only one family fires are returned
    unchanged.

    Pure function — input list is not mutated.  Order is preserved.
    Stable across reruns of the same input.
    """
    families = _families_per_dep(findings)
    out: List[SupplyChainFinding] = []
    for f in findings:
        key = _dep_key(f.dependency)
        fam_set = families.get(key, frozenset())
        if len(fam_set) >= 2:
            floor = _promotion_target(fam_set)
            if floor is not None:
                out.append(_promoted(f, floor, fam_set))
                continue
        out.append(f)
    return out
