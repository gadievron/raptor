"""Composite risk estimate for a :class:`VulnFinding`.

Implements the multiplicative formula from ``design/sca.md`` §1246
("Risk model — calibration target for follow-up PR").

**Calibration status: unverified.** The formula's individual
multipliers are reasonable guesses informed by the components people
already use to triage CVEs (CVSS, KEV, EPSS, reachability), but the
specific weights have not yet been validated against a corpus of
known-exploited vs known-fixed-not-exploited CVEs. Operators should
treat ``raptor_risk_estimate`` as a sort key — useful for "look at
the top 10 first" — and use the component breakdown
(``risk_components``) when escalating individual findings to a real
decision.

The calibration follow-up (design §1135) will:
  1. Build a 50/50 KEV / fixed-not-exploited corpus.
  2. Run candidate formulas; pick the one that ranks exploited above
     non-exploited reliably.
  3. Re-tune the multipliers in this file.
  4. Flip the calibration status from "unverified" to "validated".

Until that lands, the formula here is the seed against which
calibration runs and the shape consumers depend on (the components
dict, the 0-100 range, the sort order).
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

from .models import Dependency, VulnFinding

# ---------------------------------------------------------------------------
# Multipliers — named so calibration tweaks are config-style, not a
# refactor (per design §1334 "Future evolution").
# ---------------------------------------------------------------------------

# CVSS — a missing CVSS score defaults to a neutral 5.0 (medium) so a
# finding without a numeric score isn't free of weight. Most CVEs have
# CVSS; the missing-score path is for OSV records that didn't include
# one (older GHSA entries, pre-CVSS advisories, etc.).
_CVSS_MISSING_DEFAULT = 5.0

# KEV — known-exploited get a floor + multiplier. Floor of 80 means a
# KEV CVE with low CVSS still ranks above a non-KEV high-CVSS finding,
# matching the "active exploitation > theoretical severity" priority.
_KEV_FLOOR = 80.0
_KEV_MULTIPLIER = 1.20

# EPSS — exploit probability in the wild. Even a 0% EPSS leaves 30%
# weight (a vuln with no observed exploitation isn't impossible to
# exploit; the floor reflects "unknown is not zero").
_EPSS_FLOOR_MULTIPLIER = 0.30
_EPSS_RANGE_MULTIPLIER = 0.70
_EPSS_MISSING_DEFAULT = 0.5

# Reachability — confidently-not-reachable downgrades hard; uncertain
# stays neutral. ``not_evaluated`` (no evidence either way) gets a
# small penalty to nudge operators toward investigating.
_REACH_NOT_REACHABLE_MAX_REDUCTION = 0.70
_REACH_NOT_EVALUATED_MULTIPLIER = 0.85

# Exposure — call-site density. Maps 0.0..1.0 onto 0.5..1.0 so a dep
# imported once has half the weight of a dep imported throughout the
# codebase, but never zero (one call site is still a call site).
_EXPO_FLOOR_MULTIPLIER = 0.50
_EXPO_RANGE_MULTIPLIER = 0.50

# Depth decay — direct deps full weight; transitive decays geometrically
# at 0.7 per level. Depth-3 transitive dep ≈ 0.34 weight: still meaningful
# but reflects the longer chain to actually trigger it.
_DEPTH_DECAY_BASE = 0.70

# Final clamp — keeps the score in 0..100 even if the multipliers
# briefly compose above 100 (KEV floor × KEV multiplier = 96 before
# the rest, so 0..120 inputs are possible).
_SCORE_MIN = 0.0
_SCORE_MAX = 100.0


def compute_risk_estimate(
    finding: VulnFinding, dep: Dependency,
) -> Tuple[float, Dict[str, Any]]:
    """Return ``(score, components)`` for the finding.

    ``score`` is a 0..100 float, deterministic from the finding's
    inputs. ``components`` is the breakdown — the CVSS base after
    KEV floor, every multiplier applied in order, and the final
    clamped score. The ``calibration_status`` key is always set to
    ``"unverified"`` for now; flip when the calibration corpus is
    built (see module docstring).
    """
    components: Dict[str, Any] = {}

    # 1. CVSS base — 0-10 → 0-100. Missing → neutral 5.
    cvss = (finding.cvss_score
            if finding.cvss_score is not None
            else _CVSS_MISSING_DEFAULT)
    base = (cvss / 10.0) * 100.0
    components["cvss_base"] = base

    # 2. KEV: known-exploited gets a floor + multiplier.
    if finding.in_kev:
        base = max(base, _KEV_FLOOR) * _KEV_MULTIPLIER
        components["kev_multiplier"] = _KEV_MULTIPLIER
    else:
        components["kev_multiplier"] = 1.0

    # 3. EPSS: 0..1 probability mapped onto a 0.30..1.00 multiplier.
    epss = finding.epss if finding.epss is not None else _EPSS_MISSING_DEFAULT
    epss_mult = _EPSS_FLOOR_MULTIPLIER + _EPSS_RANGE_MULTIPLIER * epss
    base *= epss_mult
    components["epss_multiplier"] = epss_mult

    # 4. Reachability: confidently-not-reachable downgrades; uncertain
    # stays neutral; not_evaluated gets a small penalty.
    r = finding.reachability
    if r.verdict in (
        "not_reachable", "not_function_reachable", "called_in_dead_code",
    ):
        # confidence.numeric is 0..1; max reduction at numeric=1.0.
        # All three verdicts share the "code path not exercised"
        # rationale and the same downgrade group; ``confidence.numeric``
        # does the work of distinguishing how strong the evidence is:
        #   * ``not_reachable``           — confidence high (~0.95):
        #     full downgrade. Module isn't imported.
        #   * ``not_function_reachable``  — confidence high (~0.95):
        #     full downgrade. Module imported but the specific
        #     affected function isn't called.
        #   * ``called_in_dead_code``     — confidence medium (~0.7):
        #     about 75% of the full downgrade. Function IS called,
        #     but the call site is in a private-named host with no
        #     callers in the static graph; less certain because the
        #     host could still be an unseen entry point.
        conf_numeric = r.confidence.numeric or 0.0
        reach_mult = 1.0 - _REACH_NOT_REACHABLE_MAX_REDUCTION * conf_numeric
    elif r.verdict == "not_evaluated":
        reach_mult = _REACH_NOT_EVALUATED_MULTIPLIER
    else:                                       # imported / likely_called
        reach_mult = 1.0
    base *= reach_mult
    components["reachability_multiplier"] = reach_mult

    # 5. Exposure: call-site density normalised within the project.
    expo = max(0.0, min(1.0, finding.exposure_factor))
    expo_mult = _EXPO_FLOOR_MULTIPLIER + _EXPO_RANGE_MULTIPLIER * expo
    base *= expo_mult
    components["exposure_multiplier"] = expo_mult

    # 6. Direct vs transitive depth decay.
    if dep.direct or finding.transitive_depth <= 0:
        depth_mult = 1.0
    else:
        depth_mult = _DEPTH_DECAY_BASE ** finding.transitive_depth
    base *= depth_mult
    components["depth_multiplier"] = depth_mult

    # 7. Parser confidence — heuristic parsers haircut.
    parser_conf = dep.parser_confidence.numeric or 1.0
    base *= parser_conf
    components["parser_confidence"] = parser_conf

    # 8. Version-match confidence — uncertain matches penalised.
    vmc = finding.version_match_confidence.numeric or 1.0
    base *= vmc
    components["version_match_confidence"] = vmc

    final = max(_SCORE_MIN, min(_SCORE_MAX, base))
    components["final"] = final
    components["calibration_status"] = "unverified"   # pending KEV corpus

    return final, components


__all__ = ["compute_risk_estimate"]
