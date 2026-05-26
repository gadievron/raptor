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

from typing import Any, Dict, List, Optional, Tuple

from .models import Dependency, VulnFinding

# ---------------------------------------------------------------------------
# Multipliers — named so calibration tweaks are config-style, not a
# refactor (per design §1334 "Future evolution").
# ---------------------------------------------------------------------------

# CVSS — a missing CVSS score defaults to a neutral 5.0 (medium) so a
# finding without a numeric score isn't free of weight. Most CVEs have
# CVSS; the missing-score path is for OSV records that didn't include
# one (older GHSA entries, pre-CVSS advisories, etc.).
#
# When a numeric is missing BUT the advisory carries a severity
# label, ``packages.cvss.score_for_label`` returns a representative
# numeric (lower-bound of the matching tier per CVSS v3.1's
# severity-rating table) — pairing the bijection-ish severity↔score
# mapping in one module rather than duplicating it here. The
# fallback is applied below in ``compute_risk_estimate``.
_CVSS_MISSING_DEFAULT = 5.0

# KEV — known-exploited get a floor + multiplier. Floor of 80 means a
# KEV CVE with low CVSS still ranks above a non-KEV high-CVSS finding,
# matching the "active exploitation > theoretical severity" priority.
_KEV_FLOOR = 96.8
_KEV_MULTIPLIER = 1.7569

# Exploit-evidence (Exploit-DB / Metasploit / GitHub PoC). KEV's the
# strongest "actively exploited in the wild" signal, but it covers
# only ~1500 CVEs. EDB / MSF / PoC each independently testify that a
# working exploit exists for the CVE — a vuln with a public Metasploit
# module is materially more dangerous than one whose exploitability
# is only theoretical, even if it's not in KEV. The 2026-05-09
# calibration validation found 4 of 7 exploited CVEs ranked at 99,
# 174, 175, 192/343 because none were KEV-listed despite all being
# in EDB. Floor is below KEV's so KEV-listed still wins on tied CVSS;
# multiplier is smaller for the same reason — EDB/MSF/PoC are weaker
# signals than active CISA-tracked exploitation.
_EXPLOIT_EVIDENCE_FLOOR = 79.86
# Strictly below `_KEV_MULTIPLIER` — pinned by `is_admissible`'s
# `exploit_evidence_strictly_below_kev` rule. A previous refit
# pass set this to 1.21 which crossed KEV's 1.20; round-2 with
# constraint-aware refit caught the violation. If KEV_MULT moves
# later this constant has headroom to follow.
_EXPLOIT_EVIDENCE_MULTIPLIER = 1.5839

# CISA Vulnrichment SSVC — pair of tier-floors mirroring KEV /
# ExploitEvidence semantics but TUNED INDEPENDENTLY. Pre-fix
# SSVC-active aliased to ``_KEV_*`` and SSVC-poc to
# ``_EXPLOIT_EVIDENCE_*``; the calibration data on 2026-05-21
# showed Packagist ρ stuck at 0.33 because the EE multiplier
# was capped by the ``EE strictly below KEV`` cross-constraint
# and couldn't lift the many SSVC-poc-only Packagist findings.
# Decoupled here so the ρ-aware refit can move SSVC weights
# independently. Defaults match the (KEV, EE) tier values
# at the time of decoupling so behaviour is unchanged until
# refit moves them.
#
# Cross-constraint (admissibility):
#   _SSVC_POC_MULTIPLIER < _SSVC_ACTIVE_MULTIPLIER
# matches the "PoC code is a weaker signal than active
# in-the-wild exploitation" semantic. KEV / EE constraints
# stay independent — SSVC ≠ KEV / EE structurally (different
# signal source, different coverage shape).
_SSVC_ACTIVE_FLOOR = 96.8
_SSVC_ACTIVE_MULTIPLIER = 1.452
_SSVC_POC_FLOOR = 79.86
_SSVC_POC_MULTIPLIER = 1.4399

# SSVC ``Automatable`` bonus. Applied on top of an SSVC tier
# (active or poc) when the decision is ``automatable=yes``.
# CISA's intent: a PoC + automation potential is materially
# scarier than a PoC alone — the EternalBlue / Log4Shell class
# of bug fans out across the internet because each step CAN be
# automated. Modest 10% bonus to avoid double-counting (the
# tier multiplier already reflects "exploit code exists"). Only
# applies when ``Automatable=yes``; ``no`` / ``None`` carry no
# multiplier (the SSVC tier alone applies).
_SSVC_AUTOMATABLE_BONUS = 1.331

# EPSS — exploit probability in the wild. Even a 0% EPSS leaves 30%
# weight (a vuln with no observed exploitation isn't impossible to
# exploit; the floor reflects "unknown is not zero").
_EPSS_FLOOR_MULTIPLIER = 0.3993
_EPSS_RANGE_MULTIPLIER = 0.5103
_EPSS_MISSING_DEFAULT = 0.5

# Reachability — confidently-not-reachable downgrades hard; uncertain
# stays neutral. ``not_evaluated`` (no evidence either way) gets a
# small penalty to nudge operators toward investigating.
_REACH_NOT_REACHABLE_MAX_REDUCTION = 0.4593
_REACH_NOT_EVALUATED_MULTIPLIER = 0.6817

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
    *,
    overrides: Optional[Dict[str, float]] = None,
) -> Tuple[float, Dict[str, Any]]:
    """Return ``(score, components)`` for the finding.

    ``score`` is a 0..100 float, deterministic from the finding's
    inputs. ``components`` is the breakdown — the CVSS base after
    KEV floor, every multiplier applied in order, and the final
    clamped score. The ``calibration_status`` key reflects the
    latest validation report's verdict.

    ``overrides`` is an optional dict mapping named-constant
    identifiers (``"_KEV_MULTIPLIER"`` etc.) to override values.
    Used by the calibration refitter
    (``packages/sca/calibration/refit.py``) to grid-search
    multiplier values without monkey-patching module state.
    Default behaviour (``overrides=None``) is unchanged.
    """
    o = overrides or {}
    cvss_missing = o.get("_CVSS_MISSING_DEFAULT", _CVSS_MISSING_DEFAULT)
    kev_floor = o.get("_KEV_FLOOR", _KEV_FLOOR)
    kev_mult = o.get("_KEV_MULTIPLIER", _KEV_MULTIPLIER)
    ee_floor = o.get("_EXPLOIT_EVIDENCE_FLOOR", _EXPLOIT_EVIDENCE_FLOOR)
    ee_mult = o.get("_EXPLOIT_EVIDENCE_MULTIPLIER", _EXPLOIT_EVIDENCE_MULTIPLIER)
    ssvc_active_floor = o.get(
        "_SSVC_ACTIVE_FLOOR", _SSVC_ACTIVE_FLOOR,
    )
    ssvc_active_mult = o.get(
        "_SSVC_ACTIVE_MULTIPLIER", _SSVC_ACTIVE_MULTIPLIER,
    )
    ssvc_poc_floor = o.get("_SSVC_POC_FLOOR", _SSVC_POC_FLOOR)
    ssvc_poc_mult = o.get("_SSVC_POC_MULTIPLIER", _SSVC_POC_MULTIPLIER)
    ssvc_automatable_bonus = o.get(
        "_SSVC_AUTOMATABLE_BONUS", _SSVC_AUTOMATABLE_BONUS,
    )
    epss_floor = o.get("_EPSS_FLOOR_MULTIPLIER", _EPSS_FLOOR_MULTIPLIER)
    epss_range = o.get("_EPSS_RANGE_MULTIPLIER", _EPSS_RANGE_MULTIPLIER)
    epss_missing = o.get("_EPSS_MISSING_DEFAULT", _EPSS_MISSING_DEFAULT)
    reach_max_red = o.get(
        "_REACH_NOT_REACHABLE_MAX_REDUCTION",
        _REACH_NOT_REACHABLE_MAX_REDUCTION,
    )
    reach_not_eval = o.get(
        "_REACH_NOT_EVALUATED_MULTIPLIER", _REACH_NOT_EVALUATED_MULTIPLIER,
    )
    expo_floor = o.get("_EXPO_FLOOR_MULTIPLIER", _EXPO_FLOOR_MULTIPLIER)
    expo_range = o.get("_EXPO_RANGE_MULTIPLIER", _EXPO_RANGE_MULTIPLIER)
    depth_decay = o.get("_DEPTH_DECAY_BASE", _DEPTH_DECAY_BASE)

    components: Dict[str, Any] = {}

    # 1. CVSS base — 0-10 → 0-100. Missing → severity-label
    # fallback via ``packages.cvss.score_for_label`` (paired
    # with ``_SEVERITY`` in the cvss package so the
    # label↔score mapping has one source of truth) →
    # ``cvss_missing`` neutral 5.0. Many cold-start eco
    # advisories (Cargo / NuGet / Packagist) carry a severity
    # label but no parseable CVSS vector; without the fallback
    # those collapse to the neutral 5.0 even when labelled
    # CRITICAL by the upstream advisory, which depresses
    # Spearman ρ on those ecos.
    if finding.cvss_score is not None:
        cvss = finding.cvss_score
        components["cvss_source"] = "numeric"
    else:
        from packages.cvss import score_for_label
        derived = score_for_label(finding.severity or "")
        if derived is not None:
            cvss = derived
            components["cvss_source"] = "severity_label"
        else:
            cvss = cvss_missing
            components["cvss_source"] = "default"
    base = (cvss / 10.0) * 100.0
    components["cvss_base"] = base

    # 2. KEV: known-exploited gets a floor + multiplier.
    if finding.in_kev:
        base = max(base, kev_floor) * kev_mult
        components["kev_multiplier"] = kev_mult
    else:
        components["kev_multiplier"] = 1.0

    # 2-bis. Exploit evidence (EDB / MSF / GitHub PoC). Independent of
    # in_kev: a CVE can have a public Metasploit module without being
    # in CISA's KEV, and that's still a "working exploit exists"
    # signal we want to surface. KEV-listed findings ALSO get this
    # bonus on top — multipliers compose, matching the design where
    # each independent signal nudges the score upward. The floor is
    # only applied when KEV's floor wasn't (KEV strictly dominates;
    # we don't want a non-KEV PoC to push above an actually-exploited
    # KEV vuln on tied CVSS).
    has_evidence = (
        finding.exploit_evidence is not None
        and finding.exploit_evidence.has_any
        and not finding.in_kev   # not already counted
    )
    if has_evidence:
        base = max(base, ee_floor) * ee_mult
        components["exploit_evidence_multiplier"] = ee_mult
    else:
        components["exploit_evidence_multiplier"] = 1.0

    # 2-ter. CISA Vulnrichment SSVC. Broader coverage than KEV /
    # EDB / MSF (~60% of cold-start eco CVEs vs ~0%); when an
    # advisory carries an SSVC ``active`` decision, the CVE is
    # being exploited in the wild and gets KEV-tier treatment
    # even when CISA hasn't yet promoted it onto the KEV list
    # itself. ``poc`` gets ExploitEvidence-tier treatment —
    # there's public PoC code but no observed in-the-wild use.
    # Each tier checks "not already counted" to keep one signal
    # from being double-counted as KEV + SSVC-active.
    ssvc = finding.ssvc_exploitation
    ssvc_tier_applied = False
    if ssvc == "active" and not finding.in_kev:
        base = max(base, ssvc_active_floor) * ssvc_active_mult
        components["ssvc_active_multiplier"] = ssvc_active_mult
        ssvc_tier_applied = True
    elif ssvc == "poc" and not finding.in_kev and not has_evidence:
        base = max(base, ssvc_poc_floor) * ssvc_poc_mult
        components["ssvc_poc_multiplier"] = ssvc_poc_mult
        ssvc_tier_applied = True
    # ``none`` and ``None`` carry no multiplier — neutral.

    # SSVC Automatable=yes bonus. Only fires when an SSVC tier
    # bumped the base above (i.e. the CVE is at least PoC-tier),
    # otherwise an Automatable=yes on a none-tier CVE would
    # silently elevate it past actual exploitation signals.
    # Compounds multiplicatively on top of the tier multiplier
    # — matches the "each independent signal nudges the score
    # upward" composition the rest of the formula uses.
    if (ssvc_tier_applied
            and (finding.ssvc_automatable or "").lower() == "yes"):
        base = base * ssvc_automatable_bonus
        components["ssvc_automatable_multiplier"] = ssvc_automatable_bonus
    else:
        components["ssvc_automatable_multiplier"] = 1.0

    # 3. EPSS: 0..1 probability mapped onto a 0.30..1.00 multiplier.
    epss = finding.epss if finding.epss is not None else epss_missing
    epss_mult = epss_floor + epss_range * epss
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
        reach_mult = 1.0 - reach_max_red * conf_numeric
    elif r.verdict == "not_evaluated":
        reach_mult = reach_not_eval
    else:                                       # imported / likely_called
        reach_mult = 1.0
    base *= reach_mult
    components["reachability_multiplier"] = reach_mult

    # 5. Exposure: call-site density normalised within the project.
    expo = max(0.0, min(1.0, finding.exposure_factor))
    expo_mult = expo_floor + expo_range * expo
    base *= expo_mult
    components["exposure_multiplier"] = expo_mult

    # 6. Direct vs transitive depth decay.
    if dep.direct or finding.transitive_depth <= 0:
        depth_mult = 1.0
    else:
        depth_mult = depth_decay ** finding.transitive_depth
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
    components["calibration_status"] = _calibration_status()

    return final, components


# Names of the multiplier constants the refitter grid-searches over.
# Exported so the refitter doesn't have to introspect the module.
TUNABLE_CONSTANTS = (
    "_KEV_FLOOR",
    "_KEV_MULTIPLIER",
    "_EXPLOIT_EVIDENCE_FLOOR",
    "_EXPLOIT_EVIDENCE_MULTIPLIER",
    # Vulnrichment SSVC tier constants — decoupled from KEV / EE
    # 2026-05-21 so refit can tune them independently. SSVC's
    # coverage shape (broad cross-eco, biased toward PoC over
    # active) means the optimal values may diverge from KEV / EE.
    "_SSVC_ACTIVE_FLOOR",
    "_SSVC_ACTIVE_MULTIPLIER",
    "_SSVC_POC_FLOOR",
    "_SSVC_POC_MULTIPLIER",
    "_SSVC_AUTOMATABLE_BONUS",
    "_EPSS_FLOOR_MULTIPLIER",
    "_EPSS_RANGE_MULTIPLIER",
    "_REACH_NOT_REACHABLE_MAX_REDUCTION",
    "_REACH_NOT_EVALUATED_MULTIPLIER",
    "_EXPO_FLOOR_MULTIPLIER",
    "_EXPO_RANGE_MULTIPLIER",
    "_DEPTH_DECAY_BASE",
)


def current_constants() -> Dict[str, float]:
    """Return the current values of all tunable multiplier
    constants. The refitter compares its proposed values against
    these."""
    # nosemgrep: python.lang.security.dangerous-globals-use.dangerous-globals-use
    # ``name`` iterates ``TUNABLE_CONSTANTS`` (module-level literal
    # tuple, line 245). Not attacker-controlled. The refitter
    # introspects via globals() to avoid hard-coding the list twice.
    return {
        name: globals()[name] for name in TUNABLE_CONSTANTS
    }


# Per-constant absolute bounds. Refit rejects candidates outside
# these — so a wider --max-delta can't propose values that violate
# the design intent of each multiplier. The bounds encode physical
# constraints (positive multipliers, score-range floors) AND
# design intent that's too easy to drift past in a maximise-metric
# search:
#
#   * `_REACH_NOT_EVALUATED_MULTIPLIER` is a "small penalty for
#     unknown reachability"; capped < 1.0 so the search can't turn
#     it into a bonus that rewards lack-of-evidence.
#   * `_REACH_NOT_REACHABLE_MAX_REDUCTION` is the ceiling on how
#     much a confidently-not-reachable verdict can shrink a score;
#     capped 0.0..1.0.
#   * Floors are absolute score offsets (0..100); their multiplier
#     siblings are positive ratios.
#
# Refit's existing per-constant grid search filters candidates
# against these bounds. Cross-constant constraints (e.g.
# EXPLOIT_EVIDENCE_MULTIPLIER must stay < KEV_MULTIPLIER) live in
# `CROSS_CONSTRAINTS` below.
CONSTANT_BOUNDS: Dict[str, Tuple[float, float]] = {
    "_KEV_FLOOR":                          (0.0, 100.0),
    "_KEV_MULTIPLIER":                     (1.0,   3.0),
    "_EXPLOIT_EVIDENCE_FLOOR":             (0.0, 100.0),
    "_EXPLOIT_EVIDENCE_MULTIPLIER":        (1.0,   3.0),
    "_SSVC_ACTIVE_FLOOR":                  (0.0, 100.0),
    "_SSVC_ACTIVE_MULTIPLIER":             (1.0,   3.0),
    "_SSVC_POC_FLOOR":                     (0.0, 100.0),
    "_SSVC_POC_MULTIPLIER":                (1.0,   3.0),
    "_SSVC_AUTOMATABLE_BONUS":             (1.0,   1.5),
    "_EPSS_FLOOR_MULTIPLIER":              (0.0,   1.0),
    "_EPSS_RANGE_MULTIPLIER":              (0.0,   1.0),
    "_REACH_NOT_REACHABLE_MAX_REDUCTION":  (0.0,   1.0),
    "_REACH_NOT_EVALUATED_MULTIPLIER":     (0.0,   1.0),
    "_EXPO_FLOOR_MULTIPLIER":              (0.0,   1.0),
    "_EXPO_RANGE_MULTIPLIER":              (0.0,   1.0),
    "_DEPTH_DECAY_BASE":                   (0.0,   1.0),
}


# Cross-constant constraints. Each entry is a (name, predicate)
# pair where predicate receives the candidate-overrides dict
# (constant-name → value) and returns True iff the candidate is
# admissible. Refit filters proposals that fail any predicate.
#
# Naming convention: predicates are NAMED by the design rule they
# enforce so a refit-report's rejection note is human-readable.
def _ee_strictly_below_kev(values: Dict[str, float]) -> bool:
    """EDB / MSF / PoC are weaker exploit signals than KEV
    (CISA-tracked active exploitation). The multiplier must stay
    strictly below KEV's, and the floor at most equal — otherwise
    a non-KEV PoC could outrank a KEV vuln on tied CVSS, breaking
    the documented precedence in the score function."""
    ee_mult = values.get("_EXPLOIT_EVIDENCE_MULTIPLIER",
                          _EXPLOIT_EVIDENCE_MULTIPLIER)
    kev_mult = values.get("_KEV_MULTIPLIER", _KEV_MULTIPLIER)
    ee_floor = values.get("_EXPLOIT_EVIDENCE_FLOOR",
                           _EXPLOIT_EVIDENCE_FLOOR)
    kev_floor = values.get("_KEV_FLOOR", _KEV_FLOOR)
    return ee_mult < kev_mult and ee_floor <= kev_floor


def _ssvc_poc_strictly_below_active(values: Dict[str, float]) -> bool:
    """SSVC ``poc`` (public exploit code exists) is a weaker
    signal than SSVC ``active`` (exploited in the wild). Same
    relationship KEV / EE carry — the PoC multiplier must stay
    strictly below the active multiplier, and the PoC floor at
    most equal. Otherwise a refit pass that pushes PoC weight
    higher than active would invert the documented precedence:
    a PoC-only finding could outrank a CISA-active one on tied
    CVSS, which contradicts SSVC's own semantic hierarchy."""
    poc_mult = values.get("_SSVC_POC_MULTIPLIER", _SSVC_POC_MULTIPLIER)
    active_mult = values.get(
        "_SSVC_ACTIVE_MULTIPLIER", _SSVC_ACTIVE_MULTIPLIER,
    )
    poc_floor = values.get("_SSVC_POC_FLOOR", _SSVC_POC_FLOOR)
    active_floor = values.get(
        "_SSVC_ACTIVE_FLOOR", _SSVC_ACTIVE_FLOOR,
    )
    return poc_mult < active_mult and poc_floor <= active_floor


CROSS_CONSTRAINTS: List[Tuple[str, Any]] = [
    ("exploit_evidence_strictly_below_kev", _ee_strictly_below_kev),
    ("ssvc_poc_strictly_below_active", _ssvc_poc_strictly_below_active),
]


def is_admissible(values: Dict[str, float]) -> Tuple[bool, Optional[str]]:
    """Check absolute bounds + cross-constraints on a candidate.

    Returns ``(True, None)`` when admissible; ``(False, reason)``
    naming the first failed rule. Refit calls this on every
    candidate variant before evaluating its precision.
    """
    for name, value in values.items():
        bounds = CONSTANT_BOUNDS.get(name)
        if bounds is None:
            continue
        lo, hi = bounds
        if not (lo <= value <= hi):
            return False, f"{name}={value!r} outside bounds [{lo}, {hi}]"
    for rule_name, predicate in CROSS_CONSTRAINTS:
        if not predicate(values):
            return False, f"cross-constraint violated: {rule_name}"
    return True, None




# ---------------------------------------------------------------------------
# Calibration-status read
# ---------------------------------------------------------------------------
#
# The calibration validation harness (run in CI by
# ``refresh-sca-calibration.yml`` and
# ``refresh-sca-project-samples.yml``) writes its verdict to
# ``packages/sca/data/calibration/validation/<date>.json``. Each
# finding's risk score then carries the latest verdict so operators
# reading findings.json can tell whether the score is calibrated
# against ground truth or not.
#
# Verdict values (per :class:`packages.sca.calibration.validate.
# ValidationReport`):
#   * ``"validated_v1"`` — top-20 precision ≥ threshold AND
#     Spearman ρ ≥ threshold over the latest corpus
#   * ``"needs_retune"`` — ran, fell below thresholds; weights need
#     refitting
#   * ``"unverified"`` — ran but insufficient samples, OR no
#     validation report exists yet (cold start)
#
# Cached for the lifetime of the process: the validation file
# doesn't change between findings within a single SCA run.


_CALIBRATION_STATUS_CACHE: Optional[str] = None


def _calibration_status() -> str:
    """Read the latest validation verdict from disk.

    Falls back to ``"unverified"`` when:
      * No validation reports exist (cold start, e.g. tests in a
        fresh checkout)
      * The validation directory or report file is unreadable
      * The latest report's JSON is malformed or missing the
        ``verdict`` field

    Cache is populated once and reused for the rest of the
    process; SCA runs see one consistent verdict.
    """
    global _CALIBRATION_STATUS_CACHE
    if _CALIBRATION_STATUS_CACHE is not None:
        return _CALIBRATION_STATUS_CACHE
    _CALIBRATION_STATUS_CACHE = _load_latest_validation_verdict()
    return _CALIBRATION_STATUS_CACHE


def _load_latest_validation_verdict() -> str:
    """Pick the most-recent ``validation/<date>.json`` and return
    its ``verdict`` field. Defensive against every plausible
    failure — never raises."""
    import json
    from pathlib import Path
    try:
        validation_dir = (
            Path(__file__).resolve().parent
            / "data" / "calibration" / "validation"
        )
        if not validation_dir.is_dir():
            return "unverified"
        # ISO-formatted dates sort lexicographically, so sorting
        # filenames descending picks the most recent. Skip non-
        # JSON files defensively.
        candidates = sorted(
            (p for p in validation_dir.iterdir()
             if p.is_file() and p.suffix == ".json"),
            key=lambda p: p.name, reverse=True,
        )
        for path in candidates:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError, UnicodeDecodeError):
                continue
            if not isinstance(data, dict):
                continue
            verdict = data.get("verdict")
            if isinstance(verdict, str) and verdict:
                return verdict
        # Directory exists but no usable report.
        return "unverified"
    except Exception:                                       # noqa: BLE001
        # Defensive — any unanticipated error falls back to the
        # honest "unverified" rather than crashing the SCA run.
        return "unverified"


def _reset_calibration_cache_for_tests() -> None:
    """Test helper — flush the per-process calibration cache so
    tests can vary the on-disk validation state across runs."""
    global _CALIBRATION_STATUS_CACHE
    _CALIBRATION_STATUS_CACHE = None


__all__ = ["compute_risk_estimate"]
