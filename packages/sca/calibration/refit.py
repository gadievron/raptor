"""Calibration refitter — grid search over multiplier constants.

When the validator's verdict is ``needs_retune``, this module
grid-searches each tunable multiplier in :mod:`packages.sca.risk`
for a value that improves top-20 precision against the calibration
corpus, subject to a max-delta cap and an improvement gate.

## Why grid search rather than logistic regression?

The risk formula in ``risk.py`` is multiplicative:

    score = (cvss/10)*100 × kev_mult × epss_mult × reach_mult × ...

Logistic regression would assume additive log-odds; mapping the
fitted coefficients back to specific named constants is fuzzy
(each constant flows through different parts of the formula).
Grid search, by contrast:

  * Directly evaluates each constant in terms of the metric we
    care about (top-20 precision).
  * Each step is interpretable: "we tried K=1.20, K=1.08, K=1.32;
    K=1.08 had best precision."
  * Pure-Python — no numpy / sklearn dependency. Refit is a
    monthly CI job; install cost matters.
  * Captures interactions implicitly: each per-constant search
    runs against the SAME live formula (with all other constants
    at current values), so the chosen value is best given the
    rest of the formula as-is.

## Algorithm

For each tunable constant C in ``risk.TUNABLE_CONSTANTS``:

    1. Compute top-20 precision with all current constants.
       Call this ``baseline``.
    2. Compute precision with C overridden at C × 0.9, C × 1.1.
       Call these ``low``, ``high``.
    3. Pick the variant with highest precision. Apply the
       max-delta cap (already enforced by the ±10% bracket).
    4. If the chosen variant ties baseline, leave C unchanged.

## Improvement gate

After per-constant search, run validation with all proposed
overrides applied AT ONCE. If overall top-20 precision improvement
is < ``improvement_threshold`` (default 5%), reject the refit —
return a report flagging it but not proposing changes.

## Sample-count floor

The refitter refuses to run with fewer than ``MIN_SAMPLES_FOR_REFIT``
labelled findings. Below that, return verdict=``insufficient_samples``;
the corpus needs to grow before a refit is meaningful.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# Below this many labelled findings, refit refuses to run.
# Logistic-regression-style fits need more, but grid search on
# top-20 precision can be informative at lower N. 100 is a
# pragmatic floor — fewer than that and the precision metric
# itself is noisy.
MIN_SAMPLES_FOR_REFIT = 100

# Per-constant max-delta. Each refit moves a constant at most
# ±10% from its current value. Capped to prevent a noisy corpus
# from swinging the formula wildly.
DEFAULT_MAX_DELTA = 0.10

# Minimum top-20 precision improvement (absolute, not relative)
# required for the refit to ship. 0.05 = "5 more percentage
# points of precision". Below that, the refit is rejected
# regardless of per-constant gains, on the grounds that small
# gains can be noise from the corpus's idiosyncrasies.
DEFAULT_IMPROVEMENT_THRESHOLD = 0.05


@dataclass
class ConstantRefit:
    """Per-constant search result."""

    name: str
    current: float
    proposed: float
    baseline_precision: float
    proposed_precision: float

    @property
    def changed(self) -> bool:
        return self.proposed != self.current

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "current": self.current,
            "proposed": self.proposed,
            "baseline_precision": self.baseline_precision,
            "proposed_precision": self.proposed_precision,
            "changed": self.changed,
        }


@dataclass
class RefitReport:
    """Top-level refit result.

    Status values:
      * ``"proposed"`` — refit ran, improvement gate passed,
        proposed values should be applied.
      * ``"rejected"`` — refit ran, improvement below threshold;
        proposed values shipped for inspection but should NOT be
        applied.
      * ``"insufficient_samples"`` — corpus too small;
        nothing proposed.
      * ``"error"`` — refit couldn't run (corpus missing,
        unreadable, etc.).
    """

    snapshot_date: str
    status: str
    sample_count: int
    overall_baseline_precision: float
    overall_proposed_precision: float
    improvement: float
    improvement_threshold: float
    max_delta: float
    per_constant: List[ConstantRefit] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def proposed_values(self) -> Dict[str, float]:
        """Return the proposed override dict — what to feed to
        ``compute_risk_estimate(overrides=...)`` to apply this
        refit. Only constants that genuinely changed appear."""
        return {
            c.name: c.proposed for c in self.per_constant
            if c.changed
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "snapshot_date": self.snapshot_date,
            "status": self.status,
            "sample_count": self.sample_count,
            "overall_baseline_precision": self.overall_baseline_precision,
            "overall_proposed_precision": self.overall_proposed_precision,
            "improvement": self.improvement,
            "improvement_threshold": self.improvement_threshold,
            "max_delta": self.max_delta,
            "per_constant": [c.to_dict() for c in self.per_constant],
            "notes": list(self.notes),
            "proposed_values": self.proposed_values,
        }


def grid_search_refit(
    corpus_dir: Path,
    *,
    max_delta: float = DEFAULT_MAX_DELTA,
    improvement_threshold: float = DEFAULT_IMPROVEMENT_THRESHOLD,
    min_samples: int = MIN_SAMPLES_FOR_REFIT,
    out_path: Optional[Path] = None,
    ecosystem_filter: Optional[str] = None,
) -> RefitReport:
    """Run the per-constant grid search and emit a refit report.

    ``corpus_dir`` is the calibration data root containing
    ``kev_signals.json`` etc. + ``project_samples/<eco>/<name>.json``.

    Writes the report to ``corpus_dir/refit/<date>.json`` (or
    ``out_path`` when explicitly supplied).

    ``ecosystem_filter``: when set, drops findings outside the
    named ecosystem before fitting. Useful for "what would
    Maven-only optimal constants look like" investigations
    without changing the cross-ecosystem code path. The same
    ``min_samples`` cold-start gate applies to the filtered
    set — ecosystems with too few findings get rejected.
    """
    snapshot = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    notes: List[str] = []

    samples = _load_findings_with_labels(corpus_dir)
    if ecosystem_filter is not None:
        before = len(samples)
        samples = [
            (f, l) for f, l in samples
            if (f.get("ecosystem") or "?") == ecosystem_filter
        ]
        notes.append(
            f"ecosystem_filter={ecosystem_filter!r}: "
            f"{before} → {len(samples)} samples"
        )
    if not samples:
        return _emit_report(
            RefitReport(
                snapshot_date=snapshot, status="error",
                sample_count=0,
                overall_baseline_precision=0.0,
                overall_proposed_precision=0.0,
                improvement=0.0,
                improvement_threshold=improvement_threshold,
                max_delta=max_delta,
                notes=[
                    "no project samples found under "
                    f"{corpus_dir}/project_samples/",
                ],
            ),
            corpus_dir, out_path,
        )

    if len(samples) < min_samples:
        return _emit_report(
            RefitReport(
                snapshot_date=snapshot,
                status="insufficient_samples",
                sample_count=len(samples),
                overall_baseline_precision=0.0,
                overall_proposed_precision=0.0,
                improvement=0.0,
                improvement_threshold=improvement_threshold,
                max_delta=max_delta,
                notes=[
                    f"only {len(samples)} labelled findings in corpus; "
                    f"need ≥ {min_samples} for refit",
                ],
            ),
            corpus_dir, out_path,
        )

    from packages.sca.risk import (
        TUNABLE_CONSTANTS, current_constants, is_admissible,
    )
    current = current_constants()

    # Baseline precision — score every sample with current constants.
    baseline = _top_20_precision(samples, overrides=None)
    notes.append(
        f"baseline top-20 precision = {baseline:.3f} on "
        f"{len(samples)} samples"
    )

    # Per-constant search. Each candidate runs in isolation against
    # the live formula (all other constants at their current values).
    # Admissibility check filters candidates that violate the bounds
    # or cross-constraints declared in risk.py — without it, a
    # wider --max-delta would happily propose values that maximise
    # top-20 on this corpus by violating design intent (e.g. EE_MULT
    # crossing KEV_MULT, NOT_EVALUATED becoming a bonus instead of
    # penalty). Inadmissible candidates produce a precision of -inf
    # so they're never picked even when they'd numerically maximise.
    # `_search_metric` returns (top_20, top_50). max() over tuples
    # compares lexicographically — top-20 dominates, top-50 breaks
    # ties. The legacy scalar `_top_20_precision` is preserved for
    # the verdict + report fields; the search itself runs on the
    # tuple so once the corpus saturates top-20 at 1.000 the search
    # keeps moving on top-50 instead of silently sticking to the
    # first-seen candidate.
    SENTINEL_INADMISSIBLE = (float("-inf"), float("-inf"))

    per_constant: List[ConstantRefit] = []
    for name in TUNABLE_CONSTANTS:
        cur = current[name]
        candidates = [
            cur,                  # no change — always admissible
            cur * (1.0 - max_delta),
            cur * (1.0 + max_delta),
        ]
        metrics: List[Tuple[float, float]] = []
        for c in candidates:
            full_values = {**current, name: c}
            ok, _reason = is_admissible(full_values)
            if not ok:
                metrics.append(SENTINEL_INADMISSIBLE)
            else:
                metrics.append(
                    _search_metric(samples, overrides={name: c})
                )
        # Pick the highest metric tuple; tie → keep current (index 0).
        best_idx = max(range(3), key=lambda i: metrics[i])
        if metrics[best_idx] <= metrics[0]:
            best_idx = 0
        # Note inadmissible rejections so the report is honest about
        # which candidate was filtered (and why), rather than silently
        # picking the second-best.
        for idx, c in enumerate(candidates):
            if idx == 0:
                continue
            if metrics[idx] == SENTINEL_INADMISSIBLE:
                _ok, reason = is_admissible({**current, name: c})
                notes.append(
                    f"{name}={c:.4g} rejected: {reason}"
                )
        # Report fields keep the scalar top-20 precision (back-
        # compat with operator dashboards / the auto-PR diff).
        baseline_p20 = (metrics[0][0]
                        if metrics[0] != SENTINEL_INADMISSIBLE else 0.0)
        proposed_p20 = (metrics[best_idx][0]
                        if metrics[best_idx] != SENTINEL_INADMISSIBLE
                        else 0.0)
        per_constant.append(ConstantRefit(
            name=name,
            current=cur,
            proposed=candidates[best_idx],
            baseline_precision=baseline_p20,
            proposed_precision=proposed_p20,
        ))

    # Compose all proposed overrides and re-score. Per-constant
    # improvements may not stack additively; this is the joint
    # effect. The composed candidate must ALSO pass admissibility
    # — a per-constant search picks each constant in isolation, so
    # a cross-constraint that's only violated when TWO constants
    # both move in the same direction would slip past the per-
    # constant gate. Joint admissibility check catches that.
    joint_overrides = {
        c.name: c.proposed for c in per_constant if c.changed
    }
    if joint_overrides:
        joint_full = {**current, **joint_overrides}
        ok_joint, joint_reason = is_admissible(joint_full)
        if not ok_joint:
            notes.append(
                f"joint composition rejected: {joint_reason}; "
                f"falling back to baseline"
            )
            joint_overrides = {}
    joint_precision = (
        _top_20_precision(samples, overrides=joint_overrides)
        if joint_overrides else baseline
    )
    improvement = joint_precision - baseline

    if not joint_overrides:
        status = "rejected"
        notes.append("no per-constant variant beat the baseline")
    elif improvement < improvement_threshold:
        status = "rejected"
        notes.append(
            f"joint improvement {improvement:.3f} below threshold "
            f"{improvement_threshold:.3f}; refit not shipped"
        )
    else:
        status = "proposed"
        notes.append(
            f"joint improvement {improvement:.3f} ≥ threshold "
            f"{improvement_threshold:.3f}; refit ready to apply"
        )

    return _emit_report(
        RefitReport(
            snapshot_date=snapshot, status=status,
            sample_count=len(samples),
            overall_baseline_precision=baseline,
            overall_proposed_precision=joint_precision,
            improvement=improvement,
            improvement_threshold=improvement_threshold,
            max_delta=max_delta,
            per_constant=per_constant,
            notes=notes,
        ),
        corpus_dir, out_path,
    )


def _emit_report(
    report: RefitReport, corpus_dir: Path, out_path: Optional[Path],
) -> RefitReport:
    """Write the report to disk + return it. The CLI gates on
    return-value status; tests bypass the write by stubbing
    out_path to a tmp file."""
    if out_path is None:
        refit_dir = corpus_dir / "refit"
        refit_dir.mkdir(parents=True, exist_ok=True)
        out_path = refit_dir / f"{report.snapshot_date}.json"
    else:
        out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


# ---------------------------------------------------------------------------
# Sample → labelled-finding extraction
# ---------------------------------------------------------------------------


def _load_findings_with_labels(
    corpus_dir: Path,
) -> List[Tuple[Dict[str, Any], int]]:
    """Walk project samples; pair each finding with its exploited
    label (1 if any of the finding's CVE aliases appears in the
    KEV / EDB / MSF / GitHub-PoC ground-truth signals).

    Returns a list of ``(finding_dict, label)`` pairs. Findings
    without a usable score (no risk_components or non-float
    final) are dropped — the precision metric needs a numeric
    score.
    """
    signals = _load_ground_truth(corpus_dir)
    samples_dir = corpus_dir / "project_samples"
    if not samples_dir.is_dir():
        return []

    out: List[Tuple[Dict[str, Any], int]] = []
    for sample_path in sorted(samples_dir.rglob("*.json")):
        try:
            data = json.loads(sample_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
        findings = data.get("findings") if isinstance(data, dict) else None
        if not isinstance(findings, list):
            continue
        for f in findings:
            if not isinstance(f, dict):
                continue
            cve_ids = _extract_cve_ids(f.get("advisory") or {})
            label = 1 if any(c in signals for c in cve_ids) else 0
            out.append((f, label))
    return out


def _load_ground_truth(corpus_dir: Path) -> set:
    """Union of CVE IDs marked as exploited across all ground-truth
    signal files. Mirrors ``validate.py::_load_ground_truth``.

    Signal files (built by ``calibration/build.py``) carry a top-
    level ``signals`` dict mapping CVE-id → metadata. The dict's
    keys ARE the CVE IDs we want. Earlier this function looked for
    a top-level ``items`` list shape that no signal file actually
    has — refit silently saw zero exploited CVEs and rejected every
    proposed weight as "no improvement vs baseline 0.000". Test
    fixtures were written to that wrong shape too, so the unit
    tests passed against a format the production builder never
    emitted. Fixed by matching the real format.
    """
    signals: set = set()
    for fname in (
        "kev_signals.json", "exploitdb_signals.json",
        "metasploit_signals.json", "github_poc_signals.json",
        "osv_evidence_signals.json",
    ):
        path = corpus_dir / fname
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        sig_dict = data.get("signals")
        if isinstance(sig_dict, dict):
            for cve in sig_dict:
                if isinstance(cve, str) and cve:
                    signals.add(cve)
    return signals


def _extract_cve_ids(advisory: Dict[str, Any]) -> List[str]:
    """Pull CVE IDs from an advisory record. Mirrors
    ``validate.py::_extract_cve_ids``."""
    out: List[str] = []
    osv_id = advisory.get("osv_id")
    if isinstance(osv_id, str) and osv_id.startswith("CVE-"):
        out.append(osv_id)
    for alias in advisory.get("aliases", []) or []:
        if isinstance(alias, str) and alias.startswith("CVE-"):
            out.append(alias)
    return out


# ---------------------------------------------------------------------------
# Top-20 precision under override
# ---------------------------------------------------------------------------


def _top_20_precision(
    samples: List[Tuple[Dict[str, Any], int]],
    *,
    overrides: Optional[Dict[str, float]] = None,
) -> float:
    """Re-score every finding under the given overrides and
    measure the fraction of the top 20 by score that have label=1.

    Backwards-compatible scalar metric — kept for the existing
    refit verdict + report fields. The grid search itself uses
    `_search_metric` (a tuple of (top_20, top_50) precisions) so
    when top-20 saturates at 1.0 across multiple candidates,
    top-50 is the tiebreaker — without this, the search picks
    the first-seen candidate even when a strictly-better-packed
    top-50 exists.
    """
    return _search_metric(samples, overrides=overrides)[0]


def _search_metric(
    samples: List[Tuple[Dict[str, Any], int]],
    *,
    overrides: Optional[Dict[str, float]] = None,
) -> Tuple[float, float]:
    """Composite (top-20 precision, NDCG@20) used by the grid
    search's argmax.

    Tuple semantics: max() over Python tuples compares
    lexicographically — top-20 precision dominates (it's the
    operator-facing verdict metric), NDCG@20 acts only when
    precision is tied. NDCG@20 is the standard ranking-quality
    metric for top-k (Normalised Discounted Cumulative Gain): it
    rewards exploited findings appearing at LOW ranks within the
    top-k more than at high ranks.

    Why NDCG over the previous top-50 tiebreaker:

      * top-20 precision saturates at 1.0 when all 20 of top-20
        are exploited, regardless of WHICH 20. With 61 exploited
        findings in the round-3 corpus, multiple weight settings
        all hit precision=1.0 — the search couldn't distinguish.
      * top-50 was a coarser-grained tiebreaker that ALSO
        saturates once 50 of the corpus's 61 are in top-50.
      * NDCG@20 is continuous on [0, 1] and stays sensitive to
        the WITHIN-top-20 ordering: a candidate that puts the
        most-confidently-exploited finding at rank 1 vs rank 18
        scores higher even when both candidates have precision=1.0.

    Returns ``(top_20_precision, ndcg_20)``. Both fall back to
    0.0 when no findings have a usable score.
    """
    if not samples:
        return (0.0, 0.0)
    rescored: List[Tuple[float, int]] = []
    for finding_dict, label in samples:
        score = _rescore_finding(finding_dict, overrides)
        if score is None:
            continue
        rescored.append((score, label))
    if not rescored:
        return (0.0, 0.0)
    rescored.sort(key=lambda t: -t[0])
    top20 = rescored[:20]
    p20 = (sum(l for _, l in top20) / len(top20)) if top20 else 0.0
    ndcg20 = _ndcg_at_n(rescored, n=20)
    return (p20, ndcg20)


def _ndcg_at_n(
    rescored: List[Tuple[float, int]], n: int = 20,
) -> float:
    """Normalised Discounted Cumulative Gain at rank N.

    ``rescored`` MUST be sorted by score descending (the caller
    in ``_search_metric`` does this). Binary relevance: each
    finding has label 0 (not exploited) or 1 (exploited).

    Formula (binary relevance, 0-indexed positions):
       DCG@n  = sum_{i=0..n-1}  label_i / log2(i + 2)
       IDCG@n = sum_{i=0..min(n, n_exploited)-1}  1 / log2(i + 2)
       NDCG@n = DCG@n / IDCG@n

    Returns ``0.0`` when no exploited findings exist (IDCG=0).
    Returns ``1.0`` when the top n positions are all exploited
    AND there are at most n exploited findings overall — a
    "perfect" ranking. When n_exploited > n, the cap is at
    DCG of the perfect-top-n which still equals IDCG@n, so
    NDCG remains 1.0 for any candidate whose top-n is fully
    exploited.
    """
    import math
    if not rescored:
        return 0.0
    n_exploited = sum(1 for _, label in rescored if label == 1)
    if n_exploited == 0:
        return 0.0
    dcg = sum(
        label / math.log2(i + 2)
        for i, (_, label) in enumerate(rescored[:n])
    )
    idcg = sum(
        1.0 / math.log2(i + 2)
        for i in range(min(n, n_exploited))
    )
    return dcg / idcg if idcg > 0 else 0.0


def _rescore_finding(
    finding: Dict[str, Any],
    overrides: Optional[Dict[str, float]],
) -> Optional[float]:
    """Recompute the risk score for a finding dict using the
    multiplier overrides.

    ``finding`` is the dict shape ``project_samples`` archives
    (the JSON shape of :class:`packages.sca.models.VulnFinding`
    plus a ``risk_components`` block). The archived
    ``raptor_risk_estimate`` reflects whatever constants were
    active when ``collect-samples`` ran — which drifts from the
    current ``risk.py`` constants every time refit-apply edits
    them. Reading the archive directly for the baseline (pre-fix)
    let drift accumulate: refit's baseline measured against stale
    scores, the joint-improvement gate fired against an obsolete
    metric, and a freshly-applied refit looked already-applied
    on the next refit run.

    Always re-score from the underlying inputs — using the current
    module constants when ``overrides`` is None, the proposed
    set otherwise. Both paths produce a metric coherent with the
    constants in code RIGHT NOW. Falls back to the archived
    score only when the rebuild is impossible (test fixtures
    that don't carry the full inputs).

    Returns the recomputed score, or ``None`` when the finding
    has no usable score at all.
    """
    try:
        score, _components = _compute_with_overrides(
            finding, overrides or {},
        )
        return score
    except Exception:                                   # noqa: BLE001
        # Fallback for archives missing reconstruction inputs
        # (older fixtures, tests that skip the full block).
        raw = finding.get("raptor_risk_estimate")
        if isinstance(raw, (int, float)):
            return float(raw)
        return None


def _compute_with_overrides(
    finding: Dict[str, Any], overrides: Dict[str, float],
) -> Tuple[float, Dict[str, Any]]:
    """Rebuild a :class:`VulnFinding` from the archived dict and
    call ``compute_risk_estimate(overrides=...)``."""
    from packages.sca.models import (
        Dependency, PinStyle, Reachability, VulnFinding,
    )
    from packages.sca.risk import compute_risk_estimate

    # Dependency reconstruction — the project-sample archive
    # writes a ``dependency`` sub-dict mirroring the dataclass
    # fields. Use frugal defaults for any field the archive
    # omitted (Path / Confidence are required positional args).
    dep_dict = finding.get("dependency") or {}
    pc_raw = dep_dict.get("parser_confidence") or {"level": "high",
                                                     "reason": ""}
    parser_conf = _confidence_from_dict(pc_raw)
    pin_raw = dep_dict.get("pin_style", "exact")
    try:
        pin_style = PinStyle(pin_raw)
    except ValueError:
        pin_style = PinStyle.EXACT
    dep = Dependency(
        ecosystem=dep_dict.get("ecosystem", "PyPI"),
        name=dep_dict.get("name", "unknown"),
        version=dep_dict.get("version"),
        declared_in=Path(dep_dict.get("declared_in", "/unknown")),
        scope=dep_dict.get("scope", "main"),
        is_lockfile=bool(dep_dict.get("is_lockfile", False)),
        pin_style=pin_style,
        direct=bool(dep_dict.get("direct", True)),
        purl=dep_dict.get("purl", ""),
        parser_confidence=parser_conf,
    )

    reach_dict = finding.get("reachability") or {}
    reach = Reachability(
        verdict=reach_dict.get("verdict", "imported"),
        confidence=_confidence_from_dict(
            reach_dict.get("confidence")
            or {"level": "high", "reason": ""},
        ),
        evidence=list(reach_dict.get("evidence") or []),
    )

    vmc = _confidence_from_dict(
        finding.get("version_match_confidence")
        or {"level": "high", "reason": ""},
    )

    # ExploitEvidence reconstruction. Without this, refit can't
    # exercise the EDB / MSF / GitHub-PoC weight branch — every
    # archived finding would re-score as ``has_evidence=False`` and
    # the new ``_EXPLOIT_EVIDENCE_*`` constants would have no effect
    # on the grid search. The archive carries the rendered shape
    # ({"kev_listed": .., "edb_ids": [...], ...}); we accept None
    # (older archives written before the field was preserved) as
    # an empty-evidence shim.
    from packages.sca.models import ExploitEvidence
    ee_raw = finding.get("exploit_evidence") or {}
    if isinstance(ee_raw, dict):
        ee = ExploitEvidence(
            kev_listed=bool(ee_raw.get("kev_listed", False)),
            edb_ids=list(ee_raw.get("edb_ids") or []),
            msf_modules=list(ee_raw.get("msf_modules") or []),
            github_poc_urls=list(ee_raw.get("github_poc_urls") or []),
        )
    else:
        ee = None

    vf = VulnFinding(
        finding_id=finding.get("finding_id", "?"),
        dependency=dep,
        advisories=[],          # not needed for risk computation
        in_kev=bool(finding.get("in_kev", False)),
        epss=finding.get("epss"),
        fixed_version=finding.get("fixed_version"),
        reachability=reach,
        version_match_confidence=vmc,
        cvss_score=finding.get("cvss_score"),
        cvss_vector=finding.get("cvss_vector"),
        severity=finding.get("severity", "low"),
        exposure_factor=float(finding.get("exposure_factor", 0.0)),
        transitive_depth=int(finding.get("transitive_depth", 0)),
        exploit_evidence=ee,
    )
    return compute_risk_estimate(vf, dep, overrides=overrides)


def _confidence_from_dict(raw: Dict[str, Any]) -> "Any":
    """Build a Confidence from a dict, defensive against shape
    drift."""
    from packages.sca.models import Confidence
    level = raw.get("level", "high")
    if level not in ("low", "medium", "high"):
        level = "high"
    reason = raw.get("reason") or ""
    numeric = raw.get("numeric")
    if isinstance(numeric, (int, float)):
        return Confidence(level=level, reason=reason, numeric=float(numeric))
    return Confidence(level=level, reason=reason)


__all__ = [
    "ConstantRefit",
    "DEFAULT_IMPROVEMENT_THRESHOLD",
    "DEFAULT_MAX_DELTA",
    "MIN_SAMPLES_FOR_REFIT",
    "RefitReport",
    "grid_search_refit",
]
