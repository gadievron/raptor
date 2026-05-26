"""Calibration validation — measure how well
``raptor_risk_estimate`` predicts real-world exploitation against
the ground-truth signals in the corpus.

Two metrics, each with a clear pass/fail threshold:

  1. **Top-N precision.** Of the N highest-scoring findings across
     all project samples, what fraction have ANY exploitation
     signal (KEV / Exploit-DB / Metasploit module)? The score
     SHOULD concentrate true positives at the top — operators
     triaging top-20 should mostly see real, exploited issues.

  2. **Spearman rank correlation.** Across all findings, does the
     rank by ``raptor_risk_estimate`` correlate with rank by
     ground-truth exploitation? Computed with a hand-rolled
     formula (no scipy dependency — keeps SCA's deps minimal).

The validation function never re-tunes weights itself — it emits
a JSON report. Re-tuning is an operator-driven decision based on
the metrics; auto-mutating ``risk.py`` weights from CI would lose
the human review step that the calibration stamp requires.

Output: ``packages/sca/data/calibration/validation/<date>.json``
with the full metrics + per-ecosystem breakdown + corpus
provenance (which snapshot dates of which sources were consulted).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ValidationReport:
    """Validation snapshot. Field types are JSON-serialisable."""

    snapshot_date: str
    findings_total: int
    findings_with_score: int
    findings_with_signal: int
    top_20_precision: float
    top_50_precision: float
    spearman_rho: Optional[float]
    by_ecosystem: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    corpus_provenance: Dict[str, str] = field(default_factory=dict)
    threshold_top_20: float = 0.5     # operator-tunable
    threshold_spearman: float = 0.4   # operator-tunable
    verdict: str = "unverified"       # "validated_v1" | "unverified" | "needs_retune"
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = self.__dict__.copy()
        return d


def validate_corpus(
    corpus_dir: Path,
    *,
    out_path: Optional[Path] = None,
    threshold_top_20: float = 0.5,
    threshold_spearman: float = 0.4,
) -> ValidationReport:
    """Compute metrics + emit a validation report.

    ``corpus_dir`` is the calibration data directory containing
    ``kev_signals.json`` / ``exploitdb_signals.json`` /
    ``metasploit_signals.json`` plus a ``project_samples/`` tree.

    Thresholds: top-20 precision ≥ 0.5 (half of top-20 findings
    have exploit evidence) AND Spearman ρ ≥ 0.4 (moderate positive
    correlation). Below either ⇒ verdict = ``needs_retune``.
    """
    snapshot = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    signals = _load_ground_truth(corpus_dir)
    samples = _load_project_samples(corpus_dir / "project_samples")

    # Flatten all findings into one ranked list, keeping the per-
    # ecosystem breakdown separately.
    all_findings: List[Tuple[str, float, bool]] = []   # (eco, score, exploited)
    by_eco: Dict[str, List[Tuple[float, bool]]] = {}
    for sample in samples:
        for f in sample["findings"]:
            score = f.get("raptor_risk_estimate")
            if score is None or not isinstance(score, (int, float)):
                continue
            eco = f.get("ecosystem") or "?"
            advisory = f.get("advisory") or {}
            cve_ids = _extract_cve_ids(advisory)
            exploited = any(c in signals for c in cve_ids)
            all_findings.append((eco, float(score), exploited))
            by_eco.setdefault(eco, []).append((float(score), exploited))

    # Counts.
    total = sum(len(s["findings"]) for s in samples)
    with_score = len(all_findings)
    with_signal = sum(1 for _, _, ex in all_findings if ex)

    # Top-N precision.
    sorted_by_score = sorted(
        all_findings, key=lambda t: -t[1],
    )
    p20 = _top_n_precision(sorted_by_score, n=20)
    p50 = _top_n_precision(sorted_by_score, n=50)
    rho = _spearman_rho(
        [s for _, s, _ in all_findings],
        [int(ex) for _, _, ex in all_findings],
    )

    # Per-ecosystem.
    eco_breakdown: Dict[str, Dict[str, Any]] = {}
    for eco, rows in by_eco.items():
        sorted_rows = sorted(rows, key=lambda t: -t[0])
        eco_breakdown[eco] = {
            "total": len(rows),
            "with_signal": sum(1 for _, ex in rows if ex),
            "top_20_precision": _top_n_precision_2(sorted_rows, n=20),
            "spearman_rho": _spearman_rho(
                [s for s, _ in rows], [int(ex) for _, ex in rows],
            ),
        }

    # Verdict.
    verdict, notes = _verdict(
        p20=p20, rho=rho, with_score=with_score,
        threshold_top_20=threshold_top_20,
        threshold_spearman=threshold_spearman,
    )

    report = ValidationReport(
        snapshot_date=snapshot,
        findings_total=total,
        findings_with_score=with_score,
        findings_with_signal=with_signal,
        top_20_precision=p20,
        top_50_precision=p50,
        spearman_rho=rho,
        by_ecosystem=eco_breakdown,
        corpus_provenance=_provenance_summary(corpus_dir),
        threshold_top_20=threshold_top_20,
        threshold_spearman=threshold_spearman,
        verdict=verdict,
        notes=notes,
    )

    if out_path is None:
        validation_dir = corpus_dir / "validation"
        validation_dir.mkdir(parents=True, exist_ok=True)
        out_path = validation_dir / f"{snapshot}.json"
    else:
        out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


# ---------------------------------------------------------------------------
# Ground truth + sample loading
# ---------------------------------------------------------------------------


def _load_ground_truth(corpus_dir: Path) -> Set[str]:
    """Union of CVE IDs that have ANY exploitation signal.

    All four sources mirror what ``refit._load_ground_truth`` reads.
    Pre-fix this loader skipped ``github_poc_signals.json`` even
    though the file ships in the corpus and refit consumes it —
    silent drift between validate's exploited-set and refit's would
    have skewed the precision metric vs the metric refit optimises.
    """
    exploited: Set[str] = set()
    for fname in ("kev_signals.json", "exploitdb_signals.json",
                   "metasploit_signals.json", "github_poc_signals.json",
                   "osv_evidence_signals.json",
                   "vulnrichment_signals.json"):
        path = corpus_dir / fname
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(
                "sca.calibration.validate: skip %s (%s)", fname, e,
            )
            continue
        signals = data.get("signals") or {}
        if not isinstance(signals, dict):
            continue
        exploited.update(signals.keys())
    return exploited


def _load_project_samples(samples_dir: Path) -> List[Dict[str, Any]]:
    """Read all project-sample JSONs under
    ``samples_dir/<eco>/<name>.json``."""
    out: List[Dict[str, Any]] = []
    if not samples_dir.is_dir():
        return out
    for path in sorted(samples_dir.rglob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        if "findings" not in data or not isinstance(data["findings"], list):
            continue
        out.append(data)
    return out


def _extract_cve_ids(advisory: Dict[str, Any]) -> List[str]:
    """Pull CVE IDs out of an advisory summary block.

    Returns an empty list for ``informational`` advisories
    (RUSTSEC ``unsound`` / ``unmaintained`` / ``notice`` markers,
    and equivalents on other ecos). Those records aren't security
    vulnerabilities — including their CVE aliases in the
    ground-truth ``signals`` set would mark hundreds of
    non-security findings as ``exploited`` and depress
    Spearman ρ. Validator (and refit) skip them entirely so the
    metric measures actual exploitation signal only."""
    out: List[str] = []
    if not isinstance(advisory, dict):
        return out
    if advisory.get("informational"):
        return out
    aliases = advisory.get("aliases") or []
    if isinstance(aliases, list):
        for a in aliases:
            if isinstance(a, str) and a.startswith("CVE-"):
                out.append(a)
    osv_id = advisory.get("osv_id") or ""
    if isinstance(osv_id, str) and osv_id.startswith("CVE-"):
        out.append(osv_id)
    return out


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def _top_n_precision(
    sorted_findings: List[Tuple[str, float, bool]], n: int,
) -> float:
    if not sorted_findings:
        return 0.0
    top = sorted_findings[:n]
    return sum(1 for _, _, ex in top if ex) / len(top)


def _top_n_precision_2(
    sorted_findings: List[Tuple[float, bool]], n: int,
) -> float:
    if not sorted_findings:
        return 0.0
    top = sorted_findings[:n]
    return sum(1 for _, ex in top if ex) / len(top)


def _spearman_rho(
    x: List[float], y: List[int],
) -> Optional[float]:
    """Spearman rank correlation, hand-rolled (no scipy).

    ρ = 1 - (6 · Σd²) / (n · (n² - 1))

    Where d is the difference between ranks of paired values.
    Tied ranks use the average-rank convention.

    Returns None when there are fewer than 2 paired values (not
    enough to compute a meaningful correlation) or all-x or all-y
    are constant (correlation undefined).
    """
    n = len(x)
    if n != len(y) or n < 2:
        return None
    if len(set(x)) == 1 or len(set(y)) == 1:
        return None
    rx = _ranks(x)
    ry = _ranks(y)
    d2 = sum((rx[i] - ry[i]) ** 2 for i in range(n))
    return 1.0 - (6.0 * d2) / (n * (n * n - 1))


def _ranks(values: List[float]) -> List[float]:
    """Average-rank ranking (handles ties)."""
    indexed = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(indexed):
        j = i
        while (j + 1 < len(indexed)
               and values[indexed[j + 1]] == values[indexed[i]]):
            j += 1
        avg = (i + j) / 2 + 1   # 1-based rank, averaged over the tie
        for k in range(i, j + 1):
            ranks[indexed[k]] = avg
        i = j + 1
    return ranks


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------


def _verdict(
    *,
    p20: float, rho: Optional[float], with_score: int,
    threshold_top_20: float, threshold_spearman: float,
) -> Tuple[str, List[str]]:
    notes: List[str] = []
    if with_score < 50:
        notes.append(
            f"only {with_score} scored findings — corpus needs more "
            f"project samples before validation is meaningful "
            f"(target: ≥ 50)"
        )
        return "unverified", notes
    pass_p20 = p20 >= threshold_top_20
    pass_rho = rho is not None and rho >= threshold_spearman
    if not pass_p20:
        notes.append(
            f"top-20 precision {p20:.2f} below threshold "
            f"{threshold_top_20:.2f}"
        )
    if not pass_rho:
        rho_str = f"{rho:.2f}" if rho is not None else "undefined"
        notes.append(
            f"Spearman ρ {rho_str} below threshold "
            f"{threshold_spearman:.2f}"
        )
    if pass_p20 and pass_rho:
        return "validated_v1", notes
    return "needs_retune", notes


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


def _provenance_summary(corpus_dir: Path) -> Dict[str, str]:
    """Capture which snapshot date each ground-truth source had
    when validation ran. Lets reviewers reproduce metrics
    against the same corpus state."""
    out: Dict[str, str] = {}
    for fname in ("kev_signals.json", "epss_signals.json",
                   "exploitdb_signals.json", "metasploit_signals.json"):
        path = corpus_dir / fname
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        src = data.get("_source") or {}
        out[fname] = src.get("fetched_at", "unknown")
    return out


__all__ = [
    "ValidationReport",
    "validate_corpus",
]
