"""Deepen-aware pre-spend cost forecasting for /audit runs.

Estimates the LLM spend of an audit BEFORE the review loop commits,
from the gap queue the run will actually work ($0 — checklist census
plus journal priors, no LLM calls). Mirrors the openant forecast
contract (``packages/openant/forecast.py``): a ``--forecast`` mode
that prints the band and exits with zero LLM spend, an informational
line at run start, and a forecast-vs-actual calibration record at run
completion so the coefficients can be re-fitted from real data.

The forecast is a BAND, never a point, and its dominant width driver
is the DEEPEN machinery: a first-pass ``suspicious`` verdict spawns
follow-up work (inline refinement rounds, the post-loop deepen pass,
iterative caller re-review — booked as the ``refinement`` and
``re_review`` ledger phases), so total spend rides the queue's
suspicious density, which is only predictable from priors. A
suspicious-dense residual can cost several times its first-pass
economics; pricing first-pass reviews alone is the failure mode this
module exists to close.

Model shape (three phases, each with low/central/high):

* **review** — first-pass reviews: per-item affine in capped SLOC
  (the same size signal the LPT scheduler's duration hints use),
  times ``--review-passes``. Narrow band.
* **deepen** — ``re_review`` + ``refinement`` volume: proportional to
  the predicted SUSPICIOUS MASS = queue_n x predicted suspicious
  density + seeded re-review mass (prior suspicious/finding rows not
  already in the queue). Calls-per-suspicious varies most between
  runs — the widest band contributor.
* **support** — everything else the ledger books (triage, study,
  IRIS, checker synthesis, glances, summaries): a stable fraction of
  the review+deepen subtotal.

SEEDED CALIBRATION (revisitable): the coefficients below were fitted
from the cost-breakdown.json and review journals of two completed
real-world audit runs on one PHP web-application corpus — one cold
full audit and one delta pass over a suspicious-dense residual. They
are seeded, not proven: every completed run appends a
forecast-calibration entry (predicted band vs actual, per phase) to
``forecast-calibration.jsonl`` precisely so these numbers can be
re-fitted from accumulated real data. Informational only: nothing
here gates or caps a run (``--max-cost`` is the enforcement surface).
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

ESTIMATOR_VERSION = "audit-seeded-v1"

FORECAST_FILENAME = "forecast.json"
CALIBRATION_FILENAME = "forecast-calibration.jsonl"

# --- first-pass review: per-call USD ~ affine in capped SLOC ---
# Level anchored to the calibration runs' review-phase ledgers; slope
# from a per-entry cost-vs-SLOC regression over their journals (the
# fit saturates around the cap — context slices stop growing with
# function size well before the largest functions).
REVIEW_BASE_USD = 0.113
REVIEW_USD_PER_SLOC = 0.00314
REVIEW_SLOC_CAP = 200
REVIEW_BAND = (0.8, 1.25)

# --- deepen (re_review + refinement ledger phases) ---
# Volume: calls per predicted-suspicious function. The two calibration
# runs measured materially different depths (the band endpoints bound
# both with margin) — this is the widest band contributor by design.
DEEPEN_CALLS_PER_SUSPICIOUS = 3.1
DEEPEN_CALLS_BAND = (2.2, 4.4)
# Per-call level was near-identical across both calibration runs, so
# it carries no band of its own.
DEEPEN_USD_PER_CALL = 0.39

# --- predicted suspicious density ---
# Cold default from the calibration corpus' cold-run first-pass rate;
# single-corpus provenance, hence the wide absolute band. Priors
# narrow it to a multiplicative band around the journal-derived rate.
COLD_SUSPICIOUS_DENSITY = 0.35
COLD_DENSITY_BAND = (0.15, 0.55)
PRIOR_DENSITY_BAND_FACTOR = (0.7, 1.3)

# --- support phases (triage/study/iris/checkers/glances/summaries) ---
SUPPORT_FRAC = 0.08
SUPPORT_BAND = (0.04, 0.14)

# Verdicts that count as "suspicious mass" for deepen purposes: these
# are the statuses the deepen machinery actually follows up on.
_SUSPICIOUS_VERDICTS = frozenset({"suspicious", "finding"})

_MAX_CALIBRATION_BYTES = 4 * 1024 * 1024


def gap_slocs(gaps: list[dict[str, Any]] | None) -> list[int]:
    """Per-item SLOC census from a gap queue (``compute_gaps`` output
    or a persisted ``gaps.json`` item list).

    Malformed/hostile shapes degrade to size 0 for that item rather
    than crashing — gap records derive from an untrusted repo.
    """
    sizes: list[int] = []
    if not isinstance(gaps, list):
        return sizes
    for gap in gaps:
        if not isinstance(gap, dict):
            continue
        sloc = gap.get("sloc")
        if not isinstance(sloc, int) or sloc <= 0:
            ls, le = gap.get("line_start"), gap.get("line_end")
            if (isinstance(ls, int) and isinstance(le, int)
                    and 0 < ls <= le):
                sloc = le - ls + 1
            else:
                sloc = 0
        sizes.append(max(0, sloc))
    return sizes


def _gap_key(gap: dict[str, Any]) -> tuple[str, str] | None:
    file, name = gap.get("file"), gap.get("name")
    if isinstance(file, str) and isinstance(name, str) and file and name:
        return (file, name)
    return None


def prior_verdicts_from_index(project_dir: Path) -> dict[tuple[str, str], str]:
    """Latest verdict per ``(file, function)`` from the project-level
    review-journal index. Empty dict when no index exists."""
    try:
        from core.coverage.journal import load_index
        return {
            (e.file, e.function): e.verdict
            for e in load_index(Path(project_dir)).values()
            if e.file and e.function and e.verdict
        }
    except Exception:  # noqa: BLE001 — priors are best-effort
        logger.warning("forecast: journal-index priors unreadable",
                       exc_info=True)
        return {}


def prior_verdicts_from_run_dirs(
    run_dirs: list[Path],
) -> dict[tuple[str, str], str]:
    """Latest verdict per ``(file, function)`` from prior run dirs'
    ``review-journal.jsonl`` (the ``--prior-journal`` shape)."""
    result: dict[tuple[str, str], str] = {}
    ts_seen: dict[tuple[str, str], str] = {}
    for run_dir in run_dirs:
        try:
            from core.coverage.journal import load_entries
            entries = load_entries(Path(run_dir))
        except Exception:  # noqa: BLE001 — priors are best-effort
            logger.warning("forecast: prior journal unreadable: %s",
                           run_dir, exc_info=True)
            continue
        for e in entries:
            if not (e.file and e.function and e.verdict):
                continue
            key = (e.file, e.function)
            if key not in ts_seen or e.ts > ts_seen[key]:
                ts_seen[key] = e.ts
                result[key] = e.verdict
    return result


def filter_priors_to_checklist(
    prior_verdicts: dict[tuple[str, str], str] | None,
    checklist: dict[str, Any] | None,
) -> dict[tuple[str, str], str]:
    """Restrict a project-wide priors mapping to THIS run's
    ``(file, function)`` universe (the checklist).

    The journal index is project-level: on a multi-binary project it
    carries every other binary's rows, and feeding those into the
    density and seed-mass terms priced thousands of cross-target
    suspicious rows into a run whose deepen phase only ever re-reviews
    its own outcomes — inflating the band without any corresponding
    spend. Exact-key filtering keeps precisely the rows that can
    re-enter this run's deepen machinery.

    An empty/foreign checklist shape yields an empty mapping (cold
    density), the safe direction for a $0 informational forecast.
    """
    if not prior_verdicts:
        return {}
    run_keys: set[tuple[str, str]] = set()
    if isinstance(checklist, dict):
        for file_entry in checklist.get("files") or []:
            if not isinstance(file_entry, dict):
                continue
            path = file_entry.get("path")
            if not isinstance(path, str) or not path:
                continue
            items = file_entry.get("items",
                                   file_entry.get("functions", []))
            for item in items or []:
                if not isinstance(item, dict):
                    continue
                name = item.get("name")
                if isinstance(name, str) and name:
                    run_keys.add((path, name))
    return {k: v for k, v in prior_verdicts.items() if k in run_keys}


def predicted_suspicious_density(
    gaps: list[dict[str, Any]],
    prior_verdicts: dict[tuple[str, str], str] | None,
) -> dict[str, Any]:
    """Predict the queue's suspicious density from journal priors.

    Per item: an exact prior verdict for the same function wins
    (1.0 for suspicious/finding, 0.0 otherwise); else the prior
    suspicious RATE of the item's file; else the cold default. With
    no priors at all the cold default and its absolute band apply.

    Returns ``{central, low, high, source, prior_coverage}`` where
    ``source`` is ``"priors"`` or ``"cold"`` and ``prior_coverage`` is
    the fraction of queue items that had any prior signal.
    """
    items = [g for g in (gaps or []) if isinstance(g, dict)]
    priors = prior_verdicts or {}
    if not items or not priors:
        low, high = COLD_DENSITY_BAND
        return {
            "central": COLD_SUSPICIOUS_DENSITY,
            "low": low,
            "high": high,
            "source": "cold",
            "prior_coverage": 0.0,
        }

    per_file_susp: dict[str, int] = {}
    per_file_n: dict[str, int] = {}
    for (file, _fn), verdict in priors.items():
        per_file_n[file] = per_file_n.get(file, 0) + 1
        if verdict in _SUSPICIOUS_VERDICTS:
            per_file_susp[file] = per_file_susp.get(file, 0) + 1

    total = 0.0
    covered = 0
    for gap in items:
        key = _gap_key(gap)
        if key is not None and key in priors:
            covered += 1
            total += 1.0 if priors[key] in _SUSPICIOUS_VERDICTS else 0.0
            continue
        file = gap.get("file")
        n = per_file_n.get(file, 0) if isinstance(file, str) else 0
        if n:
            covered += 1
            total += per_file_susp.get(file, 0) / n
        else:
            total += COLD_SUSPICIOUS_DENSITY
    central = total / len(items)
    f_low, f_high = PRIOR_DENSITY_BAND_FACTOR
    return {
        "central": central,
        "low": max(0.0, central * f_low),
        "high": min(1.0, central * f_high),
        "source": "priors",
        "prior_coverage": covered / len(items),
    }


def seed_rereview_mass(
    prior_verdicts: dict[tuple[str, str], str] | None,
    queue_keys: set[tuple[str, str]] | None = None,
) -> int:
    """Prior suspicious/finding functions NOT already in the queue.

    These rows re-enter the deepen machinery on a follow-up pass
    (seeded re-reviews, caller re-review of recorded findings) without
    ever being first-pass queue items, so they carry deepen mass of
    their own. Queue members are excluded — their suspicious
    probability is already priced through the density term.
    """
    if not prior_verdicts:
        return 0
    exclude = queue_keys or set()
    return sum(
        1 for key, verdict in prior_verdicts.items()
        if verdict in _SUSPICIOUS_VERDICTS and key not in exclude
    )


def forecast_audit_cost(
    *,
    slocs: list[int],
    density: dict[str, Any],
    seed_mass: int = 0,
    review_passes: int = 1,
    model_overrides: int = 0,
) -> dict[str, Any]:
    """Forecast the LLM spend of the audit work described by the queue.

    ``slocs`` is the per-item size census of the gap queue (see
    :func:`gap_slocs`); ``density`` a :func:`predicted_suspicious_density`
    result; ``seed_mass`` the :func:`seed_rereview_mass` count;
    ``model_overrides`` the number of explicit ``--model`` values (the
    coefficients price a default-model run — an override is NOTED as a
    band caveat, never silently re-priced).
    """
    passes = max(1, int(review_passes))
    queue_n = len(slocs)

    review_central = passes * sum(
        REVIEW_BASE_USD
        + REVIEW_USD_PER_SLOC * min(max(0, s), REVIEW_SLOC_CAP)
        for s in slocs
    )
    r_lo, r_hi = REVIEW_BAND
    review = {
        "usd_central": review_central,
        "usd_low": review_central * r_lo,
        "usd_high": review_central * r_hi,
        "calls_central": queue_n * passes,
    }

    seed = max(0, int(seed_mass))
    mass_central = queue_n * float(density["central"]) + seed
    mass_low = queue_n * float(density["low"]) + seed
    mass_high = queue_n * float(density["high"]) + seed
    c_lo, c_hi = DEEPEN_CALLS_BAND
    deepen_calls_central = mass_central * DEEPEN_CALLS_PER_SUSPICIOUS
    deepen = {
        "usd_central": deepen_calls_central * DEEPEN_USD_PER_CALL,
        "usd_low": mass_low * c_lo * DEEPEN_USD_PER_CALL,
        "usd_high": mass_high * c_hi * DEEPEN_USD_PER_CALL,
        "calls_central": deepen_calls_central,
        "suspicious_mass_central": mass_central,
    }

    s_lo, s_hi = SUPPORT_BAND
    support = {
        "usd_central": SUPPORT_FRAC * (review["usd_central"]
                                       + deepen["usd_central"]),
        "usd_low": s_lo * (review["usd_low"] + deepen["usd_low"]),
        "usd_high": s_hi * (review["usd_high"] + deepen["usd_high"]),
    }

    phases = {"review": review, "deepen": deepen, "support": support}
    totals = {
        k: sum(p[k] for p in phases.values())
        for k in ("usd_low", "usd_central", "usd_high")
    }

    drivers: list[str] = []
    if density["source"] == "priors":
        drivers.append(
            f"suspicious density {density['central']:.2f} from journal "
            f"priors ({density['prior_coverage']:.0%} of the queue has "
            f"prior signal; band x{PRIOR_DENSITY_BAND_FACTOR[0]}-"
            f"x{PRIOR_DENSITY_BAND_FACTOR[1]})"
        )
    else:
        drivers.append(
            f"no journal priors — cold suspicious-density default "
            f"{COLD_SUSPICIOUS_DENSITY} (band "
            f"{COLD_DENSITY_BAND[0]}-{COLD_DENSITY_BAND[1]}; priors "
            f"from a prior run on this project narrow it)"
        )
    drivers.append(
        f"deepen depth: {DEEPEN_CALLS_BAND[0]}-{DEEPEN_CALLS_BAND[1]} "
        f"re-review/refinement calls per suspicious function across "
        f"calibration runs — widest band contributor"
    )
    if seed:
        drivers.append(
            f"seeded re-review mass: {seed} prior suspicious/finding "
            f"function(s) outside the queue re-enter the deepen "
            f"machinery"
        )
    if model_overrides:
        drivers.append(
            f"{model_overrides} --model override(s): coefficients "
            f"price a default-model run; a different model family "
            f"shifts the level outside this band"
        )

    def _round_phase(p: dict[str, float]) -> dict[str, float]:
        return {k: round(v, 2) for k, v in p.items()}

    return {
        "estimator": ESTIMATOR_VERSION,
        "queue_n": queue_n,
        "review_passes": passes,
        "suspicious_density": round(float(density["central"]), 4),
        "density_source": density["source"],
        "prior_coverage": round(float(density["prior_coverage"]), 4),
        "seed_rereview_mass": seed,
        "phases": {name: _round_phase(p) for name, p in phases.items()},
        "usd_low": round(totals["usd_low"], 2),
        "usd_central": round(totals["usd_central"], 2),
        "usd_high": round(totals["usd_high"], 2),
        "drivers": drivers,
    }


def format_forecast_lines(fc: dict[str, Any]) -> list[str]:
    """Human lines for the forecast — printed before any spend.

    Informational vocabulary by design: never "budget", "cap", or
    "limit" — ``--max-cost`` is the enforcement surface, these lines
    are a pre-spend estimate.
    """
    head = (
        f"Cost forecast: ${fc['usd_low']:.2f}-${fc['usd_high']:.2f} "
        f"(central ~${fc['usd_central']:.2f}) — {fc['queue_n']} queue "
        f"item(s), predicted suspicious density "
        f"{fc['suspicious_density']:.2f} ({fc['density_source']}) "
        f"[seeded-calibration estimate, not a cap]"
    )
    phases = fc.get("phases") or {}
    parts = []
    for name in ("review", "deepen", "support"):
        p = phases.get(name) or {}
        if "usd_central" in p:
            parts.append(f"{name} ~${p['usd_central']:.2f}")
    lines = [head]
    if parts:
        lines.append(f"  central split: {', '.join(parts)}")
    for driver in fc.get("drivers") or []:
        lines.append(f"  band driver: {driver}")
    return lines


def actual_phase_split(breakdown: dict[str, Any]) -> dict[str, Any]:
    """Collapse a cost-breakdown.json document onto the forecast's
    three-phase model. Tolerates missing/extra phases and keys."""
    phases = breakdown.get("phases") if isinstance(breakdown, dict) else None
    if not isinstance(phases, dict):
        phases = {}

    def _phase(name: str) -> tuple[float, int]:
        p = phases.get(name)
        if not isinstance(p, dict):
            return 0.0, 0
        cost = p.get("cost_usd")
        calls = p.get("calls")
        return (
            float(cost) if isinstance(cost, (int, float)) else 0.0,
            int(calls) if isinstance(calls, int) else 0,
        )

    review_usd, review_calls = _phase("review")
    deepen_usd, deepen_calls = 0.0, 0
    for name in ("re_review", "refinement"):
        usd, calls = _phase(name)
        deepen_usd += usd
        deepen_calls += calls
    support_usd = 0.0
    for name in phases:
        if name in ("review", "re_review", "refinement", "prior_segments"):
            continue
        support_usd += _phase(name)[0]

    totals = breakdown.get("totals") if isinstance(breakdown, dict) else None
    if not isinstance(totals, dict):
        totals = {}
    total = totals.get("total_spend_usd", totals.get("cost_usd"))
    return {
        "review_usd": round(review_usd, 2),
        "review_calls": review_calls,
        "deepen_usd": round(deepen_usd, 2),
        "deepen_calls": deepen_calls,
        "support_usd": round(support_usd, 2),
        "total_spend_usd": round(
            float(total) if isinstance(total, (int, float)) else 0.0, 2,
        ),
    }


def save_forecast(out_dir: Path, fc: dict[str, Any],
                  *, forecast_only: bool = False) -> Path:
    """Persist the pre-spend forecast into the run directory so the
    completion tail can pair it with the actual ledger."""
    from core.json import save_json
    doc = dict(fc)
    doc["outcome"] = "forecast_only" if forecast_only else "pre_run"
    path = Path(out_dir) / FORECAST_FILENAME
    save_json(path, doc)
    return path


def load_forecast(out_dir: Path) -> dict[str, Any] | None:
    """The run's persisted pre-spend forecast, or None."""
    path = Path(out_dir) / FORECAST_FILENAME
    if not path.is_file():
        return None
    try:
        from core.json.utils import load_json
        doc = load_json(path, strict=True,
                        max_bytes=_MAX_CALIBRATION_BYTES)
    except Exception:  # noqa: BLE001 — reader containment boundary
        logger.warning("forecast: %s unreadable", path, exc_info=True)
        return None
    return doc if isinstance(doc, dict) else None


def calibration_entry(
    forecast: dict[str, Any],
    breakdown: dict[str, Any],
    *,
    run_id: str,
) -> dict[str, Any]:
    """One forecast-vs-actual record: the re-fit food.

    ``within_band`` and ``central_error_ratio`` make the calibration
    file directly greppable for drift without re-deriving anything.
    """
    actual = actual_phase_split(breakdown)
    central = forecast.get("usd_central")
    total = actual["total_spend_usd"]
    ratio = None
    if isinstance(central, (int, float)) and central > 0:
        ratio = round(total / central, 3)
    low = forecast.get("usd_low")
    high = forecast.get("usd_high")
    within = None
    if isinstance(low, (int, float)) and isinstance(high, (int, float)):
        within = bool(low <= total <= high)
    predicted = {
        k: forecast.get(k)
        for k in ("estimator", "usd_low", "usd_central", "usd_high",
                  "queue_n", "review_passes", "suspicious_density",
                  "density_source", "prior_coverage",
                  "seed_rereview_mass", "phases")
    }
    return {
        "schema_version": 1,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "run_id": run_id,
        "predicted": predicted,
        "actual": actual,
        "central_error_ratio": ratio,
        "within_band": within,
    }


def append_calibration(path: Path, entry: dict[str, Any]) -> None:
    """Append one calibration record (single-line JSON). Best-effort
    with a size cap so the artifact cannot grow without bound."""
    path = Path(path)
    try:
        if path.exists() and path.stat().st_size > _MAX_CALIBRATION_BYTES:
            logger.warning(
                "forecast: %s over size cap — not appending", path)
            return
        line = json.dumps(entry, sort_keys=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        logger.warning("forecast: calibration append failed: %s",
                       path, exc_info=True)


def record_run_calibration(out_dir: Path) -> dict[str, Any] | None:
    """Completion tail: pair the run's persisted forecast with its
    cost-breakdown.json, append the calibration record (run dir, plus
    the project dir when the run is project-hosted), and return the
    record for report embedding. None when the run has no forecast or
    no ledger — never raises."""
    out_dir = Path(out_dir)
    try:
        forecast = load_forecast(out_dir)
        if not forecast or forecast.get("outcome") == "forecast_only":
            return None
        breakdown_path = out_dir / "cost-breakdown.json"
        if not breakdown_path.is_file():
            return None
        from core.json.utils import load_json
        breakdown = load_json(breakdown_path, strict=True,
                              max_bytes=_MAX_CALIBRATION_BYTES)
        if not isinstance(breakdown, dict):
            return None
        entry = calibration_entry(forecast, breakdown, run_id=out_dir.name)
        append_calibration(out_dir / CALIBRATION_FILENAME, entry)
        # Project-level accumulation, keyed off the same marker gap
        # computation uses for prior-verdict folding: the journal
        # index identifies a project directory.
        from core.coverage.journal import INDEX_FILENAME
        project_dir = out_dir.parent
        if (project_dir / INDEX_FILENAME).is_file():
            append_calibration(project_dir / CALIBRATION_FILENAME, entry)
        return entry
    except Exception:  # noqa: BLE001 — completion tail must never fail a run
        logger.warning("forecast: calibration recording failed",
                       exc_info=True)
        return None


def _usd(value: Any) -> str:
    """Render one USD figure, tolerating absent/foreign values.

    A parseable-but-partial forecast.json (key present, value ``None``
    or non-numeric) must degrade the console line to a visible ``$?``
    marker, never raise at the print seam — the completion tail runs
    after the LLM spend is already paid.
    """
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f"${value:.2f}"
    return "$?"


def format_calibration_line(entry: dict[str, Any]) -> str:
    """One console line for the completion summary."""
    pred = entry.get("predicted") or {}
    actual = entry.get("actual") or {}
    if not isinstance(pred, dict):
        pred = {}
    if not isinstance(actual, dict):
        actual = {}
    line = (
        f"Forecast vs actual: predicted "
        f"{_usd(pred.get('usd_low'))}-{_usd(pred.get('usd_high'))} "
        f"(central ~{_usd(pred.get('usd_central'))}), actual "
        f"{_usd(actual.get('total_spend_usd'))}"
    )
    within = entry.get("within_band")
    if within is not None:
        line += " — within band" if within else " — OUTSIDE band"
    ratio = entry.get("central_error_ratio")
    if isinstance(ratio, (int, float)):
        line += f" (actual/central {ratio:.2f}x)"
    return line
