"""Compute precision/recall/F1 and per-class breakdown from a corpus run.

Reads the results emitted by ``run_corpus.py`` (JSON, or legacy CSV) and
produces:
- Aggregate confusion matrix (with an explicit error cell)
- Per-bug-class precision and recall
- Trap gate (any finding = hard fail)
- Precision floor gate
- Per-class recall floor gate (zero = hard fail)
- Error-fraction gate (a crashed pipeline must not flatter precision)
- Mechanism attribution (verdict-match x mechanism-match) with a
  misattribution gate — right verdict from the WRONG mechanism fails

Use ``--diff`` to compare two runs and show what flipped.

Error semantics: a row with ``actual == "error"`` means the pipeline
never produced a verdict for that label.  Counting it as TN/FN by
verdict comparison would flatter precision and recall, so errors get
their own cell — excluded from every P/R denominator, reported per
class, and gated on aggregate fraction.

Attribution semantics: see ``core.audit.corpus.attribution``.  Rows
annotated by the runner carry ``attribution``/``observed_mechanisms``;
un-annotated rows (older results) are attributed from row-level
signals only — partial, and reported as such.
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.json import load_json


@dataclass
class ClassMetrics:
    """Confusion matrix for one bug class.

    ``error`` counts labels the pipeline never adjudicated
    (``actual == "error"``).  They are part of ``total`` but excluded
    from precision/recall/F1 denominators.
    """

    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    error: int = 0

    @property
    def precision(self) -> float | None:
        d = self.tp + self.fp
        return None if d == 0 else self.tp / d

    @property
    def recall(self) -> float | None:
        d = self.tp + self.fn
        return None if d == 0 else self.tp / d

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or (p + r) == 0:
            return None
        return 2 * p * r / (p + r)

    @property
    def adjudicated(self) -> int:
        """Rows the pipeline actually produced a verdict for."""
        return self.tp + self.fp + self.tn + self.fn

    @property
    def total(self) -> int:
        return self.adjudicated + self.error


# Statuses that constitute a claim.  ``suspicious`` counts: verdict
# matching accepts it for a finding label, so the matrix must too —
# otherwise a suspicious hit shows match=yes in the detail table while
# the same row counts as FN (and a suspicious alarm on a clean label
# counted as TN, flattering precision).
CLAIM_STATUSES = frozenset({"finding", "suspicious"})

# results files track corpus size — the checklist budget class.
_MAX_RESULTS_BYTES = 256 * 1024 * 1024


def _classify(expected: str, actual: str) -> str:
    """Map (expected, actual) to a confusion-matrix cell.

    ``actual == "error"`` is its own cell: the pipeline crashed or
    never reviewed the function, so no verdict comparison is valid.
    """
    if actual == "error":
        return "error"

    is_positive = actual in CLAIM_STATUSES
    expected_positive = expected == "finding"

    if expected_positive and is_positive:
        return "tp"
    if expected_positive and not is_positive:
        return "fn"
    if not expected_positive and is_positive:
        return "fp"
    return "tn"


def compute_metrics(
    rows: list[dict[str, Any]],
) -> tuple[ClassMetrics, dict[str, ClassMetrics], int]:
    """Compute aggregate and per-class metrics from result rows.

    Returns ``(aggregate, per_class, skipped_count)``.  Rows skipped by
    mechanical gates still count in the confusion matrix — the
    pipeline's end-to-end verdict is what the corpus measures — but the
    count is surfaced so a run that never reached the LLM is visible.
    """
    aggregate = ClassMetrics()
    per_class: dict[str, ClassMetrics] = defaultdict(ClassMetrics)
    skipped_count = 0

    for row in rows:
        expected = row["expected"]
        actual = row["actual"]
        bug_class = row["bug_class"]
        if row.get("skipped"):
            skipped_count += 1
        cell = _classify(expected, actual)

        setattr(aggregate, cell, getattr(aggregate, cell) + 1)
        cm = per_class[bug_class]
        setattr(cm, cell, getattr(cm, cell) + 1)

    return aggregate, dict(per_class), skipped_count


def error_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rows the pipeline never adjudicated."""
    return [r for r in rows if r.get("actual") == "error"]


def status_matches(expected: str, actual: str) -> bool:
    """Check if an actual status satisfies an expected ground truth.

    Same leniency as the runner's verdict scoring: ``finding`` accepts
    ``suspicious``; ``clean`` and ``dormant`` accept each other.
    """
    if expected == "finding":
        return actual in ("finding", "suspicious")
    if expected == "clean":
        return actual in ("clean", "dormant")
    if expected == "dormant":
        return actual in ("dormant", "clean")
    return False


@dataclass
class AttributionSummary:
    """Three-way verdict x mechanism scoring across a run."""

    cells: dict[str, int]
    misattributed: list[dict[str, Any]]
    unattributed: list[dict[str, Any]]
    checked: int  # rows carrying an expected_mechanism

    @property
    def attributed(self) -> int:
        return self.cells.get("attributed", 0)


def compute_attribution(rows: list[dict[str, Any]]) -> AttributionSummary:
    """Score verdict-match x mechanism-match per row.

    Rows already annotated by the runner (``attribution`` field) are
    respected; others are attributed from row-level signals only —
    that is the honest degradation path for results predating
    attribution, where run-directory receipts are gone.
    """
    from .attribution import ATTRIBUTION_CELLS, attribute_row

    cells: dict[str, int] = dict.fromkeys(ATTRIBUTION_CELLS, 0)
    misattributed: list[dict[str, Any]] = []
    unattributed: list[dict[str, Any]] = []
    checked = 0

    for row in rows:
        if row.get("attribution") in ATTRIBUTION_CELLS:
            cell = row["attribution"]
            observed = row.get("observed_mechanisms", [])
        else:
            attr = attribute_row(row)
            cell = attr["attribution"]
            observed = attr["observed_mechanisms"]

        cells[cell] = cells.get(cell, 0) + 1
        if row.get("expected_mechanism"):
            checked += 1

        detail = {
            "function_id": row.get("function_id", ""),
            "expected_mechanism": row.get("expected_mechanism", ""),
            "observed_mechanisms": list(observed),
        }
        if cell == "misattributed":
            misattributed.append(detail)
        elif cell == "unattributed":
            unattributed.append(detail)

    return AttributionSummary(
        cells=cells,
        misattributed=misattributed,
        unattributed=unattributed,
        checked=checked,
    )


def format_attribution_report(summary: AttributionSummary) -> str:
    """Human-readable attribution block."""
    c = summary.cells
    lines = []
    lines.append("Mechanism attribution "
                 f"({summary.checked} label(s) with expectations):")
    lines.append(
        f"  attributed (right verdict, right mechanism):   "
        f"{c.get('attributed', 0):>3}"
    )
    lines.append(
        f"  MISATTRIBUTED (right verdict, WRONG mechanism):"
        f"{c.get('misattributed', 0):>4}"
    )
    lines.append(
        f"  unattributed (right verdict, no receipt):      "
        f"{c.get('unattributed', 0):>3}"
    )
    lines.append(
        f"  wrong verdict:                                 "
        f"{c.get('wrong_verdict', 0):>3}"
    )
    lines.append(
        f"  error:                                         "
        f"{c.get('error', 0):>3}"
    )
    if c.get("no_expectation"):
        lines.append(
            f"  (no expected_mechanism on label:               "
            f"{c['no_expectation']:>3})"
        )
    for r in summary.misattributed:
        obs = ", ".join(r["observed_mechanisms"]) or "(none)"
        lines.append(
            f"  MISATTRIBUTED {r['function_id']}: "
            f"expected={r['expected_mechanism']} observed=[{obs}]"
        )
    lines.extend(f"  unattributed {r['function_id']}: "
            f"expected={r['expected_mechanism']}, no receipt recorded" for r in summary.unattributed)
    return "\n".join(lines)


def compute_mode_mismatches(
    rows: list[dict[str, Any]],
) -> tuple[int, list[dict[str, str]]]:
    """Check per-mode expectations where per-mode actuals exist.

    A label's ``expected_mode_results`` maps review mode -> expected
    status.  A row exposes per-mode actuals through its ``mode`` field
    (single-mode runs) and the ensemble merge's ``security_actual`` /
    ``bug_first_actual`` fields.  Modes the run never exercised are
    not counted — attribution never guesses.

    Returns ``(checked_count, mismatches)``.
    """
    checked = 0
    mismatches: list[dict[str, str]] = []
    for row in rows:
        emr = row.get("expected_mode_results") or {}
        if not emr or row.get("actual") == "error":
            continue
        actuals: dict[str, str] = {}
        if row.get("mode"):
            actuals[str(row["mode"])] = row.get("actual", "")
        if row.get("security_actual") is not None:
            actuals["security"] = row["security_actual"]
        if row.get("bug_first_actual") is not None:
            actuals["bug_first"] = row["bug_first_actual"]
        for mode, expected in emr.items():
            actual = actuals.get(mode)
            if actual is None:
                continue
            checked += 1
            if not status_matches(expected, actual):
                mismatches.append({
                    "function_id": row.get("function_id", ""),
                    "mode": mode,
                    "expected": expected,
                    "actual": actual,
                })
    return checked, mismatches


def format_mode_report(
    checked: int,
    mismatches: list[dict[str, str]],
) -> str:
    """Human-readable per-mode expectation block."""
    lines = [
        f"Mode expectations: {checked} checked, "
        f"{len(mismatches)} mismatch(es)"
    ]
    lines.extend(f"  {m['function_id']} [{m['mode']}]: "
            f"expected={m['expected']} got={m['actual']}" for m in mismatches)
    return "\n".join(lines)


def check_gate(
    aggregate: ClassMetrics,
    per_class: dict[str, ClassMetrics],
    rows: list[dict[str, Any]],
    *,
    precision_floor: float = 0.0,
    max_error_fraction: float = 0.1,
) -> list[str]:
    """Check regression gates.  Returns list of failure messages."""
    failures = []

    # Gate 1: trap hard gate — any claim is a failure.  The message
    # must be actionable on its own: what the trap is (the label's
    # rationale), what verdict/evidence flagged it, and the full
    # hypothesis — an operator should not have to join three separate
    # blocks to see why a deliberately-safe bait was flagged.
    trap = per_class.get("trap")
    if trap and trap.fp > 0:
        trap_rows = [
            r for r in rows
            if r["bug_class"] == "trap"
            and r["actual"] in CLAIM_STATUSES
        ]
        rationales = _label_rationales(
            [r.get("function_id", "") for r in trap_rows],
        )
        detail_lines = []
        for r in trap_rows:
            fid = r.get("function_id", "")
            detail_lines.append(
                f"  {fid}: expected={r.get('expected', '')} "
                f"got={r.get('actual', '')} "
                f"evidence={r.get('evidence_tool') or '(none)'}"
            )
            trap_what = rationales.get(fid, "")
            if trap_what:
                detail_lines.append(f"    trap: {trap_what}")
            hyp = r.get("hypothesis") or ""
            if hyp:
                detail_lines.append(f"    hypothesis: {hyp}")
        failures.append(
            f"Trap gate FAILED: {trap.fp} deliberately-safe "
            f"function(s) flagged:\n" + "\n".join(detail_lines)
        )

    # Gate 2: precision floor
    if precision_floor > 0 and aggregate.precision is not None:
        if aggregate.precision < precision_floor:
            failures.append(
                f"Precision floor FAILED: {aggregate.precision:.1%} "
                f"< {precision_floor:.1%}"
            )

    # Gate 3: per-class recall — zero recall means a class is blind
    for cls, cm in sorted(per_class.items()):
        if cls == "trap":
            continue
        if cm.recall is not None and cm.recall == 0.0 and (cm.tp + cm.fn) > 0:
            failures.append(
                f"Class recall gate FAILED: {cls} has 0% recall "
                f"({cm.fn} finding(s) missed)"
            )

    # Gate 4: error fraction — a crashed pipeline must not pass quietly.
    # Errors are excluded from P/R, so without this gate a run that
    # errored on every hard label would report flattering numbers.
    if aggregate.total > 0 and max_error_fraction >= 0:
        fraction = aggregate.error / aggregate.total
        if fraction > max_error_fraction:
            errored = [r["function_id"] for r in error_rows(rows)]
            failures.append(
                f"Error fraction gate FAILED: {aggregate.error}/"
                f"{aggregate.total} label(s) errored "
                f"({fraction:.0%} > {max_error_fraction:.0%}): "
                f"{', '.join(errored)}"
            )

    # Gate 5: misattribution — a right verdict produced by the WRONG
    # mechanism means the mechanism under calibration was never
    # exercised.  Verdict-only scoring would call this a pass; that is
    # the dangerous quiet cell, so it fails loudly by default.  One
    # aligned row per label — the previous single ~1,900-char joined
    # line was unreadable in a terminal and duplicated the per-label
    # attribution block wholesale.
    attribution = compute_attribution(rows)
    if attribution.misattributed:
        detail_lines = [
            f"  {'Function':<45} {'Expected mechanism':<24} Observed",
        ]
        for r in attribution.misattributed:
            fid = r["function_id"]
            if len(fid) > 44:
                fid = "..." + fid[-41:]
            observed = ", ".join(r["observed_mechanisms"]) or "(none)"
            detail_lines.append(
                f"  {fid:<45} {r['expected_mechanism']:<24} {observed}"
            )
        failures.append(
            f"Misattribution gate FAILED: "
            f"{len(attribution.misattributed)} label(s) got the right "
            f"verdict from the wrong mechanism (details also in the "
            f"'Mechanism attribution' block above):\n"
            + "\n".join(detail_lines)
        )

    return failures


def _label_rationales(function_ids: list[str]) -> dict[str, str]:
    """Best-effort ``function_id -> rationale`` join from the
    committed labels (what the trap actually is).  Results predating
    the labels, or a missing labels checkout, degrade to no rationale
    — never an error."""
    wanted = {fid for fid in function_ids if fid}
    if not wanted:
        return {}
    try:
        from .label import load_all_labels
        return {
            lb.function_id: " ".join(lb.rationale.split())
            for lb in load_all_labels()
            if lb.function_id in wanted
        }
    except Exception:  # noqa: BLE001 — enrichment only
        return {}


def format_report(
    aggregate: ClassMetrics,
    per_class: dict[str, ClassMetrics],
    *,
    model: str = "",
    skipped: int = 0,
) -> str:
    """Format a human-readable metrics report."""
    lines = []
    if model:
        lines.append(f"Model: {model}")
    agg_line = (
        f"Aggregate: P={_pct(aggregate.precision)} "
        f"R={_pct(aggregate.recall)} "
        f"F1={_pct(aggregate.f1)} "
        f"(n={aggregate.total}"
    )
    if aggregate.error:
        agg_line += (
            f", {aggregate.error} error(s) excluded from P/R"
        )
    if skipped:
        agg_line += f", {skipped} mechanically skipped"
    agg_line += ")"
    lines.append(agg_line)
    lines.append("")
    lines.append(f"{'Class':<14} {'P':>6} {'R':>6} {'F1':>6} "
                 f"{'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4} {'Err':>4}")
    lines.append("-" * 63)
    for cls in sorted(per_class):
        cm = per_class[cls]
        lines.append(
            f"{cls:<14} {_pct(cm.precision):>6} {_pct(cm.recall):>6} "
            f"{_pct(cm.f1):>6} {cm.tp:>4} {cm.fp:>4} {cm.fn:>4} "
            f"{cm.tn:>4} {cm.error:>4}"
        )
    return "\n".join(lines)


def diff_runs(
    before: list[dict[str, Any]],
    after: list[dict[str, Any]],
) -> str:
    """Show functions that changed classification between runs."""
    before_map = {r["function_id"]: r for r in before}
    after_map = {r["function_id"]: r for r in after}

    lines = []
    all_ids = sorted(set(before_map) | set(after_map))
    for fid in all_ids:
        b = before_map.get(fid)
        a = after_map.get(fid)
        if b is None or a is None:
            continue
        if b["actual"] != a["actual"]:
            expected = b["expected"]
            a_cell = _classify(expected, a["actual"])
            if a_cell == "error":
                direction = "errored"
            elif a_cell in ("tp", "tn"):
                direction = "improved"
            else:
                direction = "regressed"
            lines.append(
                f"  {fid}: {b['actual']} -> {a['actual']} "
                f"({direction}, expected={expected})"
            )

    if not lines:
        return "No classification changes."
    return f"{len(lines)} function(s) changed:\n" + "\n".join(lines)


def _pct(v: float | None) -> str:
    return "  n/a" if v is None else f"{v:.0%}"


def _read_results(path: Path) -> list[dict[str, Any]]:
    """Read result rows from a run_corpus JSON file or a legacy CSV.

    JSON may be a bare list of rows or the ``{"meta": ..., "results":
    [...]}`` wrapper that ``run_corpus._write_results`` emits.
    """
    if path.suffix.lower() == ".csv":
        with Path(path).open() as f:
            return list(csv.DictReader(f))
    raw = load_json(path, strict=True, max_bytes=_MAX_RESULTS_BYTES)
    if raw is None:
        # Strict load_json still soft-returns None for a missing file.
        raise FileNotFoundError(path)
    if isinstance(raw, dict) and "results" in raw:
        return raw["results"]
    if isinstance(raw, list):
        return raw
    msg = (
        f"{path}: expected a result list or a "
        f"{{'meta', 'results'}} wrapper, got {type(raw).__name__}"
    )
    raise ValueError(msg)


def _enrich_from_labels(rows: list[dict[str, Any]]) -> int:
    """Fill label-derived expectation fields missing from old rows.

    Results written before attribution landed carry no
    ``expected_mechanism`` / ``expected_mode_results``; the committed
    labels are the ground-truth registry, so a recompute may join them
    by function_id.  Only missing keys are filled — rows from current
    runs are untouched.  Returns the number of rows enriched.
    """
    try:
        from .label import load_all_labels
        by_id = {lb.function_id: lb for lb in load_all_labels()}
    except Exception as exc:  # noqa: BLE001 — degrade to un-enriched rows
        print(f"Label enrichment unavailable ({exc}); "
              f"scoring rows as-is.")
        return 0

    enriched = 0
    for row in rows:
        label = by_id.get(row.get("function_id", ""))
        if label is None:
            continue
        touched = False
        if "expected_mechanism" not in row:
            row["expected_mechanism"] = label.expected_mechanism
            touched = True
        if "expected_mode_results" not in row:
            row["expected_mode_results"] = dict(label.expected_mode_results)
            touched = True
        if touched:
            enriched += 1
    return enriched


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compute /audit corpus calibration metrics",
    )
    parser.add_argument(
        "results", type=Path,
        help="results JSON (or legacy CSV) from run_corpus.py",
    )
    parser.add_argument(
        "--run-dir", action="append", type=Path, default=[],
        metavar="DIR",
        help="Audit run directory to join mechanism receipts from "
             "(repeatable). Recomputes attribution for every row",
    )
    parser.add_argument(
        "--check-gate", action="store_true",
        help="Exit non-zero on regression gate failure",
    )
    parser.add_argument(
        "--precision-floor", type=float, default=0.0,
        help="Minimum aggregate precision (e.g. 0.6)",
    )
    parser.add_argument(
        "--max-error-fraction", type=float, default=0.1,
        help="Maximum fraction of labels allowed to error "
             "(default: 0.1)",
    )
    parser.add_argument(
        "--diff", type=Path, default=None, metavar="BEFORE",
        help="Compare against a prior run's results file",
    )
    args = parser.parse_args(argv)

    rows = _read_results(args.results)
    if not rows:
        print("No results to score.")
        return 1

    enriched = _enrich_from_labels(rows)
    if enriched:
        print(f"Enriched {enriched} row(s) with committed-label "
              f"expectations (results predate attribution fields).")

    if args.run_dir:
        from .attribution import annotate_results

        _, receipt_dirs = annotate_results(rows, args.run_dir)
        missing = len(args.run_dir) - receipt_dirs
        note = f"attribution recomputed from {receipt_dirs} run dir(s)"
        if missing:
            note += f"; {missing} given dir(s) missing"
        print(note.capitalize() + ".")

    model = rows[0].get("model", "")
    aggregate, per_class, skipped = compute_metrics(rows)
    print(format_report(aggregate, per_class, model=model, skipped=skipped))

    attribution = compute_attribution(rows)
    if attribution.checked:
        print()
        print(format_attribution_report(attribution))

    mode_checked, mode_mismatches = compute_mode_mismatches(rows)
    if mode_checked or mode_mismatches:
        print()
        print(format_mode_report(mode_checked, mode_mismatches))

    errored = error_rows(rows)
    if errored:
        print()
        print(f"{len(errored)} label(s) errored (excluded from P/R):")
        for r in errored:
            reason = r.get("error_reason") or r.get("error", "")
            suffix = f" — {reason}" if reason else ""
            print(f"  {r['function_id']}{suffix}")

    if args.diff:
        before = _read_results(args.diff)
        print()
        print(diff_runs(before, rows))

    if args.check_gate:
        failures = check_gate(
            aggregate, per_class, rows,
            precision_floor=args.precision_floor,
            max_error_fraction=args.max_error_fraction,
        )
        if failures:
            print()
            for f in failures:
                print(f"GATE FAIL: {f}")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
