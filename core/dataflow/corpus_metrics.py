"""Compute precision/recall/F1 + per-FP-category breakdown from a
:mod:`core.dataflow.run_corpus` CSV.

Also enforces the design's pivot gate: ``missing_sanitizer_model``
must account for at least 10% of FP labels in the corpus, otherwise
the dataflow sanitizer-bypass feature line is targeting the wrong
class. The ``--check-pivot-gate`` flag exits non-zero when the
threshold is not met so CI can wire it as a hard gate once the
corpus is large enough to be statistically meaningful.
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from core.dataflow.label import (
    FP_MISSING_SANITIZER_MODEL,
    VERDICT_FALSE_POSITIVE,
    VERDICT_TRUE_POSITIVE,
)


PIVOT_GATE_THRESHOLD = 0.10


@dataclass
class Metrics:
    """Aggregated metrics from one corpus run.

    ``tp`` / ``fp`` / ``tn`` / ``fn`` are the standard confusion-matrix
    counts where the validator's ``exploitable`` verdict is the
    positive class. ``uncertain`` rows don't contribute to any of
    these counters — their share is reported separately.
    """

    total: int = 0
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    uncertain: int = 0
    fp_categories: Counter = field(default_factory=Counter)

    @property
    def precision(self) -> Optional[float]:
        denom = self.tp + self.fp
        return None if denom == 0 else self.tp / denom

    @property
    def recall(self) -> Optional[float]:
        denom = self.tp + self.fn
        return None if denom == 0 else self.tp / denom

    @property
    def f1(self) -> Optional[float]:
        p, r = self.precision, self.recall
        if p is None or r is None or (p + r) == 0:
            return None
        return 2 * p * r / (p + r)


def compute(csv_path: Path) -> Metrics:
    m = Metrics()
    with csv_path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            m.total += 1
            label = row["label_verdict"]
            v = row["validator_label"]
            if label == VERDICT_FALSE_POSITIVE and row["fp_category"]:
                m.fp_categories[row["fp_category"]] += 1
            if v == "uncertain":
                m.uncertain += 1
                continue
            if v == VERDICT_TRUE_POSITIVE:
                if label == VERDICT_TRUE_POSITIVE:
                    m.tp += 1
                else:
                    m.fp += 1
            elif v == VERDICT_FALSE_POSITIVE:
                if label == VERDICT_TRUE_POSITIVE:
                    m.fn += 1
                else:
                    m.tn += 1
    return m


def render(m: Metrics) -> str:
    lines: List[str] = []
    lines.append(f"Total findings: {m.total}")
    tp_total = m.tp + m.fn
    fp_total = m.fp + m.tn
    lines.append(
        f"  True positives:  {tp_total}  "
        f"(validator-confirmed: {m.tp}, missed: {m.fn})"
    )
    lines.append(
        f"  False positives: {fp_total}  "
        f"(suppressed: {m.tn}, leaked: {m.fp})"
    )
    lines.append(f"  Uncertain:       {m.uncertain}")
    lines.append("")
    lines.append("Validator metrics:")
    p, r, fone = m.precision, m.recall, m.f1
    lines.append(
        f"  Precision: {p:.3f}" if p is not None
        else "  Precision: undefined (no exploitable predictions)"
    )
    lines.append(
        f"  Recall:    {r:.3f}" if r is not None
        else "  Recall:    undefined (no positives in labels)"
    )
    lines.append(
        f"  F1:        {fone:.3f}" if fone is not None
        else "  F1:        undefined"
    )
    lines.append("")
    lines.append("FP category distribution:")
    if not m.fp_categories:
        lines.append("  (no labelled FPs in corpus)")
    else:
        total_fps = sum(m.fp_categories.values())
        for cat, count in m.fp_categories.most_common():
            pct = count / total_fps * 100
            lines.append(f"  {cat}: {count} ({pct:.1f}%)")
    return "\n".join(lines)


def check_pivot_gate(m: Metrics) -> Tuple[bool, str]:
    """Return ``(ok, message)``. ``ok`` is True iff
    ``missing_sanitizer_model`` accounts for at least
    :data:`PIVOT_GATE_THRESHOLD` of the labelled FPs.
    """
    total_fps = sum(m.fp_categories.values())
    if total_fps == 0:
        return False, "no FPs in corpus; pivot gate undefined"
    msm_count = m.fp_categories.get(FP_MISSING_SANITIZER_MODEL, 0)
    share = msm_count / total_fps
    if share >= PIVOT_GATE_THRESHOLD:
        return True, (
            f"missing_sanitizer_model = {share:.1%} of FPs "
            f"(threshold {PIVOT_GATE_THRESHOLD:.0%})"
        )
    return False, (
        f"missing_sanitizer_model = {share:.1%} of FPs "
        f"(BELOW threshold {PIVOT_GATE_THRESHOLD:.0%})"
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", type=Path, help="CSV from run_corpus.py")
    parser.add_argument(
        "--check-pivot-gate",
        action="store_true",
        help=(
            "Exit non-zero if missing_sanitizer_model share is below "
            f"{PIVOT_GATE_THRESHOLD:.0%}"
        ),
    )
    args = parser.parse_args(argv)

    if not args.csv.is_file():
        print(f"CSV not found: {args.csv}", file=sys.stderr)
        return 2

    m = compute(args.csv)
    print(render(m))

    if args.check_pivot_gate:
        ok, msg = check_pivot_gate(m)
        print()
        print(f"Pivot gate: {msg}")
        if not ok:
            return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
