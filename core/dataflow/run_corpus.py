"""Replay corpus findings through a :class:`Validator` and emit a CSV
of per-finding outcomes.

The CSV is the input to :mod:`core.dataflow.corpus_metrics`, which
computes precision/recall/F1 and the per-FP-category distribution
that gates pivot decisions in the design doc.

By default the runner uses :class:`TrivialValidator` (the producer
baseline). Custom validators load from a ``module:ClassName`` import
spec — PR1 wires the LLM-backed validator that way.
"""

from __future__ import annotations

import argparse
import csv
import importlib
import sys
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from core.dataflow.finding import Finding
from core.dataflow.label import (
    GroundTruth,
    VERDICT_FALSE_POSITIVE,
    VERDICT_TRUE_POSITIVE,
)
from core.dataflow.validator import TrivialValidator, Validator, ValidatorVerdict


_DEFAULT_CORPUS_DIR = Path(__file__).resolve().parent / "corpus" / "findings"


CSV_HEADER: List[str] = [
    "finding_id",
    "producer",
    "rule_id",
    "label_verdict",
    "fp_category",
    "validator_verdict",
    "validator_label",
    "agreement",
]


def iter_corpus(corpus_dir: Path) -> Iterable[Tuple[Finding, GroundTruth]]:
    """Yield ``(finding, label)`` for every paired entry in the corpus dir."""
    for fp in sorted(corpus_dir.glob("*.json")):
        if fp.name.endswith(".label.json"):
            continue
        finding = Finding.from_json(fp.read_text())
        label_path = fp.with_suffix(".label.json")
        label = GroundTruth.from_json(label_path.read_text())
        yield finding, label


def verdict_to_label(verdict: ValidatorVerdict) -> str:
    """Map a validator verdict to the corpus's verdict-label space."""
    if verdict == ValidatorVerdict.EXPLOITABLE:
        return VERDICT_TRUE_POSITIVE
    if verdict == ValidatorVerdict.NOT_EXPLOITABLE:
        return VERDICT_FALSE_POSITIVE
    return "uncertain"


def _classify_agreement(validator_label: str, ground_truth: str) -> str:
    if validator_label == "uncertain":
        return "uncertain"
    return "agree" if validator_label == ground_truth else "disagree"


def run(corpus_dir: Path, validator: Validator, output: Path) -> int:
    """Run validator against every corpus entry; write CSV to output.

    Returns the number of findings processed.
    """
    rows = 0
    with output.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADER)
        for finding, label in iter_corpus(corpus_dir):
            verdict = validator.validate(finding)
            v_label = verdict_to_label(verdict)
            agreement = _classify_agreement(v_label, label.verdict)
            writer.writerow(
                [
                    finding.finding_id,
                    finding.producer,
                    finding.rule_id,
                    label.verdict,
                    label.fp_category or "",
                    verdict.value,
                    v_label,
                    agreement,
                ]
            )
            rows += 1
    return rows


def load_validator(spec: str) -> Validator:
    """Load a validator from a ``module.path:ClassName`` import spec."""
    module_path, _, class_name = spec.partition(":")
    if not module_path or not class_name:
        raise ValueError(
            f"validator spec must be `module.path:ClassName`, got {spec!r}"
        )
    module = importlib.import_module(module_path)
    cls = getattr(module, class_name)
    instance = cls()
    if not isinstance(instance, Validator):
        raise TypeError(
            f"{spec!r} loaded but does not implement Validator protocol "
            f"(missing .validate(finding))"
        )
    return instance


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus-dir",
        type=Path,
        default=_DEFAULT_CORPUS_DIR,
        help=f"Corpus findings directory (default: {_DEFAULT_CORPUS_DIR})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="CSV output path",
    )
    parser.add_argument(
        "--validator",
        default=None,
        help=(
            "Validator import spec, e.g. `pkg.mod:Cls`. "
            "Default: core.dataflow.validator:TrivialValidator."
        ),
    )
    args = parser.parse_args(argv)

    if not args.corpus_dir.is_dir():
        print(f"corpus dir not found: {args.corpus_dir}", file=sys.stderr)
        return 2

    validator: Validator = (
        load_validator(args.validator) if args.validator else TrivialValidator()
    )
    rows = run(args.corpus_dir, validator, args.output)
    print(f"Wrote {rows} rows to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
