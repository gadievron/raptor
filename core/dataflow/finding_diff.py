"""Diff baseline vs augmented CodeQL SARIF outputs.

Given two SARIF runs of the same CodeQL queries against the same
database — one without the sanitizer-evidence extension pack, one
with — this module reports which findings the augmented run
suppressed (the wins), which stayed flagged (the augmented sanitizer
models didn't cover them), and which appeared only in the augmented
run (shouldn't happen, but if it does the augmented pack has a bug
or CodeQL re-emitted a path with a slightly different location).

Identity uses :func:`core.dataflow.adapters.codeql.from_sarif_result`'s
stable ``finding_id`` (hash of producer + rule_id + source loc +
sink loc), so the same code path produces the same id whether
parsed from baseline or augmented SARIF.

This module does NOT run CodeQL. PR2b-2 wires the subprocess.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Set, Tuple

from core.dataflow.adapters.codeql import from_sarif_result


@dataclass(frozen=True)
class FindingDiff:
    """Outcome of a baseline-vs-augmented SARIF diff.

    ``suppression_rate`` is the headline metric for measurement:
    ``len(suppressed_ids) / baseline_count``. Higher = more findings
    the augmented sanitizer-models killed. Compare against the
    PR1 LLM-judge baseline (V2: F1 +2.7%) to decide whether the
    data-extensions approach wins.
    """

    suppressed_ids: Tuple[str, ...]
    still_flagged_ids: Tuple[str, ...]
    new_ids: Tuple[str, ...]
    baseline_count: int
    augmented_count: int

    @property
    def suppression_rate(self) -> float:
        if self.baseline_count == 0:
            return 0.0
        return len(self.suppressed_ids) / self.baseline_count

    def to_dict(self) -> dict:
        return {
            "suppressed_ids": list(self.suppressed_ids),
            "still_flagged_ids": list(self.still_flagged_ids),
            "new_ids": list(self.new_ids),
            "baseline_count": self.baseline_count,
            "augmented_count": self.augmented_count,
            "suppression_rate": self.suppression_rate,
        }


def diff_sarif_data(
    baseline: Mapping[str, Any],
    augmented: Mapping[str, Any],
) -> FindingDiff:
    """Compute the diff between two parsed SARIF documents.

    SARIF results that don't carry a dataflow path (no ``codeFlows``
    structure) are skipped — the data-extensions approach is about
    sanitizer modelling, which is meaningful only for path-aware
    findings. Non-dataflow results count toward neither baseline nor
    augmented totals.
    """
    baseline_ids = _sarif_finding_ids(baseline)
    augmented_ids = _sarif_finding_ids(augmented)

    suppressed = baseline_ids - augmented_ids
    still_flagged = baseline_ids & augmented_ids
    new = augmented_ids - baseline_ids

    return FindingDiff(
        suppressed_ids=tuple(sorted(suppressed)),
        still_flagged_ids=tuple(sorted(still_flagged)),
        new_ids=tuple(sorted(new)),
        baseline_count=len(baseline_ids),
        augmented_count=len(augmented_ids),
    )


def diff_sarif_files(
    baseline_path: Path,
    augmented_path: Path,
) -> FindingDiff:
    """File-based wrapper for :func:`diff_sarif_data`. Reads both
    SARIF JSON files and forwards the parsed dicts."""
    baseline = json.loads(baseline_path.read_text())
    augmented = json.loads(augmented_path.read_text())
    return diff_sarif_data(baseline, augmented)


def _sarif_finding_ids(sarif: Mapping[str, Any]) -> Set[str]:
    """Return the set of stable ``finding_id``s for every dataflow
    result in the SARIF document."""
    ids: Set[str] = set()
    for run in sarif.get("runs", []) or []:
        for result in run.get("results", []) or []:
            try:
                finding = from_sarif_result(result)
            except ValueError:
                continue
            if finding is None:
                continue
            ids.add(finding.finding_id)
    return ids
