"""Measurement harness for /audit capability evaluation.

Compares audit findings against a ground-truth manifest of known
vulnerabilities. Reports detection rate (did we find the bug?),
false positive rate (did we report non-bugs?), and per-capability
contribution (which capability found what?).

Usage:
    from core.audit.measurement import (
        load_ground_truth, evaluate_run, format_evaluation
    )
    truth = load_ground_truth(target_path)
    evaluation = evaluate_run(findings_path, truth)
    print(format_evaluation(evaluation))

Ground truth manifest: a JSON file (`ground-truth.json`) alongside
the target directory, listing known vulnerabilities with their
location and type.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from core.json import load_json, save_json

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class GroundTruthEntry:
    """A known vulnerability in the target codebase."""

    id: str
    file: str
    function: str
    line: int
    vuln_type: str
    description: str
    depth: str = "L1"
    failure_mode: str = ""

    def key(self) -> str:
        return f"{self.file}:{self.function}"


@dataclass
class EvaluationResult:
    """Result of comparing findings against ground truth."""

    true_positives: list[GroundTruthEntry] = field(default_factory=list)
    false_negatives: list[GroundTruthEntry] = field(default_factory=list)
    false_positives: list[dict[str, Any]] = field(default_factory=list)
    total_findings: int = 0
    total_ground_truth: int = 0

    @property
    def detection_rate(self) -> float:
        if self.total_ground_truth == 0:
            return 0.0
        return len(self.true_positives) / self.total_ground_truth

    @property
    def fp_rate(self) -> float:
        if self.total_findings == 0:
            return 0.0
        return len(self.false_positives) / self.total_findings

    @property
    def precision(self) -> float:
        tp = len(self.true_positives)
        fp = len(self.false_positives)
        if tp + fp == 0:
            return 0.0
        return tp / (tp + fp)

    @property
    def recall(self) -> float:
        return self.detection_rate

    @property
    def f1(self) -> float:
        p = self.precision
        r = self.recall
        if p + r == 0:
            return 0.0
        return 2 * p * r / (p + r)

    per_capability: dict[str, dict[str, int]] = field(default_factory=dict)
    per_cell: dict[str, dict[str, int]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "true_positives": [e.id for e in self.true_positives],
            "false_negatives": [e.id for e in self.false_negatives],
            "false_positives": [
                f"{fp.get('file', '?')}:{fp.get('function', '?')}"
                for fp in self.false_positives
            ],
            "detection_rate": round(self.detection_rate, 3),
            "fp_rate": round(self.fp_rate, 3),
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "f1": round(self.f1, 3),
            "total_findings": self.total_findings,
            "total_ground_truth": self.total_ground_truth,
        }
        if self.per_capability:
            d["per_capability"] = self.per_capability
        if self.per_cell:
            d["per_cell"] = self.per_cell
        return d


def load_ground_truth(target_path: Path) -> list[GroundTruthEntry]:
    """Load ground-truth.json from the target directory or its parent."""
    for candidate in (
        target_path / "ground-truth.json",
        target_path.parent / "ground-truth.json",
    ):
        if candidate.exists():
            data = load_json(candidate, strict=True, max_bytes=8 * 1024 * 1024)
            if data is None:  # vanished between exists() and the read
                raise FileNotFoundError(candidate)
            entries: list[GroundTruthEntry] = []
            items = data if isinstance(data, list) else data.get("vulnerabilities", [])
            for item in items:
                entries.append(GroundTruthEntry(
                    id=item.get("id", f"GT-{len(entries)+1}"),
                    file=item.get("file", ""),
                    function=item.get("function", ""),
                    line=item.get("line", 0),
                    vuln_type=item.get("vuln_type", ""),
                    description=item.get("description", ""),
                    depth=item.get("depth", "L1"),
                    failure_mode=item.get("failure_mode", ""),
                ))
            return entries
    return []


def evaluate_run(
    out_dir: Path,
    ground_truth: list[GroundTruthEntry],
) -> EvaluationResult:
    """Evaluate an audit run's findings against ground truth.

    Loads findings from findings.json or findings-graded.json in out_dir.
    Matches against ground truth by file:function key.
    """
    findings = _load_findings(out_dir)
    result = EvaluationResult(
        # Verdict rows only: the graded file carries clean/dormant
        # rows too, and counting them deflated fp_rate's denominator.
        total_findings=sum(
            1 for f in findings
            if f.get("status", "") in ("finding", "suspicious")
        ),
        total_ground_truth=len(ground_truth),
    )

    # Several planted bugs can share a file:function — keep a list per
    # key so co-located entries are each countable (dropping duplicates
    # left them neither TP nor FN).
    truth_keys: dict[str, list[GroundTruthEntry]] = {}
    for entry in ground_truth:
        truth_keys.setdefault(entry.key(), []).append(entry)

    found_ids: set[int] = set()

    for finding in findings:
        key = f"{finding.get('file', '')}:{finding.get('function', '')}"
        status = finding.get("status", "")

        if status not in ("finding", "suspicious"):
            continue

        entries = truth_keys.get(key)
        if entries is not None:
            unfound = [e for e in entries if id(e) not in found_ids]
            if not unfound:
                # Every planted bug at this location is already
                # credited; a re-report of a genuinely vulnerable
                # function is neither a new detection nor a false
                # positive.
                continue
            # Vuln type is a PREFERENCE among co-located entries, never
            # a gate — finding and manifest type vocabularies differ,
            # so a location hit with a non-matching type stays a TP.
            ftype = str(
                finding.get("vuln_type") or finding.get("cwe") or "",
            ).strip().casefold()
            entry = next(
                (e for e in unfound
                 if ftype and e.vuln_type.strip().casefold() == ftype),
                unfound[0],
            )
            result.true_positives.append(entry)
            found_ids.add(id(entry))

            evidence_sources = _extract_evidence_sources(finding)
            for src in evidence_sources:
                cap = result.per_capability.setdefault(src, {"tp": 0, "fp": 0})
                cap["tp"] += 1

            cell_key = f"{entry.depth}:{entry.failure_mode or 'none'}"
            cell = result.per_cell.setdefault(cell_key, {"tp": 0, "fn": 0})
            cell["tp"] += 1
        else:
            result.false_positives.append(finding)
            evidence_sources = _extract_evidence_sources(finding)
            for src in evidence_sources:
                cap = result.per_capability.setdefault(src, {"tp": 0, "fp": 0})
                cap["fp"] += 1

    for entry in ground_truth:
        if id(entry) not in found_ids:
            result.false_negatives.append(entry)
            cell_key = f"{entry.depth}:{entry.failure_mode or 'none'}"
            cell = result.per_cell.setdefault(cell_key, {"tp": 0, "fn": 0})
            cell["fn"] += 1

    return result


def format_evaluation(result: EvaluationResult) -> str:
    """Render an evaluation as human-readable text."""
    lines = ["## Audit Evaluation"]
    lines.append("")
    lines.append(
        f"Detection: {len(result.true_positives)}/{result.total_ground_truth} "
        f"({result.detection_rate:.0%})"
    )
    lines.append(f"Precision: {result.precision:.0%}")
    lines.append(f"F1: {result.f1:.2f}")
    lines.append("")

    if result.true_positives:
        lines.append("### Found")
        lines.extend(f"- {entry.id}: {entry.file}:{entry.function} ({entry.vuln_type})" for entry in result.true_positives)

    if result.false_negatives:
        lines.append("")
        lines.append("### Missed")
        for entry in result.false_negatives:
            lines.append(
                f"- {entry.id}: {entry.file}:{entry.function} "
                f"({entry.vuln_type}, depth={entry.depth})"
            )
            if entry.failure_mode:
                lines.append(f"  failure mode: {entry.failure_mode}")

    if result.false_positives:
        lines.append("")
        lines.append(f"### False positives ({len(result.false_positives)})")
        # `or` — a present-but-null hypothesis raised on the slice.
        lines.extend(f"- {fp.get('file', '?')}:{fp.get('function', '?')} "
                f"({(fp.get('hypothesis') or '?')[:60]})" for fp in result.false_positives[:10])
        if len(result.false_positives) > 10:
            lines.append(f"  ... and {len(result.false_positives) - 10} more")

    return "\n".join(lines)


def write_evaluation(
    result: EvaluationResult,
    out_dir: Path,
) -> Path:
    """Write evaluation.json to the run directory."""
    path = out_dir / "evaluation.json"
    save_json(path, result.to_dict())
    return path


def _extract_evidence_sources(finding: dict[str, Any]) -> list[str]:
    """Extract evidence source tags from a finding dict."""
    sources: list[str] = []
    for ev in finding.get("evidence_chain", []):
        src = ev.get("source", "")
        if src and src not in sources:
            sources.append(src)
    discovered_by = finding.get("discovered_by", "")
    if discovered_by and discovered_by not in sources:
        sources.append(discovered_by)
    if not sources:
        sources.append("llm")
    return sources


def _load_findings(out_dir: Path) -> list[dict[str, Any]]:
    """Load findings from graded or standard findings file."""
    graded_path = out_dir / "findings-graded.json"
    if graded_path.exists():
        data = load_json(graded_path, strict=True, max_bytes=256 * 1024 * 1024)
        if data is None:  # vanished between exists() and the read
            raise FileNotFoundError(graded_path)
        if isinstance(data, list):
            return data
        rows = data.get("findings", [])
        return rows if isinstance(rows, list) else []

    standard_path = out_dir / "findings.json"
    if standard_path.exists():
        data = load_json(standard_path, strict=True, max_bytes=256 * 1024 * 1024)
        if data is None:  # vanished between exists() and the read
            raise FileNotFoundError(standard_path)
        if isinstance(data, list):
            return data
        rows = data.get("findings", [])
        return rows if isinstance(rows, list) else []

    return []
