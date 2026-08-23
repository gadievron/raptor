"""Adversarial self-test framework for /audit blind spot detection.

A world-leading audit system should measure its own blind spots by
running against bugs specifically designed to evade it.

The depth x failure-mode matrix defines where bugs can hide:

Depths:  L0 (lexical) through L6 (architectural)
Failure modes:
  - attention_decay: bug buried deep in a long file
  - happy_path: bug on an error path the LLM doesn't explore
  - api_trust: dangerous API with a safe-sounding name
  - absence: the bug IS the missing check
  - composition: individually correct components compose unsafely
  - temporal: ordering dependency exploitable by concurrent access
  - naming_misdirection: function name implies safety it doesn't provide
  - scale_defeat: too many components to hold in context at once

Each cell gets synthetic bugs.  After running /audit, the matrix
shows which cells were found (blind spots close) vs missed (drive
capability development).
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

logger = logging.getLogger(__name__)


class DepthLevel:
    L0 = "L0"
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"
    L4 = "L4"
    L5 = "L5"
    L6 = "L6"

    ALL = ["L0", "L1", "L2", "L3", "L4", "L5", "L6"]


class FailureMode:
    ATTENTION_DECAY = "attention_decay"
    HAPPY_PATH = "happy_path"
    API_TRUST = "api_trust"
    ABSENCE = "absence"
    COMPOSITION = "composition"
    TEMPORAL = "temporal"
    NAMING_MISDIRECTION = "naming_misdirection"
    SCALE_DEFEAT = "scale_defeat"

    ALL = [
        "attention_decay",
        "happy_path",
        "api_trust",
        "absence",
        "composition",
        "temporal",
        "naming_misdirection",
        "scale_defeat",
    ]


_MATRIX: dict[str, frozenset] = {
    "L0": frozenset({"naming_misdirection"}),
    "L1": frozenset({"attention_decay", "happy_path", "absence", "naming_misdirection"}),
    "L2": frozenset({
        "attention_decay", "happy_path", "api_trust",
        "absence", "temporal", "naming_misdirection",
    }),
    "L3": frozenset({
        "attention_decay", "happy_path", "api_trust",
        "absence", "composition", "temporal", "naming_misdirection",
    }),
    "L4": frozenset({
        "attention_decay", "happy_path", "api_trust",
        "absence", "composition", "temporal", "naming_misdirection",
    }),
    "L5": frozenset({"absence", "composition", "scale_defeat"}),
    "L6": frozenset({"composition", "scale_defeat"}),
}


@dataclass
class PlantedBug:
    """A bug planted in the adversarial synthetic target."""

    bug_id: str
    depth: str
    failure_mode: str
    file: str
    function: str
    line: int = 0
    vuln_type: str = ""
    description: str = ""
    evasion_technique: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "bug_id": self.bug_id,
            "depth": self.depth,
            "failure_mode": self.failure_mode,
            "file": self.file,
            "function": self.function,
            "line": self.line,
            "vuln_type": self.vuln_type,
            "description": self.description,
            "evasion_technique": self.evasion_technique,
        }

    @property
    def cell_key(self) -> str:
        return f"{self.depth}:{self.failure_mode}"


@dataclass
class DetectionResult:
    """Whether a planted bug was detected by a specific configuration."""

    bug_id: str
    detected: bool
    configuration: str = ""
    evidence_tier: str = ""
    finding_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "bug_id": self.bug_id,
            "detected": self.detected,
            "configuration": self.configuration,
        }
        if self.evidence_tier:
            d["evidence_tier"] = self.evidence_tier
        if self.finding_id:
            d["finding_id"] = self.finding_id
        return d


@dataclass
class MatrixCell:
    """Result for one cell of the depth x failure-mode matrix."""

    depth: str
    failure_mode: str
    planted_bugs: list[PlantedBug] = field(default_factory=list)
    detection_results: dict[str, list[DetectionResult]] = field(default_factory=dict)

    @property
    def is_active(self) -> bool:
        return self.failure_mode in _MATRIX.get(self.depth, frozenset())

    @property
    def detection_rate(self) -> float | None:
        if not self.planted_bugs:
            return None
        total = len(self.planted_bugs)
        found = 0
        for bug in self.planted_bugs:
            detected_in_any = any(
                any(r.detected for r in results if r.bug_id == bug.bug_id)
                for results in self.detection_results.values()
            )
            if detected_in_any:
                found += 1
        return found / total if total > 0 else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "depth": self.depth,
            "failure_mode": self.failure_mode,
            "is_active": self.is_active,
            "planted_count": len(self.planted_bugs),
            "detection_rate": self.detection_rate,
        }


@dataclass
class AdversarialMatrix:
    """The full depth x failure-mode matrix with results."""

    cells: dict[str, MatrixCell] = field(default_factory=dict)
    configurations: list[str] = field(default_factory=list)

    def get_cell(self, depth: str, failure_mode: str) -> MatrixCell:
        key = f"{depth}:{failure_mode}"
        if key not in self.cells:
            self.cells[key] = MatrixCell(depth=depth, failure_mode=failure_mode)
        return self.cells[key]

    def add_planted_bug(self, bug: PlantedBug) -> None:
        cell = self.get_cell(bug.depth, bug.failure_mode)
        cell.planted_bugs.append(bug)

    def record_detection(
        self,
        bug_id: str,
        detected: bool,
        configuration: str,
        evidence_tier: str = "",
        finding_id: str = "",
    ) -> None:
        if configuration not in self.configurations:
            self.configurations.append(configuration)

        for cell in self.cells.values():
            for bug in cell.planted_bugs:
                if bug.bug_id == bug_id:
                    results = cell.detection_results.setdefault(configuration, [])
                    results.append(DetectionResult(
                        bug_id=bug_id,
                        detected=detected,
                        configuration=configuration,
                        evidence_tier=evidence_tier,
                        finding_id=finding_id,
                    ))
                    return

    def blind_spots(self) -> list[MatrixCell]:
        """Return cells where bugs were planted but none were detected."""
        spots = []
        for cell in self.cells.values():
            if not cell.is_active or not cell.planted_bugs:
                continue
            rate = cell.detection_rate
            if rate is not None and rate == 0.0:
                spots.append(cell)
        return spots

    def coverage_summary(self) -> dict[str, Any]:
        active = [c for c in self.cells.values() if c.is_active]
        populated = [c for c in active if c.planted_bugs]
        detected = [c for c in populated if (c.detection_rate or 0) > 0]
        return {
            "active_cells": len(active),
            "populated_cells": len(populated),
            "cells_with_detections": len(detected),
            "blind_spot_count": len(self.blind_spots()),
            "total_planted_bugs": sum(
                len(c.planted_bugs) for c in populated
            ),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "configurations": self.configurations,
            "cells": {k: v.to_dict() for k, v in sorted(self.cells.items())},
            "summary": self.coverage_summary(),
        }


def load_planted_bugs(manifest_path: Path) -> list[PlantedBug]:
    """Load planted bugs from a JSON manifest."""
    if not manifest_path.is_file():
        return []

    try:
        data = json.loads(manifest_path.read_text())
    except Exception:
        logger.debug("failed to load planted bugs from %s", manifest_path, exc_info=True)
        return []

    items = data if isinstance(data, list) else data.get("bugs", [])
    bugs = []
    for item in items:
        try:
            bugs.append(PlantedBug(
                bug_id=item["bug_id"],
                depth=item["depth"],
                failure_mode=item["failure_mode"],
                file=item["file"],
                function=item["function"],
                line=item.get("line", 0),
                vuln_type=item.get("vuln_type", ""),
                description=item.get("description", ""),
                evasion_technique=item.get("evasion_technique", ""),
            ))
        except (KeyError, TypeError):
            continue

    return bugs


def match_findings_to_bugs(
    findings: Sequence[dict[str, Any]],
    bugs: Sequence[PlantedBug],
    configuration: str = "default",
) -> list[DetectionResult]:
    """Match audit findings to planted bugs.

    A finding matches a planted bug if it references the same file and
    function (or overlapping line range).
    """
    results: list[DetectionResult] = []
    matched_bugs: set = set()

    for bug in bugs:
        detected = False
        evidence_tier = ""
        finding_id = ""

        for finding in findings:
            f_file = finding.get("file", "")
            f_func = finding.get("function", "")
            f_line = finding.get("line", 0)

            file_match = (
                f_file == bug.file
                or f_file.endswith(f"/{bug.file}")
                or bug.file.endswith(f"/{f_file}")
            )
            func_match = f_func == bug.function
            line_match = bug.line > 0 and abs(f_line - bug.line) <= 10

            if file_match and (func_match or line_match):
                detected = True
                evidence_tier = finding.get("evidence_tier", "")
                finding_id = finding.get("finding_id", finding.get("id", ""))
                matched_bugs.add(bug.bug_id)
                break

        results.append(DetectionResult(
            bug_id=bug.bug_id,
            detected=detected,
            configuration=configuration,
            evidence_tier=evidence_tier,
            finding_id=finding_id,
        ))

    return results


def build_matrix(bugs: Sequence[PlantedBug]) -> AdversarialMatrix:
    """Build an empty matrix populated with planted bugs."""
    matrix = AdversarialMatrix()
    for bug in bugs:
        matrix.add_planted_bug(bug)
    return matrix


def format_matrix_report(matrix: AdversarialMatrix) -> str:
    """Render the matrix as a text table for human review."""
    lines = ["# Adversarial Self-Test Matrix", ""]

    summary = matrix.coverage_summary()
    lines.append(
        f"Active cells: {summary['active_cells']} | "
        f"Populated: {summary['populated_cells']} | "
        f"Detected: {summary['cells_with_detections']} | "
        f"Blind spots: {summary['blind_spot_count']}"
    )
    lines.append("")

    header = "| Depth |"
    sep = "|-------|"
    for fm in FailureMode.ALL:
        short = fm[:8]
        header += f" {short:>8} |"
        sep += "----------|"

    lines.append(header)
    lines.append(sep)

    for depth in DepthLevel.ALL:
        row = f"| {depth:5} |"
        for fm in FailureMode.ALL:
            key = f"{depth}:{fm}"
            cell = matrix.cells.get(key)

            if fm not in _MATRIX.get(depth, frozenset()):
                row += "        — |"
            elif cell is None or not cell.planted_bugs:
                row += "     none |"
            else:
                rate = cell.detection_rate
                if rate is None:
                    row += "      n/a |"
                elif rate == 1.0:
                    row += "     100% |"
                elif rate == 0.0:
                    row += "    BLIND |"
                else:
                    row += f"    {rate:4.0%} |"
        lines.append(row)

    blind = matrix.blind_spots()
    if blind:
        lines.append("")
        lines.append(f"## Blind Spots ({len(blind)})")
        lines.extend(f"- {cell.depth} x {cell.failure_mode}: "
                f"{len(cell.planted_bugs)} bugs planted, 0 detected" for cell in blind)

    return "\n".join(lines)


def write_matrix(
    matrix: AdversarialMatrix,
    output_dir: Path,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "adversarial-matrix.json"

    fd, tmp = tempfile.mkstemp(dir=str(output_dir), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(matrix.to_dict(), f, indent=2)
        os.replace(tmp, str(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

    return path
