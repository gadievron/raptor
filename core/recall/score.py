"""Score matcher output into a recall report.

The report's headline is per-CWE and overall detector recall —
found/expected over ground truth the producers never saw — plus the
actionable tail: the list of MISSED expected findings. A secondary
counter reports findings on labelled-clean regions (benchmark FP
cases); it is kept out of the recall arithmetic.

Segregation: ``label_class`` is stamped ``recall-ground-truth`` on
every report. These labels measure false negatives; feeding them to
the FP-suppression stores or the model scorecard would corrupt both
(the ``cvefix_corpus_generator`` warning, generalised). This module
must never import those stores — pinned by test.
"""

from __future__ import annotations

import shutil
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from core.recall.manifest import RecallManifest
from core.recall.matcher import MatchResult

LABEL_CLASS = "recall-ground-truth"

SEGREGATION_NOTE = (
    "These labels are recall ground truth (false-negative measurement). "
    "They must never feed FP-suppression, verdict-reuse, or model-"
    "scorecard learning stores — ingesting them there corrupts both "
    "calibrations."
)

#: How many missed findings the human-facing report lists in full.
MISS_LIST_CAP = 50


@dataclass
class CweRow:
    cwe: str
    expected: int = 0
    found: int = 0

    @property
    def recall(self) -> float | None:
        return None if self.expected == 0 else self.found / self.expected

    def to_dict(self) -> dict[str, Any]:
        return {"cwe": self.cwe, "expected": self.expected,
                "found": self.found, "recall": self.recall}


@dataclass
class RecallReport:
    manifest_name: str
    language: str
    profile: str
    pinned_sha: str
    expected_total: int = 0
    found_total: int = 0
    per_cwe: list[CweRow] = field(default_factory=list)
    #: producer -> number of expected findings it (co-)found
    tool_attribution: dict[str, int] = field(default_factory=dict)
    #: expected entries nothing found (full list in JSON, capped in md)
    missed: list[dict[str, Any]] = field(default_factory=list)
    #: findings on labelled-clean regions — secondary, not recall
    clean_region_fp_count: int = 0
    clean_region_fps: list[dict[str, Any]] = field(default_factory=list)
    toolchain: dict[str, str] = field(default_factory=dict)
    run_output_dir: str | None = None

    @property
    def recall(self) -> float | None:
        if self.expected_total == 0:
            return None
        return self.found_total / self.expected_total

    def to_dict(self) -> dict[str, Any]:
        return {
            "label_class": LABEL_CLASS,
            "segregation": SEGREGATION_NOTE,
            "manifest": self.manifest_name,
            "language": self.language,
            "profile": self.profile,
            "pinned_sha": self.pinned_sha,
            "recall": self.recall,
            "expected_total": self.expected_total,
            "found_total": self.found_total,
            "per_cwe": [r.to_dict() for r in self.per_cwe],
            "tool_attribution": dict(sorted(self.tool_attribution.items())),
            "missed": self.missed,
            "clean_region_fp_count": self.clean_region_fp_count,
            "clean_region_fps": self.clean_region_fps,
            "toolchain": self.toolchain,
            "run_output_dir": self.run_output_dir,
        }


def collect_toolchain() -> dict[str, str]:
    """Version-stamp the tools a recall number depends on.

    Mirrors the binary-oracle precision harness: a recall figure
    without its toolchain block is not reproducible.
    """
    import sys

    versions: dict[str, str] = {
        "python": sys.version.split()[0],
    }
    for tool, argv in (
        ("semgrep", ["semgrep", "--version"]),
        ("codeql", ["codeql", "version", "--format=terse"]),
    ):
        if shutil.which(argv[0]) is None:
            continue
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=30,
                check=False,
            )
            out = (proc.stdout or proc.stderr).strip().splitlines()
            if out:
                versions[tool] = out[0][:80]
        except (OSError, subprocess.SubprocessError):
            continue
    return versions


def score(
    manifest: RecallManifest,
    matches: list[MatchResult],
    clean_hits: list[MatchResult],
    *,
    toolchain: dict[str, str] | None = None,
    run_output_dir: str | None = None,
) -> RecallReport:
    """Aggregate matcher output into a :class:`RecallReport`."""
    per_cwe: dict[str, CweRow] = defaultdict(lambda: CweRow(cwe=""))
    tool_attr: dict[str, int] = defaultdict(int)
    missed: list[dict[str, Any]] = []
    found_total = 0

    for m in matches:
        row = per_cwe[m.expected.cwe]
        if not row.cwe:
            row.cwe = m.expected.cwe
        row.expected += 1
        if m.matched:
            row.found += 1
            found_total += 1
            for t in m.tools:
                tool_attr[t] += 1
        else:
            missed.append(m.expected.to_dict())

    clean_fps: list[dict[str, Any]] = []
    for c in clean_hits:
        entry = c.expected.to_dict()
        entry["tools"] = c.tools
        # rule attribution feeds the FP census (which rules drive the
        # clean-region hits); additive — older reports lack it
        entry["rules"] = sorted(
            {str(p.get("rule_id")) for p in c.hits if p.get("rule_id")})
        clean_fps.append(entry)

    return RecallReport(
        manifest_name=manifest.name,
        language=manifest.language,
        profile=manifest.profile,
        pinned_sha=manifest.pinned_sha,
        expected_total=len(matches),
        found_total=found_total,
        per_cwe=sorted(per_cwe.values(), key=lambda r: r.cwe),
        tool_attribution=dict(tool_attr),
        missed=missed,
        clean_region_fp_count=len(clean_fps),
        clean_region_fps=clean_fps,
        toolchain=toolchain if toolchain is not None else {},
        run_output_dir=run_output_dir,
    )


def _pct(v: float | None) -> str:
    return "n/a" if v is None else f"{100 * v:.1f}%"


def render_markdown(report: RecallReport) -> str:
    """Human-facing report; the JSON is the machine record."""
    lines = [
        f"# Detector recall — {report.manifest_name}",
        "",
        f"- label class: **{LABEL_CLASS}** (never feed FP/scorecard "
        "learning stores)",
        f"- language: {report.language}  |  profile: {report.profile}",
        f"- pinned sha: `{report.pinned_sha}`",
        f"- overall recall: **{_pct(report.recall)}** "
        f"({report.found_total}/{report.expected_total})",
        f"- findings on labelled-clean regions: "
        f"{report.clean_region_fp_count}",
    ]
    if report.toolchain:
        lines.append("- toolchain: " + ", ".join(
            f"{k} {v}" for k, v in sorted(report.toolchain.items())))
    if report.run_output_dir:
        lines.append(f"- pipeline run dir: {report.run_output_dir}")
    lines += ["", "| CWE | expected | found | recall |",
              "|-----|----------|-------|--------|"]
    for row in report.per_cwe:
        lines.append(
            f"| {row.cwe} | {row.expected} | {row.found} "
            f"| {_pct(row.recall)} |")
    if report.tool_attribution:
        lines += ["", "Tool attribution (expected findings co-found):"]
        for tool, n in sorted(report.tool_attribution.items()):
            lines.append(f"- {tool}: {n}")
    if report.missed:
        lines += ["", f"## Missed ({len(report.missed)} total, "
                      f"showing up to {MISS_LIST_CAP})", ""]
        for entry in report.missed[:MISS_LIST_CAP]:
            loc = entry["file"]
            if entry.get("line_start"):
                loc += f":{entry['line_start']}"
            lines.append(f"- {entry['cwe']}  {entry['id']}  ({loc})")
        if len(report.missed) > MISS_LIST_CAP:
            lines.append(
                f"- … {len(report.missed) - MISS_LIST_CAP} more in "
                "report.json")
    lines.append("")
    return "\n".join(lines)


def compare_reports(base: dict[str, Any],
                    new: dict[str, Any]) -> dict[str, Any]:
    """Delta two report JSONs (older first) for wave-vs-wave movement."""

    def _rows(d: dict[str, Any]) -> dict[str, dict[str, Any]]:
        return {r["cwe"]: r for r in d.get("per_cwe", [])}

    base_rows, new_rows = _rows(base), _rows(new)
    deltas = []
    for cwe in sorted(set(base_rows) | set(new_rows)):
        b = base_rows.get(cwe, {"expected": 0, "found": 0})
        n = new_rows.get(cwe, {"expected": 0, "found": 0})
        deltas.append({
            "cwe": cwe,
            "base_found": b["found"], "new_found": n["found"],
            "base_expected": b["expected"], "new_expected": n["expected"],
            "delta_found": n["found"] - b["found"],
        })
    base_missed = {m["id"] for m in base.get("missed", [])}
    new_missed = {m["id"] for m in new.get("missed", [])}
    return {
        "label_class": LABEL_CLASS,
        "base": base.get("manifest"),
        "new": new.get("manifest"),
        "base_recall": base.get("recall"),
        "new_recall": new.get("recall"),
        "per_cwe": deltas,
        "newly_found": sorted(base_missed - new_missed),
        "newly_missed": sorted(new_missed - base_missed),
    }
