"""The cross-file taint pipeline phase — substrate to artifacts.

One call runs the whole native lane over a target tree: inventory →
package callgraph → route models → packs (+ the bounded learned
intake when a project IRIS store exists) → propagation → path
reconstruction → emission, and writes the two intake artifacts into
the run's output directory:

* ``crossfile-taint.sarif`` — SARIF-with-codeFlows (compact,
  ``ensure_ascii`` — the pinned byte-inert egress).
* ``crossfile-taint-findings.json`` — the scan-shaped finding dicts
  plus frontier records, caps and stats. This file is the POST-SCAN
  MERGE channel: the /agentic pipeline hands its path to the
  validation-phase merge (the OpenAnt seam), so engine findings join
  AFTER the scanner's SARIF set and never enter any scanner-side
  postpass input.

Never a scanner: the phase writes nothing into the scan SARIF list,
writes no ``suppressions.jsonl`` (it has no suppression surface),
and its report carries counts + frontier + caps — a capped or empty
run states what it could not cover, never that anything is clean.

Containment: everything target-derived stays inside the engine's own
rails (the propagation and emission layers never raise on target
content); infrastructure failures (unreadable packs, a broken
inventory) DO raise — the caller's phase wrapper records them as the
phase's error instead of masking a deployment bug as a clean scan.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.atomic_fs import write_text_atomically
from core.json import load_json, save_json
from core.taint.emission import (
    PRODUCER,
    EmissionLimits,
    EmissionReport,
    emit,
    sarif_bytes,
)
from core.taint.engine import EngineLimits, PropagationResult, propagate
from core.taint.learned_intake import LearnedIntake, intake_learned_specs
from core.taint.packs import PackSet, default_pack_names, load_packs

logger = logging.getLogger(__name__)

SARIF_FILENAME = "crossfile-taint.sarif"
FINDINGS_FILENAME = "crossfile-taint-findings.json"


@dataclass
class TaintPhaseReport:
    """One phase run: what was emitted, what was not covered, where
    the artifacts landed."""

    candidates: int = 0
    emitted: int = 0
    refused: int = 0
    frontier: int = 0
    learned_admitted: int = 0
    caps_hit: tuple = ()
    stats: dict = field(default_factory=dict)
    sarif_path: Path | None = None
    findings_path: Path | None = None

    def summary_line(self) -> str:
        """The run-summary line: counts + frontier + caps. Names
        mechanisms and counts only — no target-derived text rides
        into the terminal from here."""
        caps = ", ".join(self.caps_hit) if self.caps_hit else "none"
        parts = [
            f"Cross-file taint: {self.emitted} finding(s) emitted "
            f"({self.candidates} candidate(s))",
            f"frontier {self.frontier} unresolved call site(s)",
        ]
        if self.refused:
            parts.append(f"{self.refused} record(s) past byte budget")
        if self.learned_admitted:
            parts.append(f"{self.learned_admitted} learned spec(s)")
        parts.append(f"caps: {caps}")
        return ", ".join(parts)

    def metrics(self) -> dict[str, Any]:
        """The scan-metrics block for the run report."""
        out: dict[str, Any] = {
            "total_findings": self.emitted,
            "candidates": self.candidates,
            "frontier_records": self.frontier,
            "caps_hit": list(self.caps_hit),
        }
        if self.refused:
            out["records_refused_budget"] = self.refused
        if self.learned_admitted:
            out["learned_specs_admitted"] = self.learned_admitted
        return out


def _load_inventory(target_root: Path, out_dir: Path) -> dict:
    """Reuse the run's ``checklist.json`` when the pipeline already
    built it; otherwise build a fresh inventory in memory (no file
    side effects — the checklist stays the inventory phase's
    artifact)."""
    checklist = out_dir / "checklist.json"
    if checklist.exists():
        data = load_json(checklist, strict=False)
        if isinstance(data, dict) and isinstance(data.get("files"), list):
            return data
        logger.warning(
            "cross-file taint: %s unreadable or shape-drifted — "
            "rebuilding the inventory", checklist)
    from core.inventory import build_inventory
    return build_inventory(str(target_root))


def _learned_intake(
    packs: PackSet, out_dir: Path, target_root: Path,
) -> LearnedIntake | None:
    """Project-learned specs through the bounded intake — best-effort
    (an absent or unreadable IRIS store is a normal state, never a
    phase failure)."""
    try:
        from core.iris.api import load_project_specs
        specs = load_project_specs(out_dir=out_dir,
                                   target_path=target_root)
    except Exception:  # noqa: BLE001 — enrichment channel, never fatal
        logger.debug("cross-file taint: learned-spec load failed",
                     exc_info=True)
        return None
    if not specs:
        return None
    return intake_learned_specs(
        specs, vocabulary=packs.taint_class_vocabulary())


def run_crossfile_taint(
    target_root: str | Path,
    out_dir: str | Path,
    *,
    language: str = "python",
    engine_limits: EngineLimits | None = None,
    emission_limits: EmissionLimits | None = None,
    inventory: dict | None = None,
) -> TaintPhaseReport:
    """Run the full native lane and write the intake artifacts.

    Artifacts are written even when zero findings emit — downstream
    readers distinguish "phase ran, nothing found, N caps / frontier
    records" from "phase never ran" by the file's honest counters,
    never by absence.
    """
    from core.analysis.package_callgraph import build_package_callgraph
    from core.analysis.route_models import build_route_models

    target_root = Path(target_root)
    out_dir = Path(out_dir)

    inv = inventory if inventory is not None else _load_inventory(
        target_root, out_dir)
    graph = build_package_callgraph(inv)
    routes = build_route_models(inv, graph)
    packs = load_packs(default_pack_names(language))
    learned = _learned_intake(packs, out_dir, target_root)

    result: PropagationResult = propagate(
        graph, routes, packs, learned,
        target_root=target_root, limits=engine_limits)
    report: EmissionReport = emit(
        result, packs, language=language, limits=emission_limits)

    sarif_path = out_dir / SARIF_FILENAME
    write_text_atomically(
        sarif_path, sarif_bytes(report).decode("ascii"))

    caps = tuple(sorted({*result.caps_hit, *report.caps_hit}))
    stats = {**result.stats, **report.stats}
    findings_path = out_dir / FINDINGS_FILENAME
    save_json(findings_path, {
        "tool": PRODUCER,
        "engine_version": result.engine_version,
        "findings": report.findings,
        # The BOUNDED frontier block — the emission rail owns its
        # per-field caps and byte budget; raw FrontierRecords never
        # reach the artifact (their full occurrence count survives in
        # stats.taint_at_unresolved).
        "frontier": report.frontier,
        "caps_hit": list(caps),
        "stats": dict(sorted(stats.items())),
    })

    return TaintPhaseReport(
        candidates=len(result.candidates),
        emitted=report.emitted,
        refused=report.refused,
        # The FULL occurrence count (the record list is capped).
        frontier=result.stat("taint_at_unresolved"),
        learned_admitted=learned.admitted if learned else 0,
        caps_hit=caps,
        stats=stats,
        sarif_path=sarif_path,
        findings_path=findings_path,
    )


__all__ = [
    "FINDINGS_FILENAME",
    "SARIF_FILENAME",
    "TaintPhaseReport",
    "run_crossfile_taint",
]
