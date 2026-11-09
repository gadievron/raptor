"""Frozen SBOM evidence selections; no inventory reads, merging or verdict inference."""
from __future__ import annotations

import re

from core.reporting.document import Block
from core.reporting.writer import load_committed_report


def capture_sbom_reports(run_dirs, contexts, origins):
    """Use committed captures at known run output boundaries only.

    Counts belong to individual source populations. Imported captures remain
    recorded claims and no directory scan creates relationships between passes.
    """
    rows, notes, seen = [], [], set()
    for run in run_dirs:
        for relative in (".", "report", "sca", "sca/report"):
            if len(rows) >= 64:
                notes.append("Project SBOM view limited to 64 captured outputs; selected native inventories remain separate")
                return rows, notes
            root = run if relative == "." else run / relative
            context = contexts.get(str(run)) if relative == "." else None
            if relative == "." and context is None:
                continue  # Root selection/staleness policy was already frozen by project.
            if context is None:
                # No legacy SBOM fallback: the frozen view must not silently
                # read live inventory data when a receipt is absent or broken.
                if not (root / "reporting-manifest.json").exists():
                    continue
                try:
                    context, _, _ = load_committed_report(root, root=run)
                except (OSError, ValueError, TypeError):
                    notes.append(f"{run.name}/{relative}: committed SBOM reporting capture unavailable")
                    continue
            data = context.extensions.get("raptor.sbom")
            if context.kind.startswith("sbom-") and (not isinstance(data, dict) or not isinstance(data.get("summary"), dict)):
                data = context.extensions.get("raptor.result")
            if not isinstance(data, dict) or not isinstance(data.get("summary"), dict):
                continue
            summary = {key: value for key, value in data["summary"].items()
                       if key in {"packages", "source_candidates", "subject_records", "file_records", "unresolved_declarations",
                                  "notice_assessed_packages", "notice_gap_packages", "source_candidate_notice_gaps", "retained_notice_records"}
                       and (value is None or type(value) is int and value >= 0)}
            source = data.get("source_sha256", data.get("catalogue_sha256", ""))
            source = source if isinstance(source, str) and re.fullmatch(r"[a-f0-9]{64}", source) else ""
            fingerprint = context.snapshot_id
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            rows.append({"selection": run.name + "/" + relative, "run": run.name, "producer": context.kind,
                         "snapshot_id": fingerprint, "source_sha256": source,
                         "source_format": data["source_format"][:300] if isinstance(data.get("source_format"), str) else "not recorded",
                         "summary": summary,
                         "selected_records": data.get("selected_records") if type(data.get("selected_records")) is int else None,
                         "captured_records": data.get("captured_records") if type(data.get("captured_records")) is int else None,
                         "selection_sha256": data.get("selection_sha256", "") if isinstance(data.get("selection_sha256"), str) and re.fullmatch(r"[a-f0-9]{64}", data["selection_sha256"]) else "",
                         "notice_verification": data.get("notice_verification") if isinstance(data.get("notice_verification"), str) and data["notice_verification"] in {"verified", "not_verified", "failed"} else "not_recorded",
                         "imported": bool(origins.get(str(run))), "state": context.completion_state,
                         "scope": "individual supplied inventory; see captured snapshot for selection filters"})
    return rows, notes


def sbom_blocks(rows):
    if not rows:
        return []
    return [Block("paragraph", title="SBOM evidence scope",
                  text="Each row describes its own supplied inventory. Counts are not added across runs. Source candidates are not installed-package claims; imported evidence is not local validation."),
            Block("table", title="Selected SBOM evidence", columns=["Run / output", "Producer", "Imported", "Packages", "Unresolved declarations", "Notice verification", "Snapshot"],
                  rows=[[row["selection"], row["producer"], row["imported"], row["summary"].get("packages"),
                         row["summary"].get("unresolved_declarations"), row["notice_verification"], row["snapshot_id"]] for row in rows])]


def sbom_evidence_delta(before, after):
    """Changes in selected captures, deliberately distinct from package diffs."""
    def selection(context):
        rows = context.extensions.get("raptor.sbom_reports", [])
        if (not isinstance(rows, list) or any(not isinstance(row, dict)
                or not isinstance(row.get("selection"), str) or len(row["selection"]) > 1024
                or not isinstance(row.get("snapshot_id"), str) or not re.fullmatch(r"[a-f0-9]{64}", row["snapshot_id"]) for row in rows)):
            return None
        values = {row["selection"]: row for row in rows}
        return values if len(values) == len(rows) else None
    old, new = selection(before), selection(after)
    if old is None or new is None:
        return [], [Block("paragraph", title="SBOM evidence selection changes", text="SBOM comparison unavailable: baseline or current capture metadata is invalid or ambiguous. No evidence-resolution claim is inferred.")]
    rows = []
    for selection in sorted(old.keys() | new.keys()):
        a, b = old.get(selection), new.get(selection)
        if a and b and a["snapshot_id"] == b["snapshot_id"]:
            continue
        status = "newly selected capture" if a is None else "capture no longer selected" if b is None else "selected capture changed"
        rows.append([selection, status, a["snapshot_id"] if a else None, b["snapshot_id"] if b else None])
    blocks = []
    if old or new:
        blocks = [Block("table", title="SBOM evidence selection changes", columns=["Output", "Observation", "Baseline snapshot", "Current snapshot"], rows=rows),
                  Block("paragraph", text="These are changes in selected evidence, not package-removal or remediation verdicts. Use sca sbom diff with explicit baseline/current inventories for component comparisons.")]
    return rows, blocks
