"""Compare explicit snapshots. Absence is never a resolution verdict."""
from __future__ import annotations

from collections import Counter
import json
from .document import Block, ReportContext, ReportDocument, digest
from .builders import build_document


def build_delta(baseline: ReportContext, candidate: ReportContext, *,
                lineage: dict[str, str] | None = None) -> tuple[ReportContext, ReportDocument]:
    """Lineage maps candidate occurrence refs to baseline refs; no fuzzy joins.

    Revisions, rules, scopes, annotations, and selection remain explicit context.
    Neither matched verdict changes nor missing records imply a fixed issue.
    """
    before: dict[str, list[dict]] = {}
    after: dict[str, list[dict]] = {}
    for store, findings in ((before, baseline.findings), (after, candidate.findings)):
        for f in findings:
            store.setdefault(f["occurrence_ref"], []).append(f)
    mapping = lineage
    conflicting = set()
    if mapping is None:
        mapping = {}
        for field in ("raptor.lineage", "raptor.continuation_lineage"):
            recorded = candidate.extensions.get(field)
            if isinstance(recorded, dict):
                for ref, origin in recorded.items():
                    if (isinstance(origin, dict) and origin.get("snapshot_id") == baseline.snapshot_id
                            and ref in after and isinstance(origin.get("occurrence_ref"), str) and origin["occurrence_ref"] in before):
                        oldref = origin["occurrence_ref"]
                        if ref in mapping and mapping[ref] != oldref:
                            conflicting.add(ref)
                        else:
                            mapping[ref] = oldref
    if not isinstance(mapping, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in mapping.items()):
        raise ValueError("Lineage must map occurrence strings to occurrence strings")
    if any(ref not in after or old not in before for ref, old in mapping.items()):
        raise ValueError("Lineage contains an occurrence outside the selected snapshots")
    diagnostics = ["Delta shows recorded snapshot claims; absence does not establish a fix or disproof."]
    if (baseline.target != candidate.target or not baseline.extensions.get("raptor.scope")
            or not candidate.extensions.get("raptor.scope")
            or baseline.extensions.get("raptor.scope") != candidate.extensions.get("raptor.scope")):
        diagnostics.append("Scope differs or is not comparable; unmatched observations do not establish new or resolved issues")
    if baseline.completion_state != "completed" or candidate.completion_state != "completed":
        diagnostics.append("At least one snapshot is incomplete or has unknown completeness")
    if baseline.extensions.get("raptor.source_identity") != candidate.extensions.get("raptor.source_identity"):
        diagnostics.append("Source acquisition/revision identity differs; comparisons describe claims over differing inputs")
    rows = []
    matched: set[str] = set()
    related: set[str] = set()
    details = []
    # Include implicit exact matches: an explicit alias must not consume the
    # same baseline observation as another candidate's exact occurrence ref.
    reverse = Counter(mapping.get(ref, ref) for ref in after if mapping.get(ref, ref) in before)
    for ref, observations in after.items():
        oldref = mapping.get(ref, ref)
        old = before.get(oldref, [])
        if old:
            related.add(oldref)
        if ref in conflicting or len(observations) != 1 or len(old) > 1 or reverse[oldref] > 1:
            rows.append([ref, "uncertain match", "", ""])
            diagnostics.append(f"Ambiguous lineage for {ref}; no verdict comparison made")
            continue
        f = observations[0]
        if not old:
            rows.append([ref, "newly observed / unmatched", "", f.get("status", "Unknown")])
            continue
        matched.add(oldref)
        previous = old[0]
        changes = []
        for field in ("status", "severity", "file", "line", "suppressed", "verdict_origin", "message"):
            if previous.get(field) != f.get(field):
                changes.append(field)
                details.append({"occurrence": ref, "dimension": field,
                                "before": _preview(previous.get(field)), "after": _preview(f.get(field))})
        for field in ("native", "dataflow_path", "merge_decision", "diagnostics"):
            if previous.get(field) != f.get(field):
                changes.append("recorded evidence" if field == "native" else field)
                details.append({"occurrence": ref, "dimension": field,
                                "before": _preview(previous.get(field)), "after": _preview(f.get(field))})
        if changes:
            rows.append([ref, "changed: " + ", ".join(changes), previous.get("status", "Unknown"), f.get("status", "Unknown")])
    for ref, observations in before.items():
        if ref not in matched and ref not in related:
            rows.append([ref, "not observed / outside comparable scope", observations[0].get("status", "Unknown"), ""])
    context_changes = []
    for dimension, previous, current in _context_dimensions(baseline, candidate):
        if previous != current:
            context_changes.append({"dimension": dimension, "before": _preview(previous), "after": _preview(current)})
    context = ReportContext("delta", candidate.run_id, target=candidate.target, state="partial" if len(diagnostics) > 1 else "completed",
                            parents=[baseline.snapshot_id, candidate.snapshot_id], diagnostics=diagnostics,
                            extensions={"raptor.delta": {"baseline": baseline.snapshot_id, "candidate": candidate.snapshot_id,
                                                        "policy": "exact-occurrence-or-explicit-lineage/v1", "changes": rows,
                                                        "finding_changes": details, "context_changes": context_changes,
                                                        "lineage": mapping},
                                        "raptor.findings_available": False,
                                        "raptor.metrics": {"Baseline findings": len(baseline.findings), "Candidate findings": len(candidate.findings),
                                                           "Observation changes": len(rows), "Context/view changes": len(context_changes)}})
    block = Block("table", title="Observation changes", columns=["Occurrence", "Change", "Before", "After"], rows=rows)
    blocks = [block]
    if details:
        blocks.append(Block("code", title="Recorded finding changes", text=json.dumps(details, ensure_ascii=True, indent=2), language="json"))
    if context_changes:
        blocks.append(Block("code", title="Context and project view changes", text=json.dumps(context_changes, ensure_ascii=True, indent=2), language="json"))
    document = build_document(context, title="RAPTOR Snapshot Delta", blocks=blocks)
    document.metadata.update({"Baseline": baseline.snapshot_id, "Candidate": candidate.snapshot_id})
    document.summary = {"Baseline findings": len(baseline.findings), "Candidate findings": len(candidate.findings),
                        "Observation change records": len(rows), "Context/view changes": len(context_changes)}
    return context, document


def _preview(value):
    if value is None or isinstance(value, (bool, int, float)) or isinstance(value, str) and len(value) <= 500:
        return value
    result = {"sha256": digest(value), "kind": type(value).__name__}
    if isinstance(value, (dict, list, str)):
        result["entries_or_characters"] = len(value)
    if isinstance(value, str):
        result["preview"] = value[:500]
    result["note"] = "Full before/after data is referenced by the parent snapshots"
    return result


def _context_dimensions(baseline, candidate):
    yield "execution outcome", baseline.completion_state, candidate.completion_state
    for key in ("raptor.scope", "raptor.metrics", "raptor.accounting", "raptor.lifecycle", "raptor.source_identity", "raptor.input_selection"):
        yield key, baseline.extensions.get(key), candidate.extensions.get(key)
    bp, cp = baseline.extensions.get("raptor.project", {}), candidate.extensions.get("raptor.project", {})
    yield "project context", None if isinstance(bp, dict) else bp, None if isinstance(cp, dict) else cp
    bp, cp = (bp if isinstance(bp, dict) else {}), (cp if isinstance(cp, dict) else {})
    for key in ("selection", "merge_policy", "grouping_policy", "annotations", "annotation_digest", "readjudication"):
        yield "project " + key, bp.get(key), cp.get(key)
    def stages(context):
        from dataclasses import asdict
        return [asdict(s) for s in context.stages]
    yield "stage execution and coverage", stages(baseline), stages(candidate)
