"""Explicit observation grouping for a frozen project reporting view.

Existing origin/status/recency policy still picks the representation. Imported
identity claims, fuzzy locations, and missing snapshots never create group links.
"""
from collections import defaultdict
from pathlib import Path

from core.reporting.document import digest
from .merge import _finding_key


def local_history(directory, context, *, limit=32):
    """Read only explicitly pinned predecessors inside this selected directory.

    Do not discover generations, follow arbitrary source paths or imply that a
    later subset supersedes its parent. Returns oldest predecessors first.
    """
    from core.reporting.writer import load_report_generation
    directory = Path(directory)
    seen = {context.snapshot_id}
    history, diagnostics = [], []

    def visit(current):
        lifecycle = current.extensions.get("raptor.lifecycle")
        lifecycle = lifecycle if isinstance(lifecycle, dict) else {}
        checkpoints = []
        continuation = lifecycle.get("continuation")
        if isinstance(continuation, dict):
            checkpoints.append(continuation)
        for name in ("retry_of", "parent_execution"):
            relationship = lifecycle.get(name)
            if isinstance(relationship, dict) and (relationship.get("local") is True or relationship.get("directory") == str(directory)):
                checkpoints.append(relationship.get("checkpoint"))
        selection = current.extensions.get("raptor.input_selection")
        source = selection.get("source_checkpoint") if isinstance(selection, dict) else None
        if isinstance(source, dict) and (source.get("local") is True or source.get("directory") == str(directory.resolve())):
            checkpoints.append(source)
        for checkpoint in checkpoints:
            if not isinstance(checkpoint, dict):
                continue
            snapshot = checkpoint.get("snapshot_id")
            if not isinstance(snapshot, str) or snapshot in seen or snapshot not in current.parents:
                continue
            if len(seen) > limit:
                diagnostics.append("Local reporting history limit reached; earlier observations may be outside this view")
                return
            seen.add(snapshot)
            try:
                previous, _, manifest = load_report_generation(directory, checkpoint.get("generation"), snapshot)
            except (OSError, ValueError, TypeError):
                diagnostics.append("A pinned local predecessor is unavailable or inconsistent; earlier observations may be outside this view")
                continue
            visit(previous)
            history.append((directory / ".reporting" / manifest["generation"], previous))

    visit(context)
    return history, list(dict.fromkeys(diagnostics))


def grouping_keys(records_by_run, contexts, origins):
    observations = defaultdict(list)
    keys = {}
    for run, records in records_by_run.items():
        context = contexts.get(run)
        if context is None or origins.get(run):
            continue
        by_native = defaultdict(list)
        by_ref = {f["occurrence_ref"]: f for f in context.findings}
        for finding in context.findings:
            if isinstance(finding.get("native"), dict):
                by_native[digest(finding["native"])].append(finding)
        for index, raw in enumerate(records):
            matches = by_native.get(digest(raw), [])
            if not matches and context.kind in {"scan", "codeql"} and raw.get("report_snapshot_id") == context.snapshot_id:
                found = by_ref.get(raw.get("report_occurrence_ref"))
                matches = [found] if found and raw.get("file") == found.get("file") and raw.get("line") == found.get("line") else []
            if len(matches) == 1:
                f = matches[0]
                observations[f["occurrence_ref"]].append((run, index, raw, context, f))
    unique = {ref: rows[0] for ref, rows in observations.items() if len(rows) == 1}
    edges = {}
    diagnostics = []
    for ref, (_, _, raw, context, finding) in unique.items():
        lineage = context.extensions.get("raptor.lineage")
        continuation = context.extensions.get("raptor.continuation_lineage")
        link = lineage.get(ref) if isinstance(lineage, dict) else None
        if link is None and isinstance(continuation, dict):
            link = continuation.get(ref)
        if not isinstance(link, dict) or not isinstance(link.get("occurrence_ref"), str):
            continue
        if link["occurrence_ref"] not in unique:
            diagnostics.append("A recorded finding parent is unavailable or ambiguous in the selected project view; no grouping inferred")
            continue
        parent = unique[link["occurrence_ref"]]
        if link.get("snapshot_id") != parent[3].snapshot_id:
            diagnostics.append("A recorded finding parent snapshot is outside the selected project view; no grouping inferred")
            continue
        if finding.get("file") == parent[4].get("file") and finding.get("line") == parent[4].get("line"):
            edges[ref] = link["occurrence_ref"]
    for ref, (run, index, raw, _, _) in unique.items():
        current, seen = ref, set()
        while current in edges and current not in seen:
            seen.add(current)
            current = edges[current]
        if current in seen:
            diagnostics.append("Cyclic finding lineage retained as separate observations; no grouping inferred")
            continue
        keys[(run, index)] = _finding_key(unique[current][2])
    return keys, list(dict.fromkeys(diagnostics))
