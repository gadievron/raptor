"""Reporting projections of explicit lifecycle and import relationships.

All relationships are recorded claims, never authentication or verdict evidence.
Only the chosen input's adjacent committed snapshot is considered at import.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from pathlib import Path
import re

from core.json import save_json
from core.json.bounded import loads_bounded
from core.security.capped_read import read_capped
from core.run.metadata import load_run_metadata
from core.run.report_identity import valid_identity
from .document import digest
from .writer import load_committed_report, load_report_generation


def input_digest(data):
    try:
        return digest(data)
    except (ValueError, TypeError):
        return None


def apply_lifecycle(context, directory: Path, *, scope=None, metadata=None, producer_command: str | None = None):
    """Bind recorded identities; producer aliases require explicit adapter input."""
    metadata = load_run_metadata(directory) if metadata is None else metadata
    identity = metadata.get("reporting_identity") if isinstance(metadata, dict) else None
    if scope is not None:
        context.extensions["raptor.scope"] = scope
    expected_command = context.kind if producer_command is None else producer_command
    if not isinstance(expected_command, str) or not expected_command:
        raise ValueError("Lifecycle producer command must be a nonempty string")
    if not valid_identity(identity) or metadata.get("command") != expected_command:
        context.diagnostics.append("Lifecycle identity unavailable for this producer; pass/attempt lineage is unknown")
        return context
    context.run_id, context.pass_id, context.attempt_id = (identity[k] for k in ("run_id", "pass_id", "attempt_id"))
    context.extensions["raptor.lifecycle"] = deepcopy(identity)
    if producer_command is not None:
        context.extensions["raptor.lifecycle.producer_command"] = producer_command
    if identity.get("adopted_on_resume"):
        context.diagnostics.append("Legacy identity adopted on resume; prior pass/attempt lineage remains unknown")
    manifest = metadata.get("manifest") or {}
    context.extensions["raptor.source_identity"] = deepcopy(manifest.get("target")) if isinstance(manifest, dict) else None
    for finding in context.findings:
        old = finding.get("source_occurrence_ref") or finding["occurrence_ref"]
        finding["source_occurrence_ref"] = old
        finding["occurrence_ref"] = "occurrence:" + digest({"run": context.run_id, "pass": context.pass_id,
                                                             "attempt": context.attempt_id, "source": old})
    for stage in context.stages:
        stage.run_id, stage.pass_id, stage.attempt_id = context.run_id, context.pass_id, context.attempt_id
    continuation = identity.get("continuation")
    if isinstance(continuation, dict):
        try:
            previous, _, _ = load_report_generation(directory, continuation["generation"], continuation["snapshot_id"])
            if (previous.run_id, previous.pass_id, previous.attempt_id) != (context.run_id, context.pass_id, context.attempt_id):
                raise ValueError("Checkpoint lifecycle differs")
            context.parents.append(previous.snapshot_id)
            _link_same_attempt(context, previous)
        except (ValueError, TypeError, OSError, KeyError):
            context.diagnostics.append("Recorded resume checkpoint is unavailable or inconsistent; no continuation mapping inferred")
    for relationship in (identity.get("retry_of"), identity.get("parent_execution")):
        if isinstance(relationship, dict) and isinstance(relationship.get("checkpoint"), dict):
            parent = relationship["checkpoint"].get("snapshot_id")
            if isinstance(parent, str) and re.fullmatch(r"[a-f0-9]{64}", parent):
                context.parents.append(parent)
    context.parents = list(dict.fromkeys(context.parents))
    return context


def _site(finding):
    # These are normalized fields; arbitrary native aliases are not identity.
    return (finding.get("source_id"), finding.get("file"), finding.get("line"), finding.get("rule_id"))


def _link_same_attempt(context, previous):
    old = {_site(f): f for f in previous.findings}
    counts = Counter(_site(f) for f in previous.findings)
    current_counts = Counter(_site(f) for f in context.findings)
    links = context.extensions.setdefault("raptor.continuation_lineage", {})
    for finding in context.findings:
        key = _site(finding)
        if (key[0] or type(key[0]) is int) and counts[key] == current_counts[key] == 1:
            links[finding["occurrence_ref"]] = {"snapshot_id": previous.snapshot_id,
                                                 "occurrence_ref": old[key]["occurrence_ref"], "policy": "same-attempt-stable-producer-id-and-site/v1"}


def find_input_snapshot(source: Path, data):
    """Require exact canonical input content; never join by a fingerprint alone."""
    content_digest = input_digest(data)
    if not content_digest:
        return None
    try:
        context, _, manifest = load_committed_report(source.parent)
    except (OSError, ValueError, TypeError):
        return None
    matches = any(Path(a.get("path") or a.get("uri") or "").name == source.name
                  and a.get("canonical_digest") == content_digest for a in context.artifacts)
    if not matches and source.name == "findings.json" and context.kind == "validate":
        matches = input_digest(context.extensions.get("raptor.validation")) == content_digest
    if not matches:
        return None
    positions = {}
    artifact_digests = {a.get("digest") for a in context.artifacts
                        if Path(a.get("path") or a.get("uri") or "").name == source.name and a.get("canonical_digest") == content_digest}
    # Equal canonical content and basenames cannot choose a byte-distinct artifact.
    if len(artifact_digests) > 1:
        return None
    for finding in context.findings:
        ref = finding.get("source_occurrence_ref") or finding["occurrence_ref"]
        parts = ref.split(":")
        if len(parts) == 4 and parts[0] == "sarif" and parts[1] in artifact_digests and parts[2].isdigit() and parts[3].isdigit():
            positions[(int(parts[2]), int(parts[3]))] = {"snapshot_id": context.snapshot_id, "occurrence_ref": finding["occurrence_ref"]}
    return {"schema_version": 1, "snapshot_id": context.snapshot_id, "generation": manifest["generation"],
            "directory": str(source.parent.resolve()),
            "canonical_digest": content_digest, "source_name": source.name, "context": context, "positions": positions}


def bind_native_input(container, binding):
    rows = container.get("findings", [])
    candidates = {}
    if binding:
        for normalized in binding["context"].findings:
            raw = normalized.get("native")
            if isinstance(raw, dict):
                raw = {k: v for k, v in raw.items() if k != "_reporting_source"}
                key = input_digest(raw)
                if key:
                    candidates.setdefault(key, []).append(normalized)
    for finding in rows:
        if not isinstance(finding, dict):
            continue
        finding.pop("_reporting_source", None)
        matches = candidates.get(input_digest(finding), [])
        if len(matches) == 1:
            finding["_reporting_source"] = {"snapshot_id": binding["snapshot_id"], "occurrence_ref": matches[0]["occurrence_ref"]}


def write_input_selection(directory, container, binding, *, source_path=None):
    destination = Path(directory) / "reporting-input.json"
    if source_path is not None and Path(source_path).resolve() == destination.resolve():
        raise ValueError("Reporting input selection must not replace the source findings file")
    selection = []
    for finding in container.get("findings", []):
        if isinstance(finding, dict) and isinstance(finding.get("_reporting_source"), dict):
            selection.append({"id": finding.get("id"), "file": finding.get("file"), "line": finding.get("line"),
                              "source": finding["_reporting_source"]})
    record = {"schema_version": 1, "mode": "selected-findings", "source_snapshot": binding["snapshot_id"] if binding else None,
              "source_checkpoint": ({**{k: binding[k] for k in ("directory", "generation", "snapshot_id")},
                                     "local": binding["directory"] == str(Path(directory).resolve())} if binding else None),
              "selection": selection, "input_rows": len(container.get("findings", [])),
              "identity_policy": "exact-input-content-and-recorded-occurrence/v1"}
    metadata = load_run_metadata(Path(directory))
    identity = metadata.get("reporting_identity") if isinstance(metadata, dict) else None
    record["owner"] = {k: identity[k] for k in ("run_id", "pass_id", "attempt_id")} if valid_identity(identity) else None
    save_json(destination, record)
    return record


def clear_input_selection(directory):
    """A new inventory invocation must not inherit a prior selected-input scope.

    Unlink only this generated marker; a symlink is removed without following it.
    """
    (Path(directory) / "reporting-input.json").unlink(missing_ok=True)


def apply_input_selection(context, directory):
    limit = 8 * 1024 * 1024
    try:
        raw = read_capped(Path(directory) / "reporting-input.json", limit, raise_on_refusal=True)
    except FileNotFoundError:
        return
    except (ValueError, OSError):
        context.diagnostics.append("Input-selection record refused by safe reader; finding lineage is unknown")
        return
    try:
        record = loads_bounded(raw, max_bytes=limit)
    except (ValueError, RecursionError, UnicodeDecodeError):
        context.diagnostics.append("Invalid input-selection record ignored; finding lineage is unknown")
        return
    if (not isinstance(record, dict) or type(record.get("schema_version")) is not int or record.get("schema_version") != 1
            or record.get("mode") != "selected-findings" or record.get("identity_policy") != "exact-input-content-and-recorded-occurrence/v1"):
        return
    owner = record.get("owner")
    current_owner = {"run_id": context.run_id, "pass_id": context.pass_id, "attempt_id": context.attempt_id} if context.pass_id else None
    if owner != current_owner:
        context.diagnostics.append("Input-selection record belongs to another lifecycle; no lineage reused")
        return
    context.extensions["raptor.input_selection"] = record
    context.extensions["raptor.scope"] = {"mode": "selected-findings", "target": context.target,
                                         "source_snapshot": record.get("source_snapshot"), "selection": record.get("selection", [])}
    if not isinstance(record.get("source_snapshot"), str) or not re.fullmatch(r"[a-f0-9]{64}", record["source_snapshot"]):
        context.diagnostics.append("Selected input has no matching committed source snapshot; finding lineage is unknown")
        return
    context.parents = list(dict.fromkeys([*context.parents, record["source_snapshot"]]))
    selected = record.get("selection", [])
    if isinstance(selected, list) and type(record.get("input_rows")) is int and record["input_rows"] > len(selected):
        context.diagnostics.append(f"{record['input_rows'] - len(selected)} selected input observation(s) have unknown occurrence lineage")
    by_id = {}
    for row in selected if isinstance(selected, list) else []:
        if isinstance(row, dict) and isinstance(row.get("id"), str):
            by_id.setdefault(row.get("id"), []).append(row)
    links = context.extensions.setdefault("raptor.lineage", {})
    for finding in context.findings:
        candidates = by_id.get(finding.get("source_id"), [])
        if len(candidates) != 1:
            continue
        row = candidates[0]
        source = row.get("source")
        if (row.get("file") == finding.get("file") and (row.get("line") or None) == finding.get("line")
                and isinstance(source, dict) and source.get("snapshot_id") == record["source_snapshot"] and isinstance(source.get("occurrence_ref"), str)):
            links[finding["occurrence_ref"]] = {**row["source"], "policy": record["identity_policy"]}
