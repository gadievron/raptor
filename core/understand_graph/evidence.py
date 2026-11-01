"""Project graph producers for web, fuzzing, SCA, and threat models.

These are memory of tool reports, not a second verification authority.
All imported edges remain hint-tier, even when a report says 'confirmed'.
JSON artifacts stay the public contract and graph failures are non-fatal.
"""

from __future__ import annotations

import logging
import hashlib
import os
from itertools import islice
from pathlib import Path
from typing import Any

from core.coverage.record import RUN_ARTIFACT_MAX_BYTES

from .ingest import (
    _artifact, _artifact_digest, _resolve_ingest_target, _upsert_edge,
    _upsert_node, _upsert_snapshot, load_json,
)
from .schema import EDGE_PROVENANCE_IMPORTED, short_hash, snapshot_id
from .store import INGEST_SKIP_EXCEPTIONS, graph_path_for_run, graph_write_txn

logger = logging.getLogger(__name__)
_MAX_RECORDS = 10000
_MAX_NODES = 10000
_MAX_EDGES = 20000
_MAX_WORK = 50000


def _rows(value: Any, key: str = "findings") -> tuple[list[dict], set[str]] | None:
    """Distinguish authoritative empty arrays from unavailable/junk reports."""
    if isinstance(value, dict):
        value = value.get(key)
    if not isinstance(value, list):
        return None
    rows = [row for row in value[:_MAX_RECORDS] if isinstance(row, dict)]
    if value and not rows:
        return None
    reasons = set()
    if len(value) > _MAX_RECORDS:
        reasons.add("record_limit")
    if len(rows) != min(len(value), _MAX_RECORDS):
        reasons.add("malformed_rows")
    return rows, reasons


def _bounded_graph(records, reasons):
    """Deduplicate identities and cap total work before any database writes.

    Limits apply across ALL roots and children, not once per parent. Web
    records are also deduplicated before their child lists are constructed.
    """
    nodes, edges = {}, {}
    work = 0

    def node(kind, key, props):
        identity = (kind, str(key))
        if identity not in nodes:
            if len(nodes) >= _MAX_NODES:
                reasons.add("node_limit")
                return None
            nodes[identity] = props
        return identity

    for kind, key, props, children in records:
        if work >= _MAX_WORK:
            reasons.add("work_limit")
            break
        work += 1
        parent = node(kind, key, props)
        if parent is None:
            continue
        for child_kind, child_key, child_props, relation in children:
            if work >= _MAX_WORK:
                reasons.add("work_limit")
                break
            work += 1
            if len(edges) >= _MAX_EDGES:
                reasons.add("edge_limit")
                break
            child = node(child_kind, child_key, child_props)
            if child is not None:
                edges[(parent, child, relation)] = None
    return nodes, edges, work


def _ingest(run_dir, target_path, lane, records, artifacts, graph_path=None, *,
            authoritative_empty=False, degradation=(), artifact_digests=None):
    """Replace this run's lane atomically; historical runs stay separate."""
    if not records and not authoritative_empty:
        return None
    run_dir = Path(run_dir)
    try:
        target = _resolve_ingest_target(run_dir, target_path, lane)
        if not target:
            return None
        path = Path(graph_path) if graph_path is not None else graph_path_for_run(run_dir, target)
        pinned_digests = artifact_digests or {}
        digests = [(p, pinned_digests[p] if p in pinned_digests else _artifact_digest(p))
                   for p in artifacts if p.is_file()]
        reasons = set(degradation)
        nodes, edges, work = _bounded_graph(records, reasons)
        snap = snapshot_id(target, lane, str(run_dir.resolve()))
        with graph_write_txn(path) as conn:
            _upsert_snapshot(conn, snap, target, run_dir, producer=lane)
            from .schema import json_dumps
            conn.execute("UPDATE snapshots SET props_json=? WHERE id=?", (json_dumps({
                "ingest": {"degraded": bool(reasons), "reasons": sorted(reasons),
                           "nodes": len(nodes), "edges": len(edges), "work": work},
            }), snap))
            ids = {}
            for (kind, key), props in nodes.items():
                ids[(kind, key)] = _upsert_node(conn, snap, kind, key, {
                    **props, "graph_evidence": {"source": lane, "trust": "imported"},
                })
            for parent, child, relation in edges:
                _upsert_edge(conn, snap, relation, ids[parent], ids[child],
                             provenance=EDGE_PROVENANCE_IMPORTED,
                             evidence={"source": lane, "run_dir": str(run_dir.resolve())})
            for artifact, digest in digests:
                _artifact(conn, snap, lane, artifact, run_dir, digest=digest)
        if reasons:
            logger.warning("graph %s enrichment degraded: %s", lane, ", ".join(sorted(reasons)))
        return path
    except (OSError, *INGEST_SKIP_EXCEPTIONS):
        logger.warning("graph %s enrichment skipped", lane, exc_info=True)
        return None


def ingest_web_evidence(run_dir: Path, target_path: str | None = None, *, graph_path=None):
    """Store endpoint findings and the web oracle's reported outcomes."""
    run_dir = Path(run_dir)
    findings_path = run_dir / "web_findings.json"
    outcomes_path = run_dir / "verified-outcomes.json"
    parsed_findings = _rows(load_json(findings_path))
    parsed_outcomes = _rows(load_json(outcomes_path), "outcomes")
    # A partial/malformed report is not authority to erase prior evidence.
    if parsed_findings is None or parsed_outcomes is None:
        logger.warning("graph web enrichment skipped: incomplete or malformed report pair")
        return None
    findings, reasons = parsed_findings
    outcomes, outcome_reasons = parsed_outcomes
    reasons |= outcome_reasons
    # Exact duplicates are harmless; conflicting reused IDs are ambiguous.
    # Keep those findings separately, without inventing N*M confirmations.
    unique_findings = {short_hash(f): f for f in findings}
    unique_outcomes = {short_hash(o): o for o in outcomes}
    by_id: dict[str, list[str]] = {}
    for digest, finding in unique_findings.items():
        ref = str(finding.get("id") or finding.get("finding_id") or digest)
        by_id.setdefault(ref, []).append(digest)
    by_finding: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for digest, outcome in unique_outcomes.items():
        outcome_ref = outcome.get("finding_id") or outcome.get("source_finding_id")
        if outcome_ref is not None:
            by_finding.setdefault(str(outcome_ref), []).append((digest, outcome))
    records = []
    for digest, finding in unique_findings.items():
        ref = str(finding.get("id") or finding.get("finding_id") or digest)
        ambiguous = len(by_id[ref]) > 1
        key = f"{ref}:{digest}" if ambiguous else ref
        if ambiguous:
            reasons.add("ambiguous_finding_id")
        url = str(finding.get("url") or finding.get("file") or target_path or "")
        children = [("entry_point", url, {"name": url, "file": url}, "HAS_SOURCE")]
        if not ambiguous:
            for outcome_key, outcome in by_finding.get(ref, []):
                children.append(("verified_outcome", outcome_key, outcome, "CONFIRMED_BY"))
        records.append(("finding", key, finding, children))
    # Preserve standalone outcomes too: reports need not carry a finding id.
    records.extend(("verified_outcome", key, o, []) for key, o in unique_outcomes.items())
    return _ingest(run_dir, target_path, "web", records,
                   [findings_path, outcomes_path], graph_path,
                   authoritative_empty=not findings and not outcomes, degradation=reasons)


def ingest_fuzz_evidence(run_dir: Path, target_path: str | None = None, *,
                         result: dict | None = None, graph_path=None):
    """Store campaign status and bounded witness manifests, never witness bytes."""
    run_dir = Path(run_dir)
    report = run_dir / "fuzzing-result.json"
    if result is None:
        result = load_json(report)
        if not isinstance(result, dict):
            report = run_dir / "fuzzing_report.json"
            result = load_json(report)
    if not isinstance(result, dict):
        return None
    children = []
    artifacts = [report]
    digests = {}
    reasons = set()
    manifest_bytes = 0
    # Bound directory enumeration before sorting, and charge actual bytes
    # read rather than a racy stat size. Pin their hashes to those same bytes.
    try:
        with os.scandir(run_dir / "witnesses" / "manifests") as directory:
            entries = list(islice(directory, _MAX_RECORDS + 1))
    except FileNotFoundError:
        entries = []
    except OSError:
        entries = []
        reasons.add("manifest_unreadable")
    if len(entries) > _MAX_RECORDS:
        reasons.add("manifest_entry_limit")
    from core.json import loads_bounded
    from core.security.capped_read import read_capped
    for entry in sorted(entries[:_MAX_RECORDS], key=lambda e: e.name):
        if not entry.name.endswith(".json"):
            continue
        path = Path(entry.path)
        remaining = RUN_ARTIFACT_MAX_BYTES - manifest_bytes
        if remaining <= 0:
            reasons.add("manifest_byte_limit")
            break
        raw = read_capped(path, max_bytes=remaining)
        if raw is None:
            reasons.add("manifest_read_refused")
            continue
        manifest_bytes += len(raw)
        try:
            witness = loads_bounded(raw, max_bytes=remaining)
        except (ValueError, RecursionError):
            reasons.add("malformed_manifest")
            continue
        if isinstance(witness, dict):
            children.append(("verified_outcome", path.stem, witness, "CONFIRMED_BY"))
            artifacts.append(path)
            digests[path] = hashlib.sha256(raw).hexdigest()
        else:
            reasons.add("malformed_manifest")
    return _ingest(run_dir, target_path, "fuzz",
                   [("tool_verdict", "campaign", result, children)], artifacts, graph_path,
                   degradation=reasons, artifact_digests=digests)


def ingest_sca_evidence(run_dir: Path, target_path: str | None = None, *, graph_path=None):
    """Store dependency identity, findings, and per-dependency reachability."""
    run_dir = Path(run_dir)
    artifact = run_dir / "findings.json"
    records = []
    parsed = _rows(load_json(artifact))
    if parsed is None:
        logger.warning("graph sca enrichment skipped: unavailable or malformed findings report")
        return None
    findings, reasons = parsed
    for finding in findings:
        sca = finding.get("sca")
        if not isinstance(sca, dict) or not sca.get("name"):
            continue
        key = str(sca.get("purl") or f"{sca.get('ecosystem', '')}:{sca['name']}@{sca.get('version', '')}")
        children = [("finding", str(finding.get("id") or short_hash(finding)), finding, "AFFECTS")]
        reach = sca.get("reachability")
        if isinstance(reach, dict):
            children.append(("tool_verdict", key + ":reachability", reach, "TESTED_BY"))
        records.append(("dependency", key, {**sca, "name": sca["name"]}, children))
    return _ingest(run_dir, target_path, "sca", records, [artifact], graph_path,
                   authoritative_empty=not findings, degradation=reasons)


def ingest_threat_model(run_dir: Path, target_path: str | None = None, *,
                        model: dict | None = None, source_path: Path | None = None,
                        graph_path=None):
    """Persist generated/operator threats with their assets and boundaries."""
    run_dir = Path(run_dir)
    artifact = Path(source_path) if source_path is not None else run_dir / "threat-model.json"
    if model is None:
        model = load_json(artifact)
    if not isinstance(model, dict):
        return None
    target = target_path or model.get("target")
    records = []
    # A single model root retains context even for an empty threat list.
    root_props = {"name": "threat-model", "source": model.get("source"), "summary": model.get("summary")}
    children = []
    for section, kind in (("assets", "asset"), ("trust_boundaries", "trust_boundary"),
                          ("entry_points", "entry_point"), ("threats", "threat")):
        values = model.get(section)
        for value in values[:_MAX_RECORDS] if isinstance(values, list) else []:
            props = value if isinstance(value, dict) else {"name": str(value)}
            key = str(props.get("id") or props.get("name") or short_hash(props))
            children.append((kind, key, props, "CONTAINS"))
    records.append(("tool_verdict", "threat-model", root_props, children))
    return _ingest(run_dir, target, "threat-model", records, [artifact], graph_path)
