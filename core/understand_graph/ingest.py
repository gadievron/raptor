"""Ingest /understand artefacts into the internal graph store."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any, Iterable, Optional

from core.json import load_json as _load_json_uncapped
from core.security.capped_read import read_capped

# Run-dir artifacts are producer-written but live beside scanned-tree
# output; a runaway or hostile artifact must cost a skipped ingest,
# not memory. Same ceiling as the coverage readers
# (core.coverage.record.RUN_ARTIFACT_MAX_BYTES).
from core.coverage.record import RUN_ARTIFACT_MAX_BYTES as _ARTIFACT_MAX_BYTES


def load_json(path, **kwargs):
    """Module-wide capped load_json: every ingest reader takes the
    shared run-artifact budget unless the caller overrides it."""
    kwargs.setdefault("max_bytes", _ARTIFACT_MAX_BYTES)
    return _load_json_uncapped(path, **kwargs)


from .schema import (
    content_hash,
    function_ref,
    json_dumps,
    short_hash,
    snapshot_id as make_snapshot_id,
    stable_edge_id,
    stable_key,
    stable_node_id,
    utc_now_iso,
)
from .store import (
    INGEST_SKIP_EXCEPTIONS,
    graph_path_for_run,
    graph_sidecar_paths,
    graph_write_txn,
    open_graph,
    remove_graph_db,
)


def ingest_run(run_dir: Path, target_path: Optional[str] = None,
               *, graph_path: Optional[Path] = None) -> Optional[Path]:
    """Best-effort ingest of a run directory.

    Returns the graph path when something was ingested, otherwise
    ``None``. Sibling envelope like every newer producer: shape
    guards, one immediate transaction, junk artifacts cost a skipped
    ingest — never a crash into the caller. ``graph_path`` pins the
    destination store (rebuild uses it); default resolution rides
    :func:`graph_path_for_run`.
    """
    run_dir = Path(run_dir)
    checklist = load_json(run_dir / "checklist.json")
    if not isinstance(checklist, dict):
        # A junk-shaped checklist is not a reason to drop the other
        # artifacts — but it must never reach .get() calls.
        checklist = {}
    context_map = load_json(run_dir / "context-map.json")
    variants = load_json(run_dir / "variants.json")
    trace_paths = sorted(run_dir.glob("flow-trace-*.json"))
    result_paths = [run_dir / "hunt-result.json", run_dir / "trace-result.json"]

    if not any([isinstance(context_map, dict), isinstance(variants, (dict, list)), trace_paths, any(p.exists() for p in result_paths)]):
        return None

    target = str(
        target_path
        or checklist.get("target_path")
        or (context_map or {}).get("meta", {}).get("target", "")
        or ""
    )
    if graph_path is None:
        graph_path = graph_path_for_run(run_dir, target or None)
    checklist_hash = _hash_json(checklist)
    snap_id = make_snapshot_id(target, checklist_hash, str(run_dir.resolve()))

    # Load artifact JSON and compute sha256 digests BEFORE opening the
    # write transaction: multi-second file reads/hashes inside it hold
    # the write lock against every concurrent reader for their whole
    # duration.
    traces = [(tp, load_json(tp)) for tp in trace_paths]
    results = [(rp, load_json(rp)) for rp in result_paths]
    digests = {
        path: _artifact_digest(path)
        for path in [
            run_dir / "context-map.json",
            *trace_paths,
            run_dir / "variants.json",
            *result_paths,
        ]
        if path.exists()
    }

    try:
        with graph_write_txn(graph_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO snapshots
                (id, target_path, target_hash, git_sha, checklist_hash, created_at, producer_run, props_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snap_id,
                    target,
                    _target_hash(checklist),
                    str(checklist.get("git_sha") or checklist.get("commit") or ""),
                    checklist_hash,
                    utc_now_iso(),
                    str(run_dir.resolve()),
                    json_dumps({"total_files": checklist.get("total_files"), "total_items": checklist.get("total_items")}),
                ),
            )
            _ingest_checklist(conn, snap_id, checklist)
            if isinstance(context_map, dict):
                _ingest_context_map(conn, snap_id, context_map)
                cm_path = run_dir / "context-map.json"
                _artifact(conn, snap_id, "context_map", cm_path, run_dir,
                          digest=digests.get(cm_path, ""))
            for trace_path, trace in traces:
                if isinstance(trace, dict):
                    _ingest_flow_trace(conn, snap_id, trace)
                    _artifact(conn, snap_id, "flow_trace", trace_path, run_dir,
                              digest=digests.get(trace_path, ""))
            if variants is not None:
                _ingest_variants(conn, snap_id, variants)
                v_path = run_dir / "variants.json"
                _artifact(conn, snap_id, "variants", v_path, run_dir,
                          digest=digests.get(v_path, ""))
            for path, result in results:
                if isinstance(result, dict):
                    _ingest_multimodel_result(conn, snap_id, result)
                    _artifact(conn, snap_id, result.get("mode") or path.stem, path, run_dir,
                              digest=digests.get(path, ""))
    except INGEST_SKIP_EXCEPTIONS as exc:
        print(f"graph: understand ingest skipped ({exc})", file=sys.stderr)
        return None
    return graph_path


def _hash_json(value: Any) -> str:
    return hashlib.sha256(json_dumps(value).encode("utf-8", "surrogateescape")).hexdigest()


def _target_hash(checklist: dict[str, Any]) -> str:
    file_hashes = []
    for f in checklist.get("files") or []:
        if isinstance(f, dict) and f.get("path") and f.get("sha256"):
            file_hashes.append((f["path"], f["sha256"]))
    return _hash_json(file_hashes)


def _upsert_node(conn, snapshot_id: str, kind: str, key: str, props: dict[str, Any]) -> str:
    file = str(props.get("file") or props.get("path") or "")
    line = _int_or_none(props.get("line") or props.get("line_start") or props.get("start_line"))
    line_end = _int_or_none(props.get("line_end") or props.get("end_line"))
    name = str(props.get("name") or props.get("id") or props.get("entry") or props.get("type") or "")
    node_id = stable_node_id(kind, snapshot_id, key)
    node_stable_key = stable_key(kind, key)
    conn.execute(
        """
        INSERT INTO nodes (id, kind, stable_key, name, file, line_start, line_end, snapshot_id, props_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            kind=excluded.kind,
            stable_key=excluded.stable_key,
            name=excluded.name,
            file=excluded.file,
            line_start=excluded.line_start,
            line_end=excluded.line_end,
            snapshot_id=excluded.snapshot_id,
            stale=0,
            props_json=excluded.props_json
        """,
        (node_id, kind, node_stable_key, name, file, line, line_end, snapshot_id, json_dumps(props)),
    )
    return node_id


def _upsert_edge(conn, snapshot_id: str, kind: str, src_id: str, dst_id: str, *, confidence: str = "", evidence: Any = None, props: Any = None) -> str:
    edge_id = stable_edge_id(kind, src_id, dst_id, evidence or props or "")
    conn.execute(
        """
        INSERT INTO edges (id, src_id, dst_id, kind, confidence, snapshot_id, evidence_json, props_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            confidence=excluded.confidence,
            snapshot_id=excluded.snapshot_id,
            stale=0,
            evidence_json=excluded.evidence_json,
            props_json=excluded.props_json
        """,
        (edge_id, src_id, dst_id, kind, confidence, snapshot_id, json_dumps(evidence), json_dumps(props)),
    )
    return edge_id


def _graph_evidence(source: str, section: str, item: dict[str, Any], *, confidence: str = "") -> dict[str, Any]:
    return {
        "oracle": "understand",
        "source": source,
        "section": section,
        "confidence": confidence or str(item.get("confidence") or item.get("severity") or "candidate"),
        "confirmed": bool(item.get("confirmed")),
        "reproducible": False,
        "cwe": item.get("cwe") or item.get("cwe_id") or item.get("cwes") or [],
    }


def _with_graph_evidence(source: str, section: str, item: dict[str, Any]) -> dict[str, Any]:
    props = dict(item)
    props.setdefault("graph_evidence", _graph_evidence(source, section, props))
    return props


def _ingest_checklist(conn, snapshot_id: str, checklist: dict[str, Any]) -> None:
    for f in checklist.get("files") or []:
        if not isinstance(f, dict):
            continue
        path = f.get("path")
        if not path:
            continue
        file_id = _upsert_node(conn, snapshot_id, "file", path, f)
        for item in (f.get("items") or f.get("functions") or []):
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not name:
                continue
            props = dict(item)
            props.setdefault("file", path)
            fn_id = _upsert_node(conn, snapshot_id, "function", function_ref(path, name), props)
            _upsert_edge(conn, snapshot_id, "CONTAINS", file_id, fn_id)


def _ingest_context_map(conn, snapshot_id: str, context_map: dict[str, Any]) -> None:
    ids: dict[str, str] = {}
    for kind, section in (
        ("entry_point", "entry_points"),
        ("source", "sources"),
        ("trust_boundary", "trust_boundaries"),
        ("trust_boundary", "boundary_details"),
        ("sink", "sinks"),
        ("sink", "sink_details"),
        ("finding", "hardcoded_secrets"),
    ):
        for entry in _list(context_map.get(section)):
            key = entry.get("id") or entry.get("name") or entry.get("entry") or entry.get("location") or short_hash(entry)
            props = _with_graph_evidence("context-map.json", section, entry)
            props["_context_section"] = section
            node_id = _upsert_node(conn, snapshot_id, kind, key, props)
            if entry.get("id"):
                ids[str(entry["id"])] = node_id

    for i, flow in enumerate(_list(context_map.get("unchecked_flows"))):
        key = flow.get("id") or f"unchecked-flow-{i + 1}:{flow.get('entry_point')}->{flow.get('sink')}"
        flow_props = _with_graph_evidence("context-map.json", "unchecked_flows", flow)
        flow_id = _upsert_node(conn, snapshot_id, "unchecked_flow", key, flow_props)
        entry_id = ids.get(str(flow.get("entry_point") or ""))
        sink_id = ids.get(str(flow.get("sink") or ""))
        evidence = _graph_evidence("context-map.json", "unchecked_flows", flow)
        evidence["flow"] = flow
        if entry_id:
            _upsert_edge(conn, snapshot_id, "HAS_SOURCE", flow_id, entry_id, evidence=evidence)
        if sink_id:
            _upsert_edge(conn, snapshot_id, "HAS_SINK", flow_id, sink_id, evidence=evidence)
        if entry_id and sink_id:
            _upsert_edge(
                conn,
                snapshot_id,
                "REACHES",
                entry_id,
                sink_id,
                evidence=evidence,
                confidence=str(flow.get("confidence") or flow.get("severity") or "candidate"),
            )

    # Dependency imports — create dependency nodes + IMPORTS edges.
    for imp in _list(context_map.get("imports")):
        module = imp.get("module") or imp.get("name")
        imp_file = imp.get("file") or ""
        if not module:
            continue
        dep_id = _upsert_node(conn, snapshot_id, "dependency", module, {
            "name": module, "file": imp_file,
            "line": imp.get("line"),
        })
        file_key = stable_key("file", imp_file)
        file_row = conn.execute(
            "SELECT id FROM nodes WHERE stable_key=? AND stale=0 LIMIT 1",
            (file_key,),
        ).fetchone()
        if file_row:
            _upsert_edge(conn, snapshot_id, "IMPORTS", file_row["id"], dep_id,
                          evidence={"source": "context-map.json", "section": "imports"})


def _ingest_flow_trace(conn, snapshot_id: str, trace: dict[str, Any]) -> None:
    trace_props = _with_graph_evidence("flow-trace", "flow_trace", trace)
    trace_id = _upsert_node(conn, snapshot_id, "flow_trace", trace.get("id") or trace.get("name") or short_hash(trace), trace_props)
    prev = trace_id
    for step in _list(trace.get("steps")):
        key = f"{trace.get('id', 'trace')}::{step.get('step')}::{step.get('definition') or step.get('call_site') or short_hash(step)}"
        step_props = _with_graph_evidence("flow-trace", "steps", step)
        step_id = _upsert_node(conn, snapshot_id, "trace_step", key, step_props)
        _upsert_edge(conn, snapshot_id, "DERIVED_FROM", step_id, trace_id, evidence=step_props)
        if prev != trace_id:
            _upsert_edge(conn, snapshot_id, "REACHES", prev, step_id, evidence=step_props, confidence=str(step.get("confidence") or ""))
        prev = step_id


def _ingest_variants(conn, snapshot_id: str, variants: Any) -> None:
    items: Iterable[Any]
    if isinstance(variants, dict):
        items = variants.get("variants") or variants.get("items") or variants.get("matches") or []
    elif isinstance(variants, list):
        items = variants
    else:
        items = []
    for i, item in enumerate(items):
        if isinstance(item, dict):
            props = _with_graph_evidence("variants.json", "variants", item)
            _upsert_node(conn, snapshot_id, "variant", item.get("id") or item.get("file") or f"variant-{i + 1}", props)


def _ingest_multimodel_result(conn, snapshot_id: str, result: dict[str, Any]) -> None:
    mode = result.get("mode") or "understand"
    for i, item in enumerate(result.get("items") or []):
        if isinstance(item, dict):
            kind = "variant" if mode == "hunt" else "flow_trace"
            props = _with_graph_evidence(f"{mode}-result", "items", item)
            _upsert_node(conn, snapshot_id, kind, item.get("id") or f"{mode}-{i + 1}", props)


def _artifact_digest(path: Path) -> str:
    """sha256 of an artifact file, bounded by the shared budget
    (oversized/unreadable degrade to an empty digest)."""
    raw = read_capped(path, _ARTIFACT_MAX_BYTES)
    if raw is None:
        return ""
    return hashlib.sha256(raw).hexdigest()


def _artifact(conn, snapshot_id: str, kind: str, path: Path, run_dir: Path,
              digest: str | None = None) -> None:
    """Record an artifact row. Pass ``digest`` when calling inside a
    write transaction — hashing the file there holds the write lock
    through the whole read."""
    if not path.exists():
        return
    if digest is None:
        digest = _artifact_digest(path)
    conn.execute(
        """
        INSERT OR REPLACE INTO artifacts
        (id, kind, path, run_dir, snapshot_id, sha256, created_at, props_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            f"artifact:{short_hash(str(path.resolve()))}",
            kind,
            str(path.resolve()),
            str(run_dir.resolve()),
            snapshot_id,
            digest,
            utc_now_iso(),
            "{}",
        ),
    )


def ingest_scan_findings(run_dir: Path, target_path: Optional[str] = None,
                         *, graph_path: Optional[Path] = None) -> Optional[Path]:
    """Ingest /scan or /agentic findings into the graph.

    Creates scan_finding nodes linked to function nodes via AFFECTS edges.
    Reads findings.json — the findings artifact scan-family runs write.
    """
    run_dir = Path(run_dir)
    findings = load_json(run_dir / "findings.json")
    if not findings or not isinstance(findings, list):
        return None

    target = _resolve_ingest_target(run_dir, target_path, "scan")
    if not target:
        return None
    if graph_path is None:
        graph_path = graph_path_for_run(run_dir, target or None)
    checklist_hash = _hash_json(findings)
    snap_id = make_snapshot_id(target, checklist_hash, str(run_dir.resolve()))

    try:
        with graph_write_txn(graph_path) as conn:
            _upsert_snapshot(conn, snap_id, target, run_dir, producer="scan")
            for f in _list(findings):
                fn_name = str(f.get("function") or f.get("name") or "?")
                file_path = str(f.get("file") or f.get("path") or "?")
                key = f"{f.get('rule_id', '?')}::{file_path}::{fn_name}::{content_hash(f)}"
                node_id = _upsert_node(conn, snap_id, "scan_finding", key, f)
                fn_key = stable_key("function", function_ref(file_path, fn_name))
                fn_row = conn.execute(
                    "SELECT id FROM nodes WHERE stable_key=? AND stale=0 LIMIT 1",
                    (fn_key,),
                ).fetchone()
                if fn_row:
                    _upsert_edge(conn, snap_id, "AFFECTS", node_id, fn_row["id"])
    except INGEST_SKIP_EXCEPTIONS as exc:
        print(f"graph: scan ingest skipped ({exc})", file=sys.stderr)
        return None
    return graph_path


def ingest_codeql_sarif(run_dir: Path, target_path: Optional[str] = None,
                        *, graph_path: Optional[Path] = None) -> Optional[Path]:
    """Ingest CodeQL SARIF results into the graph.

    Creates codeql_result nodes. SARIF codeFlows are mapped to TAINTS edges.
    """
    run_dir = Path(run_dir)
    sarif_paths = sorted(run_dir.glob("*.sarif")) + sorted(run_dir.glob("*.sarif.json"))
    if not sarif_paths:
        return None

    target = _resolve_ingest_target(run_dir, target_path, "codeql")
    if not target:
        return None
    if graph_path is None:
        graph_path = graph_path_for_run(run_dir, target or None)
    ingested = False

    for sarif_path in sarif_paths:
        sarif = load_json(sarif_path)
        if not isinstance(sarif, dict):
            continue
        for run_data in sarif.get("runs") or []:
            if not isinstance(run_data, dict):
                continue
            results = run_data.get("results") or []
            if not results:
                continue
            snap_id = make_snapshot_id(target, _hash_json(results), str(sarif_path.resolve()))
            try:
                with graph_write_txn(graph_path) as conn:
                    _upsert_snapshot(conn, snap_id, target, run_dir, producer="codeql")
                    for result in results:
                        if not isinstance(result, dict):
                            continue
                        _ingest_sarif_result(conn, snap_id, result)
                ingested = True
            except INGEST_SKIP_EXCEPTIONS as exc:
                print(f"graph: codeql ingest skipped ({exc})", file=sys.stderr)
                continue
    return graph_path if ingested else None


def ingest_validation_outcomes(run_dir: Path, target_path: Optional[str] = None,
                               *, graph_path: Optional[Path] = None) -> Optional[Path]:
    """Ingest /validate outcomes into the graph.

    Creates verified_outcome nodes linked to findings via VALIDATES edges.
    """
    run_dir = Path(run_dir)
    outcomes = load_json(run_dir / "validation-outcomes.json")
    if not outcomes or not isinstance(outcomes, list):
        return None

    target = _resolve_ingest_target(run_dir, target_path, "validation")
    if not target:
        return None
    if graph_path is None:
        graph_path = graph_path_for_run(run_dir, target or None)
    snap_id = make_snapshot_id(target, _hash_json(outcomes), str(run_dir.resolve()))

    try:
        with graph_write_txn(graph_path) as conn:
            _upsert_snapshot(conn, snap_id, target, run_dir, producer="validate")
            for outcome in _list(outcomes):
                status = str(outcome.get("status") or outcome.get("verdict") or "inconclusive")
                finding_ref = outcome.get("finding_id") or outcome.get("finding") or ""
                key = f"{status}::{finding_ref}::{content_hash(outcome)}"
                props = dict(outcome)
                props["status"] = status
                vo_id = _upsert_node(conn, snap_id, "verified_outcome", key, props)
                if finding_ref:
                    # Exact-identity join, never substring LIKE: a short
                    # or numeric finding id used to substring-match an
                    # unrelated unchecked_flow, minting a VALIDATES edge
                    # that falsely suppressed a never-validated path from
                    # coverage_residual (the query-side comment there
                    # names this exact idiom). Identity = the composed
                    # stable_key or a props-extracted id; a rule id shared
                    # across findings is NOT an identity, so no exact
                    # match mints no edge.
                    ref = str(finding_ref)
                    for kind in ("scan_finding", "codeql_result", "unchecked_flow"):
                        row = conn.execute(
                            """
                            SELECT id FROM nodes
                            WHERE kind=? AND stale=0
                              AND (stable_key=?
                                   OR json_extract(props_json, '$.id')=?
                                   OR json_extract(props_json, '$.finding_id')=?)
                            LIMIT 1
                            """,
                            (kind, stable_key(kind, ref), ref, ref),
                        ).fetchone()
                        if row:
                            _upsert_edge(conn, snap_id, "VALIDATES", vo_id, row["id"])
    except INGEST_SKIP_EXCEPTIONS as exc:
        print(f"graph: validation ingest skipped ({exc})", file=sys.stderr)
        return None
    return graph_path


def ingest_audit_hypotheses(run_dir: Path, target_path: Optional[str] = None,
                            *, graph_path: Optional[Path] = None) -> Optional[Path]:
    """Ingest /audit review-journal rows into the graph.

    The vocabulary is derived from the journal's REAL producer
    (core.coverage.journal.ReviewJournalEntry via append_entry):
    hypotheses live in each row's nested ``hypotheses`` list and tool
    receipts in ``evidence_tools``. The pre-fix dispatch keyed on a
    ``type``/``kind`` field no producer writes, so every real journal
    ingested 0 nodes while still committing an empty producer='audit'
    snapshot — the only rows it COULD ingest were planted ones.

    Rows load through the journal subsystem's own tolerant reader
    (per-row quarantine — a torn tail from an interrupted append
    costs that row, never the whole ingest; size-capped like every
    other run-artifact read) and each minted node records the row's
    MAC provenance (verified / unstamped / tampered) so
    authority-tier consumers can filter; the graph's own grain is
    hint-tier prompt seeding. When nothing review-shaped ingests, the
    snapshot upsert rolls back — no junk empty snapshots in
    snapshot-ordered consumers.
    """
    from core.coverage import journal_mac
    from core.coverage.journal import JOURNAL_FILENAME, load_entries

    run_dir = Path(run_dir)
    if not (run_dir / JOURNAL_FILENAME).exists():
        return None

    target = _resolve_ingest_target(run_dir, target_path, "audit")
    if not target:
        return None
    if graph_path is None:
        graph_path = graph_path_for_run(run_dir, target or None)

    entries = load_entries(run_dir)
    if not entries:
        return None

    snap_id = make_snapshot_id(
        target, _hash_json([e.to_dict() for e in entries]),
        str(run_dir.resolve()),
    )
    minted = 0
    conn = open_graph(graph_path)
    conn.isolation_level = None
    try:
        conn.execute("BEGIN IMMEDIATE")
        _upsert_snapshot(conn, snap_id, target, run_dir, producer="audit")
        for entry in entries:
            minted += _ingest_journal_row(
                conn, snap_id, entry, journal_mac.entry_provenance(entry))
        if not minted:
            conn.execute("ROLLBACK")
            return None
        conn.execute("COMMIT")
    except (sqlite3.Error, KeyError, TypeError, ValueError) as exc:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        print(f"graph: audit ingest skipped ({exc})", file=sys.stderr)
        return None
    finally:
        conn.close()
    return graph_path


def _ingest_journal_row(conn, snap_id: str, entry: Any, provenance: str) -> int:
    """Mint hypothesis + tool_verdict nodes from ONE producer row.

    Returns the number of nodes minted. Producer shape:
    ``hypotheses`` is a list of ``{mechanism, confidence, ...}``
    dicts; ``evidence_tools`` names the tools whose OUTPUT the
    verdict carries (the confirming receipt — never the dispatched
    union).
    """
    minted = 0
    fn_ref = function_ref(entry.file, entry.function)
    fn_key = stable_key("function", fn_ref)
    fn_row = conn.execute(
        "SELECT id FROM nodes WHERE stable_key=? AND stale=0 LIMIT 1",
        (fn_key,),
    ).fetchone()

    hyp_ids: list[str] = []
    for hypothesis in entry.hypotheses or []:
        if not isinstance(hypothesis, dict):
            continue
        mechanism = str(
            hypothesis.get("mechanism")
            or hypothesis.get("text")
            or hypothesis.get("description")
            or ""
        ).strip()
        if not mechanism:
            continue
        cwe = str(hypothesis.get("cwe") or entry.cwe or "")
        key = f"{fn_ref}::{cwe}::{short_hash(mechanism, length=12)}"
        hyp_id = _upsert_node(conn, snap_id, "hypothesis", key, {
            "function": entry.function,
            "file": entry.file,
            "cwe": cwe,
            "description": mechanism,
            "confidence": str(hypothesis.get("confidence") or ""),
            "status": entry.verdict,
            "run_id": entry.run_id,
            "mac_provenance": provenance,
        })
        minted += 1
        hyp_ids.append(hyp_id)
        if fn_row:
            _upsert_edge(conn, snap_id, "AFFECTS", hyp_id, fn_row["id"])

    for tool in entry.evidence_tools or []:
        tool_name = str(tool).strip()
        if not tool_name:
            continue
        key = (f"{tool_name}::{fn_ref}::"
               f"{short_hash(f'{entry.ts}::{entry.verdict}', length=12)}")
        tv_id = _upsert_node(conn, snap_id, "tool_verdict", key, {
            "tool": tool_name,
            "verdict": entry.verdict,
            "function": entry.function,
            "file": entry.file,
            "run_id": entry.run_id,
            "mac_provenance": provenance,
        })
        minted += 1
        # Direct-id edges: the receipt and the hypotheses share the
        # row, so no lookup (and no substring join) is ever needed.
        for hyp_id in hyp_ids:
            _upsert_edge(conn, snap_id, "TESTED_BY", hyp_id, tv_id)
    return minted


# ---------------------------------------------------------------------------
# Private helpers for new producers
# ---------------------------------------------------------------------------


def _upsert_snapshot(conn, snap_id: str, target: str, run_dir: Path, *, producer: str = "understand") -> None:
    conn.execute(
        """
        INSERT OR REPLACE INTO snapshots
        (id, target_path, target_hash, git_sha, checklist_hash, created_at, producer_run, props_json, producer)
        VALUES (?, ?, '', '', '', ?, ?, '{}', ?)
        """,
        (snap_id, target, utc_now_iso(), str(run_dir.resolve()), producer),
    )


def _resolve_ingest_target(run_dir: Path, target_path: Optional[str],
                           lane: str) -> str:
    """Resolve a findings-shaped lane's target; refuse empty loudly.

    A snapshot with ``target_path=''`` is unmatchable by every
    target-scoped query (see :func:`_infer_run_target`) — better to
    skip the ingest than to mint invisible memory. Returns '' after
    printing the skip message.
    """
    target = str(target_path or _infer_run_target(run_dir))
    if not target:
        print(
            f"graph: {lane} ingest skipped (no target resolvable for "
            f"{run_dir.name})",
            file=sys.stderr,
        )
    return target


def _infer_run_target(run_dir: Path) -> str:
    """Best-effort target path for a run dir when the caller passed
    none: the run's own lifecycle metadata first, then the checklist /
    context-map. Ingesting a snapshot with target '' makes it
    unmatchable by every target-scoped query — the run's memory is
    then invisible exactly where it should answer.
    """
    from core.run.metadata import RUN_METADATA_FILE

    meta = load_json(run_dir / RUN_METADATA_FILE)
    if isinstance(meta, dict) and meta.get("target_path"):
        return str(meta["target_path"])
    checklist = load_json(run_dir / "checklist.json")
    if isinstance(checklist, dict) and checklist.get("target_path"):
        return str(checklist["target_path"])
    context_map = load_json(run_dir / "context-map.json")
    if isinstance(context_map, dict):
        target = (context_map.get("meta") or {}).get("target")
        if target:
            return str(target)
    return ""


def _ingest_sarif_result(conn, snap_id: str, result: dict[str, Any]) -> None:
    rule_id = result.get("ruleId") or ""
    rule_obj = result.get("rule")
    if not rule_id and isinstance(rule_obj, dict):
        rule_id = rule_obj.get("id") or ""
    rule_id = rule_id or "?"

    locations = result.get("locations") or []
    loc = locations[0] if locations else {}
    phys = (loc.get("physicalLocation") or {}) if isinstance(loc, dict) else {}
    art = phys.get("artifactLocation") or {}
    region = phys.get("region") or {}
    file_path = art.get("uri") or ""
    line = region.get("startLine")
    message = (result.get("message") or {}).get("text") or ""

    fingerprints = result.get("partialFingerprints") or {}
    fp = (
        fingerprints.get("primaryLocationLineHash")
        or fingerprints.get("primaryLocationStartColumnFingerprint")
        or content_hash({"message": message, "rule_id": rule_id})
    )

    fn_name = _extract_function_from_sarif(result)
    key = f"{rule_id}::{file_path}::{fn_name}::{fp}"

    props = {
        "rule_id": rule_id,
        "file": file_path,
        "line": line,
        "function": fn_name,
        "message": message,
        "severity": result.get("level") or "warning",
        "fingerprint": fp,
    }
    _upsert_node(conn, snap_id, "codeql_result", key, props)

    for code_flow in result.get("codeFlows") or []:
        if not isinstance(code_flow, dict):
            continue
        for thread_flow in code_flow.get("threadFlows") or []:
            if not isinstance(thread_flow, dict):
                continue
            prev_id = None
            for tf_loc in thread_flow.get("locations") or []:
                if not isinstance(tf_loc, dict):
                    continue
                step_loc = tf_loc.get("location") or {}
                step_phys = step_loc.get("physicalLocation") or {}
                step_art = step_phys.get("artifactLocation") or {}
                step_file = step_art.get("uri") or ""
                step_fn = "?"
                for ll in (step_loc.get("logicalLocations") or []):
                    if isinstance(ll, dict) and ll.get("name"):
                        step_fn = str(ll["name"])
                        break
                step_key = stable_key("function", function_ref(step_file, step_fn))
                fn_row = conn.execute(
                    "SELECT id FROM nodes WHERE stable_key=? AND stale=0 LIMIT 1",
                    (step_key,),
                ).fetchone()
                cur_id = fn_row["id"] if fn_row else None
                if prev_id and cur_id and prev_id != cur_id:
                    _upsert_edge(conn, snap_id, "TAINTS", prev_id, cur_id)
                if cur_id:
                    prev_id = cur_id


def _extract_function_from_sarif(result: dict[str, Any]) -> str:
    for loc in result.get("locations") or []:
        if not isinstance(loc, dict):
            continue
        for ll in loc.get("logicalLocations") or []:
            if isinstance(ll, dict) and ll.get("name"):
                return str(ll["name"])
    return "?"


def _list(value: Any) -> list[dict[str, Any]]:
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _int_or_none(value: Any) -> Optional[int]:
    try:
        if value is None or isinstance(value, bool):
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def ingest_annotations(
    run_dir: Path, target: str,
    *, graph_path: Optional[Path] = None,
) -> Optional[Path]:
    """Ingest annotation markdown into the graph as annotation nodes.

    Walks the ``annotations/`` subtree under *run_dir* (or the
    project output dir that contains *run_dir*). Creates one
    ``annotation`` node per annotated function, linked via
    ``ANNOTATED`` edges to existing ``function`` nodes.
    """
    run_dir = Path(run_dir)
    ann_dir = run_dir / "annotations"
    if not ann_dir.is_dir():
        parent = run_dir.parent
        if (parent / "annotations").is_dir():
            ann_dir = parent / "annotations"
        else:
            return None

    try:
        from core.annotations.storage import iter_all_annotations
    except ImportError:
        return None

    annotations = list(iter_all_annotations(ann_dir))
    if not annotations:
        return None

    if graph_path is None:
        graph_path = graph_path_for_run(run_dir, target or None)
    snap_id = make_snapshot_id(
        target, _hash_json([a.function for a in annotations]),
        str(run_dir.resolve()),
    )
    try:
        with graph_write_txn(graph_path) as conn:
            _upsert_snapshot(conn, snap_id, target, run_dir, producer="annotate")
            for ann in annotations:
                key = function_ref(ann.file, ann.function)
                props: dict[str, Any] = {
                    "file": ann.file,
                    "name": ann.function,
                    "status": ann.metadata.get("status", ""),
                    "source": ann.metadata.get("source", ""),
                    "cwe": ann.metadata.get("cwe", ""),
                    "body": ann.body[:500] if ann.body else "",
                }
                ann_id = _upsert_node(conn, snap_id, "annotation", key, props)
                fn_key = stable_key("function", key)
                fn_row = conn.execute(
                    "SELECT id FROM nodes WHERE stable_key=? AND stale=0 LIMIT 1",
                    (fn_key,),
                ).fetchone()
                if fn_row:
                    _upsert_edge(
                        conn, snap_id, "ANNOTATED", fn_row["id"], ann_id,
                        evidence={"source": "annotations", "status": props["status"]},
                    )
    except INGEST_SKIP_EXCEPTIONS as exc:
        print(f"graph: annotation ingest skipped ({exc})", file=sys.stderr)
        return None
    return graph_path


def rebuild_graph(project_dir: Path) -> Optional[Path]:
    """Rebuild the graph from the artefacts in *project_dir*.

    Walks every run directory, sorted by the start timestamp recorded
    in each run's ``.raptor-run.json`` (the metadata file the run
    lifecycle actually writes), calling the appropriate ``ingest_*``
    for each artefact type found. Returns the graph path on success.

    Durability contract:

    * **Containment** — the resolved store must live under
      *project_dir*. graph_path_for_run's active-project adoption
      used to resolve a non-project directory to the ACTIVE project's
      graph, which the old delete-first flow then destroyed and
      rebuilt from nothing.
    * **Temp store, swapped on success** — the rebuild ingests into a
      sibling temp DB and replaces the live store only at the end, so
      an interrupt (or a rebuild that yields nothing) never strands
      the project without its accumulated memory.
    * **Per-run best-effort** — one malformed run directory costs its
      own artefacts, never the runs after it in timestamp order.
    """
    from core.run.metadata import RUN_METADATA_FILE

    project_dir = Path(project_dir).resolve()
    graph_path = graph_path_for_run(project_dir)
    try:
        graph_path.resolve().relative_to(project_dir)
    except ValueError:
        print(
            f"graph: rebuild refused — resolved store {graph_path} is "
            f"outside {project_dir} (not a project or run directory)",
            file=sys.stderr,
        )
        return None

    # Fresh temp store beside the live one; clear any leftover from a
    # previously interrupted rebuild first.
    temp_path = graph_path.with_name(f".rebuild-{os.getpid()}-{graph_path.name}")
    remove_graph_db(temp_path)

    run_dirs: list[tuple[str, Path]] = []
    for child in sorted(project_dir.iterdir()):
        if not child.is_dir():
            continue
        if child.name in ("graph", "annotations"):
            continue
        run_meta = load_json(child / RUN_METADATA_FILE)
        ts = ""
        if isinstance(run_meta, dict):
            ts = str(run_meta.get("timestamp") or "")
        run_dirs.append((ts, child))
    run_dirs.sort(key=lambda x: x[0])

    target = ""
    skipped = 0
    for _ts, d in run_dirs:
        run_meta = load_json(d / RUN_METADATA_FILE)
        if isinstance(run_meta, dict):
            target = target or str(run_meta.get("target_path") or "")

        lanes = []
        if (d / "checklist.json").exists() or (d / "context-map.json").exists():
            lanes.append(ingest_run)
        if (d / "findings.json").exists():
            lanes.append(ingest_scan_findings)
        if list(d.glob("*.sarif")) or list(d.glob("*.sarif.json")):
            lanes.append(ingest_codeql_sarif)
        if (d / "review-journal.jsonl").exists():
            lanes.append(ingest_audit_hypotheses)
        if (d / "validation-outcomes.json").exists():
            lanes.append(ingest_validation_outcomes)
        for lane in lanes:
            try:
                lane(d, target, graph_path=temp_path)
            except Exception as exc:  # noqa: BLE001 — per-run containment: one bad artefact never costs the rest
                skipped += 1
                print(
                    f"graph: rebuild skipped {lane.__name__} for "
                    f"{d.name} ({exc})",
                    file=sys.stderr,
                )

    ann_dir = project_dir / "annotations"
    if ann_dir.is_dir():
        try:
            ingest_annotations(project_dir, target, graph_path=temp_path)
        except Exception as exc:  # noqa: BLE001 — same per-run containment
            skipped += 1
            print(f"graph: rebuild skipped annotations ({exc})", file=sys.stderr)
    if skipped:
        print(f"graph: rebuild skipped {skipped} artefact set(s)", file=sys.stderr)

    if not temp_path.exists():
        # Nothing ingested: keep whatever store already exists rather
        # than deleting memory in exchange for nothing (an operator
        # who wants an empty store has /project graph clear).
        print("graph: rebuild found no ingestable artefacts; existing "
              "store left in place", file=sys.stderr)
        return None

    # Swap: clear the live store WITH its WAL sidecars (a stale -wal
    # next to the renamed DB would replay old frames), then move the
    # temp store into place.
    if graph_path.exists() and not remove_graph_db(graph_path):
        print(
            f"graph: rebuild could not replace {graph_path.name}; "
            "previous store kept, rebuilt copy discarded",
            file=sys.stderr,
        )
        remove_graph_db(temp_path)
        return None
    for source in [temp_path, *graph_sidecar_paths(temp_path)]:
        if source.exists():
            os.replace(source, graph_path.parent / source.name.replace(
                temp_path.name, graph_path.name, 1))
    return graph_path if graph_path.exists() else None
