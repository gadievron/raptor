"""Ingest /understand artefacts into the internal graph store."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from core.json import load_json

from .schema import (
    content_hash,
    json_dumps,
    short_hash,
    snapshot_id as make_snapshot_id,
    stable_edge_id,
    stable_key,
    stable_node_id,
)
from .store import graph_connection, graph_path_for_run, open_graph


def ingest_run(run_dir: Path, target_path: Optional[str] = None) -> Optional[Path]:
    """Best-effort ingest of a run directory.

    Returns the graph path when something was ingested, otherwise ``None``.
    """
    run_dir = Path(run_dir)
    checklist = load_json(run_dir / "checklist.json") or {}
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
    graph_path = graph_path_for_run(run_dir, target or None)
    checklist_hash = _hash_json(checklist)
    snap_id = make_snapshot_id(target, checklist_hash, str(run_dir.resolve()))

    with graph_connection(graph_path) as conn:
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
                datetime.now(timezone.utc).isoformat(),
                str(run_dir.resolve()),
                json_dumps({"total_files": checklist.get("total_files"), "total_items": checklist.get("total_items")}),
            ),
        )
        _ingest_checklist(conn, snap_id, checklist)
        if isinstance(context_map, dict):
            _ingest_context_map(conn, snap_id, context_map)
            _artifact(conn, snap_id, "context_map", run_dir / "context-map.json", run_dir)
        for trace_path in trace_paths:
            trace = load_json(trace_path)
            if isinstance(trace, dict):
                _ingest_flow_trace(conn, snap_id, trace)
                _artifact(conn, snap_id, "flow_trace", trace_path, run_dir)
        if variants is not None:
            _ingest_variants(conn, snap_id, variants)
            _artifact(conn, snap_id, "variants", run_dir / "variants.json", run_dir)
        for path in result_paths:
            result = load_json(path)
            if isinstance(result, dict):
                _ingest_multimodel_result(conn, snap_id, result)
                _artifact(conn, snap_id, result.get("mode") or path.stem, path, run_dir)
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
            fn_id = _upsert_node(conn, snapshot_id, "function", f"{path}::{name}", props)
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


def _artifact(conn, snapshot_id: str, kind: str, path: Path, run_dir: Path) -> None:
    if not path.exists():
        return
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        digest = ""
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
            datetime.now(timezone.utc).isoformat(),
            "{}",
        ),
    )


def ingest_scan_findings(run_dir: Path, target_path: Optional[str] = None) -> Optional[Path]:
    """Ingest /scan or /agentic findings into the graph.

    Creates scan_finding nodes linked to function nodes via AFFECTS edges.
    Prefers findings-deduped.json (from /agentic) over findings.json.
    """
    run_dir = Path(run_dir)
    findings = load_json(run_dir / "findings-deduped.json") or load_json(run_dir / "findings.json")
    if not findings or not isinstance(findings, list):
        return None

    target = str(target_path or _infer_target(run_dir, findings))
    if not target:
        return None
    graph_path = graph_path_for_run(run_dir, target or None)
    checklist_hash = _hash_json(findings)
    snap_id = make_snapshot_id(target, checklist_hash, str(run_dir.resolve()))

    conn = open_graph(graph_path)
    conn.isolation_level = None
    try:
        conn.execute("BEGIN IMMEDIATE")
        _upsert_snapshot(conn, snap_id, target, run_dir, producer="scan")
        for f in _list(findings):
            fn_name = str(f.get("function") or f.get("name") or "?")
            file_path = str(f.get("file") or f.get("path") or "?")
            key = f"{f.get('rule_id', '?')}::{file_path}::{fn_name}::{content_hash(f)}"
            node_id = _upsert_node(conn, snap_id, "scan_finding", key, f)
            fn_key = stable_key("function", f"{file_path}::{fn_name}")
            fn_row = conn.execute(
                "SELECT id FROM nodes WHERE stable_key=? AND stale=0 LIMIT 1",
                (fn_key,),
            ).fetchone()
            if fn_row:
                _upsert_edge(conn, snap_id, "AFFECTS", node_id, fn_row["id"])
        conn.execute("COMMIT")
    except (sqlite3.Error, KeyError, TypeError, ValueError) as exc:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        print(f"graph: scan ingest skipped ({exc})", file=sys.stderr)
        return None
    finally:
        conn.close()
    return graph_path


def ingest_codeql_sarif(run_dir: Path, target_path: Optional[str] = None) -> Optional[Path]:
    """Ingest CodeQL SARIF results into the graph.

    Creates codeql_result nodes. SARIF codeFlows are mapped to TAINTS edges.
    """
    run_dir = Path(run_dir)
    sarif_paths = sorted(run_dir.glob("*.sarif")) + sorted(run_dir.glob("*.sarif.json"))
    if not sarif_paths:
        return None

    target = str(target_path or "")
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
            conn = open_graph(graph_path)
            conn.isolation_level = None
            try:
                conn.execute("BEGIN IMMEDIATE")
                _upsert_snapshot(conn, snap_id, target, run_dir, producer="codeql")
                for result in results:
                    if not isinstance(result, dict):
                        continue
                    _ingest_sarif_result(conn, snap_id, result)
                conn.execute("COMMIT")
                ingested = True
            except (sqlite3.Error, KeyError, TypeError, ValueError) as exc:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                print(f"graph: codeql ingest skipped ({exc})", file=sys.stderr)
                continue
            finally:
                conn.close()
    return graph_path if ingested else None


def ingest_validation_outcomes(run_dir: Path, target_path: Optional[str] = None) -> Optional[Path]:
    """Ingest /validate outcomes into the graph.

    Creates verified_outcome nodes linked to findings via VALIDATES edges.
    """
    run_dir = Path(run_dir)
    outcomes = load_json(run_dir / "validation-outcomes.json")
    if not outcomes or not isinstance(outcomes, list):
        return None

    target = str(target_path or "")
    graph_path = graph_path_for_run(run_dir, target or None)
    snap_id = make_snapshot_id(target, _hash_json(outcomes), str(run_dir.resolve()))

    conn = open_graph(graph_path)
    conn.isolation_level = None
    try:
        conn.execute("BEGIN IMMEDIATE")
        _upsert_snapshot(conn, snap_id, target, run_dir, producer="validate")
        for outcome in _list(outcomes):
            status = str(outcome.get("status") or outcome.get("verdict") or "inconclusive")
            finding_ref = outcome.get("finding_id") or outcome.get("finding") or ""
            key = f"{status}::{finding_ref}::{content_hash(outcome)}"
            props = dict(outcome)
            props["status"] = status
            vo_id = _upsert_node(conn, snap_id, "verified_outcome", key, props)
            if finding_ref:
                for kind in ("scan_finding", "codeql_result", "unchecked_flow"):
                    rows = conn.execute(
                        "SELECT id FROM nodes WHERE stable_key LIKE ? ESCAPE '\\' AND stale=0 LIMIT 1",
                        (f"{kind}://%{_like_escape(str(finding_ref))}%",),
                    ).fetchall()
                    for row in rows:
                        _upsert_edge(conn, snap_id, "VALIDATES", vo_id, row["id"])
        conn.execute("COMMIT")
    except (sqlite3.Error, KeyError, TypeError, ValueError) as exc:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        print(f"graph: validation ingest skipped ({exc})", file=sys.stderr)
        return None
    finally:
        conn.close()
    return graph_path


def ingest_audit_hypotheses(run_dir: Path, target_path: Optional[str] = None) -> Optional[Path]:
    """Ingest /audit journal entries into the graph.

    Creates hypothesis and tool_verdict nodes.
    """
    run_dir = Path(run_dir)
    journal_path = run_dir / "review-journal.jsonl"
    if not journal_path.exists():
        return None

    target = str(target_path or "")
    graph_path = graph_path_for_run(run_dir, target or None)

    entries: list[dict[str, Any]] = []
    try:
        for line in journal_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    except (OSError, json.JSONDecodeError):
        return None
    if not entries:
        return None

    snap_id = make_snapshot_id(target, _hash_json(entries), str(run_dir.resolve()))
    conn = open_graph(graph_path)
    conn.isolation_level = None
    try:
        conn.execute("BEGIN IMMEDIATE")
        _upsert_snapshot(conn, snap_id, target, run_dir, producer="audit")
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            entry_type = entry.get("type") or entry.get("kind") or ""
            if entry_type in ("hypothesis", "hypothesis_formed"):
                _ingest_hypothesis_entry(conn, snap_id, entry)
            elif entry_type in ("tool_verdict", "verification", "tool_result"):
                _ingest_tool_verdict_entry(conn, snap_id, entry)
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


# ---------------------------------------------------------------------------
# Private helpers for new producers
# ---------------------------------------------------------------------------


def _like_escape(value: str) -> str:
    r"""Escape LIKE wildcards using backslash as escape char."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _upsert_snapshot(conn, snap_id: str, target: str, run_dir: Path, *, producer: str = "understand") -> None:
    conn.execute(
        """
        INSERT OR REPLACE INTO snapshots
        (id, target_path, target_hash, git_sha, checklist_hash, created_at, producer_run, props_json, producer)
        VALUES (?, ?, '', '', '', ?, ?, '{}', ?)
        """,
        (snap_id, target, datetime.now(timezone.utc).isoformat(), str(run_dir.resolve()), producer),
    )


def _infer_target(run_dir: Path, findings: list) -> str:
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
                step_key = stable_key("function", f"{step_file}::{step_fn}")
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


def _ingest_hypothesis_entry(conn, snap_id: str, entry: dict[str, Any]) -> None:
    target_fn = entry.get("function") or entry.get("target") or ""
    cwe = entry.get("cwe") or ""
    key = f"{target_fn}::{cwe}::{content_hash(entry)}"
    props = {
        "function": target_fn,
        "cwe": cwe,
        "status": entry.get("status") or "formed",
        "strategy": entry.get("strategy") or "",
        "description": entry.get("description") or entry.get("hypothesis") or "",
        "file": entry.get("file") or "",
    }
    hyp_id = _upsert_node(conn, snap_id, "hypothesis", key, props)
    if target_fn:
        fn_key = stable_key("function", f"{props.get('file', '')}::{target_fn}")
        fn_row = conn.execute(
            "SELECT id FROM nodes WHERE stable_key=? AND stale=0 LIMIT 1",
            (fn_key,),
        ).fetchone()
        if fn_row:
            _upsert_edge(conn, snap_id, "AFFECTS", hyp_id, fn_row["id"])


def _ingest_tool_verdict_entry(conn, snap_id: str, entry: dict[str, Any]) -> None:
    tool = entry.get("tool") or entry.get("verifier") or "?"
    hyp_ref = entry.get("hypothesis_id") or entry.get("hypothesis") or ""
    key = f"{tool}::{hyp_ref}::{content_hash(entry)}"
    props = {
        "tool": tool,
        "hypothesis_ref": hyp_ref,
        "verdict": entry.get("verdict") or entry.get("result") or "inconclusive",
        "evidence": entry.get("evidence") or entry.get("output") or "",
    }
    tv_id = _upsert_node(conn, snap_id, "tool_verdict", key, props)
    if hyp_ref:
        escaped = _like_escape(hyp_ref)
        rows = conn.execute(
            "SELECT id FROM nodes WHERE kind='hypothesis' AND stable_key LIKE ? ESCAPE '\\' AND stale=0 LIMIT 1",
            (f"hypothesis://{escaped}%",),
        ).fetchall()
        for row in rows:
            _upsert_edge(conn, snap_id, "TESTED_BY", row["id"], tv_id)


def _list(value: Any) -> list[dict[str, Any]]:
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _int_or_none(value: Any) -> Optional[int]:
    try:
        if value is None or isinstance(value, bool):
            return None
        return int(value)
    except (TypeError, ValueError):
        return None
