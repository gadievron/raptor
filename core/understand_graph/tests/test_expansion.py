"""Tests for graph store Phase A expansion — new producers, consumers, and hardening."""

import json
import sqlite3
from pathlib import Path

from core.json import save_json
from core.understand_graph import (
    dashboard_summary,
    fuzz_targets,
    graph_summary,
    hypothesis_seeds,
    ingest_audit_hypotheses,
    ingest_codeql_sarif,
    ingest_run,
    ingest_scan_findings,
    ingest_validation_outcomes,
    propagate_binary_verdicts,
    query_graph,
    scan_dedup_chains,
)
from core.understand_graph.ingest import _like_escape
from core.understand_graph.schema import SCHEMA_VERSION, content_hash
from core.understand_graph.store import open_graph


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _write_understand_run(run_dir: Path, target: Path) -> Path:
    """Seed a minimal /understand run with entry points, sinks, functions."""
    src = target / "server.c"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text(
        'void handle_request(char *input) {\n'
        '    system(input);\n'
        '}\n'
        'void parse_header(char *buf) {\n'
        '    strcpy(local, buf);\n'
        '}\n',
        encoding="utf-8",
    )
    import hashlib
    sha = hashlib.sha256(src.read_bytes()).hexdigest()
    run_dir.mkdir(parents=True, exist_ok=True)
    save_json(run_dir / "checklist.json", {
        "target_path": str(target),
        "total_files": 1,
        "total_items": 2,
        "files": [{
            "path": "server.c",
            "language": "c",
            "sha256": sha,
            "items": [
                {"kind": "function", "name": "handle_request", "line_start": 1, "line_end": 3},
                {"kind": "function", "name": "parse_header", "line_start": 4, "line_end": 6},
            ],
        }],
    })
    save_json(run_dir / "context-map.json", {
        "meta": {"target": str(target)},
        "entry_points": [
            {"id": "EP-1", "name": "handle_request", "file": "server.c", "line": 1, "type": "exported"},
        ],
        "sink_details": [
            {"id": "SINK-1", "name": "system", "file": "server.c", "line": 2, "type": "command_injection"},
            {"id": "SINK-2", "name": "strcpy", "file": "server.c", "line": 5, "type": "buffer_overflow"},
        ],
        "unchecked_flows": [
            {"entry_point": "EP-1", "sink": "SINK-1", "confidence": "high"},
            {"entry_point": "EP-1", "sink": "SINK-2", "confidence": "medium"},
        ],
    })
    graph_path = ingest_run(run_dir, str(target))
    assert graph_path is not None
    return graph_path


def _write_scan_findings(run_dir: Path) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    save_json(run_dir / "findings.json", [
        {
            "rule_id": "command-injection",
            "file": "server.c",
            "line": 2,
            "function": "handle_request",
            "severity": "critical",
            "message": "Unsanitised input passed to system()",
        },
        {
            "rule_id": "buffer-overflow",
            "file": "server.c",
            "line": 5,
            "function": "parse_header",
            "severity": "high",
            "message": "strcpy with unchecked length",
        },
    ])


def _write_sarif(run_dir: Path) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    save_json(run_dir / "results.sarif.json", {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "CodeQL"}},
            "results": [{
                "ruleId": "cpp/command-line-injection",
                "level": "error",
                "message": {"text": "Command injection via system()"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "server.c"},
                        "region": {"startLine": 2},
                    },
                    "logicalLocations": [{"name": "handle_request"}],
                }],
                "partialFingerprints": {"primaryLocationLineHash": "abc123"},
            }],
        }],
    })


def _write_validation_outcomes(run_dir: Path) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    save_json(run_dir / "validation-outcomes.json", [
        {
            "finding_id": "command-injection",
            "status": "exploitable",
            "verdict": "exploitable",
            "description": "System call reachable from network input",
        },
    ])


def _write_audit_journal(run_dir: Path) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    lines = [
        json.dumps({
            "type": "hypothesis",
            "function": "handle_request",
            "file": "server.c",
            "cwe": "CWE-78",
            "status": "formed",
            "description": "Unsanitised user input reaches system()",
        }),
        json.dumps({
            "type": "tool_verdict",
            "tool": "semgrep",
            "hypothesis_id": "handle_request::CWE-78",
            "verdict": "confirmed",
            "evidence": "Rule matched: command-injection pattern",
        }),
    ]
    (run_dir / "review-journal.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

def test_schema_version_is_3():
    assert SCHEMA_VERSION == 3


def test_content_hash_stable():
    f1 = {"rule_id": "cmd-inject", "message": "system() call", "snippet": "system(buf)"}
    f2 = {"rule_id": "cmd-inject", "message": "system() call", "snippet": "system(buf)"}
    assert content_hash(f1) == content_hash(f2)
    assert len(content_hash(f1)) == 12


def test_content_hash_differs_on_content():
    f1 = {"rule_id": "cmd-inject", "message": "system() call"}
    f2 = {"rule_id": "buffer-overflow", "message": "strcpy() call"}
    assert content_hash(f1) != content_hash(f2)


# ---------------------------------------------------------------------------
# Store — v3 migration
# ---------------------------------------------------------------------------

def test_v3_migration_creates_composite_index_and_producer(tmp_path):
    db_path = tmp_path / "test.db"
    conn = open_graph(db_path)
    indexes = {row["name"] for row in conn.execute("PRAGMA index_list(nodes)").fetchall()}
    assert "idx_nodes_snap_kind_stale" in indexes
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(snapshots)").fetchall()}
    assert "producer" in cols
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    assert version == 3
    conn.close()


# ---------------------------------------------------------------------------
# Store — query_graph corruption guard
# ---------------------------------------------------------------------------

def test_query_graph_returns_none_for_missing_db(tmp_path):
    result = query_graph(tmp_path / "nonexistent.db", lambda conn: "should not run")
    assert result is None


def test_query_graph_deletes_corrupt_db(tmp_path):
    db_path = tmp_path / "corrupt.db"
    db_path.write_bytes(b"not a sqlite database")
    result = query_graph(db_path, lambda conn: conn.execute("SELECT 1"))
    assert result is None
    assert not db_path.exists()


def test_query_graph_passes_through_result(tmp_path):
    db_path = tmp_path / "test.db"
    conn = open_graph(db_path)
    conn.close()
    result = query_graph(db_path, lambda conn: 42)
    assert result == 42


# ---------------------------------------------------------------------------
# LIKE escape
# ---------------------------------------------------------------------------

def test_like_escape_handles_all_wildcards():
    assert _like_escape("foo%bar") == "foo\\%bar"
    assert _like_escape("foo_bar") == "foo\\_bar"
    assert _like_escape("foo\\bar") == "foo\\\\bar"
    assert _like_escape("a\\%_b") == "a\\\\\\%\\_b"


def test_like_escape_backslash_before_percent():
    escaped = _like_escape("path\\%file")
    assert escaped == "path\\\\\\%file"


# ---------------------------------------------------------------------------
# Producer — scan findings
# ---------------------------------------------------------------------------

def test_ingest_scan_findings(tmp_path):
    target = tmp_path / "target"
    run_dir = tmp_path / "understand-run"
    _write_understand_run(run_dir, target)

    # Scan writes to the same run dir so graph_path_for_run resolves the same DB
    _write_scan_findings(run_dir)
    result = ingest_scan_findings(run_dir, str(target))
    assert result is not None

    summary = graph_summary(result)
    assert summary["nodes"].get("scan_finding", 0) == 2


def test_ingest_scan_findings_links_to_functions(tmp_path):
    target = tmp_path / "target"
    run_dir = tmp_path / "understand-run"
    _write_understand_run(run_dir, target)

    _write_scan_findings(run_dir)
    graph_path = ingest_scan_findings(run_dir, str(target))

    summary = graph_summary(graph_path)
    assert summary["edges"].get("AFFECTS", 0) >= 2


def test_ingest_scan_no_findings_returns_none(tmp_path):
    run_dir = tmp_path / "empty-run"
    run_dir.mkdir()
    assert ingest_scan_findings(run_dir, "/tmp/target") is None


# ---------------------------------------------------------------------------
# Producer — CodeQL SARIF
# ---------------------------------------------------------------------------

def test_ingest_codeql_sarif(tmp_path):
    target = tmp_path / "target"
    run_dir = tmp_path / "understand-run"
    _write_understand_run(run_dir, target)

    _write_sarif(run_dir)
    result = ingest_codeql_sarif(run_dir, str(target))
    assert result is not None

    summary = graph_summary(result)
    assert summary["nodes"].get("codeql_result", 0) == 1


# ---------------------------------------------------------------------------
# Producer — validation outcomes
# ---------------------------------------------------------------------------

def test_ingest_validation_outcomes(tmp_path):
    target = tmp_path / "target"
    run_dir = tmp_path / "understand-run"
    _write_understand_run(run_dir, target)

    _write_validation_outcomes(run_dir)
    result = ingest_validation_outcomes(run_dir, str(target))
    assert result is not None

    summary = graph_summary(result)
    assert summary["nodes"].get("verified_outcome", 0) >= 1


# ---------------------------------------------------------------------------
# Producer — audit hypotheses
# ---------------------------------------------------------------------------

def test_ingest_audit_hypotheses(tmp_path):
    target = tmp_path / "target"
    run_dir = tmp_path / "understand-run"
    _write_understand_run(run_dir, target)

    _write_audit_journal(run_dir)
    result = ingest_audit_hypotheses(run_dir, str(target))
    assert result is not None

    summary = graph_summary(result)
    assert summary["nodes"].get("hypothesis", 0) >= 1
    assert summary["nodes"].get("tool_verdict", 0) >= 1
    assert summary["edges"].get("TESTED_BY", 0) >= 1


def test_audit_ingest_no_journal_returns_none(tmp_path):
    run_dir = tmp_path / "empty-run"
    run_dir.mkdir()
    assert ingest_audit_hypotheses(run_dir) is None


# ---------------------------------------------------------------------------
# Producer — transaction safety
# ---------------------------------------------------------------------------

def test_scan_ingest_atomic_on_crash(tmp_path, monkeypatch):
    """Partial ingest must not leave a snapshot in the graph."""
    target = tmp_path / "target"
    run_dir = tmp_path / "understand-run"
    graph_path = _write_understand_run(run_dir, target)

    _write_scan_findings(run_dir)

    call_count = 0

    from core.understand_graph import ingest as ingest_mod
    original_upsert = ingest_mod._upsert_node

    def bomb_on_second_call(conn, snapshot_id, kind, key, props):
        nonlocal call_count
        if kind == "scan_finding":
            call_count += 1
            if call_count >= 2:
                raise sqlite3.OperationalError("simulated crash")
        return original_upsert(conn, snapshot_id, kind, key, props)

    monkeypatch.setattr(ingest_mod, "_upsert_node", bomb_on_second_call)
    result = ingest_scan_findings(run_dir, str(target))
    assert result is None

    summary = graph_summary(graph_path)
    assert summary["nodes"].get("scan_finding", 0) == 0


# ---------------------------------------------------------------------------
# Consumer — hypothesis seeds
# ---------------------------------------------------------------------------

def test_hypothesis_seeds_returns_functions_near_flows(tmp_path):
    target = tmp_path / "target"
    run_dir = tmp_path / "understand-run"
    graph_path = _write_understand_run(run_dir, target)

    seeds = hypothesis_seeds(graph_path, str(target))
    assert len(seeds) >= 1
    assert seeds[0]["function"] == "handle_request"
    assert seeds[0]["flow_count"] >= 1


def test_hypothesis_seeds_returns_empty_without_graph(tmp_path):
    seeds = hypothesis_seeds(tmp_path / "nonexistent.db", "/tmp/target")
    assert seeds == []


# ---------------------------------------------------------------------------
# Consumer — fuzz targets
# ---------------------------------------------------------------------------

def test_fuzz_targets_finds_dangerous_sinks(tmp_path):
    target = tmp_path / "target"
    run_dir = tmp_path / "understand-run"
    graph_path = _write_understand_run(run_dir, target)

    targets = fuzz_targets(graph_path, str(target))
    assert len(targets) >= 1
    sink_names = [t["dangerous_sink"] for t in targets]
    assert any("system" in s for s in sink_names)


# ---------------------------------------------------------------------------
# Consumer — scan dedup chains
# ---------------------------------------------------------------------------

def test_scan_dedup_groups_findings_on_same_path(tmp_path):
    target = tmp_path / "target"
    run_dir = tmp_path / "understand-run"
    graph_path = _write_understand_run(run_dir, target)

    save_json(run_dir / "findings.json", [
        {"rule_id": "r1", "file": "server.c", "function": "handle_request", "severity": "high", "message": "A"},
        {"rule_id": "r2", "file": "server.c", "function": "handle_request", "severity": "critical", "message": "B"},
    ])
    ingest_scan_findings(run_dir, str(target))

    chains = scan_dedup_chains(graph_path, str(target))
    assert isinstance(chains, list)
    assert len(chains) >= 1
    assert chains[0]["chain_size"] >= 2


# ---------------------------------------------------------------------------
# Consumer — binary oracle propagation
# ---------------------------------------------------------------------------

def test_propagate_binary_verdicts_creates_suppressed_edges(tmp_path):
    target = tmp_path / "target"
    run_dir = tmp_path / "understand-run"
    graph_path = _write_understand_run(run_dir, target)

    verdicts = {
        "server.c::parse_header": "absent",
        "server.c::handle_request": "symbol_present",
    }
    count = propagate_binary_verdicts(graph_path, verdicts, binary_path="/usr/bin/server")
    assert count == 1

    summary = graph_summary(graph_path)
    assert summary["edges"].get("SUPPRESSED_BY", 0) == 1


def test_propagate_binary_verdicts_no_absent_returns_zero(tmp_path):
    target = tmp_path / "target"
    run_dir = tmp_path / "understand-run"
    graph_path = _write_understand_run(run_dir, target)

    count = propagate_binary_verdicts(graph_path, {"fn": "symbol_present"})
    assert count == 0


# ---------------------------------------------------------------------------
# Consumer — dashboard summary
# ---------------------------------------------------------------------------

def test_dashboard_summary_aggregates(tmp_path):
    target = tmp_path / "target"
    run_dir = tmp_path / "understand-run"
    graph_path = _write_understand_run(run_dir, target)

    _write_scan_findings(run_dir)
    ingest_scan_findings(run_dir, str(target))

    dash = dashboard_summary(graph_path)
    assert dash["snapshot_count"] >= 2
    assert dash["totals"]["entries"] >= 1
    assert dash["totals"]["sinks"] >= 1
    assert dash["totals"]["scan_findings"] >= 2
    assert isinstance(dash["validation_coverage"], float)


def test_dashboard_summary_empty_graph(tmp_path):
    dash = dashboard_summary(tmp_path / "nonexistent.db")
    assert dash["snapshot_count"] == 0
    assert dash["snapshots"] == []


# ---------------------------------------------------------------------------
# Consumer — coverage residual (graph-absent degrades)
# ---------------------------------------------------------------------------

def test_coverage_residual_absent_graph():
    from core.understand_graph import coverage_residual
    result = coverage_residual(Path("/nonexistent/path.db"))
    assert result == []


def test_coverage_residual_filters_validated(tmp_path):
    from core.understand_graph import coverage_residual
    target = tmp_path / "target"
    run_dir = tmp_path / "understand-run"
    graph_path = _write_understand_run(run_dir, target)

    unvalidated = coverage_residual(graph_path, str(target))
    assert len(unvalidated) >= 1

    _write_validation_outcomes(run_dir)
    ingest_validation_outcomes(run_dir, str(target))

    after = coverage_residual(graph_path, str(target))
    assert len(after) < len(unvalidated)


# ---------------------------------------------------------------------------
# Consumer — SCA reachability (graph-absent degrades)
# ---------------------------------------------------------------------------

def test_sca_reachability_absent_graph():
    from core.understand_graph import sca_reachability
    result = sca_reachability(Path("/nonexistent/path.db"), "requests")
    assert result == []


# ---------------------------------------------------------------------------
# Phase C — annotation ingest
# ---------------------------------------------------------------------------

def _write_annotation_file(base_dir: Path, source_file: str, function: str,
                           status: str = "clean") -> Path:
    """Write a minimal annotation markdown file."""
    ann_dir = base_dir / "annotations"
    ann_path = ann_dir / f"{source_file}.md"
    ann_path.parent.mkdir(parents=True, exist_ok=True)
    ann_path.write_text(
        f"## {function}\n"
        f"<!-- status={status} source=human -->\n"
        f"Reviewed: no issues found.\n",
        encoding="utf-8",
    )
    return ann_path


def test_ingest_annotations(tmp_path):
    from core.understand_graph import ingest_annotations

    target = tmp_path / "target"
    run_dir = tmp_path / "understand-run"
    graph_path = _write_understand_run(run_dir, target)

    _write_annotation_file(run_dir, "server.c", "handle_request", "finding")

    result = ingest_annotations(run_dir, str(target))
    assert result is not None

    with open_graph(graph_path) as conn:
        ann_nodes = conn.execute(
            "SELECT * FROM nodes WHERE kind='annotation' AND stale=0",
        ).fetchall()
        assert len(ann_nodes) >= 1
        assert any("handle_request" in (r["name"] or "") for r in ann_nodes)

        ann_edges = conn.execute(
            "SELECT * FROM edges WHERE kind='ANNOTATED' AND stale=0",
        ).fetchall()
        assert len(ann_edges) >= 1


def test_ingest_annotations_no_dir_returns_none(tmp_path):
    from core.understand_graph import ingest_annotations
    result = ingest_annotations(tmp_path / "nonexistent", "target")
    assert result is None


# ---------------------------------------------------------------------------
# Phase C — IMPORTS edges
# ---------------------------------------------------------------------------

def test_imports_edges(tmp_path):
    target = tmp_path / "target"
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    save_json(run_dir / "checklist.json", {
        "target_path": str(target),
        "files": [{"path": "src/auth.py", "sha256": "aaa"}],
        "total_files": 1,
        "total_items": 2,
    })
    save_json(run_dir / "context-map.json", {
        "entry_points": [{"id": "EP1", "name": "login", "file": "src/auth.py", "line": 1}],
        "sinks": [],
        "trust_boundaries": [],
        "unchecked_flows": [],
        "imports": [
            {"file": "src/auth.py", "module": "bcrypt", "line": 3},
            {"file": "src/auth.py", "module": "hashlib", "line": 4},
        ],
    })

    graph_path = ingest_run(run_dir, str(target))
    assert graph_path is not None

    with open_graph(graph_path) as conn:
        dep_nodes = conn.execute(
            "SELECT * FROM nodes WHERE kind='dependency' AND stale=0",
        ).fetchall()
        assert len(dep_nodes) == 2
        dep_names = {r["name"] for r in dep_nodes}
        assert "bcrypt" in dep_names
        assert "hashlib" in dep_names

        imp_edges = conn.execute(
            "SELECT * FROM edges WHERE kind='IMPORTS' AND stale=0",
        ).fetchall()
        assert len(imp_edges) >= 1


# ---------------------------------------------------------------------------
# Phase C — rebuild_graph
# ---------------------------------------------------------------------------

def test_rebuild_graph(tmp_path, monkeypatch):
    from core.understand_graph import rebuild_graph
    from core.understand_graph.store import GRAPH_FILENAME

    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / ".raptor-project-root").touch()

    # In production, ProjectManager makes all ingest calls resolve to
    # the same project graph. Tests have no ProjectManager, so pin
    # graph_path_for_run to the project graph.
    project_graph = project_dir / "graph" / GRAPH_FILENAME
    monkeypatch.setattr(
        "core.understand_graph.ingest.graph_path_for_run",
        lambda *_args, **_kw: project_graph,
    )

    # Run 1: an understand run
    run1 = project_dir / "run1"
    run1.mkdir()
    save_json(run1 / "lifecycle.json", {"created_at": "2026-01-01T00:00:00Z", "target": str(tmp_path / "t")})
    save_json(run1 / "checklist.json", {
        "target_path": str(tmp_path / "t"),
        "files": [{"path": "main.c", "sha256": "abc"}],
    })
    save_json(run1 / "context-map.json", {
        "entry_points": [{"id": "E1", "name": "main", "file": "main.c", "line": 1}],
        "sinks": [{"id": "S1", "name": "system", "file": "main.c", "line": 5}],
        "trust_boundaries": [],
        "unchecked_flows": [],
    })

    # Run 2: a scan run
    run2 = project_dir / "run2"
    run2.mkdir()
    save_json(run2 / "lifecycle.json", {"created_at": "2026-01-02T00:00:00Z", "target": str(tmp_path / "t")})
    save_json(run2 / "findings.json", [
        {"rule_id": "R1", "file": "main.c", "function": "main",
         "message": "cmd injection", "severity": "high"},
    ])

    result = rebuild_graph(project_dir)
    assert result is not None
    assert result.exists()

    with open_graph(result) as conn:
        entries = conn.execute("SELECT * FROM nodes WHERE kind='entry_point' AND stale=0").fetchall()
        assert len(entries) >= 1
        findings = conn.execute("SELECT * FROM nodes WHERE kind='scan_finding' AND stale=0").fetchall()
        assert len(findings) >= 1
