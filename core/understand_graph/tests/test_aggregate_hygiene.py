"""Metric honesty, list integrity, timestamp coherence, snapshot-key
identity, and source-flow path coverage — one behavioural pin each."""

import hashlib
import time

from core.json import save_json
from core.understand_graph import (
    attack_paths,
    dashboard_summary,
    graph_summary,
    hypothesis_seeds,
    ingest_run,
    ingest_scan_findings,
    ingest_validation_outcomes,
    propagate_binary_verdicts,
)
from core.understand_graph.store import open_graph


def _write_run(run_dir, target, *, sink_name="system", source_flow=False):
    src = target / "server.c"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text("void handle_request(char *i) {}\n", encoding="utf-8")
    sha = hashlib.sha256(src.read_bytes()).hexdigest()
    run_dir.mkdir(parents=True, exist_ok=True)
    save_json(run_dir / "checklist.json", {
        "target_path": str(target),
        "total_files": 1,
        "total_items": 1,
        "files": [{"path": "server.c", "sha256": sha,
                   "items": [{"name": "handle_request", "line_start": 1}]}],
    })
    context_map = {
        "meta": {"target": str(target)},
        "entry_points": [{"id": "EP-1", "name": "handle_request",
                          "file": "server.c", "line": 1}],
        "sinks": [{"id": "SINK-1", "name": sink_name,
                   "file": "server.c", "line": 2}],
        "unchecked_flows": [{"id": "FLOW-1", "entry_point": "EP-1",
                             "sink": "SINK-1", "confidence": "high",
                             "missing_boundary": "no check"}],
    }
    if source_flow:
        context_map["sources"] = [{"id": "SRC-1", "name": "recv_buf",
                                   "file": "server.c", "line": 3}]
        context_map["unchecked_flows"].append(
            {"id": "FLOW-2", "entry_point": "SRC-1", "sink": "SINK-1",
             "confidence": "high", "missing_boundary": "no check"})
    save_json(run_dir / "context-map.json", context_map)
    graph_path = ingest_run(run_dir, str(target))
    assert graph_path is not None
    return graph_path


def test_dashboard_coverage_counts_findings_once_across_snapshots(tmp_path):
    """Re-ingesting the same findings from a second run dir mints new
    snapshot-scoped node rows; the coverage denominator must count
    finding IDENTITY (stable_key), not per-snapshot row ids."""
    target = tmp_path / "target"
    run_dir = tmp_path / "run"
    graph_path = _write_run(run_dir, target)

    findings = [
        {"id": "SCAN-1", "rule_id": "r1", "file": "server.c",
         "function": "handle_request", "severity": "high", "message": "m"},
    ]
    for name in ("run", "run2"):
        d = tmp_path / name
        d.mkdir(exist_ok=True)
        save_json(d / "findings.json", findings)
        assert ingest_scan_findings(d, str(target),
                                    graph_path=graph_path) is not None

    save_json(run_dir / "validation-outcomes.json",
              [{"finding_id": "SCAN-1", "status": "exploitable"},
               {"finding_id": "FLOW-1", "status": "exploitable"}])
    ingest_validation_outcomes(run_dir, str(target))

    # Identity population: SCAN-1 + FLOW-1, both validated.
    dash = dashboard_summary(graph_path)
    assert dash["validation_coverage"] == 1.0


def test_group_concat_names_survive_commas(tmp_path):
    """A sink name containing a comma must come back as ONE list item
    — the comma-joined GROUP_CONCAT split corrupted it."""
    target = tmp_path / "target"
    run_dir = tmp_path / "run"
    graph_path = _write_run(run_dir, target,
                            sink_name="memcpy, then system")

    seeds = hypothesis_seeds(graph_path, str(target))
    assert seeds
    assert seeds[0]["nearby_sinks"] == ["memcpy, then system"]


def test_created_at_minted_in_one_format(tmp_path):
    """binary_oracle snapshots minted space-separated datetime('now')
    while every other producer wrote UTC isoformat — lexicographic
    ORDER BY ranks 'T' above ' ', so same-day binary snapshots always
    sorted older. One mint: everything isoformat."""
    target = tmp_path / "target"
    run_dir = tmp_path / "run"
    graph_path = _write_run(run_dir, target)
    time.sleep(0.01)

    assert propagate_binary_verdicts(
        graph_path,
        {"server.c::handle_request": "absent"},
        binary_path="/bin/app",
    ) == 1

    with open_graph(graph_path) as conn:
        stamps = {r["producer"]: r["created_at"] for r in conn.execute(
            "SELECT producer, created_at FROM snapshots")}
    assert "T" in stamps["binary_oracle"], stamps
    # The newest snapshot IS the binary one under lexicographic order.
    latest = graph_summary(graph_path)["latest_snapshot"]
    assert latest["producer"] == "binary_oracle"


def test_binary_verdict_snapshot_key_is_content_hashed(tmp_path):
    """Two same-size verdict sets for one binary must not collide on a
    len()-keyed snapshot id (INSERT OR IGNORE kept the stale one)."""
    target = tmp_path / "target"
    run_dir = tmp_path / "run"
    src = target / "server.c"
    src.parent.mkdir(parents=True, exist_ok=True)
    run_dir.mkdir(parents=True, exist_ok=True)
    save_json(run_dir / "checklist.json", {
        "target_path": str(target),
        "files": [{"path": "server.c", "sha256": "0" * 64,
                   "items": [{"name": "fn_a", "line_start": 1},
                             {"name": "fn_b", "line_start": 9}]}],
    })
    save_json(run_dir / "context-map.json", {"meta": {"target": str(target)},
                                             "entry_points": [], "sinks": [],
                                             "unchecked_flows": []})
    graph_path = ingest_run(run_dir, str(target))

    assert propagate_binary_verdicts(
        graph_path, {"server.c::fn_a": "absent"}, binary_path="/bin/app") == 1
    assert propagate_binary_verdicts(
        graph_path, {"server.c::fn_b": "absent"}, binary_path="/bin/app") == 1

    with open_graph(graph_path) as conn:
        snaps = conn.execute(
            "SELECT COUNT(*) AS c FROM snapshots WHERE producer='binary_oracle'"
        ).fetchone()["c"]
    assert snaps == 2, "same-size verdict sets collided on one snapshot id"


def test_attack_paths_include_source_keyed_flows(tmp_path):
    """A flow keyed to a ``sources`` entry must not silently drop just
    because entry_points is non-empty (the or-drop idiom)."""
    target = tmp_path / "target"
    run_dir = tmp_path / "run"
    graph_path = _write_run(run_dir, target, source_flow=True)

    paths = attack_paths(graph_path, str(target))
    entry_ids = {p["entry"]["id"] for p in paths}
    assert "EP-1" in entry_ids
    assert "SRC-1" in entry_ids, (
        "source-keyed flow dropped while entry_points was non-empty"
    )
