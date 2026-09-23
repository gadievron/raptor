"""VALIDATES edges join on exact identity, never substring LIKE.

The ingest used to mint VALIDATES edges via
``stable_key LIKE '%<ref>%'`` — a short or numeric finding id (a
recorded /validate shape) substring-matched an unrelated
unchecked_flow, and the exact-join coverage_residual then silently
dropped a never-validated path from the residual report while the
dashboard inflated validation_coverage. Identity is now equality on
the composed stable_key or a props-extracted id; no exact match means
NO edge.
"""

import hashlib
import json

from core.json import save_json
from core.understand_graph import (
    coverage_residual,
    dashboard_summary,
    ingest_run,
    ingest_validation_outcomes,
)
from core.understand_graph.store import open_graph


def _write_two_flow_run(run_dir, target, *, flow_ids=("FLOW-1", "FLOW-2")):
    src = target / "server.c"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text("int handle_request(){system(cmd);popen(cmd);}\n",
                   encoding="utf-8")
    sha = hashlib.sha256(src.read_bytes()).hexdigest()
    run_dir.mkdir(parents=True, exist_ok=True)
    save_json(run_dir / "checklist.json", {
        "target_path": str(target),
        "total_files": 1,
        "total_items": 1,
        "files": [{
            "path": "server.c",
            "sha256": sha,
            "items": [{"name": "handle_request", "line_start": 1}],
        }],
    })
    save_json(run_dir / "context-map.json", {
        "meta": {"target": str(target)},
        "entry_points": [{"id": "EP-1", "name": "handle_request",
                          "file": "server.c", "line": 1}],
        "sinks": [
            {"id": "SINK-1", "name": "system", "file": "server.c", "line": 1},
            {"id": "SINK-2", "name": "popen", "file": "server.c", "line": 1},
        ],
        "unchecked_flows": [
            {"id": flow_ids[0], "entry_point": "EP-1", "sink": "SINK-1",
             "confidence": "medium", "missing_boundary": "no auth"},
            {"id": flow_ids[1], "entry_point": "EP-1", "sink": "SINK-2",
             "confidence": "high", "missing_boundary": "no validation"},
        ],
    })
    graph_path = ingest_run(run_dir, str(target))
    assert graph_path is not None
    return graph_path


def _validates_targets(graph_path):
    with open_graph(graph_path) as conn:
        return sorted(
            row["stable_key"] for row in conn.execute(
                "SELECT n.stable_key FROM edges e "
                "JOIN nodes n ON n.id = e.dst_id "
                "WHERE e.kind='VALIDATES'"
            )
        )


def test_numeric_ref_never_substring_matches_a_flow(tmp_path):
    """A short numeric outcome ref ({'finding_id': '1'}) used to mint
    VALIDATES -> unchecked_flow://FLOW-1 by substring accident and
    falsely suppress SINK-1 from the residual."""
    target = tmp_path / "target"
    run_dir = tmp_path / "run"
    graph_path = _write_two_flow_run(run_dir, target)

    before = {p["sink"]["id"] for p in coverage_residual(graph_path, str(target))}
    assert before == {"SINK-1", "SINK-2"}

    save_json(run_dir / "validation-outcomes.json",
              [{"finding_id": "1", "status": "exploitable"}])
    ingest_validation_outcomes(run_dir, str(target))

    assert _validates_targets(graph_path) == []
    after = {p["sink"]["id"] for p in coverage_residual(graph_path, str(target))}
    assert after == before, "no exact match must suppress nothing"
    assert dashboard_summary(graph_path)["validation_coverage"] == 0.0


def test_prefix_ref_matches_exactly_one_flow(tmp_path):
    """FLOW-1 vs FLOW-10: validating FLOW-1 must not also (or instead)
    suppress FLOW-10's path."""
    target = tmp_path / "target"
    run_dir = tmp_path / "run"
    # FLOW-10 ingests first so the old LIKE-with-LIMIT-1 idiom hits it
    # before FLOW-1 — the discriminating order.
    graph_path = _write_two_flow_run(
        run_dir, target, flow_ids=("FLOW-10", "FLOW-1"))

    save_json(run_dir / "validation-outcomes.json",
              [{"finding_id": "FLOW-1", "status": "exploitable"}])
    ingest_validation_outcomes(run_dir, str(target))

    # FLOW-10 -> SINK-1, FLOW-1 -> SINK-2 in this fixture order.
    assert _validates_targets(graph_path) == ["unchecked_flow://FLOW-1"]
    after = {p["sink"]["id"] for p in coverage_residual(graph_path, str(target))}
    assert after == {"SINK-1"}, "FLOW-10's never-validated path must survive"


def test_props_id_equality_joins_scan_findings(tmp_path):
    """A scan finding carrying an explicit id joins by props-extracted
    identity; a rule-id-shaped ref (shared across findings) does not."""
    from core.understand_graph import ingest_scan_findings

    target = tmp_path / "target"
    run_dir = tmp_path / "run"
    graph_path = _write_two_flow_run(run_dir, target)

    # SCAN-8 ingests first: the old rule-id substring join with
    # LIMIT 1 landed on it — the discriminating order.
    save_json(run_dir / "findings.json", [
        {"id": "SCAN-8", "rule_id": "command-injection", "file": "server.c",
         "function": "handle_request", "severity": "high", "message": "m2"},
        {"id": "SCAN-7", "rule_id": "command-injection", "file": "server.c",
         "function": "handle_request", "severity": "high", "message": "m"},
    ])
    (run_dir / ".raptor-run.json").write_text(
        json.dumps({"target_path": str(target)}), encoding="utf-8")
    assert ingest_scan_findings(run_dir, str(target)) is not None

    save_json(run_dir / "validation-outcomes.json", [
        {"finding_id": "SCAN-7", "status": "exploitable"},
        {"finding_id": "command-injection", "status": "exploitable"},
    ])
    ingest_validation_outcomes(run_dir, str(target))

    targets = _validates_targets(graph_path)
    assert len(targets) == 1
    assert "SCAN-7" in targets[0] or targets[0].startswith("scan_finding://")
    with open_graph(graph_path) as conn:
        joined = conn.execute(
            "SELECT props_json FROM nodes WHERE id IN "
            "(SELECT dst_id FROM edges WHERE kind='VALIDATES')"
        ).fetchall()
    ids = {json.loads(r["props_json"]).get("id") for r in joined}
    assert ids == {"SCAN-7"}, (
        "a rule id shared across findings is not a finding identity"
    )
