"""graph_diff snapshot selection is producer-scoped.

Snapshots are per-producer projections of a target: an understand
snapshot carries entry-point/sink/flow nodes, a scan/codeql/validate/
audit snapshot carries none of them. A default diff pair that mixes
producers therefore reads as the whole attack surface appearing or
vanishing — a wrong-verdict-capable operator output after the normal
project cadence (every standalone /scan auto-ingests).
"""

import hashlib
import json

from core.json import save_json
from core.understand_graph import (
    graph_diff,
    ingest_run,
    ingest_scan_findings,
)
from core.understand_graph.store import open_graph


def _write_understand_run(run_dir, target, *, extra_flow=False,
                          extra_confidence="high"):
    src = target / "server.c"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text("void handle_request(char *i) { system(i); }\n",
                   encoding="utf-8")
    sha = hashlib.sha256(src.read_bytes()).hexdigest()
    run_dir.mkdir(parents=True, exist_ok=True)
    checklist = {
        "target_path": str(target),
        "total_files": 1,
        "total_items": 2 if extra_flow else 1,
        "files": [{
            "path": "server.c",
            "sha256": sha,
            "items": [{"name": "handle_request", "line_start": 1}],
        }],
    }
    context_map = {
        "meta": {"target": str(target)},
        "entry_points": [
            {"id": "EP-1", "name": "handle_request", "file": "server.c", "line": 1},
        ],
        "sinks": [
            {"id": "SINK-1", "name": "system", "file": "server.c", "line": 1},
            {"id": "SINK-2", "name": "popen", "file": "server.c", "line": 2},
        ],
        "unchecked_flows": [
            {"id": "FLOW-1", "entry_point": "EP-1", "sink": "SINK-1",
             "confidence": "medium", "missing_boundary": "no auth check"},
            {"id": "FLOW-2", "entry_point": "EP-1", "sink": "SINK-2",
             "confidence": "high", "missing_boundary": "no input validation"},
        ],
    }
    if extra_flow:
        context_map["sinks"].append(
            {"id": "SINK-3", "name": "execve", "file": "server.c", "line": 9})
        context_map["unchecked_flows"].append(
            {"id": "FLOW-3", "entry_point": "EP-1", "sink": "SINK-3",
             "confidence": extra_confidence,
             "missing_boundary": "no sanitisation"})
    save_json(run_dir / "checklist.json", checklist)
    save_json(run_dir / "context-map.json", context_map)
    graph_path = ingest_run(run_dir, str(target))
    assert graph_path is not None
    return graph_path


def _write_scan_run(run_dir, target):
    run_dir.mkdir(parents=True, exist_ok=True)
    save_json(run_dir / "findings.json", [
        {"rule_id": "rule-x1", "file": "server.c",
         "function": "handle_request", "severity": "high",
         "message": "cmd injection"},
    ])
    (run_dir / ".raptor-run.json").write_text(
        json.dumps({"target_path": str(target)}), encoding="utf-8")


def _bump_created_at(graph_path, producer, stamp):
    """Force a deterministic created_at ordering for one producer."""
    with open_graph(graph_path) as conn:
        conn.execute(
            "UPDATE snapshots SET created_at=? WHERE producer=?",
            (stamp, producer),
        )


def test_default_diff_ignores_other_producers_snapshots(tmp_path):
    """understand ingest then scan ingest of the SAME target: the
    default --diff pair must not treat the scan snapshot as the head
    and report the whole surface as removed."""
    target = tmp_path / "target"
    run_dir = tmp_path / "run"
    graph_path = _write_understand_run(run_dir, target)
    _write_scan_run(run_dir, target)
    assert ingest_scan_findings(run_dir, str(target)) is not None
    _bump_created_at(graph_path, "understand", "2026-01-01T00:00:00+00:00")
    _bump_created_at(graph_path, "scan", "2026-01-02T00:00:00+00:00")

    diff = graph_diff(graph_path, str(target))
    assert diff["exists"] is True
    # Only one understand snapshot exists: nothing to compare — never
    # a bogus whole-surface "removed" verdict against the scan head.
    if diff.get("is_diffable"):
        removed = [n for kind in diff["nodes"].values() for n in kind["removed"]]
        assert removed == []
        assert diff["reachability"]["removed"] == []
        assert not diff["is_drifted"]
    else:
        assert "snapshot" in str(diff.get("reason", ""))


def test_default_diff_compares_understand_pair_across_interleaved_scan(tmp_path):
    """Two understand snapshots with a NEWER scan snapshot in between:
    the default diff still compares the two understand snapshots and
    reports the genuine drift."""
    target = tmp_path / "target"
    run1 = tmp_path / "run1"
    graph_path = _write_understand_run(run1, target)
    _bump_created_at(graph_path, "understand", "2026-01-01T00:00:00+00:00")

    # Second understand snapshot: same run dir (same graph DB), new
    # checklist hash — a fresh snapshot with one extra flow.
    _write_understand_run(run1, target, extra_flow=True)
    with open_graph(graph_path) as conn:
        conn.execute(
            "UPDATE snapshots SET created_at=? WHERE producer='understand' "
            "AND created_at > '2026-01-01T00:00:01'",
            ("2026-01-02T00:00:00+00:00",),
        )

    _write_scan_run(run1, target)
    assert ingest_scan_findings(run1, str(target)) is not None
    _bump_created_at(graph_path, "scan", "2026-01-03T00:00:00+00:00")

    diff = graph_diff(graph_path, str(target))
    assert diff["is_diffable"] is True
    assert diff["base_snapshot"]["created_at"].startswith("2026-01-01")
    assert diff["head_snapshot"]["created_at"].startswith("2026-01-02")
    added_sinks = [n["id"] or n["name"] for n in diff["nodes"]["sink"]["added"]]
    assert added_sinks
    # The scan snapshot never reads as removal of the surface.
    removed = [n for kind in diff["nodes"].values() for n in kind["removed"]]
    assert removed == []


def test_single_explicit_endpoint_defaults_within_its_producer(tmp_path):
    """--head-snapshot naming a scan snapshot: the defaulted base must
    come from the SAME producer, never from understand rows (a second
    producer-blindness shape — half-explicit pairs)."""
    target = tmp_path / "target"
    run_dir = tmp_path / "run"
    graph_path = _write_understand_run(run_dir, target)
    _write_scan_run(run_dir, target)
    assert ingest_scan_findings(run_dir, str(target)) is not None
    _bump_created_at(graph_path, "understand", "2026-01-01T00:00:00+00:00")
    _bump_created_at(graph_path, "scan", "2026-01-02T00:00:00+00:00")

    with open_graph(graph_path) as conn:
        scan_snap = conn.execute(
            "SELECT id FROM snapshots WHERE producer='scan'"
        ).fetchone()["id"]

    diff = graph_diff(graph_path, str(target), head_snapshot=scan_snap)
    # Only one scan snapshot exists, so there is no same-producer base:
    # the diff refuses rather than comparing against understand rows.
    assert diff.get("is_diffable") is not True


def test_explicit_snapshot_pair_stays_unrestricted(tmp_path):
    """Explicit --base-snapshot AND --head-snapshot may cross
    producers — the operator asked for exactly that pair."""
    target = tmp_path / "target"
    run_dir = tmp_path / "run"
    graph_path = _write_understand_run(run_dir, target)
    _write_scan_run(run_dir, target)
    assert ingest_scan_findings(run_dir, str(target)) is not None

    with open_graph(graph_path) as conn:
        rows = conn.execute(
            "SELECT id, producer FROM snapshots ORDER BY producer"
        ).fetchall()
    by_producer = {r["producer"]: r["id"] for r in rows}
    diff = graph_diff(
        graph_path, str(target),
        base_snapshot=by_producer["understand"],
        head_snapshot=by_producer["scan"],
    )
    assert diff["is_diffable"] is True
    assert diff["base_snapshot"]["id"] == by_producer["understand"]
    assert diff["head_snapshot"]["id"] == by_producer["scan"]


def test_unchecked_reads_the_nested_evidence_key(tmp_path):
    """The producer stores missing_boundary under evidence["flow"];
    the diff's reachability index read it at the top level, so every
    edge rendered unchecked=False and a genuinely new unchecked flow
    below high confidence never surfaced as a new risk."""
    from core.understand_graph.queries import _snapshot_reachability_index

    target = tmp_path / "target"
    run_dir = tmp_path / "run"
    graph_path = _write_understand_run(run_dir, target)
    with open_graph(graph_path) as conn:
        snap = conn.execute(
            "SELECT id FROM snapshots ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        index = _snapshot_reachability_index(conn, snap["id"])
    assert index, "fixture must produce reachability edges"
    assert all(edge["unchecked"] for edge in index.values()), (
        "flows carrying missing_boundary must render unchecked=True"
    )


def test_new_medium_confidence_unchecked_flow_is_a_new_risk(tmp_path):
    """A NEW medium-confidence unchecked flow in the head snapshot
    appears in new_risks (the unchecked arm), not only when its
    confidence spelling lands in the high/confirmed set — which is
    also case-folded now ("Confirmed" from an upstream producer)."""
    target = tmp_path / "target"
    run_dir = tmp_path / "run"
    graph_path = _write_understand_run(run_dir, target)
    _bump_created_at(graph_path, "understand", "2026-01-01T00:00:00+00:00")

    _write_understand_run(run_dir, target, extra_flow=True,
                          extra_confidence="medium")
    diff = graph_diff(graph_path, str(target))
    assert diff["is_diffable"] is True
    added = [(e["source"], e["sink"]) for e in diff["reachability"]["added"]]
    assert ("handle_request", "execve") in added
    risks = [(e["source"], e["sink"]) for e in diff["new_risks"]]
    assert ("handle_request", "execve") in risks, (
        "medium-confidence unchecked flow missing from new_risks"
    )


def test_new_risks_confidence_set_is_case_folded(tmp_path):
    target = tmp_path / "target"
    run_dir = tmp_path / "run"
    graph_path = _write_understand_run(run_dir, target)
    _bump_created_at(graph_path, "understand", "2026-01-01T00:00:00+00:00")

    _write_understand_run(run_dir, target, extra_flow=True,
                          extra_confidence="Confirmed")
    diff = graph_diff(graph_path, str(target))
    risks = [(e["source"], e["sink"]) for e in diff["new_risks"]]
    assert ("handle_request", "execve") in risks


def test_explicit_older_head_defaults_base_backwards_in_time(tmp_path):
    """--head-snapshot naming a MIDDLE snapshot: the defaulted base
    must be the newest snapshot OLDER than the head — defaulting to
    the global newest produced a time-reversed drift verdict (the
    newest snapshot's genuinely new surface reported as removed)."""
    target = tmp_path / "target"
    run_dir = tmp_path / "run"
    graph_path = _write_understand_run(run_dir, target)
    _bump_created_at(graph_path, "understand", "2026-01-01T00:00:00+00:00")

    _write_understand_run(run_dir, target, extra_flow=True)
    with open_graph(graph_path) as conn:
        conn.execute(
            "UPDATE snapshots SET created_at=? WHERE producer='understand' "
            "AND created_at > '2026-01-01T00:00:01'",
            ("2026-01-02T00:00:00+00:00",),
        )
    # Third snapshot: a separate run dir (distinct snapshot id),
    # pinned into the same store; newest of all.
    from core.understand_graph import ingest_run as _ingest_run

    run2 = tmp_path / "run2"
    _write_understand_run(run2, target, extra_flow=True)  # seeds artifacts
    assert _ingest_run(run2, str(target), graph_path=graph_path) is not None
    with open_graph(graph_path) as conn:
        conn.execute(
            "UPDATE snapshots SET created_at=? WHERE producer='understand' "
            "AND created_at > '2026-01-02T00:00:01'",
            ("2026-01-03T00:00:00+00:00",),
        )
        middle = conn.execute(
            "SELECT id FROM snapshots WHERE created_at LIKE '2026-01-02%'"
        ).fetchone()["id"]

    diff = graph_diff(graph_path, str(target), head_snapshot=middle)
    assert diff["is_diffable"] is True
    assert diff["base_snapshot"]["created_at"].startswith("2026-01-01")
    # Time flows base -> head: nothing from the NEWEST snapshot can
    # read as removed surface.
    removed = [n for kind in diff["nodes"].values() for n in kind["removed"]]
    assert removed == []
