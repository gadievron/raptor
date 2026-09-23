"""CLI-contract tests for libexec/raptor-graph-query.

Terminal escaping: graph node ids / labels are ingested from run
artifacts — scanned-tree file and function names, LLM hypothesis text
— so the CLI's human-readable lanes must escape at the sink. A hostile
repo that puts ANSI/OSC bytes in a path or function name must not
reach the operator TTY raw through --paths / --threat-context /
--reachable-sinks.

Argument forwarding: --target and --limit must reach every query lane
— a dropped --target answers a target-A query with target-B's memory
while claiming target scope.

These spawn the real CLI as a subprocess but touch no network; they
run on the default tier so the landed terminal-escape fix (and the
forwarding contract) stay pinned on the PR gate — the ``integration``
marker means live-network and is deselected there, which left these
pins never running in CI.
"""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

# parents[3] = core/understand_graph/tests → … → repo root. Anchor to
# this file, not $RAPTOR_DIR, so the wrapper resolves within this
# worktree.
REPO_ROOT = Path(__file__).resolve().parents[3]
WRAPPER = REPO_ROOT / "libexec" / "raptor-graph-query"

sys.path.insert(0, str(REPO_ROOT))

from core.json import save_json  # noqa: E402
from core.understand_graph import ingest_run  # noqa: E402

_ANSI_NAME = "handle\x1b[31m_request\x1b]0;pwned\x07"


def _seed_hostile_graph(tmp: Path) -> Path:
    target = tmp / "target"
    target.mkdir()
    (target / "server.c").write_text("void f() {}\n")
    run_dir = tmp / "run"
    run_dir.mkdir()
    save_json(run_dir / "checklist.json", {
        "target_path": str(target),
        "files": [{"path": "server.c", "language": "c", "items": []}],
    })
    # The node IDs themselves carry hostile bytes: labels prefer
    # props["id"], so an id-borne escape is what actually reaches the
    # --threat-context / --paths lanes.
    hostile_ep = "EP-\x1b[31m1"
    save_json(run_dir / "context-map.json", {
        "meta": {"target": str(target)},
        "entry_points": [
            {"id": hostile_ep, "name": _ANSI_NAME, "file": "server.c", "line": 1},
        ],
        "sink_details": [
            {"id": "SINK-1", "name": "system\x1b[0m", "file": "server.c", "line": 2},
        ],
        "unchecked_flows": [
            # missing_boundary is free text that the threat-context
            # lane renders verbatim per flow.
            {"entry_point": hostile_ep, "sink": "SINK-1",
             "confidence": "high",
             "missing_boundary": "no auth check \x1b[35mpwned\x07"},
        ],
    })
    graph_path = ingest_run(run_dir, str(target))
    assert graph_path is not None
    return graph_path


def _run(*args):
    env = {**os.environ, "_RAPTOR_TRUSTED": "1"}
    return subprocess.run(
        [sys.executable, str(WRAPPER), *args],
        capture_output=True, text=True, timeout=60, env=env,
        cwd=str(REPO_ROOT),
    )


class GraphQueryTerminalEscapeTests(unittest.TestCase):

    def test_paths_lane_escapes_hostile_labels(self):
        with TemporaryDirectory() as td:
            graph = _seed_hostile_graph(Path(td))
            proc = _run("--db", str(graph), "--paths")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("SINK-1", proc.stdout)
            self.assertNotIn("\x1b", proc.stdout)
            self.assertNotIn("\x07", proc.stdout)

    def test_threat_context_lane_escapes_hostile_labels(self):
        with TemporaryDirectory() as td:
            graph = _seed_hostile_graph(Path(td))
            proc = _run("--db", str(graph), "--threat-context")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertNotIn("\x1b", proc.stdout)

    def test_reachable_sinks_lane_escapes_hostile_labels(self):
        with TemporaryDirectory() as td:
            graph = _seed_hostile_graph(Path(td))
            proc = _run("--db", str(graph), "--reachable-sinks")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertNotIn("\x1b", proc.stdout)

    def test_json_lane_stays_machine_exact(self):
        with TemporaryDirectory() as td:
            graph = _seed_hostile_graph(Path(td))
            proc = _run("--db", str(graph), "--paths", "--json")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            # json.dumps default ensure_ascii escapes nothing below
            # 0x20 into raw bytes — the machine lane carries \u escapes.
            self.assertNotIn("\x1b", proc.stdout)


def _seed_two_target_graph(tmp: Path) -> tuple[Path, str, str]:
    """One graph DB holding two targets' memory (target-B newest)."""
    import time

    from core.understand_graph import ingest_scan_findings

    run_dir = tmp / "run"
    graphs: list[Path] = []
    targets: list[str] = []
    for name, entry, sink in (("target-A", "alpha_entry", "system"),
                              ("target-B", "beta_entry", "execve")):
        target = tmp / name
        target.mkdir(exist_ok=True)
        (target / "code.c").write_text(f"void {entry}() {{ {sink}(x); }}\n")
        run_dir.mkdir(exist_ok=True)
        items = [{"name": entry, "line_start": 1}]
        if name == "target-B":
            items.append({"name": "gamma_entry", "line_start": 9})
        save_json(run_dir / "checklist.json", {
            "target_path": str(target),
            "files": [{"path": "code.c", "sha256": "0" * 64,
                       "items": items}],
        })
        context_map: dict[str, Any] = {
            "meta": {"target": str(target)},
            "entry_points": [{"id": "EP", "name": entry, "file": "code.c", "line": 1}],
            "sinks": [{"id": "SK", "name": sink, "file": "code.c", "line": 1}],
            "unchecked_flows": [{"id": "F", "entry_point": "EP", "sink": "SK",
                                 "confidence": "high"}],
        }
        if name == "target-B":
            # A second seed on the newest snapshot so --limit is
            # observable on the un-targeted lane.
            context_map["entry_points"].append(
                {"id": "EP2", "name": "gamma_entry", "file": "code.c", "line": 9})
            context_map["unchecked_flows"].append(
                {"id": "F2", "entry_point": "EP2", "sink": "SK",
                 "confidence": "high"})
        save_json(run_dir / "context-map.json", context_map)
        graph = ingest_run(run_dir, str(target))
        assert graph is not None
        graphs.append(graph)
        for i in range(2):
            save_json(run_dir / "findings.json", [
                {"rule_id": f"r{i}-{entry}", "file": "code.c",
                 "function": entry, "severity": "high", "message": "m"},
            ])
            ingest_scan_findings(run_dir, str(target))
        targets.append(str(target))
        time.sleep(0.02)
    assert str(graphs[0]) == str(graphs[1])
    return graphs[0], targets[0], targets[1]


class GraphQueryTargetForwardingTests(unittest.TestCase):
    """--target/--limit reach the seeds / fuzz-targets / dedup lanes."""

    def test_hypothesis_seeds_respects_target(self):
        with TemporaryDirectory() as td:
            graph, target_a, _ = _seed_two_target_graph(Path(td))
            proc = _run("--db", str(graph), "--target", target_a,
                        "--hypothesis-seeds", "--json")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            seeds = json.loads(proc.stdout)["seeds"]
            functions = {s["function"] for s in seeds}
            self.assertEqual(functions, {"alpha_entry"}, (
                "target-B's memory answered a target-A query"
            ))

    def test_fuzz_targets_respects_target(self):
        with TemporaryDirectory() as td:
            graph, target_a, _ = _seed_two_target_graph(Path(td))
            proc = _run("--db", str(graph), "--target", target_a,
                        "--fuzz-targets", "--json")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            rows = json.loads(proc.stdout)["fuzz_targets"]
            pairs = {(r["function"], r["dangerous_sink"]) for r in rows}
            self.assertEqual(pairs, {("alpha_entry", "system")})

    def test_dedup_chains_respects_target(self):
        with TemporaryDirectory() as td:
            graph, target_a, _ = _seed_two_target_graph(Path(td))
            proc = _run("--db", str(graph), "--target", target_a,
                        "--dedup-chains", "--json")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            chains = json.loads(proc.stdout)["dedup_chains"]
            self.assertEqual(len(chains), 1, chains)

    def test_limit_reaches_the_seeds_lane(self):
        with TemporaryDirectory() as td:
            graph, _target_a, target_b = _seed_two_target_graph(Path(td))
            # target-B (the newest understand snapshot) carries TWO
            # seeds; --limit 1 must cut to one. An unforwarded --limit
            # returned the lane default (20) and both came back.
            proc = _run("--db", str(graph), "--target", target_b,
                        "--hypothesis-seeds", "--limit", "1", "--json")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            seeds = json.loads(proc.stdout)["seeds"]
            self.assertEqual(len(seeds), 1, seeds)


if __name__ == "__main__":
    unittest.main()


_HOSTILE_KIND = "fn\x1b]0;PWNED\x07\x1b[2Jentry"


def _seed_hostile_kind_graph(tmp: Path) -> Path:
    """A store whose node/edge KIND columns carry hostile bytes.

    The kind vocabulary is not enforced at INSERT and the store lives
    in the run/project directory whose write grant sandboxed target
    code holds — the summary lane's kind keys are attacker-influenced
    bytes exactly like names and labels.
    """
    from core.understand_graph.store import open_graph

    db = tmp / "hostile.graph.sqlite"
    conn = open_graph(db)
    conn.execute(
        "INSERT INTO snapshots (id, target_path) VALUES ('s1', '/tgt')")
    conn.execute(
        "INSERT INTO nodes (id, kind, stable_key, name, file,"
        " snapshot_id, stale) VALUES ('n1', ?, 'k1', 'n', 'f.c',"
        " 's1', 0)", (_HOSTILE_KIND,))
    conn.execute(
        "INSERT INTO nodes (id, kind, stable_key, name, file,"
        " snapshot_id, stale) VALUES ('n2', 'sink', 'k2', 'm',"
        " 'g.c', 's1', 0)")
    conn.execute(
        "INSERT INTO edges (id, src_id, dst_id, kind, snapshot_id,"
        " stale) VALUES ('e1', 'n1', 'n2', ?, 's1', 0)",
        (_HOSTILE_KIND,))
    conn.commit()
    conn.close()
    return db


class GraphQuerySummaryKindEscapeTests(unittest.TestCase):

    def test_summary_lane_escapes_hostile_kinds(self):
        with TemporaryDirectory() as td:
            db = _seed_hostile_kind_graph(Path(td))
            proc = _run("--db", str(db), "--summary")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("Nodes:", proc.stdout)
            self.assertIn("Edges:", proc.stdout)
            self.assertNotIn("\x1b", proc.stdout)
            self.assertNotIn("\x07", proc.stdout)

    def test_summary_json_lane_stays_machine_exact(self):
        with TemporaryDirectory() as td:
            db = _seed_hostile_kind_graph(Path(td))
            proc = _run("--db", str(db), "--summary", "--json")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = __import__("json").loads(proc.stdout)
            self.assertIn(_HOSTILE_KIND, payload.get("nodes", {}))


class GraphQueryLimitFloorTests(unittest.TestCase):
    def test_limit_below_one_is_refused_at_parse_time(self):
        # 0 silently blanks the SQL lanes and a negative value is
        # LIMIT -n = unbounded in SQLite; both refuse loudly.
        for bad in ("0", "-5"):
            proc = _run("--db", "/nonexistent", "--hypothesis-seeds",
                        "--limit", bad)
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertIn(">= 1", proc.stderr)
