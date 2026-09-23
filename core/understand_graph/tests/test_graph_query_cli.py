"""Terminal-escape tests for libexec/raptor-graph-query.

Graph node ids / labels are ingested from run artifacts — scanned-tree
file and function names, LLM hypothesis text — so the CLI's
human-readable lanes must escape at the sink. A hostile repo that puts
ANSI/OSC bytes in a path or function name must not reach the operator
TTY raw through --paths / --threat-context / --reachable-sinks.
"""

import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

# Every test spawns the real libexec/raptor-graph-query as a
# subprocess; opt-in via ``pytest -m integration``.
pytestmark = pytest.mark.integration

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
