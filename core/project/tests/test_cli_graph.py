"""CLI surface for ``raptor project graph`` — hermetic smoke tests.

Drives ``core.project.cli.main`` with a temp projects dir (patched
``PROJECTS_DIR``) and captured stdout/stderr. No network, no LLM.
"""

import contextlib
import io
import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.project.cli import main
from core.project.project import ProjectManager
from core.understand_graph.schema import SCHEMA_VERSION
from core.understand_graph.store import GRAPH_FILENAME, open_graph


def _create_graph(output_dir: Path, *, nodes=None, edges=None):
    """Seed a minimal graph DB under output_dir/graph/."""
    db_path = output_dir / "graph" / GRAPH_FILENAME
    conn = open_graph(db_path)
    conn.execute(
        "INSERT INTO snapshots (id, target_path, created_at, producer_run) "
        "VALUES (?, ?, datetime('now'), ?)",
        ("snap-1", "/some/target", "test"),
    )
    for i, node in enumerate(nodes or [], start=1):
        conn.execute(
            "INSERT INTO nodes (id, snapshot_id, stable_key, kind, name, "
            "file, line_start, line_end, props_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (f"n{i}", "snap-1", f"k{i}", node.get("kind", "function"),
             node.get("name", "f"), node.get("file", "a.py"),
             1, 10, json.dumps({})),
        )
    for i, edge in enumerate(edges or [], start=1):
        conn.execute(
            "INSERT INTO edges (id, snapshot_id, kind, src_id, dst_id, "
            "props_json) VALUES (?, ?, ?, ?, ?, ?)",
            (f"e{i}", "snap-1", edge.get("kind", "CONTAINS"),
             edge.get("src", "n1"), edge.get("dst", "n2"),
             json.dumps({})),
        )
    conn.commit()
    conn.close()
    return db_path


class GraphCliTest(unittest.TestCase):

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.projects_dir = root / "projects"
        self.target = root / "code"
        self.target.mkdir()
        self.out_dir = root / "out" / "myapp"
        mgr = ProjectManager(projects_dir=self.projects_dir)
        mgr.create("myapp", str(self.target),
                    output_dir=str(self.out_dir))
        mgr.set_active("myapp")

    def _run(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        code = 0
        with patch("core.project.project.PROJECTS_DIR", self.projects_dir), \
                patch.object(sys, "argv", ["raptor-project", *argv]), \
                contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            try:
                main()
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 1
        return code, out.getvalue(), err.getvalue()

    # ------------------------------------------------------------------
    # status
    # ------------------------------------------------------------------

    def test_status_no_graph(self):
        code, out, _ = self._run("graph", "status")
        self.assertEqual(code, 0)
        self.assertIn("no graph store", out)

    def test_status_with_graph(self):
        _create_graph(
            self.out_dir,
            nodes=[
                {"kind": "function", "name": "foo"},
                {"kind": "entry_point", "name": "bar"},
            ],
            edges=[{"kind": "CONTAINS", "src": "n1", "dst": "n2"}],
        )
        code, out, _ = self._run("graph", "status")
        self.assertEqual(code, 0)
        self.assertIn("Nodes: 2", out)
        self.assertIn("Edges: 1", out)
        self.assertIn(f"Schema: v{SCHEMA_VERSION}", out)
        self.assertIn("Graph store:", out)

    # ------------------------------------------------------------------
    # stats
    # ------------------------------------------------------------------

    def test_stats_with_graph(self):
        _create_graph(
            self.out_dir,
            nodes=[
                {"kind": "function", "name": "foo"},
                {"kind": "function", "name": "baz"},
                {"kind": "entry_point", "name": "bar"},
            ],
            edges=[
                {"kind": "CONTAINS", "src": "n1", "dst": "n2"},
                {"kind": "REACHES", "src": "n2", "dst": "n3"},
            ],
        )
        code, out, _ = self._run("graph", "stats")
        self.assertEqual(code, 0)
        self.assertIn("function", out)
        self.assertIn("entry_point", out)
        self.assertIn("CONTAINS", out)
        self.assertIn("REACHES", out)
        self.assertIn("TOTAL", out)

    def test_stats_no_graph(self):
        code, out, _ = self._run("graph", "stats")
        self.assertEqual(code, 0)
        self.assertIn("no graph store", out)

    # ------------------------------------------------------------------
    # clear
    # ------------------------------------------------------------------

    def test_clear_removes_db(self):
        db_path = _create_graph(self.out_dir)
        self.assertTrue(db_path.exists())
        code, out, _ = self._run("graph", "clear")
        self.assertEqual(code, 0)
        self.assertIn("Cleared", out)
        self.assertFalse(db_path.exists())

    def test_clear_no_graph(self):
        code, out, _ = self._run("graph", "clear")
        self.assertEqual(code, 0)
        self.assertIn("no graph store to clear", out)

    # ------------------------------------------------------------------
    # rebuild
    # ------------------------------------------------------------------

    def test_rebuild_empty_project(self):
        code, out, _ = self._run("graph", "rebuild")
        self.assertEqual(code, 0)
        self.assertIn("No artefacts found", out)

    # ------------------------------------------------------------------
    # explicit project name
    # ------------------------------------------------------------------

    def test_status_explicit_name(self):
        _create_graph(
            self.out_dir,
            nodes=[{"kind": "function", "name": "x"}],
        )
        code, out, _ = self._run("graph", "status", "myapp")
        self.assertEqual(code, 0)
        self.assertIn("Nodes: 1", out)


if __name__ == "__main__":
    unittest.main()
