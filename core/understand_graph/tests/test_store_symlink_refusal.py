"""The graph DB slot must hold a regular file or nothing.

The store's integrity binding is keyed to the graph path's parent
dir, so a symlink planted at the DB name points reads at a foreign
store whose rows still VERIFY, and every write lands on the link
target. Nothing in the pipeline creates the DB as a symlink.
"""

import os
import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.understand_graph.store import (
    GRAPH_FILENAME,
    GraphStoreUnsafeError,
    graph_connection,
    open_graph,
)


class TestSymlinkedDbRefused(unittest.TestCase):

    def test_symlinked_db_refused_and_target_untouched(self):
        with TemporaryDirectory() as d:
            tmp = Path(d)
            # A real foreign store the plant redirects to.
            foreign = tmp / "foreign" / GRAPH_FILENAME
            foreign.parent.mkdir()
            conn = sqlite3.connect(foreign)
            conn.execute("CREATE TABLE marker (x INTEGER)")
            conn.commit()
            conn.close()
            before = foreign.read_bytes()

            run_graph = tmp / "run" / "graph" / GRAPH_FILENAME
            run_graph.parent.mkdir(parents=True)
            run_graph.symlink_to(foreign)

            with self.assertRaises(GraphStoreUnsafeError):
                open_graph(run_graph)
            self.assertEqual(foreign.read_bytes(), before)

    def test_dangling_symlink_refused_not_created_through(self):
        with TemporaryDirectory() as d:
            tmp = Path(d)
            victim = tmp / "victim.sqlite"
            run_graph = tmp / "graph" / GRAPH_FILENAME
            run_graph.parent.mkdir()
            run_graph.symlink_to(victim)
            with self.assertRaises(GraphStoreUnsafeError):
                open_graph(run_graph)
            # Following the dangling link would create the victim.
            self.assertFalse(victim.exists())

    def test_fifo_refused(self):
        with TemporaryDirectory() as d:
            run_graph = Path(d) / "graph" / GRAPH_FILENAME
            run_graph.parent.mkdir()
            os.mkfifo(run_graph)
            with self.assertRaises(GraphStoreUnsafeError):
                open_graph(run_graph)


class TestRegularDbUnchanged(unittest.TestCase):

    def test_fresh_create_and_reopen(self):
        with TemporaryDirectory() as d:
            run_graph = Path(d) / "graph" / GRAPH_FILENAME
            with graph_connection(run_graph) as conn:
                conn.execute(
                    "SELECT count(*) FROM sqlite_master").fetchone()
            self.assertTrue(run_graph.is_file())
            # Reopening the now-existing regular DB stays allowed.
            with graph_connection(run_graph) as conn:
                row = conn.execute("PRAGMA journal_mode").fetchone()
                self.assertEqual(row[0], "wal")


if __name__ == "__main__":
    unittest.main()
