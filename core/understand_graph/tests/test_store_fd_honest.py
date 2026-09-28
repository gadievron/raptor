"""Check-then-use closure on the graph DB slot.

The landed by-name refusal (``test_store_symlink_refusal``) covers a
STEADY-STATE plant. These tests cover the race the by-name check left
open: a swap landing between the slot check and ``sqlite3.connect``'s
own by-name open. The deterministic race hook wraps
``sqlite3.connect`` so the plant lands after every pre-check and
immediately before sqlite opens — the exact TOCTOU window.

Residual stated honestly: sqlite's own fd is unreachable from Python,
so the post-connect witness (``PRAGMA database_list`` inode identity)
catches a lingering swap but cannot catch a swap-in/swap-back pair
that completes entirely within sqlite's open; the WAL/-shm sidecar
names are opened by sqlite by name and carry no guard (unchanged from
the pre-fix posture).
"""

import os
import sqlite3
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from core.understand_graph.store import (
    GRAPH_FILENAME,
    GraphStoreUnsafeError,
    _verify_connected_identity,
    graph_connection,
    open_graph,
)


def _make_store(path: Path) -> None:
    """Create a legitimate graph store via the real open path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with graph_connection(path) as conn:
        conn.execute("SELECT count(*) FROM sqlite_master").fetchone()


def _make_foreign(path: Path) -> bytes:
    """A foreign sqlite DB the plant redirects to; returns its bytes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE marker (x INTEGER)")
    conn.commit()
    conn.close()
    return path.read_bytes()


class TestSwapBetweenCheckAndConnect(unittest.TestCase):
    """Attack direction: the swap lands INSIDE the check→use window."""

    def test_symlink_swap_before_connect_refused(self):
        with TemporaryDirectory() as d:
            tmp = Path(d)
            foreign = tmp / "foreign" / GRAPH_FILENAME
            before = _make_foreign(foreign)

            run_graph = tmp / "run" / "graph" / GRAPH_FILENAME
            _make_store(run_graph)

            real_connect = sqlite3.connect

            def swapping_connect(database, *args, **kwargs):
                # The plant lands after every pre-open check has
                # already passed, immediately before sqlite's open.
                run_graph.unlink()
                run_graph.symlink_to(foreign)
                return real_connect(database, *args, **kwargs)

            with mock.patch("sqlite3.connect", swapping_connect):
                with self.assertRaises(GraphStoreUnsafeError):
                    open_graph(run_graph)

            # The foreign store was never written: no schema
            # migration, no pragma writes, no WAL sidecars.
            self.assertEqual(foreign.read_bytes(), before)
            self.assertFalse(
                foreign.with_name(foreign.name + "-wal").exists())
            self.assertFalse(
                foreign.with_name(foreign.name + "-shm").exists())

    def test_fresh_create_symlink_swap_refused(self):
        # Fresh-create path: nothing existed at probe time, so the
        # probe pins no inode — the plant then lands before connect
        # and sqlite CREATES through the link. The post-connect
        # re-probe must refuse before any schema lands on the victim.
        with TemporaryDirectory() as d:
            tmp = Path(d)
            victim = tmp / "victim.sqlite"
            run_graph = tmp / "graph" / GRAPH_FILENAME
            run_graph.parent.mkdir(parents=True)

            real_connect = sqlite3.connect

            def swapping_connect(database, *args, **kwargs):
                if not run_graph.is_symlink():
                    run_graph.symlink_to(victim)
                return real_connect(database, *args, **kwargs)

            with mock.patch("sqlite3.connect", swapping_connect):
                with self.assertRaises(GraphStoreUnsafeError):
                    open_graph(run_graph)

            # sqlite's by-name open may have created the victim as an
            # empty file, but the refusal fired before the migration:
            # no schema was ever written through the link.
            if victim.exists():
                self.assertEqual(victim.stat().st_size, 0)

    def test_regular_file_swap_before_connect_refused(self):
        # Same-directory swap with a REGULAR file (no symlink): the
        # probe pinned the original inode; sqlite opened the impostor.
        with TemporaryDirectory() as d:
            tmp = Path(d)
            impostor = tmp / "impostor.sqlite"
            _make_foreign(impostor)

            run_graph = tmp / "graph" / GRAPH_FILENAME
            _make_store(run_graph)

            real_connect = sqlite3.connect

            def swapping_connect(database, *args, **kwargs):
                os.replace(impostor, run_graph)
                return real_connect(database, *args, **kwargs)

            with mock.patch("sqlite3.connect", swapping_connect):
                with self.assertRaises(GraphStoreUnsafeError):
                    open_graph(run_graph)

    def test_refused_connection_is_closed(self):
        # The refusal path must CLOSE the connection it opened —
        # leaking it would hold the foreign DB open (fd + sqlite
        # file locks) for the process lifetime after the identity
        # witness already said the bytes are not ours. Observed via
        # the connection object itself: executing on a closed
        # sqlite3 connection raises ProgrammingError.
        with TemporaryDirectory() as d:
            tmp = Path(d)
            foreign = tmp / "foreign" / GRAPH_FILENAME
            _make_foreign(foreign)
            run_graph = tmp / "run" / "graph" / GRAPH_FILENAME
            _make_store(run_graph)

            real_connect = sqlite3.connect
            opened: list[sqlite3.Connection] = []

            def swapping_connect(database, *args, **kwargs):
                run_graph.unlink()
                run_graph.symlink_to(foreign)
                conn = real_connect(database, *args, **kwargs)
                opened.append(conn)
                return conn

            with mock.patch("sqlite3.connect", swapping_connect):
                with self.assertRaises(GraphStoreUnsafeError):
                    open_graph(run_graph)

            self.assertEqual(len(opened), 1)
            with self.assertRaises(sqlite3.ProgrammingError):
                opened[0].execute("SELECT 1")


class TestHonestPathPreserved(unittest.TestCase):
    """Preservation direction: legitimate regular-file behaviour is
    unchanged — same schema, same WAL mode, same reopen semantics."""

    def test_fresh_create_reopen_and_wal_unchanged(self):
        with TemporaryDirectory() as d:
            run_graph = Path(d) / "graph" / GRAPH_FILENAME
            _make_store(run_graph)
            self.assertTrue(run_graph.is_file())
            with graph_connection(run_graph) as conn:
                row = conn.execute("PRAGMA journal_mode").fetchone()
                self.assertEqual(row[0], "wal")
                fk = conn.execute("PRAGMA foreign_keys").fetchone()
                self.assertEqual(fk[0], 1)

    def test_data_round_trip_unchanged(self):
        with TemporaryDirectory() as d:
            run_graph = Path(d) / "graph" / GRAPH_FILENAME
            _make_store(run_graph)
            with graph_connection(run_graph) as conn:
                version = conn.execute(
                    "PRAGMA user_version").fetchone()[0]
            self.assertGreater(version, 0)
            # A second open sees the same migrated store.
            with graph_connection(run_graph) as conn:
                self.assertEqual(
                    conn.execute("PRAGMA user_version").fetchone()[0],
                    version)

    def test_connect_called_with_the_plain_path(self):
        # The honest case still connects by the caller's path (no URI
        # rewrite, no resolve-through-parent-symlinks change).
        with TemporaryDirectory() as d:
            run_graph = Path(d) / "graph" / GRAPH_FILENAME
            run_graph.parent.mkdir(parents=True)
            seen: list[object] = []
            real_connect = sqlite3.connect

            def recording_connect(database, *args, **kwargs):
                seen.append(database)
                return real_connect(database, *args, **kwargs)

            with mock.patch("sqlite3.connect", recording_connect):
                conn = open_graph(run_graph)
                conn.close()
            self.assertEqual([Path(p) for p in seen], [run_graph])


def _fake_stat(model: os.stat_result, **overrides: int) -> os.stat_result:
    """A stat_result copied from *model* with named fields replaced."""
    fields = ["st_mode", "st_ino", "st_dev", "st_nlink", "st_uid",
              "st_gid", "st_size", "st_atime", "st_mtime", "st_ctime"]
    return os.stat_result(tuple(
        int(overrides.get(f, getattr(model, f))) for f in fields))


class TestWitnessIdentityCompare(unittest.TestCase):
    """The halves of the post-connect inode witness that
    lingering-swap tests never discriminate."""

    def test_witness_refuses_same_inode_on_a_different_device(self):
        # The witness is a (device, inode) PAIR — inode numbers
        # collide across filesystems (bind/overlay mounts, tmpfs), so
        # the device half must be consumed by the compare, not just
        # carried in the pin.
        with TemporaryDirectory() as d:
            db = Path(d) / GRAPH_FILENAME
            _make_store(db)
            conn = sqlite3.connect(db)
            try:
                real = os.stat(db)
                # The pinned probe allegedly saw the same inode number
                # on a DIFFERENT device: the witness must refuse.
                pinned = _fake_stat(real, st_dev=real.st_dev + 1)
                with self.assertRaises(GraphStoreUnsafeError):
                    _verify_connected_identity(conn, db, pinned)
            finally:
                conn.close()

    def test_swap_in_swap_back_sandwich_refused(self):
        # Plant before connect, restore before the witness reads.
        # Every by-name traversal then sees the honest file while the
        # live connection stays bound to the foreign DB — only a stat
        # of sqlite's PRAGMA-resolved OPENED path catches it. This is
        # the differentiator of the PRAGMA witness over re-statting
        # the caller's path by name.
        with TemporaryDirectory() as d:
            base = Path(d)
            foreign = base / "foreign" / GRAPH_FILENAME
            _make_foreign(foreign)
            run_graph = base / "run" / GRAPH_FILENAME
            _make_store(run_graph)
            keep = base / "keep"
            real_connect = sqlite3.connect

            def sandwich_connect(database, *args, **kwargs):
                os.replace(run_graph, keep)          # swap-in
                run_graph.symlink_to(foreign)
                c = real_connect(database, *args, **kwargs)
                run_graph.unlink()                   # swap-BACK
                os.replace(keep, run_graph)
                return c

            with mock.patch("sqlite3.connect", sandwich_connect):
                with self.assertRaises(GraphStoreUnsafeError):
                    open_graph(run_graph)


if __name__ == "__main__":
    unittest.main()
