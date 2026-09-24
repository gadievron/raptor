"""--calls / --and-not-calls set algebra: substrates, BFS bounds,
fid resolution, honesty surfaces."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import patch

from core.json import save_json

from packages.binary_analysis.hunt import (
    CALLS_MAX_DEPTH_CAP,
    CALLS_MAX_DEPTH_DEFAULT,
    MAX_CALLERS_REPORTED,
    CallGraph,
    HuntError,
    _graph_from_redb,
    callers_of,
    load_call_graph,
    run_calls_hunt,
)
from packages.binary_analysis.manifest import BinaryManifest

BUILD_ID = "fa1544052f2d4bfa87d3d3bfb1b7b9f4aa11c0de"
ANCHOR16 = BUILD_ID[:16]
SHA = "a" * 64


def _write_run_dir(tmp: Path) -> Path:
    run_dir = tmp / "run"
    run_dir.mkdir()
    save_json(run_dir / "binary-manifest.json", {
        "schema_version": 1,
        "binary_path": str(tmp / "target.bin"),
        "binary_sha256": SHA,
        "size_bytes": 128,
        "executable": True,
        "target_kind": "binary",
        "arch": "x86",
        "bits": 64,
        "binary_format": "elf",
        "build_id": BUILD_ID,
        "image_base": 0x400000,
    })
    return run_dir


def _graph() -> CallGraph:
    # a -> b -> parse -> memcpy ; c -> parse ; c -> check
    # d -> check ; parse -> check would change residuals, kept out.
    # cyc1 <-> cyc2, cyc2 -> memcpy (cycle feeding the target).
    callees = {
        "a": {"b"},
        "b": {"parse"},
        "parse": {"sym.imp.memcpy"},
        "c": {"parse", "check"},
        "d": {"check"},
        "cyc1": {"cyc2"},
        "cyc2": {"cyc1", "sym.imp.memcpy"},
    }
    meta = {
        "parse": {"address": 0x401000, "fid": f"{ANCHOR16}:0x1000",
                  "size": 64},
        "check": {"address": 0x401100, "fid": f"{ANCHOR16}:0x1100",
                  "size": 32},
        "a": {"address": 0x402000, "fid": f"{ANCHOR16}:0x2000", "size": 16},
        "b": {"address": 0x402100, "fid": f"{ANCHOR16}:0x2100", "size": 16},
        "c": {"address": 0x402200, "fid": f"{ANCHOR16}:0x2200", "size": 16},
        "d": {"address": 0x402300, "fid": f"{ANCHOR16}:0x2300", "size": 16},
    }
    return CallGraph(substrate="test graph", callees=callees, meta=meta)


def _loader(graph: CallGraph):
    def load(_run_dir: Path, _manifest: BinaryManifest) -> CallGraph:
        return graph
    return load


class TestCallersOf(unittest.TestCase):
    def test_direct_callers_only(self):
        result = callers_of(_graph(), "parse")
        self.assertEqual(result, {"b": 1, "c": 1})

    def test_transitive_with_depths(self):
        result = callers_of(_graph(), "parse", transitive=True)
        self.assertEqual(result, {"b": 1, "c": 1, "a": 2})

    def test_base_name_indexing(self):
        # A call site recorded bare must match the sym.imp. node.
        result = callers_of(_graph(), "memcpy", transitive=True)
        self.assertIn("parse", result)
        self.assertEqual(result["parse"], 1)

    def test_depth_bound_is_exclusive_beyond_cap(self):
        # Chain longer than the default depth: only the first
        # CALLS_MAX_DEPTH_DEFAULT levels appear.
        chain = {f"f{i}": {f"f{i + 1}"} for i in range(10)}
        graph = CallGraph(substrate="chain", callees=chain)
        result = callers_of(graph, "f10", transitive=True)
        self.assertEqual(len(result), CALLS_MAX_DEPTH_DEFAULT)
        self.assertNotIn("f0", result)
        # max_depth is clamped at the hard cap.
        result = callers_of(graph, "f10", transitive=True, max_depth=99)
        self.assertEqual(max(result.values()), min(10, CALLS_MAX_DEPTH_CAP))

    def test_cycles_terminate_with_min_depth(self):
        result = callers_of(_graph(), "sym.imp.memcpy", transitive=True)
        self.assertEqual(result["cyc2"], 1)
        self.assertEqual(result["cyc1"], 2)
        self.assertEqual(result["parse"], 1)

    def test_target_never_its_own_caller(self):
        graph = CallGraph(substrate="self", callees={"f": {"f"}})
        self.assertEqual(callers_of(graph, "f", transitive=True), {})


class TestRunCallsHunt(unittest.TestCase):
    def test_residual_set_algebra(self):
        with TemporaryDirectory() as tmp:
            run_dir = _write_run_dir(Path(tmp))
            payload = run_calls_hunt(
                run_dir, "parse", and_not_calls="check",
                transitive=True, graph_loader=_loader(_graph()),
            )
            callers = {e["name"]: e["depth"] for e in payload["callers"]}
            self.assertEqual(callers, {"b": 1, "c": 1, "a": 2})
            residual = payload["residual"]
            # c calls check directly; a/b never reach check.
            self.assertEqual(
                sorted(e["name"] for e in residual["entries"]),
                ["a", "b"],
            )
            self.assertEqual(residual["kind"], "HUNT_CHOKEPOINT_RESIDUAL")
            self.assertEqual(residual["confidence"], "hypothesis")
            self.assertEqual(residual["evidence_tier"], "heuristic")
            # fid + address enrichment from the substrate meta.
            entry_b = next(e for e in residual["entries"]
                           if e["name"] == "b")
            self.assertEqual(entry_b["fid"], f"{ANCHOR16}:0x2100")
            self.assertEqual(entry_b["address"], "0x402100")
            # Honesty lines both ways.
            honesty = " ".join(payload["honesty"])
            self.assertIn("Absence of a call edge", honesty)
            self.assertIn("Presence of a call edge", honesty)
            report = Path(payload["artifacts"]["report"]).read_text(
                encoding="utf-8",
            )
            self.assertIn("Absence of a call edge", report)
            self.assertIn("Presence of a call edge", report)
            self.assertIn("Chokepoint residual", report)

    def test_empty_residual_is_not_coverage(self):
        graph = CallGraph(
            substrate="test",
            callees={"x": {"parse", "check"}},
            meta={},
        )
        with TemporaryDirectory() as tmp:
            run_dir = _write_run_dir(Path(tmp))
            payload = run_calls_hunt(
                run_dir, "parse", and_not_calls="check",
                graph_loader=_loader(graph),
            )
            residual = payload["residual"]
            self.assertEqual(residual["entries"], [])
            self.assertIn("never reported as coverage",
                          residual["empty_note"])

    def test_degenerate_same_target(self):
        with TemporaryDirectory() as tmp:
            run_dir = _write_run_dir(Path(tmp))
            payload = run_calls_hunt(
                run_dir, "parse", and_not_calls="parse",
                graph_loader=_loader(_graph()),
            )
            residual = payload["residual"]
            self.assertEqual(residual["count"], 0)
            self.assertIn("same function", residual["empty_note"])

    def test_fid_query_resolution(self):
        with TemporaryDirectory() as tmp:
            run_dir = _write_run_dir(Path(tmp))
            payload = run_calls_hunt(
                run_dir, f"{ANCHOR16}:0x1000",
                graph_loader=_loader(_graph()),
            )
            self.assertEqual(payload["query"]["resolved_calls"], "parse")

    def test_unresolvable_query_recorded_and_refused(self):
        with TemporaryDirectory() as tmp:
            run_dir = _write_run_dir(Path(tmp))
            with self.assertRaises(HuntError):
                run_calls_hunt(
                    run_dir, "no_such_fn",
                    graph_loader=_loader(_graph()),
                )
            misses = json.loads(
                (Path(tmp) / "run" / "fid-misses.json").read_text(
                    encoding="utf-8",
                ),
            )
            ops = {op["operation"] for op in misses["operations"]}
            self.assertIn("binary-hunt-calls", ops)

    def test_hostile_query_echo_escaped(self):
        graph = CallGraph(
            substrate="test",
            callees={"caller": {"fn.\x1bpwn"}},
            meta={},
        )
        with TemporaryDirectory() as tmp:
            run_dir = _write_run_dir(Path(tmp))
            payload = run_calls_hunt(
                run_dir, "fn.\x1bpwn", graph_loader=_loader(graph),
            )
            blob = json.dumps(payload)
            self.assertNotIn("\x1b", blob)
            report = Path(payload["artifacts"]["report"]).read_text(
                encoding="utf-8",
            )
            self.assertNotIn("\x1b", report)

    def test_caller_flood_truncates_in_band(self):
        callees = {f"caller{i:04d}": {"parse"}
                   for i in range(MAX_CALLERS_REPORTED + 20)}
        graph = CallGraph(substrate="flood", callees=callees, meta={})
        with TemporaryDirectory() as tmp:
            run_dir = _write_run_dir(Path(tmp))
            payload = run_calls_hunt(
                run_dir, "parse", graph_loader=_loader(graph),
            )
            self.assertEqual(len(payload["callers"]),
                             MAX_CALLERS_REPORTED)
            self.assertEqual(payload["caller_count"],
                             MAX_CALLERS_REPORTED + 20)
            self.assertIn(
                f"capped at {MAX_CALLERS_REPORTED} of",
                " ".join(payload["truncation_lines"]),
            )

    def test_graph_kinds_written(self):
        from packages.binary_analysis.graph_store import (
            graph_path_for_run,
            query_edges,
        )
        with TemporaryDirectory() as tmp:
            run_dir = _write_run_dir(Path(tmp))
            run_calls_hunt(
                run_dir, "parse", and_not_calls="check",
                transitive=True, graph_loader=_loader(_graph()),
            )
            edges = query_edges(
                graph_path_for_run(run_dir),
                kind="HUNT_CHOKEPOINT_RESIDUAL",
            )
            self.assertEqual(len(edges), 2)

    def test_residual_ingest_preserves_map_function_props(self):
        """The residual references the map's function nodes on the
        map's snapshot — the ingest must be add-if-absent (a REPLACE
        wiped calls_dangerous/transitive_distance) and must never mint
        a second snapshot (begin_snapshot on the same run dir would
        cascade-delete the map graph)."""
        import sqlite3

        from packages.binary_analysis.graph_store import (
            BinaryGraphStore,
            graph_path_for_run,
        )
        with TemporaryDirectory() as tmp:
            run_dir = _write_run_dir(Path(tmp))
            graph_path = graph_path_for_run(run_dir)
            with BinaryGraphStore(graph_path) as store:
                snapshot_id = store.begin_snapshot(
                    SHA, str(Path(tmp) / "target.bin"), run_dir,
                )
                # "b" is a residual member (address 0x402100 in the
                # test graph meta -> key BFN-402100).
                store.add_node(
                    snapshot_id, SHA, "function", "BFN-402100",
                    name="b", address="0x402100",
                    props={"calls_dangerous": ["memcpy"],
                           "transitive_distance": 1},
                )
            run_calls_hunt(
                run_dir, "parse", and_not_calls="check",
                transitive=True, graph_loader=_loader(_graph()),
            )
            conn = sqlite3.connect(graph_path)
            try:
                conn.row_factory = sqlite3.Row
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) AS n FROM snapshots")
                    .fetchone()["n"], 1,
                )
                props = json.loads(conn.execute(
                    "SELECT props_json FROM nodes WHERE "
                    "stable_key='BFN-402100'").fetchone()["props_json"])
                self.assertEqual(props.get("calls_dangerous"),
                                 ["memcpy"])
            finally:
                conn.close()

    def test_max_depth_clamped_with_in_band_message(self):
        """Depth-cap survivor pin: a 14-node chain with --max-depth 99
        walks exactly CALLS_MAX_DEPTH_CAP hops, the payload records
        the clamped value, and the clamp is said in-band."""
        chain = {f"f{i:02d}": {f"f{i + 1:02d}"} for i in range(14)}
        graph = CallGraph(substrate="chain", callees=chain, meta={})
        with TemporaryDirectory() as tmp:
            run_dir = _write_run_dir(Path(tmp))
            payload = run_calls_hunt(
                run_dir, "f14", transitive=True, max_depth=99,
                graph_loader=_loader(graph),
            )
            depths = [e["depth"] for e in payload["callers"]]
            self.assertEqual(max(depths), CALLS_MAX_DEPTH_CAP)
            self.assertEqual(len(depths), CALLS_MAX_DEPTH_CAP)
            self.assertEqual(payload["query"]["max_depth"],
                             CALLS_MAX_DEPTH_CAP)
            lines = "\n".join(payload["truncation_lines"])
            self.assertIn("clamped", lines)
            self.assertIn(str(CALLS_MAX_DEPTH_CAP), lines)

    def test_mixed_depth_flood_keeps_nearest_first(self):
        """Nearest-first truncation pin on a MIXED-depth flood: every
        depth-1 caller survives; the tail of depth-2 callers is cut —
        and the kept set is order-deterministic (sorted by (depth,
        name) before the slice, never hash order)."""
        direct = {f"d1_{i:04d}": {"parse"} for i in range(150)}
        indirect = {f"d2_{i:04d}": {"d1_0000"} for i in range(100)}
        graph = CallGraph(
            substrate="flood", callees={**direct, **indirect}, meta={},
        )
        with TemporaryDirectory() as tmp:
            run_dir = _write_run_dir(Path(tmp))
            payload = run_calls_hunt(
                run_dir, "parse", transitive=True,
                graph_loader=_loader(graph),
            )
            entries = payload["callers"]
            self.assertEqual(len(entries), MAX_CALLERS_REPORTED)
            kept_d1 = [e for e in entries if e["depth"] == 1]
            kept_d2 = [e for e in entries if e["depth"] == 2]
            self.assertEqual(len(kept_d1), 150)
            self.assertEqual(len(kept_d2), MAX_CALLERS_REPORTED - 150)
            # Deterministic tail: lexicographically-first depth-2
            # names, regardless of dict/hash iteration order.
            self.assertEqual(
                [e["name"] for e in kept_d2],
                [f"d2_{i:04d}"
                 for i in range(MAX_CALLERS_REPORTED - 150)],
            )
            self.assertIn("nearest-first",
                          " ".join(payload["truncation_lines"]))


class TestSubstrates(unittest.TestCase):
    def _redb_doc(self, *, sha: str | None = SHA) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "source_tool": "ghidra",
            "binary_path": "/x/target.bin",
            "functions": [
                {"name": "caller_fn", "address": 0x1000, "size": 64,
                 "fid": f"{ANCHOR16}:0x1000"},
                {"name": "callee_fn", "address": 0x2000, "size": 32,
                 "fid": f"{ANCHOR16}:0x2000"},
            ],
            "xrefs": [
                {"from_addr": 0x1010, "to_addr": 0x2000, "kind": "call"},
                {"from_addr": 0x1020, "to_addr": 0x2000, "kind": "data"},
            ],
            "metadata": {},
        }
        if sha is not None:
            doc["metadata"]["binary_sha256"] = sha
        return doc

    def _manifest(self, tmp: Path) -> BinaryManifest:
        return BinaryManifest.from_dict({
            "schema_version": 1,
            "binary_path": str(tmp / "target.bin"),
            "binary_sha256": SHA,
            "size_bytes": 1,
            "executable": True,
            "target_kind": "binary",
            "arch": "x86",
            "bits": 64,
            "binary_format": "elf",
            "build_id": BUILD_ID,
            "image_base": 0x400000,
        })

    def test_redb_call_xrefs_resolve_containing_function(self):
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            save_json(run_dir / "re-database.json", self._redb_doc())
            graph = _graph_from_redb(run_dir, self._manifest(run_dir))
            self.assertIsNotNone(graph)
            # The data xref never becomes a call edge; the call xref
            # resolves from-inside-caller_fn -> callee_fn.
            self.assertEqual(graph.callees, {"caller_fn": {"callee_fn"}})
            self.assertEqual(graph.meta["caller_fn"]["fid"],
                             f"{ANCHOR16}:0x1000")

    def test_redb_sha_mismatch_skipped_with_note(self):
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            save_json(run_dir / "re-database.json",
                      self._redb_doc(sha="b" * 64))
            notes: list[str] = []
            self.assertIsNone(
                _graph_from_redb(run_dir, self._manifest(run_dir),
                                 notes),
            )
            # The rejection is on the record, not stderr-only.
            self.assertTrue(any("sha mismatch" in n for n in notes))

    def test_redb_mismatch_note_rides_into_artifact(self):
        """A rejected higher-precedence substrate must be visible to
        artifact consumers: the fallback graph carries the rejection
        note into substrate_notes and the report."""
        with TemporaryDirectory() as tmp:
            run_dir = _write_run_dir(Path(tmp))
            save_json(run_dir / "re-database.json",
                      self._redb_doc(sha="b" * 64))
            fallback = CallGraph(substrate="cache",
                                 callees={"x": {"parse"}})
            base = "packages.binary_analysis.hunt."
            with patch(base + "_graph_from_map_scan",
                       return_value=None), \
                    patch(base + "_graph_from_edge_cache",
                          return_value=fallback):
                payload = run_calls_hunt(run_dir, "parse")
            notes = " ".join(payload["substrate_notes"])
            self.assertIn("sha mismatch", notes)
            self.assertIn("rejected", notes)
            report = Path(payload["artifacts"]["report"]).read_text(
                encoding="utf-8",
            )
            self.assertIn("sha mismatch", report)

    def test_redb_mismatch_named_in_no_substrate_refusal(self):
        """When everything is unusable, the refusal must not claim
        'no re-database.json' while a mismatched one exists."""
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            manifest = self._manifest(run_dir)
            save_json(run_dir / "re-database.json",
                      self._redb_doc(sha="b" * 64))
            base = "packages.binary_analysis.hunt."
            with patch(base + "_graph_from_map_scan",
                       return_value=None), \
                    patch(base + "_graph_from_edge_cache",
                          return_value=None):
                with self.assertRaises(HuntError) as caught:
                    load_call_graph(run_dir, manifest)
            message = str(caught.exception)
            self.assertIn("sha mismatch", message)
            self.assertNotIn("no re-database.json", message)

    def test_unstamped_redb_used_with_identity_note(self):
        """A legacy re-database without a binary_sha256 stamp stays
        usable, but the artifact says the identity went unchecked."""
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            save_json(run_dir / "re-database.json",
                      self._redb_doc(sha=None))
            graph = _graph_from_redb(run_dir, self._manifest(run_dir))
            self.assertIsNotNone(graph)
            self.assertTrue(
                any("no binary_sha256 stamp" in n for n in graph.notes),
            )

    def test_precedence_redb_first_then_fallbacks(self):
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            manifest = self._manifest(run_dir)
            redb_graph = CallGraph(substrate="redb", callees={"a": {"b"}})
            scan_graph = CallGraph(substrate="scan", callees={"a": {"b"}})
            cache_graph = CallGraph(substrate="cache", callees={"a": {"b"}})
            base = "packages.binary_analysis.hunt."
            with patch(base + "_graph_from_redb", return_value=redb_graph), \
                    patch(base + "_graph_from_map_scan",
                          return_value=scan_graph), \
                    patch(base + "_graph_from_edge_cache",
                          return_value=cache_graph):
                self.assertEqual(
                    load_call_graph(run_dir, manifest).substrate, "redb",
                )
            with patch(base + "_graph_from_redb", return_value=None), \
                    patch(base + "_graph_from_map_scan",
                          return_value=scan_graph), \
                    patch(base + "_graph_from_edge_cache",
                          return_value=cache_graph):
                self.assertEqual(
                    load_call_graph(run_dir, manifest).substrate, "scan",
                )
            with patch(base + "_graph_from_redb", return_value=None), \
                    patch(base + "_graph_from_map_scan",
                          return_value=None), \
                    patch(base + "_graph_from_edge_cache",
                          return_value=cache_graph):
                self.assertEqual(
                    load_call_graph(run_dir, manifest).substrate, "cache",
                )
            with patch(base + "_graph_from_redb", return_value=None), \
                    patch(base + "_graph_from_map_scan",
                          return_value=None), \
                    patch(base + "_graph_from_edge_cache",
                          return_value=None):
                # No substrate is a REFUSAL, never an empty answer.
                with self.assertRaises(HuntError):
                    load_call_graph(run_dir, manifest)


if __name__ == "__main__":
    unittest.main()
