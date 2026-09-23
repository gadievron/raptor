"""Robustness tests: understand_bridge stamps the artifacts it writes.

The bridge is a writer chokepoint for attack-surface.json and
attack-paths.json (imported from LLM-authored /understand output), so
everything it persists must carry a provenance stamp with
``untrusted: true`` per docs/security.md I2-(b).
"""

import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from core.json import load_json, save_json
from core.orchestration import understand_bridge as ub


class TestMergeAttackSurfaceStamps(unittest.TestCase):

    def test_new_surface_is_stamped_untrusted(self):
        with TemporaryDirectory() as tmp:
            validate_dir = Path(tmp)
            context_map = {
                "sources": [{"type": "http", "entry": "POST /x",
                             "trust": "# markdown trust prose"}],
                "sinks": [{"type": "db_query", "location": "a.py:9"}],
                "trust_boundaries": [],
            }
            ub._merge_attack_surface(context_map, validate_dir, validate_dir)
            surface = load_json(validate_dir / "attack-surface.json")
            self.assertEqual(surface["provenance"]["generator"],
                             "understand-bridge")
            self.assertTrue(surface["provenance"]["untrusted"])
            # Marked free-text defanged at the writer
            self.assertEqual(surface["sources"][0]["trust"],
                             " markdown trust prose")

    def test_merge_into_existing_surface_keeps_stamp(self):
        with TemporaryDirectory() as tmp:
            validate_dir = Path(tmp)
            save_json(validate_dir / "attack-surface.json", {
                "sources": [], "sinks": [], "trust_boundaries": [],
            })
            context_map = {
                "sources": [{"type": "http", "entry": "POST /x"}],
                "sinks": [], "trust_boundaries": [],
            }
            ub._merge_attack_surface(context_map, validate_dir, validate_dir)
            surface = load_json(validate_dir / "attack-surface.json")
            self.assertTrue(surface["provenance"]["untrusted"])


class TestImportFlowTracesStamps(unittest.TestCase):

    def test_imported_paths_are_stamped_per_element(self):
        with TemporaryDirectory() as tmp:
            understand_dir = Path(tmp) / "u"
            validate_dir = Path(tmp) / "v"
            understand_dir.mkdir()
            validate_dir.mkdir()
            save_json(understand_dir / "flow-trace-001.json", {
                "id": "TRACE-001",
                "name": "demo trace",
                "steps": [{"step": 1, "action": "call f"}],
            })
            stats = ub._import_flow_traces(understand_dir, validate_dir)
            self.assertEqual(stats["imported_as_paths"], 1)
            paths = load_json(validate_dir / "attack-paths.json")
            self.assertIsInstance(paths, list)
            self.assertEqual(paths[0]["provenance"]["generator"],
                             "understand-bridge")
            self.assertTrue(paths[0]["provenance"]["untrusted"])

    def test_existing_path_generator_preserved(self):
        with TemporaryDirectory() as tmp:
            understand_dir = Path(tmp) / "u"
            validate_dir = Path(tmp) / "v"
            understand_dir.mkdir()
            validate_dir.mkdir()
            save_json(validate_dir / "attack-paths.json", [{
                "id": "AP-EXISTING", "proximity": 4,
                "provenance": {"generator": "claude-session",
                               "untrusted": True,
                               "schema_validated": True},
                "raptor_schema_version": 2,
            }])
            save_json(understand_dir / "flow-trace-001.json", {
                "id": "TRACE-001", "steps": [],
            })
            ub._import_flow_traces(understand_dir, validate_dir)
            paths = load_json(validate_dir / "attack-paths.json")
            by_id = {p["id"]: p for p in paths}
            # Original writer id survives the bridge rewrite; the
            # rewrite resets schema_validated (content changed).
            self.assertEqual(by_id["AP-EXISTING"]["provenance"]["generator"],
                             "claude-session")
            self.assertFalse(
                by_id["AP-EXISTING"]["provenance"]["schema_validated"])
            self.assertEqual(by_id["TRACE-001"]["provenance"]["generator"],
                             "understand-bridge")


class TestImportGraphAttackPathsStamps(unittest.TestCase):
    """The graph importer writes TWO artifacts (graph-priority-paths
    and the attack-paths merge) — both must go through the same
    sanitise+stamp chokepoint its flow-trace sibling uses."""

    _FAKE_PATHS = [{
        "id": "GP-1",
        "entry": {"id": "EP-1", "label": "main"},
        "sink": {"id": "SINK-1", "label": "exec"},
        "steps": [],
        "unchecked": True,
        "confidence": "candidate",
        "evidence": {},
        "missing_boundary": "no boundary recorded",
    }]

    def _run_import(self, validate_dir):
        import copy
        from unittest.mock import patch

        import core.understand_graph as ug
        with patch.object(
            ug, "attack_paths",
            lambda *a, **k: copy.deepcopy(self._FAKE_PATHS),
        ):
            return ub._import_graph_attack_paths(
                validate_dir / "g.sqlite", "/target", validate_dir,
            )

    def test_graph_priority_paths_stamped_per_element(self):
        with TemporaryDirectory() as tmp:
            validate_dir = Path(tmp)
            stats = self._run_import(validate_dir)
            self.assertEqual(stats["imported_as_paths"], 1)
            gpp = load_json(validate_dir / "graph-priority-paths.json")
            self.assertIsInstance(gpp, list)
            self.assertTrue(gpp[0]["provenance"]["untrusted"])

    def test_merged_attack_paths_stamped_per_element(self):
        with TemporaryDirectory() as tmp:
            validate_dir = Path(tmp)
            self._run_import(validate_dir)
            paths = load_json(validate_dir / "attack-paths.json")
            self.assertIsInstance(paths, list)
            self.assertEqual(paths[0]["id"], "GP-1")
            self.assertTrue(paths[0]["provenance"]["untrusted"])


class TestLoadUnderstandContextSurfacesProvenance(unittest.TestCase):

    def test_summary_carries_context_map_provenance(self):
        with TemporaryDirectory() as tmp:
            understand_dir = Path(tmp) / "u"
            validate_dir = Path(tmp) / "v"
            understand_dir.mkdir()
            validate_dir.mkdir()
            save_json(understand_dir / "context-map.json", {
                "sources": [], "sinks": [], "trust_boundaries": [],
                "provenance": {"generator": "understand:map",
                               "untrusted": True,
                               "schema_validated": True},
                "raptor_schema_version": 2,
            })
            summary = ub.load_understand_context(understand_dir, validate_dir)
            self.assertTrue(summary["context_map_loaded"])
            prov = summary["context_map_provenance"]
            self.assertEqual(prov["generator"], "understand:map")
            self.assertTrue(prov["untrusted"])
            self.assertFalse(prov["legacy"])

    def test_legacy_context_map_reads_untrusted(self):
        with TemporaryDirectory() as tmp:
            understand_dir = Path(tmp) / "u"
            validate_dir = Path(tmp) / "v"
            understand_dir.mkdir()
            validate_dir.mkdir()
            save_json(understand_dir / "context-map.json", {
                "sources": [], "sinks": [], "trust_boundaries": [],
            })
            summary = ub.load_understand_context(understand_dir, validate_dir)
            prov = summary["context_map_provenance"]
            self.assertTrue(prov["untrusted"])
            self.assertTrue(prov["legacy"])


def _strings_of(obj):
    """Yield every string value in a JSON-shaped structure."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for value in obj.values():
            yield from _strings_of(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _strings_of(value)


class TestImportGraphAttackPathsDefangsHostileLabels(unittest.TestCase):
    """The graph lane routes through the same chokepoint as its siblings.

    Hostile-labelled graph paths (terminal-escape bytes in label,
    missing_boundary, evidence, raw node props) must be defanged and
    stamped in BOTH artifacts the lane writes.
    """

    HOSTILE = "evil\x1b[2J\x1b]0;pwned\x07label"

    def _run_graph_import(self, validate_dir: Path) -> dict:
        import core.understand_graph as graph_mod

        def _fake_attack_paths(*_a, **_k):
            return [{
                "id": "gp-1",
                "entry": {"label": self.HOSTILE, "id": "e1",
                          "raw": {"notes": self.HOSTILE}},
                "sink": {"label": "sink", "id": "s1"},
                "steps": [],
                "unchecked": True,
                "missing_boundary": self.HOSTILE,
                "evidence": {"note": self.HOSTILE},
                "confidence": "candidate",
            }]

        original = graph_mod.attack_paths
        graph_mod.attack_paths = _fake_attack_paths
        try:
            return ub._import_graph_attack_paths(
                Path("/nonexistent.db"), "/tmp/target", validate_dir)
        finally:
            graph_mod.attack_paths = original

    def test_graph_lane_defangs_and_stamps_both_artifacts(self):
        with TemporaryDirectory() as tmp:
            validate_dir = Path(tmp)
            stats = self._run_graph_import(validate_dir)
            self.assertEqual(stats["imported_as_paths"], 1)

            paths = load_json(validate_dir / "attack-paths.json")
            entry = paths[0]
            self.assertEqual(entry["provenance"]["generator"],
                             "understand-bridge")
            self.assertTrue(entry["provenance"]["untrusted"])
            # The label reached the persisted name defanged: escape
            # bytes become literal text, never real control chars.
            self.assertIn("evil", entry["name"])
            for value in _strings_of(entry):
                self.assertNotIn("\x1b", value)
                self.assertNotIn("\x07", value)

            graph_paths = load_json(
                validate_dir / "graph-priority-paths.json")
            self.assertEqual(graph_paths[0]["provenance"]["generator"],
                             "understand-bridge")
            self.assertTrue(graph_paths[0]["provenance"]["untrusted"])
            # No-schema artifact embeds raw node dicts — every string
            # is defanged, including nested raw props and evidence.
            for value in _strings_of(graph_paths):
                self.assertNotIn("\x1b", value)
                self.assertNotIn("\x07", value)

    def test_graph_lane_merges_into_existing_paths_and_stamps_all(self):
        with TemporaryDirectory() as tmp:
            validate_dir = Path(tmp)
            save_json(validate_dir / "attack-paths.json", [
                {"id": "AP-EXISTING", "proximity": 3},
            ])
            stats = self._run_graph_import(validate_dir)
            self.assertEqual(stats["imported_as_paths"], 1)
            paths = load_json(validate_dir / "attack-paths.json")
            by_id = {p["id"]: p for p in paths}
            self.assertIn("AP-EXISTING", by_id)
            self.assertTrue(by_id["AP-EXISTING"]["provenance"]["untrusted"])
            self.assertTrue(by_id["gp-1"]["provenance"]["untrusted"])


class TestGraphContextMapWriteStamps(unittest.TestCase):
    """The graph-context arm stamps the context-map.graph.json it writes."""

    def test_graph_context_map_is_stamped_and_defanged(self):
        import core.understand_graph as graph_mod

        hostile = "boundary gap \x1b[2J prose"
        fake_map = {
            "entry_points": [], "sources": [],
            "trust_boundaries": [], "boundary_details": [],
            "sinks": [], "sink_details": [],
            "unchecked_flows": [{"entry_point": "e1", "sink": "s1",
                                 "missing_boundary": hostile}],
        }

        with TemporaryDirectory() as tmp:
            validate_dir = Path(tmp)
            graph_db = validate_dir / "graph.sqlite3"
            graph_db.write_bytes(b"")

            originals = (graph_mod.build_context_map,
                         graph_mod.graph_path_for_run,
                         graph_mod.attack_paths)
            graph_mod.build_context_map = lambda *_a, **_k: (
                {k: list(v) for k, v in fake_map.items()}, set())
            graph_mod.graph_path_for_run = lambda *_a, **_k: graph_db
            graph_mod.attack_paths = lambda *_a, **_k: []
            try:
                ub.load_understand_graph_context(validate_dir, "/tmp/target")
            finally:
                (graph_mod.build_context_map,
                 graph_mod.graph_path_for_run,
                 graph_mod.attack_paths) = originals

            written = load_json(validate_dir / "context-map.graph.json")
            self.assertEqual(written["provenance"]["generator"],
                             "understand-bridge")
            self.assertTrue(written["provenance"]["untrusted"])
            self.assertNotIn(
                "\x1b", written["unchecked_flows"][0]["missing_boundary"])


if __name__ == "__main__":
    unittest.main()


class TestMergeAttackSurfaceFieldUpdates(unittest.TestCase):
    """Re-runs persist FIELD-level updates on dedup-merged entries —
    the previous length-delta change detection dropped update-only
    merges (recomputed has_taint_flow / gaps never landed on disk)."""

    def test_update_only_rerun_persists(self):
        with TemporaryDirectory() as tmp:
            validate_dir = Path(tmp)
            context_map = {
                "sources": [{"type": "http", "entry": "POST /x"}],
                "sinks": [], "trust_boundaries": [],
            }
            ub._merge_attack_surface(context_map, validate_dir,
                                     validate_dir)
            # Same entry key, new enrichment field: no length change.
            context_map = {
                "sources": [{"type": "http", "entry": "POST /x",
                             "has_taint_flow": True}],
                "sinks": [], "trust_boundaries": [],
            }
            ub._merge_attack_surface(context_map, validate_dir,
                                     validate_dir)
            surface = load_json(validate_dir / "attack-surface.json")
            self.assertTrue(surface["sources"][0]["has_taint_flow"])

    def test_no_change_rerun_does_not_rewrite(self):
        import os
        with TemporaryDirectory() as tmp:
            validate_dir = Path(tmp)
            context_map = {
                "sources": [{"type": "http", "entry": "POST /x"}],
                "sinks": [], "trust_boundaries": [],
            }
            ub._merge_attack_surface(context_map, validate_dir,
                                     validate_dir)
            surface_path = validate_dir / "attack-surface.json"
            before = os.stat(surface_path).st_mtime_ns
            ub._merge_attack_surface(
                {"sources": [{"type": "http", "entry": "POST /x"}],
                 "sinks": [], "trust_boundaries": []},
                validate_dir, validate_dir)
            self.assertEqual(os.stat(surface_path).st_mtime_ns, before)

    def test_existing_only_fields_survive_update(self):
        with TemporaryDirectory() as tmp:
            validate_dir = Path(tmp)
            save_json(validate_dir / "attack-surface.json", {
                "sources": [{"type": "http", "entry": "POST /x",
                             "stage_b_note": "keep me"}],
                "sinks": [], "trust_boundaries": [],
            })
            ub._merge_attack_surface(
                {"sources": [{"type": "http", "entry": "POST /x",
                              "has_taint_flow": True}],
                 "sinks": [], "trust_boundaries": []},
                validate_dir, validate_dir)
            surface = load_json(validate_dir / "attack-surface.json")
            src = surface["sources"][0]
            self.assertEqual(src["stage_b_note"], "keep me")
            self.assertTrue(src["has_taint_flow"])
