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


if __name__ == "__main__":
    unittest.main()
