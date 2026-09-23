"""Robustness tests: the diagram renderer surfaces provenance stamps.

Visibility plumbing for docs/security.md I2-(b): stamped-untrusted
artifacts get an explicit note next to their diagram; legacy artifacts
(no stamp) render exactly as before.
"""

import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from core.json import save_json
from packages.diagram.renderer import render_directory


def _stamped(data, generator="understand:map"):
    data["provenance"] = {"generator": generator, "untrusted": True,
                          "schema_validated": True}
    data["raptor_schema_version"] = 2
    return data


class TestProvenanceNote(unittest.TestCase):

    def test_stamped_context_map_gets_note(self):
        with TemporaryDirectory() as tmp:
            save_json(Path(tmp) / "context-map.json", _stamped({
                "sources": [{"type": "http", "entry": "POST /x"}],
                "sinks": [{"type": "db_query", "location": "a.py:9"}],
                "trust_boundaries": [],
            }))
            out = render_directory(Path(tmp))
            self.assertIn("Provenance: LLM-derived content (untrusted)",
                          out)
            self.assertIn("`understand:map`", out)

    def test_legacy_context_map_renders_without_note(self):
        with TemporaryDirectory() as tmp:
            save_json(Path(tmp) / "context-map.json", {
                "sources": [{"type": "http", "entry": "POST /x"}],
                "sinks": [{"type": "db_query", "location": "a.py:9"}],
                "trust_boundaries": [],
            })
            out = render_directory(Path(tmp))
            self.assertNotIn("Provenance: LLM-derived", out)

    def test_hostile_generator_id_is_defanged(self):
        with TemporaryDirectory() as tmp:
            save_json(Path(tmp) / "context-map.json", _stamped({
                "sources": [{"type": "http", "entry": "POST /x"}],
                "sinks": [{"type": "db_query", "location": "a.py:9"}],
                "trust_boundaries": [],
            }, generator="evil`\x1b[31m\ngen"))
            out = render_directory(Path(tmp))
            self.assertIn("Provenance: LLM-derived", out)
            self.assertNotIn("\x1b[31m", out)
            self.assertNotIn("evil`", out)  # backtick escaped

    def test_stamped_flow_trace_gets_note(self):
        with TemporaryDirectory() as tmp:
            save_json(Path(tmp) / "flow-trace-001.json", _stamped({
                "id": "TRACE-001", "name": "demo",
                "steps": [{"step": 1, "description": "entry",
                           "definition": "a.py:1"}],
            }, generator="understand:trace"))
            out = render_directory(Path(tmp))
            self.assertIn("`understand:trace`", out)

    # The three graph-derived sections were outside the original
    # plumbing's derivation — the stamp existed and the reader lanes
    # never consulted it.

    def test_stamped_edge_obligations_gets_note(self):
        with TemporaryDirectory() as tmp:
            save_json(Path(tmp) / "edge-obligations.json", _stamped({
                "tier1": [{"caller_file": "a.c", "caller": "f",
                           "callee_file": "b.c", "callee": "g",
                           "reason": "boundary:x"}],
                "tier2": [], "blind_spots": [], "stats": {},
            }, generator="audit:edges"))
            out = render_directory(Path(tmp))
            self.assertIn("Edge Obligations", out)
            self.assertIn("`audit:edges`", out)

    def test_stamped_graph_priority_paths_gets_note(self):
        with TemporaryDirectory() as tmp:
            save_json(Path(tmp) / "graph-priority-paths.json", {
                "paths": [_stamped({
                    "id": "GP-1",
                    "entry": {"id": "EP-1", "label": "main"},
                    "sink": {"id": "S-1", "label": "exec"},
                }, generator="understand:graph")],
            })
            out = render_directory(Path(tmp))
            self.assertIn("Graph Priority Paths", out)
            self.assertIn("`understand:graph`", out)

    def test_stamped_graph_diff_gets_note(self):
        with TemporaryDirectory() as tmp:
            save_json(Path(tmp) / "graph-diff.json", _stamped({
                "is_diffable": True,
                "base_snapshot": {"id": "s1"},
                "head_snapshot": {"id": "s2"},
                "new_risks": [],
            }, generator="understand:graph-diff"))
            out = render_directory(Path(tmp))
            self.assertIn("Graph Snapshot Diff", out)
            self.assertIn("`understand:graph-diff`", out)

    def test_legacy_graph_sections_render_without_note(self):
        with TemporaryDirectory() as tmp:
            save_json(Path(tmp) / "edge-obligations.json", {
                "tier1": [], "tier2": [], "blind_spots": [], "stats": {},
            })
            save_json(Path(tmp) / "graph-diff.json", {
                "is_diffable": True,
                "base_snapshot": {"id": "s1"},
                "head_snapshot": {"id": "s2"},
            })
            out = render_directory(Path(tmp))
            self.assertNotIn("Provenance: LLM-derived", out)


if __name__ == "__main__":
    unittest.main()
