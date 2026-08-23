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


if __name__ == "__main__":
    unittest.main()
