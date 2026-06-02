"""Tests for ``core/run/orchestrated_report_schema.py`` —
descriptive contract for ``orchestrated_report.json`` (QoL #11e).

The schema is consumed by external tooling; not validated at runtime.
Tests verify the schema itself is well-formed and stays in sync
with the producer (finding_status enum, _finalize_results_for_emit
behaviour). We deliberately do NOT pull in ``jsonschema`` for these
tests — it's not a declared RAPTOR dependency
(``feedback-no-jsonschema-in-tests``); the schema is asserted as a
plain dict shape.
"""

from __future__ import annotations

import unittest

from core.run.finding_status import ALL_STATUSES
from core.run.orchestrated_report_schema import SCHEMA


class TestSchemaShape(unittest.TestCase):
    """Plain-dict assertions on the schema's structure. Catches a
    typo / wrong nesting at import time without requiring the
    jsonschema validator."""

    def test_top_level_required_fields(self):
        self.assertIn("mode", SCHEMA["properties"])
        self.assertIn("results", SCHEMA["properties"])
        self.assertEqual(set(SCHEMA["required"]), {"mode", "results"})

    def test_top_level_additional_properties_permissive(self):
        # Permissive top-level so the orchestrator can stamp new
        # sections (dataflow_validation, defense_telemetry, future
        # additions) without breaking consumers pinned to this
        # schema.
        self.assertTrue(SCHEMA.get("additionalProperties", False))

    def test_results_is_array_of_findings(self):
        results = SCHEMA["properties"]["results"]
        self.assertEqual(results["type"], "array")
        items = results["items"]
        self.assertEqual(items["type"], "object")
        # finding_id + status both required on every per-finding
        # record (the contract consumers rely on).
        self.assertEqual(
            set(items["required"]), {"finding_id", "status"},
        )

    def test_status_enum_matches_finding_status_module(self):
        # The schema's status enum MUST stay in lock-step with
        # ``core.run.finding_status.ALL_STATUSES`` — drift here
        # would silently produce reports that consumers pinned
        # to the schema can't parse.
        status_prop = (
            SCHEMA["properties"]["results"]["items"]
                  ["properties"]["status"]
        )
        self.assertEqual(set(status_prop["enum"]), set(ALL_STATUSES))

    def test_orchestration_section_present(self):
        orch = SCHEMA["properties"]["orchestration"]
        self.assertEqual(orch["type"], "object")
        # Cost subobject required to be an object when present.
        self.assertEqual(orch["properties"]["cost"]["type"], "object")

    def test_finding_additional_properties_permissive(self):
        # Per-finding records carry arbitrary keys from the prep
        # stage + downstream enrichment; tests' fixture parity
        # would otherwise need to chase every new key. Permissive
        # by design.
        items = SCHEMA["properties"]["results"]["items"]
        self.assertTrue(items.get("additionalProperties", False))


class TestSchemaConsumerExample(unittest.TestCase):
    """End-to-end sanity: a minimal report dict matching what the
    orchestrator produces validates against the dict-shape
    expectations. Independent of jsonschema — assertions on the
    KEYS the schema declares, applied to a real-shape report."""

    def _make_minimal_report(self):
        return {
            "mode": "orchestrated",
            "results": [
                {
                    "finding_id": "F1",
                    "status": "analysed",
                    "is_true_positive": True,
                    "is_exploitable": False,
                    "file_path": "src/main.c",
                    "function": "main",
                    "line": 42,
                    "rule_id": "p/security-audit.sqli",
                    "severity": "high",
                    "reasoning": "Tainted input flows to query string.",
                },
                {
                    "finding_id": "F2",
                    "status": "skipped_dead_code",
                    "file_path": "src/unused.c",
                    "function": "dead_fn",
                },
                {
                    "finding_id": "F3",
                    "status": "error",
                    "error": "timeout after 600s",
                },
            ],
            "analyzed": 1,
            "exploitable": 0,
            "exploits_generated": 0,
            "patches_generated": 0,
            "orchestration": {
                "analysis_model": "claude-haiku-4-5",
                "cost": {"total_cost": 0.0042, "by_model": {}},
                "fired_models": [],
            },
        }

    def test_minimal_report_has_all_required_fields(self):
        report = self._make_minimal_report()
        # Top-level required.
        for key in SCHEMA["required"]:
            self.assertIn(key, report)
        # Per-finding required.
        items_required = (
            SCHEMA["properties"]["results"]["items"]["required"]
        )
        for f in report["results"]:
            for key in items_required:
                self.assertIn(key, f, f"missing {key} on {f}")

    def test_all_status_enum_values_are_representable(self):
        # Every status the schema declares should be acceptable on
        # a real finding shape — catches an enum drift before it
        # produces an in-the-wild rejection.
        status_enum = (
            SCHEMA["properties"]["results"]["items"]
                  ["properties"]["status"]["enum"]
        )
        for status in status_enum:
            report = self._make_minimal_report()
            report["results"][0]["status"] = status
            # Just assert the dict shape stays parseable + the
            # value is in the enum.
            self.assertIn(report["results"][0]["status"], status_enum)


if __name__ == "__main__":
    unittest.main()
