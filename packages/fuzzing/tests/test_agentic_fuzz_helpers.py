"""Tests for /agentic fuzz handoff helpers."""

import tempfile
import unittest
from pathlib import Path

from core.json import save_json
from raptor_agentic import _build_fuzz_phase_summary, _run_fuzz_validation_smoke


class TestAgenticFuzzHelpers(unittest.TestCase):

    def test_fuzz_phase_summary_prefers_telemetry_and_lists_crashes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            crashes = root / "crashes"
            crashes.mkdir()
            (crashes / "id:000000,sig:11,src:000000,time:1,execs:42,op:havoc").write_bytes(b"x")
            telemetry = root / "fuzz-summary.json"
            save_json(telemetry, {
                "total_executions": 42,
                "executions_per_second": 1000,
                "paths_found": 4,
                "coverage_percent": 37.5,
            })

            summary = _build_fuzz_phase_summary({
                "fuzzer": "afl",
                "crashes": 1,
                "crashes_dir": str(crashes),
                "stats": {"execs_done": "0", "corpus_count": "2"},
                "telemetry": str(telemetry),
            }, root)

            self.assertTrue(summary["completed"])
            self.assertEqual(summary["executions"], 42)
            self.assertEqual(summary["paths_found"], 4)
            self.assertEqual(summary["coverage_percent"], 37.5)
            self.assertEqual(len(summary["crash_paths"]), 1)

    def test_fuzz_validation_smoke_writes_validate_report(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            findings_path = root / "crashes_for_validation.json"
            save_json(findings_path, {
                "target_path": str(root / "target"),
                "findings": [{
                    "id": "CRASH-0001",
                    "file": str(root / "target"),
                    "function": "main",
                    "line": 0,
                    "vuln_type": "crash",
                    "status": "confirmed",
                    "confidence": "high",
                    "description": "Fuzz crash.",
                    "origin": "fuzzing",
                }],
            })

            result = _run_fuzz_validation_smoke(findings_path, root / "target", root)

            self.assertTrue(result["ran"])
            self.assertTrue((root / "fuzz_validation" / "findings.json").exists())
            self.assertTrue((root / "fuzz_validation" / "validation-report.md").exists())


if __name__ == "__main__":
    unittest.main()
