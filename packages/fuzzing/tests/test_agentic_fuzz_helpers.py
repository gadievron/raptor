"""Tests for /agentic fuzz handoff helpers."""

import tempfile
import unittest
from pathlib import Path

from core.json import save_json
from raptor_agentic import (
    _build_fuzz_phase_summary,
    _collect_crash_files,
    _run_fuzz_validation_smoke,
)


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


class TestCollectCrashFilesEmptyPath(unittest.TestCase):
    def test_empty_string_path_returns_empty(self):
        assert _collect_crash_files(Path("")) == []


if __name__ == "__main__":
    unittest.main()


class TestCollectCrashFilesCwdSafety(unittest.TestCase):
    """Path('') stringifies to '.' — the empty-path guard must not fall
    through to scanning the current working directory for crash files."""

    def test_empty_path_never_scans_cwd(self):
        import os
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "crash-0001").write_bytes(b"x")
            old_cwd = os.getcwd()
            os.chdir(root)
            try:
                assert _collect_crash_files(Path("")) == []
            finally:
                os.chdir(old_cwd)


class TestCrashHandoffErrorVisibility(unittest.TestCase):
    """A failed crash triage/validation handoff must be operator-visible.

    Regression: the handler swallowed all exceptions at DEBUG right
    after printing 'Triaging N fuzz crashes...', so at the default INFO
    console level a failed triage looked like a silent no-op.
    """

    def test_handoff_handler_warns_and_prints(self):
        src = (Path(__file__).resolve().parents[3] / "raptor_agentic.py"
               ).read_text(encoding="utf-8")
        self.assertNotIn(
            'logger.debug("Crash → validate handoff failed', src,
        )
        self.assertIn(
            '"Crash → validate handoff failed: %s", e', src,
        )
        self.assertIn("Crash triage / validation handoff", src)


class TestPathsFoundKeysShared(unittest.TestCase):
    """The AFL stats key-priority list lives in one place.

    Regression: _build_fuzz_phase_summary and AFLRunner._afl_paths_found
    each carried their own copy of the key list with slightly different
    entries; a key added to one was silently missing from the other.
    """

    def test_both_consumers_honour_every_shared_key(self):
        from packages.fuzzing.afl_runner import AFL_PATHS_FOUND_KEYS, AFLRunner

        for key in AFL_PATHS_FOUND_KEYS:
            stats = {key: "7"}
            self.assertEqual(AFLRunner._afl_paths_found(stats), 7, key)

            summary = _build_fuzz_phase_summary(
                {"fuzzer": "afl", "stats": stats}, None,
            )
            self.assertEqual(summary["paths_found"], 7, key)
