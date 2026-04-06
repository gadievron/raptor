"""Tests for run metadata lifecycle."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.json import load_json
from core.run import (
    tracked_run, start_run, complete_run, fail_run, cancel_run,
    load_run_metadata, is_run_directory, infer_command_type,
    generate_run_metadata, RUN_METADATA_FILE,
)


class TestRunLifecycle(unittest.TestCase):

    def test_start_creates_metadata(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "scan-20260406"
            start_run(out, "scan")
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["command"], "scan")
            self.assertEqual(meta["status"], "running")
            self.assertEqual(meta["version"], 1)
            self.assertIn("timestamp", meta)

    def test_start_with_extra(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "scan", extra={"packs": ["injection"]})
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["extra"]["packs"], ["injection"])

    def test_complete_updates_status(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "scan")
            complete_run(out, extra={"findings_count": 12})
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "completed")
            self.assertEqual(meta["extra"]["findings_count"], 12)

    def test_fail_updates_status(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "scan")
            fail_run(out, error="timeout")
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "failed")
            self.assertEqual(meta["extra"]["error"], "timeout")

    def test_cancel_updates_status(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "agentic")
            cancel_run(out)
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "cancelled")

    def test_start_creates_directory(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "new" / "nested" / "run"
            start_run(out, "scan")
            self.assertTrue(out.exists())

    def test_load_missing(self):
        with TemporaryDirectory() as d:
            self.assertIsNone(load_run_metadata(Path(d)))

    def test_complete_without_start_raises(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "orphan"
            out.mkdir()
            with self.assertRaises(FileNotFoundError):
                complete_run(out)

    def test_fail_without_start_raises(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "orphan"
            out.mkdir()
            with self.assertRaises(FileNotFoundError):
                fail_run(out, error="test")


class TestIsRunDirectory(unittest.TestCase):

    def test_with_metadata(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "scan")
            self.assertTrue(is_run_directory(out))

    def test_with_known_prefix(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "scan_vulns_20260406"
            out.mkdir()
            self.assertTrue(is_run_directory(out))

    def test_with_typical_files(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "mystery_dir"
            out.mkdir()
            (out / "findings.json").write_text("{}")
            self.assertTrue(is_run_directory(out))

    def test_empty_dir(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "empty"
            out.mkdir()
            self.assertFalse(is_run_directory(out))

    def test_not_a_dir(self):
        with TemporaryDirectory() as d:
            f = Path(d) / "file.txt"
            f.write_text("hello")
            self.assertFalse(is_run_directory(f))


class TestInferCommandType(unittest.TestCase):

    def test_from_metadata(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "validate")
            self.assertEqual(infer_command_type(out), "validate")

    def test_from_scan_prefix(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "scan_vulns_20260406"
            out.mkdir()
            self.assertEqual(infer_command_type(out), "scan")

    def test_from_raptor_prefix(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "raptor_vulns_20260406"
            out.mkdir()
            self.assertEqual(infer_command_type(out), "agentic")

    def test_from_validate_prefix(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "exploitability-validation-20260406"
            out.mkdir()
            self.assertEqual(infer_command_type(out), "validate")

    def test_unknown(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "mystery"
            out.mkdir()
            self.assertEqual(infer_command_type(out), "unknown")


class TestGenerateRunMetadata(unittest.TestCase):

    def test_generates_for_missing(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "scan_vulns_20260406_100000"
            out.mkdir()
            generate_run_metadata(out)
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["command"], "scan")
            self.assertEqual(meta["status"], "completed")
            self.assertTrue(meta["extra"].get("adopted"))

    def test_skips_existing(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            start_run(out, "custom")
            generate_run_metadata(out)  # Should not overwrite
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["command"], "custom")

    def test_parses_timestamp_from_name(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "scan-20260406-100000"
            out.mkdir()
            generate_run_metadata(out)
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertIn("2026-04-06", meta["timestamp"])


class TestTrackedRun(unittest.TestCase):

    def test_completes_on_success(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            with tracked_run(out, "scan"):
                (out / "findings.json").write_text("[]")
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "completed")

    def test_fails_on_exception(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            with self.assertRaises(RuntimeError):
                with tracked_run(out, "scan"):
                    raise RuntimeError("something broke")
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "failed")
            self.assertIn("something broke", meta["extra"]["error"])

    def test_cancels_on_keyboard_interrupt(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            with self.assertRaises(KeyboardInterrupt):
                with tracked_run(out, "scan"):
                    raise KeyboardInterrupt()
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["status"], "cancelled")

    def test_creates_directory(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "new" / "nested" / "run"
            with tracked_run(out, "scan"):
                pass
            self.assertTrue(out.exists())

    def test_extra_metadata_preserved(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "run"
            with tracked_run(out, "scan", extra={"packs": ["injection"]}):
                pass
            meta = load_json(out / RUN_METADATA_FILE)
            self.assertEqual(meta["extra"]["packs"], ["injection"])


if __name__ == "__main__":
    unittest.main()
