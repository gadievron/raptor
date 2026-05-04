"""Tests for fuzzing telemetry."""

import io
import json
import tempfile
import time
import unittest
from pathlib import Path

from packages.fuzzing.telemetry import (
    CampaignStats,
    FuzzEvent,
    FuzzingTelemetry,
    StatusLineReporter,
    _fmt_count,
)


class TestFmtCount(unittest.TestCase):
    def test_small_numbers(self):
        self.assertEqual(_fmt_count(0), "0")
        self.assertEqual(_fmt_count(999), "999")

    def test_thousands(self):
        self.assertEqual(_fmt_count(1000), "1.0k")
        self.assertEqual(_fmt_count(12345), "12.3k")

    def test_millions(self):
        self.assertEqual(_fmt_count(1_500_000), "1.5M")
        self.assertEqual(_fmt_count(999_999_999), "1000.0M")


class TestStatusLineReporter(unittest.TestCase):
    def test_format_line_includes_key_metrics(self):
        s = CampaignStats(
            fuzzer="afl++",
            duration_s=120,
            total_executions=12345,
            executions_per_second=500,
            paths_found=42,
            crashes=2,
            corpus_size=18,
            coverage_percent=15.3,
        )
        line = StatusLineReporter._format_line(s)
        self.assertIn("[afl++", line)
        self.assertIn("120s", line)
        self.assertIn("execs=12.3k", line)
        self.assertIn("500/s", line)
        self.assertIn("paths=42", line)
        self.assertIn("crash=2", line)

    def test_render_writes_to_stream(self):
        buf = io.StringIO()
        reporter = StatusLineReporter(stream=buf, refresh_interval_seconds=0)
        s = CampaignStats(fuzzer="afl++", duration_s=10)
        reporter.render(s, force=True)
        self.assertIn("afl++", buf.getvalue())

    def test_finish_emits_terminal_newline_for_non_tty(self):
        buf = io.StringIO()
        reporter = StatusLineReporter(stream=buf, refresh_interval_seconds=0)
        s = CampaignStats(fuzzer="afl++", duration_s=10)
        reporter.finish(s)
        self.assertTrue(buf.getvalue().endswith("\n"))


class TestFuzzingTelemetry(unittest.TestCase):
    def test_lifecycle_writes_jsonl_and_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            tel = FuzzingTelemetry(out_dir=out_dir, fuzzer="afl++", target="/bin/test")
            tel.start()
            tel.update_stats(total_executions=100, paths_found=5, executions_per_second=200)
            tel.record_crash("/tmp/crash-001", signal="SIGSEGV")
            tel.stop()

            self.assertTrue((out_dir / "fuzz-events.jsonl").exists())
            self.assertTrue((out_dir / "fuzz-summary.json").exists())

            events = [
                json.loads(line)
                for line in (out_dir / "fuzz-events.jsonl").read_text().splitlines()
                if line.strip()
            ]
            kinds = [e["kind"] for e in events]
            self.assertIn("campaign_start", kinds)
            self.assertIn("crash", kinds)
            self.assertIn("campaign_end", kinds)

            summary = json.loads((out_dir / "fuzz-summary.json").read_text())
            self.assertEqual(summary["fuzzer"], "afl++")
            self.assertEqual(summary["crashes"], 1)

    def test_first_path_event_emitted_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            tel = FuzzingTelemetry(out_dir=Path(tmp))
            tel.start()
            tel.update_stats(paths_found=0)
            tel.update_stats(paths_found=1)
            tel.update_stats(paths_found=2)
            tel.update_stats(paths_found=5)
            tel.stop()

            events = [
                json.loads(line)
                for line in (Path(tmp) / "fuzz-events.jsonl").read_text().splitlines()
                if line.strip()
            ]
            first_path_events = [e for e in events if e["kind"] == "first_path"]
            self.assertEqual(len(first_path_events), 1, "first_path should emit exactly once")

    def test_record_payload_counts_and_truncates(self):
        with tempfile.TemporaryDirectory() as tmp:
            tel = FuzzingTelemetry(out_dir=Path(tmp))
            tel.start()
            tel.record_payload(b"\xde\xad\xbe\xef" * 100, source="fuzzer")
            tel.record_payload("AAAA" * 200, source="llm", rationale="boundary check")
            tel.stop()

            self.assertEqual(tel.stats.payloads_generated, 2)
            self.assertLessEqual(len(tel.stats.last_payload_excerpt), 256)

            events = [
                json.loads(line)
                for line in (Path(tmp) / "fuzz-events.jsonl").read_text().splitlines()
                if line.strip()
            ]
            payload_events = [e for e in events if e["kind"] == "payload_generated"]
            # Only LLM-sourced payloads create individual events
            self.assertEqual(len(payload_events), 1)
            self.assertEqual(payload_events[0]["source"], "llm")

    def test_thread_safe_snapshot(self):
        import threading
        with tempfile.TemporaryDirectory() as tmp:
            tel = FuzzingTelemetry(out_dir=Path(tmp))
            tel.start()

            stop = threading.Event()

            def updater():
                while not stop.is_set():
                    tel.update_stats(total_executions=tel.stats.total_executions + 1)
                    time.sleep(0.001)

            t = threading.Thread(target=updater, daemon=True)
            t.start()
            for _ in range(50):
                snapshot = tel.snapshot()
                self.assertIsInstance(snapshot["total_executions"], int)
            stop.set()
            t.join(timeout=2)
            tel.stop()

    def test_on_event_callback_invoked(self):
        captured = []

        with tempfile.TemporaryDirectory() as tmp:
            tel = FuzzingTelemetry(
                out_dir=Path(tmp),
                on_event=lambda ev: captured.append(ev.kind),
            )
            tel.start()
            tel.record_crash("/tmp/x")
            tel.stop()

        self.assertIn("campaign_start", captured)
        self.assertIn("crash", captured)
        self.assertIn("campaign_end", captured)


if __name__ == "__main__":
    unittest.main()
