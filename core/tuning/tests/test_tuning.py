"""Tests for core.tuning — loader, auto-detection, validation."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.tuning import (
    Tuning,
    load_tuning,
    _detect_available_cpus,
    _detect_cgroup_cpu_quota,
    _detect_codeql_workers,
    _detect_fuzz_parallel,
    _detect_ram_mb,
    _detect_semgrep_workers,
    _detect_threads,
)


class TestLoadTuning(unittest.TestCase):

    def test_missing_file_returns_defaults(self):
        t = load_tuning(Path("/nonexistent/tuning.json"))
        self.assertEqual(t.max_semgrep_workers, 4)
        self.assertEqual(t.max_codeql_workers, 2)
        self.assertEqual(t.max_agentic_parallel, 3)
        self.assertEqual(t.max_fuzz_parallel, 4)

    def test_empty_file_returns_defaults(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "tuning.json"
            p.write_text("")
            t = load_tuning(p)
            self.assertEqual(t.max_semgrep_workers, 4)

    def test_explicit_values(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "tuning.json"
            p.write_text(json.dumps({
                "codeql_ram_mb": 2048,
                "codeql_threads": 2,
                "max_semgrep_workers": 8,
                "max_codeql_workers": 4,
                "max_agentic_parallel": 6,
                "max_fuzz_parallel": 4,
            }))
            t = load_tuning(p)
            self.assertEqual(t.codeql_ram_mb, 2048)
            self.assertEqual(t.codeql_threads, 2)
            self.assertEqual(t.max_semgrep_workers, 8)
            self.assertEqual(t.max_codeql_workers, 4)
            self.assertEqual(t.max_agentic_parallel, 6)
            self.assertEqual(t.max_fuzz_parallel, 4)

    def test_auto_resolves_ram(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "tuning.json"
            p.write_text(json.dumps({"codeql_ram_mb": "auto"}))
            t = load_tuning(p)
            self.assertIsInstance(t.codeql_ram_mb, int)
            self.assertGreaterEqual(t.codeql_ram_mb, 2048)
            self.assertLessEqual(t.codeql_ram_mb, 16384)

    def test_auto_resolves_threads(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "tuning.json"
            p.write_text(json.dumps({"codeql_threads": "auto"}))
            t = load_tuning(p)
            # 0 = CodeQL's native "use all CPUs" mode
            self.assertEqual(t.codeql_threads, 0)

    def test_auto_resolves_semgrep_workers(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "tuning.json"
            p.write_text(json.dumps({"max_semgrep_workers": "auto"}))
            with patch("core.tuning.os.sched_getaffinity", None, create=True), patch("core.tuning.os.cpu_count", return_value=16):
                t = load_tuning(p)
            self.assertEqual(t.max_semgrep_workers, 8)

    def test_auto_resolves_semgrep_workers_when_cpu_unknown(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "tuning.json"
            p.write_text(json.dumps({"max_semgrep_workers": "auto"}))
            with patch("core.tuning.os.sched_getaffinity", None, create=True), patch("core.tuning.os.cpu_count", return_value=None):
                t = load_tuning(p)
            self.assertEqual(t.max_semgrep_workers, 2)

    def test_auto_resolves_codeql_workers(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "tuning.json"
            p.write_text(json.dumps({"max_codeql_workers": "auto"}))
            with patch("core.tuning.os.sched_getaffinity", None, create=True), patch("core.tuning.os.cpu_count", return_value=12), patch("core.tuning._detect_total_ram_mb", return_value=98304), patch("core.tuning._detect_ram_mb", return_value=16384):
                t = load_tuning(p)
            self.assertEqual(t.max_codeql_workers, 6)

    def test_auto_resolves_fuzz_parallel(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "tuning.json"
            p.write_text(json.dumps({"max_fuzz_parallel": "auto"}))
            with patch("core.tuning.os.sched_getaffinity", None, create=True), patch("core.tuning.os.cpu_count", return_value=12):
                t = load_tuning(p)
            self.assertEqual(t.max_fuzz_parallel, 6)

    def test_auto_resolves_all_cpu_backed_worker_limits_together(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "tuning.json"
            p.write_text(json.dumps({
                "max_semgrep_workers": "auto",
                "max_codeql_workers": "auto",
                "max_fuzz_parallel": "auto",
            }))
            with patch("core.tuning.os.sched_getaffinity", None, create=True), patch("core.tuning.os.cpu_count", return_value=8):
                t = load_tuning(p)
            self.assertEqual(t.max_semgrep_workers, 4)
            self.assertEqual(t.max_codeql_workers, 4)
            self.assertEqual(t.max_fuzz_parallel, 4)

    def test_auto_worker_limits_fallback_when_cpu_unknown(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "tuning.json"
            p.write_text(json.dumps({
                "max_codeql_workers": "auto",
                "max_fuzz_parallel": "auto",
            }))
            with patch("core.tuning.os.sched_getaffinity", None, create=True), patch("core.tuning.os.cpu_count", return_value=None):
                t = load_tuning(p)
            self.assertEqual(t.max_codeql_workers, 2)
            self.assertEqual(t.max_fuzz_parallel, 2)

    def test_negative_value_falls_back(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "tuning.json"
            p.write_text(json.dumps({"max_semgrep_workers": -1}))
            t = load_tuning(p)
            self.assertEqual(t.max_semgrep_workers, 4)

    def test_zero_threads_accepted(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "tuning.json"
            p.write_text(json.dumps({"codeql_threads": 0}))
            t = load_tuning(p)
            self.assertEqual(t.codeql_threads, 0)

    def test_zero_value_falls_back(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "tuning.json"
            p.write_text(json.dumps({"max_codeql_workers": 0}))
            t = load_tuning(p)
            self.assertEqual(t.max_codeql_workers, 2)

    def test_string_value_falls_back(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "tuning.json"
            p.write_text(json.dumps({"max_semgrep_workers": "banana"}))
            t = load_tuning(p)
            self.assertEqual(t.max_semgrep_workers, 4)

    def test_unknown_key_warns(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "tuning.json"
            p.write_text(json.dumps({"bogus_key": 42, "max_semgrep_workers": 8}))
            with self.assertLogs("core.tuning", level="WARNING") as cm:
                t = load_tuning(p)
            self.assertIn("bogus_key", cm.output[0])
            self.assertEqual(t.max_semgrep_workers, 8)

    def test_invalid_json_returns_defaults(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "tuning.json"
            p.write_text("{broken")
            t = load_tuning(p)
            self.assertEqual(t.max_semgrep_workers, 4)

    def test_non_object_returns_defaults(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "tuning.json"
            p.write_text("[1, 2, 3]")
            t = load_tuning(p)
            self.assertEqual(t.max_semgrep_workers, 4)

    def test_comments_in_file(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "tuning.json"
            p.write_text(
                '{\n'
                '  // override RAM\n'
                '  "codeql_ram_mb": 4096, // my box\n'
                '  "max_semgrep_workers": 8\n'
                '}\n'
            )
            t = load_tuning(p)
            self.assertEqual(t.codeql_ram_mb, 4096)
            self.assertEqual(t.max_semgrep_workers, 8)

    def test_partial_override(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "tuning.json"
            p.write_text(json.dumps({"max_fuzz_parallel": 8}))
            t = load_tuning(p)
            self.assertEqual(t.max_fuzz_parallel, 8)
            self.assertEqual(t.max_semgrep_workers, 4)
            self.assertEqual(t.max_codeql_workers, 2)


    def test_auto_creates_default_file(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "tuning.json"
            self.assertFalse(p.exists())
            with patch("core.tuning._TUNING_PATH", p):
                t = load_tuning()
            self.assertTrue(p.exists())
            self.assertEqual(t.max_semgrep_workers, 4)


class TestAutoDetection(unittest.TestCase):

    def test_ram_clamps_low(self):
        with patch("core.tuning.os.sysconf", side_effect=lambda k: {
            "SC_PHYS_PAGES": 1024 * 1024,
            "SC_PAGE_SIZE": 4096,
        }[k]):
            self.assertEqual(_detect_ram_mb(), 2048)

    def test_ram_clamps_high(self):
        with patch("core.tuning.os.sysconf", side_effect=lambda k: {
            "SC_PHYS_PAGES": 128 * 1024 * 1024,
            "SC_PAGE_SIZE": 4096,
        }[k]):
            self.assertEqual(_detect_ram_mb(), 16384)

    def test_ram_fallback_on_error(self):
        with patch("core.tuning.os.sysconf", side_effect=OSError):
            self.assertEqual(_detect_ram_mb(), 8192)

    def test_threads_returns_zero(self):
        # 0 = CodeQL's native "use all CPUs" mode
        self.assertEqual(_detect_threads(), 0)


    def test_available_cpus_respects_cgroup_v2_quota(self):
        def fake_read_text(path, encoding="utf-8"):
            if str(path) == "/sys/fs/cgroup/cpu.max":
                return "250000 100000"
            raise OSError

        with patch("core.tuning.Path.read_text", fake_read_text), patch(
            "core.tuning.os.sched_getaffinity", return_value=set(range(64)), create=True
        ), patch("core.tuning.os.cpu_count", return_value=64):
            self.assertEqual(_detect_cgroup_cpu_quota(), 3)
            self.assertEqual(_detect_available_cpus(), 3)

    def test_available_cpus_respects_cgroup_v1_quota(self):
        def fake_read_text(path, encoding="utf-8"):
            path = str(path)
            if path == "/sys/fs/cgroup/cpu.max":
                raise OSError
            if path == "/sys/fs/cgroup/cpu/cpu.cfs_quota_us":
                return "200000"
            if path == "/sys/fs/cgroup/cpu/cpu.cfs_period_us":
                return "100000"
            raise OSError

        with patch("core.tuning.Path.read_text", fake_read_text), patch(
            "core.tuning.os.sched_getaffinity", return_value=set(range(64)), create=True
        ), patch("core.tuning.os.cpu_count", return_value=64):
            self.assertEqual(_detect_cgroup_cpu_quota(), 2)
            self.assertEqual(_detect_available_cpus(), 2)

    def test_available_cpus_falls_back_when_cpu_unknown(self):
        with patch("core.tuning.Path.read_text", side_effect=OSError), patch(
            "core.tuning.os.sched_getaffinity", None, create=True
        ), patch("core.tuning.os.cpu_count", return_value=None):
            self.assertEqual(_detect_available_cpus(), 4)

    def test_semgrep_workers_uses_half_detected_cpus(self):
        with patch("core.tuning.os.sched_getaffinity", None, create=True), patch("core.tuning.os.cpu_count", return_value=10):
            self.assertEqual(_detect_semgrep_workers(), 5)

    def test_semgrep_workers_respects_affinity_before_host_cpu_count(self):
        with patch("core.tuning.os.sched_getaffinity", return_value=set(range(8)), create=True), patch("core.tuning.os.cpu_count", return_value=64):
            self.assertEqual(_detect_semgrep_workers(), 4)

    def test_semgrep_workers_has_minimum_and_unknown_cpu_fallback(self):
        with patch("core.tuning.os.sched_getaffinity", None, create=True), patch("core.tuning.os.cpu_count", return_value=1):
            self.assertEqual(_detect_semgrep_workers(), 1)
        with patch("core.tuning.os.sched_getaffinity", None, create=True), patch("core.tuning.os.cpu_count", return_value=None):
            self.assertEqual(_detect_semgrep_workers(), 2)

    def test_codeql_workers_uses_half_detected_cpus(self):
        with patch("core.tuning.os.sched_getaffinity", None, create=True), patch("core.tuning.os.cpu_count", return_value=16), patch("core.tuning._detect_total_ram_mb", return_value=262144), patch("core.tuning._detect_ram_mb", return_value=16384):
            self.assertEqual(_detect_codeql_workers(), 8)

    def test_codeql_workers_has_memory_and_hard_ceiling(self):
        with patch("core.tuning.os.sched_getaffinity", None, create=True), patch("core.tuning.os.cpu_count", return_value=256), patch("core.tuning._detect_total_ram_mb", return_value=262144), patch("core.tuning._detect_ram_mb", return_value=16384):
            self.assertEqual(_detect_codeql_workers(), 8)
        with patch("core.tuning.os.sched_getaffinity", None, create=True), patch("core.tuning.os.cpu_count", return_value=64), patch("core.tuning._detect_total_ram_mb", return_value=32768), patch("core.tuning._detect_ram_mb", return_value=16384):
            self.assertEqual(_detect_codeql_workers(), 2)

    def test_codeql_workers_has_minimum_and_unknown_cpu_fallback(self):
        with patch("core.tuning.os.sched_getaffinity", None, create=True), patch("core.tuning.os.cpu_count", return_value=1):
            self.assertEqual(_detect_codeql_workers(), 1)
        with patch("core.tuning.os.sched_getaffinity", None, create=True), patch("core.tuning.os.cpu_count", return_value=None):
            self.assertEqual(_detect_codeql_workers(), 2)

    def test_fuzz_parallel_uses_half_detected_cpus(self):
        with patch("core.tuning.os.sched_getaffinity", None, create=True), patch("core.tuning.os.cpu_count", return_value=16):
            self.assertEqual(_detect_fuzz_parallel(), 8)

    def test_fuzz_parallel_has_minimum_and_unknown_cpu_fallback(self):
        with patch("core.tuning.os.sched_getaffinity", None, create=True), patch("core.tuning.os.cpu_count", return_value=1):
            self.assertEqual(_detect_fuzz_parallel(), 1)
        with patch("core.tuning.os.sched_getaffinity", None, create=True), patch("core.tuning.os.cpu_count", return_value=None):
            self.assertEqual(_detect_fuzz_parallel(), 2)


class TestTuningFrozen(unittest.TestCase):

    def test_immutable(self):
        t = Tuning(
            codeql_ram_mb=8192, codeql_threads=8,
            max_semgrep_workers=4, max_codeql_workers=2,
            max_agentic_parallel=3, max_fuzz_parallel=1,
        )
        with self.assertRaises(AttributeError):
            t.codeql_ram_mb = 999


if __name__ == "__main__":
    unittest.main()
