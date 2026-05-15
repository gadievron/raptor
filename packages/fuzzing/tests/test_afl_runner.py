"""Tests for AFL runner utility parsing."""

import tempfile
import unittest
from pathlib import Path

from packages.fuzzing.afl_runner import AFLRunner


class TestAFLRunnerStatsParsing(unittest.TestCase):

    def test_parse_afl_int_tolerates_stale_stats_formats(self):
        self.assertEqual(AFLRunner._parse_afl_int("56269"), 56269)
        self.assertEqual(AFLRunner._parse_afl_int("51000.00"), 51000)
        self.assertEqual(AFLRunner._parse_afl_int("100.00%"), 100)
        self.assertEqual(AFLRunner._parse_afl_int("N/A"), 0)

    def test_max_crash_execs_uses_afl_filename_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            crashes = Path(tmpdir)
            (crashes / "README.txt").write_text("ignored")
            (crashes / "id:000000,sig:11,src:000000,time:284,execs:562,op:havoc,rep:3").write_bytes(b"a")
            (crashes / "id:000001,sig:06,src:000020,time:31644,execs:56269,op:havoc,rep:6").write_bytes(b"b")

            self.assertEqual(AFLRunner._max_crash_execs(crashes), 56269)

    def test_paths_found_falls_back_to_current_afl_corpus_fields(self):
        self.assertEqual(AFLRunner._afl_paths_found({"paths_found": "3"}), 3)
        self.assertEqual(AFLRunner._afl_paths_found({"corpus_found": "7"}), 7)
        self.assertEqual(AFLRunner._afl_paths_found({"corpus_count": "8"}), 8)

    def test_sanitizer_detection_ignores_afl_weak_asan_symbol(self):
        self.assertFalse(AFLRunner._has_runtime_sanitizer("__asan_region_is_poisoned", "asan"))
        self.assertTrue(AFLRunner._has_runtime_sanitizer("__asan_init\n__asan_report_store1", "asan"))
        self.assertTrue(AFLRunner._has_runtime_sanitizer("__ubsan_handle_add_overflow", "ubsan"))


if __name__ == "__main__":
    unittest.main()
