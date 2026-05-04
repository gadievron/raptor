"""Tests for capability detection."""

import unittest
from unittest.mock import patch

from packages.fuzzing.capability import CapabilityReport, probe, select_fuzzer


class TestCapabilityReport(unittest.TestCase):
    def test_report_summary_has_required_sections(self):
        report = CapabilityReport(
            platform="Linux", arch="x86_64", is_macos=False, is_linux=True,
        )
        summary = report.summary()
        self.assertIn("Platform: Linux x86_64", summary)
        self.assertIn("Fuzzers:", summary)
        self.assertIn("Sanitisers:", summary)

    def test_has_afl_requires_shmem_ok(self):
        report = CapabilityReport(
            platform="Darwin", arch="arm64", is_macos=True, is_linux=False,
            afl_fuzz="/usr/local/bin/afl-fuzz", afl_shmem_ok=False,
        )
        self.assertFalse(report.has_afl())

    def test_has_clang_fuzzer_requires_libfuzzer_flag(self):
        report = CapabilityReport(
            platform="Linux", arch="x86_64", is_macos=False, is_linux=True,
            clang="/usr/bin/clang", has_libfuzzer=False,
        )
        self.assertFalse(report.has_clang_fuzzer())

        report.has_libfuzzer = True
        self.assertTrue(report.has_clang_fuzzer())

    def test_has_any_fuzzer_or_logic(self):
        report = CapabilityReport(
            platform="Linux", arch="x86_64", is_macos=False, is_linux=True,
            afl_fuzz=None, clang=None,
        )
        self.assertFalse(report.has_any_fuzzer())

        report.afl_fuzz = "/usr/bin/afl-fuzz"
        report.afl_shmem_ok = True
        self.assertTrue(report.has_any_fuzzer())


class TestProbe(unittest.TestCase):
    def test_probe_returns_report(self):
        report = probe()
        self.assertIsInstance(report, CapabilityReport)
        self.assertIsNotNone(report.platform)
        self.assertIsNotNone(report.arch)

    @patch("packages.fuzzing.capability.shutil.which")
    def test_probe_detects_no_fuzzer_available(self, mock_which):
        mock_which.return_value = None
        with patch("packages.fuzzing.capability._probe_clang_sanitiser",
                   return_value=False):
            report = probe()
        self.assertFalse(report.has_any_fuzzer())
        self.assertTrue(any("No fuzzer available" in i for i in report.issues))


class TestSelectFuzzer(unittest.TestCase):
    def _report_with(self, **kwargs):
        defaults = dict(
            platform="Linux", arch="x86_64", is_macos=False, is_linux=True,
            afl_shmem_ok=True,
        )
        defaults.update(kwargs)
        return CapabilityReport(**defaults)

    def test_binary_target_prefers_afl_when_available(self):
        report = self._report_with(afl_fuzz="/x/afl-fuzz")
        self.assertEqual(select_fuzzer(report, "binary"), "afl")

    def test_binary_target_falls_back_to_libfuzzer(self):
        report = self._report_with(clang="/x/clang", has_libfuzzer=True)
        self.assertEqual(select_fuzzer(report, "binary"), "libfuzzer")

    def test_library_target_prefers_libfuzzer(self):
        report = self._report_with(
            afl_fuzz="/x/afl-fuzz",
            clang="/x/clang", has_libfuzzer=True,
        )
        self.assertEqual(select_fuzzer(report, "library"), "libfuzzer")

    def test_no_fuzzer_returns_none(self):
        report = self._report_with()
        self.assertIsNone(select_fuzzer(report, "binary"))

    def test_prefer_overrides_default(self):
        report = self._report_with(
            afl_fuzz="/x/afl-fuzz",
            clang="/x/clang", has_libfuzzer=True,
        )
        self.assertEqual(select_fuzzer(report, "binary", prefer="libfuzzer"), "libfuzzer")


if __name__ == "__main__":
    unittest.main()
