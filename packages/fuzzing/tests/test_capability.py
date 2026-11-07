"""Tests for capability detection."""

from pkgutil import resolve_name as _mock_owner
from core.testing.module_bindings import mock_module_attribute


import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from packages.fuzzing.capability import (
    CapabilityReport,
    _check_macos_afl_shmem,
    probe,
    select_fuzzer,
)

import pytest
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture(autouse=True)
def _isolate_subprocess_run_patches(monkeypatch):
    """Keep subprocess run mocks on consumer-owned module bindings."""
    import packages.fuzzing.capability as consumer_0

    patch_module_attribute(
        monkeypatch, consumer_0, "subprocess", "run", consumer_0.subprocess.run,
    )


@pytest.fixture(autouse=True)
def _isolate_shutil_patch_targets(monkeypatch):
    """Keep shutil patch decorators and contexts on consumer-owned views."""
    import packages.fuzzing.capability as consumer_0

    patch_module_attribute(
        monkeypatch, consumer_0, "shutil", "which", consumer_0.shutil.which,
    )
    # The capability probe delegates this lookup to the radare2 adapter.
    # Forward through the private binding rather than the host's shutil.
    import inspect

    radare2_probe = inspect.getmodule(consumer_0._probe_radare2_capability)

    patch_module_attribute(
        monkeypatch, radare2_probe, "shutil", "which",
        lambda *args, **kwargs: consumer_0.shutil.which(*args, **kwargs),
    )


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
    @patch("packages.fuzzing.capability.shutil.which")
    def test_probe_returns_report(self, mock_which):
        # Pin the tool probes (same seams as the no-fuzzer test
        # below): the real probe runs shutil.which over the fuzzing
        # toolchain plus a live clang sanitiser-compile per sanitiser
        # — host-dependent latency and side effects inside a unit
        # test. The asserted fields are platform-derived either way.
        mock_which.return_value = None
        with patch("packages.fuzzing.capability._probe_clang_sanitiser",
                   return_value=False):
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

    def test_macos_afl_shmem_probe_detects_runtime_failure(self):
        completed = subprocess.CompletedProcess(
            args=["afl-fuzz"],
            returncode=1,
            stdout="",
            stderr="[-] SYSTEM ERROR : shmget() failed, try running afl-system-config",
        )
        with patch.object(Path, "exists", return_value=True), \
             mock_module_attribute(_mock_owner('packages.fuzzing.capability'), 'subprocess', 'run',
                   return_value=completed):
            self.assertFalse(_check_macos_afl_shmem("/x/afl-fuzz"))

    def test_macos_afl_shmem_probe_allows_clean_startup(self):
        completed = subprocess.CompletedProcess(
            args=["afl-fuzz"],
            returncode=0,
            stdout="fuzzing stopped by user",
            stderr="",
        )
        with patch.object(Path, "exists", return_value=True), \
             mock_module_attribute(_mock_owner('packages.fuzzing.capability'), 'subprocess', 'run',
                   return_value=completed):
            self.assertTrue(_check_macos_afl_shmem("/x/afl-fuzz"))


def _probe_on(system: str, machine: str):
    """Run probe() with the host pinned to (system, machine).

    Tool discovery and the per-sanitiser compile probes are stubbed at
    the same seams as the probe tests above: clang is "found" and
    every sanitiser probe reports supported, so has_memory_sanitizer
    starts True and only the platform-policy downgrade can clear it.
    """
    with mock_module_attribute(_mock_owner('packages.fuzzing.capability'), 'platform', 'system',
               return_value=system), \
         mock_module_attribute(_mock_owner('packages.fuzzing.capability'), 'platform', 'machine',
               return_value=machine), \
         mock_module_attribute(_mock_owner('packages.fuzzing.capability'), 'shutil', 'which',
               side_effect=lambda name: "/x/clang" if name == "clang" else None), \
         patch("packages.fuzzing.capability._probe_clang_sanitiser",
               return_value=True), \
         patch("packages.fuzzing.capability._probe_version",
               return_value=""), \
         patch("packages.fuzzing.capability._probe_radare2_capability",
               return_value={}):
        return probe()


class TestMemorySanitizerPlatformPolicy(unittest.TestCase):
    """The downgrade guard must enforce the stated "Linux x86_64 only"
    rule via is_linux, not merely via is_macos, so exotic hosts (e.g.
    FreeBSD x86_64) are downgraded too."""

    def test_linux_x86_64_keeps_msan(self):
        report = _probe_on("Linux", "x86_64")
        self.assertTrue(report.has_memory_sanitizer)

    def test_linux_amd64_keeps_msan(self):
        report = _probe_on("Linux", "amd64")
        self.assertTrue(report.has_memory_sanitizer)

    def test_linux_aarch64_downgrades_msan(self):
        report = _probe_on("Linux", "aarch64")
        self.assertFalse(report.has_memory_sanitizer)
        self.assertTrue(any("MemorySanitizer" in i for i in report.issues))

    def test_macos_downgrades_msan(self):
        report = _probe_on("Darwin", "x86_64")
        self.assertFalse(report.has_memory_sanitizer)
        self.assertTrue(any("MemorySanitizer" in i for i in report.issues))

    def test_non_linux_non_macos_x86_64_downgrades_msan(self):
        # is_macos alone let e.g. FreeBSD x86_64 keep
        # has_memory_sanitizer=True against the Linux-x86_64-only policy.
        report = _probe_on("FreeBSD", "x86_64")
        self.assertFalse(report.has_memory_sanitizer)
        self.assertTrue(any("MemorySanitizer" in i for i in report.issues))


class TestSelectFuzzer(unittest.TestCase):
    def _report_with(self, **kwargs):
        defaults = {
            "platform": "Linux", "arch": "x86_64",
            "is_macos": False, "is_linux": True,
            "afl_shmem_ok": True,
        }
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
