"""Tests for the fuzzing orchestrator's planning logic."""

import os
import platform
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from packages.fuzzing.capability import CapabilityReport
from packages.fuzzing.orchestrator import FuzzingOrchestrator, CampaignPlan
from packages.fuzzing.target_detector import TargetInfo


def _full_caps_linux():
    return CapabilityReport(
        platform="Linux", arch="x86_64", is_macos=False, is_linux=True,
        afl_fuzz="/usr/bin/afl-fuzz", afl_shmem_ok=True,
        clang="/usr/bin/clang", has_libfuzzer=True,
        has_address_sanitizer=True, has_undefined_sanitizer=True,
    )


def _full_caps_macos():
    return CapabilityReport(
        platform="Darwin", arch="arm64", is_macos=True, is_linux=False,
        afl_fuzz="/opt/homebrew/bin/afl-fuzz", afl_shmem_ok=False,
        clang="/usr/bin/clang", has_libfuzzer=True,
        has_address_sanitizer=True, has_undefined_sanitizer=True,
        macos_afl_warning="shared memory limits too low; run 'sudo afl-system-config'",
    )


def _no_fuzzers_caps():
    return CapabilityReport(
        platform="Linux", arch="x86_64", is_macos=False, is_linux=True,
    )


class TestOrchestratorPlanning(unittest.TestCase):

    def test_plan_for_pe_sys_blocks_with_helpful_message(self):
        with tempfile.NamedTemporaryFile(suffix=".sys", delete=False) as f:
            f.write(b"MZ" + b"\x00" * 60)
            tmp = Path(f.name)
        try:
            with patch("packages.fuzzing.orchestrator.probe_capabilities",
                       return_value=_full_caps_linux()):
                orch = FuzzingOrchestrator()
                plan = orch.plan(tmp)
            self.assertFalse(plan.can_run)
            self.assertEqual(plan.target.kind, "pe-sys")
            text = " ".join(plan.blockers).lower()
            self.assertTrue(
                "kafl" in text or "snapchange" in text or "kernel" in text or
                "snapshot" in text,
                f"PE .sys plan should mention kernel-fuzzing options: {plan.blockers}",
            )
        finally:
            os.unlink(tmp)

    def test_plan_for_linux_elf_on_linux_picks_afl(self):
        if platform.system() != "Linux":
            self.skipTest("ELF binary plan only fuzzable on Linux host")
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x7fELF\x02\x01\x01" + b"\x00" * 1024)
            tmp = Path(f.name)
        try:
            tmp.chmod(0o755)
            with patch("packages.fuzzing.orchestrator.probe_capabilities",
                       return_value=_full_caps_linux()):
                orch = FuzzingOrchestrator()
                plan = orch.plan(tmp)
            self.assertEqual(plan.fuzzer, "afl")
            self.assertTrue(plan.can_run)
        finally:
            os.unlink(tmp)

    def test_plan_for_source_file_needs_harness(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
            f.write("int main(void){ return 0; }\n")
            tmp = Path(f.name)
        try:
            with patch("packages.fuzzing.orchestrator.probe_capabilities",
                       return_value=_full_caps_linux()):
                orch = FuzzingOrchestrator()
                plan = orch.plan(tmp)
            self.assertTrue(plan.needs_harness)
            self.assertEqual(plan.fuzzer, "libfuzzer")
            self.assertFalse(plan.can_run)
            self.assertTrue(any("compiled libFuzzer harness" in b for b in plan.blockers))
        finally:
            os.unlink(tmp)

    def test_plan_with_no_fuzzers_blocks(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
            f.write("int main(void){ return 0; }\n")
            tmp = Path(f.name)
        try:
            with patch("packages.fuzzing.orchestrator.probe_capabilities",
                       return_value=_no_fuzzers_caps()):
                orch = FuzzingOrchestrator()
                plan = orch.plan(tmp)
            self.assertFalse(plan.can_run)
            self.assertIsNone(plan.fuzzer)
        finally:
            os.unlink(tmp)

    def test_macos_with_broken_afl_does_not_run_plain_macho_as_libfuzzer(self):
        with tempfile.NamedTemporaryFile(suffix="", delete=False) as f:
            f.write(b"\xcf\xfa\xed\xfe" + b"\x00" * 1024)
            tmp = Path(f.name)
        try:
            tmp.chmod(0o755)
            with patch("packages.fuzzing.target_detector.platform.system",
                       return_value="Darwin"), \
                 patch("packages.fuzzing.orchestrator.probe_capabilities",
                       return_value=_full_caps_macos()):
                orch = FuzzingOrchestrator()
                plan = orch.plan(tmp)
            self.assertIsNone(plan.fuzzer)
            self.assertFalse(plan.can_run)
            self.assertTrue(any("AFL++ shared memory" in h for h in plan.hints))
            self.assertTrue(any("LLVMFuzzerTestOneInput" in b for b in plan.blockers))
        finally:
            os.unlink(tmp)

    def test_instrumented_unix_binary_can_use_libfuzzer(self):
        with tempfile.NamedTemporaryFile(suffix="", delete=False) as f:
            f.write(b"\xcf\xfa\xed\xfe" + b"\x00" * 1024)
            tmp = Path(f.name)
        try:
            tmp.chmod(0o755)
            with patch("packages.fuzzing.target_detector.platform.system",
                       return_value="Darwin"), \
                 patch("packages.fuzzing.orchestrator.probe_capabilities",
                       return_value=_full_caps_macos()), \
                 patch.object(FuzzingOrchestrator, "_is_libfuzzer_instrumented",
                              return_value=True):
                orch = FuzzingOrchestrator()
                plan = orch.plan(tmp)
            self.assertEqual(plan.fuzzer, "libfuzzer")
            self.assertTrue(plan.can_run)
        finally:
            os.unlink(tmp)

    def test_plan_summary_has_required_fields(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
            f.write("int main(void){ return 0; }\n")
            tmp = Path(f.name)
        try:
            with patch("packages.fuzzing.orchestrator.probe_capabilities",
                       return_value=_full_caps_linux()):
                orch = FuzzingOrchestrator()
                plan = orch.plan(tmp)
            summary = plan.summary()
            self.assertIn("RAPTOR FUZZING CAMPAIGN PLAN", summary)
            self.assertIn("Target:", summary)
            self.assertIn("Host capabilities:", summary)
            self.assertIn("Can run:", summary)
        finally:
            os.unlink(tmp)


if __name__ == "__main__":
    unittest.main()
