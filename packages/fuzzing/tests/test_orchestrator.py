"""Tests for the fuzzing orchestrator's planning logic."""

import os
import platform
import shutil
import tempfile
import unittest

import pytest
from pathlib import Path
from unittest.mock import patch

from packages.fuzzing.capability import CapabilityReport
from packages.fuzzing.orchestrator import FuzzingOrchestrator


def _tmpdir(case: unittest.TestCase) -> Path:
    """mkdtemp with addCleanup-driven teardown.

    Pre-fix these suites called ``tempfile.mkdtemp`` bare — every
    source-repo / out-dir fixture leaked a ``$TMPDIR/tmpXXXXXXXX``
    (observed piling up on shared hosts as anonymous dirs holding
    ``main.c`` or ``capability_report.json``/``fuzzing_plan.json``).
    ``addCleanup`` removes the dir even when the test fails or raises.
    """
    d = tempfile.mkdtemp()
    case.addCleanup(shutil.rmtree, d, ignore_errors=True)
    return Path(d)


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
                       return_value=_full_caps_linux()), \
                 patch.object(FuzzingOrchestrator, "_is_libfuzzer_instrumented",
                              return_value=False):
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

    @pytest.mark.slow
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

    def test_prepare_corpus_falls_back_to_builtin_seed_corpus(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            target = out_dir / "target"
            target.write_bytes(b"\x7fELF\x02\x01\x01")
            plan = type(
                "Plan",
                (),
                {"target": type("Target", (), {"path": target})()},
            )()
            orch = FuzzingOrchestrator.__new__(FuzzingOrchestrator)

            with patch("packages.autonomous.CorpusGenerator",
                       side_effect=RuntimeError("no generator")):
                corpus, info = orch._prepare_corpus(
                    plan,
                    out_dir=out_dir,
                    corpus_dir=None,
                    source_context_dir=None,
                )

            self.assertEqual(corpus, out_dir / "seed-corpus")
            self.assertEqual(info["source"], "raptor_builtin_seed_corpus")
            self.assertGreaterEqual(info["seeds"], 10)
            self.assertTrue((corpus / "seed-0006-http-get").is_file())
            self.assertTrue((out_dir / "seed-corpus.json").is_file())


if __name__ == "__main__":
    unittest.main()


class TestEnvBuildPlanning(unittest.TestCase):
    """Source-tree targets route to AFL env build-on-demand when
    (and only when) the operator authorised the build."""

    def _source_repo(self):
        d = _tmpdir(self)
        (d / "main.c").write_text("int main(void){return 0;}\n")
        return d

    def test_authorised_source_dir_plans_env_build(self):
        repo = self._source_repo()
        with patch("packages.fuzzing.orchestrator.probe_capabilities",
                   return_value=_full_caps_linux()), \
             patch("packages.fuzzing.env_build.env_build_candidate",
                   return_value=(True, "")):
            plan = FuzzingOrchestrator().plan(repo)
        self.assertTrue(plan.env_build)
        self.assertEqual(plan.fuzzer, "afl")
        self.assertFalse(plan.needs_harness)
        self.assertTrue(plan.can_run)

    def test_unauthorised_source_dir_keeps_todays_blocker(self):
        repo = self._source_repo()
        hint = "set the project 'build' trust marker"
        with patch("packages.fuzzing.orchestrator.probe_capabilities",
                   return_value=_full_caps_linux()), \
             patch("packages.fuzzing.env_build.env_build_candidate",
                   return_value=(False, hint)):
            plan = FuzzingOrchestrator().plan(repo)
        self.assertFalse(plan.env_build)
        self.assertTrue(plan.needs_harness)
        self.assertFalse(plan.can_run)
        self.assertTrue(
            any("libFuzzer harness" in b for b in plan.blockers))
        self.assertIn(hint, plan.hints)

    def test_env_build_off_host_afl_not_required(self):
        # afl-fuzz comes from the image; a host without AFL still plans.
        repo = self._source_repo()
        with patch("packages.fuzzing.orchestrator.probe_capabilities",
                   return_value=_no_fuzzers_caps()), \
             patch("packages.fuzzing.env_build.env_build_candidate",
                   return_value=(True, "")):
            plan = FuzzingOrchestrator().plan(repo)
        self.assertTrue(plan.can_run)

    def test_explicit_consent_flag_reaches_candidacy(self):
        repo = self._source_repo()
        seen = {}

        def fake_candidate(path, build=None):
            seen["build"] = build
            return True, ""

        with patch("packages.fuzzing.orchestrator.probe_capabilities",
                   return_value=_full_caps_linux()), \
             patch("packages.fuzzing.env_build.env_build_candidate",
                   fake_candidate):
            plan = FuzzingOrchestrator().plan(repo, env_build=True)
        self.assertIs(seen["build"], True)
        self.assertIs(plan.env_build_consent, True)


class TestEnvBuildExecution(unittest.TestCase):
    def test_pick_env_binary_rules(self):
        from types import SimpleNamespace
        pick = FuzzingOrchestrator._pick_env_binary
        one = SimpleNamespace(binaries={"app": "/src/app"})
        many = SimpleNamespace(binaries={"b": "/src/b", "a": "/src/a"})
        self.assertEqual(pick(one, None), "app")
        self.assertEqual(pick(many, None), "a")      # sorted-first
        self.assertEqual(pick(many, "b"), "b")       # explicit wins
        with self.assertRaises(RuntimeError):
            pick(many, "nope")

    def test_failed_env_build_aborts_execute(self):
        from types import SimpleNamespace
        repo = _tmpdir(self)
        (repo / "main.c").write_text("int main(void){return 0;}\n")
        with patch("packages.fuzzing.orchestrator.probe_capabilities",
                   return_value=_full_caps_linux()), \
             patch("packages.fuzzing.env_build.env_build_candidate",
                   return_value=(True, "")):
            orch = FuzzingOrchestrator()
            plan = orch.plan(repo)
        failed = SimpleNamespace(ok=False, reason="build_failed",
                                 detail="boom")
        out = _tmpdir(self)
        with patch("packages.fuzzing.env_build.env_build_for_fuzzing",
                   return_value=failed):
            with self.assertRaises(RuntimeError) as ctx:
                orch.execute(plan, out_dir=out, duration_seconds=1)
        self.assertIn("build_failed", str(ctx.exception))


class TestEnvRootfsLifetime(unittest.TestCase):
    def test_corpus_prep_failure_discards_rootfs(self):
        from types import SimpleNamespace
        repo = _tmpdir(self)
        (repo / "main.c").write_text("int main(void){return 0;}\n")
        out = _tmpdir(self)
        rootfs = out / "afl-rootfs"
        rootfs.mkdir()
        (rootfs / "big").write_bytes(b"x")
        good = SimpleNamespace(
            ok=True, rootfs=rootfs, binaries={"app": "/src/app"},
            base_image="img", command="make", command_source="detected:make",
            guessed=True, afl_fuzz="/usr/local/bin/afl-fuzz")
        with patch("packages.fuzzing.orchestrator.probe_capabilities",
                   return_value=_full_caps_linux()), \
             patch("packages.fuzzing.env_build.env_build_candidate",
                   return_value=(True, "")):
            orch = FuzzingOrchestrator()
            plan = orch.plan(repo)
        with patch("packages.fuzzing.env_build.env_build_for_fuzzing",
                   return_value=good), \
             patch.object(FuzzingOrchestrator, "_prepare_corpus",
                          side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                orch.execute(plan, out_dir=out, duration_seconds=1)
        self.assertFalse(rootfs.exists())

    def test_keep_env_rootfs_survives_corpus_prep_failure(self):
        from types import SimpleNamespace
        repo = _tmpdir(self)
        (repo / "main.c").write_text("int main(void){return 0;}\n")
        out = _tmpdir(self)
        rootfs = out / "afl-rootfs"
        rootfs.mkdir()
        good = SimpleNamespace(
            ok=True, rootfs=rootfs, binaries={"app": "/src/app"},
            base_image="img", command="make", command_source="detected:make",
            guessed=True, afl_fuzz="/usr/local/bin/afl-fuzz")
        with patch("packages.fuzzing.orchestrator.probe_capabilities",
                   return_value=_full_caps_linux()), \
             patch("packages.fuzzing.env_build.env_build_candidate",
                   return_value=(True, "")):
            orch = FuzzingOrchestrator()
            plan = orch.plan(repo)
        with patch("packages.fuzzing.env_build.env_build_for_fuzzing",
                   return_value=good), \
             patch.object(FuzzingOrchestrator, "_prepare_corpus",
                          side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                orch.execute(plan, out_dir=out, duration_seconds=1,
                             keep_env_rootfs=True)
        self.assertTrue(rootfs.exists())

    def test_env_build_plan_drops_harness_hints(self):
        repo = _tmpdir(self)
        (repo / "main.c").write_text("int main(void){return 0;}\n")
        with patch("packages.fuzzing.orchestrator.probe_capabilities",
                   return_value=_full_caps_linux()), \
             patch("packages.fuzzing.env_build.env_build_candidate",
                   return_value=(True, "")):
            plan = FuzzingOrchestrator().plan(repo)
        self.assertFalse(
            any("harness" in h.lower() for h in plan.hints))

    def test_env_build_flag_on_file_target_hints_no_op(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".c",
                                         delete=False) as f:
            f.write("int main(void){return 0;}\n")
            tmp = Path(f.name)
        try:
            with patch("packages.fuzzing.orchestrator.probe_capabilities",
                       return_value=_full_caps_linux()):
                plan = FuzzingOrchestrator().plan(tmp, env_build=True)
            self.assertTrue(
                any("--env-build applies to source-tree" in h
                    for h in plan.hints))
        finally:
            os.unlink(tmp)
