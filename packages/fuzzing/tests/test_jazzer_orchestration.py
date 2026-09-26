"""Orchestrator wiring for the jazzer engine: planning, target
resolution, engine override, corpus convention, witness recording, and
the verified-outcomes join."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from packages.fuzzing.capability import CapabilityReport
from packages.fuzzing.jazzer_runner import JavaExceptionInfo
from packages.fuzzing.orchestrator import FuzzingOrchestrator
from packages.fuzzing.witness_adapter import witness_from_jazzer_artifact


def _tmpdir(case: unittest.TestCase) -> Path:
    d = tempfile.mkdtemp()
    case.addCleanup(shutil.rmtree, d, ignore_errors=True)
    return Path(d)


def _java_project(tmp: Path,
                  targets: tuple[str, ...] = ("ParserFuzz",),
                  package: str = "com.example") -> Path:
    project = tmp / "proj"
    src = project / "src" / "test" / "java"
    src.mkdir(parents=True)
    (project / "pom.xml").write_text("<project/>\n")
    for name in targets:
        (src / f"{name}.java").write_text(
            f"package {package};\n"
            f"public class {name} {{\n"
            "  public static void fuzzerTestOneInput(byte[] data) {}\n"
            "}\n")
    return project


def _caps() -> CapabilityReport:
    return CapabilityReport(
        platform="Linux", arch="x86_64", is_macos=False, is_linux=True,
    )


def _which_with_jvm(name: str, *args, **kwargs):
    return {"jazzer": "/usr/bin/jazzer",
            "java": "/usr/bin/java",
            "mvn": "/usr/bin/mvn"}.get(name)


def _plan(case: unittest.TestCase, target: Path, **kwargs):
    """Plan against *target* with the JVM toolchain stubbed present
    (no subprocess in unit tests)."""
    with patch("packages.fuzzing.orchestrator.probe_capabilities",
               return_value=_caps()), \
         patch("packages.fuzzing.target_detector.shutil.which",
               side_effect=_which_with_jvm), \
         patch("packages.fuzzing.jazzer_runner.build_tool_executable",
               return_value="/usr/bin/mvn"):
        orch = FuzzingOrchestrator()
        return orch.plan(target, **kwargs)


class TestJazzerPlanning(unittest.TestCase):

    def test_single_target_auto_selects_and_can_run(self):
        tmp = _tmpdir(self)
        plan = _plan(self, _java_project(tmp))
        self.assertEqual(plan.fuzzer, "jazzer")
        self.assertEqual(plan.jazzer_target, "com.example.ParserFuzz")
        self.assertTrue(str(plan.jazzer_target_source)
                        .endswith("ParserFuzz.java"))
        self.assertTrue(plan.can_run, plan.blockers)
        self.assertTrue(any("auto-selected" in h for h in plan.hints))

    def test_multiple_targets_block_with_the_list(self):
        tmp = _tmpdir(self)
        plan = _plan(self, _java_project(tmp, ("AFuzz", "BFuzz")))
        self.assertIsNone(plan.jazzer_target)
        self.assertFalse(plan.can_run)
        text = " ".join(plan.blockers)
        self.assertIn("--fuzz-target", text)
        self.assertIn("com.example.AFuzz", text)
        self.assertIn("com.example.BFuzz", text)

    def test_explicit_fqcn_wins(self):
        tmp = _tmpdir(self)
        plan = _plan(self, _java_project(tmp, ("AFuzz", "BFuzz")),
                     fuzz_target="com.example.BFuzz")
        self.assertEqual(plan.jazzer_target, "com.example.BFuzz")
        self.assertTrue(plan.can_run, plan.blockers)

    def test_unambiguous_simple_name_is_honoured(self):
        tmp = _tmpdir(self)
        plan = _plan(self, _java_project(tmp, ("AFuzz", "BFuzz")),
                     fuzz_target="BFuzz")
        self.assertEqual(plan.jazzer_target, "com.example.BFuzz")
        self.assertTrue(plan.can_run, plan.blockers)

    def test_ambiguous_simple_name_blocks_with_candidates(self):
        tmp = _tmpdir(self)
        project = _java_project(tmp, ("SameFuzz",))
        other = project / "src" / "test" / "java" / "other"
        other.mkdir()
        (other / "SameFuzz.java").write_text(
            "package com.other;\n"
            "public class SameFuzz {\n"
            "  public static void fuzzerTestOneInput(byte[] d) {}\n"
            "}\n")
        plan = _plan(self, project, fuzz_target="SameFuzz")
        self.assertIsNone(plan.jazzer_target)
        self.assertFalse(plan.can_run)
        text = " ".join(plan.blockers)
        self.assertIn("ambiguous", text)
        self.assertIn("com.example.SameFuzz", text)
        self.assertIn("com.other.SameFuzz", text)

    def test_unknown_fuzz_target_blocks(self):
        tmp = _tmpdir(self)
        plan = _plan(self, _java_project(tmp), fuzz_target="Nope")
        self.assertFalse(plan.can_run)
        self.assertTrue(any("--fuzz-target" in b for b in plan.blockers))

    def test_no_fuzz_targets_block_with_harness_remedy(self):
        tmp = _tmpdir(self)
        project = tmp / "proj"
        project.mkdir()
        (project / "pom.xml").write_text("<project/>\n")
        plan = _plan(self, project)
        self.assertEqual(plan.fuzzer, "jazzer")
        self.assertTrue(plan.needs_harness)
        self.assertFalse(plan.can_run)
        self.assertTrue(any("fuzzerTestOneInput" in b
                            for b in plan.blockers))
        self.assertIn("fuzzerTestOneInput", plan.summary())

    def test_missing_toolchain_still_reports_target(self):
        tmp = _tmpdir(self)
        project = _java_project(tmp)
        with patch("packages.fuzzing.orchestrator.probe_capabilities",
                   return_value=_caps()), \
             patch("packages.fuzzing.target_detector.shutil.which",
                   return_value=None):
            orch = FuzzingOrchestrator()
            plan = orch.plan(project)
        self.assertEqual(plan.target.kind, "java-project")
        self.assertIsNone(plan.fuzzer)
        self.assertFalse(plan.can_run)
        self.assertTrue(
            any("CodeIntelligenceTesting/jazzer" in b
                for b in plan.blockers))

    def test_missing_build_tool_blocks_at_plan_time(self):
        # jazzer + java present, but the layout's build tool missing:
        # the plan blocks with the install hint instead of dying at
        # runner construction mid-execute.
        tmp = _tmpdir(self)
        project = _java_project(tmp)
        with patch("packages.fuzzing.orchestrator.probe_capabilities",
                   return_value=_caps()), \
             patch("packages.fuzzing.target_detector.shutil.which",
                   side_effect=_which_with_jvm), \
             patch("packages.fuzzing.jazzer_runner"
                   ".build_tool_executable", return_value=None):
            orch = FuzzingOrchestrator()
            plan = orch.plan(project)
        self.assertEqual(plan.jazzer_target, "com.example.ParserFuzz")
        self.assertFalse(plan.can_run)
        self.assertTrue(any("mvn" in b for b in plan.blockers),
                        plan.blockers)


class TestEngineOverride(unittest.TestCase):

    def test_engine_jazzer_on_java_project_is_honoured(self):
        tmp = _tmpdir(self)
        plan = _plan(self, _java_project(tmp), engine="jazzer")
        self.assertEqual(plan.fuzzer, "jazzer")
        self.assertTrue(plan.can_run, plan.blockers)

    def test_engine_jazzer_on_source_tree_blocks(self):
        tmp = _tmpdir(self)
        src = tmp / "csrc"
        src.mkdir()
        (src / "main.c").write_text("int main(void){return 0;}\n")
        plan = _plan(self, src, engine="jazzer")
        self.assertIsNone(plan.fuzzer)
        self.assertFalse(plan.can_run)
        self.assertTrue(
            any("--engine jazzer cannot drive" in b
                for b in plan.blockers))

    def test_engine_cargofuzz_on_java_project_blocks(self):
        tmp = _tmpdir(self)
        plan = _plan(self, _java_project(tmp), engine="cargo-fuzz")
        self.assertIsNone(plan.fuzzer)
        self.assertTrue(
            any("--engine cargo-fuzz cannot drive" in b
                for b in plan.blockers))

    def test_fuzz_target_on_other_kind_is_named_not_silently_dropped(self):
        tmp = _tmpdir(self)
        src = tmp / "csrc"
        src.mkdir()
        (src / "main.c").write_text("int main(void){return 0;}\n")
        plan = _plan(self, src, fuzz_target="ParserFuzz")
        self.assertTrue(
            any("--fuzz-target applies to rust-crate and java-project"
                in h for h in plan.hints), plan.hints)

    def test_fuzz_target_on_java_project_gets_no_ignored_hint(self):
        tmp = _tmpdir(self)
        plan = _plan(self, _java_project(tmp),
                     fuzz_target="com.example.ParserFuzz")
        self.assertFalse(
            any("ignored" in h for h in plan.hints), plan.hints)


class TestWitnessJoin(unittest.TestCase):

    def _crash_artifact(self, tmp: Path) -> Path:
        artifact = tmp / "crash-da39a3ee5e6b"
        artifact.write_bytes(b"\x00payload")
        return artifact

    def _exception(self) -> JavaExceptionInfo:
        return JavaExceptionInfo(
            exception_type="java.lang.IllegalStateException",
            message="boom: 7",
            frames=["com.example.ParserFuzz.parse(ParserFuzz.java:9)"],
            stack_key="cd" * 8,
        )

    def test_adapter_produces_fuzz_exit_signal_witness(self):
        tmp = _tmpdir(self)
        harness = tmp / "ParserFuzz.java"
        harness.write_text("class ParserFuzz {}\n")
        artifact = self._crash_artifact(tmp)
        witness, data = witness_from_jazzer_artifact(
            artifact, exception=self._exception(), harness_path=harness,
        )
        self.assertEqual(data, b"\x00payload")
        self.assertEqual(witness.source.value, "fuzz")
        self.assertEqual(witness.observed_outcome.value, "exit_signal")
        self.assertEqual(witness.produced_by, "jazzer")
        detail = witness.outcome_detail
        self.assertEqual(detail["crash_kind"], "java_exception")
        self.assertEqual(detail["exception_type"],
                         "java.lang.IllegalStateException")
        self.assertEqual(detail["exception_message"], "boom: 7")
        self.assertEqual(detail["stack_hash"], "cd" * 8)
        self.assertTrue(detail["harness_hash"])

    def test_native_crash_without_exception_detail(self):
        tmp = _tmpdir(self)
        artifact = self._crash_artifact(tmp)
        witness, _ = witness_from_jazzer_artifact(artifact)
        self.assertEqual(witness.outcome_detail["crash_kind"], "native")

    def test_adapter_refuses_oversized_artifact(self):
        # The crashes dir is target-writable: a planted oversize
        # regular file must not reach the witness store.
        tmp = _tmpdir(self)
        artifact = tmp / "crash-huge"
        with artifact.open("wb") as fh:
            fh.truncate(4 * 1024 * 1024 + 1)
        with self.assertRaises(ValueError):
            witness_from_jazzer_artifact(artifact)

    def test_recorded_witness_joins_verified_outcomes(self):
        # The full chain: a jazzer crash recorded through the
        # orchestrator's store step must surface as an oracle-verified
        # outcome for raptor-verified-outcomes.
        tmp = _tmpdir(self)
        out_dir = tmp / "out"
        out_dir.mkdir()
        result = SimpleNamespace(
            crashes=[self._crash_artifact(tmp)],
            java_exception=self._exception(),
        )
        recorded = FuzzingOrchestrator._record_jazzer_witnesses(
            out_dir, result, None,
        )
        self.assertEqual(recorded, 1)

        from core.labeled_attempts.view import collect_outcomes
        outcomes = [
            o for o in collect_outcomes(out_dir)
            if o.produced_by == "jazzer"
        ]
        self.assertEqual(len(outcomes), 1)
        self.assertEqual(outcomes[0].oracle.value, "fuzzer")
        self.assertEqual(outcomes[0].status.value, "verified")

    def test_record_witnesses_is_best_effort(self):
        tmp = _tmpdir(self)
        out_dir = tmp / "out"
        out_dir.mkdir()
        result = SimpleNamespace(
            crashes=[tmp / "crash-vanished"],   # never written
            java_exception=None,
        )
        recorded = FuzzingOrchestrator._record_jazzer_witnesses(
            out_dir, result, None,
        )
        self.assertEqual(recorded, 0)


class _FakeRunner:
    """Stands in for JazzerRunner at the orchestrator seam."""

    seen: dict = {}

    def __init__(self, project_dir, target_class, **kwargs):
        type(self).seen = {
            "project_dir": Path(project_dir),
            "target_class": target_class,
            "kwargs": kwargs,
        }
        self.output_dir = Path(kwargs["output_dir"])
        self.crashes_dir = self.output_dir / "crashes"
        self.build_tool = "maven"

    def run(self, telemetry=None):
        from packages.fuzzing.libfuzzer_runner import LibFuzzerStats
        return SimpleNamespace(
            campaign_failed=False,
            crashes=[], timeouts=[], oom_inputs=[], leak_inputs=[],
            java_exception=None,
            crash_records=[],
            stats=LibFuzzerStats(total_executions=42),
        )


class TestExecuteWiring(unittest.TestCase):

    def _execute(self, plan, out_dir: Path, corpus_dir: Path | None):
        with patch("packages.fuzzing.jazzer_runner.JazzerRunner",
                   _FakeRunner), \
             patch("packages.fuzzing.orchestrator.probe_capabilities",
                   return_value=_caps()):
            orch = FuzzingOrchestrator()
            return orch.execute(
                plan,
                out_dir=out_dir,
                duration_seconds=5,
                corpus_dir=corpus_dir,
            )

    def test_execute_runs_jazzer_with_plan_target(self):
        tmp = _tmpdir(self)
        project = _java_project(tmp)
        out_dir = tmp / "out"
        seeds = tmp / "seeds"
        seeds.mkdir()
        (seeds / "seed").write_bytes(b"hi")
        plan = _plan(self, project)
        self.assertTrue(plan.can_run, plan.blockers)

        result = self._execute(plan, out_dir, seeds)

        self.assertEqual(result["fuzzer"], "jazzer")
        self.assertFalse(result["campaign_failed"])
        self.assertEqual(result["crashes"], 0)
        self.assertEqual(result["fuzz_target"], "com.example.ParserFuzz")
        self.assertEqual(result["build_tool"], "maven")
        self.assertEqual(result["stats"]["total_executions"], 42)
        seen = _FakeRunner.seen
        self.assertEqual(seen["project_dir"], project)
        self.assertEqual(seen["target_class"], "com.example.ParserFuzz")
        self.assertEqual(seen["kwargs"]["max_total_time"], 5)
        self.assertEqual(seen["kwargs"]["corpus_dir"], seeds)
        self.assertTrue(str(seen["kwargs"]["target_source"])
                        .endswith("ParserFuzz.java"))
        # Plan record carries the jazzer field.
        plan_record = json.loads(
            (out_dir / "fuzzing_plan.json").read_text())
        self.assertEqual(plan_record["fuzzer"], "jazzer")
        self.assertEqual(plan_record["jazzer_target"],
                         "com.example.ParserFuzz")

    def test_inputs_convention_wins_without_operator_corpus(self):
        tmp = _tmpdir(self)
        project = _java_project(tmp)
        inputs = (project / "src" / "test" / "resources" / "com"
                  / "example" / "ParserFuzzInputs")
        inputs.mkdir(parents=True)
        (inputs / "seed").write_bytes(b"hi")
        out_dir = tmp / "out"
        plan = _plan(self, project)

        result = self._execute(plan, out_dir, None)

        self.assertEqual(_FakeRunner.seen["kwargs"]["corpus_dir"],
                         inputs)
        self.assertEqual(result["jazzer_corpus"]["path"], str(inputs))
        self.assertTrue((out_dir / "jazzer-corpus.json").is_file())


if __name__ == "__main__":
    unittest.main()
