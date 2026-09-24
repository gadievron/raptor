"""Orchestrator wiring for the atheris engine: planning, engine
override, harness resolution, witness recording, and the
verified-outcomes join."""

import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from packages.fuzzing.atheris_runner import PythonExceptionInfo
from packages.fuzzing.capability import CapabilityReport
from packages.fuzzing.orchestrator import FuzzingOrchestrator
from packages.fuzzing.witness_adapter import witness_from_atheris_artifact


def _tmpdir(case: unittest.TestCase) -> Path:
    d = tempfile.mkdtemp()
    case.addCleanup(shutil.rmtree, d, ignore_errors=True)
    return Path(d)


def _python_pkg(tmp: Path) -> Path:
    pkg = tmp / "pkg"
    pkg.mkdir()
    (pkg / "pyproject.toml").write_text("[project]\nname='p'\n")
    return pkg


def _caps() -> CapabilityReport:
    return CapabilityReport(
        platform="Linux", arch="x86_64", is_macos=False, is_linux=True,
    )


def _plan(case: unittest.TestCase, target: Path, **kwargs):
    """Plan against *target* with a stub atheris importable, so the
    detector reports the engine available without the real dep."""
    with patch("packages.fuzzing.orchestrator.probe_capabilities",
               return_value=_caps()), \
         patch.dict(sys.modules, {"atheris": types.ModuleType("atheris")}):
        orch = FuzzingOrchestrator()
        return orch.plan(target, **kwargs)


class TestAtherisPlanning(unittest.TestCase):

    def test_python_pkg_without_harness_blocks(self):
        tmp = _tmpdir(self)
        plan = _plan(self, _python_pkg(tmp))
        self.assertEqual(plan.fuzzer, "atheris")
        self.assertTrue(plan.needs_harness)
        self.assertFalse(plan.can_run)
        text = " ".join(plan.blockers)
        self.assertIn("--py-harness", text)
        self.assertIn("--py-entry", text)

    def test_python_pkg_without_atheris_still_reports_target(self):
        tmp = _tmpdir(self)
        with patch("packages.fuzzing.orchestrator.probe_capabilities",
                   return_value=_caps()), \
             patch.dict(sys.modules, {"atheris": None}):
            orch = FuzzingOrchestrator()
            plan = orch.plan(_python_pkg(tmp))
        self.assertEqual(plan.target.kind, "python-pkg")
        self.assertIsNone(plan.fuzzer)
        self.assertFalse(plan.can_run)
        self.assertTrue(
            any("pip install atheris" in b for b in plan.blockers))

    def test_operator_harness_makes_plan_runnable(self):
        tmp = _tmpdir(self)
        harness = tmp / "fuzz_it.py"
        harness.write_text("# harness\n")
        plan = _plan(self, _python_pkg(tmp), py_harness=harness)
        self.assertEqual(plan.fuzzer, "atheris")
        self.assertEqual(plan.atheris_harness, harness.resolve())
        self.assertFalse(plan.needs_harness)
        self.assertTrue(plan.can_run, plan.blockers)

    def test_missing_harness_file_blocks(self):
        tmp = _tmpdir(self)
        plan = _plan(self, _python_pkg(tmp),
                     py_harness=tmp / "nope.py")
        self.assertFalse(plan.can_run)
        self.assertTrue(any("--py-harness" in b for b in plan.blockers))

    def test_entry_point_makes_plan_runnable_with_scaffold_hint(self):
        tmp = _tmpdir(self)
        plan = _plan(self, _python_pkg(tmp), py_entry="mymod:parse")
        self.assertEqual(plan.atheris_entry, "mymod:parse")
        self.assertTrue(plan.can_run, plan.blockers)
        self.assertTrue(
            any("template harness" in h for h in plan.hints))

    def test_invalid_entry_point_blocks_at_plan_time(self):
        tmp = _tmpdir(self)
        plan = _plan(self, _python_pkg(tmp),
                     py_entry="mymod:func(); import os")
        self.assertFalse(plan.can_run)
        self.assertTrue(
            any("--py-entry rejected" in b for b in plan.blockers))


class TestEngineOverride(unittest.TestCase):

    def test_engine_atheris_on_python_pkg_is_honoured(self):
        tmp = _tmpdir(self)
        harness = tmp / "fuzz_it.py"
        harness.write_text("# harness\n")
        plan = _plan(self, _python_pkg(tmp), engine="atheris",
                     py_harness=harness)
        self.assertEqual(plan.fuzzer, "atheris")
        self.assertTrue(plan.can_run, plan.blockers)

    def test_engine_atheris_on_source_tree_blocks(self):
        tmp = _tmpdir(self)
        src = tmp / "csrc"
        src.mkdir()
        (src / "main.c").write_text("int main(void){return 0;}\n")
        plan = _plan(self, src, engine="atheris")
        self.assertIsNone(plan.fuzzer)
        self.assertFalse(plan.can_run)
        self.assertTrue(
            any("--engine atheris cannot drive" in b
                for b in plan.blockers))


class TestWitnessJoin(unittest.TestCase):

    def _crash_artifact(self, tmp: Path) -> Path:
        artifact = tmp / "crash-da39a3ee5e6b"
        artifact.write_bytes(b"\x00payload")
        return artifact

    def _exception(self) -> PythonExceptionInfo:
        return PythonExceptionInfo(
            exception_type="ValueError",
            message="bad payload",
            frames=["mypkg/__init__.py:4:parse"],
            stack_key="ab" * 8,
        )

    def test_adapter_produces_fuzz_exit_signal_witness(self):
        tmp = _tmpdir(self)
        harness = tmp / "fuzz_it.py"
        harness.write_text("# harness\n")
        artifact = self._crash_artifact(tmp)
        witness, data = witness_from_atheris_artifact(
            artifact, exception=self._exception(), harness_path=harness,
        )
        self.assertEqual(data, b"\x00payload")
        self.assertEqual(witness.source.value, "fuzz")
        self.assertEqual(witness.observed_outcome.value, "exit_signal")
        self.assertEqual(witness.produced_by, "atheris")
        detail = witness.outcome_detail
        self.assertEqual(detail["crash_kind"], "python_exception")
        self.assertEqual(detail["exception_type"], "ValueError")
        self.assertEqual(detail["stack_hash"], "ab" * 8)
        self.assertIn("harness_hash", detail)

    def test_adapter_refuses_oversized_artifact(self):
        # The crashes dir is target-writable: a planted oversize
        # regular file must not reach the witness store.
        tmp = _tmpdir(self)
        artifact = tmp / "crash-huge"
        with artifact.open("wb") as fh:
            fh.truncate(4 * 1024 * 1024 + 1)
        with self.assertRaises(ValueError):
            witness_from_atheris_artifact(artifact)

    def test_recorded_witness_joins_verified_outcomes(self):
        # The full chain scope item: an atheris crash recorded through
        # the orchestrator's store step must surface as an
        # oracle-verified outcome for raptor-verified-outcomes.
        tmp = _tmpdir(self)
        out_dir = tmp / "out"
        out_dir.mkdir()
        harness = tmp / "fuzz_it.py"
        harness.write_text("# harness\n")
        result = SimpleNamespace(
            crashes=[self._crash_artifact(tmp)],
            python_exception=self._exception(),
        )
        recorded = FuzzingOrchestrator._record_atheris_witnesses(
            out_dir, harness, result,
        )
        self.assertEqual(recorded, 1)

        from core.labeled_attempts.view import collect_outcomes
        outcomes = [
            o for o in collect_outcomes(out_dir)
            if o.produced_by == "atheris"
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
            python_exception=None,
        )
        recorded = FuzzingOrchestrator._record_atheris_witnesses(
            out_dir, tmp / "fuzz_it.py", result,
        )
        self.assertEqual(recorded, 0)


class TestExecuteWiring(unittest.TestCase):

    def test_execute_generates_scaffold_and_runs_atheris(self):
        tmp = _tmpdir(self)
        pkg = _python_pkg(tmp)
        out_dir = tmp / "out"
        plan = _plan(self, pkg, py_entry="mymod:parse")
        self.assertTrue(plan.can_run, plan.blockers)

        seen = {}

        class FakeRunner:
            def __init__(self, harness, **kwargs):
                seen["harness"] = Path(harness)
                seen["kwargs"] = kwargs
                self.output_dir = kwargs["output_dir"]
                self.crashes_dir = Path(kwargs["output_dir"]) / "crashes"

            def run(self, telemetry=None):
                from packages.fuzzing.libfuzzer_runner import (
                    LibFuzzerStats,
                )
                return SimpleNamespace(
                    campaign_failed=False,
                    crashes=[], timeouts=[], oom_inputs=[],
                    leak_inputs=[],
                    python_exception=None,
                    crash_records=[],
                    stats=LibFuzzerStats(total_executions=42),
                )

        with patch("packages.fuzzing.atheris_runner.AtherisRunner",
                   FakeRunner), \
             patch("packages.fuzzing.orchestrator.probe_capabilities",
                   return_value=_caps()):
            orch = FuzzingOrchestrator()
            result = orch.execute(
                plan,
                out_dir=out_dir,
                duration_seconds=5,
                corpus_dir=None,
            )

        self.assertEqual(result["fuzzer"], "atheris")
        self.assertFalse(result["campaign_failed"])
        self.assertEqual(result["crashes"], 0)
        self.assertEqual(result["stats"]["total_executions"], 42)
        # Scaffold generated into the run dir, clearly marked.
        harness = seen["harness"]
        self.assertTrue(str(harness).startswith(str(out_dir.resolve())))
        self.assertIn("GENERATED", harness.read_text(encoding="utf-8"))
        # The package tree rides in as the import root.
        self.assertEqual(seen["kwargs"]["target_dir"], pkg)
        self.assertEqual(seen["kwargs"]["max_total_time"], 5)
        # Plan record carries the atheris fields.
        import json
        plan_record = json.loads(
            (out_dir / "fuzzing_plan.json").read_text())
        self.assertEqual(plan_record["fuzzer"], "atheris")
        self.assertEqual(plan_record["atheris_entry"], "mymod:parse")


if __name__ == "__main__":
    unittest.main()
