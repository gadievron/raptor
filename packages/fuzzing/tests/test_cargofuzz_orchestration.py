"""Orchestrator wiring for the cargo-fuzz engine: planning, target
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
from packages.fuzzing.cargofuzz_runner import RustPanicInfo
from packages.fuzzing.orchestrator import FuzzingOrchestrator
from packages.fuzzing.witness_adapter import witness_from_cargofuzz_artifact


def _tmpdir(case: unittest.TestCase) -> Path:
    d = tempfile.mkdtemp()
    case.addCleanup(shutil.rmtree, d, ignore_errors=True)
    return Path(d)


def _rust_crate(tmp: Path, targets: tuple[str, ...] = ("fuzz_one",)) -> Path:
    crate = tmp / "crate"
    (crate / "fuzz" / "fuzz_targets").mkdir(parents=True)
    (crate / "Cargo.toml").write_text("[package]\nname='c'\n")
    (crate / "fuzz" / "Cargo.toml").write_text(
        "[package]\nname='c-fuzz'\n"
        "[package.metadata]\ncargo-fuzz = true\n")
    for name in targets:
        (crate / "fuzz" / "fuzz_targets" / f"{name}.rs").write_text("// ft\n")
    return crate


def _caps() -> CapabilityReport:
    return CapabilityReport(
        platform="Linux", arch="x86_64", is_macos=False, is_linux=True,
    )


def _which_with_rust(name: str, *args, **kwargs):
    return {"cargo": "/usr/bin/cargo",
            "cargo-fuzz": "/usr/bin/cargo-fuzz"}.get(name)


def _plan(case: unittest.TestCase, target: Path, **kwargs):
    """Plan against *target* with the Rust toolchain stubbed present
    and the nightly probe faked (no subprocess in unit tests)."""
    with patch("packages.fuzzing.orchestrator.probe_capabilities",
               return_value=_caps()), \
         patch("packages.fuzzing.target_detector.shutil.which",
               side_effect=_which_with_rust), \
         patch("packages.fuzzing.cargofuzz_runner.nightly_toolchain_arg",
               return_value="+nightly"):
        orch = FuzzingOrchestrator()
        return orch.plan(target, **kwargs)


class TestCargoFuzzPlanning(unittest.TestCase):

    def test_single_target_auto_selects_and_can_run(self):
        tmp = _tmpdir(self)
        plan = _plan(self, _rust_crate(tmp))
        self.assertEqual(plan.fuzzer, "cargo-fuzz")
        self.assertEqual(plan.cargofuzz_target, "fuzz_one")
        self.assertTrue(plan.can_run, plan.blockers)
        self.assertTrue(any("auto-selected" in h for h in plan.hints))

    def test_multiple_targets_block_with_the_list(self):
        tmp = _tmpdir(self)
        plan = _plan(self, _rust_crate(tmp, ("fuzz_a", "fuzz_b")))
        self.assertIsNone(plan.cargofuzz_target)
        self.assertFalse(plan.can_run)
        text = " ".join(plan.blockers)
        self.assertIn("--fuzz-target", text)
        self.assertIn("fuzz_a", text)
        self.assertIn("fuzz_b", text)

    def test_explicit_fuzz_target_wins(self):
        tmp = _tmpdir(self)
        plan = _plan(self, _rust_crate(tmp, ("fuzz_a", "fuzz_b")),
                     fuzz_target="fuzz_b")
        self.assertEqual(plan.cargofuzz_target, "fuzz_b")
        self.assertTrue(plan.can_run, plan.blockers)

    def test_unknown_fuzz_target_blocks(self):
        tmp = _tmpdir(self)
        plan = _plan(self, _rust_crate(tmp), fuzz_target="nope")
        self.assertFalse(plan.can_run)
        self.assertTrue(any("--fuzz-target" in b for b in plan.blockers))

    def test_no_fuzz_targets_block_with_scaffold_remedy(self):
        tmp = _tmpdir(self)
        crate = tmp / "crate"
        crate.mkdir()
        (crate / "Cargo.toml").write_text("[package]\n")
        plan = _plan(self, crate)
        self.assertEqual(plan.fuzzer, "cargo-fuzz")
        self.assertTrue(plan.needs_harness)
        self.assertFalse(plan.can_run)
        self.assertTrue(any("cargo fuzz init" in b for b in plan.blockers))
        self.assertIn("cargo fuzz init", plan.summary())

    def test_missing_toolchain_still_reports_target(self):
        tmp = _tmpdir(self)
        crate = _rust_crate(tmp)
        with patch("packages.fuzzing.orchestrator.probe_capabilities",
                   return_value=_caps()), \
             patch("packages.fuzzing.target_detector.shutil.which",
                   return_value=None):
            orch = FuzzingOrchestrator()
            plan = orch.plan(crate)
        self.assertEqual(plan.target.kind, "rust-crate")
        self.assertIsNone(plan.fuzzer)
        self.assertFalse(plan.can_run)
        self.assertTrue(
            any("cargo install cargo-fuzz" in b for b in plan.blockers))

    def test_no_nightly_surfaces_sanitizer_hint(self):
        tmp = _tmpdir(self)
        crate = _rust_crate(tmp)
        with patch("packages.fuzzing.orchestrator.probe_capabilities",
                   return_value=_caps()), \
             patch("packages.fuzzing.target_detector.shutil.which",
                   side_effect=_which_with_rust), \
             patch("packages.fuzzing.cargofuzz_runner.nightly_toolchain_arg",
                   return_value=None):
            orch = FuzzingOrchestrator()
            plan = orch.plan(crate)
        self.assertTrue(plan.can_run, plan.blockers)
        self.assertTrue(
            any("rustup toolchain install nightly" in h
                for h in plan.hints))


class TestEngineOverride(unittest.TestCase):

    def test_engine_cargofuzz_on_rust_crate_is_honoured(self):
        tmp = _tmpdir(self)
        plan = _plan(self, _rust_crate(tmp), engine="cargo-fuzz")
        self.assertEqual(plan.fuzzer, "cargo-fuzz")
        self.assertTrue(plan.can_run, plan.blockers)

    def test_engine_cargofuzz_on_source_tree_blocks(self):
        tmp = _tmpdir(self)
        src = tmp / "csrc"
        src.mkdir()
        (src / "main.c").write_text("int main(void){return 0;}\n")
        plan = _plan(self, src, engine="cargo-fuzz")
        self.assertIsNone(plan.fuzzer)
        self.assertFalse(plan.can_run)
        self.assertTrue(
            any("--engine cargo-fuzz cannot drive" in b
                for b in plan.blockers))

    def test_engine_atheris_on_rust_crate_blocks(self):
        tmp = _tmpdir(self)
        plan = _plan(self, _rust_crate(tmp), engine="atheris")
        self.assertIsNone(plan.fuzzer)
        self.assertTrue(
            any("--engine atheris cannot drive" in b
                for b in plan.blockers))

    def test_fuzz_target_on_other_kind_is_named_not_silently_dropped(self):
        tmp = _tmpdir(self)
        src = tmp / "csrc"
        src.mkdir()
        (src / "main.c").write_text("int main(void){return 0;}\n")
        plan = _plan(self, src, fuzz_target="fuzz_one")
        self.assertTrue(
            any("--fuzz-target applies to rust-crate targets" in h
                for h in plan.hints), plan.hints)


class TestWitnessJoin(unittest.TestCase):

    def _crash_artifact(self, tmp: Path) -> Path:
        artifact = tmp / "crash-da39a3ee5e6b"
        artifact.write_bytes(b"\x00payload")
        return artifact

    def _panic(self) -> RustPanicInfo:
        return RustPanicInfo(
            message="boom: 7",
            location="fuzz_targets/fuzz_boom.rs:6:9",
            thread="<unnamed>",
            frames=["boomcrate::boom"],
            stack_key="cd" * 8,
        )

    def test_adapter_produces_fuzz_exit_signal_witness(self):
        tmp = _tmpdir(self)
        binary = tmp / "fuzz_boom"
        binary.write_bytes(b"\x7fELF fake")
        artifact = self._crash_artifact(tmp)
        witness, data = witness_from_cargofuzz_artifact(
            artifact, panic=self._panic(), binary_path=binary,
        )
        self.assertEqual(data, b"\x00payload")
        self.assertEqual(witness.source.value, "fuzz")
        self.assertEqual(witness.observed_outcome.value, "exit_signal")
        self.assertEqual(witness.produced_by, "cargo-fuzz")
        self.assertIsNotNone(witness.target_binary_hash)
        detail = witness.outcome_detail
        self.assertEqual(detail["crash_kind"], "rust_panic")
        self.assertEqual(detail["panic_message"], "boom: 7")
        self.assertEqual(detail["stack_hash"], "cd" * 8)

    def test_native_crash_without_panic_detail(self):
        tmp = _tmpdir(self)
        artifact = self._crash_artifact(tmp)
        witness, _ = witness_from_cargofuzz_artifact(artifact)
        self.assertEqual(witness.outcome_detail["crash_kind"], "native")

    def test_adapter_refuses_oversized_artifact(self):
        # The crashes dir is target-writable: a planted oversize
        # regular file must not reach the witness store.
        tmp = _tmpdir(self)
        artifact = tmp / "crash-huge"
        with artifact.open("wb") as fh:
            fh.truncate(4 * 1024 * 1024 + 1)
        with self.assertRaises(ValueError):
            witness_from_cargofuzz_artifact(artifact)

    def test_recorded_witness_joins_verified_outcomes(self):
        # The full chain: a cargo-fuzz crash recorded through the
        # orchestrator's store step must surface as an oracle-verified
        # outcome for raptor-verified-outcomes.
        tmp = _tmpdir(self)
        out_dir = tmp / "out"
        out_dir.mkdir()
        result = SimpleNamespace(
            crashes=[self._crash_artifact(tmp)],
            rust_panic=self._panic(),
            built_binary="",
        )
        recorded = FuzzingOrchestrator._record_cargofuzz_witnesses(
            out_dir, result,
        )
        self.assertEqual(recorded, 1)

        from core.labeled_attempts.view import collect_outcomes
        outcomes = [
            o for o in collect_outcomes(out_dir)
            if o.produced_by == "cargo-fuzz"
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
            rust_panic=None,
            built_binary="",
        )
        recorded = FuzzingOrchestrator._record_cargofuzz_witnesses(
            out_dir, result,
        )
        self.assertEqual(recorded, 0)


class _FakeRunner:
    """Stands in for CargoFuzzRunner at the orchestrator seam."""

    seen: dict = {}

    def __init__(self, crate_dir, fuzz_target, **kwargs):
        type(self).seen = {
            "crate_dir": Path(crate_dir),
            "fuzz_target": fuzz_target,
            "kwargs": kwargs,
        }
        self.output_dir = Path(kwargs["output_dir"])
        self.crashes_dir = self.output_dir / "crashes"
        self.sanitizer = "address"

    def run(self, telemetry=None):
        from packages.fuzzing.libfuzzer_runner import LibFuzzerStats
        return SimpleNamespace(
            campaign_failed=False,
            crashes=[], timeouts=[], oom_inputs=[], leak_inputs=[],
            rust_panic=None,
            crash_records=[],
            built_binary=str(self.output_dir / "cargo-target"
                             / "release" / "fuzz_one"),
            stats=LibFuzzerStats(total_executions=42),
        )


class TestExecuteWiring(unittest.TestCase):

    def _execute(self, plan, out_dir: Path, corpus_dir: Path | None):
        with patch("packages.fuzzing.cargofuzz_runner.CargoFuzzRunner",
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

    def test_execute_runs_cargofuzz_with_plan_target(self):
        tmp = _tmpdir(self)
        crate = _rust_crate(tmp)
        out_dir = tmp / "out"
        seeds = tmp / "seeds"
        seeds.mkdir()
        (seeds / "seed").write_bytes(b"hi")
        plan = _plan(self, crate)
        self.assertTrue(plan.can_run, plan.blockers)

        result = self._execute(plan, out_dir, seeds)

        self.assertEqual(result["fuzzer"], "cargo-fuzz")
        self.assertFalse(result["campaign_failed"])
        self.assertEqual(result["crashes"], 0)
        self.assertEqual(result["fuzz_target"], "fuzz_one")
        self.assertEqual(result["stats"]["total_executions"], 42)
        seen = _FakeRunner.seen
        self.assertEqual(seen["crate_dir"], crate)
        self.assertEqual(seen["fuzz_target"], "fuzz_one")
        self.assertEqual(seen["kwargs"]["max_total_time"], 5)
        self.assertEqual(seen["kwargs"]["corpus_dir"], seeds)
        # Plan record carries the cargo-fuzz field.
        plan_record = json.loads(
            (out_dir / "fuzzing_plan.json").read_text())
        self.assertEqual(plan_record["fuzzer"], "cargo-fuzz")
        self.assertEqual(plan_record["cargofuzz_target"], "fuzz_one")

    def test_crate_corpus_convention_wins_without_operator_corpus(self):
        tmp = _tmpdir(self)
        crate = _rust_crate(tmp)
        crate_corpus = crate / "fuzz" / "corpus" / "fuzz_one"
        crate_corpus.mkdir(parents=True)
        (crate_corpus / "seed").write_bytes(b"hi")
        out_dir = tmp / "out"
        plan = _plan(self, crate)

        result = self._execute(plan, out_dir, None)

        self.assertEqual(_FakeRunner.seen["kwargs"]["corpus_dir"],
                         crate_corpus)
        self.assertEqual(result["crate_corpus"]["path"],
                         str(crate_corpus))
        self.assertTrue((out_dir / "crate-corpus.json").is_file())


if __name__ == "__main__":
    unittest.main()
