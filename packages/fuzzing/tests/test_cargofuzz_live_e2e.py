"""Live cargo-fuzz end-to-end: build → run → crash-collect → triage.

Gated on the real toolchain (cargo + cargo-fuzz on PATH) — CI runners
ship neither, so the default tier skips with a notice. On a host with
the toolchain, the test scaffolds a tiny crate whose fuzz target
panics on any non-empty input (libFuzzer hits it on the first seed),
fetches the fuzz dependencies once in a trusted context (the runner's
own build stays network-isolated), and walks the orchestrator's full
path: plan → sandboxed build → campaign → crash records → Witness
recording → verified-outcomes join.

Environment shortfalls skip with the exact constraint named (no
network for the dependency fetch, no nightly on a cargo-fuzz build
that requires one, sandbox unable to engage); anything else fails.
"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import pytest

_CRATE_MANIFEST = """\
[package]
name = "raptor_e2e_boom"
version = "0.0.0"
edition = "2021"
"""

_CRATE_LIB = """\
pub fn boom(data: &[u8]) {
    if !data.is_empty() {
        panic!("raptor-e2e-boom: {}", data.len());
    }
}
"""

_FUZZ_MANIFEST = """\
[package]
name = "raptor_e2e_boom-fuzz"
version = "0.0.0"
edition = "2021"

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"

[dependencies.raptor_e2e_boom]
path = ".."

[[bin]]
name = "fuzz_boom"
path = "fuzz_targets/fuzz_boom.rs"
test = false
doc = false
"""

_FUZZ_TARGET = """\
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    raptor_e2e_boom::boom(data);
});
"""


def _write_crate(tmp: Path) -> Path:
    crate = tmp / "crate"
    (crate / "src").mkdir(parents=True)
    (crate / "fuzz" / "fuzz_targets").mkdir(parents=True)
    (crate / "Cargo.toml").write_text(_CRATE_MANIFEST)
    (crate / "src" / "lib.rs").write_text(_CRATE_LIB)
    (crate / "fuzz" / "Cargo.toml").write_text(_FUZZ_MANIFEST)
    (crate / "fuzz" / "fuzz_targets" / "fuzz_boom.rs").write_text(
        _FUZZ_TARGET)
    return crate


@pytest.mark.slow
@pytest.mark.linux_native
class TestCargoFuzzLiveE2E(unittest.TestCase):
    """Thin end-to-end run on machines that actually have cargo-fuzz."""

    @unittest.skipUnless(
        shutil.which("cargo") and shutil.which("cargo-fuzz"),
        "cargo / cargo-fuzz not installed",
    )
    def test_always_panicking_target_crashes_and_records_witness(self):
        from core.sandbox import SandboxSetupError
        from packages.fuzzing.orchestrator import FuzzingOrchestrator

        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        crate = _write_crate(tmp)

        # Trusted-context dependency fetch: the runner's own build is
        # network-isolated by contract, so libfuzzer-sys must already
        # be in the local cargo cache.
        try:
            fetched = subprocess.run(
                [shutil.which("cargo"), "fetch"],
                cwd=crate / "fuzz",
                capture_output=True, text=True, timeout=600,
            )
        except (OSError, subprocess.SubprocessError) as e:
            self.skipTest(f"cargo fetch could not run: {e}")
        if fetched.returncode != 0:
            self.skipTest(
                "cargo fetch failed (no network / registry access on "
                f"this host?): {fetched.stderr[-500:]}")

        seeds = tmp / "seeds"
        seeds.mkdir()
        (seeds / "seed").write_bytes(b"X")

        orch = FuzzingOrchestrator()
        plan = orch.plan(crate)
        self.assertTrue(plan.can_run, plan.blockers)
        self.assertEqual(plan.fuzzer, "cargo-fuzz")
        self.assertEqual(plan.cargofuzz_target, "fuzz_boom")

        out_dir = tmp / "out"
        try:
            result = orch.execute(
                plan,
                out_dir=out_dir,
                duration_seconds=60,
                corpus_dir=seeds,
                binary_understand=False,
            )
        except SandboxSetupError as e:
            self.skipTest(f"sandbox cannot engage on this host: {e}")
        except RuntimeError as e:
            message = str(e)
            # Environment shortfalls named by the build's own hints —
            # skip with the constraint; real bugs still fail.
            if "cargo fetch" in message or "nightly" in message.lower():
                self.skipTest(
                    f"cargo-fuzz build blocked by environment: "
                    f"{message[:500]}")
            raise

        self.assertFalse(result["campaign_failed"])
        self.assertGreaterEqual(result["crashes"], 1)
        self.assertIsNotNone(result["rust_panic"])
        self.assertIn("raptor-e2e-boom",
                      result["rust_panic"]["panic_message"])
        self.assertTrue(Path(result["crash_records"]).is_file())
        self.assertGreaterEqual(result["witnesses_recorded"], 1)

        # Triage parity: the crashes surface as oracle-verified
        # outcomes exactly like AFL++ and atheris crashes do.
        from core.labeled_attempts.view import collect_outcomes
        outcomes = [
            o for o in collect_outcomes(out_dir)
            if o.produced_by == "cargo-fuzz"
        ]
        self.assertGreaterEqual(len(outcomes), 1)
        self.assertEqual(outcomes[0].oracle.value, "fuzzer")
        self.assertEqual(outcomes[0].status.value, "verified")


if __name__ == "__main__":
    unittest.main()
