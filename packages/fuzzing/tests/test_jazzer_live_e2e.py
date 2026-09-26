"""Live jazzer end-to-end: build → run → crash-collect → triage.

Gated on the real toolchain (jazzer + java + javac on PATH) — CI
runners ship no jazzer, so the default tier skips with a notice. On a
host with the toolchain, the test scaffolds a tiny bare-layout Java
project whose fuzzerTestOneInput throws on any non-empty input
(libFuzzer hits it on the first seed) and walks the orchestrator's
full path: plan → sandboxed javac build → campaign → crash records →
Witness recording → verified-outcomes join. The bare lane needs no
dependency fetch at all — no Maven/Gradle, no network, no cache.

Environment shortfalls skip with the exact constraint named (sandbox
unable to engage, a JVM the jazzer launcher cannot load); anything
else fails.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

import pytest

_HARNESS = """\
public class RaptorE2EFuzz {
    public static void fuzzerTestOneInput(byte[] data) {
        if (data.length > 0) {
            throw new IllegalStateException(
                "raptor-e2e-boom: " + data.length);
        }
    }
}
"""


def _write_project(tmp: Path) -> Path:
    project = tmp / "proj"
    project.mkdir()
    (project / "RaptorE2EFuzz.java").write_text(_HARNESS)
    return project


@pytest.mark.slow
@pytest.mark.linux_native
class TestJazzerLiveE2E(unittest.TestCase):
    """Thin end-to-end run on machines that actually have jazzer."""

    @unittest.skipUnless(
        shutil.which("jazzer") and shutil.which("java")
        and shutil.which("javac"),
        "jazzer / java / javac not installed",
    )
    def test_always_throwing_target_crashes_and_records_witness(self):
        from core.sandbox import SandboxSetupError
        from packages.fuzzing.orchestrator import FuzzingOrchestrator

        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        project = _write_project(tmp)

        seeds = tmp / "seeds"
        seeds.mkdir()
        (seeds / "seed").write_bytes(b"X")

        orch = FuzzingOrchestrator()
        plan = orch.plan(project)
        self.assertTrue(plan.can_run, plan.blockers)
        self.assertEqual(plan.fuzzer, "jazzer")
        self.assertEqual(plan.jazzer_target, "RaptorE2EFuzz")

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
            if "JVM" in message or "JAVA_HOME" in message:
                self.skipTest(
                    f"jazzer build blocked by environment: "
                    f"{message[:500]}")
            raise

        self.assertFalse(result["campaign_failed"])
        self.assertGreaterEqual(result["crashes"], 1)
        self.assertEqual(result["build_tool"], "bare")
        self.assertIsNotNone(result["java_exception"])
        self.assertEqual(result["java_exception"]["exception_type"],
                         "java.lang.IllegalStateException")
        self.assertIn("raptor-e2e-boom",
                      result["java_exception"]["message"])
        self.assertTrue(Path(result["crash_records"]).is_file())
        self.assertGreaterEqual(result["witnesses_recorded"], 1)

        # Triage parity: the crashes surface as oracle-verified
        # outcomes exactly like AFL++, atheris, and cargo-fuzz
        # crashes do.
        from core.labeled_attempts.view import collect_outcomes
        outcomes = [
            o for o in collect_outcomes(out_dir)
            if o.produced_by == "jazzer"
        ]
        self.assertGreaterEqual(len(outcomes), 1)
        self.assertEqual(outcomes[0].oracle.value, "fuzzer")
        self.assertEqual(outcomes[0].status.value, "verified")


if __name__ == "__main__":
    unittest.main()
