"""Tests for the libFuzzer runner process contract."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from packages.fuzzing.libfuzzer_runner import LibFuzzerRunner


class TestLibFuzzerRunner(unittest.TestCase):

    def test_run_uses_sandbox_and_sanitised_env(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            harness = tmp / "fuzz_target"
            harness.write_text("#!/bin/sh\nexit 0\n")
            harness.chmod(0o755)
            out_dir = tmp / "out"

            captured = {}

            def fake_sandbox_run(cmd, **kwargs):
                captured["cmd"] = cmd
                captured["kwargs"] = kwargs

                class Result:
                    returncode = 0
                    stdout = ""
                    stderr = "#1 DONE cov: 1 ft: 1 corp: 1/1b exec/s: 1\n"

                return Result()

            with patch.dict(os.environ, {"LD_PRELOAD": "evil.dylib"}, clear=False), \
                 patch("packages.fuzzing.libfuzzer_runner._sandbox_run",
                       side_effect=fake_sandbox_run):
                runner = LibFuzzerRunner(
                    harness_path=harness,
                    output_dir=out_dir,
                    max_total_time=1,
                )
                result = runner.run()

            self.assertEqual(result.stats.total_executions, 1)
            self.assertEqual(captured["cmd"][0], str(harness.resolve()))
            self.assertTrue(captured["kwargs"]["block_network"])
            self.assertTrue(captured["kwargs"]["restrict_reads"])
            self.assertNotIn("LD_PRELOAD", captured["kwargs"]["env"])
            self.assertEqual(captured["kwargs"]["output"], str(out_dir.resolve()))

    def test_corpus_is_copied_into_output_workspace(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            harness = tmp / "fuzz_target"
            harness.write_text("#!/bin/sh\nexit 0\n")
            harness.chmod(0o755)
            seed_dir = tmp / "seeds"
            seed_dir.mkdir()
            (seed_dir / "seed0").write_bytes(b"seed")

            runner = LibFuzzerRunner(
                harness_path=harness,
                corpus_dir=seed_dir,
                output_dir=tmp / "out",
                max_total_time=1,
            )

            self.assertEqual((runner.corpus_dir / "seed0").read_bytes(), b"seed")
            self.assertTrue(str(runner.corpus_dir).startswith(str((tmp / "out").resolve())))


if __name__ == "__main__":
    unittest.main()
