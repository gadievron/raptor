"""Tests for the atheris runner's process contract.

Hermetic: the sandbox call is faked at the same seam the libFuzzer
runner tests use, emitting realistic atheris output/exit shapes. A
thin integration test at the bottom is skip-guarded on a real atheris
install (CI has none).
"""

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

from packages.fuzzing.atheris_runner import (
    ATHERIS_INSTALL_HINT,
    AtherisResult,
    AtherisRunner,
    parse_python_exception,
)

# Realistic atheris stderr: libFuzzer banner + stats grammar, then the
# uncaught-Python-exception block, then the crash artifact line.
_ATHERIS_CRASH_STDERR = """\
INFO: Instrumenting mypkg
INFO: Seed: 12345
#2\tINITED cov: 5 ft: 5 corp: 1/1b exec/s: 0 rss: 40Mb
#100\tNEW    cov: 12 ft: 24 corp: 5/16b lim: 4 exec/s: 100 rss: 41Mb

 === Uncaught Python exception: ===
ValueError: bad payload
Traceback (most recent call last):
  File "/tmp/h/fuzz_mypkg_parse.py", line 18, in TestOneInput
    mypkg.parse(payload)
  File "/tmp/pkg/mypkg/__init__.py", line 4, in parse
    raise ValueError("bad payload")
ValueError: bad payload

==12345== ERROR: libFuzzer: fuzz target exited
SUMMARY: libFuzzer: fuzz target exited
Test unit written to ./crash-da39a3ee5e6b
"""


def _tmpdir(case: unittest.TestCase) -> Path:
    d = tempfile.mkdtemp()
    case.addCleanup(shutil.rmtree, d, ignore_errors=True)
    return Path(d)


def _make_target(tmp: Path) -> tuple[Path, Path]:
    """A harness .py and a python-pkg-shaped target dir."""
    target = tmp / "pkg"
    (target / "src").mkdir(parents=True)
    (target / "pyproject.toml").write_text("[project]\nname='p'\n")
    harness = tmp / "fuzz_it.py"
    harness.write_text("# harness\n")
    return harness, target


class TestAtherisRunnerContract(unittest.TestCase):

    def _runner(self, tmp: Path, **kwargs) -> AtherisRunner:
        harness, target = _make_target(tmp)
        with patch("packages.fuzzing.atheris_runner.atheris_available",
                   return_value=True):
            return AtherisRunner(
                harness,
                target_dir=target,
                output_dir=tmp / "out",
                max_total_time=1,
                **kwargs,
            )

    def test_run_uses_sandbox_python_and_scrubbed_env(self):
        tmp = _tmpdir(self)
        captured = {}

        def fake_sandbox_run(cmd, **kwargs):
            captured["cmd"] = cmd
            captured["kwargs"] = kwargs
            kwargs["stderr"].write(_ATHERIS_CRASH_STDERR.encode())

            class Result:
                returncode = 77

            return Result()

        with patch.dict(os.environ, {"LD_PRELOAD": "evil.so"},
                        clear=False), \
             patch("packages.fuzzing.libfuzzer_runner._sandbox_run",
                   side_effect=fake_sandbox_run):
            runner = self._runner(tmp)
            # An artifact the fake campaign "wrote".
            (runner.crashes_dir / "crash-da39a3ee5e6b").write_bytes(b"\x00A")
            result = runner.run()

        # Interpreter-prefixed command: <python> <harness.py> <corpus> ...
        self.assertEqual(captured["cmd"][0], runner.python_executable)
        self.assertEqual(captured["cmd"][1], str(runner.harness))
        self.assertEqual(captured["cmd"][2], str(runner.corpus_dir))
        self.assertIn("-max_total_time=1", captured["cmd"])

        kwargs = captured["kwargs"]
        self.assertTrue(kwargs["block_network"])
        self.assertTrue(kwargs["restrict_reads"])
        self.assertIn(str(runner.target_dir), kwargs["readable_paths"])

        env = kwargs["env"]
        self.assertNotIn("LD_PRELOAD", env)
        for ident in ("USER", "LOGNAME", "HOSTNAME", "PWD"):
            self.assertNotIn(ident, env)
        self.assertEqual(env.get("HOME"), "/tmp")
        self.assertEqual(env.get("PYTHONDONTWRITEBYTECODE"), "1")
        # PYTHONPATH roots at the target tree (+ src layout child).
        py_path = env["PYTHONPATH"].split(":")
        self.assertIn(str(runner.target_dir), py_path)
        self.assertIn(str(runner.target_dir / "src"), py_path)

        # Stats parsed from the libFuzzer grammar atheris emits.
        self.assertEqual(result.stats.total_executions, 100)
        self.assertEqual(result.stats.coverage_features, 24)

        # Crash artifact collected; exception is the triage signal.
        self.assertIsInstance(result, AtherisResult)
        self.assertEqual(len(result.crashes), 1)
        self.assertIsNotNone(result.python_exception)
        self.assertEqual(result.python_exception.exception_type,
                         "ValueError")
        self.assertEqual(result.python_exception.message, "bad payload")
        self.assertEqual(len(result.python_exception.frames), 2)
        self.assertEqual(len(result.python_exception.stack_key), 16)

        # Normalized crash records persisted beside the campaign.
        records_path = runner.output_dir / "atheris-crashes.json"
        self.assertTrue(records_path.is_file())
        records = json.loads(records_path.read_text())
        self.assertEqual(records[0]["engine"], "atheris")
        self.assertEqual(records[0]["exception_type"], "ValueError")
        self.assertEqual(records[0]["stack_hash"],
                         result.python_exception.stack_key)

        # A dirty exit WITH a finding is a normal crash-terminated
        # campaign, not a failed one.
        self.assertFalse(result.campaign_failed)

    def test_startup_death_is_campaign_failed(self):
        tmp = _tmpdir(self)

        def fake_sandbox_run(cmd, **kwargs):
            kwargs["stderr"].write(
                b"ModuleNotFoundError: No module named 'atheris'\n")

            class Result:
                returncode = 1

            return Result()

        with patch("packages.fuzzing.libfuzzer_runner._sandbox_run",
                   side_effect=fake_sandbox_run):
            runner = self._runner(tmp)
            result = runner.run()

        self.assertTrue(result.campaign_failed)
        self.assertEqual(len(result.crashes), 0)
        self.assertIsNone(result.python_exception)

    def test_missing_atheris_refuses_with_install_hint(self):
        tmp = _tmpdir(self)
        harness, target = _make_target(tmp)
        with patch("packages.fuzzing.atheris_runner.atheris_available",
                   return_value=False):
            with self.assertRaises(RuntimeError) as ctx:
                AtherisRunner(harness, target_dir=target,
                              output_dir=tmp / "out")
        self.assertEqual(str(ctx.exception), ATHERIS_INSTALL_HINT)
        self.assertIn("pip install atheris", str(ctx.exception))

    def test_harness_must_be_a_py_file(self):
        tmp = _tmpdir(self)
        _, target = _make_target(tmp)
        not_py = tmp / "harness.sh"
        not_py.write_text("#!/bin/sh\n")
        with patch("packages.fuzzing.atheris_runner.atheris_available",
                   return_value=True):
            with self.assertRaises(ValueError):
                AtherisRunner(not_py, target_dir=target,
                              output_dir=tmp / "out")
            with self.assertRaises(FileNotFoundError):
                AtherisRunner(tmp / "missing.py", target_dir=target,
                              output_dir=tmp / "out")

    def test_harness_needs_no_executable_bit(self):
        tmp = _tmpdir(self)
        harness, target = _make_target(tmp)
        harness.chmod(0o644)
        with patch("packages.fuzzing.atheris_runner.atheris_available",
                   return_value=True):
            runner = AtherisRunner(harness, target_dir=target,
                                   output_dir=tmp / "out")
        self.assertEqual(runner.harness, harness.resolve())


class TestPythonExceptionParsing(unittest.TestCase):

    def test_no_header_returns_none(self):
        self.assertIsNone(parse_python_exception("#1 NEW cov: 1\n"))

    def test_last_block_wins(self):
        stderr = (
            " === Uncaught Python exception: ===\n"
            "KeyError: 'a'\n"
            'Traceback (most recent call last):\n'
            '  File "x.py", line 1, in f\n'
            "\n"
            " === Uncaught Python exception: ===\n"
            "TypeError: nope\n"
            'Traceback (most recent call last):\n'
            '  File "y.py", line 2, in g\n'
        )
        exc = parse_python_exception(stderr)
        self.assertEqual(exc.exception_type, "TypeError")
        self.assertEqual(exc.frames, ["y.py:2:g"])

    def test_terminal_controls_stripped_from_message(self):
        stderr = (
            " === Uncaught Python exception: ===\n"
            "ValueError: \x1b]0;owned\x07bad\n"
        )
        exc = parse_python_exception(stderr)
        self.assertEqual(exc.exception_type, "ValueError")
        self.assertNotIn("\x1b", exc.message)
        self.assertNotIn("\x07", exc.message)

    def test_garbage_after_header_is_not_misattributed(self):
        stderr = (
            " === Uncaught Python exception: ===\n"
            "!!! not an exception line !!!\n"
        )
        self.assertIsNone(parse_python_exception(stderr))

    def test_frame_count_is_bounded(self):
        frames = "".join(
            f'  File "f{i}.py", line {i}, in fn\n' for i in range(500)
        )
        stderr = (
            " === Uncaught Python exception: ===\n"
            "RecursionError: max depth\n"
            "Traceback (most recent call last):\n" + frames
        )
        exc = parse_python_exception(stderr)
        self.assertLessEqual(len(exc.frames), 40)


@pytest.mark.slow
@pytest.mark.linux_native
class TestAtherisIntegration(unittest.TestCase):
    """Thin end-to-end run on machines that actually have atheris.

    CI has no atheris — the default tier never reaches this. On a
    machine with atheris the campaign spawns a real sandboxed
    interpreter, so the test also skips when the sandbox cannot
    engage.
    """

    @unittest.skipUnless(
        importlib.util.find_spec("atheris") is not None,
        "atheris not installed",
    )
    def test_always_raising_target_crashes_quickly(self):
        from core.sandbox import SandboxSetupError
        from packages.fuzzing.atheris_harness import (
            AtherisHarnessSpec,
            write_atheris_harness,
        )

        tmp = _tmpdir(self)
        target = tmp / "pkg"
        target.mkdir()
        (target / "pyproject.toml").write_text("[project]\nname='boom'\n")
        (target / "boommod.py").write_text(
            "def boom(data):\n"
            "    raise ValueError('always')\n"
        )
        harness = write_atheris_harness(
            AtherisHarnessSpec(entry="boommod:boom"),
            tmp / "harness",
        )
        runner = AtherisRunner(
            harness,
            target_dir=target,
            output_dir=tmp / "out",
            python_executable=sys.executable,
            max_total_time=20,
        )
        try:
            result = runner.run()
        except SandboxSetupError as e:
            self.skipTest(f"sandbox cannot engage on this host: {e}")
        self.assertGreaterEqual(len(result.crashes), 1)
        self.assertIsNotNone(result.python_exception)
        self.assertEqual(result.python_exception.exception_type,
                         "ValueError")


if __name__ == "__main__":
    unittest.main()
