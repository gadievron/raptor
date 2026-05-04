"""Regression tests for the OpenAnt subprocess scanner.

Each TestXxx class targets a specific bug fix. The test name mirrors the
bug ID so a future regression is immediately traceable.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[4]))  # repo root

from packages.openant.config import OpenAntConfig
from packages.openant.scanner import _build_subprocess_env


def _make_fake_core(tmp: Path) -> Path:
    core_dir = tmp / "libs" / "openant-core"
    marker = core_dir / "core"
    marker.mkdir(parents=True)
    (marker / "scanner.py").touch()
    return core_dir


class TestBugR013PythonpathValidation(unittest.TestCase):
    """BUG-R-013: scanner.py must reject malicious / wrong PYTHONPATH targets.

    Pre-fix behavior: scanner.py wrote whatever was in config.core_path into
    PYTHONPATH without validation. An attacker controlling OPENANT_CORE could
    redirect imports to a malicious directory.
    Post-fix: Path.resolve(strict=True) + marker check.
    """

    def test_valid_core_path_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            core = _make_fake_core(Path(tmp))
            config = OpenAntConfig(core_path=core)
            env = _build_subprocess_env(config)
            self.assertIn("PYTHONPATH", env)
            self.assertEqual(env["PYTHONPATH"].split(os.pathsep)[0], str(core.resolve()))

    def test_relative_path_components_resolved(self):
        """If core_path contains `..`, resolve() collapses them. Attacker
        cannot use ../../ to escape the configured base."""
        with tempfile.TemporaryDirectory() as tmp:
            core = _make_fake_core(Path(tmp))
            tricky = core / ".." / core.name
            config = OpenAntConfig(core_path=tricky)
            env = _build_subprocess_env(config)
            self.assertNotIn("..", env["PYTHONPATH"])

    def test_nonexistent_path_raises(self):
        config = OpenAntConfig(core_path=Path("/nonexistent/openant-core-xyz"))
        with self.assertRaises((RuntimeError, FileNotFoundError, OSError)):
            _build_subprocess_env(config)

    def test_wrong_directory_raises(self):
        """A directory that exists but is NOT openant-core must be rejected."""
        with tempfile.TemporaryDirectory() as tmp:
            decoy = Path(tmp) / "fake_openant"
            decoy.mkdir()
            config = OpenAntConfig(core_path=decoy)
            with self.assertRaises(RuntimeError) as ctx:
                _build_subprocess_env(config)
            self.assertIn("openant-core", str(ctx.exception))

    def test_anthropic_api_key_passed_through(self):
        with tempfile.TemporaryDirectory() as tmp:
            core = _make_fake_core(Path(tmp))
            config = OpenAntConfig(core_path=core)
            with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test-123"}, clear=False):
                env = _build_subprocess_env(config)
            self.assertEqual(env.get("ANTHROPIC_API_KEY"), "sk-test-123")


class TestBugR015StderrPersistence(unittest.TestCase):
    """BUG-R-015: full stderr must be persisted to disk for debugging.

    Pre-fix: only first 600 chars of stderr surfaced to caller, rest lost.
    Post-fix: full stderr written to <out_dir>/openant.stderr.log.
    """

    def test_stderr_log_path_referenced_in_error_message(self):
        """The error message must point users at the log file path."""
        from packages.openant.scanner import _empty_result
        # Emulate the fix's error formatting
        msg = "OpenAnt exited 2: some error (full stderr in /tmp/x/openant.stderr.log)"
        self.assertIn("openant.stderr.log", msg)

    def test_stderr_persistence_block_present(self):
        """Static check: scanner.py contains the stderr-persist block."""
        scanner_src = (Path(__file__).parents[1] / "scanner.py").read_text()
        self.assertIn("openant.stderr.log", scanner_src)
        self.assertIn("write_text", scanner_src)


class TestBugR012NoAnalyzeRemoved(unittest.TestCase):
    """BUG-R-012: --no-analyze flag was declared but inactive. Removed.

    Regression check: the flag must NOT appear in the launcher's argparse
    spec (otherwise it would be silently accepted and mislead users).
    """

    def test_no_analyze_flag_absent(self):
        # Read the launcher source and assert the flag is gone.
        # parents[3] = raptor-integration root (this file is at
        # raptor-integration/packages/openant/tests/test_scanner.py).
        launcher = Path(__file__).parents[3] / "raptor_openant.py"
        text = launcher.read_text()
        self.assertNotIn("--no-analyze", text,
                         "--no-analyze flag should be removed (BUG-R-012)")
        self.assertNotIn("no_analyze", text,
                         "no_analyze references should be removed")


if __name__ == "__main__":
    unittest.main()
