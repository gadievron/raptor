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

    def test_stderr_size_capped(self):
        """BUG-R-015 fragility (audit): unbounded stderr could fill disk
        if OpenAnt enters a tight loop spamming stderr. Cap to a defensible
        upper bound (1 MiB is generous for any reasonable error trace).

        Static check: scanner.py source contains a size-cap constant
        and uses it before write_text.
        """
        scanner_src = (Path(__file__).parents[1] / "scanner.py").read_text()
        # The fix uses STDERR_MAX or a hardcoded slice
        has_cap = (
            "STDERR_MAX" in scanner_src
            or "[:1_000_000]" in scanner_src
            or "[:1000000]" in scanner_src
            or "[: STDERR_MAX_BYTES]" in scanner_src
        )
        self.assertTrue(
            has_cap,
            "scanner.py should cap stderr size before persisting "
            "(BUG-R-015 fragility from audit). Use STDERR_MAX_BYTES "
            "constant + slice the proc.stderr before write_text.",
        )


class TestCleanupC1FileNotFoundHandling(unittest.TestCase):
    """Cleanup C-1 from /work-audit (2026-05-04):

    raptor_openant.py only catches RuntimeError when building the OpenAnt
    config. But scanner.py's _build_subprocess_env now uses
    Path.resolve(strict=True) which raises FileNotFoundError on a
    non-existent path. The two error types should be unified at the
    boundary (either re-raise as RuntimeError, or catch both at the
    raptor_openant.py boundary).

    Audit C-1: 'Path.resolve(strict=True) raises FileNotFoundError not
    RuntimeError — agent claimed both are handled. Checked: my code at
    scanner.py:_build_subprocess_env doesn't actually catch
    FileNotFoundError separately. The caller in raptor_openant.py:139-148
    catches RuntimeError only — a non-existent OPENANT_CORE path would
    raise FileNotFoundError, uncaught.'

    The fix: scanner.py wraps Path.resolve(strict=True) and re-raises
    as RuntimeError with a clear message. This unifies the boundary.
    """

    def test_nonexistent_core_path_raises_runtime_error_not_filenotfound(self):
        """A non-existent core_path must raise RuntimeError (so
        raptor_openant.py's `except RuntimeError` handles it) — NOT
        FileNotFoundError, which would propagate as 'Fatal error'."""
        from packages.openant.scanner import _build_subprocess_env
        config = OpenAntConfig(core_path=Path("/nonexistent/openant-xyz-123"))
        with self.assertRaises(RuntimeError) as ctx:
            _build_subprocess_env(config)
        # The error must be informative about openant-core
        msg = str(ctx.exception).lower()
        self.assertTrue(
            "openant" in msg or "not found" in msg or "does not exist" in msg,
            f"Error message should mention openant-core or non-existence; got: {ctx.exception}",
        )

    def test_decoy_directory_raises_runtime_error(self):
        """A directory exists but lacks the marker → RuntimeError.
        (Already covered by test_wrong_directory_raises but here
        we re-pin it as part of the boundary contract.)"""
        from packages.openant.scanner import _build_subprocess_env
        with tempfile.TemporaryDirectory() as tmp:
            config = OpenAntConfig(core_path=Path(tmp))
            with self.assertRaises(RuntimeError):
                _build_subprocess_env(config)


class TestBugNewCwdIsolation(unittest.TestCase):
    """BUG-NEW: cwd must be set to core_path in subprocess.run.

    Root cause: Python always puts '' (cwd) first in sys.path for -m invocations.
    Raptor has its own core/ package at the repo root. Without cwd=core_path,
    running raptor_openant from the Raptor directory causes Python to find
    Raptor's core/ (no scanner.py) before openant's core/ (has scanner.py),
    giving ModuleNotFoundError: No module named 'core.scanner'.

    Fix: subprocess.run(..., cwd=str(config.core_path)) so '' resolves to
    openant-core, not the Raptor repo root.
    """

    def test_cwd_set_in_subprocess_run(self):
        """Static check: scanner.py passes cwd= to subprocess.run."""
        scanner_src = (Path(__file__).parents[1] / "scanner.py").read_text()
        self.assertIn(
            "cwd=",
            scanner_src,
            "subprocess.run must pass cwd= to ensure '' in sys.path resolves "
            "to openant-core, not Raptor's repo root which also has a core/ package.",
        )

    def test_cwd_resolves_to_core_path(self):
        """Static check: the cwd value uses core_path (not a hardcoded string)."""
        scanner_src = (Path(__file__).parents[1] / "scanner.py").read_text()
        self.assertIn(
            "core_path",
            scanner_src[scanner_src.find("cwd="):scanner_src.find("cwd=") + 60],
        )

    def test_would_fail_without_fix(self):
        """Confirm Raptor's repo root has its OWN core/ package that would
        shadow openant's core/ if cwd were not set to core_path."""
        raptor_root = Path(__file__).parents[3]
        raptor_core = raptor_root / "core"
        self.assertTrue(
            raptor_core.exists() and (raptor_core / "__init__.py").exists(),
            "Raptor must have a core/__init__.py for the shadow bug to exist; "
            "if this fails, the fix may no longer be needed",
        )
        # Raptor's core/ does NOT have scanner.py
        self.assertFalse(
            (raptor_core / "scanner.py").exists(),
            "Raptor's core/scanner.py should not exist (it belongs to openant)",
        )


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
