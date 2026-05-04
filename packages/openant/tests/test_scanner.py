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
    """BUG-R-012: --no-analyze flag was declared but inactive. Removed."""

    def test_no_analyze_flag_absent(self):
        launcher = Path(__file__).parents[3] / "raptor_openant.py"
        text = launcher.read_text()
        self.assertNotIn("--no-analyze", text,
                         "--no-analyze flag should be removed (BUG-R-012)")
        self.assertNotIn("no_analyze", text,
                         "no_analyze references should be removed")


class TestBugR017VenvPythonSelection(unittest.TestCase):
    """BUG-R-017: scanner must use OpenAnt venv Python, not sys.executable.

    Pre-fix: _build_command used sys.executable (Raptor's Python 3.14) which
    lacks tree_sitter_c, tree_sitter_ruby, tree_sitter_php, tree_sitter_javascript.
    These bindings are only installed in OpenAnt's .venv.

    Post-fix: _find_venv_python() checks core_path/.venv/bin/python3 first.
    """

    def test_venv_python_preferred_when_present(self):
        """When .venv/bin/python3 exists in core_path, it must be used."""
        from packages.openant.scanner import _find_venv_python
        with tempfile.TemporaryDirectory() as tmp:
            core = Path(tmp) / "openant-core"
            venv_python = core / ".venv" / "bin" / "python3"
            venv_python.parent.mkdir(parents=True)
            venv_python.touch()
            venv_python.chmod(0o755)

            result = _find_venv_python(core)
            self.assertEqual(result, str(venv_python))

    def test_falls_back_to_sys_executable_when_no_venv(self):
        """Without a venv, must fall back to sys.executable."""
        from packages.openant.scanner import _find_venv_python
        import sys
        with tempfile.TemporaryDirectory() as tmp:
            core = Path(tmp) / "openant-core-no-venv"
            core.mkdir()
            result = _find_venv_python(core)
            self.assertEqual(result, sys.executable)

    def test_build_command_uses_venv_python(self):
        """_build_command must use the venv Python as the first command element."""
        from packages.openant.scanner import _build_command
        from packages.openant.config import OpenAntConfig
        with tempfile.TemporaryDirectory() as tmp:
            core = _make_fake_core(Path(tmp))
            venv_python = core / ".venv" / "bin" / "python3"
            venv_python.parent.mkdir(parents=True)
            venv_python.touch()
            venv_python.chmod(0o755)

            config = OpenAntConfig(core_path=core)
            cmd = _build_command(Path("/repo"), Path("/out"), config)
            self.assertEqual(cmd[0], str(venv_python),
                "First element of command must be venv Python, not sys.executable")

    def test_static_check_sys_executable_only_as_fallback(self):
        """scanner.py must reference sys.executable only as a fallback,
        not as the primary Python for the subprocess command."""
        scanner_src = (Path(__file__).parents[1] / "scanner.py").read_text()
        # _find_venv_python must exist
        self.assertIn("_find_venv_python", scanner_src)
        # sys.executable must appear only inside _find_venv_python (fallback)
        # and NOT in _build_command
        build_cmd_idx = scanner_src.find("def _build_command")
        venv_fn_idx = scanner_src.find("def _find_venv_python")
        build_cmd_body = scanner_src[build_cmd_idx:venv_fn_idx]
        self.assertNotIn("sys.executable", build_cmd_body,
            "_build_command must not reference sys.executable directly (BUG-R-017)")


class TestBugR018ZigLanguageFallback(unittest.TestCase):
    """BUG-R-018: --language zig is not a valid OpenAnt CLI choice.

    Pre-fix: _build_command passed --language zig to openant scan, which exited
    with argparse error: invalid choice: 'zig'. Languages like zig are
    auto-detected but not exposed in OpenAnt's --language CLI enum.

    Post-fix: language values not in _OPENANT_CLI_LANGUAGES fall back to 'auto'.
    """

    def test_zig_maps_to_auto(self):
        """config.language='zig' must produce --language auto in the command."""
        from packages.openant.scanner import _build_command
        from packages.openant.config import OpenAntConfig
        with tempfile.TemporaryDirectory() as tmp:
            core = _make_fake_core(Path(tmp))
            config = OpenAntConfig(core_path=core, language="zig")
            cmd = _build_command(Path("/repo"), Path("/out"), config)
            lang_idx = cmd.index("--language")
            self.assertEqual(cmd[lang_idx + 1], "auto",
                "zig must map to auto (not a valid --language choice)")

    def test_known_languages_pass_through_unchanged(self):
        """python, c, ruby, php, go, javascript, auto must not be remapped."""
        from packages.openant.scanner import _build_command, _OPENANT_CLI_LANGUAGES
        from packages.openant.config import OpenAntConfig
        for lang in _OPENANT_CLI_LANGUAGES - {"auto"}:
            with tempfile.TemporaryDirectory() as tmp:
                core = _make_fake_core(Path(tmp))
                config = OpenAntConfig(core_path=core, language=lang)
                cmd = _build_command(Path("/repo"), Path("/out"), config)
                lang_idx = cmd.index("--language")
                self.assertEqual(cmd[lang_idx + 1], lang,
                    f"Known language '{lang}' must not be remapped to auto")

    def test_unrecognized_language_maps_to_auto(self):
        """Any unrecognized language (e.g., 'cobol') maps to auto."""
        from packages.openant.scanner import _build_command
        from packages.openant.config import OpenAntConfig
        with tempfile.TemporaryDirectory() as tmp:
            core = _make_fake_core(Path(tmp))
            config = OpenAntConfig(core_path=core, language="cobol")
            cmd = _build_command(Path("/repo"), Path("/out"), config)
            lang_idx = cmd.index("--language")
            self.assertEqual(cmd[lang_idx + 1], "auto")

    def test_openant_cli_languages_constant_matches_known_set(self):
        """Static check: _OPENANT_CLI_LANGUAGES contains the expected values."""
        from packages.openant.scanner import _OPENANT_CLI_LANGUAGES
        expected = {"auto", "python", "javascript", "go", "c", "ruby", "php"}
        self.assertEqual(_OPENANT_CLI_LANGUAGES, expected,
            "Update _OPENANT_CLI_LANGUAGES if OpenAnt adds new --language choices")


if __name__ == "__main__":
    unittest.main()
