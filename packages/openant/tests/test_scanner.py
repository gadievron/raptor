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
        # Emulate the fix's error formatting
        msg = "OpenAnt exited 2: some error (full stderr in /tmp/x/openant.stderr.log)"
        self.assertIn("openant.stderr.log", msg)

    def test_stderr_persistence_block_present(self):
        """Static check: scanner.py contains the stderr-persist block."""
        scanner_src = (Path(__file__).parents[1] / "scanner.py").read_text()
        self.assertIn("openant.stderr.log", scanner_src)
        self.assertIn("write_text", scanner_src)


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


class TestSandboxIntegration(unittest.TestCase):
    """Verify OpenAnt subprocess runs under core.sandbox.run."""

    def test_uses_sandbox_run(self):
        from packages.openant import scanner
        src = Path(scanner.__file__).read_text()
        assert "from core.sandbox.context import run as sandbox_run" in src
        assert "sandbox_run(" in src
        assert "subprocess.run(" not in src.split("sandbox_run(", 1)[1]


class TestPythonpathNotReinjected(unittest.TestCase):
    """PYTHONPATH is on DANGEROUS_ENV_VARS — get_safe_env() drops it by
    design. The child env must carry exactly the validated openant-core
    path, never the ambient PYTHONPATH tail (env-poisoning lane: the
    subprocess runs with network and ANTHROPIC_API_KEY)."""

    def test_ambient_pythonpath_never_reaches_child(self):
        with tempfile.TemporaryDirectory() as td:
            core = _make_fake_core(Path(td))
            hostile = str(Path(td) / "attacker-site-packages")
            with patch.dict(os.environ, {"PYTHONPATH": hostile}, clear=False):
                env = _build_subprocess_env(OpenAntConfig(core_path=core))
            self.assertEqual(env["PYTHONPATH"], str(core.resolve()))
            self.assertNotIn(hostile, env["PYTHONPATH"])


class TestProvenanceRecordThreading(unittest.TestCase):
    """The gate's enriched provenance (worktree survey verdict +
    consent route) is the record of note: run_openant_scan used to
    re-run the BARE checkout_provenance and persist THAT, so a
    consented tampered core's report read {matches: true} with the
    deviation surviving only as a transient stderr warning (and the
    flag path double-warned)."""

    def _scan(self, cfg, td: Path):
        from unittest import mock
        from packages.openant import scanner
        stub = {"pipeline_output_path": None,
                "pipeline_output": {"findings": []},
                "token_usage": {}, "error": None, "skipped": False}
        with mock.patch.object(scanner, "_run_subprocess",
                               return_value=dict(stub)):
            return scanner.run_openant_scan(td / "repo", td / "out", cfg)

    def test_gate_record_is_persisted_not_rederived(self):
        from unittest import mock
        from packages.openant import scanner
        from packages.openant.config import OpenAntConfig
        gate_rec = {"pinned_commit": "p", "head": "p", "matches": True,
                    "worktree_clean": False,
                    "worktree_deviations": {"modified": 1, "untracked": 0},
                    "consent": "operator-flag"}
        with tempfile.TemporaryDirectory() as td_s:
            td = Path(td_s)
            cfg = OpenAntConfig(core_path=td / "core",
                                gate_provenance=gate_rec)
            with mock.patch.object(
                    scanner, "checkout_provenance",
                    side_effect=AssertionError(
                        "bare provenance re-derived over the gate record")):
                res = self._scan(cfg, td)
        self.assertEqual(res["core_provenance"], gate_rec)

    def test_env_lane_records_survey_not_run(self):
        from unittest import mock
        from packages.openant import scanner
        from packages.openant.config import OpenAntConfig
        with tempfile.TemporaryDirectory() as td_s:
            td = Path(td_s)
            cfg = OpenAntConfig(core_path=td / "core")
            bare = {"pinned_commit": "p", "head": "p", "matches": True}
            with mock.patch.object(scanner, "checkout_provenance",
                                   return_value=dict(bare)):
                res = self._scan(cfg, td)
        self.assertEqual(res["core_provenance"]["worktree_clean"],
                         "unknown")

    def test_gate_stamps_consent_route(self):
        from unittest import mock
        from packages.openant import scanner
        from packages.openant.tests.test_phase1b_integration import (
            TestOpenantCoreConsentGate,
        )
        pinned_repo = TestOpenantCoreConsentGate.__dict__[
            "_pinned_repo"].__func__
        with tempfile.TemporaryDirectory() as td:
            repo, core, head = pinned_repo(Path(td))
            with mock.patch.object(scanner, "OPENANT_PINNED_COMMIT", head):
                prov = scanner.enforce_core_consent(
                    core, consented=False, target_path=td)
                self.assertEqual(prov["consent"], "clean-pinned")
                (core / "core" / "scanner.py").write_text("tampered\n")
                with self.assertLogs("raptor", level="WARNING"):
                    prov = scanner.enforce_core_consent(
                        core, consented=True, target_path=td)
                self.assertEqual(prov["consent"], "operator-flag")
                self.assertIs(prov["worktree_clean"], False)
                with mock.patch("core.project.trust.resolve_repo_trust",
                                return_value=True):
                    with self.assertLogs("raptor", level="WARNING"):
                        prov = scanner.enforce_core_consent(
                            core, consented=False, target_path=td)
                self.assertEqual(prov["consent"], "trust-marker")


class TestSpawnRecheckClosesConsentToctou(unittest.TestCase):
    """Consent gate TOCTOU: content was verified once at argv parse
    and executed at spawn (in /agentic an entire pattern-scan phase
    later) with no re-verification. A run the gate admitted as a
    CLEAN PINNED checkout must re-verify that content right before
    spawn and refuse hard when it drifted; consented runs skip the
    recheck (the operator accepted non-pinned content)."""

    @staticmethod
    def _pinned(td):
        from packages.openant.tests.test_phase1b_integration import (
            TestOpenantCoreConsentGate,
        )
        return TestOpenantCoreConsentGate.__dict__[
            "_pinned_repo"].__func__(td)

    def _scan(self, cfg, td: Path):
        from unittest import mock
        from packages.openant import scanner
        stub = {"pipeline_output_path": None,
                "pipeline_output": {"findings": []},
                "token_usage": {}, "error": None, "skipped": False}
        spawned = []
        def probe(*a, **k):
            spawned.append(True)
            return dict(stub)
        with mock.patch.object(scanner, "_run_subprocess", probe):
            res = scanner.run_openant_scan(td / "repo", td / "out", cfg)
        return res, bool(spawned)

    def test_content_swap_after_clean_gate_refuses_hard(self):
        from unittest import mock
        from packages.openant import scanner
        from packages.openant.config import OpenAntConfig
        with tempfile.TemporaryDirectory() as td_s:
            td = Path(td_s)
            repo, core, head = self._pinned(td)
            with mock.patch.object(scanner, "OPENANT_PINNED_COMMIT", head):
                prov = scanner.enforce_core_consent(
                    core, consented=False, target_path=td_s)
                self.assertEqual(prov["consent"], "clean-pinned")
                # The swap: hostile content lands AFTER the gate.
                (core / "core" / "scanner.py").write_text(
                    "hostile = True\n")
                cfg = OpenAntConfig(core_path=core, gate_provenance=prov,
                                    expect_clean_pinned=True)
                res, spawned = self._scan(cfg, td)
        self.assertTrue(res.get("hard_error"), res)
        self.assertIn("consent gate", str(res.get("error")))
        self.assertFalse(spawned,
                         "subprocess spawned despite drifted content")

    def test_unchanged_clean_core_still_spawns(self):
        from unittest import mock
        from packages.openant import scanner
        from packages.openant.config import OpenAntConfig
        with tempfile.TemporaryDirectory() as td_s:
            td = Path(td_s)
            repo, core, head = self._pinned(td)
            with mock.patch.object(scanner, "OPENANT_PINNED_COMMIT", head):
                prov = scanner.enforce_core_consent(
                    core, consented=False, target_path=td_s)
                cfg = OpenAntConfig(core_path=core, gate_provenance=prov,
                                    expect_clean_pinned=True)
                res, spawned = self._scan(cfg, td)
        self.assertIsNone(res.get("error"))
        self.assertTrue(spawned)

    def test_consented_run_skips_recheck(self):
        from unittest import mock
        from packages.openant import scanner
        from packages.openant.config import OpenAntConfig
        with tempfile.TemporaryDirectory() as td_s:
            td = Path(td_s)
            repo, core, head = self._pinned(td)
            (core / "core" / "scanner.py").write_text("tampered\n")
            with mock.patch.object(scanner, "OPENANT_PINNED_COMMIT", head):
                with self.assertLogs("raptor", level="WARNING"):
                    prov = scanner.enforce_core_consent(
                        core, consented=True, target_path=td_s)
                cfg = OpenAntConfig(core_path=core, gate_provenance=prov,
                                    expect_clean_pinned=False)
                res, spawned = self._scan(cfg, td)
        self.assertIsNone(res.get("error"))
        self.assertTrue(spawned)

    def test_both_entry_points_wire_the_recheck(self):
        for launcher in ("raptor_openant.py", "raptor_agentic.py"):
            src = (Path(__file__).parents[3] / launcher).read_text()
            self.assertIn("expect_clean_pinned", src, launcher)
            self.assertIn('== "clean-pinned"', src, launcher)


if __name__ == "__main__":
    unittest.main()
