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

sys.path.insert(0, str(Path(__file__).parents[3]))  # repo root

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
        """The error message must point users at the log file path —
        asserted against the scanner's actual error construction (the
        old test asserted on a string literal it built itself)."""
        scanner_src = (Path(__file__).parents[1] / "scanner.py").read_text()
        exit_block = scanner_src.split("proc.returncode not in (0, 1)")[1]
        exit_block = exit_block.split("hard_error=True")[0]
        self.assertIn("full streams in", exit_block)
        self.assertIn("openant.stdout.log", exit_block)
        self.assertIn("openant.stderr.log", exit_block)

    def test_stderr_persistence_block_present(self):
        """Static check: scanner.py contains the stream-persist block,
        written no-follow (the child owns the writable out_dir)."""
        scanner_src = (Path(__file__).parents[1] / "scanner.py").read_text()
        self.assertIn("openant.stderr.log", scanner_src)
        self.assertIn("openant.stdout.log", scanner_src)
        self.assertIn("O_NOFOLLOW", scanner_src)


class TestStdoutErrorSurfaced(unittest.TestCase):
    """The pinned CLI reports errors as a JSON document on STDOUT
    (progress lines only on stderr) — a failing scan must persist
    stdout and surface it in the error when stderr is uninformative."""

    def _run_with_fake_proc(self, tmp: Path, *, stdout: str, stderr: str):
        import subprocess
        from unittest.mock import patch as _patch

        from packages.openant import scanner
        core = _make_fake_core(tmp)
        out = tmp / "out"
        out.mkdir()

        def fake_run(cmd, **kwargs):
            return subprocess.CompletedProcess(
                cmd, returncode=2, stdout=stdout, stderr=stderr)

        with _patch("core.sandbox.context.run", fake_run):
            result = scanner.run_openant_scan(
                tmp, out, OpenAntConfig(core_path=core))
        return result, out

    def test_stdout_persisted_and_in_snippet_when_stderr_thin(self):
        err_doc = '{"status": "error", "errors": ["auth method missing"]}'
        with tempfile.TemporaryDirectory() as td:
            result, out = self._run_with_fake_proc(
                Path(td), stdout=err_doc, stderr="[Scan] progress\n")
            self.assertTrue(result["hard_error"])
            self.assertIn("auth method missing", result["error"])
            self.assertEqual(
                (out / "openant.stdout.log").read_text(), err_doc)

    def test_error_doc_joins_even_when_stderr_is_chatty(self):
        """A long stderr progress line must not crowd the actual error
        (the stdout error document) out of the snippet."""
        err_doc = '{"status": "error", "errors": ["auth method missing"]}'
        with tempfile.TemporaryDirectory() as td:
            result, _ = self._run_with_fake_proc(
                Path(td), stdout=err_doc,
                stderr="[Scan] LLM config: raptor-sonnet — resolving "
                       "providers and building phase adapters")
            self.assertIn("LLM config", result["error"])
            self.assertIn("auth method missing", result["error"])

    def test_meaningful_stderr_leads_without_error_doc(self):
        with tempfile.TemporaryDirectory() as td:
            result, _ = self._run_with_fake_proc(
                Path(td),
                stdout="plain progress output, not an error document",
                stderr="openant: error: unrecognized arguments: --model x")
            self.assertIn("unrecognized arguments", result["error"])
            self.assertNotIn("plain progress output", result["error"])

    def test_stream_persist_refuses_planted_symlink(self):
        """The child owns the writable out_dir while it runs — a
        pre-planted openant.*.log symlink must not steer the
        unsandboxed parent into writing at a child-chosen path."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            victim = base / "victim.txt"
            victim.write_text("untouched")
            out_pre = base / "out"
            out_pre.mkdir()
            for name in ("openant.stdout.log", "openant.stderr.log"):
                (out_pre / name).symlink_to(victim)
            import subprocess as _sp
            from unittest.mock import patch as _patch

            from packages.openant import scanner
            core = _make_fake_core(base)

            def fake_run(cmd, **kwargs):
                return _sp.CompletedProcess(
                    cmd, returncode=2,
                    stdout='{"status": "error", "errors": ["x"]}',
                    stderr="some stderr")

            with _patch("core.sandbox.context.run", fake_run):
                scanner.run_openant_scan(
                    base, out_pre, OpenAntConfig(core_path=core))
            self.assertEqual(victim.read_text(), "untouched")
            for name in ("openant.stdout.log", "openant.stderr.log"):
                self.assertFalse((out_pre / name).is_symlink(),
                                 f"{name} still a symlink")


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


class TestVenvFallbackVisibility(unittest.TestCase):
    """The consent gate's documented refusal remedy ('re-clone at the
    pin') produces a venv-less core; _find_venv_python then silently
    fell back to sys.executable, losing the four tree-sitter grammar
    languages BUG-R-017 documents. The fallback must warn, naming
    them — and versioned interpreters are discovered by glob, not a
    hand-picked list that ended at python3.13."""

    def test_fallback_to_sys_executable_warns_lost_languages(self):
        import sys as _sys
        from packages.openant.scanner import _find_venv_python
        with tempfile.TemporaryDirectory() as td:
            core = Path(td)
            with self.assertLogs("raptor", level="WARNING") as cm:
                result = _find_venv_python(core)
        self.assertEqual(result, _sys.executable)
        joined = "\n".join(cm.output)
        for lang in ("c", "ruby", "php", "javascript"):
            self.assertIn(lang, joined)

    def test_versioned_only_venv_is_found(self):
        """A python3.14-only venv (no python3 symlink) must be used,
        not silently skipped."""
        from packages.openant.scanner import _find_venv_python
        with tempfile.TemporaryDirectory() as td:
            core = Path(td)
            bin_dir = core / ".venv" / "bin"
            bin_dir.mkdir(parents=True)
            exe = bin_dir / "python3.14"
            exe.write_text("#!/bin/sh\n")
            exe.chmod(0o755)
            result = _find_venv_python(core)
        self.assertTrue(result.endswith("python3.14"), result)

    def test_plain_python3_still_preferred(self):
        from packages.openant.scanner import _find_venv_python
        with tempfile.TemporaryDirectory() as td:
            core = Path(td)
            bin_dir = core / ".venv" / "bin"
            bin_dir.mkdir(parents=True)
            for name in ("python3", "python3.14"):
                exe = bin_dir / name
                exe.write_text("#!/bin/sh\n")
                exe.chmod(0o755)
            result = _find_venv_python(core)
        self.assertTrue(result.endswith("/python3"), result)


class TestBoundedCaptureAndByteTrueStderrCap(unittest.TestCase):
    """The 1 MiB cap bounded only the disk write (measured in CHARS,
    up to 4x the budget in UTF-8, with the notice appended PAST the
    cap), and nothing bounded the parent-buffered streams at all —
    stdout was json.loads'd whole. The scanner now passes the
    sandbox's max_capture_bytes ceiling and persists stderr
    byte-true."""

    def test_stderr_cap_is_byte_true_with_notice_inside(self):
        from packages.openant import scanner
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td)
            scanner._persist_stderr(out_dir, "é" * scanner.STDERR_MAX_BYTES)
            data = (out_dir / "openant.stderr.log").read_bytes()
        self.assertLessEqual(len(data), scanner.STDERR_MAX_BYTES)
        self.assertIn(b"[truncated", data)

    def test_under_cap_stderr_untouched(self):
        from packages.openant import scanner
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td)
            scanner._persist_stderr(out_dir, "short error\n")
            data = (out_dir / "openant.stderr.log").read_text(
                encoding="utf-8")
        self.assertEqual(data, "short error\n")
        self.assertNotIn("[truncated", data)

    def test_subprocess_capture_ceiling_wired(self):
        """The sandbox_run invocation must carry the capture ceiling
        (fork backend: transient bound; other lanes: result clamp that
        bounds the parse and persist paths)."""
        scanner_src = (Path(__file__).parents[1] / "scanner.py").read_text()
        call = scanner_src.split("proc = sandbox_run(")[1]
        call = call.split("except subprocess.TimeoutExpired")[0]
        self.assertIn("max_capture_bytes=_CAPTURE_MAX_BYTES", call)


class TestSurveyNitCorrections(unittest.TestCase):
    """P4 aggregate members on the survey and report surfaces."""

    def test_worktree_style_checkout_git_file_not_untracked(self):
        """A `git worktree` checkout carries a `.git` FILE at its
        toplevel; counting it untracked made genuinely clean
        worktree-checkouts refuse-unless-consented."""
        import subprocess
        from unittest import mock
        from packages.openant import scanner
        from packages.openant.tests.test_phase1b_integration import (
            TestOpenantCoreConsentGate,
        )
        pinned_repo = TestOpenantCoreConsentGate.__dict__[
            "_pinned_repo"].__func__
        with tempfile.TemporaryDirectory() as td:
            repo, core, head = pinned_repo(Path(td))
            wt = Path(td) / "wt"
            subprocess.run(
                ["git", "-C", str(repo), "worktree", "add", "-q",
                 str(wt), "HEAD"],
                check=True, capture_output=True)
            wt_core = wt / "libs" / "openant-core"
            with mock.patch.object(scanner, "OPENANT_PINNED_COMMIT", head):
                dev = scanner._pinned_tree_deviations(wt_core)
        self.assertEqual(dev, {"modified": 0, "untracked": 0})

    def test_survey_name_folds_nfc_on_darwin_only(self):
        """[attempt/record for the darwin-blocked PLAUSIBLE member]
        macOS filesystems hand back NFD spellings of NFC tree names —
        the membership fold is darwin-scoped and testable
        platform-independently through the helper."""
        import unicodedata
        from packages.openant.scanner import _survey_name
        nfd = unicodedata.normalize("NFD", "caf\u00e9.py")
        nfc = unicodedata.normalize("NFC", "caf\u00e9.py")
        self.assertNotEqual(nfd, nfc)
        self.assertEqual(_survey_name(nfd, platform="darwin"), nfc)
        self.assertEqual(_survey_name(nfd, platform="linux"), nfd)

    def test_dead_sentinel_removed(self):
        config_src = (Path(__file__).parents[1] / "config.py").read_text()
        self.assertNotIn("_SENTINEL", config_src)


if __name__ == "__main__":
    unittest.main()
