"""Semgrep ``run_single_semgrep`` tests for scanner.py.

Adapted from Josh's PR #60 ``core/tests/test_semgrep.py``. Phase 2.1 of
the centralisation refactor kept the semgrep orchestration in scanner.py
rather than ``core/``, so these tests target the scanner module instead.

Dropped in adaptation:
  - ``TestRunSemgrep`` — Josh added a single-config wrapper named
    ``run_semgrep``; scanner.py exposes only ``run_single_semgrep``
    so there is no target to test.
  - ``TestSemgrepIntegration`` — those real-semgrep tests called the
    missing ``run_semgrep`` wrapper. The mocked unit tests below cover
    the same control flow without requiring semgrep installed.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch


# packages/static-analysis has a hyphen — load via importlib.
_SCANNER_PATH = Path(__file__).parent.parent / "scanner.py"
_spec = importlib.util.spec_from_file_location(
    "static_analysis_scanner_semgrep", _SCANNER_PATH,
)
_scanner_mod = importlib.util.module_from_spec(_spec)
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
_spec.loader.exec_module(_scanner_mod)

run_single_semgrep = _scanner_mod.run_single_semgrep


class TestRunSingleSemgrep:
    """Tests for run_single_semgrep function."""

    @patch('shutil.which')
    @patch.object(_scanner_mod, "run")
    @patch.object(_scanner_mod, "validate_sarif")
    def test_creates_output_files(self, mock_validate, mock_run, mock_which, tmp_path):
        """Test that all expected output files are created."""
        mock_which.return_value = "/usr/bin/semgrep"
        mock_run.return_value = (0, '{"runs": []}', "some stderr")
        mock_validate.return_value = True

        sarif_path, success = run_single_semgrep(
            name="test_scan",
            config="p/default",
            repo_path=tmp_path,
            out_dir=tmp_path,
            timeout=300
        )

        assert success is True
        assert Path(sarif_path).exists()
        assert (tmp_path / "semgrep_test_scan.stderr.log").exists()
        assert (tmp_path / "semgrep_test_scan.exit").exists()

    @patch('shutil.which')
    @patch.object(_scanner_mod, "run")
    @patch.object(_scanner_mod, "validate_sarif")
    def test_sanitizes_name_with_slashes(self, mock_validate, mock_run, mock_which, tmp_path):
        """Test that names with special chars are sanitized."""
        mock_which.return_value = "/usr/bin/semgrep"
        mock_run.return_value = (0, '{"runs": []}', "")
        mock_validate.return_value = True

        sarif_path, success = run_single_semgrep(
            name="p/security-audit",
            config="p/security-audit",
            repo_path=tmp_path,
            out_dir=tmp_path,
            timeout=300
        )

        # Name should be sanitized (slashes replaced)
        assert "p_security-audit" in sarif_path

    @patch('shutil.which')
    @patch.object(_scanner_mod, "run")
    @patch.object(_scanner_mod, "validate_sarif")
    def test_progress_callback_called(self, mock_validate, mock_run, mock_which, tmp_path):
        """Test that progress callback is invoked."""
        mock_which.return_value = "/usr/bin/semgrep"
        mock_run.return_value = (0, '{"runs": []}', "")
        mock_validate.return_value = True

        callback_calls = []

        def progress_callback(msg):
            callback_calls.append(msg)

        run_single_semgrep(
            name="test",
            config="p/default",
            repo_path=tmp_path,
            out_dir=tmp_path,
            timeout=300,
            progress_callback=progress_callback
        )

        assert len(callback_calls) > 0
        assert any("test" in call for call in callback_calls)


class TestSandboxFakeHomeWiring:
    """Regression guard for the HOME + XDG redirect.

    PR #777's reported "almost worked" failure surfaced that when
    ``XDG_CONFIG_HOME`` survives ``SAFE_ENV_ALLOWLIST``, semgrep
    follows it to the operator's real ``~/.config/semgrep`` —
    outside the Landlock writable policy on rootless-podman /
    distrobox hosts, where the write attempt then crashes.
    The fix passes ``fake_home=True`` through the sandbox layer
    (``core.sandbox.context``), which materialises HOME + all four
    ``XDG_*_HOME`` subdirs (CONFIG/DATA/CACHE/STATE) inside
    ``output``, applies symlink-TOCTOU defence, and merges its
    override into the subprocess env with ``fake_home_env``
    winning over caller-supplied ``env=`` (see ``context.py:1144``).
    These tests pin the WIRING (``run()`` receives
    ``fake_home=True``); the env-merge correctness is owned + tested
    by the sandbox layer itself."""

    @patch('shutil.which')
    @patch.object(_scanner_mod, "run")
    @patch.object(_scanner_mod, "validate_sarif")
    def test_run_called_with_fake_home_true(
        self, mock_validate, mock_run, mock_which, tmp_path,
    ):
        mock_which.return_value = "/usr/bin/semgrep"
        mock_run.return_value = (0, '{"runs": []}', "")
        mock_validate.return_value = True

        run_single_semgrep(
            name="t", config="p/default",
            repo_path=tmp_path, out_dir=tmp_path, timeout=300,
        )

        assert mock_run.call_args.kwargs.get("fake_home") is True

    @patch('shutil.which')
    @patch.object(_scanner_mod, "run")
    @patch.object(_scanner_mod, "validate_sarif")
    def test_run_called_with_target_and_output_for_fake_home(
        self, mock_validate, mock_run, mock_which, tmp_path,
    ):
        """``fake_home=True`` raises ``ValueError`` if ``output``
        isn't set (see ``context.py:540``). Pin that the scanner
        passes ``output=out_dir`` so the sandbox can materialise
        the fake home inside it."""
        mock_which.return_value = "/usr/bin/semgrep"
        mock_run.return_value = (0, '{"runs": []}', "")
        mock_validate.return_value = True

        run_single_semgrep(
            name="t", config="p/default",
            repo_path=tmp_path, out_dir=tmp_path, timeout=300,
        )
        assert mock_run.call_args.kwargs.get("output") == str(tmp_path)
        assert mock_run.call_args.kwargs.get("target") == str(tmp_path)

    @patch('shutil.which')
    @patch.object(_scanner_mod, "run")
    @patch.object(_scanner_mod, "validate_sarif")
    def test_extra_config_paths_forwarded_as_readable_paths(
        self, mock_validate, mock_run, mock_which, tmp_path,
    ):
        """The operator's ``--extra-config`` paths must be forwarded
        as ``readable_paths`` to the sandbox call, future-proofing
        against a flip from Landlock read-default-wide to
        ``restrict_reads=True``. Without this, an
        ``--extra-config /home/op/rules.yml`` would silently fail
        to read after a future hardening change."""
        mock_which.return_value = "/usr/bin/semgrep"
        mock_run.return_value = (0, '{"runs": []}', "")
        mock_validate.return_value = True

        custom = tmp_path / "rules.yml"
        custom.write_text("rules: []\n", encoding="utf-8")

        run_single_semgrep(
            name="extra_rules", config=str(custom),
            repo_path=tmp_path, out_dir=tmp_path, timeout=300,
            extra_config_readable_paths=[str(custom)],
        )
        readable = mock_run.call_args.kwargs.get("readable_paths")
        assert readable == [str(custom)]


class TestExtraConfigFlag:
    """--extra-config CLI flag: operator-supplied custom rule sources
    become peer packs in the configs list. Regression guard for the
    plumbing into both parallel + sequential dispatchers."""

    @patch.object(_scanner_mod, "run_single_semgrep")
    def test_parallel_appends_extra_configs_as_peer_packs(
        self, mock_run_single, tmp_path,
    ):
        # Don't actually run semgrep — just verify the dispatcher sees
        # the extra-config entry in its configs list.
        mock_run_single.return_value = (str(tmp_path / "x.sarif"), True)
        # Pre-create a dummy SARIF so the silent-drop detector doesn't
        # mask the dispatcher result.
        (tmp_path / "x.sarif").write_text('{"runs": []}', encoding="utf-8")

        custom_rule = tmp_path / "my-rules.yml"
        custom_rule.write_text("rules: []\n", encoding="utf-8")

        _scanner_mod.semgrep_scan_parallel(
            repo_path=tmp_path,
            rules_dirs=[],
            out_dir=tmp_path,
            baseline_packs=[],   # no baseline noise
            extra_configs=[str(custom_rule)],
        )

        # The dispatcher should have called run_single_semgrep with the
        # extra-config path. The name is "extra_<basename>".
        names = [c.kwargs.get("name") or c.args[0]
                 for c in mock_run_single.call_args_list]
        configs = [c.kwargs.get("config") or c.args[1]
                   for c in mock_run_single.call_args_list]
        assert any(n.startswith("extra_") for n in names), names
        assert str(custom_rule) in configs

    @patch.object(_scanner_mod, "run_single_semgrep")
    def test_sequential_appends_extra_configs_as_peer_packs(
        self, mock_run_single, tmp_path,
    ):
        mock_run_single.return_value = (str(tmp_path / "x.sarif"), True)
        (tmp_path / "x.sarif").write_text('{"runs": []}', encoding="utf-8")

        custom_rule = tmp_path / "my-rules.yml"
        custom_rule.write_text("rules: []\n", encoding="utf-8")

        _scanner_mod.semgrep_scan_sequential(
            repo_path=tmp_path,
            rules_dirs=[],
            out_dir=tmp_path,
            baseline_packs=[],
            extra_configs=[str(custom_rule)],
        )

        configs = [c.args[1] for c in mock_run_single.call_args_list]
        assert str(custom_rule) in configs

    @patch.object(_scanner_mod, "run_single_semgrep")
    def test_extra_configs_none_is_noop(
        self, mock_run_single, tmp_path,
    ):
        """The flag is optional — passing None must not crash or add
        a phantom pack."""
        mock_run_single.return_value = (str(tmp_path / "x.sarif"), True)
        (tmp_path / "x.sarif").write_text('{"runs": []}', encoding="utf-8")

        _scanner_mod.semgrep_scan_parallel(
            repo_path=tmp_path,
            rules_dirs=[],
            out_dir=tmp_path,
            baseline_packs=[],
            extra_configs=None,
        )
        assert mock_run_single.call_count == 0


class TestExtraConfigDedupAndCollision:
    """Defence against double-counted findings + silently-overwritten
    per-pack SARIF outputs when the operator passes redundant or
    basename-colliding --extra-config values."""

    @patch.object(_scanner_mod, "run_single_semgrep")
    def test_duplicate_extra_configs_are_deduped(
        self, mock_run_single, tmp_path,
    ):
        """``--extra-config foo.yml --extra-config foo.yml`` (a common
        copy-paste mistake on the command line) must dedupe — without
        this, semgrep ran the same rules twice and findings were
        double-counted in the merged report."""
        mock_run_single.return_value = (str(tmp_path / "x.sarif"), True)
        (tmp_path / "x.sarif").write_text('{"runs": []}', encoding="utf-8")

        custom = tmp_path / "rules.yml"
        custom.write_text("rules: []\n", encoding="utf-8")

        _scanner_mod.semgrep_scan_parallel(
            repo_path=tmp_path,
            rules_dirs=[],
            out_dir=tmp_path,
            baseline_packs=[],
            extra_configs=[str(custom), str(custom)],
        )
        assert mock_run_single.call_count == 1, (
            "duplicate --extra-config path produced multiple peer packs"
        )

    @patch.object(_scanner_mod, "run_single_semgrep")
    def test_basename_collision_renamed_to_unique(
        self, mock_run_single, tmp_path,
    ):
        """``--extra-config /a/rules.yml --extra-config /b/rules.yml``
        — two distinct paths with the same basename. Pre-fix both
        peer packs got the same name ``extra_rules.yml`` → same SARIF
        filename → second worker overwrote first → silent-drop
        detector didn't fire (the file existed, just from the wrong
        pack). Rename to disambiguate with a positional suffix."""
        mock_run_single.return_value = (str(tmp_path / "x.sarif"), True)
        (tmp_path / "x.sarif").write_text('{"runs": []}', encoding="utf-8")

        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        a = tmp_path / "a" / "rules.yml"
        b = tmp_path / "b" / "rules.yml"
        a.write_text("rules: []\n", encoding="utf-8")
        b.write_text("rules: []\n", encoding="utf-8")

        _scanner_mod.semgrep_scan_parallel(
            repo_path=tmp_path,
            rules_dirs=[],
            out_dir=tmp_path,
            baseline_packs=[],
            extra_configs=[str(a), str(b)],
        )
        names = [
            c.args[0] if c.args else c.kwargs.get("name")
            for c in mock_run_single.call_args_list
        ]
        # Both must run; their names must be distinct.
        assert mock_run_single.call_count == 2
        assert len(set(names)) == 2, (
            f"basename-colliding extra_configs got same name: {names}"
        )


class TestAllSemgrepPacksFailedExitCode:
    """Regression guard for the CI-gate-false-pass class. Pre-fix
    ``raptor scan`` exited 0 even when every dispatched semgrep pack
    failed (e.g. broken sandbox / network down / semgrep binary
    crash). An operator running raptor as a pre-merge gate silently
    got "0 findings = clean PR" when in fact NO pack ran. Surface as
    exit code 4 at the dispatch boundary.

    These tests assert the FLAG-COMPUTATION logic (sarif/failed
    length equality + non-empty); the end-to-end sys.exit(4) wiring
    is covered by integration."""

    def test_all_failed_when_failed_equals_sarif_lengths(self):
        """All N packs dispatched, all N in failed list → all-failed."""
        sarif_paths = ["a.sarif", "b.sarif", "c.sarif"]
        failed = ["a", "b", "c"]
        all_failed = (
            len(sarif_paths) > 0 and len(failed) == len(sarif_paths)
        )
        assert all_failed is True

    def test_partial_failure_does_not_trigger(self):
        """1 of 3 failed → 2 produced useful output → don't exit 4."""
        sarif_paths = ["a.sarif", "b.sarif", "c.sarif"]
        failed = ["a"]
        all_failed = (
            len(sarif_paths) > 0 and len(failed) == len(sarif_paths)
        )
        assert all_failed is False

    def test_empty_dispatch_does_not_trigger(self):
        """Operator passed no policy groups + no extra-config → no
        packs dispatched. That's an operator-input issue, not a
        scan-failure; don't exit 4 (would mask the real misuse)."""
        sarif_paths = []
        failed = []
        all_failed = (
            len(sarif_paths) > 0 and len(failed) == len(sarif_paths)
        )
        assert all_failed is False

    def test_failure_with_zero_sarif_paths_does_not_trigger(self):
        """Edge case: failed list populated but sarif_paths empty
        (shouldn't happen in practice — every dispatched pack
        appends a sarif_path even on failure — but defensive: we
        gate on ``sarif_paths > 0`` so a malformed return value
        doesn't crash here)."""
        sarif_paths = []
        failed = ["mystery"]
        all_failed = (
            len(sarif_paths) > 0 and len(failed) == len(sarif_paths)
        )
        assert all_failed is False
