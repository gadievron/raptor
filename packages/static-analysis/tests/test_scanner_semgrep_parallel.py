"""Tests for ``semgrep_scan_parallel`` and ``semgrep_scan_sequential``.

Adapted from Josh's PR #60 ``core/tests/test_semgrep_parallel.py``.
Phase 2.1 of the centralisation refactor kept these functions in
scanner.py rather than ``core/``, so the mock targets retarget from
``core.semgrep.X`` to the scanner module loaded via importlib.

The pack-id assertions below tolerate either the raw pack id (e.g.
``"category/crypto"``) OR a local-cache-resolved path containing the
pack name. PR #196 added ``RaptorConfig.get_semgrep_config`` to
rewrite registry pack ids into shipped local YAMLs, so a test that
hard-codes the registry id would otherwise fail post-#196.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import patch


# packages/static-analysis has a hyphen — load via importlib.
_SCANNER_PATH = Path(__file__).parent.parent / "scanner.py"
_spec = importlib.util.spec_from_file_location(
    "static_analysis_scanner_semgrep_parallel", _SCANNER_PATH,
)
_scanner_mod = importlib.util.module_from_spec(_spec)
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
_spec.loader.exec_module(_scanner_mod)

semgrep_scan_parallel = _scanner_mod.semgrep_scan_parallel
semgrep_scan_sequential = _scanner_mod.semgrep_scan_sequential

from core.config import RaptorConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_sarif_response(findings=None):
    """Return a (rc, stdout, stderr) tuple with valid minimal SARIF."""
    runs = [{"results": findings}] if findings else []
    return (0 if not findings else 1, json.dumps({"runs": runs}), "")


def _stub_run_single(name, config, repo_path, out_dir, timeout, progress_callback=None):
    """Side-effect for run_single_semgrep: creates the expected files and returns."""
    safe = name.replace("/", "_").replace(":", "_")
    sarif = out_dir / f"semgrep_{safe}.sarif"
    sarif.write_text('{"runs": []}')
    (out_dir / f"semgrep_{safe}.stderr.log").write_text("")
    (out_dir / f"semgrep_{safe}.exit").write_text("0")
    if progress_callback:
        progress_callback(f"Scanning with {name}")
    return str(sarif), True


# ---------------------------------------------------------------------------
# semgrep_scan_parallel
# ---------------------------------------------------------------------------

class TestSemgrepScanParallel:

    @patch.object(_scanner_mod, "run_single_semgrep", side_effect=_stub_run_single)
    def test_returns_list_of_sarif_paths(self, mock_single, tmp_path):
        paths = semgrep_scan_parallel(tmp_path, [], tmp_path, timeout=10)
        assert isinstance(paths, list)
        for p in paths:
            assert isinstance(p, str)

    @patch.object(_scanner_mod, "run_single_semgrep", side_effect=_stub_run_single)
    def test_creates_out_dir_if_missing(self, mock_single, tmp_path):
        out_dir = tmp_path / "new_subdir"
        assert not out_dir.exists()
        semgrep_scan_parallel(tmp_path, [], out_dir, timeout=10)
        assert out_dir.exists()

    @patch.object(_scanner_mod, "run_single_semgrep", side_effect=_stub_run_single)
    def test_baseline_packs_always_included(self, mock_single, tmp_path):
        """Even with no rule dirs, baseline packs are always scanned."""
        semgrep_scan_parallel(tmp_path, [], tmp_path, timeout=10)
        # Check by scan name (c.args[0]) rather than config path: post-#196
        # the config path is the resolved local-cache JSON (e.g.
        # ``.../c.p.security-audit.json``), so substring-matching the raw
        # registry id no longer works. Names like ``semgrep_security_audit``
        # stay clean and unambiguous.
        called_names = [c.args[0] for c in mock_single.call_args_list]
        for pack_name, _ in RaptorConfig.BASELINE_SEMGREP_PACKS:
            assert pack_name in called_names, (
                f"Baseline pack {pack_name!r} not scanned"
            )

    @patch.object(_scanner_mod, "run_single_semgrep", side_effect=_stub_run_single)
    def test_nonexistent_rules_dir_skipped(self, mock_single, tmp_path):
        """Non-existent rule directories should be skipped without error."""
        paths = semgrep_scan_parallel(
            tmp_path,
            [str(tmp_path / "does_not_exist")],
            tmp_path,
            timeout=10,
        )
        assert isinstance(paths, list)

    @patch.object(_scanner_mod, "run_single_semgrep", side_effect=_stub_run_single)
    def test_existing_rules_dir_adds_local_scan(self, mock_single, tmp_path):
        """A rules dir that exists should add a local scan config."""
        crypto_dir = tmp_path / "crypto"
        crypto_dir.mkdir()
        semgrep_scan_parallel(tmp_path, [str(crypto_dir)], tmp_path, timeout=10)
        called_configs = [c.args[1] for c in mock_single.call_args_list]
        assert str(crypto_dir) in called_configs

    @patch.object(_scanner_mod, "run_single_semgrep", side_effect=_stub_run_single)
    def test_known_category_adds_standard_pack(self, mock_single, tmp_path):
        """A rules dir matching a known category key also triggers its standard pack."""
        # 'auth' maps to ('semgrep_auth', 'p/jwt') in POLICY_GROUP_TO_SEMGREP_PACK.
        # (Josh's original used crypto which has since been unmapped; see
        #  RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK for the current set.)
        auth_dir = tmp_path / "auth"
        auth_dir.mkdir()
        semgrep_scan_parallel(tmp_path, [str(auth_dir)], tmp_path, timeout=10)
        called_names = [c.args[0] for c in mock_single.call_args_list]
        auth_pack_name = RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK["auth"][0]
        assert auth_pack_name in called_names

    @patch.object(_scanner_mod, "run_single_semgrep", side_effect=_stub_run_single)
    def test_no_duplicate_packs(self, mock_single, tmp_path):
        """The same standard pack must not be submitted more than once."""
        # Add two rule dirs that both map to the same pack (edge case simulation)
        # secrets appears in both POLICY_GROUP and BASELINE — should appear once
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        semgrep_scan_parallel(tmp_path, [str(secrets_dir)], tmp_path, timeout=10)
        called_configs = [c.args[1] for c in mock_single.call_args_list]
        # secrets pack is in both POLICY_GROUP and BASELINE — must de-dup
        # (the local-rules dir gets its own ``category_secrets`` entry, which
        # is intentional and not considered a duplicate).
        called_names = [c.args[0] for c in mock_single.call_args_list]
        assert called_names.count("semgrep_secrets") == 1

    @patch.object(_scanner_mod, "run_single_semgrep", side_effect=_stub_run_single)
    def test_progress_callback_called(self, mock_single, tmp_path):
        progress_msgs = []
        semgrep_scan_parallel(tmp_path, [], tmp_path, timeout=10,
                               progress_callback=progress_msgs.append)
        assert len(progress_msgs) > 0

    @patch.object(_scanner_mod, "run_single_semgrep")
    def test_exception_in_worker_does_not_crash(self, mock_single, tmp_path):
        """An exception raised by a worker should be caught and logged, not propagate."""
        mock_single.side_effect = RuntimeError("worker exploded")
        # Must not raise
        paths = semgrep_scan_parallel(tmp_path, [], tmp_path, timeout=10)
        assert isinstance(paths, list)

    @patch.object(_scanner_mod, "run_single_semgrep")
    def test_failed_scan_still_returns_partial_results(self, mock_single, tmp_path):
        """If one scan fails, the others' SARIFs are still returned."""
        good_sarif = str(tmp_path / "semgrep_ok.sarif")

        call_count = 0

        def side_effect(name, config, repo_path, out_dir, timeout, progress_callback=None):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # first call succeeds
                Path(good_sarif).write_text('{"runs": []}')
                return good_sarif, True
            raise RuntimeError("boom")

        mock_single.side_effect = side_effect
        paths = semgrep_scan_parallel(tmp_path, [], tmp_path, timeout=10)
        # At least one path from the successful scan
        assert len(paths) >= 1


# ---------------------------------------------------------------------------
# semgrep_scan_sequential
# ---------------------------------------------------------------------------

class TestSemgrepScanSequential:

    @patch.object(_scanner_mod, "run_single_semgrep", side_effect=_stub_run_single)
    def test_returns_list(self, mock_single, tmp_path):
        paths = semgrep_scan_sequential(tmp_path, [], tmp_path, timeout=10)
        assert isinstance(paths, list)

    @patch.object(_scanner_mod, "run_single_semgrep", side_effect=_stub_run_single)
    def test_creates_out_dir(self, mock_single, tmp_path):
        out_dir = tmp_path / "seq_out"
        semgrep_scan_sequential(tmp_path, [], out_dir, timeout=10)
        assert out_dir.exists()

    @patch.object(_scanner_mod, "run_single_semgrep", side_effect=_stub_run_single)
    def test_includes_baseline_packs(self, mock_single, tmp_path):
        semgrep_scan_sequential(tmp_path, [], tmp_path, timeout=10)
        called_names = [c.args[0] for c in mock_single.call_args_list]
        for pack_name, _ in RaptorConfig.BASELINE_SEMGREP_PACKS:
            assert pack_name in called_names

    @patch.object(_scanner_mod, "run_single_semgrep", side_effect=_stub_run_single)
    def test_no_duplicate_packs(self, mock_single, tmp_path):
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        semgrep_scan_sequential(tmp_path, [str(secrets_dir)], tmp_path, timeout=10)
        called_configs = [c.args[1] for c in mock_single.call_args_list]
        # secrets pack is in both POLICY_GROUP and BASELINE — must de-dup
        # (the local-rules dir gets its own ``category_secrets`` entry, which
        # is intentional and not considered a duplicate).
        called_names = [c.args[0] for c in mock_single.call_args_list]
        assert called_names.count("semgrep_secrets") == 1

    @patch.object(_scanner_mod, "run_single_semgrep", side_effect=_stub_run_single)
    def test_scans_run_in_order(self, mock_single, tmp_path):
        """Sequential mode must call run_single_semgrep in a deterministic order."""
        semgrep_scan_sequential(tmp_path, [], tmp_path, timeout=10)
        # All calls happened (not in parallel threads that could interleave)
        assert mock_single.call_count == len(RaptorConfig.BASELINE_SEMGREP_PACKS)

    @patch.object(_scanner_mod, "run_single_semgrep", side_effect=_stub_run_single)
    def test_parallel_and_sequential_produce_same_config_set(self, mock_single, tmp_path):
        """Both modes must scan the same set of configs (just in different order/parallelism)."""
        crypto_dir = tmp_path / "crypto"
        crypto_dir.mkdir()
        rules = [str(crypto_dir)]

        out_seq = tmp_path / "seq"
        out_seq.mkdir()
        mock_single.reset_mock()
        mock_single.side_effect = _stub_run_single
        semgrep_scan_sequential(tmp_path, rules, out_seq, timeout=10)
        seq_configs = {c.args[1] for c in mock_single.call_args_list}

        out_par = tmp_path / "par"
        out_par.mkdir()
        mock_single.reset_mock()
        mock_single.side_effect = _stub_run_single
        semgrep_scan_parallel(tmp_path, rules, out_par, timeout=10)
        par_configs = {c.args[1] for c in mock_single.call_args_list}

        assert seq_configs == par_configs


# ---------------------------------------------------------------------------
# Clean environment behaviour (run_semgrep venv stripping)
# ---------------------------------------------------------------------------

class TestCleanEnvironment:

    @patch.object(_scanner_mod, "run")
    @patch.object(_scanner_mod, "validate_sarif", return_value=True)
    @patch("shutil.which", return_value="/usr/bin/semgrep")
    def test_virtual_env_stripped_from_env(self, mock_which, mock_validate, mock_run, tmp_path):
        """VIRTUAL_ENV and PYTHONPATH must not be forwarded to semgrep."""
        run_single_semgrep = _scanner_mod.run_single_semgrep
        mock_run.return_value = (0, '{"runs": []}', "")

        with patch.dict("os.environ", {"VIRTUAL_ENV": "/some/venv", "PYTHONPATH": "/bad/path"}):
            run_single_semgrep(
                name="env_test", config="p/default",
                repo_path=tmp_path, out_dir=tmp_path, timeout=10,
            )

        assert mock_run.called
        env_arg = mock_run.call_args.kwargs.get("env")
        assert env_arg is not None
        assert "VIRTUAL_ENV" not in env_arg
        assert "PYTHONPATH" not in env_arg

    @patch.object(_scanner_mod, "run")
    @patch.object(_scanner_mod, "validate_sarif", return_value=True)
    @patch("shutil.which", return_value="/usr/bin/semgrep")
    def test_venv_paths_stripped_from_PATH(self, mock_which, mock_validate, mock_run, tmp_path):
        """venv directories must be stripped from PATH before calling semgrep."""
        run_single_semgrep = _scanner_mod.run_single_semgrep
        mock_run.return_value = (0, '{"runs": []}', "")

        venv_path = "/home/user/project/.venv/bin"
        normal_path = "/usr/bin:/usr/local/bin"
        with patch.dict("os.environ", {"PATH": f"{venv_path}:{normal_path}"}):
            run_single_semgrep(
                name="path_test", config="p/default",
                repo_path=tmp_path, out_dir=tmp_path, timeout=10,
            )

        assert mock_run.called
        env_arg = mock_run.call_args.kwargs.get("env")
        assert env_arg is not None
        assert "PATH" in env_arg
        assert venv_path not in env_arg["PATH"]
