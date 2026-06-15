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

from core.config import RaptorConfig  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_sarif_response(findings=None):
    """Return a (rc, stdout, stderr) tuple with valid minimal SARIF."""
    runs = [{"results": findings}] if findings else []
    return (0 if not findings else 1, json.dumps({"runs": runs}), "")


def _stub_run_single(name, config, repo_path, out_dir, timeout,
                     progress_callback=None, **_ignored):
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
    def test_returns_sarif_paths_and_failed_list(self, mock_single, tmp_path):
        paths, failed = semgrep_scan_parallel(tmp_path, [], tmp_path, timeout=10)
        assert isinstance(paths, list)
        assert isinstance(failed, list)
        for p in paths:
            assert isinstance(p, str)
        # Clean run: no failures.
        assert failed == []

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
        paths, _failed = semgrep_scan_parallel(
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
        paths, _failed = semgrep_scan_parallel(tmp_path, [], tmp_path, timeout=10)
        assert isinstance(paths, list)

    @patch.object(_scanner_mod, "run_single_semgrep")
    def test_failed_scan_still_returns_partial_results(self, mock_single, tmp_path):
        """If one scan fails, the others' SARIFs are still returned."""
        good_sarif = str(tmp_path / "semgrep_ok.sarif")

        call_count = 0

        def side_effect(name, config, repo_path, out_dir, timeout,
                        progress_callback=None, **_ignored):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # first call succeeds
                Path(good_sarif).write_text('{"runs": []}')
                return good_sarif, True
            raise RuntimeError("boom")

        mock_single.side_effect = side_effect
        paths, failed = semgrep_scan_parallel(tmp_path, [], tmp_path, timeout=10)
        # At least one path from the successful scan
        assert len(paths) >= 1
        # Worker exceptions land in the failed list (per-name).
        assert len(failed) >= 1


class TestSemgrepScanParallelSilentDropDetection:
    """The silent-drop class: a worker returns (sarif_path, success=True)
    but no SARIF file ends up on disk. Pre-fix this looked clean —
    ``failure_count`` was 0, the missing SARIFs were invisible. The
    cross-check between submitted pack names and SARIFs landed on disk
    promotes silent drops to ``failed`` so callers can surface them.
    """

    @patch.object(_scanner_mod, "run_single_semgrep")
    def test_missing_sarif_promoted_to_failed(self, mock_single, tmp_path):
        # Stub: claims success but DOESN'T write the SARIF file.
        # Realistic surrogate for the bug class — anything between the
        # worker's success return and the file actually landing
        # (filesystem write failure, sandbox teardown, race) lands
        # here.
        def lying_stub(name, config, repo_path, out_dir, timeout, progress_callback=None, **_ignored):
            suffix = name.replace("/", "_").replace(":", "_")
            sarif = out_dir / f"semgrep_{suffix}.sarif"
            # Return success + sarif path — but never write the file.
            return str(sarif), True
        mock_single.side_effect = lying_stub
        paths, failed = semgrep_scan_parallel(tmp_path, [], tmp_path, timeout=10)
        # Every submitted pack name appears in failed (since none
        # produced an on-disk SARIF). Worker returned success so
        # `failure_count` from the future loop alone would have
        # reported 0 — the cross-check picks them up.
        baseline_names = {n for n, _ in RaptorConfig.BASELINE_SEMGREP_PACKS}
        assert baseline_names.issubset(set(failed)), (
            f"Expected baseline packs to be marked failed, got: {failed!r}"
        )

    @patch.object(_scanner_mod, "run_single_semgrep")
    def test_partial_landing_marks_only_missing_as_failed(self, mock_single, tmp_path):
        # First call writes its SARIF (real success). Second + third
        # claim success but produce no file (silent drop).
        call_count = 0

        def mixed_stub(name, config, repo_path, out_dir, timeout, progress_callback=None, **_ignored):
            nonlocal call_count
            call_count += 1
            suffix = name.replace("/", "_").replace(":", "_")
            sarif = out_dir / f"semgrep_{suffix}.sarif"
            if call_count == 1:
                sarif.write_text('{"runs": []}')
            # else: silent drop — return success but write nothing.
            return str(sarif), True

        mock_single.side_effect = mixed_stub
        paths, failed = semgrep_scan_parallel(tmp_path, [], tmp_path, timeout=10)
        # First pack landed → not in failed. Remaining baselines → in failed.
        # (The exact count is len(BASELINE_SEMGREP_PACKS) - 1; threading
        # makes the call-order non-deterministic so we don't assert which
        # specific name survives — just that ≥1 succeeded and the rest
        # are flagged.)
        total = len(RaptorConfig.BASELINE_SEMGREP_PACKS)
        assert 0 < total - len(failed) <= total
        assert len(failed) >= 1


# ---------------------------------------------------------------------------
# semgrep_scan_sequential
# ---------------------------------------------------------------------------

class TestSemgrepScanSequential:

    @patch.object(_scanner_mod, "run_single_semgrep", side_effect=_stub_run_single)
    def test_returns_sarif_paths_and_failed_list(self, mock_single, tmp_path):
        paths, failed = semgrep_scan_sequential(tmp_path, [], tmp_path, timeout=10)
        assert isinstance(paths, list)
        assert isinstance(failed, list)
        # Clean run: no failures.
        assert failed == []

    @patch.object(_scanner_mod, "run_single_semgrep")
    def test_silent_drop_promoted_to_failed(self, mock_single, tmp_path):
        # Same shape as the parallel-path test: worker claims success
        # but no SARIF on disk. Sequential should detect via the same
        # submitted-vs-landed cross-check.
        def lying_stub(name, config, repo_path, out_dir, timeout, progress_callback=None, **_ignored):
            suffix = name.replace("/", "_").replace(":", "_")
            sarif = out_dir / f"semgrep_{suffix}.sarif"
            return str(sarif), True  # claim success, never write
        mock_single.side_effect = lying_stub
        paths, failed = semgrep_scan_sequential(tmp_path, [], tmp_path, timeout=10)
        baseline_names = {n for n, _ in RaptorConfig.BASELINE_SEMGREP_PACKS}
        assert baseline_names.issubset(set(failed))

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
        # secrets pack is in both POLICY_GROUP and BASELINE — must de-dup
        # (the local-rules dir gets its own ``category_secrets`` entry, which
        # is intentional and not considered a duplicate).
        called_names = [c.args[0] for c in mock_single.call_args_list]
        assert called_names.count("semgrep_secrets") == 1


# ---------------------------------------------------------------------------
# filter_sarif_by_exclude_globs — operator-side --exclude-dir post-filter
# ---------------------------------------------------------------------------

class TestFilterSarifByExcludeGlobs:
    """Drop SARIF results whose file URI matches any exclude glob.
    Order-preserving for what remains. No-op when globs are empty."""

    @staticmethod
    def _result(uri: str, rule_id: str = "rule-x"):
        return {
            "ruleId": rule_id,
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": 1},
                }
            }],
        }

    def _sarif(self, *uris):
        return {"runs": [{"results": [self._result(u) for u in uris]}]}

    def test_none_globs_is_noop(self):
        sarif = self._sarif("a.c", "b.c")
        out, dropped = _scanner_mod.filter_sarif_by_exclude_globs(sarif, None)
        assert out == sarif
        assert dropped == 0

    def test_empty_globs_is_noop(self):
        sarif = self._sarif("a.c", "b.c")
        out, dropped = _scanner_mod.filter_sarif_by_exclude_globs(sarif, [])
        assert out == sarif
        assert dropped == 0

    def test_single_glob_drops_matches(self):
        sarif = self._sarif("vendor/lib.c", "src/http/server.c", "vendor/util.c")
        out, dropped = _scanner_mod.filter_sarif_by_exclude_globs(
            sarif, ["vendor/*"],
        )
        kept_uris = [
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in out["runs"][0]["results"]
        ]
        assert kept_uris == ["src/http/server.c"]
        assert dropped == 2

    def test_multiple_globs_or_semantics(self):
        sarif = self._sarif(
            "src/util.c", "vendor/lib.c", "tests/test_x.c", "src/http/server.c",
        )
        out, dropped = _scanner_mod.filter_sarif_by_exclude_globs(
            sarif, ["vendor/*", "tests/*"],
        )
        kept_uris = [
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in out["runs"][0]["results"]
        ]
        assert kept_uris == ["src/util.c", "src/http/server.c"]
        assert dropped == 2

    def test_missing_uri_kept_defensively(self):
        # Malformed location: no artifactLocation. operator-exclude
        # shouldn't silently drop these.
        sarif = {"runs": [{"results": [
            {"ruleId": "rule-x", "locations": [{"physicalLocation": {}}]},
            self._result("vendor/lib.c"),
        ]}]}
        out, dropped = _scanner_mod.filter_sarif_by_exclude_globs(
            sarif, ["vendor/*"],
        )
        assert dropped == 1
        # Malformed entry survives.
        assert len(out["runs"][0]["results"]) == 1
        assert out["runs"][0]["results"][0]["ruleId"] == "rule-x"

    def test_does_not_mutate_input(self):
        # Caller may want to keep the original for forensic record.
        sarif = self._sarif("vendor/a.c", "src/b.c")
        out, _ = _scanner_mod.filter_sarif_by_exclude_globs(
            sarif, ["vendor/*"],
        )
        # Input still has both results.
        assert len(sarif["runs"][0]["results"]) == 2
        # Output has one.
        assert len(out["runs"][0]["results"]) == 1

    def test_multi_run_sarif(self):
        # Some emitters produce multiple runs in one SARIF file.
        sarif = {
            "runs": [
                {"results": [self._result("vendor/a.c"),
                             self._result("src/x.c")]},
                {"results": [self._result("vendor/b.c"),
                             self._result("src/y.c")]},
            ],
        }
        out, dropped = _scanner_mod.filter_sarif_by_exclude_globs(
            sarif, ["vendor/*"],
        )
        assert dropped == 2
        assert len(out["runs"][0]["results"]) == 1
        assert len(out["runs"][1]["results"]) == 1

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
