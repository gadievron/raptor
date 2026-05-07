"""Tests for cleanup_per_pack_artifacts in packages/static-analysis/scanner.py.

The cleanup runs after combined.sarif is written. It removes redundant
per-pack semgrep_*.{exit,json,sarif,stderr.log} files while preserving
diagnostic artefacts for failed packs.
"""

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

# static-analysis has a hyphen — load via importlib (mirrors test_scanner.py).
_SCANNER_PATH = Path(__file__).parent.parent / "scanner.py"
_spec = importlib.util.spec_from_file_location(
    "static_analysis_scanner_cleanup", _SCANNER_PATH
)
_scanner_mod = importlib.util.module_from_spec(_spec)
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
_spec.loader.exec_module(_scanner_mod)

cleanup_per_pack_artifacts = _scanner_mod.cleanup_per_pack_artifacts
_sarif_has_findings = _scanner_mod._sarif_has_findings


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

EMPTY_SARIF = json.dumps({"version": "2.1.0", "runs": [{"results": []}]})

SARIF_WITH_FINDINGS = json.dumps({
    "version": "2.1.0",
    "runs": [
        {
            "results": [
                {"ruleId": "R1", "message": {"text": "hello"}},
            ]
        }
    ],
})


def _make_pack(out: Path, suffix: str, *, exit_code: int,
               stderr: str = "", sarif: str = EMPTY_SARIF,
               json_body: str = '{"results": []}') -> None:
    (out / f"semgrep_{suffix}.exit").write_text(str(exit_code))
    (out / f"semgrep_{suffix}.stderr.log").write_text(stderr)
    (out / f"semgrep_{suffix}.sarif").write_text(sarif)
    (out / f"semgrep_{suffix}.json").write_text(json_body)


# --------------------------------------------------------------------------
# _sarif_has_findings
# --------------------------------------------------------------------------

class TestSarifHasFindings:
    def test_empty_sarif_returns_false(self, tmp_path):
        p = tmp_path / "x.sarif"
        p.write_text(EMPTY_SARIF)
        assert _sarif_has_findings(p) is False

    def test_sarif_with_results_returns_true(self, tmp_path):
        p = tmp_path / "x.sarif"
        p.write_text(SARIF_WITH_FINDINGS)
        assert _sarif_has_findings(p) is True

    def test_missing_file_returns_false(self, tmp_path):
        assert _sarif_has_findings(tmp_path / "missing.sarif") is False

    def test_invalid_json_returns_false(self, tmp_path):
        p = tmp_path / "x.sarif"
        p.write_text("not json {{{")
        assert _sarif_has_findings(p) is False


# --------------------------------------------------------------------------
# cleanup_per_pack_artifacts
# --------------------------------------------------------------------------

class TestCleanupPerPackArtifacts:

    def test_successful_pack_with_empty_stderr_strips_everything(self, tmp_path):
        _make_pack(tmp_path, "category_auth", exit_code=0, stderr="")
        cleanup_per_pack_artifacts(tmp_path)

        for ext in (".exit", ".json", ".sarif", ".stderr.log"):
            assert not (tmp_path / f"semgrep_category_auth{ext}").exists(), (
                f"{ext} should be removed for successful pack with empty stderr"
            )

    def test_successful_pack_with_stderr_keeps_stderr_only(self, tmp_path):
        _make_pack(
            tmp_path, "p_security_audit",
            exit_code=0, stderr="WARN: rule deprecation\n",
        )
        cleanup_per_pack_artifacts(tmp_path)

        # Successful: .exit, .json, .sarif removed.
        assert not (tmp_path / "semgrep_p_security_audit.exit").exists()
        assert not (tmp_path / "semgrep_p_security_audit.json").exists()
        assert not (tmp_path / "semgrep_p_security_audit.sarif").exists()
        # Non-empty stderr: kept.
        assert (tmp_path / "semgrep_p_security_audit.stderr.log").exists()

    def test_failed_pack_with_empty_sarif_keeps_exit_and_stderr(self, tmp_path):
        _make_pack(
            tmp_path, "category_crypto",
            exit_code=1, stderr="ERROR: rule parse failed\n",
            sarif=EMPTY_SARIF,
        )
        cleanup_per_pack_artifacts(tmp_path)

        # Always-removed files
        assert not (tmp_path / "semgrep_category_crypto.json").exists()
        # Failed pack diagnostics kept
        assert (tmp_path / "semgrep_category_crypto.exit").exists()
        assert (tmp_path / "semgrep_category_crypto.stderr.log").exists()
        # Empty SARIF still removed (combined.sarif is canonical)
        assert not (tmp_path / "semgrep_category_crypto.sarif").exists()

    def test_failed_pack_with_findings_keeps_sarif(self, tmp_path):
        _make_pack(
            tmp_path, "category_injection",
            exit_code=1, stderr="ERROR: partial completion\n",
            sarif=SARIF_WITH_FINDINGS,
        )
        cleanup_per_pack_artifacts(tmp_path)

        assert not (tmp_path / "semgrep_category_injection.json").exists()
        # Diagnostics kept for the failed pack
        assert (tmp_path / "semgrep_category_injection.exit").exists()
        assert (tmp_path / "semgrep_category_injection.stderr.log").exists()
        # SARIF retained because it has findings
        assert (tmp_path / "semgrep_category_injection.sarif").exists()

    def test_unparseable_exit_treated_as_failure(self, tmp_path):
        # exit file with garbage means we don't know the outcome — treat as
        # failure so we keep diagnostics rather than silently dropping them.
        suffix = "category_garbled"
        (tmp_path / f"semgrep_{suffix}.exit").write_text("\x00not-an-int\n")
        (tmp_path / f"semgrep_{suffix}.stderr.log").write_text("oops\n")
        (tmp_path / f"semgrep_{suffix}.sarif").write_text(EMPTY_SARIF)
        (tmp_path / f"semgrep_{suffix}.json").write_text("{}")

        cleanup_per_pack_artifacts(tmp_path)

        assert not (tmp_path / f"semgrep_{suffix}.json").exists()
        # exit kept (failure treatment)
        assert (tmp_path / f"semgrep_{suffix}.exit").exists()
        # non-empty stderr kept
        assert (tmp_path / f"semgrep_{suffix}.stderr.log").exists()
        # empty SARIF removed
        assert not (tmp_path / f"semgrep_{suffix}.sarif").exists()

    def test_unrelated_files_left_alone(self, tmp_path):
        """Cleanup must only touch precisely-named per-pack files."""
        # Unrelated artefacts that must survive.
        keep = [
            "combined.sarif",
            "scan-manifest.json",
            "scan_metrics.json",
            "coverage-semgrep.json",
            "verification.json",
            "proxy-events.jsonl",
            ".raptor-run.json",
            "sarif_merge.stderr.log",  # not a per-pack file
            "codeql_python.sarif",     # codeql, not semgrep
            "semgrep.log",             # standalone, no <suffix>
        ]
        for name in keep:
            (tmp_path / name).write_text("x")

        # .semgrep_home/ subdirectory must be left intact.
        sh = tmp_path / ".semgrep_home"
        sh.mkdir()
        (sh / "settings.yml").write_text("y")

        # And one real successful pack to make sure cleanup runs.
        _make_pack(tmp_path, "category_auth", exit_code=0, stderr="")

        cleanup_per_pack_artifacts(tmp_path)

        for name in keep:
            assert (tmp_path / name).exists(), f"{name} must not be deleted"
        assert (sh / "settings.yml").exists()

        # The pack itself was cleaned.
        assert not (tmp_path / "semgrep_category_auth.exit").exists()

    def test_multiple_packs_mixed_outcomes(self, tmp_path):
        # Pack A: success, empty stderr → fully removed
        _make_pack(tmp_path, "category_auth", exit_code=0, stderr="")
        # Pack B: success, non-empty stderr → only stderr kept
        _make_pack(tmp_path, "category_logging", exit_code=0, stderr="warn\n")
        # Pack C: failed, empty sarif → exit + stderr kept
        _make_pack(
            tmp_path, "category_secrets",
            exit_code=2, stderr="boom\n", sarif=EMPTY_SARIF,
        )
        # Pack D: failed, sarif with findings → all diagnostics kept
        _make_pack(
            tmp_path, "p_default",
            exit_code=1, stderr="partial\n", sarif=SARIF_WITH_FINDINGS,
        )

        removed = cleanup_per_pack_artifacts(tmp_path)
        assert removed > 0

        # Pack A — gone
        for ext in (".exit", ".json", ".sarif", ".stderr.log"):
            assert not (tmp_path / f"semgrep_category_auth{ext}").exists()

        # Pack B — only stderr remains
        assert not (tmp_path / "semgrep_category_logging.exit").exists()
        assert not (tmp_path / "semgrep_category_logging.json").exists()
        assert not (tmp_path / "semgrep_category_logging.sarif").exists()
        assert (tmp_path / "semgrep_category_logging.stderr.log").exists()

        # Pack C — exit + stderr remain
        assert (tmp_path / "semgrep_category_secrets.exit").exists()
        assert (tmp_path / "semgrep_category_secrets.stderr.log").exists()
        assert not (tmp_path / "semgrep_category_secrets.json").exists()
        assert not (tmp_path / "semgrep_category_secrets.sarif").exists()

        # Pack D — exit + stderr + sarif (with findings) remain
        assert (tmp_path / "semgrep_p_default.exit").exists()
        assert (tmp_path / "semgrep_p_default.stderr.log").exists()
        assert (tmp_path / "semgrep_p_default.sarif").exists()
        assert not (tmp_path / "semgrep_p_default.json").exists()

    def test_missing_per_pack_files_do_not_error(self, tmp_path):
        # Only an .exit file — the other per-pack files were never written.
        (tmp_path / "semgrep_category_partial.exit").write_text("0")
        # Should run without raising.
        cleanup_per_pack_artifacts(tmp_path)
        assert not (tmp_path / "semgrep_category_partial.exit").exists()

    def test_does_not_follow_symlinks(self, tmp_path):
        # Set up a successful pack normally...
        _make_pack(tmp_path, "category_real", exit_code=0, stderr="")
        # ...and a symlink that masquerades as a per-pack file pointing at
        # an unrelated file outside the patterns we want to delete.
        sentinel = tmp_path / "outside_target.txt"
        sentinel.write_text("important")
        link = tmp_path / "semgrep_category_link.sarif"
        try:
            os.symlink(sentinel, link)
        except OSError:
            pytest.skip("symlinks not supported on this filesystem")

        cleanup_per_pack_artifacts(tmp_path)

        # The symlinked sarif must NOT have been removed (we skip symlinks).
        assert link.is_symlink(), "symlink should be left intact"
        # And the real target must be untouched.
        assert sentinel.exists()
        assert sentinel.read_text() == "important"

    def test_empty_directory_is_noop(self, tmp_path):
        removed = cleanup_per_pack_artifacts(tmp_path)
        assert removed == 0
