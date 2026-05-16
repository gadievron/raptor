"""Tests for the verification.json provenance manifest in scanner.py.

The manifest is composed by _compose_verification_manifest() which must
run BEFORE cleanup_per_pack_artifacts() — cleanup deletes most of the
per-pack SARIFs the hashes are taken from. These tests drive the helper
directly without running a full scan.
"""

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

# static-analysis has a hyphen — load via importlib (mirrors test_scanner.py).
_SCANNER_PATH = Path(__file__).parent.parent / "scanner.py"
_spec = importlib.util.spec_from_file_location(
    "static_analysis_scanner_verification", _SCANNER_PATH
)
_scanner_mod = importlib.util.module_from_spec(_spec)
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
_spec.loader.exec_module(_scanner_mod)

_compose_verification_manifest = _scanner_mod._compose_verification_manifest
cleanup_per_pack_artifacts = _scanner_mod.cleanup_per_pack_artifacts


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

EMPTY_SARIF = {"version": "2.1.0", "runs": [{"results": []}]}


def _sarif_with(n_findings: int) -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {"ruleId": f"R{i}", "message": {"text": f"finding-{i}"}}
                    for i in range(n_findings)
                ],
            }
        ],
    }


def _write_sarif(path: Path, data: dict) -> bytes:
    raw = json.dumps(data).encode("utf-8")
    path.write_bytes(raw)
    return raw


def _write_pack(out_dir: Path, suffix: str, *,
                sarif_data: dict, exit_code: int = 0,
                stderr: str = "") -> Path:
    """Mirror what run_single_semgrep produces on disk."""
    sarif = out_dir / f"semgrep_{suffix}.sarif"
    _write_sarif(sarif, sarif_data)
    (out_dir / f"semgrep_{suffix}.exit").write_text(str(exit_code))
    (out_dir / f"semgrep_{suffix}.stderr.log").write_text(stderr)
    (out_dir / f"semgrep_{suffix}.json").write_text(
        json.dumps({"results": []})
    )
    return sarif


# --------------------------------------------------------------------------
# _compose_verification_manifest — top-level shape
# --------------------------------------------------------------------------

class TestComposeManifestShape:

    def test_schema_version_and_top_level_keys(self, tmp_path):
        sarif_a = _write_pack(tmp_path, "category_auth", sarif_data=_sarif_with(2))
        combined = tmp_path / "combined.sarif"
        _write_sarif(combined, _sarif_with(2))

        manifest = _compose_verification_manifest(
            [str(sarif_a)], combined, tmp_path,
        )

        assert manifest["schema_version"] == 1
        assert set(manifest.keys()) == {"schema_version", "combined_sarif", "packs"}

    def test_combined_sarif_hash_matches_disk(self, tmp_path):
        combined = tmp_path / "combined.sarif"
        raw = _write_sarif(combined, _sarif_with(3))
        expected_sha = hashlib.sha256(raw).hexdigest()

        manifest = _compose_verification_manifest([], combined, tmp_path)

        assert manifest["combined_sarif"]["path"] == "combined.sarif"
        assert manifest["combined_sarif"]["sha256"] == expected_sha
        assert manifest["combined_sarif"]["size_bytes"] == len(raw)

    def test_no_sarif_inputs_field(self, tmp_path):
        combined = tmp_path / "combined.sarif"
        _write_sarif(combined, EMPTY_SARIF)

        manifest = _compose_verification_manifest([], combined, tmp_path)

        # Explicit assertion: the legacy field must NOT be present.
        assert "sarif_inputs" not in manifest
        assert "verify" not in manifest
        assert "metrics" not in manifest

    def test_combined_sarif_missing_degrades_gracefully(self, tmp_path):
        combined = tmp_path / "combined.sarif"  # never created

        manifest = _compose_verification_manifest([], combined, tmp_path)

        assert manifest["combined_sarif"]["path"] == "combined.sarif"
        assert manifest["combined_sarif"]["sha256"] == ""
        assert manifest["combined_sarif"]["size_bytes"] == 0


# --------------------------------------------------------------------------
# Pack-level provenance fields
# --------------------------------------------------------------------------

class TestPackProvenance:

    def test_pack_count_matches_inputs(self, tmp_path):
        a = _write_pack(tmp_path, "category_auth", sarif_data=_sarif_with(1))
        b = _write_pack(tmp_path, "category_crypto", sarif_data=_sarif_with(0))
        combined = tmp_path / "combined.sarif"
        _write_sarif(combined, EMPTY_SARIF)

        manifest = _compose_verification_manifest(
            [str(a), str(b)], combined, tmp_path,
        )

        assert len(manifest["packs"]) == 2
        names = sorted(p["name"] for p in manifest["packs"])
        assert names == ["category_auth", "category_crypto"]

    def test_pack_sha256_matches_per_pack_bytes(self, tmp_path):
        sarif = tmp_path / "semgrep_category_auth.sarif"
        raw = _write_sarif(sarif, _sarif_with(2))
        expected_sha = hashlib.sha256(raw).hexdigest()
        (tmp_path / "semgrep_category_auth.exit").write_text("0")
        combined = tmp_path / "combined.sarif"
        _write_sarif(combined, EMPTY_SARIF)

        manifest = _compose_verification_manifest(
            [str(sarif)], combined, tmp_path,
        )

        assert manifest["packs"][0]["sarif_sha256"] == expected_sha

    def test_pack_fields_present_and_typed(self, tmp_path):
        sarif = _write_pack(
            tmp_path, "category_injection",
            sarif_data=_sarif_with(5), exit_code=0,
            stderr="warn: deprecated rule\n",
        )
        combined = tmp_path / "combined.sarif"
        _write_sarif(combined, EMPTY_SARIF)

        manifest = _compose_verification_manifest(
            [str(sarif)], combined, tmp_path,
        )
        pack = manifest["packs"][0]

        assert pack["tool"] == "semgrep"
        assert pack["name"] == "category_injection"
        assert pack["exit"] == 0
        assert pack["findings"] == 5
        assert pack["stderr_size_bytes"] == len("warn: deprecated rule\n")
        assert isinstance(pack["sarif_sha256"], str)
        assert len(pack["sarif_sha256"]) == 64  # sha256 hex

    def test_codeql_pack_classified_as_codeql(self, tmp_path):
        sarif = tmp_path / "codeql_cpp.sarif"
        _write_sarif(sarif, _sarif_with(1))
        combined = tmp_path / "combined.sarif"
        _write_sarif(combined, EMPTY_SARIF)

        manifest = _compose_verification_manifest(
            [str(sarif)], combined, tmp_path,
        )
        pack = manifest["packs"][0]

        assert pack["tool"] == "codeql"
        assert pack["name"] == "cpp"
        # CodeQL: no .exit file emitted by run_codeql; presence of SARIF
        # implies success → reported as 0.
        assert pack["exit"] == 0
        # CodeQL: no per-pack stderr.log either.
        assert pack["stderr_size_bytes"] == 0

    def test_failed_pack_records_nonzero_exit(self, tmp_path):
        sarif = _write_pack(
            tmp_path, "category_secrets",
            sarif_data=_sarif_with(0), exit_code=2,
            stderr="ERROR: rule parse failed\n",
        )
        combined = tmp_path / "combined.sarif"
        _write_sarif(combined, EMPTY_SARIF)

        manifest = _compose_verification_manifest(
            [str(sarif)], combined, tmp_path,
        )
        pack = manifest["packs"][0]

        assert pack["exit"] == 2
        assert pack["findings"] == 0
        assert pack["stderr_size_bytes"] > 0

    def test_unparseable_exit_treated_as_minus_one(self, tmp_path):
        sarif = tmp_path / "semgrep_category_garbled.sarif"
        _write_sarif(sarif, EMPTY_SARIF)
        (tmp_path / "semgrep_category_garbled.exit").write_text("not-an-int")
        combined = tmp_path / "combined.sarif"
        _write_sarif(combined, EMPTY_SARIF)

        manifest = _compose_verification_manifest(
            [str(sarif)], combined, tmp_path,
        )
        assert manifest["packs"][0]["exit"] == -1


# --------------------------------------------------------------------------
# Cleanup interaction — the load-bearing invariant
# --------------------------------------------------------------------------

class TestManifestSurvivesCleanup:

    def test_pack_hash_still_correct_after_cleanup_deletes_per_pack_sarif(
            self, tmp_path):
        # 1. Set up a successful pack: cleanup will delete its .sarif.
        sarif = tmp_path / "semgrep_category_auth.sarif"
        raw = _write_sarif(sarif, _sarif_with(2))
        expected_sha = hashlib.sha256(raw).hexdigest()
        (tmp_path / "semgrep_category_auth.exit").write_text("0")
        (tmp_path / "semgrep_category_auth.stderr.log").write_text("")
        (tmp_path / "semgrep_category_auth.json").write_text(
            json.dumps({"results": []})
        )
        combined = tmp_path / "combined.sarif"
        _write_sarif(combined, _sarif_with(2))

        # 2. Compose manifest BEFORE cleanup (the production order).
        manifest = _compose_verification_manifest(
            [str(sarif)], combined, tmp_path,
        )

        # 3. Run cleanup — it deletes the per-pack .sarif.
        cleanup_per_pack_artifacts(tmp_path)
        assert not sarif.exists(), "fixture: cleanup must delete the sarif"

        # 4. The hash in the manifest still matches the original content.
        assert manifest["packs"][0]["sarif_sha256"] == expected_sha
        # And combined.sarif (canonical, untouched by cleanup) is intact.
        assert combined.exists()
