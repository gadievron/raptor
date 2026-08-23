"""Manifest schema validation."""

from __future__ import annotations

import json

import pytest

from core.recall.manifest import (
    SCHEMA_VERSION,
    ManifestError,
    load_manifest,
    parse_manifest,
)


def _valid() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "name": "fixture-corpus",
        "target": {
            "repo_url": "https://example.org/upstream/repo",
            "pinned_sha": "b06d6efaebd577a327514364951916e7df3290b4",
            "local_path": "out/fixtures/repo",
        },
        "language": "java",
        "profile": "scan-codeql",
        "expected": [
            {
                "id": "case-1",
                "file": "src/A.java",
                "line_start": 40,
                "line_end": 44,
                "cwe": "CWE-78",
                "provenance": {"kind": "benchmark", "suite": "s",
                               "case": "case-1"},
            },
            {
                "id": "case-2",
                "file": "src/B.java",
                "line_start": None,
                "line_end": None,
                "cwe": "CWE-89",
                "provenance": {
                    "kind": "cve",
                    "cve_id": "CVE-2021-12345",
                    "fix_commit": "0123456789abcdef0123456789abcdef01234567",
                },
            },
        ],
        "clean_regions": [
            {
                "id": "clean-1",
                "file": "src/C.java",
                "cwe": "CWE-78",
                "provenance": {"kind": "benchmark", "suite": "s",
                               "case": "clean-1"},
            }
        ],
    }


class TestParseManifest:
    def test_valid_manifest_parses(self):
        m = parse_manifest(_valid())
        assert m.name == "fixture-corpus"
        assert len(m.expected) == 2
        assert len(m.clean_regions) == 1
        assert m.tolerance.line_drift == 5
        assert m.tolerance.cwe_family_match is True
        assert m.expected[1].line_start is None

    def test_missing_provenance_refused(self):
        data = _valid()
        del data["expected"][0]["provenance"]
        with pytest.raises(ManifestError, match="provenance"):
            parse_manifest(data)

    def test_undisclosed_provenance_kind_refused(self):
        data = _valid()
        data["expected"][0]["provenance"] = {"kind": "internal-finding"}
        with pytest.raises(ManifestError, match="public provenance"):
            parse_manifest(data)

    def test_cve_provenance_needs_fix_commit(self):
        data = _valid()
        data["expected"][1]["provenance"] = {
            "kind": "cve", "cve_id": "CVE-2021-12345"}
        with pytest.raises(ManifestError, match="fix commit"):
            parse_manifest(data)

    def test_bad_schema_version_refused(self):
        data = _valid()
        data["schema_version"] = 99
        with pytest.raises(ManifestError, match="schema_version"):
            parse_manifest(data)

    def test_unknown_profile_refused(self):
        data = _valid()
        data["profile"] = "turbo"
        with pytest.raises(ManifestError, match="profile"):
            parse_manifest(data)

    def test_absolute_expected_path_refused(self):
        data = _valid()
        data["expected"][0]["file"] = "/etc/passwd"
        with pytest.raises(ManifestError, match="relative"):
            parse_manifest(data)

    def test_duplicate_ids_refused(self):
        data = _valid()
        data["expected"][1]["id"] = "case-1"
        with pytest.raises(ManifestError, match="duplicate"):
            parse_manifest(data)

    def test_all_errors_reported_in_one_pass(self):
        data = _valid()
        data["schema_version"] = 99
        data["profile"] = "turbo"
        with pytest.raises(ManifestError) as exc:
            parse_manifest(data)
        assert "schema_version" in str(exc.value)
        assert "profile" in str(exc.value)

    def test_empty_expected_refused(self):
        data = _valid()
        data["expected"] = []
        with pytest.raises(ManifestError, match="non-empty"):
            parse_manifest(data)


class TestLoadManifest:
    def test_round_trip(self, tmp_path):
        path = tmp_path / "m.json"
        path.write_text(json.dumps(_valid()), encoding="utf-8")
        m = load_manifest(path)
        assert m.pinned_sha.startswith("b06d6efa")

    def test_unreadable_file(self, tmp_path):
        with pytest.raises(ManifestError, match="cannot read"):
            load_manifest(tmp_path / "missing.json")

    def test_invalid_json(self, tmp_path):
        path = tmp_path / "m.json"
        path.write_text("{nope", encoding="utf-8")
        with pytest.raises(ManifestError, match="cannot read"):
            load_manifest(path)
