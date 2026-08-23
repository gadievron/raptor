"""OWASP Benchmark manifest generator."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.recall.manifest import parse_manifest
from core.recall.owasp_manifest import (
    OWASP_PINNED_SHA,
    OwaspManifestError,
    generate_manifest,
)

_CSV = """\
# test name, category, real vulnerability, cwe
BenchmarkTest00001,cmdi,true,78
BenchmarkTest00002,cmdi,false,78
BenchmarkTest00003,sqli,true,89
BenchmarkTest00004,xss,true,79
"""


@pytest.fixture
def clone(tmp_path):
    d = tmp_path / "owasp"
    d.mkdir()
    (d / "expectedresults-1.2.csv").write_text(_CSV, encoding="utf-8")
    return d


def _pinned(*_a, **_k):
    return SimpleNamespace(stdout=OWASP_PINNED_SHA + "\n", stderr="",
                           returncode=0)


class TestGenerateManifest:
    def test_tp_expected_fp_clean(self, clone):
        with patch("core.recall.owasp_manifest.subprocess.run", _pinned):
            m = generate_manifest(clone)
        assert {e["id"] for e in m["expected"]} == {
            "BenchmarkTest00001", "BenchmarkTest00003",
            "BenchmarkTest00004"}
        assert [c["id"] for c in m["clean_regions"]] == [
            "BenchmarkTest00002"]
        e = m["expected"][0]
        assert e["file"].endswith("BenchmarkTest00001.java")
        assert e["line_start"] is None  # file-level ground truth
        assert e["cwe"] == "CWE-78"
        assert e["provenance"]["kind"] == "benchmark"

    def test_output_passes_manifest_validation(self, clone):
        with patch("core.recall.owasp_manifest.subprocess.run", _pinned):
            m = generate_manifest(clone)
        parsed = parse_manifest(m)
        assert parsed.language == "java"
        assert parsed.profile == "scan-codeql"

    def test_cwe_filter(self, clone):
        with patch("core.recall.owasp_manifest.subprocess.run", _pinned):
            m = generate_manifest(clone, cwes=[89])
        assert [e["id"] for e in m["expected"]] == ["BenchmarkTest00003"]

    def test_limit_deterministic(self, clone):
        with patch("core.recall.owasp_manifest.subprocess.run", _pinned):
            a = generate_manifest(clone, limit=1)
            b = generate_manifest(clone, limit=1)
        assert a["expected"] == b["expected"]

    def test_missing_clone_names_sources_doc(self, tmp_path):
        with pytest.raises(OwaspManifestError, match="SOURCES.md"):
            generate_manifest(tmp_path / "nope")

    def test_wrong_sha_refused(self, clone):
        wrong = SimpleNamespace(stdout="0" * 40 + "\n", stderr="",
                                returncode=0)
        with patch("core.recall.owasp_manifest.subprocess.run",
                   return_value=wrong), \
             pytest.raises(OwaspManifestError, match="pinned"):
            generate_manifest(clone)

    def test_missing_csv_refused(self, tmp_path):
        d = tmp_path / "owasp"
        d.mkdir()
        with pytest.raises(OwaspManifestError, match="incomplete"):
            generate_manifest(d)
