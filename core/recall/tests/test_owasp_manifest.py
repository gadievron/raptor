"""OWASP Benchmark manifest generator."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.recall.manifest import parse_manifest
from core.recall.owasp_manifest import (
    OWASP_PINNED_SHA,
    OwaspManifestError,
    generate_manifest,
    generate_per_cwe_manifests,
    main as om_main,
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
        with patch("core.recall.pinned_clone.subprocess.run", _pinned):
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
        with patch("core.recall.pinned_clone.subprocess.run", _pinned):
            m = generate_manifest(clone)
        parsed = parse_manifest(m)
        assert parsed.language == "java"
        assert parsed.profile == "scan-codeql"

    def test_cwe_filter(self, clone):
        with patch("core.recall.pinned_clone.subprocess.run", _pinned):
            m = generate_manifest(clone, cwes=[89])
        assert [e["id"] for e in m["expected"]] == ["BenchmarkTest00003"]

    def test_limit_deterministic(self, clone):
        with patch("core.recall.pinned_clone.subprocess.run", _pinned):
            a = generate_manifest(clone, limit=1)
            b = generate_manifest(clone, limit=1)
        assert a["expected"] == b["expected"]

    def test_missing_clone_names_sources_doc(self, tmp_path):
        with pytest.raises(OwaspManifestError, match="SOURCES.md"):
            generate_manifest(tmp_path / "nope")

    def test_wrong_sha_refused(self, clone):
        wrong = SimpleNamespace(stdout="0" * 40 + "\n", stderr="",
                                returncode=0)
        with patch("core.recall.pinned_clone.subprocess.run",
                   return_value=wrong), \
             pytest.raises(OwaspManifestError, match="pinned"):
            generate_manifest(clone)

    def test_missing_csv_refused(self, tmp_path):
        d = tmp_path / "owasp"
        d.mkdir()
        with pytest.raises(OwaspManifestError, match="incomplete"):
            generate_manifest(d)


_CSV_FP_ONLY_CWE = _CSV + "BenchmarkTest00005,ldapi,false,90\n"


class TestPerCwe:
    def test_split_partitions_by_cwe(self, clone):
        with patch("core.recall.pinned_clone.subprocess.run", _pinned):
            per = generate_per_cwe_manifests(clone)
        assert sorted(per) == [78, 79, 89]
        m78 = per[78]
        assert m78["name"] == "owasp-benchmark-java-cwe78"
        assert [e["id"] for e in m78["expected"]] == ["BenchmarkTest00001"]
        assert [c["id"] for c in m78["clean_regions"]] == [
            "BenchmarkTest00002"]
        assert per[89]["clean_regions"] == []

    def test_each_manifest_validates(self, clone):
        with patch("core.recall.pinned_clone.subprocess.run", _pinned):
            per = generate_per_cwe_manifests(clone)
        for m in per.values():
            parsed = parse_manifest(m)
            assert parsed.profile == "scan-codeql"

    def test_entries_carried_verbatim(self, clone):
        """Split entries are the combined manifest's dicts, never
        rebuilt — keys a future label shape adds must pass through."""
        with patch("core.recall.pinned_clone.subprocess.run", _pinned):
            combined = generate_manifest(clone)
            per = generate_per_cwe_manifests(clone)
        split = [e for m in per.values() for e in m["expected"]]
        assert sorted(json.dumps(e, sort_keys=True) for e in split) == \
            sorted(json.dumps(e, sort_keys=True)
                   for e in combined["expected"])

    def test_all_clean_cwe_becomes_fp_only(self, tmp_path):
        d = tmp_path / "owasp"
        d.mkdir()
        (d / "expectedresults-1.2.csv").write_text(
            _CSV_FP_ONLY_CWE, encoding="utf-8")
        with patch("core.recall.pinned_clone.subprocess.run", _pinned):
            per = generate_per_cwe_manifests(d)
        m90 = per[90]
        assert m90["corpus_kind"] == "fp-only"
        assert m90["expected"] == []
        assert len(m90["clean_regions"]) == 1
        parsed = parse_manifest(m90)
        assert parsed.corpus_kind == "fp-only"

    def test_cli_per_cwe_writes_one_file_per_class(self, clone,
                                                   tmp_path, capsys):
        out_dir = tmp_path / "per-cwe"
        with patch("core.recall.pinned_clone.subprocess.run", _pinned):
            rc = om_main(["--clone-dir", str(clone), "--per-cwe",
                          "--out-dir", str(out_dir)])
        assert rc == 0
        names = sorted(p.name for p in out_dir.glob("*.json"))
        assert names == ["owasp-benchmark-java-cwe78.json",
                         "owasp-benchmark-java-cwe79.json",
                         "owasp-benchmark-java-cwe89.json"]
        assert "expected" in capsys.readouterr().out

    def test_cli_per_cwe_requires_out_dir(self, clone):
        with pytest.raises(SystemExit):
            om_main(["--clone-dir", str(clone), "--per-cwe"])

    def test_cli_single_mode_requires_out(self, clone):
        with pytest.raises(SystemExit):
            om_main(["--clone-dir", str(clone)])
