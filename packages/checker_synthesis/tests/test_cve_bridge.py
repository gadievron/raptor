"""Tests for the /cve-diff → checker-synthesis bridge.

Pins the provenance gate (public CVE id + fix SHA or refusal), the
mechanical seed derivation (changed pre-image region, snippet cap,
provenance stamp), the ground-truth fixture passthrough into the
refinement loop, and the library promotion path.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from packages.checker_synthesis import Match, SeedBug
from packages.checker_synthesis import synthesise as synth_mod
from packages.checker_synthesis.cve_bridge import (
    CveBridgeReport,
    CveFixFile,
    CveFixRecord,
    ProvenanceError,
    cli_main,
    derive_seeds,
    load_cve_run,
    synthesise_checker_from_cve,
)
from packages.checker_synthesis.models import CheckerSynthesisResult
from packages.checker_synthesis.synthesise import _SEED_SNIPPET_MAX_BYTES

CVE = "CVE-2024-12345"
SHA = "a" * 40

VULN_C = "\n".join([
    "#include <string.h>",
    "void copy(char *dst, const char *src) {",
    "    strcpy(dst, src); /* VULN */",
    "}",
])
FIXED_C = "\n".join([
    "#include <string.h>",
    "void copy(char *dst, const char *src) {",
    "    strlcpy(dst, src, 64); /* FIXED */",
    "}",
])


def _osv(cve_id=CVE, fixed=SHA, files=None, root_cause=None) -> dict:
    db: dict = {
        "files": files if files is not None else [
            {
                "path": "src/copy.c",
                "is_test": False,
                "before_source": VULN_C,
                "after_source": FIXED_C,
            },
        ],
    }
    if root_cause is not None:
        db["root_cause"] = root_cause
    return {
        "schema_version": "1.6.0",
        "id": cve_id,
        "references": [{"type": "FIX", "url": f"https://example.invalid/c/{fixed}"}],
        "affected": [
            {
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": "https://example.invalid/repo",
                        "events": [{"introduced": "0"}, {"fixed": fixed}],
                    }
                ],
            }
        ],
        "database_specific": db,
    }


def _write_run(tmp_path: Path, osv: dict, name: str = f"{CVE}.osv.json") -> Path:
    out = tmp_path / "cve-run"
    out.mkdir(exist_ok=True)
    (out / name).write_text(json.dumps(osv), encoding="utf-8")
    return out


class TestLoadCveRun:
    def test_happy_path(self, tmp_path):
        out = _write_run(tmp_path, _osv())
        record = load_cve_run(out)
        assert record.cve_id == CVE
        assert record.fix_commit == SHA
        assert record.provenance == f"cvefix:{CVE}@{'a' * 12}"
        assert record.files[0].path == "src/copy.c"

    def test_missing_osv_refused(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        with pytest.raises(ProvenanceError, match="no .*osv.json"):
            load_cve_run(empty)

    def test_multiple_osv_refused(self, tmp_path):
        out = _write_run(tmp_path, _osv())
        (out / "CVE-2024-99999.osv.json").write_text(
            json.dumps(_osv(cve_id="CVE-2024-99999")), encoding="utf-8",
        )
        with pytest.raises(ProvenanceError, match="multiple OSV"):
            load_cve_run(out)

    def test_non_cve_id_refused(self, tmp_path):
        out = _write_run(tmp_path, _osv(cve_id="GHSA-xxxx-yyyy"),
                         name="GHSA.osv.json")
        with pytest.raises(ProvenanceError, match="not a CVE identifier"):
            load_cve_run(out)

    def test_missing_fix_sha_refused(self, tmp_path):
        osv = _osv()
        osv["affected"][0]["ranges"][0]["events"] = [{"introduced": "0"}]
        out = _write_run(tmp_path, osv)
        with pytest.raises(ProvenanceError, match="fix-commit"):
            load_cve_run(out)

    def test_malformed_sha_refused(self, tmp_path):
        out = _write_run(tmp_path, _osv(fixed="not-a-sha!"))
        with pytest.raises(ProvenanceError, match="fix-commit"):
            load_cve_run(out)

    def test_root_cause_cwe_extracted(self, tmp_path):
        out = _write_run(tmp_path, _osv(root_cause={
            "cwe_id": "CWE-120", "summary": "unbounded copy",
        }))
        record = load_cve_run(out)
        assert record.cwe == "CWE-120"
        assert "unbounded copy" in record.summary


class TestDeriveSeeds:
    def _record(self, files) -> CveFixRecord:
        return CveFixRecord(
            cve_id=CVE, repository_url="", fix_commit=SHA,
            files=tuple(files),
        )

    def test_seed_from_changed_region(self):
        record = self._record([CveFixFile("src/copy.c", VULN_C, FIXED_C)])
        bundles = derive_seeds(record, cwe="CWE-120")
        assert len(bundles) == 1
        b = bundles[0]
        assert b.seed.file == "src/copy.c"
        # the strcpy line is pre-image line 3
        assert b.seed.line_start == 3
        assert b.seed.line_end == 3
        assert "strcpy" in b.seed.snippet
        assert b.seed.cwe == "CWE-120"
        assert b.seed.provenance == record.provenance
        assert b.positive_text == VULN_C
        assert b.negative_text == FIXED_C

    def test_test_files_and_unsupported_extensions_skipped(self):
        record = self._record([
            CveFixFile("test/test_copy.c", VULN_C, FIXED_C, is_test=True),
            CveFixFile("docs/notes.rst", "a", "b"),
        ])
        assert derive_seeds(record) == []

    def test_unchanged_and_sourceless_files_skipped(self):
        record = self._record([
            CveFixFile("src/same.c", VULN_C, VULN_C),
            CveFixFile("src/empty.c", "", FIXED_C),
        ])
        assert derive_seeds(record) == []

    def test_ranked_by_changed_lines_and_capped(self):
        big_before = "\n".join(f"vuln_{i}();" for i in range(10))
        big_after = "\n".join(f"safe_{i}();" for i in range(10))
        record = self._record([
            CveFixFile("src/small.c", VULN_C, FIXED_C),
            CveFixFile("src/big.c", big_before, big_after),
        ])
        bundles = derive_seeds(record, max_seeds=1)
        assert [b.seed.file for b in bundles] == ["src/big.c"]
        bundles = derive_seeds(record, max_seeds=2)
        assert [b.seed.file for b in bundles] == ["src/big.c", "src/small.c"]

    def test_snippet_capped(self):
        long_line = "x = call_site(); /* pad */" * 40
        before = "\n".join([long_line] * 600 + ["strcpy(dst, src);"])
        after = "\n".join([long_line] * 600 + ["strlcpy(dst, src, 64);"])
        record = self._record([CveFixFile("src/big.c", before, after)])
        bundles = derive_seeds(record)
        assert len(bundles) == 1
        snippet = bundles[0].seed.snippet
        assert len(snippet.encode("utf-8")) <= _SEED_SNIPPET_MAX_BYTES

    def test_explicit_cwe_beats_root_cause(self):
        record = CveFixRecord(
            cve_id=CVE, repository_url="", fix_commit=SHA,
            files=(CveFixFile("src/copy.c", VULN_C, FIXED_C),),
            cwe="CWE-787",
        )
        assert derive_seeds(record)[0].seed.cwe == "CWE-787"
        assert derive_seeds(record, cwe="CWE-120")[0].seed.cwe == "CWE-120"


class TestRefinementPassthrough:
    """The fixture pair must reach the ground-truth control through
    synthesise_with_refinement (the kwarg added for this bridge)."""

    def test_fixtures_reach_ground_truth_control(self, tmp_path, monkeypatch):
        seen: dict = {"fixture_texts": []}

        def fake_run(rule, rule_path, target):
            target = Path(target)
            if target.is_dir():
                return [], []
            text = target.read_text(encoding="utf-8")
            seen["fixture_texts"].append(text)
            if "VULN" in text:
                return [Match(file=str(target), line=1)], []
            return [], []

        monkeypatch.setattr(synth_mod, "_run_engine", fake_run)

        rule_response = {
            "rule_body": (
                "rules:\n"
                "  - id: bridge-test\n"
                "    pattern: strcpy($D, $S)\n"
                "    message: unbounded copy\n"
                "    languages: [c]\n"
                "    severity: ERROR\n"
            ),
            "rationale": "flags unbounded strcpy",
            "test_positive": "strcpy(dst, src); /* VULN */",
            "test_negative": "strlcpy(dst, src, 64); /* FIXED */",
        }

        def llm(prompt, schema, system_prompt):
            return rule_response

        seed = SeedBug(
            file="src/copy.c", function="", line_start=3, line_end=3,
            cwe="CWE-120", reasoning="cve fix", snippet="strcpy(dst, src);",
            provenance=f"cvefix:{CVE}@{'a' * 12}",
        )
        repo = tmp_path / "repo"
        repo.mkdir()
        result = synth_mod.synthesise_with_refinement(
            seed, repo, tmp_path / "out", llm,
            max_iterations=1,
            ground_truth_fixtures=(VULN_C, FIXED_C),
        )
        assert result.rule is not None
        assert result.positive_control
        # ground-truth control ran on the pre-fix AND post-fix texts
        assert any("VULN" in t for t in seen["fixture_texts"])
        assert any("FIXED" in t for t in seen["fixture_texts"])


class TestSynthesiseFromCve:
    def _fake_result(self, seed, tier="library"):
        from packages.checker_synthesis.models import (
            MatchTriage,
            SynthesisedRule,
        )
        rule = SynthesisedRule(
            rule_id="cve-rule-0", engine="semgrep", body="rules: []",
            rationale="", test_positive="p", test_negative="n",
        )
        result = CheckerSynthesisResult(seed=seed, rule=rule)
        result.rule_path = Path("checkers/cve-rule-0.yml")
        result.positive_control = True
        result.dual_control = True
        result.rule_tier = tier
        result.matches = [Match(file="other.c", line=9)]
        result.triage = [MatchTriage(match=result.matches[0], status="variant")]
        return result

    def test_promotes_with_cve_provenance(self, tmp_path, monkeypatch):
        out = _write_run(tmp_path, _osv())
        promoted: dict = {}

        def fake_synth(seed, repo_root, out_dir, llm, **kw):
            assert kw["ground_truth_fixtures"] == (VULN_C, FIXED_C)
            return self._fake_result(seed)

        class FakeEntry:
            rule_id = "cve-rule-0"

        class FakeLibrary:
            def __init__(self, library_dir=None):
                promoted["library_dir"] = library_dir

            def promote(self, result, **kw):
                promoted["source"] = kw.get("source")
                return FakeEntry()

        import packages.checker_synthesis.cve_bridge as bridge_mod
        monkeypatch.setattr(bridge_mod, "synthesise_with_refinement", fake_synth)
        monkeypatch.setattr(bridge_mod, "RuleLibrary", FakeLibrary)

        report = synthesise_checker_from_cve(
            out, tmp_path, tmp_path / "chk", lambda *a: None,
        )
        assert report.cve_id == CVE
        assert report.promoted_rule_ids == ["cve-rule-0"]
        assert promoted["source"] == f"cvefix:{CVE}@{'a' * 12}"

    def test_sweep_once_not_promoted(self, tmp_path, monkeypatch):
        out = _write_run(tmp_path, _osv())

        def fake_synth(seed, repo_root, out_dir, llm, **kw):
            return self._fake_result(seed, tier="sweep_once")

        class RefusingLibrary:
            def __init__(self, library_dir=None):
                pass

            def promote(self, result, **kw):
                # mirrors RuleLibrary: sub-library tiers are refused
                return None if result.rule_tier != "library" else object()

        import packages.checker_synthesis.cve_bridge as bridge_mod
        monkeypatch.setattr(bridge_mod, "synthesise_with_refinement", fake_synth)
        monkeypatch.setattr(bridge_mod, "RuleLibrary", RefusingLibrary)

        report = synthesise_checker_from_cve(
            out, tmp_path, tmp_path / "chk", lambda *a: None,
        )
        assert report.promoted_rule_ids == []

    def test_no_seeds_reported(self, tmp_path):
        out = _write_run(tmp_path, _osv(files=[]))
        report = synthesise_checker_from_cve(
            out, tmp_path, tmp_path / "chk", lambda *a: None,
        )
        assert report.seeds_derived == 0
        assert any("no synthesis seeds" in e for e in report.errors)

    def test_report_serialisable(self):
        assert CveBridgeReport(cve_id=CVE).to_dict()["cve_id"] == CVE


class TestCliMain:
    def test_provenance_refusal_exit_2_before_llm(self, tmp_path, monkeypatch):
        import packages.checker_synthesis.cve_bridge as bridge_mod

        def boom():
            raise AssertionError("LLM must not be built for a refused run")

        monkeypatch.setattr(bridge_mod, "_build_llm", boom)
        empty = tmp_path / "empty"
        empty.mkdir()
        rc = cli_main([str(empty), "--repo", str(tmp_path)])
        assert rc == 2

    def test_missing_repo_exit_2(self, tmp_path):
        out = _write_run(tmp_path, _osv())
        rc = cli_main([str(out), "--repo", str(tmp_path / "nope")])
        assert rc == 2

    def test_no_llm_exit_3(self, tmp_path, monkeypatch):
        import packages.checker_synthesis.cve_bridge as bridge_mod

        monkeypatch.setattr(bridge_mod, "_build_llm", lambda: None)
        out = _write_run(tmp_path, _osv())
        rc = cli_main([str(out), "--repo", str(tmp_path)])
        assert rc == 3

    def test_happy_path_prints_report(self, tmp_path, monkeypatch, capsys):
        import packages.checker_synthesis.cve_bridge as bridge_mod

        monkeypatch.setattr(bridge_mod, "_build_llm", lambda: (lambda *a: None))
        monkeypatch.setattr(
            bridge_mod, "synthesise_checker_from_cve",
            lambda *a, **kw: CveBridgeReport(cve_id=CVE, fix_commit=SHA),
        )
        out = _write_run(tmp_path, _osv())
        rc = cli_main([str(out), "--repo", str(tmp_path), "--no-promote"])
        assert rc == 0
        report = json.loads(capsys.readouterr().out)
        assert report["cve_id"] == CVE
