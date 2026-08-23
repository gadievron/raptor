"""/cve-diff run directories as a live CveFixPair source
(``load_pairs_from_cve_diff_runs`` in ``cvefix_loader``).

The acceptance contract must mirror ``load_pairs``: GitHub-hosted,
requested CWEs, CodeQL languages, resolvable before/after pair —
anything less is skipped, never guessed.
"""

from __future__ import annotations

import json

from core.dataflow.cvefix_loader import (
    CveFixPair,
    infer_language_from_paths,
    load_pairs_from_cve_diff_runs,
)

CVE = "CVE-2024-12345"
FIX = "a" * 40
PARENT = "b" * 40
REPO = "https://github.com/example/proj"


def _osv(cve_id=CVE, fixed=FIX, parent=PARENT, repo=REPO,
         paths=("src/inject.py",), cwe="CWE-89"):
    db = {
        "diff_against": parent,
        "files": [
            {"path": p, "is_test": False,
             "before_source": "x = 1\n", "after_source": "x = 2\n"}
            for p in paths
        ],
    }
    if cwe:
        db["root_cause"] = {"cwe_id": cwe, "summary": "test"}
    return {
        "schema_version": "1.6.0",
        "id": cve_id,
        "references": [{"type": "FIX", "url": f"{repo}/commit/{fixed}"}],
        "affected": [{
            "ranges": [{
                "type": "GIT",
                "repo": repo,
                "events": [{"introduced": "0"}, {"fixed": fixed}],
            }],
        }],
        "database_specific": db,
    }


def _run_dir(tmp_path, osv, name=None):
    out = tmp_path / (name or f"run-{osv['id']}")
    out.mkdir()
    (out / f"{osv['id']}.osv.json").write_text(
        json.dumps(osv), encoding="utf-8",
    )
    return out


def test_happy_path_yields_same_contract_as_sqlite_loader(tmp_path):
    run = _run_dir(tmp_path, _osv())
    pairs = load_pairs_from_cve_diff_runs([run])
    assert pairs == [CveFixPair(
        cve_id=CVE, cwe="CWE-89", repo_url=REPO,
        repo_language="Python", fix_hash=FIX, parent_hash=PARENT,
    )]


def test_skips_record_without_root_cause_cwe(tmp_path):
    run = _run_dir(tmp_path, _osv(cwe=""))
    assert load_pairs_from_cve_diff_runs([run]) == []


def test_skips_record_without_parent_pointer(tmp_path):
    osv = _osv()
    del osv["database_specific"]["diff_against"]
    assert load_pairs_from_cve_diff_runs([_run_dir(tmp_path, osv)]) == []


def test_skips_non_github_repo(tmp_path):
    run = _run_dir(tmp_path, _osv(repo="https://gitlab.com/example/proj"))
    assert load_pairs_from_cve_diff_runs([run]) == []


def test_skips_uninferable_language(tmp_path):
    run = _run_dir(tmp_path, _osv(paths=("configure.ac", "README.rst")))
    assert load_pairs_from_cve_diff_runs([run]) == []


def test_cwe_filter_applies(tmp_path):
    run = _run_dir(tmp_path, _osv(cwe="CWE-416"))
    assert load_pairs_from_cve_diff_runs([run]) == []
    pairs = load_pairs_from_cve_diff_runs([run], cwes=("CWE-416",))
    assert len(pairs) == 1 and pairs[0].cwe == "CWE-416"


def test_provenance_failures_and_limit(tmp_path):
    bad = tmp_path / "empty-run"
    bad.mkdir()
    runs = [
        bad,  # no osv.json — ProvenanceError, skipped
        _run_dir(tmp_path, _osv(cve_id="CVE-2024-10001"), name="r1"),
        _run_dir(tmp_path, _osv(cve_id="CVE-2024-10002"), name="r2"),
    ]
    pairs = load_pairs_from_cve_diff_runs(runs, limit=1)
    assert [p.cve_id for p in pairs] == ["CVE-2024-10001"]


def test_language_majority_vote():
    assert infer_language_from_paths(
        ["a.cc", "b.cpp", "include/x.h"]) == "C++"
    assert infer_language_from_paths(["only.h"]) == "C"
    assert infer_language_from_paths(["Makefile"]) == ""
