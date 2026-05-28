"""Tests for the CVEfixes metadata loader (synthetic fixture DB)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from core.dataflow.cvefix_loader import _single_parent, load_pairs


def _make_db(path: Path) -> None:
    con = sqlite3.connect(str(path))
    con.executescript(
        "CREATE TABLE cwe_classification (cve_id TEXT, cwe_id TEXT);"
        "CREATE TABLE fixes (cve_id TEXT, hash TEXT, repo_url TEXT);"
        "CREATE TABLE commits (hash TEXT, repo_url TEXT, parents TEXT);"
        "CREATE TABLE repository (repo_url TEXT, repo_name TEXT, repo_language TEXT);"
    )

    def add(cve, cwe, repo, h, parents, lang):
        con.execute("INSERT INTO cwe_classification VALUES(?,?)", (cve, cwe))
        con.execute("INSERT INTO fixes VALUES(?,?,?)", (cve, h, repo))
        con.execute("INSERT INTO commits VALUES(?,?,?)", (h, repo, parents))
        con.execute("INSERT INTO repository VALUES(?,?,?)", (repo, repo.split("/")[-1], lang))

    G = "https://github.com/org/"
    # good: Python SQLi, single parent, github  -> loads
    add("CVE-GOOD", "CWE-89", G + "py-app", "fix1", "['par1']", "Python")
    # PHP -> filtered by language
    add("CVE-PHP", "CWE-89", G + "php-app", "fix2", "['par2']", "PHP")
    # merge commit (2 parents) -> filtered (ambiguous before-state)
    add("CVE-MERGE", "CWE-78", G + "go-app", "fix3", "['pa', 'pb']", "Go")
    # non-github -> filtered
    add("CVE-GL", "CWE-79", "https://gitlab.com/org/x", "fix4", "['par4']", "Java")
    # non-injection CWE -> filtered by cwe set
    add("CVE-OTHER", "CWE-476", G + "java-app", "fix5", "['par5']", "Java")
    con.commit()
    con.close()


def test_loads_only_codeql_lang_single_parent_github_injection(tmp_path: Path):
    db = tmp_path / "meta.db"
    _make_db(db)
    pairs = load_pairs(db)
    assert len(pairs) == 1
    p = pairs[0]
    assert p.cve_id == "CVE-GOOD"
    assert p.cwe == "CWE-89"
    assert p.repo_language == "Python"
    assert p.fix_hash == "fix1"
    assert p.parent_hash == "par1"


def test_language_filter_excludes_php(tmp_path: Path):
    db = tmp_path / "meta.db"
    _make_db(db)
    # widen CWEs but PHP must still be excluded (no CodeQL extractor)
    cves = {p.cve_id for p in load_pairs(db, cwes=("CWE-89", "CWE-78", "CWE-79"))}
    assert "CVE-PHP" not in cves


def test_cwe_filter(tmp_path: Path):
    db = tmp_path / "meta.db"
    _make_db(db)
    # CVE-OTHER (CWE-476, single-parent github Java) is excluded by the default
    # injection CWE set, but loads when its CWE is explicitly requested.
    assert "CVE-OTHER" not in {p.cve_id for p in load_pairs(db)}
    cves = {p.cve_id for p in load_pairs(db, cwes=("CWE-476",), languages=("Java",))}
    assert cves == {"CVE-OTHER"}


def test_single_parent_helper():
    assert _single_parent("['abc']") == "abc"
    assert _single_parent("['a', 'b']") is None   # merge
    assert _single_parent("[]") is None            # root
    assert _single_parent("garbage") is None
    assert _single_parent(None) is None
