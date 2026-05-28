"""Tests for the CVEfixes CodeQL walker (git/CodeQL steps stubbed)."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.dataflow import cvefix_walk
from core.dataflow.cvefix_loader import CveFixPair
from core.dataflow.cvefix_walk import WalkResult, process_pair, promote_misses, query_for, walk


def test_query_for_maps_lang_and_cwe():
    assert query_for("Python", "CWE-89") == "codeql/python-queries:Security/CWE-089/SqlInjection.ql"
    # TS routes through the javascript pack; CWE-22 uses TaintedPath (not PathInjection).
    assert query_for("TypeScript", "CWE-22") == "codeql/javascript-queries:Security/CWE-022/TaintedPath.ql"
    assert query_for("Python", "CWE-22") == "codeql/python-queries:Security/CWE-022/PathInjection.ql"
    assert query_for("Python", "CWE-999") is None
    # Ruby: distinct pack + lowercase path scheme + ReflectedXSS (not ReflectedXss).
    assert query_for("Ruby", "CWE-89") == "codeql/ruby-queries:queries/security/cwe-089/SqlInjection.ql"
    assert query_for("Ruby", "CWE-79") == "codeql/ruby-queries:queries/security/cwe-079/ReflectedXSS.ql"
    # Java: java-queries, Security/CWE/CWE-0XX path level, ExecTainted for cmdi.
    assert query_for("Java", "CWE-78") == "codeql/java-queries:Security/CWE/CWE-078/ExecTainted.ql"


def test_process_pair_build_mode_autopick(monkeypatch, tmp_path: Path):
    seen = {}
    monkeypatch.setattr(cvefix_walk, "_fetch_pair", lambda *a, **k: True)

    def fake_build(src, commit, db, lang, codeql_bin, timeout, build_mode=None):
        seen["lang"], seen["mode"] = lang, build_mode
        return True

    monkeypatch.setattr(cvefix_walk, "_build_db", fake_build)
    monkeypatch.setattr(cvefix_walk, "_count_query", lambda *a, **k: 0)
    java = CveFixPair("CVE-J", "CWE-89", "https://github.com/o/a", "Java", "fJ", "pJ")
    py = CveFixPair("CVE-P", "CWE-89", "https://github.com/o/p", "Python", "fP", "pP")
    process_pair(java, work_dir=tmp_path)
    assert seen["lang"] == "java" and seen["mode"] == "none"   # buildless-compiled
    process_pair(py, work_dir=tmp_path)
    assert seen["mode"] is None                                 # source lang, no flag
    process_pair(java, work_dir=tmp_path, build_mode="autobuild")
    assert seen["mode"] == "autobuild"                          # explicit override (promote)


def _pair(cwe="CWE-89", lang="Python", fix="fix1"):
    return CveFixPair("CVE-X", cwe, "https://github.com/org/app", lang, fix, "par1")


def test_process_pair_yield(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(cvefix_walk, "_fetch_pair", lambda *a, **k: True)
    monkeypatch.setattr(cvefix_walk, "_build_db", lambda *a, **k: True)
    # _count_query called for after-db first, then before-db.
    counts = iter([1, 3])
    monkeypatch.setattr(cvefix_walk, "_count_query", lambda *a, **k: next(counts))
    res = process_pair(_pair(), work_dir=tmp_path)
    assert res.status == "ok"
    assert res.after_count == 1 and res.before_count == 3
    assert res.is_yield and res.is_fp_candidate


def test_process_pair_build_fail(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(cvefix_walk, "_fetch_pair", lambda *a, **k: True)
    monkeypatch.setattr(cvefix_walk, "_build_db", lambda *a, **k: False)
    res = process_pair(_pair(), work_dir=tmp_path)
    assert res.status == "build_fail"
    assert not res.is_yield


def test_process_pair_no_query(tmp_path: Path):
    res = process_pair(_pair(cwe="CWE-999"), work_dir=tmp_path)
    assert res.status == "no_query"


def _make_meta_db(path: Path):
    con = sqlite3.connect(str(path))
    con.executescript(
        "CREATE TABLE cwe_classification (cve_id TEXT, cwe_id TEXT);"
        "CREATE TABLE fixes (cve_id TEXT, hash TEXT, repo_url TEXT);"
        "CREATE TABLE commits (hash TEXT, repo_url TEXT, parents TEXT);"
        "CREATE TABLE repository (repo_url TEXT, repo_name TEXT, repo_language TEXT);"
    )
    G = "https://github.com/org/"
    for i in (1, 2):
        repo, h = f"{G}app{i}", f"fix{i}"
        con.execute("INSERT INTO cwe_classification VALUES(?,?)", ("CVE-%d" % i, "CWE-89"))
        con.execute("INSERT INTO fixes VALUES(?,?,?)", ("CVE-%d" % i, h, repo))
        con.execute("INSERT INTO commits VALUES(?,?,?)", (h, repo, "['par%d']" % i))
        con.execute("INSERT INTO repository VALUES(?,?,?)", (repo, "app%d" % i, "Python"))
    con.commit()
    con.close()


def test_walk_records_and_resumes(monkeypatch, tmp_path: Path):
    meta, results = tmp_path / "meta.db", tmp_path / "results.db"
    _make_meta_db(meta)
    calls = []

    def fake_process(pair, **kw):
        calls.append(pair.fix_hash)
        return WalkResult(pair.fix_hash, "ok", before_count=2, after_count=1)

    monkeypatch.setattr(cvefix_walk, "process_pair", fake_process)
    summ = walk(meta, results, work_dir=tmp_path / "w", log=lambda *a: None)
    assert summ == {"total": 2, "yield": 2, "fp_candidate": 2}
    assert len(calls) == 2

    # Second walk: everything already recorded -> nothing reprocessed.
    calls.clear()
    walk(meta, results, work_dir=tmp_path / "w", log=lambda *a: None)
    assert calls == []
    with sqlite3.connect(str(results)) as con:
        assert con.execute("SELECT count(*) FROM walk_results").fetchone()[0] == 2


def test_walk_keeps_both_cwes_of_one_commit(monkeypatch, tmp_path: Path):
    """One fix commit mapped to two CWEs must produce two rows, not collapse."""
    meta, results = tmp_path / "meta.db", tmp_path / "results.db"
    con = sqlite3.connect(str(meta))
    con.executescript(
        "CREATE TABLE cwe_classification (cve_id TEXT, cwe_id TEXT);"
        "CREATE TABLE fixes (cve_id TEXT, hash TEXT, repo_url TEXT);"
        "CREATE TABLE commits (hash TEXT, repo_url TEXT, parents TEXT);"
        "CREATE TABLE repository (repo_url TEXT, repo_name TEXT, repo_language TEXT);"
    )
    repo = "https://github.com/org/app"
    con.execute("INSERT INTO fixes VALUES(?,?,?)", ("CVE-1", "fixA", repo))
    con.execute("INSERT INTO commits VALUES(?,?,?)", ("fixA", repo, "['parA']"))
    con.execute("INSERT INTO repository VALUES(?,?,?)", (repo, "app", "Python"))
    con.execute("INSERT INTO cwe_classification VALUES(?,?)", ("CVE-1", "CWE-89"))
    con.execute("INSERT INTO cwe_classification VALUES(?,?)", ("CVE-1", "CWE-79"))
    con.commit()
    con.close()

    monkeypatch.setattr(
        cvefix_walk, "process_pair",
        lambda pair, **kw: WalkResult(pair.fix_hash, "ok", before_count=1, after_count=1),
    )
    cvefix_walk.walk(meta, results, work_dir=tmp_path / "w", log=lambda *a: None)
    with sqlite3.connect(str(results)) as con:
        rows = con.execute(
            "SELECT cwe FROM walk_results WHERE fix_hash='fixA' ORDER BY cwe").fetchall()
    assert [r[0] for r in rows] == ["CWE-79", "CWE-89"]  # both kept, not collapsed


def test_promote_updates_only_on_recovery(monkeypatch, tmp_path: Path):
    results = tmp_path / "r.db"
    con = sqlite3.connect(str(results))
    con.execute(cvefix_walk._SCHEMA)

    def ins(fix, cwe, before):
        con.execute("INSERT INTO walk_results VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (fix, "CVE-" + fix, cwe, "Java", "https://github.com/o/a",
                     fix + "p", "ok", before, 0, 0.0))
    ins("f1", "CWE-89", 0)   # buildless miss -> autobuild recovers it
    ins("f2", "CWE-79", 0)   # buildless miss -> autobuild still finds nothing
    ins("f3", "CWE-22", 2)   # already yields -> not a promote candidate
    con.commit()
    con.close()

    def fake(pair, **kw):
        assert kw.get("build_mode") == "autobuild"
        if pair.fix_hash == "f1":
            return WalkResult("f1", "ok", before_count=5, after_count=3)
        return WalkResult(pair.fix_hash, "ok", before_count=0, after_count=0)

    monkeypatch.setattr(cvefix_walk, "process_pair", fake)
    summ = promote_misses(results, work_dir=tmp_path / "w", log=lambda *a: None)
    assert summ == {"candidates": 2, "promoted": 1}             # f3 not a candidate
    with sqlite3.connect(str(results)) as con:
        got = {r[0]: (r[1], r[2], r[3]) for r in con.execute(
            "SELECT fix_hash, status, before_count, after_count FROM walk_results")}
    assert got["f1"] == ("ok_built", 5, 3)                     # promoted
    assert got["f2"] == ("ok", 0, 0)                           # unchanged (graceful)
    assert got["f3"] == ("ok", 2, 0)                           # untouched


def test_run_passes_safe_env(monkeypatch):
    from core.config import RaptorConfig
    monkeypatch.setattr(RaptorConfig, "get_safe_env", staticmethod(lambda *a, **k: {"SENT": "1"}))
    captured = {}

    def fake_run(cmd, **kw):
        captured.update(kw)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(cvefix_walk.subprocess, "run", fake_run)
    assert cvefix_walk._run(["true"], 5) is True
    assert captured["env"] == {"SENT": "1"}            # sanitised env, not os.environ


def test_autobuild_fails_closed_without_sandbox(monkeypatch):
    """Untrusted autobuild must REFUSE rather than run unsandboxed."""
    import core.sandbox as sb
    monkeypatch.setattr(sb, "check_landlock_available", lambda: False)
    with pytest.raises(RuntimeError, match="refusing to autobuild"):
        cvefix_walk._run_autobuild_sandboxed(
            ["codeql", "database", "create"], work_root=Path("/tmp/x"),
            codeql_bin="codeql", timeout=10)


def test_walk_limit(monkeypatch, tmp_path: Path):
    meta, results = tmp_path / "meta.db", tmp_path / "results.db"
    _make_meta_db(meta)
    monkeypatch.setattr(
        cvefix_walk, "process_pair",
        lambda pair, **kw: WalkResult(pair.fix_hash, "ok", before_count=0, after_count=0),
    )
    walk(meta, results, work_dir=tmp_path / "w", limit=1, log=lambda *a: None)
    with sqlite3.connect(str(results)) as con:
        assert con.execute("SELECT count(*) FROM walk_results").fetchone()[0] == 1
