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

    def fake_build(src, commit, db, lang, codeql_bin, timeout, build_mode=None, tunables=None):
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
            codeql_bin="codeql", timeout=10, lang="java")


def test_autobuild_rejects_lang_without_profile(monkeypatch):
    """Adding a compiled language must be intentional — a missing profile
    raises rather than silently routing to Maven's hosts."""
    import core.sandbox as sb
    monkeypatch.setattr(sb, "check_landlock_available", lambda: True)
    with pytest.raises(RuntimeError, match="no autobuild profile for lang='cpp'"):
        cvefix_walk._run_autobuild_sandboxed(
            ["codeql", "database", "create"], work_root=Path("/tmp/x"),
            codeql_bin="codeql", timeout=10, lang="cpp")


def test_query_for_maps_go():
    """Go pack uses the Security/CWE-0XX/ scheme (like JS/Python) with
    ReflectedXss (no second-s capital) and TaintedPath for path-traversal."""
    assert query_for("Go", "CWE-89") == "codeql/go-queries:Security/CWE-089/SqlInjection.ql"
    assert query_for("Go", "CWE-78") == "codeql/go-queries:Security/CWE-078/CommandInjection.ql"
    assert query_for("Go", "CWE-79") == "codeql/go-queries:Security/CWE-079/ReflectedXss.ql"
    assert query_for("Go", "CWE-22") == "codeql/go-queries:Security/CWE-022/TaintedPath.ql"
    assert query_for("Go", "CWE-918") == "codeql/go-queries:Security/CWE-918/RequestForgery.ql"
    # Go pack has no CodeInjection.ql — matches the Java omission convention.
    assert query_for("Go", "CWE-94") is None


def test_process_pair_routes_go_through_autobuild(monkeypatch, tmp_path: Path):
    """Go has no buildless extractor; default mode must be ``autobuild``
    so the walker uses the sandboxed path instead of running ``go build``
    unsandboxed.  Compare with Java's default ``none`` and Python's no-flag."""
    seen = {}
    monkeypatch.setattr(cvefix_walk, "_fetch_pair", lambda *a, **k: True)

    def fake_build(src, commit, db, lang, codeql_bin, timeout, build_mode=None, tunables=None):
        seen["lang"], seen["mode"] = lang, build_mode
        return True

    monkeypatch.setattr(cvefix_walk, "_build_db", fake_build)
    monkeypatch.setattr(cvefix_walk, "_count_query", lambda *a, **k: 0)
    go = CveFixPair("CVE-G", "CWE-89", "https://github.com/o/g", "Go", "fG", "pG")
    process_pair(go, work_dir=tmp_path)
    assert seen["lang"] == "go" and seen["mode"] == "autobuild"


def test_go_autobuild_env_redirects_module_cache(tmp_path: Path):
    """The Go autobuild env extender must redirect every Go cache/path
    into the work area so the sandboxed build doesn't escape Landlock's
    allow-write set.  GOCACHE was the load-bearing miss in the first
    Go walk — its absence caused 100% build_fail on 82 pairs."""
    env = cvefix_walk._go_autobuild_env(tmp_path)
    assert env["GOMODCACHE"] == str(tmp_path / "go-mod-cache")
    assert env["GOPATH"] == str(tmp_path / "gopath")
    assert env["GOCACHE"] == str(tmp_path / "go-build-cache")
    # -mod=mod allows the build to download missing modules; -mod=readonly
    # (the default in newer Go versions) would fail-closed without go.sum.
    assert env["GOFLAGS"] == "-mod=mod"


def test_autobuild_profiles_have_distinct_proxy_hosts():
    """Soundness check: the Java + Go profiles must NOT share a proxy host
    set — a copy/paste here would silently mis-route one language's
    module downloads, looking like build failures.

    Use ``set(...) >= {...}`` for the canonical-host membership checks
    rather than ``"host" in hosts_var``: CodeQL's
    ``py/incomplete-url-substring-sanitization`` FP-flags the latter on
    any list var that carries hostname-shaped strings.  Same FP class
    as the auth-vocab cleartext-logging issue — see memory
    ``feedback-codeql-cleartext-logging-auth-vocab-fp``.
    """
    java_set, _ = cvefix_walk._AUTOBUILD_PROFILES["java"]
    go_set, _ = cvefix_walk._AUTOBUILD_PROFILES["go"]
    assert set(java_set).isdisjoint(set(go_set)), \
        f"profiles share entries: {set(java_set) & set(go_set)}"
    assert set(go_set) >= {"proxy.golang.org"}
    assert set(java_set) >= {"repo.maven.apache.org"}


def test_clean_go_caches_removes_readonly_module_cache(tmp_path: Path):
    """Regression: Go's ``GOMODCACHE`` is read-only by design (proxy treats
    cache contents as immutable), so a plain rmtree silently leaves it
    behind.  Without recursive ``S_IWUSR`` chmod before rmtree, modules
    cached from one project's `replace` directives corrupt the next
    project's build — surfaced as 42/82 walks regressing build_fail in
    the overnight v3 walk on 2026-06-01."""
    # Build a mini-cache shaped like Go's: read-only files at all depths.
    cache = tmp_path / "go-mod-cache" / "rsc.io" / "quote@v1.5.2"
    cache.mkdir(parents=True)
    (cache / "go.mod").write_text("module rsc.io/quote\n")
    (cache / "quote.go").write_text("package quote\n")
    # Mark everything read-only as Go does.
    for p in cache.rglob("*"):
        if not p.is_symlink():
            import stat
            p.chmod(p.stat().st_mode & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH)
    # Sanity-check that a plain rmtree would fail.
    cvefix_walk._clean_go_caches(tmp_path)
    assert not (tmp_path / "go-mod-cache").exists(), \
        "_clean_go_caches must remove the read-only cache tree"


def test_clean_go_caches_skips_missing_dirs(tmp_path: Path):
    """No cache dirs present (e.g. first pair, or non-Go walk): no-op,
    not an error."""
    cvefix_walk._clean_go_caches(tmp_path)        # must not raise


def test_clean_go_caches_handles_all_three_locations(tmp_path: Path):
    """Pin that the cleanup walks every cache location the env-extender
    creates — GOMODCACHE, GOPATH, GOCACHE.  A missing one would leak
    state across pairs and silently re-introduce the corruption bug."""
    for sub in ("go-mod-cache", "gopath", "go-build-cache"):
        (tmp_path / sub).mkdir(parents=True)
        (tmp_path / sub / "marker").write_text("x")
    cvefix_walk._clean_go_caches(tmp_path)
    for sub in ("go-mod-cache", "gopath", "go-build-cache"):
        assert not (tmp_path / sub).exists(), f"{sub} not cleaned"


def test_codeql_tunables_appends_threads_unconditionally(tmp_path: Path):
    """``-j`` is always passed (we changed the codeql default of 1
    because it serializes the secondary HTML/JS extractor phase).
    Threads=0 means all-cores per the codeql docs."""
    t = cvefix_walk.CodeQLTunables()
    cmd = ["codeql", "database", "create"]
    t.append_to(cmd, include_disk_cache=True)
    assert "-j" in cmd and "0" in cmd
    # ram and max-disk-cache are unset (None) -> NOT appended.
    assert "-M" not in cmd
    assert not any(c.startswith("--max-disk-cache=") for c in cmd)


def test_codeql_tunables_with_ram_and_disk(tmp_path: Path):
    t = cvefix_walk.CodeQLTunables(threads=4, ram_mb=8192, max_disk_cache_mb=2048)
    cmd = ["codeql", "database", "create"]
    t.append_to(cmd, include_disk_cache=True)
    assert ["-j", "4"] == cmd[3:5]
    assert "-M" in cmd and "8192" in cmd
    assert "--max-disk-cache=2048" in cmd


def test_codeql_tunables_from_tuning_resolves_central_defaults(monkeypatch):
    """``CodeQLTunables.from_tuning()`` must source threads + ram from
    ``core.tuning``'s resolved config (the same source the rest of
    RAPTOR's CodeQL consumers use).  Pin the integration so a typo or
    schema rename here doesn't silently revert to baked-in defaults."""
    import core.tuning
    from core.tuning import Tuning

    fake_tuning = Tuning(
        codeql_enabled=True,
        codeql_ram_mb=8192, codeql_threads=12,
        codeql_max_disk_cache_mb=0,
        max_semgrep_workers=4, max_codeql_workers=2,
        max_agentic_parallel=3, max_fuzz_parallel=4,
        max_inventory_workers=4, max_json_memo_mb=128,
    )
    monkeypatch.setattr(core.tuning, "get_tuning", lambda: fake_tuning)
    t = cvefix_walk.CodeQLTunables.from_tuning()
    assert t.threads == 12
    assert t.ram_mb == 8192


def test_codeql_tunables_from_tuning_operator_override_wins(monkeypatch):
    """Operator CLI args override tuning defaults — non-None values
    in the overrides dict take precedence per field."""
    import core.tuning
    from core.tuning import Tuning

    fake_tuning = Tuning(
        codeql_enabled=True,
        codeql_ram_mb=8192, codeql_threads=12,
        codeql_max_disk_cache_mb=0,
        max_semgrep_workers=4, max_codeql_workers=2,
        max_agentic_parallel=3, max_fuzz_parallel=4,
        max_inventory_workers=4, max_json_memo_mb=128,
    )
    monkeypatch.setattr(core.tuning, "get_tuning", lambda: fake_tuning)
    # Override only threads; ram stays at tuning value.
    t = cvefix_walk.CodeQLTunables.from_tuning(
        overrides={"threads": 4, "ram_mb": None})
    assert t.threads == 4         # operator override
    assert t.ram_mb == 8192       # tuning default


def test_codeql_tunables_analyze_path_omits_max_disk_cache():
    """``codeql database analyze`` rejects --max-disk-cache as an unknown
    option; pin that the include_disk_cache=False path omits it so the
    analyze step doesn't fail with a flag error."""
    t = cvefix_walk.CodeQLTunables(max_disk_cache_mb=2048)
    cmd = ["codeql", "database", "analyze"]
    t.append_to(cmd, include_disk_cache=False)
    assert not any(c.startswith("--max-disk-cache=") for c in cmd)


def test_build_db_passes_tunables_into_create_command(monkeypatch, tmp_path: Path):
    """End-to-end pin: when an operator passes a tunables object, the
    codeql invocation includes the resource flags."""
    captured: dict = {}

    def fake_run(cmd, timeout):
        captured["cmd"] = list(cmd)
        return True

    monkeypatch.setattr(cvefix_walk, "_run", fake_run)
    src = tmp_path / "src"
    src.mkdir()
    db = tmp_path / "db"
    t = cvefix_walk.CodeQLTunables(threads=8, ram_mb=4096, max_disk_cache_mb=1024)
    ok = cvefix_walk._build_db(src, "abc", db, "python", "codeql", 120, None, tunables=t)
    assert ok
    cmd = captured["cmd"]
    # _run was called twice (git checkout + codeql); the codeql one is captured last.
    assert "-j" in cmd and "8" in cmd
    assert "-M" in cmd and "4096" in cmd
    assert "--max-disk-cache=1024" in cmd


def test_process_pair_finally_cleans_go_caches_after_each_pair(
        monkeypatch, tmp_path: Path):
    """End-to-end: process_pair must invoke _clean_go_caches for Go pairs
    so a stuck cache from pair N doesn't corrupt pair N+1.  Counter-
    test: Python pair must NOT trigger the cleanup (no-op also fine but
    pin the per-lang dispatch)."""
    monkeypatch.setattr(cvefix_walk, "_fetch_pair", lambda *a, **k: True)
    monkeypatch.setattr(cvefix_walk, "_build_db", lambda *a, **k: True)
    monkeypatch.setattr(cvefix_walk, "_count_query", lambda *a, **k: 0)
    cleaned: list = []
    monkeypatch.setattr(
        cvefix_walk, "_clean_go_caches",
        lambda wd: cleaned.append(("go", wd)),
    )
    go = CveFixPair("CVE-G", "CWE-89", "https://github.com/o/g", "Go", "fG", "pG")
    py = CveFixPair("CVE-P", "CWE-89", "https://github.com/o/p", "Python", "fP", "pP")
    process_pair(go, work_dir=tmp_path)
    process_pair(py, work_dir=tmp_path)
    # Go pair triggers cleanup; Python pair does not.
    assert cleaned == [("go", tmp_path)], cleaned


def test_walk_dedups_same_commit_cwe_across_cves(monkeypatch, tmp_path: Path):
    """One commit credited to two CVE ids (same fix_hash+cwe) is processed once."""
    meta, results = tmp_path / "meta.db", tmp_path / "results.db"
    con = sqlite3.connect(str(meta))
    con.executescript(
        "CREATE TABLE cwe_classification (cve_id TEXT, cwe_id TEXT);"
        "CREATE TABLE fixes (cve_id TEXT, hash TEXT, repo_url TEXT);"
        "CREATE TABLE commits (hash TEXT, repo_url TEXT, parents TEXT);"
        "CREATE TABLE repository (repo_url TEXT, repo_name TEXT, repo_language TEXT);"
    )
    repo = "https://github.com/org/app"
    con.execute("INSERT INTO commits VALUES(?,?,?)", ("fixA", repo, "['parA']"))
    con.execute("INSERT INTO repository VALUES(?,?,?)", (repo, "app", "Python"))
    for cve in ("CVE-1", "CVE-2"):                     # same commit, same CWE, two CVEs
        con.execute("INSERT INTO cwe_classification VALUES(?,?)", (cve, "CWE-89"))
        con.execute("INSERT INTO fixes VALUES(?,?,?)", (cve, "fixA", repo))
    con.commit()
    con.close()

    calls = []
    monkeypatch.setattr(cvefix_walk, "process_pair",
                        lambda pair, **kw: calls.append(pair.fix_hash) or
                        WalkResult(pair.fix_hash, "ok", before_count=1, after_count=1))
    cvefix_walk.walk(meta, results, work_dir=tmp_path / "w", log=lambda *a: None)
    assert calls == ["fixA"]                            # processed once, not twice


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
