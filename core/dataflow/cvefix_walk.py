"""Walk a CVEfixes metadata DB: drive each fix pair through CodeQL, harvest yielders.

For each CWE-filtered, CodeQL-language fix pair (from :mod:`cvefix_loader`):
fetch the repo at fix+parent (shallow, by-SHA), build before/after CodeQL DBs,
run the CWE-appropriate query, and record the before/after finding counts.

Designed for a long unattended campaign over thousands of pairs:
  * **Resumable** — results persist to a SQLite (`walk_results`, keyed by
    fix_hash); already-processed pairs are skipped on restart.
  * **Disk-safe** — each pair's clone + DBs are removed after measuring; a
    yielder is cheaply rebuilt later from its recorded repo + hashes.
  * **Bounded** — per-step timeouts; failures are recorded as a status, never
    fatal to the walk.

A pair with ``before_count > 0`` is a real CVE CodeQL flags (a TP); additionally
``after_count > 0`` is a candidate missing-sanitizer FP — the trust sound-tier's
input. The git/CodeQL steps are module-level functions so tests stub them.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

from core.config import RaptorConfig
from core.dataflow.cvefix_loader import CveFixPair, INJECTION_CWES, load_pairs

DEFAULT_CODEQL_BIN = "codeql"

# Package repos autobuild may fetch from. A build needing other repos fails the
# egress allowlist and falls back to buildless (graceful) — see _run_autobuild_sandboxed.
_MAVEN_PROXY_HOSTS = [
    "repo.maven.apache.org", "repo1.maven.org", "repo.maven.org",
    "central.sonatype.com", "oss.sonatype.org", "maven.google.com", "dl.google.com",
]

# Go module proxies the Go autobuilder fetches from.  Restricted to the
# canonical Google-controlled chain:
#
#   * ``proxy.golang.org``      — module-info / version-list endpoint.
#   * ``sum.golang.org``        — the Go checksum DB.
#   * ``storage.googleapis.com`` — backs the proxy's ``.zip`` downloads.
#     Without it 114 of 221 egress denials in the first Go walk were GCS;
#     every module download failed at the content step even though the
#     metadata fetch passed.
#
# Third-party mirrors (``goproxy.cn``, ``goproxy.io``) and the defunct
# ``code.google.com`` are deliberately excluded — allowlisting them
# expands trust surface to mirrors we don't control for a marginal yield
# bump.  Projects pinning a third-party mirror just hit build_fail
# under our sandbox; that's acceptable for a measurement corpus.
#
# Fail-mode is graceful: a build needing a non-allowlisted host gets
# blocked → build_fail is recorded, the walker moves on.
_GO_PROXY_HOSTS = [
    "proxy.golang.org", "sum.golang.org",
    "storage.googleapis.com",
]


# Per-language autobuild profile: which egress hosts to allowlist and what
# env vars to inject so the build never writes to host config locations
# (~/.m2, ~/go, etc.).  Keeping these together makes adding a new compiled
# language a single profile entry rather than scattered conditionals in
# the sandbox runner.
def _java_autobuild_env(work_root: Path) -> dict:
    return {"MAVEN_OPTS": f"-Dmaven.repo.local={work_root / '.m2'}"}


def _go_autobuild_env(work_root: Path) -> dict:
    """Redirect every Go cache + path into the work area so the sandboxed
    build doesn't escape Landlock's allow-write set.  THREE Go state
    locations matter — missing any one causes a permission-denied build
    fail with no actionable signal:

      * ``GOMODCACHE`` — downloaded module artifacts (was caught first).
      * ``GOPATH`` — legacy package dir (some tools still write here).
      * ``GOCACHE`` — the build cache; Go ALWAYS writes here regardless
        of module mode.  Default ``$HOME/.cache/go-build`` is outside
        the sandbox's writable set and silently fails 100% of builds.

    ``GOFLAGS=-mod=mod`` allows the build to download missing modules
    (default ``-mod=readonly`` would fail-closed without a go.sum hit).
    """
    return {
        "GOMODCACHE": str(work_root / "go-mod-cache"),
        "GOPATH": str(work_root / "gopath"),
        "GOCACHE": str(work_root / "go-build-cache"),
        "GOFLAGS": "-mod=mod",
    }


_AUTOBUILD_PROFILES = {
    "java": (_MAVEN_PROXY_HOSTS, _java_autobuild_env),
    "go":   (_GO_PROXY_HOSTS,   _go_autobuild_env),
}

# codeql extractor language -> (queries pack, {cwe: pack-relative query path}).
# Ruby uses a different path scheme (lowercase queries/security/cwe-0XX) and query
# names (ReflectedXSS, not ReflectedXss; PathInjection, not TaintedPath).
_QUERIES = {
    "python": ("python-queries", {
        "CWE-89": "Security/CWE-089/SqlInjection.ql",
        "CWE-78": "Security/CWE-078/CommandInjection.ql",
        "CWE-79": "Security/CWE-079/ReflectedXss.ql",
        "CWE-22": "Security/CWE-022/PathInjection.ql",
        "CWE-94": "Security/CWE-094/CodeInjection.ql",
        "CWE-918": "Security/CWE-918/FullServerSideRequestForgery.ql",
    }),
    "javascript": ("javascript-queries", {
        "CWE-89": "Security/CWE-089/SqlInjection.ql",
        "CWE-78": "Security/CWE-078/CommandInjection.ql",
        "CWE-79": "Security/CWE-079/ReflectedXss.ql",
        "CWE-22": "Security/CWE-022/TaintedPath.ql",
        "CWE-94": "Security/CWE-094/CodeInjection.ql",
        "CWE-918": "Security/CWE-918/RequestForgery.ql",
    }),
    "ruby": ("ruby-queries", {
        "CWE-89": "queries/security/cwe-089/SqlInjection.ql",
        "CWE-78": "queries/security/cwe-078/CommandInjection.ql",
        "CWE-79": "queries/security/cwe-079/ReflectedXSS.ql",
        "CWE-22": "queries/security/cwe-022/PathInjection.ql",
        "CWE-94": "queries/security/cwe-094/CodeInjection.ql",
        "CWE-918": "queries/security/cwe-918/ServerSideRequestForgery.ql",
    }),
    "java": ("java-queries", {
        "CWE-89": "Security/CWE/CWE-089/SqlTainted.ql",
        "CWE-78": "Security/CWE/CWE-078/ExecTainted.ql",
        "CWE-79": "Security/CWE/CWE-079/XSS.ql",
        "CWE-22": "Security/CWE/CWE-022/TaintedPath.ql",
        # CWE-94 omitted for Java: the standard pack has no generic
        # CodeInjection.ql; the framework-specific alternatives (SpEL,
        # MVEL, Groovy, JEXL, Template) are too narrow for a broad walk
        # and would silently miss most real Java code-injection fixes.
        "CWE-918": "Security/CWE/CWE-918/RequestForgery.ql",
    }),
    "go": ("go-queries", {
        # SQL injection: two query files in the Go pack — ``SqlInjection.ql``
        # (the canonical taint query) and ``StringBreak.ql`` (a narrower
        # string-literal break check).  Use the canonical one to match the
        # other languages' shape.
        "CWE-89": "Security/CWE-089/SqlInjection.ql",
        "CWE-78": "Security/CWE-078/CommandInjection.ql",
        "CWE-79": "Security/CWE-079/ReflectedXss.ql",
        # CWE-22: Go pack has three path-traversal queries — ``TaintedPath``
        # (the broad query, matches other langs' default), plus narrower
        # ``ZipSlip`` and ``UnsafeUnzipSymlink``.  TaintedPath for the walk.
        "CWE-22": "Security/CWE-022/TaintedPath.ql",
        # CWE-94 omitted for Go: pack has no CodeInjection.ql.
        "CWE-918": "Security/CWE-918/RequestForgery.ql",
    }),
}

# CVEfixes repo_language -> codeql extractor language. TypeScript extracts with
# the javascript extractor; Ruby/Java/Go are their own; else python/js.
_LANG_MAP = {"Python": "python", "Ruby": "ruby", "Java": "java", "Go": "go"}

# Compiled languages we extract build-free via `--build-mode=none`. Source-
# extracted langs (python/js/ruby) take no build mode. Java's buildless recall is
# weaker (no type resolution → Spring/interface flows missed); the build-promote
# pass recovers those `before==0` misses with a real build.
_BUILDLESS_COMPILED = {"java"}

# Compiled languages that MUST autobuild — CodeQL has no buildless extractor
# for them.  Go's extractor runs ``go build`` to walk packages; without an
# actual build the database is empty.  Go cases route through the sandboxed
# autobuild path on the FIRST attempt (no buildless fallback to promote from).
_AUTOBUILD_ONLY = {"go"}


def _codeql_lang(repo_language: str) -> str:
    return _LANG_MAP.get(repo_language, "javascript")


def query_for(repo_language: str, cwe: str) -> Optional[str]:
    pack, table = _QUERIES[_codeql_lang(repo_language)]
    sub = table.get(cwe)
    return None if sub is None else f"codeql/{pack}:{sub}"


@dataclass(frozen=True)
class WalkResult:
    fix_hash: str
    status: str               # ok | fetch_fail | build_fail | analyze_fail | no_query
    before_count: int = -1
    after_count: int = -1

    @property
    def is_yield(self) -> bool:
        return self.status == "ok" and self.before_count > 0

    @property
    def is_fp_candidate(self) -> bool:
        return self.status == "ok" and self.after_count > 0


# --- subprocess steps (module-level so tests can stub them) ---

def _run(cmd, timeout) -> bool:
    # get_safe_env() strips env vars tools may shell-evaluate (untrusted-repo
    # hygiene per CLAUDE.md); buildless extraction + git read-only ops only.
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           check=False, env=RaptorConfig.get_safe_env())
        return r.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def _toolchain_readable_paths(codeql_bin: str) -> list:
    """Paths the sandboxed autobuild must read/exec (codeql install, system
    toolchain, CA certs) on top of the work area — restrict_reads denies $HOME."""
    real = os.path.realpath(shutil.which(codeql_bin) or codeql_bin)
    return [
        str(Path(real).resolve().parent), str(Path.home() / ".local"),
        "/usr", "/etc/alternatives", "/etc/ssl", "/etc/ca-certificates",
    ]


def _run_autobuild_sandboxed(cmd, *, work_root: Path, codeql_bin: str,
                              timeout: int, lang: str) -> bool:
    """Run `codeql database create --build-mode=autobuild` — which EXECUTES the
    untrusted project build (mvn runs pom plugins = arbitrary code; ``go build``
    can run ``go:generate`` directives) — under the untrusted sandbox.  FAIL
    CLOSED: refuse rather than run an untrusted build unsandboxed.  Landlock
    restricts writes to the work area, reads exclude host credentials, egress
    is allowlisted to package repos; each language's package cache is
    redirected into the work area so the build never writes to host config
    locations (``~/.m2``, ``~/go/pkg/mod``, …).

    ``lang`` selects the egress + env profile in :data:`_AUTOBUILD_PROFILES`;
    unknown ``lang`` raises — adding a compiled language must be an
    intentional substrate change (a missed profile would default to
    Maven hosts and silently mis-route the build's network calls).
    """
    try:
        from core.sandbox import check_landlock_available, run_untrusted_networked
    except ImportError as exc:
        raise RuntimeError(
            "core.sandbox unavailable — refusing to autobuild an untrusted repo") from exc
    if not check_landlock_available():
        raise RuntimeError(
            "Landlock unavailable — refusing to autobuild an untrusted repo unsandboxed")
    if lang not in _AUTOBUILD_PROFILES:
        raise RuntimeError(
            f"no autobuild profile for lang={lang!r}; known: "
            f"{sorted(_AUTOBUILD_PROFILES)}")
    proxy_hosts, env_extender = _AUTOBUILD_PROFILES[lang]
    env = RaptorConfig.get_safe_env(preserve_proxy=True)
    env.update(env_extender(work_root))
    try:
        proc = run_untrusted_networked(
            cmd, target=str(work_root), output=str(work_root),
            proxy_hosts=proxy_hosts,
            readable_paths=_toolchain_readable_paths(codeql_bin),
            env=env, timeout=timeout,
        )
        return proc.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def _fetch_pair(repo_url: str, fix_hash: str, dest: Path, timeout: int) -> bool:
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)
    if not _run(["git", "init", "-q", str(dest)], 30):
        return False
    if not _run(["git", "-C", str(dest), "remote", "add", "origin", repo_url], 30):
        return False
    # --depth 2 brings the fix + its single parent.
    return _run(["git", "-C", str(dest), "fetch", "-q", "--depth", "2", "origin", fix_hash], timeout)


# CodeQL resource tunables live in ``packages.codeql`` — the central
# home for all CodeQL-related utilities.  We re-export the type at the
# old name so other modules in this file (and tests that import it via
# cvefix_walk) keep working without churn.
from packages.codeql.tunables import CodeQLTunables  # noqa: E402

_DEFAULT_TUNABLES = CodeQLTunables()


def _build_db(src: Path, commit: str, db: Path, lang: str, codeql_bin: str, timeout: int,
              build_mode: Optional[str] = None,
              tunables: CodeQLTunables = _DEFAULT_TUNABLES) -> bool:
    if not _run(["git", "-C", str(src), "checkout", "-q", commit], 60):
        return False
    cmd = [codeql_bin, "database", "create", str(db), f"--language={lang}",
           f"--source-root={src}", "--overwrite"]
    if build_mode:
        cmd.append(f"--build-mode={build_mode}")
    tunables.append_to(cmd, include_disk_cache=True)
    # autobuild executes untrusted build scripts → must be sandboxed (fail-closed).
    # Buildless/source extraction runs no repo code → plain spawn (get_safe_env).
    if build_mode == "autobuild":
        return _run_autobuild_sandboxed(cmd, work_root=db.parent, codeql_bin=codeql_bin,
                                        timeout=timeout, lang=lang)
    return _run(cmd, timeout)


def _count_query(db: Path, query: str, out: Path, codeql_bin: str, timeout: int,
                 tunables: CodeQLTunables = _DEFAULT_TUNABLES) -> Optional[int]:
    cmd = [codeql_bin, "database", "analyze", str(db), query,
           "--format=sarif-latest", f"--output={out}"]
    # ``database analyze`` doesn't accept ``--max-disk-cache``; suppress it
    # to avoid an "unknown option" rejection.
    tunables.append_to(cmd, include_disk_cache=False)
    if not _run(cmd, timeout):
        return None
    try:
        import json
        data = json.loads(out.read_text())
        return sum(len(r.get("results", [])) for r in data.get("runs", []))
    except (OSError, ValueError):
        return None


def _clean_go_caches(work_dir: Path) -> None:
    """Per-pair cleanup of Go's module / build caches in the work area.

    Go marks every file in ``GOMODCACHE`` read-only by design (the
    module proxy treats cache contents as immutable), so a plain
    ``shutil.rmtree`` silently fails to delete anything.  We add
    ``S_IWUSR`` recursively before the rmtree.

    Why per-pair: one project's ``replace`` directives or version pins
    can map a required module name (``github.com/armon/go-metrics``) to
    a physical module that declares a DIFFERENT path
    (``github.com/hashicorp/go-metrics``).  When the next pair's build
    requires the original path, the cached content claims to be the
    other and CodeQL's extractor aborts:

        module declares its path as: github.com/hashicorp/go-metrics
                but was required as: github.com/armon/go-metrics

    The fix is to keep the cache per-project — the cost is re-
    downloading common modules per pair (cheap; ``proxy.golang.org``
    serves at ~MB/s and total module size per repo is single-digit MB
    for typical CVE pairs).
    """
    for sub in ("go-mod-cache", "gopath", "go-build-cache"):
        p = work_dir / sub
        if not p.is_dir():
            continue
        # Recursively add owner-write so rmtree can unlink everything.
        # Symlinks are skipped (we don't want to chmod the target).
        for root, dirs, files in os.walk(p):
            for name in dirs + files:
                fp = Path(root) / name
                try:
                    if not fp.is_symlink():
                        fp.chmod(fp.stat().st_mode | stat.S_IWUSR)
                except OSError:
                    pass
        shutil.rmtree(p, ignore_errors=True)


def process_pair(
    pair: CveFixPair, *, work_dir: Path, codeql_bin: str = DEFAULT_CODEQL_BIN,
    fetch_timeout: int = 150, build_timeout: int = 240, analyze_timeout: int = 180,
    build_mode: Optional[str] = None,
    tunables: CodeQLTunables = _DEFAULT_TUNABLES,
) -> WalkResult:
    """Fetch, build before/after DBs, run the CWE query; clean up; return counts.

    ``build_mode`` overrides the CodeQL extraction mode; when None it is auto-
    picked per language (``none`` for buildless-compiled langs like Java, no flag
    for source-extracted langs). The build-promote pass passes ``autobuild``.

    ``tunables`` controls CodeQL resource limits (``-j``, ``-M``,
    ``--max-disk-cache``).  See :class:`CodeQLTunables` for defaults.
    """
    query = query_for(pair.repo_language, pair.cwe)
    if query is None:
        return WalkResult(pair.fix_hash, "no_query")
    lang = _codeql_lang(pair.repo_language)
    mode = build_mode or (
        "none" if lang in _BUILDLESS_COMPILED
        else "autobuild" if lang in _AUTOBUILD_ONLY
        else None
    )
    repo = work_dir / "repo"
    db_a, db_b = work_dir / "db-a", work_dir / "db-b"
    sa, sb = work_dir / "a.sarif", work_dir / "b.sarif"
    try:
        if not _fetch_pair(pair.repo_url, pair.fix_hash, repo, fetch_timeout):
            return WalkResult(pair.fix_hash, "fetch_fail")
        if not _build_db(repo, pair.fix_hash, db_a, lang, codeql_bin, build_timeout, mode,
                         tunables=tunables):
            return WalkResult(pair.fix_hash, "build_fail")
        if not _build_db(repo, pair.parent_hash, db_b, lang, codeql_bin, build_timeout, mode,
                         tunables=tunables):
            return WalkResult(pair.fix_hash, "build_fail")
        after = _count_query(db_a, query, sa, codeql_bin, analyze_timeout, tunables=tunables)
        before = _count_query(db_b, query, sb, codeql_bin, analyze_timeout, tunables=tunables)
        if after is None or before is None:
            return WalkResult(pair.fix_hash, "analyze_fail")
        return WalkResult(pair.fix_hash, "ok", before_count=before, after_count=after)
    finally:
        for p in (repo, db_a, db_b, sa, sb):
            shutil.rmtree(p, ignore_errors=True) if p.is_dir() else p.unlink(missing_ok=True)
        # Per-pair Go cache cleanup.  Without this, modules cached from
        # one project with its `replace` directives corrupt the next
        # project's build (CodeQL surfaces this as
        # "module declares its path as X but was required as Y" and
        # extraction fails).  Java's Maven cache doesn't have this
        # conflict shape — version conflicts resolve last-write-wins —
        # so cross-pair Maven reuse is fine and we leave it alone.
        if lang in _AUTOBUILD_PROFILES and lang == "go":
            _clean_go_caches(work_dir)


# --- resumable results store ---

# Keyed by (fix_hash, cwe): the before/after result depends on the commit AND the
# CWE-specific query, so one commit that fixes two CWEs yields two distinct
# results. (Keying on fix_hash alone collapses them.) Same fix_hash+cwe under
# different CVE ids is genuinely redundant — same DB, same query — so deduped.
_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS walk_results ("
    "fix_hash TEXT, cve_id TEXT, cwe TEXT, repo_language TEXT,"
    "repo_url TEXT, parent_hash TEXT, status TEXT, before_count INT,"
    "after_count INT, ts REAL, PRIMARY KEY (fix_hash, cwe))"
)


def _processed(con: sqlite3.Connection) -> set:
    return {(r[0], r[1]) for r in con.execute("SELECT fix_hash, cwe FROM walk_results")}


def _record(con: sqlite3.Connection, pair: CveFixPair, res: WalkResult) -> None:
    con.execute(
        "INSERT OR REPLACE INTO walk_results VALUES (?,?,?,?,?,?,?,?,?,?)",
        (res.fix_hash, pair.cve_id, pair.cwe, pair.repo_language, pair.repo_url,
         pair.parent_hash, res.status, res.before_count, res.after_count, time.time()),
    )
    con.commit()


def walk(
    db_path: Path, results_db: Path, *,
    cwes: Sequence[str] = INJECTION_CWES,
    languages=("Python", "JavaScript", "TypeScript"),
    work_dir: Path = Path("/data/corpus/clones/walk"),
    codeql_bin: str = DEFAULT_CODEQL_BIN,
    limit: Optional[int] = None,
    fetch_timeout: int = 150,
    build_timeout: int = 240,
    analyze_timeout: int = 180,
    tunables: CodeQLTunables = _DEFAULT_TUNABLES,
    log=print,
) -> dict:
    """Walk the metadata DB's pairs through CodeQL, recording results (resumable).

    Timeouts default to the conservative walker-tier values; operators
    pushing into projects with very long secondary-extractor phases
    (large Go web repos) can raise ``build_timeout``.  ``tunables``
    controls ``--threads`` / ``--ram`` / ``--max-disk-cache``."""
    pairs = load_pairs(db_path, cwes=cwes, languages=languages)
    con = sqlite3.connect(str(results_db))
    con.execute(_SCHEMA)
    # Dedup todo by (fix_hash, cwe): the same commit credited to multiple CVE ids
    # yields identical (DB, query, result), so process it once. (The PK already
    # dedups at storage, but without this we'd waste a full rebuild on each.)
    done = _processed(con)
    todo, seen = [], set()
    for p in pairs:
        key = (p.fix_hash, p.cwe)
        if key in done or key in seen:
            continue
        seen.add(key)
        todo.append(p)
    log(f"walk: {len(pairs)} pairs, {len(done)} already done, {len(todo)} to process")
    work_dir.mkdir(parents=True, exist_ok=True)
    n = 0
    for pair in todo:
        if limit is not None and n >= limit:
            break
        res = process_pair(pair, work_dir=work_dir, codeql_bin=codeql_bin,
                           fetch_timeout=fetch_timeout,
                           build_timeout=build_timeout,
                           analyze_timeout=analyze_timeout,
                           tunables=tunables)
        _record(con, pair, res)
        n += 1
        tag = "YIELD" if res.is_yield else res.status
        log(f"  [{n}/{len(todo)}] {pair.cve_id} {pair.cwe} {pair.repo_language} "
            f"{pair.repo_url.split('github.com/')[-1]}: {tag} "
            f"before={res.before_count} after={res.after_count}")
    summary = dict(con.execute(
        "SELECT 'total', count(*) FROM walk_results UNION ALL "
        "SELECT 'yield', count(*) FROM walk_results WHERE status='ok' AND before_count>0 UNION ALL "
        "SELECT 'fp_candidate', count(*) FROM walk_results WHERE status='ok' AND after_count>0"
    ).fetchall())
    con.close()
    return summary


def promote_misses(
    results_db: Path, *,
    work_dir: Path = Path("/data/corpus/clones/promote"),
    codeql_bin: str = DEFAULT_CODEQL_BIN,
    promote_languages: Sequence[str] = ("Java",),
    build_timeout: int = 600,
    limit: Optional[int] = None,
    log=print,
) -> dict:
    """Build-promote buildless misses (the second half of the Java plan).

    For ``ok`` rows in ``promote_languages`` whose buildless run flagged nothing
    (``before_count == 0`` — a likely type-resolution miss, e.g. Spring/interface
    dispatch), retry with a real ``--build-mode=autobuild``. Update the row ONLY
    if the build recovers a yielder (``before_count > 0``, status ``ok_built``);
    autobuild failures or still-0 keep the buildless row, so the result is never
    worse than buildless-only. Targeted at exactly the cases a build can help, so
    the expensive autobuilds are bounded to the buildless false-negative set.
    """
    con = sqlite3.connect(str(results_db))
    con.execute(_SCHEMA)
    ph = ",".join("?" * len(promote_languages))
    rows = con.execute(
        f"SELECT fix_hash, cve_id, cwe, repo_language, repo_url, parent_hash "
        f"FROM walk_results WHERE status='ok' AND before_count=0 "
        f"AND repo_language IN ({ph}) ORDER BY cve_id", tuple(promote_languages)
    ).fetchall()
    log(f"promote: {len(rows)} buildless-miss rows in {tuple(promote_languages)}")
    work_dir.mkdir(parents=True, exist_ok=True)
    promoted = n = 0
    for fix_hash, cve_id, cwe, lang, repo_url, parent_hash in rows:
        if limit is not None and n >= limit:
            break
        n += 1
        pair = CveFixPair(cve_id, cwe, repo_url, lang, fix_hash, parent_hash)
        res = process_pair(pair, work_dir=work_dir, codeql_bin=codeql_bin,
                           build_timeout=build_timeout, build_mode="autobuild")
        if res.status == "ok" and res.before_count > 0:
            con.execute(
                "UPDATE walk_results SET status=?, before_count=?, after_count=?, ts=? "
                "WHERE fix_hash=? AND cwe=?",
                ("ok_built", res.before_count, res.after_count, time.time(), fix_hash, cwe))
            con.commit()
            promoted += 1
            log(f"  [{n}/{len(rows)}] PROMOTED {cve_id} {cwe} "
                f"{repo_url.split('github.com/')[-1]}: before={res.before_count} "
                f"after={res.after_count}")
        else:
            log(f"  [{n}/{len(rows)}] no-recovery {cve_id} {cwe}: "
                f"{res.status} before={res.before_count}")
    con.close()
    return {"candidates": len(rows), "promoted": promoted}


def main(argv=None) -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Walk CVEfixes pairs through CodeQL, harvest yielders.")
    ap.add_argument("--db", type=Path, default=Path("/data/corpus/cvefixes-meta.db"))
    ap.add_argument("--results", type=Path, default=Path("/data/corpus/walk-results.db"))
    ap.add_argument("--work-dir", type=Path, default=Path("/data/corpus/clones/walk"))
    ap.add_argument("--languages", nargs="+", default=["Python", "JavaScript", "TypeScript"])
    ap.add_argument("--cwes", nargs="+", default=list(INJECTION_CWES))
    ap.add_argument("--codeql-bin", default=DEFAULT_CODEQL_BIN)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--promote", action="store_true",
                    help="build-promote buildless misses (autobuild) instead of walking")
    ap.add_argument("--promote-languages", nargs="+", default=["Java"])
    # CodeQL resource tunables.  Defaults come from RAPTOR's central
    # tuning config (tuning.json: codeql_threads, codeql_ram_mb) via
    # CodeQLTunables.from_tuning(); CLI flags here are operator-overrides.
    ap.add_argument("--threads", type=int, default=None,
                    help="codeql -j: extractor threads.  Default: from "
                         "tuning.json:codeql_threads ('auto' -> 0 = all "
                         "cores).  The codeql default of 1 serializes the "
                         "secondary HTML/JS extraction phase and regularly "
                         "times out build_timeout on Go web repos.")
    ap.add_argument("--ram", type=int, default=None,
                    help="codeql -M: ram budget MB hint.  Default: from "
                         "tuning.json:codeql_ram_mb ('auto' -> 25%% of "
                         "system RAM clamped [2048, 16384])")
    ap.add_argument("--max-disk-cache", type=int, default=None,
                    help="codeql --max-disk-cache MB.  Default: codeql's "
                         "unbounded.  Set when running unattended to keep "
                         "DB build cache from growing without limit. "
                         "Not in tuning.json today — add there once a "
                         "second consumer needs it")
    # Pipeline timeouts.
    ap.add_argument("--fetch-timeout", type=int, default=150,
                    help="git fetch timeout, seconds (default 150)")
    ap.add_argument("--build-timeout", type=int, default=240,
                    help="codeql database create timeout, seconds (default 240). "
                         "Raise (e.g. 600) for projects with very large "
                         "secondary-extractor footprints (Go web repos with "
                         "thousands of HTML templates)")
    ap.add_argument("--analyze-timeout", type=int, default=180,
                    help="codeql database analyze timeout, seconds (default 180)")
    a = ap.parse_args(argv)
    log = lambda m: print(m, flush=True)  # noqa: E731
    # Resolve operator overrides against tuning.json-backed defaults.
    tunables = CodeQLTunables.from_tuning(
        overrides={"threads": a.threads, "ram_mb": a.ram,
                   "max_disk_cache_mb": a.max_disk_cache},
    )
    if a.promote:
        summary = promote_misses(
            a.results, work_dir=a.work_dir, codeql_bin=a.codeql_bin,
            promote_languages=a.promote_languages, limit=a.limit, log=log,
        )
        print(f"=== PROMOTE SUMMARY {summary} ===", flush=True)
        return
    summary = walk(
        a.db, a.results, cwes=a.cwes, languages=a.languages,
        work_dir=a.work_dir, codeql_bin=a.codeql_bin, limit=a.limit,
        fetch_timeout=a.fetch_timeout, build_timeout=a.build_timeout,
        analyze_timeout=a.analyze_timeout, tunables=tunables,
        log=log,
    )
    print(f"=== SUMMARY {summary} ===", flush=True)


if __name__ == "__main__":
    main()
