"""Bridge: walker FP-candidates -> barrier synthesis -> suppression rate.

The walker (:mod:`cvefix_walk`) records, per CVE fix-commit, whether CodeQL still
flags a finding on the POST-fix code (``after_count > 0``) — a candidate
``missing_sanitizer`` false positive: the fix added a project sanitizer the
analyzer doesn't model. This bridge turns those candidates into the sound-tier's
headline metric. For each FP candidate it:

  1. rebuilds the before/after CodeQL DBs (re-fetch fix+parent),
  2. runs the CWE query on the post-fix DB to locate the flagged finding,
  3. reads the flagged source + the fix diff (which contains the added sanitizer)
     into a :class:`BarrierProposal`,
  4. runs :func:`run_synthesis_loop` — LLM proposes a barrier, CodeQL adjudicates,
     scoped to the finding's file so unrelated findings don't sink soundness.

Aggregated into a :class:`CorpusSynthReport`. The run is resumable + crash-
isolated: each candidate's outcome (and the synthesized sound barrier) is
persisted to a SQLite as it completes, a crashing candidate is recorded as an
error and the run continues, and a restart skips finished candidates. DBs are
built one pair at a time and removed after, so disk stays bounded. The proposer
is injectable so the orchestration is unit-testable with no LLM and no CodeQL.
"""

from __future__ import annotations

import json
import re
import shutil
import sqlite3
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Optional, Sequence, Tuple

from core.config import RaptorConfig
from core.dataflow import cvefix_walk
from core.dataflow.barrier_synth import (
    BarrierProposal,
    CorpusSynthReport,
    default_completer,
    make_llm_proposer,
    model_completer,
    render_corpus_report,
    run_synthesis_loop,
)
from core.dataflow.cvefix_loader import CveFixPair

# Tier 0 (SMT) is the free first-pass backend. Imported defensively so a
# missing substrate / packaging glitch can't break the existing Tier 2
# pipeline — on ImportError we just don't try Tier 0.  The module itself
# handles z3 absent via its own gate; this guard is for the module-load
# failure case only.
try:
    from core.dataflow.smt_barrier import Tier0Status, try_tier0
    _TIER0_AVAILABLE = True
except ImportError:                                  # pragma: no cover
    _TIER0_AVAILABLE = False
    Tier0Status = None                                # type: ignore[assignment]
    try_tier0 = None                                  # type: ignore[assignment]

# Tier 1B (LLM-assisted) is the middle backend — cheap-model extraction +
# mechanical adjudication.  Imported defensively for the same reason.
try:
    from core.dataflow.tier1_llm import try_tier1b
    _TIER1B_AVAILABLE = True
except ImportError:                                  # pragma: no cover
    _TIER1B_AVAILABLE = False
    try_tier1b = None                                 # type: ignore[assignment]

DEFAULT_CODEQL_BIN = cvefix_walk.DEFAULT_CODEQL_BIN

# CWE -> barrier_synth sink_class.
#
# ``codeinjection`` and ``ssrf`` have no entry in
# :data:`smt_barrier._DANGER_CHARS` at this writing — both fix patterns sit
# outside the char-class danger model.  :func:`prove_neutralizes` returns
# "no danger model" → Tier 0 DECLINED → Tier 2 takes over with the full
# LLM + CodeQL machinery.  Tier 1B's known-safe-call table also has no
# entries for these classes, so its ``library`` backend declines too —
# the LLM-extractor characterisation lands on Tier 2.
_CWE_SINK = {"CWE-78": "cmdi", "CWE-89": "sqli", "CWE-79": "xss", "CWE-22": "pathtrav",
             "CWE-94": "codeinjection", "CWE-918": "ssrf"}

# Couldn't reach (or complete) adjudication — excluded from the rate denominator.
_PIPELINE_ERRORS = {"no_query", "fetch_fail", "build_fail", "analyze_fail",
                    "no_finding", "error"}

# Source the LLM reasons over. The fix-added sanitizer is usually upstream of the
# sink (or in a helper), so give the whole file when small, else a window — plus
# the fix diff, which literally contains the sanitizer the fix added.
_SMALL_FILE = 400
_WINDOW = 60
_DIFF_CAP = 200
# Caps for the cross-file fix-diff context (other touched files beyond the
# sink file).  Per-file cap keeps a single huge refactor commit from
# dominating; total cap keeps the prompt within LLM context budget even on
# fixes that touch many files.  Conservative — the typical sanitizer fix
# touches 1-3 files and the validator chunk is small.
_OTHER_DIFF_PER_FILE_CAP = 120
_OTHER_DIFF_TOTAL_CAP = 500

# Test-file path heuristic: files matching these patterns are excluded from
# the cross-file fix-diff context.  Test files almost never contain the
# sanitizer (they exercise the validated entry-point), and feeding the LLM
# test scaffolding crowds out the real validator code with noise.
# Conservative breadth — a missed test exclusion just adds noise; a wrong
# exclusion of a non-test file would lose the validator entirely.
#
# NB: this filter is applied ONLY to OTHER files; the sink file itself is
# fed unconditionally by the existing _git_diff call, so a sink that lives
# in a test dir (CodeQL flagging a test mock as a sink) is still seen.
_TEST_PATH_RE = re.compile(
    # directory components named test/tests/spec/specs/__tests__/__test__
    r"(?:^|/)(?:tests?|specs?|__tests?__)/"
    # python: test_<name>.py at file head
    r"|(?:^|/)test_[^/]+\.py$"
    # foo_test.<ext> / foo_spec.<ext> by extension
    r"|_test\.(?:go|py|rb|js|ts|jsx|tsx|java)$"
    r"|_spec\.(?:rb|py|js|ts|jsx|tsx)$"
    # JS/TS double-dot convention: foo.test.ts / foo.spec.tsx
    r"|\.test\.[jt]sx?$"
    r"|\.spec\.[jt]sx?$"
    # Java conventions: TestX.java / XTest.java / XTests.java in any dir
    r"|(?:^|/)Test[A-Z][^/]*\.java$"
    r"|(?:^|/)[^/]+Tests?\.java$"
)


def _is_test_path(path: str) -> bool:
    """True iff ``path`` looks like a test/spec file under common
    conventions across the languages the walk targets (Python/JS/TS/
    Ruby/Java/Go).  See :data:`_TEST_PATH_RE` for the exact patterns."""
    return _TEST_PATH_RE.search(path) is not None

# CodeQL query-pack search path so the synthesized barrier's qlpack dep
# (codeql/<lang>-all) resolves at adjudication for ruby/java/python alike.
_SEARCH_PATH = Path.home() / ".local" / "codeql-queries"

_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS synth_results ("
    "fix_hash TEXT, cwe TEXT, cve_id TEXT, repo_language TEXT, finding_id TEXT,"
    "status TEXT, backend TEXT, barrier_query TEXT, detail TEXT, ts REAL,"
    " PRIMARY KEY (fix_hash, cwe))"
)

# Which backend produced the verdict — labelled by the soundness
# mechanism, not the routing tier (those tier names are internal jargon
# and meaningless in an audit trail):
#
#   "smt"     -- Z3 regex-intersection proof over the validator's
#                language and the sink-class danger language.  Spec
#                may have been extracted mechanically (the original
#                charset extractor) or LLM-assisted (an LLM pointed at
#                the source line, then mechanical cross-check + Z3).
#                Either way the soundness mechanism is identical.
#   "library" -- Match against the curated known-safe-library table
#                (core.dataflow.known_safe_calls).  Soundness rests on
#                the per-entry human-verified semantic claim.
#   "codeql"  -- LLM-proposed CodeQL barrier-guard, adjudicated by
#                running the guard on both pre- and post-fix DBs.
#   ""        -- pipeline error before any backend reached a verdict.
_BACKEND_SMT = "smt"
_BACKEND_LIBRARY = "library"
_BACKEND_CODEQL = "codeql"
_BACKEND_NONE = ""


def _default_search_path() -> Optional[str]:
    return str(_SEARCH_PATH) if _SEARCH_PATH.exists() else None


def _norm_uri(uri: str) -> str:
    """Strip a file: scheme + leading slash so `repo_root / uri` stays in-repo."""
    if uri.startswith("file://"):
        uri = uri[len("file://"):]
    elif uri.startswith("file:"):
        uri = uri[len("file:"):]
    return uri.lstrip("/")


def _git_diff(repo: Path, parent: str, fix: str, uri: str,
              *, cap: int = _DIFF_CAP, timeout: int = 60) -> str:
    """`git diff parent..fix -- <uri>` (the change that added the sanitizer),
    capped; empty string on any failure."""
    try:
        r = subprocess.run(
            ["git", "-C", str(repo), "diff", f"{parent}..{fix}", "--", uri],
            capture_output=True, text=True, timeout=timeout, check=False,
            env=RaptorConfig.get_safe_env())
    except (subprocess.TimeoutExpired, OSError):
        return ""
    if r.returncode != 0:
        return ""
    return "\n".join(r.stdout.splitlines()[:cap])


def _git_touched_files(repo: Path, parent: str, fix: str,
                       *, timeout: int = 30) -> list:
    """`git diff --name-only parent..fix` — every path the fix changed.
    Returns ``[]`` on failure (caller falls back to sink-file-only context)."""
    try:
        r = subprocess.run(
            ["git", "-C", str(repo), "diff", "--name-only", f"{parent}..{fix}"],
            capture_output=True, text=True, timeout=timeout, check=False,
            env=RaptorConfig.get_safe_env())
    except (subprocess.TimeoutExpired, OSError):
        return []
    if r.returncode != 0:
        return []
    return [ln for ln in r.stdout.splitlines() if ln.strip()]


def _git_diff_other_files(
    repo: Path, parent: str, fix: str, sink_uri: str,
    *, per_file_cap: int = _OTHER_DIFF_PER_FILE_CAP,
    total_cap: int = _OTHER_DIFF_TOTAL_CAP, timeout: int = 60,
) -> str:
    """Cross-file fix-diff context.  Returns concatenated, capped diffs of
    every non-test fix-touched file EXCEPT the sink file (which is already
    fed via :func:`_git_diff`).  Empty string when no qualifying file
    exists or the lookup fails.

    Why this exists: many fixes add the validator in a different file
    from the sink (the canonical archetype: a new ``helpers/dns.ts``
    plus a call-site change in ``middlewares/.../video-imports.ts``,
    while CodeQL flags ``mock-object-storage.ts`` as the sink).  Without
    cross-file diffs the proposer sees only the SINK file's empty diff
    and either gives up (``none()``) or hallucinates a plausible-looking
    guard.  Verified on peertube CVE-2022-0132/0508 — both cases'
    validators live in files distinct from the sink.

    Test-file exclusion is policy: test scaffolding rarely contains
    the validator and crowds out the real fix code under the LLM's
    context budget.  See :func:`_is_test_path`.

    Caps are conservative: per-file cap stops a single huge refactor
    from dominating; total cap protects the LLM context budget on
    fixes that touch many files.  Both are soft limits — when hit we
    truncate the current chunk and stop adding files.
    """
    files = _git_touched_files(repo, parent, fix, timeout=timeout)
    if not files:
        return ""
    sink_norm = _norm_uri(sink_uri)
    chunks: list = []
    total = 0
    for path in files:
        if path == sink_norm or _is_test_path(path):
            continue
        diff = _git_diff(repo, parent, fix, path, cap=per_file_cap,
                         timeout=timeout)
        if not diff:
            continue
        # Header so the LLM can tell which file each chunk belongs to —
        # `git diff` itself includes a `diff --git a/X b/X` header, but
        # an explicit ``# file: X`` line is more LLM-legible and matches
        # the existing ``# fix diff (...):`` framing.
        header = f"# file: {path}"
        budget = total_cap - total
        if budget <= 0:
            break
        body_lines = diff.splitlines()
        if len(body_lines) > budget:
            body_lines = body_lines[:budget]
            body_lines.append(f"... [truncated; per-file cap {per_file_cap} "
                              f"or total cap {total_cap} hit]")
        chunk = header + "\n" + "\n".join(body_lines)
        chunks.append(chunk)
        total += len(body_lines) + 1
        if total >= total_cap:
            break
    return "\n\n".join(chunks)


def _format_path(result: dict) -> str:
    """Format the source->sink dataflow path from a path-problem SARIF result's
    codeFlows. Gives the proposer the EXACT tainted flow — which value reaches the
    sink — so it protects that value instead of guessing from a text window."""
    cfs = result.get("codeFlows", [])
    if not cfs:
        return ""
    steps = cfs[0].get("threadFlows", [{}])[0].get("locations", [])
    rows = []
    for loc in steps:
        node = loc.get("location", {})
        phys = node.get("physicalLocation", {})
        uri = phys.get("artifactLocation", {}).get("uri", "?")
        line = phys.get("region", {}).get("startLine", "?")
        msg = node.get("message", {}).get("text", "")
        rows.append(f"  {Path(uri).name}:{line}  {msg}")
    if not rows:
        return ""
    return ("# tainted dataflow path (source at top -> sink at bottom); the barrier "
            "must neutralize the value that reaches the sink:\n" + "\n".join(rows))


def _run_query(db: Path, query_spec: str, out_sarif: Path, codeql_bin: str, timeout: int) -> bool:
    return cvefix_walk._run(
        [codeql_bin, "database", "analyze", str(db), query_spec,
         "--format=sarif-latest", f"--output={out_sarif}"], timeout)


def _extract_proposal(
    sarif_path: Path, repo_root: Path, pair: CveFixPair,
) -> Optional[Tuple[BarrierProposal, str, int]]:
    """First flagged finding -> (BarrierProposal, target_uri, target_line). Reads
    the post-fix source at the SARIF location (CodeQL SARIF omits snippet text)
    and the fix diff. ``target_uri``/``target_line`` scope the suppress check to
    this specific finding."""
    sink_class = _CWE_SINK.get(pair.cwe)
    if sink_class is None:
        return None
    try:
        data = json.loads(Path(sarif_path).read_text())
    except (OSError, ValueError):
        return None
    for run in data.get("runs", []):
        for res in run.get("results", []):
            for loc in res.get("locations", []):
                phys = loc.get("physicalLocation", {})
                raw_uri = phys.get("artifactLocation", {}).get("uri")
                line = phys.get("region", {}).get("startLine")
                if not raw_uri or not line:
                    continue
                src = repo_root / _norm_uri(raw_uri)
                if not src.is_file():
                    continue
                lines = src.read_text(errors="replace").splitlines()
                snippet = lines[line - 1].strip() if 0 < line <= len(lines) else raw_uri
                if len(lines) <= _SMALL_FILE:
                    body = "\n".join(lines)
                else:
                    lo = max(0, line - 1 - _WINDOW)
                    body = "\n".join(lines[lo:line - 1 + _WINDOW])
                diff = _git_diff(repo_root, pair.parent_hash, pair.fix_hash, _norm_uri(raw_uri))
                # Cross-file fix-diff context: other non-test fix-touched
                # files often contain the validator the fix added (the sink
                # file's own diff is frequently empty when the validator
                # lives in a helper or middleware).  Without this, the
                # proposer hallucinates plausible-looking guards on shapes
                # it has no source for.
                other_diffs = _git_diff_other_files(
                    repo_root, pair.parent_hash, pair.fix_hash, raw_uri)
                path = _format_path(res)
                context = body
                if diff:
                    context += "\n\n# fix diff (the change that added the sanitizer):\n" + diff
                if other_diffs:
                    context += ("\n\n# other fix-touched files (the validator "
                                "may live in a helper or middleware):\n"
                                + other_diffs)
                if path:
                    context += "\n\n" + path
                proposal = BarrierProposal(
                    sink_class=sink_class,
                    finding_id=f"{pair.cve_id}:{pair.cwe}:{Path(raw_uri).name}:{line}",
                    sink_snippet=snippet, source_context=context,
                    language=cvefix_walk._codeql_lang(pair.repo_language),
                )
                return (proposal, raw_uri, line)
    return None


def synthesize_one(
    pair: CveFixPair, *, work_dir: Path, proposer, status: str = "ok",
    codeql_bin: str = DEFAULT_CODEQL_BIN, search_path: Optional[str] = None,
    # Higher than the walker's 240s/180s defaults: the synth bridge does
    # ONE pair end-to-end so a single project's pathological extraction
    # blocks no other work — better to be patient and get a verdict than
    # time out and lose the case to a pipeline_error.  PeerTube
    # (1824 .ts files, 93MB) extracted in ~3-4 min on a quiet box; under
    # any background load the walker-tier 240s ran out, producing
    # spurious build_fail/analyze_fail.  Walks stay at the lower
    # defaults — corpus is bigger and an occasional build_fail is
    # acceptable noise there.
    fetch_timeout: int = 150, build_timeout: int = 600, analyze_timeout: int = 450,
    max_attempts: int = 3, max_refine_attempts: int = 0,
    tier1b_complete=None,
) -> Tuple[str, Optional[str], str, Optional[str], str]:
    """Rebuild DBs, extract the finding, synthesize a barrier.

    Returns ``(status, finding_id, backend, barrier_query, detail)``.

    Two backends, tried in cost order:

      Tier 0 — SMT (free).  Mechanical extractor pulls a charset/regex
        validator from the fix diff; CodeQL's own codeFlow gives free
        dominance evidence; Z3 proves the validator's language and the
        sink's danger language don't intersect.  No LLM tokens, no
        before-DB build.  When SOUND, ``backend="smt"`` and ``barrier_query``
        holds a structured spec like ``smt:charset:[A-Za-z0-9_.+-]+@uri:line``.

      Tier 2 — CodeQL barrier-guard (LLM-written, CodeQL-adjudicated).
        Fall-through when Tier 0 declines / can't apply.  When SOUND,
        ``backend="codeql"`` and ``barrier_query`` holds the compiled QL.

    ``barrier_query`` is also kept for not_sound at Tier 2 (the proposal
    that compiled+ran but missed — diagnostic material for the few-shot).
    ``detail`` records WHY a non-success happened (assembly/compile error
    for ``no_barrier``; which soundness check failed for ``not_sound``).
    ``status`` (the walker row's status) picks the build mode — an
    ``ok_built`` Java row was found via autobuild, so it must be rebuilt
    the same way (buildless would lose the finding).  DBs are removed
    before returning.
    """
    query = cvefix_walk.query_for(pair.repo_language, pair.cwe)
    if query is None:
        return ("no_query", None, _BACKEND_NONE, None, "")
    lang = cvefix_walk._codeql_lang(pair.repo_language)
    if lang in cvefix_walk._BUILDLESS_COMPILED:
        mode = "autobuild" if status == "ok_built" else "none"
    else:
        mode = None
    repo, after_db, before_db = work_dir / "repo", work_dir / "after", work_dir / "before"
    sarif, synth = work_dir / "after.sarif", work_dir / "synth"
    try:
        if not cvefix_walk._fetch_pair(pair.repo_url, pair.fix_hash, repo, fetch_timeout):
            return ("fetch_fail", None, _BACKEND_NONE, None, "")
        # Build the post-fix DB first; the repo is then at the fix commit, so the
        # source we read for the proposal contains the (unmodeled) sanitizer.
        if not cvefix_walk._build_db(repo, pair.fix_hash, after_db, lang, codeql_bin, build_timeout, mode):
            return ("build_fail", None, _BACKEND_NONE, None, "")
        if not _run_query(after_db, query, sarif, codeql_bin, analyze_timeout):
            return ("analyze_fail", None, _BACKEND_NONE, None, "")
        extracted = _extract_proposal(sarif, repo, pair)
        if extracted is None:
            return ("no_finding", None, _BACKEND_NONE, None, "")
        proposal, target_uri, target_line = extracted

        # Tier 0: free SMT verdict.  Defensive try/except so a bug here can
        # never break the existing Tier 2 pipeline — on any unexpected
        # failure we just fall through.  Module-level _TIER0_AVAILABLE
        # guards against a substrate-missing edge case.  Post-audit:
        # the dominance check is now AST-based (source-order + exit-on-
        # fail in the same function), no longer SARIF-codeFlow, so we
        # don't need to re-load the SARIF result here.
        if _TIER0_AVAILABLE:
            sink_class = _CWE_SINK.get(pair.cwe)
            if sink_class is not None:
                fix_diff = _git_diff(
                    repo, pair.parent_hash, pair.fix_hash, _norm_uri(target_uri))
                if fix_diff:
                    try:
                        t0 = try_tier0(
                            fix_diff=fix_diff, repo_root=repo,
                            sink_uri=_norm_uri(target_uri),
                            sink_line=target_line, sink_class=sink_class,
                            language=lang)
                    except Exception:                        # pragma: no cover
                        t0 = None
                    if t0 is not None and t0.status == Tier0Status.SOUND:
                        return ("sound", proposal.finding_id, _BACKEND_SMT,
                                t0.artifact, t0.reasoning[:400])

        # Tier 1B: cheap-LLM-assisted extraction + mechanical adjudication.
        # Runs only when Tier 0 didn't already produce SOUND.  Same
        # defensive shape — any failure falls through to Tier 2.  Requires
        # a completer (passed by ``synthesize_from_results``) — if absent,
        # Tier 1B is skipped (no automatic default to avoid baking a
        # model choice into a per-call code path).
        if _TIER1B_AVAILABLE and tier1b_complete is not None:
            sink_class = _CWE_SINK.get(pair.cwe)
            if sink_class is not None:
                fix_diff = _git_diff(
                    repo, pair.parent_hash, pair.fix_hash, _norm_uri(target_uri))
                if fix_diff:
                    try:
                        t1 = try_tier1b(
                            fix_diff=fix_diff, repo_root=repo,
                            sink_uri=_norm_uri(target_uri),
                            sink_line=target_line, sink_class=sink_class,
                            language=lang, complete=tier1b_complete)
                    except Exception:                        # pragma: no cover
                        t1 = None
                    if t1 is not None and t1.status == Tier0Status.SOUND:
                        # Backend = the proof mechanism that produced the
                        # verdict.  Z3-charset path emits ``smt:...`` (same
                        # mechanism as Tier 0).  Curated-table path emits
                        # ``library:...``.
                        artifact = t1.artifact or ""
                        if artifact.startswith("library:"):
                            backend = _BACKEND_LIBRARY
                        else:
                            backend = _BACKEND_SMT
                        return ("sound", proposal.finding_id, backend,
                                artifact, t1.reasoning[:400])

        if not cvefix_walk._build_db(repo, pair.parent_hash, before_db, lang, codeql_bin, build_timeout, mode):
            return ("build_fail", proposal.finding_id, _BACKEND_NONE, None, "")
        diag: dict = {}
        res = run_synthesis_loop(
            proposal, after_db, before_db, proposer=proposer, work_dir=synth,
            search_path=search_path, target_uri=target_uri, target_line=target_line,
            codeql_bin=codeql_bin, max_attempts=max_attempts,
            max_refine_attempts=max_refine_attempts, diag=diag)
        if res is None:
            return ("no_barrier", proposal.finding_id, _BACKEND_CODEQL, None,
                    (diag.get("last_error") or "")[:400])
        if res.is_sound:
            return ("sound", proposal.finding_id, _BACKEND_CODEQL, res.query_ql, "")
        reasons = []
        if not res.suppressed_fp:
            reasons.append(f"suppress_fp_failed(after={res.after_count})")
        if not res.preserved_tp:
            reasons.append(f"preserve_tp_failed(before={res.before_count})")
        # Keep the proposed query for not_sound too — it compiled + ran but missed,
        # so it's the diagnostic material for improving the proposer's few-shot.
        return ("not_sound", proposal.finding_id, _BACKEND_CODEQL, res.query_ql,
                "; ".join(reasons))
    finally:
        for p in (repo, after_db, before_db, synth, sarif):
            shutil.rmtree(p, ignore_errors=True) if p.is_dir() else p.unlink(missing_ok=True)


def _aggregate(syn: sqlite3.Connection) -> Tuple[CorpusSynthReport, dict]:
    sound = not_sound = no_barrier = 0
    per: list = []
    errors: Counter = Counter()
    for status, fid in syn.execute("SELECT status, finding_id FROM synth_results"):
        if status in _PIPELINE_ERRORS:
            errors[status] += 1
            continue
        per.append((fid, status))
        if status == "sound":
            sound += 1
        elif status == "not_sound":
            not_sound += 1
        else:
            no_barrier += 1
    report = CorpusSynthReport(total=len(per), sound=sound, not_sound=not_sound,
                               no_barrier=no_barrier, per_finding=tuple(per))
    return report, dict(errors)


def synthesize_from_results(
    results_db: Path, *,
    synth_db: Path = Path("/data/corpus/synth-results.db"),
    work_dir: Path = Path("/data/corpus/clones/bridge"),
    proposer=None,
    model: Optional[str] = None,
    tier1b_model: Optional[str] = None,
    codeql_bin: str = DEFAULT_CODEQL_BIN,
    search_path: Optional[str] = None,
    languages: Optional[Sequence[str]] = None,
    limit: Optional[int] = None,
    max_attempts: int = 3,
    max_refine_attempts: int = 0,
    newest_first: bool = False,
    log=print,
) -> CorpusSynthReport:
    """Synthesize a barrier for every FP candidate (after_count>0) in the walker
    results — resumable + crash-isolated, persisting each outcome to ``synth_db``.
    ``model`` pins the proposer's LLM; default None defers to RAPTOR's LLM config
    (its configured/auto-selected model). Operators override per-run, e.g.
    ``--model claude-opus-4-8``. ``newest_first`` orders by CVE id descending
    (recent, modern-framework code first) rather than the oldest tail. Returns
    the aggregate CorpusSynthReport."""
    if proposer is None:
        completer = model_completer(model) if model else default_completer()
        proposer = make_llm_proposer(completer)
    # Tier 1B uses a separately-pinned cheap-model completer.  Without
    # ``tier1b_model``, Tier 1B is skipped (the call to model_completer
    # would otherwise resolve to the operator's default LLM, which is
    # what the proposer already uses — opting Tier 1B in implicitly is
    # a per-run cost the operator should make explicit).
    tier1b_completer = model_completer(tier1b_model) if tier1b_model else None
    if search_path is None:
        search_path = _default_search_path()
    con = sqlite3.connect(f"file:{results_db}?mode=ro", uri=True)
    sql = ("SELECT fix_hash, cve_id, cwe, repo_language, repo_url, parent_hash, status "
           "FROM walk_results WHERE status IN ('ok','ok_built') AND after_count>0")
    params: tuple = ()
    if languages:
        sql += f" AND repo_language IN ({','.join('?' * len(languages))})"
        params = tuple(languages)
    sql += " ORDER BY cve_id DESC" if newest_first else " ORDER BY cve_id"
    rows = con.execute(sql, params).fetchall()
    con.close()

    syn = sqlite3.connect(str(synth_db))
    syn.execute(_SCHEMA)
    done = {(r[0], r[1]) for r in syn.execute("SELECT fix_hash, cwe FROM synth_results")}
    todo = [r for r in rows if (r[0], r[2]) not in done]
    log(f"bridge: {len(rows)} FP-candidates, {len(done)} already done, {len(todo)} to do")
    work_dir.mkdir(parents=True, exist_ok=True)
    n = 0
    for fix_hash, cve_id, cwe, lang, repo_url, parent_hash, row_status in todo:
        if limit is not None and n >= limit:
            break
        n += 1
        pair = CveFixPair(cve_id, cwe, repo_url, lang, fix_hash, parent_hash)
        try:
            status, fid, backend, barrier_q, detail = synthesize_one(
                pair, work_dir=work_dir / "item", proposer=proposer, status=row_status,
                codeql_bin=codeql_bin, search_path=search_path,
                max_attempts=max_attempts,
                max_refine_attempts=max_refine_attempts,
                tier1b_complete=tier1b_completer)
        except Exception as exc:  # one bad candidate must not abort the whole run
            status, fid, backend, barrier_q, detail = (
                "error", None, _BACKEND_NONE, None,
                f"{type(exc).__name__}: {exc}"[:400])
            log(f"  [{n}/{len(todo)}] {cve_id} {cwe}: ERROR {type(exc).__name__}: {exc}")
        syn.execute("INSERT OR REPLACE INTO synth_results VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (fix_hash, cwe, cve_id, lang, fid, status, backend, barrier_q,
                     detail, time.time()))
        syn.commit()
        if status not in ("error",):
            suffix = f"  [{detail}]" if detail else ""
            tag = f"({backend})" if backend else ""
            log(f"  [{n}/{len(todo)}] {cve_id} {cwe} {lang}: {status}{tag}{suffix}")
    report, errors = _aggregate(syn)
    syn.close()
    if errors:
        log(f"pipeline errors (excluded from rate): {errors}")
    return report


def main(argv=None) -> None:
    import argparse

    ap = argparse.ArgumentParser(description="Synthesize barriers over walker FP-candidates.")
    ap.add_argument("--results", type=Path, default=Path("/data/corpus/walk-results.db"))
    ap.add_argument("--synth-db", type=Path, default=Path("/data/corpus/synth-results.db"))
    ap.add_argument("--work-dir", type=Path, default=Path("/data/corpus/clones/bridge"))
    ap.add_argument("--search-path", default=None,
                    help="codeql query-pack search path (default: ~/.local/codeql-queries)")
    ap.add_argument("--model", default=None,
                    help="override the proposer LLM (e.g. claude-opus-4-8); "
                         "default defers to RAPTOR's LLM config")
    ap.add_argument("--llm-extract-model", default=None,
                    help="enable the LLM-assisted extraction layer "
                         "(adjudicated by Z3 or the curated known-safe "
                         "library table). Picks a cheap model "
                         "(e.g. claude-haiku-4-5). Default off — without "
                         "this flag only the mechanical extractor and "
                         "the proposer LLM are used")
    ap.add_argument("--languages", nargs="+", default=None)
    ap.add_argument("--codeql-bin", default=DEFAULT_CODEQL_BIN)
    ap.add_argument("--max-attempts", type=int, default=3,
                    help="compile-retry budget per refinement cycle (default 3)")
    ap.add_argument("--max-refine-attempts", type=int, default=0,
                    help="soundness-refinement budget (default 0 = no refinement). "
                         "When >0, a successful-but-not-sound barrier feeds its "
                         "verdict back to the proposer for another full compile-and-"
                         "adjudicate cycle; bounded by this budget")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--newest-first", action="store_true",
                    help="process recent CVEs first (modern code) instead of the oldest tail")
    a = ap.parse_args(argv)
    report = synthesize_from_results(
        a.results, synth_db=a.synth_db, work_dir=a.work_dir, codeql_bin=a.codeql_bin,
        search_path=a.search_path, model=a.model,
        tier1b_model=a.llm_extract_model,
        languages=a.languages, limit=a.limit,
        max_attempts=a.max_attempts, max_refine_attempts=a.max_refine_attempts,
        newest_first=a.newest_first,
        log=lambda m: print(m, flush=True))
    print(render_corpus_report(report), flush=True)


if __name__ == "__main__":
    main()
