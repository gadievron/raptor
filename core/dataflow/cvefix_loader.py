"""Load CVE fix-commit pairs from a CVEfixes metadata SQLite DB.

Queries a CVEfixes metadata DB (the relational dump, optionally with the
code-blob tables `method_change`/`file_change` skipped — they're irrelevant
here) for fix-commits of given CWEs in CodeQL-supported languages, yielding
before/after commit pairs. The trust-corpus pipeline then clones each repo at
the fix + parent commits and builds CodeQL DBs — so we need the repo URL +
fix hash + parent hash, not the per-method code blobs.

Join path: `cwe_classification(cve_id, cwe_id)` → `fixes(cve_id, hash, repo_url)`
→ `commits(hash, parents)` → `repository(repo_url, repo_language)`. The
`parents` column is a Python-list-repr string (e.g. `"['abc...']"`); we keep
only single-parent commits (merges have ambiguous before-state).

PHP is excluded: it's the largest injection bucket but has no CodeQL extractor
.
"""

from __future__ import annotations

import ast
import logging
import sqlite3
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence

logger = logging.getLogger(__name__)

# CodeQL-supported languages present in CVEfixes repo_language values.
CODEQL_LANGUAGES = (
    "Python", "Java", "JavaScript", "TypeScript", "Go", "Ruby", "C", "C++", "C#",
)

# Injection CWEs the trust sound-tier targets.
#
# CWE-94 (code injection) and CWE-918 (SSRF) added 2026-05-30 to extend the
# walk corpus.  CWE-94 has a Tier-2-shaped fix pattern (charset / allowlist
# strip before eval/exec); CWE-918 is allowlist-on-URL-host shape, only
# Tier 2 viable.  CWE-611/352 omitted — their fixes are parser-config /
# middleware shape, not value-barrier shape.
INJECTION_CWES = ("CWE-89", "CWE-78", "CWE-79", "CWE-22", "CWE-94", "CWE-918")


@dataclass(frozen=True)
class CveFixPair:
    cve_id: str
    cwe: str
    repo_url: str
    repo_language: str
    fix_hash: str       # the fix commit — post-fix (AFTER) state
    parent_hash: str    # its single parent — pre-fix (BEFORE) state


def _single_parent(parents_repr: Optional[str]) -> Optional[str]:
    """Extract the lone parent hash from the list-repr string; None for merges
    (≥2 parents), roots (0), or anything unparseable."""
    if not parents_repr:
        return None
    try:
        parents = ast.literal_eval(parents_repr)
    except (ValueError, SyntaxError):
        return None
    if isinstance(parents, (list, tuple)) and len(parents) == 1:
        return str(parents[0])
    return None


def load_pairs(
    db_path: Path,
    *,
    cwes: Sequence[str] = INJECTION_CWES,
    languages: Sequence[str] = CODEQL_LANGUAGES,
    limit: Optional[int] = None,
) -> List[CveFixPair]:
    """Return CodeQL-buildable before/after CVE fix-commit pairs."""
    cwe_ph = ",".join("?" * len(cwes))
    lang_ph = ",".join("?" * len(languages))
    sql = f"""
        SELECT DISTINCT f.cve_id, c.cwe_id, f.repo_url, r.repo_language,
               f.hash, cm.parents
        FROM fixes f
        JOIN cwe_classification c ON f.cve_id = c.cve_id
        JOIN commits cm ON f.hash = cm.hash
        JOIN repository r ON f.repo_url = r.repo_url
        WHERE c.cwe_id IN ({cwe_ph})
          AND r.repo_language IN ({lang_ph})
          AND f.repo_url LIKE 'https://github.com/%'
        ORDER BY f.cve_id
    """
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        rows = con.execute(sql, (*cwes, *languages)).fetchall()
    finally:
        con.close()

    pairs: List[CveFixPair] = []
    for cve_id, cwe, repo_url, lang, fix_hash, parents in rows:
        parent = _single_parent(parents)
        if parent is None:
            continue
        pairs.append(CveFixPair(cve_id, cwe, repo_url, lang, fix_hash, parent))
        if limit is not None and len(pairs) >= limit:
            break
    return pairs


# ── /cve-diff run directories as a live pair source ──────────────────────────
#
# The CVEfixes SQLite dump is a periodically published dataset; a fresh
# CVE the walk should exercise may not be in it for months. /cve-diff
# produces the same (repo, fix, parent) triple live, with public
# provenance enforced by packages.checker_synthesis.cve_bridge's OSV
# gate. This loader maps those run artifacts onto the SAME CveFixPair
# contract load_pairs yields, so cvefix_walk and the corpus generator
# consume either source unchanged.

# File-extension → CVEfixes ``repo_language`` values (the subset in
# CODEQL_LANGUAGES). ``.h`` is credited to C; a C++ project's other
# changed files vote it back via majority.
_EXT_LANGUAGE = {
    ".py": "Python",
    ".java": "Java",
    ".js": "JavaScript", ".jsx": "JavaScript",
    ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript",
    ".go": "Go",
    ".rb": "Ruby",
    ".c": "C", ".h": "C",
    ".cc": "C++", ".cpp": "C++", ".cxx": "C++",
    ".hpp": "C++", ".hh": "C++",
    ".cs": "C#",
}


def infer_language_from_paths(paths: Sequence[str]) -> str:
    """Majority-vote language over changed-file extensions; "" when no
    recognised extension appears (the caller must then skip — guessing
    would poison the walk corpus)."""
    votes = Counter(
        _EXT_LANGUAGE[Path(p).suffix.lower()]
        for p in paths
        if Path(p).suffix.lower() in _EXT_LANGUAGE
    )
    if not votes:
        return ""
    return votes.most_common(1)[0][0]


def load_pairs_from_cve_diff_runs(
    run_dirs: Sequence[Path],
    *,
    cwes: Sequence[str] = INJECTION_CWES,
    languages: Sequence[str] = CODEQL_LANGUAGES,
    limit: Optional[int] = None,
) -> List[CveFixPair]:
    """Return CveFixPairs parsed from /cve-diff output directories.

    Acceptance contract mirrors :func:`load_pairs`: GitHub-hosted repos,
    requested CWEs, CodeQL-supported languages, and a resolvable
    before/after commit pair. Records are skipped (with a debug log)
    when they lack a root-cause CWE (run without ``--with-root-cause``),
    a parent pointer (``database_specific.diff_against``), or an
    inferable language. Provenance validation is delegated to
    ``packages.checker_synthesis.cve_bridge.load_cve_run`` — the same
    OSV gate the checker-synthesis bridge enforces.
    """
    from packages.checker_synthesis.cve_bridge import (
        ProvenanceError,
        load_cve_run,
    )

    pairs: List[CveFixPair] = []
    for run_dir in run_dirs:
        try:
            rec = load_cve_run(run_dir)
        except ProvenanceError as exc:
            logger.debug("cvefix: skipping %s: %s", run_dir, exc)
            continue
        if not rec.parent_commit:
            logger.debug(
                "cvefix: %s has no parent pointer — skipping", rec.cve_id)
            continue
        if rec.cwe not in cwes:
            logger.debug(
                "cvefix: %s CWE %r outside requested set — skipping",
                rec.cve_id, rec.cwe)
            continue
        if not rec.repository_url.startswith("https://github.com/"):
            logger.debug(
                "cvefix: %s repo %s not GitHub-hosted — skipping",
                rec.cve_id, rec.repository_url)
            continue
        language = infer_language_from_paths(
            [f.path for f in rec.files if not f.is_test]
        )
        if language not in languages:
            logger.debug(
                "cvefix: %s language %r outside requested set — skipping",
                rec.cve_id, language)
            continue
        pairs.append(CveFixPair(
            cve_id=rec.cve_id,
            cwe=rec.cwe,
            repo_url=rec.repository_url,
            repo_language=language,
            fix_hash=rec.fix_commit,
            parent_hash=rec.parent_commit,
        ))
        if limit is not None and len(pairs) >= limit:
            break
    return pairs
