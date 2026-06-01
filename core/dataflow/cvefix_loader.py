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
(see `~/design/trust-witness.md` §10 — PHP needs the Semgrep-flavored tier).
"""

from __future__ import annotations

import ast
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence

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
