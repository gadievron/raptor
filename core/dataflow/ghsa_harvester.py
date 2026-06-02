"""Harvest a CVEfixes-shaped metadata DB from the GHSA Advisory Database.

The trust-witness corpus measurement (the 87-FP-candidate run on CVEfixes
v1.0.8) is bounded by what was in CVEfixes-v1.0.8 (data through ~Sep 2024).
This harvester reconstructs a metadata DB in the same schema from a more
recent slice — github/advisory-database, which is git-cloneable, regularly
updated, and has explicit fix-commit URLs in its references.

Filter chain mirrors :mod:`cvefix_loader`'s defaults: published in the
year range, CWE in the target set, ecosystem maps to a CodeQL-supported
language, and at least one ``github.com/<owner>/<repo>/commit/<sha>``
reference is present.  Parent SHA is resolved by a depth-2 shallow fetch
against the repo (no GitHub API, no token, no rate limit).

Output is a SQLite DB whose ``fixes`` / ``commits`` / ``repository`` /
``cwe_classification`` tables are populated with exactly the columns
:func:`cvefix_loader.load_pairs` reads.  Other CVEfixes columns are
intentionally absent — load_pairs ignores them and adding them would
fabricate data we don't have.  Sibling harvesters (e.g. for NVD) could
plug into the same schema.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sqlite3
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Tuple

# Ecosystem -> CVEfixes ``repo_language`` value.  Restricted to languages
# the walker explicitly supports (cvefix_walk._LANG_MAP).  npm packages
# may be JS or TS; the walker maps both to the ``javascript`` extractor,
# so JS is the safe default — no information is lost, and TS-specific
# repos still extract correctly.
#
# Go and NuGet (C#) are intentionally omitted: cvefix_walk has no Go/C#
# extractor wiring and would silently default them to ``javascript``
# (producing garbage findings or none).  Add them here once the
# C/C++/Go walk substrate (task B) lands.
_ECOSYSTEM_LANG = {
    "npm": "JavaScript",
    "PyPI": "Python",
    "Maven": "Java",
    "RubyGems": "Ruby",
}

# Default CWE set — matches the trust-witness substrate's sink-class
# coverage (4 originals + the 2 expansions in cvefix_loader.INJECTION_CWES).
_DEFAULT_CWES = ("CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-918")

# Default year range — 2024-2026 is the post-CVEfixes-v1.0.8 slice.
_DEFAULT_YEARS = ("2024", "2025", "2026")

# ``github.com/owner/repo/commit/sha`` — strict, full SHA preferred but
# accept 7-40 hex chars (GHSA refs sometimes use shortened SHAs).  We
# need an EXACT SHA for `git fetch` so short SHAs won't work — but the
# harvester still records them and the parent-resolution step will fail
# them; that's a tracked decline, not silent loss.
_COMMIT_RE = re.compile(
    r"github\.com/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+)/commit/([0-9a-f]{7,40})"
)


@dataclass(frozen=True)
class HarvestedFix:
    cve_id: str
    cwe: str
    repo_url: str
    repo_language: str
    fix_hash: str
    parent_hash: Optional[str]  # None if resolution failed


# ---------------------------------------------------------------------------
# Advisory iteration + filter
# ---------------------------------------------------------------------------

def _iter_advisories(
    root: Path, years: Iterable[str], cwes: set, ecosystems: set,
) -> Iterable[Tuple[Path, dict]]:
    """Yield ``(json_path, advisory_dict)`` for advisories matching the
    CWE + ecosystem filter.  Subtree restricted to ``github-reviewed/<year>``
    (the curated namespace; ``unreviewed`` is auto-imported NVD with much
    noisier metadata)."""
    base = root / "advisories" / "github-reviewed"
    if not base.is_dir():
        raise SystemExit(f"GHSA root does not contain advisories/github-reviewed: {root}")
    for y in years:
        ydir = base / y
        if not ydir.is_dir():
            continue
        for jp in ydir.rglob("*.json"):
            try:
                adv = json.loads(jp.read_text())
            except Exception:
                continue
            adv_cwes = set(adv.get("database_specific", {}).get("cwe_ids", []))
            if not (adv_cwes & cwes):
                continue
            ecos = {a.get("package", {}).get("ecosystem")
                    for a in adv.get("affected", [])}
            if not (ecos & ecosystems):
                continue
            yield jp, adv


def _first_commit_ref(adv: dict) -> Optional[Tuple[str, str, str]]:
    """Return ``(owner, repo, sha)`` for the first
    ``github.com/.../commit/SHA`` URL in ``references``, or None."""
    for r in adv.get("references", []):
        m = _COMMIT_RE.search(r.get("url", ""))
        if m:
            return m.group(1), m.group(2), m.group(3)
    return None


def _pick_cwe_eco(adv: dict, cwes: set, ecosystems: set) -> Tuple[str, str]:
    """Pick ONE (CWE, ecosystem) tuple from the advisory's intersection
    with our filter — sorted for determinism so the same advisory always
    gets the same label across runs.  Multi-CWE advisories are
    deliberately recorded under a single CWE for the trust-witness walk;
    if the same fix is interesting under multiple CWEs, a future
    extension can iterate ``cwes & adv_cwes``."""
    adv_cwes = sorted(set(adv.get("database_specific", {}).get("cwe_ids", [])) & cwes)
    adv_ecos = sorted({a.get("package", {}).get("ecosystem")
                       for a in adv.get("affected", [])} & ecosystems)
    return adv_cwes[0], adv_ecos[0]


# ---------------------------------------------------------------------------
# Parent SHA resolution via shallow fetch
# ---------------------------------------------------------------------------

def _resolve_parent(repo_url: str, fix_hash: str, timeout: int = 60) -> Optional[str]:
    """Depth-2 shallow-fetch ``fix_hash`` and return ``fix^1``.  Returns
    None on fetch / parse failure (gone repos, missing SHAs, merges with
    multiple parents).  No GitHub API — pure git protocol, no rate
    limits and no token required.

    Each call creates and destroys its own scratch dir so failures don't
    pollute later calls; the parent walker repeats the fetch on its own,
    so we don't bother caching the clone."""
    with tempfile.TemporaryDirectory(prefix="ghsa-resolve-") as td:
        td_p = Path(td)
        try:
            subprocess.run(["git", "init", "-q", str(td_p)],
                           check=True, timeout=15, capture_output=True)
            subprocess.run(["git", "-C", str(td_p), "remote", "add", "origin", repo_url],
                           check=True, timeout=15, capture_output=True)
            r = subprocess.run(
                ["git", "-C", str(td_p), "fetch", "-q", "--depth", "2",
                 "origin", fix_hash],
                check=False, timeout=timeout, capture_output=True,
            )
            if r.returncode != 0:
                return None
            r = subprocess.run(
                ["git", "-C", str(td_p), "rev-list", "--parents", "-n", "1", fix_hash],
                check=False, timeout=15, capture_output=True, text=True,
            )
            if r.returncode != 0:
                return None
            parts = r.stdout.split()
            # `rev-list --parents -n 1 <sha>` -> "<sha> <parent1> [<parent2> ...]"
            # We want the single-parent case: exactly one parent.  Merge
            # commits (2+ parents) and roots (0 parents) are deliberately
            # dropped — matches CVEfixes' own _single_parent filter.
            if len(parts) != 2:
                return None
            return parts[1]
        except (subprocess.TimeoutExpired, OSError):
            return None


# ---------------------------------------------------------------------------
# DB writer (CVEfixes-meta schema, minimal columns)
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS fixes (
    cve_id TEXT, hash TEXT, repo_url TEXT,
    PRIMARY KEY (cve_id, hash)
);
CREATE TABLE IF NOT EXISTS commits (
    hash TEXT PRIMARY KEY, repo_url TEXT, parents TEXT
);
CREATE TABLE IF NOT EXISTS cwe_classification (
    cve_id TEXT, cwe_id TEXT,
    PRIMARY KEY (cve_id, cwe_id)
);
CREATE TABLE IF NOT EXISTS repository (
    repo_url TEXT PRIMARY KEY, repo_language TEXT
);
"""


def _write_metadata_db(db_path: Path, harvested: list) -> None:
    """Write the harvested fixes into a fresh metadata DB.  Schema
    columns are exactly what :func:`cvefix_loader.load_pairs` needs;
    extras are deliberately omitted (don't fabricate data)."""
    if db_path.exists():
        db_path.unlink()
    con = sqlite3.connect(db_path)
    try:
        con.executescript(_SCHEMA)
        for h in harvested:
            con.execute(
                "INSERT OR IGNORE INTO fixes (cve_id, hash, repo_url) VALUES (?,?,?)",
                (h.cve_id, h.fix_hash, h.repo_url),
            )
            # CVEfixes uses a Python-list-repr string for ``parents``;
            # match that exactly so cvefix_loader._single_parent parses it
            # without any code change.
            parents_repr = repr([h.parent_hash]) if h.parent_hash else "[]"
            con.execute(
                "INSERT OR IGNORE INTO commits (hash, repo_url, parents) VALUES (?,?,?)",
                (h.fix_hash, h.repo_url, parents_repr),
            )
            con.execute(
                "INSERT OR IGNORE INTO cwe_classification (cve_id, cwe_id) VALUES (?,?)",
                (h.cve_id, h.cwe),
            )
            con.execute(
                "INSERT OR IGNORE INTO repository (repo_url, repo_language) VALUES (?,?)",
                (h.repo_url, h.repo_language),
            )
        con.commit()
    finally:
        con.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ghsa-root", required=True, type=Path,
                    help="path to the cloned github/advisory-database repo")
    ap.add_argument("--out", required=True, type=Path,
                    help="output SQLite metadata DB")
    ap.add_argument("--years", nargs="+", default=list(_DEFAULT_YEARS))
    ap.add_argument("--cwes", nargs="+", default=list(_DEFAULT_CWES))
    ap.add_argument("--ecosystems", nargs="+", default=list(_ECOSYSTEM_LANG.keys()))
    ap.add_argument("--sample-size", type=int, default=None,
                    help="random sample of N matching advisories (post-filter, "
                         "pre-resolve); default: take all")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--resolve-timeout", type=int, default=60,
                    help="per-fetch timeout in seconds (default 60)")
    ap.add_argument("--max-parent-failures", type=int, default=None,
                    help="abort if more than N consecutive parent-resolutions "
                         "fail (network outage signal)")
    args = ap.parse_args(argv)

    cwes_set = set(args.cwes)
    eco_set = set(args.ecosystems) & set(_ECOSYSTEM_LANG.keys())
    unknown_eco = set(args.ecosystems) - eco_set
    if unknown_eco:
        print(f"WARN: unsupported ecosystems ignored: {sorted(unknown_eco)}",
              file=sys.stderr)

    # Pass 1: filter advisories down to ones with a commit ref.
    candidates = []
    for jp, adv in _iter_advisories(args.ghsa_root, args.years, cwes_set, eco_set):
        ref = _first_commit_ref(adv)
        if ref is None:
            continue
        aliases = adv.get("aliases", [])
        cve_aliases = [a for a in aliases if a.startswith("CVE-")]
        if not cve_aliases:
            continue
        cve_id = cve_aliases[0]
        cwe, eco = _pick_cwe_eco(adv, cwes_set, eco_set)
        owner, repo, sha = ref
        repo_url = f"https://github.com/{owner}/{repo}"
        candidates.append((cve_id, cwe, repo_url, _ECOSYSTEM_LANG[eco], sha))
    print(f"GHSA scan: {len(candidates)} candidates (CWE + ecosystem + commit-ref + CVE alias)")

    # Sample (unbiased) before the expensive parent-resolve step.
    rng = random.Random(args.seed)
    if args.sample_size is not None and args.sample_size < len(candidates):
        rng.shuffle(candidates)
        candidates = candidates[:args.sample_size]
        print(f"sampled to {len(candidates)} (seed={args.seed})")

    # Pass 2: resolve parents per advisory.  Skip the ones we can't fetch.
    harvested = []
    consecutive_fails = 0
    for i, (cve_id, cwe, repo_url, lang, sha) in enumerate(candidates, 1):
        parent = _resolve_parent(repo_url, sha, timeout=args.resolve_timeout)
        if parent is None:
            consecutive_fails += 1
            print(f"  [{i}/{len(candidates)}] {cve_id} {cwe} {lang} {repo_url}: "
                  f"FETCH FAIL (sha={sha[:8]})")
            if (args.max_parent_failures is not None
                    and consecutive_fails >= args.max_parent_failures):
                print(f"ABORT: {consecutive_fails} consecutive fetch failures — "
                      f"likely network issue", file=sys.stderr)
                return 2
            continue
        consecutive_fails = 0
        harvested.append(HarvestedFix(cve_id, cwe, repo_url, lang, sha, parent))
        print(f"  [{i}/{len(candidates)}] {cve_id} {cwe} {lang} "
              f"{repo_url.split('github.com/')[-1]}: parent={parent[:8]}")

    _write_metadata_db(args.out, harvested)
    print(f"=== HARVEST {len(harvested)}/{len(candidates)} usable -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
