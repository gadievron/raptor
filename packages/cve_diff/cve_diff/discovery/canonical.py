"""
Canonical-repo scoring.

Discoverers may return any URL referenced in a CVE advisory, including CVE
tracker repos (advisory DBs, POC dumps, etc.). This module maps those URLs
onto a numeric score; the pipeline refuses a `RepoRef` with score ≤ 0 so
tracker-redirects are filtered before acquisition (Bug #5).

Port of the scoring logic from
  code-differ/packages/patch_analysis/canonical_mapping_cache.py
but without the SQLite cache — Phase 1 runs entirely in-memory.
"""

from __future__ import annotations

import re

from cve_diff.core.url_re import GITHUB_REPO_URL_RE, extract_github_slug as _extract_slug
from cve_diff.discovery.constants import GITHUB_MIRRORS, TRACKER_REPO_PATTERNS

_TRACKER_RES = tuple(re.compile(p, re.IGNORECASE) for p in TRACKER_REPO_PATTERNS)


def apply_mirror(url: str) -> str:
    """Replace a non-GitHub URL with its GitHub mirror if we know one."""
    for pattern, replacement in GITHUB_MIRRORS.items():
        if pattern in url:
            return replacement
    return url


def is_tracker(url: str) -> bool:
    slug = _extract_slug(url)
    if slug is None:
        return False
    return any(regex.search(slug) for regex in _TRACKER_RES)


def score(url: str) -> int:
    """
    Score a candidate repo URL. Higher is better.

    Ranges:
      0   → tracker / disallowed
      50  → non-GitHub URL (may need mirror mapping)
      100 → GitHub source repo, not a tracker
    """
    if not url:
        return 0
    mapped = apply_mirror(url)
    if is_tracker(mapped):
        return 0
    if GITHUB_REPO_URL_RE.match(mapped):
        return 100
    return 50
