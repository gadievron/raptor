"""Canonical URL regex patterns + helpers for commit URL extraction.

Single source of truth for GitHub, GitLab, and kernel.org commit URL
patterns used across packages (osv, nvd, cve_diff).
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

# SHA captures: `{7,64}` to accept both SHA-1 (40 hex) and
# SHA-256 (64 hex) git object names. Pre-fix `{7,40}` upper-
# bound at 40 chars truncated SHA-256 hashes mid-string —
# git repos that have migrated to SHA-256 (still rare in
# 2026 but increasingly real) had their commit URLs
# match-but-truncate, capturing only the first 40 of 64
# chars. Subsequent SHA comparisons (cve_diff oracle, OSV
# patch verify) then compared the truncated value against
# full-length SHAs and reported "no match" for legitimate
# patches. Trailing `\b` boundary so a URL with extra hex
# characters appended (operator typo, copy-paste artefact)
# doesn't have its SHA portion silently truncated either.
GITHUB_COMMIT_URL_RE = re.compile(
    r"https?://github\.com/([^/]+/[^/#?\s]+)/commit/([a-f0-9]{7,64})\b",
    re.IGNORECASE,
)

GITHUB_REPO_URL_RE = re.compile(
    r"https?://github\.com/([^/]+/[^/#?\s]+)",
    re.IGNORECASE,
)

KERNEL_SHA_URL_RE = re.compile(
    r"(?:kernel\.dance/|git\.kernel\.org/(?:linus|stable)/(?:c/)?)([a-f0-9]{7,64})\b",
    re.IGNORECASE,
)

LINUX_UPSTREAM_SLUG: str = "torvalds/linux"

SHA_DISPLAY_LEN: int = 12


def normalize_slug(slug: str) -> str:
    """Lower-case, strip ``.git`` suffix, strip whitespace.

    Pre-fix didn't strip TRAILING PUNCTUATION (`)`, `]`, `>`,
    `,`, `.`, `;`). The capture regex `[^/]+/[^/#?\\s]+`
    excludes only `/`, `#`, `?`, whitespace — so a URL
    appearing in prose like:

        (see https://github.com/foo/bar)
        cite: https://github.com/foo/bar.
        list: https://github.com/foo/bar; https://...

    extracts `foo/bar)`, `foo/bar.`, `foo/bar;` respectively.
    Downstream consumers (cve_diff oracle, scorecard slug
    keys) then key on the puncutated form and miss matches
    against canonical `foo/bar`.

    Strip trailing punctuation chars that are never legal in
    a github slug.
    """
    slug = slug.strip()
    # Strip trailing punctuation iteratively (multiple chars
    # may have been captured: e.g. `slug.,`).
    while slug and slug[-1] in ")]>,.;":
        slug = slug[:-1]
    if slug.endswith(".git"):
        slug = slug[:-4]
    return slug.lower()


def extract_github_slug(url: str) -> str | None:
    """Return the canonical ``owner/repo`` slug from any GitHub URL, or None.

    Uses `re.search` (not `re.match`) by design — advisory text often
    embeds GitHub URLs in prose ("see fix at https://github.com/...",
    "Mitigated by https://github.com/...") and callers depend on
    extracting the slug from that prose. See
    `tests/unit/test_url_re.py::test_extract_slug_finds_embedded_url`
    for the regression coverage. Pre-fix this docstring didn't name
    the contract, so a future maintainer might tighten to `re.match`
    and silently break advisory ingestion.
    """
    m = GITHUB_REPO_URL_RE.search(url or "")
    if not m:
        return None
    return normalize_slug(m.group(1))


def _hostname(url: str) -> str:
    """Lowercase hostname or empty string."""
    try:
        return (urlparse(url).hostname or "").lower()
    except (ValueError, AttributeError):
        return ""


def is_github_url(url: str) -> bool:
    """Hostname-anchored check (not substring)."""
    h = _hostname(url)
    return h == "github.com" or h.endswith(".github.com")


def is_gitlab_url(url: str) -> bool:
    """Hostname-anchored check for gitlab.com (not self-hosted)."""
    h = _hostname(url)
    return h == "gitlab.com" or h.endswith(".gitlab.com")


def is_kernel_org_url(url: str) -> bool:
    """Hostname-anchored check for kernel.org and subdomains."""
    h = _hostname(url)
    return h == "kernel.org" or h.endswith(".kernel.org")
