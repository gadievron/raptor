"""Canonical URL regex patterns + helpers for commit URL extraction.

Single source of truth for GitHub, GitLab, and kernel.org commit URL
patterns used across packages (osv, nvd, cve_diff).
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

GITHUB_COMMIT_URL_RE = re.compile(
    r"https?://github\.com/([^/]+/[^/#?\s]+)/commit/([a-f0-9]{7,40})",
    re.IGNORECASE,
)

GITHUB_REPO_URL_RE = re.compile(
    r"https?://github\.com/([^/]+/[^/#?\s]+)",
    re.IGNORECASE,
)

KERNEL_SHA_URL_RE = re.compile(
    r"(?:kernel\.dance/|git\.kernel\.org/(?:linus|stable)/(?:c/)?)([a-f0-9]{7,40})",
    re.IGNORECASE,
)

LINUX_UPSTREAM_SLUG: str = "torvalds/linux"

SHA_DISPLAY_LEN: int = 12


def normalize_slug(slug: str) -> str:
    """Lower-case, strip ``.git`` suffix, strip whitespace."""
    slug = slug.strip()
    if slug.endswith(".git"):
        slug = slug[:-4]
    return slug.lower()


def extract_github_slug(url: str) -> str | None:
    """Return the canonical ``owner/repo`` slug from any GitHub URL, or None."""
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
