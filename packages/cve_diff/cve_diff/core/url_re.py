"""
Canonical URL regex + helpers, single source of truth.

Consolidates four near-duplicate copies that drifted with subtle
differences (whitespace handling, scheme presence, case sensitivity).
Empirical audit 2026-04-25 found copies in:
  - cve_diff/agent/invariants.py
  - cve_diff/agent/tools.py
  - cve_diff/discovery/canonical.py
  - cve_diff/diffing/extractor.py
  - tools/oracle/osv_oracle.py

All consumers now import from here.
"""

from __future__ import annotations

import re

# `https://github.com/<owner>/<repo>/commit/<sha>` — used to extract
# both the slug and the commit SHA from OSV/NVD reference URLs and
# advisory pages. Excludes whitespace and trailing punctuation in the
# repo segment to avoid grabbing markdown-link wrappers.
GITHUB_COMMIT_URL_RE = re.compile(
    r"https?://github\.com/([^/]+/[^/#?\s]+)/commit/([a-f0-9]{7,40})",
    re.IGNORECASE,
)

# `https://github.com/<owner>/<repo>` (any tail). Used to extract the
# slug from a repo URL (no `/commit/<sha>` requirement). Allows `.` in
# the repo segment so dotted names like ``socketio/engine.io``,
# ``expressjs/express.js``, ``microsoft/vscode.dev`` are preserved.
# ``.git`` suffix stripping is handled downstream by ``normalize_slug``.
# Bug previously: this regex excluded `.` from the second segment,
# silently truncating ``engine.io`` → ``engine`` and producing
# ``sha_not_found_in_repo`` on the commit-exists invariant. Caught
# 2026-04-26 by the OSS 2022-2024 bench (CVE-2022-21676).
GITHUB_REPO_URL_RE = re.compile(
    r"https?://github\.com/([^/]+/[^/#?\s]+)",
    re.IGNORECASE,
)

# Linux-kernel shortlinks used by OSV, NVD, and distro security
# trackers. All carry a mainline SHA reachable from torvalds/linux
# thanks to `cherry-pick -x` preserving SHAs. Two cgit shortlink
# shapes exist in the wild: the older `linus/<sha>` (Debian's
# security-tracker uses this) and the newer `linus/c/<sha>` (OSV).
KERNEL_SHA_URL_RE = re.compile(
    r"(?:kernel\.dance/|git\.kernel\.org/(?:linus|stable)/(?:c/)?)([a-f0-9]{7,40})",
    re.IGNORECASE,
)

# When a kernel-shortlink hit fires, all three (slug, sha, sha) tuples
# we emit point at this slug.
LINUX_UPSTREAM_SLUG: str = "torvalds/linux"


def normalize_slug(slug: str) -> str:
    """Lower-case, strip `.git` suffix, strip whitespace.

    Used everywhere we compare slugs from disparate sources (OSV
    references, NVD CPE-to-repo guesses, GitHub API responses, kernel
    shortlinks). Lower-casing prevents `Curl/curl` ≠ `curl/curl` false
    diffs; `.git` stripping prevents `slug.git` ≠ `slug`.
    """
    slug = slug.strip()
    if slug.endswith(".git"):
        slug = slug[:-4]
    return slug.lower()


def extract_github_slug(url: str) -> str | None:
    """Return the canonical `owner/repo` slug from any GitHub URL, or None.

    Uses ``.search()`` so embedded URLs (e.g. an OSV reference body
    like ``"see fix at https://github.com/owner/repo"``) are matched.
    Pre-2026-05-02 used ``.match()``, which only matched at position 0
    and silently dropped any URL with leading prose — a real hit when
    OSV/NVD authors wrap the URL in advisory text. Consistent with
    ``discovery/osv.py``'s ``_GITHUB_COMMIT_URL_RE.search()`` usage.
    """
    m = GITHUB_REPO_URL_RE.search(url or "")
    if not m:
        return None
    return normalize_slug(m.group(1))


def _hostname(url: str) -> str:
    """Lowercase hostname or empty string. Stdlib ``urlparse`` is
    strict enough for our cases — it pulls the host out of the
    authority component and ignores path content. Empty string on
    parse failures so callers stay total-functional.
    """
    from urllib.parse import urlparse
    try:
        return (urlparse(url).hostname or "").lower()
    except (ValueError, AttributeError):
        return ""


def is_github_url(url: str) -> bool:
    """Pre-2026-05-02 several callers used ``"github.com" in url``,
    which CodeQL flagged as ``incomplete-url-substring-sanitization``:
    ``https://github.com.evil.com/...`` matches as a substring but is
    not a GitHub URL. Hostname-anchored check fixes that.
    """
    h = _hostname(url)
    return h == "github.com" or h.endswith(".github.com")


def is_gitlab_url(url: str) -> bool:
    """Canonical ``gitlab.com`` URL (including subdomains like
    ``salsa.debian.org``-style mirrors that proxy to
    ``*.gitlab.com``). Hostname-anchored — same threat model as
    :func:`is_github_url`.

    Self-hosted GitLab instances (``gitlab.<vendor>.com``) intentionally
    fall through. Naive label-anchored matches are still bypassable
    (``gitlab.com.evil.com`` starts with ``gitlab.``) and the only
    consumer in cve-diff today (bench telemetry classification) is
    happy to lose self-hosted attribution rather than accept the
    bypass surface. Callers that need self-hosted detection use
    ``_gitlab_host_and_slug`` for full host parsing.
    """
    h = _hostname(url)
    return h == "gitlab.com" or h.endswith(".gitlab.com")


def is_kernel_org_url(url: str) -> bool:
    """``kernel.org`` and subdomains (``git.kernel.org``,
    ``patchwork.kernel.org`` etc.). Hostname-anchored — closes
    the same ``kernel.org`` substring footgun as
    :func:`is_github_url`."""
    h = _hostname(url)
    return h == "kernel.org" or h.endswith(".kernel.org")
