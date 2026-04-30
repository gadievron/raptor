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
    """Return the canonical `owner/repo` slug from any GitHub URL, or None."""
    m = GITHUB_REPO_URL_RE.match(url or "")
    if not m:
        return None
    return normalize_slug(m.group(1))
