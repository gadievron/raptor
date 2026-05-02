"""
OSV (Open Source Vulnerabilities) discoverer.

Primary source of metadata in the cascade (50% success rate on the reference
project's measured runs, no API key, no effective rate limit).

Ported from code-differ/packages/patch_analysis/osv_integration.py, with two
intentional changes:

1. Parsing is a classmethod on plain dict input so it can be unit-tested
   against fixture JSON without going through HTTP.
2. Only `fixed` events produce tuples. `introduced` is treated as advisory
   metadata only; `introduced: '0'` is the OSV sentinel for "from beginning
   of history" and is dropped. This enforces the lesson that ruined Bug #1
   at the type boundary — see core/models.py.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import requests

from cve_diff.core.models import (
    CommitSha,
    DiscoveryResult,
    IntroducedMarker,
    PatchTuple,
)

BASE_URL = "https://api.osv.dev/v1"
DEFAULT_TIMEOUT_S = 10

_COMMIT_SHA_RE = re.compile(r"^[a-f0-9]{7,40}$", re.IGNORECASE)
_GITHUB_COMMIT_URL_RE = re.compile(r"github\.com/([^/]+/[^/]+)/commit/([a-f0-9]{7,40})")
# Linux-kernel short-link patterns carrying the mainline SHA. kernel.dance
# redirects to git.kernel.org; git.kernel.org/{linus,stable}/c/<sha> serve
# mainline SHAs that are reachable from torvalds/linux (stable cherry-picks
# preserve the original SHA when `git cherry-pick -x` is used).
_KERNEL_SHA_URL_RE = re.compile(
    r"(?:kernel\.dance/|git\.kernel\.org/(?:linus|stable)/c/)([a-f0-9]{7,40})",
    re.IGNORECASE,
)
_LINUX_UPSTREAM = "https://github.com/torvalds/linux"


@dataclass
class OSVDiscoverer:
    timeout_s: int = DEFAULT_TIMEOUT_S

    def fetch(self, cve_id: str) -> DiscoveryResult | None:
        """GET /vulns/<cve>, with POST /query fallback on 404."""
        try:
            response = requests.get(f"{BASE_URL}/vulns/{cve_id}", timeout=self.timeout_s)
        except requests.RequestException:
            return None

        if response.status_code == 200:
            return self.parse(response.json())
        if response.status_code == 404:
            return self._batch_query(cve_id)
        return None

    def _batch_query(self, cve_id: str) -> DiscoveryResult | None:
        try:
            response = requests.post(
                f"{BASE_URL}/query",
                json={"queries": [{"aliases": [cve_id]}]},
                timeout=self.timeout_s,
            )
        except requests.RequestException:
            return None
        if response.status_code != 200:
            return None
        data = response.json()
        results = data.get("results", []) or []
        if not results:
            return None
        vulns = results[0].get("vulns") or []
        if not vulns:
            return None
        return self.parse(vulns[0])

    @classmethod
    def parse(cls, vuln: dict[str, Any]) -> DiscoveryResult:
        """Extract PatchTuples + upstream-slug hints from an OSV record.

        Emit order matters: `references[/commit/...]` tuples go first so the
        cascade's "first best-scored wins" selection picks the advisory's
        actual bug-fix commit over the range's fixed-in-release-tag commit.
        """
        tuples: list[PatchTuple] = []
        repos_from_refs: set[str] = set()

        # Pass 1: explicit commit-bearing references — the advisory's chosen
        # "this is the fix" links. Preferred over range.fixed because OSV
        # ranges often carry the *release-tag* commit ("VERSION: 1.1.12")
        # rather than the actual bug-fix commit. Two URL shapes:
        #   - github.com/owner/repo/commit/<sha>      → (owner/repo, sha)
        #   - kernel.dance/<sha> | git.kernel.org/{linus,stable}/c/<sha>
        #     → (torvalds/linux, sha)  — kernel short-links carry mainline SHAs.
        seen_refs: set[tuple[str, str]] = set()
        for ref in vuln.get("references", []) or []:
            url = ref.get("url", "") or ""
            gh = _GITHUB_COMMIT_URL_RE.search(url)
            if gh:
                repo = f"https://github.com/{gh.group(1)}"
                commit = gh.group(2)
            else:
                km = _KERNEL_SHA_URL_RE.search(url)
                if not km:
                    continue
                repo = _LINUX_UPSTREAM
                commit = km.group(1)
            if (repo, commit) in seen_refs:
                continue
            seen_refs.add((repo, commit))
            tuples.append(
                PatchTuple(
                    repository_url=repo,
                    fix_commit=CommitSha(commit),
                    introduced=None,
                )
            )
            repos_from_refs.add(repo)

        # Pass 2: range events — skip a repo if Pass 1 already provided a fix
        # for it (keeps the ref-commit tuple as the preferred candidate).
        seen: set[tuple[str, str]] = {(t.repository_url, t.fix_commit) for t in tuples}
        for affected in vuln.get("affected", []) or []:
            for rng in affected.get("ranges", []) or []:
                if rng.get("type") != "GIT":
                    continue
                repo = cls._normalize_repo(rng.get("repo") or "")
                if not repo:
                    continue
                if repo in repos_from_refs:
                    continue

                introduced_shas = [
                    e["introduced"]
                    for e in rng.get("events", []) or []
                    if e.get("introduced") and e["introduced"] != "0"
                    and _COMMIT_SHA_RE.match(e["introduced"])
                ]
                for event in rng.get("events", []) or []:
                    fixed = event.get("fixed")
                    if not fixed:
                        continue
                    key = (repo, fixed)
                    if key in seen:
                        continue
                    seen.add(key)
                    tuples.append(
                        PatchTuple(
                            repository_url=repo,
                            fix_commit=CommitSha(fixed),
                            introduced=(
                                IntroducedMarker(introduced_shas[0])
                                if introduced_shas
                                else None
                            ),
                        )
                    )

        return DiscoveryResult(
            source="osv",
            tuples=tuple(tuples),
            confidence=min(100, 20 + 40 * (1 if tuples else 0)),
            raw=vuln,
        )

    @staticmethod
    def _normalize_repo(url: str) -> str:
        """Convert OSV ``ranges[].repo`` shapes to a canonical HTTPS form.

        OSV records carry repos in several shapes — git://, ssh://git@,
        and bare ``git@host:path`` SCP-style. We normalise every shape
        to ``https://<host>/<path>`` so downstream consumers (commit
        fetchers, slug extractors) only need to handle one form.
        """
        if not url:
            return ""
        if url.endswith(".git"):
            url = url[:-4]
        if url.startswith("git://"):
            url = "https://" + url[len("git://"):]
        elif url.startswith("ssh://git@"):
            url = "https://" + url[len("ssh://git@"):]
        elif url.startswith("git@"):
            # SCP-style: ``git@<host>:<path>`` (one colon, no scheme).
            # The naive ``.replace("git@", "https://").replace(":", "/", 1)``
            # broke because the second replace clobbered the ``://``
            # separator from the first replace. Split on the FIRST colon
            # explicitly so the host and path are unambiguous.
            rest = url[len("git@"):]
            if ":" in rest:
                host, path = rest.split(":", 1)
                url = f"https://{host}/{path}"
        return url
