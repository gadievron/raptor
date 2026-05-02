"""
OSV (Open Source Vulnerabilities) discoverer.

Primary source of metadata in the cascade (50% success rate on the reference
project's measured runs, no API key, no effective rate limit).

Wraps :mod:`packages.osv` (shared OSV.dev wire-format client + parser)
with cve-diff's domain mapping: ``OsvRecord`` → ``DiscoveryResult``
with ``PatchTuple`` candidates extracted from references and GIT
ranges. Wire-format parsing + HTTP transport live in :mod:`packages.osv`.

Behaviour preserved:

1. Parsing is a classmethod on plain dict input so it can be unit-tested
   against fixture JSON without going through HTTP.
2. Only `fixed` events produce tuples. `introduced` is treated as advisory
   metadata only; `introduced: '0'` is the OSV sentinel for "from beginning
   of history" and is dropped. This enforces the lesson that ruined Bug #1
   at the type boundary — see core/models.py.

Behaviour changed (this rewire, 2026-05-02):

* The legacy ``POST /v1/query`` 404-fallback is dropped. The body shape
  the previous code sent (``{"queries": [...]}``) didn't match OSV's
  ``/query`` endpoint contract, so the fallback returned ``None``
  deterministically in production while looking like a working path in
  tests via mocked responses. Removing it eliminates the latent
  inconsistency. OSV's ``/vulns/<id>`` endpoint resolves CVE / GHSA /
  DSA aliases server-side, so a separate alias-lookup pass isn't needed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from packages.osv import OsvClient, OsvRecord, parse_record as _shared_parse_record

from cve_diff.core.models import (
    CommitSha,
    DiscoveryResult,
    IntroducedMarker,
    PatchTuple,
)
from cve_diff.core.url_re import (
    GITHUB_COMMIT_URL_RE,
    KERNEL_SHA_URL_RE,
    LINUX_UPSTREAM_SLUG,
)

DEFAULT_TIMEOUT_S = 10

import re

_COMMIT_SHA_RE = re.compile(r"^[a-f0-9]{7,40}$", re.IGNORECASE)
_LINUX_UPSTREAM = f"https://github.com/{LINUX_UPSTREAM_SLUG}"


def _build_default_client(timeout_s: int) -> OsvClient:
    """Construct a stand-alone :class:`packages.osv.OsvClient` for the discoverer.

    OSVDiscoverer is used outside the agent loop (cascade / bench paths),
    so we build our own thin transport rather than reusing the agent's
    egress proxy. ``UrllibClient`` (no host allowlist) is appropriate
    here — the only host this module ever talks to is ``api.osv.dev``,
    hard-coded by ``packages.osv.client.OSV_BASE_URL``.
    """
    from core.http.urllib_backend import UrllibClient
    return OsvClient(http=UrllibClient(user_agent="cve-diff/0.1"))


@dataclass
class OSVDiscoverer:
    """Domain wrapper around :class:`packages.osv.OsvClient`.

    Maps schema-agnostic ``OsvRecord`` to cve-diff's ``DiscoveryResult``
    (commit-SHA candidates from references and GIT ranges). The OSV
    client is constructed lazily on first ``fetch()`` so tests can keep
    constructing ``OSVDiscoverer()`` without HTTP setup.
    """

    timeout_s: int = DEFAULT_TIMEOUT_S
    client: OsvClient | None = None

    def fetch(self, cve_id: str) -> DiscoveryResult | None:
        """``GET /vulns/<cve_id>`` via the shared OSV client.

        Returns ``None`` on 404 / network error / parse failure (the
        shared client logs and swallows these). OSV resolves CVE /
        GHSA / DSA aliases server-side, so no separate alias-lookup
        pass is needed.
        """
        client = self.client or _build_default_client(self.timeout_s)
        record = client.get_vuln(cve_id)
        if record is None:
            return None
        return self._record_to_result(record)

    @classmethod
    def parse(cls, vuln: dict[str, Any]) -> DiscoveryResult:
        """Parse an OSV record dict into a :class:`DiscoveryResult`.

        Test-friendly entrypoint: takes the raw fixture JSON and runs
        it through ``packages.osv.parse_record`` first, then through
        cve-diff's domain mapping. cve-diff's domain mapping never reads
        the OSV ``id`` (only ``references`` and ``affected[].ranges``),
        so test fixtures that omit ``id`` get a synthetic placeholder
        rather than failing the shared parser's sanity check — preserves
        the legacy test-fixture shape.
        """
        if not vuln.get("id"):
            vuln = {**vuln, "id": "OSV-FIXTURE-PLACEHOLDER"}
        return cls._record_to_result(_shared_parse_record(vuln))

    @classmethod
    def _record_to_result(cls, rec: OsvRecord) -> DiscoveryResult:
        """Extract PatchTuples + upstream-slug hints from an :class:`OsvRecord`.

        Emit order matters: ``references[/commit/...]`` tuples go first so the
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
        for ref in rec.references:
            url = ref.url or ""
            gh = GITHUB_COMMIT_URL_RE.search(url)
            if gh:
                repo = f"https://github.com/{gh.group(1)}"
                commit = gh.group(2)
            else:
                km = KERNEL_SHA_URL_RE.search(url)
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
        for blk in rec.affected:
            for rng in blk.ranges:
                if rng.type != "GIT":
                    continue
                repo = cls._normalize_repo(rng.repo or "")
                if not repo:
                    continue
                if repo in repos_from_refs:
                    continue

                introduced_shas = [
                    e["introduced"]
                    for e in rng.events
                    if e.get("introduced") and e["introduced"] != "0"
                    and _COMMIT_SHA_RE.match(e["introduced"])
                ]
                for event in rng.events:
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
            raw=rec.raw,
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
