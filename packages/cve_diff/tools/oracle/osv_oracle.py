"""OSV-based ground-truth oracle.

Calls the OSV API (same endpoint the agent's ``osv_raw`` tool uses),
extracts all ``(slug, sha)`` tuples OSV carries for the CVE — from
``references[]`` (github.com/owner/repo/commit/<sha> +
kernel.dance / git.kernel.org shortlinks) and from
``affected[].ranges[].events[].fixed`` — then returns a Verdict.

Reuses:
  - ``cve_diff.agent.tools._GITHUB_COMMIT_URL_RE``
  - ``cve_diff.agent.tools._KERNEL_SHA_URL_RE``
  - ``cve_diff.agent.tools._LINUX_UPSTREAM_SLUG``
"""

from __future__ import annotations

import requests

from cve_diff.core.url_re import (
    GITHUB_COMMIT_URL_RE as _GITHUB_COMMIT_URL_RE,
    KERNEL_SHA_URL_RE as _KERNEL_SHA_URL_RE,
    LINUX_UPSTREAM_SLUG as _LINUX_UPSTREAM_SLUG,
    extract_github_slug as _github_slug_from_url,
    normalize_slug as _normalize_slug,
)
from tools.oracle.types import OracleVerdict, Verdict

_OSV_BASE = "https://api.osv.dev/v1"
_TIMEOUT_S = 10.0


def _fetch_osv(identifier: str) -> dict | None:
    """Fetch any OSV-indexed vulnerability record (CVE, GHSA, DSA, USN, …).

    OSV's ``/vulns/<id>`` endpoint accepts all aliased ids, not just CVE ids —
    this means we can follow ``aliases`` to GHSA records (which often carry
    different references than the parent CVE, especially for GitHub-tracked
    ecosystems).
    """
    try:
        resp = requests.get(f"{_OSV_BASE}/vulns/{identifier}", timeout=_TIMEOUT_S)
    except requests.RequestException:
        return None
    if resp.status_code != 200:
        return None
    try:
        return resp.json()
    except ValueError:
        return None


def _collect_pairs_with_aliases(cve_id: str) -> tuple[list[tuple[str, str]], list[tuple[str, str]], list[str]]:
    """Fetch primary CVE record + follow GHSA aliases, merging all pairs.

    Returns ``(references_pairs, range_pairs, sources)`` where ``sources`` is
    the list of record ids consulted (primary + aliases). Deduplication of
    pairs happens at the verdict-compute level; here we keep both lists
    separate so ``MATCH_EXACT`` vs ``MATCH_RANGE`` can still discriminate.
    """
    primary = _fetch_osv(cve_id)
    if primary is None:
        return [], [], []

    sources = [cve_id]
    ref_pairs, range_pairs = _extract_osv_pairs(primary)

    # Follow GHSA aliases only (DSA/USN/DLA tend to be advisory pages,
    # not git-reference-carrying; GHSA is explicitly for GitHub-tracked
    # ecosystems and carries commit URLs).
    for alias in (primary.get("aliases") or []):
        if not isinstance(alias, str) or not alias.startswith("GHSA-"):
            continue
        ghsa = _fetch_osv(alias)
        if ghsa is None:
            continue
        sources.append(alias)
        ar, ag = _extract_osv_pairs(ghsa)
        ref_pairs.extend(ar)
        range_pairs.extend(ag)
    return ref_pairs, range_pairs, sources


def _extract_osv_pairs(payload: dict) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Return (references_pairs, range_pairs).

    references_pairs: (slug, sha) from OSV's `references[].url` that
    match either a GitHub commit URL or a kernel shortlink.
    range_pairs: (slug, sha) from OSV's `affected[].ranges[].events[].fixed`
    combined with the range's `repo` field (if it's a GitHub URL).
    """
    ref_pairs: list[tuple[str, str]] = []
    for ref in payload.get("references") or []:
        url = (ref.get("url") or "").strip()
        m = _GITHUB_COMMIT_URL_RE.search(url)
        if m:
            ref_pairs.append((_normalize_slug(m.group(1)), m.group(2).lower()))
            continue
        km = _KERNEL_SHA_URL_RE.search(url)
        if km:
            ref_pairs.append((_LINUX_UPSTREAM_SLUG.lower(), km.group(1).lower()))

    range_pairs: list[tuple[str, str]] = []
    for aff in payload.get("affected") or []:
        for rng in aff.get("ranges") or []:
            if (rng.get("type") or "").upper() != "GIT":
                continue
            repo = rng.get("repo") or ""
            slug = _github_slug_from_url(repo) or ""
            for ev in rng.get("events") or []:
                sha = (ev.get("fixed") or "").lower()
                if not sha or sha == "0":
                    continue
                if slug:
                    range_pairs.append((slug, sha))
    return ref_pairs, range_pairs


def verify(cve_id: str, picked_slug: str, picked_sha: str) -> OracleVerdict:
    """Return an OracleVerdict comparing our pick to OSV-declared pairs.

    ``picked_slug`` / ``picked_sha`` may be empty strings for cases
    where the bench refused (UnsupportedSource / DiscoveryError) —
    the oracle then reports whether OSV *would* have had an answer.
    """
    ref_pairs, range_pairs, sources = _collect_pairs_with_aliases(cve_id)
    if not sources:
        return OracleVerdict(cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
                             verdict=Verdict.ORPHAN, source="none",
                             notes="OSV 404 / network failure")

    # Deduplicate pairs (aliases often carry the same commit refs as the parent).
    ref_pairs = list(dict.fromkeys(ref_pairs))
    range_pairs = list(dict.fromkeys(range_pairs))
    all_pairs = ref_pairs + range_pairs
    source_label = "osv" if len(sources) == 1 else f"osv+{'+'.join(a for a in sources[1:])}"
    if not all_pairs:
        return OracleVerdict(cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
                             verdict=Verdict.ORPHAN, source=source_label,
                             notes=f"OSV record + {len(sources)-1} alias(es) have no commit-bearing references or ranges")

    expected_slugs = tuple(sorted({s for s, _ in all_pairs}))
    expected_shas = tuple(sorted({sha for _, sha in all_pairs}))

    # Edge: bench refused (empty pick) but OSV has answers → false-refusal signal.
    if not picked_slug or not picked_sha:
        return OracleVerdict(cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
                             verdict=Verdict.DISPUTE, source=source_label,
                             expected_slugs=expected_slugs, expected_shas=expected_shas,
                             notes="bench refused but OSV has commit data")

    pslug = _normalize_slug(picked_slug)
    psha = picked_sha.lower()

    # Exact match: slug + sha on references-pass (preferred over range-pass).
    for s, sha in ref_pairs:
        if s == pslug and sha.startswith(psha[:12]) and psha.startswith(sha[:12]):
            # startswith both directions handles SHA-length mismatch (we store
            # full 40-char, OSV may publish 40-char — compare first 12 chars
            # which is enough entropy for identity).
            return OracleVerdict(cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
                                 verdict=Verdict.MATCH_EXACT, source=source_label,
                                 expected_slugs=expected_slugs, expected_shas=expected_shas)

    # Range match: sha on any GIT range (repo may or may not be same slug).
    for s, sha in range_pairs:
        if sha.startswith(psha[:12]) and psha.startswith(sha[:12]):
            if s == pslug:
                return OracleVerdict(cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
                                     verdict=Verdict.MATCH_RANGE, source=source_label,
                                     expected_slugs=expected_slugs, expected_shas=expected_shas)
            return OracleVerdict(cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
                                 verdict=Verdict.MIRROR_DIFFERENT_SLUG, source=source_label,
                                 expected_slugs=expected_slugs, expected_shas=expected_shas,
                                 notes=f"same sha on slug={s!r}, not our {pslug!r}")

    # Same sha as OSV but different slug entirely (checked any slug in all_pairs above).
    # Not matched anywhere → dispute or hallucination.
    if pslug in expected_slugs:
        return OracleVerdict(cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
                             verdict=Verdict.DISPUTE, source=source_label,
                             expected_slugs=expected_slugs, expected_shas=expected_shas,
                             notes="our slug is in OSV list but our sha is not")
    return OracleVerdict(cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
                         verdict=Verdict.LIKELY_HALLUCINATION, source=source_label,
                         expected_slugs=expected_slugs, expected_shas=expected_shas,
                         notes=f"OSV ({len(sources)} records) has {len(all_pairs)} (slug,sha) pairs; ours is not among them")
