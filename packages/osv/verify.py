"""OSV-based ground-truth oracle for CVE commit verification.

Compares a pipeline's ``(picked_slug, picked_sha)`` against commit data
from OSV.dev — both ``references[]`` (GitHub commit URLs, kernel.org
shortlinks) and ``affected[].ranges[].events[].fixed``.

Follows GHSA aliases to recover commit refs that the primary CVE record
may lack.
"""

from __future__ import annotations

from core.url_patterns import (
    GITHUB_COMMIT_URL_RE,
    KERNEL_SHA_URL_RE,
    LINUX_UPSTREAM_SLUG,
    extract_github_slug,
    normalize_slug,
)

from .client import OsvClient
from .types import OsvRecord
from .verdicts import OracleVerdict, Verdict


def _extract_pairs(
    record: OsvRecord,
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Return ``(references_pairs, range_pairs)`` from an :class:`OsvRecord`."""
    ref_pairs: list[tuple[str, str]] = []
    for ref in record.references:
        url = ref.url.strip()
        m = GITHUB_COMMIT_URL_RE.search(url)
        if m:
            ref_pairs.append((normalize_slug(m.group(1)), m.group(2).lower()))
            continue
        km = KERNEL_SHA_URL_RE.search(url)
        if km:
            ref_pairs.append((LINUX_UPSTREAM_SLUG.lower(), km.group(1).lower()))

    range_pairs: list[tuple[str, str]] = []
    for aff in record.affected:
        for rng in aff.ranges:
            if rng.type.upper() != "GIT":
                continue
            slug = extract_github_slug(rng.repo or "") or ""
            for ev in rng.events:
                sha = (ev.get("fixed") or "").lower()
                if not sha or sha == "0":
                    continue
                if slug:
                    range_pairs.append((slug, sha))
    return ref_pairs, range_pairs


def _collect_pairs_with_aliases(
    cve_id: str,
    client: OsvClient,
) -> tuple[list[tuple[str, str]], list[tuple[str, str]], list[str]]:
    """Fetch primary CVE record + follow GHSA aliases, merging all pairs."""
    record = client.get_vuln(cve_id)
    if record is None:
        return [], [], []

    sources = [cve_id]
    ref_pairs, range_pairs = _extract_pairs(record)

    for alias in record.aliases:
        if not alias.startswith("GHSA-"):
            continue
        ghsa_record = client.get_vuln(alias)
        if ghsa_record is None:
            continue
        sources.append(alias)
        ar, ag = _extract_pairs(ghsa_record)
        ref_pairs.extend(ar)
        range_pairs.extend(ag)
    return ref_pairs, range_pairs, sources


def verify(
    cve_id: str,
    picked_slug: str,
    picked_sha: str,
    client: OsvClient,
) -> OracleVerdict:
    """Compare a ``(picked_slug, picked_sha)`` against OSV ground truth.

    *client* must be an :class:`OsvClient` instance.  The caller owns
    its lifetime and caching configuration.
    """
    ref_pairs, range_pairs, sources = _collect_pairs_with_aliases(cve_id, client)
    if not sources:
        return OracleVerdict(
            cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
            verdict=Verdict.ORPHAN, source="none",
            notes="OSV 404 / network failure",
        )

    ref_pairs = list(dict.fromkeys(ref_pairs))
    range_pairs = list(dict.fromkeys(range_pairs))
    all_pairs = ref_pairs + range_pairs
    source_label = (
        "osv" if len(sources) == 1
        else f"osv+{'+'.join(a for a in sources[1:])}"
    )

    if not all_pairs:
        return OracleVerdict(
            cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
            verdict=Verdict.ORPHAN, source=source_label,
            notes=(
                f"OSV record + {len(sources)-1} alias(es) have no "
                "commit-bearing references or ranges"
            ),
        )

    expected_slugs = tuple(sorted({s for s, _ in all_pairs}))
    expected_shas = tuple(sorted({sha for _, sha in all_pairs}))

    if not picked_slug or not picked_sha:
        return OracleVerdict(
            cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
            verdict=Verdict.DISPUTE, source=source_label,
            expected_slugs=expected_slugs, expected_shas=expected_shas,
            notes="bench refused but OSV has commit data",
        )

    pslug = normalize_slug(picked_slug)
    psha = picked_sha.lower()

    for s, sha in ref_pairs:
        if s == pslug and sha.startswith(psha[:12]) and psha.startswith(sha[:12]):
            return OracleVerdict(
                cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
                verdict=Verdict.MATCH_EXACT, source=source_label,
                expected_slugs=expected_slugs, expected_shas=expected_shas,
            )

    for s, sha in range_pairs:
        if sha.startswith(psha[:12]) and psha.startswith(sha[:12]):
            if s == pslug:
                return OracleVerdict(
                    cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
                    verdict=Verdict.MATCH_RANGE, source=source_label,
                    expected_slugs=expected_slugs, expected_shas=expected_shas,
                )
            return OracleVerdict(
                cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
                verdict=Verdict.MIRROR_DIFFERENT_SLUG, source=source_label,
                expected_slugs=expected_slugs, expected_shas=expected_shas,
                notes=f"same sha on slug={s!r}, not our {pslug!r}",
            )

    if pslug in expected_slugs:
        return OracleVerdict(
            cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
            verdict=Verdict.DISPUTE, source=source_label,
            expected_slugs=expected_slugs, expected_shas=expected_shas,
            notes="our slug is in OSV list but our sha is not",
        )
    return OracleVerdict(
        cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
        verdict=Verdict.LIKELY_HALLUCINATION, source=source_label,
        expected_slugs=expected_slugs, expected_shas=expected_shas,
        notes=(
            f"OSV ({len(sources)} records) has {len(all_pairs)} "
            "(slug,sha) pairs; ours is not among them"
        ),
    )
