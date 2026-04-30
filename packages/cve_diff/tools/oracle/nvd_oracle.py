"""NVD-based ground-truth fallback.

Used when OSV returns ``ORPHAN`` (no commit data). Extracts github
commit URLs from NVD ``references[]`` where ``tags`` contains
``"Patch"``. Reuses the disk-cached ``NvdDiscoverer.get_payload``
so repeated oracle runs don't re-hit the API.
"""

from __future__ import annotations

from cve_diff.core.url_re import (
    GITHUB_COMMIT_URL_RE as _GITHUB_COMMIT_URL_RE,
    KERNEL_SHA_URL_RE as _KERNEL_SHA_URL_RE,
    LINUX_UPSTREAM_SLUG as _LINUX_UPSTREAM_SLUG,
    normalize_slug as _normalize_slug,
)
from cve_diff.discovery.nvd import NvdDiscoverer
from tools.oracle.types import OracleVerdict, Verdict

_nvd = NvdDiscoverer()


def _extract_nvd_pairs(payload: dict) -> list[tuple[str, str]]:
    """Return (slug, sha) tuples from NVD `Patch`-tagged references + kernel shortlinks."""
    pairs: list[tuple[str, str]] = []
    for vuln in payload.get("vulnerabilities") or []:
        cve = vuln.get("cve") or {}
        for ref in cve.get("references") or []:
            url = (ref.get("url") or "").strip()
            tags = ref.get("tags") or []
            # Only trust Patch-tagged refs (NVD marks them when curator
            # verified the URL is a fix commit, not an advisory page).
            is_patch_tagged = "Patch" in tags
            m = _GITHUB_COMMIT_URL_RE.search(url)
            if m and is_patch_tagged:
                pairs.append((_normalize_slug(m.group(1)), m.group(2).lower()))
                continue
            km = _KERNEL_SHA_URL_RE.search(url)
            if km and is_patch_tagged:
                pairs.append((_LINUX_UPSTREAM_SLUG.lower(), km.group(1).lower()))
    return pairs


def verify(cve_id: str, picked_slug: str, picked_sha: str) -> OracleVerdict:
    """Return an OracleVerdict using NVD as the source of truth."""
    payload = _nvd.get_payload(cve_id)
    if payload is None:
        return OracleVerdict(cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
                             verdict=Verdict.ORPHAN, source="none",
                             notes="NVD fetch failed or 404")

    pairs = _extract_nvd_pairs(payload)
    if not pairs:
        return OracleVerdict(cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
                             verdict=Verdict.ORPHAN, source="nvd",
                             notes="NVD has record but no Patch-tagged commit refs")

    expected_slugs = tuple(sorted({s for s, _ in pairs}))
    expected_shas = tuple(sorted({sha for _, sha in pairs}))

    if not picked_slug or not picked_sha:
        return OracleVerdict(cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
                             verdict=Verdict.DISPUTE, source="nvd",
                             expected_slugs=expected_slugs, expected_shas=expected_shas,
                             notes="bench refused but NVD has Patch-tagged commit refs")

    pslug = _normalize_slug(picked_slug)
    psha = picked_sha.lower()

    for s, sha in pairs:
        if sha.startswith(psha[:12]) and psha.startswith(sha[:12]):
            if s == pslug:
                return OracleVerdict(cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
                                     verdict=Verdict.MATCH_EXACT, source="nvd",
                                     expected_slugs=expected_slugs, expected_shas=expected_shas)
            return OracleVerdict(cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
                                 verdict=Verdict.MIRROR_DIFFERENT_SLUG, source="nvd",
                                 expected_slugs=expected_slugs, expected_shas=expected_shas,
                                 notes=f"same sha on slug={s!r}, not our {pslug!r}")

    if pslug in expected_slugs:
        return OracleVerdict(cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
                             verdict=Verdict.DISPUTE, source="nvd",
                             expected_slugs=expected_slugs, expected_shas=expected_shas,
                             notes="our slug is in NVD list but our sha is not")
    return OracleVerdict(cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
                         verdict=Verdict.LIKELY_HALLUCINATION, source="nvd",
                         expected_slugs=expected_slugs, expected_shas=expected_shas,
                         notes=f"NVD has {len(pairs)} (slug,sha); ours not among them")
