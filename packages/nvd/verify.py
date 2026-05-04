"""NVD-based ground-truth oracle for CVE commit verification.

Used when OSV returns ``ORPHAN`` (no commit data).  Extracts
Patch-tagged GitHub commit URLs from the NVD payload and compares
against a pipeline's ``(picked_slug, picked_sha)`` pick.
"""

from __future__ import annotations

from core.url_patterns import normalize_slug

from packages.osv.verdicts import OracleVerdict, Verdict

from .client import NvdClient
from .parser import extract_patch_refs


def verify(
    cve_id: str,
    picked_slug: str,
    picked_sha: str,
    client: NvdClient,
) -> OracleVerdict:
    """Compare a ``(picked_slug, picked_sha)`` against NVD Patch-tagged refs."""
    payload = client.get_payload(cve_id)
    if payload is None:
        return OracleVerdict(
            cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
            verdict=Verdict.ORPHAN, source="none",
            notes="NVD fetch failed or 404",
        )

    pairs = extract_patch_refs(payload)
    if not pairs:
        return OracleVerdict(
            cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
            verdict=Verdict.ORPHAN, source="nvd",
            notes="NVD has record but no Patch-tagged commit refs",
        )

    expected_slugs = tuple(sorted({s for s, _ in pairs}))
    expected_shas = tuple(sorted({sha for _, sha in pairs}))

    if not picked_slug or not picked_sha:
        return OracleVerdict(
            cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
            verdict=Verdict.DISPUTE, source="nvd",
            expected_slugs=expected_slugs, expected_shas=expected_shas,
            notes="bench refused but NVD has Patch-tagged commit refs",
        )

    pslug = normalize_slug(picked_slug)
    psha = picked_sha.lower()

    for s, sha in pairs:
        if sha.startswith(psha[:12]) and psha.startswith(sha[:12]):
            if s == pslug:
                return OracleVerdict(
                    cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
                    verdict=Verdict.MATCH_EXACT, source="nvd",
                    expected_slugs=expected_slugs, expected_shas=expected_shas,
                )
            return OracleVerdict(
                cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
                verdict=Verdict.MIRROR_DIFFERENT_SLUG, source="nvd",
                expected_slugs=expected_slugs, expected_shas=expected_shas,
                notes=f"same sha on slug={s!r}, not our {pslug!r}",
            )

    if pslug in expected_slugs:
        return OracleVerdict(
            cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
            verdict=Verdict.DISPUTE, source="nvd",
            expected_slugs=expected_slugs, expected_shas=expected_shas,
            notes="our slug is in NVD list but our sha is not",
        )
    return OracleVerdict(
        cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
        verdict=Verdict.LIKELY_HALLUCINATION, source="nvd",
        expected_slugs=expected_slugs, expected_shas=expected_shas,
        notes=f"NVD has {len(pairs)} (slug,sha); ours not among them",
    )
