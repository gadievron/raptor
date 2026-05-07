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

    # Minimum SHA length for an "exact" verdict. Pre-fix the
    # mutual-prefix check `sha.startswith(psha[:12]) and
    # psha.startswith(sha[:12])` worked correctly when both
    # sides were ≥12 chars (12-hex collision space is 16^12 ≈
    # 2.8×10^14 — effectively unique within any one repo).
    # But when EITHER side was shorter (e.g. a 7-char short
    # SHA from a parsed reference), `psha[:12]` truncated
    # silently to its full length, and the comparison
    # accepted matches with as few as 7 chars in common.
    # Git's documented short-sha ambiguity threshold is
    # 7-8 chars — below 12 the false-positive risk is
    # operationally meaningful (cve_diff oracle then
    # reports MATCH_EXACT for unrelated commits that
    # happen to share a 7-char prefix). Require ≥12 on
    # BOTH sides; below that, downgrade to DISPUTE with
    # a note explaining why.
    _MIN_EXACT_SHA_LEN = 12
    if len(psha) < _MIN_EXACT_SHA_LEN:
        return OracleVerdict(
            cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
            verdict=Verdict.DISPUTE, source="nvd",
            expected_slugs=expected_slugs, expected_shas=expected_shas,
            notes=(
                f"picked_sha is only {len(psha)} chars — below the 12-char "
                "minimum for safe exact-match verdict"
            ),
        )

    for s, sha in pairs:
        if (
            len(sha) >= _MIN_EXACT_SHA_LEN
            and sha.startswith(psha[:12]) and psha.startswith(sha[:12])
        ):
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
