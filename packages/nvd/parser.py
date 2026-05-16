"""NVD Patch-tagged reference parser.

Extracts ``(slug, sha)`` tuples from NVD 2.0 vulnerability payloads
where ``references[].tags`` contains ``"Patch"`` and the URL matches a
GitHub commit or kernel.org shortlink pattern.
"""

from __future__ import annotations

from core.url_patterns import (
    GITHUB_COMMIT_URL_RE,
    KERNEL_SHA_URL_RE,
    LINUX_UPSTREAM_SLUG,
    normalize_slug,
)


def extract_patch_refs(payload: dict) -> list[tuple[str, str]]:
    """Return deduplicated ``(slug, sha)`` pairs from Patch-tagged refs.

    Defensive isinstance() guards on every dict/list step. Pre-fix
    `cve.get("references") or []` assumed `references` was a list,
    but real NVD JSON occasionally ships it as a dict (single-ref
    object instead of an array) or as a string (typo / malformed
    feed). Pre-fix iterating a dict yielded its KEYS as `ref`,
    then `ref.get("tags")` raised AttributeError on str — the
    whole vuln-extraction crashed for the rest of the payload,
    losing every patch ref that came after the malformed entry.

    Same for `vulnerabilities` itself (NVD usually has it as
    a list but reseller mirrors / proxy caches sometimes
    ship a dict-of-vulns).

    `ref.get("tags") or []` had a similar failure on dict-typed
    tags (`{"name": "Patch"}` instead of `["Patch"]` — observed
    in some non-canonical NVD-format converters).
    """
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    vulnerabilities = payload.get("vulnerabilities") or []
    if not isinstance(vulnerabilities, list):
        return pairs
    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        cve = vuln.get("cve") or {}
        if not isinstance(cve, dict):
            continue
        references = cve.get("references") or []
        if not isinstance(references, list):
            continue
        for ref in references:
            if not isinstance(ref, dict):
                continue
            tags = ref.get("tags") or []
            if not isinstance(tags, list):
                continue
            if "Patch" not in tags:
                continue
            url = ref.get("url")
            if not isinstance(url, str):
                continue
            url = url.strip()
            m = GITHUB_COMMIT_URL_RE.search(url)
            if m:
                slug = normalize_slug(m.group(1))
                if slug.count("/") != 1:
                    continue
                sha = m.group(2).lower()
                key = (slug, sha)
                if key not in seen:
                    seen.add(key)
                    pairs.append(key)
                continue
            km = KERNEL_SHA_URL_RE.search(url)
            if km:
                sha = km.group(1).lower()
                key = (LINUX_UPSTREAM_SLUG.lower(), sha)
                if key not in seen:
                    seen.add(key)
                    pairs.append(key)
    return pairs
