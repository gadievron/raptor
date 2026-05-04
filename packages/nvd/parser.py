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
    """Return deduplicated ``(slug, sha)`` pairs from Patch-tagged refs."""
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for vuln in payload.get("vulnerabilities") or []:
        cve = (vuln if isinstance(vuln, dict) else {}).get("cve") or {}
        for ref in cve.get("references") or []:
            tags = ref.get("tags") or []
            if "Patch" not in tags:
                continue
            url = (ref.get("url") or "").strip()
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
