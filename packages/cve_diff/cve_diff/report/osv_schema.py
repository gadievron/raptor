"""
OSV Schema 1.6.0 renderer for a `DiffBundle`.

Phase 1 ships only the fields we can produce from discovery + diff: id,
schema_version, modified, references, affected[].ranges (GIT events). Root
cause / CWE / variants will extend `database_specific` in later phases.

Spec: https://ossf.github.io/osv-schema/
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from cve_diff.analysis.analyzer import RootCause
from cve_diff.core.models import DiffBundle

OSV_SCHEMA_VERSION = "1.6.0"


def _commit_url(repository_url: str, sha: str) -> str:
    base = repository_url.removesuffix(".git").rstrip("/")
    return f"{base}/commit/{sha}"


def render(
    bundle: DiffBundle,
    modified: datetime | None = None,
    root_cause: RootCause | None = None,
) -> dict[str, Any]:
    when = (modified or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ")
    repo = bundle.repo_ref.repository_url
    introduced = bundle.repo_ref.introduced or bundle.commit_before
    osv: dict[str, Any] = {
        "schema_version": OSV_SCHEMA_VERSION,
        "id": bundle.cve_id,
        "modified": when,
        "references": [
            {"type": "FIX", "url": _commit_url(repo, bundle.commit_after)},
        ],
        "affected": [
            {
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": repo,
                        "events": [
                            {"introduced": introduced},
                            {"fixed": bundle.commit_after},
                        ],
                    }
                ],
            }
        ],
        "database_specific": {
            "files_changed": bundle.files_changed,
            "diff_bytes": bundle.bytes_size,
            "canonical_score": bundle.repo_ref.canonical_score,
            "diff_against": bundle.commit_before,
            "diff_shape": bundle.shape,
            "files": [
                {
                    "path": f.path,
                    "is_test": f.is_test,
                    "hunks_count": f.hunks_count,
                    "before_source": f.before_source,
                    "after_source": f.after_source,
                }
                for f in bundle.files
            ],
        },
    }
    if bundle.consensus is not None:
        osv["database_specific"]["consensus"] = bundle.consensus
    if bundle.extraction_agreement is not None:
        osv["database_specific"]["extraction_agreement"] = bundle.extraction_agreement
    if root_cause is not None:
        osv["database_specific"]["root_cause"] = {
            "cwe_id": root_cause.cwe_id,
            "vulnerability_type": root_cause.vulnerability_type,
            "summary": root_cause.summary,
            "why_chain": list(root_cause.why_chain),
            "affected_functions": list(root_cause.affected_functions),
            "confidence": root_cause.confidence,
            "model_id": root_cause.model_id,
        }
    _assert_osv_shape(osv)
    return osv


def _assert_osv_shape(osv: dict[str, Any]) -> None:
    """Structural sanity check on the rendered OSV record.

    Not a full JSON-schema validation. Catches the silent-empty-render
    class: a DiffBundle where repo/ref/SHAs ended up missing or empty
    would produce an OSV dict that parses but means nothing. Raise
    early so the bench marks the CVE as FAIL rather than writing a
    bogus OSV file.
    """
    for required in ("schema_version", "id", "modified", "references", "affected"):
        if required not in osv:
            raise ValueError(f"OSV render missing required field: {required}")
    if not osv["references"]:
        raise ValueError("OSV render has empty references list")
    for ref in osv["references"]:
        if not ref.get("url"):
            raise ValueError("OSV render reference has empty url")
    if not osv["affected"]:
        raise ValueError("OSV render has empty affected list")
    for aff in osv["affected"]:
        ranges = aff.get("ranges") or []
        if not ranges:
            raise ValueError("OSV render affected entry has no ranges")
        for rng in ranges:
            if not rng.get("repo"):
                raise ValueError("OSV render range has empty repo")
            events = rng.get("events") or []
            has_fixed = any("fixed" in e and e["fixed"] for e in events)
            if not has_fixed:
                raise ValueError("OSV render range has no non-empty fixed event")
