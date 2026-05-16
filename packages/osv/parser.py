"""OSV vulnerability JSON → :class:`OsvRecord` parser.

Schema-agnostic: returns the full structured shape plus the raw dict.
Consumers map :class:`OsvRecord` to their own domain types (cve-diff
extracts commit SHAs into ``PatchTuple``; SCA computes CVSS and walks
SEMVER/ECOSYSTEM ranges into ``Advisory``).

The parser is defensive — every field is guarded with ``isinstance``
checks because OSV records are user-submitted advisory data and have
been observed to ship typed-incorrectly fields in the wild. A single
malformed field never raises; only a missing/empty ``id`` raises
:class:`ValueError`. Skipping malformed sub-objects (a non-dict in
``references``, a non-string event value, etc.) keeps best-effort
extraction useful even when the record is partially corrupt.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)

from .types import (
    OsvAffected,
    OsvRange,
    OsvRecord,
    OsvReference,
    OsvSeverity,
)


def parse_record(record: dict[str, Any]) -> OsvRecord:
    """Parse one OSV vulnerability record. Raises ``ValueError`` if ``id`` is missing."""
    osv_id = str(record.get("id") or "")
    if not osv_id:
        raise ValueError("OSV record missing id")

    aliases = tuple(
        x for x in (record.get("aliases") or ()) if isinstance(x, str)
    )
    return OsvRecord(
        id=osv_id,
        aliases=aliases,
        summary=str(record.get("summary") or ""),
        details=str(record.get("details") or ""),
        references=_parse_references(record.get("references") or []),
        affected=_parse_affected(record.get("affected") or []),
        severity=_parse_severity(record.get("severity") or []),
        published=_parse_iso(record.get("published")),
        modified=_parse_iso(record.get("modified")),
        raw=record,
    )


def _parse_references(refs_raw: list[Any]) -> tuple[OsvReference, ...]:
    out: list[OsvReference] = []
    for ref in refs_raw:
        if not isinstance(ref, dict):
            continue
        url = ref.get("url")
        if not isinstance(url, str):
            continue
        out.append(OsvReference(url=url, type=str(ref.get("type") or "")))
    return tuple(out)


def _parse_affected(affected_raw: list[Any]) -> tuple[OsvAffected, ...]:
    out: list[OsvAffected] = []
    for entry in affected_raw:
        if not isinstance(entry, dict):
            continue
        pkg = entry.get("package")
        package: dict[str, str] | None = (
            {k: str(v) for k, v in pkg.items() if isinstance(v, str)}
            if isinstance(pkg, dict) else None
        )
        ranges = _parse_ranges(entry.get("ranges") or [])
        versions = tuple(
            v for v in (entry.get("versions") or ()) if isinstance(v, str)
        )
        eco = entry.get("ecosystem_specific")
        db = entry.get("database_specific")
        out.append(OsvAffected(
            package=package,
            ranges=ranges,
            versions=versions,
            ecosystem_specific=eco if isinstance(eco, dict) else None,
            database_specific=db if isinstance(db, dict) else None,
        ))
    return tuple(out)


def _parse_ranges(ranges_raw: list[Any]) -> tuple[OsvRange, ...]:
    out: list[OsvRange] = []
    for r in ranges_raw:
        if not isinstance(r, dict):
            continue
        type_str = r.get("type")
        # Match SCA's existing behaviour: unknown type is normalised to
        # ECOSYSTEM so the matcher gets a chance rather than dropping it.
        if type_str not in ("GIT", "SEMVER", "ECOSYSTEM"):
            type_str = "ECOSYSTEM"
        repo = r.get("repo") if isinstance(r.get("repo"), str) else None
        events: list[dict[str, str]] = []
        for ev in (r.get("events") or []):
            if not isinstance(ev, dict):
                continue
            events.append(
                {k: str(v) for k, v in ev.items() if isinstance(v, str)}
            )
        # Normalise event ordering: introduced before fixed/limit.
        # OSV spec requires events to be sorted by version, but
        # real feeds occasionally ship them in the order they
        # were authored (a `fixed` event written before its
        # `introduced` counterpart). The matcher assumes
        # introduced precedes the upper bound; reordering here
        # at parse time avoids matcher bugs downstream.
        # Empty events list short-circuits.
        if events:
            _ORDER = {"introduced": 0, "fixed": 1, "last_affected": 1, "limit": 2}
            events.sort(key=lambda ev: _ORDER.get(
                next(iter(ev.keys()), ""), 99,
            ))
        out.append(OsvRange(type=type_str, repo=repo, events=tuple(events)))
    return tuple(out)


def _parse_severity(severity_raw: list[Any]) -> tuple[OsvSeverity, ...]:
    out: list[OsvSeverity] = []
    for entry in severity_raw:
        if not isinstance(entry, dict):
            continue
        score = entry.get("score")
        if not isinstance(score, str):
            continue
        out.append(OsvSeverity(type=str(entry.get("type") or ""), score=score))
    return tuple(out)


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        # ``Z`` suffix isn't accepted by fromisoformat <3.11.
        return datetime.fromisoformat(
            value.replace("Z", "+00:00"),
        ).astimezone(timezone.utc)
    except ValueError:
        # Pre-fix this `except ValueError: return None` swallowed
        # the parse failure silently. Real OSV feeds occasionally
        # ship malformed timestamps (vendor mirrors with
        # locale-formatted dates, copy-paste-glitched values
        # like "2024-13-45T..."); operators triaging "why is
        # the published date None?" had no log breadcrumb to
        # correlate. Log at debug level so the failure surfaces
        # in verbose runs without spamming normal output.
        log.debug("osv: failed to parse ISO timestamp %r", value)
        return None
