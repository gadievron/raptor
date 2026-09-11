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

from .types import (  # noqa: E402
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
        msg = "OSV record missing id"
        raise ValueError(msg)

    aliases = _string_tuple(record.get("aliases"))
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


def _string_tuple(value: Any) -> tuple[str, ...]:
    """Coerce a list-of-strings field (``aliases``, ``versions``) to a tuple.

    A bare string (malformed mirrors ship ``"aliases": "CVE-2021-1234"``)
    is ONE item, not an iterable: iterating it per-character passes the
    per-item ``isinstance(x, str)`` guard for every character, silently
    polluting alias matching — and for ``versions``, minting
    single-character "versions" that parse as real versions downstream.
    """
    if isinstance(value, str):
        return (value,) if value else ()
    if isinstance(value, (list, tuple)):
        return tuple(x for x in value if isinstance(x, str))
    return ()


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
        versions = _string_tuple(entry.get("versions"))
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
        raw_type = r.get("type")
        # Case drift ("git" from mirrors/converters) normalises to the
        # canonical uppercase form rather than being rewritten away —
        # the verify layer's GIT handling is case-tolerant on purpose
        # and must still see these ranges as GIT. Truly unknown types
        # match SCA's existing behaviour: ECOSYSTEM so the matcher gets
        # a chance rather than dropping the range.
        type_str = raw_type.upper() if isinstance(raw_type, str) else ""
        if type_str not in ("GIT", "SEMVER", "ECOSYSTEM"):
            type_str = "ECOSYSTEM"
        repo = r.get("repo") if isinstance(r.get("repo"), str) else None
        events: list[dict[str, str]] = []
        for ev in (r.get("events") or []):
            if not isinstance(ev, dict):
                continue
            # JSON numbers are valid event values in the wild —
            # ``{"introduced": 0}`` is the common "vulnerable since the
            # beginning" shape. A str-only filter stripped it to ``{}``,
            # silently deleting the range's lower bound. Booleans stay
            # excluded ("True" is not a version).
            events.append({
                k: str(v)
                for k, v in ev.items()
                if isinstance(v, str)
                or (isinstance(v, (int, float)) and not isinstance(v, bool))
            })
        # Normalise event ordering: introduced before fixed/limit.
        # OSV spec requires events to be sorted by version, but
        # real feeds occasionally ship them in the order they
        # were authored (a `fixed` event written before its
        # `introduced` counterpart). The matcher assumes
        # introduced precedes the upper bound; reordering here
        # at parse time avoids matcher bugs downstream.
        #
        # ONLY for single-interval ranges (exactly one
        # ``introduced``). A multi-interval range like
        # ``[i 1.1, f 1.1.4, i 1.2, f 1.2.5]`` is already paired;
        # a type-keyed sort would regroup it to
        # ``[i 1.1, i 1.2, f 1.1.4, f 1.2.5]``, and the interval
        # walk then treats the doubled ``introduced`` as an
        # open-ended interval — silently widening the vulnerable
        # range to everything ≥ 1.1. Version-aware sorting is not
        # possible here (ecosystem comparators live above this
        # wire-format layer), so multi-interval events pass
        # through in feed order.
        n_introduced = sum(1 for ev in events if "introduced" in ev)
        if events and n_introduced <= 1:
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
