"""Schema-agnostic dataclasses for OSV records.

The shape mirrors the OSV.dev v1 vulnerability schema closely so consumers
can map raw fields to their own domain types (cve-diff: ``PatchTuple``,
SCA: ``Advisory``) without further parsing of the wire JSON.

All collections are tuples to make instances hashable-by-identity and to
discourage in-place mutation by consumers; per-event dicts inside ranges
remain dicts because OSV's event keys are open-ended (``introduced``,
``fixed``, ``last_affected``, ``limit``, plus extensions).

The full original JSON is stashed on ``OsvRecord.raw`` so consumers that
need fields we haven't promoted to structured form (e.g. ``schema_version``,
``credits``, ``database_specific`` outside ``affected``) can read the raw
dict directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class OsvReference:
    url: str
    type: str   # WEB, ADVISORY, REPORT, FIX, PACKAGE, ARTICLE, EVIDENCE, ...


@dataclass(frozen=True)
class OsvRange:
    type: str                                    # GIT, SEMVER, ECOSYSTEM
    repo: str | None                             # only for GIT ranges
    events: tuple[dict[str, str], ...]           # raw event dicts


@dataclass(frozen=True)
class OsvAffected:
    package: dict[str, str] | None               # {"name": ..., "ecosystem": ...}
    ranges: tuple[OsvRange, ...]
    versions: tuple[str, ...]
    ecosystem_specific: dict[str, Any] | None
    database_specific: dict[str, Any] | None


@dataclass(frozen=True)
class OsvSeverity:
    type: str                                    # CVSS_V2, CVSS_V3, CVSS_V31, CVSS_V4, ...
    score: str                                   # the vector string


@dataclass(frozen=True)
class OsvRecord:
    id: str
    aliases: tuple[str, ...]
    summary: str
    details: str
    references: tuple[OsvReference, ...]
    affected: tuple[OsvAffected, ...]
    severity: tuple[OsvSeverity, ...]
    published: datetime | None
    modified: datetime | None
    raw: dict[str, Any]                          # full original JSON
