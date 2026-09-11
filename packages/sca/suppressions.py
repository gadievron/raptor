"""Operator-managed suppression overlay for ``raptor-sca`` findings.

A project ships ``.raptor-sca-suppress.yml`` at its root. Every entry is a
matcher that flips ``suppressed=True`` (and records a reason) on findings
the operator has reviewed and decided to accept. The CI gate ignores
suppressed findings by default; the analyse/report layers still surface
them so reviewers can audit the active set.

Supported entry shapes (most-specific to least):

    suppressions:
      - finding_id: "sca:vuln:npm:lodash@4.17.4:GHSA-jf85-cpcp-j695"
        reason: "isolated to test fixtures"
        expires: "2026-12-31"        # ISO 8601, optional

      - advisory_id: "GHSA-jf85-cpcp-j695"
        reason: "accepted risk — see SECURITY.md"

      - ecosystem: npm
        name: lodash
        version: "4.17.4"             # optional; omit to suppress all versions
        reason: "scheduled for upgrade in Q3"

A finding matches an entry when **every key** in the entry matches the
finding's corresponding field. ``reason`` is operator-supplied; the
loader rejects entries without one so the audit trail is meaningful.

PyYAML is the only dependency; missing it logs a warning and degrades
to "no suppressions" — the safer side (fail-open against suppression
means the gate sees more, not fewer, findings).

Schema versioning: ``version: 1`` at the top of the YAML; unrecognised
versions log a warning and skip the file. Future schema changes bump
the integer.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

logger = logging.getLogger(__name__)

# Bare filename of the operator-managed file.
SUPPRESS_FILENAME = ".raptor-sca-suppress.yml"

# Latest schema version we understand. Bump when we add fields that
# change semantics (e.g., regex matchers) so old loaders refuse files
# they can't reason about.
_SUPPORTED_VERSIONS = {1}

try:
    import yaml as _yaml                  # type: ignore[import-untyped]
    from ._yaml_fast import safe_load as _safe_load
    _HAS_YAML = True
except ImportError:                       # pragma: no cover — env-dependent
    _yaml = None                          # type: ignore[assignment]
    _safe_load = None                     # type: ignore[assignment]
    _HAS_YAML = False
    logger.warning(
        "sca.suppressions: 'PyYAML' not installed — suppression files "
        "will be skipped. `pip install PyYAML` to enable."
    )


@dataclass(frozen=True)
class SuppressionEntry:
    """One entry from the YAML, normalised."""

    reason: str
    expires: date | None = None
    finding_id: str | None = None
    advisory_id: str | None = None
    ecosystem: str | None = None
    name: str | None = None
    version: str | None = None

    def is_expired(self, today: date) -> bool:
        return self.expires is not None and today > self.expires

    def matches(self, row: dict[str, Any]) -> bool:
        """True if ``row`` (a findings.json row) matches this entry.

        ``advisory_id`` must identify EVERY advisory merged into the
        row, not just one member: alias-merged findings carry all
        member records in ``all_advisories``, and a record whose own
        id/alias set does not include the suppressed id keeps the
        finding visible. Matching the union instead would let a
        crafted advisory that aliases both a long-suppressed id and a
        genuine new advisory drag the genuine one under the existing
        suppression — a suppression must never reach records the
        operator has not reviewed.

        ``finding_id`` gets the same discipline on advisory-carrying
        rows: the id embeds the representative advisory's OSV id, so
        the entry additionally requires every merged member to carry
        that representative id. A merged row can keep the previously
        suppressed finding_id (the suppressed record stays the
        representative whenever the newcomer's severity does not
        exceed it), so an id-equality match alone would hide the
        newcomer inside the old suppression. Rows without advisories
        (hygiene / supply-chain / license) match on the id alone as
        before.
        """
        sca = row.get("sca") or {}
        if self.finding_id:
            if row.get("finding_id") != self.finding_id and \
                    row.get("id") != self.finding_id:
                return False
            primary = (sca.get("advisory") or {}).get("id")
            if primary and not _advisory_id_covers_row(primary, sca):
                return False
        if self.advisory_id and not _advisory_id_covers_row(
            self.advisory_id, sca,
        ):
            return False
        if self.ecosystem and sca.get("ecosystem") != self.ecosystem:
            return False
        if self.name and sca.get("name") != self.name:
            return False
        if self.version and sca.get("version") != self.version:
            return False
        # An entry with *no* match keys would match everything — guard
        # against that defensively (the loader also rejects it).
        return any((self.finding_id, self.advisory_id, self.ecosystem, self.name, self.version))


def load(path: Path) -> list[SuppressionEntry]:
    """Read ``path`` and return every well-formed entry.

    Missing file → empty list (the common case — no suppressions yet).
    Malformed file or missing PyYAML → warning + empty list.
    """
    if not _HAS_YAML or _yaml is None:
        return []
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8")
        data = _safe_load(text)                # type: ignore[misc]
    except (OSError, _yaml.YAMLError) as e:    # type: ignore[union-attr]
        logger.warning("sca.suppressions: failed to read %s: %s", path, e)
        return []
    if not isinstance(data, dict):
        logger.warning("sca.suppressions: %s is not a top-level mapping", path)
        return []
    version = data.get("version")
    if version not in _SUPPORTED_VERSIONS:
        logger.warning(
            "sca.suppressions: %s declares version=%r; supported: %s",
            path, version, sorted(_SUPPORTED_VERSIONS),
        )
        return []
    raw = data.get("suppressions")
    if not isinstance(raw, list):
        return []

    entries: list[SuppressionEntry] = []
    for idx, item in enumerate(raw):
        entry = _coerce_entry(item, source=path, index=idx)
        if entry is not None:
            entries.append(entry)
    return entries


def apply_to_findings(
    findings: Iterable[Any],
    entries: Iterable[SuppressionEntry],
    *,
    today: date | None = None,
) -> int:
    """Mutate ``VulnFinding`` / ``HygieneFinding`` / ``SupplyChainFinding``
    objects in place, setting ``suppressed=True`` and ``suppression_reason``.

    Returns the number of findings affected. Findings already suppressed
    are left alone (first-match-wins, idempotent).
    """
    today = today or datetime.now(timezone.utc).date()
    entries_list = list(entries)
    if not entries_list:
        return 0
    n = 0
    for f in findings:
        if getattr(f, "suppressed", False):
            continue
        view = _finding_view(f)
        if view is None:
            continue
        for entry in entries_list:
            if entry.is_expired(today):
                continue
            if _matches_view(entry, view):
                f.suppressed = True
                f.suppression_reason = entry.reason
                n += 1
                break
    return n


def _advisory_id_covers_row(advisory_id: str, sca: dict[str, Any]) -> bool:
    """True when *advisory_id* identifies every advisory on the row.

    Members come from ``all_advisories`` (the full alias-merged group);
    rows without it degrade to the primary ``advisory``. A row with no
    advisory at all never matches an ``advisory_id`` entry.
    Comparison is case-insensitive, matching the alias-merge pass —
    otherwise a case-drifted alias on one member makes the merged
    finding unsuppressible by any id.
    """
    members = [
        adv for adv in (sca.get("all_advisories") or [])
        if isinstance(adv, dict)
    ]
    if not members:
        primary = sca.get("advisory")
        members = [primary] if isinstance(primary, dict) else []
    if not members:
        return False
    wanted = advisory_id.upper()
    for adv in members:
        ids = {
            x.upper()
            for x in (adv.get("id"), *(adv.get("aliases") or []))
            if isinstance(x, str)
        }
        if wanted not in ids:
            return False
    return True


def _finding_view(finding: Any) -> dict[str, Any] | None:
    """Project a finding object onto the dict shape ``SuppressionEntry``
    matches against. ``None`` for objects that aren't recognisable."""
    fid = getattr(finding, "finding_id", None)
    dep = getattr(finding, "dependency", None)
    if fid is None or dep is None:
        return None
    # One UPPERCASED id set PER advisory: an ``advisory_id`` or
    # ``finding_id`` entry must identify every member of an
    # alias-merged group (see ``SuppressionEntry.matches`` for the
    # hostile-feed rationale). Case-insensitive like the merge pass.
    advisory_id_sets: list[set[str]] = []
    primary_advisory_id: str | None = None
    for adv in getattr(finding, "advisories", []) or []:
        ids: set[str] = set()
        osv_id = getattr(adv, "osv_id", None)
        if isinstance(osv_id, str) and osv_id:
            ids.add(osv_id.upper())
            if primary_advisory_id is None:
                primary_advisory_id = osv_id.upper()
        ids.update(
            alias.upper() for alias in getattr(adv, "aliases", []) or []
            if isinstance(alias, str)
        )
        advisory_id_sets.append(ids)
    return {
        "finding_id": fid,
        "ecosystem": getattr(dep, "ecosystem", None),
        "name": getattr(dep, "name", None),
        "version": getattr(dep, "version", None),
        "advisory_id_sets": advisory_id_sets,
        "primary_advisory_id": primary_advisory_id,
    }


def _covers_every_member(advisory_id: str, view: dict[str, Any]) -> bool:
    id_sets = view["advisory_id_sets"]
    if not id_sets:
        return False
    wanted = advisory_id.upper()
    return all(wanted in ids for ids in id_sets)


def _matches_view(entry: SuppressionEntry, view: dict[str, Any]) -> bool:
    if entry.finding_id:
        if view["finding_id"] != entry.finding_id:
            return False
        # Same every-member discipline as the row path: on
        # advisory-carrying findings the representative's id must
        # identify every merged member, or a crafted bridge could hide
        # a newcomer inside the previously suppressed finding_id.
        primary = view["primary_advisory_id"]
        if primary and not _covers_every_member(primary, view):
            return False
    if entry.advisory_id and not _covers_every_member(
        entry.advisory_id, view,
    ):
        return False
    if entry.ecosystem and view["ecosystem"] != entry.ecosystem:
        return False
    if entry.name and view["name"] != entry.name:
        return False
    if entry.version and view["version"] != entry.version:
        return False
    return any((entry.finding_id, entry.advisory_id, entry.ecosystem, entry.name, entry.version))


def apply(
    rows: list[dict[str, Any]],
    entries: Iterable[SuppressionEntry],
    *,
    today: date | None = None,
) -> int:
    """Mutate each row in-place, setting ``suppressed=True`` (and the
    reason) when an unexpired entry matches. Returns the number of rows
    affected.

    Rows already marked suppressed (e.g., by an earlier overlay) are
    left alone — first-match-wins, idempotent on repeated calls.
    """
    today = today or datetime.now(timezone.utc).date()
    entries = list(entries)
    n = 0
    for row in rows:
        if row.get("suppressed"):
            continue
        for entry in entries:
            if entry.is_expired(today):
                continue
            if entry.matches(row):
                row["suppressed"] = True
                row["suppression_reason"] = entry.reason
                # Persist into the sca.* extension block too so JSON
                # consumers that key on the nested view see it.
                if isinstance(row.get("sca"), dict):
                    row["sca"]["suppressed"] = True
                    row["sca"]["suppression_reason"] = entry.reason
                n += 1
                break
    return n


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

# Allow ``2026-12-31`` and ``2026-12-31T00:00:00Z`` and bare ISO date.
_ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")


def _coerce_entry(
    item: Any, *, source: Path, index: int,
) -> SuppressionEntry | None:
    if not isinstance(item, dict):
        logger.warning(
            "sca.suppressions: %s entry %d is not a mapping; skipped",
            source, index,
        )
        return None
    reason = item.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        logger.warning(
            "sca.suppressions: %s entry %d has no reason; skipped",
            source, index,
        )
        return None

    expires_raw = item.get("expires")
    expires: date | None = None
    if isinstance(expires_raw, date) and not isinstance(expires_raw, datetime):
        expires = expires_raw
    elif isinstance(expires_raw, datetime):
        expires = expires_raw.date()
    elif isinstance(expires_raw, str) and _ISO_DATE_RE.match(expires_raw):
        try:
            expires = date.fromisoformat(expires_raw[:10])
        except ValueError:
            logger.warning(
                "sca.suppressions: %s entry %d: unparseable expires %r",
                source, index, expires_raw,
            )
    elif expires_raw is not None:
        logger.warning(
            "sca.suppressions: %s entry %d: ignoring non-ISO expires %r",
            source, index, expires_raw,
        )

    entry = SuppressionEntry(
        reason=reason.strip(),
        expires=expires,
        finding_id=_str_or_none(item.get("finding_id")),
        advisory_id=_str_or_none(item.get("advisory_id")),
        ecosystem=_str_or_none(item.get("ecosystem")),
        name=_str_or_none(item.get("name")),
        version=_str_or_none(item.get("version")),
    )
    if not any((entry.finding_id, entry.advisory_id,
                entry.ecosystem, entry.name)):
        # Match-key-less entry would suppress every finding — clearly
        # not what the operator meant.
        logger.warning(
            "sca.suppressions: %s entry %d has no match keys; skipped",
            source, index,
        )
        return None
    return entry


def _str_or_none(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


__all__ = [
    "SUPPRESS_FILENAME",
    "SuppressionEntry",
    "apply",
    "apply_to_findings",
    "load",
]
