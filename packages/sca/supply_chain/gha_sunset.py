"""Detector for ``gha_action_sunset``.

GitHub Actions versions get sunset, deprecated, or carry known
migration risk separately from CVEs:

  * Runtime deprecation (Node 12 → Node 16 → Node 20 transitions)
    → workflows fail when GitHub enforces the new runtime.
  * Major-version sunsets where behaviour or compatibility changes
    (``actions/upload-artifact@v3`` → v4 changed archive
    semantics; v3 sunset 2024-11-30).
  * Repository compromises and post-incident retags
    (``tj-actions/changed-files`` 2025-03 — operators on tag pins
    ran malicious code; the v45.x line was retired).

This detector consults a curated ``data/gha_sunset.json`` listing
known-sunset versions per action. For every Dependency with
ecosystem ``"GitHub Actions"`` whose declared version (the
``uses:`` ref) is in the sunset list, we emit a SupplyChain
finding with kind ``gha_action_sunset`` carrying the sunset
date, reason, and recommended replacement.

The detector is deliberately conservative — it ONLY flags exact
matches against the curated list. It doesn't try to resolve
"current major" (would need network calls and rate-limited
GitHub API queries; deferred to a follow-up). Curated entries
cover the high-impact sunsets that actually broke widespread
operator workflows.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from ..models import (
    Confidence,
    Dependency,
    Severity,
    SupplyChainFinding,
)

logger = logging.getLogger(__name__)


_SUNSET_DATA_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "gha_sunset.json"
)


def load_sunset_map(
    path: Optional[Path] = None,
) -> Dict[str, List[Dict[str, object]]]:
    """Load the curated sunset list. ``path`` lets tests inject a
    fixture; production callers use the default path under
    ``packages/sca/data/``.

    Returns ``{action_name: [sunset_record, ...]}``. Schema-keys
    starting with ``_`` (``_doc``, ``_schema``) are filtered out.
    Malformed entries are dropped silently — operators see fewer
    findings, never crashes.
    """
    p = path or _SUNSET_DATA_PATH
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as e:
        logger.warning(
            "sca.supply_chain.gha_sunset: cannot read %s: %s", p, e,
        )
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        logger.warning(
            "sca.supply_chain.gha_sunset: parse failed for %s: %s", p, e,
        )
        return {}
    if not isinstance(data, dict):
        return {}

    out: Dict[str, List[Dict[str, object]]] = {}
    for action_name, records in data.items():
        if action_name.startswith("_"):
            continue
        if not isinstance(records, list):
            continue
        valid: List[Dict[str, object]] = []
        for r in records:
            if not isinstance(r, dict):
                continue
            sunset_versions = r.get("sunset_versions")
            if not isinstance(sunset_versions, list):
                continue
            valid.append(r)
        if valid:
            out[action_name] = valid
    return out


def scan_dependencies(
    deps: Iterable[Dependency],
    *,
    sunset_map: Optional[Dict[str, List[Dict[str, object]]]] = None,
) -> List[SupplyChainFinding]:
    """Walk Dependencies and emit one SupplyChainFinding per action
    pinned to a sunset version.

    Match semantics:

      * Dep ``ecosystem`` must be exactly ``"GitHub Actions"``.
      * ``sunset_map`` lookup by ``dep.name`` (e.g. ``actions/checkout``).
      * Per-record match: the dep's version must appear (case-
        insensitive) in the record's ``sunset_versions``.
      * Sub-action refs (``actions/cache/restore``) are matched
        against their parent action's entry — the sunset usually
        applies to the whole repository.
    """
    if sunset_map is None:
        sunset_map = load_sunset_map()
    if not sunset_map:
        return []

    out: List[SupplyChainFinding] = []
    for dep in deps:
        if dep.ecosystem != "GitHub Actions":
            continue
        if not dep.version:
            continue
        # Match against the dep name (full path) AND the parent
        # action (e.g. ``actions/cache/restore`` → also try
        # ``actions/cache``). Most sunset records target the
        # repo, so the parent match catches sub-actions.
        for candidate in (dep.name, _parent_action(dep.name)):
            records = sunset_map.get(candidate)
            if not records:
                continue
            for record in records:
                versions_raw = record.get("sunset_versions")
                if not isinstance(versions_raw, list):
                    continue
                normalised = {
                    v.lower() for v in versions_raw if isinstance(v, str)
                }
                if dep.version.lower() not in normalised:
                    continue
                out.append(_build_finding(dep, record))
                break
            break
    return out


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _parent_action(name: str) -> str:
    """``actions/cache/restore`` → ``actions/cache``. Plain
    ``owner/repo`` returns itself (no slash beyond the first)."""
    parts = name.split("/")
    if len(parts) <= 2:
        return name
    return "/".join(parts[:2])


def _build_finding(
    dep: Dependency,
    record: Dict[str, object],
) -> SupplyChainFinding:
    severity = _coerce_severity(record.get("severity"))
    sunset_date = record.get("sunset_date") or "unannounced"
    reason = record.get("reason") or "version retired"
    replacement = record.get("replacement")
    detail = (
        f"GHA action `{dep.name}@{dep.version}` is sunset "
        f"(date: {sunset_date}). {reason}"
    )
    if replacement:
        detail += f" Recommended replacement: `{replacement}`."
    finding_id = (
        f"sca:supplychain:gha_action_sunset:"
        f"{dep.name}:{dep.version}".replace(" ", "_")
    )
    return SupplyChainFinding(
        finding_id=finding_id,
        kind="gha_action_sunset",
        dependency=dep,
        detail=detail,
        evidence={
            "action": dep.name,
            "version": dep.version,
            "sunset_date": sunset_date,
            "replacement": replacement,
        },
        severity=severity,
        confidence=Confidence(
            "high",
            reason=(
                f"matched curated sunset record for {dep.name} at "
                f"version {dep.version}"
            ),
        ),
    )


def _coerce_severity(raw: object) -> Severity:
    if isinstance(raw, str) and raw.lower() in (
        "info", "low", "medium", "high", "critical",
    ):
        return raw.lower()                          # type: ignore[return-value]
    return "medium"


__all__ = [
    "load_sunset_map",
    "scan_dependencies",
]
