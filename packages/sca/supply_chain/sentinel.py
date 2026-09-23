"""Known-malicious package sentinel detector.

Matches dependencies against ``data/sentinel_packages.json`` — a curated
list of packages involved in documented supply-chain incidents (backdoors,
account hijacks, typosquat credential stealers, protestware).

A match produces a **critical** finding with high confidence because the
signal is exact-name + exact-ecosystem (no fuzzy heuristics).  When the
sentinel entry carries specific versions, only those versions match;
``"*"`` matches any version.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from core.json import load_json_bounded

from ..models import Confidence, Dependency
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = logging.getLogger(__name__)

_DATA_FILE = Path(__file__).resolve().parents[1] / "data" / "sentinel_packages.json"

_SentinelKey = tuple[str, str]  # (ecosystem, name)


@dataclass
class SentinelHit:
    dependency: Dependency
    incident: str
    ref: str
    severity: str = "critical"
    confidence: Confidence = None  # type: ignore[assignment]

    def __post_init__(self):
        if self.confidence is None:
            self.confidence = Confidence(
                "high",
                reason=f"exact match in sentinel list: {self.incident}",
            )


_CACHE: dict[_SentinelKey, list[dict]] | None = None


def _load_sentinels() -> dict[_SentinelKey, list[dict]]:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    try:
        # Repo-bundled data file; ValueError also covers the
        # byte-budget refusal.
        data = load_json_bounded(_DATA_FILE, max_bytes=8 * 1024 * 1024)
    except (OSError, ValueError) as e:
        logger.warning("sca.supply_chain.sentinel: cannot load %s: %s",
                       _DATA_FILE, e)
        return {}
    if not isinstance(data, dict):
        # Sibling loaders isinstance-gate their bundled JSON; a
        # non-dict document here raised an uncaught AttributeError
        # (the except above covers OSError/ValueError only).
        logger.warning(
            "sca.supply_chain.sentinel: %s is not a JSON object; "
            "ignoring", _DATA_FILE,
        )
        return {}
    packages = data.get("packages", [])
    if not isinstance(packages, list):
        packages = []
    out: dict[_SentinelKey, list[dict]] = {}
    for entry in packages:
        if not isinstance(entry, dict):
            continue
        eco = entry.get("ecosystem", "")
        name = entry.get("name", "")
        if (isinstance(eco, str) and eco
                and isinstance(name, str) and name):
            out.setdefault((eco, name.lower()), []).append(entry)
    _CACHE = out
    return _CACHE


def scan_deps(deps: Iterable[Dependency]) -> list[SentinelHit]:
    sentinels = _load_sentinels()
    if not sentinels:
        return []
    hits: list[SentinelHit] = []
    seen: set[str] = set()
    for dep in deps:
        key = (dep.ecosystem, dep.name.lower())
        entries = sentinels.get(key)
        if not entries:
            continue
        for entry in entries:
            versions = entry.get("versions", ["*"])
            if "*" in versions or (dep.version and dep.version in versions):
                # Keyed per INCIDENT, not per dep — two curated
                # incidents for the same (eco, name, version) are
                # two findings; the dep-only key silently hid every
                # incident after the first.
                dedup_key = (
                    f"{dep.ecosystem}:{dep.name}:{dep.version}:"
                    f"{entry.get('incident', '')}:{entry.get('ref', '')}"
                )
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                hits.append(SentinelHit(
                    dependency=dep,
                    incident=entry.get("incident", "known-malicious package"),
                    ref=entry.get("ref", ""),
                ))
    return hits
