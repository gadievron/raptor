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

import json as _json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from ..models import Confidence, Dependency

logger = logging.getLogger(__name__)

_DATA_FILE = Path(__file__).resolve().parents[1] / "data" / "sentinel_packages.json"

_SentinelKey = Tuple[str, str]  # (ecosystem, name)


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


_CACHE: Optional[Dict[_SentinelKey, List[dict]]] = None


def _load_sentinels() -> Dict[_SentinelKey, List[dict]]:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    try:
        data = _json.loads(_DATA_FILE.read_text(encoding="utf-8"))
    except (OSError, _json.JSONDecodeError) as e:
        logger.warning("sca.supply_chain.sentinel: cannot load %s: %s",
                       _DATA_FILE, e)
        _CACHE = {}
        return _CACHE
    out: Dict[_SentinelKey, List[dict]] = {}
    for entry in data.get("packages", []):
        eco = entry.get("ecosystem", "")
        name = entry.get("name", "").lower()
        if eco and name:
            out.setdefault((eco, name), []).append(entry)
    _CACHE = out
    return _CACHE


def scan_deps(deps: Iterable[Dependency]) -> List[SentinelHit]:
    sentinels = _load_sentinels()
    if not sentinels:
        return []
    hits: List[SentinelHit] = []
    seen: Set[str] = set()
    for dep in deps:
        key = (dep.ecosystem, dep.name.lower())
        entries = sentinels.get(key)
        if not entries:
            continue
        for entry in entries:
            versions = entry.get("versions", ["*"])
            if "*" in versions or (dep.version and dep.version in versions):
                dedup_key = f"{dep.ecosystem}:{dep.name}:{dep.version}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                hits.append(SentinelHit(
                    dependency=dep,
                    incident=entry.get("incident", "known-malicious package"),
                    ref=entry.get("ref", ""),
                ))
    return hits
