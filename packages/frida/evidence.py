"""Frida run evidence discovery for downstream consumers.

Consumers (coverage layer, binary-oracle, /validate, /understand)
gate on this module to find and validate frida output before
consuming it. The gate chain:

  1. packages.frida.available() -- host has frida tooling
  2. Output files exist in run/project dir
  3. metadata.json target matches current analysis target
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from core.logging import get_logger

log = get_logger("frida.evidence")

__all__ = ["FridaEvidence", "discover_evidence", "match_target"]

_MAX_METADATA_SIZE = 10 * 1024 * 1024  # 10MB sanity cap
_MAX_SCAN_CHILDREN = 500  # cap on iterdir results per search dir


@dataclass
class FridaEvidence:
    run_dir: Path
    metadata: dict = field(default_factory=dict)
    target_binary: Optional[str] = None
    has_drcov: bool = False
    has_events: bool = False


def _load_metadata(run_dir: Path) -> Optional[dict]:
    """Load and validate metadata.json from a frida run directory."""
    meta_path = run_dir / "metadata.json"
    if not meta_path.is_file():
        return None
    try:
        size = meta_path.stat().st_size
        if size > _MAX_METADATA_SIZE:
            log.warning("metadata.json too large (%d bytes), skipping: %s",
                        size, meta_path)
            return None
        with meta_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return None
        return data
    except (json.JSONDecodeError, OSError) as exc:
        log.debug("failed to load metadata from %s: %s", meta_path, exc)
        return None


def match_target(metadata: dict, target_path: str) -> bool:
    """Check if frida metadata target matches the analysis target.

    Matches on:
    - Exact binary/raw path string match (normalized)
    - Resolved (realpath) match
    - Process name match (attach-by-name: target.name == basename of target_path)
    """
    target = metadata.get("target")
    if not isinstance(target, dict):
        return False
    binary = target.get("binary")
    raw = target.get("raw")
    candidates = [c for c in (binary, raw) if isinstance(c, str) and c]

    target_p = Path(target_path)
    try:
        target_resolved = target_p.resolve()
    except OSError:
        target_resolved = target_p

    for candidate in candidates:
        if ".." in candidate or candidate.startswith("/proc/"):
            continue
        cand_p = Path(candidate)
        if str(cand_p.resolve() if cand_p.exists() else cand_p) == str(target_resolved):
            return True
        try:
            if cand_p.resolve() == target_resolved:
                return True
        except OSError:
            pass

    name = target.get("name")
    if isinstance(name, str) and name:
        if target_p.name == name and "/" not in name:
            # Reject if target_path looks like a source file (has extension or exists on disk)
            if not (target_p.suffix or target_p.is_file()):
                return True

    return False


def _build_evidence(run_dir: Path, metadata: dict) -> FridaEvidence:
    target = metadata.get("target", {})
    binary = target.get("binary") if isinstance(target, dict) else None
    return FridaEvidence(
        run_dir=run_dir,
        metadata=metadata,
        target_binary=binary if isinstance(binary, str) and binary else None,
        has_drcov=(run_dir / "coverage.drcov").is_file(),
        has_events=_has_nonempty_events(run_dir / "events.jsonl"),
    )


def _has_nonempty_events(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        return path.stat().st_size > 0
    except OSError:
        return False


def discover_evidence(
    search_dirs: list[Path],
    target_path: Optional[str] = None,
) -> list[FridaEvidence]:
    """Scan directories for frida run output.

    search_dirs: run dirs, project output dirs, or parent dirs to scan.
    target_path: if provided, only return evidence where metadata target matches.

    Returns list of FridaEvidence, newest first (by file mtime).
    Degrades gracefully: missing metadata.json -> skip, corrupt -> skip,
    no match -> empty list.

    Scanning is capped at _MAX_SCAN_CHILDREN per directory to prevent
    unbounded traversal of large output directories.
    """
    results: list[FridaEvidence] = []
    seen: set[Path] = set()

    for search_dir in search_dirs:
        search_dir = Path(search_dir)
        if not search_dir.is_dir():
            continue
        _try_add(search_dir, target_path, results, seen)
        try:
            children_checked = 0
            for child in search_dir.iterdir():
                children_checked += 1
                if children_checked > _MAX_SCAN_CHILDREN:
                    log.debug("scan cap reached for %s", search_dir)
                    break
                if child.is_dir():
                    _try_add(child, target_path, results, seen)
        except OSError:
            continue

    results.sort(key=lambda e: _mtime(e.run_dir / "metadata.json"), reverse=True)
    return results


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _try_add(
    run_dir: Path,
    target_path: Optional[str],
    results: list[FridaEvidence],
    seen: set[Path],
) -> None:
    try:
        resolved = run_dir.resolve()
    except OSError:
        return
    if resolved in seen:
        return
    seen.add(resolved)
    metadata = _load_metadata(run_dir)
    if metadata is None:
        return
    if target_path is not None and not match_target(metadata, target_path):
        return
    results.append(_build_evidence(run_dir, metadata))
