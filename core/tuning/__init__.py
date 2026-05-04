"""Hardware-aware resource tuning for RAPTOR.

Reads ``tuning.json`` from the repo root, resolves ``"auto"`` values
using hardware detection, validates per-key, and exposes resolved
integers to consumers via ``get_tuning()``.

Invalid keys warn and fall back to defaults per-key — a single typo
never blocks a session.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from core.json import load_json_with_comments

logger = logging.getLogger(__name__)

# core/tuning/__init__.py → repo root
_REPO_ROOT = Path(__file__).resolve().parents[2]  # core/tuning/ → repo
_TUNING_PATH = _REPO_ROOT / "tuning.json"

_VALID_KEYS = frozenset({
    "codeql_ram_mb",
    "codeql_threads",
    "max_semgrep_workers",
    "max_codeql_workers",
    "max_agentic_parallel",
    "max_fuzz_parallel",
})

_DEFAULTS = {
    "codeql_ram_mb": "auto",
    "codeql_threads": "auto",
    "max_semgrep_workers": 4,
    "max_codeql_workers": 2,
    "max_agentic_parallel": 3,
    "max_fuzz_parallel": 4,
}


def _detect_ram_mb() -> int:
    """25% of system RAM, clamped to [2048, 16384] MB."""
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        total_mb = pages * page_size // (1024 * 1024)
    except (ValueError, OSError):
        return 8192
    return max(2048, min(total_mb // 4, 16384))


def _detect_threads() -> int:
    # 0 tells CodeQL to use all available CPUs — preserving its
    # native auto-detection (respects cgroups, hyperthreading, etc.)
    return 0


_AUTO_RESOLVERS = {
    "codeql_ram_mb": _detect_ram_mb,
    "codeql_threads": _detect_threads,
}

# Keys where 0 is a valid explicit value (e.g. CodeQL's "0 = all CPUs")
_ZERO_ALLOWED = frozenset({"codeql_threads"})


@dataclass(frozen=True, slots=True)
class Tuning:
    """Resolved tuning values — all integers, no ``"auto"``."""
    codeql_ram_mb: int
    codeql_threads: int
    max_semgrep_workers: int
    max_codeql_workers: int
    max_agentic_parallel: int
    max_fuzz_parallel: int


def _validate_value(key: str, raw: Any) -> Optional[int]:
    """Validate and resolve a single tuning value.

    Returns the resolved int, or None if invalid (caller uses default).
    """
    if raw == "auto":
        resolver = _AUTO_RESOLVERS.get(key)
        if resolver is None:
            logger.warning(
                'tuning.json: "%s" does not support "auto", using default (%s)',
                key, _DEFAULTS[key],
            )
            return None
        return resolver()
    min_val = 0 if key in _ZERO_ALLOWED else 1
    if isinstance(raw, int) and not isinstance(raw, bool) and raw >= min_val:
        return raw
    logger.warning(
        'tuning.json: "%s" must be "auto" or a positive integer, '
        "using default (%s)",
        key, _DEFAULTS[key],
    )
    return None


def _resolve(raw_config: Dict[str, Any]) -> Tuning:
    """Resolve raw config dict into a validated Tuning instance."""
    for key in raw_config:
        if key not in _VALID_KEYS:
            logger.warning('tuning.json: unknown key "%s" (ignored)', key)

    resolved = {}
    for key in _VALID_KEYS:
        raw = raw_config.get(key, _DEFAULTS[key])
        value = _validate_value(key, raw)
        if value is None:
            value = _validate_value(key, _DEFAULTS[key])
        resolved[key] = value
    return Tuning(**resolved)


def load_tuning(path: Optional[Path] = None) -> Tuning:
    """Load and resolve tuning from disk. Falls back to defaults.

    If the file does not exist at the default location, it is
    silently created with shipped defaults so users can discover
    and edit it.
    """
    p = path or _TUNING_PATH
    raw = load_json_with_comments(p)
    if raw is None and p == _TUNING_PATH and not p.exists():
        _create_default_file(p)
        raw = load_json_with_comments(p)
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        logger.warning("tuning.json: expected object, using all defaults")
        raw = {}
    return _resolve(raw)


def _create_default_file(path: Path) -> None:
    """Write the shipped-default tuning.json for discoverability."""
    try:
        # Import here to avoid circular dep with libexec/raptor-tune
        # which also writes this file. Use the same format.
        import json
        comments = {
            "codeql_ram_mb": "MB of RAM for CodeQL analysis",
            "codeql_threads": "CPUs for CodeQL (0 = all available)",
            "max_semgrep_workers": "parallel Semgrep scans",
            "max_codeql_workers": "parallel CodeQL database builds",
            "max_agentic_parallel": "parallel Claude Code agents for analysis",
            "max_fuzz_parallel": "ceiling for AFL++ parallel instances",
        }
        keys = list(_DEFAULTS.keys())
        entries = []
        for i, key in enumerate(keys):
            val = json.dumps(_DEFAULTS[key])
            comma = "," if i < len(keys) - 1 else ""
            entries.append((f'  "{key}": {val}{comma}', comments[key]))
        col = max(len(e) for e, _ in entries) + 2
        lines = ["{"]
        for entry, comment in entries:
            lines.append(f"{entry:<{col}}// {comment}")
        lines.append("}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError:
        pass


_cached: Optional[Tuning] = None
_cached_stat: Optional[tuple] = None  # (st_mtime_ns, st_size)


def _file_stat(path: Path) -> Optional[tuple]:
    try:
        s = path.stat()
        return (s.st_mtime_ns, s.st_size)
    except OSError:
        return None


def get_tuning() -> Tuning:
    """Return tuning values, re-reading only when the file changes."""
    global _cached, _cached_stat
    current = _file_stat(_TUNING_PATH)
    if _cached is None or current != _cached_stat:
        _cached = load_tuning()
        _cached_stat = current
    return _cached


__all__ = ["Tuning", "get_tuning", "load_tuning"]
