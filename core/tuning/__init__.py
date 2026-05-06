"""Hardware-aware resource tuning for RAPTOR.

Reads ``tuning.json`` from the repo root, resolves ``"auto"`` values
using hardware detection, validates per-key, and exposes resolved
integers to consumers via ``get_tuning()``.

Invalid keys warn and fall back to defaults per-key — a single typo
never blocks a session.
"""

from __future__ import annotations

import logging
import math
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


def _detect_total_ram_mb() -> int:
    """Return total system RAM in MB, or a conservative fallback."""
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
    except (ValueError, OSError):
        return 32768
    return pages * page_size // (1024 * 1024)


def _detect_ram_mb() -> int:
    """25% of system RAM, clamped to [2048, 16384] MB."""
    total_mb = _detect_total_ram_mb()
    return max(2048, min(total_mb // 4, 16384))


def _detect_threads() -> int:
    # 0 tells CodeQL to use all available CPUs — preserving its
    # native auto-detection (respects cgroups, hyperthreading, etc.)
    return 0


def _detect_semgrep_workers() -> int:
    """Resolve a conservative CPU-based Semgrep worker count.

    Semgrep scans are CPU and memory heavy, so the auto value should
    improve utilisation on larger machines without defaulting to every
    detected core.
    """
    return _detect_half_cpu_parallelism()


def _detect_codeql_workers() -> int:
    """Resolve a conservative parallel CodeQL database-build count."""
    per_worker_ram_mb = _detect_ram_mb()
    ram_limited_workers = max(1, _detect_total_ram_mb() // per_worker_ram_mb)
    return _detect_half_cpu_parallelism(max_workers=min(8, ram_limited_workers))


def _detect_fuzz_parallel() -> int:
    """Resolve a conservative AFL++ parallel-instance ceiling."""
    return _detect_half_cpu_parallelism()


def _detect_cgroup_cpu_quota() -> int | None:
    """Return an integer CPU quota from Linux cgroups, if configured."""
    cpu_max = Path("/sys/fs/cgroup/cpu.max")
    try:
        quota_text = cpu_max.read_text(encoding="utf-8").strip().split()
    except OSError:
        quota_text = []
    if len(quota_text) >= 2 and quota_text[0] != "max":
        try:
            quota = int(quota_text[0])
            period = int(quota_text[1])
        except ValueError:
            quota = period = 0
        if quota > 0 and period > 0:
            return max(1, math.ceil(quota / period))

    quota_path = Path("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
    period_path = Path("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
    try:
        quota = int(quota_path.read_text(encoding="utf-8").strip())
        period = int(period_path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None
    if quota > 0 and period > 0:
        return max(1, math.ceil(quota / period))
    return None


def _detect_available_cpus() -> int:
    """Return CPUs available to this process, respecting affinity/cgroups."""
    candidates: list[int] = []
    sched_getaffinity = getattr(os, "sched_getaffinity", None)
    if sched_getaffinity is not None:
        try:
            affinity_cpus = len(sched_getaffinity(0))
        except OSError:
            affinity_cpus = 0
        if affinity_cpus > 0:
            candidates.append(affinity_cpus)

    cpu_count = os.cpu_count()
    if cpu_count is not None and cpu_count > 0:
        candidates.append(cpu_count)

    cgroup_cpus = _detect_cgroup_cpu_quota()
    if cgroup_cpus is not None:
        candidates.append(cgroup_cpus)

    if not candidates:
        return 4
    return min(candidates)


def _detect_half_cpu_parallelism(max_workers: int | None = None) -> int:
    cpus = _detect_available_cpus()
    workers = max(1, cpus // 2)
    if max_workers is not None:
        workers = min(workers, max_workers)
    return workers


_AUTO_RESOLVERS = {
    "codeql_ram_mb": _detect_ram_mb,
    "codeql_threads": _detect_threads,
    "max_semgrep_workers": _detect_semgrep_workers,
    "max_codeql_workers": _detect_codeql_workers,
    "max_fuzz_parallel": _detect_fuzz_parallel,
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
            "max_semgrep_workers": "parallel Semgrep scans (auto = half available CPUs)",
            "max_codeql_workers": "parallel CodeQL DB builds (auto = half available CPUs, capped)",
            "max_agentic_parallel": "parallel Claude Code agents for analysis",
            "max_fuzz_parallel": "ceiling for AFL++ parallel instances (auto = half available CPUs)",
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
