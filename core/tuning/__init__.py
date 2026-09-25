"""Hardware-aware resource tuning for RAPTOR.

Reads ``tuning.json`` from the repo root, resolves ``"auto"`` values
using hardware detection, validates per-key, and exposes resolved
integers and booleans to consumers via ``get_tuning()``.

Invalid keys warn and fall back to defaults per-key — a single typo
never blocks a session.
"""

from __future__ import annotations

import logging
import math
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.json import load_json_with_comments

logger = logging.getLogger(__name__)

# core/tuning/__init__.py → repo root
_REPO_ROOT = Path(__file__).resolve().parents[2]  # core/tuning/ → repo
_TUNING_PATH = _REPO_ROOT / "tuning.json"

_VALID_KEYS = frozenset({
    "codeql_enabled",
    "codeql_ram_mb",
    "codeql_threads",
    "codeql_max_disk_cache_mb",
    "joern_enabled",
    "joern_heap_mb",
    "joern_heap_ceiling_mb",
    "joern_cpg_timeout_s",
    "joern_query_timeout_s",
    "max_semgrep_workers",
    "max_codeql_workers",
    "max_fuzz_parallel",
    "max_inventory_workers",
    "max_llm_workers",
    "llm_account_posture",
    "max_json_memo_mb",
    "throttle_cooldown_s",
})

_DEPRECATED_KEYS = frozenset({
    "max_agentic_parallel",
})

# Keys that are valid in tuning.json but consumed directly by their
# own modules (core/llm/concurrency.py) rather than through the
# resolved Tuning dataclass. Excluded from _resolve() / Tuning.
_PASSTHROUGH_KEYS = frozenset({
    "max_llm_workers",
    "llm_account_posture",
    "throttle_cooldown_s",
})

_BOOLEAN_KEYS = frozenset({"codeql_enabled", "joern_enabled"})

_KEY_COMMENTS = {
    "codeql_enabled": "set false to disable CodeQL across all runs (licensing)",
    "codeql_ram_mb": "MB of RAM for CodeQL (-M)",
    "codeql_threads": "CPUs for CodeQL (-j; 0 = all available)",
    "codeql_max_disk_cache_mb": "MB cap on codeql DB build cache (--max-disk-cache; 0 = codeql's unbounded default)",
    "joern_enabled": "set false to disable Joern CPG analysis across all runs",
    "joern_heap_mb": "MB of JVM heap for Joern (auto = 25% system RAM, min 1024, capped by joern_heap_ceiling_mb)",
    "joern_heap_ceiling_mb": "MB cap on the DERIVED Joern heap (auto = min(25% RAM, 65536)); explicit joern_heap_mb values are never capped",
    "joern_cpg_timeout_s": "seconds before CPG generation is killed (auto = derived from in-scope source size at build time)",
    "joern_query_timeout_s": "seconds before a single Joern query is killed",
    "max_semgrep_workers": "parallel Semgrep scans (auto = half available CPUs)",
    "max_codeql_workers": "parallel CodeQL DB builds (auto = half available CPUs, capped)",
    "max_fuzz_parallel": "ceiling for AFL++ parallel instances (auto = half available CPUs)",
    "max_inventory_workers": "per-file extractor pool for tree-sitter parse (auto = half CPUs, capped at 8)",
    "max_json_memo_mb": "MB budget for JsonCache in-process memo; oldest entries evicted past this",
    "max_llm_workers": "parallel LLM API calls (consumed by core/llm/concurrency.py)",
    "llm_account_posture": "shared = LLM account has other consumers, fair-share ceilings; solo = account belongs to this host's runs",
    "throttle_cooldown_s": "seconds to wait between LLM batches when rate-limited",
}

_DEFAULTS = {
    "codeql_enabled": True,
    "codeql_ram_mb": "auto",
    "codeql_threads": "auto",
    # 0 sentinel = "leave codeql's own unbounded default in place".  Set
    # explicit MB cap when running unattended on bounded disk; codeql's
    # DB build cache otherwise grows without limit.
    "codeql_max_disk_cache_mb": 0,
    "joern_enabled": True,
    "joern_heap_mb": "auto",
    "joern_heap_ceiling_mb": "auto",
    "joern_cpg_timeout_s": "auto",
    "joern_query_timeout_s": 300,
    # Worker counts default to hardware-aware auto: the per-process
    # jobs/threads division at the dispatch sites makes half-CPU
    # worker pools safe on any host size (previously pinned at
    # small-host literals 4/2/4).
    "max_semgrep_workers": "auto",
    "max_codeql_workers": "auto",
    "max_fuzz_parallel": "auto",
    "max_inventory_workers": "auto",
    "max_json_memo_mb": 128,
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


# Compressed-oops boundary: above ~32 GiB heaps HotSpot disables
# UseCompressedOops (verified with -XX:+PrintFlagsFinal on this
# JDK: true at -Xmx31g, false at -Xmx126916m) and every object
# reference doubles to 8 bytes. A heap in the (32, ~48] GiB band is
# strictly worse than 31 GiB: it pays the doubled references without
# holding more objects than the compressed 31 GiB heap does. CPGs
# are exactly the pointer-dense workload where this bites.
_JOERN_OOPS_SAFE_MB = 31 * 1024          # stay under the 32 GiB flip
_JOERN_OOPS_DEAD_ZONE_TOP_MB = 48 * 1024


# Default heap ceiling for the DERIVED Joern heap: 64 GiB. Both
# directions of the trade-off: lower would starve CPG builds/queries
# that measurably need large heaps (a scoped CPG over a ~3M-SLOC C
# tree built successfully at exactly 64 GiB); higher re-opens the failure
# the ceiling exists to close — a raw 25%-of-RAM derivation on a
# large box produces a heap in the 100+ GiB band that external
# memory monitors kill, silently losing the Joern channel for the
# run. Operators on monster boxes with no such monitor raise
# joern_heap_ceiling_mb; explicit joern_heap_mb values are never
# capped (an explicit number is an operator assertion).
_JOERN_HEAP_CEILING_DEFAULT_MB = 64 * 1024


def _detect_joern_heap_ceiling_mb() -> int:
    """min(25% of system RAM, 64 GiB), floor 1024 MB.

    The 25% leg keeps the ceiling meaningful on small hosts (the
    ceiling never authorises a heap the proportional rule would not
    have derived anyway); the 64 GiB leg is the large-box safety cap
    (see _JOERN_HEAP_CEILING_DEFAULT_MB).
    """
    total_mb = _detect_total_ram_mb()
    return max(1024, min(total_mb // 4, _JOERN_HEAP_CEILING_DEFAULT_MB))


def _cap_derived_joern_heap_mb(heap_mb: int, ceiling_mb: int) -> int:
    """Apply the operator/derived ceiling to a DERIVED heap value.

    The cap can land the heap in the compressed-oops dead zone (an
    explicit ceiling of e.g. 40960), so the dead-zone clamp re-runs
    after the min(): a capped heap in (31 GiB, 48 GiB] is strictly
    worse than 31 GiB (see _JOERN_OOPS_SAFE_MB). Floor 1024 preserves
    the detector's minimum against a pathological sub-GiB ceiling.
    """
    heap = max(1024, min(heap_mb, ceiling_mb))
    if _JOERN_OOPS_SAFE_MB < heap <= _JOERN_OOPS_DEAD_ZONE_TOP_MB:
        return _JOERN_OOPS_SAFE_MB
    return heap


#: Sentinel resolved value for ``joern_cpg_timeout_s: "auto"``. The
#: derivation needs the in-scope source size, which only the build
#: site knows — the static resolver cannot produce a number, so it
#: produces this marker and consumers call
#: :func:`derive_joern_cpg_timeout_s` with the scope's SLOC estimate
#: (``packages.joern.tunables.JoernTunables.from_tuning`` translates
#: it into ``cpg_timeout_auto`` plus a usable fallback number).
JOERN_CPG_TIMEOUT_DERIVED = 0

# CPG-build timeout curve. Calibration datum (measured): a scoped
# CPG over ~3,000,000 in-scope SLOC of C built in 2,849 s at a
# 64 GiB heap — ≈950 s per million SLOC. The 2.0 slack factor
# absorbs slower disks, smaller heaps (GC pressure grows as the heap
# shrinks below the calibration point), and denser code; a leaner
# factor kills legitimate builds near the curve (the failure mode
# this derivation replaces was a flat 300 s wall killing a 2,849 s
# build), while a fatter one makes a genuinely hung frontend cost
# hours before the kill.
_JOERN_CPG_S_PER_MSLOC = 2849.0 / 3.0
_JOERN_CPG_TIMEOUT_SLACK = 2.0
# Floor 300 s: identical to the historical static default, so small
# scopes keep today's hung-parse kill latency; lower would re-create
# the killed-legitimate-build class on medium scopes the curve maps
# under 300 s. Cap 14,400 s (4 h, ≈5× the calibration wall — covers
# ~7.5M SLOC on the curve): beyond it an unattended run pays a
# working day for a hung frontend; a genuinely larger scope needs an
# explicit joern_cpg_timeout_s (the cap is a derivation bound, not a
# validation bound).
_JOERN_CPG_TIMEOUT_FLOOR_S = 300
_JOERN_CPG_TIMEOUT_CAP_S = 14400
# Unknown-scope fallback: 1800 s covers ~1.4M SLOC on the curve.
# Smaller would kill medium builds whenever the size estimate is
# unavailable; larger makes a hung parse on an unmeasurable target
# cost the full cap.
_JOERN_CPG_TIMEOUT_UNKNOWN_SCOPE_S = 1800


def derive_joern_cpg_timeout_s(in_scope_sloc: int | None) -> int:
    """CPG-build timeout derived from the scope's estimated SLOC.

    Linear in SLOC through the calibration datum (see the constants
    above), with slack, floored and capped. ``None``/non-positive
    (scope size unknown) returns the documented fallback.
    """
    if not in_scope_sloc or in_scope_sloc <= 0:
        return _JOERN_CPG_TIMEOUT_UNKNOWN_SCOPE_S
    raw = (in_scope_sloc / 1_000_000.0) * _JOERN_CPG_S_PER_MSLOC
    derived = math.ceil(raw * _JOERN_CPG_TIMEOUT_SLACK)
    if raw > _JOERN_CPG_TIMEOUT_CAP_S:
        # Even the un-slacked calibration estimate exceeds the cap:
        # the capped wall is knowably undersized for this scope, and
        # the build will likely be killed mid-flight. Say so loudly
        # at derivation time — the operator can act BEFORE paying
        # the capped wall.
        logger.warning(
            "derived Joern CPG timeout capped at %ds, but the "
            "calibration curve estimates ~%ds for ~%d in-scope SLOC "
            "even before slack — the wall is likely undersized. Set "
            "joern_cpg_timeout_s explicitly in tuning.json, or "
            "narrow --scope.",
            _JOERN_CPG_TIMEOUT_CAP_S, math.ceil(raw), in_scope_sloc,
        )
    return max(
        _JOERN_CPG_TIMEOUT_FLOOR_S,
        min(derived, _JOERN_CPG_TIMEOUT_CAP_S),
    )


def derived_max_joern_cpg_timeout_s() -> int:
    """The largest timeout the derivation can produce (the curve cap).

    Retry-at-derived-max consumers use it as their upper bound.
    """
    return _JOERN_CPG_TIMEOUT_CAP_S


def derived_max_joern_heap_mb() -> int:
    """The largest heap the derivation can produce: the resolved
    ceiling, dead-zone-adjusted.

    Retry-at-derived-max consumers use it as their upper bound — the
    retry honors the same ceiling the first derivation did.
    """
    ceiling = get_tuning().joern_heap_ceiling_mb
    return _cap_derived_joern_heap_mb(ceiling, ceiling)


def _detect_joern_heap_mb() -> int:
    """25% of system RAM, floor 1024 MB, compressed-oops-aware.

    -Xmx is a ceiling, not a reservation — the JVM commits only what
    it uses (measured: a 124 GiB -Xms/-Xmx pair held RSS at ~0.9 GiB
    on an nginx-sized CPG) — and RAPTOR runs a single Joern server
    per run, so a proportional ceiling is safe. The former 4096 MB
    cap starved CPG queries on large targets when the host had RAM
    to spare (a 500 GB box was clamped to a laptop-sized heap).

    One exception: a proportional value landing in the compressed-
    oops dead zone (see _JOERN_OOPS_SAFE_MB) is clamped DOWN to the
    31 GiB compressed maximum — more effective capacity, not less.
    Values above the dead zone keep the proportional size: there the
    raw capacity genuinely exceeds what compressed 31 GiB can hold.
    """
    total_mb = _detect_total_ram_mb()
    heap = max(1024, total_mb // 4)
    if _JOERN_OOPS_SAFE_MB < heap <= _JOERN_OOPS_DEAD_ZONE_TOP_MB:
        return _JOERN_OOPS_SAFE_MB
    return heap


def _detect_inventory_workers() -> int:
    """Resolve a conservative per-file extractor pool size.

    Tree-sitter Tree objects can transiently hold tens of MB per
    file (TS / JS / large Java sources in particular). On a high-
    core box ``os.cpu_count()`` returns 16+; the resulting peak —
    ``workers × tree_size`` — dominated the inventory stage's RSS
    on a Grafana-scale repo (5.7 GB across the SCA reach stage).
    Cap at 8: extract is mostly per-file CPU with diminishing
    returns past ~8 workers, and the bound keeps the transient
    working set in line with the lighter scan stages.
    """
    return _detect_half_cpu_parallelism(max_workers=8)


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


def _resolve_cpg_timeout_auto() -> int:
    """``joern_cpg_timeout_s: "auto"`` → the derived-at-build-time
    sentinel (see :data:`JOERN_CPG_TIMEOUT_DERIVED`)."""
    return JOERN_CPG_TIMEOUT_DERIVED


_AUTO_RESOLVERS = {
    "codeql_ram_mb": _detect_ram_mb,
    "codeql_threads": _detect_threads,
    "joern_heap_mb": _detect_joern_heap_mb,
    "joern_heap_ceiling_mb": _detect_joern_heap_ceiling_mb,
    "joern_cpg_timeout_s": _resolve_cpg_timeout_auto,
    "max_semgrep_workers": _detect_semgrep_workers,
    "max_codeql_workers": _detect_codeql_workers,
    "max_fuzz_parallel": _detect_fuzz_parallel,
    "max_inventory_workers": _detect_inventory_workers,
}

# Keys where 0 is a valid explicit value:
#   - codeql_threads: 0 = all CPUs
#   - codeql_max_disk_cache_mb: 0 = use codeql's unbounded default
_ZERO_ALLOWED = frozenset({
    "codeql_threads", "codeql_max_disk_cache_mb",
})


@dataclass(frozen=True, slots=True)
class Tuning:
    """Resolved tuning values — integers and booleans, no ``"auto"``."""
    codeql_enabled: bool
    codeql_ram_mb: int
    codeql_threads: int
    codeql_max_disk_cache_mb: int
    joern_enabled: bool
    joern_heap_mb: int
    joern_heap_ceiling_mb: int
    joern_cpg_timeout_s: int
    joern_query_timeout_s: int
    max_semgrep_workers: int
    max_codeql_workers: int
    max_fuzz_parallel: int
    max_inventory_workers: int
    max_json_memo_mb: int
    # True when joern_heap_mb was DERIVED (auto), not operator-set.
    # Consumers that raise limits (the retry-at-derived-max path)
    # honor explicit numbers both directions: an explicit heap is an
    # operator assertion and is neither capped nor raised.
    joern_heap_mb_derived: bool = False


def _validate_value(key: str, raw: Any):
    """Validate and resolve a single tuning value.

    Returns the resolved value (int or bool), or None if invalid
    (caller uses default).
    """
    if key in _BOOLEAN_KEYS:
        if isinstance(raw, bool):
            return raw
        logger.warning(
            'tuning.json: "%s" must be true or false, using default (%s)',
            key, _DEFAULTS[key],
        )
        return None
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
    # Accept integer-valued floats (`4.0`, `8.0`) — JSON has no
    # int/float distinction at the wire level, and many editors /
    # config tools emit `4.0` when the user types `4`. Pre-fix
    # the strict `isinstance(raw, int)` rejected these and used
    # the default, masking the operator's intent.
    if isinstance(raw, float) and raw.is_integer() and raw >= min_val:
        return int(raw)
    logger.warning(
        'tuning.json: "%s" must be "auto" or a positive integer, '
        "using default (%s)",
        key, _DEFAULTS[key],
    )
    return None


def _resolve(raw_config: dict[str, Any]) -> Tuning:
    """Resolve raw config dict into a validated Tuning instance."""
    for key in raw_config:
        if key not in _VALID_KEYS and key not in _DEPRECATED_KEYS:
            logger.warning('tuning.json: unknown key "%s" (ignored)', key)

    resolved = {}
    fell_back_to_default: set[str] = set()
    for key in _VALID_KEYS - _PASSTHROUGH_KEYS:
        raw = raw_config.get(key, _DEFAULTS[key])
        value = _validate_value(key, raw)
        if value is None:
            fell_back_to_default.add(key)
            value = _validate_value(key, _DEFAULTS[key])
        resolved[key] = value

    # The heap ceiling caps the DERIVED heap only: an "auto" (or
    # invalid-and-defaulted-to-auto) joern_heap_mb is capped at the
    # resolved ceiling, while an explicit numeric heap is an operator
    # assertion and passes through uncapped. Capping explicit values
    # too would silently shrink a deliberate large-heap config; not
    # capping the derived value re-opens the raw-25%-of-RAM heap that
    # external memory monitors kill on large boxes.
    heap_is_derived = (
        raw_config.get("joern_heap_mb", _DEFAULTS["joern_heap_mb"]) == "auto"
        or ("joern_heap_mb" in fell_back_to_default
            and _DEFAULTS["joern_heap_mb"] == "auto")
    )
    if heap_is_derived:
        resolved["joern_heap_mb"] = _cap_derived_joern_heap_mb(
            resolved["joern_heap_mb"], resolved["joern_heap_ceiling_mb"],
        )
    return Tuning(**resolved, joern_heap_mb_derived=heap_is_derived)


def _migrate_deprecated(raw: dict[str, Any], path: Path) -> None:
    """Strip deprecated keys from raw config and rewrite the file.

    Mutates ``raw`` in place. Rewrites the file atomically when at
    least one deprecated key was present; degrades gracefully on
    read-only filesystems.
    """
    found = [k for k in list(raw) if k in _DEPRECATED_KEYS]
    if not found:
        return
    for k in found:
        del raw[k]
        logger.info('tuning.json: removed deprecated key "%s"', k)
    try:
        _rewrite_tuning(raw, path)
    except OSError as exc:
        logger.debug("could not rewrite %s after deprecation cleanup: %s", path, exc)


def _rewrite_tuning(values: dict[str, Any], path: Path) -> None:
    """Rewrite tuning.json preserving all current valid keys."""
    import json as _json
    base_keys = [k for k in _DEFAULTS if k not in _PASSTHROUGH_KEYS]
    extra_keys = [k for k in values if k in _VALID_KEYS and k not in _DEFAULTS]
    key_order = base_keys + extra_keys
    merged = dict(_DEFAULTS)
    for k in key_order:
        if k in values:
            merged[k] = values[k]
    entries = []
    for i, key in enumerate(key_order):
        val = _json.dumps(merged[key])
        comma = "," if i < len(key_order) - 1 else ""
        entries.append((f'  "{key}": {val}{comma}', _KEY_COMMENTS.get(key, "")))
    col = max(len(e) for e, _ in entries) + 2
    lines = ["{"]
    for entry, comment in entries:
        if comment:
            lines.append(f"{entry:<{col}}// {comment}")
        else:
            lines.append(entry)
    lines.append("}")
    content = "\n".join(lines) + "\n"
    tmp = path.with_name(
        f"{path.name}.tmp.{os.getpid()}.{threading.get_ident()}"
    )
    try:
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(path)
    except BaseException:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def load_tuning(path: Path | None = None) -> Tuning:
    """Load and resolve tuning from disk. Falls back to defaults.

    If the file does not exist at the default location, it is
    silently created with shipped defaults so users can discover
    and edit it.

    Deprecated keys are stripped from the file on first load so
    stale operator configs self-heal without manual intervention.
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
    _migrate_deprecated(raw, p)
    return _resolve(raw)


def _create_default_file(path: Path) -> None:
    """Write the shipped-default tuning.json for discoverability.

    Uses an atomic write (write to `.tmp.<pid>` sibling, then
    rename) so that:
      * A concurrent reader (libexec/raptor-tune, get_tuning's
        re-load) can never observe a half-written file.
      * Crash mid-write doesn't leave a corrupt tuning.json that
        every subsequent get_tuning() trip-falls over.
      * Two concurrent writers (this function + raptor-tune CLI
        racing) don't share a tempfile path — pid suffix
        disambiguates so each writer's tmp survives until its own
        rename, and the final rename is last-writer-wins.
    """
    try:
        import json
        keys = list(_DEFAULTS.keys())
        entries = []
        for i, key in enumerate(keys):
            val = json.dumps(_DEFAULTS[key])
            comma = "," if i < len(keys) - 1 else ""
            entries.append((f'  "{key}": {val}{comma}', _KEY_COMMENTS.get(key, "")))
        col = max(len(e) for e, _ in entries) + 2
        lines = ["{"]
        for entry, comment in entries:
            lines.append(f"{entry:<{col}}// {comment}")
        lines.append("}")
        content = "\n".join(lines) + "\n"
        # pid+tid suffix — same-process threads can race on save().
        import threading
        tmp = path.with_name(
            f"{path.name}.tmp.{os.getpid()}.{threading.get_ident()}"
        )
        try:
            tmp.write_text(content, encoding="utf-8")
            tmp.replace(path)
        except BaseException:
            # Clean up partial tmp on any failure (including
            # KeyboardInterrupt mid-write) so the next call doesn't
            # find an orphan and racers don't see stale tmp files
            # piling up.
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise
    except OSError:
        pass


_cached: Tuning | None = None
_cached_stat: tuple | None = None  # (st_mtime_ns, st_size)
# Lock around the cache check + update. Pre-fix `get_tuning` was
# racy: two threads calling it concurrently could both see
# `_cached is None`, both call `load_tuning()` (file I/O + JSON
# parse), both write to the cache. Worse, the WINNING write could
# be the older one if the threads interleaved between the assigns.
# Holding the lock briefly serialises check-then-update.
_cached_lock = threading.Lock()


def _file_stat(path: Path) -> tuple | None:
    try:
        s = path.stat()
        return (s.st_mtime_ns, s.st_size)
    except OSError:
        return None


def get_tuning() -> Tuning:
    """Return tuning values, re-reading only when the file changes.

    Thread-safe via `_cached_lock`. Pre-fix the check-then-update
    sequence was racy across threads — two callers could both
    observe `_cached is None`, both issue a file read + JSON parse,
    both write to the cache. The winning write was order-dependent
    and could be older than the loser. Hold the lock briefly to
    serialise.
    """
    global _cached, _cached_stat
    current = _file_stat(_TUNING_PATH)
    with _cached_lock:
        if _cached is None or current != _cached_stat:
            _cached = load_tuning()
            _cached_stat = current
        return _cached


__all__ = [
    "JOERN_CPG_TIMEOUT_DERIVED",
    "Tuning",
    "derive_joern_cpg_timeout_s",
    "derived_max_joern_cpg_timeout_s",
    "derived_max_joern_heap_mb",
    "get_tuning",
    "load_tuning",
]
