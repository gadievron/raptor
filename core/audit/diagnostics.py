"""Tier diagnostics and utility helpers for /audit.

Reporting, tier-counter manipulation, IRIS candidate conversion,
and function-source reading.  No orchestrator state mutation.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, TYPE_CHECKING
from pathlib import Path

from core.json import load_json, save_json

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

_MAX_DISCOVERED_PER_FUNCTION = 20

# scope-coverage.json is a small RAPTOR-written slot-allocation report.
_MAX_SCOPE_COVERAGE_BYTES = 8 * 1024 * 1024


def read_function_source(
    target_path: Path, file_path: str, _function_name: str,
    line_start: int = 0, line_end: int = 0,
) -> str:
    """Best-effort read of a function's source from the target.

    With a valid ``line_start``/``line_end`` span the read is sliced
    to those lines (1-based, inclusive). Without one the whole file
    is returned — callers that attribute pattern matches to a
    specific function MUST pass the span, or a match anywhere in the
    file binds to whatever symbol the caller happens to hold.

    ``file_path`` comes from run artefacts (checklists, findings —
    LLM-writable), so the join is containment-checked: an absolute
    path discards ``target_path`` entirely under ``/`` semantics and
    ``../`` segments escape the root (CWE-22).  Reads outside the
    target refuse with the function's normal empty-string degradation.
    """
    try:
        full = (target_path / file_path).resolve()
        if not full.is_relative_to(Path(target_path).resolve()):
            logger.warning(
                "read_function_source: refusing path outside target "
                "root: %r", file_path,
            )
            return ""
    except (OSError, ValueError):
        return ""
    if not full.is_file():
        return ""
    # Cap BEFORE reading: the oversize refusal used to buffer (and
    # decode) the whole file first, so a planted multi-hundred-MB
    # file cost its full size in peak memory just to be refused.
    from core.source import read_text_capped, split_lines
    # newline="": the span pairs with raw-byte-model line numbers, so
    # a plantable bare \r must reach split_lines un-translated (the
    # universal-newline default would turn it into a break).
    got = read_text_capped(full, 500_000, newline="")
    if got is None:
        return ""
    text, truncated = got
    if truncated:
        # Preserve the documented contract: oversized files return
        # empty, never a silently truncated prefix (a prefix would
        # mis-attribute spans past the cap).
        return ""
    if line_start > 0 and line_end >= line_start:
        # \n-model split (core.source.lines contract): the span comes
        # from the pinned checklist, whose inventory counts \n.
        return "\n".join(split_lines(text)[line_start - 1:line_end])
    # Whole-file fallback: trim exactly one \r before each \n — the
    # same per-line content the span path's split_lines join hands
    # consumers, with the whole-file byte shape (trailing newline)
    # kept. A bare \r stays in-line: same plantable-byte posture as
    # the span path, never a break.
    return text.replace("\r\n", "\n")


# Tier counters are incremented from parallel review workers and the
# parallel post-loop passes; the read-modify-write below silently loses
# increments without exclusion. One process-wide lock is enough — the
# increments are tiny, so contention stays negligible even at the
# 32-worker cap.
_TIER_COUNTER_LOCK = threading.Lock()

# Unknown tiers already warned about (once per tier per process).
# Telemetry must never crash a run, but an unregistered tier's
# tallies vanish from the tier-effectiveness table — that has to be
# loud, or a channel erroring 100% of the time stays invisible in
# exactly the surface built to expose channel degradation.
_UNKNOWN_TIERS_WARNED: set[str] = set()


def warn_unknown_tier(tier: str) -> None:
    """Warn (once per process) that *tier* has no registry entry.

    Called by every tier-counter increment path when the tier is
    missing from the counters dict: the increment is dropped, and
    this is the only trace. Registration lives in the orchestrator's
    ``_make_tier_counters()``.
    """
    with _TIER_COUNTER_LOCK:
        if tier in _UNKNOWN_TIERS_WARNED:
            return
        _UNKNOWN_TIERS_WARNED.add(tier)
    logger.warning(
        "tier %r is not registered in _make_tier_counters() — its "
        "telemetry increments are dropped and the tier-effectiveness "
        "table will never show it",
        tier,
    )


def increment_tier_dict(
    tier_counters: dict[str, Any],
    tier: str,
    field: str,
    value: float = 1,
) -> None:
    """Increment a counter field on a tier_counters dict entry.

    ``value`` accepts floats for the wall-clock fields
    (``wall_time_s`` / ``cpg_build_s``); count fields keep passing
    ints.  Thread-safe.
    """
    if tier in tier_counters:
        with _TIER_COUNTER_LOCK:
            current = getattr(tier_counters[tier], field, 0)
            setattr(tier_counters[tier], field, current + value)
    else:
        warn_unknown_tier(tier)


def increment_tier(
    result: Any,
    tier: str,
    outcome_str: str,
) -> None:
    """Increment a tier counter based on tool outcome.

    Thread-safe: callers run in parallel review workers, and the
    ``+= 1`` below is a read-modify-write that loses increments
    without exclusion (same hazard as ``increment_tier_dict``).
    """
    tc = result.tier_counters.get(tier)
    if tc is None:
        warn_unknown_tier(tier)
        return
    with _TIER_COUNTER_LOCK:
        if outcome_str == "confirmed":
            tc.confirmed += 1
        elif outcome_str == "refuted":
            tc.refuted += 1
        elif outcome_str == "error":
            tc.errors += 1
        elif outcome_str == "skipped":
            # Did-not-look outcomes get their own counter — folding
            # them into inconclusive read as "the tier looked and
            # could not decide", which overstates its coverage.
            tc.skipped += 1
        else:
            tc.inconclusive += 1


def tally_substrate_skip_language(
    tier_counters: dict[str, Any],
    tier: str,
    language: str | None,
) -> None:
    """Bump the tier's substrate-skip language tally (thread-safe).

    ``None`` folds into "unknown" — the receipt itself carries the
    detail; the tally only has to name the dominant unmodeled
    language for the report."""
    tc = tier_counters.get(tier)
    if tc is None:
        warn_unknown_tier(tier)
        return
    lang = language or "unknown"
    with _TIER_COUNTER_LOCK:
        langs = getattr(tc, "substrate_skip_languages", None)
        if langs is None:
            return
        langs[lang] = langs.get(lang, 0) + 1


def format_tier_diagnostics(
    tier_counters: dict[str, Any],
) -> str:
    """Format tier diagnostics as a human-readable table."""
    lines = ["Mechanical tier effectiveness:"]
    for name, tc in tier_counters.items():
        total = tc.confirmed + tc.refuted + tc.inconclusive + tc.errors
        if total == 0 and tc.skipped == 0:
            continue
        parts = []
        if tc.confirmed:
            parts.append(f"{tc.confirmed} confirmed")
        if tc.refuted:
            parts.append(f"{tc.refuted} refuted")
        if tc.inconclusive:
            parts.append(f"{tc.inconclusive} inconclusive")
        if tc.skipped:
            parts.append(f"{tc.skipped} skipped")
        if tc.errors:
            parts.append(f"{tc.errors} errors")
        if tc.wall_time_s > 0:
            wall_str = f"{tc.wall_time_s:.1f}s"
            if tc.cpg_build_s > 0:
                wall_str += f" (CPG build: {tc.cpg_build_s:.1f}s)"
            parts.append(wall_str)
        lines.append(f"  {name:16s} {', '.join(parts)}")
    return "\n".join(lines)


def inject_discovered_evidence(
    discovered: dict[str, Any],
    file_path: str,
    function_name: str,
    tool: str,
    hypothesis: str,
) -> None:
    """Add a mid-loop tool discovery to the discovered_evidence dict."""
    key = f"{file_path}:{function_name}"
    entries = discovered.setdefault(key, [])
    if len(entries) >= _MAX_DISCOVERED_PER_FUNCTION:
        entries.pop(0)
        logger.debug(
            "discovered_evidence cap (%d) reached for %s, oldest dropped",
            _MAX_DISCOVERED_PER_FUNCTION, key,
        )
    entries.append({
        "tool": tool,
        "text": f"{tool} confirmed: {hypothesis}" if hypothesis else f"{tool} confirmed",
    })


def write_tier_diagnostics(
    tier_counters: dict[str, Any],
    out_dir: Path,
    channel_health: dict[str, Any] | None = None,
) -> None:
    """Write tier-diagnostics.json to the output directory.

    ``channel_health`` (channel name → health snapshot, e.g. the
    joern gate's ``to_dict()``) is written under ``channel_health``
    when provided, so a tripped channel's zero-receipt tiers read as
    "channel went down mid-run" instead of "tool found nothing".
    """
    data: dict[str, Any] = {}
    for name, tc in tier_counters.items():
        data[name] = {
            "confirmed": tc.confirmed,
            "refuted": tc.refuted,
            "inconclusive": tc.inconclusive,
            "skipped": tc.skipped,
            "errors": tc.errors,
            "wall_time_s": round(tc.wall_time_s, 2),
        }
        if tc.cpg_build_s > 0:
            data[name]["cpg_build_s"] = round(tc.cpg_build_s, 2)
        # Substrate-skip breakdown (sub-count of "skipped"): written
        # only when present, so pre-existing consumers of the plain
        # skipped counter see no shape change on unaffected runs.
        if getattr(tc, "skipped_substrate", 0):
            data[name]["skipped_substrate"] = tc.skipped_substrate
            langs = getattr(tc, "substrate_skip_languages", None)
            if langs:
                data[name]["substrate_skip_languages"] = dict(langs)
    # Scoped-run slot-allocation report (see gaps.truncate_gaps_to_
    # budget): surfaced here so an operator reading tier diagnostics
    # sees which in-scope files got zero review slots.
    sc_path = out_dir / "scope-coverage.json"
    if sc_path.is_file():
        sc = load_json(sc_path, max_bytes=_MAX_SCOPE_COVERAGE_BYTES)
        if sc is not None:
            data["scope_coverage"] = sc
    if channel_health:
        data["channel_health"] = channel_health
    path = out_dir / "tier-diagnostics.json"
    save_json(path, data)


def iris_candidate_to_spec(candidate):
    """Convert an IRIS CandidateFunction to a TaintSpec via name heuristics."""
    from core.evidence import EvidenceTier

    from .iris_specs import TaintSpec
    name = candidate.function.lower()
    role = "propagator"
    if any(p in name for p in ("sanitize", "sanitise", "escape", "encode", "filter", "clean", "purify")):
        role = "sanitiser"
    elif any(p in name for p in ("read", "recv", "fetch", "load", "input", "get_user", "getenv")):
        role = "source"
    elif any(p in name for p in ("write", "send", "execute", "exec", "eval", "query", "system", "render", "emit")):
        role = "sink"
    return TaintSpec(
        function=candidate.function,
        file=candidate.file,
        role=role,
        confidence=0.6 if candidate.has_security_name else 0.4,
        evidence_tier=EvidenceTier.HEURISTIC,
    )
