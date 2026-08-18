"""Tier diagnostics and utility helpers for /audit.

Reporting, tier-counter manipulation, IRIS candidate conversion,
and function-source reading.  No orchestrator state mutation.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_MAX_DISCOVERED_PER_FUNCTION = 20


def read_function_source(
    target_path: Path, file_path: str, function_name: str,
) -> str:
    """Best-effort read of a function's source from the target."""
    full = target_path / file_path
    if not full.is_file():
        return ""
    try:
        text = full.read_text(errors="replace")
    except OSError:
        return ""
    if len(text) > 500_000:
        return ""
    return text


def increment_tier_dict(
    tier_counters: dict[str, Any],
    tier: str,
    field: str,
    value: float = 1,
) -> None:
    """Increment a counter field on a tier_counters dict entry.

    ``value`` accepts floats for the wall-clock fields
    (``wall_time_s`` / ``cpg_build_s``); count fields keep passing
    ints.
    """
    if tier in tier_counters:
        current = getattr(tier_counters[tier], field, 0)
        setattr(tier_counters[tier], field, current + value)


def increment_tier(
    result: Any,
    tier: str,
    outcome_str: str,
) -> None:
    """Increment a tier counter based on tool outcome."""
    tc = result.tier_counters.get(tier)
    if tc is None:
        return
    if outcome_str == "confirmed":
        tc.confirmed += 1
    elif outcome_str == "refuted":
        tc.refuted += 1
    elif outcome_str == "error":
        tc.errors += 1
    else:
        tc.inconclusive += 1


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
) -> None:
    """Write tier-diagnostics.json to the output directory."""
    data = {}
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
    # Scoped-run slot-allocation report (see gaps.truncate_gaps_to_
    # budget): surfaced here so an operator reading tier diagnostics
    # sees which in-scope files got zero review slots.
    sc_path = out_dir / "scope-coverage.json"
    if sc_path.is_file():
        try:
            with open(sc_path, encoding="utf-8") as f:
                data["scope_coverage"] = json.load(f)
        except (OSError, ValueError):
            logger.debug("scope-coverage.json unreadable", exc_info=True)
    path = out_dir / "tier-diagnostics.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


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
