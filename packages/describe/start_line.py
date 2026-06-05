"""Start-line target summary for /scan, /agentic, /codeql.

A single line emitted at run START — operator gets confirmation
RAPTOR understood the target shape BEFORE any LLM cost or
analysis time burns. Pre-fix the start surfaced only the
catalog cost estimate ("Expected: $25-$50, 40-75 min …") which
told the operator NOTHING about whether RAPTOR detected the
right languages, build system, target type. The richer line
closes that loop.

Format::

    Analyzing C++ (95%, 47k LOC), autotools, c.userspace-daemon —
    $25-$50, 40-75 min estimated

* Primary language + share + LOC (the dominant signal — answers
  "did RAPTOR think this is C++?")
* Build system (answers "did the build detector recognise the
  manifest?")
* Catalog target type (answers "did the catalog match? was it
  the right type?")
* Cost + time estimate (the existing surface, preserved as a
  tail clause so the budget gate's information stays surfaced)

Any missing piece is omitted rather than rendered as "unknown" —
keep the line compact when signals are sparse, since the
operator can run /describe for the full breakdown.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional


def format_start_line(target_path: Path) -> Optional[str]:
    """Compose a one-line start-of-run target summary. Returns
    None when /describe substrate is unavailable (caller falls
    back to the bare cost estimate).
    """
    try:
        from packages.describe.target_shape import infer_target_shape
        from core.inventory.languages import display_lang
    except Exception:  # noqa: BLE001
        return None

    try:
        shape = infer_target_shape(target_path)
    except Exception:  # noqa: BLE001
        return None

    parts: list = []

    # Primary language + share + LOC.
    primary = shape.primary_language
    if primary and shape.language_breakdown:
        pct = shape.language_breakdown.get(primary)
        loc = shape.language_lines.get(primary) if shape.language_lines else None
        head = display_lang(primary)
        if pct is not None:
            head = f"{head} ({pct:g}%"
            if loc:
                head += f", {_short_loc(loc)} LOC"
            head += ")"
        parts.append(head)

    # Build system (primary language's).
    if primary and shape.build_systems and primary in shape.build_systems:
        parts.append(shape.build_systems[primary])

    # Catalog target type (skip the bland "generic" default —
    # adds noise to the line when no real type matched).
    if shape.target_type and shape.target_type != "generic":
        parts.append(shape.target_type)

    head_str = ", ".join(parts) if parts else None

    # Cost estimate — preserve the existing format so the budget
    # gate's "Expected" framing is recognisable; "estimated" tail
    # word ties it to the new richer head.
    estimate_str = _format_compact_estimate(target_path)

    # "Target:" not "Analyzing": this line emits at run start,
    # BEFORE any tool actually runs. "Analyzing" implies the
    # LLM is already burning tokens which is misleading; "Target:"
    # accurately frames it as the operator-facing shape RAPTOR
    # detected before kicking off the work.
    if head_str and estimate_str:
        return f"Target: {head_str} — {estimate_str} estimated"
    if head_str:
        return f"Target: {head_str}"
    if estimate_str:
        return f"Expected: {estimate_str}"
    return None


def _short_loc(n: int) -> str:
    """52000 → '52k'; 1500000 → '1.5M'."""
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n // 1_000}k"
    return str(n)


def _format_compact_estimate(target_path: Path) -> Optional[str]:
    """Compact "$25-$50, 40-75 min" form — drops the "Expected:"
    prefix + the "(target type: …)" suffix that
    ``core.run.estimator.format_estimate`` adds (we already
    name the target type in the head clause). None on
    estimator failure / no catalog match.
    """
    try:
        from core.run.estimator import estimate_run, format_estimate
        est = estimate_run(target_path)
        if est is None:
            return None
        full = format_estimate(est)
        if not full:
            return None
        full = full.removeprefix("Expected: ")
        return full.split(" (target type:", 1)[0]
    except Exception:  # noqa: BLE001
        return None


__all__ = ["format_start_line"]
