"""Start-line target summary for /scan, /agentic, /codeql.

A single line emitted at run START — operator gets confirmation
RAPTOR understood the target shape BEFORE any LLM cost or
analysis time burns.

Format::

    Target: C++ (95%, 47k LOC), autotools, c.userspace-daemon

* Primary language + share + LOC (the dominant signal — answers
  "did RAPTOR think this is C++?")
* Build system (answers "did the build detector recognise the
  manifest?")
* Catalog target type (answers "did the catalog match? was it
  the right type?")

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

    # Catalog target type (skip generic fallbacks — the language
    # is already shown from extension detection).
    if shape.target_type and not shape.target_type.endswith("generic"):
        parts.append(shape.target_type)

    if not parts:
        return None

    line = f"Target: {', '.join(parts)}"

    # Scorecard-derived cost/time estimate (when data exists).
    est_str = _scorecard_estimate_clause(target_path, shape.target_type)
    if est_str:
        line = f"{line}  {est_str}"

    return line


def _scorecard_estimate_clause(
    target_path: Path, target_type: Optional[str],
) -> Optional[str]:
    """Return a compact estimate string from scorecard data, or None."""
    try:
        from core.run.target_types import load as _load_catalog
        from core.run.estimator import estimate_from_scorecard, format_estimate
        from core.llm.model_data import PROVIDER_DEFAULT_MODELS

        entry = _load_catalog(target_path)
        n_findings = entry.typical_findings_count if entry else 0
        if n_findings <= 0:
            return None

        model = PROVIDER_DEFAULT_MODELS.get("anthropic", "")
        if not model:
            return None

        est = estimate_from_scorecard(model, n_findings)
        if est is None:
            return None

        return format_estimate(est)
    except Exception:  # noqa: BLE001
        return None


def _short_loc(n: int) -> str:
    """52000 → '52k'; 1500000 → '1.5M'."""
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{round(n / 1_000)}k"
    return str(n)



__all__ = ["format_start_line"]
