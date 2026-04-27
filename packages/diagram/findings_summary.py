"""Findings summary diagrams — verdict and vulnerability type pie charts.

Input: findings.json (from /validate) or orchestrated_report.json results (from /agentic).
"""

from typing import Any, Dict, List, Tuple

from core.reporting.formatting import get_display_status, title_case_type
from .sanitize import sanitize as _sanitize

# Verdict colours — neutral palette, no red/green value judgement.
# Exploitable vs Ruled Out is perspective-dependent (attacker vs defender).
_VERDICT_ORDER: List[Tuple[str, str]] = [
    ("Exploitable", "#dc2626"),              # red — high severity, demands attention
    ("Confirmed", "#f97316"),                # orange
    ("Confirmed (Constrained)", "#ca8a04"),  # amber
    ("Confirmed (Blocked)", "#d97706"),      # dark amber
    ("False Positive", "#94a3b8"),           # grey
    ("Ruled Out", "#64748b"),                # dark grey
    ("Unknown", "#cbd5e1"),                  # light grey
    ("Uncategorised", "#cbd5e1"),            # light grey
]

# Type colours — use a broader palette for variety.
_TYPE_COLOURS = [
    "#dc2626", "#3b82f6", "#16a34a", "#ca8a04", "#8b5cf6",
    "#ec4899", "#06b6d4", "#f97316", "#6366f1", "#14b8a6",
]


def generate_verdict_pie(findings: List[Dict[str, Any]]) -> str:
    """Pie chart of finding verdicts (Exploitable/Confirmed/Ruled Out/etc)."""
    counts: Dict[str, int] = {}
    for f in findings:
        status = get_display_status(f)
        counts[status] = counts.get(status, 0) + 1

    # Sort by the defined order so colours match
    ordered = []
    for label, colour in _VERDICT_ORDER:
        if label in counts:
            ordered.append((label, counts.pop(label), colour))
    # Any remaining (unexpected statuses)
    for label, count in sorted(counts.items(), key=lambda x: -x[1]):
        ordered.append((label, count, "#cbd5e1"))

    return _pie_with_colours("Finding Verdicts", ordered)


def generate_type_pie(findings: List[Dict[str, Any]]) -> str:
    """Pie chart of vulnerability types (Buffer Overflow/XSS/etc)."""
    counts: Dict[str, int] = {}
    for f in findings:
        vtype = title_case_type(f.get("vuln_type", ""))
        counts[vtype] = counts.get(vtype, 0) + 1

    ordered = []
    for i, (label, count) in enumerate(sorted(counts.items(), key=lambda x: -x[1])):
        colour = _TYPE_COLOURS[i % len(_TYPE_COLOURS)]
        ordered.append((label, count, colour))

    return _pie_with_colours("Vulnerability Types", ordered)


def _pie_with_colours(title: str, slices: List[Tuple[str, int, str]]) -> str:
    if not slices:
        return f'pie title {title}\n    "No findings" : 1'

    # Build theme init with per-slice colours
    theme_vars = ", ".join(
        f"'pie{i+1}': '{colour}'" for i, (_label, _count, colour) in enumerate(slices)
    )
    lines = [
        f"%%{{init: {{'theme': 'base', 'themeVariables': {{{theme_vars}}}}}}}%%",
        f"pie title {title}",
    ]
    for label, count, _colour in slices:
        lines.append(f'    "{_sanitize(label)}" : {count}')

    return "\n".join(lines)
