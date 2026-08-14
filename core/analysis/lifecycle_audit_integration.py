"""Integration point for /audit orchestrator.

Provides :func:`check_lifecycle_at_function` which the orchestrator
calls during proactive validation.  Given a function that reads a
lifecycle-sensitive state field, checks whether the read site is
covered by the field's write-site preconditions.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List

from .lifecycle_checker import check_coverage
from .lifecycle_context_map import load_state_fields
from .lifecycle_model import LifecycleFinding

logger = logging.getLogger(__name__)


def check_lifecycle_at_function(
    file_path: str,
    function_name: str,
    source: str,
    out_dir: Path,
    line: int = 0,
) -> List[LifecycleFinding]:
    """Check a function for lifecycle-precondition violations.

    Loads state fields from context-map.json, checks whether this
    function reads any of them without the required guards.

    Returns findings (may be empty).
    """
    fields = load_state_fields(out_dir)
    if not fields:
        return []

    findings: List[LifecycleFinding] = []

    for field in fields:
        for rs in field.read_sites:
            if rs.file == file_path and rs.function == function_name:
                field_findings = check_coverage(field)
                for f in field_findings:
                    if f.read_site == rs:
                        findings.append(f)

    return findings


def format_lifecycle_evidence(findings: List[LifecycleFinding]) -> str:
    """Format lifecycle findings as evidence prose for the LLM reviewer."""
    if not findings:
        return ""

    lines = ["## Lifecycle-Precondition Analysis\n"]
    for f in findings:
        lines.append(
            f"**{f.state_field.struct_type}.{f.state_field.name}** "
            f"read at {f.read_site.file}:{f.read_site.line} "
            f"in `{f.read_site.function}()`"
        )
        lines.append(f"  Invariant: {f.state_field.invariant}")
        lines.append(f"  Missing guards: {', '.join(sorted(f.missing_guards))}")
        lines.append(f"  Confidence: {f.confidence}")
        lines.append("")

    return "\n".join(lines)


def lifecycle_findings_to_constraints(
    findings: List[LifecycleFinding],
) -> List[Dict[str, Any]]:
    """Convert lifecycle findings to audit constraint format.

    Each finding becomes a 'precondition' constraint that can be
    propagated through the constraint system.
    """
    constraints: List[Dict[str, Any]] = []
    for f in findings:
        constraints.append({
            "kind": "precondition",
            "target": f"{f.state_field.struct_type}.{f.state_field.name}",
            "rule": (
                f"guard '{', '.join(sorted(f.missing_guards))}' "
                f"required before reading {f.state_field.name}"
            ),
            "violation": (
                f"read at {f.read_site.file}:{f.read_site.line} "
                f"lacks guard — {f.state_field.invariant} may not hold"
            ),
            "cwe": f.state_field.cwe,
            "function": f.read_site.function,
            "file": f.read_site.file,
            "propagation": "callers",
        })
    return constraints
