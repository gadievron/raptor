"""Offer already-ready, occurrence-bound context before one review reservation."""
from __future__ import annotations

from .continuation_context import context_version


def offer_ready_joern_context(runtime, ctx, gap, ready_gaps, evidence_index) -> bool:
    """Coalesce a completed producer's actual section, without waiting for it.

    The caller supplies its pipeline-owned pre-build review inventory. Bare
    function names and legacy records without occurrence bounds do not qualify.
    This offers advisory analysis context, never verification authority.
    """
    occurrence = (gap.get("file"), gap.get("name"), gap.get("line_start"))
    if type(occurrence[2]) is not int or occurrence[2] <= 0:
        return False
    if not any((item.get("file"), item.get("name"), item.get("line_start")) == occurrence
               for item in ready_gaps):
        return False
    record = evidence_index.get(f"{occurrence[0]}:{occurrence[1]}")
    if (record is None or (record.file, record.function, record.line_start) != occurrence
            or not record.joern_flows):
        return False
    value = ctx.get("mechanical_evidence")
    if not isinstance(value, str) or not value:
        return False
    return runtime.offer_context_delta(ctx, kind="late_joern", version=context_version(value))
