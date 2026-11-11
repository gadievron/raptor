"""Pipeline context identities and full-section delivery; no evidence authority."""
from __future__ import annotations

from hashlib import sha256
from typing import cast

# Each adapted producer names its actual existing prompt input and section.
_CONTEXT_INPUTS = {
    "late_joern": ("mechanical_evidence", "evidence"),
    "live_sinks": ("live_sinks", "live_sinks"),
    "disagreement": ("disagreement_override", "disagreement_override"),
    "deepen_quality": ("deepen_quality_selection", "deepen_quality"),
    "callee_contract": ("callee_contract_violation", "callee_contract"),
}


def context_version(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def context_spec(ctx: dict, *, kind: str, version: str) -> dict | None:
    fields = _CONTEXT_INPUTS.get(kind)
    if fields is None:
        return None
    key, section = fields
    value = ctx.get(key)
    if kind == "callee_contract":
        from .callee_review_context import render_callee_context
        from .context import _defend_identifier

        value = render_callee_context(value, defend_identifier=_defend_identifier)
    if kind == "disagreement":
        from .disagreement_review_context import render_disagreement_context
        from .context import _defend_identifier

        value = render_disagreement_context(value, defend_identifier=_defend_identifier)
    if kind == "live_sinks":
        from .live_sink_continuation import render_live_sink_context
        from .context import _defend_identifier

        value = render_live_sink_context(value, defend_identifier=_defend_identifier)
    if kind == "deepen_quality":
        from .deepen_continuation import render_deepen_selection

        value = render_deepen_selection(value)
    if not isinstance(value, str) or not value or context_version(value) != version:
        return None
    return {"context_id": f"context:{kind}:{version}", "kind": kind, "version": version,
            "context_key": key, "section": section}


def context_delivery(ctx: dict, original, kept) -> list[dict]:
    """Credit only an exact, complete section surviving actual prompt fitting."""
    rows: list[dict] = []
    specs = ctx.get("continuation_context_inputs", ())
    if not isinstance(specs, (list, tuple)):
        return rows
    for spec in specs:
        if not isinstance(spec, dict):
            continue
        valid = context_spec(ctx, kind=cast(str, spec.get("kind")), version=cast(str, spec.get("version")))
        if valid != spec:
            continue
        sections = [s for s in original if s.label == spec["section"]]
        delivered = bool(sections) and all(any(k.label == s.label and k.text == s.text for k in kept) for s in sections)
        rows.append({**spec, "delivered": delivered,
                     "reason": "complete_prompt_section" if delivered else "context_not_fitted"})
    return rows
