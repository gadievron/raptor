"""Provenance edges — every piece of evidence carries its hypothesis hash.

This pre-emptively kills a class of bugs in any future iteration loop
where evidence from hypothesis n−1 leaks into hypothesis n. The runner
calls `ensure_same_provenance` before combining evidence; if any item
refers to a different hypothesis, the call raises and the verdict
collapses to INCONCLUSIVE rather than silently mixing claims.

The hash is content-addressed (SHA-256 over a canonical JSON encoding
of the hypothesis fields) so it is stable across processes and across
the wire — useful for caching, audit trails, and the deferred typed-plan
DAG checker.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable, Union

from .hypothesis import Hypothesis
from .types import TypedHypothesis


HypothesisHash = str  # 64-char hex digest of SHA-256


class ProvenanceMismatch(ValueError):
    """Raised when evidence with different `refers_to` is combined."""


def _canonical(obj: Any) -> str:
    """Stable JSON encoding for hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def hash_hypothesis(h: Union[Hypothesis, TypedHypothesis]) -> HypothesisHash:
    """Content-address a hypothesis.

    Both the legacy `Hypothesis` dataclass and the new `TypedHypothesis`
    Pydantic model are accepted. The hash spans the legacy and typed
    surfaces so a hypothesis migrated between them keeps its identity
    only when its content is preserved verbatim.
    """
    if isinstance(h, TypedHypothesis):
        payload = {"_type": "typed", **h.model_dump(mode="json")}
    elif isinstance(h, Hypothesis):
        payload = {"_type": "legacy", **h.to_dict()}
    else:
        raise TypeError(f"unhashable hypothesis type: {type(h)!r}")
    digest = hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()
    return digest


def ensure_same_provenance(items: Iterable[Any]) -> HypothesisHash:
    """Assert every item carries the same `refers_to`. Returns that hash.

    Items lacking a `refers_to` attribute are skipped — older evidence
    types from before the typed layer don't carry the field, and a
    missing edge is treated as "unknown" rather than silently equal.
    Raises `ProvenanceMismatch` if two distinct non-empty hashes appear.
    """
    seen: set[str] = set()
    for it in items:
        ref = getattr(it, "refers_to", "") or ""
        if ref:
            seen.add(ref)
    if len(seen) > 1:
        raise ProvenanceMismatch(
            f"evidence list spans multiple hypotheses: {sorted(seen)}"
        )
    return next(iter(seen), "")


def stamp(items: Iterable[Any], refers_to: HypothesisHash) -> list:
    """Set `refers_to` on every item that supports the field.

    Used by the runner immediately after producing evidence so the
    provenance edge is attached at the source rather than threaded
    through every adapter's signature. Items without the field (legacy
    `Evidence`/`ToolEvidence` from before this commit) are left
    untouched — `setattr` on a frozen Pydantic model would raise, so we
    guard with hasattr + try.
    """
    out = []
    for it in items:
        try:
            if hasattr(it, "refers_to"):
                # Frozen Pydantic models reject __setattr__; fall back to
                # model_copy(update=...) for those.
                if hasattr(it, "model_copy"):
                    it = it.model_copy(update={"refers_to": refers_to})
                else:
                    setattr(it, "refers_to", refers_to)
        except (AttributeError, TypeError, ValueError):
            pass
        out.append(it)
    return out


__all__ = [
    "HypothesisHash",
    "ProvenanceMismatch",
    "hash_hypothesis",
    "ensure_same_provenance",
    "stamp",
]
