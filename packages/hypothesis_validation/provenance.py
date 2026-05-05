"""Provenance edges — every piece of evidence carries its hypothesis hash.

Two pieces:

  hash_hypothesis(h)         -> stable HypothesisHash (sha256 hex)
  ensure_same_provenance(es) -> str         | raises ProvenanceMismatch

Stability is the contract: the same hypothesis content must produce the
same hash across processes, machines, and Python versions. We get that
by serialising to JSON with sorted keys and by normalising whitespace
in every string field (collapse runs of whitespace to a single space,
strip leading/trailing space) before hashing.

Why normalise whitespace: the LLM frequently re-emits the same claim
with different wrapping ("foo\\n  bar" vs "foo bar") between iteration
rounds. Without normalisation, two semantically identical hypotheses
hash differently and the runner cannot deduplicate or detect "this is
the same hypothesis as last round".
"""

import hashlib
import json
import re
from typing import Any, Iterable

from .hypothesis import Hypothesis


HypothesisHash = str  # 64-char hex digest of SHA-256


class ProvenanceMismatch(ValueError):
    """Raised when evidence with different `refers_to` is combined."""


_WS_RE = re.compile(r"\s+")


def _normalise_string(s: str) -> str:
    """Collapse runs of whitespace into one space; strip ends.

    Applied to every string value before hashing. Idempotent.
    """
    return _WS_RE.sub(" ", s).strip()


def _normalise(value: Any) -> Any:
    """Recursively normalise strings inside dicts/lists/tuples."""
    if isinstance(value, str):
        return _normalise_string(value)
    if isinstance(value, dict):
        return {k: _normalise(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalise(v) for v in value]
    return value


def hash_hypothesis(h: Hypothesis) -> HypothesisHash:
    """Stable content-addressed hash of a Hypothesis.

    Steps (each chosen so the hash is unaffected by superficial changes):
      1. Serialise via h.to_dict() so the field set is canonical.
      2. Normalise whitespace in every string field.
      3. JSON-encode with sort_keys=True (stable key order across
         Python releases) and minimal separators (no whitespace at all
         in the encoded form).
      4. SHA-256 the bytes.

    The output is 64 hex chars suitable for use as Evidence.refers_to.
    """
    payload = _normalise(h.to_dict())
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def ensure_same_provenance(items: Iterable[Any]) -> HypothesisHash:
    """Assert every item shares the same `refers_to`. Return that hash.

    Items lacking a `refers_to` attribute, or with an empty value, are
    skipped — older evidence types from before provenance tracking
    don't carry the field, and an empty edge is treated as "unknown"
    rather than silently equal. Raises `ProvenanceMismatch` if two
    distinct non-empty hashes appear.
    """
    seen: set = set()
    for it in items:
        ref = getattr(it, "refers_to", "") or ""
        if ref:
            seen.add(ref)
    if len(seen) > 1:
        raise ProvenanceMismatch(
            f"evidence list spans multiple hypotheses: {sorted(seen)}"
        )
    return next(iter(seen), "")


__all__ = [
    "HypothesisHash",
    "ProvenanceMismatch",
    "hash_hypothesis",
    "ensure_same_provenance",
]
