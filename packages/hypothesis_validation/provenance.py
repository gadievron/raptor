"""Provenance edges — every piece of evidence carries its hypothesis hash.

Two pieces:

  hash_hypothesis(h)         -> stable HypothesisHash (sha256 hex)
  ensure_same_provenance(es) -> str         | raises ProvenanceMismatch

Stability is the contract: the same hypothesis content must produce the
same hash across processes, machines, and Python versions. We get that
by serialising to JSON with sorted keys, normalising whitespace in every
string field, and pure-text path-normalising fields that hold filesystem
paths (`target`, and the `file` attribute of nested locations / flow
steps).

Why normalise whitespace: the LLM frequently re-emits the same claim
with different wrapping ("foo\\n  bar" vs "foo bar") between iteration
rounds. Without normalisation, two semantically identical hypotheses
hash differently and the runner cannot deduplicate or detect "this is
the same hypothesis as last round".

Why normalise paths: the LLM (and the runner) regularly emit `./foo.c`,
`src/./foo.c`, and `src/../src/foo.c` interchangeably. `posixpath.normpath`
collapses these without filesystem access. We use `posixpath` rather
than `os.path` because the latter is platform-dependent — on Windows
it rewrites `/` to `\\`, so a hypothesis hashed on a Linux dev machine
and the same hypothesis hashed on a Windows CI runner would produce
different hashes, defeating the cross-machine stability that's the
whole point of this hash. Note that absolute and relative forms of the
same path still hash distinctly — `normpath` cannot canonicalise that
without a cwd, and a cwd-dependent hash would not be process-stable.
Callers that need abs-vs-rel equivalence should resolve paths before
constructing the Hypothesis.
"""

import hashlib
import json
import posixpath
import re
from typing import Any, Iterable

from .hypothesis import Hypothesis


HypothesisHash = str  # 64-char hex digest of SHA-256


class ProvenanceMismatch(ValueError):
    """Raised when evidence with different `refers_to` is combined."""


_WS_RE = re.compile(r"\s+")

# Keys whose string values are filesystem paths and so receive
# `os.path.normpath` in addition to whitespace normalisation. Listed
# explicitly rather than detected heuristically because path-shaped
# strings appear elsewhere (e.g. in match `message` fields) where we
# do *not* want to mangle them.
_PATH_KEYS = frozenset({"target", "file"})


def _normalise_string(s: str, *, is_path: bool = False) -> str:
    """Collapse runs of whitespace into one space; strip ends.

    When `is_path` is set, additionally apply `posixpath.normpath` to
    fold redundant separators and `.`/`..` segments. We use `posixpath`
    explicitly so the result is platform-independent: `os.path.normpath`
    rewrites `/` to `\\` on Windows, which would make hashes diverge
    across machines. The empty string is preserved as-is —
    `normpath("")` returns `"."`, which would change the hash for an
    unset path field.
    """
    out = _WS_RE.sub(" ", s).strip()
    if is_path and out:
        out = posixpath.normpath(out)
    return out


def _normalise(value: Any, key: Any = None) -> Any:
    """Recursively normalise strings inside dicts/lists/tuples.

    `key` carries the parent dict key when descending into dict values,
    so path-shaped string fields can be normalised with `normpath`
    while leaving sibling string fields alone.
    """
    if isinstance(value, str):
        return _normalise_string(value, is_path=key in _PATH_KEYS)
    if isinstance(value, dict):
        return {k: _normalise(v, key=k) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalise(v, key=key) for v in value]
    return value


def hash_hypothesis(h: Hypothesis) -> HypothesisHash:
    """Stable content-addressed hash of a Hypothesis.

    Steps (each chosen so the hash is unaffected by superficial changes):
      1. Serialise via h.to_dict() so the field set is canonical.
      2. Normalise whitespace in every string field; additionally apply
         os.path.normpath to known path-bearing fields (`target`, nested
         `file`).
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
