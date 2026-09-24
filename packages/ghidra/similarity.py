"""Decompilation-similarity primitives shared by matcher and clustering.

The cross-version matcher (:mod:`packages.ghidra.match`) grew the
normalisation/hash/shingle/Jaccard primitives as private helpers of
its 1:1 bipartite cascade. The cascade itself is NOT reusable for
many-to-many clustering — every tier consumes matched functions from
both pools and refuses ambiguity, which is exactly wrong for peer
grouping where "several functions look alike" is the answer, not a
conflict. The PRIMITIVES, however, are one implementation with two
consumers:

* the matcher's tier 2 (normalized decompilation hash) and tier 5
  (token-shingle Jaccard with two-sided margin), and
* candidate-set similarity for peer-group formation (functions inside
  ONE database whose decompilations hash equal or score similar).

This module is that single home. :mod:`packages.ghidra.match` imports
these functions under its historical private names, so the matcher's
behaviour is the seam's behaviour by construction — a fork of either
side breaks the equivalence tests loudly instead of drifting apart
silently.

All input text is attacker-derived (decompilation of a hostile
binary): NUL bytes are stripped before masking so sentinel forgery is
impossible, shingling is token- and text-capped, and nothing here
emits text — callers own escaping at their emission chokepoints.
"""

from __future__ import annotations

import hashlib
import re
from typing import TYPE_CHECKING, Dict, FrozenSet, Optional

if TYPE_CHECKING:
    from .model import REFunction

#: Tokens per function fed into shingling — attacker decompilation is
#: unbounded; ~1k tokens is plenty for similarity.
MAX_SHINGLE_TOKENS = 1024
#: Text prefix fed into shingle normalization — 1024 tokens fit in a
#: fraction of this; the rest only costs memory.
MAX_SHINGLE_TEXT = 262_144
#: Minimum normalized length for a decompilation hash — single-line
#: stubs collide constantly; too weak to key on.
MIN_DECOMP_HASH_CHARS = 16

_AUTO_NAME = re.compile(
    r"\b(?:thunk_FUN|j_FUN|FUN|DAT|LAB|SUB|loc|fcn|sub|switchD|caseD)"
    r"_[0-9a-fA-F]+\b")
_HEX_CONST = re.compile(r"0x[0-9a-fA-F]+")
_WS = re.compile(r"\s+")
#: Mask sentinels are NUL-delimited so no legal C/C++ identifier can
#: collide with them (a genuine variable named "A1" or "H" must not
#: hash-equal a masked auto-name or constant); the token regex matches
#: them so masked positions still participate in shingles.
MASK_HEX = "\x00H\x00"
MASK_OWN = "\x00F\x00"
_TOKEN = re.compile(
    r"\x00[A-Za-z0-9]+\x00|[A-Za-z_][A-Za-z0-9_]*"
    r"|[{}();,*&\[\]=+<>!-]")


def strip_nul(text: str) -> str:
    """Remove raw NUL bytes from attacker-derived text.

    Mask sentinels are NUL-delimited; input text containing literal
    NULs (legal in the JSON round-trip) could forge a sentinel and
    fake normalized equality. Applied at every text entry point,
    BEFORE any masking."""
    return text.replace("\x00", " ")


def mask_own_name(text: str, own: str) -> str:
    """Mask a function's own (possibly renamed) name in its text.

    Word-bounded — a name that is a substring of other identifiers
    ("a" in "max") must not be masked there — and replaced via a
    callable so the sentinel is never interpreted for backreferences.
    """
    if not own:
        return text
    return re.sub(
        r"(?<![A-Za-z0-9_])" + re.escape(own) + r"(?![A-Za-z0-9_])",
        lambda _m: MASK_OWN, text)


def mask_auto_names(text: str) -> str:
    """Auto-generated names → canonical per-text indices (A1, A2, …).

    A rebase renames every auto-name consistently, which preserves
    the occurrence structure — but a retargeted reference (FUN_X →
    FUN_Y where Y is referenced elsewhere in the body) changes it, so
    canonical numbering keeps rebase tolerance without flattening
    every auto-name into one indistinguishable token.
    """
    seen: Dict[str, str] = {}

    def _canon(mo: "re.Match[str]") -> str:
        name = mo.group(0)
        idx = seen.get(name)
        if idx is None:
            idx = f"\x00A{len(seen) + 1}\x00"
            seen[name] = idx
        return idx

    return _AUTO_NAME.sub(_canon, text)


def normalize_decomp(text: str) -> str:
    """Decompilation normalized for cross-build comparison.

    Auto-generated names and hex constants embed addresses that shift
    between builds; whitespace embeds none. Both are masked so the
    hash keys on structure and real identifiers only.
    """
    text = mask_auto_names(text)
    text = _HEX_CONST.sub(MASK_HEX, text)
    return _WS.sub(" ", text).strip()


def normalize_keep_constants(text: str) -> str:
    """Like :func:`normalize_decomp` but hex constants survive.

    The comparison layer uses this as the second stage: a pair whose
    fully-normalized text matches but whose constants differ carries
    a real change (bounds, masks, auth constants) that full masking
    would silently swallow.
    """
    text = mask_auto_names(text)
    return _WS.sub(" ", text).strip()


def decomp_hash_text(text: object, own: str = "") -> Optional[str]:
    """Normalized-decompilation hash of raw decompiled text.

    ``own`` masks the function's own identifier (rename-aware
    comparison) INSIDE the single strip→mask→normalize pipeline. The
    mask sentinel is NUL-delimited, so masking must happen AFTER the
    one NUL strip and the stripped text must never be re-stripped: a
    caller-side ``mask_own_name`` followed by a second strip here
    would dissolve the sentinel into a bare identifier that a
    literal ``F`` in another function could forge equality with.

    ``None`` when the text is empty or normalizes below
    :data:`MIN_DECOMP_HASH_CHARS` (single-line stubs collide
    constantly; too weak to key on).
    """
    if not text:
        return None
    subject = mask_own_name(strip_nul(str(text)), own)
    norm = normalize_decomp(subject)
    if len(norm) < MIN_DECOMP_HASH_CHARS:
        return None
    return hashlib.sha256(norm.encode("utf-8", "replace")).hexdigest()


def decomp_hash(func: "REFunction") -> Optional[str]:
    """Normalized-decompilation hash of a function record."""
    if not func.decompilation:
        return None
    return decomp_hash_text(func.decompilation)


def shingles_text(text: object, own: str = "") -> FrozenSet[str]:
    """3-token shingles of normalized decompiled text (capped).

    ``own`` masks the function's own identifier inside the single
    strip→mask→normalize pipeline (see :func:`decomp_hash_text` for
    why the mask must ride between the one strip and normalization).

    The token cap is applied while ITERATING — materializing the full
    token list first turned one hostile multi-megabyte decompilation
    into hundreds of MB of peak memory before the cap could bite.
    """
    if not text:
        return frozenset()
    from itertools import islice
    subject = strip_nul(str(text))
    if len(subject) > MAX_SHINGLE_TEXT:
        # the token cap never needs more input than this; without the
        # text cap the normalizer's intermediate strings are the
        # memory sink on hostile multi-MB decompilations
        subject = subject[:MAX_SHINGLE_TEXT]
    subject = mask_own_name(subject, own)
    toks = [m.group(0) for m in islice(
        _TOKEN.finditer(normalize_decomp(subject)),
        MAX_SHINGLE_TOKENS)]
    if len(toks) < 3:
        return frozenset(toks)
    return frozenset(
        " ".join(toks[i:i + 3]) for i in range(len(toks) - 2)
    )


def shingles(func: "REFunction") -> FrozenSet[str]:
    """3-token shingles of a function record's decompilation."""
    if not func.decompilation:
        return frozenset()
    return shingles_text(func.decompilation)


def jaccard(a: FrozenSet[str], b: FrozenSet[str]) -> Optional[float]:
    """Jaccard similarity of two shingle sets; ``None`` when either
    side is empty (no evidence, not zero similarity)."""
    if not a or not b:
        return None
    union = len(a | b)
    return len(a & b) / union if union else None


def decomp_similarity(text_a: object, text_b: object) -> Optional[float]:
    """Shingle-Jaccard similarity of two raw decompiled texts.

    Convenience wrapper for candidate-set consumers that hold text,
    not :class:`REFunction` records. ``None`` means "no evidence"
    (either side empty or too short to shingle), never 0.0.
    """
    return jaccard(shingles_text(text_a), shingles_text(text_b))


__all__ = [
    "MASK_HEX",
    "MASK_OWN",
    "MAX_SHINGLE_TEXT",
    "MAX_SHINGLE_TOKENS",
    "MIN_DECOMP_HASH_CHARS",
    "decomp_hash",
    "decomp_hash_text",
    "decomp_similarity",
    "jaccard",
    "mask_auto_names",
    "mask_own_name",
    "normalize_decomp",
    "normalize_keep_constants",
    "shingles",
    "shingles_text",
    "strip_nul",
]
