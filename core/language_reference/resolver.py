"""Bounded demand lookup over reviewed, immutable language reference entries."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from functools import lru_cache
from typing import Literal


@dataclass(frozen=True)
class ReferenceContext:
    """Configured facts, supplied by the pipeline rather than the reviewer.

    A source suffix or binary ABI does not establish a language edition.
    Unknown edition returns conditional material, never a guessed mode.
    """

    language: str
    edition: str | None = None


@dataclass(frozen=True)
class ReferenceEntry:
    entry_id: str
    version: int
    language: str
    editions: tuple[str, ...]
    title: str
    topics: tuple[str, ...]
    summary: str
    rule: str
    conditions: tuple[str, ...]
    required_target_facts: tuple[str, ...]
    citations: tuple[str, ...]
    prerequisites: tuple[str, ...] = ()

    def render_core(self) -> str:
        """One indivisible prompt unit; fitting must not slice its conditions."""
        return "\n".join((
            f"{self.entry_id} v{self.version}: {self.title}",
            f"Applicability: {self.language}; editions: {', '.join(self.editions)}.",
            self.rule,
            "Conditions: " + " ".join(self.conditions),
            "Target facts needed: " + "; ".join(self.required_target_facts),
            "Source: " + "; ".join(self.citations),
        ))


@dataclass(frozen=True)
class ReferenceAnswer:
    request_id: str
    status: Literal["answered", "needs_target_facts", "ambiguous", "unsupported"]
    entries: tuple[ReferenceEntry, ...] = ()
    reason: str = ""
    missing_facts: tuple[str, ...] = ()
    pack_version: str = "c-integers-1"
    # Presentation provenance only, never applicability or delivery authority.
    selection_origin: Literal["requested", "initial"] = "requested"
    selection_kind: Literal["topic", "entry_id"] = "topic"


_TOKEN = re.compile(r"[a-z0-9_]+")
_MAX_TOPIC_CHARS = 512
_MAX_CANDIDATES = 3
_MAX_PACK_ENTRIES = 256
_STOP_WORDS = frozenset((
    "a", "an", "and", "are", "as", "at", "be", "by", "can", "do", "does",
    "for", "from", "how", "i", "in", "is", "it", "of", "on", "or", "that",
    "the", "their", "these", "this", "to", "what", "when", "which", "with",
))


def _tokens(text: str) -> frozenset[str]:
    return frozenset(_TOKEN.findall(text.casefold())) - _STOP_WORDS


def lookup(
    request_id: str,
    topic: str,
    context: ReferenceContext,
    *,
    entry_id: str | None = None,
) -> ReferenceAnswer:
    """Return full candidate bundles without IO, model calls or target claims.

    Exact IDs bypass ranking, never applicability checks. Topic similarity
    selects reading only. Near top-ranked candidates remain ambiguous.
    Prerequisites travel with each candidate so promotion conditions cannot
    disappear from the usual-conversions rule.
    """
    from .c_integer import ENTRIES

    if not isinstance(topic, str) or len(topic) > _MAX_TOPIC_CHARS:
        return ReferenceAnswer(request_id, "unsupported", reason="invalid or oversized topic")
    if not isinstance(ENTRIES, tuple) or len(ENTRIES) > _MAX_PACK_ENTRIES:
        return ReferenceAnswer(request_id, "unsupported", reason="reference pack is outside immutable bounds")
    if entry_id is not None and not isinstance(entry_id, str):
        return ReferenceAnswer(request_id, "unsupported", reason="invalid reference entry identity")
    terms = _tokens(topic) if entry_id is None else frozenset()
    pack_version = ReferenceAnswer("", "unsupported").pack_version
    try:
        answer = _lookup_cached(terms, context, entry_id, ENTRIES, pack_version)
    except TypeError:
        return ReferenceAnswer(request_id, "unsupported", reason="reference lookup inputs are not immutable")
    return replace(answer, request_id=request_id, pack_version=pack_version,
                   selection_kind="entry_id" if entry_id is not None else "topic")


@lru_cache(maxsize=128)
def _lookup_cached(
    terms: frozenset[str], context: ReferenceContext, entry_id: str | None,
    pack: tuple[ReferenceEntry, ...], pack_version: str,
) -> ReferenceAnswer:
    """Share only immutable reading; IDs and delivery stay with each caller.

    The full pack is part of the key: ranking metadata and prerequisite links
    can change without changing rendered rule text. The captured pack label
    also keys the template and is rebound by the caller with its request ID.
    """
    request_id = ""
    available = tuple(e for e in pack if e.language == context.language)
    if not available:
        return ReferenceAnswer(request_id, "unsupported", reason="language is outside this reference pack")
    if context.edition is not None:
        available = tuple(e for e in available if context.edition in e.editions)
        if not available:
            return ReferenceAnswer(request_id, "unsupported", reason="language edition is outside this reference pack")
    if entry_id is not None:
        candidates = tuple(e for e in available if e.entry_id == entry_id)
    else:
        ranked = sorted((
            (4 * len(terms & _tokens(e.title))
             + 2 * len(terms & _tokens(" ".join(e.topics)))
             + len(terms & _tokens(e.summary)), e)
            for e in available
        ), key=lambda pair: (-pair[0], pair[1].entry_id))
        highest = ranked[0][0] if ranked else 0
        # A one-point summary-word advantage must not decide a broad topic.
        # Keep candidates within 80% of the highest score. This is an initial
        # retrieval policy, not an applicability or semantic-confidence test.
        candidates = tuple(e for score, e in ranked if score > 0 and 5 * score >= 4 * highest)
    if not candidates:
        return ReferenceAnswer(request_id, "unsupported", reason="no reviewed entry matches this request")
    if len(candidates) > _MAX_CANDIDATES:
        return ReferenceAnswer(request_id, "ambiguous", reason="too many near-ranked entries; narrow the topic")
    by_id = {e.entry_id: e for e in available}
    bundle: dict[str, ReferenceEntry] = {}

    def add(entry: ReferenceEntry) -> None:
        if entry.entry_id in bundle:
            return
        for required in entry.prerequisites:
            add(by_id[required])
        bundle[entry.entry_id] = entry

    for candidate in candidates:
        add(candidate)
    entries = tuple(bundle.values())
    if len(candidates) > 1:
        return ReferenceAnswer(request_id, "ambiguous", entries,
                               "near-ranked reading candidates; applicability is not established",
                               ("language edition",) if context.edition is None else ())
    if context.edition is None:
        return ReferenceAnswer(request_id, "needs_target_facts", entries,
                               "conditional C11 material; target language edition is unknown",
                               ("language edition",))
    return ReferenceAnswer(request_id, "answered", entries,
                           "reference supplied; target applicability still requires code review")
