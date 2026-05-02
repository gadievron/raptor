"""Model-family detection and cross-family checker selection.

When schema validation rejects an LLM response, the caller can re-issue the
request through ``validate_response``'s ``llm_call`` callback. The
*Attacker Moves Second* finding (arXiv 2510.09023) shows that a single
model's output parser is bypassable under adaptive attack at >90% ASR.
Routing the retry through a model from a different family raises the bar
from "bypass one parser" to "bypass two unrelated parsers simultaneously".

This module provides the family-detection helpers callers compose with
``validate_response``. It does not change ``validate_response`` itself —
the cross-family routing is a caller concern (which model is the producer,
which models are available as checkers).

Family is the deployment vendor / training lineage, not the prompt-defence
profile shape. They overlap by prefix because vendor identifiers do — see
``prompt_defense_profiles._BY_PREFIX`` for the same prefix list. They are
separate concepts: a profile selects envelope shape and which defences
apply; a family selects who trained the model so that a "different family"
checker is meaningfully independent.
"""

from __future__ import annotations

from typing import Iterable, Literal, Optional


Family = Literal["anthropic", "openai", "google", "meta", "ollama", "unknown"]


_FAMILY_PREFIXES: tuple[tuple[str, Family], ...] = (
    ("claude-", "anthropic"),
    ("anthropic/", "anthropic"),
    ("gpt-", "openai"),
    ("o1-", "openai"),
    ("o3-", "openai"),
    ("openai/", "openai"),
    ("gemini-", "google"),
    ("gemini/", "google"),
    ("google/", "google"),
    ("llama-", "meta"),
    ("meta-llama/", "meta"),
    ("ollama/", "ollama"),
)


def family_of(model_id: str) -> Family:
    """Return the model family for a model identifier.

    Matching is by prefix on the lowered identifier (so ``claude-opus-4-7``
    and ``anthropic/claude-haiku-4-5`` both resolve to ``"anthropic"``).
    Unknown identifiers return ``"unknown"``.
    """
    needle = model_id.lower()
    for prefix, family in _FAMILY_PREFIXES:
        if needle.startswith(prefix):
            return family
    return "unknown"


def same_family(a: str, b: str) -> bool:
    """True if ``a`` and ``b`` resolve to the same family.

    Two ``"unknown"`` identifiers are NOT considered the same family —
    we cannot prove they share lineage, and treating them as related
    would weaken the cross-family invariant.
    """
    fa = family_of(a)
    fb = family_of(b)
    if fa == "unknown" or fb == "unknown":
        return False
    return fa == fb


def select_cross_family_checker(
    producer_model_id: str,
    candidates: Iterable[str],
) -> Optional[str]:
    """Pick the first candidate that is from a different family than the producer.

    Returns ``None`` if no suitable candidate exists. ``"unknown"`` family
    candidates are skipped — they cannot be proven cross-family. The
    ordering of ``candidates`` is preserved so callers can pass a
    preference list (e.g. cheapest-first or fastest-first).

    Caller composes this with ``llm_response_schema.validate_response``:
    the chosen candidate becomes the model used inside the retry callback.
    """
    for candidate in candidates:
        if not same_family(producer_model_id, candidate) and family_of(candidate) != "unknown":
            return candidate
    return None
