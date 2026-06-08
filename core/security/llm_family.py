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


Family = Literal[
    "anthropic", "openai", "google", "meta", "mistral",
    "ollama", "cohere", "unknown",
]


_PROVIDER_STEMS: tuple[tuple[str, Family], ...] = (
    ("anthropic", "anthropic"),
    ("openai", "openai"),
    ("gemini", "google"),
    ("google", "google"),
    ("meta-llama", "meta"),
    ("mistral", "mistral"),
    ("mistralai", "mistral"),
    ("ollama", "ollama"),
    ("cohere", "cohere"),
    # Aggregator hosts (Together, Groq, OpenRouter, Fireworks) re-host
    # models from underlying families. The provider stem alone doesn't
    # tell us the family — `together/meta-llama/Llama-3-8B` is meta,
    # `together/anthropic/claude-haiku-4-5` is anthropic. Strip the
    # aggregator prefix and recurse on the remainder. Without this,
    # cross-family validation against an aggregator-hosted model
    # produced "unknown" and the safety check silently no-op'd.
    # Handled below in family_of() rather than as a stem here.
)

_MODEL_STEMS: tuple[tuple[str, Family], ...] = (
    ("claude", "anthropic"),
    ("gpt", "openai"),
    ("o1", "openai"),
    ("o3", "openai"),
    ("o4", "openai"),
    ("gemini", "google"),
    ("llama", "meta"),
    ("mistral", "mistral"),
    ("mixtral", "mistral"),
    ("command", "cohere"),  # cohere's `command-r-plus`, `command-light`
)


_AGGREGATOR_PREFIXES: tuple[str, ...] = (
    "together/",
    "groq/",
    "openrouter/",
    "fireworks/",
    "deepinfra/",
    "perplexity/",
    "replicate/",
)


# AWS Bedrock model identifiers use a different shape from the
# `provider/model` form: a regional inference-profile prefix
# (`us.` / `eu.` / `au.` / `apac.` / `global.`) followed by a
# `<provider>.` segment then the model id, all dot-separated.
# Family detection must strip the regional prefix and then map
# the provider segment, otherwise `us.anthropic.claude-opus-4-7`
# resolves to "unknown" and the cross-family checker (Attacker
# Moves Second, arXiv 2510.09023) silently treats a Bedrock-Claude
# producer and a direct-API-Claude checker as "different families"
# — the exact failure mode the validator exists to prevent.
#
# Constants are imported from the single-source-of-truth module so
# adding a new region or provider segment updates one place.
from core.llm.bedrock_prefixes import (  # noqa: E402
    BEDROCK_PROVIDER_SEGMENTS as _BEDROCK_PROVIDER_SEGMENTS,
    BEDROCK_REGIONAL_PREFIXES as _BEDROCK_REGIONAL_PREFIXES,
)

# Local mapping segment → Family (Family is a Literal local to this
# module, can't live in the shared constants module without a
# circular import).
_BEDROCK_PROVIDER_PREFIXES: tuple[tuple[str, Family], ...] = (
    ("anthropic.", "anthropic"),
    ("meta.",      "meta"),
    ("mistral.",   "mistral"),
    ("cohere.",    "cohere"),
)
# Sanity: every segment listed in the shared module must have a
# Family mapping here (or be intentionally Family-less, in which
# case it's not in BEDROCK_PROVIDER_SEGMENTS).
assert {p for p, _ in _BEDROCK_PROVIDER_PREFIXES} == set(
    _BEDROCK_PROVIDER_SEGMENTS,
), "Bedrock provider segments out of sync with Family mapping"


def _strip_bedrock_regional_prefix(needle: str) -> str:
    """Strip a single Bedrock regional prefix when present.
    Operates on the LOWERED identifier; caller is responsible for
    re-applying to the original-case string if needed."""
    for prefix in _BEDROCK_REGIONAL_PREFIXES:
        if needle.startswith(prefix):
            return needle[len(prefix):]
    return needle


_FAMILY_TO_PROVIDER: dict[Family, str] = {
    "anthropic": "anthropic",
    "openai": "openai",
    "google": "gemini",
    "meta": "ollama",
    "mistral": "mistral",
    "ollama": "ollama",
    "cohere": "cohere",
}


def provider_for_family(family: Family) -> str:
    """Map a model family to its provider string (for ModelConfig)."""
    return _FAMILY_TO_PROVIDER.get(family, "")


def provider_of(model_id: str) -> str:
    """Model identifier → ROUTING provider string.

    Distinct from :func:`family_of`: family is the model's training
    lineage (what's the cross-family checker invariant), provider is
    the routing target (which SDK/endpoint/dispatcher rule handles
    this request).  The two diverge for Bedrock-routed Claude: family
    is ``anthropic`` (so cross-family validation correctly refuses to
    pair a Bedrock-Claude producer with a direct-API-Claude checker),
    but the ROUTING provider is ``bedrock`` (so config-file lookups,
    auth selection, and dispatcher routing pick the Bedrock path).

    Order:
      1. Bedrock-shaped IDs (``<region>.<provider>.<model>``) →
         ``"bedrock"`` — every Bedrock prefix combination resolves
         the same way regardless of underlying model family.
      2. Otherwise fall back to :func:`family_of` → provider mapping,
         preserving the existing direct-API behaviour.
    """
    needle = model_id.lower()
    # Same iterated peel as family_of so chained shapes like
    # ``together/us.anthropic.claude-opus-4-7`` resolve to
    # ``"bedrock"`` routing (the model is Bedrock-routed even when
    # nominally aggregator-prefixed; the aggregator can't host a
    # Bedrock-shaped id meaningfully).
    for _ in range(5):
        peeled = False
        before_bedrock = needle
        needle = _strip_bedrock_regional_prefix(needle)
        if needle != before_bedrock:
            peeled = True
        for prefix, _family in _BEDROCK_PROVIDER_PREFIXES:
            if needle.startswith(prefix):
                return "bedrock"
        for prefix in _AGGREGATOR_PREFIXES:
            if needle.startswith(prefix):
                needle = needle[len(prefix):]
                peeled = True
                break
        if not peeled:
            break
    return provider_for_family(family_of(model_id))


def unknown_model_message(model_id: str) -> str:
    """Operator-facing hint for a model id whose provider can't be resolved.

    Used to fail loudly (instead of silently producing a keyless / provider-
    less config) when an operator passes a prefix-less nickname like
    ``opus-4-8`` rather than a recognizable id."""
    return (
        f"unrecognized model {model_id!r}: cannot determine its provider. "
        f"Use a recognizable id (e.g. 'claude-opus-4-8', 'gpt-5', "
        f"'gemini-2.5-pro') or an explicit 'provider/model' form "
        f"(e.g. 'anthropic/claude-opus-4-8')."
    )


def bare_model_id(model_id: str) -> str:
    """Return the model identifier with any aggregator + provider
    prefix peeled off.

    Mirrors :func:`family_of`'s aggregator-peel loop and then strips a
    single ``<provider>/`` prefix when the head matches one of the
    known provider strings. Examples::

        bare_model_id("anthropic/claude-haiku-4-5")
            -> "claude-haiku-4-5"
        bare_model_id("together/anthropic/claude-haiku-4-5")
            -> "claude-haiku-4-5"
        bare_model_id("claude-haiku-4-5")
            -> "claude-haiku-4-5"

    Used by call-sites that need to match user-supplied ``--model``
    arguments against ``models.json`` entries (which store the bare
    model under a separate ``provider`` key).
    """
    needle = model_id
    # Bedrock regional prefix (``us.``/``eu.``/...) peel first, then
    # the dot-separated Bedrock provider segment.  Mirrors
    # :func:`family_of`'s peel order so the two helpers stay
    # consistent on Bedrock identifiers.
    lowered = needle.lower()
    for prefix in _BEDROCK_REGIONAL_PREFIXES:
        if lowered.startswith(prefix):
            needle = needle[len(prefix):]
            lowered = lowered[len(prefix):]
            break
    for prefix, _family in _BEDROCK_PROVIDER_PREFIXES:
        if lowered.startswith(prefix):
            needle = needle[len(prefix):]
            lowered = lowered[len(prefix):]
            break
    for _ in range(4):
        peeled = False
        for prefix in _AGGREGATOR_PREFIXES:
            if needle.lower().startswith(prefix):
                needle = needle[len(prefix):]
                peeled = True
                break
        if not peeled:
            break
    if "/" in needle:
        head, rest = needle.split("/", 1)
        if head.lower() in {v for v in _FAMILY_TO_PROVIDER.values()}:
            needle = rest
    return needle


def family_of(model_id: str) -> Family:
    """Return the model family for a model identifier.

    Matching is by prefix on the lowered identifier (so ``claude-opus-4-7``
    and ``anthropic/claude-haiku-4-5`` both resolve to ``"anthropic"``).
    Provider routing prefixes (``provider/model``) are checked first so
    that e.g. ``ollama/llama-3`` resolves to ``ollama`` not ``meta``.

    Aggregator-host prefixes (``together/``, ``groq/``, ``openrouter/``,
    etc.) are STRIPPED first before family resolution — they re-host
    models from underlying families and must not be mistaken for a
    family of their own. Without this peel,
    `together/anthropic/claude-haiku-4-5` resolved to "unknown" and
    the cross-family safety check silently no-op'd.

    Unknown identifiers return ``"unknown"``.
    """
    needle = model_id.lower()
    # Iterate both peels (Bedrock regional + aggregator) so chained
    # shapes like ``together/us.anthropic.claude-opus-4-7`` resolve
    # correctly.  Bedrock and aggregator prefixes use different
    # separators (``.`` vs ``/``) and don't overlap in vocabulary,
    # so a fixed-bound iteration converges in at most a handful of
    # passes.  Bound at 5 to defend against pathological inputs.
    for _ in range(5):
        peeled = False
        before_bedrock = needle
        needle = _strip_bedrock_regional_prefix(needle)
        if needle != before_bedrock:
            peeled = True
        for prefix, family in _BEDROCK_PROVIDER_PREFIXES:
            if needle.startswith(prefix):
                return family
        for prefix in _AGGREGATOR_PREFIXES:
            if needle.startswith(prefix):
                needle = needle[len(prefix):]
                peeled = True
                break
        if not peeled:
            break
    for stem, family in _PROVIDER_STEMS:
        if needle.startswith(stem + "/"):
            return family
    for stem, family in _MODEL_STEMS:
        if needle.startswith(stem + "-"):
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
