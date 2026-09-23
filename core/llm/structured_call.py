"""Shared consumer-side envelope for ``generate_structured`` calls.

Two idioms were re-implemented at every structured-call site:

1. **Unwrap**: ``LLMClient.generate_structured`` returns a
   ``StructuredResponse`` with ``.result`` (and cost/model/usage
   attributes); older code paths and test stubs return a
   ``(dict, raw)`` tuple that can be unpacked as a 2-tuple. Each
   consumer hand-rolled the ``hasattr(response, "result")`` dance and
   the ``getattr(response, "cost", 0.0)`` extraction.

2. **Error classification**: two divergent classifiers existed —
   audit's substring markers (``"blocked by" in msg``) and
   /agentic's word-boundary regexes. The substring version
   false-positived ("thread-safety violation", "line 401, in foo");
   the regex version lacked several of audit's provider phrasings
   ("model refused", ``content_filter``). This module carries ONE
   word-boundary classifier over the UNION vocabulary.

Only the mechanics live here. What a consumer does with a
classification (retry, demote, abort) stays consumer-side.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Error classification (word-boundary — see module docstring).
# ---------------------------------------------------------------------------

# Pre-fix the substring `in lower` checks produced false positives:
#   * `"401"` matched any error string containing the digits "401"
#     anywhere — including stack-trace line numbers (`line 401, in
#     ...`), HTTP status logs from unrelated endpoints, content-
#     length headers, etc.
#   * `"safety"` matched legitimate non-content-filter contexts
#     ("safety check failed in tokenizer", "thread-safety
#     violation", "safe to retry").
#   * `"credit"` matched "credentials", "credit card validation",
#     "discredit". The intent was billing-credit-exhausted but
#     the substring caught everything credit-shaped.
# Word-boundary regex via `\b...\b` keeps the keywords but
# anchors them to token boundaries.
#
# Bare 401/403 only when preceded by a status-context word (HTTP,
# status, code) — "line 401" / "column 401" in a stack trace or JSON
# decode error otherwise false-positives. The context arm accepts an
# optional colon (`\s*:?\s*`): the genuine SDK shape is
# ``Error code: 401 - ...`` and a plain `\s+` never matched it.
_STATUS_40X = r"(?:http|status|code)\s*:?\s*40[13]\b"
# google-genai renders errors as ``"<code> <STATUS>. {...}"`` —
# message-leading status position plus the gRPC SCREAMING_SNAKE
# reason vocabulary ("401 UNAUTHENTICATED", "403 PERMISSION_DENIED").
# Mirrors the sibling anchors that already model this SDK shape:
# RATE_LIMIT_KEYWORDS_RE's ``^\s*429\b`` arm and _HTTP_500_STATUS_RE's
# ``500 INTERNAL`` arm in client.py. Kept OUTSIDE the ``\b(...)\b``
# wrapper below — a leading ``\b`` never matches before ``^``.
_STATUS_40X_LEADING = r"^\s*40[13]\b"
_AUTH_40X_REASONS = (
    r"40[13]\s+(?:unauthorized|forbidden|unauthenticated|"
    r"permission[_ ]denied)"
)

AUTH_KEYWORDS_RE = re.compile(
    r"\b(" + _STATUS_40X + r"|" + _AUTH_40X_REASONS + r"|"
    r"authentication|unauthorized|unauthenticated|invalid api key|"
    r"billing|"
    r"quota|rate limit|insufficient_quota|credits?|"
    r"api[_ ]?key (?:invalid|expired|missing))\b"
    r"|" + _STATUS_40X_LEADING,
    re.IGNORECASE,
)

# STRICT auth-refusal subset: 401/403 status context + credential
# vocabulary ONLY — no billing/quota/rate-limit terms. Consumers that
# treat "auth refused" as terminal (the persistent-401 phase-abort
# tracker) must not trip on a burst of 429s or a billing cap, which
# are transient/budget classes with their own handling.
AUTH_STATUS_RE = re.compile(
    r"\b(" + _STATUS_40X + r"|" + _AUTH_40X_REASONS + r"|"
    r"authentication(?:[_ ]error)?|unauthorized|unauthenticated|"
    r"permission[_ ]denied|access denied|"
    r"invalid (?:api[_ ]?key|x-api-key)|"
    r"api[_ ]?key (?:invalid|expired|missing|not valid)|"
    r"incorrect api key)\b"
    r"|" + _STATUS_40X_LEADING,
    re.IGNORECASE,
)

# Union of the /agentic regex vocabulary and audit's marker list
# (`content_filter`, "model refused", "blocked by" were audit-only).
BLOCKED_KEYWORDS_RE = re.compile(
    r"\b(content filter|content_filter|blocked response|"
    r"content (?:policy|safety) violation|"
    r"refused (?:request|to respond)|response (?:was )?refused|"
    r"model refused|blocked by|"
    r"safety filter|content blocked|moderation block)\b",
    re.IGNORECASE,
)

TIMEOUT_KEYWORDS_RE = re.compile(
    r"\b(timeout|timed out|deadline exceeded|read timed? out)\b",
    re.IGNORECASE,
)

# Rate-limit shapes AUTH_KEYWORDS_RE misses: the underscored/hyphened
# provider error type and inflections (``rate_limit_error``,
# ``rate-limit``, "rate limiting in effect", "exceeded your rate
# limits" — real provider phrasings), and a 429 status. The 429 arm
# is boundary-anchored AND context-anchored (status-context word —
# including the "HTTP error 429" / bare "API Error: 429" phrasings
# wrappers emit — message-leading position, or the canonical reason
# phrases, colon-separated or not) so unrelated numerics like
# stack-trace "line 429, in foo" don't classify as a limit.
RATE_LIMIT_KEYWORDS_RE = re.compile(
    r"rate[_ -]limit(?:_error|ed|ing|s)?\b"
    r"|\b(?:http|status|code|api\s+error)\s*:?\s*429\b"
    r"|\b(?:http|status|code)\s*error\s*:?\s*429\b"
    r"|^\s*429\b"
    r"|\b429\s*:?\s+(?:too many requests|resource_exhausted)\b",
    re.IGNORECASE,
)


def is_auth_error_text(error_str: str) -> bool:
    """True when an error string indicates an auth/billing failure.

    Word-boundary matched (see module-level RE comments) so a
    "line 401, in foo" stack-trace fragment doesn't false-positive.
    For SDK *exception objects*, prefer the type-aware
    ``core.llm.client._is_auth_error``; this is the string-side check.
    """
    return bool(AUTH_KEYWORDS_RE.search(error_str or ""))


def is_auth_status_text(error_str: str) -> bool:
    """True when an error string indicates a STRICT auth refusal
    (401/403 status context or credential vocabulary), excluding the
    billing/quota/rate-limit terms :func:`is_auth_error_text` also
    accepts. The persistent-auth phase-abort path uses this — quota
    bursts must never read as credential death."""
    return bool(AUTH_STATUS_RE.search(error_str or ""))


def is_content_filter_text(error_str: str) -> bool:
    """True when an error string indicates a content-filter block."""
    return bool(BLOCKED_KEYWORDS_RE.search(error_str or ""))


# Refusal-SPECIFIC vocabulary — deliberately narrower than
# BLOCKED_KEYWORDS_RE: providers phrase model refusals with
# "refusal"/"refused request", while transport blocks say
# "blocked"/"denied" — and, critically, socket errors say "connection
# refused": a bare "refus" match classified a transient endpoint
# outage as a model refusal, which is non-retryable and excluded from
# identical-retry re-queues. Phrase-anchored so only model-boundary
# language matches.
REFUSAL_TEXT_RE = re.compile(
    r"\brefusal\b|refused request|model refused|stop_reason[=:]?\s*refusal",
    re.IGNORECASE,
)


def is_content_filter_error(exc: BaseException) -> bool:
    """Chain-walking form of :func:`is_content_filter_text`.

    The client's all-models-failed wrapper re-raises ``from
    last_error``; a wrapper whose own message does not quote its cause
    hides the block from a plain ``str(exc)`` check. Every classifier
    that labels blocked/refused failures must walk the chain — this is
    the one shared implementation (bounded, cycle-safe).
    """
    from core.llm.client import _exception_chain
    return any(is_content_filter_text(str(e)) for e in _exception_chain(exc))


def is_refusal_error(exc: BaseException) -> bool:
    """Chain-walking model-refusal check (see ``REFUSAL_TEXT_RE`` for
    why this is narrower than the content-filter vocabulary)."""
    from core.llm.client import _exception_chain
    return any(
        REFUSAL_TEXT_RE.search(str(e)) for e in _exception_chain(exc)
    )


def classify_error_text(error_str: str) -> str:
    """Classify an error string for structured reporting.

    Returns: ``'blocked'`` (content filter/safety/refusal),
    ``'auth'`` (key/billing/quota), ``'timeout'``, or ``'error'``
    (everything else).
    """
    text = error_str or ""
    if BLOCKED_KEYWORDS_RE.search(text):
        return "blocked"
    if is_auth_error_text(text):
        return "auth"
    # Underscored/status rate-limit shapes join the same class as the
    # spaced "rate limit" AUTH_KEYWORDS_RE already accepts — a limit
    # is never evidence about response shape.
    if RATE_LIMIT_KEYWORDS_RE.search(text):
        return "auth"
    if TIMEOUT_KEYWORDS_RE.search(text):
        return "timeout"
    return "error"


# ---------------------------------------------------------------------------
# Response unwrap.
# ---------------------------------------------------------------------------


@dataclass
class StructuredCallResult:
    """Uniform view over a ``generate_structured`` return value."""

    result: Any = None
    cost: float = 0.0
    model: str = ""
    usage: dict[str, int] = field(default_factory=dict)


def unwrap_structured_response(
    response: Any, *, empty_result: Any = None,
) -> StructuredCallResult:
    """Unwrap a ``generate_structured`` return value.

    Handles both shapes: a ``StructuredResponse`` (``.result`` plus
    cost/model/usage attributes) and the legacy ``(result, raw)``
    tuple. ``empty_result`` is what ``result`` becomes when the
    response is falsy or unsubscriptable (callers pick their own
    sentinel: an error dict, ``None``, ...).

    Result extraction DELEGATES to
    :func:`core.llm.coerce.structured_result` — the one spelling of
    the ``.result``-or-``(result, raw)`` tolerance — so the two
    helpers cannot drift on shape semantics (pre-unification a bare
    dict unwrapped fine through one and became ``empty_result``
    through the other). This wrapper adds only the cost/model/usage
    view; callers that need the result alone should use
    ``structured_result`` directly.
    """
    from core.llm.coerce import structured_result

    result = structured_result(response, default=empty_result)
    try:
        cost = float(getattr(response, "cost", 0.0) or 0.0)
    except (TypeError, ValueError):
        cost = 0.0
    return StructuredCallResult(
        result=result,
        cost=cost,
        model=getattr(response, "model", "") or "",
        usage={
            "tokens_in": getattr(response, "input_tokens", 0) or 0,
            "tokens_out": getattr(response, "output_tokens", 0) or 0,
            "cache_read_tokens": getattr(
                response, "cache_read_tokens", 0) or 0,
            "cache_write_tokens": getattr(
                response, "cache_write_tokens", 0) or 0,
        },
    )


__all__ = [
    "AUTH_KEYWORDS_RE",
    "AUTH_STATUS_RE",
    "BLOCKED_KEYWORDS_RE",
    "RATE_LIMIT_KEYWORDS_RE",
    "REFUSAL_TEXT_RE",
    "TIMEOUT_KEYWORDS_RE",
    "StructuredCallResult",
    "classify_error_text",
    "is_auth_error_text",
    "is_auth_status_text",
    "is_content_filter_error",
    "is_content_filter_text",
    "is_refusal_error",
    "unwrap_structured_response",
]
