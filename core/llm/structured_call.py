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

AUTH_KEYWORDS_RE = re.compile(
    r"\b(" + _STATUS_40X + r"|"
    r"40[13]\s+(?:unauthorized|forbidden)|"
    r"authentication|unauthorized|invalid api key|billing|"
    r"quota|rate limit|insufficient_quota|credits?|"
    r"api[_ ]?key (?:invalid|expired|missing))\b",
    re.IGNORECASE,
)

# STRICT auth-refusal subset: 401/403 status context + credential
# vocabulary ONLY — no billing/quota/rate-limit terms. Consumers that
# treat "auth refused" as terminal (the persistent-401 phase-abort
# tracker) must not trip on a burst of 429s or a billing cap, which
# are transient/budget classes with their own handling.
AUTH_STATUS_RE = re.compile(
    r"\b(" + _STATUS_40X + r"|"
    r"40[13]\s+(?:unauthorized|forbidden)|"
    r"authentication(?:[_ ]error)?|unauthorized|"
    r"permission denied|access denied|"
    r"invalid (?:api[_ ]?key|x-api-key)|"
    r"api[_ ]?key (?:invalid|expired|missing|not valid)|"
    r"incorrect api key)\b",
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
    """
    result = empty_result
    if hasattr(response, "result"):
        result = response.result
    elif response:
        try:
            result = response[0]
        except (TypeError, KeyError, IndexError):
            result = empty_result
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
    "BLOCKED_KEYWORDS_RE",
    "TIMEOUT_KEYWORDS_RE",
    "StructuredCallResult",
    "classify_error_text",
    "is_auth_error_text",
    "is_content_filter_text",
    "unwrap_structured_response",
]
