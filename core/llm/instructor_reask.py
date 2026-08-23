"""Tool-use / tool-result pairing repair for instructor reask retries.

Instructor's Anthropic tools-mode reask handler rebuilds the retry
conversation after a schema-validation failure: it appends the failed
assistant completion (including its ``tool_use`` blocks) plus one user
message carrying the validation error as a ``tool_result``.  The
handler tracks a SINGLE ``tool_use_id`` while walking the completion's
content, so when the model emitted parallel tool calls — several
``tool_use`` blocks in one completion — only the LAST block gets a
``tool_result`` and every other id is left unpaired.  Anthropic
rejects the retry request outright::

    400 invalid_request_error: messages.N: `tool_use` ids were found
    without `tool_result` blocks immediately after: toolu_..., ...
    Each `tool_use` block must have a corresponding `tool_result`
    block in the next message.

The retry that was supposed to rescue a malformed structured response
instead burns an attempt on a guaranteed protocol error (observed
live: a review call whose completion carried four parallel tool_use
blocks died on attempt 2 with three unmatched ids).

:func:`repair_tool_result_pairing` walks an Anthropic-shape message
list and inserts an ``is_error`` ``tool_result`` for every unpaired
``tool_use`` id — in the immediately-following user message when one
exists, in a fresh user message otherwise (covering a trailing
assistant tool_use message too).  :func:`ensure_anthropic_reask_pairing`
wraps instructor's registered reask handler so the repair runs on
every reask-assembled conversation.  Both are defensive: any failure
degrades to the unrepaired input rather than raising, and the wrap is
a no-op when instructor (or its v2 registry layout) is absent.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Marker attribute stamped on the wrapper so repeat calls (one per
# provider construction) never double-wrap the registered handler.
_WRAP_MARKER = "_raptor_tool_result_pairing"

# Body for the tool_results this module has to invent. Mirrors the
# reask handler's own error text closely enough that the model treats
# the synthetic block the same way as instructor's genuine one.
_SYNTHETIC_RESULT = (
    "Validation Error found for a parallel tool call — recall the "
    "function correctly, fix the errors, and reply with a single "
    "tool call."
)


def _block_field(block: Any, key: str) -> Any:
    """Read ``key`` from a content block that may be a dict (reask-
    appended) or an SDK object (provider-returned)."""
    if isinstance(block, dict):
        return block.get(key)
    return getattr(block, key, None)


def _tool_use_ids(message: Any) -> list[str]:
    """The ``tool_use`` block ids of one message (empty for non-list
    content, e.g. plain-string user messages)."""
    content = _block_field(message, "content")
    if not isinstance(content, list):
        return []
    return [
        _block_field(b, "id")
        for b in content
        if _block_field(b, "type") == "tool_use" and _block_field(b, "id")
    ]


def _tool_result_ids(message: Any) -> set[str]:
    r"""The ``tool_use_id``\ s answered by one message's tool_results."""
    content = _block_field(message, "content")
    if not isinstance(content, list):
        return set()
    return {
        _block_field(b, "tool_use_id")
        for b in content
        if _block_field(b, "type") == "tool_result"
        and _block_field(b, "tool_use_id")
    }


def _result_block(tool_use_id: str) -> dict[str, Any]:
    return {
        "type": "tool_result",
        "tool_use_id": tool_use_id,
        "content": _SYNTHETIC_RESULT,
        "is_error": True,
    }


def repair_tool_result_pairing(messages: list[Any]) -> int:
    """Pair every assistant ``tool_use`` block with a ``tool_result``.

    Mutates *messages* in place; returns the number of synthetic
    ``tool_result`` blocks inserted (0 = conversation already valid).

    For each assistant message carrying ``tool_use`` blocks:

    * the immediately-following user message gains ``tool_result``
      blocks for any unanswered ids, PREPENDED so results sit before
      the reask prose (string content is converted to a text block);
    * a trailing assistant tool_use message (or one followed by
      another assistant message) gains a fresh user message carrying
      the missing results.

    Only dict-shaped messages are mutated — provider-object messages
    never come through the reask path this repairs.
    """
    inserted = 0
    i = 0
    while i < len(messages):
        msg = messages[i]
        ids = (
            _tool_use_ids(msg)
            if _block_field(msg, "role") == "assistant"
            else []
        )
        if not ids:
            i += 1
            continue

        nxt = messages[i + 1] if i + 1 < len(messages) else None
        if nxt is not None and _block_field(nxt, "role") == "user":
            missing = [t for t in ids if t not in _tool_result_ids(nxt)]
            if missing and isinstance(nxt, dict):
                content = nxt.get("content")
                if isinstance(content, str):
                    content = [{"type": "text", "text": content}]
                elif not isinstance(content, list):
                    content = []
                nxt["content"] = [
                    _result_block(t) for t in missing
                ] + content
                inserted += len(missing)
        else:
            # Trailing assistant tool_use (or assistant follows
            # assistant): the API rejects both — give the ids their
            # own tool_result user message.
            messages.insert(
                i + 1,
                {
                    "role": "user",
                    "content": [_result_block(t) for t in ids],
                },
            )
            inserted += len(ids)
        i += 1
    return inserted


def _wrap_reask(original):
    """Wrap one registered reask handler with the pairing repair."""

    def paired_reask(
        kwargs: dict[str, Any],
        response: Any,
        exception: Exception,
    ) -> dict[str, Any]:
        new_kwargs = original(
            kwargs=kwargs, response=response, exception=exception,
        )
        try:
            inserted = repair_tool_result_pairing(
                new_kwargs.get("messages") or [],
            )
            if inserted:
                logger.debug(
                    "instructor reask: paired %d orphaned tool_use "
                    "block(s) with synthetic tool_results",
                    inserted,
                )
        except Exception:  # repair must never break the retry itself
            logger.debug(
                "instructor reask pairing repair failed", exc_info=True,
            )
        return new_kwargs

    setattr(paired_reask, _WRAP_MARKER, True)
    # functools.wraps-style backlink so diagnostics (and tests) can
    # reach the stock handler under the wrap.
    paired_reask.__wrapped__ = original
    return paired_reask


def ensure_anthropic_reask_pairing() -> bool:
    """Wrap instructor's Anthropic tools-mode reask handler (idempotent).

    Returns True when the pairing wrap is in place (freshly installed
    or already present).  False — with a DEBUG log — when instructor
    is missing or its registry layout changed; callers proceed
    unwrapped (the pre-fix behaviour, not an error).
    """
    try:
        from instructor.mode import Mode
        from instructor.v2.core.registry import Provider, mode_registry

        handlers = mode_registry.get_handlers(Provider.ANTHROPIC, Mode.TOOLS)
    except Exception:
        logger.debug(
            "instructor reask pairing unavailable "
            "(instructor missing or registry layout changed)",
            exc_info=True,
        )
        return False
    try:
        if getattr(handlers.reask_handler, _WRAP_MARKER, False):
            return True
        handlers.reask_handler = _wrap_reask(handlers.reask_handler)
        return True
    except Exception:
        logger.debug(
            "instructor reask pairing install failed", exc_info=True,
        )
        return False
