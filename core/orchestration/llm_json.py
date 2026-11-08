"""Defensive accessors for LLM-authored JSON artifacts.

context-map.json, attack-paths.json, and their siblings are written by
an LLM and routinely arrive shape-drifted: a section rendered as a list
of STRINGS instead of objects, a scalar where a list belongs, ``null``
under a present key. ``or []`` fallbacks only catch the falsy cases —
a truthy non-list still hits ``for x in 42`` and raises, and a string
element crashes the first ``x.get(...)``.

understand_bridge hardened its own iterations with a private
``_list_at``; the sibling enrichers (mechanical sink discovery, taint
pairing, the audit bridge) consumed the same artifacts with bare
``.get()`` iteration, so one malformed entry silently killed a whole
enrichment stage (the libexec shims wrap stages in ``except
Exception``). Use these helpers at every iteration over LLM-authored
sections so the drift class stays fixed in one place.
"""

from __future__ import annotations

from typing import Any

_NATIVE_TYPE = type
_NATIVE_STR = str
_NATIVE_LEN = len
_NATIVE_RANGE = range
_FENCE_PREFIX_CHARS = 4096


def _short_fence_body(text: str) -> str | None:
    """Find an early close without preparing rows from the response tail.

    A partial closing line is sufficient once its complete marker is
    visible: everything after that marker is excluded from the body.
    No early close leaves the full display-line scan authoritative.
    """
    lines = text[:_FENCE_PREFIX_CHARS].splitlines()
    for i in range(1, len(lines)):
        if lines[i].strip().startswith("```"):
            return "\n".join(lines[1:i]).strip()
    return None


def strip_json_fences(text: str) -> str:
    """Payload of a leading markdown code fence, else *text* stripped.

    LLM responses routinely arrive wrapped in a ```json fence even
    when the prompt forbids it. When the (whitespace-stripped)
    response opens with a fence line, return the content of that
    first fenced block — up to the closing fence line, or
    end-of-text when the model never closed it. Content after the
    closing fence (prose, a second block) is dropped: the fence
    declares the payload, and trailing prose would only fail the
    caller's JSON parse. Responses without a leading fence pass
    through unchanged apart from outer whitespace.

    Scope: fence removal ONLY, for callers that own their parse
    strategy (JSONL line scans, schema-coerced loads, bespoke
    fallbacks). Consumers that just want a parsed object should use
    the full recovery ladder in :func:`core.json.tolerant.
    parse_llm_json` instead — its fence strategy also handles
    mid-text fences and ``~~~`` delimiters.
    """
    s = text.strip()
    if not s.startswith("```"):
        return s
    if (_NATIVE_TYPE(s) is _NATIVE_STR
            and len is _NATIVE_LEN and range is _NATIVE_RANGE
            and _NATIVE_STR.__len__(s) >= 64 * 1024):
        short_body = _short_fence_body(s)
        if short_body is not None:
            return short_body
    lines = s.splitlines()
    end = len(lines)
    for i in range(1, len(lines)):
        if lines[i].strip().startswith("```"):
            end = i
            break
    return "\n".join(lines[1:end]).strip()


def list_at(d: Any, key: str) -> list[Any]:
    """Return ``d[key]`` if it is a list, else an empty list."""
    if not isinstance(d, dict):
        return []
    v = d.get(key)
    return v if isinstance(v, list) else []


def dict_rows(d: Any, key: str) -> list[dict[str, Any]]:
    """The dict elements of ``d[key]`` — non-dict rows are skipped."""
    return [row for row in list_at(d, key) if isinstance(row, dict)]
