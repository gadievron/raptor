"""Tolerant JSON parser for LLM-generated structured output.

Models frequently deviate from strict JSON: markdown-fenced code blocks,
prose padding, trailing commas, single-quoted strings, Python-style
``None`` / ``True`` / ``False``, or unclosed braces from mid-output
truncation. Every consumer that hand-rolls a ``_parse_json`` at each
call site handles a subset — the shared pattern is 30 LOC of split /
strip / retry that works for some models and silently drops good output
from others. When a valid-content-wrong-shape response is dropped, the
model's insight is lost and downstream self-improvement machinery
regresses.

This module is the ONE canonical recovery ladder for consumers that
receive JSON structured output from an LLM. Sibling to
:mod:`core.json.jsonc` (JSONC dialect for third-party config files)
and the ``//`` + ``#`` dialect used by RAPTOR's own model / tuning
configs. Same pattern: name the dialect, own the tolerance policy in
one place.

Strategy ladder:

1. **Strict** — ``json.loads`` on the raw text.
2. **Fence** — locate the first markdown code fence (```````
   or ``~~~``, optionally with a language marker), extract the payload,
   parse.
3. **Brace-span** — regex-locate the largest balanced-brace ``{...}``
   span anywhere in the text. Handles prose-before, prose-after, and
   the "model wrote a paragraph before the JSON" shape.
4. **Quasi-JSON fixup** — after brace-span extraction, apply common
   post-hoc fixups: strip trailing commas, single-quote → double-quote,
   Python literals (``None`` / ``True`` / ``False``) → JSON. Each fixup
   is retried in isolation so a broken combination doesn't wedge the
   parser.

Returns ``(parsed_or_None, ExtractionDiagnostic)`` so callers get:

- ``parsed`` — the parsed dict, or ``None`` when the whole ladder failed.
- ``diagnostic`` — a structured record of which strategy succeeded (or
  which one failed with what error). Feed this into your observability
  layer to catch rising-non-strict rates before they silently degrade
  a downstream loop.

Explicit non-goals:

* **Not** a YAML / TOML / JSON5 parser. The wire is JSON; recovery is
  for common LLM drift, not alternate serialization formats. Consumers
  that need alternate formats should reject the response and ask again.
* **Not** a retry-with-error-feedback loop. Callers that want to
  re-prompt the model on parse failure compose that themselves — no
  hidden budget consumption.
* **Not** a persistence layer. Callers own the "where to save the raw
  response on failure" decision, because the right location depends
  on the caller's project directory / run identity / observability
  policy.

Design contract for reviewers:

* The parser MUST NOT mutate the input text before running strict
  parsing. Any transformation that touches raw bytes is only applied
  inside the recovery-ladder branches, so a valid JSON input always
  round-trips through strategy 1.
* The parser MUST record which strategy succeeded, even on success,
  so operators can detect model-behaviour drift (e.g. "haiku on Fri
  started fence-wrapping — was 100% strict on Thu").
* The parser MUST NOT raise on malformed input. Every failure returns
  ``(None, ExtractionDiagnostic(strategy='failed', ...))``.
* The parser MUST fail closed on quasi-JSON fixups that could execute
  code (e.g. no ``eval`` fallback, no PyYAML fallback).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Optional, Tuple


#: Hard cap on input size. LLM structured-output responses are typically
#: <100 KB; this cap protects against a hostile model / prompt-injection
#: response that ships megabytes of nested braces to DoS the parser's
#: brace walker. Inputs above the cap fail closed with a diagnostic.
_MAX_INPUT_LEN = 1_048_576

#: Sentinel distinguishing "no parse attempt succeeded" from "parse
#: succeeded but the result is JSON ``null``". Callers that pass
#: ``require_object=False`` want ``null`` to round-trip; the module
#: MUST NOT collapse the two cases.
_MISSING: Any = object()


# Fence patterns tried in order. Anchored to line starts (``^``) with
# ``re.MULTILINE`` so a triple-backtick inside a string field (e.g. a
# code-snippet-in-a-reason) doesn't accidentally win. LLM outputs almost
# always put the fence at the start of a line.
#
# The close fence marker MUST match the open (``\`\`\``` opens, ``\`\`\``` closes;
# ``~~~`` opens, ``~~~`` closes) via named-group backreference — an
# earlier permissive pattern accepted mixed open/close pairs, which is
# never emitted by real models and only served to widen the attack
# surface for adversarial prompt-injection payloads.
#
# The close fence line accepts trailing non-newline garbage (``.*$``
# rather than ``\s*$``). Some model outputs put a stray char after the
# closing fence (a stray period, an unclosed reasoning bracket). The
# strict ``\s*$`` variant fell through to ``_FENCE_OPEN_RE`` which
# swallowed the close fence into the body, breaking strict parse.
_FENCE_RE = re.compile(
    r"^\s*(?P<delim>```|~~~)\s*(?P<lang>[a-zA-Z0-9_+-]*)\s*\n"
    r"(?P<body>[\s\S]*?)"
    r"\n\s*(?P=delim)[^\n]*$",
    re.MULTILINE,
)

# For the "no closing fence" case (model truncated), match the opening
# fence and take everything after it. Fallback within strategy 2.
_FENCE_OPEN_RE = re.compile(
    r"^\s*(?:```|~~~)\s*(?P<lang>[a-zA-Z0-9_+-]*)\s*\n(?P<body>[\s\S]*)$",
    re.MULTILINE,
)


@dataclass(frozen=True)
class ExtractionDiagnostic:
    """Which strategy succeeded (or failed) and why.

    A caller building a per-run observability wire counts non-``strict``
    outcomes to detect rising model drift. A caller doing RCA looks at
    ``final_error`` when ``strategy == 'failed'`` to see what the
    ultimate parse attempt raised.

    Fields not applicable to the winning strategy are left at their
    defaults so consumers can filter without special-casing.
    """

    #: One of ``strict``, ``fence``, ``brace_span``, ``quasi_json_fixup``,
    #: ``failed``. Names the winning branch — or ``failed`` when the
    #: whole ladder came up empty.
    strategy: str

    #: Populated when ``strategy == 'fence'``. Empty string when the
    #: fence carried no language marker, ``"json"`` / ``"json5"`` /
    #: whatever the model wrote otherwise.
    fence_language: str = ""

    #: Populated when ``strategy == 'brace_span'``. Byte length of the
    #: prose before / after the JSON payload — useful for observability
    #: (a rising trend suggests prompt drift).
    prose_before_bytes: int = 0
    prose_after_bytes: int = 0

    #: Populated when ``strategy == 'quasi_json_fixup'``. Tuple of the
    #: fixup names that were applied, in order. Empty tuple when the
    #: strategy succeeded without any fixup (i.e. brace-span extraction
    #: yielded strict JSON).
    quasi_fixups_applied: Tuple[str, ...] = ()

    #: Populated when ``strategy == 'failed'``. Stringified exception
    #: from the last recovery attempt. ``None`` on success.
    final_error: Optional[str] = None

    #: Populated when ``strategy == 'failed'`` and the ladder saw at
    #: least some structured content before giving up (e.g. the fence
    #: matched and we can see ``"action"`` and ``"reason"`` as keys
    #: before an unclosed brace broke the parse). Best-effort — reflects
    #: what the recovery layer inspected, not a formal partial parse.
    #: Callers doing observability can log this to see "we saw an
    #: action key but the payload broke elsewhere" without needing
    #: their own regex over the raw text. Fail-closed policy still
    #: applies: this field never appears with a successful parse and
    #: callers MUST NOT act on partial data based on this signal
    #: alone. The whole PAYLOAD is either parsed (success strategies)
    #: or dropped (failed).
    partial_keys_seen: Tuple[str, ...] = ()


def parse_llm_json(
    text: str,
    *,
    require_object: bool = True,
) -> Tuple[Optional[dict], ExtractionDiagnostic]:
    """Parse ``text`` as JSON, tolerating common LLM output shapes.

    :param text: The raw model output.
    :param require_object: When ``True`` (default) the returned value
        must be a JSON object (dict). A JSON array / string / number
        at top level is treated as parse failure — most LLM structured-
        output contracts want an object. Set ``False`` if the caller
        genuinely accepts non-object top-level values.

    Returns ``(parsed, diagnostic)``. On success ``parsed`` is the
    dict (or top-level value when ``require_object=False``); on
    failure ``parsed`` is ``None`` and ``diagnostic.strategy ==
    "failed"``.

    Does not raise. Every input — including ``None``, empty string,
    or ``b"binary"`` — is handled by returning a failure diagnostic.
    """
    if not isinstance(text, str) or not text.strip():
        return None, ExtractionDiagnostic(
            strategy="failed",
            final_error="empty or non-string input",
        )
    if len(text) > _MAX_INPUT_LEN:
        return None, ExtractionDiagnostic(
            strategy="failed",
            final_error=(
                f"input length {len(text)} exceeds {_MAX_INPUT_LEN}-byte cap"
            ),
        )

    def _accept(parsed: Any) -> bool:
        """The result gate applied at every strategy exit."""
        if parsed is _MISSING:
            return False
        if require_object and not isinstance(parsed, dict):
            return False
        return True

    # Strategy 1 — strict.
    parsed, strict_err = _try_strict(text)
    if _accept(parsed):
        return parsed, ExtractionDiagnostic(strategy="strict")

    # Strategy 2 — fence.
    fence_lang, fence_body = _extract_fence(text)
    if fence_body is not None:
        parsed, _ = _try_strict(fence_body)
        if _accept(parsed):
            return parsed, ExtractionDiagnostic(
                strategy="fence",
                fence_language=fence_lang or "",
            )

    # Strategy 3 — balanced-brace span extraction.
    span_body, before, after = _extract_brace_span(text)
    if span_body is not None:
        parsed, _ = _try_strict(span_body)
        if _accept(parsed):
            return parsed, ExtractionDiagnostic(
                strategy="brace_span",
                prose_before_bytes=before,
                prose_after_bytes=after,
            )

        # Strategy 4 — quasi-JSON fixup applied to the extracted span.
        # Only run after brace-span produced a plausible payload so we
        # don't try fixups on obviously-broken input.
        parsed, fixups = _try_quasi_json_fixups(span_body)
        if _accept(parsed):
            return parsed, ExtractionDiagnostic(
                strategy="quasi_json_fixup",
                prose_before_bytes=before,
                prose_after_bytes=after,
                quasi_fixups_applied=fixups,
            )

    # Ladder exhausted. Report the strict-parse error captured on
    # strategy 1 (recovery strategies each swallowed their own errors
    # as they attempted transformations, so strict is the cleanest
    # signal for RCA). Also best-effort surface any object-key names
    # the recovery layer saw, so observability catches "we saw an
    # ``action`` key but the payload broke" without the caller needing
    # its own regex over the raw text.
    err = strict_err or "no valid JSON found in text"
    partial = _extract_partial_keys(fence_body if fence_body is not None else span_body if span_body is not None else text)
    return None, ExtractionDiagnostic(
        strategy="failed",
        final_error=err,
        partial_keys_seen=partial,
    )


def _try_strict(text: str) -> Tuple[Any, Optional[str]]:
    """Attempt strict ``json.loads``.

    Returns ``(parsed, err)`` where:

    * On success: ``parsed`` is the parsed value (which may be JSON
      ``null``, i.e. Python ``None``) and ``err`` is ``None``.
    * On failure: ``parsed`` is the module-level ``_MISSING`` sentinel
      and ``err`` is the stringified exception.

    Callers MUST NOT compare ``parsed`` to ``None`` for a success
    check — use ``parsed is not _MISSING`` instead. This distinction
    matters when ``require_object=False`` and the model legitimately
    emitted ``null``. The paired ``err`` lets the top-level ladder
    surface the underlying parse error in the failure diagnostic
    without a second ``json.loads`` pass.
    """
    try:
        return json.loads(text.strip()), None
    except (json.JSONDecodeError, ValueError) as e:
        return _MISSING, str(e)


def _extract_fence(text: str) -> Tuple[Optional[str], Optional[str]]:
    """Look for a markdown code fence; return ``(language, body)`` or ``(None, None)``.

    Prefers matched open+close fences with matching delimiters. Falls
    back to open-only (truncated output) if no close fence exists.
    When multiple fences are present, picks the first one — LLM
    structured output usually wraps its whole response in one block.
    """
    m = _FENCE_RE.search(text)
    if m is not None:
        return m.group("lang"), m.group("body")

    # Truncated output — take everything after the opening fence.
    m = _FENCE_OPEN_RE.search(text)
    if m is not None:
        return m.group("lang"), m.group("body")

    return None, None


def _extract_brace_span(text: str) -> Tuple[Optional[str], int, int]:
    """Find the LAST top-level balanced-brace ``{...}`` span in ``text``.

    Returns ``(span, prose_before_bytes, prose_after_bytes)``. Span is
    ``None`` when no balanced ``{...}`` is present. Single linear pass
    over ``text`` — O(n) — tracking depth and JSON string literals so
    a ``}`` inside a string field never fools the walker.

    Prefers the LAST balanced span when a model emits multiple
    candidate objects. Consider the "retry-and-restate" LLM shape:

    .. code-block:: text

        {"action": "test", "reason": "short"}
        Actually, correction: {"action": "propose", ...detail...}

    An earlier implementation preferred "largest" — that was safe only
    by luck (the corrected object happened to be longer). Preferring
    "last" matches the LLM convention that a self-correction is
    emitted last, and matches how a caller reading a transcript would
    interpret the final answer. Test coverage in ``TestBraceSpan`` /
    ``TestAdversarial`` locks the invariant.
    """
    n = len(text)
    depth = 0
    in_string = False
    escape = False
    span_start = -1

    last_start = -1
    last_end = -1

    for i in range(n):
        c = text[i]
        if escape:
            escape = False
            continue
        if in_string:
            if c == "\\":
                escape = True
            elif c == '"':
                in_string = False
            continue
        if c == '"':
            in_string = True
            continue
        if c == "{":
            if depth == 0:
                span_start = i
            depth += 1
        elif c == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and span_start >= 0:
                    last_start = span_start
                    last_end = i
                    span_start = -1

    if last_start < 0:
        return None, 0, 0

    body = text[last_start : last_end + 1]
    return body, last_start, n - last_end - 1


# Quasi-JSON fixups. Each is a ``(name, transform)`` pair. Applied
# ONE at a time on the input to avoid interference — if a single
# fixup rescues the parse, we stop. The parser records which
# fixups were tried so observability sees the specific drift.
def _fix_trailing_commas(s: str) -> str:
    """Strip trailing commas before ``]`` / ``}``.

    Aware of BOTH single- and double-quoted strings so a comma inside
    ``"reason": "value ends with,"`` (or the single-quoted variant a
    model that mixed quote styles emitted) never gets stripped as a
    trailing comma. Order matters: this fixup MUST run AFTER
    :func:`_fix_single_quotes` if a caller composes them, but the
    single-quote awareness here is the belt-and-braces defence so
    order alone doesn't determine correctness.
    """
    out = []
    in_double = False
    in_single = False
    escape = False
    i = 0
    while i < len(s):
        c = s[i]
        if escape:
            out.append(c)
            escape = False
            i += 1
            continue
        if in_double:
            out.append(c)
            if c == "\\":
                escape = True
            elif c == '"':
                in_double = False
            i += 1
            continue
        if in_single:
            out.append(c)
            if c == "\\":
                escape = True
            elif c == "'":
                in_single = False
            i += 1
            continue
        if c == '"':
            in_double = True
            out.append(c)
            i += 1
            continue
        if c == "'":
            in_single = True
            out.append(c)
            i += 1
            continue
        if c == ",":
            # Peek forward for whitespace + closing bracket.
            j = i + 1
            while j < len(s) and s[j] in " \t\r\n":
                j += 1
            if j < len(s) and s[j] in "]}":
                # Drop the trailing comma.
                i = j
                continue
        out.append(c)
        i += 1
    return "".join(out)


def _fix_python_literals(s: str) -> str:
    """Replace bare ``None`` / ``True`` / ``False`` with JSON literals.

    Only outside string literals. Whole-word match to avoid ``NoneType``
    or ``Truthy`` collisions. Python literals inside string fields
    (e.g. ``"reason": "returned None"``) are left alone.
    """
    replacements = {"None": "null", "True": "true", "False": "false"}
    out = []
    in_string = False
    escape = False
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if escape:
            out.append(c)
            escape = False
            i += 1
            continue
        if in_string:
            out.append(c)
            if c == "\\":
                escape = True
            elif c == '"':
                in_string = False
            i += 1
            continue
        if c == '"':
            in_string = True
            out.append(c)
            i += 1
            continue
        # Whole-word match for the Python literals.
        for py, js in replacements.items():
            end = i + len(py)
            if s[i:end] == py:
                # Boundary check — preceding + following char must not
                # be alphanumeric / underscore.
                prev = s[i - 1] if i > 0 else " "
                nxt = s[end] if end < n else " "
                if not prev.isalnum() and prev != "_" and not nxt.isalnum() and nxt != "_":
                    out.append(js)
                    i = end
                    break
        else:
            out.append(c)
            i += 1
            continue
    return "".join(out)


def _fix_single_quotes(s: str) -> str:
    """Swap single-quoted strings to double-quoted.

    Only when the token looks like a string (matching pair, no
    embedded double-quote). Skips content inside existing double-quoted
    strings so ``"reason": "it's fine"`` is left alone.
    """
    out = []
    in_dq = False
    dq_escape = False
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if dq_escape:
            out.append(c)
            dq_escape = False
            i += 1
            continue
        if in_dq:
            out.append(c)
            if c == "\\":
                dq_escape = True
            elif c == '"':
                in_dq = False
            i += 1
            continue
        if c == '"':
            in_dq = True
            out.append(c)
            i += 1
            continue
        if c == "'":
            # Find matching close single-quote. Skip if the content
            # contains a bare double-quote (which would break the swap).
            j = i + 1
            has_dq = False
            while j < n and s[j] != "'":
                if s[j] == '"':
                    has_dq = True
                if s[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                j += 1
            if j < n and not has_dq:
                out.append('"')
                out.append(s[i + 1 : j])
                out.append('"')
                i = j + 1
                continue
        out.append(c)
        i += 1
    return "".join(out)


#: Ordered fixup ladder. ``single_quotes`` runs FIRST so any string
#: containing a stray ``,`` gets recognised as a JSON string (by
#: ``_fix_trailing_commas`` in the same combined pass) rather than
#: mis-treated as a top-level trailing comma. Reordering these
#: without preserving the "quote fix before comma fix" invariant
#: silently corrupts inputs like ``{'reason': 'value ends with,'}``
#: (test coverage in ``TestQuasiJsonFixups``).
_QUASI_FIXUPS = (
    ("single_quotes", _fix_single_quotes),
    ("python_literals", _fix_python_literals),
    ("trailing_commas", _fix_trailing_commas),
)


def _try_quasi_json_fixups(text: str) -> Tuple[Any, Tuple[str, ...]]:
    """Apply each quasi-JSON fixup individually, then in combination.

    Returns ``(parsed, applied_names)`` — ``parsed`` is the parsed
    value on success or ``_MISSING`` when every combination failed;
    ``applied_names`` is the ordered tuple of fixup labels that were
    applied.
    """
    # First try each fixup in isolation.
    for name, transform in _QUASI_FIXUPS:
        transformed = transform(text)
        if transformed == text:
            continue
        parsed, _ = _try_strict(transformed)
        if parsed is not _MISSING:
            return parsed, (name,)

    # Then try all together — some inputs need multiple fixes to parse.
    current = text
    applied: list[str] = []
    for name, transform in _QUASI_FIXUPS:
        new = transform(current)
        if new != current:
            applied.append(name)
            current = new
    if current != text:
        parsed, _ = _try_strict(current)
        if parsed is not _MISSING:
            return parsed, tuple(applied)

    return _MISSING, ()


def _extract_partial_keys(text: Optional[str]) -> Tuple[str, ...]:
    """Best-effort extract JSON object keys from a possibly-broken payload.

    Regex matches ``"key":`` patterns outside of ``\\``-escaped string
    content. Not a JSON parser — deliberately permissive to catch
    partial signal in truncated / broken payloads. Returns keys in
    document order, de-duplicated, capped at 32 to protect against
    pathological inputs (a broken payload with 10k keys is a rare
    case not worth optimising for; the cap prevents log blow-up).
    """
    if not text:
        return ()
    # Match ``"key":`` — accepts a leading digit / hyphen / dot in key
    # names so keys like ``"2fa_enabled"``, ``"user-id"``, ``"api.key"``
    # (which models legitimately emit) are surfaced. Deliberately does
    # NOT try to handle key names with embedded escaped quotes — that
    # would risk the regex over-matching, and such names are extremely
    # rare in structured LLM output.
    seen: list[str] = []
    seen_set: set[str] = set()
    for m in re.finditer(r'"([A-Za-z0-9_][A-Za-z0-9_.\-]*)"\s*:', text):
        k = m.group(1)
        if k not in seen_set:
            seen_set.add(k)
            seen.append(k)
        if len(seen) >= 32:
            break
    return tuple(seen)


__all__ = [
    "ExtractionDiagnostic",
    "parse_llm_json",
]
