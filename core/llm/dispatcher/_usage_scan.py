"""Pure usage-scan core for relayed LLM response bytes.

One function: bounded head/tail windows of a response body in, the
``{model, input_tokens, output_tokens, cache_read_tokens,
cache_creation_tokens}`` usage struct out. The bytes come from a
remote LLM backend — a semi-trusted network peer — and embed
MODEL-AUTHORED text, so every interpretation here (SSE line splitting,
``json.loads``, the truncation-recovery scans) treats its input as
hostile: nothing about how the scan reads a response may be steerable
by body content, and the scan itself never raises on malformed input
(worst case: the zeros struct, which the booking path makes loud).

Deliberately stdlib-only (json, re) with no package imports: this
module is executed inside the confined scan worker
(``_usage_scan_child.py``) whose Landlock policy grants read-only
access to the code trees alone, and it doubles as the in-process
degradation tier and the differential-equivalence oracle in tests
(see ``usage_scan_jail.py``).

Extracted from ``server.py``'s former in-process ``_UsageScanner``
parse helpers; the buffering half (bounded window feeding) stays in
the server — byte copying carries no parse risk.
"""

import json
import re

# Injection note for the recovery helpers below: model-authored
# response text rides inside JSON string values, whose ``"`` and
# newline characters arrive escaped (``\"``, ``\n``) — so a raw
# ``"usage"`` / ``"model"`` key token (unescaped quotes) can only come
# from the response document's own structure, never from content a
# prompt-injected child steered the model into emitting.
_MODEL_KEY_RE = re.compile(r'"model"\s*:\s*"([^"\\]+)"')


def _model_id_from_text(text: str) -> "str | None":
    """Best-effort model id from a partial JSON document (the model
    key rides early in Anthropic Messages JSON, so it survives in the
    head window of a truncated body)."""
    m = _MODEL_KEY_RE.search(text)
    return m.group(1) if m else None


def _usage_object_from_text(text: str) -> "dict | None":
    """Recover the trailing ``usage`` object from a truncated non-SSE
    body's retained tail. Bounded: one reverse find plus a single
    brace scan over the (already capped) tail. Returns ``None`` when
    no parseable usage object is present."""
    idx = text.rfind('"usage"')
    if idx < 0:
        return None
    brace = text.find("{", idx)
    if brace < 0:
        return None
    depth = 0
    in_str = False
    escaped = False
    for i in range(brace, len(text)):
        c = text[i]
        if in_str:
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                try:
                    obj = json.loads(text[brace:i + 1])
                except (json.JSONDecodeError, ValueError):
                    return None
                return obj if isinstance(obj, dict) else None
    return None


def _is_sse(head: str, tail: str, content_type: "str | None") -> bool:
    """SSE classification. Header wins; the body fallback is
    LINE-anchored (an SSE field name starts a line) — a ``data:``
    substring inside a JSON string value cannot start a line
    because JSON string encoding escapes newlines."""
    if content_type is not None:
        return "text/event-stream" in content_type.lower()
    # Tail bytes start mid-line whenever the tail buffer is in
    # use (it only fills after the head cap, and front-trimming
    # also cuts mid-line) — skip that fragment line so a cut
    # landing inside a JSON string can't fabricate a line start.
    for lines in (head.splitlines(), tail.splitlines()[1:]):
        for line in lines:
            if line.startswith(("data:", "event:")):
                return True
    return False


def _merge_event(obj: dict, out: dict) -> None:
    etype = obj.get("type")
    if etype == "message_start":
        message = obj.get("message")
        if isinstance(message, dict):
            if isinstance(message.get("model"), str):
                out["model"] = message["model"]
            _merge_usage(message.get("usage"), out)
    elif etype == "message_delta":
        _merge_usage(obj.get("usage"), out)


def _merge_usage(usage: object, out: dict) -> None:
    if not isinstance(usage, dict):
        return
    for src, dst in (
        ("input_tokens", "input_tokens"),
        ("output_tokens", "output_tokens"),
        ("cache_read_input_tokens", "cache_read_tokens"),
        ("cache_creation_input_tokens", "cache_creation_tokens"),
    ):
        v = usage.get(src)
        if isinstance(v, int) and not isinstance(v, bool) and v >= 0:
            # Later frames report cumulative totals — take the max
            # so a final message_delta overrides, while partial
            # streams (abort) keep whatever the upstream reported.
            out[dst] = max(out[dst], v)


def scan_usage(
    head: bytes,
    tail: bytes,
    *,
    truncated: bool,
    content_type: "str | None",
) -> dict:
    """Return ``{model, input_tokens, output_tokens,
    cache_read_tokens, cache_creation_tokens}`` (zeros / None when
    the body carried no usage).

    ``head``/``tail`` are the bounded windows the relay retained
    (tail only fills once the head cap is exceeded); ``truncated``
    says bytes were dropped between them. SSE-vs-JSON classification
    comes from ``content_type`` — the header the relay already trusts
    for its own SSE handling — because the scanned bytes include
    model-authored text and a content substring must never pick the
    parser. Only when the upstream sent no Content-Type does the
    line-anchored structural check run instead.
    """
    out: dict = {
        "model": None,
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_tokens": 0,
        "cache_creation_tokens": 0,
    }
    head_text = head.decode("utf-8", "replace")
    tail_text = tail.decode("utf-8", "replace")
    if _is_sse(head_text, tail_text, content_type):
        for text in (head_text, tail_text):
            for line in text.splitlines():
                line = line.strip()
                if not line.startswith("data:"):
                    continue
                try:
                    obj = json.loads(line[len("data:"):].strip())
                except (json.JSONDecodeError, ValueError):
                    continue
                if not isinstance(obj, dict):
                    continue
                _merge_event(obj, out)
        return out
    # Non-streamed JSON body.
    if not truncated:
        try:
            obj = json.loads(head_text + tail_text)
        except (json.JSONDecodeError, ValueError):
            obj = None
        if isinstance(obj, dict):
            if isinstance(obj.get("model"), str):
                out["model"] = obj["model"]
            _merge_usage(obj.get("usage"), out)
        return out
    # Truncated non-SSE body: the middle is gone, so a full parse
    # is impossible — but Anthropic Messages JSON carries its
    # ``usage`` block at the END, inside the retained tail.
    # Recover it there so an oversize response still books its
    # real cost instead of $0 (the caller warns loudly when even
    # this fails — see ``_book_child_usage``).
    _merge_usage(_usage_object_from_text(tail_text), out)
    model = _model_id_from_text(head_text) or _model_id_from_text(tail_text)
    if model:
        out["model"] = model
    return out
