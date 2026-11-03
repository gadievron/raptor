"""Bound automatic pytest IDs without changing test data or explicit labels.

Pytest's default embeds string and byte values in node IDs. Hostile parser
fixtures can consequently fill logs and JUnit names with source code, escape
sequences or tens of thousands of brackets. Its public ID hook is consulted
only after explicit row/decorator IDs, so named scenarios retain precedence.
"""
from __future__ import annotations

import hashlib
import re
import unicodedata

_MAX_VALUE_LENGTH = 80
_CONTROLS = {
    0: "nul", 9: "tab", 10: "line-feed", 11: "vertical-tab", 12: "form-feed",
    13: "carriage-return", 27: "escape", 28: "file-separator",
    29: "group-separator", 30: "record-separator", 31: "unit-separator",
    127: "delete", 133: "next-line",
}
_ESCAPE = re.compile(r"\\(?:[nrt0]|x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8})")
_SOURCE = re.compile(
    r"[{};]|(?:^|\s)(?:def|class)\s+\w+\s*[:({]|^\s*def\s+\w+$|"
    r"^\s*return\s+.*[(\$]|\b(?:SELECT|INSERT|DELETE|UPDATE|DROP|CREATE|EXPORT)\s|"
    r"^\s*(?:#include\b|<\?php|(?:SELECT|WITH|INSERT|DELETE|UPDATE|DROP|CREATE|EXPORT)\s)|"
    r"\bHTTP/\d\.\d|<[/!]?\w+[^>]*>"
)
_HEX = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32,}")


def pytest_make_parametrize_id(val: object, argname: str) -> str | None:
    """Use compact stable IDs for payloads; defer other values to pytest."""
    is_pattern = isinstance(val, re.Pattern)
    if is_pattern:
        val = val.pattern
    if not isinstance(val, (str, bytes)):
        return None
    prefix = re.sub(r"[^A-Za-z0-9_-]", "-", argname)[:24] or "parameter"
    is_bytes = isinstance(val, bytes)
    text = bytes.decode(val, "ascii", errors="backslashreplace") if is_bytes else str.__str__(val)
    if (bytes.__len__(val) if is_bytes else len(text)) == 1:
        code = bytes.__getitem__(val, 0) if is_bytes else ord(text)
        if code < 32 or code >= 127:
            if is_bytes:
                kind = "byte-" + _CONTROLS.get(code, f"{code:02x}")
            else:
                kind = _CONTROLS.get(code) or unicodedata.name(text, f"u{code:04x}").lower().replace(" ", "-")
            label = f"{prefix}-{kind}"
            if len(label) <= 80:
                return label
    if not text:
        kind = "empty-bytes" if is_bytes else "empty-text"
    elif text.isspace():
        kind = "whitespace"
    elif "\n" in text or "\r" in text:
        kind = "multiline"
    elif any(unicodedata.category(c) in {"Cc", "Cf", "Cs"} for c in text):
        kind = "control-text"
    elif is_bytes and not bytes.isascii(val):
        kind = "binary"
    elif any(ord(c) > 126 for c in text):
        kind = "unicode-text"
    elif _ESCAPE.search(text):
        kind = "escaped-text"
    elif _HEX.search(text):
        kind = "hex-text"
    elif text[0] in "[{" and text[-1] in "]}":
        kind = "structured-text"
    elif len(text) > _MAX_VALUE_LENGTH:
        kind = "long-bytes" if is_bytes else "long-text"
    elif _SOURCE.search(text):
        kind = "source-text"
    else:
        return None
    raw = val if is_bytes else text.encode("utf-8", errors="surrogatepass")
    digest = hashlib.sha256(b"bytes:" if is_bytes else b"text:")
    digest.update(raw)
    return f"{prefix}-{'regex-' if is_pattern else ''}{kind}-{digest.hexdigest()[:10]}"
