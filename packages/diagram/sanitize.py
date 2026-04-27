"""Mermaid label and ID sanitizer — shared across all diagram renderers."""

import re

# Default max length for a single line within a node label.
# Individual renderers can pass a different value or None to disable.
DEFAULT_MAX_LEN = 80

_SAFE_ID_RE = re.compile(r'[^A-Za-z0-9_-]')


def sanitize(text: str, max_len: int = None) -> str:
    """Escape characters that break Mermaid node labels.

    This sanitizer is for quoted node labels and similarly quoted text. It does
    not escape ``|`` because Mermaid uses that character as edge-label syntax;
    callers must not pass user-controlled text into unquoted edge labels.

    Args:
        text: Raw label text.
        max_len: Truncate the escaped text to this length with '...' suffix.
                 Because truncation happens after HTML entity escaping, the
                 result may cut through an entity (for example, ``&am...``);
                 this is cosmetic only, not a Mermaid injection boundary.
                 Pass None to disable truncation (default).
    """
    result = (
        str(text)
        .replace("&", "&amp;")
        .replace('"', "'")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("{", "(")
        .replace("}", ")")
        .replace("\n", " ")
        .replace("\r", " ")
        .replace("\u2028", " ")
        .replace("\u2029", " ")
    )
    if max_len and len(result) > max_len:
        result = result[:max_len - 3] + "..."
    return result


def sanitize_id(node_id: str) -> str:
    """Sanitize a Mermaid node ID to prevent markup injection.

    Node IDs (unlike labels) are not quoted in Mermaid syntax, so a crafted
    ID can inject arbitrary Mermaid directives including click callbacks
    that execute JavaScript when rendered in a browser.

    Strips everything except [A-Za-z0-9_-].
    """
    sanitized = _SAFE_ID_RE.sub('_', str(node_id))
    return sanitized if sanitized.strip('_') else "node"
