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


def detect_id_collisions(raw_ids) -> list[tuple[str, list[str]]]:
    """Return list of (sanitized_id, [raw_ids_that_collapsed_to_it])
    for any sanitization that produced collisions.

    `sanitize_id` deterministically maps two distinct raw ids
    (e.g. `"foo!"` and `"foo?"`) to the same sanitized form
    (`"foo_"`). The renderer then can't visually distinguish
    them — a single collapsed Mermaid node represents two
    semantically-distinct source nodes, structural information
    is lost silently.

    Pre-fix nothing surfaced these collisions. This helper lets
    callers (renderer assembly) detect and log them so the
    operator knows which input ids need disambiguation.
    Returns empty list when no collisions present.
    """
    by_sanitized: dict[str, list[str]] = {}
    for raw in raw_ids:
        s = sanitize_id(raw)
        by_sanitized.setdefault(s, []).append(str(raw))
    return [
        (sanitized, originals)
        for sanitized, originals in by_sanitized.items()
        if len(set(originals)) > 1
    ]
