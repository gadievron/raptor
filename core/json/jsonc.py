"""Tolerant JSON-with-comments (JSONC) loading.

``devcontainer.json``, ``tsconfig.json`` and friends are JSONC: standard JSON
plus ``//`` / ``/* */`` comments and trailing commas. A naive regex strip of
``//`` corrupts string *values* that contain ``//`` — a ``https://`` URL is the
common casualty, which silently breaks the parse — so the comment stripper here
is string-aware: it only removes comment markers that sit outside string
literals.

Sibling, not duplicate: :func:`core.json.load_json_with_comments` is the
loader for RAPTOR's own *config* files (``models.json``, ``tuning.json``),
which use the ``//`` + ``#`` dialect. This module targets the standard-JSONC
dialect (``//`` + ``/* */`` + trailing commas, no ``#``) used by third-party
data files we parse but don't own. They stay separate because the config
stripper is line-oriented (can't span a multi-line ``/* */`` block) and ``#``
is a *value* character in JSONC, not a comment.
"""

from __future__ import annotations

import json
import re
from typing import Any, List


def strip_jsonc_comments(text: str) -> str:
    """Remove ``//`` and ``/* */`` comments that are OUTSIDE string literals.

    Walks the text tracking string state (and backslash escapes) so a comment
    marker inside a quoted value — e.g. the ``//`` in ``"https://..."`` — is
    left untouched. A regex can't do this safely.
    """
    out: List[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:        # keep the escaped char verbatim
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            i += 2
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


_TRAILING_COMMA_RE = re.compile(r",(\s*[}\]])")


def load_jsonc(text: str) -> Any:
    """Parse JSONC ``text``: strip comments (string-aware) and tolerate
    trailing commas (``{ "a": 1, }``), then ``json.loads``. Raises
    ``json.JSONDecodeError`` on genuinely malformed input, like ``json.loads``.
    """
    cleaned = strip_jsonc_comments(text)
    cleaned = _TRAILING_COMMA_RE.sub(r"\1", cleaned)
    return json.loads(cleaned)


__all__ = ["strip_jsonc_comments", "load_jsonc"]
