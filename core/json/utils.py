"""JSON utilities — load, save, and comment-stripping.

Centralises the json.loads(path.read_text()) and json.dump(f, indent=2)
patterns used across 60+ files, with consistent error handling and
serialization of Path/datetime objects.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Union

from core.atomic_fs import write_text_atomically

logger = logging.getLogger(__name__)


def _reject_non_finite(token: str) -> Any:
    """`parse_constant` callback rejecting JSON5-ish ``NaN``/``Infinity``.

    Stdlib `json` accepts the literal tokens ``NaN``, ``Infinity``, and
    ``-Infinity`` by default — strictly an extension to RFC 8259, but
    enabled out of the box. Once those land in a Python float, every
    downstream `int(...)` / range check has to defend against
    ``OverflowError`` and ``ValueError`` (``int(float('inf'))`` raises
    ``OverflowError``; ``int(float('nan'))`` raises ``ValueError``;
    comparisons against NaN are silently False), and forgetting that
    branch leaks an unrelated exception type to a caller whose
    ``except (OSError, ValueError)`` doesn't cover it.

    Reject at parse time so corrupt or hostile config files surface
    as a clean ``json.JSONDecodeError`` (the existing handler) rather
    than as an arbitrary downstream crash.
    """
    raise ValueError(f"non-finite JSON constant rejected: {token}")


def load_json(
    path: Union[str, Path],
    strict: bool = False,
    *,
    allow_non_finite: bool = False,
) -> Optional[Any]:
    """Load a JSON file.

    Returns None if the file does not exist. If the file exists but is
    malformed or unreadable, behaviour depends on ``strict``:

    - strict=False (default): return None (for optional/best-effort files)
    - strict=True: raise the underlying exception (for required files)

    Reads with ``utf-8-sig`` to transparently handle UTF-8 BOM
    (`\\ufeff` at the start of the file). Pre-fix utf-8 read passed
    the BOM straight to the JSON parser which rejected it with
    "Expecting value: line 1 column 1 (char 0)" — Windows-edited
    config files, files round-tripped through some text editors,
    and many JSON exports from Office tools all carry a BOM.
    `utf-8-sig` is a strict superset of `utf-8`: identical for
    BOM-less files, transparent for BOM-prefixed ones.

    ``allow_non_finite`` (keyword-only): opt in to accepting
    ``NaN``, ``Infinity``, ``-Infinity`` literals at parse time. Off by
    default — see ``_reject_non_finite`` for the threat model.
    Callers reading reports from upstream analysers that legitimately
    emit non-finite numeric scores (LLM confidence layers, certain
    fuzzers) opt in here so the parse doesn't reject the whole file
    on one NaN cell. Caller is then responsible for handling
    non-finite values downstream (treat-as-zero, skip, etc).
    """
    p = Path(path)
    if not p.exists():
        return None
    parse_constant = None if allow_non_finite else _reject_non_finite
    if strict:
        return json.loads(
            p.read_text(encoding="utf-8-sig"),
            parse_constant=parse_constant,
        )
    try:
        return json.loads(
            p.read_text(encoding="utf-8-sig"),
            parse_constant=parse_constant,
        )
    except (json.JSONDecodeError, ValueError, OSError, RecursionError) as e:
        # Pre-fix this returned None silently. Operators investigating
        # "why is my config not loading" had no signal — the file
        # existed, the function returned None, downstream code
        # crashed on missing data without any breadcrumb pointing
        # at the parse failure. Log at warning so a developer
        # debugging "missing data" sees the JSON error and the file
        # path; not error so legitimate optional/best-effort callers
        # don't trigger alarm.
        #
        # RecursionError is included because deeply-nested JSON
        # (>~500 levels) blows the Python recursion limit during
        # json.loads — caller should see the same warn-and-None
        # path as a JSONDecodeError rather than an uncaught crash.
        logger.warning("load_json: failed to parse %s: %s", p, e)
        return None


def _strip_json_comments(text: str) -> str:
    """Strip ``//`` and ``#`` comments from JSON text, respecting strings.

    Handles full-line comments, inline trailing comments, and comment
    characters inside quoted strings (e.g. ``"url": "https://x.com"``
    or ``"color": "#fff"``).

    `in_string` state persists across line boundaries. Pre-fix the
    state was reset per line, so a multi-line string (legal in JSON5
    via `\\\\\\n` line continuations and accepted by tolerant parsers
    like simdjson; common in human-edited config) lost track of the
    in-string context at line breaks. A `//` or `#` inside the
    spanning string was then incorrectly treated as a comment start
    and the rest of that line was stripped — corrupting the value.
    """
    result = []
    in_string = False  # persists across lines
    for line in text.split('\n'):
        i = 0
        while i < len(line):
            ch = line[i]
            if ch == '\\' and in_string:
                i += 2
                continue
            if ch == '"':
                in_string = not in_string
            elif not in_string:
                if ch == '/' and line[i:i + 2] == '//':
                    line = line[:i]
                    break
                if ch == '#':
                    line = line[:i]
                    break
            i += 1
        result.append(line)
    return '\n'.join(result)


def load_json_with_comments(path: Union[str, Path]) -> Optional[Any]:
    """Load a JSON file that may contain ``//`` or ``#`` comments.

    Strips full-line and inline comments before parsing, while
    preserving comment characters inside quoted strings. Used for
    config files (e.g. ``tuning.json``, ``models.json``). Returns
    None on missing file or parse error.
    """
    p = Path(path)
    if not p.exists():
        return None
    try:
        # `utf-8-sig` for BOM tolerance — config files written /
        # round-tripped through Windows editors commonly carry a
        # leading `﻿` that vanilla utf-8 read passes through
        # to the JSON parser as an unexpected character.
        text = p.read_text(encoding="utf-8-sig")
        stripped = _strip_json_comments(text)
        if not stripped.strip():
            return None
        return json.loads(stripped, parse_constant=_reject_non_finite)
    except (json.JSONDecodeError, ValueError, OSError, RecursionError) as e:
        logger.warning("load_json_with_comments: failed to parse %s: %s", p, e)
        return None


class _RaptorEncoder(json.JSONEncoder):
    """JSON encoder that handles Path and datetime objects."""

    def default(self, obj):
        if isinstance(obj, Path):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        # Fallback: stringify unknown types (matches the default=str pattern
        # used by several callers before centralisation)
        try:
            return super().default(obj)
        except TypeError:
            return str(obj)


def save_json(path: Union[str, Path], data: Any, mode: int = None) -> None:
    """Save data as pretty-printed JSON. Handles Path/datetime serialization.

    Delegates to :func:`core.atomic_fs.write_text_atomically` — the shared
    primitive owns the tempfile + fsync + rename + parent-dir fsync dance,
    plus O_EXCL/O_NOFOLLOW tempfile hardening.

    Atomic write: threat models, checklists, run reports, project state —
    every JSON produced through this helper is an operator-facing artefact
    where a torn write (interrupt, power loss, sigkill) surfaces as
    "path exists but fails to parse" on the next read.

    Args:
        mode: Optional POSIX file permission bits (e.g. 0o600). When set,
              the mode is installed on the tempfile before rename — no
              chmod-after-rename window.
    """
    content = json.dumps(data, indent=2, cls=_RaptorEncoder, allow_nan=False) + "\n"
    write_text_atomically(path, content, mode=mode, tmp_prefix=".~savejson-")
