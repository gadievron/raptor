"""JSON utilities — load, save, and comment-stripping.

Centralises the json.loads(path.read_text()) and json.dump(f, indent=2)
patterns used across 60+ files, with consistent error handling and
serialization of Path/datetime objects.
"""

import json
import logging
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Union

logger = logging.getLogger(__name__)


def load_json(path: Union[str, Path], strict: bool = False) -> Optional[Any]:
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
    """
    p = Path(path)
    if not p.exists():
        return None
    if strict:
        return json.loads(p.read_text(encoding="utf-8-sig"))
    try:
        return json.loads(p.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, OSError) as e:
        # Pre-fix this returned None silently. Operators investigating
        # "why is my config not loading" had no signal — the file
        # existed, the function returned None, downstream code
        # crashed on missing data without any breadcrumb pointing
        # at the parse failure. Log at warning so a developer
        # debugging "missing data" sees the JSON error and the file
        # path; not error so legitimate optional/best-effort callers
        # don't trigger alarm.
        logger.warning("load_json: failed to parse %s: %s", p, e)
        return None


def _strip_json_comments(text: str) -> str:
    """Strip ``//`` and ``#`` comments from JSON text, respecting strings.

    Handles full-line comments, inline trailing comments, and comment
    characters inside quoted strings (e.g. ``"url": "https://x.com"``
    or ``"color": "#fff"``).
    """
    result = []
    for line in text.split('\n'):
        in_string = False
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
        return json.loads(stripped)
    except (json.JSONDecodeError, OSError) as e:
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

    Creates parent directories if needed. Uses atomic write (write to temp
    file then rename) to prevent corruption if the process is killed mid-write.
    Raises on write failure — a failed save should not be silent.

    Args:
        mode: Optional POSIX file permission bits (e.g. 0o600). When set,
              the temp file is created with these permissions atomically —
              no window where the file exists with default permissions.

    Durability: fsyncs the data file BEFORE the rename, then fsyncs the
    parent directory AFTER. Pre-fix the atomic-write pattern used
    `tmp.write_text` + `tmp.replace(p)` without either fsync — the
    rename is atomic at the filesystem-metadata layer, but the data
    pages may not be on disk yet. A power loss / hard reboot between
    the rename and the next pdflush cycle produced a renamed file
    containing zero bytes (or a torn fragment) — operator next boot
    saw the path exist but the JSON failed to parse. The two fsyncs
    cost a few hundred microseconds per save vs. the cost of losing
    a checklist or report on power loss.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(data, indent=2, cls=_RaptorEncoder) + "\n"

    # Write to temp file then rename — atomic on POSIX (same filesystem).
    # .~ prefix makes stale temps visually obvious and excluded by
    # get_run_dirs. The pid+tid suffix is what makes concurrent writers
    # safe: two threads (or two processes) writing the same target path
    # would otherwise share a tempfile path, and the second open with
    # O_TRUNC would clobber the first's partial write — leaving a torn
    # file that fails to parse on the next read. With pid+tid each
    # writer has its own tempfile; the final rename is last-writer-wins.
    tmp = p.with_name(f".~{p.name}.tmp.{os.getpid()}.{threading.get_ident()}")
    try:
        if mode is not None:
            # Create temp file with explicit permissions — no race window
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
        else:
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
        tmp.replace(p)
        # fsync the parent directory so the rename's metadata is also
        # durable. Some filesystems (ext4 default, xfs) don't propagate
        # rename ordering to the next dir-entry flush without this.
        try:
            dir_fd = os.open(str(p.parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            # Some filesystems (notably some FUSE / network mounts)
            # don't support fsync on directory fds. Best-effort.
            pass
    except BaseException:
        # Clean up temp file on any failure
        tmp.unlink(missing_ok=True)
        raise
