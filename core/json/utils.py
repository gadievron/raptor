"""JSON utilities — load, save, and comment-stripping.

Centralises the json.loads(path.read_text()) and json.dump(f, indent=2)
patterns used across 60+ files, with consistent error handling and
serialization of Path/datetime objects.
"""

import json
import os
import re
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Union


def load_json(path: Union[str, Path], strict: bool = False) -> Optional[Any]:
    """Load a JSON file.

    Returns None if the file does not exist. If the file exists but is
    malformed or unreadable, behaviour depends on ``strict``:

    - strict=False (default): return None (for optional/best-effort files)
    - strict=True: raise the underlying exception (for required files)
    """
    p = Path(path)
    if not p.exists():
        return None
    if strict:
        return json.loads(p.read_text(encoding="utf-8"))
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def load_json_with_comments(path: Union[str, Path]) -> Optional[Any]:
    """Load a JSON file that may contain // line comments.

    Strips comment lines before parsing. Used for config files
    (e.g. ~/.config/raptor/models.json). Returns None on missing
    file or parse error.
    """
    p = Path(path)
    if not p.exists():
        return None
    try:
        text = p.read_text(encoding="utf-8")
        stripped = re.sub(r'^\s*//.*$', '', text, flags=re.MULTILINE)
        if not stripped.strip():
            return None
        return json.loads(stripped)
    except (json.JSONDecodeError, OSError):
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
        else:
            tmp.write_text(content, encoding="utf-8")
        tmp.replace(p)
    except BaseException:
        # Clean up temp file on any failure
        tmp.unlink(missing_ok=True)
        raise
