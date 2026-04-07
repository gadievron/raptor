"""JSON utilities — load, save, and comment-stripping.

Centralises the json.loads(path.read_text()) and json.dump(f, indent=2)
patterns used across 60+ files, with consistent error handling and
serialization of Path/datetime objects.
"""

import json
import re
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


def save_json(path: Union[str, Path], data: Any) -> None:
    """Save data as pretty-printed JSON. Handles Path/datetime serialization.

    Creates parent directories if needed. Uses atomic write (write to temp
    file then rename) to prevent corruption if the process is killed mid-write.
    Raises on write failure — a failed save should not be silent.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(data, indent=2, cls=_RaptorEncoder) + "\n"

    # Write to temp file then rename — atomic on POSIX (same filesystem).
    # .~ prefix makes stale temps visually obvious and excluded by get_run_dirs.
    tmp = p.with_name(f".~{p.name}.tmp")
    try:
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(p)
    except BaseException:
        # Clean up temp file on any failure
        tmp.unlink(missing_ok=True)
        raise
