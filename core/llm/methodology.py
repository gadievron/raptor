"""Load methodology files from tiers/ for injection into LLM system prompts.

Bridges the tiers/ persona files (consumed by Claude Code via progressive
loading) to the Python LLM dispatch path (Gemini, Ollama, multi-model).
Strips YAML frontmatter and the leading H1 so the injected text is pure
methodology content.

The module-level env lookup is deferred so that importing this module in
test environments (where RAPTOR_DIR may not be set) does not raise.
"""

from __future__ import annotations

import os
from pathlib import Path

_raptor_dir: Path | None = None
_cache: dict[str, tuple[str, float]] = {}


def _get_methodology_dir() -> Path:
    global _raptor_dir
    if _raptor_dir is None:
        _raptor_dir = Path(os.environ["RAPTOR_DIR"])
    return _raptor_dir / "tiers"


def load_methodology(name: str) -> str:
    """Return the body of a tiers/ file, stripped of frontmatter and H1.

    Returns "" if the file does not exist.  Results are cached with
    mtime-based invalidation so repeated calls within the same process
    are free.
    """
    path = _get_methodology_dir() / name
    if not path.is_file():
        return ""
    mtime = path.stat().st_mtime
    if name in _cache:
        cached_body, cached_mtime = _cache[name]
        if cached_mtime == mtime:
            return cached_body
    text = path.read_text(encoding="utf-8")
    body = _strip_frontmatter(text)
    _cache[name] = (body, mtime)
    return body


def _strip_frontmatter(text: str) -> str:
    """Remove YAML frontmatter (``---`` delimited) and the first H1 line."""
    lines = text.splitlines()
    result: list[str] = []
    in_frontmatter = False
    past_header = False
    for line in lines:
        if not past_header and not in_frontmatter and line.startswith("---"):
            in_frontmatter = True
            continue
        if in_frontmatter:
            if line.startswith("---"):
                in_frontmatter = False
            continue
        if not past_header and line.startswith("# "):
            continue
        past_header = True
        result.append(line)
    return "\n".join(result).strip()


def clear_cache() -> None:
    """Clear the mtime cache (useful in tests)."""
    global _raptor_dir
    _cache.clear()
    _raptor_dir = None
