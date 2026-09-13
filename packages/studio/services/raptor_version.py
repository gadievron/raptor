"""Raptor's canonical version for the UI to display.

``packages.studio`` lives inside the raptor tree, so the version is a
direct import of ``core.config.RaptorConfig.VERSION``. The standalone
companion repo (yesnet0/raptor-studio) uses a regex-scrape fallback
because it can't count on raptor being importable; we don't need that
here.
"""

from __future__ import annotations

from functools import lru_cache


@lru_cache(maxsize=1)
def raptor_version() -> str:
    """Return raptor's version string, or ``""`` if RaptorConfig is unimportable."""
    try:
        from core.config import RaptorConfig
    except ImportError:
        return ""
    val = getattr(RaptorConfig, "VERSION", "") or ""
    return str(val).strip()
