"""Build-on-demand shared-library stubs for sandbox workarounds.

Each stub is compiled once and cached under ``~/.cache/raptor/shims/``
keyed by a content hash of the source, so rebuilds only happen when
the source changes.
"""

from __future__ import annotations

import hashlib
import logging
import subprocess
import sys
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

_SHIMS_DIR = Path(__file__).resolve().parent
_CACHE_DIR = Path.home() / ".cache" / "raptor" / "shims"


def _content_hash(src: Path) -> str:
    """Short hash of *src* content for cache keying."""
    return hashlib.sha256(src.read_bytes()).hexdigest()[:12]


def build_setgroups_stub() -> Optional[Path]:
    """Compile ``setgroups_stub.c`` into a shared library.

    Returns the path to the ``.so`` on success, ``None`` on failure
    (missing gcc, cross-platform, etc.).  The result is cached by
    source content hash.
    """
    if sys.platform != "linux":
        return None

    src = _SHIMS_DIR / "setgroups_stub.c"
    if not src.is_file():
        log.debug("setgroups_stub.c not found at %s", src)
        return None

    h = _content_hash(src)
    out = _CACHE_DIR / f"libsetgroups_stub-{h}.so"

    if out.is_file():
        return out

    _CACHE_DIR.mkdir(parents=True, exist_ok=True)

    # Compile to a temp name and rename — atomic on same filesystem.
    tmp = out.with_suffix(".tmp.so")
    try:
        subprocess.run(
            ["gcc", "-shared", "-fPIC", "-O2", "-o", str(tmp), str(src)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if not tmp.is_file():
            log.debug("gcc produced no output for setgroups_stub")
            return None
        tmp.rename(out)
        log.debug("Built setgroups stub at %s", out)
        return out
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        log.debug("Failed to build setgroups stub: %s", exc)
        tmp.unlink(missing_ok=True)
        return None
