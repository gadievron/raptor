"""Build-on-demand shared-library stubs for sandbox workarounds.

Each stub is compiled once and cached under ``~/.cache/raptor/shims/``
keyed by a content hash of the source, so rebuilds only happen when
the source changes.
"""

from __future__ import annotations

import hashlib
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path

log = logging.getLogger(__name__)

_SHIMS_DIR = Path(__file__).resolve().parent
_CACHE_DIR = Path.home() / ".cache" / "raptor" / "shims"


def _content_hash(src: Path) -> str:
    """Short hash of *src* content for cache keying."""
    return hashlib.sha256(src.read_bytes()).hexdigest()[:12]


def build_setgroups_stub() -> Path | None:
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

    # Compile to a PER-PROCESS temp name and os.replace() — atomic on
    # the same filesystem. A deterministic temp path would let two
    # concurrent cold builders write the same file and rename a
    # partially written .so into the cache.
    fd, tmp_name = tempfile.mkstemp(
        dir=_CACHE_DIR, prefix=f"libsetgroups_stub-{h}.", suffix=".tmp.so",
    )
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        r = subprocess.run(
            ["gcc", "-shared", "-fPIC", "-O2", "-o", str(tmp), str(src)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,  # returncode handled explicitly below
        )
        if r.returncode != 0:
            # A failed compile can still leave partial output at -o;
            # never promote it into the cache, and keep the stderr so
            # the failure is diagnosable.
            log.debug(
                "gcc failed for setgroups_stub (rc=%s): %s",
                r.returncode, (r.stderr or "").strip()[:500],
            )
            return None
        if not tmp.is_file() or tmp.stat().st_size == 0:
            log.debug("gcc produced no output for setgroups_stub")
            return None
        # mkstemp creates 0600; match the default-umask mode gcc used
        # to produce so sandboxed children can keep dlopen'ing it.
        os.chmod(tmp, 0o644)
        os.replace(tmp, out)
        log.debug("Built setgroups stub at %s", out)
        return out
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        log.debug("Failed to build setgroups stub: %s", exc)
        return None
    finally:
        tmp.unlink(missing_ok=True)
