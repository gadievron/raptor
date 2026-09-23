"""Containment-checked, size-capped file reads.

Single home for the read discipline that analysis surfaces apply when
the path being read derives from a scanned (untrusted) repository —
SARIF locations, finding records, crash artifacts:

- **Containment** — the path must resolve under the analysed root
  (``core.paths.confine``: traversal segments, out-of-root absolute
  paths, and symlink escapes all refuse). Without it, a hostile
  finding record steers the analyser into reading arbitrary host
  files and quoting them into LLM prompts or reports.
- **Size cap** — bounded-read discipline: open then ``read(cap + 1)``
  and check the probe, never stat-then-read (the file can be
  target-writable, so a size check followed by an unbounded read
  still races a growing plant). Without it, a multi-hundred-MB
  generated/planted file is loaded whole into host memory per
  finding.
- **Regular files only, race-free regularity** — the open itself
  carries ``O_NOFOLLOW | O_NONBLOCK`` and the opened fd is
  ``fstat``-checked ``S_ISREG`` before any read. A plain ``open()``
  on a repo-planted reader-less FIFO blocks the analyser forever, and
  any check-by-name (``is_file()``) can be swapped between check and
  open — the guard must live on the fd. Symlinks at the FINAL path
  component are refused by the capped readers; callers that
  legitimately read through symlinks resolve first
  (``read_contained`` does, via ``confine``), which also keeps
  resolved in-root symlinks working.

  Scope of the race-free claim: it covers the REGULARITY check (fd,
  not name) and the final component (``O_NOFOLLOW``). CONTAINMENT is
  resolve-then-open: an attacker with concurrent local write access
  inside the target tree can swap an INTERMEDIATE directory for an
  out-of-tree symlink between ``confine()``'s resolve and the open,
  steering the read out of root — a materially narrower threat than
  the static plants above (it needs an active local attacker racing
  the analyser, not repo content), and closable only with
  ``openat2(RESOLVE_BENEATH)`` / a dir-fd walk. Consumers must not
  build on a stronger reading.

Sites that need distinct refusal messaging (outside-root vs
unreadable) compose :func:`core.paths.confine` with
:func:`read_text_capped` directly; :func:`read_contained` is the
one-call form for callers that treat every failure the same way.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import IO

from core.paths import confine

__all__ = [
    "DEFAULT_MAX_SOURCE_CHARS",
    "open_regular",
    "read_bytes_capped",
    "read_contained",
    "read_text_capped",
]

# Default text-read cap. 10 MB covers every legitimate human-authored
# source file by orders of magnitude (the largest single C file
# observed in a major OSS project is ~3 MB); generated lexer tables /
# bundled JS blobs past the cap still yield a usable truncated read.
# Text-mode ``read(n)`` counts CHARACTERS; with ``errors="replace"``
# every character decodes from at least one byte, so the cap bounds
# in-memory size within a small constant factor of the byte count.
DEFAULT_MAX_SOURCE_CHARS = 10 * 1024 * 1024


def open_regular(path: str | Path, mode: str, **kwargs) -> IO | None:
    """Open *path* for reading iff it is a regular file, without ever
    blocking or following a final-component symlink.

    ``O_NONBLOCK`` makes the open of a reader-less FIFO return instead
    of hanging; the ``fstat(S_ISREG)`` check on the OPENED fd (not a
    by-name stat, which races a swap) then refuses FIFOs/devices;
    ``O_NOFOLLOW`` refuses a symlink swapped in at the final
    component. Regular-file reads ignore ``O_NONBLOCK``, so the flag
    costs nothing on the accept path. Mirrors
    ``core.license.detector._read_license_full``.

    Public (not just the capped readers' plumbing): readers that need
    their own streaming/locking over an untrusted-dir file consume
    the same discipline instead of re-growing check-by-name
    ``lstat``/``is_file`` probes that race a swap — the coverage
    manifest reader ingested a foreign file through exactly that
    check-then-open window.
    """
    try:
        fd = os.open(
            str(path),
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
        )
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            return None
        return os.fdopen(fd, mode, **kwargs)
    except OSError:
        os.close(fd)
        return None


def read_text_capped(
    path: str | Path,
    max_chars: int = DEFAULT_MAX_SOURCE_CHARS,
    *,
    errors: str = "replace",
) -> tuple[str, bool] | None:
    """Read at most *max_chars* characters of UTF-8 text from *path*.

    Returns ``(text, truncated)``, or ``None`` when the file cannot be
    opened or read (``OSError``), is not a regular file (FIFO, device,
    directory), or is a symlink at the final path component (resolve
    first when reading through symlinks is intended). On truncation the trailing partial
    line is dropped (avoids splitting mid-token in rendered context);
    when the capped read contains no newline at all the raw capped
    text is kept — returning ``""`` would turn a pathological
    single-line file into a silent empty read.
    """
    f = open_regular(path, "r", encoding="utf-8", errors=errors)
    if f is None:
        return None
    try:
        with f:
            content = f.read(max_chars + 1)
    except OSError:
        return None
    if len(content) <= max_chars:
        return content, False
    content = content[:max_chars]
    if "\n" in content:
        content = content.rsplit("\n", 1)[0] + "\n"
    return content, True


def read_bytes_capped(
    path: str | Path,
    max_bytes: int,
) -> tuple[bytes, bool] | None:
    """Read at most *max_bytes* bytes from *path* (binary).

    Returns ``(data, truncated)`` where ``truncated`` means the file
    held MORE than *max_bytes* (``data`` carries exactly the first
    *max_bytes*), or ``None`` when the file cannot be opened or read,
    is not a regular file, or is a final-component symlink.
    Callers with refuse-on-oversize semantics raise on
    ``truncated=True``; callers with degrade semantics keep the
    prefix.
    """
    f = open_regular(path, "rb")
    if f is None:
        return None
    try:
        with f:
            data = f.read(max_bytes + 1)
    except OSError:
        return None
    if len(data) > max_bytes:
        return data[:max_bytes], True
    return data, False


def read_contained(
    root: str | Path,
    candidate: str | Path,
    *,
    max_chars: int = DEFAULT_MAX_SOURCE_CHARS,
    errors: str = "replace",
) -> str | None:
    """Containment-checked, capped text read of *candidate* under *root*.

    ``None`` when the path escapes *root* (traversal, out-of-root
    absolute path, symlink escape), is not a regular file, or cannot
    be read. An in-cap read returns the full text; an over-cap file
    returns the capped prefix (trailing partial line dropped) —
    callers that must distinguish truncation use
    :func:`read_text_capped` with :func:`core.paths.confine`.
    """
    resolved = confine(root, candidate)
    if resolved is None or not resolved.is_file():
        return None
    got = read_text_capped(resolved, max_chars, errors=errors)
    return None if got is None else got[0]
