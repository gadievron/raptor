"""Raising-flavor gated text read — the strict sibling of
:mod:`core.source.contained`.

The capped readers in :mod:`core.source.contained` are None-flavor:
every refusal (unreadable, non-regular, over-cap) collapses into one
"no text" answer, which suits best-effort analysis reads. Loaders
with a REQUIRED file — config, budget-gated JSON, spec documents —
need the opposite: each refusal class surfaces as a distinct
exception so the caller can report it (and only it) precisely.
:func:`read_bytes_gated` is the single body for that flavor
(:func:`read_text_gated` is its decode wrapper); it grew up as
``core.json.utils._read_text_gated`` backing ``load_json`` and is
promoted here so non-JSON strict readers consume the same discipline
instead of re-growing their own fstat/budget idiom
(``core.json.utils`` imports THIS implementation — one body, both
flavors' doctrine in one module family). The bytes flavor serves
consume-by-copy callers that must hash/archive the exact bytes they
parsed without a second read.

Raising vs None-flavor is the only axis that kept the two apart;
the gates are identical in kind:

- Regular files only, checked on the OPENED fd (a FIFO stats as 0
  bytes and then blocks a plain reader forever; ``O_NONBLOCK`` makes
  even the open of a reader-less FIFO return instead of hanging).
- ``max_bytes`` checked on the fstat size AND re-checked after a
  capped read, so a file that grows between fstat and read is
  refused instead of buffered unbounded (the GROW gate).
- ``follow_symlinks=False`` adds ``O_NOFOLLOW`` for callers whose
  path must not read through a final-component link. The default
  FOLLOWS symlinks by design — config loaders legitimately read
  through links; symlink-to-FIFO is still refused with the FIFO.
"""

from __future__ import annotations

import os
import stat as _stat_mod
from pathlib import Path
from typing import IO

__all__ = [
    "ReadBudgetExceededError",
    "open_regular_gated",
    "read_bytes_gated",
    "read_text_gated",
]


class ReadBudgetExceededError(ValueError):
    """A gated read refused a file for exceeding its byte budget.

    Subclasses ``ValueError`` so pre-existing ``except ValueError``
    handlers keep refusing gracefully; strict callers catch THIS
    class to report the budget refusal distinctly (an over-budget
    required file is actionable — raise the budget or shrink the
    file — where a malformed one is not).
    """


def _open_gated(
    p: str | Path,
    *,
    follow_symlinks: bool,
) -> tuple[IO[bytes], os.stat_result]:
    """One open, ONE fstat: the shared body behind
    :func:`open_regular_gated` and :func:`read_bytes_gated`.

    Returning the stat alongside the stream lets the byte reader run
    its size gate on the SAME fstat that proved regularity — a second
    by-fd stat would be sound (same inode) but would split the gates
    across two kernel snapshots, so a file growing between them would
    trip the size gate with the wrong refusal message.
    """
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    if not follow_symlinks:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(p), flags)
    try:
        st = os.fstat(fd)
        if not _stat_mod.S_ISREG(st.st_mode):
            msg = f"not a regular file: {p}"
            raise ValueError(msg)
        fh = os.fdopen(fd, "rb")
        fd = -1  # fdopen owns it now
        return fh, st
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


def open_regular_gated(
    p: str | Path,
    *,
    follow_symlinks: bool = True,
) -> IO[bytes]:
    """Raising fd-gated open of a regular file for reading.

    The open half of :func:`read_bytes_gated`, exposed for callers
    that need their own read shape (streamed hashing, held inode
    pins) over the same discipline — one body, so a new consumer can
    never re-grow a check-by-name ``is_file()``/``lstat()`` probe
    that races a swap between check and open:

    * ``O_NONBLOCK`` — the open of a reader-less FIFO returns instead
      of blocking forever (no effect on regular-file reads).
    * ``fstat`` ``S_ISREG`` on the OPENED fd — the regularity verdict
      binds to the inode actually opened, not to a name that can be
      swapped between a check and the open.
    * ``follow_symlinks=False`` adds ``O_NOFOLLOW`` so a
      final-component symlink refuses with ``ELOOP`` — the posture
      for trust-bearing reads whose path must denote the file itself.

    Returns the open binary stream (its ``fileno()`` carries the
    verified inode for identity pinning). Raises ``ValueError`` for a
    non-regular file and ``OSError`` for open failures (``ELOOP``
    when ``follow_symlinks=False`` meets a link).
    """
    fh, _st = _open_gated(p, follow_symlinks=follow_symlinks)
    return fh


def read_bytes_gated(
    p: str | Path,
    max_bytes: int | None,
    *,
    follow_symlinks: bool = True,
    budget_error: type[ValueError] = ReadBudgetExceededError,
) -> bytes:
    """Open-then-fstat gated read of a required file, returning raw
    bytes.

    The byte-mode body behind :func:`read_text_gated` — identical
    gates, no decode — for callers that hash, archive, or re-serve
    the exact consumed bytes and therefore must not read twice (a
    second read could describe different bytes than the first).

    Both gates check the OPEN fd's inode, not a name that can be
    swapped between calls:

    * Regular files only — a FIFO stats as 0 bytes (passing any
      ``max_bytes``) and then BLOCKS the reader forever, a plantable
      hang for every consumer of files in another principal's write
      grant. ``O_NONBLOCK`` makes a FIFO/device open return instead
      of blocking (no effect on regular-file reads), so even the
      open itself can't hang. Symlink-to-regular resolves by default
      (``follow_symlinks=False`` adds ``O_NOFOLLOW`` to refuse a
      final-component link); symlink-to-FIFO is refused with the
      FIFO either way.
    * ``max_bytes`` — checked on the fstat size AND re-checked after
      a capped read, so a file that grows between fstat and read is
      refused instead of buffered unbounded (``core.json.bounded``
      closed exactly this window; same pattern here).

    Raises ``ValueError`` for non-regular files, *budget_error*
    (default :class:`ReadBudgetExceededError`, a ``ValueError``) for
    over-budget files — so a strict caller can report the refusal
    distinctly — and ``OSError`` for open/read failures (``ELOOP``
    when ``follow_symlinks=False`` meets a link).
    """
    fh, st = _open_gated(p, follow_symlinks=follow_symlinks)
    with fh:
        if max_bytes is not None and st.st_size > max_bytes:
            msg = (
                f"file size {st.st_size} bytes exceeds "
                f"max_bytes={max_bytes}: {p}"
            )
            raise budget_error(msg)
        raw = fh.read(max_bytes + 1 if max_bytes is not None else -1)
    if max_bytes is not None and len(raw) > max_bytes:
        msg = (
            f"file grew past max_bytes={max_bytes} during read: {p}"
        )
        raise budget_error(msg)
    return raw


def read_text_gated(
    p: str | Path,
    max_bytes: int | None,
    *,
    follow_symlinks: bool = True,
    encoding: str = "utf-8-sig",
    budget_error: type[ValueError] = ReadBudgetExceededError,
) -> str:
    """Open-then-fstat gated read of a required text file.

    Thin decode wrapper over :func:`read_bytes_gated` — one body
    carries the gates for both flavors (see there for the fd-checked
    regularity, O_NONBLOCK, and grow-recheck contract).

    Raises as :func:`read_bytes_gated`, plus ``UnicodeDecodeError``
    (a ``ValueError``) for bytes *encoding* cannot decode. The
    default ``utf-8-sig`` transparently strips a UTF-8 BOM and is
    byte-identical to ``utf-8`` for BOM-less files.
    """
    return read_bytes_gated(
        p,
        max_bytes,
        follow_symlinks=follow_symlinks,
        budget_error=budget_error,
    ).decode(encoding)
