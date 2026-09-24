"""Raising-flavor gated text read — the strict sibling of
:mod:`core.source.contained`.

The capped readers in :mod:`core.source.contained` are None-flavor:
every refusal (unreadable, non-regular, over-cap) collapses into one
"no text" answer, which suits best-effort analysis reads. Loaders
with a REQUIRED file — config, budget-gated JSON, spec documents —
need the opposite: each refusal class surfaces as a distinct
exception so the caller can report it (and only it) precisely.
:func:`read_text_gated` is the single body for that flavor; it grew
up as ``core.json.utils._read_text_gated`` backing ``load_json`` and
is promoted here so non-JSON strict readers consume the same
discipline instead of re-growing their own fstat/budget idiom
(``core.json.utils`` imports THIS implementation — one body, both
flavors' doctrine in one module family).

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

__all__ = ["ReadBudgetExceededError", "read_text_gated"]


class ReadBudgetExceededError(ValueError):
    """A gated read refused a file for exceeding its byte budget.

    Subclasses ``ValueError`` so pre-existing ``except ValueError``
    handlers keep refusing gracefully; strict callers catch THIS
    class to report the budget refusal distinctly (an over-budget
    required file is actionable — raise the budget or shrink the
    file — where a malformed one is not).
    """


def read_text_gated(
    p: str | Path,
    max_bytes: int | None,
    *,
    follow_symlinks: bool = True,
    encoding: str = "utf-8-sig",
    budget_error: type[ValueError] = ReadBudgetExceededError,
) -> str:
    """Open-then-fstat gated read of a required text file.

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
    distinctly — ``OSError`` for open/read failures (``ELOOP`` when
    ``follow_symlinks=False`` meets a link), and
    ``UnicodeDecodeError`` (a ``ValueError``) for bytes *encoding*
    cannot decode. The default ``utf-8-sig`` transparently strips a
    UTF-8 BOM and is byte-identical to ``utf-8`` for BOM-less files.
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
        if max_bytes is not None and st.st_size > max_bytes:
            msg = (
                f"file size {st.st_size} bytes exceeds "
                f"max_bytes={max_bytes}: {p}"
            )
            raise budget_error(msg)
        with os.fdopen(fd, "rb") as fh:
            fd = -1  # fdopen owns it now
            raw = fh.read(max_bytes + 1 if max_bytes is not None else -1)
        if max_bytes is not None and len(raw) > max_bytes:
            msg = (
                f"file grew past max_bytes={max_bytes} during read: {p}"
            )
            raise budget_error(msg)
        return raw.decode(encoding)
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
