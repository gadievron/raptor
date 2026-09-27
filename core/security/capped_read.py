"""Hardened, size-capped file read for config/trust scanners.

Owns the open-flags dance the CC-side and CodeQL-side trust scanners
previously each carried a private copy of. The cap stays with the
caller (the two scanners historically chose different limits), the
hardening lives here once.

Two axes of caller policy are parametrized so consumers with a
different ERROR CONTRACT (raise vs None) or SYMLINK STANCE (an
operator-named path may legitimately be a symlink) can still share
the one hardened dance instead of re-deriving it:

  * ``raise_on_refusal=True`` propagates the open/read ``OSError``
    and raises :class:`CappedReadRefused` (a ``ValueError``) on
    policy refusals — for callers whose degradation path is an
    exception handler rather than a ``None`` check.
  * ``follow_symlinks=True`` drops ``O_NOFOLLOW`` — ONLY for paths
    the operator named explicitly; target-controlled paths must keep
    the default refusal.

:func:`read_capped_text` layers the UTF-8 ``errors="replace"``
decode the text-consuming callers (build-config and manifest
parsers) all repeated.
"""

from __future__ import annotations

import os
import stat
from typing import TYPE_CHECKING, Literal, overload

if TYPE_CHECKING:
    from pathlib import Path


class CappedReadRefused(ValueError):
    """A policy refusal (not an OS error) from :func:`read_capped`.

    Raised only under ``raise_on_refusal=True``. ``ValueError``
    subclass so pre-existing ``except (OSError, ValueError)``
    degradation paths catch it unchanged. ``reason`` is machine-
    checkable: ``"not_regular"`` | ``"over_cap"`` | ``"grew_past_cap"``.
    ``st_mode``/``st_size`` come from the fstat of the actually-opened
    inode (never a racy path-level stat).
    """

    def __init__(
        self,
        message: str,
        *,
        reason: str,
        st_mode: int | None = None,
        st_size: int | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.st_mode = st_mode
        self.st_size = st_size


def _read_capped_or_raise(
    path: Path, max_bytes: int, *, follow_symlinks: bool,
) -> bytes:
    """The one hardened dance; raises on every refusal.

    O_NONBLOCK + fstat(S_ISREG) closes the FIFO-DoS and stat-vs-open
    TOCTOU holes. O_NOFOLLOW closes the symlink-redirect hole — the
    callers' walk-side symlink checks record symlinks as findings
    without reading them, but a TOCTOU race could swap a regular file
    for a symlink between that check and the open here; with
    O_NOFOLLOW the open fails with ELOOP. O_CLOEXEC keeps the fd from
    leaking across an unrelated concurrent exec. The fstat size gate
    refuses an over-cap file BEFORE any bytes are read (a planted
    multi-GiB blob must not cost a cap-sized read to refuse), and the
    ``max_bytes + 1`` read re-checks so a file that grew between
    fstat and read is refused rather than silently truncated.
    """
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    if not follow_symlinks:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise CappedReadRefused(
                f"not a regular file: {path}",
                reason="not_regular",
                st_mode=st.st_mode,
                st_size=st.st_size,
            )
        if st.st_size > max_bytes:
            raise CappedReadRefused(
                f"file size {st.st_size} exceeds {max_bytes} byte cap: "
                f"{path}",
                reason="over_cap",
                st_mode=st.st_mode,
                st_size=st.st_size,
            )
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read(max_bytes + 1)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    if len(data) > max_bytes:
        raise CappedReadRefused(
            f"file grew past {max_bytes} byte cap: {path}",
            reason="grew_past_cap",
        )
    return data


@overload
def read_capped(
    path: Path,
    max_bytes: int,
    *,
    follow_symlinks: bool = ...,
    raise_on_refusal: Literal[True],
) -> bytes: ...


@overload
def read_capped(
    path: Path,
    max_bytes: int,
    *,
    follow_symlinks: bool = ...,
    raise_on_refusal: Literal[False] = ...,
) -> bytes | None: ...


def read_capped(
    path: Path,
    max_bytes: int,
    *,
    follow_symlinks: bool = False,
    raise_on_refusal: bool = False,
) -> bytes | None:
    """Read up to ``max_bytes`` from ``path``; refuse oversized,
    non-regular, or unreadable files.

    Default contract (unchanged from the original chokepoint): None
    on any refusal, broad except — fail-closed is the safe stance for
    the trust scanners. With ``raise_on_refusal=True`` the caller
    gets the open/read ``OSError`` unswallowed and
    :class:`CappedReadRefused` (a ``ValueError``) for policy
    refusals. ``follow_symlinks=True`` drops ``O_NOFOLLOW`` for
    operator-named paths; the fstat regular-file check still refuses
    a non-regular final target.
    """
    if raise_on_refusal:
        return _read_capped_or_raise(
            path, max_bytes, follow_symlinks=follow_symlinks,
        )
    try:
        return _read_capped_or_raise(
            path, max_bytes, follow_symlinks=follow_symlinks,
        )
    except Exception:  # noqa: BLE001 — any I/O surprise fails closed
        return None


@overload
def read_capped_text(
    path: Path,
    max_bytes: int,
    *,
    encoding: str = ...,
    errors: str = ...,
    follow_symlinks: bool = ...,
    raise_on_refusal: Literal[True],
) -> str: ...


@overload
def read_capped_text(
    path: Path,
    max_bytes: int,
    *,
    encoding: str = ...,
    errors: str = ...,
    follow_symlinks: bool = ...,
    raise_on_refusal: Literal[False] = ...,
) -> str | None: ...


def read_capped_text(
    path: Path,
    max_bytes: int,
    *,
    encoding: str = "utf-8",
    errors: str = "replace",
    follow_symlinks: bool = False,
    raise_on_refusal: bool = False,
) -> str | None:
    """:func:`read_capped` plus the decode step every text consumer
    repeated. ``errors="replace"`` by default so adversarial byte
    sequences surface as U+FFFD instead of crashing the caller's
    parser (the cap is byte-level; decoding happens after the read
    is accepted).

    The error contract covers the decode too: in the default no-raise
    mode a decode failure (a caller-passed ``errors="strict"`` on
    undecodable bytes) returns None like any other refusal, so no
    ``errors=`` policy lets an exception escape. Under
    ``raise_on_refusal=True`` the ``UnicodeDecodeError`` propagates,
    exactly like the open/read ``OSError``.
    """
    if raise_on_refusal:
        return read_capped(
            path, max_bytes,
            follow_symlinks=follow_symlinks, raise_on_refusal=True,
        ).decode(encoding, errors=errors)
    raw = read_capped(
        path, max_bytes, follow_symlinks=follow_symlinks,
    )
    if raw is None:
        return None
    try:
        return raw.decode(encoding, errors=errors)
    except UnicodeDecodeError:
        return None
