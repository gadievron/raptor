"""Read the labs admission header without putting its value on the command line."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path


HEADER_NAME = "X-Origin-Verify"
_VALUE = re.compile(r"[0-9a-fA-F]{64}\Z")


def validate_value(value: str) -> str:
    if not isinstance(value, str) or not _VALUE.fullmatch(value):
        raise ValueError("origin verification value must be 64 hexadecimal characters")
    return value


def with_origin_header(headers: tuple[str, ...], value: str) -> tuple[str, ...]:
    """Set the target admission header once in a private tool config."""
    validate_value(value)
    kept = tuple(
        header for header in headers
        if header.split(":", 1)[0].strip().lower() != HEADER_NAME.lower()
    )
    return (*kept, f"{HEADER_NAME}: {value}")


def read_value(path: str | Path) -> str:
    """Read a private, regular, owner-only file without following symlinks."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        try:
            mode = os.fstat(fd).st_mode
            if not stat.S_ISREG(mode) or mode & 0o077:
                raise ValueError("origin verification file must be regular and owner-only")
            data = os.read(fd, 129)
        finally:
            os.close(fd)
    except OSError as exc:
        raise ValueError("cannot read origin verification file") from exc
    if len(data) > 128:
        raise ValueError("origin verification file is too large")
    try:
        return validate_value(data.decode("ascii").strip())
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("origin verification file has invalid content") from exc
