"""Lifetime checks for a parsed REDB projection and caller-supplied read metadata.

Constructing this data does not authenticate a read, extraction or build. The
loader must capture the original metadata and digest at its own read boundary.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from math import isfinite
import os
from pathlib import Path
import re
import stat
from typing import Any

from core.json import iterencode_canonical


def _primitive_snapshot(value: Any) -> Any:
    """Copy only literal JSON data; the canonical encoder owns this copy."""
    if value is None or type(value) in (str, int, bool):
        return value
    if type(value) is float:
        if not isfinite(value):
            raise ValueError("non-finite projection value")
        return value
    if type(value) is list:
        return [_primitive_snapshot(item) for item in value]
    if type(value) is dict:
        copied: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError("non-string projection key")
            copied[key] = _primitive_snapshot(item)
        return copied
    raise ValueError("non-primitive projection value")


def database_projection_digest(database: Any, max_bytes: int) -> str | None:
    """Hash a bounded primitive public projection, without object coercion."""
    if type(max_bytes) is not int or max_bytes < 0:
        return None
    try:
        document = database.to_dict()
        if type(document) is not dict:
            return None
        # An owned primitive snapshot prevents late input mutation from
        # reaching canonical JSON's historical default=str conversion.
        primitive_document = _primitive_snapshot(document)
        digest = sha256()
        size = 0
        for chunk in iterencode_canonical(primitive_document):
            size += len(chunk)
            if size > max_bytes:
                return None
            digest.update(chunk)
        return digest.hexdigest()
    except Exception:
        return None


@dataclass(frozen=True)
class RedbReadScope:
    """Original read data supplied by a loader; not an authenticated receipt."""

    path: Path
    resolved_path: Path
    version: tuple[int, ...]
    max_bytes: int
    database: Any = field(compare=False, repr=False)
    projection_sha256: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.path, Path) or not isinstance(self.resolved_path, Path):
            raise ValueError("read paths must be Path objects")
        object.__setattr__(self, "path", Path(os.path.abspath(self.path)))
        if not self.resolved_path.is_absolute():
            raise ValueError("resolved read path must be absolute")
        if (type(self.version) is not tuple or len(self.version) != 5
                or any(type(item) is not int for item in self.version)):
            raise ValueError("read version must contain five literal integers")
        if type(self.max_bytes) is not int or self.max_bytes < 0:
            raise ValueError("read byte limit must be a non-negative literal integer")
        if self.projection_sha256 is not None and (
            type(self.projection_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self.projection_sha256) is None
        ):
            raise ValueError("projection digest must be a lowercase SHA256 or None")

    def file_current(self) -> bool:
        """Check the original path/version, without reading file content."""
        try:
            before = self.path.stat()
            if not stat.S_ISREG(before.st_mode) or before.st_size > self.max_bytes:
                return False
            if self.path.resolve(strict=True) != self.resolved_path:
                return False
            after = self.path.stat()
            return stat.S_ISREG(after.st_mode) and all(
                (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns) == self.version
                for item in (before, after)
            )
        except Exception:
            return False

    def current(self) -> bool:
        """Best-effort lifetime check; this is not an atomic filesystem guard."""
        return (self.projection_sha256 is not None and self.file_current()
                and database_projection_digest(self.database, self.max_bytes) == self.projection_sha256
                and self.file_current())
