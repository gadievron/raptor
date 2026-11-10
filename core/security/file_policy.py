"""Permission policies for metadata from an already opened inode.

This module performs no I/O and imports only the standard library. File kind,
path resolution, descriptor ownership and error translation belong to callers.
"""

from __future__ import annotations

import os
import stat
from typing import Literal


class FilePermissionRefused(ValueError):
    """A metadata-policy refusal, distinct from a failed metadata read."""

    def __init__(self, reason: Literal["owner", "mode", "links"], metadata: os.stat_result):
        super().__init__(f"file permission policy refused: {reason}")
        self.reason = reason
        self.metadata = metadata


def validate_file_permissions(
    metadata: os.stat_result,
    *,
    owner_uid: int | None = None,
    forbidden_mode_bits: int = 0,
    require_single_link: bool = False,
) -> None:
    """Validate one fstat snapshot without reading or reopening the file.

    Every constraint is explicit: the default imposes no permission policy.
    ``0o077`` forbids group/other access; ``0o022`` forbids their writes while
    allowing reads. The caller supplies the intended real/effective UID.
    A single-link rule is appropriate only for consumers that require it.
    """
    if owner_uid is not None and (type(owner_uid) is not int or owner_uid < 0):
        raise ValueError("owner_uid must be a non-negative integer or None")
    if type(forbidden_mode_bits) is not int or not 0 <= forbidden_mode_bits <= 0o7777:
        raise ValueError("forbidden_mode_bits must be permission bits between 0 and 0o7777")
    if type(require_single_link) is not bool:
        raise ValueError("require_single_link must be a bool")
    if owner_uid is not None and metadata.st_uid != owner_uid:
        raise FilePermissionRefused("owner", metadata)
    if stat.S_IMODE(metadata.st_mode) & forbidden_mode_bits:
        raise FilePermissionRefused("mode", metadata)
    if require_single_link and metadata.st_nlink != 1:
        raise FilePermissionRefused("links", metadata)
