"""Repeatable bounded findings traversal without retaining the whole document."""
from __future__ import annotations

from collections.abc import Sequence
from itertools import islice
from pathlib import Path
import os

from core.json.projection import iter_array
from core.source.gated import open_regular_gated, ReadBudgetExceededError
from .kinds import MAX_FINDINGS_BYTES


class FindingsFile(Sequence):
    """A local findings array, decoded one row at a time on each traversal."""

    def __init__(self, path: Path, *, max_bytes=MAX_FINDINGS_BYTES):
        self.path = path
        self.max_bytes = max_bytes
        self._count = None

    def __iter__(self):
        with open_regular_gated(self.path) as stream:
            if os.fstat(stream.fileno()).st_size > self.max_bytes:
                raise ReadBudgetExceededError(f"findings exceeds max_bytes={self.max_bytes}")
            yield from iter_array(stream, max_bytes=self.max_bytes, max_depth=64)

    def __len__(self):
        if self._count is None:
            self._count = sum(1 for _ in self)
        return self._count

    def __getitem__(self, key):
        if isinstance(key, slice):
            start, stop, step = key.indices(len(self))
            if step < 0:
                return list(self)[key]
            return list(islice(iter(self), start, stop, step))
        if key < 0:
            key += len(self)
        if key < 0:
            raise IndexError(key)
        try:
            return next(islice(iter(self), key, key + 1))
        except StopIteration:
            raise IndexError(key) from None
