"""Live binary-module stamps for review dispatch, never checker evidence.

A module stamp binds observed file bytes and their physical version. It does
not establish extraction correspondence, image base, ABI or build closure.
It is transient and must not be restored from model output or journal JSON.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BinaryModuleSnapshot:
    path: Path
    resolved_path: Path
    sha256: str
    version: tuple[int, ...]

    def current(self) -> bool:
        return capture_binary_module(self.path) == self


def capture_binary_module(path: Path | str) -> BinaryModuleSnapshot | None:
    """Capture a stable regular module using the existing full-content reader.

    A project container is not its selected binary. Until a selected module
    is available explicitly it remains unknown here. Before/after checks are
    best effort; they do not make a mutable module immutable.
    """
    from .binary_context import _binary_content_version, _target_content_sha

    try:
        candidate = Path(path).absolute()
        if candidate.suffix.lower() == ".gpr":
            return None
        resolved = candidate.resolve()
        before = _binary_content_version(candidate.stat())
        digest = _target_content_sha(candidate)
        if (digest is None or candidate.resolve() != resolved
                or _binary_content_version(candidate.stat()) != before):
            return None
        return BinaryModuleSnapshot(candidate, resolved, digest, before)
    except (OSError, ValueError, TypeError, RuntimeError):
        return None
