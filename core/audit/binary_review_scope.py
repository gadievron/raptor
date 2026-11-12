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


@dataclass(frozen=True)
class BinaryReviewPublicationScope:
    """One recorded binary occurrence and its original live module bytes.

    Address and size are recorded view metadata, not a decoded extent, FID,
    image-base proof or correspondence between instructions and decompilation.
    """
    module: BinaryModuleSnapshot
    file: str
    function: str
    address: int
    size: int

    def record(self) -> dict:
        return {"version": 1, "domain": "binary_module", "file": self.file,
                "function": self.function, "module_sha256": self.module.sha256,
                "address": self.address, "size": self.size}

    def matches(self, outcome, gap: dict) -> bool:
        from .record import _as_int

        metadata = gap.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        address = gap.get("address", metadata.get("address"))
        size = gap.get("size", metadata.get("size"))
        return ((outcome.file, outcome.function) == (self.file, self.function)
                and type(outcome.line) is int and outcome.line == 0
                and gap.get("file") == self.file
                and gap.get("name", gap.get("function")) == self.function
                and type(gap.get("line_start", 0)) is int and gap.get("line_start", 0) == 0
                and (gap.get("line_end") is None
                     or type(gap.get("line_end")) is int and gap.get("line_end") == 0)
                # Gap projections may omit address/size. The collector also
                # requires the checklist-derived full anchor to match this
                # scope, so an omitted projection never supplies an extent.
                and (address is None or _as_int(address) == self.address)
                and (size is None or _as_int(size) == self.size))

    def current(self, target_path) -> bool:
        try:
            return Path(target_path).absolute() == self.module.path and self.module.current()
        except (TypeError, ValueError, OSError, RuntimeError):
            return False

    def anchor(self) -> str:
        from .record import binary_item_hash

        value = binary_item_hash({"sha256": self.module.sha256},
                                 {"address": self.address, "size": self.size})
        assert value is not None
        return value


def capture_binary_publication_scope(ctx: dict, module: BinaryModuleSnapshot) -> BinaryReviewPublicationScope | None:
    from core.inventory.binary_builder import BINARY_PATH_PREFIX

    file, function = ctx.get("file"), ctx.get("function")
    address = ctx.get("address")
    metadata = ctx.get("metadata")
    size = metadata.get("size") if isinstance(metadata, dict) else None
    if (not isinstance(file, str) or not file.startswith(BINARY_PATH_PREFIX)
            or not isinstance(function, str) or not function
            or type(address) is not int or address < 0 or type(size) is not int or size <= 0):
        return None
    return BinaryReviewPublicationScope(module, file, function, address, size)
