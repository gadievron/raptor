"""Bounded bytes for explicitly declared dependency references.

These observations do not discover a dependency closure or establish an
immutable namespace/build epoch. Rechecking old references cannot detect a new
header or changed negative include lookup. No preparation authority is minted.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path

from core.source import open_regular_beneath
from core.source.streams import preserving_stream_error

from .refutation_source import SourceIdentity


@dataclass(frozen=True)
class DependencyReference:
    root: str
    path: str


@dataclass(frozen=True)
class DependencyMaterial:
    reference: DependencyReference
    content: bytes
    identity: SourceIdentity


@dataclass(frozen=True)
class DependencyMaterialUnavailable:
    reason: str
    reference: DependencyReference | None = None


def _version(st) -> tuple[int, ...]:
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns


def _valid_reference(reference: DependencyReference) -> bool:
    return (type(reference) is DependencyReference
            and isinstance(reference.root, str) and bool(reference.root) and "\0" not in reference.root
            and isinstance(reference.path, str) and bool(reference.path)
            and "\0" not in reference.path and "\\" not in reference.path
            and not Path(reference.path).is_absolute()
            and all(part not in {"", ".", ".."} for part in reference.path.split("/"))
            and ":" not in reference.path)


def capture_dependency_materials(
    references: tuple[DependencyReference, ...], *, roots: Mapping[str, Path],
    max_files: int, max_file_bytes: int, max_total_bytes: int,
) -> tuple[DependencyMaterial, ...] | DependencyMaterialUnavailable:
    """Capture complete declared files or return one explicit refusal.

    Limits are positive integers; declaration count applies before exact
    deduplication. Actual payload reads total at most ``max_total_bytes + 1``
    (the extra byte detects growth). All paths open through the existing
    anchored regular-file reader. The final stamp pass detects observed drift
    across this capture, but does not make the group atomic or exclude ABA.
    """
    if any(type(cap) is not int or cap < 1 for cap in (max_files, max_file_bytes, max_total_bytes)):
        return DependencyMaterialUnavailable("invalid_dependency_material_budget")
    if type(references) is not tuple or len(references) > max_files:
        return DependencyMaterialUnavailable("dependency_material_count_budget")
    if any(not _valid_reference(reference) for reference in references):
        return DependencyMaterialUnavailable("invalid_dependency_reference")
    selected = tuple(dict.fromkeys(references))
    material: list[DependencyMaterial] = []
    root_paths: dict[str, Path] = {}
    for reference in selected:
        if reference.root in root_paths:
            continue
        root = roots.get(reference.root)
        if root is None:
            return DependencyMaterialUnavailable("unknown_dependency_root", reference)
        try:
            root_paths[reference.root] = Path(root)
        except (TypeError, ValueError):
            return DependencyMaterialUnavailable("invalid_dependency_root", reference)
    total = 0
    for reference in selected:
        try:
            stream = open_regular_beneath(root_paths[reference.root], Path(reference.path), "rb")
            if stream is None:
                return DependencyMaterialUnavailable("dependency_material_unavailable", reference)
            with preserving_stream_error(stream):
                before = os.fstat(stream.fileno())
                if before.st_size > max_file_bytes:
                    return DependencyMaterialUnavailable("dependency_file_byte_budget", reference)
                if before.st_size > max_total_bytes - total:
                    return DependencyMaterialUnavailable("dependency_total_byte_budget", reference)
                content = stream.read(before.st_size + 1)
                after = os.fstat(stream.fileno())
            if len(content) != before.st_size or _version(before) != _version(after):
                return DependencyMaterialUnavailable("dependency_changed_during_read", reference)
            total += len(content)
            material.append(DependencyMaterial(reference, content, SourceIdentity(
                hashlib.sha256(content).hexdigest(), _version(after))))
        except (OSError, ValueError, RuntimeError):
            return DependencyMaterialUnavailable("dependency_material_read_failed", reference)
    for item in material:
        try:
            stream = open_regular_beneath(root_paths[item.reference.root], Path(item.reference.path), "rb")
            if stream is None:
                return DependencyMaterialUnavailable("dependency_material_unavailable", item.reference)
            with preserving_stream_error(stream):
                version = _version(os.fstat(stream.fileno()))
            if version != item.identity.version:
                return DependencyMaterialUnavailable("dependency_capture_changed", item.reference)
        except (OSError, ValueError, RuntimeError):
            return DependencyMaterialUnavailable("dependency_material_read_failed", item.reference)
    return tuple(material)


def dependency_materials_current(
    materials: tuple[DependencyMaterial, ...], *, references: tuple[DependencyReference, ...],
    roots: Mapping[str, Path], max_files: int, max_file_bytes: int, max_total_bytes: int,
) -> bool:
    """Compare this entire supplied reference group, not namespace completeness."""
    if type(materials) is not tuple or any(type(item) is not DependencyMaterial for item in materials):
        return False
    current = capture_dependency_materials(references, roots=roots, max_files=max_files,
                                          max_file_bytes=max_file_bytes, max_total_bytes=max_total_bytes)
    return isinstance(current, tuple) and current == materials
