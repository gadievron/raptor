"""Owned acquisition of compilation declarations, without build authentication."""

from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from threading import RLock

from .prepared_declaration_custody import DeclarationOwner, SelectedDeclaration
from .prepared_dependency_material import (
    DependencyMaterialUnavailable, DependencyReference, capture_dependency_materials,
)
from .prepared_invocation_candidate import CandidateUnavailable
from .refutation_source import SourceIdentity


@dataclass(frozen=True)
class AcquiredDeclaration:
    reference: DependencyReference
    source_identity: SourceIdentity
    selected: SelectedDeclaration

    @property
    def authenticated_build(self) -> bool:
        return False


class CompilationDatabaseOwner:
    """Serialize bounded file acquisition and identity-owned declaration custody.

    Roots and build associations are caller declarations, not measured build
    authority. IO occurs under this owner's lock. Retention budgets count payload
    bytes and records, not Python heap usage. File stamps detect observed drift,
    not an atomic filesystem epoch or complete compiler search namespace.
    """

    def __init__(self, roots: Mapping[str, Path], *, max_retained_bytes: int,
                 max_captures: int, max_selections: int):
        self._declarations = DeclarationOwner(max_retained_bytes=max_retained_bytes,
                                             max_captures=max_captures,
                                             max_selections=max_selections)
        self._roots = {name: Path(path) for name, path in roots.items()}
        self._issued: dict[int, AcquiredDeclaration] = {}
        self._closed = False
        self._lock = RLock()

    @property
    def retained_payload_bytes(self) -> int:
        with self._lock:
            return self._declarations.retained_payload_bytes

    def acquire(self, reference: DependencyReference, translation_unit: str, *,
                declared_build_association: str, max_database_bytes: int,
                max_entries: int, max_entry_bytes: int, max_depth: int) -> AcquiredDeclaration:
        """Acquire exactly one supplied reference and select one original entry.

        Refusals raise CandidateUnavailable. No dictionary reserialization,
        shell parsing, response expansion or freshness renewal takes place.
        An unsuccessful selection releases its unpublished capture even when
        parsing is interrupted. Existing issued acquisitions are unaffected.
        """
        with self._lock:
            if self._closed:
                raise CandidateUnavailable("owner_closed")
            if any(type(cap) is not int or cap < 1 for cap in
                   (max_database_bytes, max_entries, max_entry_bytes, max_depth)):
                raise CandidateUnavailable("invalid_acquisition_budget")
            material = capture_dependency_materials(
                (reference,), roots=self._roots, max_files=1,
                max_file_bytes=max_database_bytes, max_total_bytes=max_database_bytes)
            if isinstance(material, DependencyMaterialUnavailable):
                raise CandidateUnavailable(material.reason)
            captured = material[0]
            capture = None
            acquired = None
            committed = False
            try:
                capture = self._declarations.capture(
                    captured.content, declared_build_association=declared_build_association,
                    max_database_bytes=max_database_bytes, max_entries=max_entries,
                    max_entry_bytes=max_entry_bytes, max_depth=max_depth)
                selected = self._declarations.select(
                    capture, translation_unit, max_entry_bytes=max_entry_bytes,
                    max_entries=max_entries)
                acquired = AcquiredDeclaration(captured.reference, captured.identity, selected)
                self._issued[id(acquired)] = acquired
                committed = True
                return acquired
            finally:
                if acquired is not None and not committed:
                    with suppress(BaseException):
                        self._issued.pop(id(acquired), None)
                if capture is not None and not committed:
                    # A cleanup diagnostic must not replace the parsing primary.
                    with suppress(BaseException):
                        self._declarations.release_capture(capture)

    def retains(self, acquired: AcquiredDeclaration) -> bool:
        with self._lock:
            return (type(acquired) is AcquiredDeclaration and not self._closed
                    and self._issued.get(id(acquired)) is acquired
                    and self._declarations.retains(acquired.selected))

    def release(self, acquired: AcquiredDeclaration) -> bool:
        with self._lock:
            if type(acquired) is not AcquiredDeclaration or self._issued.get(id(acquired)) is not acquired:
                return False
            self._declarations.release_capture(acquired.selected.capture)
            del self._issued[id(acquired)]
            return True

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._issued.clear()
            self._declarations.close()
