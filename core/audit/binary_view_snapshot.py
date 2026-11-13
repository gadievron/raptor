"""Cached implementation-view observations, never extraction correspondence."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .binary_review_scope import (
    BinaryInputIdentity, BinaryModuleSnapshot, capture_binary_module,
    capture_binary_publication_scope,
)
from .redb_read_scope import RedbReadScope


@dataclass(frozen=True)
class BinaryViewSnapshot:
    """Original parsed data and module lifetime for cached-only view assembly.

    Metadata declaring module bytes is required but is not verified extraction
    or build correspondence. This object must remain pipeline-owned.
    """
    read_scope: RedbReadScope
    module: BinaryModuleSnapshot

    def current(self) -> bool:
        metadata = getattr(self.read_scope.database, "metadata", None)
        return (isinstance(metadata, dict) and metadata.get("binary_sha256") == self.module.sha256
                and self.read_scope.current() and self.module.current())

    def _owned_inventory(self) -> dict:
        from core.inventory.binary_builder import build_binary_checklist
        return build_binary_checklist(self.read_scope.database, binary_path=self.module.path,
                                      include_auto_named=True, min_size=0)

    def view_identity(self, *, file: str, function: str, checklist: dict) -> BinaryInputIdentity | None:
        """Observe the sanitised assembler view without launching a backend."""
        if not self.current():
            return None
        identity = self._observe(file=file, function=function, checklist=checklist,
                                 owned=self._owned_inventory())
        return identity if self.current() else None

    def view_identities(self, checklist: dict) -> dict[str, BinaryInputIdentity]:
        """Bracket bulk assembly with two original parsed-projection checks."""
        from core.coverage.journal import make_function_key
        if not self.current():
            return {}
        owned = self._owned_inventory()
        identities = {}
        files = checklist.get("files")
        for entry in files if isinstance(files, list) else []:
            if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                continue
            items = entry.get("items", entry.get("functions"))
            for item in items if isinstance(items, list) else []:
                if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                    continue
                identity = self._observe(file=entry["path"], function=item["name"],
                                         checklist=checklist, owned=owned)
                if identity is not None:
                    identities[make_function_key(entry["path"], item["name"])] = identity
        return identities if self.current() else {}

    def _observe(self, *, file: str, function: str, checklist: dict,
                 owned: dict) -> BinaryInputIdentity | None:
        from core.inventory.binary_builder import binary_path_key
        from .binary_context import assemble_binary_context
        if file != binary_path_key(self.module.path):
            return None
        accepted = _inventory_item(owned, file, function)
        supplied = _inventory_item(checklist, file, function)
        if not isinstance(accepted, dict) or not isinstance(supplied, dict):
            return None
        for item in (accepted, supplied):
            metadata = item.get("metadata")
            if not isinstance(metadata, dict):
                return None
            if any(type(item.get(key)) is not int or type(metadata.get(key)) is not int
                   or item[key] != metadata[key] for key in ("address", "size")):
                return None
        if any(accepted[key] != supplied[key] for key in ("address", "size")):
            return None
        ctx = assemble_binary_context(target_path=self.module.path, file_path=file,
            function_name=function, checklist=owned,
            db=self.read_scope.database, cached_only=True)
        assembled_module = ctx.get("_binary_module_snapshot")
        if not isinstance(assembled_module, BinaryModuleSnapshot) or assembled_module != self.module:
            return None
        scope = capture_binary_publication_scope(ctx, assembled_module)
        if scope is None or scope.view_identity is None or not scope.current(self.module.path):
            return None
        return scope.view_identity


def capture_binary_view_snapshot(read_scope: RedbReadScope, target_path: Path) -> BinaryViewSnapshot | None:
    """Bind an original accepted read to declared current module bytes."""
    module = capture_binary_module(target_path)
    metadata = getattr(read_scope.database, 'metadata', None)
    if (module is None or not isinstance(metadata, dict)
            or metadata.get('binary_sha256') != module.sha256):
        return None
    snapshot = BinaryViewSnapshot(read_scope, module)
    return snapshot if snapshot.current() else None


def _inventory_item(checklist: dict, file: str, function: str) -> dict | None:
    files = checklist.get("files")
    if not isinstance(files, list):
        return None
    matches: list[dict] = []
    for entry in files:
        if not isinstance(entry, dict) or entry.get("path") != file:
            continue
        items = entry.get("items", entry.get("functions"))
        if not isinstance(items, list):
            return None
        matches.extend(item for item in items
                       if isinstance(item, dict) and item.get("name") == function)
    return matches[0] if len(matches) == 1 else None
