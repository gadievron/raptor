"""Owned conditional integer-layout material, never binary proof authority."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, cast

from core.json import dumps_canonical, loads

from .integer_abi import IntegerABI, IntegerABIInput, resolve_integer_abi, select_integer_abi
from .integer_abi_context import compare_integer_abi


def _canonical_material(value: object) -> str | None:
    """Reject coercion and bound checks of a possibly replaced context value."""
    nodes_left = 256
    characters_left = 16384

    invalid = object()

    def primitive(item: object) -> object:
        nonlocal nodes_left, characters_left
        nodes_left -= 1
        if nodes_left < 0:
            return invalid
        if item is None or type(item) is bool:
            return item
        if type(item) is int:
            return item if item.bit_length() <= 64 else invalid
        if type(item) is str:
            characters_left -= len(item)
            return item if characters_left >= 0 else invalid
        if type(item) is list:
            if len(item) > nodes_left:
                return invalid
            copied = []
            for child in item:
                value = primitive(child)
                if value is invalid:
                    return invalid
                copied.append(value)
            return copied
        if type(item) is dict:
            if len(item) > nodes_left:
                return invalid
            result = {}
            for key, child in item.items():
                if type(key) is not str or primitive(key) is invalid:
                    return invalid
                value = primitive(child)
                if value is invalid:
                    return invalid
                result[key] = value
            return result
        return invalid

    try:
        if type(value) is not dict:
            return None
        owned = primitive(value)
        if owned is invalid:
            return None
        encoded = dumps_canonical(owned)
        return encoded if len(encoded.encode("utf-8")) <= 16384 else None
    except (TypeError, ValueError, UnicodeError, RecursionError, RuntimeError):
        return None


@dataclass(frozen=True)
class BinaryIntegerContext:
    """One immutable rendered assumption snapshot and its original selection.

    Rechecking platform metadata is best effort. Neither this snapshot nor a
    matching digest establishes build options, source types or checker facts.
    """
    selection: IntegerABI | None
    target_path: Path
    _material_json: str

    def __post_init__(self) -> None:
        if (not isinstance(self.target_path, Path) or not self.target_path.is_absolute()
                or (self.selection is not None and type(self.selection) is not IntegerABI)
                or type(self._material_json) is not str):
            raise ValueError("binary integer context requires original immutable inputs")
        material = loads(self._material_json, max_bytes=16384)
        expected = self.selection.record() if self.selection is not None else None
        if (_canonical_material(material) != self._material_json
                or material.get("selected") != expected):
            raise ValueError("binary integer context requires canonical selected material")

    @property
    def material(self) -> dict[str, Any]:
        """Return a fresh context value, retaining the original immutable text."""
        return cast(dict[str, Any], loads(self._material_json, max_bytes=16384))

    @property
    def digest(self) -> str:
        return sha256(b"binary-integer-material/v1\0" + self._material_json.encode("utf-8")).hexdigest()

    def current(self, material: object) -> bool:
        """Refuse context edits or observed changes; never adopt a new record."""
        try:
            return (_canonical_material(material) == self._material_json
                    and _canonical_material(compare_integer_abi(
                        self.selection, target_path=self.target_path)) == self._material_json)
        except (OSError, TypeError, ValueError, UnicodeError, RecursionError):
            return False

    def render(self) -> str:
        return ("### Selected integer-layout assumptions\n"
                "Conditional assumptions, not verification evidence.\n"
                + self._material_json)


def capture_binary_integer_context(
    value: IntegerABIInput, *, target_path: Path,
) -> BinaryIntegerContext | None:
    """Freeze the existing selector's result, including explicit unknown."""
    target = Path(target_path).absolute()
    if target.is_dir():
        return None
    selected = resolve_integer_abi(select_integer_abi(value, target_path=target))
    if selected is not None:
        # Keep an exact frozen layout, independent of the caller's input dict.
        selected = IntegerABI(**selected.record())
    material = _canonical_material(compare_integer_abi(selected, target_path=target))
    return BinaryIntegerContext(selected, target, material) if material is not None else None
