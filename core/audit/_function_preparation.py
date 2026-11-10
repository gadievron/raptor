"""Bounded native function rows shared by successive Python checks."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any
import re

_TYPE = (0).__class__.__class__
_STR = ''.__class__
_INT = (0).__class__
_LIST: type[list[Any]] = [].__class__
_TUPLE: type[tuple[Any, ...]] = ().__class__
_DICT: type[dict[Any, Any]] = {}.__class__
_FUNCTION = (lambda: None).__class__
_BUILTIN_FUNCTION: type = [].append.__class__
_PATTERN = re.Pattern
_EXCEPTION = Exception


def _length(value: Any) -> int:
    # Call only after exact native container admission.
    return value.__len__()


class FunctionPreparation:
    """One bounded immutable value, with a fresh list for each consumer."""

    __slots__ = ('key', 'rows', 'hits', 'misses', 'fallbacks')

    key: tuple[object, ...] | None
    rows: tuple[tuple[str, int, str], ...] | None
    hits: int
    misses: int
    fallbacks: int

    def __init__(self) -> None:
        self.key = None
        self.rows = None
        self.hits = self.misses = self.fallbacks = 0

    def release(self) -> None:
        self.key = self.rows = None

    @staticmethod
    def _key(source: object, exporter: Any) -> tuple[object, ...] | None:
        if _TYPE(source) is not _STR or _TYPE(exporter) is not _FUNCTION:
            return None
        ns = exporter.__globals__
        if _TYPE(ns) is not _DICT:
            return None
        for key in ns:
            if _TYPE(key) is not _STR:
                return None
        marker = ns.get('_FUNCTION_EXTRACTION_NATIVE_STATE')
        if _TYPE(marker) is not _TUPLE or _length(marker) != 7:
            return None
        function, code, pattern, original_pattern, type_fn, str_type, len_fn = marker
        if (type_fn is not _TYPE or str_type is not _STR
                or _TYPE(len_fn) is not _BUILTIN_FUNCTION
                or _TYPE(len_fn.__name__) is not _STR or len_fn.__name__ != 'len'
                or _TYPE(len_fn.__module__) is not _STR or len_fn.__module__ != 'builtins'):
            return None
        if (exporter is not function or exporter.__code__ is not code
                or _TYPE(pattern) is not _PATTERN or pattern is not original_pattern
                or ns.get('_FUNC_DEF_RE') is not pattern
                or ns.get('_FUNC_DEF_IMPL') is not original_pattern):
            return None
        builtins = exporter.__builtins__
        if _TYPE(builtins) is not _DICT:
            return None
        for key in builtins:
            if _TYPE(key) is not _STR:
                return None
        for name, expected in (('type', type_fn), ('str', str_type), ('len', len_fn)):
            if ns.get(name, builtins.get(name)) is not expected:
                return None
        return source, exporter, code, pattern, marker, type_fn, str_type, len_fn

    def get(
        self, source: str, exporter: Callable[[str], Any],
        pure_consumers: Callable[[], bool],
    ) -> list:
        try:
            key = self._key(source, exporter) if pure_consumers() else None
        except _EXCEPTION:
            key = None
        if key is None:
            self.release()
            self.fallbacks += 1
            return exporter(source)
        old_key, old_rows = self.key, self.rows
        if old_key is not None and old_rows is not None:
            same = True
            index = 0
            while same and index < _length(key):
                same = key[index] is old_key[index]
                index += 1
            if same:
                try:
                    fresh = _LIST(old_rows)
                except _EXCEPTION:
                    self.release()
                    return exporter(source)
                self.hits += 1
                return fresh
        self.release()
        result = exporter(source)  # Producer errors propagate and store nothing.
        self.misses += 1
        if _TYPE(result) is not _LIST or _length(result) > 512:
            return result
        characters = 0
        for row in result:
            if (_TYPE(row) is not _TUPLE or _length(row) != 3
                    or _TYPE(row[0]) is not _STR or _TYPE(row[1]) is not _INT
                    or _TYPE(row[2]) is not _STR):
                return result
            characters += _length(row[0]) + _length(row[2])
            if characters > 500_000:
                return result
        try:
            rows = _TUPLE(result)
        except _EXCEPTION:
            return result
        self.key, self.rows = key, rows
        return result
