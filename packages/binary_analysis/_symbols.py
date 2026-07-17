"""Shared symbol name normalisation for binary analysis modules."""

from __future__ import annotations

_IMPORT_PREFIXES = ("sym.imp.", "imp.", "__imp_", "_")


def strip_import_prefix(name: str) -> str:
    """Remove radare2 / linker import prefixes, keeping dotted segments."""
    value = str(name or "")
    for prefix in _IMPORT_PREFIXES:
        if value.startswith(prefix):
            value = value[len(prefix):]
    return value


def symbol_base_name(name: str) -> str:
    """Strip import prefixes then take the last dotted segment."""
    return strip_import_prefix(name).split(".")[-1]
