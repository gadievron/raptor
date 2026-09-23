"""Symbol-name normalisation: prefix stripping must not conflate
underscore-significant libc names with their unprefixed cousins."""

from __future__ import annotations

from packages.binary_analysis._symbols import (
    strip_import_prefix,
    symbol_base_name,
)


def test_import_prefixes_stripped():
    assert strip_import_prefix("sym.imp.read") == "read"
    assert strip_import_prefix("imp.read") == "read"
    assert strip_import_prefix("__imp_read") == "read"
    assert strip_import_prefix("_read") == "read"


def test_underscore_significant_libc_names_preserved():
    # _exit is not exit (no atexit handlers); _setjmp/_longjmp are the
    # no-signal-mask variants — stripping the underscore conflates two
    # distinct functions in the tier-1 fingerprints.
    assert strip_import_prefix("_exit") == "_exit"
    assert strip_import_prefix("_Exit") == "_Exit"
    assert strip_import_prefix("_setjmp") == "_setjmp"
    assert strip_import_prefix("_longjmp") == "_longjmp"
    # ...including when they arrive under an r2 import prefix.
    assert strip_import_prefix("sym.imp._exit") == "_exit"


def test_symbol_base_name_keeps_last_segment():
    assert symbol_base_name("sym.imp.libc.so.6.read") == "read"
