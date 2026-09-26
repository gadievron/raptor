"""Shared symbol name normalisation for binary analysis modules."""

from __future__ import annotations

_IMPORT_PREFIXES = ("sym.imp.", "imp.", "__imp_", "_")

# Names where the leading underscore IS the identity, not a Mach-O
# global-symbol decoration: stripping it conflates two distinct
# functions in the tier-1 fingerprints and classify_security_api
# (_exit is not exit — no atexit handlers; _setjmp/_longjmp are the
# no-signal-mask variants of setjmp/longjmp). The Windows CRT/SEH
# names below are exported WITH their underscores (_mbscpy is the
# real msvcrt export, not a decorated mbscpy; the SEH personality
# routines only exist in underscored form) — stripping would leave
# names that match nothing in any catalog. __C_specific_handler keeps
# both spellings: the raw export and the once-stripped form that a
# generic single-underscore normaliser upstream may hand us.
# Deliberately a small seed, per the learn-vocab discipline.
_UNDERSCORE_SIGNIFICANT = frozenset({
    "_exit",
    "_Exit",
    "_setjmp",
    "_longjmp",
    # Windows multibyte CRT copy/concat (real underscored exports).
    "_mbscpy",
    "_mbscat",
    # Windows SEH personality routines.
    "_except_handler3",
    "_except_handler4",
    "__C_specific_handler",
    "_C_specific_handler",
})


def strip_import_prefix(name: str) -> str:
    """Remove radare2 / linker import prefixes, keeping dotted segments."""
    value = str(name or "")
    for prefix in _IMPORT_PREFIXES:
        if prefix == "_" and value in _UNDERSCORE_SIGNIFICANT:
            continue
        value = value.removeprefix(prefix)
    return value


def symbol_base_name(name: str) -> str:
    """Strip import prefixes then take the last dotted segment."""
    return strip_import_prefix(name).split(".")[-1]
