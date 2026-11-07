"""Integer storage sizes in target C bytes, with no host/layout guesses."""

from .integer_abi import resolve_integer_abi
from .integer_types import integer_type


def builtin_integer_sizeof(spelling, integer_abi):
    """Return storage size only when this layout actually specifies it.

    Boolean value bits do not specify boolean storage. Pointer, floating,
    aggregate and typedef layouts are absent from the integer ABI model.
    """
    abi = resolve_integer_abi(integer_abi)
    if abi is None:
        return None
    if spelling == "char":
        return 1
    kind = integer_type(spelling, abi)
    if kind is None or kind.width % abi.char_bits:
        return None
    return kind.width // abi.char_bits
