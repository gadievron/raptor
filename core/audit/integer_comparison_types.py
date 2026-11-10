"""Pure builtin comparison types and conservative converted value ranges."""

from core.smt_solver.integer_types import IntegerType


def comparison_frame(left, right):
    """Numeric common type after promotions in approved padding-free ABIs."""
    width = max(left.promoted_width, right.promoted_width)
    if left.promoted_signed == right.promoted_signed:
        signed = left.promoted_signed
    else:
        signed_kind, unsigned_kind = (left, right) if left.promoted_signed else (right, left)
        # Builtin ranks/widths are monotone. A strictly wider signed type
        # represents the unsigned range; equal width converts to unsigned.
        signed = signed_kind.promoted_width > unsigned_kind.promoted_width
    return IntegerType(width, signed, width, signed)


def converted_interval(low, high, frame):
    """Enclose a storage interval after conversion, without a solver.

    A modular wrap can split an interval. Use a full-range enclosure in
    that case; losing candidates is preferable to inventing constant truth.
    """
    if low > high:
        return None
    if frame.signed:
        minimum, maximum = -(1 << (frame.width - 1)), (1 << (frame.width - 1)) - 1
        return (low, high) if minimum <= low <= high <= maximum else None
    modulus = 1 << frame.width
    if low // modulus != high // modulus:
        return 0, modulus - 1
    return low % modulus, high % modulus
