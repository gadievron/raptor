"""C-semantics helpers for SMT bitvector reasoning.

Width coercion, overflow predicates, and shift disambiguators used by
domain encoders (``smt_onegadget``, ``smt_path_validator``) when they
need to reason about real C arithmetic rather than abstract bitvector
math.

- **Overflow predicates** turn ``a + b`` into "does this wrap under
  {signed, unsigned} {add, sub, mul}" — the primitives that make
  CWE-190 (integer overflow / wraparound) expressible as SAT.
- **Width coercion** — truncation (``Extract``), sign/zero extension
  (``SignExt``/``ZeroExt``) — lets an encoder model a narrow C type
  feeding a wider expression or vice versa.
- **Shift disambiguators** (``ashr`` vs ``lshr``): Z3's ``>>`` on a
  bitvec is arithmetic right shift; the logical form is ``z3.LShR``.
  Wrapping both by name stops encoders from silently picking the wrong
  one for a given signedness.
- **``cast``** combines the above to simulate a C-style conversion
  between integer types.

Usage::

    # CWE-190: detect count * N wrapping through a bound check
    from core.smt_solver import new_solver, z3
    from core.smt_solver.csem import umul_overflows

    s = new_solver()
    count = z3.BitVec("count", 32)
    s.add(count < 0x40000000)                           # visible guard
    s.add(umul_overflows(count, z3.BitVecVal(16, 32)))  # mul wraps at 2^32
    if s.check() == z3.sat:
        print("Wraparound witness:", s.model()[count])

    # CWE-197: narrowing cast discards significant bits
    from core.smt_solver.csem import truncation_loses_bits

    value32 = z3.BitVec("value32", 32)
    s.add(truncation_loses_bits(value32, to_width=8, to_signed=False))
    # SAT when a uint32→uint8 narrowing changes the value

    # Sign-preserving widening composed with arithmetic right shift
    from core.smt_solver.csem import cast, ashr

    i8 = z3.BitVec("i8", 8)
    i32 = cast(i8, to_width=32, from_signed=True)     # sign-extend
    shifted = ashr(i32, z3.BitVecVal(1, 32))          # arithmetic shift
"""
from __future__ import annotations

from typing import Any

from .availability import z3


# ---------------------------------------------------------------------------
# Width coercion
# ---------------------------------------------------------------------------

def truncate(bv: Any, to_width: int) -> Any:
    """Discard high bits, keeping the low ``to_width`` bits.

    Pre-fix this called ``z3.Extract(to_width - 1, 0, bv)`` with no
    width validation. Two crash modes that bypassed the encoder:

      * ``to_width <= 0`` — Extract requires ``hi >= lo``, so a
        zero-or-negative target width fed in by a buggy upstream
        type-inference pass would surface as a Z3 internal
        assertion failure instead of an actionable error.
      * ``to_width > bv.size()`` — narrowing to a width WIDER than
        the input is nonsensical (truncation can only lose bits)
        and Z3 raises an assertion error from inside the C++
        layer, where the operator can't tell which RAPTOR caller
        produced the bad input.

    Validate explicitly so a malformed call surfaces a Python
    ValueError pointing at THIS function with both widths in the
    message — the caller backtrace identifies the upstream bug.
    """
    src_width = bv.size()
    if to_width <= 0 or to_width > src_width:
        raise ValueError(
            f"truncate: to_width={to_width} out of range for "
            f"{src_width}-bit operand (must be 1..{src_width})"
        )
    return z3.Extract(to_width - 1, 0, bv)


def sign_extend(bv: Any, to_width: int) -> Any:
    """Extend ``bv`` to ``to_width`` bits preserving the sign bit.

    Pre-fix called ``z3.SignExt(to_width - bv.size(), bv)`` with
    no validation. SignExt's first arg is the number of bits to
    add and must be ``>= 0``; ``to_width < bv.size()`` produced
    a negative ext-width and a Z3 assertion failure from inside
    the C++ layer.
    """
    src_width = bv.size()
    if to_width < src_width:
        raise ValueError(
            f"sign_extend: to_width={to_width} narrower than "
            f"source {src_width}-bit operand (use truncate() to narrow)"
        )
    return z3.SignExt(to_width - src_width, bv)


def zero_extend(bv: Any, to_width: int) -> Any:
    """Extend ``bv`` to ``to_width`` bits padding with zeros.

    Pre-fix called ``z3.ZeroExt(to_width - bv.size(), bv)`` with
    no validation. Same crash mode as sign_extend: ``to_width <
    bv.size()`` produced a negative ext-width and a Z3 assertion
    failure.
    """
    src_width = bv.size()
    if to_width < src_width:
        raise ValueError(
            f"zero_extend: to_width={to_width} narrower than "
            f"source {src_width}-bit operand (use truncate() to narrow)"
        )
    return z3.ZeroExt(to_width - src_width, bv)


def truncation_loses_bits(bv: Any, to_width: int, to_signed: bool) -> Any:
    """Predicate: does truncating ``bv`` to ``to_width`` lose information?

    True exactly when the narrow value, re-extended to the original width
    under the *narrow (destination) type's* signedness, differs from the
    original — i.e. the C "value changes when assigned to a narrower type"
    semantic.  ``to_signed`` names the narrow type's signedness to
    parallel ``cast(..., from_signed=...)``.

    Pre-fix this assumed ``to_width <= bv.size()`` (truncation must
    narrow). When called with ``to_width > bv.size()`` (e.g. from a
    miscalibrated overflow check that swapped the from/to widths),
    the ``truncate(bv, to_width)`` call would have crashed inside Z3
    with an opaque assertion error from C++. Now ``truncate``'s own
    width guard fires first with a Python-readable ValueError that
    pinpoints THIS predicate as the caller, so an incorrectly-flipped
    width pair is debuggable from the traceback.
    """
    narrow = truncate(bv, to_width)
    wide = sign_extend(narrow, bv.size()) if to_signed else zero_extend(narrow, bv.size())
    return wide != bv


# ---------------------------------------------------------------------------
# Overflow predicates
# ---------------------------------------------------------------------------

def uadd_overflows(a: Any, b: Any) -> Any:
    """Unsigned addition wraps around (result < BOTH operands).

    Pre-fix the docstring read `(result < either operand)`.
    "Either" in English is ambiguous between "at least one of"
    and "any one of"; the correct mathematical condition for
    unsigned-add overflow is `result < a AND result < b`
    (when wrap occurs the sum is smaller than EVERY input).
    Reading the loose form as "at least one" gives a strictly
    weaker condition that doesn't characterise overflow —
    `a + b < a` alone is true when `b > UINT_MAX/2` even
    without overflow on some bit widths. The Z3 implementation
    (`Not(BVAddNoOverflow)`) is correct; only the docstring
    wording was confusable.
    """
    return z3.Not(z3.BVAddNoOverflow(a, b, signed=False))


def sadd_overflows(a: Any, b: Any) -> Any:
    """Signed addition overflows in either direction (positive→wrap-to-negative or vice versa)."""
    return z3.Or(
        z3.Not(z3.BVAddNoOverflow(a, b, signed=True)),
        z3.Not(z3.BVAddNoUnderflow(a, b)),
    )


def usub_underflows(a: Any, b: Any) -> Any:
    """Unsigned subtraction wraps around (a < b)."""
    return z3.Not(z3.BVSubNoUnderflow(a, b, signed=False))


def ssub_overflows(a: Any, b: Any) -> Any:
    """Signed subtraction overflows in either direction."""
    return z3.Or(
        z3.Not(z3.BVSubNoOverflow(a, b)),
        z3.Not(z3.BVSubNoUnderflow(a, b, signed=True)),
    )


def umul_overflows(a: Any, b: Any) -> Any:
    """Unsigned multiplication wraps around."""
    return z3.Not(z3.BVMulNoOverflow(a, b, signed=False))


def smul_overflows(a: Any, b: Any) -> Any:
    """Signed multiplication overflows in either direction."""
    return z3.Or(
        z3.Not(z3.BVMulNoOverflow(a, b, signed=True)),
        z3.Not(z3.BVMulNoUnderflow(a, b)),
    )


# ---------------------------------------------------------------------------
# Shift disambiguators
# ---------------------------------------------------------------------------

def ashr(a: Any, b: Any) -> Any:
    """Arithmetic right shift — preserves the sign bit.

    Z3's ``>>`` operator on a bitvec is already arithmetic shift; this
    helper exists so call sites read the intent rather than relying on
    the reader to remember the Python-operator-to-Z3-semantics mapping.
    """
    return a >> b


def lshr(a: Any, b: Any) -> Any:
    """Logical right shift — shifts in zeros (unsigned semantics)."""
    return z3.LShR(a, b)


# ---------------------------------------------------------------------------
# C-style cast
# ---------------------------------------------------------------------------

def cast(bv: Any, to_width: int, from_signed: bool) -> Any:
    """Simulate a C-style integer cast.

    - Widening: sign-extends when the source is signed, zero-extends when
      unsigned (matching C's ``(int64_t)int32`` vs ``(uint64_t)uint32``
      behaviour).
    - Narrowing: truncates (discards high bits).
    - Same width: no-op.

    The *destination* signedness doesn't change the bit pattern in C —
    callers interpret the result with the semantics they want (via
    signed/unsigned comparisons downstream), so it's not a parameter.
    """
    from_width = bv.size()
    if to_width > from_width:
        return sign_extend(bv, to_width) if from_signed else zero_extend(bv, to_width)
    if to_width < from_width:
        return truncate(bv, to_width)
    return bv
