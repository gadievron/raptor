"""C-semantics helpers for SMT bitvector reasoning.

Width coercion, overflow predicates, and shift disambiguators used by
domain encoders (``smt_onegadget``, ``smt_path_validator``) when they
need explicit bitvector arithmetic models. Binding those models to C
source types, promotions, definedness, and build assumptions is the
encoder's responsibility.

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
- **Definedness predicates** — ``division_undefined`` and
  ``shift_count_invalid`` — expose invalid arithmetic cases that Z3
  otherwise assigns total bitvector results. They require explicit
  promoted operand types; they do not infer source-language semantics.
- **``cast``** combines the above to simulate a C-style conversion
  between integer types.

Binary operands must be explicit bitvectors of matching width and context;
construct literal values explicitly instead of relying on Z3 coercions.

Usage::

    # CWE-190: detect count * N wrapping through a bound check
    from core.smt_solver import new_solver, z3
    from core.smt_solver.csem import umul_overflows

    s = new_solver()
    count = z3.BitVec("count", 32)
    s.add(z3.ULT(count, z3.BitVecVal(0x40000000, 32)))  # unsigned guard
    s.add(umul_overflows(count, z3.BitVecVal(16, 32)))  # mul wraps at 2^32
    if s.check() == z3.sat:
        print("Wraparound witness:", s.model()[count])

    # CWE-197: narrowing cast discards significant bits
    from core.smt_solver.csem import truncation_loses_bits

    value32 = z3.BitVec("value32", 32)
    s.add(truncation_loses_bits(value32, to_width=8, to_signed=False, from_signed=False))
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
from ._validation import require_bool, require_bv, require_bv_pair, require_width


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
    require_width(to_width, argument="to_width")
    require_bv(bv)
    src_width = bv.size()
    if to_width <= 0 or to_width > src_width:
        msg = (
            f"truncate: to_width={to_width} out of range for "
            f"{src_width}-bit operand (must be 1..{src_width})"
        )
        raise ValueError(msg)
    return z3.Extract(to_width - 1, 0, bv)


def sign_extend(bv: Any, to_width: int) -> Any:
    """Extend ``bv`` to ``to_width`` bits preserving the sign bit.

    Pre-fix called ``z3.SignExt(to_width - bv.size(), bv)`` with
    no validation. SignExt's first arg is the number of bits to
    add and must be ``>= 0``; ``to_width < bv.size()`` produced
    a negative ext-width and a Z3 assertion failure from inside
    the C++ layer.
    """
    require_width(to_width, argument="to_width")
    require_bv(bv)
    src_width = bv.size()
    if to_width < src_width:
        msg = (
            f"sign_extend: to_width={to_width} narrower than "
            f"source {src_width}-bit operand (use truncate() to narrow)"
        )
        raise ValueError(msg)
    return z3.SignExt(to_width - src_width, bv)


def zero_extend(bv: Any, to_width: int) -> Any:
    """Extend ``bv`` to ``to_width`` bits padding with zeros.

    Pre-fix called ``z3.ZeroExt(to_width - bv.size(), bv)`` with
    no validation. Same crash mode as sign_extend: ``to_width <
    bv.size()`` produced a negative ext-width and a Z3 assertion
    failure.
    """
    require_width(to_width, argument="to_width")
    require_bv(bv)
    src_width = bv.size()
    if to_width < src_width:
        msg = (
            f"zero_extend: to_width={to_width} narrower than "
            f"source {src_width}-bit operand (use truncate() to narrow)"
        )
        raise ValueError(msg)
    return z3.ZeroExt(to_width - src_width, bv)


def truncation_loses_bits(bv: Any, to_width: int, to_signed: bool, *, from_signed: bool) -> Any:
    """Predicate: does this narrowing/reinterpretation change the integer value?

    Both source and destination signedness are required. The same source
    bits can denote -1 or an unsigned maximum, with different narrowing
    outcomes. Compare both values after extending to one bit wider than
    the source: that frame distinguishes negative values from every
    unsigned source value. A same-width signedness change is covered too.

    This models a specified bit-pattern conversion; it does not bind an
    actual C cast or establish language/target-specific definedness.
    """
    require_width(to_width, argument="to_width")
    require_bv(bv)
    if to_width > bv.size():
        raise ValueError("truncation target cannot be wider than its source")
    return conversion_changes_value(bv, to_width, to_signed, from_signed=from_signed)


def conversion_changes_value(bv: Any, to_width: int, to_signed: bool, *, from_signed: bool) -> Any:
    """Predicate for integer value change under a specified bit-pattern cast.

    Covers narrowing, widening, and same-width reinterpretation. A common
    comparison frame one bit wider than either type distinguishes every
    unsigned value from all negative values. This is a conditional integer
    conversion model, not evidence about a source cast or its definedness.
    """
    require_width(to_width, argument="to_width")
    require_bool(from_signed, argument="from_signed")
    require_bool(to_signed, argument="to_signed")
    require_bv(bv)
    converted = cast(bv, to_width, from_signed)
    compare_width = max(bv.size(), to_width) + 1
    source_value = sign_extend(bv, compare_width) if from_signed else zero_extend(bv, compare_width)
    target_value = sign_extend(converted, compare_width) if to_signed else zero_extend(converted, compare_width)
    return source_value != target_value


# ---------------------------------------------------------------------------
# Overflow predicates
# ---------------------------------------------------------------------------

def uadd_overflows(a: Any, b: Any) -> Any:
    """Unsigned mathematical sum exceeds the representable maximum.

    Equivalently, the modular result is less than either input under
    unsigned comparison: each individual comparison characterizes wrap.
    """
    require_bv_pair(a, b)
    return z3.Not(z3.BVAddNoOverflow(a, b, signed=False))


def sadd_overflows(a: Any, b: Any) -> Any:
    """Signed addition overflows in either direction (positive→wrap-to-negative or vice versa)."""
    require_bv_pair(a, b)
    return z3.Or(
        z3.Not(z3.BVAddNoOverflow(a, b, signed=True)),
        z3.Not(z3.BVAddNoUnderflow(a, b)),
    )


def usub_underflows(a: Any, b: Any) -> Any:
    """Unsigned subtraction wraps around (a < b)."""
    require_bv_pair(a, b)
    return z3.Not(z3.BVSubNoUnderflow(a, b, signed=False))


def ssub_overflows(a: Any, b: Any) -> Any:
    """Signed subtraction overflows in either direction."""
    require_bv_pair(a, b)
    return z3.Or(
        z3.Not(z3.BVSubNoOverflow(a, b)),
        z3.Not(z3.BVSubNoUnderflow(a, b, signed=True)),
    )


def umul_overflows(a: Any, b: Any) -> Any:
    """Unsigned multiplication wraps around.

    Asymmetry vs `smul_overflows`: unsigned has no negative range,
    so there's no `BVMulNoUnderflow` complement to add. `BVMulNoOverflow`
    with `signed=False` is the only condition that defines wrap.
    Pre-fix the lack of comment made the asymmetry look like a bug
    (signed has TWO clauses, unsigned has ONE — was the unsigned
    side missing a check?). It isn't: there's no smaller-than-zero
    region to underflow into for unsigned arithmetic.
    """
    require_bv_pair(a, b)
    return z3.Not(z3.BVMulNoOverflow(a, b, signed=False))


def smul_overflows(a: Any, b: Any) -> Any:
    """Signed multiplication overflows in either direction.

    Two clauses (Or):
      - `BVMulNoOverflow(signed=True)` covers positive overflow
        (result wraps off the high end into negative).
      - `BVMulNoUnderflow` covers the dual: result wraps off the
        low end into positive.
    See `umul_overflows` for why the unsigned variant has only
    one clause.
    """
    require_bv_pair(a, b)
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
    require_bv_pair(a, b)
    # Z3 shifts are total. C shift-count/definedness obligations are separate.
    return a >> b


def lshr(a: Any, b: Any) -> Any:
    """Logical right shift — shifts in zeros (unsigned semantics)."""
    require_bv_pair(a, b)
    return z3.LShR(a, b)


# ---------------------------------------------------------------------------
# C-style cast
# ---------------------------------------------------------------------------

def cast(bv: Any, to_width: int, from_signed: bool) -> Any:
    """Model a specified integer bit-pattern conversion.

    - Widening: sign-extends when the source is signed, zero-extends when
      unsigned (matching C's ``(int64_t)int32`` vs ``(uint64_t)uint32``
      behaviour).
    - Narrowing: truncates (discards high bits).
    - Same width: no-op.

    The *destination* signedness doesn't change the bit pattern in C —
    callers interpret the result with the semantics they want (via
    signed/unsigned comparisons downstream), so it's not a parameter.
    This does not establish a source conversion's language- or
    implementation-defined behavior.
    """
    require_width(to_width, argument="to_width")
    require_bool(from_signed, argument="from_signed")
    require_bv(bv)
    from_width = bv.size()
    if to_width > from_width:
        return sign_extend(bv, to_width) if from_signed else zero_extend(bv, to_width)
    if to_width < from_width:
        return truncate(bv, to_width)
    return bv


# ---------------------------------------------------------------------------
# Arithmetic definedness obligations
# ---------------------------------------------------------------------------

def division_undefined(a: Any, b: Any, *, signed: bool) -> Any:
    """Invalid division/remainder for explicit, already-promoted integers.

    Z3 division and remainder are total, including a zero divisor and the
    signed minimum divided by minus one. C integer / and % are undefined
    for both cases, even though the mathematical remainder in the latter
    case would be zero. Unsigned division only excludes a zero divisor.

    This predicate adds no constraints and performs no query. Assert it to
    search for an invalid operation; assert its negation when modeling a
    defined execution. Source types, promotions and reachability remain
    separate obligations. Width-one vectors follow this integer model;
    they do not establish C Boolean arithmetic semantics.
    """
    require_bool(signed, argument="signed")
    require_bv_pair(a, b)
    zero = z3.BitVecVal(0, b.size(), ctx=b.ctx)
    invalid = b == zero
    if signed:
        minimum = z3.BitVecVal(1 << (a.size() - 1), a.size(), ctx=a.ctx)
        minus_one = z3.BitVecVal(-1, b.size(), ctx=b.ctx)
        invalid = z3.Or(invalid, z3.And(a == minimum, b == minus_one))
    return invalid


def shift_count_invalid(count: Any, value_width: int, *, signed: bool) -> Any:
    """Count is negative or at least the promoted left operand's bit width.

    The count may have a different width from the shifted value, as C's
    integer promotions apply to the operands independently. ``signed`` is
    the promoted count's signedness. A wider comparison frame prevents a
    large value_width from wrapping into the count's narrower bitvector.

    This covers counts for either shift direction. It does not establish
    signed left-shift value definedness or choose the implementation's
    behavior for right-shifting a negative signed value.
    """
    require_bool(signed, argument="signed")
    require_width(value_width, argument="value_width")
    require_bv(count, argument="count")
    compare_width = max(count.size(), value_width.bit_length())
    extended = zero_extend(count, compare_width)
    limit = z3.BitVecVal(value_width, compare_width, ctx=count.ctx)
    too_large = z3.UGE(extended, limit)
    return z3.Or(count < z3.BitVecVal(0, count.size(), ctx=count.ctx), too_large) if signed else too_large
