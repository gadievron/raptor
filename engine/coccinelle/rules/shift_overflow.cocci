// shift_overflow.cocci — Review literal-based shift counts.
// Negative integer-literal counts are invalid for built-in shifts.
// Width candidates use the existing conventional int=32, long/long long=64
// thresholds; the target ABI can differ. In particular, long counts 32..63
// on ILP32/LLP64 need target-width analysis outside this heuristic.
//
// Both shift directions and C integer suffix/base spellings are covered.
// Positive width checks retain the literal-one scope; negative counts also
// cover other integer-literal left operands. Arbitrary constant expressions,
// variable operands and overloaded C++ operators are outside this rule.
// A match is not independent proof of a reachable security defect.
// CWE-682: Incorrect Calculation
// @role: detection

// Select literal-shaped counts before crossing into Python. Keep the
// optional sign branch separate so whitespace runs have no ambiguous split.
@literal_shift@
constant LEFT;
expression COUNT =~ "^[ (]*\([-+] *[0-9]\|[0-9]\)[0-9a-fA-FxXbBuUlL() ]*$";
position p;
@@
(
LEFT << COUNT@p
|
LEFT >> COUNT@p
)

@script:python shift_report depends on literal_shift@
LEFT << literal_shift.LEFT;
COUNT << literal_shift.COUNT;
p << literal_shift.p;
@@
import json

def shift_integer_literal(value):
    text = "".join(str(value).split())
    opening = len(text) - len(text.lstrip("("))
    closing = len(text) - len(text.rstrip(")"))
    if opening and opening == closing:
        text = text[opening:-closing]
    # Bound integer conversion and decimal formatting for hostile/extended
    # numeric spellings. This is not a target integer-width inference.
    if len(text) > 128:
        return None
    digits = text.rstrip("uUlL")
    suffix = text[len(digits):].lower()
    if suffix not in ("", "u", "l", "ul", "lu", "ll", "ull", "llu"):
        return None
    unsigned_digits = digits.lstrip("+-")
    try:
        number = int(digits, 8 if unsigned_digits.startswith("0") and unsigned_digits.isdigit() else 0)
    except ValueError:
        return None
    return number, suffix, unsigned_digits

left = shift_integer_literal(LEFT)
count = shift_integer_literal(COUNT)
if left is not None and count is not None:
    amount, count_suffix, magnitude = count
    # Unsigned unary negation wraps. Unsuffixed hex/octal/binary literals
    # can also select an unsigned type, depending on the target widths.
    # Only identify a negative value when its literal is guaranteed signed.
    decimal = not magnitude.startswith("0")
    minimum_signed_max = (2**63 - 1 if "ll" in count_suffix
                          else 2**31 - 1 if "l" in count_suffix else 32767)
    guaranteed_signed = "u" not in count_suffix and (
        abs(amount) <= minimum_signed_max or decimal and abs(amount) <= 2**63 - 1
    )
    negative = amount < 0 and guaranteed_signed
    if negative:
        msg = {"rule": "shift_overflow_negative"}
        message = "Candidate: negative count %d in a built-in literal shift; review reachability and the intended operation (CWE-682)" % amount
    elif left[0] == 1 and amount >= (64 if "l" in left[1] else 32):
        msg = ({"rule": "shift_overflow_long"} if "l" in left[1]
               else {"rule": "shift_overflow_int"})
        message = "Candidate: shift count %d reaches the conventional %s literal width; verify the promoted operand width and target ABI (CWE-682)" % (amount, "long/long long" if "l" in left[1] else "int")
    else:
        msg = None
    if msg is not None:
        msg.update({
            "file": p[0].file,
            "line": int(p[0].line),
            "col": int(p[0].column),
            "message": message,
        })
        print("COCCIRESULT:" + json.dumps(msg))
