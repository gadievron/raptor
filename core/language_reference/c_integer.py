"""C11 integer explanations checked against WG14 N1570, not bug patterns.

Coverage is deliberately C11 only. Other editions and C++ require their own
review; source-file suffixes do not make these rules universally applicable.
All text below is paraphrased. No runtime network lookup is performed.
"""

from .resolver import ReferenceEntry

_N1570 = "https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1570.pdf"

ENTRIES = (
    ReferenceEntry(
        "c.integer-conversion", 1, "c", ("c11",),
        "Integer conversion destinations",
        ("conversion", "narrowing", "cast", "signed", "unsigned", "assignment"),
        "Distinguish a representable integer value, an unsigned destination, a signed destination and _Bool.",
        "For conversion between integer types other than a _Bool destination, a value "
        "representable in the destination is unchanged. Otherwise, an unsigned "
        "destination produces the mathematical value modulo one plus that type's "
        "maximum. An out-of-range signed destination has an implementation-defined "
        "result or raises an implementation-defined signal. Conversion to _Bool "
        "instead produces zero for a scalar value comparing equal to zero and one otherwise.",
        ("Integer-to-integer conversion is distinct from floating-to-integer conversion.",
         "A cast or destination type does not determine the type used to evaluate an earlier arithmetic expression.",
         "Do not assume out-of-range signed conversion is portable truncation or undefined arithmetic overflow."),
        ("source and destination types", "destination range", "implementation choice for out-of-range signed conversion"),
        (_N1570 + " sections 6.3.1.2 and 6.3.1.3",),
    ),
    ReferenceEntry(
        "c.integer-promotion", 1, "c", ("c11",),
        "Integer promotions and rank",
        ("promotion", "promotions", "rank", "short", "char", "bitfield"),
        "Promotion to int depends on range and rank, not an assumed host width.",
        "For an integer type other than int or unsigned int with rank at most "
        "that of int, or a bit-field of type _Bool, int, signed int or unsigned int, "
        "integer promotion yields int if int represents every value of the original "
        "type (restricted by bit-field width); otherwise it yields unsigned int. "
        "Other types are unchanged. Promotions preserve the value and sign. "
        "Standard signed ranks increase from signed char through short, int, long "
        "and long long; the corresponding unsigned type has the same rank.",
        ("Apply promotions only where the operator or argument rules require them.",
         "Plain char signedness and relevant extended-type ranks need implementation facts.",
         "Do not assume every uint16_t expression promotes to int on every ABI."),
        ("operand type and rank", "int representable range", "bit-field type and width when relevant"),
        (_N1570 + " section 6.3.1.1 and footnote 58",),
    ),
    ReferenceEntry(
        "c.integer-usual-conversions", 1, "c", ("c11",),
        "Usual arithmetic conversions for integers",
        ("arithmetic", "comparison", "mixed", "signed", "unsigned", "result", "conversion"),
        "Determine the common integer type from promoted operand ranks and ranges.",
        "For integer operands of an operator specifying the usual arithmetic "
        "conversions, promote both operands first. Equal types remain unchanged. "
        "With equal signedness, convert to the type of greater rank. With mixed "
        "signedness, use the unsigned type if its rank is at least the signed "
        "type's rank; otherwise use the signed type if it represents all values "
        "of the unsigned type; otherwise use the unsigned type corresponding to "
        "that signed type. The common type is generally also the result type "
        "unless the operator specifies otherwise.",
        ("This is the integer branch; floating and complex operands use other rules.",
         "Shifts, casts and assignments have their own conversion rules.",
         "Comparison operators produce int even though these conversions determine their operands.",
         "Result definedness must be checked separately; conversion rules do not prove arithmetic safe."),
        ("operator", "promoted operand types", "conversion ranks", "representable ranges"),
        (_N1570 + " sections 6.3.1.8, 6.5.8 and 6.5.9",),
        ("c.integer-promotion",),
    ),
    ReferenceEntry(
        "c.integer-shift", 1, "c", ("c11",),
        "Shift operands and counts",
        ("shift", "shifts", "left", "right", "count", "promotion"),
        "Count validity and shifted values depend on independently promoted operands.",
        "Both operands must be integers. Promote each independently; the result "
        "uses the promoted left type. A negative count or a count not below that "
        "type's width makes behaviour undefined. Unsigned left shift scales by "
        "two to the count, reducing modulo one plus the result maximum. Signed "
        "left shift requires a nonnegative left value and a scaled value "
        "representable in the result type; otherwise behaviour is undefined. "
        "Right shift of unsigned or nonnegative signed values yields the "
        "truncated quotient by that power of two. Negative signed right shift "
        "is implementation-defined.",
        ("Shifts do not apply the usual common-type arithmetic conversions.",
         "Compound shifts evaluate the left lvalue once and convert for assignment; check atomic and concurrency semantics separately.",
         "These C11 conditions do not establish target applicability or safe operand ranges."),
        ("configured language edition", "promoted operand types", "promoted-left width and range",
         "operand values", "implementation choice for negative signed right shift"),
        (_N1570 + " sections 6.5.7, 6.3.1.1 and 6.5.16.2",),
        ("c.integer-promotion", "c.integer-conversion"),
    ),
    ReferenceEntry(
        "c.integer-update", 1, "c", ("c11",),
        "Increment and decrement values",
        ("increment", "decrement", "update", "prefix", "postfix", "store"),
        "Separate expression values, intermediate calculation and subsequent storage conversion.",
        "For a non-atomic integer object designated by a modifiable lvalue, "
        "increment adds one and decrement subtracts one. Prefix yields the "
        "updated stored value; postfix yields the prior value, whose computation "
        "precedes the object update. Evaluate the operand's lvalue once. "
        "Determine arithmetic evaluation types using required promotions and "
        "conversions, perform the operation, then convert for storage. Signed "
        "arithmetic outside the evaluated result type's range is undefined; a "
        "representable promoted computation followed by out-of-range signed "
        "storage conversion instead follows the implementation-defined result "
        "or signal rule. Unsigned storage alone does not establish unsigned "
        "intermediate arithmetic.",
        ("Pointer, floating and atomic updates need their own rules and facts.",
         "Keep the old or new expression value, evaluated result type and stored type distinct.",
         "Check sequencing relative to other accesses separately; this core does not establish whole-expression safety."),
        ("configured language edition", "operand type and atomicity", "arithmetic types and ranges",
         "stored type and range", "operand values", "sequencing with other accesses"),
        (_N1570 + " sections 6.5.2.4, 6.5.3.1 and 6.5.16.1-2",),
        ("c.integer-definedness", "c.integer-conversion"),
    ),
    ReferenceEntry(
        "c.integer-unary-sign", 1, "c", ("c11",),
        "Unary plus and minus",
        ("unary", "plus", "minus", "negation", "negative", "promote"),
        "Promoted operand types control negation, not the declared storage type.",
        "For integer operands of unary plus and minus, apply integer promotions "
        "first; the result uses the promoted operand type. Unary plus keeps the "
        "promoted value. Unary minus forms its mathematical negative. If the "
        "promoted type is unsigned, negation reduces modulo one plus that type's "
        "maximum. If it is signed, an unrepresentable negation result is "
        "undefined. An unsigned declared object can promote to signed int, "
        "so its negation need not be unsigned. A later cast or assignment "
        "cannot repair undefined negation.",
        ("Use the actual promoted range, not an assumed host width or two's-complement representation.",
         "Floating or complex arithmetic, bitwise complement, logical negation and pointer operators need other rules.",
         "Value rules do not settle volatile or atomic reads, representation details or sequencing of larger expressions."),
        ("configured language edition", "original operand type and rank", "promotion ranges",
         "promoted type and range", "operand value", "access and sequencing constraints"),
        (_N1570 + " sections 6.5.3.3 paragraphs 2-3, 6.3.1.1, 6.2.5 paragraph 9 and 6.5 paragraph 5",),
        ("c.integer-promotion",),
    ),
    ReferenceEntry(
        "c.integer-definedness", 1, "c", ("c11",),
        "Integer arithmetic definedness",
        ("overflow", "wrap", "wrapping", "definedness", "undefined", "arithmetic"),
        "Unsigned arithmetic reduction and signed arithmetic overflow are different from later conversion.",
        "A computation involving unsigned operands uses reduction modulo one plus "
        "the largest value representable in its resulting unsigned type. For "
        "signed integer arithmetic, a mathematically undefined result or a result "
        "outside the result type's range has undefined behaviour. A later "
        "assignment or cast cannot repair undefined behaviour during evaluation.",
        ("Determine the actual evaluated operand/result types after required conversions first.",
         "The declared destination's unsigned type does not make an intermediate signed expression unsigned.",
         "Division by zero, shifts and other operator-specific constraints must be checked separately.",
         "Compiler extensions and options need explicit implementation facts; they are not this C11 rule."),
        ("operator and operand types", "converted result type", "operand ranges", "configured language mode"),
        (_N1570 + " sections 6.2.5 paragraph 9 and 6.5 paragraph 5",),
        ("c.integer-promotion", "c.integer-usual-conversions"),
    ),
)
