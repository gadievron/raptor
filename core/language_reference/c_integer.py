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
