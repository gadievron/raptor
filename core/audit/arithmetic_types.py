"""Source-bound arithmetic under an explicit target integer ABI.

Unresolved aliases, pointers, references, enums, volatile objects and mixed
promoted profiles require a richer model. No host or C32 default is used.
"""

import re
from dataclasses import dataclass

from .arithmetic_operation import _INTEGER_LITERAL_RE
from .narrowing_bindings import visible_declarations
from .integer_abi import resolve_integer_abi

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_MAX_TYPED_VARIABLES = 8


@dataclass(frozen=True)
class IntegerType:
    width: int
    signed: bool
    promoted_width: int
    promoted_signed: bool

    @property
    def profile(self):
        return f"{'int' if self.promoted_signed else 'uint'}{self.promoted_width}"


@dataclass(frozen=True)
class ArithmeticModel:
    status: str
    profile: str = ""
    kind: str = ""
    domains: tuple[str, ...] = ()
    types: tuple[tuple[str, str], ...] = ()


def integer_type(spelling, integer_abi=None):
    """Parse supported builtin integer grammar, without trusting aliases."""
    abi = resolve_integer_abi(integer_abi)
    if abi is None or not isinstance(spelling, str):
        return None

    def kind(width, signed, promote=True):
        return IntegerType(width, signed, abi.int_bits if promote else width,
                           (signed or width < abi.int_bits) if promote else signed)
    words = spelling.split()
    tokens = set(words)
    if not words or any(words.count(word) > (2 if word == "long" else 1) for word in tokens) or not tokens <= {
        "signed", "unsigned", "char", "short", "int", "long", "bool", "_Bool",
    }:
        return None
    if {"signed", "unsigned"} <= tokens:
        return None
    if "bool" in tokens or "_Bool" in tokens:
        return kind(1, False) if len(words) == 1 else None
    if "char" in tokens:
        if tokens not in ({"signed", "char"}, {"unsigned", "char"}):
            return None  # plain char signedness is implementation-defined
        return kind(abi.char_bits, "signed" in tokens)
    if "short" in tokens:
        return kind(abi.short_bits, "unsigned" not in tokens) if "long" not in tokens else None
    if "long" in tokens:
        if words.count("long") > 2:
            return None
        return kind(abi.long_long_bits if words.count("long") == 2 else abi.long_bits,
                    "unsigned" not in tokens, promote=False)
    return kind(abi.int_bits, "unsigned" not in tokens, promote=False)


def model_for_operation(target, data, operands, operator, premises, integer_abi=None):
    """Resolve every arithmetic/guard name and preserve promotion domains."""
    abi = resolve_integer_abi(integer_abi)
    if abi is None:
        return ArithmeticModel("unavailable")
    declarations = visible_declarations(target, data)
    names = set()
    literals = []
    for atom in operands:
        if _INTEGER_LITERAL_RE.fullmatch(atom):
            literals.append(atom)
        elif _IDENTIFIER.fullmatch(atom):
            names.add(atom)
        else:
            return ArithmeticModel("unavailable")
    for predicate in premises:
        parts = predicate.split()
        if len(parts) != 3:
            return ArithmeticModel("unavailable")
        for atom in (parts[0], parts[2]):
            if _INTEGER_LITERAL_RE.fullmatch(atom):
                literals.append(atom)
            elif _IDENTIFIER.fullmatch(atom):
                names.add(atom)
            else:
                return ArithmeticModel("unavailable")
    if len(names) > _MAX_TYPED_VARIABLES:
        return ArithmeticModel("unavailable")
    # Larger unsuffixed literals change C's comparison/arithmetic type. Do not
    # model them at a guessed width merely because a bit pattern fits.
    for literal in literals:
        if len(literal) > 22 or int(literal, 16 if literal.lower().startswith("0x") else 10) > (1 << (abi.int_bits - 1)) - 1:
            return ArithmeticModel("unavailable")
    resolved = {}
    spellings = {}
    for name in sorted(names):
        record = declarations.get(name)
        if record is None or record[0] is None:
            return ArithmeticModel("unavailable")
        spelling, declaration = record
        type_node = declaration.child_by_field_name("type")
        if type_node is None or type_node.type not in {"primitive_type", "sized_type_specifier"}:
            return ArithmeticModel("unavailable")
        kind = integer_type(spelling, abi)
        if kind is None:
            return ArithmeticModel("unavailable")
        if any(child.type == "type_qualifier" and data[child.start_byte:child.end_byte] != b"const"
               for child in declaration.named_children):
            return ArithmeticModel("unavailable")
        resolved[name] = kind
        spellings[name] = spelling
    profiles = {kind.profile for kind in resolved.values()}
    if len(profiles) != 1:
        return ArithmeticModel("unavailable")
    profile = profiles.pop()
    if profile.startswith("int") and operator == "-":
        return ArithmeticModel("unavailable")  # backend has no signed-subtract oracle
    domains = []
    for name, kind in resolved.items():
        if kind.width == kind.promoted_width:
            continue  # every bit pattern already denotes an admissible int value
        low = -(1 << (kind.width - 1)) if kind.signed else 0
        high = (1 << (kind.width - (1 if kind.signed else 0))) - 1
        # The predicate parser accepts binary subtraction, not negative literals.
        lower = f"(0 - {-low})" if low < 0 else "0"
        domains.extend((f"{name} >= {lower}", f"{name} <= {high}"))
    return ArithmeticModel("bound", profile,
                           "signed_wrap" if profile.startswith("int") else "unsigned_wrap",
                           tuple(domains), tuple(spellings.items()))
