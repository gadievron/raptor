"""Source-bound arithmetic under an explicit target integer ABI.

Unresolved aliases, pointers, references, enums, volatile objects and mixed
promoted signedness require a richer model. No host or C32 default is used.
"""

import re
from dataclasses import dataclass
from core.smt_solver.integer_types import IntegerType as IntegerType, integer_type as integer_type

from .integer_literals import integer_literal_value
from .narrowing_bindings import visible_declarations
from .integer_abi import resolve_integer_abi

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_MAX_TYPED_VARIABLES = 8


@dataclass(frozen=True)
class ArithmeticModel:
    status: str
    profile: str = ""
    kind: str = ""
    domains: tuple[str, ...] = ()
    types: tuple[tuple[str, str], ...] = ()


def common_integer_type(operands, types, integer_abi):
    """Result frame for atomic operands with one promoted signedness.

    Same-signedness C conversions preserve values and select the wider
    promoted range. Small supported literals have type int; converting a
    nonnegative int literal to a wider/equal unsigned frame preserves it.
    Mixed signed/unsigned variables still require rank/conversion modeling.
    Guard-only variables do not select the operation's result range.
    """
    abi = resolve_integer_abi(integer_abi)
    if abi is None or not operands:
        return None
    declared = dict(types)
    kinds, literals = [], []
    for atom in operands:
        value = integer_literal_value(atom)
        if value is not None:
            if abs(value) > (1 << (abi.int_bits - 1)) - 1:
                return None
            literals.append(value)
        else:
            kind = integer_type(declared.get(atom), abi)
            if kind is None:
                return None
            kinds.append(kind)
    signs = {kind.promoted_signed for kind in kinds}
    if len(signs) > 1:
        return None
    signed = next(iter(signs), True)
    if not signed and any(value < 0 for value in literals):
        return None
    width = max([kind.promoted_width for kind in kinds] + ([abi.int_bits] if literals else []))
    return IntegerType(width, signed, width, signed)


def has_builtin_integer_type(type_node, spelling, language=None):
    """Recognize grammar builtin types, including C's reserved _Bool token."""
    return type_node is not None and (
        type_node.type in {"primitive_type", "sized_type_specifier"}
        or (language == "c" and type_node.type == "type_identifier" and spelling == "_Bool")
    )


def model_for_integer_terms(target, data, operands, premises, integer_abi=None, *, language=None, result_operands=None):
    """Resolve integer terms and guard names with their promotion domains."""
    abi = resolve_integer_abi(integer_abi)
    if abi is None:
        return ArithmeticModel("unavailable")
    declarations = visible_declarations(target, data, language=language)
    names = set()
    literals = []
    for atom in operands:
        if (value := integer_literal_value(atom)) is not None:
            literals.append(value)
        elif _IDENTIFIER.fullmatch(atom):
            names.add(atom)
        else:
            return ArithmeticModel("unavailable")
    for predicate in premises:
        parts = predicate.split()
        if len(parts) != 3:
            return ArithmeticModel("unavailable")
        for atom in (parts[0], parts[2]):
            if (value := integer_literal_value(atom)) is not None:
                literals.append(value)
            elif _IDENTIFIER.fullmatch(atom):
                names.add(atom)
            else:
                return ArithmeticModel("unavailable")
    if len(names) > _MAX_TYPED_VARIABLES:
        return ArithmeticModel("unavailable")
    # Larger unsuffixed literals change C's comparison/arithmetic type. Do not
    # model them at a guessed width merely because a bit pattern fits.
    for value in literals:
        if abs(value) > (1 << (abi.int_bits - 1)) - 1:
            return ArithmeticModel("unavailable")
    resolved = {}
    spellings = {}
    from core.smt_solver.path_feasibility import is_literal_identifier
    for name in sorted(names):
        if is_literal_identifier(name):
            return ArithmeticModel("unavailable")
        record = declarations.get(name)
        if record is None or record[0] is None:
            return ArithmeticModel("unavailable")
        spelling, declaration = record
        # A type is not a value definition. Local initializers, globals and
        # static storage require value-flow facts before they may range over
        # an unconstrained entry domain. Parameters are entry inputs.
        if declaration.type != "parameter_declaration":
            return ArithmeticModel("unavailable")
        declarator = declaration.child_by_field_name("declarator")
        if declarator is None or declarator.type != "identifier":
            return ArithmeticModel("unavailable")
        type_node = declaration.child_by_field_name("type")
        # Attribute syntax can change the value type or width (mode/vector
        # extensions) without changing the visible builtin type spelling.
        if any(child not in (type_node, declarator) and child.type != "comment"
               and not (child.type == "type_qualifier" and data[child.start_byte:child.end_byte] == b"const")
               for child in declaration.named_children):
            return ArithmeticModel("unavailable")
        if not has_builtin_integer_type(type_node, spelling, language):
            return ArithmeticModel("unavailable")
        kind = integer_type(spelling, abi)
        if kind is None:
            return ArithmeticModel("unavailable")
        if any(child.type == "type_qualifier" and data[child.start_byte:child.end_byte] != b"const"
               for child in declaration.named_children):
            return ArithmeticModel("unavailable")
        resolved[name] = kind
        spellings[name] = spelling
    result_type = common_integer_type(operands if result_operands is None else result_operands,
                                      spellings.items(), abi)
    if result_type is None or not resolved:
        return ArithmeticModel("unavailable")
    # The single-profile predicate DSL preserves these atomic comparisons
    # only when every value fits the result frame with the same signedness.
    # A wider guard variable must not silently widen the arithmetic query.
    if any(kind.promoted_signed != result_type.signed or kind.promoted_width > result_type.width
           for kind in resolved.values()):
        return ArithmeticModel("unavailable")
    profile = result_type.profile
    if not result_type.signed and any(value < 0 for value in literals):
        return ArithmeticModel("unavailable")
    domains = []
    for name, kind in resolved.items():
        if kind.width == result_type.width:
            continue  # every bit pattern already denotes an admissible int value
        low = -(1 << (kind.width - 1)) if kind.signed else 0
        high = (1 << (kind.width - (1 if kind.signed else 0))) - 1
        # Express the storage minimum exactly in the selected wider frame.
        lower = f"(0 - {-low})" if low < 0 else "0"
        domains.extend((f"{name} >= {lower}", f"{name} <= {high}"))
    return ArithmeticModel("bound", profile,
                           "signed_wrap" if profile.startswith("int") else "unsigned_wrap",
                           tuple(domains), tuple(spellings.items()))


def model_for_operation(target, data, operands, operator, premises, integer_abi=None, *, language=None):
    """Integer facts for a supported atomic arithmetic operation."""
    if operator not in {"+", "-", "*", "/", "%"}:
        return ArithmeticModel("unavailable")
    return model_for_integer_terms(target, data, operands, premises, integer_abi, language=language)
