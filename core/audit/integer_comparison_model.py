"""Per-expression builtin C integer conversions and independent replay.

This fragment admits immutable builtin entry parameters and small int
literals. It does not change the shared mathematical predicate bridge.
"""

import operator

from core.smt_solver import ge, gt, le, lt, mk_val, mk_var
from core.smt_solver.csem import cast

from .arithmetic_expression_types import promoted
from .arithmetic_types import common_integer_type, integer_type, model_for_integer_terms
from .integer_comparison_types import comparison_frame
from .integer_literals import integer_literal_value

COMPARISONS = {"<": operator.lt, "<=": operator.le, ">": operator.gt, ">=": operator.ge,
               "==": operator.eq, "!=": operator.ne}


class UnsupportedComparison(ValueError):
    pass


class ComparisonModel:
    """Own each parameter at its promoted width, converting per comparison."""

    def __init__(self, target, data, abi, language):
        self.target, self.data, self.abi, self.language = target, data, abi, language
        self.registry, self.kinds, self.types = {}, {}, {}

    def kind(self, atom):
        if integer_literal_value(atom) is not None:
            kind = common_integer_type([atom], (), self.abi)
            if kind is None:
                raise UnsupportedComparison("literal requires an unsupported integer type")
            return kind
        if atom not in self.kinds:
            model = model_for_integer_terms(self.target, self.data, [atom], (), self.abi, language=self.language)
            spelling = dict(model.types).get(atom)
            kind = integer_type(spelling, self.abi)
            if model.status != "bound" or kind is None or len(self.registry) >= 8:
                raise UnsupportedComparison("bounded immutable builtin entry parameters required")
            self.kinds[atom], self.types[atom] = kind, spelling
            self.registry[atom] = mk_var(atom, kind.promoted_width)
        return promoted(self.kinds[atom])

    def frame(self, a, b):
        return comparison_frame(self.kind(a), self.kind(b))

    def predicate(self, a, op, b):
        frame = self.frame(a, b)

        def value(atom):
            kind = self.kind(atom)
            raw = self.registry[atom] if atom in self.registry else mk_val(integer_literal_value(atom), kind.width)
            return cast(raw, frame.width, kind.signed)

        left, right = value(a), value(b)
        if op in {"==", "!="}:
            return left == right if op == "==" else left != right
        return {"<": lt, "<=": le, ">": gt, ">=": ge}[op](left, right, frame.signed)

    def storage_constraints(self):
        constraints = []
        for name, kind in self.kinds.items():
            low = -(1 << (kind.width - 1)) if kind.signed else 0
            high = (1 << (kind.width - (1 if kind.signed else 0))) - 1
            constraints.extend((ge(self.registry[name], mk_val(low, kind.promoted_width), kind.promoted_signed),
                                le(self.registry[name], mk_val(high, kind.promoted_width), kind.promoted_signed)))
        return constraints

    def evaluate(self, a, op, b, values):
        """Replay conversions with Python integers, independently of Z3."""
        frame = self.frame(a, b)

        def value(atom):
            raw = values[atom] if atom in values else integer_literal_value(atom)
            bits = raw % (1 << frame.width)
            return bits - (1 << frame.width) if frame.signed and bits >= (1 << (frame.width - 1)) else bits

        return COMPARISONS[op](value(a), value(b))
