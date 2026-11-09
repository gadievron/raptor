"""Conservative value domains for evaluated integer prefixes.

This validates primitive reads and conversions before a selected operation.
It does not infer values for locals, execute user conversions, or guess
implementation-defined signed narrowing behavior.
"""

from core.smt_solver.sizeof_model import builtin_integer_sizeof

from .arithmetic_operation import _unwrap
from .arithmetic_prefix_obligations import PrefixProofBudget, binary_domain, unary_domain
from .arithmetic_expression_types import MAX_PREFIX_DEPTH as _MAX_DEPTH, expression_kind
from .arithmetic_evaluation import unevaluated_context
from .arithmetic_types import integer_type, common_integer_type, has_builtin_integer_type
from .integer_literals import source_integer_atom, integer_literal_value
from .narrowing_bindings import visible_declarations


class PrefixIntegerModel:
    """Per-source type/domain checks without shared mutable parser state."""

    def __init__(self, data, language, abi):
        self.data = data
        self.language = language
        self.abi = abi
        self._domains = {}
        self._kinds = {}
        self.proofs = PrefixProofBudget()

    def text(self, node):
        return self.data[node.start_byte:node.end_byte].decode("utf-8") if node is not None else ""

    def plain_declaration(self, declaration, *, read=True):
        type_node = declaration.child_by_field_name("type")
        declarators = declaration.children_by_field_name("declarator")
        qualifiers = {"const"} if read else {"const", "volatile"}
        for child in declaration.named_children:
            if child == type_node or child in declarators or child.type == "comment":
                continue
            if child.type == "type_qualifier" and self.text(child) in qualifiers:
                continue
            if declaration.type == "declaration" and child.type == "storage_class_specifier":
                continue
            return False
        return True

    def descriptor_base(self, descriptor):
        if descriptor is None or descriptor.type != "type_descriptor" or descriptor.child_by_field_name("declarator") is not None:
            return None
        base = descriptor.child_by_field_name("type")
        for child in descriptor.named_children:
            if child == base or child.type == "comment":
                continue
            if child.type == "type_qualifier" and self.text(child) in {"const", "volatile"}:
                continue
            return None
        return base

    def kind_for_name(self, node, *, read=True):
        record = visible_declarations(node, self.data, language=self.language).get(self.text(node))
        if record is None or record[0] is None:
            return None
        spelling, declaration = record
        if read and declaration.type == "declaration" and declaration.start_byte <= node.start_byte < declaration.end_byte:
            # Storage type alone does not establish that a local has been
            # initialized. In particular, its own initializer may read it.
            # Same-declaration value flow requires a separate model too.
            return None
        if not self.plain_declaration(declaration, read=read):
            return None
        type_node = declaration.child_by_field_name("type")
        if not has_builtin_integer_type(type_node, spelling, self.language):
            return None
        if read and any(child.type == "type_qualifier" and self.text(child) != "const"
                        for child in declaration.named_children):
            return None
        return integer_type(spelling, self.abi)

    def cast_kind(self, node):
        base = self.descriptor_base(node.child_by_field_name("type"))
        return integer_type(self.text(base), self.abi) if has_builtin_integer_type(base, self.text(base), self.language) else None

    def expression_kind(self, node, depth=0):
        return expression_kind(self, node, depth)

    def discarded_integer_cast(self, node):
        return (self.text(self.descriptor_base(node.child_by_field_name("type"))) == "void"
                and self.value_domain(node.child_by_field_name("value")) is not None)

    def size_domain(self, node):
        argument = _unwrap(node.child_by_field_name("value"))
        if argument is None:
            argument = _unwrap(node.child_by_field_name("type"))
        kind = None
        if argument is not None and argument.type == "type_descriptor" and argument.child_by_field_name("declarator") is None:
            type_node = self.descriptor_base(argument)
            spelling = self.text(type_node)
            value = builtin_integer_sizeof(spelling, self.abi)
            if value is None:
                return (1, None) if node.type == "alignof_expression" else (0, None)
            return (1, value) if node.type == "alignof_expression" else (value, value)
        elif argument is not None and argument.type == "cast_expression":
            kind = self.cast_kind(argument)
            if kind is not None and kind.width == 1:
                kind = None
        elif argument is not None and argument.type == "identifier":
            kind = self.kind_for_name(argument, read=False)
            if kind is not None and kind.width == 1:
                kind = None
        elif argument is not None and (atom := source_integer_atom(argument, self.data)) is not None:
            kind = common_integer_type([atom], (), self.abi)
        elif argument is not None and argument.type == "binary_expression" and self.text(argument.child_by_field_name("operator")) in {"+", "-", "*"}:
            left, right = (_unwrap(argument.child_by_field_name(field)) for field in ("left", "right"))
            if left is not None and right is not None:
                atoms = [self.text(item) if item.type == "identifier" else source_integer_atom(item, self.data) for item in (left, right)]
                declarations = visible_declarations(argument, self.data, language=self.language)
                if (all(atom is not None for atom in atoms)
                        and all(item.type != "identifier" or self.kind_for_name(item, read=False) is not None
                                for item in (left, right))):
                    kind = common_integer_type(atoms, [(name, value[0]) for name, value in declarations.items()], self.abi)
        size = max(1, kind.width // self.abi.char_bits) if kind is not None and self.abi is not None else None
        if node.type == "alignof_expression":
            return (1, size)
        return (size, size) if size is not None else (0, None)

    def value_domain(self, node, depth=0):
        node = _unwrap(node)
        if node is None or self.abi is None or depth > _MAX_DEPTH:
            return None
        key = node.start_byte, node.end_byte
        if key in self._domains:
            return self._domains[key]
        result = None
        if node.type == "condition_clause":
            result = self.value_domain(node.child_by_field_name("value"), depth + 1)
        elif node.type == "identifier":
            kind = self.kind_for_name(node)
            if kind is not None:
                result = (-(1 << (kind.width - 1)), (1 << (kind.width - 1)) - 1) if kind.signed else (0, (1 << kind.width) - 1)
        elif node.type in {"sizeof_expression", "alignof_expression"}:
            result = self.size_domain(node)
        elif unevaluated_context(node, self.data, self.language) and node.type in {"noexcept_expression", "call_expression"}:
            result = (0, 1)
        elif node.type in {"true", "false"}:
            value = 1 if node.type == "true" else 0
            result = (value, value)
        elif (atom := source_integer_atom(node, self.data)) is not None:
            value = integer_literal_value(atom)
            if type(value) is int and abs(value) <= (1 << (self.abi.int_bits - 1)) - 1:
                result = (value, value)
        elif node.type == "cast_expression":
            kind = self.cast_kind(node)
            domain = self.value_domain(node.child_by_field_name("value"), depth + 1)
            if kind is not None and domain is not None:
                low, high = domain
                minimum = -(1 << (kind.width - 1)) if kind.signed else 0
                maximum = (1 << (kind.width - (1 if kind.signed else 0))) - 1
                if low is not None and high is not None and minimum <= low <= high <= maximum:
                    result = domain
                elif not kind.signed:
                    result = (minimum, maximum)
        elif node.type == "unary_expression" and self.text(node.child_by_field_name("operator")) in {"+", "-", "~"}:
            result = unary_domain(self, node, depth)
        elif node.type == "unary_expression" and self.text(node.child_by_field_name("operator")) == "!":
            if self.value_domain(node.child_by_field_name("argument"), depth + 1) is not None:
                result = (0, 1)
        elif node.type == "binary_expression" and self.text(node.child_by_field_name("operator")) in {"+", "-", "*", "/", "%", "<<", ">>", "&", "|", "^"}:
            result = binary_domain(self, node, depth)
        elif node.type == "binary_expression" and self.text(node.child_by_field_name("operator")) in {"<", "<=", ">", ">=", "==", "!=", "&&", "||"}:
            if all(self.value_domain(node.child_by_field_name(field), depth + 1) is not None for field in ("left", "right")):
                result = (0, 1)
        elif node.type == "initializer_list":
            children = [child for child in node.named_children if child.type != "comment"]
            result = (0, 0) if not children else self.value_domain(children[0], depth + 1) if len(children) == 1 else None
        self._domains[key] = result
        return result

    def list_initialization_allowed(self, value, kind, depth=0):
        """Check C++ scalar list conversions without solving the expression.

        The selected operation may itself overflow. Its surrounding static
        conversion must be admissible without assuming that operation safe.
        """
        if self.language != "cpp" or value.type != "initializer_list":
            return True
        if kind is None or depth > _MAX_DEPTH:
            return False
        children = [child for child in value.named_children if child.type != "comment"]
        if len(children) > 1:
            return False  # a scalar cannot consume multiple list elements
        if not children:
            return True
        child = children[0]
        if child.type == "initializer_list":
            return self.list_initialization_allowed(child, kind, depth + 1)
        incoming = self.expression_kind(child)
        if incoming is None:
            return False
        minimum = -(1 << (kind.width - 1)) if kind.signed else 0
        maximum = (1 << (kind.width - (1 if kind.signed else 0))) - 1
        atom = source_integer_atom(child, self.data)
        if atom is not None:
            low = high = integer_literal_value(atom)
        else:
            # A runtime interval is not a C++ constant expression.
            # Admit a nonconstant only if its entire type fits.
            low = -(1 << (incoming.width - 1)) if incoming.signed else 0
            high = (1 << (incoming.width - (1 if incoming.signed else 0))) - 1
        return minimum <= low <= high <= maximum

    def initialization_defined(self, value, kind, depth=0):
        if kind is None or depth > _MAX_DEPTH:
            return False
        if value.type == "initializer_list":
            if not self.list_initialization_allowed(value, kind, depth):
                return False
            children = [child for child in value.named_children if child.type != "comment"]
            return all(self.initialization_defined(child, kind, depth + 1) for child in children)
        domain = self.value_domain(value)
        if domain is None:
            return False
        if not kind.signed:
            return True  # integer-to-unsigned conversion is defined modulo its range
        low, high = domain
        return (low is not None and high is not None
                and -(1 << (kind.width - 1)) <= low <= high <= (1 << (kind.width - 1)) - 1)
