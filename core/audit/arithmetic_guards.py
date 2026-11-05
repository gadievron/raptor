"""Supported branch predicates that hold at one selected arithmetic operation.

This is a bounded syntactic path walk, not a complete CFG or type model.
Unsupported control flow and invalidated values decline guard credit.
"""

from dataclasses import dataclass

from .arithmetic_operation import _INTEGER_LITERAL_RE, _unwrap

_MAX_PREMISES = 8
_MAX_CONDITION_NODES = 128
_MAX_PATH_DEPTH = 64


@dataclass(frozen=True)
class GuardPremises:
    status: str
    premises: tuple[str, ...] = ()


def _nodes(node):
    stack = [node]
    while stack:
        item = stack.pop()
        yield item
        stack.extend(reversed(item.named_children))


def guards_for_operation(body, target, data, operands):
    """Collect conjunctions with known branch polarity and unchanged names."""
    def text(node):
        return data[node.start_byte:node.end_byte].decode("utf-8") if node is not None else ""

    def contains(node):
        return node is not None and node.start_byte <= target.start_byte < node.end_byte

    def names(node):
        return {text(item) for item in _nodes(node) if item.type == "identifier"}

    condition_work = 0

    def condition(node, truth):
        nonlocal condition_work
        condition_work += 1
        if condition_work > _MAX_CONDITION_NODES:
            return None
        node = _unwrap(node)
        if node is not None and node.type == "condition_clause":
            node = _unwrap(node.child_by_field_name("value"))
        if node is None:
            return None
        if node.type == "identifier":
            return [(f"{text(node)} {'!=' if truth else '=='} 0", {text(node)})]
        if node.type == "unary_expression" and text(node.child_by_field_name("operator")) == "!":
            return condition(node.child_by_field_name("argument"), not truth)
        if node.type != "binary_expression":
            return None
        operator = text(node.child_by_field_name("operator"))
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        if operator in {"&&", "||"}:
            if (operator == "&&") != truth:
                return None  # a disjunction cannot be flattened into premises
            a, b = condition(left, truth), condition(right, truth)
            return a + b if a is not None and b is not None and len(a) + len(b) <= _MAX_PREMISES else None
        inverse = {"<": ">=", "<=": ">", ">": "<=", ">=": "<", "==": "!=", "!=": "=="}
        if operator not in inverse:
            return None
        left, right = _unwrap(left), _unwrap(right)
        if left is None or right is None:
            return None
        if left.type not in {"identifier", "number_literal"} or right.type not in {"identifier", "number_literal"}:
            return None
        # Do not flatten suffixes, character constants, or C octal syntax into
        # a different numeric value. The solver gate validates width as well.
        for item in (left, right):
            if item.type == "number_literal" and not _INTEGER_LITERAL_RE.fullmatch(text(item)):
                return None
        return [(f"{text(left)} {operator if truth else inverse[operator]} {text(right)}", names(node))]

    def exits(node):
        if node is None:
            return False
        if node.type == "return_statement":
            return True
        children = [child for child in node.named_children if child.type != "comment"]
        return node.type == "compound_statement" and bool(children) and exits(children[-1])

    def effects(node, watched):
        if node is None:
            return True
        for item in _nodes(node):
            if item.type == "call_expression":
                return True  # aliases and globals are not summarized here
            if item != target and item.type in {"subscript_expression", "pointer_expression", "field_expression"}:
                return True  # a preceding read may itself require a safety obligation
            if item.type == "binary_expression" and item != target and text(item.child_by_field_name("operator")) in {
                "+", "-", "*", "/", "%", "<<", ">>",
            }:
                return True  # arithmetic definedness/value flow is not encoded
            if item.type == "unary_expression" and text(item.child_by_field_name("operator")) in {"*", "-"}:
                return True
            if item.type in {"assignment_expression", "update_expression", "new_expression", "delete_expression"}:
                return True  # no alias/evaluation-order model, including C++ references
            if item.type == "declaration":
                type_node = item.child_by_field_name("type")
                if type_node is None or type_node.type not in {"primitive_type", "sized_type_specifier"}:
                    return True  # an implicit C++ constructor may throw or mutate state
                for decl in item.children_by_field_name("declarator"):
                    if decl.type == "identifier":
                        return True  # later indeterminate reads have no value-flow model
                    if decl.type == "init_declarator":
                        decl = decl.child_by_field_name("declarator")
                    if decl is not None and names(decl) & watched:
                        return True  # includes shadowing and reference declarators
            if item.type == "array_declarator":
                size = item.child_by_field_name("size")
                if size is None or size.type != "number_literal" or not _INTEGER_LITERAL_RE.fullmatch(text(size)):
                    return True  # variable extents need allocation/definedness facts
        return False

    def watched(facts):
        return set(operands).union(*(variables for _, variables in facts))

    def walk(node, facts, depth=0):
        if depth > _MAX_PATH_DEPTH or len(facts) > _MAX_PREMISES:
            return None
        if node.type == "compound_statement":
            for child in node.named_children:
                if contains(child):
                    return walk(child, facts, depth + 1)
                if child.end_byte > target.start_byte:
                    break
                if child.type == "if_statement":
                    test = child.child_by_field_name("condition")
                    yes = child.child_by_field_name("consequence")
                    if child.child_by_field_name("alternative") is None and exits(yes):
                        constraints = condition(test, False)
                        if constraints is None or effects(test, watched(facts)):
                            return None
                        facts = facts + constraints
                        if len(facts) > _MAX_PREMISES:
                            return None
                        continue
                if any(item.type == "return_statement" for item in _nodes(child)):
                    return None  # an unmodeled exit could restrict the reaching path
                if effects(child, watched(facts)):
                    return None
            return None
        if node.type == "if_statement":
            test = node.child_by_field_name("condition")
            if effects(test, watched(facts)):
                return None
            for field, truth in (("consequence", True), ("alternative", False)):
                branch = node.child_by_field_name(field)
                if contains(branch):
                    constraints = condition(test, truth)
                    if constraints is None:
                        return None
                    return walk(branch, facts + constraints, depth + 1)
            return None  # operation is in the condition, not a guarded branch
        if node.type == "else_clause":
            children = [child for child in node.named_children if child.type != "comment"]
            return walk(children[0], facts, depth + 1) if len(children) == 1 else None
        if node.type not in {"return_statement", "declaration", "expression_statement"}:
            return None
        if effects(node, watched(facts)):
            return None
        for item in _nodes(node):
            if item != node and item.type.endswith("_statement"):
                return None  # statement expressions require another path walk
            if item.type == "conditional_expression":
                return None
            if item.type == "binary_expression" and text(item.child_by_field_name("operator")) in {"&&", "||"}:
                return None
        return facts

    for item in _nodes(body):
        if item.type.endswith("_statement") and item.type not in {
            "compound_statement", "if_statement", "return_statement", "expression_statement",
        }:
            return GuardPremises("unavailable")
    facts = walk(body, [])
    if facts is None:
        return GuardPremises("unavailable")
    if not any(variables & set(operands) for _, variables in facts):
        return GuardPremises("no-guards", tuple(dict.fromkeys(predicate for predicate, _ in facts)))
    return GuardPremises("bound", tuple(dict.fromkeys(predicate for predicate, _ in facts)))
