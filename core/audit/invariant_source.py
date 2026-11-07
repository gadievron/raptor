"""Bounded C syntax admission for mathematical invariant transition sites.

This binds lvalues and reaching guard snapshots, not C integer types, alias
identities, arbitrary control flow, or application reachability.
"""

from dataclasses import dataclass
import re

from core.source.lines import split_lines

from .condition_extraction import _get_parser
from .source_view import sanitized_view

_MAX_NODES = 4096
_INVERSE = {"<": ">=", "<=": ">", ">": "<=", ">=": "<", "==": "!=", "!=": "=="}


@dataclass(frozen=True)
class Mutation:
    line: int
    code: str
    var: str = ""
    op: str = ""
    rhs: str = ""
    guards: tuple[str, ...] = ()
    reason: str = ""


def _unwrap(node):
    for _ in range(65):
        if node is None or node.type != "parenthesized_expression":
            return node
        children = [child for child in node.named_children if child.type != "comment"]
        if len(children) != 1:
            return None
        node = children[0]
    return None


def source_mutations(source, variables=None):
    """Return (sites, unmodeled effects, refusal reason); no regex proof fallback.

    variables=None is the CFG snapshot probe, not a preservation proof.
    Values captured by a guard may be locals; the probe only checks that
    their captured state is unchanged before the selected write.
    """
    parser = _get_parser("c")
    if parser is None:
        return [], [], "C source parser unavailable"
    data = source.encode("utf-8")
    root = parser.parse(data).root_node
    if root.has_error:
        return [], [], "invalid or unsupported C source"
    nodes, pending = [], [root]
    while pending:
        node = pending.pop()
        nodes.append(node)
        if len(nodes) > _MAX_NODES:
            return [], [], "source node budget exhausted"
        pending.extend(reversed(node.named_children))
    if sum(node.type == "function_definition" for node in nodes) > 1:
        return [], [], "one scoped function or statement sequence required"
    lines = split_lines(sanitized_view(source, language="c"))

    def text(node):
        return (
            data[node.start_byte : node.end_byte].decode("utf-8")
            if node is not None
            else ""
        )

    def expr(node):
        return re.sub(
            r"\s*(->|\.)\s*", r"\1", sanitized_view(text(node), language="c")
        ).strip()

    def canonical(node, depth=0):
        node = _unwrap(node)
        if node is None or depth > 64:
            return None
        if node.type in {"identifier", "field_identifier"}:
            return text(node)
        if node.type == "field_expression":
            base = canonical(node.child_by_field_name("argument"), depth + 1)
            field = node.child_by_field_name("field")
            operator = node.child_by_field_name("operator")
            if (
                base is not None
                and field is not None
                and field.type == "field_identifier"
                and text(operator) in {"->", "."}
            ):
                return base + text(operator) + text(field)
        return None

    def descendants(node):
        pending = [node]
        while pending:
            item = pending.pop()
            yield item
            pending.extend(item.named_children)

    def relevant(node):
        if variables is None:
            return True
        name = canonical(node)
        roots = {
            re.split(r"->|\.", variable)[0]
            for variable in variables
            if "->" in variable or "." in variable
        }
        if name in variables or name in roots:
            return True
        leaves = {re.split(r"->|\.", name)[-1] for name in variables}
        return any(
            item.type in {"identifier", "field_identifier"}
            and text(item) in (leaves | roots)
            for item in descendants(node)
        )

    def record(node, **kwargs):
        line = node.start_point[0] + 1
        return Mutation(line=line, code=lines[line - 1].strip(), **kwargs)

    def in_unevaluated(node):
        parent = node.parent
        while parent is not None:
            if parent.type == "sizeof_expression":
                # Variable-modified type sizes require separate entry/effect
                # reasoning. Ordinary expression operands are unevaluated.
                return not any(
                    item.type in {"array_declarator", "abstract_array_declarator"}
                    for item in descendants(parent)
                )
            parent = parent.parent
        return False

    def facts(node, truth):
        node = _unwrap(node)
        if node is None:
            return None
        if (
            node.type == "unary_expression"
            and text(node.child_by_field_name("operator")) == "!"
        ):
            return facts(node.child_by_field_name("argument"), not truth)
        if node.type == "binary_expression":
            op = text(node.child_by_field_name("operator"))
            left, right = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            )
            if (op == "&&" and truth) or (op == "||" and not truth):
                a, b = facts(left, truth), facts(right, truth)
                return (
                    a + b
                    if a is not None and b is not None and len(a) + len(b) <= 64
                    else None
                )
            if op in _INVERSE:
                return [f"{expr(left)} {op if truth else _INVERSE[op]} {expr(right)}"]
        if node.type in {"identifier", "field_expression", "number_literal"}:
            return [f"{expr(node)} {'!=' if truth else '=='} 0"]
        return None

    def guard_frame(target):
        current = target
        while (
            current.parent is not None
            and current.parent.type == "parenthesized_expression"
        ):
            current = current.parent
        if current.parent is None or current.parent.type not in {
            "expression_statement",
            "return_statement",
        }:
            return (), "embedded mutation requires an evaluation-order model"
        guards, watched, guard_start = [], set(), target.start_byte
        prefixes = []
        current = current.parent
        while current.parent is not None:
            parent = current.parent
            if parent.type == "if_statement":
                yes = parent.child_by_field_name("consequence")
                no = parent.child_by_field_name("alternative")
                condition = parent.child_by_field_name("condition")
                truth = (
                    yes is not None
                    and yes.start_byte <= target.start_byte < yes.end_byte
                )
                if not truth and not (
                    no is not None and no.start_byte <= target.start_byte < no.end_byte
                ):
                    return (), "mutation in a condition requires value-flow modeling"
                from .narrowing_bindings import visible_declarations

                declarations = visible_declarations(condition, data)
                for item in descendants(condition):
                    if in_unevaluated(item):
                        continue
                    if item.type in {
                        "assignment_expression",
                        "update_expression",
                        "array_declarator",
                        "abstract_array_declarator",
                    }:
                        return (), "evaluated guard effects require a value-flow model"
                    if item.type != "identifier":
                        continue
                    name = text(item)
                    if (
                        item.parent.type == "call_expression"
                        and item.parent.child_by_field_name("function") == item
                        and name in {"min", "max"}
                    ):
                        continue
                    declaration = declarations.get(name)
                    if (
                        variables is not None
                        and declaration is not None
                        and declaration[1].type == "declaration"
                    ):
                        return (), "guard local values require a value-flow model"
                    if (
                        variables is not None
                        and name not in variables
                        and (
                            declaration is None
                            or declaration[1].type != "parameter_declaration"
                        )
                    ):
                        return (), "guard name has no bound entry value"
                parsed = facts(condition, truth)
                if parsed is None or len(guards) + len(parsed) > 64:
                    return (
                        (),
                        "reaching source condition is outside the supported fragment",
                    )
                guards.extend(parsed)
                watched.update(
                    canonical(item)
                    for item in descendants(condition)
                    if canonical(item) is not None
                )
                guard_start = min(guard_start, condition.end_byte)
            elif parent.type == "compound_statement":
                for sibling in parent.named_children:
                    if sibling.end_byte > current.start_byte:
                        break
                    prefixes.append(sibling)
            elif parent.type not in {
                "translation_unit",
                "function_definition",
                "else_clause",
            }:
                return (), "control or execution context is unsupported"
            current = parent
        # Discover all dominating predicates before checking their snapshots.
        # The guarded block is visited before its owning if during ascent.
        for sibling in prefixes:
            for item in descendants(sibling):
                if item.type in {
                    "return_statement",
                    "goto_statement",
                    "break_statement",
                    "continue_statement",
                }:
                    return (), "preceding control transfer requires path modeling"
                if watched and item.start_byte >= guard_start:
                    if item.type == "call_expression":
                        return (), "call may invalidate the reaching guard snapshot"
                    if item.type in {"assignment_expression", "update_expression"}:
                        left = (
                            item.child_by_field_name("left")
                            if item.type == "assignment_expression"
                            else item.child_by_field_name("argument")
                        )
                        name = canonical(left)
                        if name is None or name in watched:
                            return (
                                (),
                                "mutation invalidates the reaching guard snapshot",
                            )
        return tuple(guards), ""

    sites, effects = [], []
    for node in nodes:
        if in_unevaluated(node):
            continue
        if node.type == "gnu_asm_expression":
            effects.append(
                record(node, reason="assembly effects require a separate model")
            )
        if node.type == "call_expression":
            callee = node.child_by_field_name("function")
            if text(callee) not in {"min", "max"}:
                effects.append(
                    record(
                        node,
                        reason="call effects require alias or interprocedural reasoning",
                    )
                )
        if (
            node.type == "pointer_expression"
            and text(node.child_by_field_name("operator")) == "&"
        ):
            if relevant(node.child_by_field_name("argument")):
                effects.append(
                    record(node, reason="address-taken invariant needs alias reasoning")
                )
        if node.type == "declaration" and variables is not None:
            if any(
                relevant(declarator)
                for declarator in node.children_by_field_name("declarator")
            ):
                effects.append(
                    record(
                        node,
                        reason="local binding or initialization needs base-case reasoning",
                    )
                )
        if node.type not in {"assignment_expression", "update_expression"}:
            continue
        left = (
            node.child_by_field_name("left")
            if node.type == "assignment_expression"
            else node.child_by_field_name("argument")
        )
        if left is None:
            continue
        name = canonical(left)
        if name is None:
            effects.append(
                record(node, reason="indirect mutation requires alias reasoning")
            )
            continue
        if not relevant(left):
            continue
        if variables is not None and name not in variables:
            effects.append(
                record(
                    node,
                    reason="indirect or qualified mutation requires alias/binding reasoning",
                )
            )
            continue
        op = text(node.child_by_field_name("operator"))
        right = node.child_by_field_name("right")
        guards, reason = guard_frame(node)
        sites.append(
            record(node, var=name, op=op, rhs=expr(right), guards=guards, reason=reason)
        )
    return sites, effects, ""


def guard_snapshot_supported(source, function_name, line):
    """A CFG predicate is usable only at a source-bound unchanged write site."""
    from .probe_function_scope import source_for_function

    _, selected = source_for_function(source, "source.c", function_name)
    if selected is None:
        return False
    sites, _effects, refusal = source_mutations(selected)
    at_line = [site for site in sites if site.line == line]
    return not refusal and bool(at_line) and all(not site.reason for site in at_line)
