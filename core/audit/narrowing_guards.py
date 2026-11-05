"""Recognized C range guards for one direct integer initializer.

This deliberately does not infer protection from proximity. Unknown syntax,
parser failure, possible mutation, and unmodeled control flow earn no guard
credit. Widths retain the narrowing checker's existing target-model assumptions.
"""

import re


def integer_range(type_name: str, width: int) -> tuple[int, int] | None:
    name = type_name.strip()
    if name == "char":  # implementation-defined signedness
        return None
    unsigned = (
        name.startswith(("unsigned", "uint", "__u"))
        or bool(re.fullmatch(r"u\d+", name))
        or name in {"size_t", "uintptr_t"}
    )
    return (
        (0, (1 << width) - 1)
        if unsigned
        else (-(1 << (width - 1)), (1 << (width - 1)) - 1)
    )


def _nodes(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.named_children))


def _unwrap(node):
    while (
        node is not None
        and node.type == "parenthesized_expression"
        and len(node.named_children) == 1
    ):
        node = node.named_children[0]
    return node


class NarrowingGuardContext:
    """One bounded source parse shared by initializer and guard checks."""

    def __init__(self, source: str, *, language="c"):
        self.language = language
        self.source = source
        self.lines = source.split("\n")  # line-model: raw LF byte columns; retain CR for AST offsets
        self.data = source.encode("utf-8")
        self.root = None
        self.loaded = False
        self.offsets = [0]
        for line in self.lines[:-1]:
            self.offsets.append(self.offsets[-1] + len(line.encode("utf-8")) + 1)

    def _node_source(self, node):
        return (
            self.data[node.start_byte : node.end_byte].decode("utf-8")
            if node is not None
            else ""
        )

    def _declares(self, node, variable):
        if node.type not in {"declaration", "parameter_declaration"}:
            return False
        for declarator in node.children_by_field_name("declarator"):
            if declarator.type == "init_declarator":
                declarator = declarator.child_by_field_name("declarator")
            if (
                declarator is not None
                and declarator.type == "identifier"
                and self._node_source(declarator) == variable
            ):
                return True
        return False

    def _effects(self, node, variable):
        for item in _nodes(node):
            if item.type in {
                "call_expression",
                "for_statement",
                "while_statement",
                "do_statement",
                "switch_statement",
            }:
                return True
            if self._declares(item, variable):
                return True
            if item.type in {"assignment_expression", "update_expression"}:
                operand = _unwrap(
                    item.child_by_field_name(
                        "left" if item.type == "assignment_expression" else "argument"
                    )
                )
                if (
                    operand is not None
                    and operand.type == "identifier"
                    and self._node_source(operand) == variable
                ):
                    return True
        return False

    def _constant(self, node, source_range):
        node = _unwrap(node)
        text = self._node_source(node).strip()
        if not text:
            return None
        if node.type == "identifier":
            if re.search(
                rf"^[^\S\r\n]*#[^\S\r\n]*(?:define|undef)[^\S\r\n]+{re.escape(text)}\b",
                self.source,
                re.MULTILINE,
            ):
                return None
            widths = {
                "SCHAR": 8,
                "UCHAR": 8,
                "SHRT": 16,
                "USHRT": 16,
                "INT": 32,
                "UINT": 32,
                "LONG": 64,
                "ULONG": 64,
                "LLONG": 64,
                "ULLONG": 64,
            }
            match = re.fullmatch(
                r"(SCHAR|UCHAR|SHRT|USHRT|INT|UINT|LONG|ULONG|LLONG|ULLONG|U?INT(?:8|16|32|64))_(MIN|MAX)",
                text,
            )
            if not match:
                return None
            kind, edge = match.groups()
            unsigned = kind.startswith("U")
            if unsigned and source_range[0] < 0:
                return None  # do not guess C's usual arithmetic conversions
            width = widths.get(kind) or int(re.search(r"\d+", kind).group())
            low, high = (
                (0, (1 << width) - 1)
                if unsigned
                else (-(1 << (width - 1)), (1 << (width - 1)) - 1)
            )
            value = low if edge == "MIN" else high
        else:
            match = re.fullmatch(
                r"(-?)\s*(0[xX][0-9a-fA-F]+|0[bB][01]+|[0-9]+)([uUlL]*)", text
            )
            if not match:
                return None
            sign, digits, suffix = match.groups()
            if "u" in suffix.lower() and source_range[0] < 0:
                return None
            base = (
                16
                if digits.lower().startswith("0x")
                else 2
                if digits.lower().startswith("0b")
                else 8
                if len(digits) > 1 and digits.startswith("0")
                else 10
            )
            try:
                value = int(digits, base) * (-1 if sign else 1)
            except ValueError:
                return None
        return value if source_range[0] <= value <= source_range[1] else None

    def _constrain(self, condition, truth, interval, variable, source_range):
        node = _unwrap(condition)
        if node is None:
            return interval
        if (
            node.type == "unary_expression"
            and self._node_source(node.child_by_field_name("operator")) == "!"
        ):
            return self._constrain(
                node.child_by_field_name("argument"),
                not truth,
                interval,
                variable,
                source_range,
            )
        if node.type != "binary_expression":
            return interval
        op = self._node_source(node.child_by_field_name("operator"))
        left, right = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        )
        if op in {"&&", "||"}:
            intersection = (op == "&&") == truth
            a = self._constrain(left, truth, interval, variable, source_range)
            b = self._constrain(right, truth, interval, variable, source_range)
            return (
                (max(a[0], b[0]), min(a[1], b[1]))
                if intersection
                else (min(a[0], b[0]), max(a[1], b[1]))
            )
        if op not in {"<", "<=", ">", ">=", "==", "!="}:
            return interval
        left, right = _unwrap(left), _unwrap(right)
        if left.type == "identifier" and self._node_source(left) == variable:
            bound = self._constant(right, source_range)
        elif right.type == "identifier" and self._node_source(right) == variable:
            bound = self._constant(left, source_range)
            op = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}[
                op
            ]
        else:
            return interval
        if bound is None:
            return interval
        if not truth:
            op = {"<": ">=", "<=": ">", ">": "<=", ">=": "<", "==": "!=", "!=": "=="}[
                op
            ]
        low, high = interval
        if op == "<":
            high = min(high, bound - 1)
        elif op == "<=":
            high = min(high, bound)
        elif op == ">":
            low = max(low, bound + 1)
        elif op == ">=":
            low = max(low, bound)
        elif op == "==":
            low, high = max(low, bound), min(high, bound)
        return low, high

    @staticmethod
    def _returns(node):
        if node is None:
            return False
        if node.type == "return_statement":
            return True
        return (
            node.type == "compound_statement"
            and bool(node.named_children)
            and node.named_children[-1].type == "return_statement"
        )

    def _walk(self, block, target, interval, variable, source_range):
        for child in block.named_children:
            if child.start_byte <= target.start_byte < child.end_byte:
                if child == target or child.type == "declaration":
                    return source_range if self._effects(child, variable) else interval
                if child.type == "compound_statement":
                    return self._walk(child, target, interval, variable, source_range)
                if child.type == "if_statement":
                    condition = child.child_by_field_name("condition")
                    state = (
                        source_range if self._effects(condition, variable) else interval
                    )
                    for field, truth in (("consequence", True), ("alternative", False)):
                        body = child.child_by_field_name(field)
                        if (
                            body is not None
                            and body.start_byte <= target.start_byte < body.end_byte
                        ):
                            if not self._effects(condition, variable):
                                state = self._constrain(
                                    condition, truth, state, variable, source_range
                                )
                            return self._walk(
                                body, target, state, variable, source_range
                            )
                return None
            if child.end_byte > target.start_byte:
                break
            if child.type == "if_statement":
                condition = child.child_by_field_name("condition")
                if self._effects(condition, variable):
                    interval = source_range
                    continue  # comparisons before a mutation do not bound its result
                if child.child_by_field_name("alternative") is None and self._returns(
                    child.child_by_field_name("consequence")
                ):
                    interval = self._constrain(
                        condition, False, interval, variable, source_range
                    )
                    continue
            if self._effects(child, variable) or child.type.startswith("preproc_"):
                interval = source_range
        return None

    def _load_root(self):
        if not self.loaded:
            self.loaded = True
            try:
                from .condition_extraction import _get_parser

                parser = _get_parser(self.language)
                self.root = (
                    parser.parse(self.data).root_node if parser is not None else None
                )
            except Exception:
                self.root = None
        return self.root

    def function_scope(self, function_name):
        from .probe_function_scope import select_function

        return select_function(
            self._load_root(), self.data, function_name, self.language
        )

    def in_function(self, line, column, scope):
        target = self._initializer_at(line, column)
        if target is not None and any(start <= target.start_byte < end for start, end in scope.excluded):
            return False
        while target is not None and target.type != "function_definition":
            target = target.parent
        return target is not None and (target.start_byte, target.end_byte) == (
            scope.start,
            scope.end,
        )

    def _initializer_at(self, line, column):
        root = self._load_root()
        if root is None or root.has_error:
            return None
        offset = self.offsets[line] + len(self.lines[line][:column].encode("utf-8"))
        target = self.root.descendant_for_byte_range(offset, offset)
        while target is not None and target.type != "init_declarator":
            target = target.parent
        return target

    def visible_types(self, line, column):
        target = self._initializer_at(line, column)
        if target is None:
            return None
        from .narrowing_bindings import visible_types

        return visible_types(target, self.data)

    def may_use_value(self, variable, line, column):
        target = self._initializer_at(line, column)
        if target is None:
            return True  # missing syntax cannot prove that a use is argument-only
        from .initializer import initializer_may_use_value

        return initializer_may_use_value(
            target.child_by_field_name("value"),
            self.data,
            variable,
        )

    def protects(self, variable, line, column, source_range, dest_range, source_type):
        if source_range is None or dest_range is None:
            return False
        target = self._initializer_at(line, column)
        if target is None:
            return False
        value = _unwrap(target.child_by_field_name("value"))
        if (
            value is None
            or value.type != "identifier"
            or self._node_source(value) != variable
        ):
            return False  # guarding an operand does not bound an arbitrary expression
        function = target.parent
        while function is not None and function.type != "function_definition":
            function = function.parent
        if function is None:
            return False
        items = list(_nodes(function))
        bindings = [item for item in items if self._declares(item, variable)]
        if len(bindings) != 1:
            return False  # globals, pointers, or shadowing require another model
        if " ".join(
            self._node_source(bindings[0].child_by_field_name("type")).split()
        ) != " ".join(source_type.split()):
            return False  # a same-named variable elsewhere cannot supply this type
        if any(item.type in {"goto_statement", "labeled_statement"} for item in items):
            return False
        if any(
            item.type == "pointer_expression"
            and self._node_source(item.child_by_field_name("operator")) == "&"
            and any(
                n.type == "identifier" and self._node_source(n) == variable
                for n in _nodes(item)
            )
            for item in items
        ):
            return False  # escaped addresses can invalidate a local range
        state = self._walk(
            function.child_by_field_name("body"),
            target,
            source_range,
            variable,
            source_range,
        )
        return (
            state is not None and dest_range[0] <= state[0] <= state[1] <= dest_range[1]
        )
