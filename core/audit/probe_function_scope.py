"""Select a unique named function for a source-derived audit observation."""

from dataclasses import dataclass


@dataclass(frozen=True)
class FunctionScope:
    status: str
    start: int = 0
    end: int = 0

    def source_span(self, source: str) -> str:
        """Keep original line positions for a line-oriented scoped checker."""
        raw = source.encode("utf-8")
        masked = bytearray(c if c in (10, 13) else 32 for c in raw)
        masked[self.start : self.end] = raw[self.start : self.end]
        return masked.decode("utf-8")


def _text(node, source):
    return (
        source[node.start_byte : node.end_byte].decode("utf-8")
        if node is not None
        else ""
    )


def _name(node, source, language):
    if language == "go":
        name = _text(node.child_by_field_name("name"), source)
        receiver = node.child_by_field_name("receiver")
        if receiver is not None:
            stack = [receiver]
            while stack:
                item = stack.pop()
                if item.type == "type_identifier":
                    return _text(item, source) + "." + name
                stack.extend(reversed(item.named_children))
        return name
    declarator = node.child_by_field_name("declarator")
    while declarator is not None:
        if declarator.type in {
            "identifier",
            "field_identifier",
            "qualified_identifier",
            "destructor_name",
            "operator_name",
        }:
            name = _text(declarator, source).replace("::", ".")
            parents = []
            parent = node.parent
            while parent is not None:
                if parent.type in {
                    "namespace_definition",
                    "class_specifier",
                    "struct_specifier",
                }:
                    part = _text(parent.child_by_field_name("name"), source)
                    if part:
                        parents.append(part.replace("::", "."))
                parent = parent.parent
            return ".".join([*reversed(parents), name])
        child = declarator.child_by_field_name("declarator")
        if (
            child is None
            and declarator.type == "parenthesized_declarator"
            and len(declarator.named_children) == 1
        ):
            child = declarator.named_children[0]
        declarator = child
    return ""


def select_function(
    root, source: bytes, function_name: str, language: str
) -> FunctionScope:
    if not isinstance(function_name, str) or not function_name.strip():
        return FunctionScope("missing")
    if root is None or root.has_error:
        return FunctionScope("unavailable")
    kinds = (
        {"function_declaration", "method_declaration"}
        if language == "go"
        else {"function_definition"}
    )
    requested = function_name.strip().replace("::", ".")
    matches = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type in kinds:
            name = _name(node, source, language)
            if name == requested or (
                "." not in requested and name.rsplit(".", 1)[-1] == requested
            ):
                matches.append(node)
        stack.extend(node.named_children)
    if len(matches) != 1:
        return FunctionScope("missing" if not matches else "ambiguous")
    return FunctionScope("selected", matches[0].start_byte, matches[0].end_byte)


def go_function_scope(source: str, function_name: str) -> FunctionScope:
    try:
        from .condition_extraction import _get_parser

        parser = _get_parser("go")
        root = (
            parser.parse(source.encode("utf-8")).root_node
            if parser is not None
            else None
        )
        return select_function(root, source.encode("utf-8"), function_name, "go")
    except Exception:
        return FunctionScope("unavailable")
