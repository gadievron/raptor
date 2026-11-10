"""Select a unique named function for a source-derived audit observation."""

from dataclasses import dataclass

_MASK_TABLE = bytes(value if value in (10, 13) else 32 for value in range(256))


@dataclass(frozen=True)
class FunctionScope:
    status: str
    start: int = 0
    end: int = 0
    excluded: tuple[tuple[int, int], ...] = ()

    def source_span(self, source: str) -> str:
        """Keep original line positions for a line-oriented scoped checker."""
        if self.status != "selected":
            raise ValueError("unresolved function scope has no probe source")
        raw = source.encode("utf-8")
        masked = bytearray(raw.translate(_MASK_TABLE))
        masked[self.start : self.end] = raw[self.start : self.end]
        for start, end in self.excluded:
            masked[start:end] = raw[start:end].translate(_MASK_TABLE)
        return masked.decode("utf-8")


def _node_source(node, source):
    return (
        source[node.start_byte : node.end_byte].decode("utf-8")
        if node is not None
        else ""
    )


def _name(node, source, language):
    if language not in {"c", "cpp"}:
        name = _node_source(node.child_by_field_name("name"), source)
        receiver = node.child_by_field_name("receiver") if language == "go" else None
        if receiver is not None:
            stack = [receiver]
            while stack:
                item = stack.pop()
                if item.type == "type_identifier":
                    return _node_source(item, source) + "." + name
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
            name = _node_source(declarator, source).replace("::", ".")
            parents = []
            parent = node.parent
            while parent is not None:
                if parent.type in {
                    "namespace_definition",
                    "class_specifier",
                    "struct_specifier",
                }:
                    part = _node_source(parent.child_by_field_name("name"), source)
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
    from .condition_extraction import _FUNCTION_TYPES

    kinds = _FUNCTION_TYPES.get(language, ())
    if not kinds:
        return FunctionScope("unavailable")
    requested = function_name.strip().replace("::", ".")
    matches = []
    callables = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type in kinds or node.type in {"lambda_expression", "lambda"}:
            callables.append(node)
        if node.type in kinds:
            name = _name(node, source, language)
            if name == requested or (
                "." not in requested and name.rsplit(".", 1)[-1] == requested
            ):
                matches.append(node)
        stack.extend(node.named_children)
    if len(matches) != 1:
        return FunctionScope("missing" if not matches else "ambiguous")
    selected = matches[0]
    excluded = tuple(
        (node.start_byte, node.end_byte)
        for node in callables
        if selected.start_byte < node.start_byte < node.end_byte <= selected.end_byte
    )
    return FunctionScope("selected", selected.start_byte, selected.end_byte, excluded)


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


def source_for_function(source: str, file_path: str, function_name: str):
    """Return a selected scope and raw function source, or no probe source."""
    try:
        from .condition_extraction import _get_parser, language_for_file

        language = language_for_file(file_path)
        parser = _get_parser(language) if language else None
        data = source.encode("utf-8")
        root = parser.parse(data).root_node if parser is not None else None
        scope = select_function(root, data, function_name, language or "")
        return scope, scope.source_span(source) if scope.status == "selected" else None
    except Exception:
        return FunctionScope("unavailable"), None


def source_binding(source: str, function_name: str, *, verb: str, integer_abi=None, hypothesis: str = "") -> dict:
    """A worker receipt must describe the exact scoped input it analyzed."""
    import hashlib

    binding = {
        "function": function_name,
        "verb": verb,
        "sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
    }
    if verb in {"check-overflow", "check-oob", "check-overflow-to-oob", "check-negative-bypass", "check-array-bounds", "check-integer-division", "check-shift-count", "check-integer-comparison", "check-integer-conversion"}:
        binding["hypothesis_sha256"] = hashlib.sha256(hypothesis.encode("utf-8", "surrogatepass")).hexdigest()
    if verb == "check-overflow":
        # Matching source is insufficient: replies must satisfy the current
        # explicit claim, operation, guard, type and variable-identity contract.
        from .integer_abi import integer_abi_record
        binding["query_contract"] = "common-width-integer-operands-v25"
        binding["goal_contract"] = "closed-overflow-objective-v2"
        binding["integer_abi"] = integer_abi_record(integer_abi)
    elif verb == "check-integer-conversion":
        from .integer_abi import integer_abi_record
        binding["query_contract"] = "source-unsigned-conversion-v1"
        binding["integer_abi"] = integer_abi_record(integer_abi)
    elif verb == "check-integer-comparison":
        from .integer_abi import integer_abi_record
        binding["query_contract"] = "source-integer-comparison-v3"
        binding["integer_abi"] = integer_abi_record(integer_abi)
    elif verb == "check-shift-count":
        from .integer_abi import integer_abi_record
        binding["query_contract"] = "independent-shift-count-v2"
        binding["integer_abi"] = integer_abi_record(integer_abi)
    elif verb == "check-integer-division":
        from .integer_abi import integer_abi_record
        binding["query_contract"] = "source-integer-division-v3"
        binding["integer_abi"] = integer_abi_record(integer_abi)
    elif verb == "check-array-bounds":
        from .integer_abi import integer_abi_record
        binding["query_contract"] = "common-width-array-guards-v13"
        binding["integer_abi"] = integer_abi_record(integer_abi)
    elif verb == "check-oob":
        binding["query_contract"] = "explicit-bounds-roles-v1"
    elif verb == "check-negative-bypass":
        binding["query_contract"] = "explicit-negative-roles-v1"
    return binding
