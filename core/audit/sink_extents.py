"""Exact destination capacities and size signedness for copy sinks.

The copy-length sufficiency model compares a sink's size argument
against a destination capacity it must be handed, and its verdicts
depend on whether that argument's declared type can carry a negative
value into the size conversion. Both facts are minted here only when
they are exact by construction; anything unmodeled derives nothing
rather than guessing, because a wrong capacity or a wrong signedness
would either invent an insufficiency or clear a guard.

A capacity requires: the destination argument is one bare identifier
resolving to a single same-function declaration of a one-dimensional
array with a literal extent and a builtin integer element type, and the
size argument is itself a bare identifier (so the per-variable length
model is the actual copy length). A signedness verdict requires the
size identifier to resolve to a single simple declaration (a parameter
of the function or a same-function local) whose type spelling is in a
closed signed or unsigned set.

What makes the resolution exact for code that compiles:

- Every occurrence of the destination identifier in the enclosing
  function is accounted for: one declaring occurrence and the
  destination argument itself. The size identifier may be used freely,
  but only its one declaring occurrence may exist.
- On the path from the call up to each governing declaration's scope,
  every preceding statement is one that cannot splice a hidden
  declaration into a live scope: comments, declarations whose
  initializers contain only literals, and control-flow statements whose
  own scopes have closed again. Plain expression statements decline —
  a statement-level macro there could legally shadow the name.
- Any preprocessor directive inside the function, or a file-level
  definition (macro or typedef) of a governing name or type word,
  declines: expansion could change resolution, extents or signedness.
- The sink name itself must appear in the function only as a callee.

Shared boundary: like every source-level oracle here, macros defined in
headers are invisible before expansion; the consumers of these facts
(the legacy guard-model detectors) already hold them at hint tier.

``sizeof`` is counted in character units, exactly as the sinks' length
arguments are, so ``sizeof(char)`` is one by definition and every other
element width comes from the resolved integer ABI or not at all.
"""

from dataclasses import dataclass

from core.smt_solver.integer_abi import resolve_integer_abi
from core.smt_solver.integer_types import integer_type

from .integer_literals import integer_literal_value

#: Zero-based destination-argument position per modeled sink. The wide
#: and append-style copiers (wmemcpy, strncat) and the user-space
#: transfer pair stay unmodeled: their length is not a plain character
#: count against a local array capacity. Every modeled sink takes its
#: length third.
_DEST_ARG_POSITIONS = {"memcpy": 0, "memmove": 0, "strncpy": 0, "bcopy": 1}
_SIZE_ARG_POSITION = 2
_SINK_ARG_COUNT = 3
_CHAR_SPELLINGS = frozenset({"char", "signed char", "unsigned char"})
_TYPE_NODES = frozenset({"primitive_type", "sized_type_specifier"})
_UNSIGNED_SPELLINGS = frozenset({
    "unsigned", "unsigned char", "unsigned short", "unsigned short int",
    "unsigned int", "unsigned long", "unsigned long int",
    "unsigned long long", "unsigned long long int",
    "size_t", "uintptr_t", "uintmax_t",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
})
_SIGNED_SPELLINGS = frozenset({
    "short", "short int", "signed short", "signed short int",
    "int", "signed", "signed int",
    "long", "long int", "signed long", "signed long int",
    "long long", "long long int", "signed long long",
    "signed long long int",
    "ptrdiff_t", "ssize_t", "intptr_t", "intmax_t",
    "int8_t", "int16_t", "int32_t", "int64_t",
})
#: Statements that cannot splice a declaration into the scope they sit
#: in: control statements reclose any scope they open, jumps and
#: comments declare nothing. Expression statements are absent — a
#: statement-level macro invocation parses as one.
_SCOPE_INERT_STATEMENTS = frozenset({
    "comment", "if_statement", "for_statement", "while_statement",
    "do_statement", "switch_statement", "return_statement",
    "break_statement", "continue_statement", "goto_statement",
})
_LITERAL_NODES = frozenset({
    "number_literal", "char_literal", "string_literal", "initializer_list",
    "string_content", "escape_sequence", "comment",
})
_DECLARATOR_WRAPPERS = frozenset({
    "array_declarator", "pointer_declarator", "function_declarator",
    "parenthesized_declarator", "reference_declarator", "init_declarator",
})
_MAX_SOURCE_CHARS = 1 << 21
_MAX_EXTENT = 1 << 31
_MAX_CAPACITY = 1 << 63


@dataclass(frozen=True)
class SinkCopyFacts:
    """Per-sink-line derived facts; absent fields were not derivable."""

    capacity: int | None = None
    size_signedness: str | None = None  # "signed" | "unsigned"


def _text(node, data):
    return data[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _walk(root):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(node.named_children)


def _element_size(spelling, abi):
    """The element's sizeof in character units, or None without an ABI."""
    if spelling in _CHAR_SPELLINGS:
        # sizeof(char) is one by definition under every C ABI.
        return 1
    if abi is None:
        return None
    kind = integer_type(spelling, abi)
    if kind is None or kind.width % abi.char_bits:
        return None
    return kind.width // abi.char_bits


def _call_on_line(root, row, api, data):
    """The unique bare call to *api* starting on *row*, else None."""
    matches = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "call_expression" and node.start_point[0] == row:
            callee = node.child_by_field_name("function")
            if (callee is not None and callee.type == "identifier"
                    and _text(callee, data) == api):
                matches.append(node)
        stack.extend(child for child in node.children
                     if child.start_point[0] <= row <= child.end_point[0])
    return matches[0] if len(matches) == 1 else None


def _enclosing_function(call):
    node = call.parent
    while node is not None and node.type != "function_definition":
        node = node.parent
    return node


def _literal_only(node):
    """True when a subtree can only denote literal values, never a macro."""
    return all(item.type in _LITERAL_NODES for item in _walk(node))


def _scope_inert(statement):
    """True when this earlier sibling cannot hide a declaration."""
    if statement.type in _SCOPE_INERT_STATEMENTS:
        return True
    if statement.type != "declaration":
        return False
    for child in statement.named_children:
        if child.type == "init_declarator":
            value = child.child_by_field_name("value")
            if value is not None and not _literal_only(value):
                return False
    return True


def _chain_is_clean(call, stop_compound):
    """Every scope from the call through *stop_compound* opens with it.

    Each compound on the ancestor path, the stop compound included, may
    hold only scope-inert statements before the call; *stop_compound*
    must actually be an ancestor.
    """
    node = call
    while node.parent is not None:
        parent = node.parent
        if parent.type == "compound_statement":
            for child in parent.named_children:
                if child.end_byte <= call.start_byte and not _scope_inert(child):
                    return False
        if parent == stop_compound:
            return True
        node = parent
    return False


def _is_declaring(occurrence):
    """True when this identifier introduces a name in a declaration."""
    current, parent = occurrence, occurrence.parent
    while parent is not None and parent.type in _DECLARATOR_WRAPPERS:
        if parent.child_by_field_name("declarator") != current:
            return False
        current, parent = parent, parent.parent
    if parent is None:
        return False
    if parent.type == "parameter_declaration":
        return parent.child_by_field_name("declarator") == current
    if parent.type in {"declaration", "field_declaration", "type_definition"}:
        return (current in parent.named_children
                and parent.child_by_field_name("type") != current)
    return False


def _array_declaration(occurrence, data):
    """(declaration, spelling, extent) for a canonical local array, or None."""
    declarator = occurrence.parent
    if declarator is None or declarator.type != "array_declarator":
        return None
    if declarator.child_by_field_name("declarator") != occurrence:
        return None
    size = declarator.child_by_field_name("size")
    if size is None or size.type != "number_literal":
        return None
    extent = integer_literal_value(_text(size, data))
    if extent is None or not 1 <= extent <= _MAX_EXTENT:
        return None
    declaration = declarator.parent
    if declaration is not None and declaration.type == "init_declarator":
        value = declaration.child_by_field_name("value")
        # A literal initializer never changes a literal-extent array's
        # capacity; anything else could carry a macro.
        if declaration.child_by_field_name("declarator") != declarator:
            return None
        if value is not None and not _literal_only(value):
            return None
        declaration = declaration.parent
    if declaration is None or declaration.type != "declaration":
        return None
    if declaration.parent is None or declaration.parent.type != "compound_statement":
        return None
    named = [child for child in declaration.named_children if child.type != "comment"]
    if len(named) != 2 or named[0].type not in _TYPE_NODES:
        return None
    spelling = " ".join(_text(named[0], data).split())
    return declaration, spelling, extent


def _simple_declaration(occurrence, data):
    """(declaration | parameter_declaration, spelling) for a plain object."""
    holder = occurrence.parent
    if holder is not None and holder.type == "init_declarator":
        if holder.child_by_field_name("declarator") != occurrence:
            return None
        value = holder.child_by_field_name("value")
        if value is not None and not _literal_only(value):
            return None
        holder = holder.parent
    if holder is None or holder.type not in {"declaration", "parameter_declaration"}:
        return None
    named = [child for child in holder.named_children if child.type != "comment"]
    if len(named) != 2 or named[0].type not in _TYPE_NODES:
        return None
    return holder, " ".join(_text(named[0], data).split())


def _is_function_parameter(declaration, func):
    """True when *declaration* is a parameter of *func* itself."""
    node = declaration.parent
    if node is None or node.type != "parameter_list":
        return False
    node = node.parent
    if node is None or node.type != "function_declarator":
        return False
    while node is not None and node != func:
        if node.type not in _DECLARATOR_WRAPPERS and node.type != "function_definition":
            return False
        if node.type == "function_definition":
            break
        node = node.parent
    return node == func


def _size_signedness(func, call, size_name, data, occurrences):
    """"signed"/"unsigned" for the size identifier's declared type, or None."""
    declaring = [node for node in occurrences if _is_declaring(node)]
    if len(declaring) != 1:
        return None
    bound = _simple_declaration(declaring[0], data)
    if bound is None:
        return None
    declaration, spelling = bound
    if spelling in _UNSIGNED_SPELLINGS:
        verdict = "unsigned"
    elif spelling in _SIGNED_SPELLINGS:
        verdict = "signed"
    else:
        return None
    if declaration.type == "parameter_declaration":
        if not _is_function_parameter(declaration, func):
            return None
        body = func.child_by_field_name("body")
        if body is None or not _chain_is_clean(call, body):
            return None
    else:
        if (declaration.parent is None
                or declaration.parent.type != "compound_statement"
                or declaration.end_byte > call.start_byte
                or not _chain_is_clean(call, declaration.parent)):
            return None
    return verdict, spelling


def sink_copy_facts(source, guards, *, file_path, integer_abi=None):
    """Map sink_line to exact SinkCopyFacts for modeled copy sinks."""
    from .condition_extraction import _get_parser, language_for_file

    if not guards or not isinstance(source, str) or len(source) > _MAX_SOURCE_CHARS:
        return {}
    language = language_for_file(file_path)
    if language not in {"c", "cpp"}:
        return {}
    parser = _get_parser(language)
    if parser is None:
        return {}
    abi = resolve_integer_abi(integer_abi)
    data = source.encode("utf-8")
    root = parser.parse(data).root_node
    defined = set()
    for node in _walk(root):
        if node.type in {"preproc_def", "preproc_function_def"}:
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                defined.add(_text(name_node, data))
        elif node.type == "type_definition":
            # Over-collecting type words is only ever more conservative.
            # Standard names in the declarator slot parse as
            # primitive_type, so every type word in the typedef counts.
            for item in _walk(node):
                if item.type in {"type_identifier", "primitive_type",
                                 "sized_type_specifier"}:
                    defined.update(_text(item, data).split())
    facts = {}
    for guard in guards:
        line = getattr(guard, "sink_line", None)
        api = str(getattr(guard, "sink_api", "")).rsplit(".", 1)[-1]
        if (api not in _DEST_ARG_POSITIONS or type(line) is not int
                or line < 1 or line in facts):
            continue
        call = _call_on_line(root, line - 1, api, data)
        if call is None:
            continue
        func = _enclosing_function(call)
        if func is None or func.has_error:
            continue
        derived = _facts_for_call(func, call, api, data, abi, defined)
        if derived is not None:
            facts[line] = derived
    return facts


def _facts_for_call(func, call, api, data, abi, defined):
    arguments = call.child_by_field_name("arguments")
    if arguments is None:
        return None
    args = [child for child in arguments.named_children if child.type != "comment"]
    if len(args) != _SINK_ARG_COUNT:
        return None
    destination = args[_DEST_ARG_POSITIONS[api]]
    size_argument = args[_SIZE_ARG_POSITION]
    if destination.type != "identifier" or size_argument.type != "identifier":
        return None
    dest_name = _text(destination, data)
    size_name = _text(size_argument, data)
    if dest_name == size_name:
        return None
    dest_sites, size_sites = [], []
    for node in _walk(func):
        if node.type.startswith("preproc"):
            return None
        if node.type != "identifier":
            continue
        text = _text(node, data)
        if text == dest_name:
            dest_sites.append(node)
        elif text == size_name:
            size_sites.append(node)
        elif text == api:
            parent = node.parent
            if (parent is None or parent.type != "call_expression"
                    or parent.child_by_field_name("function") != node):
                return None
    signedness = _size_signedness(func, call, size_name, data, size_sites)
    spelling_words = set() if signedness is None else set(signedness[1].split())
    if defined & {size_name, api, *spelling_words}:
        return None
    facts = SinkCopyFacts(
        capacity=_destination_capacity(call, data, abi, defined, api,
                                       destination, dest_sites),
        size_signedness=None if signedness is None else signedness[0],
    )
    return facts if (facts.capacity, facts.size_signedness) != (None, None) else None


def _destination_capacity(call, data, abi, defined, api, destination, dest_sites):
    """The exact character capacity of the destination array, or None."""
    if len(dest_sites) != 2 or destination not in dest_sites:
        return None
    declaring = dest_sites[0] if dest_sites[1] == destination else dest_sites[1]
    bound = _array_declaration(declaring, data)
    if bound is None:
        return None
    declaration, spelling, extent = bound
    if declaration.end_byte > call.start_byte:
        return None
    if not _chain_is_clean(call, declaration.parent):
        return None
    size = _element_size(spelling, abi)
    if size is None:
        return None
    capacity = extent * size
    if not 0 < capacity < _MAX_CAPACITY:
        return None
    name = _text(declaring, data)
    if defined & {name, api, *spelling.split()}:
        return None
    return capacity


def sink_buffer_sizes(source, guards, *, file_path, integer_abi=None):
    """Map sink_line to the exact destination capacity for modeled sinks."""
    return {line: facts.capacity
            for line, facts in sink_copy_facts(
                source, guards, file_path=file_path, integer_abi=integer_abi,
            ).items() if facts.capacity is not None}


def sink_size_signedness(source, guards, *, file_path, integer_abi=None):
    """Map sink_line to the size argument's declared signedness."""
    return {line: facts.size_signedness
            for line, facts in sink_copy_facts(
                source, guards, file_path=file_path, integer_abi=integer_abi,
            ).items() if facts.size_signedness is not None}
