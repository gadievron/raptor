"""Source-bound bounds obligations for one locally allocated buffer.

One visible ``T *p = malloc(n)`` / ``T *p = malloc(n * sizeof(T))`` with a
mandatory null-check exit, one direct read indexed by an immutable integer
parameter, supported branch guards, and an explicit target ABI. The extent
is the symbolic element count ``n``, so this oracle only ever confirms: a
sat witness shows one entry that reaches the access with ``index < 0`` or
``count >= 0 AND index >= count``, which is out of the allocated object on
every conforming allocator (a non-null result never provides more usable
storage than requested, and size_t conversion only shrinks a non-negative
request). An unsat obligation claims nothing — allocation-size conversion
and wrap behavior are unmodeled, so no safety verdict exists here.
"""

from dataclasses import asdict, dataclass
import logging

from core.smt_solver import BVProfile, DEFAULT_TIMEOUT_MS, ge, lt, z3, z3_available as _z3_available
from core.smt_solver.session import query_budget
from core.smt_solver.path_feasibility import PathCondition, check_path_feasibility, check_verb_feasibility, make_var
from core.smt_solver.sizeof_model import builtin_integer_sizeof

from .arithmetic_guards import guards_for_operation
from .arithmetic_operation import _unwrap
from .arithmetic_types import common_integer_type, has_builtin_integer_type, integer_type, model_for_integer_terms
from .array_bounds import has_array_read_goal, parse_array_access_claim
from .array_index import affine_access_claim
from .condition_extraction import _get_parser
from .function_execution_frame import ordinary_function_frame
from .integer_abi import integer_abi_record, resolve_integer_abi
from .integer_witness import source_model_scope, validate_integer_witness
from .narrowing_bindings import callable_declarator, visible_declarations

logger = logging.getLogger(__name__)
_MAX_SOURCE_CHARS = 65536
_MAX_NODES = 2048
# Closed tree-sitter grammar for the admitted frame, not application names.
_FRAME_NODES = frozenset({
    "compound_statement", "declaration", "primitive_type", "sized_type_specifier",
    "pointer_declarator", "init_declarator", "identifier", "number_literal",
    "call_expression", "argument_list", "if_statement", "condition_clause",
    "parenthesized_expression", "binary_expression", "unary_expression",
    "return_statement", "subscript_expression", "subscript_argument_list",
    "else_clause", "comment", "sizeof_expression", "type_descriptor",
})
_ALLOCATION_ASSUMPTIONS = (
    "the sole malloc result is the accessed object",
    "a non-null allocation provides at most the requested storage",
    "the witness path takes a successful (non-null) allocation of the witness count",
)


@dataclass(frozen=True)
class AllocAccess:
    status: str
    reason: str = ""
    object_name: str = ""
    index: str = ""
    count: str = ""
    element_type: str = ""
    element_size: int = 0
    # "count": malloc(n) over a one-byte element type. "count-times-sizeof":
    # malloc(n * sizeof(T)) with T spelled exactly as the element type.
    size_form: str = ""
    line: int = 0
    column: int = 0
    profile: str = ""
    width: int = 0
    signed: bool = False
    premises: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    types: tuple[tuple[str, str], ...] = ()
    parameters: tuple[tuple[str, str], ...] = ()


def _nodes(root):
    result, pending = [], [root]
    while pending:
        item = pending.pop()
        result.append(item)
        if len(result) > _MAX_NODES:
            return None
        pending.extend(reversed(item.named_children))
    return result


def _selected_condition(node):
    """The one tested expression under C parens or a C++ condition clause."""
    node = _unwrap(node)
    if node is not None and node.type == "condition_clause":
        node = _unwrap(node.child_by_field_name("value"))
    return node


def _null_check_shape(statement, pointer_name, data):
    """The pointer identifier tested by an exact ``if (!p) return 0;`` exit."""
    def text(node):
        return data[node.start_byte:node.end_byte].decode("utf-8") if node is not None else ""

    if statement.type != "if_statement" or statement.child_by_field_name("alternative") is not None:
        return None
    test = _selected_condition(statement.child_by_field_name("condition"))
    tested = None
    if test is not None and test.type == "unary_expression" and text(test.child_by_field_name("operator")) == "!":
        tested = _unwrap(test.child_by_field_name("argument"))
    elif test is not None and test.type == "binary_expression" and text(test.child_by_field_name("operator")) == "==":
        sides = [_unwrap(test.child_by_field_name(field)) for field in ("left", "right")]
        names = [side for side in sides if side is not None and side.type == "identifier"]
        zeros = [side for side in sides if side is not None and side.type == "number_literal" and text(side) == "0"]
        if len(names) == 1 and len(zeros) == 1:
            tested = names[0]
    if tested is None or tested.type != "identifier" or text(tested) != pointer_name:
        return None
    consequence = statement.child_by_field_name("consequence")
    if consequence is not None and consequence.type == "compound_statement":
        children = [child for child in consequence.named_children if child.type != "comment"]
        consequence = children[0] if len(children) == 1 else None
    if consequence is None or consequence.type != "return_statement":
        return None
    values = [child for child in consequence.named_children if child.type != "comment"]
    if len(values) != 1 or values[0].type != "number_literal" or text(values[0]) != "0":
        return None
    return tested


def _allocation_count(size_node, element_text, element_size, data, abi, language):
    """The element-count identifier under an exact byte-size discipline."""
    def text(node):
        return data[node.start_byte:node.end_byte].decode("utf-8") if node is not None else ""

    size_node = _unwrap(size_node)
    if size_node is None:
        return None
    if size_node.type == "identifier":
        # malloc(n): bytes equal elements only for a one-byte element type.
        return (text(size_node), "count") if element_size == 1 else None
    if size_node.type != "binary_expression" or text(size_node.child_by_field_name("operator")) != "*":
        return None
    sides = [_unwrap(size_node.child_by_field_name(field)) for field in ("left", "right")]
    names = [side for side in sides if side is not None and side.type == "identifier"]
    sizeofs = [side for side in sides if side is not None and side.type == "sizeof_expression"]
    if len(names) != 1 or len(sizeofs) != 1:
        return None
    descriptor = sizeofs[0].child_by_field_name("type")
    type_node = descriptor.child_by_field_name("type") if descriptor is not None else None
    if descriptor is None or len(descriptor.named_children) != 1 or not has_builtin_integer_type(type_node, text(type_node), language):
        return None
    if text(type_node) != element_text or builtin_integer_sizeof(text(type_node), abi) != element_size:
        return None
    return text(names[0]), "count-times-sizeof"


def bind_alloc_access(source, hypothesis, *, language, integer_abi=None):
    """Build a symbolic-extent obligation without guessing allocator behavior."""
    abi = resolve_integer_abi(integer_abi)
    claim = parse_array_access_claim(hypothesis)
    if claim is not None and affine_access_claim(hypothesis) is not None:
        # An adjusted claim like `p[i + 1]` must never bind a bare `p[i]`.
        return AllocAccess("unavailable", "a bare-identifier index claim is required")
    if abi is None or claim is None or language not in {"c", "cpp"} or len(source) > _MAX_SOURCE_CHARS:
        return AllocAccess("unavailable", "target ABI, atomic access claim, or supported source unavailable")
    try:
        parser = _get_parser(language)
        if parser is None:
            return AllocAccess("unavailable", "source parser unavailable")
        data = source.encode("utf-8")
        root = parser.parse(data).root_node
    except Exception:
        logger.debug("allocation access parse unavailable", exc_info=True)
        return AllocAccess("unavailable", "source parser unavailable")
    nodes = _nodes(root)
    if root.has_error or nodes is None:
        return AllocAccess("unavailable", "invalid or over-budget source")

    def text(node):
        return data[node.start_byte:node.end_byte].decode("utf-8") if node is not None else ""

    functions = [node for node in nodes if node.type == "function_definition"]
    if len(functions) != 1:
        return AllocAccess("unavailable", "one scoped function required")
    function = functions[0]
    body = function.child_by_field_name("body")
    function_declarator = function.child_by_field_name("declarator")
    if (function_declarator is None or function_declarator.type != "function_declarator"
            or callable_declarator(function) != function_declarator):
        return AllocAccess("unavailable", "plain function declaration required")
    if not ordinary_function_frame(function, data, language):
        return AllocAccess("unavailable", "function execution frame is unsupported")
    body_nodes = _nodes(body) if body is not None else None
    if body_nodes is None:
        return AllocAccess("unavailable", "function body unavailable")
    if any(node.type not in _FRAME_NODES for node in body_nodes):
        return AllocAccess("unavailable", "frame syntax or effects are unsupported")
    parameters = function_declarator.child_by_field_name("parameters")
    if parameters is None:
        return AllocAccess("unavailable", "parameter declarations unavailable")
    parameter_names, parameter_types = [], []
    for parameter in parameters.named_children:
        if parameter.type == "comment":
            continue
        name = parameter.child_by_field_name("declarator")
        type_node = parameter.child_by_field_name("type")
        if parameter.type != "parameter_declaration" or name is None or name.type != "identifier" or not has_builtin_integer_type(type_node, text(type_node), language) or integer_type(text(type_node), abi) is None:
            return AllocAccess("unavailable", "plain builtin integer parameters required")
        if any(child not in (name, type_node) and child.type != "comment"
               and not (child.type == "type_qualifier" and text(child) == "const") for child in parameter.named_children):
            return AllocAccess("unavailable", "parameter attributes or qualifiers are unsupported")
        parameter_names.append(text(name))
        parameter_types.append((text(name), text(type_node)))
    if len(set(parameter_names)) != len(parameter_names) or claim[0] in parameter_names:
        return AllocAccess("unavailable", "parameter binding is ambiguous")

    accesses = [node for node in body_nodes if node.type == "subscript_expression"]
    if len(accesses) != 1:
        return AllocAccess("unavailable", "one actual array access required")
    target = accesses[0]
    array = _unwrap(target.child_by_field_name("argument"))
    index = _unwrap(target.child_by_field_name("index"))
    if language == "cpp":
        indices = target.child_by_field_name("indices")
        named = [item for item in indices.named_children if item.type != "comment"] if indices is not None else []
        index = _unwrap(named[0]) if len(named) == 1 else None
    if (array is None or array.type != "identifier" or index is None or index.type != "identifier"
            or (text(array), text(index)) != claim):
        return AllocAccess("unavailable", "claim does not bind one atomic source access")
    statement = target.parent
    while statement is not None and statement.type == "parenthesized_expression":
        statement = statement.parent
    children = [child for child in statement.named_children if child.type != "comment"] if statement is not None else []
    if statement is None or statement.type != "return_statement" or len(children) != 1 or _unwrap(children[0]) != target:
        return AllocAccess("unavailable", "a direct array read is required")

    declarations = visible_declarations(target, data, language=language)
    record = declarations.get(claim[0])
    declaration = record[1] if record is not None else None
    if declaration is None or declaration.type != "declaration" or declaration.parent != body:
        return AllocAccess("unavailable", "a locally allocated object is required")
    declarators = declaration.children_by_field_name("declarator")
    if len(declarators) != 1 or declarators[0].type != "init_declarator":
        return AllocAccess("unavailable", "one initialized allocation declaration required")
    value = _unwrap(declarators[0].child_by_field_name("value"))
    pointer = declarators[0].child_by_field_name("declarator")
    if pointer is None or pointer.type != "pointer_declarator":
        return AllocAccess("unavailable", "a single-level object pointer is required")
    pointer_children = [child for child in pointer.named_children if child.type != "comment"]
    name = pointer_children[0] if len(pointer_children) == 1 else None
    if name is None or name.type != "identifier" or text(name) != claim[0]:
        return AllocAccess("unavailable", "a single-level object pointer is required")
    element = declaration.child_by_field_name("type")
    result_type = function.child_by_field_name("type")
    if any(not has_builtin_integer_type(node, text(node), language)
           or (text(node) != "char" and integer_type(text(node), abi) is None) for node in (element, result_type)):
        return AllocAccess("unavailable", "builtin element and return types required")
    if any(child.type in {"storage_class_specifier", "type_qualifier"} for child in declaration.named_children):
        return AllocAccess("unavailable", "automatic unqualified allocation required")
    element_size = builtin_integer_sizeof(text(element), abi)
    if element_size is None:
        return AllocAccess("unavailable", "element storage layout is unresolved")
    if value is None or value.type != "call_expression":
        return AllocAccess("unavailable", "one visible malloc initializer required")
    callee = value.child_by_field_name("function")
    arguments = value.child_by_field_name("arguments")
    if callee is None or callee.type != "identifier" or text(callee) != "malloc" or arguments is None:
        return AllocAccess("unavailable", "one visible malloc initializer required")
    sizes = [child for child in arguments.named_children if child.type != "comment"]
    counted = _allocation_count(sizes[0], text(element), element_size, data, abi, language) if len(sizes) == 1 else None
    if counted is None:
        return AllocAccess("unavailable", "allocation size must be the element count under an exact byte discipline")
    count_name, size_form = counted
    if count_name not in parameter_names:
        return AllocAccess("unavailable", "an immutable parameter element count is required")
    if any(node.type == "call_expression" and node != value for node in body_nodes):
        return AllocAccess("unavailable", "another call requires effect modeling")
    if any(node.type == "declaration" and node != declaration for node in body_nodes):
        return AllocAccess("unavailable", "additional objects require value-flow modeling")

    # The confirm direction needs the non-null path: a failed allocation is
    # a different defect from an out-of-bounds read of a live object.
    checks = [node for node in body_nodes
              if node.type == "if_statement" and node.parent == body
              and any(item.type == "identifier" and text(item) == claim[0]
                      for item in _nodes(node.child_by_field_name("condition") or node) or [])]
    tested = _null_check_shape(checks[0], claim[0], data) if len(checks) == 1 else None
    if tested is None or len(checks) != 1:
        return AllocAccess("unavailable", "one exact null-check exit is required")
    null_check = checks[0]
    if not declaration.end_byte <= null_check.start_byte <= null_check.end_byte <= target.start_byte:
        return AllocAccess("unavailable", "the null check must precede the access")
    for node in body_nodes:
        if node.type == "identifier" and text(node) == claim[0] and node not in (name, array, tested):
            return AllocAccess("unavailable", "the object has another use or escape")
        if node.type == "return_statement" and node != statement:
            values = [child for child in node.named_children if child.type != "comment"]
            if len(values) != 1 or values[0].type != "number_literal" or text(values[0]) != "0":
                return AllocAccess("unavailable", "other return effects are unsupported")

    guards = guards_for_operation(body, target, data, [claim[1], count_name],
                                  language=language, integer_abi=abi,
                                  admitted=(declaration, null_check))
    if guards.status == "unavailable":
        return AllocAccess("unavailable", "reaching guards unavailable")
    premises = guards.premises
    terms = [claim[1], count_name]
    model = model_for_integer_terms(target, data, terms, premises, abi, language=language, result_operands=terms)
    if model.status != "bound" or any(declarations[name][1].type != "parameter_declaration" for name, _ in model.types):
        return AllocAccess("unavailable", "immutable builtin parameter types required")
    kind = common_integer_type(terms, model.types, abi)
    if kind is None:
        return AllocAccess("unavailable", "a common index and count comparison type is required")
    return AllocAccess("bound", object_name=claim[0], index=claim[1], count=count_name,
                       element_type=text(element), element_size=element_size, size_form=size_form,
                       line=target.start_point[0] + 1, column=target.start_point[1] + 1,
                       profile=model.profile, width=kind.width, signed=kind.signed,
                       premises=premises, domains=model.domains, types=model.types,
                       parameters=tuple(parameter_types))


def _obligation(access):
    # A negative count converts to an enormous size_t request whose usable
    # extent is unmodeled, so `index >= count` only violates when the count
    # is non-negative. A negative index is below the object regardless.
    return f"{access.index} < 0 OR ({access.count} >= 0 AND {access.index} >= {access.count})"


def _solve_access(access):
    profile = BVProfile(access.width, access.signed)
    guards = [PathCondition(text, index) for index, text in enumerate(access.premises + access.domains)]
    if guards:
        entry = check_path_feasibility(guards, profile=profile, reduce_constraints=False)
        if entry.feasible is not True or entry.unknown or entry.unknown_reasons:
            return entry, None
    variables = {}
    index = make_var(access.index, variables, profile=profile)
    count = make_var(access.count, variables, profile=profile)
    zero = z3.BitVecVal(0, access.width)
    outside = z3.Or(lt(index, zero, access.signed),
                    z3.And(ge(count, zero, access.signed), ge(index, count, access.signed)))
    result = check_verb_feasibility([(_obligation(access), outside)],
                                    guards, variables, profile=profile, reduce_constraints=False)
    return None, result


def _witness_violation(access, model, abi):
    """Independently replay the comparison; (index, count, violation) or Nones."""
    values = validate_integer_witness(model, access.parameters, access.premises, abi)
    if values is None:
        return None, None, None
    index, count = values.get(access.index), values.get(access.count)
    if type(index) is not int or type(count) is not int:
        return None, None, None
    # Same-signedness operands no wider than the common frame convert
    # value-preservingly, so the mathematical comparison is the C one.
    return index, count, index < 0 or (count >= 0 and index >= count)


def check_alloc_bounds(source, hypothesis, *, language, integer_abi=None):
    """A source-linked function-entry counterexample; unsat claims nothing."""
    if not has_array_read_goal(hypothesis):
        return {"alloc_bounds_status": "unavailable", "violation": None,
                "reason": "closed positive array access goal required"}
    access = bind_alloc_access(source, hypothesis, language=language, integer_abi=integer_abi)
    details = {"alloc_bounds_status": "unavailable", "reason": access.reason, "violation": None}
    if access.status != "bound" or not _z3_available():
        return details
    scope = source_model_scope()
    scope["assumptions"] = list(scope["assumptions"]) + list(_ALLOCATION_ASSUMPTIONS)
    details.update(alloc_bounds_status="checked", source_access=asdict(access),
                   integer_abi=integer_abi_record(integer_abi), access_kind="read", **scope)
    # The entry and access probes share one default query budget; a
    # nested caller budget may tighten it, never extend it.
    with query_budget(DEFAULT_TIMEOUT_MS):
        entry, result = _solve_access(access)
    if entry is not None:
        details.update(entry_feasible=entry.feasible, reason="entry path is infeasible or unencodable")
        return details
    if result is None or result.unknown or result.unknown_reasons or result.feasible is None:
        details.update(reason="bounds obligation not completely solved")
        return details
    if result.feasible is not True:
        # Never report False: a size_t conversion or multiplication wrap
        # could shrink the real allocation below the symbolic count.
        details.update(violation=None,
                       reason="no counterexample found; allocation-size conversion and wrap are unmodeled, so no safety claim is made")
        return details
    model = dict(result.model)
    for name, _ in access.parameters:
        model.setdefault(name, 0)
    index, count, violation = _witness_violation(access, model, integer_abi)
    if violation is not True:
        details.update(reason="witness does not satisfy the source obligation")
        return details
    details.update(violation=True, reason=result.reasoning, model=model,
                   witness_index=index, witness_count=count, obligation=_obligation(access))
    return details
