"""Source-bound loop progression obligations for one fixed local array.

One ``T a[N];`` with a literal extent, one counted for-loop whose body is
exactly one literal store ``a[i] = <literal>``, a literal start and step,
and a loop bound that is either a literal or an immutable builtin integer
parameter declared with the counter's exact type. The visited indices form
a closed arithmetic progression, so the first index at or past the extent
is a literal: a sat witness shows one entry whose loop condition admits
that index, and a direct bounded re-execution of the source loop replays
the access independently. A safety verdict exists only where the exit
increment provably stays inside the counter's storage type; any possible
counter wrap declines instead of guessing the wrapped progression.
"""

from dataclasses import asdict, dataclass
import logging

from core.smt_solver import BVProfile, DEFAULT_TIMEOUT_MS, ge, lt, z3, z3_available as _z3_available
from core.smt_solver.session import query_budget
from core.smt_solver.path_feasibility import PathCondition, check_path_feasibility, check_verb_feasibility, make_var

from .arithmetic_guards import guards_for_operation
from .arithmetic_operation import _unwrap
from .arithmetic_types import common_integer_type, has_builtin_integer_type, integer_type, model_for_integer_terms
from .array_bounds import has_array_write_goal, parse_array_access_claim
from .array_index import affine_access_claim
from .condition_extraction import _get_parser
from .function_execution_frame import ordinary_function_frame
from .integer_abi import integer_abi_record, resolve_integer_abi
from .integer_literals import integer_literal_value, source_integer_atom
from .integer_witness import source_model_scope, validate_integer_witness
from .narrowing_bindings import callable_declarator, visible_declarations

logger = logging.getLogger(__name__)
_MAX_SOURCE_CHARS = 65536
_MAX_NODES = 2048
_MAX_EXTENT = 65536
_MAX_STEPS = 1 << 18
# Closed tree-sitter grammar for the admitted frame, not application names.
_FRAME_NODES = frozenset({
    "compound_statement", "declaration", "primitive_type", "sized_type_specifier",
    "array_declarator", "init_declarator", "identifier", "number_literal",
    "if_statement", "condition_clause", "parenthesized_expression",
    "binary_expression", "unary_expression", "update_expression",
    "assignment_expression", "expression_statement", "for_statement",
    "return_statement", "subscript_expression", "subscript_argument_list",
    "else_clause", "comment",
})


@dataclass(frozen=True)
class LoopAccess:
    status: str
    reason: str = ""
    object_name: str = ""
    index: str = ""
    bound: str = ""
    # "literal": the loop bound is a source constant and the whole loop is
    # re-executed directly. "parameter": the bound is one immutable builtin
    # integer parameter with the counter's exact declared type.
    bound_kind: str = ""
    bound_value: int = 0
    extent: int = 0
    start: int = 0
    step: int = 0
    comparison: str = ""
    first_violating_index: int = 0
    element_type: str = ""
    index_type: str = ""
    index_width: int = 0
    index_signed: bool = False
    # True when every admitted exit increment stays inside the counter's
    # storage type, so a no-counterexample result may claim safety.
    safe_exit_modeled: bool = False
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


def _literal(node, data):
    atom = source_integer_atom(node, data)
    return integer_literal_value(atom) if atom is not None else None


def _single_statement(node):
    """Unwrap one optional brace level around a single loop-body statement."""
    if node is not None and node.type == "compound_statement":
        children = [child for child in node.named_children if child.type != "comment"]
        node = children[0] if len(children) == 1 else None
    return node


def bind_loop_access(source, hypothesis, *, language, integer_abi=None):
    """Build a closed loop-progression obligation without guessing wrap behavior."""
    abi = resolve_integer_abi(integer_abi)
    claim = parse_array_access_claim(hypothesis, access_kind="write")
    if claim is not None and affine_access_claim(hypothesis) is not None:
        # An adjusted claim like `a[i + 1]` must never bind a bare `a[i]`.
        return LoopAccess("unavailable", "a bare-identifier index claim is required")
    if abi is None or claim is None or language not in {"c", "cpp"} or len(source) > _MAX_SOURCE_CHARS:
        return LoopAccess("unavailable", "target ABI, atomic access claim, or supported source unavailable")
    try:
        parser = _get_parser(language)
        if parser is None:
            return LoopAccess("unavailable", "source parser unavailable")
        data = source.encode("utf-8")
        root = parser.parse(data).root_node
    except Exception:
        logger.debug("loop access parse unavailable", exc_info=True)
        return LoopAccess("unavailable", "source parser unavailable")
    nodes = _nodes(root)
    if root.has_error or nodes is None:
        return LoopAccess("unavailable", "invalid or over-budget source")

    def text(node):
        return data[node.start_byte:node.end_byte].decode("utf-8") if node is not None else ""

    functions = [node for node in nodes if node.type == "function_definition"]
    if len(functions) != 1:
        return LoopAccess("unavailable", "one scoped function required")
    function = functions[0]
    body = function.child_by_field_name("body")
    function_declarator = function.child_by_field_name("declarator")
    if (function_declarator is None or function_declarator.type != "function_declarator"
            or callable_declarator(function) != function_declarator):
        return LoopAccess("unavailable", "plain function declaration required")
    if not ordinary_function_frame(function, data, language):
        return LoopAccess("unavailable", "function execution frame is unsupported")
    body_nodes = _nodes(body) if body is not None else None
    if body_nodes is None:
        return LoopAccess("unavailable", "function body unavailable")
    if any(node.type not in _FRAME_NODES for node in body_nodes):
        return LoopAccess("unavailable", "frame syntax or effects are unsupported")
    result_type = function.child_by_field_name("type")
    if text(result_type) != "void" and (not has_builtin_integer_type(result_type, text(result_type), language)
                                        or integer_type(text(result_type), abi) is None):
        return LoopAccess("unavailable", "a void or builtin integer return type is required")
    parameters = function_declarator.child_by_field_name("parameters")
    parameter_names, parameter_types = [], []
    for parameter in parameters.named_children if parameters is not None else []:
        if parameter.type == "comment":
            continue
        name = parameter.child_by_field_name("declarator")
        type_node = parameter.child_by_field_name("type")
        if (parameter.type == "parameter_declaration" and name is None
                and text(type_node) == "void" and len(parameter.named_children) == 1):
            continue  # an explicit empty C parameter list
        if parameter.type != "parameter_declaration" or name is None or name.type != "identifier" or not has_builtin_integer_type(type_node, text(type_node), language) or integer_type(text(type_node), abi) is None:
            return LoopAccess("unavailable", "plain builtin integer parameters required")
        if any(child not in (name, type_node) and child.type != "comment"
               and not (child.type == "type_qualifier" and text(child) == "const") for child in parameter.named_children):
            return LoopAccess("unavailable", "parameter attributes or qualifiers are unsupported")
        parameter_names.append(text(name))
        parameter_types.append((text(name), text(type_node)))
    if len(set(parameter_names)) != len(parameter_names) or claim[0] in parameter_names or claim[1] in parameter_names:
        return LoopAccess("unavailable", "parameter binding is ambiguous")

    loops = [node for node in body_nodes if node.type == "for_statement"]
    accesses = [node for node in body_nodes if node.type == "subscript_expression"]
    if len(loops) != 1 or len(accesses) != 1:
        return LoopAccess("unavailable", "one counted loop with one array access required")
    loop, target = loops[0], accesses[0]
    array = _unwrap(target.child_by_field_name("argument"))
    index = _unwrap(target.child_by_field_name("index"))
    if language == "cpp":
        indices = target.child_by_field_name("indices")
        named = [item for item in indices.named_children if item.type != "comment"] if indices is not None else []
        index = _unwrap(named[0]) if len(named) == 1 else None
    if (array is None or array.type != "identifier" or index is None or index.type != "identifier"
            or (text(array), text(index)) != claim):
        return LoopAccess("unavailable", "claim does not bind one atomic source access")

    # The counter: a literal-initialized declaration owned by the loop.
    initializer = loop.child_by_field_name("initializer")
    counter_type_node = initializer.child_by_field_name("type") if initializer is not None and initializer.type == "declaration" else None
    declarators = initializer.children_by_field_name("declarator") if initializer is not None else []
    init_declarator = declarators[0] if len(declarators) == 1 and declarators[0].type == "init_declarator" else None
    counter_name = init_declarator.child_by_field_name("declarator") if init_declarator is not None else None
    start = _literal(init_declarator.child_by_field_name("value"), data) if init_declarator is not None else None
    if (counter_type_node is None or counter_name is None or counter_name.type != "identifier"
            or text(counter_name) != claim[1] or start is None
            or not has_builtin_integer_type(counter_type_node, text(counter_type_node), language)):
        return LoopAccess("unavailable", "a literal-initialized loop counter declaration is required")
    counter_type = integer_type(text(counter_type_node), abi)
    if counter_type is None:
        return LoopAccess("unavailable", "the counter storage type is unresolved")
    if start < 0:
        return LoopAccess("unavailable", "a non-negative literal start is required")

    condition = _unwrap(loop.child_by_field_name("condition"))
    if condition is not None and condition.type == "condition_clause":
        condition = _unwrap(condition.child_by_field_name("value"))
    comparison = text(condition.child_by_field_name("operator")) if condition is not None and condition.type == "binary_expression" else ""
    left = _unwrap(condition.child_by_field_name("left")) if condition is not None and condition.type == "binary_expression" else None
    bound_node = _unwrap(condition.child_by_field_name("right")) if condition is not None and condition.type == "binary_expression" else None
    if comparison not in {"<", "<="} or left is None or left.type != "identifier" or text(left) != claim[1] or bound_node is None:
        return LoopAccess("unavailable", "a counter upper-bound loop condition is required")

    update = _unwrap(loop.child_by_field_name("update"))
    step = None
    if update is not None and update.type == "update_expression":
        argument = _unwrap(update.child_by_field_name("argument"))
        if (text(update.child_by_field_name("operator")) == "++" and argument is not None
                and argument.type == "identifier" and text(argument) == claim[1]):
            step = 1
    elif update is not None and update.type == "assignment_expression":
        argument = _unwrap(update.child_by_field_name("left"))
        if (text(update.child_by_field_name("operator")) == "+=" and argument is not None
                and argument.type == "identifier" and text(argument) == claim[1]):
            step = _literal(update.child_by_field_name("right"), data)
    if step is None or not 1 <= step <= _MAX_EXTENT:
        return LoopAccess("unavailable", "a literal positive counter increment is required")

    store = _single_statement(loop.child_by_field_name("body"))
    assignment = _unwrap(store.named_children[0]) if store is not None and store.type == "expression_statement" and len([child for child in store.named_children if child.type != "comment"]) == 1 else None
    if (assignment is None or assignment.type != "assignment_expression"
            or text(assignment.child_by_field_name("operator")) != "="
            or _unwrap(assignment.child_by_field_name("left")) != target
            or _literal(assignment.child_by_field_name("right"), data) is None):
        return LoopAccess("unavailable", "the loop body must be exactly one literal array store")

    declarations = visible_declarations(target, data, language=language)
    record = declarations.get(claim[0])
    declaration = record[1] if record is not None else None
    if declaration is None or declaration.type != "declaration" or declaration.parent != body:
        return LoopAccess("unavailable", "a local fixed array is required")
    array_declarators = declaration.children_by_field_name("declarator")
    array_declarator = array_declarators[0] if len(array_declarators) == 1 and array_declarators[0].type == "array_declarator" else None
    declared_name = array_declarator.child_by_field_name("declarator") if array_declarator is not None else None
    extent = _literal(array_declarator.child_by_field_name("size"), data) if array_declarator is not None else None
    element = declaration.child_by_field_name("type")
    if (declared_name is None or declared_name.type != "identifier" or text(declared_name) != claim[0]
            or extent is None or not 1 <= extent <= _MAX_EXTENT
            or not has_builtin_integer_type(element, text(element), language)
            or (text(element) != "char" and integer_type(text(element), abi) is None)):
        return LoopAccess("unavailable", "a literal-extent builtin-element local array is required")
    if any(child.type in {"storage_class_specifier", "type_qualifier"} for child in declaration.named_children):
        return LoopAccess("unavailable", "automatic unqualified array storage required")
    if declaration.end_byte > loop.start_byte:
        return LoopAccess("unavailable", "the array declaration must precede the loop")
    if any(node.type == "declaration" and node not in (declaration, initializer) for node in body_nodes):
        return LoopAccess("unavailable", "additional objects require value-flow modeling")

    bound_name, bound_value = "", 0
    if bound_node.type == "identifier":
        bound_name = text(bound_node)
        if bound_name not in parameter_names:
            return LoopAccess("unavailable", "an immutable parameter loop bound is required")
        if dict(parameter_types)[bound_name] != text(counter_type_node):
            # One declared type gives one promoted comparison frame; mixed
            # counter/bound conversions are not modeled here.
            return LoopAccess("unavailable", "the bound must share the counter's declared type")
    else:
        literal_bound = _literal(bound_node, data)
        if literal_bound is None or not 0 <= literal_bound <= (1 << (abi.int_bits - 1)) - 1:
            return LoopAccess("unavailable", "a non-negative int-range literal bound is required")
        bound_value = literal_bound

    # Identifier accounting: the array, counter, and bound have no other
    # uses or escapes anywhere in the frame.
    counter_sites = {counter_name, left, argument, index}
    for node in body_nodes:
        if node.type != "identifier":
            continue
        if text(node) == claim[0] and node not in (declared_name, array):
            return LoopAccess("unavailable", "the array has another use or escape")
        if text(node) == claim[1] and node not in counter_sites:
            return LoopAccess("unavailable", "the counter has another use or escape")
        if bound_name and text(node) == bound_name and node != bound_node and node.start_byte >= loop.start_byte:
            return LoopAccess("unavailable", "the bound has another use inside the loop frame")
    for node in body_nodes:
        if node.type == "return_statement":
            values = [child for child in node.named_children if child.type != "comment"]
            if values and (len(values) != 1 or values[0].type != "number_literal" or text(values[0]) != "0"):
                return LoopAccess("unavailable", "other return effects are unsupported")

    storage_max = (1 << (counter_type.width - 1)) - 1 if counter_type.signed else (1 << counter_type.width) - 1
    first = start if start >= extent else start + ((extent - start + step - 1) // step) * step
    if not (start <= storage_max and first <= storage_max):
        return LoopAccess("unavailable", "the first out-of-bounds index is not representable in the counter type")
    safe_exit_modeled = first - 1 + step <= storage_max

    guards = guards_for_operation(body, loop, data, [bound_name] if bound_name else [],
                                  language=language, integer_abi=abi)
    if guards.status == "unavailable":
        return LoopAccess("unavailable", "reaching guards unavailable")
    premises = guards.premises
    if not bound_name:
        if premises:
            # A literal-bound loop is decided by direct execution alone;
            # entry constraints would need their own reachability model.
            return LoopAccess("unavailable", "entry guards on a fixed literal bound are not modeled")
        kind = counter_type
        profile, domains, types = kind.profile, (), ()
    else:
        model = model_for_integer_terms(target, data, [bound_name], premises, abi, language=language, result_operands=[bound_name])
        if model.status != "bound" or any(declarations[name][1].type != "parameter_declaration" for name, _ in model.types):
            return LoopAccess("unavailable", "immutable builtin parameter types required")
        kind = common_integer_type([bound_name], model.types, abi)
        if kind is None:
            return LoopAccess("unavailable", "a common counter and bound comparison type is required")
        profile, domains, types = model.profile, model.domains, model.types
    frame_max = (1 << (kind.width - 1)) - 1 if kind.signed else (1 << kind.width) - 1
    if first > frame_max or (not bound_name and bound_value > frame_max):
        return LoopAccess("unavailable", "the first out-of-bounds index is not representable in the comparison frame")
    return LoopAccess("bound", object_name=claim[0], index=claim[1],
                      bound=bound_name or str(bound_value),
                      bound_kind="parameter" if bound_name else "literal", bound_value=bound_value,
                      extent=extent, start=start, step=step, comparison=comparison,
                      first_violating_index=first, element_type=text(element),
                      index_type=text(counter_type_node), index_width=counter_type.width,
                      index_signed=counter_type.signed, safe_exit_modeled=safe_exit_modeled,
                      line=target.start_point[0] + 1, column=target.start_point[1] + 1,
                      profile=profile, width=kind.width, signed=kind.signed,
                      premises=premises, domains=domains, types=types,
                      parameters=tuple(parameter_types))


def _obligation(access):
    # The progression visits its first at-or-past-extent index exactly when
    # that literal still satisfies the source loop condition.
    return f"{access.first_violating_index} {access.comparison} {access.bound}"


def _execute_loop(access, bound_value):
    """Directly run the source loop with exact mathematical values.

    Returns ``(first out-of-bounds index, True)``, ``(None, False)`` on a
    modeled safe exit, or ``(None, None)`` when execution would leave the
    counter's storage type or the step budget — never a guessed verdict.
    """
    storage_max = (1 << (access.index_width - 1)) - 1 if access.index_signed else (1 << access.index_width) - 1
    counter, steps = access.start, 0
    while counter < bound_value if access.comparison == "<" else counter <= bound_value:
        if counter >= access.extent:
            return counter, True
        steps += 1
        if steps > _MAX_STEPS:
            return None, None
        counter += access.step
        if counter > storage_max:
            return None, None
    return None, False


def _solve_bound(access):
    profile = BVProfile(access.width, access.signed)
    guards = [PathCondition(text, index) for index, text in enumerate(access.premises + access.domains)]
    if guards:
        entry = check_path_feasibility(guards, profile=profile, reduce_constraints=False)
        if entry.feasible is not True or entry.unknown or entry.unknown_reasons:
            return entry, None
    variables = {}
    bound = make_var(access.bound, variables, profile=profile)
    first = z3.BitVecVal(access.first_violating_index, access.width)
    reached = (lt(first, bound, access.signed) if access.comparison == "<"
               else ge(bound, first, access.signed))
    result = check_verb_feasibility([(_obligation(access), reached)],
                                    guards, variables, profile=profile, reduce_constraints=False)
    return None, result


def _witness_violation(access, model, abi):
    """Independently re-execute the loop; (index, bound, violation) or Nones."""
    values = validate_integer_witness(model, access.parameters, access.premises, abi)
    if values is None:
        return None, None, None
    bound_value = values.get(access.bound)
    if type(bound_value) is not int:
        return None, None, None
    index, violation = _execute_loop(access, bound_value)
    return index, bound_value, violation


def check_loop_bounds(source, hypothesis, *, language, integer_abi=None):
    """A source-linked entry or direct execution; wrap risks claim nothing."""
    if not has_array_write_goal(hypothesis):
        return {"loop_bounds_status": "unavailable", "violation": None,
                "reason": "closed array write objective required"}
    access = bind_loop_access(source, hypothesis, language=language, integer_abi=integer_abi)
    details = {"loop_bounds_status": "unavailable", "reason": access.reason, "violation": None}
    if access.status != "bound":
        return details
    details.update(loop_bounds_status="checked", source_access=asdict(access),
                   integer_abi=integer_abi_record(integer_abi), access_kind="write", **source_model_scope())
    if access.bound_kind == "literal":
        index, violation = _execute_loop(access, access.bound_value)
        if violation is True and index == access.first_violating_index:
            details.update(violation=True, model={}, witness_index=index,
                           witness_bound=access.bound_value, obligation=_obligation(access),
                           reason="direct bounded execution reaches the access past the extent")
        elif violation is False:
            # The execution itself checked every increment against the
            # counter's storage type, so this exit is fully modeled.
            details.update(violation=False, reason="direct bounded execution exits before the extent")
        else:
            details.update(violation=None,
                           reason="loop execution leaves the modeled counter domain, so no verdict is made")
        return details
    if not _z3_available():
        details.update(loop_bounds_status="unavailable", reason="solver unavailable")
        return details
    # The entry and bound probes share one default query budget; a nested
    # caller budget may tighten it, never extend it.
    with query_budget(DEFAULT_TIMEOUT_MS):
        entry, result = _solve_bound(access)
    if entry is not None:
        details.update(entry_feasible=entry.feasible, reason="entry path is infeasible or unencodable")
        return details
    if result is None or result.unknown or result.unknown_reasons or result.feasible is None:
        details.update(reason="bound obligation not completely solved")
        return details
    if result.feasible is not True:
        if access.safe_exit_modeled:
            details.update(violation=False,
                           reason="no admitted entry lets the loop condition reach the first out-of-bounds index")
        else:
            # An exit increment could leave the counter's storage type, and
            # the wrapped progression is unmodeled.
            details.update(violation=None,
                           reason="no counterexample found; a possible counter wrap on exit is unmodeled, so no safety claim is made")
        return details
    model = dict(result.model)
    for name, _ in access.parameters:
        model.setdefault(name, 0)
    index, bound_value, violation = _witness_violation(access, model, integer_abi)
    if violation is not True or index != access.first_violating_index:
        details.update(reason="witness does not re-execute the loop to the obligation index")
        return details
    details.update(violation=True, reason=result.reasoning, model=model,
                   witness_index=index, witness_bound=bound_value, obligation=_obligation(access))
    return details
