"""Source-bound bounds obligations for a deliberately small C/C++ frame.

One local fixed-size builtin array, one read indexed by an immutable integer
parameter, supported branch guards, defined scalar prefixes, and an explicit
target ABI. Witnesses are conditional on the supplied source representing the active build and on
function-entry parameter domains; caller reachability is not established.
"""

from dataclasses import asdict, dataclass
import logging
import operator
import re

from core.smt_solver import BVProfile, DEFAULT_TIMEOUT_MS, ge, lt, z3, z3_available as _z3_available
from core.smt_solver.session import query_budget
from core.smt_solver.path_feasibility import PathCondition, check_path_feasibility, check_verb_feasibility, make_var
from core.smt_solver.sizeof_model import builtin_integer_sizeof

from .arithmetic_operation import _INTEGER_LITERAL_RE, _unwrap
from .array_index import affine_access_claim, evaluate_array_index, index_expression, source_index
from .arithmetic_guards import guards_for_operation
from .arithmetic_types import common_integer_type, has_builtin_integer_type, integer_type, model_for_integer_terms
from .condition_extraction import _get_parser
from .function_execution_frame import ordinary_function_frame
from .integer_goal import ARRAY_READ_GOALS, parse_integer_goal
from .integer_abi import integer_abi_record, resolve_integer_abi
from .integer_witness import source_model_scope, validate_integer_witness
from .narrowing_bindings import callable_declarator, visible_declarations

logger = logging.getLogger(__name__)
_MAX_SOURCE_CHARS = 65536
_MAX_NODES = 2048
_WRITE_CLAIM = re.compile(r"\b(?:writ(?:e|es|ing|ten)|stor(?:e|es|ing)|overwrit(?:e|es|ing|ten))\b", re.IGNORECASE)
_ACCESS = re.compile(r"(?<![\w$.>])([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*([A-Za-z_][A-Za-z0-9_]*)\s*\]")
# Closed tree-sitter grammar for the admitted frame, not application names.
_FRAME_NODES = frozenset({
    "compound_statement", "declaration", "primitive_type", "sized_type_specifier",
    "init_declarator", "array_declarator", "identifier", "number_literal",
    "initializer_list", "if_statement", "condition_clause", "parenthesized_expression",
    "binary_expression", "unary_expression", "return_statement", "subscript_expression",
    "subscript_argument_list", "else_clause", "comment", "sizeof_expression", "type_descriptor",
})
_COMPARISONS = {"<": operator.lt, "<=": operator.le, ">": operator.gt, ">=": operator.ge, "==": operator.eq, "!=": operator.ne}


@dataclass(frozen=True)
class ArrayAccess:
    status: str
    reason: str = ""
    object_name: str = ""
    index: str = ""
    extent: int = 0
    line: int = 0
    column: int = 0
    profile: str = ""
    width: int = 0
    signed: bool = False
    premises: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    types: tuple[tuple[str, str], ...] = ()
    parameters: tuple[tuple[str, str], ...] = ()
    index_operator: str = ""
    index_offset: int = 0


def parse_array_access_claim(hypothesis):
    """One unambiguous atomic object[index] reference, preserving case."""
    if not isinstance(hypothesis, str) or len(hypothesis) > 8192 or _WRITE_CLAIM.search(hypothesis):
        return None
    affine = affine_access_claim(hypothesis)
    if affine is not None:
        return affine[0], affine[1]
    for quoted in re.finditer(r"`([^`\r\n]*)`", hypothesis):
        text = quoted.group(1)
        if "[" in text and _ACCESS.fullmatch(text.strip()) is None:
            return None
    selected = None
    for match in _ACCESS.finditer(hypothesis):
        before = match.start() - 1
        while before >= 0 and hypothesis[before].isspace():
            before -= 1
        if before >= 0 and (hypothesis[before] in ".>*&" or hypothesis[max(0, before - 1):before + 1] == "::"):
            return None
        after = match.end()
        while after < len(hypothesis) and hypothesis[after].isspace():
            after += 1
        if after < len(hypothesis) and hypothesis[after] in "[(.+-*/%":
            return None
        pair = match.group(1), match.group(2)
        if selected is not None and selected != pair:
            return None
        selected = pair
    return selected


def _nodes(root):
    result, pending = [], [root]
    while pending:
        item = pending.pop()
        result.append(item)
        if len(result) > _MAX_NODES:
            return None
        pending.extend(reversed(item.named_children))
    return result


def bind_array_access(source, hypothesis, *, language, integer_abi=None):
    """Build an access obligation without borrowing extents or mutable values."""
    return _bind_array_access(source, hypothesis, language=language, integer_abi=integer_abi, candidate_only=False)


def array_access_candidate(source, hypothesis, *, language, integer_abi=None):
    """Bind syntax, extent and index type only; never prove a reaching prefix.

    The candidate status cannot enter the native bounds oracle. Its full
    binder must still establish the source path and prefix definedness.
    """
    return _bind_array_access(source, hypothesis, language=language, integer_abi=integer_abi, candidate_only=True)


def _bind_array_access(source, hypothesis, *, language, integer_abi, candidate_only):
    abi = resolve_integer_abi(integer_abi)
    claim = parse_array_access_claim(hypothesis)
    affine = affine_access_claim(hypothesis)
    index_operator, index_offset = affine[2:] if affine is not None else ("", 0)
    if abi is None or claim is None or language not in {"c", "cpp"} or len(source) > _MAX_SOURCE_CHARS:
        return ArrayAccess("unavailable", "target ABI, atomic access claim, or supported source unavailable")
    try:
        parser = _get_parser(language)
        if parser is None:
            return ArrayAccess("unavailable", "source parser unavailable")
        data = source.encode("utf-8")
        root = parser.parse(data).root_node
    except Exception:
        logger.debug("array access parse unavailable", exc_info=True)
        return ArrayAccess("unavailable", "source parser unavailable")
    nodes = _nodes(root)
    if root.has_error or nodes is None:
        return ArrayAccess("unavailable", "invalid or over-budget source")

    def text(node):
        return data[node.start_byte:node.end_byte].decode("utf-8") if node is not None else ""

    functions = [node for node in nodes if node.type == "function_definition"]
    if len(functions) != 1:
        return ArrayAccess("unavailable", "one scoped function required")
    function = functions[0]
    body = function.child_by_field_name("body")
    function_declarator = function.child_by_field_name("declarator")
    if (function_declarator is None or function_declarator.type != "function_declarator"
            or callable_declarator(function) != function_declarator):
        return ArrayAccess("unavailable", "plain function declaration required")
    if not ordinary_function_frame(function, data, language):
        return ArrayAccess("unavailable", "function execution frame is unsupported")
    body_nodes = _nodes(body) if body is not None else None
    if body_nodes is None:
        return ArrayAccess("unavailable", "function body unavailable")
    if any(node.type not in _FRAME_NODES for node in body_nodes):
        return ArrayAccess("unavailable", "frame syntax or effects are unsupported")
    parameters = function_declarator.child_by_field_name("parameters")
    if parameters is None:
        return ArrayAccess("unavailable", "parameter declarations unavailable")
    parameter_names, parameter_types = [], []
    for parameter in parameters.named_children:
        if parameter.type == "comment":
            continue
        name = parameter.child_by_field_name("declarator")
        type_node = parameter.child_by_field_name("type")
        if parameter.type != "parameter_declaration" or name is None or name.type != "identifier" or not has_builtin_integer_type(type_node, text(type_node), language) or integer_type(text(type_node), abi) is None:
            return ArrayAccess("unavailable", "plain builtin integer parameters required")
        if any(child not in (name, type_node) and child.type != "comment"
               and not (child.type == "type_qualifier" and text(child) == "const") for child in parameter.named_children):
            return ArrayAccess("unavailable", "parameter attributes or qualifiers are unsupported")
        parameter_names.append(text(name))
        parameter_types.append((text(name), text(type_node)))
    if len(set(parameter_names)) != len(parameter_names) or claim[0] in parameter_names:
        return ArrayAccess("unavailable", "parameter binding is ambiguous")
    accesses = [node for node in body_nodes if node.type == "subscript_expression"]
    if len(accesses) != 1:
        return ArrayAccess("unavailable", "one actual array access required")
    target = accesses[0]
    array = _unwrap(target.child_by_field_name("argument"))
    index = _unwrap(target.child_by_field_name("index"))
    if language == "cpp":
        indices = target.child_by_field_name("indices")
        index = _unwrap(indices.named_children[0]) if indices is not None and len(indices.named_children) == 1 else None
    index_shape = source_index(index, data)
    if (array is None or array.type != "identifier" or index_shape is None
            or (text(array), index_shape[0]) != claim or index_shape[1:] != (index_operator, index_offset)):
        return ArrayAccess("unavailable", "claim does not bind one atomic source access")
    statement = target.parent
    while statement is not None and statement.type == "parenthesized_expression":
        statement = statement.parent
    children = [child for child in statement.named_children if child.type != "comment"] if statement is not None else []
    if statement is None or statement.type != "return_statement" or len(children) != 1:
        return ArrayAccess("unavailable", "a direct array read is required")
    if _unwrap(children[0]) != target:
        return ArrayAccess("unavailable", "array read is embedded in another operation")

    declarations = visible_declarations(target, data, language=language)
    record = declarations.get(claim[0])
    declaration = record[1] if record is not None else None
    if declaration is None or declaration.type != "declaration" or declaration.parent.type != "compound_statement":
        return ArrayAccess("unavailable", "a local array object is required, not a pointer or array parameter")
    declarators = declaration.children_by_field_name("declarator")
    if len(declarators) != 1:
        return ArrayAccess("unavailable", "one local array declaration required")
    declarator = declarators[0]
    initializer = None
    if declarator.type == "init_declarator":
        initializer = declarator.child_by_field_name("value")
        declarator = declarator.child_by_field_name("declarator")
    if declarator is None or declarator.type != "array_declarator":
        return ArrayAccess("unavailable", "array object declaration unavailable")
    name = declarator.child_by_field_name("declarator")
    size = declarator.child_by_field_name("size")
    if name is None or name.type != "identifier" or text(name) != claim[0] or size is None:
        return ArrayAccess("unavailable", "a one-dimensional bound extent is required")
    if size.type == "number_literal":
        literal = text(size)
        if len(literal) > 22 or not _INTEGER_LITERAL_RE.fullmatch(literal):
            return ArrayAccess("unavailable", "extent literal semantics unavailable")
        extent = int(literal, 16 if literal.lower().startswith("0x") else 10)
    elif size.type == "sizeof_expression":
        descriptor = size.child_by_field_name("type")
        type_node = descriptor.child_by_field_name("type") if descriptor is not None else None
        if descriptor is None or len(descriptor.named_children) != 1 or not has_builtin_integer_type(type_node, text(type_node), language):
            return ArrayAccess("unavailable", "sizeof extent needs a builtin integer type")
        extent = builtin_integer_sizeof(text(type_node), abi)
        if extent is None:
            return ArrayAccess("unavailable", "sizeof storage layout is unresolved")
    else:
        return ArrayAccess("unavailable", "extent semantics unavailable")
    if not 0 < extent <= (1 << (abi.int_bits - 1)) - 1:
        return ArrayAccess("unavailable", "extent outside supported literal range")
    element = declaration.child_by_field_name("type")
    result_type = function.child_by_field_name("type")
    if any(not has_builtin_integer_type(node, text(node), language)
           or (text(node) != "char" and integer_type(text(node), abi) is None) for node in (element, result_type)):
        return ArrayAccess("unavailable", "builtin element and return types required")
    if any(child.type in {"storage_class_specifier", "type_qualifier"} for child in declaration.named_children):
        return ArrayAccess("unavailable", "automatic unqualified array required")
    if initializer is not None:
        values = [child for child in initializer.named_children if child.type != "comment"]
        if initializer.type != "initializer_list" or len(values) > extent or any(child.type != "number_literal" or text(child) != "0" for child in values):
            return ArrayAccess("unavailable", "array initializer effects are unsupported")

    for node in body_nodes:
        if node.type == "identifier" and text(node) == claim[0] and node not in (name, array):
            return ArrayAccess("unavailable", "the object has another use or escape")
        if node.type == "declaration" and node != declaration:
            extras = node.children_by_field_name("declarator")
            if not extras or any(extra.type != "init_declarator"
                                 or extra.child_by_field_name("declarator") is None
                                 or extra.child_by_field_name("declarator").type != "identifier"
                                 or extra.child_by_field_name("value") is None for extra in extras):
                return ArrayAccess("unavailable", "additional objects require value-flow modeling")
        if node.type == "return_statement" and node != statement:
            children = [child for child in node.named_children if child.type != "comment"]
            if len(children) != 1 or children[0].type != "number_literal" or text(children[0]) != "0":
                return ArrayAccess("unavailable", "other return effects are unsupported")
    premises = ()
    if not candidate_only:
        extra = {'selected_value': index} if index_operator else {}
        guards = guards_for_operation(body, target, data, [claim[1]],
                                      language=language, integer_abi=abi, **extra)
        if guards.status == "unavailable":
            return ArrayAccess("unavailable", "reaching guards unavailable")
        premises = guards.premises
    # Full binding checks prefix definedness over complete entry domains;
    # candidates carry no such credit. Only the index and reaching guards
    # belong in a proved access's typed formula;
    # unrelated scalar locals must not become unconstrained entry inputs.
    terms = [claim[1]]
    model = model_for_integer_terms(target, data, terms, premises, abi, language=language, result_operands=[claim[1]])
    if model.status != "bound" or any(declarations[name][1].type != "parameter_declaration" for name, _ in model.types):
        return ArrayAccess("unavailable", "immutable builtin parameter types required")
    kind = integer_type(dict(model.types)[claim[1]], abi)
    if index_operator and common_integer_type([claim[1], str(index_offset)], model.types, abi) is None:
        return ArrayAccess("unavailable", "affine index literal conversion is unsupported")
    return ArrayAccess("candidate" if candidate_only else "bound",
                       reason="source candidate; reaching prefix unverified" if candidate_only else "",
                       object_name=claim[0], index=claim[1], extent=extent,
                       line=target.start_point[0] + 1, column=target.start_point[1] + 1,
                       profile=model.profile, width=kind.promoted_width, signed=kind.promoted_signed,
                       premises=premises, domains=model.domains, types=model.types,
                       parameters=tuple(parameter_types), index_operator=index_operator, index_offset=index_offset)


def _solve_access(access):
    profile = BVProfile(access.width, access.signed)
    guards = [PathCondition(text, index) for index, text in enumerate(access.premises + access.domains)]
    if guards:
        entry = check_path_feasibility(guards, profile=profile, reduce_constraints=False)
        if entry.feasible is not True or entry.unknown or entry.unknown_reasons:
            return entry, None
    variables = {}
    index = make_var(access.index, variables, profile=profile)
    if access.index_operator:
        offset = z3.BitVecVal(access.index_offset, access.width)
        if access.index_operator == '%':
            index = z3.SRem(index, offset) if access.signed else z3.URem(index, offset)
        else:
            index = index + offset if access.index_operator == '+' else index - offset
    outside = z3.Or(lt(index, z3.BitVecVal(0, access.width), access.signed),
                    ge(index, z3.BitVecVal(access.extent, access.width), access.signed))
    result = check_verb_feasibility([(f"{index_expression(access)} < 0 OR {index_expression(access)} >= {access.extent}", outside)],
                                    guards, variables, profile=profile, reduce_constraints=False)
    return None, result


def _valid_witness(access, model, abi):
    if validate_integer_witness(model, access.parameters, access.premises, abi) is None:
        return False
    index = evaluate_array_index(access, model, abi)
    return index is not None and (index < 0 or index >= access.extent)


def has_array_read_goal(hypothesis):
    """Admit only a complete positive read goal, without binding its source."""
    goal = hypothesis
    if isinstance(goal, str) and "`" not in goal and len(goal) <= 8192:
        accesses = list(_ACCESS.finditer(goal))
        if len(accesses) == 1:
            access_match = accesses[0]
            goal = (goal[:access_match.start()] + "`" + access_match.group() + "`"
                    + goal[access_match.end():])
    return parse_integer_goal(goal, ARRAY_READ_GOALS) is not None


def check_array_bounds(source, hypothesis, *, language, integer_abi=None):
    """A source-linked function-entry counterexample; safe sites never refute a function."""
    if not has_array_read_goal(hypothesis):
        return {"array_bounds_status": "unavailable", "violation": None,
                "reason": "closed positive array read goal required"}
    access = bind_array_access(source, hypothesis, language=language, integer_abi=integer_abi)
    details = {"array_bounds_status": "unavailable", "reason": access.reason, "violation": None}
    if access.status != "bound" or not _z3_available():
        return details
    details.update(array_bounds_status="checked", source_access=asdict(access),
                   integer_abi=integer_abi_record(integer_abi), access_kind="read", **source_model_scope())
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
    details.update(violation=result.feasible, reason=result.reasoning)
    if result.feasible:
        # Z3 may omit irrelevant/tautological parameters. Complete them
        # with zero, then independently check every source guard and type.
        model = dict(result.model)
        for name, _ in access.parameters:
            model.setdefault(name, 0)
        if not _valid_witness(access, model, integer_abi):
            details.update(violation=None, reason="witness does not satisfy the source obligation")
            return details
        details.update(model=model, witness_index=evaluate_array_index(access, model, integer_abi),
                       obligation=f"{index_expression(access)} < 0 OR {index_expression(access)} >= {access.extent}")
    return details
