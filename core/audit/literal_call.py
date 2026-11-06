"""One-edge source obligations for unconditional, literal-only C/C++ calls.

These prove a violation conditional on entry to the cited wrapper, not that
an application entry point reaches that wrapper. Source is supplied data;
no target code is compiled or executed and no files are opened here.
"""

from dataclasses import asdict
import hashlib
import logging

from ._util import IDENTIFIER_RE
from .arithmetic_claim import parse_arithmetic_claim
from .arithmetic_operation import ArithmeticOperation, _INTEGER_LITERAL_RE, _unwrap, bind_arithmetic_operation
from .arithmetic_types import has_builtin_integer_type, integer_type
from .array_bounds import ArrayAccess, bind_array_access, parse_array_access_claim
from .condition_extraction import _get_parser
from .integer_abi import integer_abi_record, resolve_integer_abi
from .integer_witness import evaluate_integer_operation, validate_integer_witness

MAX_SOURCE_CHARS = 65536
_MAX_NODES = 2048
_MAX_SITES = 40
logger = logging.getLogger(__name__)


def literal_call_binding(source, function_name, verb, hypothesis, integer_abi, site_lines, language="c"):
    """Bind worker replies to the complete caller/callee source and query."""
    return {
        "query_contract": "literal-direct-call-v1",
        "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "function": function_name,
        "verb": verb,
        "language": language,
        "hypothesis_sha256": hashlib.sha256(hypothesis.encode("utf-8", "surrogatepass")).hexdigest(),
        "integer_abi": integer_abi_record(integer_abi),
        "site_lines": site_lines,
    }


def _nodes(root):
    nodes, pending = [], [root]
    while pending:
        node = pending.pop()
        nodes.append(node)
        if len(nodes) > _MAX_NODES:
            return None
        pending.extend(reversed(node.named_children))
    return nodes


def _signature(function, text, abi, language):
    body = function.child_by_field_name("body")
    result = function.child_by_field_name("type")
    declarator = function.child_by_field_name("declarator")
    if body is None or declarator is None or declarator.type != "function_declarator":
        return None
    name = declarator.child_by_field_name("declarator")
    params = declarator.child_by_field_name("parameters")
    if name is None or name.type != "identifier" or not IDENTIFIER_RE.fullmatch(text(name)) or params is None:
        return None
    if not has_builtin_integer_type(result, text(result), language) or integer_type(text(result), abi) is None:
        return None
    for child in function.named_children:
        if child in (body, result, declarator) or child.type == "comment":
            continue
        if child.type in {"storage_class_specifier", "function_specifier"} and text(child) in {"static", "extern", "inline"}:
            continue
        return None
    if any(child not in (name, params) and child.type != "comment" for child in declarator.named_children):
        return None
    parameters = []
    children = [child for child in params.named_children if child.type != "comment"]
    if len(children) == 1 and text(children[0]) == "void":
        children = []
    for parameter in children:
        ptype, pname = parameter.child_by_field_name("type"), parameter.child_by_field_name("declarator")
        if parameter.type != "parameter_declaration" or pname is None or pname.type != "identifier":
            return None
        if not has_builtin_integer_type(ptype, text(ptype), language) or integer_type(text(ptype), abi) is None:
            return None
        if any(child not in (ptype, pname) and child.type != "comment"
               and not (child.type == "type_qualifier" and text(child) == "const") for child in parameter.named_children):
            return None
        parameters.append((text(pname), text(ptype)))
    if len(parameters) > 8 or len({name for name, _ in parameters}) != len(parameters):
        return None
    return text(name), tuple(parameters), body


def _literal(node, text, abi):
    node = _unwrap(node)
    negative = False
    if node is not None and node.type == "unary_expression" and text(node.child_by_field_name("operator")) == "-":
        negative = True
        node = _unwrap(node.child_by_field_name("argument"))
    if node is None or node.type != "number_literal":
        return None
    literal = text(node)
    # Pinned C/C++ grammars may include the minus in number_literal.
    if literal.startswith("-") and not negative:
        negative, literal = True, literal[1:]
    if not _INTEGER_LITERAL_RE.fullmatch(literal):
        return None
    if len(literal) > 22:
        return None
    value = int(literal, 16 if literal.lower().startswith("0x") else 10)
    # Only unambiguous int literals. Wider/suffixed literals and conversion
    # wrap require explicit C conversion rules, not Python int coercion.
    if value > (1 << (abi.int_bits - 1)) - 1:
        return None
    return -value if negative else value


def check_literal_calls(source, function_name, verb, hypothesis, integer_abi, site_lines, language="c"):
    """Check complete literal argument tuples against the admitted callee."""
    result = {"status": "unavailable", "calls": [], "reason": "unsupported source or call frame"}
    abi = resolve_integer_abi(integer_abi)
    if abi is None or language not in {"c", "cpp"} or len(source) > MAX_SOURCE_CHARS:
        return result
    if not isinstance(site_lines, list) or not 0 < len(site_lines) <= _MAX_SITES or any(type(line) is not int or line <= 0 for line in site_lines):
        return result
    if verb not in {"check-overflow", "check-array-bounds"}:
        return result
    result["binding"] = literal_call_binding(source, function_name, verb, hypothesis, abi, site_lines, language)
    parser = _get_parser(language)
    if parser is None:
        return result
    data = source.encode("utf-8")
    root = parser.parse(data).root_node
    nodes = _nodes(root)
    if root.has_error or nodes is None or any(child.type not in {"function_definition", "comment"} for child in root.named_children):
        return result

    def text(node):
        return data[node.start_byte:node.end_byte].decode("utf-8") if node is not None else ""

    functions = [node for node in root.named_children if node.type == "function_definition"]
    signatures = [(node, _signature(node, text, abi, language)) for node in functions]
    callees = [(node, signature) for node, signature in signatures if signature is not None and signature[0] == function_name]
    if len(callees) != 1:
        return result
    callee, (_, parameters, _) = callees[0]
    # Reject same-name definitions even if one has an unsupported signature.
    from .probe_function_scope import source_for_function
    _, selected = source_for_function(source, "source." + language, function_name)
    if selected is None:
        return result
    if verb == "check-array-bounds":
        obligation = bind_array_access(selected, hypothesis, language=language, integer_abi=abi)
        if obligation.status != "bound":
            return result
    else:
        claim = parse_arithmetic_claim(hypothesis)
        if claim is None:
            return result
        obligation = bind_arithmetic_operation(selected, list(claim.operands), claim.operator, language=language, integer_abi=abi)
        if obligation.status != "bound" or obligation.type_status != "bound" or obligation.guard_status == "unavailable":
            return result
    result.update(status="checked", reason="literal caller-entry obligations evaluated",
                  proof_scope="caller-entry-source-model", callee_obligation=asdict(obligation),
                  parameter_types=parameters,
                  assumptions=["supplied declarations describe the active build", "entry to the cited wrapper is assumed", "no application-entry reachability is established"])
    for function, signature in signatures:
        if function == callee or signature is None:
            continue
        caller, caller_params, body = signature
        if caller_params:
            continue  # first frame: a wrapper whose complete call tuple is literal
        statements = [child for child in body.named_children if child.type != "comment"]
        if len(statements) != 1 or statements[0].type != "return_statement":
            continue
        values = [child for child in statements[0].named_children if child.type != "comment"]
        call = _unwrap(values[0]) if len(values) == 1 else None
        if call is None or call.type != "call_expression" or call.start_point[0] + 1 not in site_lines:
            continue
        name, args = call.child_by_field_name("function"), call.child_by_field_name("arguments")
        if name is None or name.type != "identifier" or text(name) != function_name or args is None:
            continue
        arguments = [child for child in args.named_children if child.type != "comment"]
        if len(arguments) != len(parameters):
            continue
        assignment = {name: _literal(argument, text, abi) for (name, _), argument in zip(parameters, arguments)}
        # No implicit wrap, bool conversion, or guessed narrowing is admitted.
        if validate_integer_witness(assignment, parameters, (), abi) is None:
            continue
        check = {"caller": caller, "line": call.start_point[0] + 1, "arguments": assignment,
                 "verdict": "guard-excluded"}
        if validate_integer_witness(assignment, parameters, obligation.premises, abi) is not None:
            if verb == "check-array-bounds":
                index = assignment[obligation.index]
                violation = index < 0 or index >= obligation.extent
                check.update(verdict="violation" if violation else "safe", witness_index=index)
            else:
                evaluated = evaluate_integer_operation(obligation, list(claim.operands), claim.operator, assignment, abi)
                if evaluated is None:
                    continue
                value, low, high = evaluated
                check.update(verdict="safe" if low <= value <= high else "violation", mathematical_result=value,
                             result_range={"minimum": low, "maximum": high})
        result["calls"].append(check)
    return result


def literal_call_witness_valid(reply, call, verb, hypothesis, integer_abi):
    """Independently check a positive worker tuple before granting promotion."""
    if verb not in {"check-array-bounds", "check-overflow"}:
        return False
    parameters, arguments = reply.get("parameter_types"), call.get("arguments")
    if not isinstance(parameters, (list, tuple)) or not 0 < len(parameters) <= 8 or not isinstance(arguments, dict):
        return False
    if any(not isinstance(pair, (list, tuple)) or len(pair) != 2
           or any(not isinstance(atom, str) for atom in pair) for pair in parameters):
        return False
    if len({name for name, _ in parameters}) != len(parameters) or set(arguments) != {name for name, _ in parameters}:
        return False
    try:
        raw = reply.get("callee_obligation")
        obligation = ArrayAccess(**raw) if verb == "check-array-bounds" else ArithmeticOperation(**raw)
        if obligation.status != "bound":
            return False
        values = validate_integer_witness(arguments, parameters, obligation.premises, integer_abi)
        if values is None:
            return False
        if verb == "check-array-bounds":
            claim = parse_array_access_claim(hypothesis)
            if (claim != (obligation.object_name, obligation.index) or obligation.index not in values
                    or dict(obligation.parameters) != dict(parameters)):
                return False
            index = values[obligation.index]
            return (type(obligation.extent) is int and obligation.extent > 0
                    and (index < 0 or index >= obligation.extent)
                    and type(call.get("witness_index")) is int and call["witness_index"] == index)
        claim = parse_arithmetic_claim(hypothesis)
        if claim is None or obligation.type_status != "bound":
            return False
        declared = dict(parameters)
        if any(declared.get(name) != spelling for name, spelling in obligation.types):
            return False
        evaluated = evaluate_integer_operation(obligation, list(claim.operands), claim.operator, values, integer_abi)
        if evaluated is None:
            return False
        value, low, high = evaluated
        return (not low <= value <= high and type(call.get("mathematical_result")) is int
                and call["mathematical_result"] == value and call.get("result_range") == {"minimum": low, "maximum": high})
    except (KeyError, TypeError, ValueError, AttributeError):
        logger.debug("malformed literal caller counterexample", exc_info=True)
        return False
