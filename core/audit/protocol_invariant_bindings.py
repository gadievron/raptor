"""Source-transition and field-projection admission for protocol invariants.

This is a binding check, not an alias or object-identity proof. Distinct
spellings must not be merged merely because their final field names match.
"""

import re

from .invariant_expression import ParseError, expression_vars, parse_expr
from .invariant_smt import _parse_invariant
from .invariant_source import mutation_snapshot, source_mutations
from .invariant_worker import _MAX_SOURCE, _MAX_TEXT


def census_source_refusal(source, function_name, line, code):
    """Require census code to describe the selected source transition.

    A cropped statement may omit enclosing source guards, which are passed
    separately. Embedded census guards may not add facts absent from source.
    """
    if len(code) > _MAX_SOURCE:
        return "census source binding input budget exhausted"
    actual = mutation_snapshot(source, function_name.rsplit(".", 1)[-1], line)
    if actual is None:
        return "census write has no unambiguous source mutation binding"
    sites, effects, refusal = source_mutations(code)
    if refusal or len(sites) != 1 or effects or sites[0].reason:
        return refusal or "census code requires one admitted mutation without additional effects"
    claimed = sites[0]
    if (claimed.var, claimed.op) != (actual.var, actual.op):
        return "census mutation target or operator disagrees with source"
    if actual.op not in {"=", "+=", "-=", "++", "--"}:
        return "source transition is outside the supported arithmetic model"
    try:
        if actual.op in {"=", "+=", "-="} and parse_expr(claimed.rhs) != parse_expr(actual.rhs):
            return "census mutation value disagrees with source"
        guards = {_parse_invariant(guard) for guard in actual.guards}
        if any(_parse_invariant(guard) not in guards for guard in claimed.guards):
            return "census code adds a guard absent from the source frame"
    except ParseError:
        return "census source binding requires supported transition and guard expressions"
    return ""


def projection_refusal(code, guards, variables):
    """Return a reason when bare-field normalization would erase a binding."""
    if (
        len(code) > _MAX_SOURCE
        or len(guards) > 64
        or any(len(g) > _MAX_TEXT for g in guards)
    ):
        return "field projection input budget exhausted"
    sites, _effects, refusal = source_mutations(code)
    if refusal or len(sites) != 1:
        return refusal or "one source-bound mutation required for field projection"
    site = sites[0]
    parts = re.split(r"(->|\.)", site.var)
    if parts[-1] not in variables:
        return "census site does not bind an invariant mutation"
    owner = "".join(parts[:-1])
    names = {site.var}
    try:
        if site.op in {"=", "+=", "-="}:
            names.update(expression_vars(parse_expr(site.rhs)))
        for guard in guards:
            left, _op, right = _parse_invariant(guard)
            names.update(expression_vars(left) | expression_vars(right))
    except ParseError:
        return "field projection requires supported source expressions"
    for name in names:
        pieces = re.split(r"(->|\.)", name)
        if pieces[-1] in variables and "".join(pieces[:-1]) != owner:
            return "field projection would merge distinct scalar or object bindings"
    return ""


def census_coverage_refusal(sources, variables, fields, *, deadline, clock):
    """Check that direct source field writes are represented in the census.

    This closes lexical layout gaps, not alias, macro or reachability gaps.
    Missing syntax or exhausted budgets cannot establish complete coverage.
    """
    from .condition_extraction import _get_parser
    from .invariant_source import _MAX_NODES

    parser = None
    for path, source in sources:
        if clock() >= deadline:
            return "source census coverage budget exhausted"
        if not isinstance(source, str) or len(source) > _MAX_SOURCE:
            return "source census coverage input budget exhausted"
        if parser is None:
            parser = _get_parser("c")
        if parser is None:
            return "source census coverage parser unavailable"
        data = source.encode("utf-8")
        root = parser.parse(data).root_node
        if root.has_error:
            return "source census coverage requires supported C syntax"
        remaining = _MAX_NODES

        def descendants(node):
            nonlocal remaining
            pending = [node]
            while pending:
                remaining -= 1
                if remaining < 0:
                    raise ValueError("source census coverage node budget exhausted")
                item = pending.pop()
                yield item
                pending.extend(reversed(item.named_children))

        try:
            pending = [root]
            while pending:
                node = pending.pop()
                remaining -= 1
                if remaining < 0:
                    return "source census coverage node budget exhausted"
                if remaining % 128 == 0 and clock() >= deadline:
                    return "source census coverage budget exhausted"
                if node.type == "sizeof_expression" and not any(
                    item.type in {"array_declarator", "abstract_array_declarator"}
                    for item in descendants(node)
                ):
                    continue
                pending.extend(reversed(node.named_children))
                if node.type not in {"assignment_expression", "update_expression"}:
                    continue
                target = node.child_by_field_name(
                    "left" if node.type == "assignment_expression" else "argument"
                )
                if target is None:
                    return "source census coverage has an unsupported mutation target"
                for item in descendants(target):
                    if item.type != "field_identifier":
                        continue
                    field = data[item.start_byte:item.end_byte].decode("utf-8")
                    if field not in variables:
                        continue
                    line = item.start_point[0] + 1
                    writes = (fields.get(field) or {}).get("writes") or []
                    if not any(site.get("file") == path and site.get("line") == line for site in writes):
                        return "source field write absent from census"
        except ValueError as exc:
            return str(exc)
    if clock() >= deadline:
        return "source census coverage budget exhausted"
    return ""
