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
