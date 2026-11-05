"""The authority boundary between supplied predicates and source semantics."""

_PREDICATE_ONLY_RULES = frozenset({
    "validate-path", "path-feasible", "path_feasibility", "path-feasibility",
})


def is_predicate_only_smt_rule(rule_id: str) -> bool:
    if not isinstance(rule_id, str):
        return False
    part = rule_id.removeprefix("smt:").split(":", 1)[0]
    return part in _PREDICATE_ONLY_RULES


def scope_smt_feasibility(verb: str, outcome: str, data: dict) -> tuple[str, dict]:
    """Predicate satisfiability does not refute a source-level claim."""
    if verb != "validate-path":
        return outcome, {}
    if data.get("oracle_scope") == "supplied-predicates":
        value = data.get("feasible")
        feasible = value if isinstance(value, bool) else None
    else:
        feasible = True if outcome == "confirmed" else False if outcome == "refuted" else None
    details = dict(data)
    details.update(oracle_scope="supplied-predicates", feasible=feasible)
    return ("confirmed" if feasible is True else "inconclusive"), details
