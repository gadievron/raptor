"""Authority bounds for diagnostic SMT and source-pattern observations."""

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


_DIAGNOSTIC_ORACLE_SCOPES = {
    "check-null-deref": "pointer-nullability-only",
    "check-lock-discipline": "lexical-lock-discipline",
    "check-integer-narrowing": "type-width-only",
    "check-auth-bypass": "source-pattern",
    "check-resource-leak": "source-pattern",
    "check-null-propagation": "source-pattern",
    "check-early-release": "source-pattern",
    "check-lock-domain": "source-pattern",
    "check-toctou": "source-pattern",
}


def is_diagnostic_smt_rule(rule_id: str) -> bool:
    """These producers do not model source semantics sufficiently for verdicts."""
    if not isinstance(rule_id, str):
        return False
    verb = rule_id.removeprefix("smt:").split(":", 1)[0]
    return is_predicate_only_smt_rule(rule_id) or verb in _DIAGNOSTIC_ORACLE_SCOPES


def scope_smt_observation(verb: str, outcome: str, data: dict) -> tuple[str, dict]:
    if verb in _DIAGNOSTIC_ORACLE_SCOPES:
        details = dict(data)
        details["oracle_scope"] = _DIAGNOSTIC_ORACLE_SCOPES[verb]
        return ("confirmed" if outcome == "confirmed" else "inconclusive"), details
    return scope_smt_feasibility(verb, outcome, data)
