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
    "check-integer-conversion": "source-unsigned-conversion",
    # Predicate truth alone does not establish an unintended coding defect.
    "check-integer-comparison": "source-integer-comparison",
    # These adapters infer numeric operands from text but do not bind an
    # access/allocation/conversion site, its reaching path, or target types.
    "check-oob": "inferred-arithmetic-model",
    "check-overflow-to-oob": "inferred-arithmetic-model",
    "check-negative-bypass": "inferred-arithmetic-model",
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
    if "supplied-model" in rule_id.split(":"):
        return True
    part = rule_id.removeprefix("smt:")
    verb = part.split(":", 1)[0]
    if verb == "check-overflow" and "literal-call" in part.split(":")[1:]:
        return part != "check-overflow:literal-call"
    if verb in {"check-array-bounds", "check-integer-division", "check-shift-count"} and part != verb:
        return True  # this source producer mints only the exact bare receipt
    return is_predicate_only_smt_rule(rule_id) or verb in _DIAGNOSTIC_ORACLE_SCOPES


def is_non_refuting_smt_rule(rule_id: str) -> bool:
    """A scoped positive safety obligation cannot clear a whole function."""
    if not isinstance(rule_id, str):
        return True
    return rule_id.removeprefix("smt:") == "check-overflow:literal-call" or is_diagnostic_smt_rule(rule_id) or rule_id.removeprefix("smt:").split(":", 1)[0] in {"check-array-bounds", "check-integer-division", "check-shift-count"}


def scope_smt_observation(verb: str, outcome: str, data: dict) -> tuple[str, dict]:
    if verb == "check-overflow":
        return outcome, dict(data)
    if verb in {"check-array-bounds", "check-integer-division", "check-shift-count"}:
        details = dict(data)
        details["oracle_scope"] = ("fixed-local-array-access" if verb == "check-array-bounds"
                                  else "integer-shift-count" if verb == "check-shift-count" else "integer-division-fault")
        return ("confirmed" if outcome == "confirmed" else "inconclusive"), details
    if "supplied-model" in verb.split(":"):
        details = dict(data)
        feasible = data.get("feasible")
        if not isinstance(feasible, bool):
            feasible = True if outcome == "confirmed" else False if outcome == "refuted" else None
        details.update(oracle_scope="supplied-model", feasible=feasible)
        return ("confirmed" if outcome == "confirmed" else "inconclusive"), details
    if verb in _DIAGNOSTIC_ORACLE_SCOPES:
        details = dict(data)
        details["oracle_scope"] = _DIAGNOSTIC_ORACLE_SCOPES[verb]
        return ("confirmed" if outcome == "confirmed" else "inconclusive"), details
    return scope_smt_feasibility(verb, outcome, data)


LEGACY_GUARD_MODEL_NAMESPACES = frozenset({
    "dead_path_smt", "insufficient_guard_smt", "signed_mismatch_smt",
})


def is_legacy_guard_model_rule(rule_id: str) -> bool:
    """Legacy condition-bridge models never bind a complete source defect."""
    if not isinstance(rule_id, str):
        return False
    return rule_id.removeprefix("clean-refuted:").split(":", 1)[0] in LEGACY_GUARD_MODEL_NAMESPACES
