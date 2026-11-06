"""Independent literal-caller observations after an inconclusive callee query.

Caller source is deliberately read afresh outside the callee sweep memo.
The resulting positive receipt depends on the complete translation unit,
not only on the reviewed function's text. No negative claim is minted.
"""

import logging

from .integer_abi import resolve_integer_abi
from .literal_call import MAX_SOURCE_CHARS

logger = logging.getLogger(__name__)
LITERAL_OVERFLOW_RECEIPT = "smt:check-overflow:literal-call"


def read_literal_call_source(target_path, file_path):
    """A complete, contained UTF-8 snapshot, never a capped text prefix."""
    from core.source import read_contained_bytes

    got = read_contained_bytes(target_path, file_path, 4 * MAX_SOURCE_CHARS)
    if got is None or got[1]:
        return None
    try:
        source = got[0].decode("utf-8")
    except UnicodeDecodeError:
        return None
    return source if len(source) <= MAX_SOURCE_CHARS else None


def complete_literal_overflow_observation(result, *, target_path, file_path,
                                          function_name, source, hypothesis, integer_abi):
    """Only a checked concrete tuple can replace an inconclusive query."""
    if (result.outcome != "inconclusive" or result.rule_id != "smt:check-overflow"
            or not target_path or resolve_integer_abi(integer_abi) is None):
        return result
    try:
        from .literal_call_gate import evaluate_literal_caller_gate
        defining_source = read_literal_call_source(target_path, file_path)
        if defining_source is None:
            return result
        decision = evaluate_literal_caller_gate(
            file_path, function_name, "check-overflow", hypothesis,
            defining_source=defining_source, source=source, integer_abi=integer_abi,
        )
        if decision is None or decision.action != "promote":
            return result
        from .sweep import SweepResult
        details = {**decision.details, "callee_observation": result.details,
                   "caller_citation": decision.citation}
        return SweepResult(tool="smt", file_path=file_path, function_name=function_name,
                           outcome="confirmed", rule_id=LITERAL_OVERFLOW_RECEIPT,
                           details=details, matches=[decision.details])
    except Exception:
        logger.debug("independent literal overflow observation unavailable", exc_info=True)
        return result
