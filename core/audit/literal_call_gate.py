"""Confined literal-call evidence for source arithmetic promotion gates."""

import re
from .condition_extraction import language_for_file
from .integer_abi import resolve_integer_abi
from .literal_call import MAX_SOURCE_CHARS, literal_call_binding, literal_call_witness_valid
from .probe_function_scope import source_for_function
from .source_view import sanitized_view


def _candidate_lines(source, scope, function_name, language):
    """Bounded hints in this exact snapshot; only the worker grants credit."""
    data = source.encode("utf-8")
    # Exclude the reviewed definition, including recursive calls. Byte masking
    # preserves UTF-8 line positions without borrowing an inventory snapshot.
    data = data[:scope.start] + re.sub(rb"[^\n\r]", b" ", data[scope.start:scope.end]) + data[scope.end:]
    view = sanitized_view(data.decode("utf-8"), "source." + language)
    lines = set()
    for count, match in enumerate(re.finditer(rf"(?<![\w.>:]){re.escape(function_name)}\s*\(", view), 1):
        if count > 40:
            return None
        lines.add(view.count("\n", 0, match.start()) + 1)
    return sorted(lines)


def evaluate_literal_caller_gate(file_path, function_name, verb, mechanism, *,
                                 defining_source, source, integer_abi):
    """Conditional caller-entry proof; unsupported callers cannot refute claims."""
    from .smt_promotion_gate import CallerGateDecision
    from .condition_smt import _run_z3_child

    abi = resolve_integer_abi(integer_abi)
    if abi is None or verb not in {"check-overflow", "check-array-bounds"}:
        return None

    def hold(reason, details=None, count=0):
        return CallerGateDecision(action="hold", reason="literal caller gate: " + reason,
                                  channel_outcome="inconclusive", site_count=count, details=details or {})

    language = language_for_file(file_path)
    if language not in {"c", "cpp"} or not source:
        return hold("source model or supported language unavailable")
    if len(defining_source) > MAX_SOURCE_CHARS or len(source) > MAX_SOURCE_CHARS:
        return hold("source exceeds the literal-call proof budget")
    # The original SMT observation must still refer to the callee in the
    # current file snapshot. Caller arguments cannot repair stale evidence.
    scope, current = source_for_function(defining_source, file_path, function_name)
    _, reviewed = source_for_function(source, file_path, function_name)
    if current is None or reviewed is None or current.strip() != reviewed.strip():
        return hold("callee source changed or could not be uniquely bound")
    lines = _candidate_lines(defining_source, scope, function_name, language)
    if lines is None:
        return hold("same-file candidate budget exhausted")
    if not lines:
        return hold("no same-file direct caller candidate; cross-file and external callers remain unresolved")
    expected = literal_call_binding(defining_source, function_name, verb, mechanism, abi, lines, language)
    reply = _run_z3_child("literal_call", dict(source=defining_source, function_name=function_name, verb=verb,
                         hypothesis=mechanism, integer_abi=abi.record(), site_lines=lines, language=language))
    if not isinstance(reply, dict) or reply.get("binding") != expected or reply.get("status") != "checked" or reply.get("proof_scope") != "caller-entry-source-model":
        return hold("worker failed, source/query binding mismatched, or frame unsupported")
    calls = reply.get("calls")
    if not isinstance(calls, list):
        return hold("worker returned no structured call obligations")
    for call in calls:
        if not isinstance(call, dict) or type(call.get("line")) is not int or call["line"] not in lines:
            return hold("worker returned an unbound call obligation")
    for call in calls:
        if call.get("verdict") == "violation":
            if not literal_call_witness_valid(reply, call, verb, mechanism, abi):
                return hold("worker counterexample failed independent tuple validation")
            from core.security.log_sanitisation import escape_nonprintable
            citation = escape_nonprintable(f"{file_path[:512]}:{call['line']} ({str(call.get('caller', ''))[:128]} entry; literal arguments satisfy the callee guards and violate its safety obligation)")
            return CallerGateDecision(action="promote", reason="literal caller gate: " + citation,
                                      precondition="complete typed argument tuple and callee reaching guards",
                                      site_count=len(calls), citation=citation, channel_outcome="confirmed", details=reply)
    return hold("no admitted literal call violates the source obligation; other callers and application-entry reachability remain unresolved",
                details=reply, count=len(calls))
