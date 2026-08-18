"""Mechanical spec inference for audit review.

Infers what a function SHOULD do from naming, types, annotations,
docstrings, tests, and caller usage patterns — then the review becomes
"where does the implementation deviate from the spec?" This is how
you find logic bugs that no pattern-matching tool can detect (Cap 2).

All inference is mechanical (no LLM calls). LLM-based spec inference
is deferred to a future phase.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any

from core.security.prompt_framing import with_audit_framing

logger = logging.getLogger(__name__)


@dataclass
class SpecSource:
    """Where a piece of inferred spec came from."""

    signal: str
    confidence: str
    evidence: str


@dataclass
class InferredSpec:
    """Mechanical specification inferred for one function."""

    function: str
    file: str
    intent: str = ""
    preconditions: list[str] = field(default_factory=list)
    postconditions: list[str] = field(default_factory=list)
    invariants: list[str] = field(default_factory=list)
    negative_specs: list[str] = field(default_factory=list)
    sources: list[SpecSource] = field(default_factory=list)
    #: LLM claims whose source anchor did NOT verify against the
    #: function source (hint tier — the receipts.py precedent:
    #: unverified answers surface only as explicitly-marked hints).
    #: Never merged into the spec lists above, so precondition
    #: verification and evidence fusion never consume them.
    llm_hints: list[str] = field(default_factory=list)


_NAME_INTENT: list[tuple] = [
    (re.compile(r"^(?:validate|verify|check)_"), "validates", "high"),
    (re.compile(r"^sanitize_|^clean_|^escape_"), "sanitizes input for", "high"),
    (re.compile(r"^parse_|^decode_|^deserialize_"), "parses/decodes", "high"),
    (re.compile(r"^encode_|^serialize_"), "encodes/serializes", "medium"),
    (re.compile(r"^init(?:ialize)?_|^setup_|^create_"), "initializes", "medium"),
    (re.compile(r"^free_|^destroy_|^cleanup_|^close_|^release_"), "releases/frees", "high"),
    (re.compile(r"^alloc(?:ate)?_"), "allocates", "medium"),
    (re.compile(r"^auth(?:enticate)?_|^login_|^verify_(?:password|token|cred)"), "authenticates", "high"),
    (re.compile(r"^hash_|^hmac_|^sign_|^encrypt_|^decrypt_"), "performs crypto operation on", "high"),
    (re.compile(r"^is_|^has_|^can_|^should_"), "tests predicate for", "medium"),
    (re.compile(r"^get_|^fetch_|^read_|^load_|^find_|^lookup_"), "retrieves", "medium"),
    (re.compile(r"^set_|^update_|^write_|^store_|^save_"), "mutates/stores", "medium"),
    (re.compile(r"^delete_|^remove_|^drop_|^unlink_"), "deletes", "medium"),
    (re.compile(r"^copy_|^clone_|^dup(?:licate)?_"), "copies", "medium"),
    (re.compile(r"^compare_|^cmp_|^diff_|^eq_"), "compares", "medium"),
    (re.compile(r"^handle_|^process_|^on_|^dispatch_"), "handles/processes", "low"),
    (re.compile(r"^send_|^emit_|^publish_|^notify_"), "sends/emits", "medium"),
    (re.compile(r"^recv_|^receive_|^consume_|^subscribe_"), "receives", "medium"),
]

_PARAM_PRECONDITIONS: list[tuple] = [
    (re.compile(r"__user\b"), "pointer is user-space (must copy_from_user)"),
    (re.compile(r"\bsize_t\b.*\blen\b|\bsize_t\b.*\bsize\b|\bsize_t\b.*\bcount\b"),
     "length parameter must be bounds-checked"),
    (re.compile(r"\bconst\s+char\s*\*"), "string pointer must not be NULL"),
    (re.compile(r"\bFILE\s*\*"), "file handle must be open and valid"),
    (re.compile(r"\bint\s+fd\b"), "file descriptor must be valid (>= 0)"),
    (re.compile(r"\bvoid\s*\*\s*\w+\s*,\s*(?:size_t|int|unsigned)"),
     "buffer/length pair — length must not exceed buffer size"),
]

_ATTR_INVARIANTS: dict[str, str] = {
    "__must_check": "return value must be checked by caller",
    "warn_unused_result": "return value must be checked by caller",
    "nodiscard": "return value must be checked by caller",
    "login_required": "caller must be authenticated",
    "permission_required": "caller must have specific permissions",
    "csrf_protect": "must verify CSRF token",
    "csrf_exempt": "CSRF protection intentionally skipped — verify safe",
    "atomic": "must execute atomically",
    "synchronized": "must hold lock",
    "deprecated": "should not be called from new code",
    "unsafe": "caller must uphold safety invariants",
    "__init": "runs once during initialization only",
    "__exit": "runs once during cleanup only",
    "nonnull": "pointer parameters must not be NULL",
    "pure": "must have no side effects",
    "const": "must have no side effects and not read global state",
    "malloc": "returned pointer must be freed by caller",
}

_NEGATIVE_KEYWORDS: dict[str, str] = {
    "password": "must NOT log or store in plaintext",
    "secret": "must NOT log or store in plaintext",
    "token": "must NOT log or expose in error messages",
    "key": "must NOT embed in source or log",
    "credential": "must NOT log or store in plaintext",
    "private_key": "must NOT log or expose",
    "session": "must NOT be predictable or reused",
    "nonce": "must NOT be reused",
    "iv": "must NOT be reused with same key",
    "salt": "must NOT be constant or predictable",
}


def infer_spec_mechanical(
    gap: dict[str, Any],
    checklist: dict[str, Any] | None = None,
    tests: dict[str, Any] | None = None,
    summaries: dict[str, Any] | None = None,
    census: dict[str, Any] | None = None,
) -> InferredSpec:
    """Infer a function's specification from mechanical signals only.

    *census*: the prep phase's return-usage census
    (``callee → CalleeCensus``). When present, caller-usage inference
    consumes it instead of recomputing caller checks from checklist
    sources — one majority computation in the tree (design §2.2.5).
    """
    file_path = gap.get("file", "")
    function_name = gap.get("name", "")

    spec = InferredSpec(function=function_name, file=file_path)

    _infer_from_name(spec, function_name)
    _infer_from_params(spec, gap)
    _infer_from_attributes(spec, gap)
    _infer_from_docstring(spec, gap)
    _infer_from_tests(spec, function_name, tests)
    _infer_from_caller_usage(
        spec, function_name, checklist, summaries, census=census,
    )
    _infer_negative_specs(spec, function_name, gap)
    _infer_from_assertions(spec, gap)

    return spec


def should_infer_with_llm(
    gap: dict[str, Any],
    triage_bucket: str,
    is_entry_point: bool = False,
    is_sink: bool = False,
) -> bool:
    """Whether this function warrants LLM-based spec inference.

    Returns True for high-value targets only (entry points, sinks,
    auth-strategy functions, deep_dive bucket). Mechanical-only for
    everything else.
    """
    if triage_bucket in ("deep_dive",):
        return True
    if is_entry_point or is_sink:
        return True

    strategy = gap.get("strategy", "")
    return strategy in ("auth", "crypto", "privilege", "injection")


def format_spec_for_context(spec: InferredSpec) -> str:
    """Render an inferred spec as a prompt section."""
    if not spec.intent and not spec.preconditions and not spec.postconditions:
        return ""

    lines = ["### Inferred specification"]

    if spec.intent:
        lines.append(f"**Intent:** {spec.intent}")

    if spec.preconditions:
        lines.append("**Preconditions:**")
        for p in spec.preconditions[:6]:
            lines.append(f"- {p}")

    if spec.postconditions:
        lines.append("**Postconditions:**")
        for p in spec.postconditions[:6]:
            lines.append(f"- {p}")

    if spec.invariants:
        lines.append("**Invariants:**")
        for inv in spec.invariants[:4]:
            lines.append(f"- {inv}")

    if spec.negative_specs:
        lines.append("**Must NOT:**")
        for ns in spec.negative_specs[:4]:
            lines.append(f"- {ns}")

    if spec.llm_hints:
        lines.append(
            "**Unverified LLM hints** (no source anchor — NOT part of "
            "the spec; treat as leads only):"
        )
        for hint in spec.llm_hints[:4]:
            lines.append(f"- {hint}")

    source_strs = []
    for s in spec.sources[:5]:
        source_strs.append(f"{s.signal} [{s.confidence}]")
    if source_strs:
        lines.append(f"*(Sources: {', '.join(source_strs)})*")

    lines.append("")
    lines.append(
        "Review this function against its specification. "
        "Where does the implementation deviate from the above? "
        "A deviation IS the bug."
    )

    return "\n".join(lines)


def _infer_from_name(spec: InferredSpec, name: str) -> None:
    """Infer intent from function naming pattern."""
    lower = name.lower()

    for pattern, verb, confidence in _NAME_INTENT:
        m = pattern.search(lower)
        if m:
            suffix = lower[m.end():]
            subject = suffix.replace("_", " ").strip()
            spec.intent = f"{verb} {subject}" if subject else verb
            spec.sources.append(SpecSource(
                signal="function_name",
                confidence=confidence,
                evidence=f"name matches {verb} pattern",
            ))
            return


def _infer_from_params(spec: InferredSpec, gap: dict[str, Any]) -> None:
    """Infer preconditions from parameter types and names."""
    params = gap.get("params", [])
    signature = gap.get("signature", "")

    combined = signature
    if isinstance(params, list):
        combined += " " + " ".join(str(p) for p in params)

    for pattern, precondition in _PARAM_PRECONDITIONS:
        if pattern.search(combined):
            spec.preconditions.append(precondition)
            spec.sources.append(SpecSource(
                signal="parameter_type",
                confidence="high",
                evidence=f"param pattern: {pattern.pattern[:40]}",
            ))


def _infer_from_attributes(spec: InferredSpec, gap: dict[str, Any]) -> None:
    """Infer invariants from function attributes and annotations."""
    attrs = gap.get("attributes", [])
    if isinstance(attrs, str):
        attrs = [attrs]

    for attr in attrs:
        attr_lower = attr.lower().strip("@_")
        for key, invariant in _ATTR_INVARIANTS.items():
            if key.lower().strip("_") in attr_lower:
                spec.invariants.append(invariant)
                spec.sources.append(SpecSource(
                    signal="annotation",
                    confidence="high",
                    evidence=f"attribute: {attr}",
                ))
                break


def _infer_from_docstring(spec: InferredSpec, gap: dict[str, Any]) -> None:
    """Extract preconditions and postconditions from docstrings."""
    docstring = gap.get("docstring", "") or ""
    if not docstring:
        source = gap.get("source", "")
        if source:
            doc_match = re.search(
                r'(?:"""|\'\'\'|/\*\*)(.*?)(?:"""|\'\'\'|\*/)',
                source, re.DOTALL,
            )
            if doc_match:
                docstring = doc_match.group(1).strip()

    if not docstring or len(docstring) < 10:
        return

    if not spec.intent:
        first_line = docstring.split("\n")[0].strip().rstrip(".")
        if 10 <= len(first_line) <= 200:
            spec.intent = first_line.lower()
            spec.sources.append(SpecSource(
                signal="docstring",
                confidence="medium",
                evidence=f"first line: {first_line[:60]}",
            ))

    for line in docstring.split("\n"):
        line_stripped = line.strip().lower()

        if any(k in line_stripped for k in ("raises", "throw", "error")):
            spec.postconditions.append(line.strip()[:120])

        if any(k in line_stripped for k in ("returns", "return")):
            spec.postconditions.append(line.strip()[:120])

        if any(k in line_stripped for k in ("must be", "should be",
                                             "must not", "requires",
                                             "precondition", "expects")):
            spec.preconditions.append(line.strip()[:120])


def _infer_from_tests(
    spec: InferredSpec,
    function_name: str,
    tests: dict[str, Any] | None,
) -> None:
    """Extract postconditions from test assertions."""
    if not tests:
        return

    test_cases = tests.get(function_name, [])
    if not test_cases:
        return

    added = 0
    for tc in test_cases:
        assertions = getattr(tc, "assertions", []) if hasattr(tc, "assertions") else tc.get("assertions", [])
        for assertion in assertions:
            if added >= 5:
                break
            spec.postconditions.append(f"[test] {assertion[:100]}")
            added += 1

    if test_cases:
        spec.sources.append(SpecSource(
            signal="test_assertions",
            confidence="high",
            evidence=f"{len(test_cases)} test(s), {added} assertion(s)",
        ))


def _infer_from_caller_usage(
    spec: InferredSpec,
    function_name: str,
    checklist: dict[str, Any] | None,
    summaries: dict[str, Any] | None,
    census: dict[str, Any] | None = None,
) -> None:
    """Infer spec from how callers use the return value.

    When the prep census carries an entry for this function, its
    counts ARE the caller-usage majority (same thresholds, one
    computation in the tree); the checklist recomputation remains the
    fallback for census-less callers.
    """
    caller_count = 0
    callers_that_check_return = 0

    entry = (census or {}).get(function_name)
    considered = getattr(entry, "considered", 0) if entry else 0
    if considered >= 3:
        caller_count = considered
        callers_that_check_return = entry.count("tested")
    elif checklist:
        items = checklist.get("items", [])
        for item in items:
            callees = item.get("callees", [])
            for callee in callees:
                callee_name = callee.get("name", "") if isinstance(callee, dict) else str(callee)
                if callee_name == function_name:
                    caller_count += 1
                    source = item.get("source", "")
                    if _checks_return_value(source, function_name):
                        callers_that_check_return += 1
                    break

    if caller_count >= 3:
        check_rate = callers_that_check_return / caller_count
        if check_rate >= 0.8:
            spec.invariants.append(
                f"return value must be checked "
                f"({callers_that_check_return}/{caller_count} callers check it)"
            )
            spec.sources.append(SpecSource(
                signal="caller_usage",
                confidence="high",
                evidence=f"{check_rate:.0%} of callers check return value",
            ))
        elif 0.4 <= check_rate < 0.8:
            spec.invariants.append(
                f"return value is checked by some callers "
                f"({callers_that_check_return}/{caller_count}) — inconsistent"
            )
            spec.sources.append(SpecSource(
                signal="caller_usage",
                confidence="medium",
                evidence=f"{check_rate:.0%} of callers check return value (inconsistent)",
            ))


def _infer_negative_specs(
    spec: InferredSpec,
    function_name: str,
    gap: dict[str, Any],
) -> None:
    """Infer what the function must NOT do based on its domain."""
    combined = f"{function_name} {gap.get('params', '')} {gap.get('source', '')}"
    combined_lower = combined.lower()

    for keyword, prohibition in _NEGATIVE_KEYWORDS.items():
        if keyword in combined_lower:
            spec.negative_specs.append(f"{keyword}: {prohibition}")
            if not any(s.signal == "sensitive_data" for s in spec.sources):
                spec.sources.append(SpecSource(
                    signal="sensitive_data",
                    confidence="high",
                    evidence=f"handles '{keyword}'",
                ))


_ASSERTION_PATTERNS: list[tuple] = [
    (re.compile(r"\bBUG_ON\s*\((.+?)\)"), "invariant"),
    (re.compile(r"\bWARN_ON\s*\((.+?)\)"), "postcondition"),
    (re.compile(r"\bBUILD_BUG_ON\s*\((.+?)\)"), "compile_time_invariant"),
    (re.compile(r"\blockdep_assert_held\s*\((.+?)\)"), "lock_precondition"),
    (re.compile(r"\blockdep_assert_held_read\s*\((.+?)\)"), "lock_precondition"),
    (re.compile(r"\bassert\s*\((.+?)\)"), "precondition"),
    (re.compile(r"\bASSERT\s*\((.+?)\)"), "precondition"),
    (re.compile(r"\bCHECK\s*\((.+?)\)"), "precondition"),
    (re.compile(r"\bDCHECK\s*\((.+?)\)"), "precondition"),
    (re.compile(r"\bg_assert\s*\((.+?)\)"), "precondition"),
    (re.compile(r"\bg_return_if_fail\s*\((.+?)\)"), "precondition"),
    (re.compile(r"\bg_return_val_if_fail\s*\((.+?)\s*,"), "precondition"),
    (re.compile(r"\bprecondition\s*\((.+?)\)"), "precondition"),
    (re.compile(r"\bPy_CHECK_TYPE\s*\((.+?)\)"), "type_precondition"),
]


def _infer_from_assertions(
    spec: InferredSpec,
    gap: dict[str, Any],
) -> None:
    """Extract preconditions/invariants from assertion macros."""
    source = gap.get("source", "")
    if not source:
        return

    line_start = gap.get("line_start", 0)
    for i, line in enumerate(source.splitlines()):
        stripped = line.strip()
        if stripped.startswith(("//", "/*")):
            continue
        for pattern, kind in _ASSERTION_PATTERNS:
            m = pattern.search(stripped)
            if not m:
                continue
            condition = m.group(1).strip()
            if kind == "lock_precondition":
                text = f"lock {condition} must be held on entry"
                spec.preconditions.append(text)
            elif kind == "compile_time_invariant":
                spec.invariants.append(f"compile-time: {condition}")
            elif kind in ("precondition", "type_precondition"):
                spec.preconditions.append(condition)
            elif kind == "invariant":
                spec.invariants.append(condition)
            elif kind == "postcondition":
                spec.postconditions.append(f"warns if {condition}")
            spec.sources.append(SpecSource(
                signal="assertion_macro",
                confidence="high",
                evidence=f"line {line_start + i}: {stripped[:80]}",
            ))


@dataclass
class PreconditionVerification:
    """Result of verifying a precondition against all call sites."""

    precondition: str
    total_call_sites: int
    verified_sites: int
    violated_sites: int
    unknown_sites: int
    is_universally_satisfied: bool = False
    evidence: list[dict[str, str]] = field(default_factory=list)


def verify_preconditions_at_call_sites(
    spec: InferredSpec,
    callers: list[dict[str, Any]],
    checklist: dict[str, Any] | None = None,
) -> list[PreconditionVerification]:
    """Cross-reference preconditions against call sites.

    For each precondition, checks whether all callers satisfy it.
    Returns one PreconditionVerification per precondition.
    """
    if not spec.preconditions or not callers:
        return []

    results: list[PreconditionVerification] = []
    for precond in spec.preconditions:
        v = _verify_one_precondition(precond, callers, checklist)
        results.append(v)
    return results


def _verify_one_precondition(
    precondition: str,
    callers: list[dict[str, Any]],
    checklist: dict[str, Any] | None,
) -> PreconditionVerification:
    """Check one precondition against all known callers."""
    verified = 0
    violated = 0
    unknown = 0
    evidence: list[dict[str, str]] = []

    check_type = _classify_precondition(precondition)

    for caller in callers:
        caller_source = caller.get("source", "")
        if not caller_source and checklist:
            caller_source = _get_source_from_checklist(
                caller.get("file", ""),
                caller.get("name", caller.get("function", "")),
                checklist,
            )

        if not caller_source:
            unknown += 1
            continue

        satisfied = _check_precondition_in_source(
            check_type, precondition, caller_source,
        )
        caller_id = f"{caller.get('file', '')}:{caller.get('name', caller.get('function', ''))}"

        if satisfied is True:
            verified += 1
            evidence.append({"caller": caller_id, "status": "verified"})
        elif satisfied is False:
            violated += 1
            evidence.append({"caller": caller_id, "status": "violated"})
        else:
            unknown += 1
            evidence.append({"caller": caller_id, "status": "unknown"})

    total = verified + violated + unknown
    return PreconditionVerification(
        precondition=precondition,
        total_call_sites=total,
        verified_sites=verified,
        violated_sites=violated,
        unknown_sites=unknown,
        is_universally_satisfied=(total > 0 and verified == total),
        evidence=evidence,
    )


def _classify_precondition(precondition: str) -> str:
    """Classify a precondition for mechanical verification."""
    lower = precondition.lower()
    if "null" in lower or "!= null" in lower or "!= 0" in lower:
        return "null_check"
    if any(w in lower for w in ("<=", ">=", "< ", "> ", "bound", "size", "len")):
        return "bounds_check"
    if "lock" in lower or "held" in lower:
        return "lock_held"
    if "unsigned" in lower or ">= 0" in lower or "non-negative" in lower:
        return "non_negative"
    return "general"


def _check_precondition_in_source(
    check_type: str,
    precondition: str,
    caller_source: str,
) -> bool | None:
    """Check if the caller source satisfies the precondition."""
    if check_type == "null_check":
        var_match = re.search(r"(\w+)\s*(?:!=\s*(?:NULL|0)|!= null)", precondition)
        if var_match:
            var = var_match.group(1)
            if re.search(
                rf"if\s*\(\s*!?\s*{re.escape(var)}\s*\)|"
                rf"if\s*\(\s*{re.escape(var)}\s*==\s*NULL|"
                rf"if\s*\(\s*{re.escape(var)}\s*!=\s*NULL",
                caller_source,
            ):
                return True
        return None

    if check_type == "bounds_check":
        return None

    if check_type == "lock_held":
        lock_match = re.search(r"lock\s+(\w+)", precondition)
        if lock_match:
            lock_name = lock_match.group(1)
            if re.search(
                rf"(?:spin_lock|mutex_lock|read_lock|write_lock)\s*\(\s*&?{re.escape(lock_name)}",
                caller_source,
            ):
                return True
        return None

    return None


def _get_source_from_checklist(
    file_path: str,
    function_name: str,
    checklist: dict[str, Any],
) -> str:
    """Get function source from checklist data."""
    for f in checklist.get("files", []):
        if f.get("path") != file_path:
            continue
        for gap in f.get("gaps", []):
            if gap.get("name") == function_name:
                return gap.get("source", "")
    return ""


def format_precondition_verification(
    verifications: list[PreconditionVerification],
) -> str:
    """Render precondition verification as a context section for the LLM."""
    if not verifications:
        return ""
    lines = ["### Precondition verification (mechanical)"]
    for v in verifications:
        if v.total_call_sites == 0:
            continue
        status = "UNIVERSALLY SATISFIED" if v.is_universally_satisfied else (
            f"{v.verified_sites}/{v.total_call_sites} callers verified "
            f"({v.violated_sites} violated, {v.unknown_sites} unknown)"
        )
        lines.append(f"- `{v.precondition}`: {status}")
        if v.is_universally_satisfied:
            lines.append(
                "  A hypothesis that callers violate this precondition "
                "is mechanically refuted."
            )
        elif v.violated_sites > 0:
            lines.append(
                "  At least one caller mechanically violates this "
                "precondition — chase the violating call site(s) first."
            )
    return "\n".join(lines)


def _checks_return_value(source: str, function_name: str) -> bool:
    """Heuristic: does the source check the return of function_name?"""
    if not source:
        return False

    patterns = [
        rf"if\s*\(\s*!?\s*{re.escape(function_name)}\s*\(",
        rf"(?:ret|rc|err|result|status|rv)\s*=\s*{re.escape(function_name)}\s*\(",
        r"if\s*\(\s*(?:ret|rc|err|result|status|rv)\s*[!=<>]",
    ]

    for pat in patterns:
        if re.search(pat, source):
            return True

    return False


# Audit-purpose framing: this class (the IRIS spec/refine leg) was
# AUP-refused 19/19 in one comparison audit and again 19/19 with the
# v1 one-paragraph framing — same gap as the summary class. v2
# framing + contract-inference vocabulary below. See
# core.security.prompt_framing for the measured history.
_LLM_SPEC_SYSTEM = with_audit_framing("""\
You are inferring a function's behavioural contract (its specification) \
so the audit's verification tools can check the implementation against \
it. Given the source code in the untrusted block (its file and function \
name are in the slots), determine what this function SHOULD do — its \
contract with callers.

Respond with JSON only:
{
  "intent": "one sentence describing what this function should do",
  "preconditions": [{"claim": "condition that must hold on entry",
                     "anchor": "verbatim code from the source that grounds the claim"}],
  "postconditions": [{"claim": "condition that must hold on exit", "anchor": "..."}],
  "invariants": [{"claim": "property that must hold throughout", "anchor": "..."}],
  "negative_specs": [{"claim": "what this function must NOT do", "anchor": "..."}]
}

Every claim MUST carry an "anchor": a short snippet copied VERBATIM \
from the provided source (a parameter declaration, a check, a call — \
whatever the claim is grounded in). Anchors are verified mechanically \
against the source; a claim whose anchor does not appear in the source \
is demoted to an unverified hint. Do not paraphrase anchors.

Focus on the safety-relevant parts of the contract: bounds on sizes, \
null-safety, authentication requirements, sanitization guarantees, \
resource lifecycle, crypto properties. Omit trivial specs (e.g. \
"returns a value").
""")

# Cap on source going into the spec prompt.
_SPEC_SOURCE_MAX_CHARS = 4000


def build_spec_prompt(
    function_name: str,
    file_path: str,
    source: str,
    *,
    model_id: str = "",
) -> tuple[str, str]:
    """Envelope the spec-inference prompt: source in an
    ``UntrustedBlock``, identifiers in slots, instructions in system.
    Returns ``(user, system)``."""
    from core.security.prompt_envelope import TaintedString, UntrustedBlock

    from ._util import envelope_prompt

    block = UntrustedBlock(
        content=source[:_SPEC_SOURCE_MAX_CHARS],
        kind="source-code",
        origin=f"{file_path}:{function_name}",
    )
    slots = {
        "file": TaintedString(value=file_path, trust="untrusted"),
        "function": TaintedString(value=function_name, trust="untrusted"),
    }
    # transparent_payload: the spec-extraction ask over an ENCODED
    # payload is hard-refused 100% by Claude models while the same ask
    # over plaintext succeeds (measured; see envelope_prompt's
    # docstring). Compensating defences for the plaintext rendering:
    # pre-call injection preflight and envelope-echo discard in
    # infer_spec_with_llm_sync; prose spec fields only ever ADD to a
    # mechanically-derived spec whose consumers treat llm_inference
    # sources as medium-confidence hints.
    return envelope_prompt(
        _LLM_SPEC_SYSTEM, (block,), slots, model_id=model_id,
        transparent_payload=True,
    )


# Strict top-level schema for the spec response — the keys the prompt
# declares, and nothing else. Unknown fields REJECT the whole response
# (schema-invalid == malformed; callers already treat an empty dict as
# "no LLM data"). Same floor policy as
# core.llm.response_validation.unknown_response_fields.
_SPEC_RESPONSE_KEYS = frozenset({
    "intent",
    "preconditions",
    "postconditions",
    "invariants",
    "negative_specs",
})


def _parse_llm_spec_response(response: str) -> dict[str, Any]:
    """Parse LLM JSON response, handling markdown fences.

    Returns {} for malformed responses — including non-object JSON and
    responses carrying top-level fields outside
    :data:`_SPEC_RESPONSE_KEYS` (strict unknown-field floor).
    """
    import json as _json

    text = response.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        start = 1
        end = len(lines)
        for i in range(1, len(lines)):
            if lines[i].strip() == "```":
                end = i
                break
        text = "\n".join(lines[start:end])

    data: Any = None
    try:
        data = _json.loads(text)
    except _json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            try:
                data = _json.loads(text[start:end + 1])
            except _json.JSONDecodeError:
                pass
    if not isinstance(data, dict):
        return {}
    unknown = sorted(k for k in data if k not in _SPEC_RESPONSE_KEYS)
    if unknown:
        logger.debug(
            "spec response rejected — unknown fields %s", unknown,
        )
        return {}
    return data


# Source-grounding for LLM spec claims (the receipts.py verify
# precedent, applied at this seam): every claim must carry an anchor —
# a verbatim source snippet — that verifies mechanically against the
# exact source slice the model was shown. Anchors below the floor
# ("}", "return;") verify trivially and carry no evidential weight;
# the floor is lower than receipts.MIN_QUOTE_CHARS because code
# anchors ("if (!p)") are denser than prose quotes.
_ANCHOR_MIN_CHARS = 8


def _normalise_anchor(text: str) -> str:
    return re.sub(r"\s+", " ", str(text)).strip()


def _anchor_verifies(anchor: str, norm_source: str) -> bool:
    """True when *anchor* is a verbatim (whitespace-normalised)
    substring of the source the model was shown."""
    norm = _normalise_anchor(anchor)
    return len(norm) >= _ANCHOR_MIN_CHARS and norm in norm_source


def _ground_spec_claims(
    items: Any, norm_source: str,
) -> tuple[list[str], list[str]]:
    """Split raw claim items into (anchored, unanchored) claim texts.

    Accepts the prompt's ``{"claim", "anchor"}`` objects; a bare
    string (schema drift) has no anchor and lands in the unanchored
    bucket. Items without usable claim text are dropped.
    """
    anchored: list[str] = []
    unanchored: list[str] = []
    if not isinstance(items, list):
        return anchored, unanchored
    for item in items:
        if isinstance(item, dict):
            claim = str(item.get("claim", "") or "").strip()
            if not claim:
                continue
            if _anchor_verifies(str(item.get("anchor", "") or ""),
                                norm_source):
                anchored.append(claim)
            else:
                unanchored.append(claim)
        elif isinstance(item, str) and item.strip():
            unanchored.append(item.strip())
    return anchored, unanchored


def infer_spec_with_llm_sync(
    gap: dict[str, Any],
    mechanical_spec: InferredSpec | None = None,
    *,
    client: Any | None = None,
) -> InferredSpec | None:
    """Synchronous LLM spec inference for use in the review loop.

    Fires only for high-value targets (entry points, sinks, auth/crypto)
    where mechanical inference produced incomplete results.

    ``client`` should be the run's budget-governed LLM client so
    spec-inference spend enters the run ledger and the per-call
    reservation gate (a private client here once left 28 calls of
    spend invisible to the --max-cost cap). Falls back to a fresh
    client for library callers.
    """
    function_name = gap.get("name", "")
    file_path = gap.get("file", "")
    source = gap.get("source", "")

    if not source:
        return mechanical_spec

    # Injection preflight over the source BEFORE spending the call —
    # the spec class renders its payload plaintext (build_spec_prompt),
    # so a source carrying known injection phrasing keeps the
    # mechanical spec only.
    from core.security.prompt_input_preflight import preflight

    pf = preflight(source)
    if pf.has_injection_indicators:
        logger.warning(
            "spec_inference: injection indicators (%s) in %s:%s source "
            "— skipping LLM spec inference (mechanical spec only)",
            ",".join(pf.indicators), file_path, function_name,
        )
        return mechanical_spec

    try:
        if client is None:
            from core.llm.client import LLMClient
            client = LLMClient()
        prompt, system_prompt = build_spec_prompt(
            function_name, file_path, source,
            model_id=getattr(client, "model_name", "") or "",
        )
        response = client.generate(
            prompt, system_prompt=system_prompt, task_type="audit",
            call_class="spec_inference",
        )
        text = response.text if hasattr(response, "text") else str(response)
    except Exception:  # noqa: BLE001 — inference is best-effort; fall back to mechanical spec
        logger.debug("LLM spec inference unavailable for %s:%s", file_path, function_name)
        return mechanical_spec

    spec = mechanical_spec or InferredSpec(function=function_name, file=file_path)

    # Envelope-echo discard: a response replaying envelope structure is
    # contamination evidence, not an answer.
    if "<untrusted-" in text:
        logger.warning(
            "spec_inference: response for %s:%s discarded — envelope "
            "structure echoed in output (possible injection "
            "contamination)",
            file_path, function_name,
        )
        return spec

    data = _parse_llm_spec_response(text)
    if not data:
        return spec

    if data.get("intent") and not spec.intent:
        # Intent is one sentence of descriptive prose consumed as
        # context only (same pass-through as _ground_summary's state
        # transitions) — it grounds no verification decision.
        spec.intent = str(data["intent"])
        spec.sources.append(SpecSource(
            signal="llm_inference", confidence="medium", evidence="LLM-inferred intent",
        ))

    # Source-grounding: only claims whose verbatim anchor verifies
    # against the exact source slice the model was shown enter the
    # spec lists; the rest are demoted to the hint tier (llm_hints).
    norm_source = _normalise_anchor(source[:_SPEC_SOURCE_MAX_CHARS])
    hint_count = 0
    for field_name, target in (
        ("preconditions", spec.preconditions),
        ("postconditions", spec.postconditions),
        ("invariants", spec.invariants),
        ("negative_specs", spec.negative_specs),
    ):
        anchored, unanchored = _ground_spec_claims(
            data.get(field_name, []), norm_source,
        )
        for claim in anchored:
            if claim not in target:
                target.append(claim)
        for claim in unanchored:
            hint = f"{field_name}: {claim}"
            if hint not in spec.llm_hints:
                spec.llm_hints.append(hint)
                hint_count += 1
    if hint_count:
        logger.debug(
            "spec_inference: %d unanchored claim(s) for %s:%s demoted "
            "to hint tier", hint_count, file_path, function_name,
        )

    if not any(s.signal == "llm_inference" for s in spec.sources):
        spec.sources.append(SpecSource(
            signal="llm_inference", confidence="medium", evidence="LLM semantic analysis",
        ))

    return spec


def find_peer_functions(
    function_name: str,
    checklist: dict[str, Any],
) -> list[dict[str, Any]]:
    """Find peer functions with similar names for comparison.

    Detects versioned functions (parse_v1/parse_v2), copy-paste variants
    (validate_email/validate_phone), and overloaded methods. Divergences
    between peers are likely bugs.
    """
    base = _extract_base_name(function_name)
    if not base or len(base) < 3:
        return []

    peers = []
    for file_entry in checklist.get("files", []):
        for item in file_entry.get("items", file_entry.get("functions", [])):
            name = item.get("name", "")
            if name == function_name:
                continue
            if _is_peer(base, function_name, name):
                peers.append({
                    "name": name,
                    "file": file_entry.get("path", ""),
                    "line": item.get("line_start", 0),
                })

    return peers[:5]


def _extract_base_name(name: str) -> str:
    """Strip version suffixes and common prefixes to get the base concept."""
    stripped = re.sub(r"_?v\d+$", "", name)
    stripped = re.sub(r"_(?:new|old|orig|fixed|safe|unsafe)$", "", stripped)
    stripped = re.sub(r"\d+$", "", stripped)
    return stripped


def _is_peer(base: str, original: str, candidate: str) -> bool:
    """Check if candidate is a peer of original given the base name."""
    if candidate == original:
        return False
    cand_base = _extract_base_name(candidate)
    if cand_base == base and cand_base != candidate:
        return True
    prefix_len = len(os.path.commonprefix([original, candidate]))
    return prefix_len >= len(original) * 0.6 and prefix_len >= 4
