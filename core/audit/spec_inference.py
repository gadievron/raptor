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
from typing import Any, Dict, List, Optional

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
    preconditions: List[str] = field(default_factory=list)
    postconditions: List[str] = field(default_factory=list)
    invariants: List[str] = field(default_factory=list)
    negative_specs: List[str] = field(default_factory=list)
    sources: List[SpecSource] = field(default_factory=list)


_NAME_INTENT: List[tuple] = [
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

_PARAM_PRECONDITIONS: List[tuple] = [
    (re.compile(r"__user\b"), "pointer is user-space (must copy_from_user)"),
    (re.compile(r"\bsize_t\b.*\blen\b|\bsize_t\b.*\bsize\b|\bsize_t\b.*\bcount\b"),
     "length parameter must be bounds-checked"),
    (re.compile(r"\bconst\s+char\s*\*"), "string pointer must not be NULL"),
    (re.compile(r"\bFILE\s*\*"), "file handle must be open and valid"),
    (re.compile(r"\bint\s+fd\b"), "file descriptor must be valid (>= 0)"),
    (re.compile(r"\bvoid\s*\*\s*\w+\s*,\s*(?:size_t|int|unsigned)"),
     "buffer/length pair — length must not exceed buffer size"),
]

_ATTR_INVARIANTS: Dict[str, str] = {
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

_NEGATIVE_KEYWORDS: Dict[str, str] = {
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
    gap: Dict[str, Any],
    checklist: Optional[Dict[str, Any]] = None,
    tests: Optional[Dict[str, Any]] = None,
    summaries: Optional[Dict[str, Any]] = None,
) -> InferredSpec:
    """Infer a function's specification from mechanical signals only."""
    file_path = gap.get("file", "")
    function_name = gap.get("name", "")

    spec = InferredSpec(function=function_name, file=file_path)

    _infer_from_name(spec, function_name)
    _infer_from_params(spec, gap)
    _infer_from_attributes(spec, gap)
    _infer_from_docstring(spec, gap)
    _infer_from_tests(spec, function_name, tests)
    _infer_from_caller_usage(spec, function_name, checklist, summaries)
    _infer_negative_specs(spec, function_name, gap)
    _infer_from_assertions(spec, gap)

    return spec


def should_infer_with_llm(
    gap: Dict[str, Any],
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
    if strategy in ("auth", "crypto", "privilege", "injection"):
        return True

    return False


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


def _infer_from_params(spec: InferredSpec, gap: Dict[str, Any]) -> None:
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


def _infer_from_attributes(spec: InferredSpec, gap: Dict[str, Any]) -> None:
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


def _infer_from_docstring(spec: InferredSpec, gap: Dict[str, Any]) -> None:
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
    tests: Optional[Dict[str, Any]],
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
    checklist: Optional[Dict[str, Any]],
    summaries: Optional[Dict[str, Any]],
) -> None:
    """Infer spec from how callers use the return value."""
    if not checklist:
        return

    items = checklist.get("items", [])
    caller_count = 0
    callers_that_check_return = 0

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
    gap: Dict[str, Any],
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


_ASSERTION_PATTERNS: List[tuple] = [
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
    gap: Dict[str, Any],
) -> None:
    """Extract preconditions/invariants from assertion macros."""
    source = gap.get("source", "")
    if not source:
        return

    line_start = gap.get("line_start", 0)
    for i, line in enumerate(source.splitlines()):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*"):
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
    evidence: List[Dict[str, str]] = field(default_factory=list)

    @property
    def verification_rate(self) -> float:
        if self.total_call_sites == 0:
            return 0.0
        return self.verified_sites / self.total_call_sites


def verify_preconditions_at_call_sites(
    spec: InferredSpec,
    callers: List[Dict[str, Any]],
    checklist: Optional[Dict[str, Any]] = None,
) -> List[PreconditionVerification]:
    """Cross-reference preconditions against call sites.

    For each precondition, checks whether all callers satisfy it.
    Returns one PreconditionVerification per precondition.
    """
    if not spec.preconditions or not callers:
        return []

    results: List[PreconditionVerification] = []
    for precond in spec.preconditions:
        v = _verify_one_precondition(precond, callers, checklist)
        results.append(v)
    return results


def _verify_one_precondition(
    precondition: str,
    callers: List[Dict[str, Any]],
    checklist: Optional[Dict[str, Any]],
) -> PreconditionVerification:
    """Check one precondition against all known callers."""
    verified = 0
    violated = 0
    unknown = 0
    evidence: List[Dict[str, str]] = []

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
) -> Optional[bool]:
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
    checklist: Dict[str, Any],
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
    verifications: List[PreconditionVerification],
) -> str:
    """Render precondition verification as a context section for the LLM."""
    if not verifications:
        return ""
    lines = ["### Precondition verification (mechanical)"]
    for v in verifications:
        if v.total_call_sites == 0:
            continue
        status = "UNIVERSALLY SATISFIED" if v.is_universally_satisfied else (
            f"{v.verified_sites}/{v.total_call_sites} callers verified"
        )
        lines.append(f"- `{v.precondition}`: {status}")
        if v.is_universally_satisfied:
            lines.append(
                "  A hypothesis that callers violate this precondition "
                "is mechanically refuted."
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


_LLM_SPEC_PROMPT = """\
You are inferring a security specification for a function. Given the source \
code, determine what this function SHOULD do — its contract with callers.

Function: {function} in {file}
```
{source}
```

Respond with JSON only:
{{
  "intent": "one sentence describing what this function should do",
  "preconditions": ["condition that must hold on entry"],
  "postconditions": ["condition that must hold on exit"],
  "invariants": ["property that must hold throughout"],
  "negative_specs": ["what this function must NOT do"]
}}

Focus on security-relevant specifications: bounds on sizes, null-safety, \
authentication requirements, sanitization guarantees, resource lifecycle, \
crypto properties. Omit trivial specs (e.g. "returns a value").
"""


async def infer_spec_with_llm(
    gap: Dict[str, Any],
    llm_call,
    mechanical_spec: Optional[InferredSpec] = None,
) -> InferredSpec:
    """Infer a function's specification using an LLM for semantic understanding.

    Supplements mechanical inference for high-value targets (entry points,
    sinks, auth/crypto functions). The LLM reads source code and infers
    the function's security contract — what it SHOULD do.

    llm_call: async callable(prompt: str) -> str
    """
    function_name = gap.get("name", "")
    file_path = gap.get("file", "")
    source = gap.get("source", "")

    if not source:
        return mechanical_spec or InferredSpec(function=function_name, file=file_path)

    prompt = _LLM_SPEC_PROMPT.format(
        function=function_name,
        file=file_path,
        source=source[:4000],
    )

    spec = mechanical_spec or InferredSpec(function=function_name, file=file_path)

    try:
        response = await llm_call(prompt)
        data = _parse_llm_spec_response(response)
    except Exception:
        logger.debug("LLM spec inference failed for %s:%s", file_path, function_name)
        return spec

    if data.get("intent") and not spec.intent:
        spec.intent = data["intent"]
        spec.sources.append(SpecSource(
            signal="llm_inference", confidence="medium", evidence="LLM-inferred intent",
        ))

    for pc in data.get("preconditions", []):
        if pc and pc not in spec.preconditions:
            spec.preconditions.append(pc)

    for pc in data.get("postconditions", []):
        if pc and pc not in spec.postconditions:
            spec.postconditions.append(pc)

    for inv in data.get("invariants", []):
        if inv and inv not in spec.invariants:
            spec.invariants.append(inv)

    for ns in data.get("negative_specs", []):
        if ns and ns not in spec.negative_specs:
            spec.negative_specs.append(ns)

    if not any(s.signal == "llm_inference" for s in spec.sources):
        spec.sources.append(SpecSource(
            signal="llm_inference", confidence="medium", evidence="LLM semantic analysis",
        ))

    return spec


def _parse_llm_spec_response(response: str) -> Dict[str, Any]:
    """Parse LLM JSON response, handling markdown fences."""
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

    try:
        return _json.loads(text)
    except _json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            try:
                return _json.loads(text[start:end + 1])
            except _json.JSONDecodeError:
                pass
    return {}


def infer_spec_with_llm_sync(
    gap: Dict[str, Any],
    mechanical_spec: Optional[InferredSpec] = None,
) -> Optional[InferredSpec]:
    """Synchronous LLM spec inference for use in the review loop.

    Fires only for high-value targets (entry points, sinks, auth/crypto)
    where mechanical inference produced incomplete results.
    """
    function_name = gap.get("name", "")
    file_path = gap.get("file", "")
    source = gap.get("source", "")

    if not source:
        return mechanical_spec

    prompt = _LLM_SPEC_PROMPT.format(
        function=function_name,
        file=file_path,
        source=source[:4000],
    )

    try:
        from core.llm.client import LLMClient
        client = LLMClient()
        response = client.generate(prompt, task_type="audit")
        text = response.text if hasattr(response, "text") else str(response)
    except Exception:
        logger.debug("LLM spec inference unavailable for %s:%s", file_path, function_name)
        return mechanical_spec

    spec = mechanical_spec or InferredSpec(function=function_name, file=file_path)

    data = _parse_llm_spec_response(text)
    if not data:
        return spec

    if data.get("intent") and not spec.intent:
        spec.intent = data["intent"]
        spec.sources.append(SpecSource(
            signal="llm_inference", confidence="medium", evidence="LLM-inferred intent",
        ))

    for pc in data.get("preconditions", []):
        if pc and pc not in spec.preconditions:
            spec.preconditions.append(pc)

    for pc in data.get("postconditions", []):
        if pc and pc not in spec.postconditions:
            spec.postconditions.append(pc)

    for inv in data.get("invariants", []):
        if inv and inv not in spec.invariants:
            spec.invariants.append(inv)

    for ns in data.get("negative_specs", []):
        if ns and ns not in spec.negative_specs:
            spec.negative_specs.append(ns)

    if not any(s.signal == "llm_inference" for s in spec.sources):
        spec.sources.append(SpecSource(
            signal="llm_inference", confidence="medium", evidence="LLM semantic analysis",
        ))

    return spec


def find_peer_functions(
    function_name: str,
    checklist: Dict[str, Any],
) -> List[Dict[str, Any]]:
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
    if prefix_len >= len(original) * 0.6 and prefix_len >= 4:
        return True
    return False
