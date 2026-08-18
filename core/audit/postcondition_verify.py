"""Cross-module postcondition verification for inter-module semantic bugs.

The hardest bug class emerges when two individually correct components
interact through a false postcondition.  Component A claims
"output is safe" but its implementation violates that claim for specific
inputs (e.g., Unicode normalisation after metacharacter stripping).
Component B trusts the claim and passes the output to a sink.

This module identifies security-critical functions (sanitisers, validators,
encoders), extracts their postconditions, and flags three violation patterns:

1. Ordering violations — a postcondition-relevant step is not the last
   transformation (e.g., sanitise then normalise reintroduces characters).

2. Completeness gaps — a postcondition claims safety against a character
   class but the implementation misses representations (Unicode, URL
   encoding, HTML entities, double encoding).

3. Composition violations — function A's postcondition is trusted by
   function B, but A's implementation doesn't actually guarantee it.

Applied selectively: only to functions whose purpose is enforcing a
security property (sanitisers, validators, encoders, deserialisers).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)

_SANITISER_PATTERNS = re.compile(
    r"\b(?:sanitiz|sanitise|clean|strip|escape|filter|purif|scrub|bleach|safe)",
    re.IGNORECASE,
)

_VALIDATOR_PATTERNS = re.compile(
    r"\b(?:validat|verify|check|assert|is_valid|is_safe|ensure|confirm|guard)",
    re.IGNORECASE,
)

_ENCODER_PATTERNS = re.compile(
    r"\b(?:encod|decod|serial|deserial|marshal|unmarshal|pack|unpack|render|format)",
    re.IGNORECASE,
)


class PostconditionKind(str):
    SAFETY_GUARANTEE = "safety_guarantee"
    VALIDATION_GUARANTEE = "validation_guarantee"
    ENCODING_GUARANTEE = "encoding_guarantee"
    TYPE_GUARANTEE = "type_guarantee"


class ViolationKind(str):
    ORDERING = "ordering"
    COMPLETENESS = "completeness"
    COMPOSITION = "composition"


class FunctionRole(str):
    SANITISER = "sanitiser"
    VALIDATOR = "validator"
    ENCODER = "encoder"
    DECODER = "decoder"
    SERIALISER = "serialiser"
    DESERIALISER = "deserialiser"


@dataclass
class Postcondition:
    """A claimed postcondition of a function."""

    function: str
    file: str
    kind: str
    description: str
    claimed_guarantee: str
    role: str = ""
    source: str = "summary"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "function": self.function,
            "file": self.file,
            "kind": self.kind,
            "description": self.description,
            "claimed_guarantee": self.claimed_guarantee,
            "role": self.role,
            "source": self.source,
        }


@dataclass
class PostconditionViolation:
    """A detected violation of a function's postcondition."""

    function: str
    file: str
    violation_kind: str
    postcondition: Postcondition
    description: str
    detail: str = ""
    consumer_function: str = ""
    consumer_file: str = ""
    confidence: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "function": self.function,
            "file": self.file,
            "violation_kind": self.violation_kind,
            "postcondition": self.postcondition.to_dict(),
            "description": self.description,
            "confidence": self.confidence,
        }
        if self.detail:
            d["detail"] = self.detail
        if self.consumer_function:
            d["consumer_function"] = self.consumer_function
            d["consumer_file"] = self.consumer_file
        return d


@dataclass
class PostconditionVerifyResult:
    """Result of postcondition verification across a codebase."""

    postconditions: List[Postcondition] = field(default_factory=list)
    violations: List[PostconditionViolation] = field(default_factory=list)
    functions_checked: int = 0
    functions_with_postconditions: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "postconditions": [p.to_dict() for p in self.postconditions],
            "violations": [v.to_dict() for v in self.violations],
            "functions_checked": self.functions_checked,
            "functions_with_postconditions": self.functions_with_postconditions,
        }


def classify_function_role(
    function_name: str,
    *,
    return_type: str = "",
    summary_text: str = "",
) -> Optional[str]:
    """Classify a function's security role from its name and signature."""
    name_lower = function_name.lower()
    combined = f"{name_lower} {summary_text.lower()}"

    if _SANITISER_PATTERNS.search(combined):
        return FunctionRole.SANITISER
    if _VALIDATOR_PATTERNS.search(combined):
        if return_type in ("bool", "boolean", "int"):
            return FunctionRole.VALIDATOR
        if re.search(r"\bis_\w+|check_\w+|valid", name_lower):
            return FunctionRole.VALIDATOR
    if _ENCODER_PATTERNS.search(combined):
        if re.search(r"de(?:serial|marshal)", name_lower):
            return FunctionRole.DESERIALISER
        if re.search(r"decod", name_lower):
            return FunctionRole.DECODER
        if re.search(r"serial|marshal", name_lower):
            return FunctionRole.SERIALISER
        return FunctionRole.ENCODER

    return None


def extract_postconditions(
    gaps: Sequence[Dict[str, Any]],
    summaries: Dict[str, Any],
) -> List[Postcondition]:
    """Extract postconditions from function summaries.

    Only examines functions with a security-relevant role (sanitiser,
    validator, encoder, decoder, serialiser, deserialiser).
    """
    postconditions: List[Postcondition] = []

    for gap in gaps:
        func_name = gap.get("name", "")
        file_path = gap.get("file", "")
        if not func_name:
            continue

        summary = _lookup_summary(func_name, file_path, summaries)
        return_type = gap.get("return_type", "")
        summary_text = ""
        if summary:
            summary_text = getattr(summary, "summary", "")

        role = classify_function_role(
            func_name,
            return_type=return_type,
            summary_text=summary_text,
        )
        if role is None:
            continue

        extracted = _extract_postconditions_from_summary(
            func_name, file_path, role, summary,
        )
        postconditions.extend(extracted)

    return postconditions


def check_ordering_violations(
    postcondition: Postcondition,
    call_sequence: Sequence[str],
    *,
    consumer_function: Optional[str] = None,
    consumer_file: Optional[str] = None,
) -> Optional[PostconditionViolation]:
    """Check whether the postcondition-relevant operation is the last step.

    A sanitiser that strips dangerous characters then normalises Unicode
    violates its postcondition because normalisation can reintroduce
    stripped characters.

    ``call_sequence`` is the CONSUMER's call sequence; the misordering
    is a property of that consumer, so the violation is attributed to
    ``consumer_function``/``consumer_file`` when given. ``postcondition``
    names the guarantee at risk (the sanitising callee's) — without the
    consumer attribution the record would blame the sanitiser's own
    defining module for its caller's ordering bug.
    """
    if not call_sequence or len(call_sequence) < 2:
        return None

    safety_calls = set()
    transform_calls = set()

    for call in call_sequence:
        call_lower = call.lower()
        if _SANITISER_PATTERNS.search(call_lower):
            safety_calls.add(call)
        if re.search(
            r"(?:normaliz|normalis|lower|upper|trim|replace|convert|transform)",
            call_lower,
        ):
            transform_calls.add(call)

    if not safety_calls or not transform_calls:
        return None

    last_safety_idx = -1
    last_transform_idx = -1
    for i, call in enumerate(call_sequence):
        if call in safety_calls:
            last_safety_idx = i
        if call in transform_calls:
            last_transform_idx = i

    if last_transform_idx > last_safety_idx >= 0:
        transform_after = [
            c for i, c in enumerate(call_sequence)
            if c in transform_calls and i > last_safety_idx
        ]
        return PostconditionViolation(
            function=consumer_function or postcondition.function,
            file=consumer_file or postcondition.file,
            violation_kind=ViolationKind.ORDERING,
            postcondition=postcondition,
            description=(
                f"transformation after safety check: "
                f"{', '.join(transform_after)} runs after "
                f"the last sanitisation step"
            ),
            confidence="high",
        )

    return None


def check_composition_violations(
    producer: Postcondition,
    consumer_function: str,
    consumer_file: str,
    consumer_preconditions: Sequence[str],
) -> List[PostconditionViolation]:
    """Check that a producer's postcondition satisfies a consumer's preconditions.

    When function A's output feeds function B's input, A's postcondition
    should imply B's preconditions.  This flags cases where the
    postcondition is too weak or doesn't cover the precondition.
    """
    violations: List[PostconditionViolation] = []
    guarantee = producer.claimed_guarantee.lower()

    for precond in consumer_preconditions:
        precond_lower = precond.lower()

        coverage = _postcondition_covers_precondition(guarantee, precond_lower)
        if not coverage:
            violations.append(PostconditionViolation(
                function=producer.function,
                file=producer.file,
                violation_kind=ViolationKind.COMPOSITION,
                postcondition=producer,
                description=(
                    f"postcondition may not satisfy consumer precondition: "
                    f"'{precond[:100]}'"
                ),
                consumer_function=consumer_function,
                consumer_file=consumer_file,
                confidence="medium",
            ))

    return violations


def check_completeness(
    postcondition: Postcondition,
    handled_representations: Sequence[str],
    known_representations: Optional[Sequence[str]] = None,
) -> Optional[PostconditionViolation]:
    """Check whether a safety guarantee covers all representations.

    If a sanitiser claims "no shell metacharacters" but only strips
    ASCII semicolons without handling Unicode fullwidth semicolons,
    URL-encoded %3B, HTML entity &#59;, etc., flag the gap.
    """
    if known_representations is None:
        known_representations = _default_representations()

    handled_set = {r.lower() for r in handled_representations}
    known_set = {r.lower() for r in known_representations}

    # Score only representations the handled-representation extractor can
    # actually report; tokens outside its vocabulary would count as missing
    # for every function regardless of the implementation, making the
    # check non-discriminating.
    missing = (known_set & _EXTRACTABLE_REPRESENTATIONS) - handled_set
    if not missing:
        return None

    return PostconditionViolation(
        function=postcondition.function,
        file=postcondition.file,
        violation_kind=ViolationKind.COMPLETENESS,
        postcondition=postcondition,
        description=(
            f"postcondition may miss {len(missing)} representations: "
            f"{', '.join(sorted(missing)[:5])}"
        ),
        confidence="low",
    )


def verify_postconditions(
    gaps: Sequence[Dict[str, Any]],
    summaries: Dict[str, Any],
    call_graphs: Optional[Dict[str, Any]] = None,
) -> PostconditionVerifyResult:
    """Run postcondition verification across the codebase.

    Extracts postconditions, then checks ordering and composition
    where call graph data is available.
    """
    postconditions = extract_postconditions(gaps, summaries)

    result = PostconditionVerifyResult(
        postconditions=postconditions,
        functions_checked=len(gaps),
        functions_with_postconditions=len(
            {(pc.file, pc.function) for pc in postconditions}
        ),
    )

    postcond_by_func: Dict[str, Postcondition] = {}
    for pc in postconditions:
        key = f"{pc.file}:{pc.function}"
        postcond_by_func[key] = pc

    if not call_graphs:
        return result

    # Index the call graphs so gaps carrying no callee data can be
    # filled from them: "file:caller" -> [callee tail names]. The
    # ``call_graphs`` parameter used to be a pure boolean gate the
    # loop never read — and every production caller passed None, so
    # this whole ordering/composition tier had never executed.
    graph_callees: Dict[str, List[str]] = {}
    for cg_file, fcg in call_graphs.items():
        for cs in getattr(fcg, "calls", None) or ():
            chain = getattr(cs, "chain", None) or []
            caller = getattr(cs, "caller", None)
            if not chain or not caller:
                continue
            graph_callees.setdefault(
                f"{cg_file}:{caller}", [],
            ).append(chain[-1])

    for gap in gaps:
        func_name = gap.get("name", "")
        file_path = gap.get("file", "")
        key = f"{file_path}:{func_name}"

        callees = gap.get("callees", []) or graph_callees.get(key, [])
        callee_names = [
            c if isinstance(c, str) else c.get("name", "")
            for c in callees
        ]

        consumer_preconditions = _extract_consumer_preconditions(gap, summaries)

        # Ordering is a property of THIS gap's call sequence — check it
        # once per gap and attribute it to the consumer, not once per
        # callee attributed to whichever producer module the loop was
        # visiting. The at-risk postcondition is the last sanitising
        # callee's (the guarantee a later transform can undo).
        gap_producers = [
            (c, postcond_by_func[k])
            for c in callee_names
            for k in (_find_key_for_function(c, postcond_by_func),)
            if k is not None
        ]
        ordering_pc = None
        for c, pc in gap_producers:
            if _SANITISER_PATTERNS.search(c.lower()):
                ordering_pc = pc  # latest sanitising callee wins
        if ordering_pc is None and gap_producers:
            ordering_pc = gap_producers[-1][1]
        if ordering_pc is not None:
            ordering_viol = check_ordering_violations(
                ordering_pc, callee_names,
                consumer_function=func_name,
                consumer_file=file_path,
            )
            if ordering_viol:
                result.violations.append(ordering_viol)

        for callee in callee_names:
            callee_key = _find_key_for_function(callee, postcond_by_func)
            if callee_key is None:
                continue

            producer_pc = postcond_by_func[callee_key]

            if consumer_preconditions:
                comp_viols = check_composition_violations(
                    producer_pc, func_name, file_path,
                    consumer_preconditions,
                )
                result.violations.extend(comp_viols)

            # Completeness only for postconditions a summary actually
            # CLAIMED — an "inferred" postcondition is this module's
            # own name-based guess, and scoring the guess against the
            # representation catalogue just argues with itself
            # (measured on a large tree: every sanitiser-NAMED
            # function produced the same boilerplate
            # missing-representations row). Deduped per
            # (file, function, kind): the enclosing loop visits a
            # producer once per CALLER, and per-encounter emission
            # multiplied each violation by its call-site count.
            if producer_pc.source != "inferred" and producer_pc.role in (
                FunctionRole.SANITISER, FunctionRole.ENCODER,
                FunctionRole.SERIALISER,
            ):
                handled = _extract_handled_representations(
                    producer_pc, summaries,
                )
                completeness_viol = check_completeness(
                    producer_pc, handled,
                )
                if completeness_viol:
                    result.violations.append(completeness_viol)

    # Dedup: the gap loop reaches the same producer through every
    # caller; identical violations differ only by traversal path.
    _seen: set = set()
    _unique = []
    for v in result.violations:
        d = v.to_dict()
        k = (d.get("function"), d.get("file"), d.get("violation_kind"),
             str(d.get("description", ""))[:120])
        if k in _seen:
            continue
        _seen.add(k)
        _unique.append(v)
    result.violations[:] = _unique

    return result


def check_sibling_ordering(
    siblings: Sequence[Dict[str, Any]],
) -> List[PostconditionViolation]:
    """Compare operation ordering across sibling functions.

    When peer functions (render_X, render_Y) apply the same safety
    operations in different orders, the one that differs from the
    majority is likely wrong.  This catches the sanitizer-ordering
    bug: strip_whitespace then strip_invisible vs the reverse.
    """
    from core.audit.sibling_analysis import check_operation_order

    if len(siblings) < 2:
        return []

    call_sequences: List[tuple] = []
    for sib in siblings:
        seq = sib.get("call_sequence", [])
        if not seq:
            callees = sib.get("callees", [])
            seq = [
                c if isinstance(c, str) else c.get("name", "")
                for c in callees
            ]
        call_sequences.append((sib, seq))

    violations: List[PostconditionViolation] = []
    seen_pairs: set = set()

    for i, (sib_a, seq_a) in enumerate(call_sequences):
        for j, (sib_b, seq_b) in enumerate(call_sequences):
            if i >= j:
                continue
            pair_key = (i, j)
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)

            order_issue = check_operation_order(seq_a, seq_b)
            if not order_issue:
                continue

            name_a = sib_a.get("name", f"sibling_{i}")
            name_b = sib_b.get("name", f"sibling_{j}")
            file_a = sib_a.get("file", "")
            file_b = sib_b.get("file", "")

            pc = Postcondition(
                function=name_a,
                file=file_a,
                kind=PostconditionKind.SAFETY_GUARANTEE,
                description=f"inferred: operation ordering should match sibling {name_b}",
                claimed_guarantee="security operations applied in consistent order",
                role="",
                source="sibling_comparison",
            )

            violations.append(PostconditionViolation(
                function=name_a,
                file=file_a,
                violation_kind=ViolationKind.ORDERING,
                postcondition=pc,
                description=(
                    f"sibling ordering mismatch with {name_b}: {order_issue}"
                ),
                consumer_function=name_b,
                consumer_file=file_b,
                confidence="medium",
            ))

    return violations


def check_sibling_sanitizer_strength(
    siblings: Sequence[Dict[str, Any]],
) -> List[PostconditionViolation]:
    """Compare sanitizer strength across sibling functions.

    When peer functions use different sanitizers for the same purpose,
    the one using a weaker sanitizer is a likely bug — especially when
    the majority uses the strong one.
    """
    from core.audit.sibling_analysis import classify_sanitizer_strength

    if len(siblings) < 2:
        return []

    strengths: List[tuple] = []
    for sib in siblings:
        sanitizer = sib.get("sanitizer", "")
        if not sanitizer:
            callees = sib.get("callees", [])
            for c in callees:
                name = c if isinstance(c, str) else c.get("name", "")
                strength = classify_sanitizer_strength(name)
                if strength != "unknown":
                    sanitizer = name
                    break
        if sanitizer:
            strengths.append((sib, sanitizer, classify_sanitizer_strength(sanitizer)))

    if len(strengths) < 2:
        return []

    strong_count = sum(1 for _, _, s in strengths if s == "strong")
    weak_entries = [(sib, san) for sib, san, s in strengths if s == "weak"]

    if strong_count == 0 or not weak_entries:
        return []

    violations: List[PostconditionViolation] = []
    for sib, san in weak_entries:
        name = sib.get("name", "")
        file_path = sib.get("file", "")

        pc = Postcondition(
            function=name,
            file=file_path,
            kind=PostconditionKind.SAFETY_GUARANTEE,
            description="inferred: should use strong sanitizer like siblings",
            claimed_guarantee="output sanitized with strength matching peer functions",
            role=FunctionRole.SANITISER,
            source="sibling_comparison",
        )

        violations.append(PostconditionViolation(
            function=name,
            file=file_path,
            violation_kind=ViolationKind.COMPOSITION,
            postcondition=pc,
            description=(
                f"uses weak sanitizer '{san}' while "
                f"{strong_count} siblings use a strong sanitizer"
            ),
            confidence="high" if strong_count >= 2 else "medium",
        ))

    return violations


def format_postcondition_context(
    postconditions: Sequence[Postcondition],
    violations: Sequence[PostconditionViolation],
) -> str:
    """Render postcondition verification results for LLM prompt injection."""
    if not postconditions and not violations:
        return ""

    lines = ["### Postcondition verification"]

    if postconditions:
        lines.append("")
        lines.append(f"**{len(postconditions)} security-critical functions with postconditions:**")
        for pc in postconditions[:10]:
            lines.append(
                f"- `{pc.function}()` ({pc.role}): {pc.claimed_guarantee[:120]}"
            )
        if len(postconditions) > 10:
            lines.append(f"  ...and {len(postconditions) - 10} more")

    if violations:
        lines.append("")
        lines.append(f"**{len(violations)} postcondition violations detected:**")
        for v in violations:
            lines.append(
                f"- [{v.confidence.upper()}] `{v.function}()`: "
                f"{v.description[:150]}"
            )
            if v.consumer_function:
                lines.append(
                    f"  Consumer: `{v.consumer_function}()` ({v.consumer_file})"
                )

    return "\n".join(lines)


# -- Internal helpers --

def _lookup_summary(
    function_name: str,
    file_path: str,
    summaries: Dict[str, Any],
) -> Any:
    if file_path:
        key = f"{file_path}:{function_name}"
        if key in summaries:
            return summaries[key]

    for k, v in summaries.items():
        if k.endswith(f":{function_name}"):
            return v

    return summaries.get(function_name)


def _extract_postconditions_from_summary(
    function_name: str,
    file_path: str,
    role: str,
    summary: Any,
) -> List[Postcondition]:
    postconditions: List[Postcondition] = []

    postconds = getattr(summary, "postconditions", []) if summary else []
    for pc in postconds:
        guarantee = getattr(pc, "guarantee", "") or getattr(pc, "description", "")
        if guarantee:
            postconditions.append(Postcondition(
                function=function_name,
                file=file_path,
                kind=PostconditionKind.SAFETY_GUARANTEE,
                description=f"postcondition from summary: {guarantee[:200]}",
                claimed_guarantee=guarantee,
                role=role,
            ))

    if not postconditions:
        summary_text = getattr(summary, "summary", "") if summary else ""
        inferred = _infer_postcondition(function_name, role, summary_text)
        if inferred:
            inferred.file = file_path
            postconditions.append(inferred)

    return postconditions


def _infer_postcondition(
    function_name: str,
    role: str,
    summary_text: str,
) -> Optional[Postcondition]:
    if role == FunctionRole.SANITISER:
        return Postcondition(
            function=function_name,
            file="",
            kind=PostconditionKind.SAFETY_GUARANTEE,
            description="inferred: output is sanitised/safe",
            claimed_guarantee="output does not contain dangerous characters or sequences",
            role=role,
            source="inferred",
        )
    if role == FunctionRole.VALIDATOR:
        return Postcondition(
            function=function_name,
            file="",
            kind=PostconditionKind.VALIDATION_GUARANTEE,
            description="inferred: input is validated when returns true",
            claimed_guarantee="returns true only if input satisfies validation criteria",
            role=role,
            source="inferred",
        )
    return None


def _postcondition_covers_precondition(
    guarantee: str,
    precondition: str,
) -> bool:
    """Heuristic: does the guarantee text semantically cover the precondition?

    Very conservative — returns True (no violation) when uncertain.
    Only flags obvious gaps.
    """
    safety_terms = {"safe", "sanitiz", "sanitise", "clean", "escap", "strip"}
    has_safety = any(t in guarantee for t in safety_terms)
    needs_safety = any(t in precondition for t in safety_terms)
    if needs_safety and not has_safety:
        return False

    validation_terms = {"valid", "check", "verify", "confirm"}
    has_validation = any(t in guarantee for t in validation_terms)
    needs_validation = any(t in precondition for t in validation_terms)
    if needs_validation and not has_validation:
        return False

    return True


def _default_representations() -> List[str]:
    return [
        "ascii",
        "unicode",
        "url_encoded",
        "html_entity",
        "double_encoded",
        "utf8_overlong",
    ]


def _find_key_for_function(
    function_name: str,
    index: Dict[str, Any],
) -> Optional[str]:
    for key in index:
        if key.endswith(f":{function_name}") or key == function_name:
            return key
    return None


def _extract_consumer_preconditions(
    gap: Dict[str, Any],
    summaries: Dict[str, Any],
) -> List[str]:
    """Extract preconditions that a consumer function expects from its inputs."""
    func_name = gap.get("name", "")
    file_path = gap.get("file", "")
    summary = _lookup_summary(func_name, file_path, summaries)
    if summary is None:
        return []
    preconds = getattr(summary, "preconditions", [])
    result: List[str] = []
    for p in preconds:
        conds = getattr(p, "conditions", [])
        for c in conds:
            text = str(c)[:200]
            if text:
                result.append(text)
    return result[:10]


# Vocabulary of representations _extract_handled_representations can emit.
# check_completeness scores against this set — a token the extractor can
# never report as handled must not be counted as missing.
_EXTRACTABLE_REPRESENTATIONS = frozenset({
    "ascii",
    "url_encoded",
    "html_entity",
    "unicode",
})


def _extract_handled_representations(
    postcondition: Postcondition,
    summaries: Dict[str, Any],
) -> List[str]:
    """Extract character representations the sanitiser handles."""
    summary = _lookup_summary(
        postcondition.function, postcondition.file, summaries,
    )
    handled: List[str] = []
    guarantee = postcondition.claimed_guarantee.lower()
    if "ascii" in guarantee or "metacharacter" in guarantee:
        handled.append("ascii")
    if "url" in guarantee or "percent" in guarantee:
        handled.append("url_encoded")
    if "html" in guarantee or "entity" in guarantee:
        handled.append("html_entity")
    if "unicode" in guarantee:
        handled.append("unicode")
    if summary:
        body = getattr(summary, "summary", "") or ""
        body_lower = body.lower()
        if "replace" in body_lower or "strip" in body_lower:
            handled.append("ascii")
        if "urldecode" in body_lower or "unquote" in body_lower:
            handled.append("url_encoded")
    return handled
