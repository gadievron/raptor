"""Sibling asymmetry detection for /audit.

The most productive source-audit pattern: find sibling code paths
that should behave identically for security, then diff their safety
properties.  When N-1 siblings do the safe thing and 1 doesn't,
that's almost always a real bug — not a design trade-off.

Sibling types:
  - error_vs_normal:  error/exception branch vs the happy path
  - peer_functions:   functions doing the same job (renderers,
                      validators, parsers) identified by naming
                      pattern or call-graph position
  - paired_operations: sanitizer/encoder pairs that should be
                       symmetric (encode on input ↔ decode on output)

Peer-group *formation* lives in ``core.analysis.peer_groups`` (the
layered L0–L6 resolver); this module supplies the group/path data
model and the comparators.

Safety properties compared across siblings:
  - sanitizer_used:       which sanitizer function (identity, name)
  - sanitizer_strength:   strong vs weak (by call target)
  - validation_present:   does this path validate input?
  - env_handling:         does this path scrub env vars?
  - return_on_error:      does the error path block/abort?
  - guard_present:        does this path have a context check?
  - path_validation:      does this path check traversal?
  - operation_order:       order of security-relevant operations
  - coverage_completeness: does this path cover all cases?
  - selection_policy:      first-vs-last, any-vs-all, etc.

When N siblings agree on a property and K disagree (K < N/2),
the K are flagged as asymmetry findings with confidence
proportional to (N-K)/N.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SiblingType(str, Enum):
    ERROR_VS_NORMAL = "error_vs_normal"
    PEER_FUNCTIONS = "peer_functions"
    PAIRED_OPERATIONS = "paired_operations"


class SafetyProperty(str, Enum):
    SANITIZER_USED = "sanitizer_used"
    SANITIZER_STRENGTH = "sanitizer_strength"
    VALIDATION_PRESENT = "validation_present"
    ENV_HANDLING = "env_handling"
    RETURN_ON_ERROR = "return_on_error"
    GUARD_PRESENT = "guard_present"
    PATH_VALIDATION = "path_validation"
    OPERATION_ORDER = "operation_order"
    COVERAGE_COMPLETENESS = "coverage_completeness"
    SELECTION_POLICY = "selection_policy"


@dataclass
class SiblingPath:
    """One arm of a sibling group."""

    label: str
    file: str
    function: str
    line: int = 0
    is_error_path: bool = False
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "file": self.file,
            "function": self.function,
            "line": self.line,
            "is_error_path": self.is_error_path,
            "properties": self.properties,
        }


@dataclass
class SiblingGroup:
    """A group of code paths that should share safety properties."""

    group_id: str
    sibling_type: SiblingType
    description: str
    siblings: list[SiblingPath] = field(default_factory=list)
    shared_context: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "group_id": self.group_id,
            "sibling_type": self.sibling_type.value,
            "description": self.description,
            "siblings": [s.to_dict() for s in self.siblings],
            "shared_context": self.shared_context,
        }


@dataclass
class Asymmetry:
    """A detected safety-property asymmetry between siblings."""

    group_id: str
    property_name: str
    majority_value: Any
    minority_value: Any
    majority_count: int
    minority_count: int
    minority_siblings: list[str]
    confidence: float
    severity: str = "medium"
    explanation: str = ""

    @property
    def is_high_confidence(self) -> bool:
        return self.confidence >= 0.75

    def to_dict(self) -> dict[str, Any]:
        return {
            "group_id": self.group_id,
            "property": self.property_name,
            "majority_value": str(self.majority_value),
            "minority_value": str(self.minority_value),
            "majority_count": self.majority_count,
            "minority_count": self.minority_count,
            "minority_siblings": self.minority_siblings,
            "confidence": round(self.confidence, 2),
            "severity": self.severity,
            "explanation": self.explanation,
        }


def find_asymmetries(group: SiblingGroup) -> list[Asymmetry]:
    """Compare safety properties across siblings in a group.

    For each property present in any sibling, count how many agree
    on each value.  When a minority disagrees with the majority,
    flag it as an asymmetry.
    """
    if len(group.siblings) < 2:
        return []

    all_props: set[str] = set()
    for sibling in group.siblings:
        all_props.update(sibling.properties.keys())

    asymmetries = []
    for prop in sorted(all_props):
        values: dict[Any, list[str]] = {}
        for sibling in group.siblings:
            val = sibling.properties.get(prop)
            if val is None:
                continue
            key = _normalize_value(val)
            if key not in values:
                values[key] = []
            values[key].append(sibling.label)

        if len(values) < 2:
            continue

        sorted_groups = sorted(values.items(), key=lambda x: len(x[1]), reverse=True)
        majority_val, majority_labels = sorted_groups[0]
        total_with_prop = sum(len(v) for v in values.values())

        for minority_val, minority_labels in sorted_groups[1:]:
            if len(minority_labels) >= len(majority_labels):
                continue

            confidence = len(majority_labels) / total_with_prop
            severity = _estimate_severity(prop, confidence, group.sibling_type)

            asymmetries.append(Asymmetry(
                group_id=group.group_id,
                property_name=prop,
                majority_value=majority_val,
                minority_value=minority_val,
                majority_count=len(majority_labels),
                minority_count=len(minority_labels),
                minority_siblings=minority_labels,
                confidence=confidence,
                severity=severity,
                explanation=(
                    f"{len(majority_labels)}/{total_with_prop} siblings have "
                    f"{prop}={majority_val}; {', '.join(minority_labels)} "
                    f"have {prop}={minority_val}"
                ),
            ))

    return asymmetries


def _normalize_value(val: Any) -> str:
    if isinstance(val, bool):
        return str(val).lower()
    if isinstance(val, (list, tuple)):
        return ",".join(str(v) for v in sorted(val))
    return str(val)


_SEVERITY_ESCALATION = {
    SafetyProperty.RETURN_ON_ERROR.value: "high",
    SafetyProperty.ENV_HANDLING.value: "high",
    SafetyProperty.PATH_VALIDATION.value: "high",
    SafetyProperty.SANITIZER_USED.value: "medium",
    SafetyProperty.SANITIZER_STRENGTH.value: "medium",
    SafetyProperty.GUARD_PRESENT.value: "medium",
    SafetyProperty.VALIDATION_PRESENT.value: "medium",
    SafetyProperty.OPERATION_ORDER.value: "medium",
    SafetyProperty.SELECTION_POLICY.value: "medium",
    SafetyProperty.COVERAGE_COMPLETENESS.value: "low",
}


def _estimate_severity(
    prop: str,
    confidence: float,
    sibling_type: SiblingType,
) -> str:
    base = _SEVERITY_ESCALATION.get(prop, "medium")

    if sibling_type == SiblingType.ERROR_VS_NORMAL and base == "medium":
        base = "high"

    if confidence >= 0.9 and base == "medium":
        base = "high"

    return base


# ── Sibling identification heuristics ──────────────────────────────

_ERROR_BRANCH_PATTERNS = frozenset({
    "except", "catch", "rescue", "on_error", "onerror",
    "error_handler", "handle_error", "err_",
    "if err", "if error", "else",
})

_PEER_NAME_GROUPS = [
    re.compile(r"^(render|format|emit|display)_(\w+)$", re.IGNORECASE),
    re.compile(r"^(validate|check|verify)_(\w+)$", re.IGNORECASE),
    re.compile(r"^(sanitize|sanitise|escape|clean|scrub)_(\w+)$", re.IGNORECASE),
    re.compile(r"^(parse|decode|deserialize|unmarshal)_(\w+)$", re.IGNORECASE),
    re.compile(r"^(handle|process|dispatch)_(\w+)$", re.IGNORECASE),
    re.compile(r"^(scan|detect|identify)_(\w+)$", re.IGNORECASE),
]


def identify_peer_groups(
    functions: list[dict[str, Any]],
) -> list[SiblingGroup]:
    """Group functions into peer groups by naming pattern.

    Functions that share a verb prefix (render_X, render_Y) are
    likely siblings that should share safety properties.
    """
    groups: dict[str, list[dict[str, Any]]] = {}

    for func in functions:
        name = func.get("name", "")
        for pattern in _PEER_NAME_GROUPS:
            m = pattern.match(name)
            if m:
                verb = m.group(1).lower()
                key = f"{verb}_group"
                if key not in groups:
                    groups[key] = []
                groups[key].append(func)
                break

    result = []
    for key, members in groups.items():
        if len(members) < 2:
            continue

        group = SiblingGroup(
            group_id=key,
            sibling_type=SiblingType.PEER_FUNCTIONS,
            description=f"Peer functions: {key}",
            siblings=[
                SiblingPath(
                    label=m.get("name", ""),
                    file=m.get("file", ""),
                    function=m.get("name", ""),
                    line=m.get("line", 0),
                )
                for m in members
            ],
        )
        result.append(group)

    return result


def identify_error_branches(
    function_name: str,
    file: str,
    branches: list[dict[str, Any]],
) -> SiblingGroup | None:
    """Create a sibling group from normal vs error branches
    within a single function.
    """
    if len(branches) < 2:
        return None

    siblings = []
    for branch in branches:
        label = branch.get("label", "branch")
        is_error = any(
            pat in label.lower()
            for pat in _ERROR_BRANCH_PATTERNS
        )
        siblings.append(SiblingPath(
            label=label,
            file=file,
            function=function_name,
            line=branch.get("line", 0),
            is_error_path=is_error,
            properties=branch.get("properties", {}),
        ))

    if not any(s.is_error_path for s in siblings):
        return None

    return SiblingGroup(
        group_id=f"{file}:{function_name}:error_branches",
        sibling_type=SiblingType.ERROR_VS_NORMAL,
        description=f"Error vs normal branches in {function_name}",
        siblings=siblings,
    )


# ── Sanitizer strength comparison ──────────────────────────────────

_STRONG_SANITIZERS = frozenset({
    "escape_html", "html_escape", "htmlspecialchars",
    "parameterize", "parameterise", "prepared_statement",
    "bleach.clean", "sanitize_strict", "strong_sanitize",
    "defuse", "purify",
})

_WEAK_SANITIZERS = frozenset({
    "strip_tags", "strip", "replace", "gsub",
    "basic_escape", "simple_sanitize", "weak_sanitize",
    "truncate",
})


def classify_sanitizer_strength(sanitizer_name: str) -> str:
    """Classify a sanitizer as strong, weak, or unknown."""
    name_lower = sanitizer_name.lower()
    if any(s in name_lower for s in _STRONG_SANITIZERS):
        return "strong"
    if any(s in name_lower for s in _WEAK_SANITIZERS):
        return "weak"
    return "unknown"


# ── Operation ordering comparison ──────────────────────────────────

def check_operation_order(
    ops_a: list[str],
    ops_b: list[str],
) -> str | None:
    """Check if two operation sequences have a security-relevant
    ordering difference.

    Returns a description of the ordering issue, or None if
    the sequences are compatible.
    """
    if not ops_a or not ops_b:
        return None

    common = [op for op in ops_a if op in ops_b]
    if len(common) < 2:
        return None

    positions_a: dict[str, list[int]] = {}
    for idx, op in enumerate(ops_a):
        positions_a.setdefault(op, []).append(idx)
    positions_b: dict[str, list[int]] = {}
    for idx, op in enumerate(ops_b):
        positions_b.setdefault(op, []).append(idx)

    for i in range(len(common) - 1):
        idxs_a_i = positions_a.get(common[i], [])
        idxs_a_next = positions_a.get(common[i + 1], [])
        idxs_b_i = positions_b.get(common[i], [])
        idxs_b_next = positions_b.get(common[i + 1], [])
        if not idxs_a_i or not idxs_a_next or not idxs_b_i or not idxs_b_next:
            continue
        idx_a_i = idxs_a_i[-1]
        idx_a_next = idxs_a_next[-1]
        idx_b_i = idxs_b_i[-1]
        idx_b_next = idxs_b_next[-1]

        if (idx_a_i < idx_a_next) != (idx_b_i < idx_b_next):
            return (
                f"Operation order differs: {common[i]} and {common[i+1]} "
                f"are swapped between siblings"
            )

    return None


# ── Format helpers ─────────────────────────────────────────────────

def format_asymmetry_finding(asymmetry: Asymmetry) -> str:
    """Format an asymmetry as a finding description for the LLM prompt.

    Property names / explanations embed target identifiers, so they
    are defanged with ``neutralize_tag_forgery`` before landing in the
    review prompt.
    """
    from core.security.prompt_envelope import neutralize_tag_forgery

    lines = [
        (f"Sibling asymmetry [{asymmetry.severity.upper()}]: "
         f"{neutralize_tag_forgery(asymmetry.property_name)}"),
        f"  {neutralize_tag_forgery(asymmetry.explanation)}",
    ]
    if asymmetry.confidence >= 0.75:
        lines.append(
            f"  Confidence: {asymmetry.confidence:.0%} — "
            f"strong convention, likely a real bug"
        )
    return "\n".join(lines)


def format_asymmetry_report(asymmetries: list[Asymmetry]) -> str:
    """Format all asymmetries for the operator."""
    if not asymmetries:
        return "Sibling analysis: no asymmetries detected"

    high = [a for a in asymmetries if a.severity == "high"]
    medium = [a for a in asymmetries if a.severity == "medium"]
    low = [a for a in asymmetries if a.severity == "low"]

    lines = [
        (f"Sibling analysis: {len(asymmetries)} asymmetries "
         f"({len(high)} high, {len(medium)} medium, {len(low)} low)"),
        "",
    ]

    _sev_order = {"high": 0, "medium": 1, "low": 2}
    for a in sorted(asymmetries, key=lambda x: _sev_order.get(x.severity, 3)):
        lines.append(format_asymmetry_finding(a))
        lines.append("")

    return "\n".join(lines)


def format_for_prompt(
    groups: list[SiblingGroup],
    asymmetries: list[Asymmetry],
) -> str:
    """Format sibling analysis results for injection into the LLM
    review prompt."""
    if not asymmetries:
        return ""

    high_conf = [a for a in asymmetries if a.is_high_confidence]
    if not high_conf:
        return ""

    lines = [
        "SIBLING ASYMMETRIES DETECTED — investigate these first:",
        "",
    ]
    for a in high_conf:
        lines.append(format_asymmetry_finding(a))
        lines.append("")

    return "\n".join(lines)


# ── Semantic consistency checks ──────────────────────────────────
#
# Source-code regex patterns that detect security-relevant practices.
# Used by check_semantic_consistency to find outlier siblings that
# skip a practice the majority performs.

_AUTH_CHECK_RE = re.compile(
    r"\b(?:is_authenticated|is_authorized|check_auth|require_auth"
    r"|check_permission|has_permission|has_role|require_login"
    r"|login_required|auth_required|verify_token|check_token"
    r"|authenticate|authorize"
    r"|@login_required|@permission_required|@auth_required)\b",
)

_ERROR_RETURN_RE = re.compile(
    r"(?:"
    r"\breturn\s+(?:err\b|error\b|nil\b|null\b|None\b|false\b|False\b|-1\b)"
    r"|\b(?:raise|throw)\s+\w+"
    r"|\b(?:abort|exit|panic|die|fatal)\s*\("
    r")",
)

_INCLUSIVE_BOUND_RE = re.compile(
    r"\b\w+\s*<=\s*(?:len\s*\(|\w+\.(?:length|size|count)\b"
    r"|\w*(?:max|limit|bound|capacity|_len|_size)\b)",
    re.IGNORECASE,
)

_STRICT_BOUND_RE = re.compile(
    r"\b\w+\s*<(?!=)\s*(?:len\s*\(|\w+\.(?:length|size|count)\b"
    r"|\w*(?:max|limit|bound|capacity|_len|_size)\b)",
    re.IGNORECASE,
)

_NULL_GUARD_RE = re.compile(
    r"(?:"
    r"\bif\b.*\bis\s+None\b"
    r"|\bif\s*\(.*==\s*(?:NULL|null|nil|nullptr)\b"
    r"|\bif\s*\(\s*!\s*\w+\s*[)\s{]"
    r"|\bif\s+not\s+\w+\b"
    r"|\bif\s*\(.*!=\s*(?:NULL|null|nil|nullptr)\b"
    r")",
    re.IGNORECASE,
)

_BOUNDS_GUARD_RE = re.compile(
    r"(?:"
    r"\bif\b.*\blen\s*\("
    r"|\bif\b.*\.(?:size|length|count)\s*\("
    r"|\bif\b.*\b(?:index|idx|offset|pos)\s*[<>=!]"
    r")",
    re.IGNORECASE,
)


def _find_sibling(
    group: SiblingGroup, func_name: str,
) -> SiblingPath | None:
    """Find a SiblingPath by function name."""
    for s in group.siblings:
        if s.function == func_name:
            return s
    return None


def _flag_outliers(
    group: SiblingGroup,
    sources: dict[str, str],
    check_fn: Any,
    inconsistency_template: str,
    cwe: str,
) -> list[dict]:
    """Flag siblings that don't match a pattern when the majority does.

    ``check_fn`` is called with the function's source and should
    return a truthy value when the practice is present.
    """
    results: dict[str, bool] = {}
    for func, src in sources.items():
        results[func] = bool(check_fn(src))

    present = sum(1 for v in results.values() if v)
    absent = sum(1 for v in results.values() if not v)
    total = len(results)

    # Need a clear majority: at least 2 have the pattern, at least
    # 1 doesn't, and the minority is strictly smaller.
    if total < 3 or present < 2 or absent == 0 or absent >= present:
        return []

    confidence = present / total
    findings: list[dict] = []
    for func, has_pattern in results.items():
        if not has_pattern:
            sib = _find_sibling(group, func)
            findings.append({
                "file": sib.file if sib else "",
                "function": func,
                "siblings": [
                    s.function for s in group.siblings
                    if s.function != func
                ],
                "inconsistency": inconsistency_template.format(
                    present=present,
                    total=total,
                    function=func,
                ),
                "confidence": round(confidence, 2),
                "cwe": cwe,
            })

    return findings


def _check_variable_use(
    group: SiblingGroup,
    sources: dict[str, str],
) -> list[dict]:
    """Flag siblings that skip auth/permission checks present in peers."""
    return _flag_outliers(
        group,
        sources,
        lambda src: _AUTH_CHECK_RE.search(src),
        "{present}/{total} siblings perform auth/permission checks; "
        "{function} does not",
        "CWE-862",
    )


def _check_error_handling(
    group: SiblingGroup,
    sources: dict[str, str],
) -> list[dict]:
    """Flag siblings that silently continue when peers return errors."""
    return _flag_outliers(
        group,
        sources,
        lambda src: _ERROR_RETURN_RE.search(src),
        "{present}/{total} siblings return error codes on failure; "
        "{function} silently continues",
        "CWE-390",
    )


def _check_boundary_values(
    group: SiblingGroup,
    sources: dict[str, str],
) -> list[dict]:
    """Flag siblings using different comparison operators for bounds checks.

    If most siblings use ``<`` (strict) for bounds and one uses ``<=``
    (inclusive), or vice versa, the outlier may have an off-by-one.
    """
    styles: dict[str, str] = {}
    for func, src in sources.items():
        has_inclusive = bool(_INCLUSIVE_BOUND_RE.search(src))
        has_strict = bool(_STRICT_BOUND_RE.search(src))
        if has_inclusive and not has_strict:
            styles[func] = "inclusive (<=)"
        elif has_strict and not has_inclusive:
            styles[func] = "strict (<)"
        # Mixed or no bounds comparisons — skip this sibling.

    if len(styles) < 3:
        return []

    counts: dict[str, int] = {}
    for val in styles.values():
        counts[val] = counts.get(val, 0) + 1

    if len(counts) < 2:
        return []

    majority_style = max(counts, key=lambda k: counts[k])
    majority_count = counts[majority_style]
    total = len(styles)

    findings: list[dict] = []
    for func, style in styles.items():
        if style != majority_style and counts[style] < majority_count:
            sib = _find_sibling(group, func)
            confidence = majority_count / total
            findings.append({
                "file": sib.file if sib else "",
                "function": func,
                "siblings": [
                    s.function for s in group.siblings
                    if s.function != func
                ],
                "inconsistency": (
                    f"{majority_count}/{total} siblings use "
                    f"{majority_style} for bounds checks; {func} "
                    f"uses {style} — potential off-by-one"
                ),
                "confidence": round(confidence, 2),
                "cwe": "CWE-193",
            })

    return findings


def _check_guard_consistency(
    group: SiblingGroup,
    sources: dict[str, str],
) -> list[dict]:
    """Flag siblings that skip null/bounds guards present in peers."""
    findings: list[dict] = []
    findings.extend(_flag_outliers(
        group,
        sources,
        lambda src: _NULL_GUARD_RE.search(src),
        "{present}/{total} siblings have null/none checks; "
        "{function} skips the guard",
        "CWE-476",
    ))
    findings.extend(_flag_outliers(
        group,
        sources,
        lambda src: _BOUNDS_GUARD_RE.search(src),
        "{present}/{total} siblings have bounds/length checks; "
        "{function} skips the guard",
        "CWE-129",
    ))
    return findings


def check_semantic_consistency(
    siblings: list[SiblingGroup],
    checklist: dict,
) -> list[dict]:
    """Check for semantic inconsistencies between sibling functions.

    Scans source code of sibling functions via regex for patterns
    where N-1 siblings agree on a security-relevant practice but
    one outlier doesn't — a strong signal for a real bug.

    Consistency checks:
      1. Variable-use: auth/permission checks present in most but
         missing from an outlier (CWE-862).
      2. Error handling: error returns/raises in most but one
         sibling silently continues (CWE-390).
      3. Boundary values: ``<=`` vs ``<`` in bounds checks — if
         siblings disagree, potential off-by-one (CWE-193).
      4. Guard consistency: null/bounds guards in most but skipped
         by an outlier (CWE-476, CWE-129).

    Args:
        siblings: Sibling groups to analyse.
        checklist: Maps ``"file:function"`` keys to dicts with at
            least a ``"source"`` field containing the function's
            source code.

    Returns:
        List of finding dicts, each with keys: ``file``,
        ``function``, ``siblings``, ``inconsistency``,
        ``confidence``, ``cwe``.
    """
    findings: list[dict] = []

    for group in siblings:
        if len(group.siblings) < 3:
            continue

        # Resolve source code for each sibling from the checklist.
        sources: dict[str, str] = {}
        for sib in group.siblings:
            key = f"{sib.file}:{sib.function}"
            entry = checklist.get(key, {})
            src = (
                entry.get("source", "")
                if isinstance(entry, dict)
                else ""
            )
            if src:
                sources[sib.function] = src

        if len(sources) < 3:
            continue

        findings.extend(_check_variable_use(group, sources))
        findings.extend(_check_error_handling(group, sources))
        findings.extend(_check_boundary_values(group, sources))
        findings.extend(_check_guard_consistency(group, sources))

    return findings


def semantic_findings_to_mechanical(
    findings: list[dict],
) -> list[dict]:
    """Convert :func:`check_semantic_consistency` outputs into the
    mechanical-detector finding shape (``file``/``function``/
    ``detector``/``line``/``description``).

    This is how semantic-consistency outliers reach
    ``mechanical-findings.json`` and the per-gap review prompt —
    the same route every other mechanical detector uses.
    """
    mechanical: list[dict] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        file = f.get("file", "")
        function = f.get("function", "")
        if not function:
            continue
        desc = f.get("inconsistency", "")
        cwe = f.get("cwe", "")
        confidence = f.get("confidence")
        detail = []
        if cwe:
            detail.append(cwe)
        if confidence is not None:
            detail.append(f"confidence {confidence}")
        if detail:
            desc = f"{desc} [{', '.join(detail)}]"
        mechanical.append({
            "file": file,
            "function": function,
            "detector": "semantic_consistency",
            "line": 0,
            "description": desc,
        })
    return mechanical
