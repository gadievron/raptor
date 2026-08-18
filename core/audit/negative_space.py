"""Negative-space analysis: find bugs that exist as absence.

Missing auth checks, missing input validation, missing error handling,
missing bounds checks — bugs invisible to pattern matchers because
there's no code to match against.

Two-phase approach:
  1. Discover the project's actual security conventions
  2. Check which functions should follow them but don't

Convention-relative checking ("47/50 handlers use @require_auth, this
one doesn't") produces much higher precision than hardcoded checklists.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .gaps import read_gap_source

logger = logging.getLogger(__name__)

CONCERN_AUTH = "auth"
CONCERN_VALIDATION = "validation"
CONCERN_ERROR_HANDLING = "error_handling"
CONCERN_BOUNDS = "bounds"
CONCERN_NULL_CHECK = "null_check"
CONCERN_CONSTANT_TIME = "constant_time"
CONCERN_SECURE_RANDOM = "secure_random"
CONCERN_LOCK = "lock"

ALL_CONCERNS = frozenset({
    CONCERN_AUTH, CONCERN_VALIDATION, CONCERN_ERROR_HANDLING,
    CONCERN_BOUNDS, CONCERN_NULL_CHECK, CONCERN_CONSTANT_TIME,
    CONCERN_SECURE_RANDOM, CONCERN_LOCK,
})

_STRATEGY_CONCERNS: dict[str, list[str]] = {
    "auth": [CONCERN_AUTH],
    "input_handling": [CONCERN_VALIDATION, CONCERN_BOUNDS],
    "memory": [CONCERN_NULL_CHECK, CONCERN_BOUNDS],
    "crypto": [CONCERN_CONSTANT_TIME, CONCERN_SECURE_RANDOM],
    "concurrency": [CONCERN_LOCK],
    "general": [CONCERN_ERROR_HANDLING],
    "aliasing": [],
}

_CONCERN_CWE: dict[str, str] = {
    CONCERN_AUTH: "CWE-306",
    CONCERN_VALIDATION: "CWE-20",
    CONCERN_ERROR_HANDLING: "CWE-252",
    CONCERN_BOUNDS: "CWE-120",
    CONCERN_NULL_CHECK: "CWE-476",
    CONCERN_CONSTANT_TIME: "CWE-208",
    CONCERN_SECURE_RANDOM: "CWE-330",
    CONCERN_LOCK: "CWE-362",
}

MIN_CONVENTION_OCCURRENCES = 3
HIGH_CONFIDENCE_THRESHOLD = 0.8


@dataclass
class SecurityConvention:
    """A project-specific security convention discovered by pattern scan."""

    concern: str
    pattern: str
    occurrences: int
    locations: list[str] = field(default_factory=list)
    framework: str = ""
    confidence: float = 0.5

    @property
    def is_high_confidence(self) -> bool:
        return self.confidence >= HIGH_CONFIDENCE_THRESHOLD


@dataclass
class NegativeSpaceFinding:
    """A missing security check detected by convention-relative analysis."""

    check_type: str
    expected: str
    evidence: str
    cwe: str
    confidence: str
    convention: str
    strategy: str
    file: str = ""
    function: str = ""
    title: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "check_type": self.check_type,
            "expected": self.expected,
            "evidence": self.evidence,
            "cwe": self.cwe,
            "confidence": self.confidence,
            "convention": self.convention,
            "strategy": self.strategy,
        }
        if self.file:
            d["file"] = self.file
        if self.function:
            d["function"] = self.function
        if self.title:
            d["title"] = self.title
        return d


_FRAMEWORK_PATTERNS: dict[str, dict[str, list[str]]] = {
    "django": {
        CONCERN_AUTH: [
            r"@login_required",
            r"request\.user\.is_authenticated",
            r"@permission_required",
            r"LoginRequiredMixin",
        ],
        CONCERN_VALIDATION: [
            r"\.is_valid\(\)",
            r"clean_",
            r"validate_",
        ],
    },
    "flask": {
        CONCERN_AUTH: [
            r"@login_required",
            r"current_user\.is_authenticated",
            r"@auth\.login_required",
        ],
        CONCERN_VALIDATION: [
            r"wtforms.*validate",
            r"request\.form\.get",
        ],
    },
    "express": {
        CONCERN_AUTH: [
            r"req\.isAuthenticated",
            r"passport\.authenticate",
            r"authMiddleware",
        ],
        CONCERN_VALIDATION: [
            r"express-validator",
            r"\.check\(",
            r"\.validationResult",
        ],
    },
    "spring": {
        CONCERN_AUTH: [
            r"@PreAuthorize",
            r"@Secured",
            r"SecurityContextHolder",
            r"@RolesAllowed",
        ],
        CONCERN_VALIDATION: [
            r"@Valid",
            r"@NotNull",
            r"@Size",
            r"BindingResult",
        ],
    },
    "go": {
        CONCERN_ERROR_HANDLING: [
            r"if\s+err\s*!=\s*nil",
        ],
    },
}

_GENERIC_PATTERNS: dict[str, list[str]] = {
    CONCERN_AUTH: [
        r"check_auth",
        r"require_auth",
        r"is_authorized",
        r"require_role",
        r"check_permission",
        r"verify_token",
        r"authenticate",
    ],
    CONCERN_VALIDATION: [
        r"validate_",
        r"check_input",
        r"sanitize_",
        r"verify_",
    ],
    CONCERN_ERROR_HANDLING: [
        r"if\s*\(\s*\w+\s*[<>=!]=?\s*(?:NULL|nullptr|nil|0|false|-1)\s*\)",
        r"if\s+err\s*!=\s*nil",
        r"except\s+\w+",
    ],
    CONCERN_BOUNDS: [
        r"if\s*\(\s*\w+\s*[<>]=?\s*\w+\s*\)",
        r"assert.*len",
        r"check_bounds",
    ],
    CONCERN_NULL_CHECK: [
        r"if\s*\(\s*\w+\s*==\s*NULL\s*\)",
        r"if\s*\(\s*!\s*\w+\s*\)",
        r"if\s*\(\s*\w+\s*==\s*nullptr\s*\)",
    ],
    CONCERN_CONSTANT_TIME: [
        r"constant_time_compare",
        r"hmac\.compare_digest",
        r"crypto\.timingSafeEqual",
        r"CRYPTO_memcmp",
    ],
    CONCERN_SECURE_RANDOM: [
        r"os\.urandom",
        r"secrets\.",
        r"crypto/rand",
        r"SecureRandom",
        r"RAND_bytes",
    ],
    CONCERN_LOCK: [
        r"mutex\.lock\(\)",
        r"pthread_mutex_lock",
        r"sync\.Mutex",
        r"synchronized",
        r"\.acquire\(\)",
    ],
}


def detect_framework(
    gaps: Sequence[dict[str, Any]],
) -> str:
    """Detect the project's web framework from import/require patterns.

    Returns framework name ("django", "flask", "express", "spring", "go", "")
    or empty string if no framework detected.
    """
    gaps = [g for g in gaps if not g.get("dead")]
    signals: dict[str, int] = {}

    framework_imports = {
        "django": ["from django", "import django", "django."],
        "flask": ["from flask", "import flask", "Flask("],
        "express": ["require('express')", 'require("express")', "from 'express'"],
        "spring": ["org.springframework", "@SpringBootApplication", "@RestController"],
        "go": ["net/http", "func.*http.HandlerFunc", "http.Handle"],
    }

    for gap in gaps:
        source = gap.get("source", "")
        if not source:
            continue
        for fw, patterns in framework_imports.items():
            for pat in patterns:
                if pat in source:
                    signals[fw] = signals.get(fw, 0) + 1

    if not signals:
        return ""

    best = max(signals, key=lambda k: signals[k])
    if signals[best] >= 2:
        return best
    return ""


def discover_conventions(
    gaps: Sequence[dict[str, Any]],
    *,
    framework: str = "",
    domain_vocab: Any = None,
) -> list[SecurityConvention]:
    """Discover the project's security conventions by scanning source code.

    Counts how many functions use each security pattern and emits
    conventions with ≥MIN_CONVENTION_OCCURRENCES occurrences.

    *domain_vocab* is an optional
    :class:`~core.audit.condition_smt.DomainVocabulary`; its
    ``auth_predicates`` (study-learned project gates plus any
    target-kind pack) extend the generic auth patterns additively, so
    convention discovery recognises project-specific auth gates
    (``foo_may_access``, ``ns_capable``) the framework/generic seeds
    never matched.
    """
    gaps = [g for g in gaps if not g.get("dead")]
    if not framework:
        framework = detect_framework(gaps)

    pattern_hits: dict[str, dict[str, list[str]]] = {}

    fw_patterns = _FRAMEWORK_PATTERNS.get(framework, {})

    vocab_auth_patterns: list[str] = []
    if domain_vocab is not None:
        preds = getattr(domain_vocab, "auth_predicates", frozenset())
        vocab_auth_patterns = [
            rf"\b{re.escape(name)}\s*\("
            for name, _kind in sorted(preds)
            if name
        ]

    for concern in ALL_CONCERNS:
        patterns_to_check: list[str] = []
        patterns_to_check.extend(fw_patterns.get(concern, []))
        patterns_to_check.extend(_GENERIC_PATTERNS.get(concern, []))
        if concern == CONCERN_AUTH:
            patterns_to_check.extend(vocab_auth_patterns)

        if not patterns_to_check:
            continue

        for gap in gaps:
            source = gap.get("source", "")
            if not source:
                continue
            key = f"{gap.get('file', '')}:{gap.get('name', '')}"

            for pat in patterns_to_check:
                try:
                    if re.search(pat, source):
                        bucket = pattern_hits.setdefault(concern, {})
                        locs = bucket.setdefault(pat, [])
                        if key not in locs:
                            locs.append(key)
                        break
                except re.error:
                    continue

    conventions: list[SecurityConvention] = []
    for concern, pat_map in pattern_hits.items():
        best_pat = max(pat_map, key=lambda p: len(pat_map[p]))
        locs = pat_map[best_pat]
        if len(locs) < MIN_CONVENTION_OCCURRENCES:
            continue

        total_in_strategy = _count_functions_in_concern(gaps, concern)
        adoption = len(locs) / total_in_strategy if total_in_strategy > 0 else 0.0

        conventions.append(SecurityConvention(
            concern=concern,
            pattern=best_pat,
            occurrences=len(locs),
            locations=locs,
            framework=framework,
            confidence=min(adoption, 1.0),
        ))

    return conventions


def _count_functions_in_concern(
    gaps: Sequence[dict[str, Any]],
    concern: str,
) -> int:
    """Count how many functions are in strategies relevant to this concern."""
    relevant_strategies: set[str] = set()
    for strat, concerns in _STRATEGY_CONCERNS.items():
        if concern in concerns:
            relevant_strategies.add(strat)

    if not relevant_strategies:
        return len(gaps)

    count = 0
    for gap in gaps:
        strategies = gap.get("strategies", set())
        if isinstance(strategies, (list, tuple)):
            strategies = set(strategies)
        if strategies & relevant_strategies:
            count += 1

    return count if count > 0 else len(gaps)


def check_negative_space(
    gap: dict[str, Any],
    conventions: Sequence[SecurityConvention],
    strategy: str,
) -> list[NegativeSpaceFinding]:
    """Check a single function for missing security checks.

    Returns findings for each convention this function should follow
    but doesn't.
    """
    source = gap.get("source", "")
    if not source:
        return []

    relevant_concerns = _STRATEGY_CONCERNS.get(strategy, [])
    if not relevant_concerns:
        return []

    findings: list[NegativeSpaceFinding] = []
    key = f"{gap['file']}:{gap['name']}"

    for conv in conventions:
        if conv.concern not in relevant_concerns:
            continue

        if key in conv.locations:
            continue

        if not _should_have_convention(gap, conv):
            continue

        try:
            if re.search(conv.pattern, source):
                continue
        except re.error:
            continue

        adoption_pct = int(conv.confidence * 100)
        confidence = "high" if conv.is_high_confidence else "medium"

        findings.append(NegativeSpaceFinding(
            check_type=f"missing_{conv.concern}",
            expected=(
                f"{conv.pattern} "
                f"(used by {conv.occurrences} functions, ~{adoption_pct}% adoption)"
            ),
            evidence=f"no {conv.concern} check found matching convention",
            cwe=_CONCERN_CWE.get(conv.concern, ""),
            confidence=confidence,
            convention=conv.pattern,
            strategy=strategy,
        ))

    return findings


def _should_have_convention(
    gap: dict[str, Any],
    convention: SecurityConvention,
) -> bool:
    """Decide if this function is in a context where the convention applies.

    Filters out functions that legitimately don't need the check:
    - Internal helpers (not entry points, not handlers)
    - Test functions
    - Very small utility functions (≤5 SLOC)
    """
    name = gap.get("name", "").lower()

    if name.startswith(("test_", "_test")):
        return False

    sloc = gap.get("sloc", 0)
    if sloc > 0 and sloc <= 5:
        return False

    if convention.concern == CONCERN_AUTH:
        is_handler = _looks_like_handler(gap)
        if not is_handler:
            return False

    return True


def _looks_like_handler(gap: dict[str, Any]) -> bool:
    """Heuristic: does this function look like a request/API handler?"""
    name = gap.get("name", "").lower()
    handler_signals = [
        "handle", "view", "endpoint", "route", "api",
        "get", "post", "put", "delete", "patch",
        "create", "update", "destroy", "list", "retrieve",
        "index", "show", "edit", "new",
    ]
    for sig in handler_signals:
        if re.search(r'(?:^|_)' + re.escape(sig) + r'(?:_|$)', name):
            return True

    source = gap.get("source", "")
    decorator_signals = ["@app.route", "@api_view", "@router.", "def get(", "def post("]
    for sig in decorator_signals:
        if sig in source:
            return True

    callers = gap.get("callers", [])
    if not callers:
        is_entry = gap.get("is_entry_point", False)
        if is_entry:
            return True

    return False


def check_sibling_negative_space(
    gaps: Sequence[dict[str, Any]],
    conventions: Sequence[SecurityConvention],
    peer_groups=None,
) -> list[NegativeSpaceFinding]:
    """Detect convention violations by comparing sibling functions.

    Groups functions by naming pattern (render_X / render_Y), then
    checks whether siblings agree on convention adherence.  When most
    siblings in a peer group follow a convention but one doesn't, that's
    stronger evidence than a standalone missing-check finding.

    This catches the "one arm drifted" pattern: 3 renderers use
    html_escape, the 4th uses strip_tags.

    When *peer_groups* is provided, reuses them instead of resolving
    internally — avoids a redundant resolve_peer_groups call.
    """
    gaps = [g for g in gaps if not g.get("dead")]
    from core.audit.sibling_analysis import (
        SiblingGroup,
        SiblingPath,
        SiblingType,
        find_asymmetries,
    )

    if peer_groups is None:
        from core.analysis.peer_groups import resolve_peer_groups

        func_dicts = [
            {"name": g.get("name", ""), "file": g.get("file", ""), "line": g.get("line", 0)}
            for g in gaps
            if g.get("name")
        ]
        peer_groups = resolve_peer_groups(func_dicts)
    if not peer_groups:
        return []

    gap_by_key: dict[str, dict[str, Any]] = {}
    for g in gaps:
        key = f"{g.get('file', '')}:{g.get('name', '')}"
        gap_by_key[key] = g

    findings: list[NegativeSpaceFinding] = []

    for pg in peer_groups:
        enriched_siblings = []
        for sibling in pg.siblings:
            sib_copy = SiblingPath(
                label=sibling.label,
                file=sibling.file,
                function=sibling.function,
                line=sibling.line,
                is_error_path=sibling.is_error_path,
                properties=dict(sibling.properties),
            )
            enriched_siblings.append(sib_copy)

        for conv in conventions:
            for sib_copy in enriched_siblings:
                key = f"{sib_copy.file}:{sib_copy.function}"
                gap = gap_by_key.get(key)
                if not gap:
                    continue
                source = gap.get("source", "")
                adheres = key in conv.locations
                if not adheres and source:
                    try:
                        adheres = bool(re.search(conv.pattern, source))
                    except re.error:
                        pass
                sib_copy.properties[f"convention_{conv.concern}"] = adheres

        enriched_group = SiblingGroup(
            group_id=pg.group_id,
            sibling_type=SiblingType.PEER_FUNCTIONS,
            description=pg.description,
            siblings=enriched_siblings,
        )
        asymmetries = find_asymmetries(enriched_group)

        for asym in asymmetries:
            prop = asym.property_name
            if not prop.startswith("convention_"):
                continue
            concern = prop[len("convention_"):]
            if asym.minority_value != "false":
                continue

            cwe = _CONCERN_CWE.get(concern, "")
            conv_match = next(
                (c for c in conventions if c.concern == concern), None,
            )
            convention_str = conv_match.pattern if conv_match else concern

            for sib_label in asym.minority_siblings:
                findings.append(NegativeSpaceFinding(
                    check_type=f"sibling_missing_{concern}",
                    expected=(
                        f"{asym.majority_count}/{asym.majority_count + asym.minority_count} "
                        f"peer functions follow this convention"
                    ),
                    evidence=(
                        f"{sib_label} lacks {concern} check that "
                        f"its siblings have"
                    ),
                    cwe=cwe,
                    confidence="high" if asym.is_high_confidence else "medium",
                    convention=convention_str,
                    strategy="sibling_asymmetry",
                ))

    return findings


def format_negative_space_prose(
    findings: Sequence[NegativeSpaceFinding],
) -> str:
    """Render negative-space findings as prose for LLM context injection."""
    if not findings:
        return ""

    lines = [
        "### Convention deviations",
        ("Sibling functions in this file follow conventions that this "
        "function deviates from. A deviation is an observation, not a "
        "finding — the function may handle the concern differently, "
        "or the convention may not apply here. Evaluate independently."),
    ]
    for f in findings:
        conf = f"[{f.confidence}]" if f.confidence == "high" else ""
        lines.append(
            f"- ({f.cwe}) {f.check_type} — "
            f"expected {f.expected}. {f.evidence}. {conf}"
        )

    return "\n".join(lines)


# ── Post-loop pattern checks ────────────────────────────────────────
# Pattern-based checks that detect known-dangerous constructs, missing
# security features, and protocol ambiguities across the whole codebase.

_REDOS_SUSPICIOUS = re.compile(
    r"""re\.compile\(\s*[rfbu]*["'].*(?:\+\)\+|\*\)\*|\+\)\*|\*\)\+)""",
    re.IGNORECASE,
)

_UNBOUNDED_ALLOC = re.compile(
    r"(?:malloc|calloc|realloc|new\s+\w+\[)\s*\(\s*\w+\s*(?:\+|\*)\s*\w+",
    re.IGNORECASE,
)

_XML_ENTITY_EXPANSION = re.compile(
    r"(?:XMLParser|xml\.(?:sax|dom|etree|parsers)|parseString|parse\(|fromstring)\s*\(",
    re.IGNORECASE,
)

_XML_SAFE_GUARD = re.compile(
    r"(?:defusedxml|resolve_entities\s*=\s*False|XMLParser\s*\([^)]*resolve_entities|"
    r"set_feature\s*\(\s*feature_external_ges)",
    re.IGNORECASE,
)

_UNBOUNDED_WRITE = re.compile(
    r"\.(?:write|send|sendall|sendto|put|append|extend)\s*\([^)]*\bwhile\b|"
    r"(?:fwrite|fputs|fprintf|write)\s*\(.*\bwhile\b|"
    r"\bwhile\b[^{]*\.(?:write|send|append)\s*\(",
    re.IGNORECASE | re.DOTALL,
)

_HASH_COLLISION = re.compile(
    r"(?:dict|HashMap|HashSet|hash_map|unordered_map|defaultdict)\s*\(",
    re.IGNORECASE,
)

_HASH_COLLISION_GUARD = re.compile(
    r"(?:max_size|capacity|limit|max_entries|MAX_\w+|threshold)",
    re.IGNORECASE,
)

_RECURSIVE_CALL = re.compile(
    r"def\s+(\w+)\s*\([^)]*\).*?\b\1\s*\(",
    re.DOTALL,
)

_RECURSION_GUARD = re.compile(
    r"(?:depth|level|max_depth|MAX_DEPTH|recursion_limit|sys\.setrecursionlimit)",
    re.IGNORECASE,
)


def check_resource_exhaustion(
    gaps: Sequence[dict[str, Any]],
    *,
    target_path: Path | None = None,
    domain_vocab: Any = None,
) -> list[NegativeSpaceFinding]:
    """Detect resource exhaustion patterns."""
    findings: list[NegativeSpaceFinding] = []

    for gap in gaps:
        source = gap.get("source", "") or (
            read_gap_source(gap, target_path) if target_path else ""
        )
        if not source:
            continue

        if _REDOS_SUSPICIOUS.search(source):
            findings.append(NegativeSpaceFinding(
                check_type="resource_exhaustion",
                expected="linear-time regex (no nested quantifiers)",
                evidence=(
                    f"regex in {gap.get('name', '?')} has nested quantifiers "
                    f"that may cause exponential backtracking on adversarial input"
                ),
                cwe="CWE-1333",
                confidence="medium",
                convention="",
                strategy="pattern_scan",
                file=gap.get("file", ""),
                function=gap.get("name", ""),
                title="Potentially catastrophic regex backtracking",
            ))

        unbounded_re = _UNBOUNDED_ALLOC
        if domain_vocab is not None:
            extra = getattr(domain_vocab, "allocators", frozenset())
            if extra:
                alloc_alts = "|".join(
                    re.escape(n) for n in sorted(extra, key=len, reverse=True)
                )
                unbounded_re = re.compile(
                    rf"(?:malloc|calloc|realloc|{alloc_alts}|new\s+\w+\[)\s*\("
                    r"\s*\w+\s*(?:\+|\*)\s*\w+",
                    re.IGNORECASE,
                )
        if unbounded_re.search(source):
            is_checked = bool(re.search(
                r"if\s*\(.*(?:size|len|count|num).*[<>]", source, re.IGNORECASE,
            ))
            if not is_checked:
                findings.append(NegativeSpaceFinding(
                    check_type="resource_exhaustion",
                    expected="bounds check before allocation with arithmetic on user-influenced size",
                    evidence=(
                        f"allocation in {gap.get('name', '?')} uses arithmetic "
                        f"on a size parameter without visible overflow check"
                    ),
                    cwe="CWE-190",
                    confidence="medium",
                    convention="",
                    strategy="pattern_scan",
                    file=gap.get("file", ""),
                    function=gap.get("name", ""),
                    title="Allocation with arithmetic on user-influenced size",
                ))

        if (_XML_ENTITY_EXPANSION.search(source)
                and not _XML_SAFE_GUARD.search(source)):
            findings.append(NegativeSpaceFinding(
                    check_type="resource_exhaustion",
                    expected="defusedxml or entity resolution disabled",
                    evidence=(
                        f"XML parsing in {gap.get('name', '?')} without "
                        f"entity expansion protection"
                    ),
                    cwe="CWE-776",
                    confidence="medium",
                    convention="",
                    strategy="pattern_scan",
                    file=gap.get("file", ""),
                    function=gap.get("name", ""),
                    title="XML entity expansion without protection",
                ))

        if _HASH_COLLISION.search(source):
            has_external_input = bool(re.search(
                r'\b(?:request|input|argv|user|params|query|form|body|headers)\b',
                source, re.IGNORECASE,
            ))
            if has_external_input and not _HASH_COLLISION_GUARD.search(source):
                findings.append(NegativeSpaceFinding(
                    check_type="resource_exhaustion",
                    expected="size limit on hash-based container with external keys",
                    evidence=(
                        f"hash container in {gap.get('name', '?')} with no "
                        f"visible size limit — adversarial keys cause O(n^2)"
                    ),
                    cwe="CWE-407",
                    confidence="low",
                    convention="",
                    strategy="pattern_scan",
                    file=gap.get("file", ""),
                    function=gap.get("name", ""),
                    title="Hash container without size limit",
                ))

        if (_RECURSIVE_CALL.search(source)
                and not _RECURSION_GUARD.search(source)):
            findings.append(NegativeSpaceFinding(
                    check_type="resource_exhaustion",
                    expected="depth limit on recursive function",
                    evidence=(
                        f"recursive call in {gap.get('name', '?')} without "
                        f"visible depth guard"
                    ),
                    cwe="CWE-674",
                    confidence="medium",
                    convention="",
                    strategy="pattern_scan",
                    file=gap.get("file", ""),
                    function=gap.get("name", ""),
                    title="Unbounded recursion without depth limit",
                ))

    return findings


@dataclass
class ProtocolCheck:
    protocol: str
    pattern: re.Pattern
    ambiguity: str
    question: str
    cwe: str
    # Protocol-evidence gate (the check_missing_app_features
    # precedent): when set, the source must ALSO show this evidence
    # before the check fires. Trigger words like "session"/"cookie"
    # are shared vocabulary across protocols — TLS session-cache code
    # was flagged with an HTTP CRLF-injection question purely on the
    # word "session".
    context: re.Pattern | None = None


# Evidence that the source actually speaks HTTP (not merely shares
# vocabulary with it): version strings, header-plumbing identifiers,
# literal header writes.
_HTTP_CONTEXT_RE = re.compile(
    r"(?:HTTP/[0-9]"
    r"|https?://"
    r"|http[_-]?(?:request|response|header|server|client|conn)"
    r"|(?:request|response)[_-]?headers?"
    r"|Content-Length|Transfer-Encoding|Set-Cookie"
    r"|X-Forwarded|status[_ -]?code)",
    re.IGNORECASE,
)


_PROTOCOL_CHECKS = [
    ProtocolCheck(
        protocol="HTTP",
        pattern=re.compile(r"(?:Content-Length|Transfer-Encoding)", re.IGNORECASE),
        ambiguity="CL vs TE request smuggling",
        question="When both Content-Length and Transfer-Encoding are present, does the parser reject or pick one consistently?",
        cwe="CWE-444",
        context=_HTTP_CONTEXT_RE,
    ),
    ProtocolCheck(
        protocol="HTTP",
        pattern=re.compile(r"(?:Set-Cookie|cookie|session)", re.IGNORECASE),
        ambiguity="CRLF header injection",
        question="Are header values checked for \\r\\n before being used in HTTP responses?",
        cwe="CWE-113",
        context=_HTTP_CONTEXT_RE,
    ),
    ProtocolCheck(
        protocol="JWT",
        pattern=re.compile(r"(?:jwt|json.web.token|jose)", re.IGNORECASE),
        ambiguity="Algorithm confusion",
        question="Does the JWT verifier enforce the expected algorithm, or accept alg:none / HS256 when RSA is expected?",
        cwe="CWE-327",
    ),
    ProtocolCheck(
        protocol="XML",
        pattern=re.compile(r"(?:xml\.etree|lxml|minidom|SAXParser|XMLReader|DocumentBuilder)", re.IGNORECASE),
        ambiguity="XXE / entity expansion",
        question="Is entity expansion disabled or limited in the XML parser?",
        cwe="CWE-611",
    ),
    ProtocolCheck(
        protocol="OAuth",
        pattern=re.compile(r"(?:redirect_uri|oauth|authorization_code)", re.IGNORECASE),
        ambiguity="Open redirect in redirect_uri",
        question="Is redirect_uri validated against a strict allowlist?",
        cwe="CWE-601",
    ),
    ProtocolCheck(
        protocol="SAML",
        pattern=re.compile(r"(?:saml|assertion|xmldsig)", re.IGNORECASE),
        ambiguity="XML signature wrapping",
        question="Does the SAML processor verify that the signed element is the one being consumed?",
        cwe="CWE-347",
    ),
]


def check_protocol_ambiguity(
    gaps: Sequence[dict[str, Any]],
    *,
    target_path: Path | None = None,
) -> list[NegativeSpaceFinding]:
    """Flag protocol-handling code vulnerable to known ambiguity classes."""
    findings: list[NegativeSpaceFinding] = []
    seen: set[str] = set()

    for gap in gaps:
        source = gap.get("source", "") or (
            read_gap_source(gap, target_path) if target_path else ""
        )
        if not source:
            continue

        for check in _PROTOCOL_CHECKS:
            if not check.pattern.search(source):
                continue
            if check.context is not None and not check.context.search(source):
                # Trigger word without protocol evidence — shared
                # vocabulary, not a protocol handler.
                continue

            key = f"{gap.get('file')}:{check.protocol}:{check.ambiguity}"
            if key in seen:
                continue
            seen.add(key)

            findings.append(NegativeSpaceFinding(
                check_type="protocol_ambiguity",
                expected=f"{check.protocol} parser handles {check.ambiguity} safely",
                evidence=check.question,
                cwe=check.cwe,
                confidence="low",
                convention="",
                strategy="protocol_checklist",
                file=gap.get("file", ""),
                function=gap.get("name", ""),
                title=f"{check.protocol}: {check.ambiguity}",
            ))

    return findings


@dataclass
class AppFeatureCheck:
    feature: str
    search_patterns: list[re.Pattern]
    finding_if_absent: str
    cwe: str


_APP_FEATURE_CHECKS = [
    AppFeatureCheck(
        feature="Rate limiting",
        search_patterns=[
            re.compile(r"(?:rate.?limit|throttl|RateLimit|slowdown)", re.IGNORECASE),
        ],
        finding_if_absent=(
            "No rate limiting found. Authentication endpoints and "
            "resource-intensive operations may be vulnerable to brute-force "
            "or denial-of-service attacks."
        ),
        cwe="CWE-770",
    ),
    AppFeatureCheck(
        feature="Account lockout",
        search_patterns=[
            re.compile(r"(?:lockout|lock.?out|max.?attempts|failed.?login.?count)", re.IGNORECASE),
        ],
        finding_if_absent=(
            "No account lockout mechanism found. Repeated failed login "
            "attempts are not throttled or blocked."
        ),
        cwe="CWE-307",
    ),
    AppFeatureCheck(
        feature="CSRF protection",
        search_patterns=[
            re.compile(r"(?:csrf|xsrf|CSRFMiddleware|SameSite|anti.?forgery)", re.IGNORECASE),
        ],
        finding_if_absent=(
            "No CSRF protection found on state-changing endpoints. "
            "Cross-site request forgery attacks are unmitigated."
        ),
        cwe="CWE-352",
    ),
    AppFeatureCheck(
        feature="Session timeout",
        search_patterns=[
            re.compile(r"(?:session.?timeout|session.?expir|SESSION_COOKIE_AGE|maxAge)", re.IGNORECASE),
        ],
        finding_if_absent=(
            "No session timeout configured. Sessions may persist indefinitely, "
            "increasing window for session hijacking."
        ),
        cwe="CWE-613",
    ),
    AppFeatureCheck(
        feature="Security headers",
        search_patterns=[
            re.compile(r"(?:Content-Security-Policy|X-Frame-Options|HSTS|Strict-Transport-Security|X-Content-Type-Options)", re.IGNORECASE),
        ],
        finding_if_absent=(
            "No HTTP security headers detected. Missing CSP, HSTS, "
            "X-Frame-Options, or X-Content-Type-Options."
        ),
        cwe="CWE-693",
    ),
    AppFeatureCheck(
        feature="Global error handler",
        search_patterns=[
            re.compile(r"(?:error.?handler|exception.?handler|500|handler500|errorMiddleware|unhandledException)", re.IGNORECASE),
        ],
        finding_if_absent=(
            "No global error handler. Unhandled exceptions may leak "
            "stack traces, internal paths, or configuration to users."
        ),
        cwe="CWE-209",
    ),
]


# File suffixes of languages web applications are written in. The
# app-feature checklist (CSRF, session timeout, rate limiting, …)
# asserts *web-application* obligations: on a target with none of
# these languages (a C crypto library, a kernel module) every check
# "fails" vacuously and pollutes the post-loop findings with noise —
# one measured run emitted all six against pure C.
_WEB_APP_SUFFIXES = frozenset({
    ".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".php", ".rb", ".java", ".kt", ".cs", ".go", ".scala",
})

# Framework / HTTP-server evidence: a web-capable language alone is
# not enough (a Python CLI tool has no CSRF surface either).
_WEB_FRAMEWORK_RE = re.compile(
    r"(?:flask|django|fastapi|starlette|tornado|bottle|aiohttp"
    r"|express\(|require\(['\"]express|fastify|createServer"
    r"|rails|sinatra|rack"
    r"|spring|servlet|@RestController|@RequestMapping|HttpServlet"
    r"|laravel|symfony|asp\.net"
    r"|net/http|http\.Handle|gin\.Default|echo\.New|fiber\.New"
    r"|@app\.route|@router\.|add_url_rule|HttpServer)",
    re.IGNORECASE,
)


def check_missing_app_features(
    gaps: Sequence[dict[str, Any]],
    *,
    target_path: Path | None = None,
) -> list[NegativeSpaceFinding]:
    """Check for application-level security features that should exist
    but may not have been implemented.

    Gated on target language/framework evidence: only runs when the
    target contains web-application-capable language files AND some
    reviewed source shows framework / HTTP-server usage. Anything else
    returns empty with one visible skip line instead of six vacuous
    "Missing: CSRF protection"-style findings.
    """
    if not any(
        Path(gap.get("file", "")).suffix.lower() in _WEB_APP_SUFFIXES
        for gap in gaps
    ):
        logger.info(
            "app-feature checklist skipped — target has no "
            "web-application-capable language files",
        )
        return []

    found_features: set[int] = set()
    framework_seen = False
    for gap in gaps:
        if framework_seen and len(found_features) == len(_APP_FEATURE_CHECKS):
            break
        source = gap.get("source", "") or (
            read_gap_source(gap, target_path) if target_path else ""
        )
        if not source:
            continue
        if not framework_seen and _WEB_FRAMEWORK_RE.search(source):
            framework_seen = True
        for idx, check in enumerate(_APP_FEATURE_CHECKS):
            if idx in found_features:
                continue
            if any(p.search(source) for p in check.search_patterns):
                found_features.add(idx)

    if not framework_seen:
        logger.info(
            "app-feature checklist skipped — no web framework / "
            "HTTP-server evidence in target sources",
        )
        return []

    findings: list[NegativeSpaceFinding] = []
    for idx, check in enumerate(_APP_FEATURE_CHECKS):
        if idx not in found_features:
            findings.append(NegativeSpaceFinding(
                check_type="missing_app_feature",
                expected=f"{check.feature} present in application",
                evidence=check.finding_if_absent,
                cwe=check.cwe,
                confidence="low",
                convention="",
                strategy="app_feature_checklist",
                title=f"Missing: {check.feature}",
            ))

    return findings


_UB_PATTERNS = [
    (
        re.compile(r"if\s*\(\s*\w+\s*\+\s*\w+\s*<\s*\w+\s*\)"),
        "Signed overflow check may be optimized away",
        "CWE-190",
    ),
    (
        re.compile(r"\*\s*\(\s*(?:int|long|short|float|double)\s*\*\s*\)\s*\w+"),
        "Type-punning through pointer cast (strict aliasing violation)",
        "CWE-843",
    ),
    (
        re.compile(r"<<\s*(?:32|64)\b"),
        "Shift by type width (undefined for 32/64-bit types)",
        "CWE-682",
    ),
    (
        re.compile(r"memcpy\s*\([^,]+,\s*[^,]+\s*(?:\+|-)\s*\w+\s*,"),
        "memcpy with overlapping regions risk (should use memmove)",
        "CWE-120",
    ),
    (
        re.compile(
            r"(?:void|char)\s*\*\s*\w+.*(?:sizeof\s*\(|sizeof\b)|"
            r"sizeof\s*\(.*(?:void|char)\s*\*\s*\w+",
        ),
        "Pointer arithmetic on void*/char* near sizeof (potential type confusion)",
        "CWE-843",
    ),
    (
        re.compile(r"union\s+\w+\s*\{[^}]*\b(?:int|float|double|long|short|char)\b[^}]*\}"),
        "Union used for type punning (strict aliasing violation candidate)",
        "CWE-843",
    ),
]


def check_ub_patterns(
    gaps: Sequence[dict[str, Any]],
    *,
    languages: set[str] | None = None,
    target_path: Path | None = None,
) -> list[NegativeSpaceFinding]:
    """Detect known undefined behaviour patterns in C/C++ source."""
    if languages and not (languages & {"c", "cpp", "c++"}):
        return []

    findings: list[NegativeSpaceFinding] = []
    for gap in gaps:
        source = gap.get("source", "") or (
            read_gap_source(gap, target_path) if target_path else ""
        )
        if not source:
            continue

        file_path = gap.get("file", "")
        if not file_path.endswith((".c", ".h", ".cpp", ".cc", ".cxx", ".hpp")):
            continue

        for pattern, desc, cwe in _UB_PATTERNS:
            if pattern.search(source):
                findings.append(NegativeSpaceFinding(
                    check_type="undefined_behaviour",
                    expected="no undefined behaviour patterns",
                    evidence=(
                        f"in {gap.get('name', '?')}: {desc}. "
                        f"Compiler optimizations may silently remove safety checks."
                    ),
                    cwe=cwe,
                    confidence="medium",
                    convention="",
                    strategy="pattern_scan",
                    file=file_path,
                    function=gap.get("name", ""),
                    title=desc,
                ))

    return findings


_SIGNAL_UNSAFE_CALLS = frozenset({
    "malloc", "free", "calloc", "realloc",
    "printf", "fprintf", "sprintf", "snprintf",
    "syslog", "openlog",
    "exit", "abort",
    "pthread_mutex_lock", "pthread_mutex_unlock",
    "fopen", "fclose", "fread", "fwrite",
    "strtok",
})


def check_signal_safety(
    gaps: Sequence[dict[str, Any]],
    *,
    target_path: Path | None = None,
    domain_vocab: Any = None,
) -> list[NegativeSpaceFinding]:
    """Flag signal handlers that call signal-unsafe functions."""
    findings: list[NegativeSpaceFinding] = []

    handler_funcs: set[str] = set()
    for gap in gaps:
        source = gap.get("source", "") or (
            read_gap_source(gap, target_path) if target_path else ""
        )
        handler_matches = re.findall(
            r"signal\s*\(\s*\w+\s*,\s*(\w+)\s*\)", source,
        )
        for hname in handler_matches:
            if hname not in ("SIG_IGN", "SIG_DFL"):
                handler_funcs.add(hname)

    for gap in gaps:
        name = gap.get("name", "")
        if name not in handler_funcs:
            continue

        callees = gap.get("callees", [])
        callee_names = {
            (c if isinstance(c, str) else c.get("name", ""))
            for c in callees
        }

        unsafe_names = _SIGNAL_UNSAFE_CALLS
        if domain_vocab is not None:
            unsafe_names = unsafe_names | (
                getattr(domain_vocab, "allocators", frozenset())
                | getattr(domain_vocab, "deallocators", frozenset())
            )
        unsafe_used = callee_names & unsafe_names
        if unsafe_used:
            findings.append(NegativeSpaceFinding(
                check_type="signal_safety",
                expected="only async-signal-safe functions in signal handler",
                evidence=(
                    f"signal handler {name} calls {', '.join(sorted(unsafe_used))} "
                    f"which are not async-signal-safe per POSIX"
                ),
                cwe="CWE-479",
                confidence="high",
                convention="",
                strategy="pattern_scan",
                file=gap.get("file", ""),
                function=name,
                title="Signal handler calls signal-unsafe functions",
            ))

    return findings


# ── Side-channel patterns ─────────────────────────────────────────────

_EARLY_RETURN_AUTH = re.compile(
    r"(?:password|passwd|secret|token|key|hmac|digest)\s*\[.*\]\s*!=.*:\s*return\s+False",
    re.IGNORECASE,
)

_NON_CONSTANT_TIME_CMP = re.compile(
    r"(?:strcmp|memcmp|==)\s*\(?\s*(?:password|passwd|token|secret|key|hmac|api_key|auth)",
    re.IGNORECASE,
)

_TIMING_BRANCH = re.compile(
    r"if\s+(?:is_admin|is_superuser|is_root|is_privileged|has_role)\s*(?:\(|:)",
    re.IGNORECASE,
)


def check_side_channels(
    gaps: Sequence[dict[str, Any]],
    *,
    target_path: Path | None = None,
) -> list[NegativeSpaceFinding]:
    """Blind spot 12: flag secret-dependent branches and timing leaks."""
    findings: list[NegativeSpaceFinding] = []

    for gap in gaps:
        source = gap.get("source", "") or (
            read_gap_source(gap, target_path) if target_path else ""
        )
        if not source:
            continue
        file = gap.get("file", "")
        function = gap.get("name", "")

        if _EARLY_RETURN_AUTH.search(source):
            findings.append(NegativeSpaceFinding(
                check_type="side_channel",
                expected="constant-time comparison for secret data",
                evidence=(
                    f"in {function}: early-return on byte-by-byte secret comparison "
                    f"leaks secret length via timing"
                ),
                cwe="CWE-208",
                confidence="medium",
                convention="",
                strategy="pattern_scan",
                file=file,
                function=function,
                title="Early-return in secret comparison (timing side channel)",
            ))

        if _NON_CONSTANT_TIME_CMP.search(source):
            findings.append(NegativeSpaceFinding(
                check_type="side_channel",
                expected="hmac.compare_digest or equivalent constant-time compare",
                evidence=(
                    f"in {function}: non-constant-time comparison of "
                    f"secret material (strcmp/memcmp/==)"
                ),
                cwe="CWE-208",
                confidence="medium",
                convention="",
                strategy="pattern_scan",
                file=file,
                function=function,
                title="Non-constant-time comparison of secrets",
            ))

        if _TIMING_BRANCH.search(source):
            findings.append(NegativeSpaceFinding(
                check_type="side_channel",
                expected="privilege check not correlated with observable timing difference",
                evidence=(
                    f"in {function}: privilege-dependent branch before "
                    f"expensive operation may leak role via timing"
                ),
                cwe="CWE-208",
                confidence="medium",
                convention="",
                strategy="pattern_scan",
                file=file,
                function=function,
                title="Timing-variable branch on privilege check",
            ))

    return findings


# ── Multi-process trust boundary patterns ─────────────────────────────

_IPC_DESER_NO_VALIDATE = re.compile(
    r"(?:pickle\.loads?|yaml\.(?:unsafe_)?load|json\.loads?)\s*\(\s*"
    r"(?:\w+\.)?(?:recv|read|readline|recvfrom|recvmsg)\s*\(",
    re.IGNORECASE,
)

_IPC_DESER_SIMPLE = re.compile(
    r"(?:pickle\.loads?|yaml\.(?:unsafe_)?load)\s*\(",
    re.IGNORECASE,
)

_IPC_DESER_SCHEMA_GUARD = re.compile(
    r"(?:schema|validate|pydantic|marshmallow|jsonschema|voluptuous|cerberus)",
    re.IGNORECASE,
)

_SHM_NO_LOCK = re.compile(
    r"(?:mmap\.mmap|shm_open|shmget|shared_memory|SharedMemory)\s*\(",
    re.IGNORECASE,
)

_SHM_LOCK_GUARD = re.compile(
    r"(?:Lock|RLock|Semaphore|mutex|flock|fcntl\.lockf|msync)",
    re.IGNORECASE,
)

_CROSS_PROC_PRIV = re.compile(
    r"(?:os\.getuid|os\.geteuid|os\.getpid|getuid|geteuid)\s*\(\s*\)",
    re.IGNORECASE,
)

_CROSS_PROC_PRIV_CONTEXT = re.compile(
    r"if\s+.*(?:os\.getuid|os\.geteuid|getuid|geteuid)\s*\(",
    re.IGNORECASE,
)

_SUBPROCESS_SHELL_UNTRUSTED = re.compile(
    r"subprocess\.(?:Popen|call|run|check_output|check_call)\s*\([^)]*shell\s*=\s*True",
    re.IGNORECASE,
)


def check_multi_process(
    gaps: Sequence[dict[str, Any]],
    *,
    target_path: Path | None = None,
) -> list[NegativeSpaceFinding]:
    """Blind spot 3: cross-service trust boundary analysis."""
    findings: list[NegativeSpaceFinding] = []

    for gap in gaps:
        source = gap.get("source", "") or (
            read_gap_source(gap, target_path) if target_path else ""
        )
        if not source:
            continue
        file = gap.get("file", "")
        function = gap.get("name", "")

        if _IPC_DESER_NO_VALIDATE.search(source) or (
            _IPC_DESER_SIMPLE.search(source) and not _IPC_DESER_SCHEMA_GUARD.search(source)
        ):
            findings.append(NegativeSpaceFinding(
                check_type="multi_process",
                expected="schema validation on deserialized IPC data",
                evidence=(
                    f"in {function}: IPC deserialization (pickle/yaml/json from "
                    f"socket/pipe) without schema validation"
                ),
                cwe="CWE-502",
                confidence="medium",
                convention="",
                strategy="pattern_scan",
                file=file,
                function=function,
                title="IPC deserialization without validation",
            ))

        if _SHM_NO_LOCK.search(source) and not _SHM_LOCK_GUARD.search(source):
            findings.append(NegativeSpaceFinding(
                check_type="multi_process",
                expected="synchronization primitive around shared memory access",
                evidence=(
                    f"in {function}: shared memory access (mmap/shm_open) "
                    f"without visible locking or synchronization"
                ),
                cwe="CWE-362",
                confidence="medium",
                convention="",
                strategy="pattern_scan",
                file=file,
                function=function,
                title="Shared memory access without synchronization",
            ))

        if _CROSS_PROC_PRIV_CONTEXT.search(source):
            findings.append(NegativeSpaceFinding(
                check_type="multi_process",
                expected="privilege decisions based on verified credentials, not PID/UID",
                evidence=(
                    f"in {function}: security decision based on os.getuid/getpid "
                    f"which can be spoofed across process boundaries"
                ),
                cwe="CWE-250",
                confidence="medium",
                convention="",
                strategy="pattern_scan",
                file=file,
                function=function,
                title="Cross-process privilege assumption via PID/UID",
            ))

        if _SUBPROCESS_SHELL_UNTRUSTED.search(source):
            findings.append(NegativeSpaceFinding(
                check_type="multi_process",
                expected="subprocess with shell=False and list arguments",
                evidence=(
                    f"in {function}: subprocess call with shell=True "
                    f"may execute untrusted data as shell commands"
                ),
                cwe="CWE-78",
                confidence="medium",
                convention="",
                strategy="pattern_scan",
                file=file,
                function=function,
                title="Subprocess with shell=True from external input",
            ))

    return findings


# ── Deployment assumption patterns ────────────────────────────────────

_HARDCODED_LOCALHOST = re.compile(
    r"""(?:127\.0\.0\.1|localhost|0\.0\.0\.0).*(?:auth|secur|allow|trust|permit|acl|whitelist)"""
    r"""|(?:auth|secur|allow|trust|permit|acl|whitelist).*(?:127\.0\.0\.1|localhost|0\.0\.0\.0)""",
    re.IGNORECASE,
)

_GLOBAL_STATE_NO_LOCK = re.compile(
    r"(?:global\s+\w+|_(?:cache|state|registry|store|sessions|connections)\s*(?:=|\[))",
    re.IGNORECASE,
)

_GLOBAL_STATE_LOCK_GUARD = re.compile(
    r"(?:Lock|RLock|threading\.Lock|mutex|synchronized|atomic)",
    re.IGNORECASE,
)

_HARDCODED_PATHS = re.compile(
    r"""(?:/tmp/|/var/run/|/var/tmp/)[\w./-]+""",
)

_HARDCODED_PATH_SECURITY_CONTEXT = re.compile(
    r"(?:secret|key|password|token|cert|credential|auth|session|cookie)",
    re.IGNORECASE,
)

_DEBUG_SKIP_SECURITY = re.compile(
    r"if\s+.*(?:DEBUG|TESTING|DEV_MODE|DEVELOPMENT|TEST_MODE)\s*"
    r"(?::|.*(?:skip|disable|bypass|no).*(?:auth|secur|valid|check|verif))",
    re.IGNORECASE,
)


def check_deployment_assumptions(
    gaps: Sequence[dict[str, Any]],
    *,
    target_path: Path | None = None,
) -> list[NegativeSpaceFinding]:
    """Blind spot 9: deployment mismatch detection."""
    findings: list[NegativeSpaceFinding] = []

    for gap in gaps:
        source = gap.get("source", "") or (
            read_gap_source(gap, target_path) if target_path else ""
        )
        if not source:
            continue
        file = gap.get("file", "")
        function = gap.get("name", "")

        if _HARDCODED_LOCALHOST.search(source):
            findings.append(NegativeSpaceFinding(
                check_type="deployment_assumption",
                expected="security checks not conditional on localhost/127.0.0.1",
                evidence=(
                    f"in {function}: hardcoded localhost/127.0.0.1 in security "
                    f"check — may be bypassed in containerised or proxied deployments"
                ),
                cwe="CWE-1188",
                confidence="low",
                convention="",
                strategy="pattern_scan",
                file=file,
                function=function,
                title="Hardcoded localhost in security check",
            ))

        if _GLOBAL_STATE_NO_LOCK.search(source) and not _GLOBAL_STATE_LOCK_GUARD.search(source):
            findings.append(NegativeSpaceFinding(
                check_type="deployment_assumption",
                expected="thread-safe access to global/module-level state",
                evidence=(
                    f"in {function}: global state mutation without locking — "
                    f"single-threaded assumption breaks under multi-worker deployments"
                ),
                cwe="CWE-1188",
                confidence="low",
                convention="",
                strategy="pattern_scan",
                file=file,
                function=function,
                title="Global state without thread synchronization",
            ))

        if _HARDCODED_PATHS.search(source) and _HARDCODED_PATH_SECURITY_CONTEXT.search(source):
            findings.append(NegativeSpaceFinding(
                check_type="deployment_assumption",
                expected="configurable paths for security-sensitive files",
                evidence=(
                    f"in {function}: hardcoded /tmp or /var path in "
                    f"security-sensitive context — symlink races and "
                    f"world-readable defaults in shared environments"
                ),
                cwe="CWE-1188",
                confidence="low",
                convention="",
                strategy="pattern_scan",
                file=file,
                function=function,
                title="Hardcoded temp/var path in security context",
            ))

        if _DEBUG_SKIP_SECURITY.search(source):
            findings.append(NegativeSpaceFinding(
                check_type="deployment_assumption",
                expected="no security bypass gated on DEBUG/development flags",
                evidence=(
                    f"in {function}: DEBUG/TESTING flag disables security "
                    f"checks — flag may leak to production"
                ),
                cwe="CWE-1188",
                confidence="low",
                convention="",
                strategy="pattern_scan",
                file=file,
                function=function,
                title="DEBUG flag disables security checks",
            ))

    return findings


# ── Lock ordering patterns ────────────────────────────────────────────

_LOCK_ACQUIRE = re.compile(
    r"(?:(\w+)\.acquire\s*\(|pthread_mutex_lock\s*\(\s*&?\s*(\w+)|"
    r"(\w+)\.lock\s*\(|with\s+(\w+)\s*:)",
)

_LOCK_IN_SIGNAL_HANDLER = re.compile(
    r"(?:pthread_mutex_lock|\.acquire\s*\(|\.lock\s*\()",
    re.IGNORECASE,
)

_LOCK_MISSING_UNLOCK = re.compile(
    r"(?:\.acquire\s*\(|pthread_mutex_lock\s*\(|\.lock\s*\()",
    re.IGNORECASE,
)

_UNLOCK_PATTERN = re.compile(
    r"(?:\.release\s*\(|pthread_mutex_unlock\s*\(|\.unlock\s*\()",
    re.IGNORECASE,
)

_CONTEXT_MANAGER_LOCK = re.compile(
    r"with\s+\w+",
)

_NON_REENTRANT_CALLS = frozenset({
    "strtok", "localtime", "gmtime", "asctime", "ctime",
    "getenv", "setenv", "rand", "srand",
    "readdir", "strerror", "tmpnam", "getpwnam", "gethostbyname",
})


def check_lock_ordering(
    gaps: Sequence[dict[str, Any]],
    *,
    target_path: Path | None = None,
    domain_vocab: Any = None,
) -> list[NegativeSpaceFinding]:
    """Extends blind spot 11: lock ordering and locking discipline analysis."""
    lock_acquire_re = _LOCK_ACQUIRE
    lock_missing_re = _LOCK_MISSING_UNLOCK
    unlock_re = _UNLOCK_PATTERN
    if domain_vocab and (domain_vocab.lock_acquires or domain_vocab.lock_releases):
        extra_acq_names = "|".join(
            re.escape(n) for n in domain_vocab.lock_acquires
        )
        extra_rel = "|".join(
            rf"{re.escape(n)}\s*\(" for n in domain_vocab.lock_releases
        )
        if extra_acq_names:
            lock_acquire_re = re.compile(
                _LOCK_ACQUIRE.pattern + rf"|({extra_acq_names})\s*\(",
            )
            lock_missing_re = re.compile(
                _LOCK_MISSING_UNLOCK.pattern + "|" + extra_acq_names + r"\s*\(", re.IGNORECASE,
            )
        if extra_rel:
            unlock_re = re.compile(
                _UNLOCK_PATTERN.pattern + "|" + extra_rel, re.IGNORECASE,
            )

    findings: list[NegativeSpaceFinding] = []

    for gap in gaps:
        source = gap.get("source", "") or (
            read_gap_source(gap, target_path) if target_path else ""
        )
        if not source:
            continue
        file = gap.get("file", "")
        function = gap.get("name", "")

        lock_matches = lock_acquire_re.findall(source)
        lock_names = []
        for groups in lock_matches:
            name = next((g for g in groups if g), None)
            if name:
                lock_names.append(name)

        unique_locks = list(dict.fromkeys(lock_names))
        if len(unique_locks) >= 2:
            findings.append(NegativeSpaceFinding(
                check_type="lock_ordering",
                expected="consistent lock acquisition order to prevent deadlocks",
                evidence=(
                    f"in {function}: acquires multiple locks "
                    f"({', '.join(unique_locks[:4])}) — verify ordering is "
                    f"consistent with other call sites"
                ),
                cwe="CWE-764",
                confidence="medium",
                convention="",
                strategy="pattern_scan",
                file=file,
                function=function,
                title="Multiple lock acquisitions (potential ordering violation)",
            ))

        if (re.search(r"(?:signal|sigaction)\s*\(", source)
                and _LOCK_IN_SIGNAL_HANDLER.search(source)):
            findings.append(NegativeSpaceFinding(
                    check_type="lock_ordering",
                    expected="no lock operations in signal handler context",
                    evidence=(
                        f"in {function}: lock acquisition in or near signal "
                        f"handler registration — deadlock if signal arrives "
                        f"while lock is held"
                    ),
                    cwe="CWE-667",
                    confidence="medium",
                    convention="",
                    strategy="pattern_scan",
                    file=file,
                    function=function,
                    title="Lock acquisition in signal handler context",
                ))

        if lock_missing_re.search(source) and not _CONTEXT_MANAGER_LOCK.search(source):
            has_acquire = lock_missing_re.search(source)
            has_release = unlock_re.search(source)
            has_error_path = re.search(
                r"(?:raise\s+\w+|return\s+(?:None|False|-1|err)|except\s+\w+)",
                source,
            )
            if has_acquire and not has_release and has_error_path:
                findings.append(NegativeSpaceFinding(
                    check_type="lock_ordering",
                    expected="lock released on all paths (use context manager or try/finally)",
                    evidence=(
                        f"in {function}: lock acquired but no visible release — "
                        f"error/return paths may leave lock held"
                    ),
                    cwe="CWE-667",
                    confidence="medium",
                    convention="",
                    strategy="pattern_scan",
                    file=file,
                    function=function,
                    title="Missing unlock in error path",
                ))

        if lock_missing_re.search(source):
            for call in _NON_REENTRANT_CALLS:
                if re.search(rf"\b{call}\s*\(", source):
                    findings.append(NegativeSpaceFinding(
                        check_type="lock_ordering",
                        expected="only reentrant functions called while holding locks",
                        evidence=(
                            f"in {function}: calls non-reentrant function "
                            f"{call}() while potentially holding a lock"
                        ),
                        cwe="CWE-667",
                        confidence="medium",
                        convention="",
                        strategy="pattern_scan",
                        file=file,
                        function=function,
                        title=f"Non-reentrant {call}() called under lock",
                    ))
                    break

    return findings
