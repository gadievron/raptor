"""Guard–variable binding analysis.

Checks whether guard conditions actually reference variables that flow
to the sink (vs. "decorative" guards that check something unrelated).

From Yamaguchi et al. (IEEE S&P 2014): the UNSANITIZED traversal checks
that the sanitizer operates on the SAME symbol that flows source→sink.
A bounds check on variable X is irrelevant if the overflow is on variable Y.

Two resolution layers:
  1. Intraprocedural (this module): Extract identifiers from guard condition
     text AND from sink call arguments; if no overlap → guard is decorative.
  2. Interprocedural (via Joern CPG): Check data-dependency edges to confirm
     the guard variable is on the PDG path from source to sink.

Layer 1 is a fast approximation that catches obvious decorative guards.
Layer 2 (condition_cpg.py) handles aliases, struct fields, and indirect flow.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Set

from .condition_extraction import SinkGuard

# ---------------------------------------------------------------------------
# Identifier extraction
# ---------------------------------------------------------------------------

# Matches C/Go/Rust/Java/Python identifiers (not keywords, not type names)
_IDENT_RE = re.compile(r"\b([a-zA-Z_]\w*)\b")

# Common keywords/types to exclude from identifier extraction
_KEYWORDS: FrozenSet[str] = frozenset({
    # C/C++ keywords
    "if", "else", "while", "for", "return", "break", "continue",
    "switch", "case", "default", "goto", "do", "sizeof", "typeof",
    "struct", "enum", "union", "typedef", "static", "extern", "const",
    "volatile", "inline", "void", "int", "char", "short", "long",
    "float", "double", "unsigned", "signed", "bool", "true", "false",
    "NULL", "nullptr", "auto", "register",
    # Python keywords
    "and", "or", "not", "in", "is", "None", "True", "False",
    "def", "class", "import", "from", "as", "with", "try", "except",
    "finally", "raise", "pass", "yield", "lambda", "global", "nonlocal",
    "assert", "del", "elif", "async", "await",
    # Go keywords
    "func", "var", "type", "package", "nil", "make", "new",
    "append", "copy", "delete", "range", "defer", "panic", "recover",
    "chan", "map", "interface", "select", "go",
    # Java keywords
    "this", "super", "new", "instanceof", "throw", "throws", "catch",
    "final", "abstract", "implements", "extends", "public", "private",
    "protected", "synchronized", "transient", "native",
    # Rust keywords
    "let", "mut", "fn", "impl", "trait", "pub", "crate", "mod",
    "use", "self", "Self", "match", "ref", "move", "unsafe", "where",
    # Common type names
    "String", "string", "size_t", "ssize_t", "uint8_t", "uint16_t",
    "uint32_t", "uint64_t", "int8_t", "int16_t", "int32_t", "int64_t",
    "usize", "isize", "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64",
    # Common functions treated as operators (not variable names)
    "sizeof", "strlen", "wcslen",
})

# Struct/field access patterns
_FIELD_RE = re.compile(r"([a-zA-Z_]\w*)(?:->|\.)([a-zA-Z_]\w*)")

# Array subscript: arr[idx]
_SUBSCRIPT_RE = re.compile(r"([a-zA-Z_]\w*)\s*\[")


def extract_identifiers(text: str) -> FrozenSet[str]:
    """Extract meaningful identifiers from an expression.

    Excludes language keywords, type names, and common function names
    that don't represent data variables.
    """
    raw = set(_IDENT_RE.findall(text))
    return frozenset(raw - _KEYWORDS)


def extract_field_accesses(text: str) -> FrozenSet[str]:
    """Extract struct/object field access patterns (obj.field, ptr->field).

    Returns both the base and the full access for matching flexibility.
    """
    results: Set[str] = set()
    for base, fld in _FIELD_RE.findall(text):
        if base not in _KEYWORDS:
            results.add(base)
            results.add(f"{base}.{fld}")
    return frozenset(results)


def extract_sink_arg_identifiers(
    source: str,
    sink_line: int,
    sink_api: str,
) -> FrozenSet[str]:
    """Extract identifiers from a sink call's arguments.

    Finds the call at the given line and extracts all variable names
    used as arguments. This is a best-effort text extraction — for
    precise analysis, use the AST/CST layer.
    """
    lines = source.split("\n")
    if sink_line < 1 or sink_line > len(lines):
        return frozenset()

    # Gather lines that might be part of the call (multi-line args)
    call_text = ""
    paren_depth = 0
    started = False
    for i in range(sink_line - 1, min(sink_line + 4, len(lines))):
        line = lines[i]
        if not started:
            # Find the sink API call on this line
            idx = line.find(sink_api)
            if idx < 0:
                # Try last component with word boundary
                parts = sink_api.split(".")
                wb_match = re.search(r'\b' + re.escape(parts[-1]) + r'\b', line)
                if wb_match:
                    idx = wb_match.start()
            if idx >= 0:
                started = True
                line = line[idx:]
        if started:
            call_text += line + " "
            paren_depth += line.count("(") - line.count(")")
            if paren_depth <= 0:
                break

    if not call_text:
        return frozenset()

    # Extract the argument portion (inside parens)
    paren_start = call_text.find("(")
    if paren_start < 0:
        return frozenset()
    args_text = call_text[paren_start + 1:]
    # Strip trailing paren
    paren_end = _find_matching_paren(args_text)
    if paren_end >= 0:
        args_text = args_text[:paren_end]

    idents = extract_identifiers(args_text)
    fields = extract_field_accesses(args_text)
    return idents | fields


def _find_matching_paren(text: str) -> int:
    """Find the position of the matching close paren (depth 0)."""
    depth = 0
    for i, ch in enumerate(text):
        if ch == "(":
            depth += 1
        elif ch == ")":
            if depth == 0:
                return i
            depth -= 1
    return -1


# ---------------------------------------------------------------------------
# Binding analysis
# ---------------------------------------------------------------------------


@dataclass
class BindingResult:
    """Result of checking whether a guard binds to the sink's data flow."""

    guard_text: str
    guard_category: str
    guard_identifiers: FrozenSet[str]
    sink_identifiers: FrozenSet[str]
    bound_identifiers: FrozenSet[str]
    is_bound: bool
    confidence: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "guard_text": self.guard_text,
            "guard_category": self.guard_category,
            "guard_identifiers": sorted(self.guard_identifiers),
            "sink_identifiers": sorted(self.sink_identifiers),
            "bound_identifiers": sorted(self.bound_identifiers),
            "is_bound": self.is_bound,
            "confidence": self.confidence,
        }


@dataclass
class SinkBindingAnalysis:
    """Full binding analysis for a sink guard set."""

    sink_file: str
    sink_line: int
    sink_api: str
    sink_identifiers: FrozenSet[str]
    binding_results: List[BindingResult] = field(default_factory=list)
    has_any_bound_guard: bool = False
    all_guards_decorative: bool = False
    decorative_guard_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sink_file": self.sink_file,
            "sink_line": self.sink_line,
            "sink_api": self.sink_api,
            "sink_identifiers": sorted(self.sink_identifiers),
            "has_any_bound_guard": self.has_any_bound_guard,
            "all_guards_decorative": self.all_guards_decorative,
            "decorative_guard_count": self.decorative_guard_count,
            "binding_results": [b.to_dict() for b in self.binding_results],
        }


def check_guard_binding(
    source: str,
    sink_guard: SinkGuard,
) -> SinkBindingAnalysis:
    """Check whether each guard condition references sink argument variables.

    A guard that checks variables unrelated to the sink arguments is
    "decorative" — it exists but doesn't protect against the sink's
    specific bug class.
    """
    sink_idents = extract_sink_arg_identifiers(
        source, sink_guard.sink_line, sink_guard.sink_api,
    )

    results: List[BindingResult] = []
    any_bound = False

    for guard in sink_guard.guards:
        guard_idents = extract_identifiers(guard.text)
        guard_fields = extract_field_accesses(guard.text)
        all_guard_idents = guard_idents | guard_fields

        # Check overlap
        bound = all_guard_idents & sink_idents

        # Special cases that always count as bound:
        # - Auth guards (they protect the whole operation, not a specific arg)
        # - Config guards (they gate feature access)
        always_relevant = guard.category in ("auth", "config")

        is_bound = bool(bound) or always_relevant

        # Confidence:
        # - Direct variable match: 0.9
        # - Auth/config always-relevant: 0.7
        # - No overlap but guard has few identifiers (might be aliased): 0.4
        # - Clear no-overlap: 0.9 confidence it's decorative
        if bound:
            conf = 0.9
        elif always_relevant:
            conf = 0.7
        elif not all_guard_idents or not sink_idents:
            conf = 0.4  # can't determine
        else:
            conf = 0.85

        if is_bound:
            any_bound = True

        results.append(BindingResult(
            guard_text=guard.text,
            guard_category=guard.category,
            guard_identifiers=all_guard_idents,
            sink_identifiers=sink_idents,
            bound_identifiers=bound,
            is_bound=is_bound,
            confidence=conf,
        ))

    decorative_count = sum(1 for r in results if not r.is_bound)

    return SinkBindingAnalysis(
        sink_file=sink_guard.sink_file,
        sink_line=sink_guard.sink_line,
        sink_api=sink_guard.sink_api,
        sink_identifiers=sink_idents,
        binding_results=results,
        has_any_bound_guard=any_bound,
        all_guards_decorative=(
            len(results) > 0 and not any_bound
        ),
        decorative_guard_count=decorative_count,
    )


# ---------------------------------------------------------------------------
# Batch API
# ---------------------------------------------------------------------------


def check_all_bindings(
    source: str,
    guards: List[SinkGuard],
) -> List[SinkBindingAnalysis]:
    """Check binding for all sink guards in a file."""
    return [check_guard_binding(source, sg) for sg in guards]
