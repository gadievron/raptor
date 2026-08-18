"""Detect call-site deviations via Engler-style statistical inference.

If a function's return value is captured at most call sites but discarded
at a few, the discarding sites are likely bugs — missing error checks,
ignored validation results, swallowed status codes.

Phase 1 of the consistency programme upgrades the per-site boolean
``discarded`` to a six-value **usage enum** (design
/tmp/consistency-unchecked-return-design.md §2.1):

* ``tested`` — a condition / comparison consumes the result;
* ``captured_used`` — assigned and the binding is read later;
* ``captured_unused`` — assigned then never read. Go shapes live
  here: ``_ = f()`` blank discard, and ``v, err := f()`` where ``err``
  is never consulted before rebinding/exit;
* ``discarded`` — bare expression statement;
* ``acknowledged`` — explicit-discard idioms (C/C++ ``(void)f()``,
  Rust ``let _ =``, Python ``_ =``): the author demonstrably saw the
  return, so the site refutes rather than supports a deviation;
* ``propagated`` — ``return f()`` / ``yield f()``: the caller inherits
  the obligation.

The per-callee aggregate is a first-class artifact
(:class:`CalleeCensus` → ``return-census.json``), consumed by the
``consistency`` verification channel, ``spec_inference`` (one majority
computation in the tree) and the flag/mode comparator.

Intellectual ancestor: Engler et al., "Bugs as Deviant Behavior" (2001).
"""

from __future__ import annotations

import logging
import re
from collections import OrderedDict, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from .prompt_defence import sanitise_for_prompt

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tree-sitter availability
# ---------------------------------------------------------------------------

try:
    from .condition_extraction import _get_parser
    from .ts_extract import (
        _CALL_TYPES,
        _FUNCTION_TYPES,
        _find_enclosing_function,
        _get_func_name,
        _node_line,
        _node_text,
        _walk_descendants,
    )
    _TS_AVAILABLE = True
except ImportError:
    _TS_AVAILABLE = False

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

MIN_CALL_SITES = 3
MAJORITY_THRESHOLD = 0.75

# Usage enum (§2.1). Plain strings so the census JSON stays greppable.
USAGE_TESTED = "tested"
USAGE_CAPTURED_USED = "captured_used"
USAGE_CAPTURED_UNUSED = "captured_unused"
USAGE_DISCARDED = "discarded"
USAGE_ACKNOWLEDGED = "acknowledged"
USAGE_PROPAGATED = "propagated"

ALL_USAGES = (
    USAGE_TESTED,
    USAGE_CAPTURED_USED,
    USAGE_CAPTURED_UNUSED,
    USAGE_DISCARDED,
    USAGE_ACKNOWLEDGED,
    USAGE_PROPAGATED,
)

# Deviant-eligible classes: the return demonstrably went unobserved.
DEVIANT_USAGES = frozenset({USAGE_DISCARDED, USAGE_CAPTURED_UNUSED})

# Contract-source "majority" thresholds (§2.2.5 — the exact
# spec_inference._infer_from_caller_usage floor).
MAJORITY_CONTRACT_MIN_SITES = 4
MAJORITY_CONTRACT_RATIO = 0.8

_SECURITY_CALLEE_RE = re.compile(
    r"\b(?:valid|verif|check|auth|saniti|pars|escap|encod|decod|"
    r"connect|open|clos|lock|unlock|init|clean|free|dealloc|"
    r"login|permit|sign|hash|crypt|token|certif|handshake|"
    r"resolv|bind|listen|accept|recv|send|write|read|exec|eval|"
    r"compil|load|fetch|query|prepar|marshal|unmarshal|deseriali)",
    re.IGNORECASE,
)

_STRING_OR_BLOCK_COMMENT_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"'
    r"|'(?:[^'\\]|\\.)*'"
    r"|/\*.*?\*/",
    re.DOTALL,
)


def _strip_block_comments(source: str) -> str:
    def _repl(m: re.Match) -> str:
        if m.group().startswith("/*"):
            return ""
        return m.group()
    return _STRING_OR_BLOCK_COMMENT_RE.sub(_repl, source)


_KEYWORDS = frozenset({
    "if", "else", "elif", "while", "for", "switch", "case", "catch",
    "return", "yield", "raise", "throw", "new", "delete", "sizeof",
    "typeof", "instanceof", "assert", "print", "println",
    "import", "from", "class", "struct", "enum", "interface",
    "try", "except", "finally", "with", "as", "in", "range",
    "func", "function", "def", "fn", "pub", "private", "protected",
    "var", "let", "const", "auto", "static", "extern", "volatile",
    "int", "char", "void", "bool", "float", "double", "long",
    "string", "byte", "uint", "int32", "int64", "uint32", "uint64",
    "package", "type", "go", "defer", "select",
    "not", "and", "or", "is", "None", "True", "False",
    "null", "nil", "undefined", "true", "false",
})


@dataclass
class CallSite:
    """A single call site in the codebase."""

    file: str
    line: int
    callee: str
    enclosing_function: str
    discarded: bool = False
    #: Six-value usage classification (§2.1). When constructed with the
    #: legacy boolean only, the usage is derived coarsely; when
    #: constructed with a usage, ``discarded`` is derived (True for the
    #: deviant-eligible classes) so the legacy majority statistics stay
    #: consistent with the enum.
    usage: str = ""
    #: The site sits inside an error handler / error-return branch —
    #: acting on the value there may be impossible (§2.3
    #: ``deviant-on-error-path``).
    on_error_path: bool = False
    #: Which extractor produced this row: "ts" (tree-sitter, in-file)
    #: or "cpg" (Joern, cross-file). Provenance for the mixed majority
    #: statistic, plus the deviation pass's safety rule: a deviation
    #: verdict must not rest on a usage class the extracting engine
    #: cannot produce.
    engine: str = "ts"

    def __post_init__(self) -> None:
        if not self.usage:
            self.usage = (
                USAGE_DISCARDED if self.discarded else USAGE_CAPTURED_USED
            )
        else:
            self.discarded = self.usage in DEVIANT_USAGES

    @property
    def is_deviant_eligible(self) -> bool:
        return self.usage in DEVIANT_USAGES

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "enclosing_function": self.enclosing_function,
            "usage": self.usage,
            "on_error_path": self.on_error_path,
            "engine": self.engine,
        }


@dataclass
class CallSiteDeviation:
    """A call site that deviates from the majority pattern."""

    callee: str
    file: str
    line: int
    enclosing_function: str
    total_sites: int
    captured_count: int
    discarded_count: int
    security_relevant: bool = False
    usage: str = ""

    def __post_init__(self) -> None:
        if not self.security_relevant:
            self.security_relevant = bool(_SECURITY_CALLEE_RE.search(self.callee))

    @property
    def confidence(self) -> float:
        majority = max(self.captured_count, self.discarded_count)
        return majority / self.total_sites if self.total_sites else 0.0

    def to_dict(self) -> dict:
        d = {
            "callee": self.callee,
            "file": self.file,
            "line": self.line,
            "enclosing_function": self.enclosing_function,
            "total_sites": self.total_sites,
            "captured_count": self.captured_count,
            "discarded_count": self.discarded_count,
            "confidence": round(self.confidence, 2),
            "security_relevant": self.security_relevant,
        }
        if self.usage:
            d["usage"] = self.usage
        return d


@dataclass
class CalleeCensus:
    """Per-callee return-usage aggregate — the ``return-census.json``
    row (§2.1). ``contract`` is filled by the failure-semantics binder
    (:mod:`core.audit.return_contracts`); the census itself is pure
    AST arithmetic."""

    callee: str
    sites: list[CallSite] = field(default_factory=list)
    security_relevant: bool = False
    contract: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if not self.security_relevant:
            self.security_relevant = bool(
                _SECURITY_CALLEE_RE.search(self.callee),
            )

    @property
    def n(self) -> int:
        return len(self.sites)

    def count(self, usage: str) -> int:
        return sum(1 for s in self.sites if s.usage == usage)

    @property
    def counts(self) -> dict[str, int]:
        c = dict.fromkeys(ALL_USAGES, 0)
        for s in self.sites:
            c[s.usage] = c.get(s.usage, 0) + 1
        return c

    @property
    def considered(self) -> int:
        """Sites participating in the check-majority statistic.

        ``acknowledged`` refutes rather than votes (§2.3) and
        ``propagated`` transfers the obligation (§2.1), so neither
        side of the ratio counts them.
        """
        return self.n - self.count(USAGE_ACKNOWLEDGED) - self.count(
            USAGE_PROPAGATED,
        )

    @property
    def check_ratio(self) -> float:
        considered = self.considered
        if considered <= 0:
            return 0.0
        return self.count(USAGE_TESTED) / considered

    @property
    def discard_ratio(self) -> float:
        considered = self.considered
        if considered <= 0:
            return 0.0
        deviant = sum(1 for s in self.sites if s.usage in DEVIANT_USAGES)
        return deviant / considered

    @property
    def deviants(self) -> list[CallSite]:
        return [s for s in self.sites if s.usage in DEVIANT_USAGES]

    @property
    def acknowledged_sites(self) -> list[CallSite]:
        return [s for s in self.sites if s.usage == USAGE_ACKNOWLEDGED]

    @property
    def conforming(self) -> list[CallSite]:
        """The checking exhibits (majority-leg witnesses)."""
        return [s for s in self.sites if s.usage == USAGE_TESTED]

    @property
    def majority_says_check(self) -> bool:
        """§2.2.5 majority evidence: the project's own convention."""
        return (
            self.considered >= MAJORITY_CONTRACT_MIN_SITES
            and self.check_ratio >= MAJORITY_CONTRACT_RATIO
        )

    @property
    def majority_says_discard_ok(self) -> bool:
        """Symmetric inference (§2.2.5): majority-discards ⇒
        discard-ok — printf-class noise suppressed without any
        hardcoded ignore list."""
        return (
            self.considered >= MAJORITY_CONTRACT_MIN_SITES
            and self.discard_ratio >= MAJORITY_CONTRACT_RATIO
        )

    @property
    def all_python(self) -> bool:
        return bool(self.sites) and all(
            s.file.endswith(".py") for s in self.sites
        )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "callee": self.callee,
            "sites": self.n,
            "counts": self.counts,
            "check_ratio": round(self.check_ratio, 3),
            "security_relevant": self.security_relevant,
            "deviants": [s.to_dict() for s in self.deviants],
        }
        if self.contract is not None:
            d["contract"] = self.contract
        return d


# ---------------------------------------------------------------------------
# Shared parse cache
# ---------------------------------------------------------------------------
# The census, the flag/mode comparator and the cleanup comparator all
# walk the same trees; one parse per (file, content) is kept in a small
# LRU so the prep-phase passes stop re-parsing the same sources.

_PARSE_CACHE_MAX = 256
_parse_cache: OrderedDict[tuple[str, int, int], tuple[Any, str | None]] = (
    OrderedDict()
)


def parse_source_cached(file_path: str, source: str):
    """Parse *source* with tree-sitter, returning ``(tree, lang)``.

    Returns ``(None, None)`` when tree-sitter (or the grammar for the
    file's language) is unavailable. Language detection goes strictly
    through ``core.inventory.languages`` (the dedup wave-3 rule — no
    per-module extension lists).
    """
    if not _TS_AVAILABLE:
        return None, None
    key = (file_path, len(source), hash(source))
    cached = _parse_cache.get(key)
    if cached is not None:
        _parse_cache.move_to_end(key)
        return cached
    from core.inventory.languages import detect_language
    lang = detect_language(file_path)
    parser = _get_parser(lang) if lang else None
    if not lang or not parser:
        result = (None, None)
    else:
        src_bytes = source.encode("utf-8", errors="replace")
        result = (parser.parse(src_bytes), lang)
    if len(_parse_cache) >= _PARSE_CACHE_MAX:
        _parse_cache.popitem(last=False)
    _parse_cache[key] = result
    return result


def clear_parse_cache() -> None:
    """Drop cached trees (tests / long-lived processes)."""
    _parse_cache.clear()


# ---------------------------------------------------------------------------
# Tree-sitter extraction
# ---------------------------------------------------------------------------

def _callee_name_ts(call_node, lang: str, src: bytes) -> str | None:
    """Extract the function/method name from a call node."""
    func = call_node.child_by_field_name("function")
    if func is None:
        func = call_node.child_by_field_name("name")
    if func is None:
        if call_node.children:
            func = call_node.children[0]
        else:
            return None

    if func.type in ("identifier", "name"):
        return _node_text(func, src)

    if func.type in ("member_expression", "attribute",
                      "field_expression", "selector_expression"):
        for child in reversed(func.children):
            if child.type in ("identifier", "property_identifier",
                              "field_identifier"):
                return _node_text(child, src)

    if func.type == "scoped_identifier":
        name_node = func.child_by_field_name("name")
        if name_node:
            return _node_text(name_node, src)

    text = _node_text(func, src)
    if "." in text:
        return text.rsplit(".", 1)[-1]
    return text


# Go assignment forms whose left-hand side can be the blank
# identifier.  `_ = f()` (and `_, _ = g()`) is an explicit discard of
# the return value — the classic CWE-252 shape — yet structurally it
# is an assignment, so a naive parent-walk would classify it captured.
_GO_ASSIGN_TYPES = ("assignment_statement", "short_var_declaration")

# Wrapper nodes the classification walk passes through transparently.
_TRANSPARENT_TYPES = (
    "expression_list", "parenthesized_expression", "await_expression",
    "argument", "try_expression",
)

# Capture parents: (node type → LHS field name) per shape. The name
# field of a declarator carries the binding; assignment LHS carries
# the target expression.
_ASSIGN_LHS_FIELDS = {
    "assignment_expression": "left",
    "assignment": "left",
    "assignment_statement": "left",
    "short_var_declaration": "left",
    "augmented_assignment": "left",
    "init_declarator": "declarator",
    "variable_declarator": "name",
    "let_declaration": "pattern",
}

_RETURN_TYPES = (
    "return_statement", "return_expression", "yield", "yield_expression",
    "yield_statement", "throw_statement",
)

_COMPARISON_OPS = frozenset({
    "==", "!=", "<", ">", "<=", ">=", "===", "!==", "<=>",
})

# Condition-bearing constructs: node type → the field whose subtree
# consumes the value as a truth test.
_CONDITION_FIELDS = {
    "if_statement": "condition",
    "while_statement": "condition",
    "do_statement": "condition",
    "conditional_expression": "condition",
    "ternary_expression": "condition",
    "switch_statement": "condition",
    "expression_switch_statement": "value",
    "match_statement": "subject",
    "match_expression": "value",
    "if_expression": "condition",
    "while_expression": "condition",
    "elif_clause": "condition",
    "guard_statement": "condition",
    "for_statement": "condition",
}

_ASSERT_TYPES = ("assert_statement", "assert_expression")

if _TS_AVAILABLE:
    _ALL_FUNCTION_TYPES = frozenset(
        t for types in _FUNCTION_TYPES.values() for t in types
    )
else:
    _ALL_FUNCTION_TYPES = frozenset()

# Error-handler node types per language (deviant-on-error-path).
_ERROR_HANDLER_NODE_TYPES = frozenset({
    "except_clause", "catch_clause", "catch_block", "rescue",
    "catch_formal_parameter", "finally_clause",
})


def _contains(ancestor, node) -> bool:
    return (
        ancestor.start_byte <= node.start_byte
        and node.end_byte <= ancestor.end_byte
    )


def _is_blank_discard_assignment(assign_node, src: bytes) -> bool:
    """True when every LHS identifier is the Go blank identifier ``_``.

    ``v, _ := f()`` partially captures and stays captured; only an
    all-blank LHS (``_ = f()``, ``_, _ = g()``) is a discard.
    """
    left = assign_node.child_by_field_name("left")
    if left is None or left.type != "expression_list":
        return False
    idents = [c for c in left.children if c.is_named]
    if not idents:
        return False
    return all(
        c.type == "identifier" and _node_text(c, src) == "_"
        for c in idents
    )


def _lhs_identifiers(lhs_node, src: bytes) -> list[str]:
    """Bound identifier names on an assignment/declarator LHS."""
    if lhs_node is None:
        return []
    if lhs_node.type in ("identifier", "name", "field_identifier"):
        return [_node_text(lhs_node, src)]
    names: list[str] = []
    for n in _walk_descendants(lhs_node):
        if n.type in ("identifier", "name", "field_identifier"):
            names.append(_node_text(n, src))
    return names


def _condition_consumes(parent, node) -> bool:
    """True when *parent* is a condition-bearing construct whose
    condition field contains *node* (the call feeds a truth test)."""
    field_name = _CONDITION_FIELDS.get(parent.type)
    if field_name is None:
        return parent.type in _ASSERT_TYPES
    cond = parent.child_by_field_name(field_name)
    return cond is not None and _contains(cond, node)


def _is_write_target(id_node) -> bool:
    """Is this identifier the target of an assignment / declaration
    (a write, not a read)?"""
    node = id_node
    while node.parent is not None:
        parent = node.parent
        lhs_field = _ASSIGN_LHS_FIELDS.get(parent.type)
        if lhs_field is not None:
            lhs = parent.child_by_field_name(lhs_field)
            return lhs is not None and _contains(lhs, id_node)
        if parent.type in _TRANSPARENT_TYPES or parent.type in (
                "tuple", "pattern_list", "tuple_pattern"):
            node = parent
            continue
        return False
    return False


def _classify_binding_usage(
    anchor, names: list[str], lang: str, src: bytes,
) -> str:
    """Classify a captured binding: is it later tested, read, rebound
    without a read, or never touched (§2.1 ``captured_used`` vs
    ``captured_unused`` vs ``tested``)."""
    live = {n for n in names if n and n != "_"}
    if not live:
        return USAGE_CAPTURED_UNUSED
    func = _find_enclosing_function(anchor, lang)
    scope = func if func is not None else _root_of(anchor)
    tested = False
    used = False
    rebound: set[str] = set()
    for n in _walk_descendants(scope):
        if n.start_byte < anchor.end_byte:
            continue
        if n.type not in ("identifier", "name", "field_identifier"):
            continue
        text = _node_text(n, src)
        if text not in live or text in rebound:
            continue
        if _is_write_target(n):
            # Rebinding ends the scan for this name (§2.1: a read must
            # dominate the rebinding to count).
            rebound.add(text)
            continue
        used = True
        if _read_is_tested(n):
            tested = True
            break
    if tested:
        return USAGE_TESTED
    if used:
        return USAGE_CAPTURED_USED
    return USAGE_CAPTURED_UNUSED


def _root_of(node):
    while node.parent is not None:
        node = node.parent
    return node


def _read_is_tested(id_node) -> bool:
    """Does this identifier read feed a condition / comparison?"""
    node = id_node
    while node.parent is not None:
        parent = node.parent
        if _condition_consumes(parent, id_node):
            return True
        if parent.type in ("binary_expression", "comparison_operator",
                           "binary_operator", "relational_expression",
                           "equality_expression"):
            for child in parent.children:
                if not child.is_named and child.type in _COMPARISON_OPS:
                    return True
        if parent.type in _ALL_FUNCTION_TYPES:
            return False
        node = parent
    return False


def _classify_usage_ts(call_node, lang: str, src: bytes) -> str:
    """Six-value usage classification for one call site (§2.1).

    This grew out of the phase-0 ``_is_discarded_ts`` seam; the walk
    structure is the same, each step now lands in a usage class
    instead of a boolean.
    """
    node = call_node
    while node.parent:
        parent = node.parent
        ptype = parent.type

        if ptype == "expression_statement":
            return USAGE_DISCARDED

        if ptype == "cast_expression" and lang in ("c", "cpp"):
            ty = parent.child_by_field_name("type")
            if ty is not None and _node_text(ty, src).strip() == "void":
                return USAGE_ACKNOWLEDGED
            node = parent
            continue

        if ptype in _RETURN_TYPES:
            return USAGE_PROPAGATED

        if lang == "go" and ptype in _GO_ASSIGN_TYPES:
            if _is_blank_discard_assignment(parent, src):
                # Go blank discard: assigned-then-never-readable —
                # deviant-eligible, unlike the acknowledged idioms
                # (§2.1: "Go shapes live here").
                return USAGE_CAPTURED_UNUSED
            lhs = parent.child_by_field_name("left")
            return _classify_binding_usage(
                parent, _lhs_identifiers(lhs, src), lang, src,
            )

        if lang == "python" and ptype == "assignment":
            lhs = parent.child_by_field_name("left")
            names = _lhs_identifiers(lhs, src)
            if names == ["_"]:
                return USAGE_ACKNOWLEDGED
            return _classify_binding_usage(parent, names, lang, src)

        if lang == "rust" and ptype == "let_declaration":
            pat = parent.child_by_field_name("pattern")
            if pat is not None and _node_text(pat, src).strip() == "_":
                return USAGE_ACKNOWLEDGED
            return _classify_binding_usage(
                parent, _lhs_identifiers(pat, src), lang, src,
            )

        lhs_field = _ASSIGN_LHS_FIELDS.get(ptype)
        if lhs_field is not None:
            lhs = parent.child_by_field_name(lhs_field)
            if lhs is not None and _contains(lhs, node):
                # The call computes the *target*, not the value.
                node = parent
                continue
            return _classify_binding_usage(
                parent, _lhs_identifiers(lhs, src), lang, src,
            )

        if _condition_consumes(parent, node):
            return USAGE_TESTED

        if ptype in ("binary_expression", "comparison_operator",
                     "relational_expression", "equality_expression"):
            for child in parent.children:
                if not child.is_named and child.type in _COMPARISON_OPS:
                    return USAGE_TESTED
            node = parent
            continue

        if ptype in ("unary_expression", "not_operator"):
            node = parent
            continue

        if ptype in ("argument_list", "arguments"):
            # Consumed as an argument to another call.
            return USAGE_CAPTURED_USED

        if ptype in _TRANSPARENT_TYPES:
            node = parent
            continue

        # Any other consuming context (subscript, field access, string
        # interpolation, …): the value is observed.
        return USAGE_CAPTURED_USED
    return USAGE_DISCARDED


def _is_discarded_ts(call_node, src: bytes, lang: str = "c") -> bool:
    """Phase-0 boolean seam, kept for compatibility: True when the
    usage classification lands in a deviant-eligible class."""
    return _classify_usage_ts(call_node, lang, src) in DEVIANT_USAGES


def _on_error_path_ts(call_node, lang: str, src: bytes) -> bool:
    """Is the call inside an error handler / Go `if err != nil` arm?"""
    node = call_node.parent
    while node is not None:
        if node.type in _ERROR_HANDLER_NODE_TYPES:
            return True
        if lang == "go" and node.type == "if_statement":
            cond = node.child_by_field_name("condition")
            if cond is not None:
                text = _node_text(cond, src)
                if "err" in text and "!=" in text and "nil" in text:
                    return True
        node = node.parent
    return False


def _parse_file(source: str, file_path: str):
    """Parse source with tree-sitter, return (tree, lang) or (None, None)."""
    return parse_source_cached(file_path, source)


def _extract_callsites_ts(
    file_path: str, source: str,
) -> list[CallSite] | None:
    """Extract call sites via tree-sitter. Returns None if unavailable."""
    tree, lang = _parse_file(source, file_path)
    if tree is None or lang is None:
        return None

    call_types = _CALL_TYPES.get(lang, ())
    if not call_types:
        return None

    src = source.encode("utf-8", errors="replace")
    sites: list[CallSite] = []

    for node in _walk_descendants(tree.root_node):
        if node.type not in call_types:
            continue

        callee = _callee_name_ts(node, lang, src)
        if not callee or callee in _KEYWORDS:
            continue
        if len(callee) < 2:
            continue

        enclosing = _find_enclosing_function(node, lang)
        func_name = _get_func_name(enclosing, lang, src) if enclosing else "<module>"

        sites.append(CallSite(
            file=file_path,
            line=_node_line(node),
            callee=callee,
            enclosing_function=func_name,
            usage=_classify_usage_ts(node, lang, src),
            on_error_path=_on_error_path_ts(node, lang, src),
        ))

    return sites


# ---------------------------------------------------------------------------
# Regex fallback — keeps the coarse classes (§2.1: "regex fallback
# keeps today's coarse classes"; no read-scan without a tree).
# ---------------------------------------------------------------------------

_FUNC_HEADER_RE = re.compile(
    r"\s*(?:"
    r"(?:def|func|function|fn)\s+"
    r"(?:\([^)]*\)\s+)?"
    r"(\w+)"
    r"|(?:public|private|protected|static|async|export|default)\s+"
    r".*?(\w+)\s*\("
    r")",
)

_CALL_IN_LINE_RE = re.compile(
    r"(\w+(?:\.\w+)*)\s*\(",
)

# C/C++-style function definition or prototype: type token(s), then
# the function name, then a parameter list, ending in `{` (definition),
# `;` (prototype/declaration) or nothing (K&R brace-on-next-line).
# Without this the fallback census counted every same-repo prototype
# (`int do_auth(void);` in a header) as a DISCARDED call site — a
# phantom deviant per declaration — and never tracked the enclosing
# function for C (every site attributed to ``<module>``). Keyword
# lookahead keeps control-flow lines (`if (f() != 0)`) and
# `return f();` on the call-site path.
_C_FUNC_HEADER_RE = re.compile(
    r"^\s*"
    r"(?:__attribute__\s*\(\([^()]*(?:\([^()]*\)[^()]*)*\)\)\s*)*"
    r"(?!(?:if|else|while|for|switch|do|case|goto|return|yield|"
    r"sizeof|new|delete|throw|await)\b)"
    r"(?:[A-Za-z_]\w*[ \t*&]+)+"
    r"(?:__attribute__\s*\(\([^()]*(?:\([^()]*\)[^()]*)*\)\)\s*)*"
    r"(?P<name>[A-Za-z_]\w*)\s*"
    r"\([^;{}()]*\)\s*"
    r"(?P<tail>[{;])?\s*$",
)

_ASSIGN_LINE_RE = re.compile(
    r"^\s*(?:(?:const|let|var|auto|int|char|void|bool|string|float|double|"
    r"long|unsigned|size_t|ssize_t|[\w:*&]+)\s+)?"
    r"\w+\s*(?::=|=[^=])"
)

_RETURN_LINE_RE = re.compile(r"^\s*(?:return|yield)\s+")

_COND_LINE_RE = re.compile(
    r"^\s*(?:if|while|elif|else\s+if|assert)\s*[\s(]"
)

_STMT_ONLY_LINE_RE = re.compile(
    r"^\s*(\w+(?:\.\w+)*)\s*\(",
)

# Go blank-identifier assignment: `_ = f()`, `_, _ = g()`.  An
# explicit discard, not a capture — mirrors _is_blank_discard_assignment
# on the tree-sitter path.  Anchored to an all-blank LHS so `v, _ = f()`
# still counts as captured.
_GO_BLANK_ASSIGN_RE = re.compile(
    r"^\s*_\s*(?:,\s*_\s*)*=[^=]"
)

# Acknowledged-discard idioms per language (§2.1).
_C_VOID_CAST_RE = re.compile(r"^\s*\(\s*void\s*\)")
_RUST_LET_UNDERSCORE_RE = re.compile(r"^\s*let\s+_\s*=")
_PY_UNDERSCORE_ASSIGN_RE = re.compile(r"^\s*_\s*=[^=]")


def _extract_callsites_regex(
    file_path: str, source: str,
) -> list[CallSite]:
    """Regex fallback for call site extraction."""
    sites: list[CallSite] = []
    lines = source.splitlines()
    current_func = "<module>"

    for lineno_0, line in enumerate(lines):
        lineno = lineno_0 + 1

        fm = _FUNC_HEADER_RE.match(line)
        if fm:
            current_func = fm.group(1) or fm.group(2) or current_func
            continue

        cm = _C_FUNC_HEADER_RE.match(line)
        if cm:
            if cm.group("name") not in _KEYWORDS:
                if cm.group("tail") != ";":
                    # Definition header: subsequent sites belong to it.
                    current_func = cm.group("name")
                # Either way the line itself declares — the name-plus-
                # parens here is not a call site.
                continue

        stripped = line.lstrip()
        # Determine how this line consumes return values.
        is_blank_discard = (
            file_path.endswith(".go")
            and bool(_GO_BLANK_ASSIGN_RE.match(stripped))
        )
        is_acknowledged = bool(
            _C_VOID_CAST_RE.match(stripped)
            or _RUST_LET_UNDERSCORE_RE.match(stripped)
            or (file_path.endswith(".py")
                and _PY_UNDERSCORE_ASSIGN_RE.match(stripped))
        )
        is_assign = bool(_ASSIGN_LINE_RE.match(stripped))
        is_return = bool(_RETURN_LINE_RE.match(stripped))
        is_cond = bool(_COND_LINE_RE.match(stripped))
        is_stmt_only = bool(_STMT_ONLY_LINE_RE.match(line))

        for m in _CALL_IN_LINE_RE.finditer(line):
            callee_full = m.group(1)
            callee = callee_full.rsplit(".", 1)[-1] if "." in callee_full else callee_full
            if callee in _KEYWORDS or len(callee) < 2:
                continue

            if is_blank_discard:
                usage = USAGE_CAPTURED_UNUSED
            elif is_acknowledged:
                usage = USAGE_ACKNOWLEDGED
            elif is_cond:
                usage = USAGE_TESTED
            elif is_return:
                usage = USAGE_PROPAGATED
            elif is_assign:
                usage = USAGE_CAPTURED_USED
            elif is_stmt_only:
                usage = USAGE_DISCARDED
            else:
                usage = USAGE_CAPTURED_USED

            sites.append(CallSite(
                file=file_path,
                line=lineno,
                callee=callee,
                enclosing_function=current_func,
                usage=usage,
            ))

    return sites


# ---------------------------------------------------------------------------
# Statistical analysis
# ---------------------------------------------------------------------------

def build_return_census(
    source_texts: dict[str, str],
    *,
    joern_server=None,
) -> dict[str, CalleeCensus]:
    """One parse per file → per-callee usage census (§2.1).

    The artifact behind ``return-census.json``; also the site index
    the deviation detector and the flag/mode comparator share.
    """
    all_sites: list[CallSite] = []

    for file_path, source in source_texts.items():
        ts_sites = _extract_callsites_ts(file_path, source)
        if ts_sites is not None:
            all_sites.extend(ts_sites)
        else:
            cleaned = _strip_block_comments(source) if "/*" in source else source
            all_sites.extend(_extract_callsites_regex(file_path, cleaned))

    if joern_server is not None and all_sites:
        seen_callees = frozenset({s.callee for s in all_sites})
        seen_keys = {(s.file, s.line, s.callee) for s in all_sites}
        try:
            cpg_sites = _extract_callsites_cpg(joern_server, seen_callees)
            added = 0
            for cs in cpg_sites:
                key = (cs.file, cs.line, cs.callee)
                if key not in seen_keys:
                    all_sites.append(cs)
                    seen_keys.add(key)
                    added += 1
            if added:
                logger.debug(
                    "callsite_consistency: CPG added %d cross-file sites",
                    added,
                )
        except Exception:
            logger.debug(
                "callsite_consistency: CPG enhancement failed",
                exc_info=True,
            )

    by_callee: dict[str, CalleeCensus] = {}
    grouped: dict[str, list[CallSite]] = defaultdict(list)
    for site in all_sites:
        grouped[site.callee].append(site)
    for callee, sites in sorted(grouped.items()):
        by_callee[callee] = CalleeCensus(callee=callee, sites=sites)
    return by_callee


def census_to_dict(census: dict[str, CalleeCensus]) -> dict[str, Any]:
    """Serializable form of the census (``return-census.json``)."""
    return {callee: c.to_dict() for callee, c in sorted(census.items())}


def _deviations_from_census(
    census: dict[str, CalleeCensus],
    min_sites: int = MIN_CALL_SITES,
    threshold: float = MAJORITY_THRESHOLD,
) -> list[CallSiteDeviation]:
    """Legacy lead shape from the census. Same majority arithmetic as
    the pre-enum detector: ``captured`` = every non-deviant class."""
    deviations: list[CallSiteDeviation] = []

    for callee, c in sorted(census.items()):
        if c.n < min_sites:
            continue

        captured = [s for s in c.sites if not s.discarded]
        deviant = c.deviants
        total = c.n

        if not deviant or not captured:
            continue

        captured_ratio = len(captured) / total
        discarded_ratio = len(deviant) / total

        if captured_ratio >= threshold:
            flagged = deviant
        elif discarded_ratio >= threshold:
            # Reverse direction: capture-minority among a discarding
            # majority. Kept as a (weak) lead; the census's symmetric
            # ignorability (majority_says_discard_ok) refutes the
            # majority-leg *verdict* for these callees.
            flagged = [s for s in captured if s.usage != USAGE_ACKNOWLEDGED]
        else:
            continue

        for site in flagged:
            deviations.append(CallSiteDeviation(
                callee=callee,
                file=site.file,
                line=site.line,
                enclosing_function=site.enclosing_function,
                total_sites=total,
                captured_count=len(captured),
                discarded_count=len(deviant),
                usage=site.usage,
            ))

    return deviations


def _find_deviations(
    sites: list[CallSite],
    min_sites: int = MIN_CALL_SITES,
    threshold: float = MAJORITY_THRESHOLD,
) -> list[CallSiteDeviation]:
    """Find call sites that deviate from the majority pattern."""
    grouped: dict[str, list[CallSite]] = defaultdict(list)
    for site in sites:
        grouped[site.callee].append(site)
    census = {
        callee: CalleeCensus(callee=callee, sites=cs)
        for callee, cs in grouped.items()
    }
    return _deviations_from_census(census, min_sites, threshold)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_CPG_CALLEE_CAP = 100
_CPG_BATCH_SIZE = 25


def _extract_callsites_cpg(
    joern_server,
    callee_names: frozenset[str],
) -> list[CallSite]:
    """Query Joern CPG for cross-file callsite data.

    Batches callees into groups to avoid per-callee query overhead that
    can deadlock the JVM under sustained load.  Caps at _CPG_CALLEE_CAP
    callees (prioritised by name length as a proxy for specificity).

    Usage classes are coarse on this leg (control-structure →
    ``tested``, return → ``propagated``, non-blank assignment →
    ``captured_used``, blank assignment / bare statement →
    ``discarded``): the phase-0 hole where a Go ``_ = f()`` counted as
    captured because ANY assignment ancestor did is closed by testing
    the assignment's LHS code for the all-blank shape.
    """
    from .cross_function_verify import _run_query, _safe_name

    safe_callees = []
    for callee in callee_names:
        safe = _safe_name(callee)
        if safe is not None:
            safe_callees.append((callee, safe))

    if not safe_callees:
        return []

    safe_callees.sort(key=lambda t: -len(t[0]))
    if len(safe_callees) > _CPG_CALLEE_CAP:
        logger.debug(
            "callsite_consistency: capping CPG callees %d → %d",
            len(safe_callees), _CPG_CALLEE_CAP,
        )
        safe_callees = safe_callees[:_CPG_CALLEE_CAP]

    sites: list[CallSite] = []
    for batch_start in range(0, len(safe_callees), _CPG_BATCH_SIZE):
        batch = safe_callees[batch_start:batch_start + _CPG_BATCH_SIZE]
        names_scala = ", ".join(f'"{s}"' for _, s in batch)
        name_to_orig = {s: orig for orig, s in batch}

        query = (
            f"val targets = List({names_scala})\n"
            f"cpg.call.filter(c => targets.contains(c.name)).map {{ call =>\n"
            f"  val enc = call.method.name\n"
            f"  val fname = call.file.name.headOption.getOrElse(\"\")\n"
            f"  val ln = call.lineNumber.getOrElse(0)\n"
            f"  val tested = call.inAst.isControlStructure.nonEmpty\n"
            f"  val propagated = call.inAst.isReturn.nonEmpty\n"
            f"  val assigns = "
            f"call.inAst.isCall.name(\"<operator>.assignment.*\").l\n"
            f"  val blank = assigns.nonEmpty && assigns.forall(a => "
            f"a.argument(1).code.trim.matches(\"_(\\\\s*,\\\\s*_)*\"))\n"
            f"  val captured = assigns.nonEmpty && !blank\n"
            # Consumed as an argument to a REAL call (f(g(x))): the
            # value is observed — tree-sitter's leg classifies this
            # captured_used, and without the parity this leg called
            # it discarded (deviant), flipping majority stats by
            # extraction engine. <operator>.* calls are excluded:
            # assignment/arithmetic operators are calls in the CPG,
            # and the assignment case must stay governed by the
            # blank-LHS logic above.
            f"  val asArg = call.inCall"
            f".filterNot(_.name.startsWith(\"<operator>\")).nonEmpty\n"
            f"  val usage = if (tested) \"tested\" "
            f"else if (propagated) \"propagated\" "
            f"else if (captured) \"captured_used\" "
            f"else if (asArg) \"captured_used\" "
            f"else \"discarded\"\n"
            f"  val callee = call.name\n"
            f"  (callee, enc, fname, ln, usage)\n"
            f"}}.l"
        )

        raw = _run_query(joern_server, query)
        if not raw:
            continue

        for item in raw:
            if not isinstance(item, (list, tuple)) or len(item) < 5:
                continue
            callee_name = str(item[0])
            orig = name_to_orig.get(callee_name, callee_name)
            usage = str(item[4])
            if usage not in ALL_USAGES:
                # Back-compat: an old-style boolean payload.
                usage = (
                    USAGE_DISCARDED if usage.lower() == "true"
                    else USAGE_CAPTURED_USED
                )
            sites.append(CallSite(
                file=str(item[2]),
                line=int(item[3]),
                callee=orig,
                enclosing_function=str(item[1]),
                usage=usage,
                engine="cpg",
            ))

    return sites


def detect_callsite_deviations(
    source_texts: dict[str, str],
    *,
    min_sites: int = MIN_CALL_SITES,
    threshold: float = MAJORITY_THRESHOLD,
    extra_security_names: frozenset | None = None,
    joern_server=None,
    census: dict[str, CalleeCensus] | None = None,
) -> list[CallSiteDeviation]:
    """Detect call sites that deviate from the majority return-value handling.

    *extra_security_names*: additional callee names considered
    security-relevant (e.g. from IRIS spec store).

    When *joern_server* is provided, CPG queries supplement the
    source_texts-based extraction with cross-file callsites from the
    entire indexed codebase.

    When *census* is provided (the prep phase already built it), the
    extraction pass is skipped entirely — one census per run.

    Returns deviations sorted by (security_relevant desc, confidence desc).
    """
    if census is None:
        census = build_return_census(
            source_texts, joern_server=joern_server,
        )

    deviations = _deviations_from_census(census, min_sites, threshold)
    extra = extra_security_names or frozenset()
    for d in deviations:
        if d.callee in extra:
            d.security_relevant = True
    deviations.sort(key=lambda d: (not d.security_relevant, -d.confidence, d.file, d.line))
    return deviations


def format_callsite_deviations_for_prompt(
    deviations: Sequence[CallSiteDeviation],
) -> str:
    """Format deviations for injection into the LLM review prompt."""
    if not deviations:
        return ""

    parts = ["### Return-value handling deviations\n"]
    for d in deviations:
        safe_callee = sanitise_for_prompt(d.callee, content_type="name")
        safe_file = sanitise_for_prompt(d.file, content_type="path")
        safe_enclosing = sanitise_for_prompt(d.enclosing_function, content_type="name")
        majority = "captured" if d.captured_count > d.discarded_count else "discarded"
        minority = "discarded" if majority == "captured" else "captured"
        ratio = d.captured_count if majority == "captured" else d.discarded_count
        parts.append(
            f"- `{safe_callee}()` return value {minority} at "
            f"{safe_file}:{d.line} (in `{safe_enclosing}`), "
            f"but {majority} at {ratio}/{d.total_sites} other sites"
        )
        if minority == "discarded":
            parts.append(
                f"  → CHECK: Is the return value of `{safe_callee}()` "
                f"meaningful here? If callers typically check it, this "
                f"may be a missing error/validation check."
            )
    return "\n".join(parts)
