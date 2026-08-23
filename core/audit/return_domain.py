"""Return-domain mismatch witness (mechanical, no LLM in the verdict).

A caller decides a branch by comparing a callee's return value against
exactly ``-1`` (``f(...) == -1`` / ``f(...) != -1``) while the callee's
return domain provably contains another negative error value. Error
returns outside the tested sentinel then take the fall-through path —
when that path is the success path, the check fails open (CWE-390:
detection of error condition without action).

The witness is constructive: it fires only when a concrete value
``v < -1`` is PROVEN returnable from the callee's own body, via

* a direct ``return <literal-or-resolved-constant>``,
* a literal/constant assignment to the returned variable immediately
  followed by a ``goto``/``return`` that provably carries it out, or
* a proven propagation of another function's return
  (``return g(...)``, ``if ((v = g(...)) OP LIT) return v;`` or
  ``... goto L;`` with a reassignment-free label region), one bounded
  hop deep, with the guard operator filtering the propagated set.

Named constants resolve through the uniqueness-gated
:mod:`core.audit.constant_resolution` table — never a hardcoded
vocabulary. Positive extra values (``read``-style payload domains) and
callees whose domain is exactly the binary ``{0, -1}`` never fire.
Multiple definitions of the same name must EVERY one prove a wider
domain (intersection rule); unresolved or budget-truncated derivations
fail toward silence.

Peer call sites of the same callee that test ``!= 0`` / ``< 0`` are
recorded as corroboration on the witness; they are never
verdict-bearing on their own.
"""

from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence
    from tree_sitter import Node

logger = logging.getLogger(__name__)

# The witness is C-family only: the sentinel idiom under test is the
# C error-code convention. Other languages have their own fail-open
# legs (handler outcomes, discarded errors, unawaited rejections).
_C_LANGUAGES = frozenset({"c", "cpp"})

_SENTINEL = -1

# Self-limits (return-census discipline: a detector must bound its own
# work and stamp truncation rather than stall the prep phase).
_DEFAULT_BUDGET_S = 20.0
_MAX_HOPS = 2
_MAX_DEFINITIONS = 4
_MAX_SITES_PER_FILE = 200
_MAX_FINDINGS = 40
_MAX_WALK_FILES = 20000

_PRUNE_DIRS = frozenset({
    ".git", "__pycache__", "node_modules", "out", ".out",
})

_INT_SUFFIX_RE = re.compile(r"[uUlL]+$")

# Comparison operators a guard can filter a propagated value set with.
_GUARD_OPS = frozenset({"==", "!=", "<", "<=", ">", ">="})

_FLIP_EQ = {"==": "!=", "!=": "=="}


class _Budget:
    """Monotonic deadline; exhaustion flips ``truncated``."""

    def __init__(self, budget_s: float) -> None:
        self._deadline = time.monotonic() + max(0.0, budget_s)
        self.truncated = False

    def ok(self) -> bool:
        if time.monotonic() > self._deadline:
            self.truncated = True
            return False
        return True

    @property
    def remaining_s(self) -> float:
        return max(0.0, self._deadline - time.monotonic())


@dataclass
class ReturnValueProof:
    """One constructive proof that a value is returnable."""

    value: int
    file: str
    line: int
    chain: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "file": self.file,
            "line": self.line,
            "chain": self.chain,
        }


@dataclass
class ReturnDomain:
    """Provably returnable values of one callee."""

    callee: str
    proven_values: set[int] = field(default_factory=set)
    proofs: list[ReturnValueProof] = field(default_factory=list)
    definitions: list[tuple[str, int]] = field(default_factory=list)
    truncated: bool = False

    @property
    def wider_values(self) -> list[int]:
        """Proven values in the negative error family beyond -1."""
        return sorted(v for v in self.proven_values if v < _SENTINEL)

    @property
    def proven_wider(self) -> bool:
        return bool(self.wider_values) and not self.truncated

    def to_dict(self) -> dict[str, Any]:
        return {
            "callee": self.callee,
            "proven_values": sorted(self.proven_values),
            "wider_values": self.wider_values,
            "proofs": [p.to_dict() for p in self.proofs],
            "definitions": [
                {"file": f, "line": ln} for f, ln in self.definitions
            ],
            "truncated": self.truncated,
        }


@dataclass
class SentinelSite:
    """One uncaptured ``callee(...) ==/!= -1`` decision-edge site."""

    file: str
    line: int
    code: str
    callee: str
    op: str                    # "==" or "!=" after normalisation
    enclosing_function: str

    @property
    def shape(self) -> str:
        return f"{self.op} {_SENTINEL}"


@dataclass
class ReturnDomainMismatch:
    """Detector finding: sentinel comparison vs a wider proven domain."""

    file: str
    function: str
    line: int
    callee: str
    shape: str
    code: str
    domain: ReturnDomain
    peer_checks: list[str] = field(default_factory=list)

    @property
    def description(self) -> str:
        wider = ", ".join(str(v) for v in self.domain.wider_values)
        chain = "; ".join(
            p.chain for p in self.domain.proofs if p.value < _SENTINEL
        )
        peers = (
            f" (peer sites test the full error domain: "
            f"{'; '.join(self.peer_checks)})" if self.peer_checks else ""
        )
        return (
            f"{self.callee}: decision tests `{self.shape}` but the "
            f"callee provably also returns {{{wider}}} — {chain}; error "
            f"returns outside the sentinel take the fall-through path"
            f"{peers}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "function": self.function,
            "line": self.line,
            "callee": self.callee,
            "shape": self.shape,
            "code": self.code,
            "domain": self.domain.to_dict(),
            "peer_checks": list(self.peer_checks),
            "description": self.description,
        }


# ── tree-sitter plumbing (shared with the fail-open channel) ─────────


def _parser(language: str):
    from .fail_open_lang import _ts_parser
    return _ts_parser(language)


def _text(node: Node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode(
        "utf-8", errors="replace",
    )


def _line(node: Node) -> int:
    return node.start_point[0] + 1


def _language_of(file_path: str) -> str | None:
    from .fail_open_lang import language_for_path
    return language_for_path(file_path)


def _walk(node) -> Iterator[Any]:
    stack = [node]
    while stack:
        cur = stack.pop()
        yield cur
        # C++ lambdas open a new return scope; their returns are not
        # the enclosing function's returns.
        stack.extend(
            c for c in cur.children if c.type != "lambda_expression"
        )


def _unwrap(node, _src: bytes):
    """Strip parentheses, casts and comma tails around an expression."""
    while node is not None and node.type in (
            "parenthesized_expression", "cast_expression",
    ):
        inner = node.child_by_field_name("value")
        if inner is None:
            named = [c for c in node.children if c.is_named]
            inner = named[-1] if named else None
        if inner is None:
            return node
        node = inner
    return node


def _int_literal(node, src: bytes) -> int | None:
    """Integer value of a literal expression node (incl. unary minus)."""
    node = _unwrap(node, src)
    if node is None:
        return None
    if node.type == "number_literal" or (
        node.type == "unary_expression"
        and _text(node, src).lstrip().startswith("-")
        and any(c.type == "number_literal" for c in node.children)
    ):
        raw = _INT_SUFFIX_RE.sub("", _text(node, src).replace(" ", ""))
        try:
            return int(raw, 0)
        except ValueError:
            return None
    return None


def _call_callee_identifier(node: Node, src: bytes) -> str | None:
    """Callee name of a plain-identifier call (pointer/member calls
    are unresolvable without points-to analysis — excluded)."""
    if node is None or node.type != "call_expression":
        return None
    fn = node.child_by_field_name("function")
    if fn is None or fn.type != "identifier":
        return None
    return _text(fn, src)


def _declarator_name(node, src: bytes) -> str:
    for child in node.children:
        if child.type in ("function_declarator", "declarator",
                          "pointer_declarator"):
            inner = _declarator_name(child, src)
            if inner:
                return inner
        if child.type in ("identifier", "field_identifier"):
            return _text(child, src)
    return ""


def _enclosing_function(node, src: bytes) -> str:
    cur = node.parent
    while cur is not None:
        if cur.type == "function_definition":
            return _declarator_name(cur, src)
        cur = cur.parent
    return ""


# ── sentinel comparison sites ────────────────────────────────────────


def _comparison_context(call_node, src: bytes) -> tuple[str, int] | None:
    """(op, literal) when *call_node*'s value is consumed solely by a
    binary comparison against an integer literal. ``None`` when the
    result is captured or otherwise consumed."""
    cur = call_node
    parent = cur.parent
    while parent is not None and parent.type == "parenthesized_expression":
        cur, parent = parent, parent.parent
    if parent is None or parent.type != "binary_expression":
        return None
    op_node = parent.child_by_field_name("operator")
    op = op_node.type if op_node is not None else ""
    if op not in ("==", "!="):
        return None
    left = parent.child_by_field_name("left")
    right = parent.child_by_field_name("right")
    other = right if left is not None and cur in (
        left, *_parens_chain(left),
    ) else left
    lit = _int_literal(other, src) if other is not None else None
    if lit is None:
        return None
    # `!(f() == -1)` flips the effective comparison.
    outer = parent.parent
    while outer is not None:
        if outer.type == "parenthesized_expression":
            outer = outer.parent
            continue
        if outer.type == "unary_expression" and _text(
                outer, src).lstrip().startswith("!"):
            op = _FLIP_EQ[op]
            outer = outer.parent
            continue
        break
    return op, lit


def _parens_chain(node) -> list:
    chain = []
    while node is not None and node.type == "parenthesized_expression":
        named = [c for c in node.children if c.is_named]
        node = named[0] if named else None
        if node is not None:
            chain.append(node)
    return chain


def _on_if_decision_edge(comparison_node) -> bool:
    """True when the comparison (through parens/!/&&/||) is (part of)
    an ``if`` condition — the decision-edge gate."""
    cur = comparison_node.parent
    while cur is not None:
        t = cur.type
        if t == "parenthesized_expression":
            cur = cur.parent
            continue
        if t == "unary_expression":
            cur = cur.parent
            continue
        if t == "binary_expression":
            op = cur.child_by_field_name("operator")
            if op is not None and op.type in ("&&", "||"):
                cur = cur.parent
                continue
            return False
        return t == "if_statement"
    return False


def _comparison_of(call_node) -> Any:
    cur = call_node.parent
    while cur is not None and cur.type == "parenthesized_expression":
        cur = cur.parent
    return cur


def sentinel_comparison_sites(
    source: str,
    file_path: str,
    *,
    language: str = "c",
    function_span: tuple[int, int] | None = None,
    callee: str | None = None,
) -> list[SentinelSite]:
    """Uncaptured ``f(...) == -1`` / ``!= -1`` decision-edge sites.

    The uncaptured direct-comparison shape is the precision anchor: the
    result is consumed by exactly one comparison, so no second failure
    check can follow elsewhere. ``callee`` restricts the scan;
    ``function_span`` restricts it to one function's lines.
    """
    parser = _parser(language)
    if parser is None:
        return []
    src = source.encode("utf-8", errors="replace")
    try:
        tree = parser.parse(src)
    except Exception:
        logger.debug("return_domain: parse failed for %s", file_path,
                     exc_info=True)
        return []
    lines = source.splitlines()
    sites: list[SentinelSite] = []
    for node in _walk(tree.root_node):
        if node.type != "call_expression":
            continue
        name = _call_callee_identifier(node, src)
        if not name or (callee is not None and name != callee):
            continue
        line = _line(node)
        if function_span and not (
                function_span[0] <= line <= function_span[1]):
            continue
        ctx = _comparison_context(node, src)
        if ctx is None or ctx[1] != _SENTINEL:
            continue
        comparison = _comparison_of(node)
        if comparison is None or not _on_if_decision_edge(comparison):
            continue
        sites.append(SentinelSite(
            file=file_path,
            line=line,
            code=lines[line - 1].strip() if line <= len(lines) else "",
            callee=name,
            op=ctx[0],
            enclosing_function=_enclosing_function(node, src),
        ))
        if len(sites) >= _MAX_SITES_PER_FILE:
            break
    return sites


# ── callee definition search ─────────────────────────────────────────


def _c_family_files(root: Path, budget: _Budget) -> Iterator[Path]:
    from core.inventory.languages import LANGUAGE_MAP
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _PRUNE_DIRS]
        if not budget.ok():
            return
        for fname in filenames:
            lang = LANGUAGE_MAP.get(Path(fname).suffix.lower())
            if lang not in _C_LANGUAGES:
                continue
            seen += 1
            if seen > _MAX_WALK_FILES:
                budget.truncated = True
                return
            yield Path(dirpath) / fname


def _find_definitions(
    callee: str,
    roots: Sequence[Path],
    budget: _Budget,
) -> list[tuple[Path, str, bytes, Any, Any]]:
    """Locate function definitions of *callee* across *roots*.

    Returns up to ``_MAX_DEFINITIONS`` tuples of
    (root, relative file, source bytes, tree, definition node). The
    first root that yields any definition wins (audited tree before
    any wider source root), so an in-tree definition is never shadowed
    by an out-of-tree copy.
    """
    prefilter = re.compile(
        rb"\b" + re.escape(callee).encode() + rb"\s*\(",
    )
    results: list[tuple[Path, str, bytes, Any, Any]] = []
    for root in roots:
        if not root or not Path(root).is_dir():
            continue
        root = Path(root)
        for path in _c_family_files(root, budget):
            if not budget.ok() or len(results) >= _MAX_DEFINITIONS:
                break
            try:
                raw = path.read_bytes()
            except OSError:
                continue
            if not prefilter.search(raw):
                continue
            lang = _language_of(str(path)) or "c"
            parser = _parser(lang)
            if parser is None:
                continue
            try:
                tree = parser.parse(raw)
            except Exception:
                continue
            for node in _walk(tree.root_node):
                if node.type != "function_definition":
                    continue
                if _declarator_name(node, raw) == callee:
                    rel = str(path.relative_to(root))
                    results.append((root, rel, raw, tree, node))
                    break
        if results:
            return results
    return results


# ── domain derivation ────────────────────────────────────────────────


_GUARD_COND_RE = re.compile(r"^\s*#\s*(?:if|ifdef|ifndef)\b")
_GUARD_IFNDEF_RE = re.compile(r"^\s*#\s*ifndef\s+([A-Za-z_][A-Za-z0-9_]*)\s*$")
_GUARD_ENDIF_RE = re.compile(r"^\s*#\s*endif\b")


def _strip_include_guard(text: str) -> str:
    """Blank out a classic include guard so its body reads as
    unconditional.

    The uniqueness-gated constant table treats any ``#if``-nested
    definition as conditional — correct for real variants, but an
    include guard wraps EVERY header definition, which would reject
    the entire error-code vocabulary of a project. A guard is
    recognised only in the airtight shape: the file's first
    conditional is ``#ifndef X`` immediately followed by
    ``#define X`` (bare), and its matching ``#endif`` closes the file.
    """
    lines = text.splitlines()
    first = None
    for i, ln in enumerate(lines):
        if _GUARD_COND_RE.match(ln):
            first = i
            break
    if first is None:
        return text
    m = _GUARD_IFNDEF_RE.match(lines[first])
    if m is None or first + 1 >= len(lines):
        return text
    guard_def = re.compile(
        rf"^\s*#\s*define\s+{re.escape(m.group(1))}\s*$",
    )
    if not guard_def.match(lines[first + 1]):
        return text
    depth = 0
    closing = None
    for k in range(first, len(lines)):
        if _GUARD_COND_RE.match(lines[k]):
            depth += 1
        elif _GUARD_ENDIF_RE.match(lines[k]):
            depth -= 1
            if depth == 0:
                closing = k
                break
    if closing is None:
        return text
    for tail in lines[closing + 1:]:
        s = tail.strip()
        if s and not s.startswith(("/*", "*", "//")):
            return text
    lines[first] = ""
    lines[first + 1] = ""
    lines[closing] = ""
    return "\n".join(lines)


_CONSTANTS_CACHE: dict[str, dict[str, int]] = {}


def _constants_for_root(root: Path) -> dict[str, int]:
    """Uniqueness-gated integer constants under *root*, include-guard
    aware.

    Mirrors :func:`core.audit.constant_resolution.build_unique_constants`
    (single evaluable definition tree-wide, no conditional nesting) but
    normalises classic include guards first — a header's error-code
    family must not read as conditional merely because the header
    guards itself. Local to this witness; the SMT-facing table keeps
    its stricter reading.
    """
    cache_key = str(root)
    if cache_key in _CONSTANTS_CACHE:
        return _CONSTANTS_CACHE[cache_key]
    try:
        from core.inventory.macro_resolve import (
            _ENUM_BLOCK_RE,
            _ENUMERATOR_NAME_RE,
            _MACRO_DEF_RE,
            _SKIP_IDENTS_C,
            _parse_enumerator_value,
        )

        from .constant_resolution import (
            _compute_conditional_depths,
            _try_evaluate,
        )
    except ImportError:
        _CONSTANTS_CACHE[cache_key] = {}
        return {}
    defs: dict[str, list[int]] = {}
    budget = _Budget(_DEFAULT_BUDGET_S)
    for path in _c_family_files(Path(root), budget):
        if not budget.ok():
            break
        try:
            text = path.read_text(errors="replace", encoding="utf-8")
        except OSError:
            continue
        text = _strip_include_guard(text)
        depths = _compute_conditional_depths(text)
        for m in _MACRO_DEF_RE.finditer(text):
            name = m.group(1)
            if name in _SKIP_IDENTS_C or m.group(2):
                continue
            line = text[:m.start()].count("\n") + 1
            if depths.get(line, 0) != 0:
                continue
            value = _try_evaluate(m.group(3).strip())
            if value is not None:
                defs.setdefault(name, []).append(value)
        for em in _ENUM_BLOCK_RE.finditer(text):
            line = text[:em.start()].count("\n") + 1
            if depths.get(line, 0) != 0:
                continue
            body = em.group(1)
            for ev in _ENUMERATOR_NAME_RE.finditer(body):
                name = ev.group(1).strip()
                if name in _SKIP_IDENTS_C:
                    continue
                raw_value = _parse_enumerator_value(body, ev.end())
                if not raw_value:
                    continue
                value = _try_evaluate(raw_value)
                if value is not None:
                    defs.setdefault(name, []).append(value)
    table = {
        name: vals[0] for name, vals in defs.items() if len(vals) == 1
    }
    _CONSTANTS_CACHE[cache_key] = table
    return table


def _guard_filter(values: set[int], op: str, literal: int) -> set[int]:
    """Values of a propagated set that satisfy ``value OP literal``."""
    ops = {
        "==": lambda v: v == literal,
        "!=": lambda v: v != literal,
        "<": lambda v: v < literal,
        "<=": lambda v: v <= literal,
        ">": lambda v: v > literal,
        ">=": lambda v: v >= literal,
    }
    fn = ops.get(op)
    if fn is None:
        return set()
    return {v for v in values if fn(v)}


def _statement_of(node) -> Any:
    """Nearest enclosing statement node."""
    cur = node
    while cur is not None and not cur.type.endswith("statement"):
        cur = cur.parent
    return cur


def _next_named_sibling(node: Node) -> Any:
    sib = node.next_named_sibling if node is not None else None
    while sib is not None and sib.type == "comment":
        sib = sib.next_named_sibling
    return sib


def _returns_identifier(stmt, src: bytes, var: str) -> bool:
    if stmt is None or stmt.type != "return_statement":
        return False
    expr = next((c for c in stmt.children if c.is_named), None)
    expr = _unwrap(expr, src) if expr is not None else None
    return (expr is not None and expr.type == "identifier"
            and _text(expr, src) == var)


def _assigns_var(node, src: bytes, var: str) -> bool:
    for sub in _walk(node):
        if sub.type == "assignment_expression":
            left = sub.child_by_field_name("left")
            if left is not None and left.type == "identifier" \
                    and _text(left, src) == var:
                return True
        elif sub.type == "init_declarator":
            decl = sub.child_by_field_name("declarator")
            if decl is not None and decl.type == "identifier" \
                    and _text(decl, src) == var:
                return True
    return False


def _assignment_nodes_to(node, src: bytes, var: str) -> list:
    hits = []
    for sub in _walk(node):
        if sub.type == "assignment_expression":
            left = sub.child_by_field_name("left")
            if left is not None and left.type == "identifier" \
                    and _text(left, src) == var:
                hits.append(sub)
        elif sub.type == "init_declarator":
            decl = sub.child_by_field_name("declarator")
            if decl is not None and decl.type == "identifier" \
                    and _text(decl, src) == var:
                hits.append(sub)
    return hits


def _excludes_wider(op: str, lit: int) -> bool:
    """True when ``v OP lit`` is false for every ``v < -1`` — the
    comparison shapes that cannot be satisfied by a negative error
    value beyond the sentinel."""
    if op == "==":
        return lit >= _SENTINEL
    if op == ">=":
        return lit >= _SENTINEL
    if op == ">":
        return lit >= _SENTINEL - 1
    return False


def _and_conjuncts(node, src: bytes) -> list:
    """Top-level ``&&`` conjuncts of a condition expression (an ``||``
    anywhere at the top level yields no conjuncts — a disjunct does
    not dominate the branch)."""
    node = _unwrap(node, src)
    if node is None:
        return []
    if node.type == "binary_expression":
        op = node.child_by_field_name("operator")
        if op is not None and op.type == "&&":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            return (_and_conjuncts(left, src)
                    + _and_conjuncts(right, src))
        if op is not None and op.type == "||":
            return []
    return [node]


def _shielded_assignment(assign, boundary, src: bytes, var: str) -> bool:
    """True when *assign* (an assignment to *var* nested below
    *boundary*) is dominated by an ``if`` whose condition provably
    excludes every wider value of *var* — such a reassignment cannot
    alter a propagated negative error return."""
    cur = assign.parent
    # NOTE: py-tree-sitter hands out fresh Node wrappers on every
    # child/parent access — compare nodes with ``==`` (id-based),
    # never ``is``.
    while cur is not None and cur != boundary:
        if cur.type == "if_statement":
            consequence = cur.child_by_field_name("consequence")
            in_consequence = False
            probe = assign
            while probe is not None and probe != cur:
                if probe == consequence:
                    in_consequence = True
                    break
                probe = probe.parent
            if in_consequence:
                cond = cur.child_by_field_name("condition")
                for conj in _and_conjuncts(cond, src) if cond else []:
                    if conj.type != "binary_expression":
                        continue
                    op_node = conj.child_by_field_name("operator")
                    left = conj.child_by_field_name("left")
                    right = conj.child_by_field_name("right")
                    if op_node is None or left is None or right is None:
                        continue
                    op = op_node.type
                    lhs = _unwrap(left, src)
                    lit = _int_literal(right, src)
                    if lit is None:
                        lhs = _unwrap(right, src)
                        lit = _int_literal(left, src)
                        flip = {"<": ">", ">": "<",
                                "<=": ">=", ">=": "<="}
                        op = flip.get(op, op)
                    if (lit is not None and lhs is not None
                            and lhs.type == "identifier"
                            and _text(lhs, src) == var
                            and _excludes_wider(op, lit)):
                        return True
        cur = cur.parent
    return False


def _region_statement_kills(stmt, src: bytes, var: str) -> bool:
    """True when a region statement carries an assignment to *var*
    that could alter a propagated wider value (unshielded)."""
    return any(
        not _shielded_assignment(a, stmt.parent, src, var)
        for a in _assignment_nodes_to(stmt, src, var)
    )


def _label_region_returns(
    def_node, src: bytes, label: str, var: str,
) -> Any:
    """The ``return var`` statement a ``goto label`` provably reaches
    with *var*'s wider values intact, else ``None``.

    The scan covers the labeled statement and its following siblings.
    An assignment to *var* in the region fails the proof unless it is
    shielded — dominated by an ``if`` condition that provably excludes
    every value ``< -1`` (e.g. a ``var == 0`` conjunct), in which case
    it cannot alter a propagated negative error return.
    """
    target = None
    for node in _walk(def_node):
        if node.type != "labeled_statement":
            continue
        lab = node.child_by_field_name("label")
        if lab is not None and _text(lab, src) == label:
            target = node
            break
    if target is None:
        return None
    inner = next(
        (c for c in target.children
         if c.is_named and c.type != "statement_identifier"),
        None,
    )
    cursor = inner
    hop_guard = 0
    while cursor is not None and hop_guard < 200:
        hop_guard += 1
        if _returns_identifier(cursor, src, var):
            return cursor
        if _region_statement_kills(cursor, src, var):
            return None
        if cursor.type == "goto_statement":
            return None
        if cursor == inner:
            cursor = _next_named_sibling(target)
        else:
            cursor = _next_named_sibling(cursor)
    return None


def _jump_carries_out(
    assign_stmt, def_node, src: bytes, var: str,
) -> Any:
    """The ``return var`` a jump adjacent to *assign_stmt* provably
    reaches, for the ``var = X; goto L;`` / ``var = X; return var;``
    shapes."""
    nxt = _next_named_sibling(assign_stmt)
    if nxt is None:
        return None
    if _returns_identifier(nxt, src, var):
        return nxt
    if nxt.type == "goto_statement":
        lab = nxt.child_by_field_name("label")
        if lab is not None:
            return _label_region_returns(
                def_node, src, _text(lab, src), var,
            )
    return None


def _guarded_jump_of_condition_assign(assign_node, src: bytes, var: str):
    """For ``if ((var = g(...)) OP LIT) <jump>``: ((op, lit), jump_stmt).

    The assignment must sit inside the ``if`` condition; the jump is
    the consequent's ``return var`` / ``goto``. A bare truth test
    (``if ((var = g(...))) ...``) filters with ``!= 0``.
    """
    cur = assign_node.parent
    op, lit = "!=", 0
    while cur is not None and cur.type == "parenthesized_expression":
        cur = cur.parent
    if cur is not None and cur.type == "binary_expression":
        op_node = cur.child_by_field_name("operator")
        op = op_node.type if op_node is not None else ""
        if op not in _GUARD_OPS:
            return None
        left = cur.child_by_field_name("left")
        right = cur.child_by_field_name("right")
        lit_val = _int_literal(right, src)
        if lit_val is None:
            lit_val = _int_literal(left, src)
            flip = {"<": ">", ">": "<", "<=": ">=", ">=": "<="}
            op = flip.get(op, op)
        if lit_val is None:
            return None
        lit = lit_val
        cur = cur.parent
        while cur is not None and cur.type == "parenthesized_expression":
            cur = cur.parent
    if cur is None or cur.type != "if_statement":
        return None
    consequent = cur.child_by_field_name("consequence")
    if consequent is None:
        return None
    stmt = consequent
    if stmt.type == "compound_statement":
        named = [c for c in stmt.children if c.is_named]
        if len(named) != 1:
            return None
        stmt = named[0]
    return (op, lit), stmt


_DOMAIN_CACHE: dict[tuple[str, tuple[str, ...]], ReturnDomain | None] = {}


def clear_cache() -> None:
    _DOMAIN_CACHE.clear()
    _CONSTANTS_CACHE.clear()


def derive_return_domain(
    callee: str,
    roots: Sequence[Path],
    *,
    budget_s: float = _DEFAULT_BUDGET_S,
) -> ReturnDomain | None:
    """Derive the provable return-value domain of *callee*.

    ``None`` when no definition is found under *roots*. With multiple
    definitions of the same name, the returned domain is
    ``proven_wider`` only when EVERY definition independently proves a
    value ``< -1`` (a linked-copy ambiguity must not manufacture a
    witness).
    """
    key = (callee, tuple(str(r) for r in roots))
    if key in _DOMAIN_CACHE:
        return _DOMAIN_CACHE[key]
    budget = _Budget(budget_s)
    result = _derive(callee, roots, budget, _MAX_HOPS, set())
    if not budget.truncated:
        # A truncated derivation must not poison the cache — a later
        # caller with a fresh budget deserves the full analysis.
        _DOMAIN_CACHE[key] = result
    return result


def _derive(
    callee: str,
    roots: Sequence[Path],
    budget: _Budget,
    hops: int,
    visited: set[str],
) -> ReturnDomain | None:
    if callee in visited:
        return None
    visited = visited | {callee}
    defs = _find_definitions(callee, roots, budget)
    if not defs:
        return None
    domain = ReturnDomain(callee=callee, truncated=budget.truncated)
    per_def_wider: list[bool] = []
    for root, rel, raw, _tree, def_node in defs:
        values, proofs = _analyze_definition(
            callee, root, rel, raw, def_node, roots, budget, hops,
            visited,
        )
        domain.proven_values |= values
        domain.proofs.extend(proofs)
        domain.definitions.append((rel, _line(def_node)))
        per_def_wider.append(any(v < _SENTINEL for v in values))
    domain.truncated = domain.truncated or budget.truncated
    if not all(per_def_wider):
        # Intersection rule: strip the wider claim when any definition
        # of this name fails to prove one — keep the union of values
        # for diagnostics but never let a linked-copy ambiguity fire.
        domain.proven_values = {
            v for v in domain.proven_values if v >= _SENTINEL
        }
        domain.proofs = [
            p for p in domain.proofs if p.value >= _SENTINEL
        ]
    return domain


def _analyze_definition(
    callee: str,
    root: Path,
    rel: str,
    raw: bytes,
    def_node,
    roots: Sequence[Path],
    budget: _Budget,
    hops: int,
    visited: set[str],
) -> tuple[set[int], list[ReturnValueProof]]:
    consts = _constants_for_root(root)
    values: set[int] = set()
    proofs: list[ReturnValueProof] = []

    def _prove(value: int, line: int, chain: str) -> None:
        if value not in values:
            values.add(value)
            proofs.append(ReturnValueProof(
                value=value, file=rel, line=line, chain=chain,
            ))

    returned_vars: set[str] = set()
    for node in _walk(def_node):
        if not budget.ok():
            return values, proofs
        if node.type != "return_statement":
            continue
        expr = next((c for c in node.children if c.is_named), None)
        if expr is None:
            continue
        expr = _unwrap(expr, raw)
        line = _line(node)
        lit = _int_literal(expr, raw)
        if lit is not None:
            _prove(lit, line, f"{rel}:{line} returns {lit}")
            continue
        if expr.type == "identifier":
            name = _text(expr, raw)
            if _assigns_var(def_node, raw, name):
                returned_vars.add(name)
            elif name in consts:
                _prove(
                    consts[name], line,
                    f"{rel}:{line} returns {name} (= {consts[name]})",
                )
            continue
        if expr.type == "call_expression" and hops > 0:
            g = _call_callee_identifier(expr, raw)
            if g:
                sub = _derive(g, roots, budget, hops - 1, visited)
                if sub is not None:
                    for v in sub.proven_values:
                        _prove(
                            v, line,
                            f"{rel}:{line} returns {g}(...) which "
                            f"provably returns {v}",
                        )

    for var in returned_vars:
        _analyze_returned_var(
            var, callee, rel, raw, def_node, consts, roots, budget,
            hops, visited, _prove,
        )
    return values, proofs


def _analyze_returned_var(
    var: str,
    _callee: str,
    rel: str,
    raw: bytes,
    def_node,
    consts: dict[str, int],
    roots: Sequence[Path],
    budget: _Budget,
    hops: int,
    visited: set[str],
    _prove,
) -> None:
    for node in _walk(def_node):
        if not budget.ok():
            return
        if node.type != "assignment_expression":
            continue
        left = node.child_by_field_name("left")
        if left is None or left.type != "identifier" \
                or _text(left, raw) != var:
            continue
        op_node = node.child_by_field_name("operator")
        if op_node is not None and op_node.type != "=":
            continue
        rhs = _unwrap(node.child_by_field_name("right"), raw)
        if rhs is None:
            continue
        line = _line(node)

        lit = _int_literal(rhs, raw)
        const_val = (
            consts.get(_text(rhs, raw))
            if lit is None and rhs.type == "identifier" else None
        )
        if lit is not None or const_val is not None:
            value = lit if lit is not None else const_val
            stmt = _statement_of(node)
            carried = (
                _jump_carries_out(stmt, def_node, raw, var)
                if stmt is not None else None
            )
            if carried is not None:
                what = (_text(rhs, raw) + f" (= {value})"
                        if const_val is not None else str(value))
                _prove(
                    value, line,
                    f"{rel}:{line} sets the returned variable to "
                    f"{what} and jumps to a return that carries it "
                    f"out unmodified",
                )
            continue

        if rhs.type == "call_expression" and hops > 0:
            g = _call_callee_identifier(rhs, raw)
            if not g:
                continue
            guarded = _guarded_jump_of_condition_assign(node, raw, var)
            if guarded is None:
                continue
            (g_op, g_lit), jump_stmt = guarded
            reach = None
            if _returns_identifier(jump_stmt, raw, var):
                reach = jump_stmt
            elif jump_stmt.type == "goto_statement":
                lab = jump_stmt.child_by_field_name("label")
                if lab is not None:
                    reach = _label_region_returns(
                        def_node, raw, _text(lab, raw), var,
                    )
            if reach is None:
                continue
            sub = _derive(g, roots, budget, hops - 1, visited)
            if sub is None:
                continue
            for v in _guard_filter(sub.proven_values, g_op, g_lit):
                _prove(
                    v, line,
                    f"{rel}:{line} captures {g}(...) (provably "
                    f"returns {v}), the `{g_op} {g_lit}` guard jumps "
                    f"to a return that carries it out unmodified",
                )


# ── peer-caller corroboration (never verdict-bearing) ────────────────


def _peer_checks(
    source_texts: dict[str, str],
    callee: str,
    exclude: tuple[str, int],
) -> list[str]:
    """Peer sites of *callee* whose comparison tests the whole error
    domain (``!= 0`` / ``< 0`` / ``>= 0``-style) — recorded as
    corroboration on the witness."""
    peers: list[str] = []
    pattern = re.compile(
        rf"\b{re.escape(callee)}\s*\([^;{{}}]*?\)\s*"
        rf"(!=\s*0|<\s*0|>=\s*0)\b",
    )
    for fp, source in source_texts.items():
        lang = _language_of(fp)
        if lang not in _C_LANGUAGES:
            continue
        for idx, line_text in enumerate(source.splitlines(), 1):
            if (fp, idx) == exclude:
                continue
            m = pattern.search(line_text)
            if m:
                peers.append(f"{fp}:{idx} tests `{m.group(1)}`")
            if len(peers) >= 5:
                return peers
    return peers


# ── detector entry point ─────────────────────────────────────────────


def detect_return_domain_mismatches(
    source_texts: dict[str, str],
    *,
    roots: Sequence[Path],
    budget_s: float = _DEFAULT_BUDGET_S,
) -> list[ReturnDomainMismatch]:
    """Sweep *source_texts* for sentinel-vs-domain mismatches.

    *roots* are the definition-search trees in priority order (the
    audited tree first, then any wider source root the run knows
    about). All adjudication is constructive; a callee without an
    in-tree definition, an unproven domain, or a budget truncation
    yields nothing.
    """
    budget = _Budget(budget_s)
    findings: list[ReturnDomainMismatch] = []
    for fp, source in source_texts.items():
        if not budget.ok() or len(findings) >= _MAX_FINDINGS:
            break
        lang = _language_of(fp)
        if lang not in _C_LANGUAGES:
            continue
        try:
            sites = sentinel_comparison_sites(source, fp, language=lang)
        except Exception:
            logger.debug(
                "return_domain: site scan failed for %s", fp,
                exc_info=True,
            )
            continue
        for site in sites:
            if not budget.ok() or len(findings) >= _MAX_FINDINGS:
                break
            try:
                domain = derive_return_domain(
                    site.callee, roots, budget_s=budget.remaining_s,
                )
            except Exception:
                logger.debug(
                    "return_domain: derivation failed for %s",
                    site.callee, exc_info=True,
                )
                continue
            if domain is None or not domain.proven_wider:
                continue
            findings.append(ReturnDomainMismatch(
                file=site.file,
                function=site.enclosing_function,
                line=site.line,
                callee=site.callee,
                shape=site.shape,
                code=site.code,
                domain=domain,
                peer_checks=_peer_checks(
                    source_texts, site.callee, (site.file, site.line),
                ),
            ))
    if budget.truncated:
        logger.info(
            "return_domain: budget exhausted — sweep truncated "
            "(%d finding(s) kept)", len(findings),
        )
    return findings
