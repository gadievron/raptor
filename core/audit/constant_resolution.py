"""Uniqueness-gated constant resolution for SMT predicate equivalence.

Wraps the extraction from ``core.inventory.macro_resolve`` with a
soundness filter: only constants with a single, unconditional, numeric
definition are resolved.  A wrong constant value in SMT silently
produces wrong guard-equivalence verdicts (the dumpability-bug class
of error), so the gate errs on the side of rejection.

Safety contract: ``ToolSource.CONSTANT_RESOLUTION`` is NOT on the
suppress allowlist.  Resolved constants feed INTO the proof chain
(help SMT prove more equivalences) — they never suppress findings.
"""

from __future__ import annotations

import ast
import logging
import operator
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path

from core.inventory.macro_resolve import (
    _C_EXTENSIONS,
    _ENUM_BLOCK_RE,
    _ENUMERATOR_NAME_RE,
    _MACRO_DEF_RE,
    _SKIP_IDENTS_C,
    _parse_enumerator_value,
)

logger = logging.getLogger(__name__)

_IF_RE = re.compile(r"^\s*#\s*(?:if|ifdef|ifndef)\b", re.MULTILINE)
_ENDIF_RE = re.compile(r"^\s*#\s*endif\b", re.MULTILINE)

_IDENT_RE = re.compile(r"[a-zA-Z_]")
_SAFE_ARITH_RE = re.compile(
    r"^[-()\s0-9a-fA-FxX+*/%|&^~<>]+$"
)

# Evaluation caps: macro bodies come from the audited (untrusted) repo,
# so the evaluator must be bounded. Legitimate C macro constants sit far
# below these limits (typical: (1<<31), 0xFFFFFFFFFFFFFFFF, byte sizes);
# a body like (1<<999999999999) would otherwise force a huge bigint.
_MAX_BODY_LEN = 512
_MAX_LITERAL_MAGNITUDE = 1 << 64
_MAX_SHIFT_BITS = 256
_MAX_RESULT_MAGNITUDE = 1 << 128

_ARITH_BINOPS: dict[type[ast.operator], object] = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.LShift: operator.lshift,
    ast.RShift: operator.rshift,
    ast.BitOr: operator.or_,
    ast.BitAnd: operator.and_,
    ast.BitXor: operator.xor,
}


@dataclass(frozen=True)
class ResolvedConstant:
    name: str
    value: int
    file: str
    line: int


@dataclass
class ConstantTable:
    unique: dict[str, ResolvedConstant] = field(default_factory=dict)
    rejected: dict[str, str] = field(default_factory=dict)

    def as_int_dict(self) -> dict[str, int]:
        return {name: rc.value for name, rc in self.unique.items()}


_CACHE_MAX = 8
_cache: OrderedDict[str, ConstantTable] = OrderedDict()


@dataclass(frozen=True)
class _RawDefinition:
    name: str
    params: str
    body: str
    file: str
    line: int
    conditional_depth: int


def _eval_arith_node(node: ast.AST) -> int | None:
    """Bounded bottom-up evaluation of an arithmetic AST node.

    Returns None for any node kind, literal magnitude, shift amount,
    or intermediate result outside the caps above.
    """
    if isinstance(node, ast.Constant):
        value = node.value
        if type(value) is int and abs(value) <= _MAX_LITERAL_MAGNITUDE:
            return value
        return None

    if isinstance(node, ast.UnaryOp):
        operand = _eval_arith_node(node.operand)
        if operand is None:
            return None
        if isinstance(node.op, ast.USub):
            return -operand
        if isinstance(node.op, ast.UAdd):
            return operand
        if isinstance(node.op, ast.Invert):
            return ~operand
        return None

    if isinstance(node, ast.BinOp):
        left = _eval_arith_node(node.left)
        if left is None:
            return None
        right = _eval_arith_node(node.right)
        if right is None:
            return None
        op_type = type(node.op)
        fn = _ARITH_BINOPS.get(op_type)
        if fn is None:
            return None
        if op_type in (ast.LShift, ast.RShift) and not (
            0 <= right <= _MAX_SHIFT_BITS
        ):
            return None
        try:
            result = fn(left, right)  # type: ignore[operator]
        except (ZeroDivisionError, ValueError, OverflowError):
            return None
        if abs(result) > _MAX_RESULT_MAGNITUDE:
            return None
        return result

    return None


def _try_evaluate(body: str) -> int | None:
    """Evaluate a constant body to an integer, or None if unsafe.

    Accepts: integer literals (decimal, hex, negative), and pure
    arithmetic on integer literals (e.g. ``4 * 1024``, ``(1 << 12)``).
    Rejects: anything containing identifiers, function calls, casts,
    or sizeof — and any body exceeding the evaluation caps (oversized
    literals, huge shift amounts, results beyond 2**128), since macro
    bodies come from the audited repo and must not be able to force
    unbounded bigint work.
    """
    cleaned = body.strip()
    if not cleaned or len(cleaned) > _MAX_BODY_LEN:
        return None

    if not _SAFE_ARITH_RE.match(cleaned):
        return None

    if '**' in cleaned:
        return None

    try:
        tree = ast.parse(cleaned, mode="eval")
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    return _eval_arith_node(tree.body)


def _scan_definitions(target_path: Path) -> dict[str, list[_RawDefinition]]:
    """Scan all C/C++ files and collect ALL definitions per name."""
    defs: dict[str, list[_RawDefinition]] = {}

    try:
        paths = sorted(
            p for p in target_path.rglob("*")
            if p.is_file() and p.suffix in _C_EXTENSIONS
        )
    except OSError:
        return defs

    for p in paths:
        try:
            text = p.read_text(errors="replace", encoding="utf-8")
        except OSError:
            continue

        text_joined = text.replace("\\\n", " ")
        cond_depth = _compute_conditional_depths(text)

        # Build a mapping from joined-text position to original line number.
        # Each "\\\n" removed shifts subsequent positions by 1 (2-char seq
        # replaced by 1-char " "). Walk the original text to record where
        # each continuation was removed.
        _cont_offsets: list[int] = []
        _search_pos = 0
        while True:
            _idx = text.find("\\\n", _search_pos)
            if _idx < 0:
                break
            _cont_offsets.append(_idx)
            _search_pos = _idx + 2

        def _original_line(joined_pos: int) -> int:
            """Map a position in text_joined to a 1-based line in text."""
            # Each continuation before joined_pos added one extra newline
            # that is absent in text_joined.
            extra = 0
            orig_pos = joined_pos
            for off in _cont_offsets:  # noqa: B023 — closure used only within this file's iteration
                # In the joined text the continuation at original offset
                # `off` becomes offset `off - extra` (each prior removal
                # shifted by 1). If joined_pos is past that point, the
                # original position is one further ahead.
                if off - extra <= joined_pos:
                    extra += 1
                    orig_pos += 1
                else:
                    break
            return text[:orig_pos].count("\n") + 1  # noqa: B023 — closure used only within this file's iteration

        rel = str(p.relative_to(target_path)) if p.is_relative_to(target_path) else str(p)

        for m in _MACRO_DEF_RE.finditer(text_joined):
            name = m.group(1)
            if name in _SKIP_IDENTS_C:
                continue
            params = m.group(2) or ""
            body = m.group(3).strip()
            if not body:
                continue
            line = _original_line(m.start())
            depth = cond_depth.get(line, 0)
            defs.setdefault(name, []).append(
                _RawDefinition(name, params, body, rel, line, depth)
            )

        for em in _ENUM_BLOCK_RE.finditer(text_joined):
            block_line = _original_line(em.start())
            block_depth = cond_depth.get(block_line, 0)
            body = em.group(1)
            for ev in _ENUMERATOR_NAME_RE.finditer(body):
                ename = ev.group(1).strip()
                evalue = _parse_enumerator_value(body, ev.end())
                if ename in _SKIP_IDENTS_C:
                    continue
                enum_line = block_line + body[:ev.start()].count("\n")
                defs.setdefault(ename, []).append(
                    _RawDefinition(ename, "", evalue, rel, enum_line, block_depth)
                )

    return defs


def _compute_conditional_depths(text: str) -> dict[int, int]:
    """Map line numbers to their #if/#ifdef nesting depth.

    Returns a dict with an entry for EVERY line (1-based): the
    conditional nesting depth at that line. Depth 0 means
    unconditional. Callers look up #define lines and enum-block
    start lines by number.
    """
    depths: dict[int, int] = {}
    depth = 0
    for i, raw_line in enumerate(text.splitlines(), 1):
        stripped = raw_line.lstrip()
        if stripped.startswith("#"):
            if _IF_RE.match(raw_line):
                depth += 1
            elif _ENDIF_RE.match(raw_line):
                depth = max(0, depth - 1)
        depths[i] = depth
    return depths


def build_unique_constants(target_path: Path) -> ConstantTable:
    """Scan target for constants, return only provably-unique ones.

    Applies rejection filters:
    1. Function-like macros (have params) — reject
    2. Multi-definition with different bodies — reject
    3. Conditional compilation (inside #if/#ifdef) — reject
    4. Non-evaluable body — reject
    """
    from core.audit.safety_contract import assert_boost_only
    assert_boost_only("constant_resolution")

    key = str(target_path)
    if key in _cache:
        _cache.move_to_end(key)
        return _cache[key]

    all_defs = _scan_definitions(target_path)
    table = ConstantTable()

    for name, definitions in all_defs.items():
        if any(d.params for d in definitions):
            table.rejected[name] = "function-like macro"
            continue

        if any(d.conditional_depth > 0 for d in definitions):
            table.rejected[name] = "conditional compilation"
            continue

        bodies = {d.body for d in definitions}
        if len(bodies) > 1:
            table.rejected[name] = "redefined with different value"
            continue

        body = next(iter(bodies))
        value = _try_evaluate(body)
        if value is None:
            table.rejected[name] = f"non-evaluable body: {body!r}"
            continue

        first = definitions[0]
        table.unique[name] = ResolvedConstant(
            name=name, value=value, file=first.file, line=first.line,
        )

    if table.unique:
        logger.info(
            "constant_resolution: %d unique, %d rejected from %s",
            len(table.unique), len(table.rejected), target_path,
        )

    if len(_cache) >= _CACHE_MAX:
        _cache.popitem(last=False)
    _cache[key] = table
    return table


def clear_cache() -> None:
    """Clear the constant table cache (for testing)."""
    _cache.clear()
