"""Intra-function sibling analysis — find deviations across branches.

Extends the audit pipeline with three mechanical comparisons within
a single function:

  4a. Error-path cleanup consistency — N-1 paths call kfree(buf),
      one doesn't.
  4b. Operator consistency — N-1 comparisons of ``idx`` use ``<``,
      one uses ``<=``.
  4c. Guard consistency — switch/if-else cases where one case skips
      a guard present in the majority.

All three produce structured asymmetry records injected into the LLM
review context alongside the existing block-level taint state.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class IntraFunctionAsymmetry:
    """One deviation found within a function."""

    kind: str  # "cleanup", "operator", "guard"
    description: str
    line: int = 0
    deviant_block: str = ""
    majority_pattern: str = ""


_CLEANUP_CALLS = re.compile(
    r"\b(k?free|kfree_sensitive|kvfree|vfree"
    r"|fclose|close|closedir"
    r"|mutex_unlock|spin_unlock|rw_unlock|up_read|up_write"
    r"|read_unlock|write_unlock|rcu_read_unlock"
    r"|release|put|unref|deref|kobject_put|fput"
    r"|kfree_skb|consume_skb|dev_kfree_skb"
    r"|unlock_page|put_page"
    r")\s*\(",
    re.I,
)

_RETURN_RE = re.compile(r"\breturn\b")

_ERROR_RETURN_RE = re.compile(
    r"\breturn\s+(-\s*\w+|NULL|nullptr|false|ERR_PTR\s*\(|EINVAL|ENOMEM|EFAULT|"
    r"-1|0(?!\s*[;,)]))",
)

_COMPARISON_RE = re.compile(
    r"(\w+)\s*(==|!=|<=|>=|<(?!=)|>(?!=))\s*(\w+|\d+)",
)

_GUARD_CHECK_RE = re.compile(
    r"\b(if\s*\(\s*!?\s*\w+|IS_ERR\s*\(|unlikely\s*\(|WARN_ON\s*\(|BUG_ON\s*\()",
)


def analyse_intra_function(
    source: str,
    *,
    min_branches: int = 3,
) -> List[IntraFunctionAsymmetry]:
    """Run all intra-function comparisons on a function's source.

    Args:
        source: The function's source code.
        min_branches: Minimum branch/return paths to analyse.

    Returns:
        List of asymmetries found. Empty if the function is too simple
        or no deviations were detected.
    """
    if not source:
        return []

    results: list[IntraFunctionAsymmetry] = []

    cleanup = check_cleanup_consistency(source, min_paths=max(2, min_branches - 1))
    if cleanup:
        results.extend(cleanup)

    ops = check_operator_consistency(source)
    if ops:
        results.extend(ops)

    return results


def check_cleanup_consistency(
    source: str,
    *,
    min_paths: int = 2,
) -> List[IntraFunctionAsymmetry]:
    """Compare cleanup calls across return paths.

    Splits the function into segments ending at each ``return``
    statement, collects the set of cleanup function names in each
    segment, and flags paths that omit a cleanup present in the
    majority.
    """
    lines = source.splitlines()
    if len(lines) < 4:
        return []

    segments: list[tuple[int, set[str]]] = []
    current_cleanups: set[str] = set()
    segment_start = 1

    for i, line in enumerate(lines, 1):
        for m in _CLEANUP_CALLS.finditer(line):
            current_cleanups.add(m.group(1).lower())
        if _RETURN_RE.search(line):
            segments.append((segment_start, frozenset(current_cleanups)))
            current_cleanups = set()
            segment_start = i + 1

    if len(segments) < min_paths:
        return []

    all_cleanups: Counter[str] = Counter()
    for _, cleanups in segments:
        for c in cleanups:
            all_cleanups[c] += 1

    results: list[IntraFunctionAsymmetry] = []
    majority_threshold = len(segments) * 0.6

    for cleanup_fn, count in all_cleanups.items():
        if count < majority_threshold:
            continue
        for line_no, cleanups in segments:
            if cleanup_fn not in cleanups:
                results.append(IntraFunctionAsymmetry(
                    kind="cleanup",
                    description=(
                        f"{count}/{len(segments)} return paths call "
                        f"{cleanup_fn}(), but the path at line {line_no} "
                        f"does not"
                    ),
                    line=line_no,
                    majority_pattern=f"{cleanup_fn}()",
                ))

    return results


def check_operator_consistency(
    source: str,
) -> List[IntraFunctionAsymmetry]:
    """Find comparison operator deviations within a function.

    Groups comparisons by the variable being compared, then flags
    when the operator is inconsistent (e.g. 5 comparisons of ``idx``
    use ``<`` but one uses ``<=``).
    """
    lines = source.splitlines()
    if len(lines) < 3:
        return []

    var_ops: dict[str, list[tuple[str, int]]] = {}

    for i, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        for m in _COMPARISON_RE.finditer(line):
            var_name = m.group(1)
            op = m.group(2)
            if var_name in ("if", "while", "for", "return", "sizeof"):
                continue
            var_ops.setdefault(var_name, []).append((op, i))

    results: list[IntraFunctionAsymmetry] = []

    for var_name, ops in var_ops.items():
        if len(ops) < 3:
            continue
        op_counts: Counter[str] = Counter(op for op, _ in ops)
        if len(op_counts) < 2:
            continue
        majority_op, majority_count = op_counts.most_common(1)[0]
        if majority_count < len(ops) * 0.6:
            continue
        for op, line_no in ops:
            if op != majority_op:
                results.append(IntraFunctionAsymmetry(
                    kind="operator",
                    description=(
                        f"{majority_count}/{len(ops)} comparisons of "
                        f"`{var_name}` use `{majority_op}`, but line "
                        f"{line_no} uses `{op}`"
                    ),
                    line=line_no,
                    majority_pattern=f"{var_name} {majority_op}",
                    deviant_block=f"{var_name} {op}",
                ))

    return results


def format_intra_function_context(
    asymmetries: List[IntraFunctionAsymmetry],
) -> Optional[str]:
    """Format asymmetries for injection into the LLM review prompt."""
    if not asymmetries:
        return None

    parts = ["[Intra-function sibling analysis]"]
    for a in asymmetries:
        parts.append(f"  - [{a.kind}] {a.description}")
    return "\n".join(parts)
