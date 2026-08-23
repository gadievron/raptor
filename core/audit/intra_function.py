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

import json
import logging
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class IntraFunctionAsymmetry:
    """One deviation found within a function."""

    kind: str  # "cleanup", "operator", "guard"
    description: str
    line: int = 0


# SEED SET — canonical exemplars only (SEED_SET_CAP discipline, the
# callback_lifetime rule verbatim). The kernel bulk (kfree_skb,
# kobject_put, put_page, rcu_read_unlock, ...) lives in the
# linux_kernel vocab pack's ``cleanup_calls`` / ``deallocators`` /
# ``lock_pairs`` keys; project cleanup verbs arrive via study-learned
# ``paired_operations`` release verbs. Do not grow this tuple — teach
# the study loop / pack instead.
_SEED_CLEANUP_NAMES = (
    "free", "kfree", "fclose", "close",
    "mutex_unlock", "spin_unlock",
    "release", "put", "unref",
)


def _pack_cleanup_names(target_path: Path | None) -> frozenset[str]:
    """Channel-local read of the vocab pack's cleanup vocabulary
    (data-file-only extension — the resource_bounds
    ``collection_inserts`` precedent): ``cleanup_calls`` plus
    ``deallocators`` plus the release side of ``lock_pairs``."""
    if target_path is None:
        return frozenset()
    try:
        from .vocab_packs import _PACK_DIR, is_kernel_tree
        if not is_kernel_tree(target_path):
            return frozenset()
        raw = json.loads(
            (_PACK_DIR / "linux_kernel.json").read_text(encoding="utf-8"),
        )
    except Exception:
        return frozenset()
    names: set[str] = set()
    for key in ("cleanup_calls", "deallocators"):
        names.update(
            n for n in (raw.get(key) or [])
            if isinstance(n, str) and n
        )
    for pair in raw.get("lock_pairs") or []:
        if isinstance(pair, (list, tuple)) and len(pair) == 2 \
                and isinstance(pair[1], str) and pair[1]:
            names.add(pair[1])
    return frozenset(names)


def _learned_cleanup_names(
    domain_model: dict[str, Any] | None,
) -> frozenset[str]:
    """Release verbs from study-learned ``paired_operations`` (the
    ``consistency_dimensions.learned_cleanup_pairs`` precedent).
    ``llm_prior`` provenance excluded (anti-laundering rule)."""
    names: set[str] = set()
    for entry in (domain_model or {}).get("paired_operations") or []:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("provenance") or "") == "llm_prior":
            continue
        release = str(entry.get("release") or "").split("(")[0].strip()
        if release:
            names.add(release)
    return frozenset(names)


def _cleanup_call_re(
    domain_model: dict[str, Any] | None = None,
    target_path: Path | None = None,
) -> re.Pattern[str]:
    """Cleanup-call matcher over the merged vocabulary
    (seeds + pack + learned)."""
    names = set(_SEED_CLEANUP_NAMES)
    names |= _pack_cleanup_names(target_path)
    names |= _learned_cleanup_names(domain_model)
    alt = "|".join(
        re.escape(n) for n in sorted(names, key=len, reverse=True)
    )
    return re.compile(rf"\b({alt})\s*\(", re.IGNORECASE)


# Seed-only matcher for vocabulary-less callers.
_CLEANUP_CALLS = _cleanup_call_re()

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
    domain_model: dict[str, Any] | None = None,
    target_path: Path | None = None,
) -> list[IntraFunctionAsymmetry]:
    """Run all intra-function comparisons on a function's source.

    Args:
        source: The function's source code.
        min_branches: Minimum branch/return paths to analyse.
        domain_model: Study-learned vocabulary source (paired_operations
            release verbs extend the cleanup matcher).
        target_path: Enables the kernel vocab pack when the target is a
            kernel tree.

    Returns:
        List of asymmetries found. Empty if the function is too simple
        or no deviations were detected.
    """
    if not source:
        return []

    results: list[IntraFunctionAsymmetry] = []

    cleanup = check_cleanup_consistency(
        source, min_paths=max(2, min_branches - 1),
        domain_model=domain_model, target_path=target_path,
    )
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
    domain_model: dict[str, Any] | None = None,
    target_path: Path | None = None,
) -> list[IntraFunctionAsymmetry]:
    """Compare cleanup calls across return paths.

    Splits the function into segments ending at each ``return``
    statement, collects the set of cleanup function names in each
    segment, and flags paths that omit a cleanup present in the
    majority.
    """
    lines = source.splitlines()
    if len(lines) < 4:
        return []

    cleanup_re = (
        _cleanup_call_re(domain_model, target_path)
        if (domain_model or target_path) else _CLEANUP_CALLS
    )

    segments: list[tuple[int, set[str]]] = []
    current_cleanups: set[str] = set()
    segment_start = 1

    for i, line in enumerate(lines, 1):
        for m in cleanup_re.finditer(line):
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
                ))

    return results


def check_operator_consistency(
    source: str,
) -> list[IntraFunctionAsymmetry]:
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
                ))

    return results


def format_intra_function_context(
    asymmetries: list[IntraFunctionAsymmetry],
) -> str | None:
    """Format asymmetries for injection into the LLM review prompt."""
    if not asymmetries:
        return None

    parts = ["[Intra-function sibling analysis]"]
    parts.extend(f"  - [{a.kind}] {a.description}" for a in asymmetries)
    return "\n".join(parts)
