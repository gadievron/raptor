"""Constraint propagation via the hybrid resolver chain.

Resolves constraints through a chain of mechanical tools, falling
back to LLM-assisted review only for callers that survive all
mechanical filters.  The chain:

    CodeQL → Coccinelle → Semgrep → TreeSitter heuristic → LLM

Each resolver either fully resolves the constraint (confirmed/refuted),
narrows the caller set, or passes through.

Depth limit (default 5) controls how many hops of caller propagation
before stopping.  At the ceiling, a one-hop probe estimates remaining
depth and (if the constraint is taint-expressible) recommends a CodeQL
DB build.

Constraints persist across runs with freshness checks (same staleness
model as annotations).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .constraints import Constraint
from ._util import find_function_line, find_function_lines, safe_join, SAFE_COCCI_RULE_RE

logger = logging.getLogger(__name__)

DEFAULT_MAX_DEPTH = 5
DEFAULT_MAX_CALLERS_PER_HOP = 10
_MAX_SOURCE_BYTES = 2 * 1024 * 1024  # 2 MB cap for heuristic source reads

_BOUNDS_CHECK_RE = re.compile(
    r"""
    (?:if|while|assert|CHECK|DCHECK|BUG_ON|WARN_ON)
    \s*\(
    [^)]*
    (?:<=?|>=?|==|!=|<|>)
    [^)]*
    \)
    """,
    re.VERBOSE,
)

_TEST_PATH_RE = re.compile(
    r"(?:^|/)(?:test|tests|testing|__tests__|spec|specs)/|_test\.\w+$|test_\w+\.\w+$",
)


@dataclass
class CallerCandidate:
    """A caller scored by the tree-sitter heuristic."""

    file: str
    function: str
    line: int
    score: float = 0.0
    reasons: List[str] = field(default_factory=list)
    is_entry_point: bool = False
    is_passthrough: bool = False


@dataclass
class PropagationResult:
    """Result of propagating one constraint one hop."""

    constraint: Constraint
    resolved: bool = False
    resolution: str = ""          # "confirmed" | "refuted" | "depth_limited"
    resolver_used: str = ""       # "codeql" | "coccinelle" | "semgrep" | "heuristic" | "llm"
    callers_scheduled: List[CallerCandidate] = field(default_factory=list)
    callers_filtered: int = 0
    finding: Optional[Dict[str, Any]] = None
    depth_probe: Optional[DepthProbe] = None


@dataclass
class DepthProbe:
    """One-hop probe beyond the depth ceiling."""

    callers_at_ceiling: List[str]
    entry_points_within_one_hop: List[str]
    estimated_remaining: str       # "1-2" | "3+" | "unknown"
    codeql_recommended: bool = False
    codeql_setup_hint: str = ""


@dataclass
class PropagationConfig:
    """Configuration for a propagation run."""

    max_depth: int = DEFAULT_MAX_DEPTH
    max_callers_per_hop: int = DEFAULT_MAX_CALLERS_PER_HOP
    codeql_db_path: Optional[str] = None
    codeql_bin: Optional[str] = None
    coccinelle_available: bool = False
    target_path: Optional[Path] = None
    binary_verdicts: Optional[Dict[str, str]] = None
    inventory: Optional[Dict[str, Any]] = None
    evidence_index: Optional[Dict[str, Any]] = None


def score_caller(
    caller_file: str,
    caller_function: str,
    caller_line: int,
    constraint: Constraint,
    *,
    entry_points: Set[str],
    checklist: Optional[Dict[str, Any]] = None,
    target_path: Optional[Path] = None,
    inventory: Optional[Dict[str, Any]] = None,
) -> CallerCandidate:
    """Score a caller by likelihood of violating a constraint.

    Higher score = more likely to violate = review first.
    """
    candidate = CallerCandidate(
        file=caller_file,
        function=caller_function,
        line=caller_line,
    )
    key = f"{caller_file}:{caller_function}"

    if key in entry_points:
        candidate.score += 10
        candidate.is_entry_point = True
        candidate.reasons.append("entry_point")

    if _TEST_PATH_RE.search(caller_file):
        candidate.score -= 20
        candidate.reasons.append("test_file")

    if inventory:
        reach = _entry_reachability_verdict(
            inventory, caller_file, caller_function, caller_line,
        )
        if reach == "no_path_from_entry":
            candidate.score -= 5
            candidate.reasons.append("no_entry_path")

    if target_path and constraint.kind == "parameter":
        source_file = safe_join(target_path, caller_file)
        if source_file and source_file.exists():
            try:
                size = source_file.stat().st_size
                if size <= _MAX_SOURCE_BYTES:
                    source = source_file.read_text(errors="replace")
                    # Scope to the caller function body so we don't
                    # attribute evidence from unrelated functions in the
                    # same file.
                    scoped = _scope_to_function(
                        source, caller_function, caller_line,
                        checklist, caller_file,
                    )
                    _score_from_source(
                        candidate, scoped, constraint, caller_function,
                    )
            except OSError:
                pass

    if checklist:
        _score_passthrough(
            candidate, constraint, caller_file, caller_function, checklist,
        )

    return candidate


def _scope_to_function(
    source: str,
    function_name: str,
    caller_line: int,
    checklist: Optional[Dict[str, Any]],
    caller_file: str,
) -> str:
    """Extract the source text for a single function body.

    Uses checklist line_start/line_end when available, falling back to
    caller_line with a heuristic end boundary.  Returns the full source
    unchanged if scoping fails entirely.
    """
    lines = source.splitlines(keepends=True)
    start = 0
    end = len(lines)

    if checklist:
        ls, le = find_function_lines(checklist, caller_file, function_name)
        if ls > 0:
            start = max(ls - 1, 0)
            end = le if le > ls else end

    if start == 0 and caller_line > 0:
        start = max(caller_line - 1, 0)
        if end == len(lines):
            end = min(start + 200, len(lines))

    if start == 0 and end == len(lines):
        return source

    return "".join(lines[start:end])


def _score_from_source(
    candidate: CallerCandidate,
    source: str,
    constraint: Constraint,
    caller_function: str,
) -> None:
    """Score based on source text analysis."""
    call_pattern = re.compile(
        rf"\b{re.escape(constraint.function)}\s*\(",
    )
    if not call_pattern.search(source):
        return

    has_literal = re.search(
        rf"{re.escape(constraint.function)}\s*\([^)]*\b\d+\b",
        source,
    )
    if has_literal:
        candidate.score += 2
        candidate.reasons.append("literal_arg")
    else:
        candidate.score += 5
        candidate.reasons.append("variable_arg")

    if _BOUNDS_CHECK_RE.search(source):
        pass
    else:
        candidate.score += 3
        candidate.reasons.append("no_bounds_check")


def _score_passthrough(
    candidate: CallerCandidate,
    constraint: Constraint,
    caller_file: str,
    caller_function: str,
    checklist: Dict[str, Any],
) -> None:
    """Detect parameter passthrough (caller forwards its own param)."""
    if constraint.kind != "parameter":
        return

    for file_info in checklist.get("files", []):
        if file_info.get("path", "") != caller_file:
            continue
        for item in file_info.get("items", file_info.get("functions", [])):
            if item.get("name") != caller_function:
                continue
            params = (item.get("metadata") or {}).get("parameters", [])
            param_names = set()
            for p in params:
                if isinstance(p, dict):
                    param_names.add(p.get("name", ""))
                elif isinstance(p, (list, tuple)) and p:
                    param_names.add(str(p[0]))
            if constraint.target in param_names:
                candidate.score += 4
                candidate.is_passthrough = True
                candidate.reasons.append("passthrough")
        break


def rank_callers(
    candidates: List[CallerCandidate],
    *,
    max_callers: int = DEFAULT_MAX_CALLERS_PER_HOP,
) -> List[CallerCandidate]:
    """Rank and filter caller candidates by score.

    Returns top-N candidates with score > 0.
    """
    eligible = [c for c in candidates if c.score > 0]
    eligible.sort(key=lambda c: (-c.score, c.file, c.function))
    return eligible[:max_callers]


def get_callers(
    file_path: str,
    function_name: str,
    line: int,
    inventory: Optional[Dict[str, Any]],
) -> Optional[List[Tuple[str, str, int]]]:
    """Get direct callers of a function via the reachability API.

    Returns:
        List of (file, function, line) tuples on success (may be empty
        if the function genuinely has zero callers).
        None if the reachability module isn't available, inventory is
        missing, or the query failed — callers are unknown, not
        confirmed-zero.
    """
    if inventory is None:
        return None

    try:
        from core.analysis.reachability import callers_of, InternalFunction
    except ImportError:
        logger.debug("reachability module not available")
        return None

    try:
        target = InternalFunction(
            file_path=file_path, name=function_name, line=line,
        )
        result = callers_of(inventory, target)
        return [
            (c.file_path, c.name, c.line)
            for c in result.all_callers
        ]
    except Exception:
        logger.debug(
            "callers_of failed for %s:%s", file_path, function_name,
            exc_info=True,
        )
        return None


def try_codeql_resolve(
    constraint: Constraint,
    config: PropagationConfig,
) -> Optional[PropagationResult]:
    """Attempt to resolve a parameter constraint via CodeQL taint query.

    Returns None if CodeQL is unavailable or the constraint isn't
    taint-expressible.
    """
    if not constraint.is_taint_expressible():
        return None
    if not config.codeql_db_path:
        return None

    db = Path(config.codeql_db_path)
    if not db.is_dir():
        return None

    try:
        from .codeql_validation import (
            DataflowClaim,
            validate_dataflow_claim,
        )
    except ImportError:
        return None

    claim = DataflowClaim(
        source_file="",
        source_function="",
        sink_file=constraint.file,
        sink_function=constraint.function,
        source_type="remote",
        sink_type=constraint.target,
        description=constraint.rule,
    )

    try:
        result = validate_dataflow_claim(
            claim,
            db_path=config.codeql_db_path,
            codeql_bin=config.codeql_bin,
        )
        if result.confirmed is True:
            return PropagationResult(
                constraint=constraint,
                resolved=True,
                resolution="confirmed",
                resolver_used="codeql",
            )
        elif result.confirmed is False:
            return PropagationResult(
                constraint=constraint,
                resolved=True,
                resolution="refuted",
                resolver_used="codeql",
            )
    except Exception:
        logger.debug("CodeQL resolve failed", exc_info=True)

    return None


_COCCI_DEFAULT_RULES: Dict[str, List[str]] = {
    "postcondition": ["unchecked_return.cocci"],
    "precondition": [
        "missing_null_check.cocci",
        "missing_bounds_check.cocci",
        "copy_to_user_uninit.cocci",
        "rcu_no_lock.cocci",
    ],
    "state": [
        "lock_imbalance.cocci",
        "use_after_unlock.cocci",
        "unsafe_list_del.cocci",
        "double_fetch.cocci",
    ],
}

_COCCI_SUPPORTED_KINDS = frozenset(_COCCI_DEFAULT_RULES)


def try_coccinelle_resolve(
    constraint: Constraint,
    config: PropagationConfig,
) -> Optional[PropagationResult]:
    """Attempt to resolve a constraint via Coccinelle consistency checks.

    Handles postcondition, precondition, and state constraints using
    parametric rules from engine/coccinelle/rules/.  Each constraint
    kind maps to a set of default rules; the constraint's
    mechanical_check field overrides the default when set.
    """
    if constraint.kind not in _COCCI_SUPPORTED_KINDS:
        return None
    if not config.coccinelle_available:
        return None
    if not config.target_path:
        return None

    try:
        from .sweep import run_consistency_check
    except ImportError:
        return None

    if constraint.mechanical_check:
        rules = [constraint.mechanical_check]
    else:
        rules = _COCCI_DEFAULT_RULES.get(constraint.kind, [])

    all_callers: List[CallerCandidate] = []

    for rule_name in rules:
        if not SAFE_COCCI_RULE_RE.match(rule_name):
            logger.warning(
                "rejected unsafe cocci rule name: %r", rule_name,
            )
            continue

        result = run_consistency_check(
            target_path=config.target_path,
            function_name=constraint.function,
            cocci_rule=rule_name,
        )

        if result.outcome == "error":
            continue

        if result.outcome == "confirmed" and result.matches:
            for m in result.matches:
                if isinstance(m, dict) and m.get("file"):
                    all_callers.append(CallerCandidate(
                        file=m["file"],
                        function=m.get("function", ""),
                        line=m.get("line", 0),
                        score=8,
                        reasons=[f"coccinelle:{rule_name}"],
                    ))

    if all_callers:
        return PropagationResult(
            constraint=constraint,
            resolved=False,
            resolver_used="coccinelle",
            callers_scheduled=all_callers,
        )

    return None


def probe_beyond_ceiling(
    constraint: Constraint,
    ceiling_callers: List[Tuple[str, str, int]],
    inventory: Optional[Dict[str, Any]],
    entry_points: Set[str],
) -> DepthProbe:
    """One-hop probe beyond the depth ceiling to estimate remaining depth.

    Checks whether any callers of the ceiling-level functions are
    entry points.  Zero LLM cost — just call graph traversal.
    """
    caller_names = [
        f"{f}:{fn}" for f, fn, _ in ceiling_callers
    ]
    entry_points_found = []
    all_next_callers = []

    for file_path, func_name, line in ceiling_callers:
        next_callers = get_callers(file_path, func_name, line, inventory)
        if next_callers is None:
            continue
        for nf, nn, nl in next_callers:
            key = f"{nf}:{nn}"
            all_next_callers.append(key)
            if key in entry_points:
                entry_points_found.append(key)

    if entry_points_found:
        estimated = "1-2"
    elif all_next_callers:
        estimated = "3+"
    else:
        estimated = "unknown"

    codeql_recommended = (
        constraint.is_taint_expressible() and estimated == "3+"
    )
    hint = ""
    if codeql_recommended:
        hint = (
            "codeql database create db --language=cpp --source-root=.\n"
            "# then re-run /audit — taint query resolves in 1 pass"
        )

    return DepthProbe(
        callers_at_ceiling=caller_names,
        entry_points_within_one_hop=entry_points_found,
        estimated_remaining=estimated,
        codeql_recommended=codeql_recommended,
        codeql_setup_hint=hint,
    )


def _try_taint_approx_resolve(
    constraint: Constraint,
    config: PropagationConfig,
) -> Optional[PropagationResult]:
    """Tier 1: resolve constraint via tree-sitter taint approximation."""
    if not config.evidence_index:
        return None

    if constraint.kind != "parameter":
        return None

    key = f"{constraint.file}:{constraint.function}"
    rec = config.evidence_index.get(key)
    if rec is None or not hasattr(rec, "taint_approx") or rec.taint_approx is None:
        return None

    approx = rec.taint_approx
    param_name = constraint.target
    if not param_name:
        return None

    param_idx = None
    for i, p in enumerate(approx.params):
        if p == param_name:
            param_idx = i
            break

    if param_idx is None:
        return None

    if param_idx in approx.dangerous_flows and approx.dangerous_flows[param_idx]:
        return PropagationResult(
            constraint=constraint,
            resolved=True,
            resolution="confirmed",
            resolver_used="taint_approx",
        )

    if approx.has_opaque_flow:
        return None

    return None


def _try_taint_summary_resolve(
    constraint: Constraint,
    config: PropagationConfig,
) -> Optional[PropagationResult]:
    """Tier 1: resolve constraint via Python CFG-based taint summary."""
    if not config.evidence_index:
        return None

    if constraint.kind != "parameter":
        return None

    key = f"{constraint.file}:{constraint.function}"
    rec = config.evidence_index.get(key)
    if rec is None or not hasattr(rec, "taint_summary") or rec.taint_summary is None:
        return None

    ts = rec.taint_summary
    param_name = constraint.target
    if not param_name:
        return None

    param_idx = None
    for i, p in enumerate(ts.params):
        if p == param_name:
            param_idx = i
            break

    if param_idx is None:
        return None

    if hasattr(ts, "call_arg_taint"):
        for callee, arg_idx, pidx in ts.call_arg_taint:
            if pidx == param_idx:
                return PropagationResult(
                    constraint=constraint,
                    resolved=True,
                    resolution="confirmed",
                    resolver_used="taint_summary",
                )

    if hasattr(ts, "return_sanitizers_for_param"):
        sanitizers = ts.return_sanitizers_for_param(param_idx)
        if sanitizers:
            return PropagationResult(
                constraint=constraint,
                resolved=True,
                resolution="refuted",
                resolver_used="taint_summary",
            )

    if hasattr(ts, "summary_unknown") and ts.summary_unknown:
        return None

    return None


def _try_joern_resolve(
    constraint: Constraint,
    config: PropagationConfig,
) -> Optional[PropagationResult]:
    """Tier 3: resolve constraint via Joern CPG taint flows."""
    if not config.evidence_index:
        return None

    if constraint.kind != "parameter":
        return None

    key = f"{constraint.file}:{constraint.function}"
    rec = config.evidence_index.get(key)
    if rec is None:
        return None
    if not hasattr(rec, "joern_flows") or not hasattr(rec, "imported_joern_flows"):
        return None

    all_flows = (rec.joern_flows or []) + (rec.imported_joern_flows or [])
    if not all_flows:
        return None

    param_name = constraint.target

    for flow in all_flows:
        src_param = getattr(flow, "source_param", "")
        if param_name and src_param != param_name:
            continue
        return PropagationResult(
            constraint=constraint,
            resolved=True,
            resolution="confirmed",
            resolver_used="joern",
        )

    return None


def _tick_tier(
    tier_counters: Optional[Dict[str, Any]],
    tier: str,
    result: "PropagationResult",
) -> None:
    """Increment a tier counter based on propagation result."""
    if tier_counters is None or tier not in tier_counters:
        return
    tc = tier_counters[tier]
    if result.resolved:
        tc.confirmed += 1
    else:
        tc.inconclusive += 1


def propagate_one_hop(
    constraint: Constraint,
    *,
    checklist: Dict[str, Any],
    entry_points: Set[str],
    config: PropagationConfig,
    current_depth: int = 0,
    tier_counters: Optional[Dict[str, Any]] = None,
) -> PropagationResult:
    """Propagate a constraint one hop through the resolver chain.

    Tries mechanical resolvers first, falls back to tree-sitter
    heuristic scoring for LLM review scheduling.
    """
    if config.binary_verdicts:
        key = f"{constraint.file}:{constraint.function}"
        verdict = config.binary_verdicts.get(key)
        if verdict == "absent":
            return PropagationResult(
                constraint=constraint,
                resolved=True,
                resolution="refuted",
                resolver_used="binary_oracle",
            )

    if current_depth >= config.max_depth:
        line = find_function_line(
            checklist, constraint.file, constraint.function,
        )
        ceiling_callers = get_callers(
            constraint.file, constraint.function, line,
            config.inventory,
        ) or []
        probe = probe_beyond_ceiling(
            constraint, ceiling_callers, config.inventory, entry_points,
        )
        return PropagationResult(
            constraint=constraint,
            resolved=False,
            resolution="depth_limited",
            depth_probe=probe,
        )

    taint_result = _try_taint_approx_resolve(constraint, config)
    if taint_result:
        _tick_tier(tier_counters, "taint_approx", taint_result)
        return taint_result

    taint_summary_result = _try_taint_summary_resolve(constraint, config)
    if taint_summary_result:
        _tick_tier(tier_counters, "taint_summary", taint_summary_result)
        return taint_summary_result

    joern_result = _try_joern_resolve(constraint, config)
    if joern_result:
        _tick_tier(tier_counters, "joern", joern_result)
        return joern_result

    codeql_result = try_codeql_resolve(constraint, config)
    if codeql_result:
        _tick_tier(tier_counters, "codeql", codeql_result)
        return codeql_result

    coccinelle_result = try_coccinelle_resolve(constraint, config)
    if coccinelle_result and coccinelle_result.callers_scheduled:
        _tick_tier(tier_counters, "coccinelle", coccinelle_result)
        return coccinelle_result

    line = find_function_line(
        checklist, constraint.file, constraint.function,
    )
    raw_callers = get_callers(
        constraint.file, constraint.function, line, config.inventory,
    )

    if raw_callers is None:
        return PropagationResult(
            constraint=constraint,
            resolved=False,
            resolution="inconclusive",
            resolver_used="heuristic",
        )

    if not raw_callers:
        # Empty caller list from static analysis does not prove
        # unreachability — function pointers, dlsym, dynamic dispatch
        # are invisible to the static call graph.
        return PropagationResult(
            constraint=constraint,
            resolved=False,
            resolution="inconclusive",
            resolver_used="heuristic",
        )

    candidates = [
        score_caller(
            f, fn, ln, constraint,
            entry_points=entry_points,
            checklist=checklist,
            target_path=config.target_path,
            inventory=config.inventory,
        )
        for f, fn, ln in raw_callers
    ]

    ranked = rank_callers(
        candidates, max_callers=config.max_callers_per_hop,
    )

    return PropagationResult(
        constraint=constraint,
        resolved=False,
        resolver_used="heuristic",
        callers_scheduled=ranked,
        callers_filtered=len(candidates) - len(ranked),
    )


def format_depth_limit_report(
    constraint: Constraint,
    probe: DepthProbe,
    depth: int,
    max_depth: int,
) -> str:
    """Format the operator-facing depth limit report."""
    lines = [
        f"Depth limit reached ({depth}/{max_depth} hops)",
        "",
        f"  Constraint: {constraint.rule} ({constraint.violation})",
        f"  Function: {constraint.function} ({constraint.file})",
    ]
    if constraint.propagation_chain:
        chain = " <- ".join(constraint.propagation_chain)
        lines.append(f"  Chain: {constraint.function} <- {chain}")

    lines.append("")

    if probe.entry_points_within_one_hop:
        ep_list = ", ".join(probe.entry_points_within_one_hop[:3])
        lines.append(
            f"  Probe beyond ceiling: entry points within 1 hop: {ep_list}",
        )
        lines.append(
            f"  Estimated remaining depth: {probe.estimated_remaining} hops",
        )
    elif probe.callers_at_ceiling:
        n = len(probe.callers_at_ceiling)
        lines.append(
            f"  Probe beyond ceiling: {n} callers, no entry points within 1 hop",
        )
        lines.append(
            f"  Estimated remaining depth: {probe.estimated_remaining} hops",
        )
    else:
        lines.append("  Probe beyond ceiling: no callers found")

    lines.append("")
    lines.append("  Options:")
    if probe.codeql_recommended:
        lines.append(
            "  - Build CodeQL DB (recommended for deep taint):",
        )
        for hint_line in probe.codeql_setup_hint.splitlines():
            lines.append(f"    {hint_line}")
    lines.append(
        f"  - Raise depth: /audit --max-propagation-depth {max_depth * 2}",
    )
    lines.append("  - Manual review from the chain endpoint upward")

    return "\n".join(lines)


def _entry_reachability_verdict(
    inventory: Dict[str, Any],
    file_path: str,
    function_name: str,
    line: int,
) -> str:
    """Query entry_reachability, returning the verdict or "uncertain"."""
    try:
        from core.analysis.reachability import (
            entry_reachability, InternalFunction,
        )
        target = InternalFunction(
            file_path=file_path, name=function_name, line=line,
        )
        return entry_reachability(inventory, target)
    except Exception:
        return "uncertain"
