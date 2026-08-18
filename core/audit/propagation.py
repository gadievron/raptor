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
from typing import Any

from ._util import (
    SAFE_COCCI_RULE_RE,
    find_function_line,
    find_function_lines,
    safe_join,
)
from .constraints import Constraint

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
    reasons: list[str] = field(default_factory=list)
    is_entry_point: bool = False
    is_passthrough: bool = False


@dataclass
class PropagationResult:
    """Result of propagating one constraint one hop."""

    constraint: Constraint
    resolved: bool = False
    resolution: str = ""          # "confirmed" | "refuted" | "depth_limited"
    resolver_used: str = ""       # "codeql" | "coccinelle" | "semgrep" | "heuristic" | "llm"
    callers_scheduled: list[CallerCandidate] = field(default_factory=list)
    finding: dict[str, Any] | None = None
    depth_probe: DepthProbe | None = None


@dataclass
class DepthProbe:
    """One-hop probe beyond the depth ceiling."""

    callers_at_ceiling: list[str]
    entry_points_within_one_hop: list[str]
    estimated_remaining: str       # "1-2" | "3+" | "unknown"
    codeql_recommended: bool = False
    codeql_setup_hint: str = ""


@dataclass
class PropagationConfig:
    """Configuration for a propagation run."""

    max_depth: int = DEFAULT_MAX_DEPTH
    max_callers_per_hop: int = DEFAULT_MAX_CALLERS_PER_HOP
    codeql_db_path: str | None = None
    codeql_bin: str | None = None
    coccinelle_available: bool = False
    target_path: Path | None = None
    binary_verdicts: dict[str, str] | None = None
    inventory: dict[str, Any] | None = None
    evidence_index: dict[str, Any] | None = None
    # Live Joern server (warm CPG) for the dominance resolver tier
    # (P23). None = tier disabled; the orchestrator threads its
    # already-running server in, this module never starts one.
    joern_server: Any | None = None


def score_caller(
    caller_file: str,
    caller_function: str,
    caller_line: int,
    constraint: Constraint,
    *,
    entry_points: set[str],
    checklist: dict[str, Any] | None = None,
    target_path: Path | None = None,
    inventory: dict[str, Any] | None = None,
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
    checklist: dict[str, Any] | None,
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
    checklist: dict[str, Any],
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
    candidates: list[CallerCandidate],
    *,
    max_callers: int = DEFAULT_MAX_CALLERS_PER_HOP,
) -> list[CallerCandidate]:
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
    inventory: dict[str, Any] | None,
) -> list[tuple[str, str, int]] | None:
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
        from core.analysis.reachability import InternalFunction, callers_of
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
) -> PropagationResult | None:
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


_COCCI_DEFAULT_RULES: dict[str, list[str]] = {
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


_COCCI_RULES_DIR = Path(__file__).resolve().parents[2] / "engine" / "coccinelle" / "rules"


def try_coccinelle_resolve(
    constraint: Constraint,
    config: PropagationConfig,
) -> PropagationResult | None:
    """Attempt to resolve a constraint via Coccinelle consistency checks.

    Handles postcondition, precondition, and state constraints using
    rules from engine/coccinelle/rules/.  Each constraint kind maps to
    a set of default rules; the constraint's mechanical_check field
    overrides the default when set.

    When multiple rules apply, they are batched into a single spatch
    invocation so the target AST is parsed once.
    """
    if constraint.kind not in _COCCI_SUPPORTED_KINDS:
        return None
    if not config.coccinelle_available:
        return None
    if not config.target_path:
        return None

    try:
        from packages.coccinelle.runner import (
            is_available,
            run_rule,
            run_rules_batched,
        )
    except ImportError:
        return None

    if not is_available():
        return None

    if constraint.mechanical_check:
        raw_rules = [constraint.mechanical_check]
    else:
        raw_rules = _COCCI_DEFAULT_RULES.get(constraint.kind, [])

    rule_paths: list[Path] = []
    for rule_name in raw_rules:
        if not SAFE_COCCI_RULE_RE.match(rule_name):
            logger.warning(
                "rejected unsafe cocci rule name: %r", rule_name,
            )
            continue
        p = Path(rule_name)
        if not p.is_absolute():
            p = _COCCI_RULES_DIR / rule_name
        if p.exists():
            rule_paths.append(p)

    if not rule_paths:
        return None

    _PARAMETRIC_RE = re.compile(r"identifier\s+virtual\.", re.MULTILINE)

    parametric: list[Path] = []
    batchable: list[Path] = []
    for rp in rule_paths:
        try:
            head = rp.read_text()[:4096]
        except OSError:
            continue
        if _PARAMETRIC_RE.search(head):
            parametric.append(rp)
        else:
            batchable.append(rp)

    all_results: dict[str, Any] = {}
    if batchable:
        all_results.update(run_rules_batched(
            config.target_path,
            batchable,
            timeout=300,
            # In-repo engine/coccinelle rules (code trust) — their
            # @script:python reporting blocks are trusted.
            allow_scripting=True,
        ))

    for rp in parametric:
        defines = {"func": constraint.function} if constraint.function else {}
        sr = run_rule(
            config.target_path,
            str(rp),
            defines=defines,
            timeout=300,
            # In-repo engine/coccinelle rules (code trust).
            allow_scripting=True,
        )
        all_results[rp.stem] = sr

    all_callers: list[CallerCandidate] = []
    for rule_stem, result in all_results.items():
        if not result.ok and not result.matches:
            continue
        for m in result.matches:
            if m.file:
                all_callers.append(CallerCandidate(
                    file=m.file,
                    function="",
                    line=m.line,
                    score=8,
                    reasons=[f"coccinelle:{rule_stem}"],
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
    ceiling_callers: list[tuple[str, str, int]],
    inventory: dict[str, Any] | None,
    entry_points: set[str],
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
) -> PropagationResult | None:
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
    params = approx.get("params", []) if isinstance(approx, dict) else getattr(approx, "params", [])
    for i, p in enumerate(params):
        if p == param_name:
            param_idx = i
            break

    if param_idx is None:
        return None

    df = approx.get("dangerous_flows", {}) if isinstance(approx, dict) else getattr(approx, "dangerous_flows", {})
    if df.get(param_idx):
        return PropagationResult(
            constraint=constraint,
            resolved=True,
            resolution="confirmed",
            resolver_used="taint_approx",
        )

    has_opaque = approx.get("has_opaque_flow", False) if isinstance(approx, dict) else getattr(approx, "has_opaque_flow", False)
    if has_opaque:
        return None

    return None


def _try_taint_summary_resolve(
    constraint: Constraint,
    config: PropagationConfig,
) -> PropagationResult | None:
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
        if sanitizers and constraint.cwe:
            from core.dataflow.sanitizer_catalog import sanitizer_callables_for_cwe

            from .prefilter import detect_language
            lang = detect_language(constraint.file)
            if lang:
                relevant = sanitizer_callables_for_cwe(constraint.cwe, lang)
                sanitizers = frozenset(
                    (name, idx) for name, idx in sanitizers if name in relevant
                )
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
) -> PropagationResult | None:
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


# Callers probed per dominance check: each is one Joern round-trip.
_DOMINANCE_MAX_CALLERS = 3


def _try_joern_dominance_resolve(
    constraint: Constraint,
    config: PropagationConfig,
    checklist: dict[str, Any],
) -> PropagationResult | None:
    """Tier 3b (P23): verify a caller-contract constraint via CFG
    dominance when the CPG is warm.

    The flow tier (:func:`_try_joern_resolve`) confirms via flow
    *existence* — a parameter that flows in from a caller. This tier
    checks the claimed caller-side GUARD instead: in each caller, does
    a condition on ``constraint.target`` dominate the call to
    ``constraint.function``?

    * every probed caller guards the call → ``refuted`` (contract
      satisfied — same resolution the sanitizer branch of the taint
      tier uses);
    * any probed caller has an unguarded call site mentioning the
      identifier → ``confirmed`` (violation);
    * anything else (cold server, no callers, unbindable identifiers,
      inconclusive queries) → ``None``, falling through to the next
      resolver.
    """
    server = getattr(config, "joern_server", None)
    if server is None or config.target_path is None:
        return None
    if constraint.kind not in ("parameter", "precondition"):
        return None
    if constraint.direction not in ("callers", "both"):
        return None

    from ._util import is_valid_identifier
    ident = constraint.target or ""
    sink = constraint.function or ""
    if not is_valid_identifier(ident) or not is_valid_identifier(sink):
        return None

    line = find_function_line(checklist, constraint.file, constraint.function)
    callers = get_callers(
        constraint.file, constraint.function, line, config.inventory,
    ) or []
    if not callers:
        return None

    from .joern_verify import run_guard_dominance_check

    outcomes: list[str] = []
    for caller_file, caller_fn, _ln in callers[:_DOMINANCE_MAX_CALLERS]:
        try:
            res = run_guard_dominance_check(
                target_path=Path(config.target_path),
                file_path=caller_file,
                function_name=caller_fn,
                identifier=ident,
                sink_call=sink,
                server=server,
            )
        except Exception:
            logger.debug(
                "dominance resolve failed for %s in %s:%s",
                constraint.identity, caller_file, caller_fn,
                exc_info=True,
            )
            return None
        outcomes.append(res.outcome)

    if "confirmed" in outcomes:
        return PropagationResult(
            constraint=constraint,
            resolved=True,
            resolution="confirmed",
            resolver_used="joern_dominance",
        )
    if outcomes and all(o == "refuted" for o in outcomes):
        # A dominating check on the constrained identifier exists in
        # EVERY probed caller — the caller contract is mechanically
        # satisfied.
        return PropagationResult(
            constraint=constraint,
            resolved=True,
            resolution="refuted",
            resolver_used="joern_dominance",
        )
    return None


def _tick_tier(
    tier_counters: dict[str, Any] | None,
    tier: str,
    result: PropagationResult,
) -> None:
    """Increment a tier counter based on propagation result."""
    if tier_counters is None or tier not in tier_counters:
        return
    tc = tier_counters[tier]
    if result.resolved and result.resolution == "confirmed":
        tc.confirmed += 1
    elif result.resolved:
        tc.refuted += 1
    else:
        tc.inconclusive += 1


def propagate_one_hop(
    constraint: Constraint,
    *,
    checklist: dict[str, Any],
    entry_points: set[str],
    config: PropagationConfig,
    current_depth: int = 0,
    tier_counters: dict[str, Any] | None = None,
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

    dominance_result = _try_joern_dominance_resolve(
        constraint, config, checklist,
    )
    if dominance_result:
        _tick_tier(tier_counters, "joern_dominance", dominance_result)
        return dominance_result

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
    inventory: dict[str, Any],
    file_path: str,
    function_name: str,
    line: int,
) -> str:
    """Query entry_reachability, returning the verdict or "uncertain"."""
    try:
        from core.analysis.reachability import (
            InternalFunction,
            entry_reachability,
        )
        target = InternalFunction(
            file_path=file_path, name=function_name, line=line,
        )
        return entry_reachability(inventory, target)
    except Exception:  # noqa: BLE001
        return "uncertain"


# ── Confidence propagation ─────────────────────────────────────────

_CALLER_VIOLATION_RE = re.compile(
    r"(?:if\s+)?(?:the\s+|a\s+)?caller\s+(?:passes|provides|supplies|sends|could\s+"
    r"(?:provide|pass|send|supply))|"
    r"(?:caller|upstream)\s+(?:fails\s+to|does\s+not|doesn't)\s+"
    r"(?:validate|check|bound|sanitise|sanitize)|"
    r"trusts\s+(?:the\s+|its\s+)?caller|"
    r"no\s+(?:validation|bounds\s+check|sanitisation|sanitization)\s+"
    r"(?:on|of|for)\s+(?:the\s+)?(?:input|parameter|argument)",
    re.IGNORECASE,
)

_CALLEE_VIOLATION_RE = re.compile(
    r"(\w+)\(\)\s+(?:returns|produces|yields|could\s+(?:return|produce|fail))|"
    r"assumes\s+(\w+)\(\)\s+(?:will|always)|"
    r"(?:if|when)\s+(\w+)\(\)\s+(?:fails|errors|returns\s+(?:null|NULL|-1|error))",
    re.IGNORECASE,
)


@dataclass
class ConfidenceDemotion:
    """A function whose verdict should be demoted based on propagated confidence."""

    file: str
    function: str
    reason: str
    source_functions: list[str]


def propagate_confidence(
    outcomes: list[Any],
    call_edge_index: dict[str, Any],
    checklist_index: dict[tuple[str, str], Any] | None = None,
    *,
    max_iterations: int = 5,
    min_callers: int = 2,
) -> list[ConfidenceDemotion]:
    """Propagate clean verdicts through the call graph to refute contract-violation hypotheses.

    Only propagates from outcomes with tool-backed or confirmed
    verification tiers to avoid LLM-trusts-LLM circular reasoning.

    ``min_callers`` requires at least N known callers before propagating
    caller-direction demotions.  The call-edge index may be incomplete
    (function pointers, virtual dispatch, callbacks are invisible), so
    a single known-clean caller is insufficient evidence.

    Returns a list of demotions to apply. Runs to fixpoint or
    max_iterations, whichever comes first.
    """
    trusted_clean: set[tuple[str, str]] = set()
    for o in outcomes:
        if o.status == "clean" and getattr(o, "verification_tier", "") in (
            "confirmed", "tool_backed",
        ):
            trusted_clean.add((o.file, o.function))

    all_demotions: list[ConfidenceDemotion] = []

    for iteration in range(max_iterations):
        round_demotions: list[ConfidenceDemotion] = []

        suspicious = [
            o for o in outcomes
            if o.status == "suspicious"
            and (o.file, o.function) not in trusted_clean
        ]

        for outcome in suspicious:
            hypotheses = getattr(outcome, "hypotheses", None) or []
            if not hypotheses:
                continue

            has_caller_violation = any(
                _CALLER_VIOLATION_RE.search(
                    h.get("mechanism", "") + " " + h.get("counter", "")
                )
                for h in hypotheses
                if isinstance(h, dict)
            )

            has_callee_violation = any(
                _CALLEE_VIOLATION_RE.search(
                    h.get("mechanism", "") + " " + h.get("counter", "")
                )
                for h in hypotheses
                if isinstance(h, dict)
            )

            if not has_caller_violation and not has_callee_violation:
                continue

            key = f"{outcome.file}:{outcome.function}"

            if has_caller_violation:
                callers = _get_callers_from_index(
                    key, call_edge_index,
                )
                if len(callers) >= min_callers and all(
                    (cf, cn) in trusted_clean for cf, cn in callers
                ):
                    caller_names = [f"{cf}:{cn}" for cf, cn in callers]
                    round_demotions.append(ConfidenceDemotion(
                        file=outcome.file,
                        function=outcome.function,
                        reason=f"all {len(callers)} callers confirmed clean: "
                               f"{', '.join(caller_names[:5])}",
                        source_functions=caller_names,
                    ))
                    continue

            if has_callee_violation:
                callees = _get_callees_from_index(
                    key, call_edge_index,
                )
                flagged_callees = _extract_callee_names(hypotheses)
                if flagged_callees and callees:
                    matched = [
                        cn for cn in flagged_callees
                        if any(cn == callee_name for _, callee_name in callees)
                    ]
                    if matched:
                        all_clean = all(
                            any(
                                (cf, cn) in trusted_clean
                                for cf, cn in callees
                                if cn == callee_name
                            )
                            for callee_name in matched
                        )
                        if all_clean:
                            round_demotions.append(ConfidenceDemotion(
                                file=outcome.file,
                                function=outcome.function,
                                reason=f"hypothesised callee(s) confirmed clean: "
                                       f"{', '.join(matched)}",
                                source_functions=list(matched),
                            ))

        if not round_demotions:
            break

        for d in round_demotions:
            for o in outcomes:
                if o.file == d.file and o.function == d.function:
                    o.status = "clean"
                    break

        all_demotions.extend(round_demotions)
        logger.info(
            "confidence propagation round %d: %d demotions",
            iteration + 1, len(round_demotions),
        )

    return all_demotions


def _get_callers_from_index(
    key: str,
    call_edge_index: dict[str, Any],
) -> list[tuple[str, str]]:
    """Get caller (file, function) pairs from the call-edge index.

    Production edges have keys caller_file, caller, callee_file, callee.
    Test edges may use the 'target' key as a file:function composite.

    Returns deduplicated callers — edges are indexed under both caller
    and callee keys so the same edge appears twice in a full scan.
    """
    seen: set[tuple[str, str]] = set()
    callers: list[tuple[str, str]] = []
    _key_file, _, key_func = key.rpartition(":")
    for edge_key, edges in call_edge_index.items():
        if not isinstance(edges, list):
            continue
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            callee_file = edge.get("callee_file", "")
            callee_name = edge.get("callee") or ""
            if callee_file and callee_name:
                callee_key = f"{callee_file}:{callee_name}"
                if callee_key == key or callee_name == key_func:
                    caller_file = edge.get("caller_file", "")
                    caller_name = edge.get("caller", "")
                    if caller_file and caller_name:
                        pair = (caller_file, caller_name)
                        if pair not in seen:
                            seen.add(pair)
                            callers.append(pair)
                        continue
            target = edge.get("target") or callee_name
            if target == key or (key_func and target == key_func):
                parts = edge_key.split(":", 1)
                if len(parts) == 2:
                    pair = (parts[0], parts[1])
                    if pair not in seen:
                        seen.add(pair)
                        callers.append(pair)
    return callers


def _get_callees_from_index(
    key: str,
    call_edge_index: dict[str, Any],
) -> list[tuple[str, str]]:
    """Get callee (file, function) pairs from the call-edge index."""
    callees = []
    edges = call_edge_index.get(key) or []
    if not isinstance(edges, list):
        return callees
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        callee_file = edge.get("callee_file", "")
        callee_name = edge.get("callee") or edge.get("target") or ""
        if callee_file and callee_name:
            callees.append((callee_file, callee_name))
        elif callee_name:
            target = callee_name
            parts = target.split(":", 1)
            if len(parts) == 2:
                callees.append((parts[0], parts[1]))
            else:
                callees.append(("", target))
    return callees


def _extract_callee_names(hypotheses: list[dict[str, Any]]) -> set[str]:
    """Extract callee function names from hypothesis text."""
    names: set[str] = set()
    for h in hypotheses:
        if not isinstance(h, dict):
            continue
        text = h.get("mechanism", "") + " " + h.get("counter", "")
        for m in _CALLEE_VIOLATION_RE.finditer(text):
            for g in m.groups():
                if g:
                    names.add(g)
    return names
