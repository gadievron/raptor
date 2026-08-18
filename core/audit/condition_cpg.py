"""CPG-based guard relevance and interprocedural guard analysis (Layer 3).

Uses Joern CPG queries to verify guard–data-flow binding when the
intraprocedural heuristic (condition_binding.py) cannot resolve aliases,
struct fields, or indirect flows.

Also provides interprocedural guard lookup: checks whether callers of a
function guard the call site, so an apparently-unguarded sink in a callee
might be adequately protected at every call site.

Requires a running Joern server (packages.joern.server.JoernServer).
Gracefully no-ops when unavailable — all public functions accept an
optional ``joern_server`` parameter and return empty/fallback results
when None.

From Yamaguchi et al. (IEEE S&P 2014):
  "A statement sanitizes a variable only if the variable is
   data-dependent on the sanitizer's output AND the sanitizer
   dominates the sink in the CFG."
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from .condition_extraction import SinkGuard

logger = logging.getLogger(__name__)

_ADMIN_RE = re.compile(
    r"\b(?:admin|superuser|staff|owner)", re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class CpgGuardResult:
    """Result of CPG-based guard relevance check."""

    sink_file: str
    sink_line: int
    sink_api: str
    guard_text: str
    # Does the guard operate on a variable on the data-dependency path?
    data_dep_bound: bool | None = None
    # Does the guard dominate the sink in the CFG?
    dominates_sink: bool | None = None
    # Identifiers on the taint path that the guard references
    tainted_vars_in_guard: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def verified_relevant(self) -> bool:
        """Guard is verified relevant: bound to taint path AND dominates."""
        return (
            self.data_dep_bound is True
            and self.dominates_sink is True
        )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "sink_file": self.sink_file,
            "sink_line": self.sink_line,
            "sink_api": self.sink_api,
            "guard_text": self.guard_text,
        }
        if self.data_dep_bound is not None:
            d["data_dep_bound"] = self.data_dep_bound
        if self.dominates_sink is not None:
            d["dominates_sink"] = self.dominates_sink
        if self.tainted_vars_in_guard:
            d["tainted_vars_in_guard"] = self.tainted_vars_in_guard
        if self.error:
            d["error"] = self.error
        return d


@dataclass
class CallerGuard:
    """A guard condition found at a caller site."""

    caller_file: str
    caller_function: str
    caller_line: int
    guard_text: str
    guard_category: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "caller_file": self.caller_file,
            "caller_function": self.caller_function,
            "caller_line": self.caller_line,
            "guard_text": self.guard_text,
            "guard_category": self.guard_category,
        }


@dataclass
class InterproceduralGuardResult:
    """Result of checking callers for guards."""

    callee_function: str
    callee_file: str
    total_callers: int
    guarded_callers: int
    unguarded_callers: int
    caller_guards: list[CallerGuard] = field(default_factory=list)
    all_callers_guarded: bool = False
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "callee_function": self.callee_function,
            "callee_file": self.callee_file,
            "total_callers": self.total_callers,
            "guarded_callers": self.guarded_callers,
            "unguarded_callers": self.unguarded_callers,
            "all_callers_guarded": self.all_callers_guarded,
        }
        if self.caller_guards:
            d["caller_guards"] = [cg.to_dict() for cg in self.caller_guards]
        if self.error:
            d["error"] = self.error
        return d


# ---------------------------------------------------------------------------
# Joern query builders — aligned with packages/joern API
# ---------------------------------------------------------------------------

# These produce CPGQL strings compatible with JoernServer.query().
# Use cpg.method.fullNameExact() for precise matching, or
# cpg.method.name() for substring matching. We use .name() here because
# sink_function is often just a bare name without package prefix.
#
# Query patterns validated against:
#   - callers: .caller.fullName.l
#   - guards:  .ast.isControlStructure.condition.code.l
#   - packages/joern/runner.py _build_taint_query: reachableByFlows


def _safe_name(value: str) -> str | None:
    """Validate and escape a name for Joern query interpolation.

    Returns the escaped string or None if the value is unsafe.
    """
    try:
        from packages.joern.runner import (
            _escape_scala_string,
            _validate_substitution_value,
        )
    except ImportError:
        # Fallback: basic validation
        if not value or not value.replace(".", "").replace("_", "").isalnum():
            return None
        # Reject control characters (codepoint < 0x20)
        if any(ord(ch) < 0x20 for ch in value):
            return None
        return value.replace("\\", "\\\\").replace('"', '\\"')

    if not _validate_substitution_value(value):
        return None
    return _escape_scala_string(value)


def _build_guard_identifiers_query(
    method_name: str,
    guard_line: int,
) -> str | None:
    """Get identifiers used in a guard condition at a specific line."""
    safe = _safe_name(method_name)
    if safe is None:
        return None
    return (
        f'cpg.method.name("{safe}")'
        f".ast.isControlStructure"
        f".filter(_.lineNumber == Some({guard_line}))"
        f".condition.isIdentifier.name.l"
    )


def _build_sink_arg_identifiers_query(
    method_name: str,
    sink_line: int,
) -> str | None:
    """Get identifiers in a sink call's arguments at a specific line."""
    safe = _safe_name(method_name)
    if safe is None:
        return None
    return (
        f'cpg.method.name("{safe}")'
        f".ast.isCall"
        f".filter(_.lineNumber == Some({sink_line}))"
        f".argument.isIdentifier.name.l"
    )


def _build_taint_reaches_guard_query(
    method_name: str,
    sink_api: str,
) -> str | None:
    """Check if taint flows from method params through guards to the sink.

    Uses reachableByFlows — the gold standard from the Joern paper.
    If a taint flow passes through the guard's variables, the guard
    is on the data-dependency path.
    """
    safe_method = _safe_name(method_name)
    safe_sink = _safe_name(sink_api)
    if safe_method is None or safe_sink is None:
        return None
    return (
        "import io.joern.dataflowengineoss.queryengine.{EngineConfig, EngineContext}\n"
        "val ctx = EngineContext(config = EngineConfig(maxCallDepth = 2))\n"
        f'val src = cpg.method.name("{safe_method}").parameter\n'
        f'val sink = cpg.method.name("{safe_method}")'
        f'.ast.isCall.name("{safe_sink}").argument\n'
        f"sink.reachableByFlows(src)(ctx).l.flatMap(_.elements.map(_.code)).l"
    )


def _build_dominance_query(
    method_name: str,
    guard_line: int,
    sink_line: int,
) -> str | None:
    """Check if a guard node dominates the sink in the CFG.

    Joern's .dominates traversal walks the dominator tree.
    """
    safe = _safe_name(method_name)
    if safe is None:
        return None
    return (
        f'cpg.method.name("{safe}")'
        f".ast.isControlStructure"
        f".filter(_.lineNumber == Some({guard_line}))"
        f".dominates"
        f".filter(_.lineNumber == Some({sink_line}))"
        f".l"
    )


def _build_callers_query(function_name: str) -> str | None:
    """Find all callers of a function.

    Uses .caller (not .callIn) — resolves to the calling METHOD
    rather than the call site node.
    """
    safe = _safe_name(function_name)
    if safe is None:
        return None
    return (
        f'cpg.method.name("{safe}")'
        f".caller"
        f".map(m => (m.filename, m.name, m.lineNumber.getOrElse(0)))"
        f".l"
    )


def _build_caller_guards_query(
    caller_method: str,
    call_line: int,
) -> str | None:
    """Find guard conditions enclosing a call site in a caller.

    Pattern:
    .ast.isControlStructure.controlStructureType("IF").condition.code.l
    """
    safe = _safe_name(caller_method)
    if safe is None:
        return None
    return (
        f'cpg.method.name("{safe}")'
        f".ast.isCall"
        f".filter(_.lineNumber == Some({call_line}))"
        f'.inAst.filter(_.isControlStructure).where(_.controlStructureType("IF"))'
        f".condition.code.l"
    )


# ---------------------------------------------------------------------------
# Main API: CPG guard relevance
# ---------------------------------------------------------------------------


def verify_guard_relevance_cpg(
    sink_guard: SinkGuard,
    *,
    joern_server: Any | None = None,
) -> list[CpgGuardResult]:
    """Verify guard relevance via Joern CPG queries.

    For each guard condition, checks:
    1. Are identifiers in the guard on the data-dependency path to the sink?
       Uses reachableByFlows for precise data-flow tracking (not just
       identifier name overlap).
    2. Does the guard dominate the sink in the CFG?

    Args:
        joern_server: A packages.joern.server.JoernServer instance
            (must have a CPG loaded). Pass None to get empty results.

    Returns empty list if Joern is unavailable.
    """
    from .safety_contract import assert_boost_only
    assert_boost_only("condition_cpg")

    if joern_server is None:
        return []

    results: list[CpgGuardResult] = []

    for guard in sink_guard.guards:
        result = CpgGuardResult(
            sink_file=sink_guard.sink_file,
            sink_line=sink_guard.sink_line,
            sink_api=sink_guard.sink_api,
            guard_text=guard.text,
        )

        try:
            # Strategy 1: Use reachableByFlows to get the taint path elements.
            # If any element on the taint path is at the guard's line, the
            # guard is definitively on the data-flow path.
            taint_query = _build_taint_reaches_guard_query(
                sink_guard.sink_function,
                sink_guard.sink_api,
            )
            if taint_query is not None:
                taint_result = _run_query(joern_server, taint_query)
                if taint_result:
                    from .condition_binding import extract_identifiers
                    guard_idents = extract_identifiers(guard.text)
                    taint_codes = set(taint_result)
                    taint_idents: set[str] = set()
                    for code in taint_codes:
                        taint_idents.update(extract_identifiers(str(code)))
                    overlap = guard_idents & taint_idents
                    result.data_dep_bound = bool(overlap)
                    result.tainted_vars_in_guard = sorted(overlap)

            # Strategy 2 (fallback): identifier overlap between guard and sink args
            if result.data_dep_bound is None:
                guard_q = _build_guard_identifiers_query(
                    sink_guard.sink_function, guard.line,
                )
                sink_q = _build_sink_arg_identifiers_query(
                    sink_guard.sink_function, sink_guard.sink_line,
                )
                if guard_q and sink_q:
                    guard_idents_cpg = _run_query(joern_server, guard_q)
                    sink_idents_cpg = _run_query(joern_server, sink_q)
                    if guard_idents_cpg and sink_idents_cpg:
                        overlap = set(guard_idents_cpg) & set(sink_idents_cpg)
                        result.data_dep_bound = bool(overlap)
                        result.tainted_vars_in_guard = sorted(overlap)
                    elif guard_idents_cpg is None or sink_idents_cpg is None:
                        result.error = "query returned no results"

            # Strategy 3: Dominance check
            dom_query = _build_dominance_query(
                sink_guard.sink_function,
                guard.line,
                sink_guard.sink_line,
            )
            if dom_query is not None:
                dom_result = _run_query(joern_server, dom_query)
                if dom_result is not None:
                    result.dominates_sink = len(dom_result) > 0

        except Exception as e:  # noqa: BLE001 — advisory CPG check: record and degrade
            result.error = str(e)
            logger.debug(
                "CPG guard check failed for %s:%d: %s",
                sink_guard.sink_file, sink_guard.sink_line, e,
            )

        results.append(result)

    return results


# ---------------------------------------------------------------------------
# Interprocedural guard lookup
# ---------------------------------------------------------------------------


def check_interprocedural_guards(
    function_name: str,
    file_path: str,
    *,
    joern_server: Any | None = None,
    source_map: dict[str, str] | None = None,
) -> InterproceduralGuardResult:
    """Check whether all callers of a function guard the call site.

    If Joern is available, queries the CPG for callers and their guards.
    Falls back to a simpler grep + condition_extraction heuristic when
    only source_map is available.

    Args:
        function_name: The callee function to check.
        file_path: Path to the callee's file.
        joern_server: A packages.joern.server.JoernServer instance.
        source_map: Optional map of filepath → source for fallback analysis.
    """
    from .safety_contract import assert_boost_only
    assert_boost_only("condition_cpg")

    if joern_server is None:
        return _fallback_interprocedural(function_name, file_path, source_map)

    try:
        callers_query = _build_callers_query(function_name)
        if callers_query is None:
            return InterproceduralGuardResult(
                callee_function=function_name,
                callee_file=file_path,
                total_callers=0,
                guarded_callers=0,
                unguarded_callers=0,
                error=f"invalid function name: {function_name!r}",
            )

        callers = _run_query(joern_server, callers_query)

        if not callers:
            return InterproceduralGuardResult(
                callee_function=function_name,
                callee_file=file_path,
                total_callers=0,
                guarded_callers=0,
                unguarded_callers=0,
                all_callers_guarded=False,
            )

        caller_guards: list[CallerGuard] = []
        guarded = 0
        unguarded = 0

        for caller_info in callers:
            if not isinstance(caller_info, (list, tuple)) or len(caller_info) < 3:
                unguarded += 1
                continue
            caller_file, caller_func, caller_line = (
                caller_info[0], caller_info[1], caller_info[2]
            )

            guards_query = _build_caller_guards_query(
                str(caller_func), int(caller_line) if caller_line is not None else 0,
            )
            if guards_query is None:
                unguarded += 1
                continue

            guard_texts = _run_query(joern_server, guards_query)

            if guard_texts:
                guarded += 1
                for gt in guard_texts:
                    category = _classify_guard_text(str(gt))
                    caller_guards.append(CallerGuard(
                        caller_file=str(caller_file),
                        caller_function=str(caller_func),
                        caller_line=int(caller_line) if caller_line is not None else 0,
                        guard_text=str(gt),
                        guard_category=category,
                    ))
            else:
                unguarded += 1

        total = guarded + unguarded
        return InterproceduralGuardResult(
            callee_function=function_name,
            callee_file=file_path,
            total_callers=total,
            guarded_callers=guarded,
            unguarded_callers=unguarded,
            caller_guards=caller_guards,
            all_callers_guarded=(unguarded == 0 and total > 0),
        )

    except Exception as e:  # noqa: BLE001 — advisory check: degrade to unknown
        logger.debug("interprocedural guard check failed: %s", e)
        return InterproceduralGuardResult(
            callee_function=function_name,
            callee_file=file_path,
            total_callers=0,
            guarded_callers=0,
            unguarded_callers=0,
            error=str(e),
        )


# ---------------------------------------------------------------------------
# Framework exposure context
# ---------------------------------------------------------------------------


@dataclass
class ExposureContext:
    """How exposed a sink is based on entry-point framework context."""

    sink_file: str
    sink_line: int
    sink_api: str
    entry_point_route: str = ""
    requires_auth: bool = False
    exposure_level: str = "unknown"  # public, authenticated, admin, internal

    @property
    def priority_adjustment(self) -> float:
        """Priority adjustment based on exposure.

        Public endpoints increase priority; admin-only reduce it.
        """
        adjustments = {
            "public": 0.2,
            "unknown": 0.0,
            "authenticated": -0.1,
            "admin": -0.2,
            "internal": -0.3,
        }
        return adjustments.get(self.exposure_level, 0.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sink_file": self.sink_file,
            "sink_line": self.sink_line,
            "sink_api": self.sink_api,
            "entry_point_route": self.entry_point_route,
            "requires_auth": self.requires_auth,
            "exposure_level": self.exposure_level,
            "priority_adjustment": self.priority_adjustment,
        }


def assess_exposure_context(
    sink_guard: SinkGuard,
    entry_points: list[dict[str, Any]],
    reachability: dict[str, list[str]] | None = None,
) -> ExposureContext | None:
    """Assess a sink's exposure level from entry-point annotations.

    Connects the guard analysis to the /understand --map context:
    a sink reachable only from @admin_required endpoints is lower
    priority than one on a public unauthenticated route.

    Args:
        sink_guard: The sink to assess.
        entry_points: Entry points from context-map (with decorators, auth info).
        reachability: Map of function → reachable entry points.
    """
    reaching_eps: list[dict[str, Any]] = []

    if reachability:
        reach_key = f"{sink_guard.sink_file}:{sink_guard.sink_function}"
        reaching_names = reachability.get(reach_key, [])
        for ep in entry_points:
            ep_key = f"{ep.get('file', '')}:{ep.get('name', '')}"
            if ep_key in reaching_names or ep.get("name") in reaching_names:
                reaching_eps.append(ep)
    else:
        # Heuristic: same file = likely reachable
        for ep in entry_points:
            if ep.get("file") == sink_guard.sink_file:
                reaching_eps.append(ep)

    if not reaching_eps:
        return None

    # Determine highest exposure level among reaching entry points
    exposure_levels: set[str] = set()

    for ep in reaching_eps:
        decorators = ep.get("decorators", [])
        auth_decorators = ep.get("auth_decorators", [])
        auth_required = ep.get("auth_required", False)

        if auth_required or auth_decorators:
            is_admin = any(
                _ADMIN_RE.search(str(d))
                for d in (auth_decorators or decorators)
            )
            if is_admin:
                exposure_levels.add("admin")
            else:
                exposure_levels.add("authenticated")
        elif ep.get("internal", False):
            exposure_levels.add("internal")
        else:
            exposure_levels.add("public")

    # Worst (most exposed) wins
    level_order = ["public", "authenticated", "admin", "internal"]
    exposure = "unknown"
    for lvl in level_order:
        if lvl in exposure_levels:
            exposure = lvl
            break

    best_ep = reaching_eps[0]
    return ExposureContext(
        sink_file=sink_guard.sink_file,
        sink_line=sink_guard.sink_line,
        sink_api=sink_guard.sink_api,
        entry_point_route=best_ep.get("route", best_ep.get("name", "")),
        requires_auth="authenticated" in exposure_levels or "admin" in exposure_levels,
        exposure_level=exposure,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_query(server: Any, query: str) -> list | None:
    """Run a Joern query and return parsed results as a list.

    Compatible with packages.joern.server.JoernServer.query() which
    returns a JoernResult with .raw_output (string) and .ok (bool).
    For list queries (.l), the raw output is a Scala list representation
    that we parse. For simple queries, returns the raw lines.
    """
    try:
        result = server.query(query)

        # JoernResult protocol (packages/joern/models.py)
        if hasattr(result, "ok"):
            if not result.ok:
                return None
            raw = getattr(result, "raw_output", "")
            if not raw or raw.strip() == "List()":
                return []
            return _parse_scala_list(raw)

        # Direct list return (mock servers in tests)
        if isinstance(result, list):
            return result
        return None

    except (TimeoutError, KeyboardInterrupt):
        raise
    except Exception as e:  # noqa: BLE001 — advisory query: degrade to no answer
        logger.debug("Joern query failed: %s — %s", query[:80], e)
        return None


def _split_scala_items(text: str) -> list:
    """Split comma-separated items, respecting double-quoted strings."""
    items: list[str] = []
    current: list[str] = []
    in_quotes = False
    for ch in text:
        if ch == '"' and not in_quotes:
            in_quotes = True
            continue
        if ch == '"' and in_quotes:
            in_quotes = False
            continue
        if ch == ',' and not in_quotes:
            items.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    tail = "".join(current).strip()
    if tail:
        items.append(tail)
    return items


def _parse_scala_list(raw: str) -> list:
    """Best-effort parse of Joern's Scala list output.

    Handles:
    - List(a, b, c) → ["a", "b", "c"]
    - List((a, b, 1), (c, d, 2)) → [["a", "b", "1"], ["c", "d", "2"]]
    - Simple newline-separated values
    """
    raw = raw.strip()
    if raw.startswith("List(") and raw.endswith(")"):
        inner = raw[5:-1].strip()
        if not inner:
            return []
        # Tuple list: List((a, b), (c, d))
        if inner.startswith("("):
            tuples = []
            depth = 0
            current = ""
            for ch in inner:
                if ch == "(":
                    depth += 1
                    if depth == 1:
                        current = ""
                        continue
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        tuples.append(_split_scala_items(current))
                        current = ""
                        continue
                if depth >= 1:
                    current += ch
            return tuples
        # Simple list: List(a, b, c) — handle commas inside quoted strings
        return _split_scala_items(inner)

    # Newline-separated fallback
    lines = [ln.strip() for ln in raw.split("\n") if ln.strip()]
    return lines


def _classify_guard_text(text: str) -> str:
    """Quick classification of guard text from CPG query results."""
    try:
        from .condition_classifier import classify_condition
        return classify_condition(text)
    except ImportError:
        return "unknown"


def _fallback_interprocedural(
    function_name: str,
    file_path: str,
    source_map: dict[str, str] | None,
) -> InterproceduralGuardResult:
    """Fallback interprocedural check using grep + condition_extraction.

    Without Joern, we can still do basic caller checking by:
    1. Grep for calls to the function across the source map
    2. Extract guards at those call sites using condition_extraction
    """
    if not source_map:
        return InterproceduralGuardResult(
            callee_function=function_name,
            callee_file=file_path,
            total_callers=0,
            guarded_callers=0,
            unguarded_callers=0,
            error="no source map and no Joern server",
        )

    import re

    from .condition_extraction import extract_sink_guards, language_for_file

    call_pattern = re.compile(
        rf"\b{re.escape(function_name)}\s*\(",
    )

    caller_guards: list[CallerGuard] = []
    guarded = 0
    unguarded = 0

    for fp, source in source_map.items():
        if fp == file_path:
            continue
        lang = language_for_file(fp)
        if not lang:
            continue

        for i, line in enumerate(source.split("\n"), 1):
            if call_pattern.search(line):
                guards = extract_sink_guards(
                    source, fp, sink_lines=[i],
                )
                if guards and guards[0].guards:
                    guarded += 1
                    for g in guards[0].guards:
                        caller_guards.append(CallerGuard(
                            caller_file=fp,
                            caller_function="<detected>",
                            caller_line=i,
                            guard_text=g.text,
                            guard_category=g.category,
                        ))
                else:
                    unguarded += 1

    total = guarded + unguarded
    return InterproceduralGuardResult(
        callee_function=function_name,
        callee_file=file_path,
        total_callers=total,
        guarded_callers=guarded,
        unguarded_callers=unguarded,
        caller_guards=caller_guards,
        all_callers_guarded=(unguarded == 0 and total > 0),
    )
