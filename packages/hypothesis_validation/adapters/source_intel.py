"""Source_intel adapter — hypothesis validation via pre-computed
cocci-derived structural evidence.

Different shape from the other adapters in this package: the LLM does
NOT supply a tool-native rule. Instead, the "rule" is a small JSON
query that selects which slice of RAPTOR's pre-computed
:class:`~packages.source_intel.SourceIntelResult` to surface as
matches. The shipped cocci rules (~34 across 7 axes) ran ahead of
time; this adapter exposes their results.

Why a separate adapter:
  * Hypothesis-validation flows benefit from RAPTOR's curated cocci
    rules without the LLM having to author SmPL (which it generally
    does poorly — wrong metavar shapes, missing position binds, etc.).
  * The :class:`~packages.hypothesis_validation.adapters.coccinelle.CoccinelleAdapter`
    still ships, and the two coexist: LLM-authored hypotheses use the
    coccinelle adapter; pre-computed KB lookups use source_intel.

Query shape (JSON in ``rule`` parameter)::

    {
      "function": "tcp_v4_send_reset",      // required — sink fn name
      "axes": ["attrs", "aborts", "allocations"],  // optional, default ALL
      "kind": "warn_unused_result",         // optional, attrs filter
      "file": "net/ipv4/tcp_ipv4.c"          // optional, location filter
    }

Output: ``ToolEvidence`` with ``matches`` populated as one entry per
observation that satisfies the query. Each match is a dict with
``file``, ``line``, ``axis``, ``message`` keys + axis-specific fields.

Caching: identical to :func:`packages.source_intel.llm_bridge.make_source_intel_collector`
— constructor takes a :class:`SourceIntelCache` which is consulted
before invoking spatch. Operators share one cache across all hypotheses
in a run so spatch runs once per target.

Security: this adapter does NOT execute LLM-supplied code. The "rule"
JSON is parsed into the query shape above with strict field
validation; unknown / extra fields are rejected. No spatch
``@script:`` risk path because the rules running here are
RAPTOR-shipped, not LLM-generated.
"""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .base import ToolAdapter, ToolCapability, ToolEvidence


# Closed enum of axes operators may request. Mirrors the axis layout
# under engine/coccinelle/source_intel/. ``compile_time`` is separate
# from ``attrs`` so a query for ``no_sanitize`` doesn't fall under the
# attribute interpretation rules.
_VALID_AXES: Set[str] = {
    "attrs",          # axis 1
    "aborts",         # axis 2 — abort-class call proximity
    "allocations",    # axis 3 — unchecked alloc / paired free / double free
    "privilege",      # axis 4 — capability checks, lsm, cred manipulation
    "variants",       # axis 5 — checked alloc, structural fingerprints
    "build_flags",    # axis 6 — FORTIFY_SOURCE, -fstack-protector, etc.
    "hazards",        # axis 7 — deprecated calls, signed alloc, unsafe temp
}

_VALID_KEYS = {"function", "axes", "kind", "file"}


_SYNTAX_EXAMPLE = """\
// SourceIntelAdapter takes a JSON query, not an SmPL rule:
{
  "function": "tcp_v4_send_reset",
  "axes": ["attrs", "aborts", "allocations"]
}
// Or to scope by attribute kind:
{
  "function": "kmalloc",
  "axes": ["attrs"],
  "kind": "warn_unused_result"
}
// `axes` is optional; omitting it queries every axis."""


class SourceIntelAdapter(ToolAdapter):
    """Adapter exposing source_intel's pre-computed KB to hypothesis
    validation.

    Args:
        cache: Shared :class:`~packages.source_intel.SourceIntelCache`.
            When supplied, spatch runs once per (target, rules_hash)
            and every adapter call reads from cache. When ``None``,
            every call re-runs spatch (do not do this for production).
        sandbox: Whether the underlying spatch invocation runs in a
            network-blocked sandbox. Default ``True``. Passed through
            via :func:`packages.source_intel.analyze.analyze` — that
            function is itself the sandboxed entry point.
    """

    def __init__(self, *, cache: Optional[Any] = None, sandbox: bool = True):
        self._cache = cache
        self._sandbox = sandbox

    @property
    def name(self) -> str:
        return "source_intel"

    def is_available(self) -> bool:
        try:
            from packages.coccinelle import is_available
            return is_available()
        except ImportError:
            return False

    def describe(self) -> ToolCapability:
        return ToolCapability(
            name=self.name,
            good_for=[
                "Looking up function-attribute annotations "
                "(warn_unused_result, nonnull, returns_nonnull, "
                "alloc_size, malloc, noreturn, no_stack_protector, "
                "access, counted_by, nodiscard, deprecated, pure, const)",
                "Checking proximity of abort-class calls to a sink "
                "(panic, BUG, abort, assert) with grade "
                "(dominates / same_path / same_function)",
                "Allocation back-walk and unchecked-alloc / paired-free / "
                "double-free observations for memory-corruption findings",
                "Privilege gradient: capability_check, LSM hooks, "
                "credential manipulation, setuid/setgid call sites",
                "Build-flag context: FORTIFY_SOURCE level, "
                "-fstack-protector, -fdelete-null-pointer-checks, "
                "active sanitizers",
                "Hazard signals: deprecated unsafe calls "
                "(strcpy/sprintf/gets/...), signed alloc, type-confusion "
                "casts, unsafe temp-file calls",
            ],
            bad_for=[
                "Languages other than C/C++ — coccinelle parses C only.",
                "Author-defined patterns not in RAPTOR's shipped rules "
                "— use the coccinelle adapter for LLM-authored SmPL.",
                "Path satisfiability / SMT — use smt adapter.",
                "Inter-procedural dataflow — use codeql.",
            ],
            syntax_example=_SYNTAX_EXAMPLE,
            languages=["c", "cpp"],
        )

    def run(
        self,
        rule: str,
        target: Path,
        *,
        timeout: int = 300,
        env: Optional[Dict[str, str]] = None,
    ) -> ToolEvidence:
        """Execute a structured KB query against source_intel.

        ``rule`` must parse as JSON with the shape documented at module
        level. ``timeout`` and ``env`` are accepted for ToolAdapter
        signature compatibility but ignored — caching makes the
        spatch invocation amortise across all adapter calls in a run.
        """
        if not rule or not rule.strip():
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error="empty rule (expected JSON query object)",
            )
        try:
            query = json.loads(rule)
        except json.JSONDecodeError as e:
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error=f"rule is not valid JSON: {e}",
            )
        if not isinstance(query, dict):
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error=(
                    "rule JSON must be an object with at least a "
                    "'function' field"
                ),
            )
        extra = set(query.keys()) - _VALID_KEYS
        if extra:
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error=(
                    f"unknown query field(s): {sorted(extra)} — valid: "
                    f"{sorted(_VALID_KEYS)}"
                ),
            )
        function_name = query.get("function")
        if not function_name or not isinstance(function_name, str):
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error="query missing required 'function' (string)",
            )
        axes_req = query.get("axes")
        if axes_req is None:
            axes_req = sorted(_VALID_AXES)
        if not isinstance(axes_req, list) or not all(
            isinstance(a, str) for a in axes_req
        ):
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error="'axes' must be a list of strings",
            )
        bad_axes = set(axes_req) - _VALID_AXES
        if bad_axes:
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error=(
                    f"unknown axis name(s): {sorted(bad_axes)} — valid: "
                    f"{sorted(_VALID_AXES)}"
                ),
            )
        kind_filter = query.get("kind")
        file_filter = query.get("file")

        if not self.is_available():
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error="spatch is not installed",
            )

        result = self._load_result(target)

        if result.is_skipped:
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error=f"source_intel skipped: {result.skipped_reason}",
            )

        matches: List[Dict[str, Any]] = []
        for axis in axes_req:
            matches.extend(
                self._collect_axis(
                    axis=axis,
                    result=result,
                    function_name=function_name,
                    kind_filter=kind_filter,
                    file_filter=file_filter,
                    target=target,
                )
            )

        n = len(matches)
        files = sorted({m["file"] for m in matches if m.get("file")})
        summary = (
            f"{n} match{'es' if n != 1 else ''} for {function_name} "
            f"across {len(axes_req)} axis{'es' if len(axes_req) != 1 else ''} "
            f"in {len(files)} file{'s' if len(files) != 1 else ''}"
            if n
            else f"no source_intel observation matches {function_name}"
        )

        return ToolEvidence(
            tool=self.name,
            rule=rule,
            success=True,
            matches=matches,
            summary=summary,
        )

    # ---- internal --------------------------------------------------

    def _load_result(self, target: Path):
        """Return cached SourceIntelResult or run analyze."""
        import importlib
        analyze_mod = importlib.import_module(
            "packages.source_intel.analyze"
        )
        if self._cache is not None:
            cached = self._cache.get(target)
            if cached is not None:
                return cached
        result = analyze_mod.analyze(target)
        if self._cache is not None:
            self._cache.put(target, None, result)
        return result

    def _collect_axis(
        self,
        *,
        axis: str,
        result,
        function_name: str,
        kind_filter: Optional[str],
        file_filter: Optional[str],
        target: Path,
    ) -> List[Dict[str, Any]]:
        """Materialise one axis's observations matching the query."""
        out: List[Dict[str, Any]] = []

        if axis == "attrs":
            for ev in result.attributes:
                if ev.function_name != function_name:
                    continue
                if kind_filter is not None and ev.kind != kind_filter:
                    continue
                file_path = ev.location[0]
                if file_filter and not file_path.endswith(file_filter):
                    continue
                out.append({
                    "axis": axis,
                    "file": file_path,
                    "line": ev.location[1],
                    "kind": ev.kind,
                    "function": ev.function_name,
                    "match_source": ev.match_source,
                    "conditional_on": ev.conditional_on,
                    "message": (
                        f"attr:{ev.kind} on {ev.function_name} "
                        f"({ev.match_source})"
                    ),
                })

        elif axis == "aborts":
            for ab in result.aborts:
                if ab.enclosing_function not in (function_name, None):
                    continue
                file_path = ab.location[0]
                if file_filter and not file_path.endswith(file_filter):
                    continue
                out.append({
                    "axis": axis,
                    "file": file_path,
                    "line": ab.location[1],
                    "macro": ab.macro,
                    "grade": ab.grade,
                    "function": ab.enclosing_function,
                    "conditional_on": ab.conditional_on,
                    "message": (
                        f"abort:{ab.macro} grade={ab.grade} "
                        f"near {ab.enclosing_function or '?'}"
                    ),
                })

        elif axis == "allocations":
            for ae in result.allocations:
                if ae.enclosing_function not in (function_name, None):
                    continue
                file_path = ae.location[0]
                if file_filter and not file_path.endswith(file_filter):
                    continue
                out.append({
                    "axis": axis,
                    "file": file_path,
                    "line": ae.location[1],
                    "allocator": ae.allocator,
                    "target_field": ae.target_field,
                    "function": ae.enclosing_function,
                    "conditional_on": ae.conditional_on,
                    "message": (
                        f"unchecked-alloc {ae.allocator} → "
                        f"{ae.target_field or '<location>'} "
                        f"in {ae.enclosing_function or '?'}"
                    ),
                })
            # double-frees and paired-frees attach to the same axis.
            for df in getattr(result, "double_frees", ()):
                if df.enclosing_function not in (function_name, None):
                    continue
                file_path = df.location[0]
                if file_filter and not file_path.endswith(file_filter):
                    continue
                out.append({
                    "axis": axis,
                    "kind": "double_free",
                    "file": file_path,
                    "line": df.location[1],
                    "function": df.enclosing_function,
                    "message": (
                        f"double-free in {df.enclosing_function or '?'}"
                    ),
                })

        elif axis == "privilege":
            for cap in getattr(result, "capabilities", ()):
                if cap.enclosing_function not in (function_name, None):
                    continue
                file_path = cap.location[0]
                if file_filter and not file_path.endswith(file_filter):
                    continue
                out.append({
                    "axis": axis,
                    "file": file_path,
                    "line": cap.location[1],
                    "capability": getattr(cap, "capability", None),
                    "grade": getattr(cap, "grade", None),
                    "function": cap.enclosing_function,
                    "message": (
                        f"cap:{getattr(cap, 'capability', '?')} "
                        f"in {cap.enclosing_function or '?'}"
                    ),
                })

        elif axis == "hazards":
            for hz in getattr(result, "hazards", ()):
                if hz.enclosing_function not in (function_name, None):
                    continue
                file_path = hz.location[0]
                if file_filter and not file_path.endswith(file_filter):
                    continue
                out.append({
                    "axis": axis,
                    "file": file_path,
                    "line": hz.location[1],
                    "hazard_kind": getattr(hz, "kind", None),
                    "detail": getattr(hz, "detail", None),
                    "function": hz.enclosing_function,
                    "message": (
                        f"hazard:{getattr(hz, 'kind', '?')} in "
                        f"{hz.enclosing_function or '?'}"
                    ),
                })

        elif axis == "variants":
            # Variant signals attach to the result-level "variants"
            # tuple when present; absence means axis 5 didn't fire.
            for v in getattr(result, "variants", ()):
                # variants currently key by file/line; function filter
                # is best-effort against per-variant function field
                # when present.
                fn = getattr(v, "function", None)
                if fn is not None and fn != function_name:
                    continue
                loc = getattr(v, "location", None)
                file_path = loc[0] if loc else ""
                if file_filter and not file_path.endswith(file_filter):
                    continue
                out.append({
                    "axis": axis,
                    "file": file_path,
                    "line": loc[1] if loc else 0,
                    "variant_kind": getattr(v, "kind", None),
                    "function": fn,
                    "message": (
                        f"variant:{getattr(v, 'kind', '?')} "
                        f"in {fn or '?'}"
                    ),
                })

        elif axis == "build_flags":
            # Build-flags axis is not per-function; expose the target-
            # wide context once when the query touches this axis.
            try:
                from core.build.build_flags import extract_flags
                flags = extract_flags(target)
            except Exception:  # noqa: BLE001
                flags = None
            if flags is not None and flags.extraction_confidence != "absent":
                fields = (
                    asdict(flags) if is_dataclass(flags) else {}
                )
                out.append({
                    "axis": axis,
                    "file": "",
                    "line": 0,
                    "function": None,
                    "build_flags": fields,
                    "message": (
                        f"build-flags fortify={fields.get('fortify_source_level')} "
                        f"stack_protector={fields.get('stack_protector_level')} "
                        f"delete_null_pointer_checks="
                        f"{fields.get('delete_null_pointer_checks')} "
                        f"sanitizers={list(fields.get('sanitizers_enabled', ()))}"
                    ),
                })

        return out
