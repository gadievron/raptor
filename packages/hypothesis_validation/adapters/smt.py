"""SMT adapter — hypothesis validation via path-condition feasibility.

SMT is the right tool when the hypothesis is "this path is reachable
under these constraints" or "these branch conditions are mutually
exclusive". The LLM expresses constraints as line-separated text in
the syntax that core/smt_solver/path_feasibility accepts:

    size > 0
    offset + length <= buffer_size
    flags & 0x1 == 0
    count * 16 < max_alloc

The adapter feeds those into Z3 and reports satisfiability:

    sat       — there exist concrete inputs that satisfy all constraints.
                For "is this path reachable" hypotheses → CONFIRMED, with
                the model values surfaced as match details. Only reported
                when EVERY condition parsed — sat over a subset proves
                nothing about the full path, so partially-parsed sat is
                surfaced as a tool failure naming the dropped conditions.
    unsat     — constraints are mutually exclusive, no input can satisfy
                them. For "is this path reachable" hypotheses → REFUTED;
                for "these constraints are mutually exclusive / the path
                is infeasible" hypotheses → CONFIRMED. The evidence
                carries empty_matches_conclusive; the verdict DIRECTION
                is derived mechanically from the hypothesis's declared
                ``polarity`` (undeclared polarity fails closed to
                inconclusive rather than letting the evaluating LLM's
                phrasing-aware claim pick the label — see
                ``verdict.verdict_from``). Sound even when some
                conditions were dropped as unparseable.
    unknown   — Z3 unavailable, all constraints unparseable, or solver
                timed out. The runner converts to inconclusive.

Call heads do not establish callee contracts. Opaque-call SAT assignments
are conditional models, not verified call executions; call-dependent UNSAT
cores likewise cannot supply conclusive path evidence. Independent scalar
contradictions remain usable. Name-based call summaries are disabled.

Different from the other adapters: there is no source code being scanned.
The "matches" are values satisfying the supplied mathematical predicates;
they do not establish source execution. The `target` argument is
informational only.

"""

from pathlib import Path

from core.smt_solver.path_feasibility import (
    PathCondition,
    PathSMTResult,
    check_path_feasibility,
    check_path_feasibility_dual,
)

from core.smt_solver.session import query_budget

from .base import ToolAdapter, ToolCapability, ToolEvidence

_SYNTAX_EXAMPLE = """\
# Each non-empty line is a single path condition. Conditions must all
# hold simultaneously for the path to be reachable.
size > 0
size < 1024
offset + length > buffer_size
flags & 0x1 == 0

# Prefix a line with `!` to negate (the condition must be false):
! size == 0

# Comments start with #
"""


def _z3_available() -> bool:
    """Check whether Z3 is importable. Imported lazily to avoid forcing
    z3-solver as a hard dependency at import time."""
    try:
        from core.smt_solver import z3_available  # type: ignore[import-not-found]
        return z3_available()
    except Exception:  # noqa: BLE001 — optional dependency probe; any failure means "not available"
        return False


class SMTAdapter(ToolAdapter):
    """Adapter wrapping core/smt_solver/path_feasibility for hypothesis validation.

    Args:
        bv_profile: Optional BVProfile from core.smt_solver. Defaults to
            BV_C_UINT64 (matches sizes/offsets/counts). Pass BV_C_UINT32
            for CWE-190 wraparound paths, BV_C_INT32 for signed integer
            conditions.
    """

    def __init__(self, bv_profile=None) -> None:
        self._bv_profile = bv_profile  # resolved lazily — see _profile()

    @property
    def name(self) -> str:
        return "smt"

    def is_available(self) -> bool:
        return _z3_available()

    def describe(self) -> ToolCapability:
        return ToolCapability(
            name=self.name,
            good_for=[
                "Path feasibility ('is this set of branch conditions jointly satisfiable?')",
                "False-positive elimination on dataflow paths (unsat ⇒ unreachable)",
                "Concrete trigger-input synthesis for confirmed paths (Z3 witness)",
                "CWE-190 integer overflow / wraparound reasoning (use uint32 profile)",
                "CWE-129 array index sign/range checks",
            ],
            bad_for=[
                "Source-code scanning — SMT does not look at code",
                "String/regex patterns",
                "Pointer chasing or memory aliasing",
                "Unsupported predicate syntax or unmodeled source-language semantics",
            ],
            syntax_example=_SYNTAX_EXAMPLE,
            languages=[],  # language-agnostic
        )

    def run(
        self,
        rule: str,
        target: Path,
        *,
        timeout: int = 60,
        env: dict[str, str] | None = None,
    ) -> ToolEvidence:
        """Check satisfiability of LLM-generated path conditions.

        The `target` and `env` arguments are accepted for protocol
        uniformity but ignored — SMT operates on the constraint text only.
        `timeout` is a nonnegative integer in seconds. It shares a soft
        query budget across both profiles and optional solver subqueries,
        while retaining each factory solver's smaller per-query cap. It
        is not a process wall-time limit.
        """
        if type(timeout) is not int or timeout < 0:
            return ToolEvidence(tool=self.name, rule=rule, success=False,
                                error="timeout must be a nonnegative integer in seconds")
        if not self.is_available():
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error="z3-solver is not installed",
            )

        try:
            conditions = _parse_conditions(rule)
        except (ValueError, TypeError) as exc:
            return ToolEvidence(tool=self.name, rule=rule, success=False,
                                error=f"invalid SMT condition syntax: {exc}")
        if not conditions:
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error="no parseable conditions in rule",
            )

        try:
            profile = self._profile()
            # Signedness honesty: the default uint64 profile is a
            # GUESS — under it the ubiquitous signed error check
            # (``ret < 0``) encodes as ``ULT(ret, 0)``, unsat, so one
            # signedness-mismatched guard would refute (and thereby
            # confirm infeasibility for) a perfectly live path. When
            # the operator did not pin a profile, an unsat verdict is
            # honored only if BOTH signedness profiles agree
            # (check_path_feasibility_dual); a caller-supplied
            # bv_profile asserts known signedness and keeps the
            # cheaper single-profile check.
            check = (
                check_path_feasibility if self._bv_profile is not None
                else check_path_feasibility_dual
            )
            with query_budget(timeout * 1000):
                result: PathSMTResult = check(
                    conditions, profile=profile, use_call_summaries=False,
                )
        except Exception as e:  # noqa: BLE001 — solver failure becomes tool-evidence error, never a crash
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error=f"SMT solver error: {e}",
            )

        if result.feasible is True and result.anon_var_map:
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error="unbound call results: a conditional model is not a verified call execution",
            )

        # A profile does not bind a callee's identity or return type. A
        # conditional contradiction involving opaque call terms must not
        # become conclusive evidence about the hypothesized path.
        if (result.feasible is False and result.anon_var_map
                and result.refutation_uses_call_terms is not False):
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error="unbound call return types: encoded contradiction is conditional",
            )

        if result.feasible is None:
            reason = result.reasoning or "SMT verdict unknown"
            dropped = list(result.unknown or [])
            if dropped:
                shown = ", ".join(repr(c) for c in dropped[:5])
                more = f" (+{len(dropped) - 5} more)" if len(dropped) > 5 else ""
                reason += f"; {len(dropped)} unparseable condition(s): {shown}{more}"
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error=reason,
            )

        dropped = list(result.unknown or [])

        if result.feasible and dropped:
            # sat over a strict subset of the conditions is NOT proof
            # that the full path is feasible — adding back the dropped
            # (unparseable) conditions can only shrink the solution
            # space. Reporting the subset-sat as clean witness evidence
            # would let a hypothesis be graded confirmed on a
            # near-empty check, so surface it as a tool failure
            # (mechanically inconclusive) naming what was dropped.
            # The unsat side below stays sound under dropped
            # conditions: unsat over a subset implies unsat overall.
            shown = ", ".join(repr(c) for c in dropped[:5])
            more = f" (+{len(dropped) - 5} more)" if len(dropped) > 5 else ""
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error=(
                    f"sat over a partial constraint set only — "
                    f"{len(dropped)} of {len(conditions)} condition(s) "
                    f"dropped as unparseable: {shown}{more}; rephrase "
                    f"the dropped conditions in linear bit-vector form"
                ),
            )

        # Build evidence. For sat (feasible=True), expose the witness as
        # "matches" — each model entry is a concrete input value. For unsat
        # (feasible=False), there are no matches; the empty match list is
        # itself the tool's definitive result (see
        # empty_matches_conclusive below).
        matches: list[dict] = []
        if result.feasible and result.model:
            for var, value in sorted(result.model.items()):
                matches.append({
                    "file": str(target),
                    "line": 0,
                    "rule": "smt-witness",
                    "message": f"{var} = {value}",
                    "variable": var,
                    "value": value,
                })

        if result.feasible:
            n = len(matches)
            summary = (
                f"sat — {n} witness value{'s' if n != 1 else ''}"
                if matches else "sat — no model returned"
            )
        else:
            # Phrase both readings so the evaluating LLM can map the
            # proof onto the hypothesis's phrasing: unsat REFUTES a
            # reachability claim and CONFIRMS an infeasibility /
            # mutual-exclusivity claim.
            summary = (
                "unsat — constraints are mutually exclusive (refutes a "
                "reachability claim; confirms an infeasibility claim)"
            )
            if dropped:
                summary += (
                    f" — note: {len(dropped)} unparseable condition(s) "
                    f"were excluded (sound: unsat over a subset implies "
                    f"unsat over the whole set)"
                )

        return ToolEvidence(
            tool=self.name,
            rule=rule,
            success=True,
            matches=matches,
            summary=summary,
            # unsat is a definitive proof despite the empty match list.
            # The flag tells the verdict ladder this emptiness is a
            # tool result; the ladder then derives the verdict
            # direction from the hypothesis's declared polarity
            # (never from the LLM's post-hoc reading).
            empty_matches_conclusive=not result.feasible,
        )

    def _profile(self):
        if self._bv_profile is not None:
            return self._bv_profile
        # Lazy import to avoid hard-failing when core.smt_solver is
        # unavailable. The is_available() gate above ensures we only
        # reach this when Z3 (and the smt_solver package) are present.
        from core.smt_solver import BV_C_UINT64
        return BV_C_UINT64


def _parse_conditions(rule: str) -> list[PathCondition]:
    """Convert the LLM's line-separated constraint text into PathCondition objects.

    Format:
        # comment        — ignored
        text             — constraint that must hold
        ! text           — constraint that must NOT hold (negated)
        <blank>          — ignored
    """
    conditions: list[PathCondition] = []
    for idx, raw_line in enumerate(rule.splitlines()):
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            continue
        negated = False
        if line.startswith("!"):
            negated = True
            line = line[1:].strip()
            if not line:
                raise ValueError("negation requires a condition")
        conditions.append(PathCondition(
            text=line, step_index=idx, negated=negated,
        ))
    return conditions
