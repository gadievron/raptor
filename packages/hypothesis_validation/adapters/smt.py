"""SMT adapter — hypothesis validation via path-condition feasibility.

SMT is the right tool when the hypothesis is "this path is reachable
under these constraints" or "these branch conditions are mutually
exclusive". The LLM expresses constraints as line-separated text in
the syntax that packages/codeql/smt_path_validator accepts:

    size > 0
    offset + length <= buffer_size
    flags & 0x1 == 0
    count * 16 < max_alloc

The adapter feeds those into Z3 and reports satisfiability:

    sat       — there exist concrete inputs that satisfy all constraints.
                For "is this path reachable" hypotheses → CONFIRMED, with
                the model values surfaced as match details.
    unsat     — constraints are mutually exclusive, no input can satisfy
                them. For "is this path reachable" hypotheses → REFUTED.
                The unsat core names the conflicting constraints.
    unknown   — Z3 unavailable, all constraints unparseable, or solver
                timed out. The runner converts to inconclusive.

Different from the other adapters: there is no source code being scanned.
The "matches" are Z3 model values (concrete input bytes that trigger the
path). The `target` argument is informational only.

Research basis: SAILOR (arXiv:2604.06506) used SMT to validate LLM-
identified suspicious paths, achieving 379 vulnerabilities found vs 12
for pure-agentic approaches.
"""

from pathlib import Path
from typing import Dict, List, Optional

from packages.codeql.smt_path_validator import (
    PathCondition,
    PathSMTResult,
    check_path_feasibility,
)

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
        from core.smt_solver import z3_available  # type: ignore
        return z3_available()
    except Exception:
        return False


class SMTAdapter(ToolAdapter):
    """Adapter wrapping packages/codeql/smt_path_validator for hypothesis validation.

    Args:
        bv_profile: Optional BVProfile from core.smt_solver. Defaults to
            BV_C_UINT64 (matches sizes/offsets/counts). Pass BV_C_UINT32
            for CWE-190 wraparound paths, BV_C_INT32 for signed integer
            conditions.
    """

    def __init__(self, bv_profile=None):
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
                "Anything not expressible in linear bit-vector arithmetic",
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
        env: Optional[Dict[str, str]] = None,
    ) -> ToolEvidence:
        """Check satisfiability of LLM-generated path conditions.

        The `target` and `env` arguments are accepted for protocol
        uniformity but ignored — SMT operates on the constraint text only.
        `timeout` is also ignored at present (Z3 has its own internal
        timeout via DEFAULT_TIMEOUT_MS in core.smt_solver).
        """
        if not self.is_available():
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error="z3-solver is not installed",
            )

        conditions = _parse_conditions(rule)
        if not conditions:
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error="no parseable conditions in rule",
            )

        try:
            profile = self._profile()
            result: PathSMTResult = check_path_feasibility(
                conditions, profile=profile,
            )
        except Exception as e:
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error=f"SMT solver error: {e}",
            )

        if result.feasible is None:
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error=result.reasoning or "SMT verdict unknown",
            )

        # Build evidence. For sat (feasible=True), expose the witness as
        # "matches" — each model entry is a concrete input value. For unsat
        # (feasible=False), there are no matches; success=True with empty
        # matches means refuted.
        matches: List[Dict] = []
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
            summary = "unsat — constraints are mutually exclusive"

        return ToolEvidence(
            tool=self.name,
            rule=rule,
            success=True,
            matches=matches,
            summary=summary,
        )

    def _profile(self):
        if self._bv_profile is not None:
            return self._bv_profile
        # Lazy import to avoid hard-failing when core.smt_solver is
        # unavailable. The is_available() gate above ensures we only
        # reach this when Z3 (and the smt_solver package) are present.
        from core.smt_solver import BV_C_UINT64
        return BV_C_UINT64


def _parse_conditions(rule: str) -> List[PathCondition]:
    """Convert the LLM's line-separated constraint text into PathCondition objects.

    Format:
        # comment        — ignored
        text             — constraint that must hold
        ! text           — constraint that must NOT hold (negated)
        <blank>          — ignored
    """
    conditions: List[PathCondition] = []
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
                continue
        conditions.append(PathCondition(
            text=line, step_index=idx, negated=negated,
        ))
    return conditions
