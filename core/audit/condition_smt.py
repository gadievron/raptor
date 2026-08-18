"""Constant-to-SMT bridge for guard sufficiency.

Bridges the concrete_values extracted by condition_extraction (Layer 0/2)
into Z3 SMT queries via the existing path_feasibility infrastructure.

Answers: "Given this guard checks `len < MAX_SIZE` where MAX_SIZE=1024,
and the sink is memcpy(dst, src, len) where dst is 256 bytes, is the
guard sufficient to prevent overflow?"

The key insight from the CPG paper: once you have CONCRETE values from
constant resolution, you can PROVE guard insufficiency mechanically.
A guard `if (n < 4096)` doesn't prevent overflow into a 256-byte buffer.
"""

from __future__ import annotations

import logging
import os
import pickle
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .condition_extraction import GuardCondition, SinkGuard

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Domain vocabulary — study-discovered operation pairs
# ---------------------------------------------------------------------------


@dataclass
class DomainVocabulary:
    """Project-specific API names extracted from domain-model.json.

    Built from ``paired_operations`` entries discovered by study-prep's
    Layer 1 transitive wrapper analysis.  Passed to mechanical checks so
    they use project vocabulary instead of only hardcoded seed names.

    ``lock_pairs`` preserves the exact acquire→release pairing (the
    name sets alone force a lossy heuristic re-pairing downstream).
    ``nullable_returns`` / ``auth_predicates`` / ``boundary_transfers``
    are populated from the corresponding domain-model keys when the
    study loop emits them, and by target-kind vocab packs
    (:mod:`core.audit.vocab_packs`).
    ``callback_registers`` / ``callback_cancels`` carry async-callback
    registration / cancellation verbs (timer, workqueue, notifier
    shapes) from ``paired_operations`` entries with a callback-family
    ``kind`` — consumed by :mod:`core.audit.callback_lifetime`.

    Vocabulary entries may be plain strings or dicts carrying a
    ``provenance`` tier (study receipts convention: verbatim /
    mechanical / llm_summarized / llm_prior). Entries whose provenance
    is ``llm_prior`` (training memory, no on-disk evidence) are not
    consumed.
    """

    allocators: frozenset = field(default_factory=frozenset)
    deallocators: frozenset = field(default_factory=frozenset)
    lock_acquires: frozenset = field(default_factory=frozenset)
    lock_releases: frozenset = field(default_factory=frozenset)
    lock_pairs: frozenset = field(default_factory=frozenset)
    refcount_gets: frozenset = field(default_factory=frozenset)
    refcount_puts: frozenset = field(default_factory=frozenset)
    callback_registers: frozenset = field(default_factory=frozenset)
    callback_cancels: frozenset = field(default_factory=frozenset)
    security_fields: frozenset = field(default_factory=frozenset)
    nullable_returns: frozenset = field(default_factory=frozenset)
    auth_predicates: frozenset = field(default_factory=frozenset)
    boundary_transfers: frozenset = field(default_factory=frozenset)

    def merged(self, other: DomainVocabulary) -> DomainVocabulary:
        """Union of two vocabularies (learned model + target pack)."""
        return DomainVocabulary(
            allocators=self.allocators | other.allocators,
            deallocators=self.deallocators | other.deallocators,
            lock_acquires=self.lock_acquires | other.lock_acquires,
            lock_releases=self.lock_releases | other.lock_releases,
            lock_pairs=self.lock_pairs | other.lock_pairs,
            refcount_gets=self.refcount_gets | other.refcount_gets,
            refcount_puts=self.refcount_puts | other.refcount_puts,
            callback_registers=(
                self.callback_registers | other.callback_registers
            ),
            callback_cancels=self.callback_cancels | other.callback_cancels,
            security_fields=self.security_fields | other.security_fields,
            nullable_returns=self.nullable_returns | other.nullable_returns,
            auth_predicates=self.auth_predicates | other.auth_predicates,
            boundary_transfers=(
                self.boundary_transfers | other.boundary_transfers
            ),
        )

    @classmethod
    def from_domain_model(
        cls, domain_model: dict[str, Any] | None,
        target_path: str | Path | None = None,
    ) -> DomainVocabulary:
        """Build from a domain model, merged with any target-kind pack.

        ``target_path`` gates the vocab packs: when the target looks
        like a Linux kernel tree, the kernel pack supplies the kernel
        API bulk that used to be hardcoded in the checkers. Without a
        domain model AND without a matching pack this returns the empty
        vocabulary (checkers fall back to their universal seeds).
        """
        vocab = cls._from_domain_model_only(domain_model)
        if target_path is not None:
            try:
                from .vocab_packs import pack_for_target
                pack = pack_for_target(target_path)
            except Exception:
                logger.debug("vocab pack load failed", exc_info=True)
                pack = None
            if pack is not None:
                vocab = vocab.merged(pack)
        return vocab

    @classmethod
    def _from_domain_model_only(
        cls, domain_model: dict[str, Any] | None,
    ) -> DomainVocabulary:
        if not domain_model:
            return cls()
        pairs = domain_model.get("paired_operations", [])

        alloc: set[str] = set()
        dealloc: set[str] = set()
        lock_acq: set[str] = set()
        lock_rel: set[str] = set()
        lock_pairs: set[tuple[str, str]] = set()
        ref_get: set[str] = set()
        ref_put: set[str] = set()
        cb_reg: set[str] = set()
        cb_cancel: set[str] = set()

        # Pair-kind aliases per vocabulary class. The study prompt
        # elicits the canonical kinds (alloc/lock/refcount/callback);
        # the aliases cover in-session-written domain models.
        _ALLOC_KINDS = ("alloc", "allocator")
        _REFCOUNT_KINDS = ("refcount",)
        _LOCK_KINDS = (
            "spinlock", "mutex", "rwlock", "rcu", "lock", "semaphore",
        )
        _CALLBACK_KINDS = (
            "callback", "register", "timer", "work", "workqueue",
            "tasklet", "hrtimer", "notifier",
        )
        _KIND_MAP: dict[str, tuple[set[str], set[str]]] = {}
        for kinds, buckets_for_kind in (
            (_ALLOC_KINDS, (alloc, dealloc)),
            (_REFCOUNT_KINDS, (ref_get, ref_put)),
            (_LOCK_KINDS, (lock_acq, lock_rel)),
            (_CALLBACK_KINDS, (cb_reg, cb_cancel)),
        ):
            for k in kinds:
                _KIND_MAP[k] = buckets_for_kind

        for pair in (pairs or []):
            if not isinstance(pair, dict) or not _entry_actionable(pair):
                continue
            acquire = pair.get("acquire", "")
            release = pair.get("release", "")
            kind = pair.get("kind", "").lower()
            if not acquire or not release:
                continue

            acq_name = acquire.split("(")[0].strip()
            rel_name = release.split("(")[0].strip()

            buckets = _KIND_MAP.get(kind)
            if buckets:
                buckets[0].add(acq_name)
                buckets[1].add(rel_name)
                if buckets[0] is lock_acq:
                    # Preserve the exact pairing the study discovered.
                    lock_pairs.add((acq_name, rel_name))

        sec_fields: set[str] = set()
        for key in (
            "security_fields", "security_attributes", "sensitive_fields",
        ):
            for entry in domain_model.get(key, []):
                name = _entry_name(entry)
                if name:
                    sec_fields.add(name)

        nullable: set[str] = set()
        for entry in domain_model.get("nullable_returns", []):
            name = _entry_name(entry)
            if name:
                nullable.add(name.split("(")[0].strip())

        auth: set[tuple[str, str]] = set()
        for entry in domain_model.get("auth_predicates", []):
            if isinstance(entry, str):
                auth.add((entry.split("(")[0].strip(), "domain"))
            elif (
                isinstance(entry, dict) and entry.get("name")
                and _entry_actionable(entry)
            ):
                auth.add((
                    str(entry["name"]).split("(")[0].strip(),
                    str(entry.get("kind", "domain")),
                ))

        return cls(
            allocators=frozenset(alloc),
            deallocators=frozenset(dealloc),
            lock_acquires=frozenset(lock_acq),
            lock_releases=frozenset(lock_rel),
            lock_pairs=frozenset(lock_pairs),
            refcount_gets=frozenset(ref_get),
            refcount_puts=frozenset(ref_put),
            callback_registers=frozenset(cb_reg),
            callback_cancels=frozenset(cb_cancel),
            security_fields=frozenset(sec_fields),
            nullable_returns=frozenset(nullable),
            auth_predicates=frozenset(auth),
        )

    @property
    def has_content(self) -> bool:
        return bool(
            self.allocators or self.deallocators
            or self.lock_acquires or self.lock_releases
            or self.lock_pairs
            or self.refcount_gets or self.refcount_puts
            or self.callback_registers or self.callback_cancels
            or self.nullable_returns or self.auth_predicates
            or self.boundary_transfers
        )


def _entry_actionable(entry: dict[str, Any]) -> bool:
    """Study receipts tier gate for vocabulary dict entries.

    ``llm_prior`` marks a claim backed only by training memory (see
    ``core.concepts.receipts``) — never consumed as vocabulary. All
    other tiers (and untiered legacy entries) pass: the mechanical
    checkers verify the actual code, so vocabulary names only direct
    attention.
    """
    return entry.get("provenance", "") != "llm_prior"


def _entry_name(entry: Any) -> str:
    """Name of a vocabulary entry — plain string or tier-carrying dict."""
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict) and entry.get("name"):
        if not _entry_actionable(entry):
            return ""
        return str(entry["name"])
    return ""


_EMPTY_VOCAB = DomainVocabulary()


@dataclass
class SmtSufficiencyResult:
    """Result of SMT check on guard sufficiency."""

    guard_text: str
    feasible: bool | None = None  # True=guard insufficient, False=guard sufficient
    reasoning: str = ""
    concrete_values: dict[str, str] = field(default_factory=dict)
    witness: dict[str, int] | None = None
    error: str = ""

    @property
    def guard_sufficient(self) -> bool | None:
        """True if the guard provably prevents the bug."""
        if self.feasible is None:
            return None
        return not self.feasible  # infeasible overflow = sufficient guard

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "guard_text": self.guard_text,
            "reasoning": self.reasoning,
        }
        if self.feasible is not None:
            d["feasible"] = self.feasible
            d["guard_sufficient"] = self.guard_sufficient
        if self.concrete_values:
            d["concrete_values"] = self.concrete_values
        if self.witness:
            d["witness"] = self.witness
        if self.error:
            d["error"] = self.error
        return d


@dataclass
class PathFeasibilityResult:
    """Result of checking whether a path to a sink is satisfiable."""

    feasible: bool | None = None  # True=path reachable, False=dead path
    reasoning: str = ""
    witness: dict[str, int] | None = None
    guard_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"reasoning": self.reasoning, "guard_count": self.guard_count}
        if self.feasible is not None:
            d["feasible"] = self.feasible
        if self.witness:
            d["witness"] = self.witness
        return d


@dataclass
class SignedMismatchResult:
    """Result of checking signed/unsigned comparison mismatch."""

    mismatch: bool = False
    variable: str = ""
    reasoning: str = ""
    witness: dict[str, int] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"mismatch": self.mismatch, "reasoning": self.reasoning}
        if self.variable:
            d["variable"] = self.variable
        if self.witness:
            d["witness"] = self.witness
        return d


# ---------------------------------------------------------------------------
# Comparison extraction
# ---------------------------------------------------------------------------

# Matches comparisons: var <op> value, value <op> var
_COMPARISON_RE = re.compile(
    r"([a-zA-Z_]\w*(?:\.\w+)*)\s*(==|!=|<=|>=|<|>)\s*"
    r"([a-zA-Z_]\w*(?:\.\w+)*|0x[0-9a-fA-F]+|\d+(?:\.\d+)?)",
)

# Reverse comparisons: value <op> var
_COMPARISON_REV_RE = re.compile(
    r"(0x[0-9a-fA-F]+|\d+(?:\.\d+)?)\s*(==|!=|<=|>=|<|>)\s*"
    r"([a-zA-Z_]\w*(?:\.\w+)*)",
)


@dataclass
class BoundsConstraint:
    """A concrete bounds constraint extracted from a guard."""
    variable: str
    operator: str  # <, <=, >, >=, ==, !=
    bound_value: int
    source_text: str = ""


def extract_bounds_constraints(
    guard: GuardCondition,
) -> list[BoundsConstraint]:
    """Extract numeric bounds constraints from a guard condition.

    Uses concrete_values when available for constant resolution.
    """
    constraints: list[BoundsConstraint] = []
    text = guard.text

    # Resolve constants in the text
    resolved_text = text
    for name, value in sorted(guard.concrete_values.items(), key=lambda kv: -len(kv[0])):
        resolved_text = re.sub(r'\b' + re.escape(name) + r'\b', value, resolved_text)

    # Forward: var op value
    for m in _COMPARISON_RE.finditer(resolved_text):
        var, op, val_str = m.group(1), m.group(2), m.group(3)
        val = _try_parse_int(val_str)
        if val is not None:
            constraints.append(BoundsConstraint(
                variable=var, operator=op, bound_value=val,
                source_text=m.group(0),
            ))

    # Reverse: value op var → flip operator
    for m in _COMPARISON_REV_RE.finditer(resolved_text):
        val_str, op, var = m.group(1), m.group(2), m.group(3)
        val = _try_parse_int(val_str)
        if val is not None:
            flipped_op = _flip_operator(op)
            if flipped_op:
                constraints.append(BoundsConstraint(
                    variable=var, operator=flipped_op, bound_value=val,
                    source_text=m.group(0),
                ))

    return constraints


def _try_parse_int(s: str) -> int | None:
    """Try to parse an integer from string (decimal or hex)."""
    try:
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        return int(s)
    except (ValueError, TypeError):
        return None


def _flip_operator(op: str) -> str | None:
    """Flip a comparison operator for reversed operands."""
    flips = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}
    return flips.get(op)


# ---------------------------------------------------------------------------
# Polarity-aware constraint builder
# ---------------------------------------------------------------------------

_NEGATE_OP = {"<": ">=", "<=": ">", ">": "<=", ">=": "<", "==": "!=", "!=": "=="}


def constraints_for_guard(
    guard: GuardCondition,
    *,
    respect_polarity: bool = True,
) -> list[BoundsConstraint]:
    """Extract constraints with polarity awareness.

    When polarity is "excluded" (sink is in the else-branch), the
    guard condition is negated: ``len < 1024`` becomes ``len >= 1024``.
    """
    raw = extract_bounds_constraints(guard)
    if not respect_polarity or guard.polarity != "excluded":
        return raw
    negated = []
    for c in raw:
        neg_op = _NEGATE_OP.get(c.operator)
        if neg_op:
            negated.append(BoundsConstraint(
                variable=c.variable, operator=neg_op,
                bound_value=c.bound_value, source_text=c.source_text,
            ))
    return negated


# ---------------------------------------------------------------------------
# Path feasibility — are all guards jointly satisfiable?
# ---------------------------------------------------------------------------


def check_path_feasibility(
    guards: list[GuardCondition],
) -> PathFeasibilityResult:
    """Check whether the conjunction of guard conditions is satisfiable.

    If UNSAT, the sink is on a dead path and can never be reached.
    If SAT, returns concrete witness values.
    """
    from .safety_contract import assert_boost_only
    assert_boost_only("condition_smt")

    all_constraints: list[BoundsConstraint] = []
    for g in guards:
        all_constraints.extend(constraints_for_guard(g, respect_polarity=True))

    if not all_constraints:
        return PathFeasibilityResult(
            feasible=None,
            reasoning="no extractable constraints",
            guard_count=len(guards),
        )

    z3_result = _try_z3_path_feasibility(all_constraints)
    if z3_result is not None:
        return PathFeasibilityResult(
            feasible=z3_result[0],
            reasoning=z3_result[1],
            witness=z3_result[2],
            guard_count=len(guards),
        )

    return _arithmetic_path_feasibility(all_constraints, len(guards))


def _try_z3_path_feasibility(
    constraints: list[BoundsConstraint],
) -> tuple[bool, str, dict[str, int] | None] | None:
    """Z3 path feasibility check. Returns None if Z3 unavailable."""
    try:
        import importlib.util
        if importlib.util.find_spec("z3") is None:
            return None
    except ImportError:
        return None

    payload = pickle.dumps(("path_feasibility", constraints))
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _Z3_CHILD_SCRIPT_V2],
            input=payload, capture_output=True, timeout=10,
            check=False,
            env=_z3_child_env(),
        )
        if proc.returncode == 0:
            try:
                return pickle.loads(proc.stdout)
            except Exception:  # malformed child output degrades to None
                logger.debug("z3 child output unpicklable", exc_info=True)
    except subprocess.TimeoutExpired:
        logger.debug("z3 child timed out")
    return None


def _arithmetic_path_feasibility(
    constraints: list[BoundsConstraint],
    guard_count: int,
) -> PathFeasibilityResult:
    """Simple arithmetic path-feasibility check without Z3.

    Detects contradictions like ``x < 10 && x > 20``.
    """
    per_var: dict[str, list[BoundsConstraint]] = {}
    for c in constraints:
        per_var.setdefault(c.variable, []).append(c)

    for var, cs in per_var.items():
        lower: int | None = None
        upper: int | None = None
        for c in cs:
            if c.operator in ("<", "<="):
                ub = c.bound_value - 1 if c.operator == "<" else c.bound_value
                if upper is None or ub < upper:
                    upper = ub
            elif c.operator in (">", ">="):
                lb = c.bound_value + 1 if c.operator == ">" else c.bound_value
                if lower is None or lb > lower:
                    lower = lb
        if lower is not None and upper is not None and lower > upper:
            return PathFeasibilityResult(
                feasible=False,
                reasoning=f"dead path: {var} requires [{lower}, {upper}]",
                guard_count=guard_count,
            )

    return PathFeasibilityResult(
        feasible=True,
        reasoning="no arithmetic contradiction found",
        guard_count=guard_count,
    )


# ---------------------------------------------------------------------------
# Signed/unsigned mismatch detection
# ---------------------------------------------------------------------------


def check_signed_mismatch(
    guard: GuardCondition,
    *,
    var_is_unsigned: bool = True,
    bit_width: int = 32,
) -> SignedMismatchResult:
    """Detect signed comparison on an unsigned variable.

    Pattern: ``if ((int)size < MAX)`` where size is size_t —
    negative int values pass the guard but wrap to huge unsigned values.
    """
    from .safety_contract import assert_boost_only
    assert_boost_only("condition_smt")

    if not var_is_unsigned:
        return SignedMismatchResult(reasoning="variable is signed — no mismatch")

    constraints = extract_bounds_constraints(guard)
    for c in constraints:
        if c.operator in ("<", "<=") and c.bound_value >= 0:
            z3_result = _try_z3_signed_mismatch(
                c.variable, c.operator, c.bound_value, bit_width,
            )
            if z3_result is not None:
                return z3_result
            # Arithmetic fallback: a signed comparison allows negative
            # values which wrap to large unsigned values
            signed_max = (1 << (bit_width - 1)) - 1
            if c.bound_value <= signed_max:
                return SignedMismatchResult(
                    mismatch=True,
                    variable=c.variable,
                    reasoning=(
                        f"signed comparison '{c.source_text}' allows negative "
                        f"values that wrap to large unsigned values "
                        f"(e.g. -1 → {(1 << bit_width) - 1})"
                    ),
                    witness={c.variable: -1},
                )

    return SignedMismatchResult(reasoning="no signed/unsigned mismatch detected")


def _try_z3_signed_mismatch(
    variable: str,
    operator: str,
    bound: int,
    bit_width: int,
) -> SignedMismatchResult | None:
    """Z3 check for signed/unsigned mismatch. Returns None if Z3 unavailable."""
    try:
        import importlib.util
        if importlib.util.find_spec("z3") is None:
            return None
    except ImportError:
        return None

    payload = pickle.dumps(("signed_mismatch", variable, operator, bound, bit_width))
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _Z3_CHILD_SCRIPT_V2],
            input=payload, capture_output=True, timeout=10,
            check=False,
            env=_z3_child_env(),
        )
        if proc.returncode == 0:
            try:
                return pickle.loads(proc.stdout)
            except Exception:  # malformed child output degrades to None
                logger.debug("z3 child output unpicklable", exc_info=True)
    except subprocess.TimeoutExpired:
        logger.debug("z3 child timed out")
    return None


# ---------------------------------------------------------------------------
# Off-by-one detection
# ---------------------------------------------------------------------------


def check_off_by_one(
    sink_guard: SinkGuard,
    *,
    buffer_size: int | None = None,
    copies_null_terminator: bool = True,
) -> list[SmtSufficiencyResult]:
    """Detect off-by-one when guard allows exactly buffer_size but sink appends.

    Pattern: ``if (len <= buf_size) strncpy(dst, src, len)``
    where strncpy writes len+1 bytes (null terminator).
    """
    from .safety_contract import assert_boost_only
    assert_boost_only("condition_smt")

    if buffer_size is None or not copies_null_terminator:
        return []

    null_term_sinks = frozenset({
        "strncat",
    })
    api_base = sink_guard.sink_api.split(".")[-1] if "." in sink_guard.sink_api else sink_guard.sink_api
    if api_base not in null_term_sinks:
        return []

    results: list[SmtSufficiencyResult] = []
    for guard in sink_guard.guards:
        if not guard.resolvable or not guard.concrete_values:
            continue
        constraints = extract_bounds_constraints(guard)
        for c in constraints:
            if c.operator == "<=" and c.bound_value == buffer_size:
                results.append(SmtSufficiencyResult(
                    guard_text=guard.text,
                    feasible=True,
                    reasoning=(
                        f"off-by-one: guard allows {c.variable}={c.bound_value} "
                        f"but {api_base} writes up to {c.bound_value}+1 bytes "
                        f"(null terminator) into {buffer_size}-byte buffer"
                    ),
                    concrete_values=guard.concrete_values,
                    witness={c.variable: c.bound_value},
                ))
            elif c.operator == "<" and c.bound_value == buffer_size + 1:
                results.append(SmtSufficiencyResult(
                    guard_text=guard.text,
                    feasible=True,
                    reasoning=(
                        f"off-by-one: guard allows {c.variable}={c.bound_value - 1} "
                        f"but {api_base} writes up to {c.bound_value} bytes "
                        f"(null terminator) into {buffer_size}-byte buffer"
                    ),
                    concrete_values=guard.concrete_values,
                    witness={c.variable: c.bound_value - 1},
                ))
    return results


# ---------------------------------------------------------------------------
# SMT sufficiency check
# ---------------------------------------------------------------------------


def check_guard_sufficiency(
    sink_guard: SinkGuard,
    *,
    buffer_size: int | None = None,
    sink_context: dict[str, Any] | None = None,
) -> list[SmtSufficiencyResult]:
    """Check whether guard conditions are sufficient via SMT.

    For each resolvable guard with concrete values, formulates a query:
    "Can the constrained variable still violate the safety property?"

    Args:
        sink_guard: The guard set to check.
        buffer_size: Known buffer size for overflow sinks (from allocation).
        sink_context: Additional context (e.g., from annotations).

    Returns:
        List of SMT results, one per resolvable guard.
    """
    from .safety_contract import assert_boost_only
    assert_boost_only("condition_smt")

    results: list[SmtSufficiencyResult] = []

    for guard in sink_guard.guards:
        if not guard.resolvable or not guard.concrete_values:
            continue

        constraints = extract_bounds_constraints(guard)
        if not constraints:
            continue

        result = _check_constraints_vs_safety(
            constraints=constraints,
            guard=guard,
            buffer_size=buffer_size,
            sink_api=sink_guard.sink_api,
            sink_context=sink_context,
        )
        results.append(result)

    return results


def _check_constraints_vs_safety(
    constraints: list[BoundsConstraint],
    guard: GuardCondition,
    buffer_size: int | None,
    sink_api: str,
    sink_context: dict[str, Any] | None,
) -> SmtSufficiencyResult:
    """Check if constraints are sufficient for the safety property.

    For buffer overflow sinks: can the constrained length still exceed
    the buffer size?
    """
    # Try Z3 first
    z3_result = _try_z3_check(constraints, buffer_size, sink_api)
    if z3_result is not None:
        witness = z3_result[2] if len(z3_result) > 2 else None
        return SmtSufficiencyResult(
            guard_text=guard.text,
            feasible=z3_result[0],
            reasoning=z3_result[1],
            concrete_values=guard.concrete_values,
            witness=witness,
        )

    # Fallback: simple arithmetic reasoning
    return _arithmetic_check(constraints, guard, buffer_size, sink_api)


def _try_z3_check(
    constraints: list[BoundsConstraint],
    buffer_size: int | None,
    sink_api: str,
) -> tuple[bool, str, dict[str, int] | None] | None:
    """Try Z3 SMT check. Returns None if Z3 unavailable.

    Runs in a forked subprocess so Z3 assertion failures (segfaults in
    the C++ core) don't kill the parent process.
    """
    try:
        import importlib.util
        if importlib.util.find_spec("z3") is None:
            return None
    except ImportError:
        return None

    return _z3_in_subprocess(constraints, buffer_size, sink_api)


_Z3_CHILD_SCRIPT = (
    "import sys,os,pickle\n"
    "sys.path.insert(0,os.environ['RAPTOR_DIR'])\n"
    "from core.audit.condition_smt import _z3_dispatch\n"
    "r=_z3_dispatch(*pickle.loads(sys.stdin.buffer.read()))\n"
    "sys.stdout.buffer.write(pickle.dumps(r))\n"
)

_Z3_CHILD_SCRIPT_V2 = (
    "import sys,os,pickle\n"
    "sys.path.insert(0,os.environ['RAPTOR_DIR'])\n"
    "from core.audit.condition_smt import _z3_dispatch_v2\n"
    "r=_z3_dispatch_v2(pickle.loads(sys.stdin.buffer.read()))\n"
    "sys.stdout.buffer.write(pickle.dumps(r))\n"
)


def _z3_child_env() -> dict:
    """Env for the Z3 probe child with RAPTOR_DIR pinned to THIS tree.

    The child bootstraps ``sys.path`` from ``RAPTOR_DIR``; an ambient
    value from the launching shell can point at a different checkout,
    making the child import the OTHER tree's ``core.audit.
    condition_smt`` (cross-checkout skew: wrong dispatch signatures,
    silent behavioural drift). Same chokepoint rule as
    ``core.audit.sweep.smt_child_env``, including the LLM-env strip:
    Z3 probe children make no LLM calls — no credentials, no backend
    selection, no half-inherited dispatcher route.
    """
    from core.config import RaptorConfig, pin_raptor_dir
    return RaptorConfig.strip_llm_env_vars(
        pin_raptor_dir(dict(os.environ)))


def _z3_in_subprocess(
    constraints: list[BoundsConstraint],
    buffer_size: int | None,
    sink_api: str,
    *,
    timeout: int = 10,
) -> tuple[bool, str, dict[str, int] | None] | None:
    """Run Z3 in a subprocess; return None on crash or timeout.

    Uses subprocess.Popen (fork+exec) rather than bare os.fork() so the
    child gets a clean, single-threaded process image -- safe when the
    parent has worker threads.
    """
    payload = pickle.dumps((constraints, buffer_size, sink_api))
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _Z3_CHILD_SCRIPT],
            input=payload, capture_output=True, timeout=timeout,
            check=False,
            env=_z3_child_env(),
        )
        if proc.returncode == 0:
            try:
                return pickle.loads(proc.stdout)
            except Exception:  # malformed child output degrades to None
                logger.debug("z3 child output unpicklable", exc_info=True)
        logger.debug("Z3 subprocess exited with code %d", proc.returncode)
    except subprocess.TimeoutExpired:
        logger.debug("Z3 subprocess timed out after %ds", timeout)
    return None


def _z3_dispatch(
    constraints: list[BoundsConstraint],
    buffer_size: int | None,
    sink_api: str,
) -> tuple[bool, str, dict[str, int] | None] | None:
    """Route to the appropriate Z3 check."""
    memcpy_sinks = {
        "memcpy", "memmove", "strncpy", "strncat", "bcopy",
        "copy_from_user", "copy_to_user", "wmemcpy",
        "CopyMemory", "RtlCopyMemory",
    }
    alloc_sinks = {
        "malloc", "calloc", "realloc", "kmalloc", "kzalloc",
    }

    api_base = sink_api.split(".")[-1] if "." in sink_api else sink_api

    if api_base in memcpy_sinks and buffer_size is not None:
        return _z3_overflow_check(constraints, buffer_size)
    elif api_base in alloc_sinks:
        return _z3_alloc_overflow_check(constraints)

    return _z3_consistency_check(constraints)


def _z3_overflow_check(
    constraints: list[BoundsConstraint],
    buffer_size: int,
) -> tuple[bool, str, dict[str, int] | None]:
    """Z3: Can length still overflow given the guard constraints?"""
    import z3

    solver = z3.Solver()
    solver.set("timeout", 5000)

    # Create variables for each constraint's subject
    vars_map: dict[str, z3.ArithRef] = {}
    for c in constraints:
        if c.variable not in vars_map:
            vars_map[c.variable] = z3.Int(c.variable)

    # Add guard constraints
    for c in constraints:
        v = vars_map[c.variable]
        if c.operator == "<":
            solver.add(v < c.bound_value)
        elif c.operator == "<=":
            solver.add(v <= c.bound_value)
        elif c.operator == ">":
            solver.add(v > c.bound_value)
        elif c.operator == ">=":
            solver.add(v >= c.bound_value)
        elif c.operator == "==":
            solver.add(v == c.bound_value)
        elif c.operator == "!=":
            solver.add(v != c.bound_value)

    # Ask: can any constrained variable exceed buffer_size?
    for v in vars_map.values():
        solver.push()
        solver.add(v > buffer_size)
        result = solver.check()
        if result == z3.sat:
            model = solver.model()
            val = model[v]
            solver.pop()
            witness = {}
            for wname, wv in vars_map.items():
                wval = model[wv]
                if wval is not None:
                    try:
                        witness[wname] = wval.as_long()
                    except AttributeError:
                        pass
            return (True, f"overflow possible: {v} can be {val} > {buffer_size}", witness or None)
        if result == z3.unknown:
            solver.pop()
            return (True, "solver timeout — conservatively assume guard insufficient", None)
        solver.pop()

    return (False, f"guard sufficient: all constrained vars ≤ {buffer_size}", None)


def _z3_alloc_overflow_check(
    constraints: list[BoundsConstraint],
) -> tuple[bool, str, dict[str, int] | None]:
    """Z3: Can an allocation size integer-overflow given the constraints?"""
    import z3

    solver = z3.Solver()
    solver.set("timeout", 5000)

    vars_map: dict[str, z3.BitVecRef] = {}
    for c in constraints:
        if c.variable not in vars_map:
            vars_map[c.variable] = z3.BitVec(c.variable, 64)

    for c in constraints:
        v = vars_map[c.variable]
        bv_val = z3.BitVecVal(c.bound_value, 64)
        if c.operator == "<":
            solver.add(z3.ULT(v, bv_val))
        elif c.operator == "<=":
            solver.add(z3.ULE(v, bv_val))
        elif c.operator == ">":
            solver.add(z3.UGT(v, bv_val))
        elif c.operator == ">=":
            solver.add(z3.UGE(v, bv_val))
        elif c.operator == "==":
            solver.add(v == bv_val)
        elif c.operator == "!=":
            solver.add(v != bv_val)

    # Check: can multiplication of any two constrained vars wrap?
    var_list = list(vars_map.items())
    if len(var_list) >= 2:
        for i in range(len(var_list)):
            for j in range(i + 1, len(var_list)):
                (_, a), (_, b) = var_list[i], var_list[j]
                solver.push()
                a_ext = z3.ZeroExt(64, a)
                b_ext = z3.ZeroExt(64, b)
                full_product = a_ext * b_ext
                upper_bits = z3.Extract(127, 64, full_product)
                solver.add(upper_bits != z3.BitVecVal(0, 64))

                result = solver.check()
                if result == z3.sat:
                    model = solver.model()
                    witness = {}
                    for wn, wv in vars_map.items():
                        wval = model[wv]
                        if wval is not None:
                            try:
                                witness[wn] = wval.as_long()
                            except AttributeError:
                                pass
                    solver.pop()
                    return (True, "integer overflow in allocation size is possible", witness or None)
                solver.pop()
                if result == z3.unknown:
                    return (True, "solver timeout — conservatively assume overflow possible", None)
        return (False, "allocation size cannot overflow given constraints", None)

    return (False, "insufficient variables for multiplication overflow check", None)


def _z3_consistency_check(
    constraints: list[BoundsConstraint],
) -> tuple[bool, str, dict[str, int] | None]:
    """Z3: Are the constraints internally consistent?"""
    import z3

    solver = z3.Solver()
    solver.set("timeout", 5000)

    vars_map: dict[str, z3.ArithRef] = {}
    for c in constraints:
        if c.variable not in vars_map:
            vars_map[c.variable] = z3.Int(c.variable)

    for c in constraints:
        v = vars_map[c.variable]
        if c.operator == "<":
            solver.add(v < c.bound_value)
        elif c.operator == "<=":
            solver.add(v <= c.bound_value)
        elif c.operator == ">":
            solver.add(v > c.bound_value)
        elif c.operator == ">=":
            solver.add(v >= c.bound_value)
        elif c.operator == "==":
            solver.add(v == c.bound_value)
        elif c.operator == "!=":
            solver.add(v != c.bound_value)

    result = solver.check()
    if result == z3.unsat:
        return (False, "constraints are contradictory — dead path", None)
    # SAT or unknown: constraints are consistent (or inconclusive)
    return (False, "constraints are consistent — no insufficiency proven", None)


def _z3_dispatch_v2(args: tuple):
    """Unified v2 dispatcher for new Z3 checks."""
    tag = args[0]
    if tag == "path_feasibility":
        return _z3_path_feasibility_check(args[1])
    elif tag == "signed_mismatch":
        return _z3_signed_mismatch_check(args[1], args[2], args[3], args[4])
    elif tag == "auth_bypass":
        return _z3_auth_bypass_check(args[1], args[2])
    elif tag == "lock_discipline":
        return _z3_lock_discipline_check(args[1], args[2], args[3])
    elif tag == "resource_leak":
        return _z3_resource_leak_check(args[1], args[2], args[3], args[4], args[5])
    elif tag == "null_propagation":
        pass
    elif tag == "integer_narrowing":
        return _z3_integer_narrowing_check(args[1], args[2], args[3], args[4])
    elif tag == "integer_overflow":
        return _z3_integer_overflow_check(args[1], args[2], args[3])
    return None


def _z3_path_feasibility_check(
    constraints: list[BoundsConstraint],
) -> tuple[bool, str, dict[str, int] | None]:
    """Z3: Check if all constraints can be satisfied simultaneously.

    Uses z3.Int (integer sort) rather than bitvectors because guards
    extracted from tree-sitter are arithmetic comparisons, not
    bit-width-bounded.  Uses core.smt_solver.session for solver
    construction with timeout.
    """
    from core.smt_solver.availability import z3
    from core.smt_solver.session import new_solver

    solver = new_solver()

    vars_map: dict[str, z3.ArithRef] = {}
    for c in constraints:
        if c.variable not in vars_map:
            vars_map[c.variable] = z3.Int(c.variable)

    for c in constraints:
        v = vars_map[c.variable]
        if c.operator == "<":
            solver.add(v < c.bound_value)
        elif c.operator == "<=":
            solver.add(v <= c.bound_value)
        elif c.operator == ">":
            solver.add(v > c.bound_value)
        elif c.operator == ">=":
            solver.add(v >= c.bound_value)
        elif c.operator == "==":
            solver.add(v == c.bound_value)
        elif c.operator == "!=":
            solver.add(v != c.bound_value)

    result = solver.check()
    if result == z3.unsat:
        return (False, "path infeasible: guard conjunction is unsatisfiable", None)
    elif result == z3.sat:
        model = solver.model()
        witness = {}
        for name, var in vars_map.items():
            val = model[var]
            if val is not None:
                try:
                    witness[name] = val.as_long()
                except AttributeError:
                    pass
        return (True, "path feasible", witness if witness else None)
    return (True, "solver timeout — conservatively assume path feasible", None)


def _z3_signed_mismatch_check(
    variable: str,
    operator: str,
    bound: int,
    bit_width: int,
) -> SignedMismatchResult:
    """Z3: Check if signed comparison allows negative values that wrap unsigned.

    Uses core.smt_solver bitvec primitives for variable/value
    construction and signedness-aware comparison routing.
    """
    from core.smt_solver.availability import z3
    from core.smt_solver.bitvec import gt, le, lt, mk_val, mk_var
    from core.smt_solver.session import new_solver
    from core.smt_solver.witness import bv_to_int

    signed_var = mk_var(f"{variable}_signed", bit_width)
    unsigned_var = mk_var(f"{variable}_unsigned", bit_width)
    bv_bound = mk_val(bound, bit_width)

    solver = new_solver()

    solver.add(signed_var == unsigned_var)

    # Signed comparison passes (signed=True routes through z3's default signed cmp)
    if operator == "<":
        solver.add(lt(signed_var, bv_bound, signed=True))
    elif operator == "<=":
        solver.add(le(signed_var, bv_bound, signed=True))

    # But unsigned interpretation is huge (unsigned > bound)
    solver.add(gt(unsigned_var, bv_bound, signed=False))

    result = solver.check()
    if result == z3.sat:
        model = solver.model()
        signed_val = model[signed_var]
        unsigned_val = model[unsigned_var]
        try:
            sv = bv_to_int(signed_val.as_long(), bit_width, signed=True)
            uv = bv_to_int(unsigned_val.as_long(), bit_width, signed=False)
        except Exception:  # noqa: BLE001 — any model-extraction failure falls back to sentinel witnesses
            sv, uv = -1, (1 << bit_width) - 1
        return SignedMismatchResult(
            mismatch=True,
            variable=variable,
            reasoning=(
                f"signed comparison '{variable} {operator} {bound}' allows "
                f"negative value {sv} which wraps to {uv} unsigned"
            ),
            witness={variable: sv},
        )
    return SignedMismatchResult(
        reasoning="no signed/unsigned mismatch: Z3 proved safe",
    )


def _z3_auth_bypass_check(
    guard_text: str,
    bypassed_checks: list[str],
) -> AuthBypassResult:
    """Z3: Check if an early-return guard condition is satisfiable.

    If SAT, the early return can be taken, bypassing the later auth
    checks.  The guard condition is parsed for comparisons and encoded
    as Z3 integer constraints.  A satisfying assignment is the witness
    that demonstrates the bypass.
    """
    from core.smt_solver.availability import z3
    from core.smt_solver.session import new_solver

    comparisons = _COMPARISON_RE.findall(guard_text)
    comparisons_rev = _COMPARISON_REV_RE.findall(guard_text)

    constraints: list[BoundsConstraint] = []
    for var, op, val_str in comparisons:
        val = _try_parse_int(val_str)
        if val is not None:
            constraints.append(BoundsConstraint(var, op, val, guard_text))
    for val_str, op, var in comparisons_rev:
        val = _try_parse_int(val_str)
        if val is not None:
            flipped = _flip_operator(op)
            if flipped:
                constraints.append(BoundsConstraint(var, flipped, val, guard_text))

    if not constraints:
        return AuthBypassResult(
            bypass_found=True,
            guard_text=guard_text,
            bypassed_checks=bypassed_checks,
            reasoning=(
                f"early return guarded by '{guard_text.strip()}' bypasses "
                f"auth checks {', '.join(bypassed_checks)} — guard has no "
                f"numeric constraints (identity/state check, always feasible)"
            ),
        )

    solver = new_solver()
    vars_map: dict[str, z3.ArithRef] = {}
    for c in constraints:
        if c.variable not in vars_map:
            vars_map[c.variable] = z3.Int(c.variable)

    for c in constraints:
        v = vars_map[c.variable]
        if c.operator == "<":
            solver.add(v < c.bound_value)
        elif c.operator == "<=":
            solver.add(v <= c.bound_value)
        elif c.operator == ">":
            solver.add(v > c.bound_value)
        elif c.operator == ">=":
            solver.add(v >= c.bound_value)
        elif c.operator == "==":
            solver.add(v == c.bound_value)
        elif c.operator == "!=":
            solver.add(v != c.bound_value)

    result = solver.check()
    if result == z3.sat:
        model = solver.model()
        witness: dict[str, Any] = {}
        for name, var in vars_map.items():
            val = model[var]
            if val is not None:
                try:
                    witness[name] = val.as_long()
                except AttributeError:
                    pass
        return AuthBypassResult(
            bypass_found=True,
            guard_text=guard_text,
            bypassed_checks=bypassed_checks,
            reasoning=(
                f"Z3 SAT: guard '{guard_text.strip()}' is satisfiable — "
                f"early return bypasses {', '.join(bypassed_checks)}"
            ),
            witness=witness if witness else None,
        )
    elif result == z3.unsat:
        return AuthBypassResult(
            bypass_found=False,
            guard_text=guard_text,
            reasoning=(
                f"Z3 UNSAT: guard '{guard_text.strip()}' is infeasible — "
                f"no bypass possible"
            ),
        )
    return AuthBypassResult(
        bypass_found=True,
        guard_text=guard_text,
        bypassed_checks=bypassed_checks,
        reasoning="Z3 timeout — conservatively flag as potential bypass",
    )


def _arithmetic_check(
    constraints: list[BoundsConstraint],
    guard: GuardCondition,
    buffer_size: int | None,
    sink_api: str,
) -> SmtSufficiencyResult:
    """Simple arithmetic reasoning when Z3 is unavailable.

    For `len < MAX_SIZE` where MAX_SIZE=4096 and buffer=256:
    The guard allows len up to 4095, but buffer is only 256 → insufficient.

    When multiple upper-bound constraints exist (conjunctive guard),
    the tightest (minimum max_allowed) determines sufficiency.
    """
    if buffer_size is None:
        return SmtSufficiencyResult(
            guard_text=guard.text,
            feasible=None,
            reasoning="no buffer size known for arithmetic check",
            concrete_values=guard.concrete_values,
        )

    tightest_max: int | None = None
    tightest_var: str = ""

    for c in constraints:
        max_allowed: int | None = None
        if c.operator == "<":
            max_allowed = c.bound_value - 1
        elif c.operator == "<=":
            max_allowed = c.bound_value

        if max_allowed is not None and (
            tightest_max is None or max_allowed < tightest_max
        ):
            tightest_max = max_allowed
            tightest_var = c.variable

    if tightest_max is None:
        return SmtSufficiencyResult(
            guard_text=guard.text,
            feasible=None,
            reasoning="no upper-bound constraint found for arithmetic check",
            concrete_values=guard.concrete_values,
        )

    if tightest_max > buffer_size:
        return SmtSufficiencyResult(
            guard_text=guard.text,
            feasible=True,
            reasoning=(
                f"guard allows {tightest_var} up to {tightest_max}, "
                f"but buffer is only {buffer_size} bytes"
            ),
            concrete_values=guard.concrete_values,
        )

    return SmtSufficiencyResult(
        guard_text=guard.text,
        feasible=False,
        reasoning=(
            f"guard limits {tightest_var} to ≤{tightest_max}, "
            f"within buffer size {buffer_size}"
        ),
        concrete_values=guard.concrete_values,
    )


# ---------------------------------------------------------------------------
# Batch API
# ---------------------------------------------------------------------------


def check_all_sufficiency(
    guards: list[SinkGuard],
    *,
    buffer_sizes: dict[int, int] | None = None,
) -> list[list[SmtSufficiencyResult]]:
    """Check sufficiency for all guards.

    Args:
        guards: List of SinkGuard instances.
        buffer_sizes: Map of sink_line → known buffer size.

    Returns:
        List of results per guard (one inner list per SinkGuard).
    """
    from .safety_contract import assert_boost_only
    assert_boost_only("condition_smt")

    if buffer_sizes is None:
        buffer_sizes = {}

    return [
        check_guard_sufficiency(
            sg,
            buffer_size=buffer_sizes.get(sg.sink_line),
        )
        for sg in guards
    ]


# ---------------------------------------------------------------------------
# Auth bypass detection
# ---------------------------------------------------------------------------

# SEED SET — shape patterns (LSM prefix family, cred field access) plus
# two canonical exemplars. The kernel predicate bulk (ns_capable,
# inode_permission, ptrace_may_access, ...) lives in the linux_kernel
# vocab pack; project predicates arrive via
# DomainVocabulary.auth_predicates. Do not grow this list — teach the
# study loop / pack instead.
_AUTH_CHECK_PATTERNS = [
    (re.compile(r"\b(capable)\s*\("), "capability"),
    (re.compile(r"\b(security_\w+)\s*\("), "lsm"),
    (re.compile(r"\b(uid_eq)\s*\("), "uid"),
    (re.compile(r"\bcred->(uid|euid|suid|fsuid)\b"), "uid"),
]


def _auth_patterns(
    vocab: DomainVocabulary = _EMPTY_VOCAB,
) -> list[tuple[re.Pattern, str]]:
    """Seed auth patterns extended with vocab-supplied predicates."""
    patterns = list(_AUTH_CHECK_PATTERNS)
    if vocab.auth_predicates:
        by_kind: dict[str, list[str]] = {}
        for name, kind in sorted(vocab.auth_predicates):
            by_kind.setdefault(kind, []).append(name)
        for kind in sorted(by_kind):
            alts = "|".join(
                re.escape(n)
                for n in sorted(by_kind[kind], key=len, reverse=True)
            )
            patterns.append((re.compile(rf"\b({alts})\s*\("), kind))
    return patterns

_SUCCESS_RETURN_RE = re.compile(
    r"^\s*return\s+(0|nil|None|True|true|EXIT_SUCCESS)\s*;?\s*$",
    re.MULTILINE,
)

_DENY_RETURN_RE = re.compile(
    r"return\s+(-E[A-Z]+|-1|EPERM|EACCES|false|False)",
)


@dataclass
class AuthBypassResult:
    """Result of checking for auth check bypass via early return."""

    bypass_found: bool = False
    early_return_line: int = 0
    guard_text: str = ""
    bypassed_checks: list[str] = field(default_factory=list)
    reasoning: str = ""
    witness: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "bypass_found": self.bypass_found,
            "reasoning": self.reasoning,
        }
        if self.early_return_line:
            d["early_return_line"] = self.early_return_line
        if self.guard_text:
            d["guard_text"] = self.guard_text
        if self.bypassed_checks:
            d["bypassed_checks"] = self.bypassed_checks
        if self.witness:
            d["witness"] = self.witness
        return d


def check_auth_bypass(
    source: str,
    vocab: DomainVocabulary = _EMPTY_VOCAB,
) -> AuthBypassResult:
    """Detect auth check bypass via early success return.

    Scans for the pattern: a success return (return 0) guarded by a
    weaker condition that appears BEFORE a stronger auth check
    (capable(), uid_eq(), security_*()).  If the early return can be
    taken without passing the later auth check, the later check is
    bypassed.

    Uses Z3 when available to verify guard feasibility; falls back to
    structural ordering analysis.
    """
    from .safety_contract import assert_boost_only
    assert_boost_only("condition_smt")

    lines = source.split("\n")

    auth_checks = _extract_auth_checks(lines, vocab)
    if not auth_checks:
        return AuthBypassResult(reasoning="no auth checks found in source")

    success_returns = _extract_success_returns(lines)
    if not success_returns:
        return AuthBypassResult(reasoning="no success returns found")

    last_auth_line = max(c[0] for c in auth_checks)

    for ret_line in success_returns:
        if ret_line >= last_auth_line:
            continue

        guard_text = _find_enclosing_guard(lines, ret_line)
        if not guard_text:
            continue

        if _guard_is_auth_check(guard_text, auth_checks):
            continue

        bypassed = [
            f"{atype}:{afunc}" for aline, atype, afunc in auth_checks
            if aline > ret_line
        ]
        if not bypassed:
            continue

        # Cascading permission function: if the exact same auth call
        # (same function AND arguments) appears both before and after
        # the early return, this is an intentional early-out path.
        bypassed_calls = {
            call for aline, _, call in auth_checks if aline > ret_line
        }
        earlier_calls = {
            call for aline, _, call in auth_checks if aline < ret_line
        }
        if bypassed_calls & earlier_calls:
            continue

        z3_result = _try_z3_auth_bypass(guard_text, bypassed)
        if z3_result is not None:
            return z3_result

        return AuthBypassResult(
            bypass_found=True,
            early_return_line=ret_line + 1,
            guard_text=guard_text,
            bypassed_checks=bypassed,
            reasoning=(
                f"success return at line {ret_line + 1} guarded by "
                f"'{guard_text.strip()}' bypasses later auth checks: "
                f"{', '.join(bypassed)}"
            ),
        )

    return AuthBypassResult(reasoning="no bypass pattern detected")


def _extract_auth_checks(
    lines: list[str],
    vocab: DomainVocabulary = _EMPTY_VOCAB,
) -> list[tuple[int, str, str]]:
    """Extract (line_idx, check_type, call_text) for auth checks.

    call_text includes function name and arguments so that e.g.
    capable(CAP_SYS_ADMIN) and capable(CAP_NET_ADMIN) are distinct.
    """
    patterns = _auth_patterns(vocab)
    results: list[tuple[int, str, str]] = []
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith(("//", "/*")):
            continue
        for pattern, check_type in patterns:
            m = pattern.search(line)
            if m:
                call_text = _extract_call_text(line, m.start())
                results.append((i, check_type, call_text))
                break
    return results


def _extract_call_text(line: str, start: int) -> str:
    """Extract 'func(args)' starting at start position."""
    depth = 0
    for i in range(start, len(line)):
        if line[i] == "(":
            depth += 1
        elif line[i] == ")":
            depth -= 1
            if depth == 0:
                return line[start:i + 1].strip()
    return line[start:].strip()


def _extract_success_returns(lines: list[str]) -> list[int]:
    """Extract line indices of success returns."""
    results: list[int] = []
    for i, line in enumerate(lines):
        if _SUCCESS_RETURN_RE.match(line):
            results.append(i)
    return results


def _find_enclosing_guard(lines: list[str], ret_line: int) -> str:
    """Walk backwards from ret_line to find the enclosing if-condition."""
    depth = 0
    for i in range(ret_line - 1, max(ret_line - 15, -1), -1):
        stripped = lines[i].strip()
        depth += stripped.count("}") - stripped.count("{")
        if stripped.startswith("if") and "(" in stripped:
            paren_start = stripped.index("(")
            paren_depth = 0
            cond = []
            for ch in stripped[paren_start:]:
                if ch == "(":
                    paren_depth += 1
                elif ch == ")":
                    paren_depth -= 1
                cond.append(ch)
                if paren_depth == 0:
                    break
            return "".join(cond)
    return ""


def _guard_is_auth_check(
    guard_text: str, auth_checks: list[tuple[int, str, str]],
) -> bool:
    """Check if the guard itself is one of the auth checks."""
    for _, _, func_name in auth_checks:
        if func_name in guard_text:
            return True
    return False


def _try_z3_auth_bypass(
    guard_text: str,
    bypassed_checks: list[str],
) -> AuthBypassResult | None:
    """Z3 feasibility check on the bypass guard. Returns None if Z3 unavailable."""
    try:
        import importlib.util
        if importlib.util.find_spec("z3") is None:
            return None
    except ImportError:
        return None

    payload = pickle.dumps(("auth_bypass", guard_text, bypassed_checks))
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _Z3_CHILD_SCRIPT_V2],
            input=payload, capture_output=True, timeout=10,
            check=False,
            env=_z3_child_env(),
        )
        if proc.returncode == 0:
            try:
                return pickle.loads(proc.stdout)
            except Exception:  # malformed child output degrades to None
                logger.debug("z3 child output unpicklable", exc_info=True)
    except subprocess.TimeoutExpired:
        logger.debug("z3 child timed out")
    return None


# ---------------------------------------------------------------------------
# Lock discipline verification
# ---------------------------------------------------------------------------

# SEED SET — the three canonical kernel exemplars (kept because they
# double as documentation of the pattern shape). The kernel lock-pair
# bulk (down_read/up_read, lock_sock/release_sock, local_irq_*,
# preempt_*, ...) lives in the linux_kernel vocab pack; project pairs
# arrive via DomainVocabulary.lock_pairs (exact pairing) or the
# lock_acquires/lock_releases name sets (heuristic pairing). The
# suffix-based *_lock/*_unlock discovery below covers conventional
# names mechanically. Do not grow this list — teach the study loop /
# pack instead.
_LOCK_PAIRS = [
    (re.compile(r"\b(spin_lock(?:_irq(?:save)?|_bh)?)\s*\("), "spin_unlock"),
    (re.compile(r"\b(mutex_lock(?:_interruptible|_killable)?)\s*\("), "mutex_unlock"),
    (re.compile(r"\b(rcu_read_lock)\s*\("), "rcu_read_unlock"),
]

_RETURN_RE = re.compile(r"^\s*return\b", re.MULTILINE)

_GOTO_RE = re.compile(r"\bgoto\s+(\w+)\s*;")

_LABEL_RE = re.compile(r"^(\w+)\s*:", re.MULTILINE)


@dataclass
class LockDisciplineResult:
    """Result of checking lock acquire/release discipline."""

    violation_found: bool = False
    lock_type: str = ""
    acquire_line: int = 0
    return_line: int = 0
    reasoning: str = ""
    witness: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "violation_found": self.violation_found,
            "reasoning": self.reasoning,
        }
        if self.lock_type:
            d["lock_type"] = self.lock_type
        if self.acquire_line:
            d["acquire_line"] = self.acquire_line
        if self.return_line:
            d["return_line"] = self.return_line
        if self.witness:
            d["witness"] = self.witness
        return d


def check_lock_discipline(
    source: str,
    vocab: DomainVocabulary = _EMPTY_VOCAB,
) -> LockDisciplineResult:
    """Detect lock acquire without matching release on a return path.

    Scans for lock/unlock pairs and checks whether any return
    statement falls between an acquire and its matching release.
    Handles goto-based error paths by resolving labels.
    """
    from .safety_contract import assert_boost_only
    assert_boost_only("condition_smt")

    lines = source.split("\n")
    acquires = _extract_lock_acquires(lines, vocab)
    if not acquires:
        return LockDisciplineResult(reasoning="no lock acquires found")

    returns = _extract_returns(lines)
    goto_targets = _extract_goto_targets(lines)
    labels = _extract_labels(lines)

    for acq_line, lock_func, unlock_name, lock_obj in acquires:
        unlock_lines = _find_unlocks(lines, unlock_name, lock_obj)
        if not unlock_lines:
            return LockDisciplineResult(
                violation_found=True,
                lock_type=lock_func,
                acquire_line=acq_line + 1,
                reasoning=(
                    f"{lock_func} at line {acq_line + 1} has no matching "
                    f"{unlock_name} in function"
                ),
            )

        for ret_line in returns:
            if ret_line <= acq_line:
                continue

            acq_indent = len(lines[acq_line]) - len(lines[acq_line].lstrip())
            if any(
                ul < ret_line and ul > acq_line
                and (len(lines[ul]) - len(lines[ul].lstrip())) <= acq_indent
                for ul in unlock_lines
            ):
                continue

            # if (...) { unlock(); return; } — same-indent unlock
            ret_indent = len(lines[ret_line]) - len(lines[ret_line].lstrip())
            if any(
                ul < ret_line and ul > acq_line
                and (ret_line - ul) <= 3
                and (len(lines[ul]) - len(lines[ul].lstrip())) == ret_indent
                for ul in unlock_lines
            ):
                continue

            ret_text = lines[ret_line].strip()
            if _return_is_in_error_goto_block(
                ret_line, lines, goto_targets, labels, unlock_name,
            ):
                continue

            guard = _find_enclosing_guard(lines, ret_line)
            bypassed_unlocks = [
                f"line {ul + 1}" for ul in unlock_lines if ul > ret_line
            ]

            z3_result = _try_z3_lock_discipline(
                guard, lock_func, ret_line + 1, bypassed_unlocks,
            )
            if z3_result is not None:
                return z3_result

            return LockDisciplineResult(
                violation_found=True,
                lock_type=lock_func,
                acquire_line=acq_line + 1,
                return_line=ret_line + 1,
                reasoning=(
                    f"return at line {ret_line + 1} ('{ret_text}') is "
                    f"between {lock_func} (line {acq_line + 1}) and "
                    f"{unlock_name} ({', '.join(bypassed_unlocks)}) — "
                    f"lock held on exit"
                ),
            )

    return LockDisciplineResult(reasoning="all lock/unlock pairs balanced on return paths")


def _extract_lock_object(line: str, match_end: int) -> str:
    """Extract the first argument to a lock/unlock call as a normalised key.

    Returns the text between the opening '(' and the first ',' or ')',
    stripped of '&' and whitespace.  When the argument cannot be parsed
    (macros, nested calls), returns "" so callers fall back to
    name-only matching.
    """
    rest = line[match_end:]
    depth = 0
    buf: list[str] = []
    for ch in rest:
        if ch == "(":
            depth += 1
            buf.append(ch)
        elif ch == ")":
            if depth == 0:
                break
            depth -= 1
            buf.append(ch)
        elif ch == "," and depth == 0:
            break
        else:
            buf.append(ch)
    raw = "".join(buf).strip().lstrip("&").strip()
    if not raw or raw.startswith("("):
        return ""
    return raw


def _extract_lock_acquires(
    lines: list[str],
    vocab: DomainVocabulary = _EMPTY_VOCAB,
) -> list[tuple[int, str, str, str]]:
    """Extract (line_idx, lock_function, expected_unlock, lock_object).

    ``lock_object`` is the normalised first argument (e.g. ``ep->lock``).
    Empty string when the argument cannot be parsed.
    """
    pairs = list(_LOCK_PAIRS)
    used = {m.pattern for m, _ in _LOCK_PAIRS}
    # Exact pairs first (vocab packs, study-discovered paired_operations).
    for acq, rel in sorted(vocab.lock_pairs):
        pat_str = rf"\b({re.escape(acq)})\s*\("
        if pat_str in used:
            continue
        pairs.append((re.compile(pat_str), rel))
        used.add(pat_str)
    # Name-set fallback: heuristically pair acquire/release names when
    # only the flat sets are available.
    if vocab.lock_acquires and vocab.lock_releases:
        for acq in sorted(vocab.lock_acquires):
            pat_str = rf"\b({re.escape(acq)})\s*\("
            if pat_str in used:
                continue
            for rel in sorted(vocab.lock_releases):
                if _paired_name_match(acq, rel):
                    pairs.append((re.compile(pat_str), rel))
                    used.add(pat_str)
                    break
    # Suffix-based discovery: scan for *_lock() / *_unlock() pairs
    # not already covered by explicit pairs or vocab.
    known_acq = {p.pattern for p, _ in pairs}
    full_text = "\n".join(lines)
    for m_lock in re.finditer(r"\b(\w+_lock)\s*\(", full_text):
        acq_name = m_lock.group(1)
        pat_str = rf"\b({re.escape(acq_name)})\s*\("
        if pat_str in known_acq:
            continue
        unlock_name = acq_name.replace("_lock", "_unlock", 1)
        if re.search(rf"\b{re.escape(unlock_name)}\s*\(", full_text):
            pairs.append((re.compile(pat_str), unlock_name))
            known_acq.add(pat_str)

    results: list[tuple[int, str, str, str]] = []
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith(("//", "/*")):
            continue
        for pattern, unlock_name in pairs:
            m = pattern.search(line)
            if m:
                lock_obj = _extract_lock_object(line, m.end())
                results.append((i, m.group(1), unlock_name, lock_obj))
                break
    return results


def _paired_name_match(acquire: str, release: str) -> bool:
    """Heuristic: names share a root with lock/unlock or acquire/release."""
    swaps = [
        ("lock", "unlock"), ("acquire", "release"),
        ("read_lock", "read_unlock"), ("write_lock", "write_unlock"),
        ("down_", "up_"), ("get", "put"),
    ]
    a, r = acquire.lower(), release.lower()
    for s_acq, s_rel in swaps:
        if s_acq in a and r == a.replace(s_acq, s_rel, 1):
            return True
    return a.rsplit("_", 1)[0] == r.rsplit("_", 1)[0]


def _find_unlocks(
    lines: list[str],
    unlock_name: str,
    lock_object: str = "",
) -> list[int]:
    """Find line indices where unlock_name is called on lock_object."""
    pat = re.compile(
        rf"\b{re.escape(unlock_name)}(?:_irq(?:restore)?|_bh)?\s*\("
    )
    results: list[int] = []
    for i, line in enumerate(lines):
        m = pat.search(line)
        if not m:
            continue
        if lock_object:
            obj = _extract_lock_object(line, m.end())
            if obj and obj != lock_object:
                continue
        results.append(i)
    return results


def _extract_returns(lines: list[str]) -> list[int]:
    """Extract line indices of return statements."""
    return [i for i, line in enumerate(lines) if _RETURN_RE.match(line)]


def _extract_goto_targets(lines: list[str]) -> dict[int, str]:
    """Map line_idx → goto target label."""
    results: dict[int, str] = {}
    for i, line in enumerate(lines):
        m = _GOTO_RE.search(line)
        if m:
            results[i] = m.group(1)
    return results


def _extract_labels(lines: list[str]) -> dict[str, int]:
    """Map label_name → line_idx."""
    results: dict[str, int] = {}
    for i, line in enumerate(lines):
        m = _LABEL_RE.match(line)
        if m and m.group(1) not in ("default", "case"):
            results[m.group(1)] = i
    return results


def _return_is_in_error_goto_block(
    ret_line: int,
    lines: list[str],
    goto_targets: dict[int, str],
    labels: dict[str, int],
    unlock_name: str,
) -> bool:
    """Check if the return is in a goto-target block that unlocks."""
    for label_line in labels.values():
        if label_line > ret_line:
            continue
        if ret_line - label_line > 10:
            continue
        block = "\n".join(lines[label_line:ret_line + 1])
        if unlock_name in block:
            return True
    return False


def _try_z3_lock_discipline(
    guard_text: str,
    lock_func: str,
    ret_line: int,
    bypassed_unlocks: list[str],
) -> LockDisciplineResult | None:
    """Z3 feasibility check on the guard of a lock-held return."""
    if not guard_text:
        return None
    try:
        import importlib.util
        if importlib.util.find_spec("z3") is None:
            return None
    except ImportError:
        return None

    payload = pickle.dumps(("lock_discipline", guard_text, lock_func, ret_line))
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _Z3_CHILD_SCRIPT_V2],
            input=payload, capture_output=True, timeout=10,
            check=False,
            env=_z3_child_env(),
        )
        if proc.returncode == 0:
            try:
                return pickle.loads(proc.stdout)
            except Exception:  # malformed child output degrades to None
                logger.debug("z3 child output unpicklable", exc_info=True)
    except subprocess.TimeoutExpired:
        logger.debug("z3 child timed out")
    return None


def _z3_lock_discipline_check(
    guard_text: str,
    lock_func: str,
    ret_line: int,
) -> LockDisciplineResult:
    """Z3: Check if a lock-held return guard is satisfiable."""
    from core.smt_solver.availability import z3
    from core.smt_solver.session import new_solver

    comparisons = _COMPARISON_RE.findall(guard_text)
    comparisons_rev = _COMPARISON_REV_RE.findall(guard_text)

    constraints: list[BoundsConstraint] = []
    for var, op, val_str in comparisons:
        val = _try_parse_int(val_str)
        if val is not None:
            constraints.append(BoundsConstraint(var, op, val, guard_text))
    for val_str, op, var in comparisons_rev:
        val = _try_parse_int(val_str)
        if val is not None:
            flipped = _flip_operator(op)
            if flipped:
                constraints.append(BoundsConstraint(var, flipped, val, guard_text))

    if not constraints:
        return LockDisciplineResult(
            violation_found=True,
            lock_type=lock_func,
            return_line=ret_line,
            reasoning=(
                f"return at line {ret_line} guarded by '{guard_text.strip()}' "
                f"holds {lock_func} — guard is non-numeric (always feasible)"
            ),
        )

    solver = new_solver()
    vars_map: dict[str, z3.ArithRef] = {}
    for c in constraints:
        if c.variable not in vars_map:
            vars_map[c.variable] = z3.Int(c.variable)

    for c in constraints:
        v = vars_map[c.variable]
        if c.operator == "<":
            solver.add(v < c.bound_value)
        elif c.operator == "<=":
            solver.add(v <= c.bound_value)
        elif c.operator == ">":
            solver.add(v > c.bound_value)
        elif c.operator == ">=":
            solver.add(v >= c.bound_value)
        elif c.operator == "==":
            solver.add(v == c.bound_value)
        elif c.operator == "!=":
            solver.add(v != c.bound_value)

    result = solver.check()
    if result == z3.sat:
        model = solver.model()
        witness: dict[str, Any] = {}
        for name, var in vars_map.items():
            val = model[var]
            if val is not None:
                try:
                    witness[name] = val.as_long()
                except AttributeError:
                    pass
        return LockDisciplineResult(
            violation_found=True,
            lock_type=lock_func,
            return_line=ret_line,
            reasoning=(
                f"Z3 SAT: return at line {ret_line} with {lock_func} held — "
                f"guard '{guard_text.strip()}' is satisfiable"
            ),
            witness=witness if witness else None,
        )
    elif result == z3.unsat:
        return LockDisciplineResult(
            violation_found=False,
            reasoning=(
                f"Z3 UNSAT: guard '{guard_text.strip()}' is infeasible — "
                f"lock-held return path unreachable"
            ),
        )
    return LockDisciplineResult(
        violation_found=True,
        lock_type=lock_func,
        return_line=ret_line,
        reasoning="Z3 timeout — conservatively flag lock discipline issue",
    )


# ---------------------------------------------------------------------------
# Error path resource leak detection
# ---------------------------------------------------------------------------

# SEED SET — universal libc allocators, the two canonical kernel
# exemplars, and the subsystem shape regex. The kernel allocator bulk
# (kvmalloc, devm_kzalloc, alloc_skb, kstrdup, ...) lives in the
# linux_kernel vocab pack; project allocators arrive via
# DomainVocabulary.allocators / refcount_gets. Do not grow this list —
# teach the study loop / pack instead.
_ALLOC_PATTERNS = [
    re.compile(r"\b(\w+)\s*=\s*(malloc|calloc|realloc)\s*\("),
    re.compile(r"\b(\w+)\s*=\s*(kmalloc|kzalloc)\s*\("),
    re.compile(r"\b(\w+)\s*=\s*(\w+_alloc_\w+)\s*\("),
]

# SEED SET — universal free plus the canonical kernel exemplar; the
# kernel deallocator bulk lives in the linux_kernel vocab pack, and
# project deallocators arrive via DomainVocabulary.deallocators /
# refcount_puts (the *_free_* shape regex below stays).
_FREE_NAMES = frozenset({
    "free", "kfree",
})

_FREE_RE = re.compile(r"\b(\w+_free_\w+)\s*\(")

_ERROR_RETURN_RE = re.compile(
    r"^\s*return\s+(-\w+|NULL|ERR_PTR\s*\(|err|ret|rc|status)",
    re.MULTILINE,
)


@dataclass
class ResourceLeakResult:
    """Result of checking error-path resource leak."""

    leak_found: bool = False
    alloc_var: str = ""
    alloc_func: str = ""
    alloc_line: int = 0
    return_line: int = 0
    reasoning: str = ""
    witness: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "leak_found": self.leak_found,
            "reasoning": self.reasoning,
        }
        if self.alloc_var:
            d["alloc_var"] = self.alloc_var
        if self.alloc_func:
            d["alloc_func"] = self.alloc_func
        if self.alloc_line:
            d["alloc_line"] = self.alloc_line
        if self.return_line:
            d["return_line"] = self.return_line
        if self.witness:
            d["witness"] = self.witness
        return d


def check_resource_leak(
    source: str,
    vocab: DomainVocabulary = _EMPTY_VOCAB,
) -> ResourceLeakResult:
    """Detect allocated resources not freed on error return paths."""
    from .safety_contract import assert_boost_only
    assert_boost_only("condition_smt")

    lines = source.split("\n")
    allocs = _extract_allocs(lines, vocab)
    if not allocs:
        return ResourceLeakResult(reasoning="no allocations found")

    error_returns = _extract_error_returns(lines)
    if not error_returns:
        return ResourceLeakResult(reasoning="no error returns found")

    goto_targets = _extract_goto_targets(lines)
    labels = _extract_labels(lines)

    for alloc_line, var_name, alloc_func in allocs:
        for ret_line in error_returns:
            if ret_line <= alloc_line:
                continue

            free_line = _var_freed_between(
                lines, var_name, alloc_line, ret_line, vocab,
            )
            bypassed = False
            if free_line >= 0:
                if not _goto_bypasses_free(
                    lines, goto_targets, labels,
                    alloc_line, free_line, var_name, vocab,
                ):
                    continue
                bypassed = True

            if _return_gotos_to_free(
                ret_line, lines, goto_targets, labels, var_name, vocab,
            ):
                continue

            if not bypassed and _null_guarded_return(
                lines, alloc_line, ret_line, var_name,
            ):
                continue

            guard = _find_enclosing_guard(lines, ret_line)
            z3_result = _try_z3_resource_leak(
                guard, var_name, alloc_func, alloc_line + 1, ret_line + 1,
            )
            if z3_result is not None:
                return z3_result

            return ResourceLeakResult(
                leak_found=True,
                alloc_var=var_name,
                alloc_func=alloc_func,
                alloc_line=alloc_line + 1,
                return_line=ret_line + 1,
                reasoning=(
                    f"'{var_name}' allocated by {alloc_func} at line "
                    f"{alloc_line + 1} not freed before error return at "
                    f"line {ret_line + 1}"
                ),
            )

    return ResourceLeakResult(
        reasoning="all allocations freed on error paths",
    )


def _extract_allocs(
    lines: list[str],
    vocab: DomainVocabulary = _EMPTY_VOCAB,
) -> list[tuple[int, str, str]]:
    """Extract (line_idx, variable_name, alloc_function) tuples."""
    patterns = list(_ALLOC_PATTERNS)
    if vocab.allocators:
        names = "|".join(re.escape(n) for n in sorted(vocab.allocators))
        patterns.append(re.compile(rf"\b(\w+)\s*=\s*({names})\s*\("))
    if vocab.refcount_gets:
        names = "|".join(re.escape(n) for n in sorted(vocab.refcount_gets))
        patterns.append(re.compile(rf"\b(\w+)\s*=\s*({names})\s*\("))

    results: list[tuple[int, str, str]] = []
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith(("//", "/*")):
            continue
        for pattern in patterns:
            m = pattern.search(line)
            if m:
                results.append((i, m.group(1), m.group(2)))
                break
    return results


def _extract_error_returns(lines: list[str]) -> list[int]:
    """Extract line indices of error return statements."""
    results: list[int] = []
    for i, line in enumerate(lines):
        if _ERROR_RETURN_RE.match(line):
            results.append(i)
    return results


def _build_free_patterns(
    var_name: str,
    vocab: DomainVocabulary = _EMPTY_VOCAB,
) -> tuple[re.Pattern, re.Pattern]:
    """Build free-detection regexes, extended with study-discovered names."""
    all_frees = _FREE_NAMES | vocab.deallocators | vocab.refcount_puts
    free_pat = re.compile(
        rf"\b({'|'.join(re.escape(f) for f in sorted(all_frees))})"
        rf"\s*\(\s*{re.escape(var_name)}\b"
    )
    subsystem_free_pat = re.compile(
        rf"\b\w+_free_\w+\s*\(\s*{re.escape(var_name)}\b"
    )
    return free_pat, subsystem_free_pat


def _var_freed_between(
    lines: list[str], var_name: str, start: int, end: int,
    vocab: DomainVocabulary = _EMPTY_VOCAB,
) -> int:
    """Return line index where var_name is freed, or -1 if not found."""
    free_pat, subsystem_free_pat = _build_free_patterns(var_name, vocab)
    for i in range(start + 1, min(end, len(lines))):
        if free_pat.search(lines[i]) or subsystem_free_pat.search(lines[i]):
            return i
    return -1


def _goto_bypasses_free(
    lines: list[str],
    goto_targets: dict[int, str],
    labels: dict[str, int],
    alloc_line: int,
    free_line: int,
    var_name: str,
    vocab: DomainVocabulary = _EMPTY_VOCAB,
) -> bool:
    """Detect gotos between alloc and return that jump past the free.

    Common kernel pattern: error_ci frees ci, error does not.
    ``goto error`` after a successful alloc bypasses error_ci's free.
    Only flags gotos that follow a successful-alloc guard (past the
    IS_ERR / NULL check) so the first goto-on-alloc-failure is ignored.
    """
    err_guard_end = alloc_line
    esc = re.escape(var_name)
    for i in range(alloc_line + 1, min(free_line, len(lines))):
        line = lines[i].strip()
        if re.search(rf"if\s*\(\s*!{esc}\s*\)", line) or re.search(
            rf"if\s*\(\s*(?:IS_ERR|!)\s*\(\s*{esc}\s*\)", line,
        ) or re.search(
            rf"if\s*\(\s*{esc}\s*==\s*NULL\s*\)", line,
        ):
            brace_depth = 0
            for j in range(i, min(free_line, len(lines))):
                brace_depth += lines[j].count("{") - lines[j].count("}")
                if brace_depth <= 0:
                    if j == i:
                        # Braceless if: guard covers the next statement
                        for nxt in range(j + 1, min(j + 4, len(lines))):
                            nxt_s = lines[nxt].strip()
                            if nxt_s and not nxt_s.startswith(("//", "/*")):
                                err_guard_end = nxt
                                break
                        else:
                            err_guard_end = j
                    else:
                        err_guard_end = j
                    break
            else:
                err_guard_end = i + 3
            break

    free_pat, subsystem_free_pat = _build_free_patterns(var_name, vocab)
    ownership_re = re.compile(rf"->\w+\s*=\s*{esc}\s*;")

    for goto_line in range(err_guard_end + 1, free_line):
        if goto_line not in goto_targets:
            continue
        target_label = goto_targets[goto_line]
        target_line = labels.get(target_label)
        if target_line is None or target_line <= free_line:
            continue
        block = "\n".join(lines[target_line:min(target_line + 10, len(lines))])
        if free_pat.search(block) or subsystem_free_pat.search(block):
            continue
        # Ownership transfer: var stored into a struct field before this
        # goto means cleanup happens via the enclosing struct (callbacks,
        # completion handlers, embedded references).
        if any(
            ownership_re.search(lines[k])
            for k in range(alloc_line + 1, goto_line)
        ):
            continue
        return True
    return False


def _return_gotos_to_free(
    ret_line: int,
    lines: list[str],
    goto_targets: dict[int, str],
    labels: dict[str, int],
    var_name: str,
    vocab: DomainVocabulary = _EMPTY_VOCAB,
) -> bool:
    """Check if there's a goto before the return leading to a block that frees."""
    all_frees = _FREE_NAMES | vocab.deallocators | vocab.refcount_puts
    for goto_line in range(max(0, ret_line - 3), ret_line):
        if goto_line in goto_targets:
            label = goto_targets[goto_line]
            label_line = labels.get(label)
            if label_line is not None:
                block = "\n".join(
                    lines[label_line:min(label_line + 10, len(lines))]
                )
                if var_name in block and (
                    any(f in block for f in all_frees)
                    or _FREE_RE.search(block)
                ):
                    return True
    return False


def _null_guarded_return(
    lines: list[str], alloc_line: int, ret_line: int, var_name: str,
) -> bool:
    """Check if the error return is guarded by a NULL check on the alloc var.

    Pattern: if (!ptr) return -ENOMEM; — this is BEFORE any use,
    so there's nothing to leak (the alloc failed).

    Only returns True if ret_line is INSIDE the null-check block (within
    3 lines of the check).  A return further away is after the alloc
    succeeded and may leak.
    """
    null_pats = [
        re.compile(rf"if\s*\(\s*!{re.escape(var_name)}\s*\)"),
        re.compile(rf"if\s*\(\s*{re.escape(var_name)}\s*==\s*NULL\s*\)"),
        re.compile(rf"if\s*\(\s*IS_ERR\s*\(\s*{re.escape(var_name)}\s*\)\s*\)"),
    ]
    for i in range(alloc_line + 1, min(ret_line + 1, len(lines))):
        line = lines[i]
        if any(p.search(line) for p in null_pats) and ret_line <= i + 3:
            return True
    return False


def _try_z3_resource_leak(
    guard_text: str,
    var_name: str,
    alloc_func: str,
    alloc_line: int,
    ret_line: int,
) -> ResourceLeakResult | None:
    """Z3 feasibility check on the guard of a leak-path return."""
    if not guard_text:
        return None
    try:
        import importlib.util
        if importlib.util.find_spec("z3") is None:
            return None
    except ImportError:
        return None

    payload = pickle.dumps((
        "resource_leak", guard_text, var_name, alloc_func,
        alloc_line, ret_line,
    ))
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _Z3_CHILD_SCRIPT_V2],
            input=payload, capture_output=True, timeout=10,
            check=False,
            env=_z3_child_env(),
        )
        if proc.returncode == 0:
            try:
                return pickle.loads(proc.stdout)
            except Exception:  # malformed child output degrades to None
                logger.debug("z3 child output unpicklable", exc_info=True)
    except subprocess.TimeoutExpired:
        logger.debug("z3 child timed out")
    return None


def _z3_resource_leak_check(
    guard_text: str,
    var_name: str,
    alloc_func: str,
    alloc_line: int,
    ret_line: int,
) -> ResourceLeakResult:
    """Z3: Check if a leak-path guard is satisfiable."""
    from core.smt_solver.availability import z3
    from core.smt_solver.session import new_solver

    comparisons = _COMPARISON_RE.findall(guard_text)
    comparisons_rev = _COMPARISON_REV_RE.findall(guard_text)

    constraints: list[BoundsConstraint] = []
    for var, op, val_str in comparisons:
        val = _try_parse_int(val_str)
        if val is not None:
            constraints.append(BoundsConstraint(var, op, val, guard_text))
    for val_str, op, var in comparisons_rev:
        val = _try_parse_int(val_str)
        if val is not None:
            flipped = _flip_operator(op)
            if flipped:
                constraints.append(BoundsConstraint(var, flipped, val, guard_text))

    if not constraints:
        return ResourceLeakResult(
            leak_found=True,
            alloc_var=var_name,
            alloc_func=alloc_func,
            alloc_line=alloc_line,
            return_line=ret_line,
            reasoning=(
                f"error return at line {ret_line} guarded by "
                f"'{guard_text.strip()}' leaks '{var_name}' — "
                f"guard is non-numeric (always feasible)"
            ),
        )

    solver = new_solver()
    vars_map: dict[str, z3.ArithRef] = {}
    for c in constraints:
        if c.variable not in vars_map:
            vars_map[c.variable] = z3.Int(c.variable)

    for c in constraints:
        v = vars_map[c.variable]
        if c.operator == "<":
            solver.add(v < c.bound_value)
        elif c.operator == "<=":
            solver.add(v <= c.bound_value)
        elif c.operator == ">":
            solver.add(v > c.bound_value)
        elif c.operator == ">=":
            solver.add(v >= c.bound_value)
        elif c.operator == "==":
            solver.add(v == c.bound_value)
        elif c.operator == "!=":
            solver.add(v != c.bound_value)

    result = solver.check()
    if result == z3.sat:
        model = solver.model()
        witness: dict[str, Any] = {}
        for name, zvar in vars_map.items():
            val = model[zvar]
            if val is not None:
                try:
                    witness[name] = val.as_long()
                except AttributeError:
                    pass
        return ResourceLeakResult(
            leak_found=True,
            alloc_var=var_name,
            alloc_func=alloc_func,
            alloc_line=alloc_line,
            return_line=ret_line,
            reasoning=(
                f"Z3 SAT: error return at line {ret_line} leaks "
                f"'{var_name}' — guard '{guard_text.strip()}' "
                f"is satisfiable"
            ),
            witness=witness if witness else None,
        )
    elif result == z3.unsat:
        return ResourceLeakResult(
            leak_found=False,
            reasoning=(
                f"Z3 UNSAT: guard '{guard_text.strip()}' is infeasible — "
                f"leak path unreachable"
            ),
        )
    return ResourceLeakResult(
        leak_found=True,
        alloc_var=var_name,
        alloc_func=alloc_func,
        alloc_line=alloc_line,
        return_line=ret_line,
        reasoning="Z3 timeout — conservatively flag resource leak",
    )


# ---------------------------------------------------------------------------
# Null propagation detection
# ---------------------------------------------------------------------------

# Derived from the _NULLABLE_CALL_NAMES seed set below (kept as a
# module-level compiled default for the no-vocab fast path).

_NULL_CHECK_RE_TEMPLATE = r"(?:if\s*\(\s*!{var}\s*\)|if\s*\(\s*{var}\s*==\s*NULL\s*\)|if\s*\(\s*IS_ERR(?:_OR_NULL)?\s*\(\s*{var}\s*\)\s*\)|if\s*\(\s*unlikely\s*\(\s*!{var}\s*\)\s*\))"

_DEREF_RE_TEMPLATE = r"(?:{var}\s*->|(?:\*\s*{var})\b)"


@dataclass
class NullPropagationResult:
    """Result of checking null propagation."""

    null_deref_found: bool = False
    var_name: str = ""
    source_func: str = ""
    assign_line: int = 0
    deref_line: int = 0
    reasoning: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "null_deref_found": self.null_deref_found,
            "reasoning": self.reasoning,
        }
        if self.var_name:
            d["var_name"] = self.var_name
        if self.source_func:
            d["source_func"] = self.source_func
        if self.assign_line:
            d["assign_line"] = self.assign_line
        if self.deref_line:
            d["deref_line"] = self.deref_line
        return d


def check_null_propagation(
    source: str, vocab: DomainVocabulary | None = None,
) -> NullPropagationResult:
    """Detect use of a possibly-NULL pointer without a null check."""
    from .safety_contract import assert_boost_only
    assert_boost_only("condition_smt")

    lines = source.split("\n")
    assigns = _extract_nullable_assigns(lines, vocab=vocab)
    if not assigns:
        return NullPropagationResult(reasoning="no nullable assignments found")

    for assign_line, var_name, source_func in assigns:
        null_check = _find_null_check(lines, var_name, assign_line)
        first_deref = _find_first_deref(lines, var_name, assign_line)

        if first_deref is None:
            continue

        if (
            null_check is not None
            and null_check < first_deref
            and _null_check_exits(lines, null_check)
        ):
            continue

        return NullPropagationResult(
            null_deref_found=True,
            var_name=var_name,
            source_func=source_func,
            assign_line=assign_line + 1,
            deref_line=first_deref + 1,
            reasoning=(
                f"'{var_name}' from {source_func} (line {assign_line + 1}) "
                f"dereferenced at line {first_deref + 1} without null check"
            ),
        )

    return NullPropagationResult(
        reasoning="all nullable pointers checked before use",
    )


# SEED SET — universal libc allocators plus the two canonical kernel
# exemplars. The kernel bulk (kv*/devm_* allocators, driver-model
# getters like dev_get_drvdata / platform_get_resource) lives in the
# linux_kernel vocab pack; project names arrive via
# DomainVocabulary.allocators and .nullable_returns. Do not grow this
# list — teach the study loop / pack instead.
_NULLABLE_CALL_NAMES = frozenset({
    "malloc", "calloc", "realloc",
    "kmalloc", "kzalloc",
})


def _build_nullable_re(extra: frozenset = frozenset()) -> re.Pattern:
    names = _NULLABLE_CALL_NAMES | extra
    alts = "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))
    return re.compile(rf"\b(\w+)\s*=\s*({alts})\s*\(")


_NULLABLE_CALLS = _build_nullable_re()


_EXIT_RE = re.compile(
    r"\b(return\b|goto\b|break\b|abort\s*\(|BUG\s*\(|panic\s*\()",
)


def _null_check_exits(lines: list[str], check_line: int) -> bool:
    """Verify the null-check block contains an exit (return/goto/break)."""
    for i in range(check_line, min(check_line + 4, len(lines))):
        if _EXIT_RE.search(lines[i]):
            return True
    return False


def _extract_nullable_assigns(
    lines: list[str],
    vocab: DomainVocabulary | None = None,
) -> list[tuple[int, str, str]]:
    """Extract (line_idx, var_name, source_function) from nullable calls."""
    extra = (
        (vocab.allocators | vocab.nullable_returns | vocab.refcount_gets)
        if vocab is not None else frozenset()
    )
    nullable_re = _NULLABLE_CALLS if not extra else _build_nullable_re(extra)
    results: list[tuple[int, str, str]] = []
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith(("//", "/*")):
            continue
        m = nullable_re.search(line)
        if m:
            results.append((i, m.group(1), m.group(2)))
    return results


def _find_null_check(
    lines: list[str], var_name: str, after_line: int,
) -> int | None:
    """Find first null check of var_name after after_line."""
    pat = re.compile(
        _NULL_CHECK_RE_TEMPLATE.format(var=re.escape(var_name))
    )
    for i in range(after_line + 1, len(lines)):
        if pat.search(lines[i]):
            return i
    return None


def _find_first_deref(
    lines: list[str], var_name: str, after_line: int,
) -> int | None:
    """Find first dereference of var_name after after_line."""
    pat = re.compile(
        _DEREF_RE_TEMPLATE.format(var=re.escape(var_name))
    )
    for i in range(after_line + 1, len(lines)):
        stripped = lines[i].lstrip()
        if stripped.startswith(("//", "/*")):
            continue
        if pat.search(lines[i]):
            return i
    return None


# ---------------------------------------------------------------------------
# Integer narrowing/widening detection
# ---------------------------------------------------------------------------

_TYPE_WIDTHS: dict[str, int] = {
    "char": 8, "signed char": 8, "unsigned char": 8,
    "u8": 8, "s8": 8, "__u8": 8, "__s8": 8, "uint8_t": 8, "int8_t": 8,
    "short": 16, "unsigned short": 16,
    "u16": 16, "s16": 16, "__u16": 16, "__s16": 16, "uint16_t": 16, "int16_t": 16,
    "int": 32, "unsigned int": 32, "unsigned": 32,
    "u32": 32, "s32": 32, "__u32": 32, "__s32": 32, "uint32_t": 32, "int32_t": 32,
    "long": 64, "unsigned long": 64, "long long": 64, "unsigned long long": 64,
    "u64": 64, "s64": 64, "__u64": 64, "__s64": 64, "uint64_t": 64, "int64_t": 64,
    "size_t": 64, "ssize_t": 64, "off_t": 64, "loff_t": 64,
    "uintptr_t": 64, "ptrdiff_t": 64,
}

_NARROWING_ASSIGN_RE = re.compile(
    r"(?:^|\s)"
    r"((?:unsigned\s+)?(?:char|short|int|long(?:\s+long)?)"
    r"|u8|u16|u32|u64|s8|s16|s32|s64"
    r"|__u8|__u16|__u32|__u64|__s8|__s16|__s32|__s64"
    r"|uint8_t|uint16_t|uint32_t|uint64_t"
    r"|int8_t|int16_t|int32_t|int64_t"
    r"|size_t|ssize_t|off_t|loff_t)"
    r"\s+(\w+)\s*="
)

_CAST_NARROWING_RE = re.compile(
    r"\(\s*((?:unsigned\s+)?(?:char|short|int|long(?:\s+long)?)"
    r"|u8|u16|u32|u64|s8|s16|s32|s64"
    r"|__u8|__u16|__u32|__u64|__s8|__s16|__s32|__s64"
    r"|uint8_t|uint16_t|uint32_t|uint64_t"
    r"|int8_t|int16_t|int32_t|int64_t"
    r"|size_t|ssize_t|off_t|loff_t)\s*\)"
    r"\s*(\w+)"
)

_BOUNDS_CHECK_RE_TEMPLATE = (
    r"if\s*\(\s*{var}\s*[<>]=?\s*\w+\s*\)"
    r"|if\s*\(\s*{var}\s*[<>]=?\s*\d+\s*\)"
    r"|min\s*\(\s*{var}\s*,"
    r"|min_t\s*\([^,]+,\s*{var}\s*,"
    r"|clamp\s*\(\s*{var}\s*,"
)


@dataclass
class IntegerNarrowingResult:
    """Result of checking integer narrowing."""

    narrowing_found: bool = False
    source_type: str = ""
    dest_type: str = ""
    source_width: int = 0
    dest_width: int = 0
    assign_line: int = 0
    reasoning: str = ""
    witness: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "narrowing_found": self.narrowing_found,
            "reasoning": self.reasoning,
        }
        if self.source_type:
            d["source_type"] = self.source_type
        if self.dest_type:
            d["dest_type"] = self.dest_type
        if self.source_width:
            d["source_width"] = self.source_width
        if self.dest_width:
            d["dest_width"] = self.dest_width
        if self.assign_line:
            d["assign_line"] = self.assign_line
        if self.witness:
            d["witness"] = self.witness
        return d


def check_integer_narrowing(source: str) -> IntegerNarrowingResult:
    """Detect implicit integer narrowing without bounds checking."""
    from .safety_contract import assert_boost_only
    assert_boost_only("condition_smt")

    lines = source.split("\n")
    is_go = any(
        "func " in ln or "package " in ln
        for ln in lines[:30]
    )

    if is_go:
        result = _check_integer_narrowing_go(lines)
        if result.narrowing_found:
            return result

    params = _extract_param_types(source)
    decls = _extract_local_decls(lines)

    all_vars: dict[str, tuple[str, int]] = {}
    for name, type_str in {**params, **decls}.items():
        width = _type_to_width(type_str)
        if width:
            all_vars[name] = (type_str, width)

    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith(("//", "/*")):
            continue

        m = _NARROWING_ASSIGN_RE.search(line)
        if m:
            dest_type = m.group(1).strip()
            dest_var = m.group(2)
            dest_width = _type_to_width(dest_type)
            if not dest_width:
                continue

            rhs = line[m.end():]
            for src_var, (src_type, src_width) in all_vars.items():
                if src_var == dest_var:
                    continue
                if src_width <= dest_width:
                    continue
                if re.search(rf"\b{re.escape(src_var)}\b", rhs):
                    if _has_bounds_check_before(lines, src_var, i):
                        continue
                    # Skip when the wide var appears only as a
                    # function argument — the narrowing is from
                    # the return value, not the argument.
                    if _var_only_in_call_args(rhs, src_var):
                        continue

                    z3_result = _try_z3_integer_narrowing(
                        src_var, src_type, dest_type,
                        src_width, dest_width, i + 1,
                    )
                    if z3_result is not None:
                        return z3_result

                    return IntegerNarrowingResult(
                        narrowing_found=True,
                        source_type=src_type,
                        dest_type=dest_type,
                        source_width=src_width,
                        dest_width=dest_width,
                        assign_line=i + 1,
                        reasoning=(
                            f"'{src_var}' ({src_type}, {src_width}-bit) "
                            f"narrowed to '{dest_var}' ({dest_type}, "
                            f"{dest_width}-bit) at line {i + 1} "
                            f"without bounds check"
                        ),
                    )

    return IntegerNarrowingResult(
        reasoning="no unchecked integer narrowing found",
    )


def _type_to_width(type_str: str) -> int | None:
    """Map a C type string to its width in bits."""
    normalized = type_str.strip()
    return _TYPE_WIDTHS.get(normalized)


_GO_TYPE_WIDTHS: dict[str, int] = {
    "byte": 8, "uint8": 8, "int8": 8,
    "uint16": 16, "int16": 16,
    "uint32": 32, "int32": 32, "rune": 32,
    "uint64": 64, "int64": 64,
    "int": 64, "uint": 64, "uintptr": 64,
}

_GO_CAST_RE = re.compile(
    r"(\w+)\s*(?::?=)\s*((?:u?int(?:8|16|32|64)?|byte|rune|uint|uintptr))\s*\(\s*(\w+)\s*\)"
)

_GO_ATOI_RE = re.compile(
    r"(\w+)\s*(?:,\s*\w+)?\s*(?::?=)\s*strconv\.(?:Atoi|ParseInt|ParseUint)\s*\("
)

_GO_BOUNDS_CHECK_RE = re.compile(
    r"if\s+\w+\s*[<>]=?\s*(?:math\.Max|math\.Min)?\w*\s*\{"
    r"|if\s+\w+\s*<\s*0\s*(?:\|\||&&)"
    r"|if\s+\w+\s*>\s*math\.Max"
)


def _check_integer_narrowing_go(lines: list[str]) -> IntegerNarrowingResult:
    """Go-specific integer narrowing via explicit type casts."""
    wide_vars: dict[str, tuple[str, int]] = {}

    for i, line in enumerate(lines):
        am = _GO_ATOI_RE.search(line)
        if am:
            wide_vars[am.group(1)] = ("int", 64)

    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith("//"):
            continue

        cm = _GO_CAST_RE.search(line)
        if not cm:
            continue

        dest_type = cm.group(2)
        src_var = cm.group(3)

        dest_width = _GO_TYPE_WIDTHS.get(dest_type)
        if not dest_width:
            continue

        src_info = wide_vars.get(src_var)
        if not src_info:
            continue
        src_type, src_width = src_info
        if src_width <= dest_width:
            continue

        has_check = False
        for j in range(max(0, i - 15), i):
            if re.search(
                rf"\b{re.escape(src_var)}\b.*[<>]=?\s*(?:math\.Max|0\b|\d{{4,}})",
                lines[j],
            ):
                has_check = True
                break
            if _GO_BOUNDS_CHECK_RE.search(lines[j]) and re.search(
                rf"\b{re.escape(src_var)}\b", lines[j],
            ):
                has_check = True
                break
        if has_check:
            continue

        return IntegerNarrowingResult(
            narrowing_found=True,
            source_type=src_type,
            dest_type=dest_type,
            source_width=src_width,
            dest_width=dest_width,
            assign_line=i + 1,
            reasoning=(
                f"'{src_var}' ({src_type}, {src_width}-bit) narrowed "
                f"to {dest_type} ({dest_width}-bit) via explicit cast "
                f"at line {i + 1} without bounds check"
            ),
        )

    return IntegerNarrowingResult(
        reasoning="no unchecked integer narrowing found",
    )


def _extract_param_types(source: str) -> dict[str, str]:
    """Extract parameter name → type from function signature."""
    results: dict[str, str] = {}
    sig_match = re.search(r"\([^)]*\)", source[:500])
    if not sig_match:
        return results
    params_str = sig_match.group(0)[1:-1]
    for param in params_str.split(","):
        param = param.strip()
        parts = param.rsplit(None, 1)
        if len(parts) == 2:
            type_str = parts[0].replace("*", "").strip()
            name = parts[1].replace("*", "").strip()
            if name and type_str:
                results[name] = type_str
    return results


def _extract_local_decls(lines: list[str]) -> dict[str, str]:
    """Extract local variable declarations with types."""
    results: dict[str, str] = {}
    for line in lines:
        m = _NARROWING_ASSIGN_RE.search(line)
        if m:
            results[m.group(2)] = m.group(1).strip()
    return results


def _var_only_in_call_args(rhs: str, var_name: str) -> bool:
    """True when *var_name* appears on *rhs* only inside function-call parens.

    ``int x = func(wide_var);``  → wide_var is a call argument, not the
    value being assigned (the return value of func is).
    """
    # Strip the var from inside balanced (...) groups, then check if it
    # still appears.
    depth = 0
    stripped: list = []
    for ch in rhs:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0:
            stripped.append(ch)
    remainder = "".join(stripped)
    return not re.search(rf"\b{re.escape(var_name)}\b", remainder)


def _has_bounds_check_before(
    lines: list[str], var_name: str, before_line: int,
) -> bool:
    """Check if there's a bounds check on var_name before the given line."""
    pat = re.compile(
        _BOUNDS_CHECK_RE_TEMPLATE.format(var=re.escape(var_name))
    )
    for i in range(max(0, before_line - 15), before_line):
        if pat.search(lines[i]):
            return True
    return False


def _try_z3_integer_narrowing(
    var_name: str,
    src_type: str,
    dest_type: str,
    src_width: int,
    dest_width: int,
    assign_line: int,
) -> IntegerNarrowingResult | None:
    """Z3 check: can a value outside dest range reach the narrowing?"""
    try:
        import importlib.util
        if importlib.util.find_spec("z3") is None:
            return None
    except ImportError:
        return None

    payload = pickle.dumps((
        "integer_narrowing", var_name, src_type, dest_type, assign_line,
    ))
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _Z3_CHILD_SCRIPT_V2],
            input=payload, capture_output=True, timeout=10,
            check=False,
            env=_z3_child_env(),
        )
        if proc.returncode == 0:
            try:
                return pickle.loads(proc.stdout)
            except Exception:  # malformed child output degrades to None
                logger.debug("z3 child output unpicklable", exc_info=True)
    except subprocess.TimeoutExpired:
        logger.debug("z3 child timed out")
    return None


def _z3_integer_narrowing_check(
    var_name: str,
    src_type: str,
    dest_type: str,
    assign_line: int,
) -> IntegerNarrowingResult:
    """Z3: Prove narrowing can lose data."""
    from core.smt_solver.availability import z3
    from core.smt_solver.session import new_solver

    src_width = _type_to_width(src_type) or 64
    dest_width = _type_to_width(dest_type) or 32

    solver = new_solver()
    v = z3.BitVec(var_name, src_width)

    max_dest = (1 << dest_width) - 1
    solver.add(z3.UGT(v, max_dest))

    result = solver.check()
    if result == z3.sat:
        model = solver.model()
        witness_val = model[v]
        w: dict[str, Any] = {}
        if witness_val is not None:
            try:
                w[var_name] = witness_val.as_long()
            except AttributeError:
                pass
        return IntegerNarrowingResult(
            narrowing_found=True,
            source_type=src_type,
            dest_type=dest_type,
            source_width=src_width,
            dest_width=dest_width,
            assign_line=assign_line,
            reasoning=(
                f"Z3 SAT: {src_type} ({src_width}-bit) → {dest_type} "
                f"({dest_width}-bit) can overflow at line {assign_line}"
            ),
            witness=w if w else None,
        )
    return IntegerNarrowingResult(
        narrowing_found=False,
        reasoning="Z3 UNSAT: narrowing cannot lose data",
    )


# ---------------------------------------------------------------------------
# Early lock release (check-early-release)
# ---------------------------------------------------------------------------


@dataclass
class EarlyReleaseResult:
    """Result of checking for early lock release (use-after-unlock)."""

    early_release_found: bool = False
    lock_type: str = ""
    acquire_line: int = 0
    release_line: int = 0
    use_line: int = 0
    variable: str = ""
    reasoning: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "early_release_found": self.early_release_found,
            "reasoning": self.reasoning,
        }
        if self.lock_type:
            d["lock_type"] = self.lock_type
        if self.acquire_line:
            d["acquire_line"] = self.acquire_line
        if self.release_line:
            d["release_line"] = self.release_line
        if self.use_line:
            d["use_line"] = self.use_line
        if self.variable:
            d["variable"] = self.variable
        return d


_GUARD_EXIT_RE = re.compile(
    r"^\s*(?:return\b|goto\s+\w+\s*;)"
)


def _find_scope_unlock(
    lines: list[str],
    acquire_line: int,
    unlock_re: re.Pattern[str],
    search_limit: int = 80,
) -> int | None:
    """Find the scope-ending unlock, skipping guard-exit unlocks.

    A guard-exit unlock is one that (a) is at a deeper brace depth than
    the acquire AND (b) is immediately followed by ``return`` or ``goto``.
    The function leaves the current path inside a conditional, so this
    unlock is not the scope boundary for the happy path.

    An unlock at the same brace depth as the acquire, or one not
    followed by return/goto, is accepted as a scope boundary.

    Returns the line index of the scope-ending unlock, or None.
    """
    acquire_depth = 0
    for k in range(acquire_line + 1):
        acquire_depth += lines[k].count("{") - lines[k].count("}")

    end = min(len(lines), acquire_line + search_limit)
    depth = acquire_depth

    for j in range(acquire_line + 1, end):
        depth += lines[j].count("{") - lines[j].count("}")

        if not unlock_re.search(lines[j]):
            continue

        if depth > acquire_depth:
            is_guard = False
            for look in range(j + 1, min(len(lines), j + 3)):
                stripped = lines[look].lstrip()
                if not stripped or stripped.startswith(("//", "/*")):
                    continue
                if _GUARD_EXIT_RE.match(stripped):
                    is_guard = True
                break

            if is_guard:
                continue

        return j

    return None


def check_early_release(
    source: str,
    vocab: DomainVocabulary = _EMPTY_VOCAB,
) -> EarlyReleaseResult:
    """Detect lock-read-unlock-use patterns (use-after-unlock race).

    Finds cases where a value is read under a lock, the lock is released,
    and the value is then used — creating a race window where another
    thread can invalidate the value between release and use.

    Supports both C (spin_lock/mutex/rcu) and Go (sync.Mutex/RWMutex).
    """
    from .safety_contract import assert_boost_only
    assert_boost_only("condition_smt")
    lines = source.split("\n")
    is_go = any(
        "func " in ln or "package " in ln or ".Lock()" in ln
        for ln in lines[:30]
    )

    if is_go:
        return _check_early_release_go(lines)
    return _check_early_release_c(lines, vocab)


_GO_READ_RE = re.compile(
    r"(\w+)\s*(?::=|=)\s*"
    r"(?:\w+\.(\w+)(?:\s*\(.*\))?|\w+\[.+\])"
)

_GO_MULTI_RETURN_RE = re.compile(
    r"(\w+)\s*,\s*\w+\s*(?::=|=)\s*\w+\.(\w+)\s*\("
)


def _check_early_release_go(lines: list[str]) -> EarlyReleaseResult:
    """Go-specific early lock release detection."""
    lock_re = re.compile(r"(\w+)\.(RLock|Lock)\s*\(\s*\)")
    unlock_re_tpl = r"{name}\.(?:RUnlock|Unlock)\s*\(\s*\)"
    defer_re = re.compile(r"defer\s+(\w+)\.(RUnlock|Unlock)\s*\(\s*\)")

    func_end = len(lines)
    brace_depth = 0
    in_func = False
    for j, ln in enumerate(lines):
        if "func " in ln and "{" in ln:
            in_func = True
            brace_depth = 0
        if in_func:
            brace_depth += ln.count("{") - ln.count("}")
            if brace_depth <= 0 and j > 0:
                func_end = j

    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith("//"):
            continue

        lm = lock_re.search(line)
        if not lm:
            continue

        lock_name = lm.group(1)
        lock_type = lm.group(2)
        unlock_re = re.compile(unlock_re_tpl.format(name=re.escape(lock_name)))

        has_defer = defer_re.search(line) or any(
            defer_re.search(lines[j])
            for j in range(max(0, i - 1), min(len(lines), i + 3))
        )

        unlock_line = _find_scope_unlock(lines, i, unlock_re, search_limit=50)

        if has_defer and unlock_line is None:
            unlock_line = func_end

        if unlock_line is None:
            continue

        reads_under_lock: list[tuple[int, str]] = []
        for j in range(i + 1, unlock_line):
            for rx in (_GO_MULTI_RETURN_RE, _GO_READ_RE):
                fm = rx.search(lines[j])
                if fm:
                    reads_under_lock.append((j, fm.group(1)))
                    break

        if not reads_under_lock:
            continue

        search_end = min(len(lines), unlock_line + 30)
        for read_line, var_name in reads_under_lock:
            var_use_re = re.compile(r"\b" + re.escape(var_name) + r"\b")
            for k in range(unlock_line + 1, search_end):
                if var_use_re.search(lines[k]):
                    return EarlyReleaseResult(
                        early_release_found=True,
                        lock_type=f"{lock_name}.{lock_type}",
                        acquire_line=i + 1,
                        release_line=unlock_line + 1,
                        use_line=k + 1,
                        variable=var_name,
                        reasoning=(
                            f"'{var_name}' read at line {read_line + 1} under "
                            f"{lock_name}.{lock_type} (line {i + 1}), lock "
                            f"released at line {unlock_line + 1}, value used "
                            f"at line {k + 1} — race window"
                        ),
                    )

    return EarlyReleaseResult(
        reasoning="no early lock release patterns found",
    )


def _check_early_release_c(
    lines: list[str],
    vocab: DomainVocabulary = _EMPTY_VOCAB,
) -> EarlyReleaseResult:
    """C-specific early lock release detection (RCU/spinlock/mutex)."""
    # Direct struct field read: var = ptr->field  /  var = obj.field
    field_read_re = re.compile(
        r"(\w+)\s*=\s*(?:(\w+)->(\w+)|(\w+)\.(\w+))"
    )
    # Macro-wrapped field read: var = MACRO(ptr->field) or MACRO(&ptr->field)
    # Covers rcu_dereference*, READ_ONCE, smp_load_acquire, atomic*_read, etc.
    macro_read_re = re.compile(
        r"(\w+)\s*=\s*\w+\s*\([^)]*->[^)]*\)"
    )
    # Function-call assignment: var = func(args)
    func_assign_re = re.compile(r"(\w+)\s*=\s*\w+\s*\(")
    # Output parameter: func(&var)
    out_param_re = re.compile(r"\w+\s*\(\s*&(\w+)\s*[,)]")

    acquires = _extract_lock_acquires(lines, vocab)
    if not acquires:
        # Release-only heuristic: if unlock calls exist but no acquires,
        # the caller holds the lock. Treat function entry as implicit hold.
        release_only: list[tuple[int, str, str]] = []
        for i, line in enumerate(lines):
            stripped = line.lstrip()
            if stripped.startswith(("//", "/*")):
                continue
            seed_unlocks = [u for _, u in _LOCK_PAIRS]
            vocab_unlocks = sorted(
                {r for _, r in vocab.lock_pairs} | vocab.lock_releases,
            )
            for unlock_name in seed_unlocks + vocab_unlocks:
                unlock_pat = re.compile(
                    r"\b" + re.escape(unlock_name)
                    + r"(?:_irq(?:restore)?|_bh)?\s*\(",
                )
                if unlock_pat.search(line):
                    release_only.append((0, "caller_held", unlock_name))
                    break
        if not release_only:
            return EarlyReleaseResult(reasoning="no lock acquires found")
        acquires = release_only

    for acq_line, lock_func, unlock_name, *_ in acquires:
        unlock_re = re.compile(
            r"\b" + re.escape(unlock_name) + r"(?:_irq(?:restore)?|_bh)?\s*\("
        )
        unlock_line = _find_scope_unlock(lines, acq_line, unlock_re)

        if unlock_line is None:
            continue

        reads_under_lock: list[tuple[int, str]] = []

        for j in range(acq_line + 1, unlock_line):
            stripped = lines[j].lstrip()
            if stripped.startswith(("//", "/*")):
                continue
            fm = field_read_re.search(lines[j])
            if fm:
                var_name = fm.group(1)
                reads_under_lock.append((j, var_name))
                continue
            fm = macro_read_re.search(lines[j])
            if fm:
                reads_under_lock.append((j, fm.group(1)))
                continue
            fm = func_assign_re.search(lines[j])
            if fm:
                reads_under_lock.append((j, fm.group(1)))
                continue
            fm = out_param_re.search(lines[j])
            if fm:
                reads_under_lock.append((j, fm.group(1)))

        if not reads_under_lock:
            continue

        # Only flag when the variable is dereferenced as a pointer
        # after unlock. Scalar copies (int, port, uid) used by
        # value are safe — the copy is local.
        for read_line, var_name in reads_under_lock:
            var_deref_re = re.compile(
                r"\b" + re.escape(var_name) + r"\s*->"
                r"|&\s*" + re.escape(var_name) + r"\s*->"
                r"|\*\s*" + re.escape(var_name) + r"\b"
            )
            for k in range(unlock_line + 1, min(len(lines), unlock_line + 30)):
                stripped = lines[k].lstrip()
                if stripped.startswith(("//", "/*")):
                    continue
                if var_deref_re.search(lines[k]):
                    return EarlyReleaseResult(
                        early_release_found=True,
                        lock_type=lock_func,
                        acquire_line=acq_line + 1,
                        release_line=unlock_line + 1,
                        use_line=k + 1,
                        variable=var_name,
                        reasoning=(
                            f"'{var_name}' read at line {read_line + 1} "
                            f"under {lock_func} (line {acq_line + 1}), "
                            f"lock released at line {unlock_line + 1}, "
                            f"pointer dereferenced at line {k + 1} — "
                            f"race window"
                        ),
                    )

        # Decision variables: scalars assigned from a function call
        # under the lock, then used in a branch after unlock.
        func_assigned_re = re.compile(r"(\w+)\s*=\s*\w+\s*\(")
        for read_line, var_name in reads_under_lock:
            assign_line_str = lines[read_line]
            if not func_assigned_re.search(assign_line_str):
                continue
            branch_re = re.compile(
                r"\bif\s*\(\s*!?" + re.escape(var_name) + r"\s*[)&|!=<>]"
            )
            for k in range(unlock_line + 1, min(len(lines), unlock_line + 20)):
                stripped = lines[k].lstrip()
                if stripped.startswith(("//", "/*")):
                    continue
                if branch_re.search(lines[k]):
                    has_side_effect = False
                    for eff in range(k + 1, min(len(lines), k + 5)):
                        eff_s = lines[eff].strip()
                        if re.search(r"\w+\s*\(", eff_s) or "return" in eff_s:
                            has_side_effect = True
                            break
                    if has_side_effect:
                        return EarlyReleaseResult(
                            early_release_found=True,
                            lock_type=lock_func,
                            acquire_line=acq_line + 1,
                            release_line=unlock_line + 1,
                            use_line=k + 1,
                            variable=var_name,
                            reasoning=(
                                f"'{var_name}' computed at line "
                                f"{read_line + 1} under {lock_func} "
                                f"(line {acq_line + 1}), lock released "
                                f"at line {unlock_line + 1}, stale "
                                f"value gates branch at line {k + 1}"
                            ),
                        )

    return EarlyReleaseResult(
        reasoning="no early lock release patterns found",
    )


# ---------------------------------------------------------------------------
# Lock-domain mismatch (check-lock-domain)
# ---------------------------------------------------------------------------


@dataclass
class LockDomainResult:
    """Result of checking for cross-lock-domain field access."""

    mismatch_found: bool = False
    field: str = ""
    lock1: str = ""
    lock1_line: int = 0
    lock2: str = ""
    lock2_line: int = 0
    access1_line: int = 0
    access2_line: int = 0
    reasoning: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "mismatch_found": self.mismatch_found,
            "reasoning": self.reasoning,
        }
        if self.field:
            d["field"] = self.field
        if self.lock1:
            d["lock1"] = self.lock1
            d["lock1_line"] = self.lock1_line
        if self.lock2:
            d["lock2"] = self.lock2
            d["lock2_line"] = self.lock2_line
        if self.access1_line:
            d["access1_line"] = self.access1_line
        if self.access2_line:
            d["access2_line"] = self.access2_line
        return d


def check_lock_domain(
    source: str,
    vocab: DomainVocabulary = _EMPTY_VOCAB,
) -> LockDomainResult:
    """Detect struct field accesses under different locks (TOCTOU).

    Scans for struct field reads/writes (via -> or .) and tracks which
    lock scope protects each access. When the same field is accessed
    under two different lock names, flags a potential TOCTOU.

    Supports C (spin_lock/mutex/rcu) and Go (sync.Mutex/RWMutex).
    """
    from .safety_contract import assert_boost_only
    assert_boost_only("condition_smt")
    lines = source.split("\n")
    is_go = any(
        "func " in ln or "package " in ln or ".Lock()" in ln
        for ln in lines[:30]
    )

    if is_go:
        return _check_lock_domain_go(lines)
    return _check_lock_domain_c(lines, vocab)


def _check_lock_domain_go(lines: list[str]) -> LockDomainResult:
    """Go-specific lock-domain mismatch detection."""
    lock_re = re.compile(r"(\w+)\.(RLock|Lock)\s*\(\s*\)")
    unlock_re_tpl = r"{name}\.(?:RUnlock|Unlock)\s*\(\s*\)"
    field_re = re.compile(r"(\w+)\.(\w+)")

    lock_scopes: list[tuple[int, int, str]] = []

    i = 0
    while i < len(lines):
        lm = lock_re.search(lines[i])
        if lm:
            lock_name = lm.group(1)
            lock_type = f"{lock_name}.{lm.group(2)}"
            unlock_re = re.compile(
                unlock_re_tpl.format(name=re.escape(lock_name))
            )
            for j in range(i + 1, min(len(lines), i + 80)):
                if unlock_re.search(lines[j]):
                    lock_scopes.append((i, j, lock_type))
                    break
        i += 1

    if len(lock_scopes) < 2:
        return LockDomainResult(reasoning="fewer than 2 lock scopes found")

    field_accesses: dict[str, list[tuple[int, str]]] = {}
    for scope_start, scope_end, lock_type in lock_scopes:
        for j in range(scope_start + 1, scope_end):
            for fm in field_re.finditer(lines[j]):
                obj, fld = fm.group(1), fm.group(2)
                if obj in ("sync", "fmt", "log", "os", "io"):
                    continue
                key = f"{obj}.{fld}"
                field_accesses.setdefault(key, []).append((j, lock_type))

    for field_key, accesses in field_accesses.items():
        locks_seen: dict[str, int] = {}
        for line_no, lock_type in accesses:
            if lock_type not in locks_seen:
                locks_seen[lock_type] = line_no
        if len(locks_seen) >= 2:
            items = list(locks_seen.items())
            return LockDomainResult(
                mismatch_found=True,
                field=field_key,
                lock1=items[0][0],
                lock1_line=items[0][1] + 1,
                lock2=items[1][0],
                lock2_line=items[1][1] + 1,
                access1_line=items[0][1] + 1,
                access2_line=items[1][1] + 1,
                reasoning=(
                    f"'{field_key}' accessed under {items[0][0]} "
                    f"(line {items[0][1] + 1}) and {items[1][0]} "
                    f"(line {items[1][1] + 1}) — cross-lock-domain TOCTOU"
                ),
            )

    return LockDomainResult(reasoning="no cross-lock-domain accesses found")


# SEED SET — generic POSIX credential concepts. The kernel
# task_struct/cred field bulk (cap_effective, dumpable, seccomp, ...)
# lives in the linux_kernel vocab pack; project fields arrive via
# DomainVocabulary.security_fields (domain-model security_fields /
# security_attributes / sensitive_fields keys). Do not grow this list —
# teach the study loop / pack instead.
_SECURITY_FIELDS = frozenset({
    "uid", "euid", "gid", "egid",
})


def _check_correlated_field_access(
    lines: list[str],
    lock_scopes: list[tuple[int, int, str, str]],
    vocab: DomainVocabulary = _EMPTY_VOCAB,
) -> LockDomainResult | None:
    """Detect security-relevant fields read under different locks.

    Fires when two or more security-relevant fields are each accessed
    under a different lock type — even when no single field appears
    under two locks. The concern is atomicity: reading cred under
    rcu_read_lock and mm under task_lock means the two reads are not
    atomic with respect to setuid().
    """
    if not lock_scopes:
        return None

    sec_fields = _SECURITY_FIELDS | vocab.security_fields
    if not sec_fields:
        return None

    field_re = re.compile(r"(\w+)->(\w+)")
    security_accesses: dict[str, list[tuple[int, str]]] = {}

    for scope_start, scope_end, lock_func, _ in lock_scopes:
        for j in range(scope_start + 1, scope_end):
            stripped = lines[j].lstrip()
            if stripped.startswith(("//", "/*")):
                continue
            for fm in field_re.finditer(lines[j]):
                fld = fm.group(2)
                if fld in sec_fields:
                    security_accesses.setdefault(fld, []).append(
                        (j, lock_func)
                    )

    if len(security_accesses) < 2:
        return None

    by_lock: dict[str, list[tuple[str, int]]] = {}
    for fld, accesses in security_accesses.items():
        for line_no, lock_func in accesses:
            by_lock.setdefault(lock_func, []).append((fld, line_no))

    if len(by_lock) < 2:
        return None

    lock_items = list(by_lock.items())
    lock1, fields1 = lock_items[0]
    lock2, fields2 = lock_items[1]
    f1, l1 = fields1[0]
    f2, l2 = fields2[0]

    return LockDomainResult(
        mismatch_found=True,
        field=f"{f1} + {f2}",
        lock1=lock1,
        lock1_line=l1 + 1,
        lock2=lock2,
        lock2_line=l2 + 1,
        access1_line=l1 + 1,
        access2_line=l2 + 1,
        reasoning=(
            f"security-relevant fields '{f1}' and '{f2}' read "
            f"under different locks ({lock1} and {lock2}) — "
            f"TOCTOU: concurrent modification between reads"
        ),
    )


def _check_lock_domain_c(
    lines: list[str],
    vocab: DomainVocabulary = _EMPTY_VOCAB,
) -> LockDomainResult:
    """C-specific lock-domain mismatch detection."""
    field_re = re.compile(r"(\w+)->(\w+)")

    acquires = _extract_lock_acquires(lines, vocab)

    lock_scopes: list[tuple[int, int, str, str]] = []
    for acq_line, lock_func, unlock_name, *_ in acquires:
        unlock_re = re.compile(
            r"\b" + re.escape(unlock_name) + r"(?:_irq(?:restore)?|_bh)?\s*\("
        )
        for j in range(acq_line + 1, min(len(lines), acq_line + 100)):
            if unlock_re.search(lines[j]):
                lock_scopes.append((acq_line, j, lock_func, unlock_name))
                break

    # Barrier-inside-lock: smp_load_acquire/READ_ONCE/atomic_read under
    # a lock implies writers that bypass it (cross-function domain).
    _barrier_re = re.compile(
        r"\b(smp_load_acquire|atomic_read"
        r"|atomic_long_read|smp_store_release)\s*\("
    )
    if lock_scopes:
        for scope_start, scope_end, lock_func, _ in lock_scopes:
            for j in range(scope_start + 1, scope_end):
                bm = _barrier_re.search(lines[j])
                if not bm:
                    continue
                fm = field_re.search(lines[j])
                if fm:
                    fld = f"{fm.group(1)}->{fm.group(2)}"
                    return LockDomainResult(
                        mismatch_found=True,
                        field=fld,
                        lock1=lock_func,
                        lock1_line=scope_start + 1,
                        lock2=bm.group(1),
                        lock2_line=j + 1,
                        access1_line=scope_start + 1,
                        access2_line=j + 1,
                        reasoning=(
                            f"'{fld}' read via {bm.group(1)} at "
                            f"line {j + 1} inside {lock_func} scope — "
                            f"barrier is redundant under exclusive lock, "
                            f"implies cross-function unlocked writers"
                        ),
                    )

    correlated = _check_correlated_field_access(lines, lock_scopes, vocab)
    if correlated is not None:
        return correlated

    if len(lock_scopes) < 2:
        return LockDomainResult(
            reasoning="fewer than 2 complete lock scopes found",
        )

    field_accesses: dict[str, list[tuple[int, str]]] = {}
    for scope_start, scope_end, lock_func, _ in lock_scopes:
        for j in range(scope_start + 1, scope_end):
            stripped = lines[j].lstrip()
            if stripped.startswith(("//", "/*")):
                continue
            for fm in field_re.finditer(lines[j]):
                key = f"{fm.group(1)}->{fm.group(2)}"
                field_accesses.setdefault(key, []).append((j, lock_func))

    for field_key, accesses in field_accesses.items():
        locks_seen: dict[str, int] = {}
        for line_no, lock_func in accesses:
            if lock_func not in locks_seen:
                locks_seen[lock_func] = line_no
        if len(locks_seen) >= 2:
            items = list(locks_seen.items())
            a1_line = items[0][1]
            a2_line = items[1][1]
            # Nested locking: if both accesses fall within a single
            # enclosing lock scope, the outer lock protects both.
            if any(
                s <= a1_line <= e and s <= a2_line <= e
                for s, e, _, _ in lock_scopes
            ):
                continue
            return LockDomainResult(
                mismatch_found=True,
                field=field_key,
                lock1=items[0][0],
                lock1_line=a1_line + 1,
                lock2=items[1][0],
                lock2_line=items[1][1] + 1,
                access1_line=a1_line + 1,
                access2_line=items[1][1] + 1,
                reasoning=(
                    f"'{field_key}' accessed under {items[0][0]} "
                    f"(line {a1_line + 1}) and {items[1][0]} "
                    f"(line {items[1][1] + 1}) — different locks "
                    f"protect the same field"
                ),
            )

    return LockDomainResult(reasoning="no cross-lock-domain accesses found")


# ---------------------------------------------------------------------------
# TOCTOU (check-then-act) detector
# ---------------------------------------------------------------------------

@dataclass
class TocTouResult:
    """Result of TOCTOU pattern detection."""

    toctou_found: bool = False
    check_call: str = ""
    check_line: int = 0
    use_call: str = ""
    use_line: int = 0
    variable: str = ""
    reasoning: str = ""

    def to_dict(self) -> dict:
        return {
            "toctou_found": self.toctou_found,
            "check_call": self.check_call,
            "check_line": self.check_line,
            "use_call": self.use_call,
            "use_line": self.use_line,
            "variable": self.variable,
            "reasoning": self.reasoning,
        }


_TOCTOU_C_CHECKS = re.compile(
    r"\b(access|stat|lstat|fstatat|faccessat"
    r"|__xstat|__lxstat|__fxstatat"
    r"|PathFileExistsA|GetFileAttributesA"
    r")\s*\(",
)

_TOCTOU_C_USES = re.compile(
    r"\b(open|fopen|creat|chmod|chown|lchown|fchmodat|fchownat"
    r"|unlink|remove|rename|link|symlink|mkdir|rmdir"
    r"|truncate|execve|execvp|execlp"
    r"|CreateFileA|DeleteFileA|MoveFileA"
    r")\s*\(",
)

_TOCTOU_C_DOUBLE_FETCH = re.compile(
    r"\b(copy_from_user|get_user|__get_user"
    r"|copy_from_iter|copyin)\s*\(",
)

_TOCTOU_GO_CHECKS = re.compile(
    r"\b(os\.Stat|os\.Lstat|os\.IsExist|os\.IsNotExist"
    r"|filepath\.Exists|os\.Access)\s*\(",
)

_TOCTOU_GO_USES = re.compile(
    r"\b(os\.Open|os\.OpenFile|os\.Create|os\.Remove"
    r"|os\.RemoveAll|os\.Rename|os\.Mkdir|os\.MkdirAll"
    r"|os\.Chmod|os\.Chown|os\.Link|os\.Symlink"
    r"|ioutil\.ReadFile|ioutil\.WriteFile)\s*\(",
)

_TOCTOU_PY_CHECKS = re.compile(
    r"\b(os\.path\.exists|os\.path\.isfile|os\.path\.isdir"
    r"|os\.access|os\.stat|os\.lstat|Path\([^)]*\)\.exists\(\)"
    r"|Path\([^)]*\)\.is_file\(\)|Path\([^)]*\)\.is_dir\(\))"
    r"\s*[\(.]?",
)

_TOCTOU_PY_USES = re.compile(
    r"\b(open|os\.open|os\.remove|os\.unlink|os\.rename"
    r"|os\.chmod|os\.chown|os\.mkdir|os\.makedirs"
    r"|shutil\.rmtree|shutil\.move"
    r"|Path\([^)]*\)\.open\(\)|Path\([^)]*\)\.unlink\(\))"
    r"\s*\(",
)


def _extract_path_arg(line: str, call_match: re.Match) -> str:
    """Extract the first argument (path variable) from a function call."""
    rest = line[call_match.end() - 1:]
    depth = 0
    arg_start = -1
    for i, ch in enumerate(rest):
        if ch == "(":
            depth += 1
            if depth == 1:
                arg_start = i + 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and arg_start >= 0:
                arg = rest[arg_start:i].split(",")[0].strip().strip('"\'')
                return arg
        elif ch == "," and depth == 1 and arg_start >= 0:
            arg = rest[arg_start:i].strip().strip('"\'')
            return arg
    return ""


def _check_toctou_pairs(
    lines: list,
    check_re: re.Pattern,
    use_re: re.Pattern,
) -> TocTouResult:
    """Scan for check-then-act pairs on the same path variable."""
    checks: list[tuple[int, str, str]] = []
    for i, line in enumerate(lines):
        m = check_re.search(line)
        if m:
            path_arg = _extract_path_arg(line, m)
            if path_arg:
                checks.append((i, m.group(1), path_arg))

    for i, line in enumerate(lines):
        m = use_re.search(line)
        if m:
            use_arg = _extract_path_arg(line, m)
            if not use_arg:
                continue
            for check_line, check_call, check_arg in checks:
                if i <= check_line:
                    continue
                if check_arg == use_arg or (
                    check_arg in use_arg or use_arg in check_arg
                ):
                    return TocTouResult(
                        toctou_found=True,
                        check_call=check_call,
                        check_line=check_line + 1,
                        use_call=m.group(1),
                        use_line=i + 1,
                        variable=check_arg,
                        reasoning=(
                            f"'{check_call}' checks '{check_arg}' at line "
                            f"{check_line + 1}, then '{m.group(1)}' uses it "
                            f"at line {i + 1} — filesystem state can change "
                            f"between check and use"
                        ),
                    )

    return TocTouResult(reasoning="no TOCTOU pattern found")


def _extract_nth_arg(line: str, call_match: re.Match, n: int = 0) -> str:
    """Extract the nth comma-separated argument from a function call."""
    rest = line[call_match.end() - 1:]
    depth = 0
    arg_start = -1
    args: list[str] = []
    for i, ch in enumerate(rest):
        if ch == "(":
            depth += 1
            if depth == 1:
                arg_start = i + 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and arg_start >= 0:
                args.append(rest[arg_start:i].strip())
                break
        elif ch == "," and depth == 1 and arg_start >= 0:
            args.append(rest[arg_start:i].strip())
            arg_start = i + 1
    if n < len(args):
        return args[n].strip().strip('"\'')
    return ""


def _check_toctou_double_fetch(lines: list) -> TocTouResult:
    """Detect copy_from_user double-fetch: same user pointer copied twice."""
    fetches: dict[str, list[tuple[int, str]]] = {}
    for i, line in enumerate(lines):
        m = _TOCTOU_C_DOUBLE_FETCH.search(line)
        if m:
            src_arg = _extract_nth_arg(line, m, n=1)
            if src_arg:
                fetches.setdefault(src_arg, []).append((i, m.group(1)))

    for arg, locs in fetches.items():
        if len(locs) >= 2:
            return TocTouResult(
                toctou_found=True,
                check_call=locs[0][1],
                check_line=locs[0][0] + 1,
                use_call=locs[1][1],
                use_line=locs[1][0] + 1,
                variable=arg,
                reasoning=(
                    f"double fetch of user pointer '{arg}': first at line "
                    f"{locs[0][0] + 1}, second at line {locs[1][0] + 1} — "
                    f"user space can modify between fetches"
                ),
            )

    return TocTouResult(reasoning="no double-fetch pattern found")


def check_toctou(source: str) -> TocTouResult:
    """Detect TOCTOU (check-then-act) filesystem races and double fetches."""
    from .safety_contract import assert_boost_only
    assert_boost_only("condition_smt")
    if not source or not source.strip():
        return TocTouResult(reasoning="empty source")

    lines = source.splitlines()

    has_go = any(kw in source for kw in ("func ", "package ", "import ("))
    has_py = any(kw in source for kw in ("def ", "import os", "from pathlib"))

    if has_go:
        result = _check_toctou_pairs(lines, _TOCTOU_GO_CHECKS, _TOCTOU_GO_USES)
        if result.toctou_found:
            return result

    if has_py:
        result = _check_toctou_pairs(lines, _TOCTOU_PY_CHECKS, _TOCTOU_PY_USES)
        if result.toctou_found:
            return result

    result = _check_toctou_pairs(lines, _TOCTOU_C_CHECKS, _TOCTOU_C_USES)
    if result.toctou_found:
        return result

    result = _check_toctou_double_fetch(lines)
    if result.toctou_found:
        return result

    return TocTouResult(reasoning="no TOCTOU pattern found")


# ---------------------------------------------------------------------------
# Race-protection verification (inverse of check_lock_domain)
# ---------------------------------------------------------------------------

_ATOMIC_ACCESSOR_RE = re.compile(
    r"\b(?:atomic_read|atomic_set|atomic_inc|atomic_dec"
    r"|atomic_add|atomic_sub|atomic_cmpxchg|atomic_xchg"
    r"|atomic_long_read|atomic_long_set"
    r"|smp_load_acquire|smp_store_release"
    r"|READ_ONCE|WRITE_ONCE"
    r"|xchg|cmpxchg"
    r"|refcount_read|refcount_set|refcount_inc|refcount_dec"
    r"|kref_get|kref_put)\s*\(",
)

_RCU_ACCESSOR_RE = re.compile(
    r"\b(?:rcu_dereference|rcu_dereference_protected"
    r"|rcu_dereference_check|rcu_dereference_raw"
    r"|rcu_assign_pointer|RCU_INIT_POINTER)\s*\(",
)

_PER_CPU_RE = re.compile(
    r"\b(?:per_cpu|this_cpu_ptr|this_cpu_read|this_cpu_write"
    r"|__this_cpu_read|__this_cpu_write"
    r"|per_cpu_ptr|raw_cpu_ptr)\s*\(",
)


@dataclass
class RaceProtectionResult:
    """Result of checking whether accesses are race-protected."""

    protected: bool = False
    total_accesses: int = 0
    protected_accesses: int = 0
    unprotected_accesses: int = 0
    lock_scopes: int = 0
    reasoning: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "protected": self.protected,
            "total_accesses": self.total_accesses,
            "protected_accesses": self.protected_accesses,
            "unprotected_accesses": self.unprotected_accesses,
            "lock_scopes": self.lock_scopes,
            "reasoning": self.reasoning,
        }


def check_race_protection(
    source: str,
    vocab: DomainVocabulary | None = None,
) -> RaceProtectionResult:
    """Check whether shared-state accesses are protected by synchronisation.

    Scans for struct field dereferences (ptr->field) and checks whether
    each access is inside a lock scope, uses an atomic/RCU accessor,
    or is a per-CPU operation.  If ALL accesses are protected, returns
    protected=True — the function has no unprotected shared-state
    access and a race hypothesis can be mechanically refuted.

    Only operates on C code.  Returns protected=False (inconclusive)
    for non-C or when no field accesses are found.
    """
    from .safety_contract import assert_boost_only
    assert_boost_only("condition_smt")
    if not source or not source.strip():
        return RaceProtectionResult(reasoning="empty source")

    lines = source.split("\n")

    # Non-C: bail
    if any(kw in source for kw in ("func ", "package ", "import (")):
        return RaceProtectionResult(reasoning="Go source, not applicable")
    if any(kw in source for kw in ("def ", "import os", "class ")):
        return RaceProtectionResult(reasoning="Python source, not applicable")

    field_re = re.compile(r"(\w+)->(\w+)")

    # Build lock scopes
    if vocab is None:
        vocab = _EMPTY_VOCAB
    acquires = _extract_lock_acquires(lines, vocab)
    lock_scopes: list[tuple[int, int]] = []
    for acq_line, _lock_func, unlock_name, *_ in acquires:
        unlock_re = re.compile(
            r"\b" + re.escape(unlock_name) + r"(?:_irq(?:restore)?|_bh)?\s*\("
        )
        for j in range(acq_line + 1, min(len(lines), acq_line + 200)):
            if unlock_re.search(lines[j]):
                lock_scopes.append((acq_line, j))
                break

    # rcu_read_lock..rcu_read_unlock scopes
    rcu_scopes: list[tuple[int, int]] = []
    rcu_lock_re = re.compile(r"\brcu_read_lock\s*\(\s*\)")
    rcu_unlock_re = re.compile(r"\brcu_read_unlock\s*\(\s*\)")
    for i, line in enumerate(lines):
        if rcu_lock_re.search(line):
            for j in range(i + 1, min(len(lines), i + 200)):
                if rcu_unlock_re.search(lines[j]):
                    rcu_scopes.append((i, j))
                    break
    lock_scopes.extend(rcu_scopes)

    # preempt_disable / local_irq_save scopes (needed for per-CPU safety)
    preempt_scopes: list[tuple[int, int]] = []
    preempt_acq_re = re.compile(
        r"\b(preempt_disable|local_irq_save|local_irq_disable"
        r"|get_cpu|migrate_disable)\s*\(",
    )
    preempt_rel_re = re.compile(
        r"\b(preempt_enable|local_irq_restore|local_irq_enable"
        r"|put_cpu|migrate_enable)\s*\(",
    )
    for i, line in enumerate(lines):
        if preempt_acq_re.search(line):
            for j in range(i + 1, min(len(lines), i + 200)):
                if preempt_rel_re.search(lines[j]):
                    preempt_scopes.append((i, j))
                    break
    lock_scopes.extend(preempt_scopes)

    def _in_lock_scope(line_idx: int) -> bool:
        return any(start <= line_idx <= end for start, end in lock_scopes)

    def _in_rcu_scope(line_idx: int) -> bool:
        return any(start <= line_idx <= end for start, end in rcu_scopes)

    def _in_preempt_scope(line_idx: int) -> bool:
        return any(start <= line_idx <= end for start, end in preempt_scopes)

    # Init dereferences of function parameters before any lock.
    # Pattern: `type *var = param->field;` where param is a function arg.
    # Only when locks exist — without locks there is no safe pre-lock zone.
    init_lines: set[int] = set()
    if lock_scopes:
        param_names: set[str] = set()
        sig_re = re.compile(r"\b\w+\s*\*\s*(\w+)")
        for i, line in enumerate(lines):
            stripped = line.strip()
            if "{" in stripped:
                for m in sig_re.finditer(line):
                    param_names.add(m.group(1))
                break
        first_lock_line = min(s for s, _ in lock_scopes)
        init_deref_re = re.compile(
            r"^\s+(?:struct\s+\w+\s+\*|[\w]+\s+\*?)\w+\s*=\s*(\w+)->\w+"
        )
        for i in range(min(first_lock_line, len(lines))):
            m = init_deref_re.match(lines[i])
            if m and m.group(1) in param_names:
                init_lines.add(i)

    total = 0
    protected = 0
    unprotected_lines: list[int] = []

    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith(("//", "/*")):
            continue
        if stripped.startswith("*") and not stripped.startswith("*/"):
            continue

        accesses = list(field_re.finditer(line))
        if not accesses:
            continue

        for _fm in accesses:
            total += 1
            if _in_lock_scope(i) or _ATOMIC_ACCESSOR_RE.search(line) or _RCU_ACCESSOR_RE.search(line) and _in_rcu_scope(i) or _PER_CPU_RE.search(line) and _in_preempt_scope(i) or i in init_lines:
                protected += 1
            else:
                unprotected_lines.append(i + 1)

    unprotected_count = total - protected

    if total == 0:
        return RaceProtectionResult(
            lock_scopes=len(lock_scopes),
            reasoning="no struct field dereferences found",
        )

    if unprotected_count == 0:
        return RaceProtectionResult(
            protected=True,
            total_accesses=total,
            protected_accesses=protected,
            unprotected_accesses=0,
            lock_scopes=len(lock_scopes),
            reasoning=(
                f"all {total} field accesses are inside lock scopes "
                f"or use atomic/RCU/per-CPU accessors"
            ),
        )

    return RaceProtectionResult(
        protected=False,
        total_accesses=total,
        protected_accesses=protected,
        unprotected_accesses=unprotected_count,
        lock_scopes=len(lock_scopes),
        reasoning=(
            f"{unprotected_count}/{total} field accesses at "
            f"lines {unprotected_lines[:5]} are outside lock scopes "
            f"and don't use atomic/RCU accessors"
        ),
    )


# ---------------------------------------------------------------------------
# Hypothesis disproof
# ---------------------------------------------------------------------------

_INT_HYPO_RE = re.compile(
    r"(?:integer|int)\s*(?:overflow|underflow|wraparound)"
    r".*?(?:in|of|when|during)\s+"
    r"(?:the\s+)?(?:calculation|multiplication|expression|addition|subtraction)?"
    r"[^.]*?(`[^`]+`|[a-zA-Z_]\w*(?:\s*[*+\-]\s*[a-zA-Z_]\w*)*)",
    re.IGNORECASE,
)

_DISPROOF_TYPE_WIDTHS = _TYPE_WIDTHS


@dataclass
class HypothesisDisproofResult:
    """Result of attempting to mechanically disprove a hypothesis."""

    hypothesis_class: str = ""
    disproved: bool | None = None
    reasoning: str = ""
    witness: dict[str, Any] | None = None
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "hypothesis_class": self.hypothesis_class,
            "reasoning": self.reasoning,
        }
        if self.disproved is not None:
            d["disproved"] = self.disproved
        if self.witness:
            d["witness"] = self.witness
        if self.error:
            d["error"] = self.error
        return d


def disprove_integer_overflow(
    hypothesis: str,
    source_context: str,
    var_types: dict[str, str] | None = None,
) -> HypothesisDisproofResult:
    """Attempt to disprove an integer overflow/underflow hypothesis via SMT.

    Extracts the claimed overflow expression from the hypothesis, resolves
    variable types from source context, and checks whether the overflow
    is actually feasible given the type widths.

    Returns disproved=True if UNSAT (overflow cannot happen),
    disproved=False if SAT (overflow is feasible), None if inconclusive.
    """
    from .safety_contract import assert_boost_only
    assert_boost_only("condition_smt")

    import importlib.util
    if not importlib.util.find_spec("z3"):
        return HypothesisDisproofResult(
            hypothesis_class="integer_overflow",
            error="z3 not installed",
        )

    var_types = var_types or {}

    m = _INT_HYPO_RE.search(hypothesis)
    if not m:
        return HypothesisDisproofResult(
            hypothesis_class="integer_overflow",
            reasoning="could not extract expression from hypothesis",
        )

    expr_text = m.group(1).strip("`").strip()
    op_match = re.search(r"\s*([*+\-])\s*", expr_text)
    op_char = op_match.group(1) if op_match else "*"
    parts = re.split(r"\s*[*+\-]\s*", expr_text)
    var_names = [p.strip() for p in parts if p.strip() and re.match(r"[a-zA-Z_]", p.strip())]

    if not var_names:
        return HypothesisDisproofResult(
            hypothesis_class="integer_overflow",
            reasoning=f"no variables found in expression '{expr_text}'",
        )

    resolved_types: dict[str, int] = {}
    for vn in var_names:
        vtype = var_types.get(vn, "")
        if not vtype:
            type_re = re.compile(
                r"\b((?:unsigned\s+)?(?:int|long|short|char)"
                r"|[su]?int(?:8|16|32|64)_t"
                r"|size_t|ssize_t|off_t)\s+" + re.escape(vn) + r"\b",
            )
            tm = type_re.search(source_context)
            if tm:
                vtype = tm.group(1).strip()
        width = _TYPE_WIDTHS.get(vtype, 0)
        if width:
            resolved_types[vn] = width

    if not resolved_types:
        return HypothesisDisproofResult(
            hypothesis_class="integer_overflow",
            reasoning="could not resolve type widths for any variables",
        )

    payload = pickle.dumps((
        "integer_overflow", resolved_types, op_char, var_types,
    ))
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _Z3_CHILD_SCRIPT_V2],
            input=payload, capture_output=True, timeout=10,
            check=False,
            env=_z3_child_env(),
        )
        if proc.returncode == 0:
            try:
                result = pickle.loads(proc.stdout)
                if result is not None:
                    return result
            except Exception:  # malformed child output degrades to None
                logger.debug("z3 child output unpicklable", exc_info=True)
        logger.debug("Z3 overflow subprocess exited with code %d", proc.returncode)
    except subprocess.TimeoutExpired:
        logger.debug("Z3 overflow subprocess timed out")

    return HypothesisDisproofResult(
        hypothesis_class="integer_overflow",
        reasoning="Z3 subprocess inconclusive",
    )


def _z3_integer_overflow_check(
    resolved_types: dict[str, int],
    op_char: str,
    var_types: dict[str, str],
) -> HypothesisDisproofResult | None:
    """Z3: check whether an arithmetic overflow is feasible."""
    import z3

    width = max(resolved_types.values())

    z3_vars = {}
    solver = z3.Solver()
    solver.set("timeout", 2000)

    for vn, w in resolved_types.items():
        z3_vars[vn] = z3.BitVec(vn, w)

    _OP_LABEL = {"*": "multiplication", "+": "addition", "-": "subtraction"}

    if len(z3_vars) >= 2:
        vals = list(z3_vars.values())

        full_bits = width * 2
        acc = z3.ZeroExt(full_bits - vals[0].size(), vals[0])
        for v in vals[1:]:
            ext = z3.ZeroExt(full_bits - v.size(), v)
            if op_char == "+":
                acc = acc + ext
            elif op_char == "-":
                acc = acc - ext
            else:
                acc = acc * ext
        max_val = (1 << width) - 1
        solver.add(z3.UGT(acc, max_val))

        result = solver.check()
        op_label = _OP_LABEL.get(op_char, op_char)
        if result == z3.unsat:
            return HypothesisDisproofResult(
                hypothesis_class="integer_overflow",
                disproved=True,
                reasoning=(
                    f"Z3 UNSAT: {op_label} of {list(resolved_types.keys())} "
                    f"cannot overflow {width}-bit — hypothesis disproved"
                ),
            )
        elif result == z3.sat:
            model = solver.model()
            witness = {}
            for vn, bv in z3_vars.items():
                val = model[bv]
                if val is not None:
                    try:
                        witness[vn] = val.as_long()
                    except AttributeError:
                        pass
            return HypothesisDisproofResult(
                hypothesis_class="integer_overflow",
                disproved=False,
                reasoning=(
                    f"Z3 SAT: overflow IS feasible for "
                    f"{list(resolved_types.keys())} at {width}-bit"
                ),
                witness=witness if witness else None,
            )

    return None
