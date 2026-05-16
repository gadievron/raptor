"""Source intelligence analyzer — orchestrates cocci rules + alias
scanning to produce structured evidence per target.

Phase 2 (substrate) ships exactly one axis: ``axis 1 / attrs`` covering
``warn_unused_result``. Axes 2-7 plug in by adding rule directories
under ``engine/coccinelle/source_intel/`` and aggregators here.

The output is a :class:`SourceIntelResult` (frozen) keyed on target +
rule-set hash. The Stage D LLM consumer consumes it via
:mod:`packages.source_intel.render`; the corpus runner consumes it
via :mod:`packages.source_intel.adapter`.

Hard invariants (carried from design):
  * Strict sidecar — produces evidence, never overrides verdict.
  * ``--no-includes`` to spatch by default (untrusted-target posture
    matching PR-3 cocci scan + PR-4 prereqs).
  * Out-of-tree symbols never fabricated — `function_attrs_status`
    explicit when a symbol isn't found.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from core.build.build_flags import BuildFlagsContext, extract_flags
from packages.source_intel.aliases import (
    ALL_WUR_ALIASES,
    wur_alias_in,
    wur_alias_origin,
)

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1


# =====================================================================
# Data shape
# =====================================================================


#: Recognised attribute kinds. Axis-N PRs add to this set; the cocci
#: rule's COCCIRESULT message prefix (``<kind>:<function>``) must match
#: one of these to be parsed.
KIND_WUR = "wur"
KIND_NONNULL = "nonnull"
KIND_ALLOC_SIZE = "alloc_size"
KIND_RETURNS_NONNULL = "returns_nonnull"
KIND_NORETURN = "noreturn"
KIND_MALLOC = "malloc"
KIND_NO_STACK_PROTECTOR = "no_stack_protector"
KIND_ACCESS = "access"

ALL_KINDS: Tuple[str, ...] = (
    KIND_WUR,
    KIND_NONNULL,
    KIND_ALLOC_SIZE,
    KIND_RETURNS_NONNULL,
    KIND_NORETURN,
    KIND_MALLOC,
    KIND_NO_STACK_PROTECTOR,
    KIND_ACCESS,
)


#: Proximity grades — ordered weakest → strongest. Phase 5a emits
#: only "same_function"; later phases add "same_path" + "dominates".
GRADE_SAME_FUNCTION = "same_function"
GRADE_SAME_PATH = "same_path"
GRADE_DOMINATES = "dominates"

ALL_GRADES: Tuple[str, ...] = (
    GRADE_SAME_FUNCTION,
    GRADE_SAME_PATH,
    GRADE_DOMINATES,
)


@dataclass(frozen=True)
class AllocationEvidence:
    """A single observation of an allocator call site, optionally
    flagged as unchecked. Phase 6a ships only the
    ``unchecked_alloc_field`` shape (struct_p->fld = alloc(...) with
    no subsequent NULL check); axis-3-expansion adds local-var,
    nested-field, and aliased-deref shapes.

    The cocci rule already filters for "no NULL check" via `when !=`
    clauses, so every emitted observation IS unchecked. The
    ``shape`` field carries the cocci sub-rule that fired —
    consumers can dispatch on it for kind-specific rendering.

    Stage D LLM consumer reads this evidence as "the allocator's
    return wasn't checked before the function continued"; combined
    with the finding's CWE-476 / null-deref claim, this is direct
    support for an EXPLOITABLE verdict.
    """

    allocator: str  # which allocator (kstrdup, kmalloc, etc.)
    location: Tuple[str, int]  # (file_path, line)
    shape: str  # "field" | "local" | "nested_field" (Phase 6a: only "field")
    target_field: Optional[str] = None  # struct field name for "field" shape
    enclosing_function: Optional[str] = None
    conditional_on: Optional[str] = None


@dataclass(frozen=True)
class AbortEvidence:
    """A single observation of an abort-class call (BUG_ON, panic,
    abort, __builtin_trap, _Exit, assert).

    ``grade`` encodes how confidently the abort dominates a bug
    primitive. Phase 5a emits only ``same_function`` grade.

    The aggregator computes per-finding "is there an abort in the
    finding's function?" lookups; the Validator's verdict policy
    emits NOT_EXPLOITABLE on findings where the abort dominates.
    """

    macro: str  # which macro fired (BUG_ON, panic, …)
    location: Tuple[str, int]  # (file_path, line)
    grade: str  # one of ``ALL_GRADES``
    enclosing_function: Optional[str] = None  # function name when known
    conditional_on: Optional[str] = None  # surrounding #ifdef condition


@dataclass(frozen=True)
class HazardEvidence:
    """A single observation of an axis-7 hazardous code pattern.

    Hazard kinds:
      * ``deprecated_func`` — call to a historically-unsafe libc
        function (gets/strcpy/strcat/sprintf/scanf). When CodeQL
        flags a cpp/unbounded-write at one of these call sites, the
        EXPLOITABLE verdict is supported: the function family
        doesn't carry its own bounds, so the caller must have
        established them.
      * ``signed_alloc`` — `int sgnvar; alloc_fn(sgnvar * sizeof(T),
        ...)` pattern. The signed multiplication is the classic
        CWE-190 → CWE-122 source. Direct structural evidence for an
        uncontrolled-allocation-size finding.

    The ``detail`` field carries the kind-specific extra info:
    function name for ``deprecated_func``, allocator-var pair for
    ``signed_alloc``.
    """

    kind: str  # "deprecated_func" | "signed_alloc"
    detail: str
    location: Tuple[str, int]
    enclosing_function: Optional[str] = None


@dataclass(frozen=True)
class CheckedAllocationEvidence:
    """A single observation of a CHECKED allocator call site —
    `local = alloc_fn(...); if (!local) ...` shape. Complement to
    AllocationEvidence (axis-3 unchecked).

    Used by axis-5 variant analysis to compute checked/unchecked
    ratios per allocator. The ratio is informational only in
    Phase 9 — Stage D LLM consumes it; the verdict policy doesn't
    yet act on it (deferred until corpus shows it helps).
    """

    allocator: str
    location: Tuple[str, int]
    enclosing_function: Optional[str] = None


@dataclass(frozen=True)
class CapabilityEvidence:
    """A single observation of a capability-check call (capable,
    ns_capable, perfmon_capable, etc.). Mirrors AbortEvidence shape:
    same grading scheme, same per-finding aggregation pattern.

    A capability check that dominates a finding's bug primitive
    means the attacker must already hold that capability before
    the bug is reachable. For most kernel CWE classes this DOES NOT
    eliminate the finding (privilege-bearing attackers exist), but
    it materially reduces severity — the Validator's verdict policy
    treats this as a **soft** signal: emits NOT_EXPLOITABLE only
    when the capability is one of the privileged-equivalent classes
    (CAP_SYS_ADMIN / equivalent) that already grant the attacker
    enough power to do the harm directly.

    Phase 8 emits same_function grading only; path-domination grading
    arrives with shared axis-2/axis-4 grading machinery later.
    """

    cap_function: str  # "capable", "ns_capable", "perfmon_capable", etc.
    location: Tuple[str, int]  # (file_path, line)
    grade: str  # one of ``ALL_GRADES``
    enclosing_function: Optional[str] = None
    conditional_on: Optional[str] = None


@dataclass(frozen=True)
class AttributeEvidence:
    """A single observation of a compiler attribute on a function.

    The ``kind`` field distinguishes evidence classes (``wur``,
    ``nonnull``, …). Axis-1-expansion adds more kinds; the data shape
    stays uniform so render / adapter code dispatches on ``kind``
    rather than carrying class-specific subtypes.

    ``conditional_on`` captures the innermost ``#if*`` condition
    enclosing the match (None when the match is unconditional). The
    Stage D consumer downweights matches whose condition wasn't
    confirmed-active in the actual build.
    """

    kind: str  # one of ``ALL_KINDS``
    function_name: str
    location: Tuple[str, int]  # (file_path, line)
    match_source: str  # "literal" | "known_alias" | "project_alias"
    raw_match: str  # actual spelling for provenance
    conditional_on: Optional[str] = None  # innermost enclosing #if* condition


def WurEvidence(  # noqa: N802 — back-compat factory for Phase 2 callers
    function_name: str,
    location: Tuple[str, int],
    match_source: str,
    raw_match: str,
    conditional_on: Optional[str] = None,
) -> AttributeEvidence:
    """Back-compat factory: returns an :class:`AttributeEvidence` with
    ``kind="wur"``. Phase 2 callers (tests, downstream code) used the
    name ``WurEvidence`` as a constructor; that name is preserved as a
    factory to avoid breaking imports.
    """
    return AttributeEvidence(
        kind=KIND_WUR,
        function_name=function_name,
        location=location,
        match_source=match_source,
        raw_match=raw_match,
        conditional_on=conditional_on,
    )


@dataclass(frozen=True)
class SourceIntelResult:
    """Per-target source-intelligence facts.

    Phase 2 shipped one evidence kind (``wur``); Phase 3 adds
    ``nonnull`` and lays the substrate for more kinds. The data shape
    is uniform — all attribute observations live in ``attributes`` and
    consumers filter / lookup by ``kind``.
    """

    schema_version: int = SCHEMA_VERSION
    target: str = ""
    rules_executed: Tuple[str, ...] = ()
    rules_failed: Tuple[Tuple[str, str], ...] = ()
    skipped_reason: Optional[str] = None
    spatch_version: Optional[str] = None

    #: All attribute observations across all kinds.
    attributes: Tuple[AttributeEvidence, ...] = ()

    #: Project-specific alias macros discovered in the target's
    #: headers, keyed by kind. Empty when discovery skipped (target
    #: had no headers or only the curated table was used).
    discovered_aliases: Tuple[Tuple[str, Tuple[str, ...]], ...] = ()

    #: Axis 2: abort-class call sites (BUG_ON, panic, abort, etc.)
    #: with grading. Empty in Phase 2-4; Phase 5a populates from
    #: abort_proximate.cocci output.
    aborts: Tuple[AbortEvidence, ...] = ()

    #: Axis 3: unchecked allocator call sites. Empty before Phase 6a;
    #: Phase 6a populates from unchecked_alloc.cocci output. Each entry
    #: indicates an allocator return value that wasn't NULL-checked
    #: before the function continued (see AllocationEvidence).
    allocations: Tuple[AllocationEvidence, ...] = ()

    #: Axis 4: capability-check call sites (capable, ns_capable, …).
    #: Empty before Phase 8; Phase 8 populates from
    #: capability_check.cocci. Each entry records a privilege check
    #: site whose dominance over the finding is graded by the
    #: aggregator (see CapabilityEvidence).
    capabilities: Tuple[CapabilityEvidence, ...] = ()

    #: Axis 5: CHECKED allocator call sites — complement to
    #: ``allocations`` (which is unchecked-only). Ratio of checked
    #: to total is exposed via ``variant_ratio()``.
    checked_allocations: Tuple[CheckedAllocationEvidence, ...] = ()

    #: Axis 7: hazardous code patterns (deprecated functions,
    #: signed-into-allocator). Empty before axis-7 ships; populated
    #: from engine/coccinelle/source_intel/hazards/ output.
    hazards: Tuple[HazardEvidence, ...] = ()

    #: Axis 6 consumer: build-hardening flags observed in the target's
    #: build configuration. Populated from core.build.build_flags when
    #: signal exists; otherwise default BuildFlagsContext() (all None,
    #: source="absent"). The verdict policy reads this to attenuate
    #: certain claims (FORTIFY_SOURCE intercepts unbounded-write,
    #: stack canaries gate stack BOF exploitation, etc.).
    build_flags: Optional[BuildFlagsContext] = None

    @property
    def is_skipped(self) -> bool:
        return self.skipped_reason is not None

    @property
    def wur_functions(self) -> Tuple[AttributeEvidence, ...]:
        """Back-compat: WUR-only subset. Phase 2 callers / tests used
        this accessor; preserved by filtering ``attributes`` on kind.
        """
        return tuple(a for a in self.attributes if a.kind == KIND_WUR)

    def attrs_of_kind(self, kind: str) -> Tuple[AttributeEvidence, ...]:
        """Filter observations by attribute kind."""
        return tuple(a for a in self.attributes if a.kind == kind)

    def function_attrs(self, name: str) -> Tuple[AttributeEvidence, ...]:
        """All attribute observations for a given function name."""
        return tuple(a for a in self.attributes if a.function_name == name)

    def function_has_wur(self, name: str) -> Optional[AttributeEvidence]:
        """Lookup: is function ``name`` annotated WUR? Returns first
        observation or None. Back-compat from Phase 2."""
        for a in self.attributes:
            if a.kind == KIND_WUR and a.function_name == name:
                return a
        return None

    def function_has_kind(
        self, name: str, kind: str,
    ) -> Optional[AttributeEvidence]:
        """Generalised lookup — returns first observation of ``kind``
        on function ``name``, or None."""
        for a in self.attributes:
            if a.kind == kind and a.function_name == name:
                return a
        return None

    def variant_ratio(self, allocator: str) -> Tuple[int, int]:
        """Return (checked_count, unchecked_count) for ``allocator``
        across the analyzed target. Used by axis-5 to assess whether
        an unchecked site is anomalous within the project's idiom.

        Dedupes by (file, line) within each bucket — the same alloc
        site may be matched by multiple shape-rules (e.g. both
        ``unchecked_alloc`` field-shape AND ``unchecked_alloc_local``
        when the LHS is a field expression). Without dedup the same
        site is counted twice, skewing the ratio.

        Caveats:
          * Counts are scoped to the analyzed target subtree only —
            they don't see external callers.
          * The denominator (checked+unchecked) is the total
            cocci-OBSERVED sites, not the actual call count
            (cocci's pattern matching may miss aliased/macro forms).
        """
        checked_sites = {
            c.location for c in self.checked_allocations
            if c.allocator == allocator
        }
        unchecked_sites = {
            a.location for a in self.allocations
            if a.allocator == allocator
        }
        return (len(checked_sites), len(unchecked_sites))


# =====================================================================
# Shipped rule discovery
# =====================================================================


def _shipped_rules_root() -> Optional[Path]:
    """Return the in-tree shipped rules root, or None if absent
    (minimal install / packaging strip).

    Layout: ``engine/coccinelle/source_intel/<axis>/`` per-axis subdirs
    (``attrs/`` for axis 1; later axes get ``proximity/``,
    ``allocation/``, etc.). Each subdir contains one or more
    ``.cocci`` files; ``analyze`` iterates the subdirs and runs each
    in turn so the per-axis rule sets stay scoped.
    """
    # packages/source_intel/analyze.py -> repo root -> engine/...
    here = Path(__file__).resolve()
    candidate = here.parents[2] / "engine" / "coccinelle" / "source_intel"
    return candidate if candidate.is_dir() else None


# Back-compat alias for external test code that may import the old name.
_shipped_rules_dir = _shipped_rules_root


def _axis_dirs(rules_root: Path) -> List[Path]:
    """List of per-axis subdirectories under the rules root.

    Phase 2 ships ``attrs/`` only. Axes 2-7 add sibling dirs; this
    function picks all of them up automatically so adding an axis
    means dropping rules into a new subdir without touching analyze.
    Order is deterministic (sorted by name).
    """
    return sorted(d for d in rules_root.iterdir() if d.is_dir())


# =====================================================================
# Source-language heuristic (cocci is C-family only)
# =====================================================================


_C_CPP_EXTS: Tuple[str, ...] = (
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh",
)


def _has_c_cpp_source(target: Path, max_files: int = 200) -> bool:
    """Bounded rglob — same heuristic as PR-3 scan + PR-4 prereqs.
    Quick reject for pure-Python / pure-Go targets so we don't waste
    a spatch run.
    """
    if not target.is_dir():
        # Single-file target — accept if it's C-family.
        return target.suffix.lower() in _C_CPP_EXTS
    seen = 0
    for entry in target.rglob("*"):
        if not entry.is_file():
            continue
        seen += 1
        if entry.suffix.lower() in _C_CPP_EXTS:
            return True
        if seen >= max_files:
            return False
    return False


# =====================================================================
# Public API
# =====================================================================


def analyze(
    target: Path,
    rules_dir: Optional[Path] = None,
    timeout_per_rule: int = 60,
) -> SourceIntelResult:
    """Run shipped source_intel cocci rules against ``target``.

    Skip-silent semantics:
      * spatch not on PATH → ``skipped_reason="spatch_not_available"``
      * target has no C/C++ source → ``skipped_reason="no_c_cpp_source"``
      * shipped rules dir missing → ``skipped_reason="rules_dir_missing"``

    Returns a :class:`SourceIntelResult` with parsed evidence. Never
    raises — failures collapse to per-rule entries in ``rules_failed``
    or a global ``skipped_reason``.
    """
    target = Path(target)

    # Import locally so a packaging strip of packages/coccinelle
    # degrades to skipped rather than ImportError at module load.
    try:
        from packages.coccinelle.runner import (
            is_available as spatch_available,
            run_rules as spatch_run_rules,
            version as spatch_version,
        )
    except ImportError:
        return SourceIntelResult(
            target=str(target),
            skipped_reason="coccinelle_package_missing",
        )

    if not spatch_available():
        return SourceIntelResult(
            target=str(target),
            skipped_reason="spatch_not_available",
        )
    if not _has_c_cpp_source(target):
        return SourceIntelResult(
            target=str(target),
            skipped_reason="no_c_cpp_source",
        )

    effective_rules_root = (
        rules_dir if rules_dir else _shipped_rules_root()
    )
    if effective_rules_root is None:
        return SourceIntelResult(
            target=str(target),
            skipped_reason="rules_dir_missing",
        )

    # The shipped layout has per-axis subdirs (``attrs/`` etc.). When a
    # caller hands us a flat rules_dir (e.g. tests), accept that too —
    # if no subdirs are present, run rules from the dir directly.
    axis_dirs = _axis_dirs(effective_rules_root)
    rule_dirs = axis_dirs if axis_dirs else [effective_rules_root]

    rules_executed: List[str] = []
    rules_failed: List[Tuple[str, str]] = []
    observations: List[AttributeEvidence] = []
    abort_observations: List[AbortEvidence] = []
    allocation_observations: List[AllocationEvidence] = []
    capability_observations: List[CapabilityEvidence] = []
    checked_allocation_observations: List[CheckedAllocationEvidence] = []
    hazard_observations: List[HazardEvidence] = []

    # spatch invocation per axis. ``no_includes=True`` matches the
    # existing PR-3 scan + PR-4 prereqs untrusted-target posture;
    # trusted-mode opt-in is a future operator flag.
    for axis_dir in rule_dirs:
        spatch_results = spatch_run_rules(
            target=target,
            rules_dir=axis_dir,
            timeout_per_rule=timeout_per_rule,
            no_includes=True,
        )
        for result in spatch_results:
            rules_executed.append(result.rule)
            if result.errors:
                # Per-rule failure — collect but don't abort. Other rules
                # still contribute evidence.
                rules_failed.append(
                    (result.rule, "; ".join(result.errors)[:500])
                )
            for match in result.matches:
                # The same parser dispatches by message prefix:
                # attribute kinds → AttributeEvidence; abort → AbortEvidence;
                # unchecked_alloc_field → AllocationEvidence.
                observations.extend(_parse_match_to_attribute(match))
                abort_observations.extend(_parse_match_to_abort(match))
                allocation_observations.extend(
                    _parse_match_to_allocation(match)
                )
                capability_observations.extend(
                    _parse_match_to_capability(match)
                )
                checked_allocation_observations.extend(
                    _parse_match_to_checked_allocation(match)
                )
                hazard_observations.extend(
                    _parse_match_to_hazard(match)
                )

    # Project-specific alias discovery: walk target headers, classify
    # `#define MACRO __attribute__((...))` patterns by family, count
    # usage, cap per family.
    try:
        from packages.source_intel.discovery import discover_aliases
        discovery = discover_aliases(target)
        discovered_alias_tuple = tuple(
            (family, names)
            for family, names in sorted(discovery.aliases_by_family.items())
        )
    except ImportError:
        discovered_alias_tuple = ()

    # Augment cocci output with alias scanning. Phase 2 shipped curated
    # WUR aliases only; Phase 3c also scans for project-discovered
    # aliases (any kind) with provenance = "project_alias".
    observations.extend(_scan_alias_observations(target))
    observations.extend(
        _scan_project_alias_observations(
            target,
            discovered_alias_tuple,
        )
    )

    return SourceIntelResult(
        target=str(target),
        rules_executed=tuple(rules_executed),
        rules_failed=tuple(rules_failed),
        spatch_version=spatch_version(),
        attributes=tuple(observations),
        discovered_aliases=discovered_alias_tuple,
        aborts=tuple(abort_observations),
        allocations=tuple(allocation_observations),
        capabilities=tuple(capability_observations),
        checked_allocations=tuple(checked_allocation_observations),
        hazards=tuple(hazard_observations),
        build_flags=extract_flags(target),
    )


# =====================================================================
# Internal — match parsing
# =====================================================================


#: Raw-match strings to record for each cocci-emitted kind. The cocci
#: rules match a small fixed set of literal spellings, so we map kind
#: → canonical provenance string once. (Per-spelling provenance lands
#: with axis-1-expansion's alias-discovery pass — projects that use
#: __must_check / __wur etc. would benefit from the exact spelling.)
_KIND_TO_RAW_MATCH: Dict[str, str] = {
    KIND_WUR: "__attribute__((warn_unused_result))",
    KIND_NONNULL: "__attribute__((nonnull))",
    KIND_ALLOC_SIZE: "__attribute__((alloc_size(...)))",
    KIND_RETURNS_NONNULL: "__attribute__((returns_nonnull))",
    KIND_NORETURN: "__attribute__((noreturn))",
    KIND_MALLOC: "__attribute__((malloc))",
    KIND_NO_STACK_PROTECTOR: "__attribute__((no_stack_protector))",
    KIND_ACCESS: "__attribute__((access(...)))",
}


def _parse_match_to_allocation(match: Any) -> List[AllocationEvidence]:
    """Convert a cocci :class:`SpatchMatch` from an allocation rule
    into an :class:`AllocationEvidence` record.

    Cocci emits one of:
      * ``unchecked_alloc_field:<allocator>:<field>`` — field shape
      * ``unchecked_alloc_local:<allocator>`` — local-var shape

    The enclosing-function lookup uses the same regex-based heuristic
    as abort parsing.
    """
    msg = (getattr(match, "message", "") or "").strip()
    file_path = getattr(match, "file", "")
    line_no = int(getattr(match, "line", 0))

    shape: Optional[str] = None
    allocator = ""
    target_field: Optional[str] = None

    if msg.startswith("unchecked_alloc_field:"):
        payload = msg[len("unchecked_alloc_field:"):].strip()
        if ":" in payload:
            allocator, _, target_field = payload.partition(":")
            allocator = allocator.strip()
            target_field = target_field.strip() or None
            shape = "field"
    elif msg.startswith("unchecked_alloc_local:"):
        allocator = msg[len("unchecked_alloc_local:"):].strip()
        shape = "local"

    if shape is None or not allocator:
        return []

    enclosing_fn = _enclosing_function(file_path, line_no) if file_path else None

    try:
        from packages.source_intel.conditional import enclosing_condition
        cond = enclosing_condition(file_path, line_no) if file_path else None
    except ImportError:
        cond = None

    return [AllocationEvidence(
        allocator=allocator,
        location=(file_path, line_no),
        shape=shape,
        target_field=target_field,
        enclosing_function=enclosing_fn,
        conditional_on=cond,
    )]


def _parse_match_to_abort(match: Any) -> List[AbortEvidence]:
    """Convert a cocci :class:`SpatchMatch` from abort_proximate.cocci
    into an :class:`AbortEvidence` record.

    Cocci emits ``abort:<macro_name>``. The enclosing-function lookup
    is best-effort via a Python-side regex on the source file —
    cocci doesn't carry function context into the COCCIRESULT payload
    in v1. The aggregator's per-finding lookup composes both.

    Phase 5a hard-codes ``grade=same_function`` since path-domination
    grading isn't computed yet.
    """
    msg = (getattr(match, "message", "") or "").strip()
    if not msg.startswith("abort:"):
        return []
    macro = msg[len("abort:"):].strip()
    if not macro:
        return []
    file_path = getattr(match, "file", "")
    line_no = int(getattr(match, "line", 0))

    enclosing_fn = _enclosing_function(file_path, line_no) if file_path else None

    try:
        from packages.source_intel.conditional import enclosing_condition
        cond = enclosing_condition(file_path, line_no) if file_path else None
    except ImportError:
        cond = None

    return [AbortEvidence(
        macro=macro,
        location=(file_path, line_no),
        grade=GRADE_SAME_FUNCTION,
        enclosing_function=enclosing_fn,
        conditional_on=cond,
    )]


def _parse_match_to_capability(match: Any) -> List[CapabilityEvidence]:
    """Convert a cocci :class:`SpatchMatch` from
    capability_check.cocci into a :class:`CapabilityEvidence` record.

    Cocci emits ``capability:<cap_function>``. Per-function lookup
    matches the abort-evidence shape — the aggregator scopes the
    observation to the finding's enclosing function.

    Phase 8 hard-codes ``grade=same_function`` (matching axis-2's
    Phase 5a). Path-domination grading lands when the shared
    grading machinery for axes 2/4 ships.
    """
    msg = (getattr(match, "message", "") or "").strip()
    if not msg.startswith("capability:"):
        return []
    cap_fn = msg[len("capability:"):].strip()
    if not cap_fn:
        return []
    file_path = getattr(match, "file", "")
    line_no = int(getattr(match, "line", 0))

    enclosing_fn = (
        _enclosing_function(file_path, line_no) if file_path else None
    )

    try:
        from packages.source_intel.conditional import enclosing_condition
        cond = (
            enclosing_condition(file_path, line_no)
            if file_path else None
        )
    except ImportError:
        cond = None

    return [CapabilityEvidence(
        cap_function=cap_fn,
        location=(file_path, line_no),
        grade=GRADE_SAME_FUNCTION,
        enclosing_function=enclosing_fn,
        conditional_on=cond,
    )]


def _parse_match_to_hazard(match: Any) -> List[HazardEvidence]:
    """Convert a cocci :class:`SpatchMatch` from
    engine/coccinelle/source_intel/hazards/ into a
    :class:`HazardEvidence` record.

    Message prefix is ``hazard:<kind>:<detail>``. Currently kinds
    are ``deprecated_func`` and ``signed_alloc``. New hazard kinds
    just need a new cocci rule emitting the same prefix shape and
    the parser will pick them up.
    """
    msg = (getattr(match, "message", "") or "").strip()
    if not msg.startswith("hazard:"):
        return []
    parts = msg.split(":", 2)
    if len(parts) < 3:
        return []
    _hazard, kind, detail = parts
    kind = kind.strip()
    detail = detail.strip()
    if not kind:
        return []
    file_path = getattr(match, "file", "")
    line_no = int(getattr(match, "line", 0))
    enclosing_fn = (
        _enclosing_function(file_path, line_no) if file_path else None
    )
    return [HazardEvidence(
        kind=kind,
        detail=detail,
        location=(file_path, line_no),
        enclosing_function=enclosing_fn,
    )]


def _parse_match_to_checked_allocation(
    match: Any,
) -> List[CheckedAllocationEvidence]:
    """Convert a cocci :class:`SpatchMatch` from
    checked_alloc.cocci into a :class:`CheckedAllocationEvidence`
    record. Cocci emits ``checked_alloc:<allocator>``.
    """
    msg = (getattr(match, "message", "") or "").strip()
    if not msg.startswith("checked_alloc:"):
        return []
    allocator = msg[len("checked_alloc:"):].strip()
    if not allocator:
        return []
    file_path = getattr(match, "file", "")
    line_no = int(getattr(match, "line", 0))
    enclosing_fn = (
        _enclosing_function(file_path, line_no) if file_path else None
    )
    return [CheckedAllocationEvidence(
        allocator=allocator,
        location=(file_path, line_no),
        enclosing_function=enclosing_fn,
    )]


# Cache for per-file function bounds. Pattern matches a C function
# definition opener: optional storage class / attributes / type, then
# the name + `(`. Best-effort — we don't parse C, just locate function
# openers by `^<name>(...)` optionally followed by `{` on the same
# line (for one-line defs) or with no following `{` (multi-line where
# the body opener is on a separate line). Lines ending with `;` are
# rejected upstream (declarations, not definitions).
_FUNC_DEF_RE = re.compile(
    r"^\s*(?:[A-Za-z_][A-Za-z0-9_]*\s+)*([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{]*?\)\s*\{?",
)

#: C keywords that look like function names to the naive regex above.
#: Without filtering, `if (cond) { ... }` is mis-classified as a
#: function definition named "if". Required-type-prefix check would
#: be cleaner but the regex allows zero type prefixes for K&R-style
#: defs (rare) — keep the regex permissive, reject these keywords
#: post-hoc.
_C_KEYWORDS: FrozenSet[str] = frozenset({
    "if", "else", "while", "for", "switch", "case", "do", "return",
    "goto", "break", "continue", "sizeof", "typeof", "static_assert",
    "_Static_assert", "__builtin_expect", "likely", "unlikely",
})


def _enclosing_function(file_path: str, line: int) -> Optional[str]:
    """Best-effort: find the C function definition enclosing ``line``.

    Implementation: scan backward from ``line``, find the most recent
    line that looks like a function definition opener (identifier
    followed by parameter list, no semicolon at end). Returns the
    function name or None when ambiguous.

    NOT a C parser. Misses: K&R-style decls, function-pointer typedefs,
    macros that expand to function-like things. Good enough for the
    common case (kernel + curl follow standard ANSI C function decl
    style); ambiguous cases return None which the aggregator handles
    by leaving the abort un-attributed.
    """
    try:
        with open(file_path, "r", errors="replace") as f:
            lines = f.readlines()
    except (OSError, IOError):
        return None
    if line < 1 or line > len(lines):
        return None
    # Walk backward looking for a likely function opener. Bound the
    # walk so a malformed file doesn't take forever. ``range()`` end
    # is exclusive — use -1 (or line-1-max_walk-1, whichever is larger)
    # so we include lines[0].
    max_walk = 1000
    stop = max(-1, line - 1 - max_walk - 1)
    for i in range(line - 1, stop, -1):
        candidate = lines[i].rstrip("\n")
        # Skip preprocessor lines, comments, declarations ending with ;
        if candidate.lstrip().startswith(("#", "//", "/*", "*")):
            continue
        if candidate.rstrip().endswith(";"):
            continue
        m = _FUNC_DEF_RE.match(candidate)
        if m:
            name = m.group(1)
            # Reject C keywords that look like function names —
            # `if (cond) { ... }` regex-matches as "function `if`".
            if name in _C_KEYWORDS:
                continue
            return name
    return None


def _parse_match_to_attribute(match: Any) -> List[AttributeEvidence]:
    """Convert a cocci :class:`SpatchMatch` into ``AttributeEvidence``
    records.

    The shipped attrs/*.cocci rules emit messages of the form
    ``<kind>:<function_name>`` where ``<kind>`` is one of ``ALL_KINDS``.
    Other message shapes are ignored (future-proof for non-attrs
    axes that may share this parser path).

    ``conditional_on`` is captured by looking up the innermost
    enclosing ``#if*`` block at the match's (file, line). The lookup
    is cached file-by-file; multiple matches in the same file share
    the parse cost.
    """
    msg = (getattr(match, "message", "") or "").strip()
    if ":" not in msg:
        return []
    kind, _, func_name = msg.partition(":")
    kind = kind.strip()
    func_name = func_name.strip()
    if not func_name or kind not in ALL_KINDS:
        return []
    file_path = getattr(match, "file", "")
    line_no = int(getattr(match, "line", 0))

    # Import locally to keep conditional capture optional — if the
    # module is stripped from a minimal install, evidence still emits.
    try:
        from packages.source_intel.conditional import enclosing_condition
        cond = enclosing_condition(file_path, line_no) if file_path else None
    except ImportError:
        cond = None

    return [AttributeEvidence(
        kind=kind,
        function_name=func_name,
        location=(file_path, line_no),
        match_source="literal",
        raw_match=_KIND_TO_RAW_MATCH.get(kind, ""),
        conditional_on=cond,
    )]


# Back-compat alias: tests that import the Phase 2 name keep working.
_parse_match_to_wur = _parse_match_to_attribute


def _scan_alias_observations(target: Path) -> List[AttributeEvidence]:
    """Curated-alias substring scan. Looks for known macro spellings
    in C/H files under ``target`` and emits one observation per file
    where any alias is seen.

    Limitations (documented; tightened in axis-1-expansion):
      * Function-name attribution is best-effort: we record an
        empty ``function_name`` because substring matching can't
        tell us which function the alias applied to.
      * Counted once per file; multiple aliases in one file produce
        one observation.

    These limitations are why the per-rule cocci approach is the
    primary evidence source — the alias scan is supplementary, not
    substitutive.
    """
    observations: List[AttributeEvidence] = []
    if not target.is_dir():
        # Single-file target — scan that file directly.
        if target.is_file() and target.suffix.lower() in _C_CPP_EXTS:
            return _scan_alias_in_file(target)
        return observations

    seen_files = 0
    for entry in target.rglob("*"):
        if seen_files >= 500:
            # Bound the scan; large kernel trees would overflow.
            break
        if not entry.is_file():
            continue
        if entry.suffix.lower() not in _C_CPP_EXTS:
            continue
        seen_files += 1
        observations.extend(_scan_alias_in_file(entry))
    return observations


def _scan_project_alias_observations(
    target: Path,
    discovered_alias_tuple: Tuple[Tuple[str, Tuple[str, ...]], ...],
) -> List[AttributeEvidence]:
    """For each discovered project-specific alias macro, scan source
    files for occurrences and emit ``match_source="project_alias"``
    evidence.

    Limitations match the curated-alias scan: function-name attribution
    is best-effort (empty). The per-alias cocci rules planned for
    future axes will bind aliases to functions; this pass just records
    that the macro appears in a C source file.
    """
    observations: List[AttributeEvidence] = []
    if not target.is_dir():
        return observations

    # Build a flat list of (kind, alias_name) tuples for the scan.
    alias_pairs: List[Tuple[str, str]] = []
    for family, names in discovered_alias_tuple:
        for name in names:
            alias_pairs.append((family, name))
    if not alias_pairs:
        return observations

    seen_files = 0
    for entry in target.rglob("*"):
        if seen_files >= 500:
            break
        if not entry.is_file():
            continue
        if entry.suffix.lower() not in _C_CPP_EXTS:
            continue
        seen_files += 1
        try:
            text = entry.read_text(errors="replace")
        except OSError:
            continue
        for family, alias_name in alias_pairs:
            # Word-boundary check; substring would risk false positives
            # on prefix-overlap (FOO_CHECK vs MUST_CHECK).
            if not _is_word_present(text, alias_name):
                continue
            # First-occurrence line for prompt context.
            line_no = 0
            for n, line in enumerate(text.split("\n"), start=1):
                if _is_word_present(line, alias_name):
                    line_no = n
                    break
            observations.append(AttributeEvidence(
                kind=family,
                function_name="",  # see scan_alias_in_file docstring
                location=(str(entry), line_no),
                match_source="project_alias",
                raw_match=alias_name,
            ))
    return observations


def _is_word_present(text: str, word: str) -> bool:
    """Word-boundary substring check. Avoids false positives where
    one macro name is a prefix of another (e.g. ``CHECK`` matching in
    ``CHECK_RETURN``)."""
    return bool(re.search(r"\b" + re.escape(word) + r"\b", text))


def _scan_alias_in_file(path: Path) -> List[AttributeEvidence]:
    """Best-effort: detect WUR alias spellings in a single C/H file.

    One observation per (file, alias_spelling) pair — multiple aliases
    in the same file produce multiple observations because each may
    apply to a different function. We can't bind the alias to a function
    name without parsing the C, which is exactly cocci's job; the
    alias-scan exists to surface that "this file has hardening intent"
    even when the cocci rule didn't fire (which it won't for non-literal
    spellings until per-alias rules ship).
    """
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return []

    observations: List[AttributeEvidence] = []
    for spelling in ALL_WUR_ALIASES:
        if spelling in text:
            # First occurrence line — for prompt rendering's sake.
            line_no = 0
            for n, line in enumerate(text.split("\n"), start=1):
                if spelling in line:
                    line_no = n
                    break
            observations.append(AttributeEvidence(
                kind=KIND_WUR,
                function_name="",  # see docstring — best-effort gap
                location=(str(path), line_no),
                match_source="known_alias",
                raw_match=spelling,
            ))
    return observations
