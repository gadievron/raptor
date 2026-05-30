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
import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from core.build.build_flags import BuildFlagsContext, extract_flags
from core.function_taxonomy import (
    DEVICE_CONTROL_FUNCS,
    IPC_FUNCS,
    KERNEL_USERSPACE_FUNCS,
    NETWORK_INGEST_FUNCS,
    PROCESS_BOUNDARY_FUNCS,
    SCAN_FAMILY_FUNCS,
    STREAM_INPUT_FUNCS,
)
from packages.source_intel.aliases import (
    ALL_WUR_ALIASES,
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


# Source-side L1 calls are composed locally from the shared function catalog.
# The shared catalog deliberately omits ubiquitous import-table signals such
# as read/fread, so this scanner adds those back only for source-code call-site
# evidence. argv/envp/environ stay scanner-local because they are identifiers,
# not function names.
_SOURCE_SIDE_FD_READ_FUNCS: FrozenSet[str] = frozenset({
    "read",
    "fread",
})

# The shared taxonomy sets are intentionally broader for binary fingerprinting.
# Keep only call sites that directly ingest bytes for L1 source evidence.
_SOURCE_SIDE_SOCKET_INPUT_FUNCS: FrozenSet[str] = NETWORK_INGEST_FUNCS - frozenset({
    "accept",
    "bind",
    "listen",
})
_SOURCE_SIDE_STREAM_INPUT_FUNCS: FrozenSet[str] = (
    STREAM_INPUT_FUNCS | SCAN_FAMILY_FUNCS
) - frozenset({
    "sscanf",
    "vsscanf",
    "swscanf",
})

_C_L1_SOURCE_CALLS: Dict[str, str] = {
    **{name: "fd" for name in sorted(_SOURCE_SIDE_FD_READ_FUNCS)},
    **{name: "socket" for name in sorted(_SOURCE_SIDE_SOCKET_INPUT_FUNCS)},
    **{name: "stream" for name in sorted(_SOURCE_SIDE_STREAM_INPUT_FUNCS)},
    **{name: "env" for name in sorted(PROCESS_BOUNDARY_FUNCS)},
    **{name: "kernel_user" for name in sorted(KERNEL_USERSPACE_FUNCS)},
    **{name: "ipc" for name in sorted(IPC_FUNCS)},
    **{name: "device_control" for name in sorted(DEVICE_CONTROL_FUNCS)},
}


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
    #: Axis-3 size-source classification (Tier 2.3). One of:
    #:   "literal" — kmalloc(8, ...)
    #:   "sizeof" — kmalloc(sizeof(struct foo), ...)
    #:   "variable" — kmalloc(n, ...)
    #:   "multiplied" — kmalloc(n * sizeof(*p), ...)
    #:   "user_controlled" — multiplied with user-input-shaped var
    #:   None — not classified / parser failed
    size_source: Optional[str] = None


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
class PairedFreeEvidence:
    """An allocator call site whose return value IS subsequently
    freed within the same function (via matching free_fn family).

    INFORMATIONAL only — emitted at the ALLOC site location. Stage
    D LLM consumer reads as "this allocation is freed in-function".

    Useful negative signal for CodeQL cpp/memory-leak findings —
    when the same alloc-site IS paired, the leak claim is suspect
    (but not definitively wrong — error paths may still leak).

    Why not verdict-active for memory-leak suppression: cocci
    pairing means "we found A free path", not "every path frees
    correctly". CFG-level all-paths analysis is out of scope for
    a cocci-only tool.
    """

    allocator: str  # kmalloc / kzalloc / vmalloc / ...
    free_fn: str    # kfree / vfree / kvfree / free
    location: Tuple[str, int]  # at the alloc site
    enclosing_function: Optional[str] = None


@dataclass(frozen=True)
class DoubleFreeEvidence:
    """A single observation of a `kfree(X); ... kfree(X);` shape
    without intervening reassignment to NULL or a new allocation.

    Cocci emits TWO records per match: ``role="first"`` at the
    first kfree, ``role="second"`` at the second. Both have the
    same enclosing function (verified by Python).

    Verdict-active: when a CodeQL cpp/double-free finding sits at
    either kfree site, this is direct structural evidence → fire
    EXPLOITABLE.
    """

    role: str  # "first" | "second"
    free_fn: str  # kfree / kvfree / vfree / free
    location: Tuple[str, int]
    enclosing_function: Optional[str] = None


@dataclass(frozen=True)
class BoundaryEvidence:
    """Kernel/user trust-boundary crossing (copy_from_user etc.).

    INFORMATIONAL only — feeds Stage D LLM context. Useful for:
      * privilege-gradient reasoning (data crossed user→kernel
        boundary, attacker-controlled at this point)
      * info-leak (copy_to_user before sink — kernel data may
        leak to userland)
      * input-validation analysis (where validation needs to
        happen given the boundary location)
    """

    boundary_fn: str  # "copy_from_user", "copy_to_user", etc.
    location: Tuple[str, int]
    enclosing_function: Optional[str] = None


@dataclass(frozen=True)
class CLevelSourceEvidence:
    """C/C++ L1 source observation for /understand and /validate.

    Unlike ``BoundaryEvidence`` (kernel/userspace privilege crossings),
    this captures ordinary user-space input origins that seed taint:
    process arguments, environment variables, stream/socket reads, and
    fd-level reads. It is informational context for the LLM rather than
    a direct verdict override.
    """

    source_kind: str  # "argv" | "env" | "stream" | "socket" | "fd"
    source_name: str  # argv/envp/getenv/read/recv/fgets/etc.
    location: Tuple[str, int]
    enclosing_function: Optional[str] = None


@dataclass(frozen=True)
class LsmEvidence:
    """Linux Security Module hook call site (security_*).

    INFORMATIONAL only. Indicates the kernel code path is subject
    to LSM policy enforcement (SELinux/AppArmor/Smack/Lockdown).
    """

    hook_name: str
    location: Tuple[str, int]
    enclosing_function: Optional[str] = None


@dataclass(frozen=True)
class LockSiteEvidence:
    """A single lock acquire or release site (spin/mutex/rw/pthread).

    Enumeration only — does NOT imply imbalance or bug. Populated from
    engine/coccinelle/source_intel/concurrency/lock_sites.cocci output.
    Feeds the Phase B `shared_state` /understand --map section.
    """

    op: str                                       # "acquire" | "release"
    kind: str                                     # "spin" | "mutex" | "rw" | "pthread_mutex"
    fn: str                                       # concrete function name (e.g. "spin_lock_irqsave")
    lock_var: str                                 # first-arg expression, normalised
    location: Tuple[str, int]
    enclosing_function: Optional[str] = None


@dataclass(frozen=True)
class WarnEvidence:
    """A single observation of a non-aborting runtime-warning call
    (WARN_ON / pr_warn / KASAN_REPORT etc.).

    INFORMATIONAL only — warn-class doesn't terminate execution, so
    a verdict policy can't suppress on its presence. Surfaces to
    Stage D LLM as "the runtime emits a warning here" context.
    """

    warn_fn: str
    location: Tuple[str, int]
    enclosing_function: Optional[str] = None


@dataclass(frozen=True)
class NullGuardEvidence:
    """A single observation of an explicit NULL-check site.

    Sub-kinds:
      * ``bang`` — `if (!e)`
      * ``eq_null`` — `if (e == NULL)`
      * ``is_err`` — `IS_ERR(e)` / `IS_ERR_OR_NULL(e)`

    INFORMATIONAL only in Phase 12 — axis-3's unchecked_alloc rule
    already uses null-check presence implicitly (via cocci `when !=`)
    to suppress unchecked-alloc claims. This dataclass makes those
    checks visible to consumers (Stage D / `/exploit`) as standalone
    evidence, with locations.
    """

    kind: str  # "bang" | "eq_null" | "is_err"
    location: Tuple[str, int]
    enclosing_function: Optional[str] = None


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
class PrivilegeBackWalkEvidence:
    """Result of an N-hop privilege back-walk from a finding's
    enclosing function up through the callgraph.

    Computed by :func:`compute_privilege_back_walk_evidence` (which
    shares the walk logic with the verdict-side
    :func:`packages.source_intel.adapter._privilege_back_walk_suppresses`)
    but produces prose-renderable evidence rather than a boolean
    suppression decision.

    Fields:
      * ``finding_function`` — the function the walk started from.
      * ``all_paths_gated`` — True iff every reachable caller-path
        within ``depth_used`` hops passes through a privileged
        ``capable()`` check.
      * ``gating_examples`` — list of ``(caller_function,
        cap_function, file_path, line)`` records of gates the walk
        actually found. Examples — not exhaustive when the
        callgraph is large.
      * ``ungated_caller`` — when ``all_paths_gated`` is False, the
        first caller path that lacks a gate (concrete counter-
        example for the LLM). ``None`` when all gated or when no
        callers were found.
      * ``depth_used`` — actual depth budget consumed.
      * ``no_callers`` — True iff the walk found no callers (finding
        function is likely a top-level entry; back-walk inapplicable).
    """

    finding_function: str
    all_paths_gated: bool
    gating_examples: Tuple[Tuple[str, str, str, int], ...] = ()
    ungated_caller: Optional[str] = None
    depth_used: int = 0
    no_callers: bool = False


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

    #: Axis 2 sub-class: warn-class call sites (informational).
    warns: Tuple[WarnEvidence, ...] = ()

    #: Axis 2 sub-class: explicit NULL-check sites (informational).
    null_guards: Tuple[NullGuardEvidence, ...] = ()

    #: Axis 4 expansion: kernel/user trust-boundary crossings
    #: (copy_from_user, copy_to_user, get_user, put_user, etc.).
    #: Informational; feeds Stage D LLM privilege/data-flow context.
    boundary_crossings: Tuple[BoundaryEvidence, ...] = ()

    #: L1 source table expansion: C/C++ user-controlled inputs
    #: (read/recv/fgets/argv/env/getenv, etc.). Informational; feeds
    #: Stage D LLM source/taint context for /understand + /validate.
    c_level_sources: Tuple[CLevelSourceEvidence, ...] = ()

    #: Axis 4 expansion: LSM (Linux Security Module) hook calls.
    #: Informational; indicates policy-enforcement points.
    lsm_hooks: Tuple[LsmEvidence, ...] = ()

    #: Axis 3 expansion: double-free call sites
    #: (`kfree(X); ... kfree(X);` shape with no intervening
    #: reassignment). Verdict-active for cpp/double-free.
    double_frees: Tuple[DoubleFreeEvidence, ...] = ()

    #: Axis 3 expansion: alloc sites whose return is freed in-
    #: function (`local = alloc(...); ... free(local);` shape).
    #: Informational — feeds Stage D LLM as memory-leak corroboration.
    paired_frees: Tuple[PairedFreeEvidence, ...] = ()

    #: Phase B (concurrency axis): lock acquire/release sites
    #: enumerated by lock_sites.cocci. Informational; feeds the
    #: shared_state /understand --map section + per-function
    #: annotations. No verdict policy attached — pairing/imbalance
    #: detection is lock_imbalance.cocci's job.
    lock_sites: Tuple[LockSiteEvidence, ...] = ()

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

    def function_intel_status(
        self, function_name: str, target: Optional[Path] = None,
    ) -> str:
        """Return the source_intel status for ``function_name`` —
        per design strict invariant: never fabricate; explicitly
        report ``name_not_in_tree`` when PR-4 prereqs ran but
        didn't see the function.

        Returns one of:
          * ``"in_tree"``         — PR-4 found a definition for the name
          * ``"name_not_in_tree"`` — PR-4 ran, no definition for this name
          * ``"prereqs_skipped"`` — PR-4 unavailable (no spatch, etc.)
          * ``"unknown"``         — cannot determine (no target / no PR-4)

        ``target`` is the scan dir for PR-4 prereqs. When None,
        defaults to the result's recorded target. When PR-4
        prereqs aren't available (cocci missing, import fails),
        returns ``"prereqs_skipped"``.

        Stage D LLM consumers should treat ``name_not_in_tree``
        as "I scanned and the name isn't here" — different from
        "I haven't scanned" (``prereqs_skipped``).
        """
        try:
            from packages.coccinelle.prereqs import gather_prereqs
        except ImportError:
            return "prereqs_skipped"
        scan_target = target or (Path(self.target) if self.target else None)
        if scan_target is None:
            return "unknown"
        if not scan_target.is_dir():
            return "unknown"
        try:
            facts = gather_prereqs(scan_target)
        except Exception:  # noqa: BLE001
            return "prereqs_skipped"
        if facts.is_skipped:
            return "prereqs_skipped"
        return "in_tree" if facts.function_exists(function_name) else "name_not_in_tree"

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
    timeout_per_rule: int = 180,
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

    # Build + register the inventory for the target so the parser
    # path's `_enclosing_function` lookups go through tree-sitter
    # instead of the regex fallback. Best-effort — when inventory
    # build raises, evidence parsing continues with the regex
    # fallback path.
    _maybe_register_inventory(target)

    rules_executed: List[str] = []
    rules_failed: List[Tuple[str, str]] = []
    observations: List[AttributeEvidence] = []
    abort_observations: List[AbortEvidence] = []
    allocation_observations: List[AllocationEvidence] = []
    capability_observations: List[CapabilityEvidence] = []
    checked_allocation_observations: List[CheckedAllocationEvidence] = []
    hazard_observations: List[HazardEvidence] = []
    warn_observations: List[WarnEvidence] = []
    null_guard_observations: List[NullGuardEvidence] = []
    boundary_observations: List[BoundaryEvidence] = []
    lsm_observations: List[LsmEvidence] = []
    c_level_source_observations: List[CLevelSourceEvidence] = []
    double_free_observations: List[DoubleFreeEvidence] = []
    paired_free_observations: List[PairedFreeEvidence] = []
    lock_site_observations: List[LockSiteEvidence] = []

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
                warn_observations.extend(
                    _parse_match_to_warn(match)
                )
                null_guard_observations.extend(
                    _parse_match_to_null_guard(match)
                )
                boundary_observations.extend(
                    _parse_match_to_boundary(match)
                )
                lsm_observations.extend(
                    _parse_match_to_lsm(match)
                )
                double_free_observations.extend(
                    _parse_match_to_double_free(match)
                )
                paired_free_observations.extend(
                    _parse_match_to_paired_free(match)
                )
                lock_site_observations.extend(
                    _parse_match_to_lock_site(match)
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
    c_level_source_observations.extend(_scan_c_level_source_inputs(target))

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
        warns=tuple(warn_observations),
        null_guards=tuple(null_guard_observations),
        boundary_crossings=tuple(boundary_observations),
        c_level_sources=tuple(c_level_source_observations),
        lsm_hooks=tuple(lsm_observations),
        double_frees=tuple(double_free_observations),
        paired_frees=tuple(paired_free_observations),
        lock_sites=tuple(lock_site_observations),
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

    size_source = _classify_size_source(file_path, line_no, allocator)

    return [AllocationEvidence(
        allocator=allocator,
        location=(file_path, line_no),
        shape=shape,
        target_field=target_field,
        enclosing_function=enclosing_fn,
        conditional_on=cond,
        size_source=size_source,
    )]


# Heuristic name patterns suggesting a variable carries user input.
# Conservative — operators routinely use these names for kernel-side
# computations too, but in the presence of a CWE-190/CWE-122 finding
# the "user_controlled" label is a useful Stage D LLM hint.
_USER_INPUT_VAR_NAMES: FrozenSet[str] = frozenset({
    "n", "len", "length", "size", "count", "nr", "num",
    "user_size", "user_len", "input_len", "input_size",
    "msg_len", "data_len", "payload_len", "buf_len",
    "nbytes", "nelems", "cnt",
})


def _classify_size_source(
    file_path: str,
    line_no: int,
    allocator: str,
) -> Optional[str]:
    """Read the source line and classify the first argument shape of
    the allocator call.

    Categories:
      * ``literal`` — `kmalloc(8, ...)` — digit literal
      * ``sizeof`` — `kmalloc(sizeof(struct foo), ...)` — sizeof-only
      * ``variable`` — `kmalloc(n, ...)` — single identifier
      * ``multiplied`` — `kmalloc(n * sizeof(T), ...)` — multiplication
      * ``user_controlled`` — multiplied with a var name matching the
        user-input name set (``n``, ``len``, ``count``, ``nbytes``…)

    Returns None when:
      * the file can't be read
      * the alloc call isn't found at the expected line
      * the first arg doesn't match any pattern
    """
    if not file_path or not line_no:
        return None
    try:
        with open(file_path, "r", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return None
    if line_no < 1 or line_no > len(lines):
        return None
    src_line = lines[line_no - 1]

    # Find `<allocator>(` and extract through matching `)` accounting
    # for nested parens (the first arg might contain sizeof(T) etc.).
    alloc_pat = re.compile(r"\b" + re.escape(allocator) + r"\s*\(")
    m = alloc_pat.search(src_line)
    if not m:
        return None
    start = m.end()  # position just past the opening (
    depth = 1
    arg_end = None
    for i in range(start, len(src_line)):
        ch = src_line[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                arg_end = i
                break
        elif ch == "," and depth == 1:
            # First arg ends at this comma.
            arg_end = i
            break
    if arg_end is None:
        return None
    first_arg = src_line[start:arg_end].strip()
    if not first_arg:
        return None

    # Classify.
    return _classify_arg_shape(first_arg)


_DIGIT_RE = re.compile(r"^-?\d+[uUlL]*$|^0[xX][0-9a-fA-F]+[uUlL]*$")
_SIZEOF_RE = re.compile(r"^\s*sizeof\s*\(")
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z_0-9]*$")
_MUL_RE = re.compile(r"\*")


def _is_pure_sizeof(arg: str) -> bool:
    """Return True iff ``arg`` is exactly `sizeof(...)` with balanced
    parens and nothing after. `sizeof(*p)` qualifies (the `*` is
    inside the parens — dereference, not multiplication).
    """
    arg = arg.strip()
    if not arg.startswith("sizeof"):
        return False
    rest = arg[len("sizeof"):].lstrip()
    if not rest.startswith("("):
        return False
    # Walk balancing parens.
    depth = 0
    for i, ch in enumerate(rest):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                # rest[i+1:] must be empty (no trailing arithmetic).
                return rest[i+1:].strip() == ""
    return False


def _classify_arg_shape(arg: str) -> Optional[str]:
    """Classify a single allocator argument string."""
    arg = arg.strip()
    if not arg:
        return None
    if _DIGIT_RE.match(arg):
        return "literal"
    # Pure sizeof(...) with no top-level multiplication. Check by
    # verifying the entire arg is just `sizeof(...)` — i.e., no `*`
    # outside the sizeof parens. `*` inside the parens (e.g.
    # `sizeof(*p)`) is dereference syntax, NOT multiplication.
    if _is_pure_sizeof(arg):
        return "sizeof"
    # Multiplication present — could be sizeof*var or var*sizeof.
    if "*" in arg:
        # Look for a known user-input var name in the operands.
        operands = [op.strip() for op in arg.split("*")]
        for op in operands:
            # Strip sizeof(...) wrappers.
            if op.startswith("sizeof"):
                continue
            # Strip parens.
            naked = op.strip("()").strip()
            if naked in _USER_INPUT_VAR_NAMES:
                return "user_controlled"
        return "multiplied"
    # Single identifier.
    if _IDENT_RE.match(arg):
        if arg in _USER_INPUT_VAR_NAMES:
            return "user_controlled"
        return "variable"
    return None


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

    grade = _classify_call_site_grade(file_path, line_no)

    return [AbortEvidence(
        macro=macro,
        location=(file_path, line_no),
        grade=grade,
        enclosing_function=enclosing_fn,
        conditional_on=cond,
    )]


def _classify_call_site_grade(file_path: str, call_line: int) -> str:
    """Best-effort structural classifier for axis-2 / axis-4 grade.

    Reads the source file and inspects the brace-depth + control-flow
    shape around ``call_line`` to upgrade the default
    ``same_function`` grade to ``same_path`` or ``dominates`` when
    structural evidence supports it.

    Used by axis-2 abort detection AND axis-4 capability detection —
    both have the same shape: "a call site within a function;
    does it dominate the function from entry?"

    Heuristic:
      * Walk forwards from line 0 to ``call_line``.
      * Track brace depth (function body = depth 1).
      * If call is at depth 1 AND no `return` / `goto` precedes it
        at depth 1: grade = DOMINATES (call runs on every path from
        function entry to the call line; nothing has returned
        before).
      * If call is at depth > 1 (inside if/for/while): grade =
        SAME_PATH (call is on at least one branch; conservative
        upgrade — it IS on a path, just not provably the only path).
      * Else: SAME_FUNCTION (default).

    Conservative on file-read failure or unparseable shape — returns
    SAME_FUNCTION.
    """
    if not file_path or not call_line:
        return GRADE_SAME_FUNCTION
    try:
        with open(file_path, "r", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return GRADE_SAME_FUNCTION
    if call_line < 1 or call_line > len(lines):
        return GRADE_SAME_FUNCTION

    call_idx = call_line - 1  # 0-indexed
    # Walk forward counting braces. We want the brace depth of the
    # call line, measured relative to the enclosing function's
    # opening brace.
    depth = 0
    function_open_at: Optional[int] = None
    saw_early_exit_at_depth_1 = False
    bypass_re = re.compile(r"\b(?:return\b|goto\b)")

    for i in range(0, call_idx + 1):
        line = lines[i]
        # Strip comments (rough — same approach as adapter.py)
        stripped = re.sub(r"/\*.*?\*/", "", line, flags=re.DOTALL)
        stripped = re.sub(r"//.*$", "", stripped, flags=re.MULTILINE)

        # Look for `return` / `goto` BEFORE the call line at depth 1
        # (function body), which would mean a normal exit path
        # precedes the call — call no longer dominates.
        if i < call_idx and depth == 1 and bypass_re.search(stripped):
            saw_early_exit_at_depth_1 = True

        for ch in stripped:
            if ch == "{":
                depth += 1
                if function_open_at is None and depth == 1:
                    function_open_at = i
            elif ch == "}":
                depth -= 1
                if depth < 0:
                    depth = 0

    # If we never saw an opening brace, we're outside a function —
    # default grade.
    if function_open_at is None:
        return GRADE_SAME_FUNCTION

    call_depth = depth
    if call_depth == 1 and not saw_early_exit_at_depth_1:
        return GRADE_DOMINATES
    if call_depth > 1:
        return GRADE_SAME_PATH
    return GRADE_SAME_FUNCTION


# Back-compat alias — Phase 5a tests referenced this name.
_classify_abort_grade = _classify_call_site_grade


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

    grade = _classify_call_site_grade(file_path, line_no)

    return [CapabilityEvidence(
        cap_function=cap_fn,
        location=(file_path, line_no),
        grade=grade,
        enclosing_function=enclosing_fn,
        conditional_on=cond,
    )]


def _parse_match_to_paired_free(
    match: Any,
) -> List[PairedFreeEvidence]:
    """Convert a cocci SpatchMatch from paired_free.cocci into a
    PairedFreeEvidence record.

    Cocci emits ``alloc_paired:<allocator>:<free_fn>`` at the
    alloc-site line.
    """
    msg = (getattr(match, "message", "") or "").strip()
    if not msg.startswith("alloc_paired:"):
        return []
    parts = msg.split(":", 2)
    if len(parts) < 3:
        return []
    _label, allocator, free_fn = parts
    allocator = allocator.strip()
    free_fn = free_fn.strip()
    if not allocator or not free_fn:
        return []
    file_path = getattr(match, "file", "")
    line_no = int(getattr(match, "line", 0))
    enclosing_fn = (
        _enclosing_function(file_path, line_no) if file_path else None
    )
    return [PairedFreeEvidence(
        allocator=allocator, free_fn=free_fn,
        location=(file_path, line_no),
        enclosing_function=enclosing_fn,
    )]


def _parse_match_to_double_free(
    match: Any,
) -> List[DoubleFreeEvidence]:
    """Convert a cocci SpatchMatch from double_free.cocci into a
    DoubleFreeEvidence record.

    Cocci emits messages of the form
    ``double_free:<role>:<free_fn>`` where role is "first" or
    "second".
    """
    msg = (getattr(match, "message", "") or "").strip()
    if not msg.startswith("double_free:"):
        return []
    parts = msg.split(":", 2)
    if len(parts) < 3:
        return []
    _label, role, free_fn = parts
    role = role.strip()
    free_fn = free_fn.strip()
    if role not in ("first", "second") or not free_fn:
        return []
    file_path = getattr(match, "file", "")
    line_no = int(getattr(match, "line", 0))
    enclosing_fn = (
        _enclosing_function(file_path, line_no) if file_path else None
    )
    return [DoubleFreeEvidence(
        role=role, free_fn=free_fn,
        location=(file_path, line_no),
        enclosing_function=enclosing_fn,
    )]


def _parse_match_to_boundary(match: Any) -> List[BoundaryEvidence]:
    """Convert a cocci SpatchMatch from user_boundary.cocci into a
    BoundaryEvidence record. Message: ``boundary:<fn>``."""
    msg = (getattr(match, "message", "") or "").strip()
    if not msg.startswith("boundary:"):
        return []
    fn = msg[len("boundary:"):].strip()
    if not fn:
        return []
    file_path = getattr(match, "file", "")
    line_no = int(getattr(match, "line", 0))
    enclosing_fn = (
        _enclosing_function(file_path, line_no) if file_path else None
    )
    return [BoundaryEvidence(
        boundary_fn=fn,
        location=(file_path, line_no),
        enclosing_function=enclosing_fn,
    )]


def _parse_match_to_lsm(match: Any) -> List[LsmEvidence]:
    """Convert a cocci SpatchMatch from lsm_hooks.cocci into an
    LsmEvidence record. Message: ``lsm:<hook_name>``."""
    msg = (getattr(match, "message", "") or "").strip()
    if not msg.startswith("lsm:"):
        return []
    hook = msg[len("lsm:"):].strip()
    if not hook:
        return []
    file_path = getattr(match, "file", "")
    line_no = int(getattr(match, "line", 0))
    enclosing_fn = (
        _enclosing_function(file_path, line_no) if file_path else None
    )
    return [LsmEvidence(
        hook_name=hook,
        location=(file_path, line_no),
        enclosing_function=enclosing_fn,
    )]


_LOCK_SITE_KINDS = frozenset({"spin", "mutex", "rw", "pthread_mutex"})
_LOCK_SITE_OPS = frozenset({"acquire", "release"})


def _parse_match_to_lock_site(match: Any) -> List[LockSiteEvidence]:
    """Convert a cocci SpatchMatch from lock_sites.cocci into a
    LockSiteEvidence record. Message: ``lock_site:<op>:<kind>:<fn>:<lock_var>``.
    The lock_var segment can contain ``:`` if the expression uses scope
    resolution etc. — only the first 4 segments are structural; the
    rest is rejoined as the lock_var."""
    msg = (getattr(match, "message", "") or "").strip()
    if not msg.startswith("lock_site:"):
        return []
    parts = msg.split(":", 4)
    if len(parts) < 5:
        return []
    _prefix, op, kind, fn, lock_var = parts
    if op not in _LOCK_SITE_OPS or kind not in _LOCK_SITE_KINDS:
        return []
    if not fn:
        return []
    # spatch renders `&foo` as `& foo`; normalise the common cases so
    # downstream consumers can group by lock_var without re-parsing.
    lock_var = lock_var.strip().replace("& ", "&")
    file_path = getattr(match, "file", "")
    line_no = int(getattr(match, "line", 0))
    enclosing_fn = (
        _enclosing_function(file_path, line_no) if file_path else None
    )
    return [LockSiteEvidence(
        op=op,
        kind=kind,
        fn=fn,
        lock_var=lock_var,
        location=(file_path, line_no),
        enclosing_function=enclosing_fn,
    )]


def _parse_match_to_warn(match: Any) -> List[WarnEvidence]:
    """Convert a cocci SpatchMatch from warn_class.cocci into a
    WarnEvidence record. Message: ``warn:<fn>``."""
    msg = (getattr(match, "message", "") or "").strip()
    if not msg.startswith("warn:"):
        return []
    warn_fn = msg[len("warn:"):].strip()
    if not warn_fn:
        return []
    file_path = getattr(match, "file", "")
    line_no = int(getattr(match, "line", 0))
    enclosing_fn = (
        _enclosing_function(file_path, line_no) if file_path else None
    )
    return [WarnEvidence(
        warn_fn=warn_fn,
        location=(file_path, line_no),
        enclosing_function=enclosing_fn,
    )]


def _parse_match_to_null_guard(match: Any) -> List[NullGuardEvidence]:
    """Convert a cocci SpatchMatch from null_guards.cocci into a
    NullGuardEvidence record. Message: ``null_guard:<kind>``."""
    msg = (getattr(match, "message", "") or "").strip()
    if not msg.startswith("null_guard:"):
        return []
    kind = msg[len("null_guard:"):].strip()
    if not kind:
        return []
    file_path = getattr(match, "file", "")
    line_no = int(getattr(match, "line", 0))
    enclosing_fn = (
        _enclosing_function(file_path, line_no) if file_path else None
    )
    return [NullGuardEvidence(
        kind=kind,
        location=(file_path, line_no),
        enclosing_function=enclosing_fn,
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
    r"^\s*(?:[A-Za-z_][A-Za-z0-9_]*[\s*&]+)*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{]*?\)\s*\{?",
)

# Cheap-match prefix used by the multi-line walker — does the line
# START like a function-definition opener (`[typespecs] name(`)? If
# so, the walker forward-joins lines until the paren balances and
# re-tests against the full ``_FUNC_DEF_RE``. The prefix regex
# deliberately doesn't require closing `)` — multi-line decls have
# it on a later line.
#
# Type-prefix tokens accepted between the first identifier and the
# function name: more identifiers (typedef chains like
# `unsigned long`), pointer/reference sigils (`*`, `**`, `&`), and
# whitespace. Required because pointer-returning functions like
# `struct page *foo(void)` have a `*` interrupting the
# type → name sequence and the simpler regex `<word>\s+<word>(`
# misses them on kernel-style code.
_FUNC_DEF_PREFIX_RE = re.compile(
    r"^\s*(?:[A-Za-z_][A-Za-z0-9_]*[\s*&]+)+"
    r"[A-Za-z_][A-Za-z0-9_]*\s*\(",
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
    # Preprocessor pseudo-functions that look like calls but aren't.
    "defined",
})


# Process-global cache of inventory dicts keyed by the absolute,
# resolved target directory they were built for. Populated by
# :func:`analyze` and consulted by :func:`_enclosing_function` when
# the queried file lives under (or at) a cached target.
#
# Cache keys are absolute resolved paths. Lookups walk the file's
# parent chain to find the deepest matching target — supports
# nested analyze() calls on subdirectories.
#
# Why module-global: ``_enclosing_function`` is called from 15+
# sites across analyze.py + adapter.py without a context-carrying
# parameter. Threading inventory through every call site would
# touch ~30 lines per consumer and break test mocks that don't
# care about the inventory. The cache lets analyze() seed the
# tree-sitter path while leaving the function signature and
# behaviour identical for downstream code.
#
# Each value is a ``(signature, inventory)`` tuple where signature
# is produced by :func:`packages.source_intel.cache.compute_target_signature`.
# Lookups recompute the signature and silently drop entries that
# don't match — auto-invalidation across consecutive runs in the
# same process. Two ``/agentic`` runs on the same path see a stale
# inventory only if the source hasn't changed (correct), and see a
# fresh build whenever any file's mtime/size or build-marker shifts.
#
# Thread-safety: the dict is guarded by ``_INVENTORY_LOCK`` (an
# ``RLock`` so a callback firing inside a lookup that triggers
# another lookup doesn't self-deadlock). The CPython GIL would in
# practice make dict reads + writes atomic at the bytecode level,
# but the multi-step lookup (find best_target → recompute signature
# → pop-or-return) reads the dict twice and would race with a
# concurrent register or another lookup's pop. The lock is taken
# only around the dict ops themselves, not while computing the
# signature (which walks the filesystem and could take ms).
_INVENTORY_BY_TARGET: Dict[str, Tuple[str, Any]] = {}
_INVENTORY_LOCK = threading.RLock()


def _register_inventory(target: Path, inventory: Any) -> None:
    """Stash an inventory for later ``_enclosing_function`` lookups.
    Called by :func:`analyze` once per target before evidence
    parsing. Idempotent — second call for the same target overwrites
    the entry (signature is recomputed)."""
    try:
        from packages.source_intel.cache import compute_target_signature
        resolved = str(target.resolve())
        sig = compute_target_signature(target)
    except (OSError, ValueError):  # unresolvable path → skip cache
        return
    with _INVENTORY_LOCK:
        _INVENTORY_BY_TARGET[resolved] = (sig, inventory)


def clear_inventory_cache() -> None:
    """Drop every cached inventory.

    Public invalidation lever for orchestrators that know a fresh
    start is wanted (e.g. between two ``/agentic`` runs on different
    targets). Signature-based auto-invalidation already covers
    same-path/content-changed cases — this is the explicit reset
    for callers that don't want to rely on the implicit path.
    """
    with _INVENTORY_LOCK:
        _INVENTORY_BY_TARGET.clear()


def _maybe_register_inventory(target: Path) -> None:
    """Best-effort: build the inventory for ``target`` and stash it
    in the module-global cache so subsequent ``_enclosing_function``
    queries route through tree-sitter (real C/C++ AST) instead of
    the regex fallback.

    Failure modes silently fall through (no inventory cached → regex
    fallback handles the queries):
      * :mod:`core.inventory` not importable (packaging strip / minimal install)
      * tree-sitter grammars not installed (build still works but
        returns regex-extracted items; still better than our walker
        for split-type / pointer-return / multi-line cases)
      * ``build_inventory`` raises (permission errors, malformed
        files) — log at debug level, continue without inventory
    """
    try:
        from core.inventory import build_inventory
    except ImportError:
        return
    try:
        inv = build_inventory(str(target))
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "inventory build for %s failed (%s); "
            "_enclosing_function will use regex fallback",
            target, e,
        )
        return
    _register_inventory(target, inv)


def _lookup_cached_inventory(file_path: str) -> Tuple[Optional[Any], Optional[str]]:
    """Return ``(inventory, target_dir)`` for the deepest cached
    target containing ``file_path``, or ``(None, None)`` if no
    cached target is an ancestor.

    Deepest-match wins so nested ``analyze()`` calls on
    sub-projects route queries to the most specific inventory.

    Stale entries — whose stored signature no longer matches the
    target's on-disk state — are silently dropped during the walk
    and treated as a miss. This is the production invalidation
    path for cross-run reuse in a single process.
    """
    # Snapshot the keys + best entry inside the lock. Holding the
    # lock for the filesystem-walking signature compute would
    # serialise all concurrent lookups on disk I/O latency — the
    # walk runs unlocked, and a final lock-protected re-check
    # decides whether to pop or return.
    with _INVENTORY_LOCK:
        if not _INVENTORY_BY_TARGET:
            return None, None
        try:
            fp = Path(file_path).resolve()
        except (OSError, ValueError):
            return None, None
        best_target: Optional[str] = None
        best_depth = -1
        fp_str = str(fp)
        for target in _INVENTORY_BY_TARGET:
            # File is under target iff the resolved file path string
            # starts with target + os.sep (or equals target for
            # single-file targets — unusual but supported).
            if fp_str == target or fp_str.startswith(target + os.sep):
                depth = target.count(os.sep)
                if depth > best_depth:
                    best_target = target
                    best_depth = depth
        if best_target is None:
            return None, None
        stored_sig, inventory = _INVENTORY_BY_TARGET[best_target]

    # Validate freshness outside the lock — signature compute walks
    # the filesystem and would otherwise serialise concurrent
    # lookups for unrelated targets.
    from packages.source_intel.cache import compute_target_signature
    current_sig = compute_target_signature(Path(best_target))
    if stored_sig != current_sig:
        # Re-check under the lock that the entry we're popping is
        # the same one we read above. A concurrent register may
        # have refreshed it with a current signature in the gap.
        with _INVENTORY_LOCK:
            current_entry = _INVENTORY_BY_TARGET.get(best_target)
            if current_entry is not None and current_entry[0] == stored_sig:
                _INVENTORY_BY_TARGET.pop(best_target, None)
        return None, None
    return inventory, best_target


def _enclosing_function_via_inventory(
    file_path: str, line: int,
) -> Optional[str]:
    """Tree-sitter-backed enclosing-function lookup via the cached
    inventory built in :func:`analyze`. Returns ``None`` when no
    cached inventory covers ``file_path`` — caller falls back to
    the regex walker.
    """
    inv, target_dir = _lookup_cached_inventory(file_path)
    if inv is None:
        return None
    try:
        from core.inventory.reachability import enclosing_function as _inv_enc
    except ImportError:
        return None
    # Inventory keys files by the relative path from the target dir.
    try:
        rel = str(Path(file_path).resolve().relative_to(target_dir))
    except (ValueError, OSError):
        # File outside the cached target — shouldn't happen
        # (_lookup_cached_inventory checked containment) but bail
        # safely.
        return None
    try:
        result = _inv_enc(inv, rel, line)
    except Exception:  # noqa: BLE001
        return None
    return result.name if result is not None else None


def _enclosing_function(file_path: str, line: int) -> Optional[str]:
    """Find the C function definition enclosing ``line`` in ``file_path``.

    Resolution order:
      1. Tree-sitter inventory cache (preferred — real AST parse via
         :mod:`core.inventory.extractors`, populated by :func:`analyze`).
      2. Regex walker fallback (used when no inventory is cached for
         the file's target — e.g. corpus-runner fixtures, tests).

    The regex fallback is documented as best-effort and has historic
    edge cases (multi-line decls, pointer-return types, split type/name
    across lines, K&R decls). Inventory-backed resolution sidesteps
    every one of those because tree-sitter parses real C.

    Algorithm of the regex fallback (Phase B PR3 + post-E2E fixes):
      1. Walk backward from ``line``. Skip preprocessor lines,
         comment-only lines, and lines whose stripped form ends in
         ``;`` (declarations).
      2. For each candidate that looks like the START of a function
         opener (matches the loose ``_FUNC_DEF_PREFIX_RE`` —
         ``[typespecs] name(``), forward-join subsequent lines until
         the paren count balances. If the balanced statement then
         matches the full ``_FUNC_DEF_RE`` (``name(args)[{``) and the
         name isn't a C control keyword, return it.
      3. Multi-line definitions like
         ``static CURLcode do_sendmsg(\\n    struct Curl_cfilter *cf,\\n    ...)``
         are matched once paren balance is reached on a later line.

    NOT a full C parser — still misses (in fallback mode only):
    K&R-style decls, function-pointer typedefs that look like calls,
    split type+name across lines. Good enough for the kernel and
    curl-style ANSI C; ambiguous cases return ``None`` which the
    aggregator handles by leaving the abort un-attributed.
    """
    # 1. Tree-sitter via cached inventory (preferred).
    via_inv = _enclosing_function_via_inventory(file_path, line)
    if via_inv is not None:
        return via_inv
    # 2. Regex fallback (only path when no inventory is cached).
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
        stripped = candidate.lstrip()
        # Skip preprocessor lines and comment-only lines.
        if stripped.startswith(("#", "//", "/*", "*")):
            continue
        # Strip trailing comments before checking for `;` — a line
        # `memcpy(buf, src, n);  /* note */` has the `;` mid-string
        # but is NOT a function definition. Without this strip the
        # candidate `endswith(";")` check misses call sites.
        code_only = _strip_trailing_comments(candidate)
        # Lines ending in `;` are declarations or statements, never
        # function-definition openers. Skip outright.
        if code_only.endswith(";"):
            continue
        # Quick prefix test: does this line LOOK like the start of a
        # function opener (`[type...] name(`)? Cheap reject before
        # doing the multi-line paren-balance walk.
        if not _FUNC_DEF_PREFIX_RE.match(candidate):
            continue

        # Build the balanced statement by joining forward lines until
        # the open-paren count reaches zero. Bounded to 50 forward
        # lines so a pathological run-on doesn't burn time.
        joined, paren_terminator_line = _join_until_paren_balanced(
            lines, start=i, max_forward=50,
        )
        if joined is None:
            continue
        # After balancing, the statement must not be a declaration
        # (semicolon after the closing paren).
        joined_no_comments = _strip_trailing_comments(joined)
        # Find content after the matching close paren: must be either
        # empty / whitespace / `{` (definition body opener). A `;`
        # there means it's a function declaration / prototype, not a
        # definition — skip and keep walking back.
        m = _FUNC_DEF_RE.match(joined_no_comments)
        if not m:
            continue
        # Reject C keywords that look like function names —
        # `if (cond) { ... }` regex-matches as "function `if`".
        name = m.group(1)
        if name in _C_KEYWORDS:
            continue
        # Definitive: walker matched a function-definition opener at
        # or below ``line``. The body span isn't validated (the
        # walker doesn't know where the body ends without a real C
        # parser), so this still over-attributes when ``line`` is
        # actually below the body's close brace — caller knows this
        # is best-effort.
        return name
    return None


def _strip_trailing_comments(s: str) -> str:
    """Trim ``// …`` and ``/* … */`` trailing comments + whitespace."""
    s = re.sub(r"/\*.*$", "", s)
    s = re.sub(r"//.*$", "", s)
    return s.rstrip()


def _join_until_paren_balanced(
    lines: List[str], *, start: int, max_forward: int,
) -> Tuple[Optional[str], Optional[int]]:
    """Concatenate ``lines[start:]`` forward until the open-paren
    count reaches zero.

    Returns ``(joined_text, terminator_line_index)`` when balanced
    within ``max_forward`` lines; ``(None, None)`` otherwise. The
    joined text has newlines collapsed to single spaces AND inline
    block comments (``/* ... */`` complete on the line) stripped
    out so downstream regexes see a clean single-line statement.

    Paren counting is naive: literal parens in strings / chars are
    counted too. For function-definition openers (identifiers +
    types + ``(...)``) this is fine — the chance of a string
    literal inside a function prototype is near zero.
    """
    depth = 0
    pieces: List[str] = []
    for j in range(start, min(len(lines), start + max_forward)):
        text = lines[j].rstrip("\n")
        # Strip inline block comments AND line comments; this is the
        # text we both count parens on AND emit into the joined result
        # (so downstream comment-stripping doesn't run away on the
        # now-single-line joined text — see _strip_trailing_comments
        # which is line-anchored and assumes /* without */ on same
        # line means comment-to-EOF).
        text_clean = re.sub(r"/\*.*?\*/", "", text)
        text_clean = re.sub(r"//.*$", "", text_clean)
        pieces.append(text_clean)
        for ch in text_clean:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
        if depth <= 0 and j > start:
            return " ".join(p.strip() for p in pieces), j
        if depth <= 0 and j == start:
            # Balanced on the same line — caller's existing regex
            # would handle this; return for uniform treatment.
            return text_clean, j
    return None, None


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


def _scan_c_level_source_inputs(target: Path) -> List[CLevelSourceEvidence]:
    """Best-effort C/C++ L1 source table scanner.

    Coccinelle rules handle many structural axes, but L1 inputs include
    process-boundary shapes (``argv``/``envp``) and ubiquitous calls such
    as ``read`` that are deliberately omitted from import-based fuzz
    prioritisation. This bounded source scan records them as prompt
    context without changing verdict policy.
    """
    files: List[Path] = []
    if target.is_file() and target.suffix.lower() in _C_CPP_EXTS:
        files = [target]
    elif target.is_dir():
        for entry in sorted(target.rglob("*")):
            if len(files) >= 500:
                break
            if entry.is_file() and entry.suffix.lower() in _C_CPP_EXTS:
                files.append(entry)

    observations: List[CLevelSourceEvidence] = []
    seen: set[Tuple[str, int, str, str]] = set()
    for path in files:
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            continue
        in_block_comment = False
        for line_no, line in enumerate(lines, start=1):
            if _PREPROC_LINE_RE.match(line):
                continue
            stripped, in_block_comment = _strip_c_source_comments_and_literals(
                line, in_block_comment=in_block_comment,
            )
            if not stripped.strip():
                continue
            for name, kind in _C_L1_SOURCE_CALLS.items():
                if not _line_has_c_source_call(stripped, name):
                    continue
                key = (str(path), line_no, kind, name)
                if key in seen:
                    continue
                seen.add(key)
                observations.append(CLevelSourceEvidence(
                    source_kind=kind,
                    source_name=name,
                    location=(str(path), line_no),
                    enclosing_function=_enclosing_function(str(path), line_no),
                ))
            if _line_mentions_argv_source(stripped):
                key = (str(path), line_no, "argv", "argv")
                if key not in seen:
                    seen.add(key)
                    observations.append(CLevelSourceEvidence(
                        source_kind="argv",
                        source_name="argv",
                        location=(str(path), line_no),
                        enclosing_function=_enclosing_function(str(path), line_no),
                    ))
            if _line_mentions_env_source(stripped):
                key = (str(path), line_no, "env", "envp")
                if key not in seen:
                    seen.add(key)
                    observations.append(CLevelSourceEvidence(
                        source_kind="env",
                        source_name="envp",
                        location=(str(path), line_no),
                        enclosing_function=_enclosing_function(str(path), line_no),
                    ))
    return observations


def _strip_c_source_comments_and_literals(
    line: str, *, in_block_comment: bool = False,
) -> Tuple[str, bool]:
    """Remove C/C++ comments and string/char literals from one line.

    The C-level source pass is intentionally lightweight, but it should
    not record ``read(`` inside comments, diagnostics, or example strings.
    Keep non-literal code characters so word-boundary call/use regexes can
    still match the surrounding statement.
    """
    out: List[str] = []
    i = 0
    quote: Optional[str] = None
    while i < len(line):
        ch = line[i]
        nxt = line[i + 1] if i + 1 < len(line) else ""
        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                out.extend("  ")
                i += 2
            else:
                out.append(" ")
                i += 1
            continue
        if quote is not None:
            if ch == "\\":
                out.append(" ")
                if i + 1 < len(line):
                    out.append(" ")
                    i += 2
                else:
                    i += 1
                continue
            out.append(" ")
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch == "/" and nxt == "/":
            out.extend(" " * (len(line) - i))
            break
        if ch == "/" and nxt == "*":
            in_block_comment = True
            out.extend("  ")
            i += 2
            continue
        if ch in {'"', "'"}:
            quote = ch
            out.append(" ")
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out), in_block_comment


def _line_has_c_source_call(line: str, name: str) -> bool:
    if not re.search(r"\b" + re.escape(name) + r"\s*\(", line):
        return False
    # Function prototypes/declarations are not source observations.
    # This intentionally stays conservative: calls embedded in assignment
    # statements (``n = read(...)``) do not match this declaration shape.
    return not bool(
        re.match(
            r"^\s*(?:extern\s+|static\s+|inline\s+|"
            r"[A-Za-z_][\w_]*\s+)+[*\s]*"
            + re.escape(name)
            + r"\s*\([^;{}]*\)\s*;\s*$",
            line,
        )
    )


def _line_mentions_argv_source(line: str) -> bool:
    return bool(
        re.search(r"\bargv\s*(?:\[|,)", line)
        or re.search(r"\bchar\s*\*\s*argv\s*\[", line)
        or re.search(r"\bchar\s*\*\s*\*\s*argv\b", line)
    )


def _line_mentions_env_source(line: str) -> bool:
    return bool(
        re.search(r"\benvp\s*(?:\[|,)", line)
        or re.search(r"\benviron\s*\[", line)
        or re.search(r"\bchar\s*\*\s*envp\s*\[", line)
        or re.search(r"\bchar\s*\*\s*\*\s*envp\b", line)
    )


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
        file_lines = text.split("\n")
        for family, alias_name in alias_pairs:
            # Word-boundary check; substring would risk false positives
            # on prefix-overlap (FOO_CHECK vs MUST_CHECK).
            if not _is_word_present(text, alias_name):
                continue
            for n, line in enumerate(file_lines, start=1):
                if not _is_word_present(line, alias_name):
                    continue
                # Skip the alias's own #define line.
                # Skip ALL preprocessor lines — the alias appearing on
                # a #define / #if line is part of macro plumbing
                # (definition, conditional gating, or fallback empty
                # body), never a USE applying to a function.
                if _PREPROC_LINE_RE.match(line):
                    continue
                fn_name = _extract_function_name_near_alias(
                    file_lines, line_idx_one_based=n,
                    alias=alias_name,
                )
                observations.append(AttributeEvidence(
                    kind=family,
                    function_name=fn_name or "",
                    location=(str(entry), n),
                    match_source="project_alias",
                    raw_match=alias_name,
                ))
    return observations


def _is_word_present(text: str, word: str) -> bool:
    """Word-boundary substring check. Avoids false positives where
    one macro name is a prefix of another (e.g. ``CHECK`` matching in
    ``CHECK_RETURN``).

    Aliases that contain non-word characters (e.g.
    ``__attribute__((warn_unused_result))``) can't be safely
    bounded by ``\\b`` — both ends are non-word chars and
    ``\\b`` requires a word-on-one-side transition. For those,
    fall back to plain substring containment; prefix-overlap risk
    is negligible for any alias containing parens.
    """
    if not (word[:1].isalnum() or word[:1] == "_") or not (
        word[-1:].isalnum() or word[-1:] == "_"
    ):
        return word in text
    return bool(re.search(r"\b" + re.escape(word) + r"\b", text))


def _scan_alias_in_file(path: Path) -> List[AttributeEvidence]:
    """Best-effort: detect WUR alias spellings in a single C/H file.

    One observation per (file, alias_spelling, line) tuple — every
    occurrence of an alias spelling in the file emits one
    observation. We attempt best-effort function-name extraction
    from the local declaration context (see
    :func:`_extract_function_name_near_alias`); when the alias is
    on a macro #define line or otherwise not adjacent to a
    declaration, ``function_name`` stays empty (the consumer
    renders the file-level observation either way).
    """
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return []

    observations: List[AttributeEvidence] = []
    file_lines = text.split("\n")
    for spelling in ALL_WUR_ALIASES:
        if spelling not in text:
            continue
        # Every occurrence — multi-attribute headers carry many
        # decls; one-per-file would conflate them.
        for n, line in enumerate(file_lines, start=1):
            if not _is_word_present(line, spelling):
                continue
            # Skip the macro definition line itself (e.g.
            # `#define WARN_UNUSED_RESULT __attribute__(...)`).
            if _PREPROC_LINE_RE.match(line):
                continue
            fn_name = _extract_function_name_near_alias(
                file_lines, line_idx_one_based=n, alias=spelling,
            )
            observations.append(AttributeEvidence(
                kind=KIND_WUR,
                function_name=fn_name or "",
                location=(str(path), n),
                match_source="known_alias",
                raw_match=spelling,
            ))
    return observations


# Token-name extractor used when binding a WUR-alias / project-alias
# observation to its function. Looser than ``_FUNC_DEF_PREFIX_RE`` —
# we only need ``<name>(`` shape, not a typespec prefix, because the
# alias scan can land on the same line as the name without the type.
_FUNC_NAME_CALL_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\("
)


_PREPROC_LINE_RE = re.compile(r"^\s*#")

# Visibility / linkage / calling-convention decoration macros that
# real codebases sprinkle BEFORE the actual function name. Excluded
# from the alias-near function-name extractor — they look like
# function calls (`CURL_EXTERN`, `__declspec`) but aren't.
_DECORATION_PREFIXES: FrozenSet[str] = frozenset({
    "CURL_EXTERN", "ALLOC_FUNC",
    "__declspec", "__attribute__", "__cdecl", "__stdcall",
    "__fastcall", "__thiscall",
    "extern", "static", "inline", "_Noreturn",
})


def _extract_function_name_near_alias(
    file_lines: List[str],
    *,
    line_idx_one_based: int,
    alias: str,
) -> Optional[str]:
    """Best-effort: extract the function name a WUR alias applies to.

    Strategy: inspect a small window (1 line before, line itself,
    2 lines after) of the alias hit. Filter out:
      * Preprocessor lines (``#define`` / ``#if`` / ``#elif`` etc.)
        — these are macro plumbing, not function declarations.
      * Inline block comments and trailing line comments.
      * The alias spelling itself (so its internal ``(`` doesn't
        get mis-extracted as a function name).
      * The universal ``__attribute__((...))`` form.

    Then look for the first ``<name>(`` pattern; reject C keywords,
    preprocessor pseudo-functions (``defined``), and the alias
    family identifiers themselves.

    Returns the candidate function name or None when the window
    contains no recognisable declaration. None cases include:
      * alias on a #define line (declaration of the macro itself)
      * alias on a typedef / struct decl
      * alias inside a comment block
      * alias in a preprocessor conditional with no nearby decl
    """
    n = line_idx_one_based
    window_lo = max(0, n - 2)  # one line BEFORE (0-indexed)
    window_hi = min(len(file_lines), n + 2)  # two lines AFTER
    window = file_lines[window_lo:window_hi]
    # Drop preprocessor lines so #if defined(...) and #define lines
    # never feed the name regex.
    filtered = [
        ln for ln in window
        if not _PREPROC_LINE_RE.match(ln)
    ]
    joined = " ".join(filtered)
    cleaned = joined.replace(alias, " ")
    cleaned = re.sub(r"__attribute__\s*\(\([^)]*\)\)", " ", cleaned)
    cleaned = re.sub(r"/\*.*?\*/", " ", cleaned)
    cleaned = re.sub(r"//.*", " ", cleaned)

    # Collect ALL `<name>(` candidates first. We then prefer:
    #   1. The first non-decoration, non-uppercase-macro name.
    #   2. Failing that, the last candidate (best guess at the
    #      actual function name even if it looked macro-ish).
    candidates: List[str] = []
    for m in _FUNC_NAME_CALL_RE.finditer(cleaned):
        name = m.group(1)
        if name in _C_KEYWORDS:
            continue
        if name in ALL_WUR_ALIASES:
            continue
        candidates.append(name)
    if not candidates:
        return None
    for name in candidates:
        if name in _DECORATION_PREFIXES:
            continue
        # Reject all-uppercase identifiers — they're almost always
        # macros in real C code (`CURL_EXTERN`, `EXPORT_SYMBOL`,
        # `ALLOC_FUNC`). Real function names mix case. False negative:
        # legitimate all-caps statics like `MAIN` — rare enough to
        # tolerate. Keep names that start with a single uppercase
        # letter followed by lowercase (e.g. `Curl_…`).
        if name.isupper():
            continue
        return name
    # Fall back: every candidate looked macro-ish. Return the last —
    # in `MACRO MACRO void *real_name(...)` the real name is at the
    # end. Better than None for the consumer.
    return candidates[-1]


# =====================================================================
# Axis-4 multi-hop privilege back-walk — evidence-producing wrapper
# =====================================================================


# Privileged-capability constants shared with the verdict-side back-
# walk in :mod:`packages.source_intel.adapter`. Duplicated here (not
# imported) because adapter imports from analyze; importing back
# would create a cycle. Keep both lists in sync — see adapter.py's
# `_PRIVILEGED_CAP_CONSTANTS` for the canonical commentary.
_PRIVILEGED_CAP_CONSTANTS_FOR_EVIDENCE: FrozenSet[str] = frozenset({
    "CAP_SYS_ADMIN",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_BOOT",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
})

# Capability functions that grade the same way (cap_function set must
# match adapter.py's `_PRIVILEGED_CAP_FUNCTIONS`).
_PRIVILEGED_CAP_FUNCTIONS_FOR_EVIDENCE: FrozenSet[str] = frozenset({
    "capable",
})


def compute_privilege_back_walk_evidence(
    finding_function: str,
    target: Path,
    result: "SourceIntelResult",
    *,
    max_depth: int = 3,
) -> Optional["PrivilegeBackWalkEvidence"]:
    """Run the multi-hop privilege back-walk from ``finding_function``
    up through the inverted callgraph and return prose-renderable
    evidence (not just a boolean verdict signal).

    Returns ``None`` when:
      * PR-4 prereqs aren't available (``packages.coccinelle`` not
        importable, spatch missing) — caller falls back to "no
        back-walk evidence".
      * ``target`` isn't a directory.
      * The walk found no callers AND no privileged cap in the
        finding function itself (a true entry point: callers-axis
        inapplicable).

    Mirrors the verdict-side
    :func:`packages.source_intel.adapter._privilege_back_walk_suppresses`
    walk but produces concrete examples for the LLM prompt — gating
    sites the walk actually traversed, plus the first ungated path
    when one exists.
    """
    try:
        from packages.coccinelle.prereqs import gather_prereqs
    except ImportError:
        return None
    if not target.is_dir():
        return None
    try:
        facts = gather_prereqs(target)
    except Exception:  # noqa: BLE001
        return None
    if facts.is_skipped:
        return None

    callers = facts.callers_of(finding_function)
    if not callers:
        return PrivilegeBackWalkEvidence(
            finding_function=finding_function,
            all_paths_gated=False,
            no_callers=True,
        )

    effective_depth = max(1, min(max_depth, 5))
    visited = {finding_function}
    gating_examples: List[Tuple[str, str, str, int]] = []
    ungated_caller: Optional[str] = None
    all_gated = True

    for call_file, call_line in callers:
        caller_fn = _enclosing_function(call_file, call_line)
        if not caller_fn:
            all_gated = False
            ungated_caller = ungated_caller or "<unknown caller>"
            continue
        gated, examples = _path_is_gated_with_examples(
            caller_fn, facts, result,
            remaining_depth=effective_depth - 1,
            visited=visited,
        )
        if gated:
            gating_examples.extend(examples)
        else:
            all_gated = False
            ungated_caller = ungated_caller or caller_fn

    # Cap examples surfaced to the LLM at 3 — concrete enough to be
    # actionable, bounded enough not to crowd the prompt.
    capped_examples = tuple(gating_examples[:3])

    return PrivilegeBackWalkEvidence(
        finding_function=finding_function,
        all_paths_gated=all_gated,
        gating_examples=capped_examples,
        ungated_caller=ungated_caller if not all_gated else None,
        depth_used=effective_depth,
        no_callers=False,
    )


def _path_is_gated_with_examples(
    fn_name: str,
    facts: Any,
    result: "SourceIntelResult",
    *,
    remaining_depth: int,
    visited: set,
) -> Tuple[bool, List[Tuple[str, str, str, int]]]:
    """Recursive walker — same logic as adapter.py's
    ``_path_is_gated`` but additionally records the concrete gating
    sites along the way for prose evidence.

    Returns ``(gated, examples)`` where ``examples`` is a list of
    ``(gating_fn, cap_function, file_path, line)`` tuples for each
    privileged ``capable()`` call site discovered on a gated path.
    """
    if fn_name in visited:
        return False, []
    example = _function_privileged_cap_site(fn_name, result)
    if example is not None:
        return True, [example]
    if remaining_depth <= 0:
        return False, []
    callers = facts.callers_of(fn_name)
    if not callers:
        return False, []
    next_visited = visited | {fn_name}
    collected: List[Tuple[str, str, str, int]] = []
    for call_file, call_line in callers:
        caller_fn = _enclosing_function(call_file, call_line)
        if not caller_fn:
            return False, []
        sub_gated, sub_examples = _path_is_gated_with_examples(
            caller_fn, facts, result,
            remaining_depth=remaining_depth - 1,
            visited=next_visited,
        )
        if not sub_gated:
            return False, []
        collected.extend(sub_examples)
    return True, collected


def _function_privileged_cap_site(
    fn_name: str,
    result: "SourceIntelResult",
) -> Optional[Tuple[str, str, str, int]]:
    """If ``fn_name`` body contains a privileged ``capable(CAP_X)``
    call site, return ``(fn_name, cap_function, file_path, line)``
    for the first one found. Else ``None``.

    Reuses the line-level privileged-cap check from adapter (defined
    there to keep the canonical ``_PRIVILEGED_CAP_CONSTANTS`` list
    single-sourced) when importable; falls back to a local
    re-implementation otherwise.
    """
    try:
        from packages.source_intel.adapter import _line_uses_privileged_cap
    except ImportError:
        _line_uses_privileged_cap = _local_line_uses_privileged_cap  # noqa: F811
    for cap in result.capabilities:
        if cap.enclosing_function != fn_name:
            continue
        if cap.cap_function not in _PRIVILEGED_CAP_FUNCTIONS_FOR_EVIDENCE:
            continue
        cap_path, cap_line = cap.location
        if _line_uses_privileged_cap(cap_path, cap_line):
            return (fn_name, cap.cap_function, cap_path, cap_line)
    return None


def _local_line_uses_privileged_cap(file_path: str, line_no: int) -> bool:
    """Fallback used only when adapter.py isn't importable. Reads the
    line at ``file_path:line_no`` and checks for any privileged cap
    constant. Functionally equivalent to adapter's helper but
    duplicated here to break the import cycle in minimal installs."""
    try:
        with open(file_path, "r", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return False
    if line_no < 1 or line_no > len(lines):
        return False
    text = lines[line_no - 1]
    return any(const in text for const in _PRIVILEGED_CAP_CONSTANTS_FOR_EVIDENCE)
