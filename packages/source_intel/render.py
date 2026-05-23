"""Render :class:`SourceIntelResult` evidence into prompt-friendly
strings for Stage D / `/exploit` / `/agentic` consumers.

The output is a list of human-readable lines; ordering puts the
strongest signal first (literal observations before alias-only).
Consumers concatenate the lines into a structured block under
TaintedString / UntrustedBlock envelopes per the project's prompt-
envelope discipline.

Three styles surfaced in Phase 2:
  * ``stage_d`` — evidence supporting/against a Stage D ruling
  * ``exploit_plan`` — constraints to plan around for /exploit
  * ``agentic_variant`` — seed candidates for variant hunting

For substrate, all three render the same content with style-specific
phrasing. Axes 2-7 may diverge per style when their evidence
classes have distinct interpretations per consumer.

Also provides ``derive_mitigations_found()`` — structured list of
``Mitigation`` records per design strict invariant ("mitigations_found:
[...] shape; no boolean hardened. Absence ≠ unhardened.").
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from core.build.build_flags import BuildFlagsContext
from packages.source_intel.analyze import (
    GRADE_DOMINATES,
    GRADE_SAME_FUNCTION,
    GRADE_SAME_PATH,
    KIND_ACCESS,
    KIND_ALLOC_SIZE,
    KIND_MALLOC,
    KIND_NO_STACK_PROTECTOR,
    KIND_NONNULL,
    KIND_NORETURN,
    KIND_RETURNS_NONNULL,
    KIND_WUR,
    AbortEvidence,
    AllocationEvidence,
    AttributeEvidence,
    CapabilityEvidence,
    DoubleFreeEvidence,
    HazardEvidence,
    LsmEvidence,
    NullGuardEvidence,
    PairedFreeEvidence,
    PrivilegeBackWalkEvidence,
    SourceIntelResult,
)


@dataclass(frozen=True)
class Mitigation:
    """Structured mitigation entry per design strict invariant.

    ``name`` is the canonical mitigation kind (abort_dominates,
    fortify_blocks, etc.). ``axis`` is the source_intel axis id
    that detected it. ``confidence`` is one of:
        * ``"high"`` — strong evidence (DOMINATES grade, exact
          line match, FORTIFY blocks intercepted call site)
        * ``"medium"`` — moderate (same_path grade, near-line)
        * ``"low"`` — same_function grade with proximity,
          informational signals

    Absence of a mitigation in the list does NOT imply unhardened —
    it means source_intel didn't detect that mitigation (which may
    be a coverage gap, not real absence). Per the design strict
    invariant: never emit ``hardened: True/False``; only the
    structured-list shape.
    """

    name: str
    axis: str  # "axis_1" through "axis_8"
    confidence: str  # "low" | "medium" | "high"
    detail: str
    location: Optional[tuple] = None  # (file, line) or None


_STYLES = ("stage_d", "exploit_plan", "agentic_variant")


# Stage E binary-verdict values that supersede source_intel's
# EXPLOITABLE-leaning signal. Per design: "Binary observation
# supersedes source intent when both available (Stage E binary wins)."
# When the binary side says the bug can't reach exploitable runtime
# (RELRO blocks GOT overwrite, no usable ROP, sanitizer in production
# build, etc.), source_intel's structural evidence is reframed as
# informational rather than verdict-bearing.
#
# Verdicts from ``packages.exploit_feasibility.api:analyze_binary``:
#   "exploitable" | "likely_exploitable"  — binary agrees with EXPLOITABLE
#   "blocked"                              — binary says NO
#   "requires_environment"                 — binary says probably-NO
_BINARY_SUPERSEDING_VERDICTS = frozenset({
    "blocked",
    "requires_environment",
})


def _supersession_prefix(binary_verdict: Optional[str]) -> Optional[str]:
    """Return a one-line SUPERSEDED marker when the binary verdict
    overrides source_intel; ``None`` otherwise.

    Stage E semantics: binary observation always wins over source
    intent when both are available. This prefix tells the consumer
    LLM: "the following source_intel observations are factually
    correct, but the binary side already proved the path isn't
    exploitable — weigh them as context, not as exploitability
    evidence."
    """
    if binary_verdict is None:
        return None
    if binary_verdict not in _BINARY_SUPERSEDING_VERDICTS:
        return None
    return (
        f"SUPERSEDED: binary verdict `{binary_verdict}` from "
        f"packages.exploit_feasibility — the following source_intel "
        f"observations are STRUCTURALLY CORRECT but DO NOT change "
        f"exploitability. Binary side already proved the primitive "
        f"can't reach exploitable runtime. Treat the lines below as "
        f"context for the verdict explanation, not as evidence "
        f"for/against EXPLOITABLE."
    )


def derive_evidence_strings(
    result: SourceIntelResult,
    finding_function: Optional[str] = None,
    build_flags: Optional[BuildFlagsContext] = None,
    style: str = "stage_d",
    max_lines: Optional[int] = None,
    binary_verdict: Optional[str] = None,
    privilege_back_walk: Optional[PrivilegeBackWalkEvidence] = None,
) -> List[str]:
    """Render source_intel evidence for a finding into prompt lines.

    Args:
      result: the per-target SourceIntelResult
      finding_function: the function the finding cites (used to filter
        WUR evidence to relevant functions; when None, all observations
        surface)
      build_flags: per-target build-flag context (for compile-enforcement
        interpretation of WUR — `__must_check` is binding only if
        `-Werror=unused-result` was on)
      style: "stage_d" | "exploit_plan" | "agentic_variant" — chooses
        framing. Substrate ships identical content per style; axis-N
        PRs can diverge.
      max_lines: cap the number of returned lines (for context-tight
        prompt budgets); None = no cap.
      binary_verdict: optional Stage E binary-side verdict from
        :mod:`packages.exploit_feasibility`. Per design Stage E,
        the binary observation supersedes source intent when both
        are available. When this verdict is ``"blocked"`` or
        ``"requires_environment"`` (binary says NOT exploitable),
        the rendered output is prefixed with a SUPERSEDED marker
        and reframed as informational-only: the LLM should weigh
        the binary verdict over any source_intel EXPLOITABLE signal.
        ``None`` (default): no binary side; emit unchanged.

    Returns an empty list when the result is skipped or carries no
    relevant evidence — consumers can render "no source_intel signal"
    or omit the block entirely.
    """
    if style not in _STYLES:
        raise ValueError(f"unknown style: {style!r} (expected one of {_STYLES})")

    lines: List[str] = []

    if result.is_skipped:
        # Surface the skip reason so consumers know there was no
        # evidence at all — distinct from "evidence ran and found
        # nothing." This is critical: consumers MUST NOT interpret
        # an empty block as "unhardened".
        lines.append(
            f"Source_intel skipped: {result.skipped_reason}. "
            f"No evidence either way."
        )
        # Stage E supersession still applies even when source_intel
        # was skipped — the consumer needs to see the binary verdict
        # disposition regardless.
        prefix = _supersession_prefix(binary_verdict)
        if prefix is not None:
            lines = [prefix] + lines
        return _truncate(lines, max_lines)

    # Filter attributes to the finding's function when supplied.
    observations = list(result.attributes)
    if finding_function:
        observations = [
            ev for ev in observations
            if ev.function_name == finding_function
        ]
    # Literal observations first, then known-alias.
    observations.sort(key=lambda ev: 0 if ev.match_source == "literal" else 1)

    for ev in observations:
        line = _render_attribute_line(ev, build_flags, style)
        if line is not None:
            lines.append(line)

    # Abort evidence (axis 2). Filter to the finding's function when
    # supplied (same composition as attributes). Strongest grade
    # first so dominate-grade signal appears at the top.
    aborts = list(result.aborts)
    if finding_function:
        aborts = [
            ab for ab in aborts
            if ab.enclosing_function == finding_function
            or ab.enclosing_function is None
        ]
    _GRADE_ORDER = {
        GRADE_DOMINATES: 0,
        GRADE_SAME_PATH: 1,
        GRADE_SAME_FUNCTION: 2,
    }
    aborts.sort(key=lambda ab: _GRADE_ORDER.get(ab.grade, 99))
    for ab in aborts:
        lines.append(_render_abort_line(ab, style))

    # Allocation evidence (axis 3). Filter to the finding's function
    # when supplied. Phase 6a: only the field-assignment shape lands;
    # later shapes are added as axis-3-expansion ships.
    allocations = list(result.allocations)
    if finding_function:
        allocations = [
            ae for ae in allocations
            if ae.enclosing_function == finding_function
            or ae.enclosing_function is None
        ]
    for ae in allocations:
        lines.append(_render_allocation_line(ae, style))

    # Axis-7 hazard evidence (deprecated_func / signed_alloc / type
    # confusion / unsafe temp). Filter to finding's function when
    # supplied. Critical for memory-corruption CWEs — strcpy at a
    # CWE-120 sink line IS direct supporting evidence.
    hazards = list(result.hazards)
    if finding_function:
        hazards = [
            h for h in hazards
            if h.enclosing_function in (finding_function, None)
        ]
    for h in hazards:
        lines.append(_render_hazard_line(h, style))

    # Axis-3 paired-free evidence — INFORMATIONAL for memory-leak
    # findings. When an alloc IS paired with a free in-function the
    # leak claim is suspect (cocci can't prove all-paths-free, only
    # "some-path-free"). Filter to finding's function.
    paired_frees = list(result.paired_frees)
    if finding_function:
        paired_frees = [
            p for p in paired_frees
            if p.enclosing_function in (finding_function, None)
        ]
    for p in paired_frees:
        lines.append(_render_paired_free_line(p, style))

    # Axis-3 double-free evidence. Direct EXPLOITABLE-supporting
    # evidence for cpp/double-free findings. Filter to finding's
    # function.
    double_frees = list(result.double_frees)
    if finding_function:
        double_frees = [
            d for d in double_frees
            if d.enclosing_function in (finding_function, None)
        ]
    for d in double_frees:
        lines.append(_render_double_free_line(d, style))

    # Axis-4 capability evidence — privilege gating at sink. When
    # a capable(CAP_PRIV) check dominates the sink, the attacker
    # already holds that privilege; weighs the verdict accordingly.
    capabilities = list(result.capabilities)
    if finding_function:
        capabilities = [
            c for c in capabilities
            if c.enclosing_function in (finding_function, None)
        ]
    for c in capabilities:
        lines.append(_render_capability_line(c, style))

    # Axis-4 LSM hook evidence — Linux Security Module hooks gate
    # the sink path. Same severity caveat as capabilities.
    lsm_hooks = list(result.lsm_hooks)
    if finding_function:
        lsm_hooks = [
            hook for hook in lsm_hooks
            if hook.enclosing_function in (finding_function, None)
        ]
    for hook in lsm_hooks:
        lines.append(_render_lsm_line(hook, style))

    # Axis-4 multi-hop privilege back-walk evidence (Phase D follow-
    # up). Surfaces the back-walk's prose findings — the verdict-side
    # walk in adapter.py produces a boolean suppression decision; this
    # path produces concrete examples the LLM weighs (the privileged
    # gate(s) along the path, OR the ungated counter-example caller).
    if privilege_back_walk is not None:
        line = _render_privilege_back_walk_line(
            privilege_back_walk, style,
        )
        if line is not None:
            lines.append(line)

    # Axis-2 null-guard evidence — null check on pointer before
    # use. Lowers severity of cpp/null-dereference findings when
    # a guard dominates the sink line.
    null_guards = list(result.null_guards)
    if finding_function:
        null_guards = [
            ng for ng in null_guards
            if ng.enclosing_function in (finding_function, None)
        ]
    for ng in null_guards:
        lines.append(_render_null_guard_line(ng, style))

    # Axis-6 sanitizer context. Surfaced once per finding (target-wide,
    # not per-call-site) when build_flags carries observed sanitizers.
    # The LLM weighs this in two opposing directions per consumer:
    #   * Production-equivalent builds: a memory bug in code compiled
    #     with -fsanitize=address / KASAN is caught at the cost of a
    #     panic — bug becomes DoS, not RCE.
    #   * Test / CI builds with sanitizers: bug surface is wider than
    #     production, but the finding may be a sanitizer-only artefact.
    sanitizer_line = _render_sanitizers_line(build_flags, style)
    if sanitizer_line is not None:
        lines.append(sanitizer_line)

    # When source_intel ran but found nothing relevant — emit an
    # explicit "no signal" line so the consumer prompt template
    # carries the absence acknowledgement.
    if not lines:
        lines.append(
            "Source_intel ran; no attribute or proximity evidence for "
            f"{finding_function or '<finding function>'}. "
            f"Absence of evidence is NOT evidence of unhardened code."
        )

    # Stage E binary-supersedes (Phase C PR2). When the binary side
    # says NOT exploitable, prepend a SUPERSEDED marker reframing
    # everything below as informational. Always applies — even when
    # only the "no signal" line was emitted — so the consumer sees
    # the consistent "binary wins" disposition.
    prefix = _supersession_prefix(binary_verdict)
    if prefix is not None:
        lines = [prefix] + lines

    return _truncate(lines, max_lines)


def _render_allocation_line(ae: AllocationEvidence, style: str) -> str:
    """Render one unchecked-allocation observation."""
    fn_text = (
        f"function `{ae.enclosing_function}`"
        if ae.enclosing_function
        else f"in {ae.location[0]} near line {ae.location[1]}"
    )
    field_text = (
        f"field `->{ae.target_field}`"
        if ae.target_field
        else "the assigned location"
    )

    if style == "stage_d":
        prefix = "Allocator-result not checked"
    elif style == "exploit_plan":
        prefix = "Primitive — unchecked allocator result"
    else:
        prefix = "Variant hint — unchecked alloc shape"

    caveat = ""
    if ae.conditional_on:
        caveat = (
            f" (CONDITIONAL: gated by `#if* {ae.conditional_on}` — "
            f"downweight unless the actual build enables this.)"
        )

    return (
        f"{prefix}: `{ae.allocator}` at {ae.location[0]}:{ae.location[1]} "
        f"{fn_text} stores into {field_text} with NO subsequent NULL "
        f"check on that location. Allocation failure → NULL stored → "
        f"downstream deref crashes (CWE-476).{caveat}"
    )


def _render_hazard_line(h: HazardEvidence, style: str) -> str:
    """Render one axis-7 hazard observation."""
    fn_text = (
        f"function `{h.enclosing_function}`"
        if h.enclosing_function
        else f"in {h.location[0]} near line {h.location[1]}"
    )
    if style == "stage_d":
        prefix = "Hazardous call site — unsafe-by-design API"
    elif style == "exploit_plan":
        prefix = "Primitive — unsafe API at sink"
    else:
        prefix = "Variant hint — hazardous API"
    explainer = {
        "deprecated_func": (
            "doesn't carry its own bounds; caller must have "
            "established length safety. Direct supporting evidence "
            "for cpp/unbounded-write."
        ),
        "signed_alloc": (
            "signed multiplication into alloc size — classic "
            "CWE-190 → CWE-122 source. Supports an uncontrolled-"
            "allocation-size finding."
        ),
        "type_confusion_cast": (
            "casts between incompatible pointer types without "
            "validation — supports type-confusion variants of "
            "CWE-704."
        ),
        "unsafe_temp": (
            "predictable filename + race window between name and "
            "open — supports CWE-377 / CWE-379."
        ),
    }.get(h.kind, "")
    return (
        f"{prefix}: `{h.detail}` ({h.kind}) at "
        f"{h.location[0]}:{h.location[1]} {fn_text}. {explainer}"
    )


def _render_paired_free_line(p: PairedFreeEvidence, style: str) -> str:
    """Render one axis-3 paired-alloc/free observation."""
    fn_text = (
        f"function `{p.enclosing_function}`"
        if p.enclosing_function
        else f"in {p.location[0]} near line {p.location[1]}"
    )
    if style == "stage_d":
        prefix = "Memory-leak suspect signal — alloc paired with free"
    elif style == "exploit_plan":
        prefix = "Constraint — free pairing observed"
    else:
        prefix = "Variant hint — paired alloc/free"
    return (
        f"{prefix}: `{p.allocator}` at "
        f"{p.location[0]}:{p.location[1]} {fn_text} IS paired with a "
        f"`{p.free_fn}` call in the same function. Cocci can prove "
        f"\"some-path-free\", not \"all-paths-free\" — error paths "
        f"may still leak — but a cpp/memory-leak claim on this "
        f"alloc-site is suspect."
    )


def _render_double_free_line(d: DoubleFreeEvidence, style: str) -> str:
    """Render one axis-3 double-free observation."""
    fn_text = (
        f"function `{d.enclosing_function}`"
        if d.enclosing_function
        else f"in {d.location[0]} near line {d.location[1]}"
    )
    if style == "stage_d":
        prefix = "Primitive — double-free observed"
    elif style == "exploit_plan":
        prefix = "Primitive — double-free at sink"
    else:
        prefix = "Variant hint — double-free shape"
    return (
        f"{prefix}: `{d.free_fn}` called twice on the same expression "
        f"with no intervening reassignment to NULL or a new "
        f"allocation. First free at "
        f"{d.location[0]}:{d.location[1]} {fn_text}. Direct "
        f"supporting evidence for cpp/double-free (CWE-415)."
    )


# Constants the in-function capability render treats as "root-
# equivalent". Mirrors ``adapter.py:_PRIVILEGED_CAP_CONSTANTS`` and
# ``analyze.py:_PRIVILEGED_CAP_CONSTANTS_FOR_EVIDENCE``. Single
# source of truth for "which CAP_ kills the bug as a meaningful
# escalation" lives in adapter.py per Phase B PR3; copy is kept
# here to avoid an import cycle (render → adapter → render).
# Lifting to a shared constants module is a follow-up.
_PRIVILEGED_CAP_CONSTANTS_FOR_RENDER = frozenset({
    "CAP_SYS_ADMIN",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_BOOT",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
})

# Capability-check functions that test the GLOBAL/INIT user
# namespace's credentials. A True return means the caller holds
# that capability against the host root user — true privilege
# escalation if the bug is reachable.
#
# Functions NOT in this set are namespace-scoped (or otherwise
# weaker): `ns_capable(ns, CAP)` returns True for a userns admin
# holding CAP inside `ns`, even if the userns was created by an
# otherwise-unprivileged process. `has_capability_noaudit`,
# `ptracer_capable`, and similar variants gate against task or
# tracer creds — not always equivalent to global root.
#
# The render prose escalates "ROOT-EQUIVALENT, not a meaningful
# escalation" ONLY when both:
#   1. cap_function is in this set (gates against global creds), AND
#   2. cap constant is in ``_PRIVILEGED_CAP_CONSTANTS_FOR_RENDER``.
# For namespace-scoped checks gating root-equivalent caps we emit
# the userns-caveat prose instead — bug is still reachable via
# `unshare -U` from an unprivileged process.
_GLOBAL_CRED_CAP_FUNCTIONS = frozenset({
    "capable",
})

# Capability-check functions that gate against namespace-scoped
# credentials. Surfacing as a SEPARATE set (rather than
# "everything not in global") so future additions (perfmon_capable,
# bpf_capable) are explicit choices, not silent inclusions.
_NS_SCOPED_CAP_FUNCTIONS = frozenset({
    "ns_capable",
    "ns_capable_noaudit",
    "has_capability",
    "has_capability_noaudit",
    "capable_wrt_inode_uidgid",
    "file_ns_capable",
    "ptracer_capable",
    "checkpoint_restore_ns_capable",
})

_CAP_CONST_RE = re.compile(r"\bCAP_[A-Z_]+\b")


def _privileged_cap_constant_on_line(
    file_path: str, line_no: int,
) -> Optional[str]:
    """Return the first privileged CAP_ constant on the given line,
    or ``None`` when the line can't be read OR carries no privileged
    constant. Used by ``_render_capability_line`` to strengthen the
    prose when the check is root-equivalent.

    Mirrors the verdict-side ``adapter.py:_line_uses_privileged_cap``
    but returns the constant name rather than a boolean (so the
    render can include it in the prose)."""
    try:
        with open(file_path, "r", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return None
    if line_no < 1 or line_no > len(lines):
        return None
    for m in _CAP_CONST_RE.finditer(lines[line_no - 1]):
        if m.group(0) in _PRIVILEGED_CAP_CONSTANTS_FOR_RENDER:
            return m.group(0)
    return None


def _render_capability_line(c: CapabilityEvidence, style: str) -> str:
    """Render one axis-4 capability-check observation.

    Three prose tiers based on (cap_function, cap_constant, grade):

      1. Strongest ("ROOT-EQUIVALENT, finding is privilege-gated"):
         cap_function gates against GLOBAL credentials
         (``_GLOBAL_CRED_CAP_FUNCTIONS``: ``capable``) AND constant
         is root-equivalent (``_PRIVILEGED_CAP_CONSTANTS_FOR_RENDER``).
         Bug not reachable from unprivileged context.

      2. Userns-caveat ("namespace-scoped, root-equivalent CAP can
         be held by userns admin"): cap_function is namespace-scoped
         (``_NS_SCOPED_CAP_FUNCTIONS``: ``ns_capable`` and
         relatives) BUT constant is root-equivalent. An unprivileged
         user can ``unshare -U`` into a userns and hold the CAP
         there — bug IS reachable, just one userns hop away. LLM
         must NOT treat as privilege-gated.

      3. Generic ("Attacker must hold checked capability"): cap
         constant not in root-equivalent set OR cap_function
         unknown. Soft-signal prose; LLM weighs.

    The (cap_function, grade) gate matters: on ``same_path``
    grade, the cap may be on a branch the sink isn't on, so even
    a root-equivalent constant doesn't gate. Only ``dominates``
    and ``same_function`` qualify for the strong/userns tiers.
    """
    fn_text = (
        f"function `{c.enclosing_function}`"
        if c.enclosing_function
        else f"in {c.location[0]} near line {c.location[1]}"
    )
    grade_phrase = {
        GRADE_DOMINATES: "DOMINATES the function body (depth-1, no early exit precedes)",
        GRADE_SAME_PATH: "on a nested control-flow path (depth>1, inside if/loop/switch)",
        GRADE_SAME_FUNCTION: "shares the function with the sink",
    }.get(c.grade, c.grade)

    # Detect a privileged-equivalent constant on the source line.
    # Only meaningful when the grade actually guards the sink path.
    priv_cap: Optional[str] = None
    if c.grade in (GRADE_DOMINATES, GRADE_SAME_FUNCTION):
        priv_cap = _privileged_cap_constant_on_line(
            c.location[0], c.location[1],
        )

    if style == "stage_d":
        prefix = "Privilege gating — capability check near sink"
    elif style == "exploit_plan":
        prefix = "Constraint — capability required to reach sink"
    else:
        prefix = "Variant hint — capability check"

    # Tier 1: global-creds check + root-equivalent constant.
    if priv_cap is not None and c.cap_function in _GLOBAL_CRED_CAP_FUNCTIONS:
        return (
            f"{prefix}: `{c.cap_function}({priv_cap})` at "
            f"{c.location[0]}:{c.location[1]} {fn_text} — "
            f"{grade_phrase}. `{priv_cap}` is ROOT-EQUIVALENT "
            f"(grants kernel-level powers: arbitrary memory access, "
            f"module load, file DAC bypass — depending on the cap). "
            f"`{c.cap_function}()` gates against GLOBAL credentials. "
            f"Attacker must already hold this capability against the "
            f"host root user to reach the sink; the bug is NOT a "
            f"meaningful privilege escalation. Finding is effectively "
            f"privilege-gated."
        )

    # Tier 2: namespace-scoped check + root-equivalent constant.
    # The cap CAN be held by a userns admin without global root,
    # so the bug is reachable via `unshare -U`.
    if priv_cap is not None and c.cap_function in _NS_SCOPED_CAP_FUNCTIONS:
        return (
            f"{prefix}: `{c.cap_function}(..., {priv_cap})` at "
            f"{c.location[0]}:{c.location[1]} {fn_text} — "
            f"{grade_phrase}. `{priv_cap}` is root-equivalent ONLY "
            f"against the init user namespace; `{c.cap_function}()` "
            f"is NAMESPACE-SCOPED — a userns admin (created via "
            f"`unshare -U` from an otherwise-unprivileged process) "
            f"holds the cap inside their own ns. The bug IS "
            f"reachable from unprivileged context; do NOT treat as "
            f"privilege-gated. Mitigates only against pure-no-cap "
            f"local attackers without userns availability."
        )

    # Tier 3: generic prose — unknown function family OR non-
    # root-equivalent constant.
    return (
        f"{prefix}: `{c.cap_function}(...)` at "
        f"{c.location[0]}:{c.location[1]} {fn_text} — {grade_phrase}. "
        f"Attacker must already hold the checked capability before "
        f"the sink is reachable; for root-equivalent caps the bug "
        f"may not be a meaningful escalation."
    )


def _render_privilege_back_walk_line(
    bw: PrivilegeBackWalkEvidence, style: str,
) -> Optional[str]:
    """Render the axis-4 multi-hop privilege back-walk result as one
    prose line. Three cases:

      * no_callers — finding function is a top-level entry; the
        back-walk is inapplicable. Return None (nothing to say).
      * all_paths_gated — concrete privileged-gate examples from
        the walk. Strongest signal: bug is only reachable from
        already-privileged callers.
      * partial — some paths gated, but an ungated counter-example
        exists. Surfaces the counter-example so the LLM can weigh
        it (don't claim full gating when one ungated path remains).
    """
    if bw.no_callers:
        return None
    if style == "stage_d":
        prefix = "Privilege gating — multi-hop back-walk"
    elif style == "exploit_plan":
        prefix = "Constraint — bug only reachable via privileged callers"
    else:
        prefix = "Variant hint — privilege back-walk"

    if bw.all_paths_gated and bw.gating_examples:
        # Render the FIRST gating example; mention if there are more.
        first = bw.gating_examples[0]
        gating_fn, cap_fn, fp, ln = first
        extra = ""
        if len(bw.gating_examples) > 1:
            extra = (
                f" (and {len(bw.gating_examples) - 1} more gating "
                f"site(s) along other call paths within depth "
                f"{bw.depth_used})"
            )
        return (
            f"{prefix}: function `{bw.finding_function}` is reachable "
            f"ONLY via callers that pass through a privileged "
            f"`{cap_fn}(CAP_...)` check (e.g. `{gating_fn}` at "
            f"{fp}:{ln}){extra}. Attacker without the required "
            f"capability cannot trigger the bug; finding is "
            f"privilege-gated and is not a meaningful escalation "
            f"for already-privileged code."
        )
    if bw.all_paths_gated:
        # Gated but no examples surfaced (shouldn't normally happen
        # but handle defensively).
        return (
            f"{prefix}: all paths to function `{bw.finding_function}` "
            f"(within depth {bw.depth_used}) pass through a "
            f"privileged capability check. Finding is privilege-gated."
        )
    # Partial gating: ungated path exists.
    ungated = bw.ungated_caller or "<unknown caller>"
    if bw.gating_examples:
        gating_fn = bw.gating_examples[0][0]
        gated_note = (
            f" Some paths ARE gated (e.g. via `{gating_fn}`) — "
            f"but at least one unprivileged path remains."
        )
    else:
        gated_note = ""
    return (
        f"{prefix} (partial): function `{bw.finding_function}` is "
        f"reachable via at least one ungated caller `{ungated}` "
        f"within depth {bw.depth_used}.{gated_note} The bug "
        f"remains reachable from unprivileged context — do not "
        f"discount the finding on privilege grounds."
    )


def _render_lsm_line(hook: LsmEvidence, style: str) -> str:
    """Render one axis-4 LSM hook observation."""
    fn_text = (
        f"function `{hook.enclosing_function}`"
        if hook.enclosing_function
        else f"in {hook.location[0]} near line {hook.location[1]}"
    )
    if style == "stage_d":
        prefix = "Privilege gating — LSM hook near sink"
    elif style == "exploit_plan":
        prefix = "Constraint — LSM hook on path to sink"
    else:
        prefix = "Variant hint — LSM hook"
    return (
        f"{prefix}: `{hook.hook_name}` at "
        f"{hook.location[0]}:{hook.location[1]} {fn_text}. Linux Security "
        f"Module checks the operation; deployments with active LSM "
        f"(SELinux/AppArmor/Smack) may block exploitation even when "
        f"the C-level bug exists."
    )


def _render_null_guard_line(ng: NullGuardEvidence, style: str) -> str:
    """Render one axis-2 null-guard observation."""
    fn_text = (
        f"function `{ng.enclosing_function}`"
        if ng.enclosing_function
        else f"in {ng.location[0]} near line {ng.location[1]}"
    )
    if style == "stage_d":
        prefix = "Defensive check — null guard observed"
    elif style == "exploit_plan":
        prefix = "Constraint — null check precedes sink"
    else:
        prefix = "Variant hint — null guard"
    kind_phrase = {
        "bang": "`if (!e)`",
        "eq_null": "`if (e == NULL)`",
        "is_err": "`IS_ERR(e)` / `IS_ERR_OR_NULL(e)`",
    }.get(ng.kind, ng.kind)
    return (
        f"{prefix}: {kind_phrase}-shape null check at "
        f"{ng.location[0]}:{ng.location[1]} {fn_text}. Reduces "
        f"likelihood of cpp/null-dereference reaching runtime — "
        f"but doesn't prove ALL null paths are guarded (cocci "
        f"only sees the matched site)."
    )


def _render_abort_line(ab: AbortEvidence, style: str) -> str:
    """Render one abort-evidence observation."""
    fn_text = (
        f"function `{ab.enclosing_function}`"
        if ab.enclosing_function
        else f"in {ab.location[0]} near line {ab.location[1]}"
    )
    grade_phrase = {
        GRADE_DOMINATES: "DOMINATES the function body (depth-1, no early exit precedes)",
        GRADE_SAME_PATH: "appears on a nested control-flow path (depth>1, inside if/loop/switch)",
        GRADE_SAME_FUNCTION: "shares the function with the sink",
    }.get(ab.grade, ab.grade)

    if style == "stage_d":
        prefix = "Control-flow signal — abort-class call near sink"
    elif style == "exploit_plan":
        prefix = "DoS-only constraint — abort proximate to sink"
    else:
        prefix = "Variant hint — abort proximity"

    caveat = ""
    if ab.conditional_on:
        caveat = (
            f" (CONDITIONAL: gated by `#if* {ab.conditional_on}` — "
            f"downweight unless the actual build enables this.)"
        )
    if ab.grade == GRADE_SAME_PATH:
        # Phase C PR1: explicit weaker-than-dominates caveat.
        # `same_path` means the abort sits inside a nested branch
        # (depth>1) — execution that enters that branch DOES hit the
        # abort, but other branches in the function bypass it. This
        # is mid-strength evidence, NOT a guarantee like `dominates`.
        caveat += (
            " Grade `same_path` is mid-strength: the abort sits on "
            "SOME control-flow path through the function but other "
            "branches (else / loop fall-through / different switch "
            "arms) bypass it. The bug primitive may reach runtime via "
            "an unguarded branch. Stronger grade `dominates` (depth-1, "
            "no early exit) would be needed to prove DoS-only outcome."
        )
    if ab.grade == GRADE_SAME_FUNCTION:
        caveat += (
            " Grade `same_function` is weak: the abort may be on an "
            "unrelated path within the function. Stronger grades "
            "(`same_path`, `dominates`) require axis-2-expansion."
        )
    return (
        f"{prefix}: `{ab.macro}` call at {ab.location[0]}:{ab.location[1]} "
        f"{fn_text} — {grade_phrase}. If this abort is reached before "
        f"the bug primitive, the program halts and the bug becomes "
        f"DoS-only.{caveat}"
    )


def _render_attribute_line(
    ev: AttributeEvidence,
    build_flags: Optional[BuildFlagsContext],
    style: str,
) -> Optional[str]:
    """Dispatch to the per-kind renderer. Unknown kinds return None
    (silently dropped — render is best-effort).

    When ``conditional_on`` is set, the rendered line is suffixed with
    a caveat: matches under unknown ``#ifdef`` blocks may not apply
    to the binary that was actually built.
    """
    if ev.kind == KIND_WUR:
        line = _render_wur_line(ev, build_flags, style)
    elif ev.kind == KIND_NONNULL:
        line = _render_nonnull_line(ev, build_flags, style)
    elif ev.kind == KIND_ALLOC_SIZE:
        line = _render_alloc_size_line(ev, build_flags, style)
    elif ev.kind == KIND_RETURNS_NONNULL:
        line = _render_returns_nonnull_line(ev, build_flags, style)
    elif ev.kind == KIND_NORETURN:
        line = _render_noreturn_line(ev, build_flags, style)
    elif ev.kind == KIND_MALLOC:
        line = _render_malloc_line(ev, build_flags, style)
    elif ev.kind == KIND_NO_STACK_PROTECTOR:
        line = _render_no_stack_protector_line(ev, build_flags, style)
    elif ev.kind == KIND_ACCESS:
        line = _render_access_line(ev, build_flags, style)
    else:
        return None
    return _append_conditional_caveat(line, ev)


def _append_conditional_caveat(
    line: str,
    ev: AttributeEvidence,
) -> str:
    """Append the ``conditional_on`` caveat when the match is under
    an ``#if*`` block. Caller-side ``derive_evidence_strings`` consumes
    the suffix as part of the single evidence string."""
    if not ev.conditional_on:
        return line
    return (
        f"{line} (CONDITIONAL: this annotation is gated by "
        f"`#if* {ev.conditional_on}` — downweight unless the actual "
        f"build is known to enable this config.)"
    )


# =====================================================================
# Per-evidence-kind line builders
# =====================================================================


def _render_wur_line(
    ev: AttributeEvidence,
    build_flags: Optional[BuildFlagsContext],
    style: str,
) -> str:
    """One line of WUR evidence, framed per consumer style.

    The enforcement-status caveat depends on build flags:
      * `-Werror=unused-result` known True → "compile-enforced"
      * `-Werror=unused-result` known False → "author intent only;
        warning was suppressed"
      * None / build_flags absent → "advisory; enforcement depends
        on build flags not in evidence"
    """
    fn_text = (
        f"function `{ev.function_name}`"
        if ev.function_name
        else f"function in {ev.location[0]} at line {ev.location[1]}"
    )
    src_text = (
        "literal __attribute__((warn_unused_result))"
        if ev.match_source == "literal"
        else f"known alias `{ev.raw_match}`"
    )

    enforcement = _enforcement_phrase(build_flags)

    if style == "stage_d":
        prefix = "Author intent — must-check contract"
    elif style == "exploit_plan":
        prefix = "Constraint — caller-must-check contract"
    else:  # agentic_variant
        prefix = "Variant hint — must-check signal"

    return (
        f"{prefix}: {fn_text} annotated as warn_unused_result via "
        f"{src_text}. {enforcement}"
    )


def _render_nonnull_line(
    ev: AttributeEvidence,
    build_flags: Optional[BuildFlagsContext],
    style: str,
) -> str:
    """Render nonnull evidence.

    Nonnull is a TWO-EDGED signal for memory corruption:
      * Author intent — caller MUST pass non-null pointers.
      * Compiler behaviour — when -O2+ AND -fdelete-null-pointer-checks
        is ON (GCC userspace default), the compiler may eliminate
        redundant null-checks inside the annotated function. A real
        NULL reaching the function then dereferences without the
        defensive branch the author may have written.
      * In the kernel, -fno-delete-null-pointer-checks is in CFLAGS
        since 4.9, so the elimination doesn't happen — defensive null
        checks are preserved.

    The Stage D consumer reads this evidence WITH the build-flag
    context to determine effective semantics.
    """
    fn_text = (
        f"function `{ev.function_name}`"
        if ev.function_name
        else f"function in {ev.location[0]} at line {ev.location[1]}"
    )

    null_check_phrase = _nonnull_null_check_phrase(build_flags)

    if style == "stage_d":
        prefix = "Author intent + compiler signal — nonnull"
    elif style == "exploit_plan":
        prefix = "Constraint — caller-must-be-non-null contract"
    else:
        prefix = "Variant hint — nonnull annotation"

    return (
        f"{prefix}: {fn_text} annotated nonnull (caller must pass "
        f"non-null). {null_check_phrase}"
    )


def _nonnull_null_check_phrase(build_flags: Optional[BuildFlagsContext]) -> str:
    """Compose the dead-code-elimination caveat for nonnull."""
    if build_flags is None or build_flags.extraction_confidence == "absent":
        return (
            "Compiler-elimination status unknown (build flags not in "
            "evidence); a NULL reaching this function may be more or "
            "less exploitable depending on -fdelete-null-pointer-checks."
        )
    if build_flags.delete_null_pointer_checks is False:
        return (
            "Build flags include -fno-delete-null-pointer-checks — "
            "defensive null checks inside the function are preserved; "
            "any NULL dereference behaves as the source code shows."
        )
    if build_flags.delete_null_pointer_checks is True:
        return (
            "Build flags explicitly enable -fdelete-null-pointer-checks "
            "— compiler may dead-code-eliminate redundant null checks "
            "inside the function; a real NULL would reach the deref."
        )
    return (
        "Compiler-elimination status not pinned by observed flags — "
        "default depends on -O level and compiler version."
    )


def _render_alloc_size_line(
    ev: AttributeEvidence,
    build_flags: Optional[BuildFlagsContext],
    style: str,
) -> str:
    """Render alloc_size evidence.

    The annotation tells the compiler the return buffer's byte size.
    When FORTIFY_SOURCE is on, this unlocks __builtin_object_size and
    fortified intrinsics (memcpy_chk etc.) — operations on the return
    value get bounds-checked at runtime. Without FORTIFY_SOURCE, the
    annotation is mostly hint-for-analyzers.
    """
    fn_text = (
        f"function `{ev.function_name}`"
        if ev.function_name
        else f"function in {ev.location[0]} at line {ev.location[1]}"
    )

    fortify_phrase = _alloc_size_fortify_phrase(build_flags)

    if style == "stage_d":
        prefix = "Author intent + compiler signal — alloc_size"
    elif style == "exploit_plan":
        prefix = "Constraint — alloc_size advertises returned buffer size"
    else:
        prefix = "Variant hint — alloc_size annotation"

    return (
        f"{prefix}: {fn_text} returns a buffer whose byte size equals "
        f"the value of the annotated parameter(s). {fortify_phrase}"
    )


def _alloc_size_fortify_phrase(build_flags: Optional[BuildFlagsContext]) -> str:
    if build_flags is None or build_flags.extraction_confidence == "absent":
        return (
            "FORTIFY_SOURCE status unknown (build flags not in evidence); "
            "any runtime bounds-checking on the returned buffer depends "
            "on _FORTIFY_SOURCE level at compile time."
        )
    level = build_flags.fortify_source_level
    if level is None:
        return (
            "FORTIFY_SOURCE not set in observed flags; the alloc_size "
            "annotation gives the static-analyzer hint but no runtime "
            "bounds-check on the buffer."
        )
    if level >= 2:
        return (
            f"FORTIFY_SOURCE=_{level}_ — fortified intrinsics will "
            f"bounds-check operations against the returned buffer at "
            f"runtime; some overflows in the caller would be caught."
        )
    if level == 1:
        return (
            "FORTIFY_SOURCE=1 — limited runtime bounds-checking active; "
            "caller-side memcpy_chk catches overflows when the source "
            "length is also known statically."
        )
    return (
        "_FORTIFY_SOURCE=0 (explicitly disabled); annotation is "
        "static-analyzer-only, no runtime protection."
    )


def _render_returns_nonnull_line(
    ev: AttributeEvidence,
    build_flags: Optional[BuildFlagsContext],
    style: str,
) -> str:
    """Render returns_nonnull evidence.

    Author promises the function never returns NULL. Callers may
    legitimately skip null checks. If the annotation is wrong AND
    -fdelete-null-pointer-checks is enabled (gcc userspace default),
    the compiler may also dead-code-eliminate any defensive null
    checks the caller DID write — making a wrong annotation actively
    dangerous.
    """
    fn_text = (
        f"function `{ev.function_name}`"
        if ev.function_name
        else f"function in {ev.location[0]} at line {ev.location[1]}"
    )

    caveat = _returns_nonnull_caveat_phrase(build_flags)

    if style == "stage_d":
        prefix = "Author claim — returns_nonnull"
    elif style == "exploit_plan":
        prefix = "Constraint — caller may skip null check on return"
    else:
        prefix = "Variant hint — returns_nonnull annotation"

    return (
        f"{prefix}: {fn_text} promises never to return NULL. {caveat}"
    )


def _returns_nonnull_caveat_phrase(
    build_flags: Optional[BuildFlagsContext],
) -> str:
    if build_flags is None or build_flags.extraction_confidence == "absent":
        return (
            "Compiler-elimination status unknown (build flags not in "
            "evidence); if the annotation is wrong, a returned NULL "
            "may bypass defensive caller checks depending on "
            "-fdelete-null-pointer-checks."
        )
    if build_flags.delete_null_pointer_checks is False:
        return (
            "Build flags include -fno-delete-null-pointer-checks — "
            "defensive null checks in the caller are preserved even if "
            "the annotation is incorrect."
        )
    if build_flags.delete_null_pointer_checks is True:
        return (
            "Build flags enable -fdelete-null-pointer-checks — if the "
            "annotation is wrong, compiler may eliminate caller-side "
            "null checks, making a returned NULL a real deref."
        )
    return (
        "Compiler-elimination status not pinned by observed flags — "
        "default depends on -O level and compiler version."
    )


def _render_noreturn_line(
    ev: AttributeEvidence,
    build_flags: Optional[BuildFlagsContext],
    style: str,
) -> str:
    """Render noreturn evidence.

    Marks the function as a guaranteed abort (panic, _Exit, BUG-style).
    Strong DoS-vs-RCE discriminator: if the abort sits on the path
    between source and bug primitive, exploitation collapses to DoS.
    """
    fn_text = (
        f"function `{ev.function_name}`"
        if ev.function_name
        else f"function in {ev.location[0]} at line {ev.location[1]}"
    )

    if style == "stage_d":
        prefix = "Control-flow signal — noreturn"
    elif style == "exploit_plan":
        prefix = "DoS-only constraint — noreturn function"
    else:
        prefix = "Variant hint — noreturn annotation"

    return (
        f"{prefix}: {fn_text} is declared noreturn. If this function "
        f"is invoked on the path between source and the bug primitive, "
        f"the program aborts before exploitation; the bug becomes DoS-only."
    )


def _render_malloc_line(
    ev: AttributeEvidence,
    build_flags: Optional[BuildFlagsContext],
    style: str,
) -> str:
    """Render malloc evidence.

    The annotation declares the function as an allocator — returned
    pointer is fresh and unaliased. The gcc 11+ paramised form
    `malloc(free_fn[, n])` pairs the allocator with its deallocator.
    Source_intel records the annotation; combined with alloc_size,
    the LLM can recognise allocator semantics even when the function
    name doesn't say "malloc".
    """
    fn_text = (
        f"function `{ev.function_name}`"
        if ev.function_name
        else f"function in {ev.location[0]} at line {ev.location[1]}"
    )

    if style == "stage_d":
        prefix = "Allocator signal — malloc"
    elif style == "exploit_plan":
        prefix = "Constraint — function declared as allocator"
    else:
        prefix = "Variant hint — malloc annotation"

    return (
        f"{prefix}: {fn_text} declared as an allocator — returned "
        f"pointer is fresh and unaliased per the annotation. May be "
        f"paired with a deallocator on gcc 11+ (`malloc(free_fn)`)."
    )


def _render_no_stack_protector_line(
    ev: AttributeEvidence,
    build_flags: Optional[BuildFlagsContext],
    style: str,
) -> str:
    """Render no_stack_protector evidence.

    This is an explicit HARDENING HOLE — the function opts out of the
    stack-canary insertion that -fstack-protector* would normally add.
    A stack buffer overflow in such a function bypasses the canary
    check entirely.
    """
    fn_text = (
        f"function `{ev.function_name}`"
        if ev.function_name
        else f"function in {ev.location[0]} at line {ev.location[1]}"
    )

    sp_phrase = _stack_protector_phrase(build_flags)

    if style == "stage_d":
        prefix = "Hardening hole — no_stack_protector"
    elif style == "exploit_plan":
        prefix = "Constraint relaxed — no canary on this function"
    else:
        prefix = "Variant hint — no_stack_protector annotation"

    return (
        f"{prefix}: {fn_text} explicitly OPTS OUT of -fstack-protector. "
        f"A stack buffer overflow in this function bypasses the canary "
        f"check; saved return address reaches via overflow without "
        f"defence. {sp_phrase}"
    )


def _stack_protector_phrase(build_flags: Optional[BuildFlagsContext]) -> str:
    """Phrase describing what the build-wide stack protector level is —
    the no_stack_protector attribute matters most when the build was
    otherwise enabling canary insertion."""
    if build_flags is None or build_flags.extraction_confidence == "absent":
        return (
            "Build-wide stack-protector level unknown; the opt-out "
            "matters most when the rest of the binary was canary-"
            "protected."
        )
    level = build_flags.stack_protector_level
    if level in ("strong", "all"):
        return (
            f"Build flags include -fstack-protector-{level} — most of "
            f"the binary has canary protection that this function "
            f"explicitly disables."
        )
    if level == "weak":
        return (
            "Build flags include -fstack-protector (weak); the opt-out "
            "matters for functions that would have qualified for "
            "canary insertion."
        )
    if level == "none":
        return (
            "Build-wide stack-protector is disabled (-fno-stack-protector); "
            "this function's opt-out is redundant — canary wasn't "
            "present anyway."
        )
    return (
        "Build-wide stack-protector status not pinned by observed flags."
    )


def _render_access_line(
    ev: AttributeEvidence,
    build_flags: Optional[BuildFlagsContext],
    style: str,
) -> str:
    """Render access evidence.

    Declares which pointer parameters are read-only / write-only /
    read-write, and optionally ties access width to another parameter.
    Combined with FORTIFY_SOURCE, this unlocks runtime bounds-checking
    on the annotated parameters.
    """
    fn_text = (
        f"function `{ev.function_name}`"
        if ev.function_name
        else f"function in {ev.location[0]} at line {ev.location[1]}"
    )

    fortify_phrase = _access_fortify_phrase(build_flags)

    if style == "stage_d":
        prefix = "Author intent + compiler signal — access"
    elif style == "exploit_plan":
        prefix = "Constraint — declared parameter access pattern"
    else:
        prefix = "Variant hint — access annotation"

    return (
        f"{prefix}: {fn_text} declares parameter access pattern "
        f"(read_only / write_only / read_write, possibly tied to a size "
        f"parameter). {fortify_phrase}"
    )


def _access_fortify_phrase(build_flags: Optional[BuildFlagsContext]) -> str:
    """Same FORTIFY_SOURCE caveat shape as alloc_size — annotations
    unlock runtime checks when fortified intrinsics are active."""
    if build_flags is None or build_flags.extraction_confidence == "absent":
        return (
            "FORTIFY_SOURCE status unknown; whether the declared access "
            "pattern triggers runtime bounds-checking depends on the "
            "compile-time _FORTIFY_SOURCE level."
        )
    level = build_flags.fortify_source_level
    if level is None:
        return (
            "FORTIFY_SOURCE not set in observed flags; access annotation "
            "is static-analyzer-only, no runtime bounds-check enforcement."
        )
    if level >= 2:
        return (
            f"FORTIFY_SOURCE={level} — runtime bounds-checking active "
            f"on the annotated parameters; caller overflows would be "
            f"caught."
        )
    if level == 1:
        return (
            "FORTIFY_SOURCE=1 — limited runtime bounds-checking active."
        )
    return (
        "_FORTIFY_SOURCE=0 — annotation is static-analyzer-only."
    )


def _enforcement_phrase(build_flags: Optional[BuildFlagsContext]) -> str:
    """Compose the compile-enforcement caveat from build flag context."""
    if build_flags is None or build_flags.extraction_confidence == "absent":
        return (
            "Compile-enforcement status unknown (build flags not in "
            "evidence); advisory only."
        )
    if build_flags.werror_unused_result is True:
        return (
            "Build flags include -Werror=unused-result — "
            "compile-enforced; callers that ignore the return "
            "would not compile."
        )
    if build_flags.werror_unused_result is False:
        return (
            "Build flags include -Wno-error=unused-result — "
            "warning suppressed; advisory only."
        )
    return (
        "Build flags observed but -Werror=unused-result not set; "
        "advisory unless -Werror is added."
    )


# =====================================================================
# Axis 6 — sanitizer build context
# =====================================================================


# Sanitizer names worth surfacing in evidence — both userspace
# (-fsanitize=X) and kernel-config-derived. Restricted to those that
# materially change exploitability reasoning for memory-corruption
# CWEs. We deliberately drop sanitizers that only affect undefined-
# behaviour (UBSAN) for non-memory CWEs, because the prose framing
# below is memory-specific.
_RELEVANT_SANITIZERS = frozenset({
    "address",       # -fsanitize=address (userspace ASan)
    "kasan",         # CONFIG_KASAN (kernel ASan)
    "kfence",        # CONFIG_KFENCE
    "hwaddress",     # -fsanitize=hwaddress (HW-tag ASan)
    "memory",        # -fsanitize=memory (MSan — uninit reads)
    "thread",        # -fsanitize=thread (TSan — races)
    "undefined",     # -fsanitize=undefined (UBSan — int overflows etc.)
    "ubsan",         # CONFIG_UBSAN
    "kcsan",         # CONFIG_KCSAN
    "kcov",          # CONFIG_KCOV (not a sanitizer per se but the
                     # fuzzer-coverage runtime that often pairs with KASAN)
})


def _render_sanitizers_line(
    build_flags: Optional[BuildFlagsContext],
    style: str,
) -> Optional[str]:
    """Render a single line summarising active sanitizers when any
    are present in ``build_flags``. Returns None when:
      * build_flags is None,
      * extraction_confidence == "absent",
      * sanitizers_enabled is empty,
      * no enabled sanitizer is in ``_RELEVANT_SANITIZERS``.

    The line is target-wide, not per-call-site — sanitizers are a
    build-wide property. Consumer prompt may dedup if multiple
    evidence blocks for the same target are rendered together; in
    practice each finding gets its own evidence block, so one line
    per finding is correct.
    """
    if build_flags is None:
        return None
    if build_flags.extraction_confidence == "absent":
        return None
    enabled = tuple(
        s for s in build_flags.sanitizers_enabled
        if s in _RELEVANT_SANITIZERS
    )
    if not enabled:
        return None

    listed = ", ".join(enabled)
    if style == "stage_d":
        prefix = "Build-flag context — active sanitizers"
    elif style == "exploit_plan":
        prefix = "Constraint — sanitizers active in build"
    else:
        prefix = "Variant hint — sanitizer build"

    # Memory-corruption-CWE prose. Surfaces both interpretations the
    # LLM should weigh: production-equivalent KASAN catches the bug
    # at panic-cost (DoS-only outcome), but if the binary under
    # analysis is the sanitizer build itself, the finding may not
    # reproduce in stripped production binaries.
    return (
        f"{prefix}: {listed}. If this is a production-equivalent build "
        f"with these sanitizers active, memory-corruption primitives "
        f"reaching runtime trigger a panic / abort — the bug is "
        f"DoS-only, not RCE. If this is a CI / fuzzer build only, "
        f"the production binary lacks these checks and the primitive "
        f"survives uninstrumented."
    )


# =====================================================================
# Helpers
# =====================================================================


def _truncate(lines: List[str], max_lines: Optional[int]) -> List[str]:
    """Cap line count for tight prompt budgets."""
    if max_lines is None or len(lines) <= max_lines:
        return lines
    return lines[:max_lines]


def derive_mitigations_found(
    result: SourceIntelResult,
    finding_function: Optional[str] = None,
    finding_file: Optional[str] = None,
    finding_line: Optional[int] = None,
) -> List[Mitigation]:
    """Return the structured `mitigations_found` list for a finding.

    Per design strict invariant: a positively-detected mitigation
    earns an entry; ABSENCE earns no entry (don't emit
    ``hardened: False`` because we may have missed signal).

    Walks every evidence axis on ``result`` that could meaningfully
    indicate hardening / verdict-suppression:

      * axis_2 abort  — abort-class call in finding's function
        (`abort_dominates` if grade=dominates, `abort_proximate`
        for same_function/same_path)
      * axis_4 priv   — privileged capable() in finding's function
        (`priv_dominates`)
      * axis_6 fortify — FORTIFY_SOURCE active + fortified call
        (`fortify_intercepted`)
      * axis_7 dead   — function dead per PR-4 + static
        (`dead_code`)
      * axis_8 valid  — downstream relational+early-exit guard
        (`downstream_validation`)
      * axis_3 paired — alloc paired with free in function
        (`paired_free` — informational for leak findings)

    Each entry includes location when known so Stage D LLM can
    cross-reference the source.
    """
    mitigations: List[Mitigation] = []

    # axis_2 abort — same function as finding
    for ab in result.aborts:
        if (finding_function and ab.enclosing_function
                and ab.enclosing_function != finding_function):
            continue
        if ab.grade == GRADE_DOMINATES:
            confidence = "high"
            name = "abort_dominates"
        elif ab.grade == GRADE_SAME_PATH:
            confidence = "medium"
            name = "abort_on_path"
        else:
            confidence = "low"
            name = "abort_proximate"
        mitigations.append(Mitigation(
            name=name, axis="axis_2", confidence=confidence,
            detail=f"{ab.macro} ({ab.grade})",
            location=ab.location,
        ))

    # axis_4 privilege — capable() in same function
    for cap in result.capabilities:
        if (finding_function and cap.enclosing_function
                and cap.enclosing_function != finding_function):
            continue
        mitigations.append(Mitigation(
            name="privilege_gate",
            axis="axis_4", confidence="medium",
            detail=f"{cap.cap_function} (grade={cap.grade})",
            location=cap.location,
        ))

    # axis_6 FORTIFY — surface only when level present
    if result.build_flags and result.build_flags.fortify_source_level:
        level = result.build_flags.fortify_source_level
        confidence = "high" if level >= 2 else "medium"
        mitigations.append(Mitigation(
            name="fortify_source",
            axis="axis_6", confidence=confidence,
            detail=f"_FORTIFY_SOURCE={level} ({result.build_flags.source})",
            location=None,
        ))

    # axis_3 paired-free — informational for cpp/memory-leak FPs
    for pf in result.paired_frees:
        if finding_function and pf.enclosing_function != finding_function:
            continue
        mitigations.append(Mitigation(
            name="paired_free",
            axis="axis_3", confidence="medium",
            detail=f"{pf.allocator} paired with {pf.free_fn}",
            location=pf.location,
        ))

    # axis_2 sub-class: warn-class is informational, not a real
    # mitigation; null-guards likewise (axis-3's `when !=` does the
    # verdict work). We don't emit these as mitigations to avoid
    # false-confidence in Stage D output.

    return mitigations


def aggregate_confidence(mitigations: List[Mitigation]) -> str:
    """Compute overall confidence per design strict invariant:
    "confidence capped at strongest individual signal; no
    multiplicative inflation".

    Multiple mediums do NOT combine into a high. Multiple highs
    don't combine into something stronger than high. The single
    strongest signal wins.

    Returns one of: "high" | "medium" | "low" | "none" (no
    evidence at all).
    """
    if not mitigations:
        return "none"
    ranks = {"high": 3, "medium": 2, "low": 1}
    best = max(ranks.get(m.confidence, 0) for m in mitigations)
    return next(
        (k for k, v in ranks.items() if v == best),
        "none",
    )
