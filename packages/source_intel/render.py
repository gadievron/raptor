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
"""

from __future__ import annotations

from typing import List, Optional

from core.build.build_flags import BuildFlagsContext
from packages.source_intel.analyze import (
    KIND_ACCESS,
    KIND_ALLOC_SIZE,
    KIND_MALLOC,
    KIND_NO_STACK_PROTECTOR,
    KIND_NONNULL,
    KIND_NORETURN,
    KIND_RETURNS_NONNULL,
    KIND_WUR,
    AttributeEvidence,
    SourceIntelResult,
)


_STYLES = ("stage_d", "exploit_plan", "agentic_variant")


def derive_evidence_strings(
    result: SourceIntelResult,
    finding_function: Optional[str] = None,
    build_flags: Optional[BuildFlagsContext] = None,
    style: str = "stage_d",
    max_lines: Optional[int] = None,
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
        return _truncate(lines, max_lines)

    # Filter to the finding's function when supplied.
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

    # When source_intel ran but found nothing relevant — emit an
    # explicit "no signal" line so the consumer prompt template
    # carries the absence acknowledgement.
    if not lines:
        lines.append(
            "Source_intel ran; no attribute evidence for "
            f"{finding_function or '<finding function>'}. "
            f"Absence of evidence is NOT evidence of unhardened code."
        )

    return _truncate(lines, max_lines)


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
# Helpers
# =====================================================================


def _truncate(lines: List[str], max_lines: Optional[int]) -> List[str]:
    """Cap line count for tight prompt budgets."""
    if max_lines is None or len(lines) <= max_lines:
        return lines
    return lines[:max_lines]
