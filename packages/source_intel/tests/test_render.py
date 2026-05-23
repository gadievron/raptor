"""Tests for ``packages.source_intel.render``."""

from __future__ import annotations

import pytest

from core.build.build_flags import BuildFlagsContext
from packages.source_intel.analyze import SourceIntelResult, WurEvidence
from packages.source_intel.render import derive_evidence_strings


def _result_with_wur(*evs):
    return SourceIntelResult(attributes=tuple(evs))


def _wur(function_name="alloc_thing", source="literal",
         spelling="__attribute__((warn_unused_result))"):
    return WurEvidence(
        function_name=function_name,
        location=("a.c", 10),
        match_source=source,
        raw_match=spelling,
    )


# =====================================================================
# Style validation
# =====================================================================


def test_unknown_style_raises():
    r = _result_with_wur(_wur())
    with pytest.raises(ValueError, match="unknown style"):
        derive_evidence_strings(r, style="invalid")


def test_each_known_style_emits_distinct_prefix():
    """The three styles render with consumer-specific prefixes so the
    LLM consumer sees framing appropriate to its task."""
    r = _result_with_wur(_wur())
    stage_d = derive_evidence_strings(r, style="stage_d")
    exploit = derive_evidence_strings(r, style="exploit_plan")
    variant = derive_evidence_strings(r, style="agentic_variant")
    assert stage_d != exploit
    assert exploit != variant
    assert "Author intent" in stage_d[0]
    assert "Constraint" in exploit[0]
    assert "Variant hint" in variant[0]


# =====================================================================
# Skip-state framing
# =====================================================================


def test_skipped_result_surfaces_skip_reason():
    """Consumers need to know there was NO evidence — explicit skip
    framing prevents "absence = no hardening" misinterpretation."""
    r = SourceIntelResult(skipped_reason="spatch_not_available")
    lines = derive_evidence_strings(r)
    assert len(lines) == 1
    assert "skipped" in lines[0].lower()
    assert "spatch_not_available" in lines[0]
    assert "no evidence either way" in lines[0].lower()


def test_empty_result_emits_absence_acknowledgement():
    """SourceIntel ran but found nothing relevant — explicit
    "absence ≠ unhardened" line so the LLM doesn't infer hardening
    from silence."""
    r = SourceIntelResult()  # ran, but no WUR observations
    lines = derive_evidence_strings(r, finding_function="my_func")
    assert len(lines) == 1
    assert "absence" in lines[0].lower()


# =====================================================================
# WUR rendering
# =====================================================================


def test_wur_evidence_line_includes_function_name():
    r = _result_with_wur(_wur("validate_input"))
    lines = derive_evidence_strings(r, finding_function="validate_input")
    assert any("validate_input" in line for line in lines)
    assert any("warn_unused_result" in line for line in lines)


def test_finding_function_filter_excludes_other_functions():
    r = _result_with_wur(
        _wur("validate_input"),
        _wur("other_func"),
    )
    lines = derive_evidence_strings(r, finding_function="validate_input")
    rendered = "\n".join(lines)
    assert "validate_input" in rendered
    assert "other_func" not in rendered


def test_literal_evidence_sorted_before_alias():
    """Strongest signal first — literal observations precede known-
    alias observations."""
    r = _result_with_wur(
        _wur("alias_func", source="known_alias", spelling="__must_check"),
        _wur("literal_func", source="literal",
             spelling="__attribute__((warn_unused_result))"),
    )
    lines = derive_evidence_strings(r)
    assert "literal_func" in lines[0]
    assert "alias_func" in lines[1]


def test_known_alias_rendering_cites_spelling():
    r = _result_with_wur(
        _wur("foo", source="known_alias", spelling="__must_check"),
    )
    lines = derive_evidence_strings(r)
    assert "__must_check" in lines[0]
    assert "known alias" in lines[0].lower()


# =====================================================================
# Build-flag enforcement framing
# =====================================================================


def test_enforcement_unknown_when_no_build_flags():
    r = _result_with_wur(_wur())
    lines = derive_evidence_strings(r)
    assert "advisory" in lines[0].lower()
    assert "build flags not in evidence" in lines[0].lower()


def test_enforcement_compile_enforced_when_werror_unused_result():
    bf = BuildFlagsContext(
        source="compile_commands.json",
        extraction_confidence="high",
        werror_unused_result=True,
    )
    r = _result_with_wur(_wur())
    lines = derive_evidence_strings(r, build_flags=bf)
    assert "compile-enforced" in lines[0].lower()


def test_enforcement_advisory_when_werror_explicitly_off():
    bf = BuildFlagsContext(
        source="compile_commands.json",
        extraction_confidence="high",
        werror_unused_result=False,
    )
    r = _result_with_wur(_wur())
    lines = derive_evidence_strings(r, build_flags=bf)
    assert "suppressed" in lines[0].lower()


def test_enforcement_partial_when_other_flags_observed():
    """Build flags present but -Werror=unused-result not set →
    advisory framing."""
    bf = BuildFlagsContext(
        source="compile_commands.json",
        extraction_confidence="high",
        fortify_source_level=2,
        # werror_unused_result intentionally None
    )
    r = _result_with_wur(_wur())
    lines = derive_evidence_strings(r, build_flags=bf)
    assert "advisory" in lines[0].lower() or "advisory unless" in lines[0].lower()


# =====================================================================
# max_lines truncation
# =====================================================================


def test_max_lines_caps_output():
    r = _result_with_wur(*(
        _wur(f"f{i}", source="literal") for i in range(5)
    ))
    lines = derive_evidence_strings(r, max_lines=2)
    assert len(lines) == 2


def test_max_lines_none_means_no_cap():
    r = _result_with_wur(*(
        _wur(f"f{i}") for i in range(5)
    ))
    lines = derive_evidence_strings(r, max_lines=None)
    assert len(lines) == 5


# =====================================================================
# Nonnull rendering (Phase 3a)
# =====================================================================


def _nonnull(function_name="alloc_thing"):
    from packages.source_intel.analyze import KIND_NONNULL, AttributeEvidence
    return AttributeEvidence(
        kind=KIND_NONNULL,
        function_name=function_name,
        location=("a.c", 10),
        match_source="literal",
        raw_match="__attribute__((nonnull))",
    )


def test_nonnull_evidence_renders_with_two_edged_caveat():
    """Nonnull renderer must convey the two-edged signal — both
    "caller must pass non-null" AND the compiler-elimination caveat.
    Without the caveat the LLM might infer hardening from author intent
    alone."""
    r = SourceIntelResult(attributes=(_nonnull("validate_input"),))
    lines = derive_evidence_strings(r)
    text = "\n".join(lines)
    assert "nonnull" in text.lower()
    assert "validate_input" in text


def test_nonnull_caveat_preserved_when_delete_null_checks_off():
    """With kernel's -fno-delete-null-pointer-checks observed, the
    caveat changes — defensive null checks ARE preserved."""
    bf = BuildFlagsContext(
        source="compile_commands.json",
        extraction_confidence="high",
        delete_null_pointer_checks=False,
    )
    r = SourceIntelResult(attributes=(_nonnull(),))
    lines = derive_evidence_strings(r, build_flags=bf)
    text = "\n".join(lines)
    assert "preserved" in text.lower()


def test_nonnull_caveat_warns_when_delete_null_checks_on():
    """With explicit -fdelete-null-pointer-checks, the renderer warns
    that the compiler may eliminate null guards — a NULL deref would
    actually fire."""
    bf = BuildFlagsContext(
        source="compile_commands.json",
        extraction_confidence="high",
        delete_null_pointer_checks=True,
    )
    r = SourceIntelResult(attributes=(_nonnull(),))
    lines = derive_evidence_strings(r, build_flags=bf)
    text = "\n".join(lines)
    assert "eliminate" in text.lower()


def test_nonnull_and_wur_both_rendered():
    """A function with both annotations produces evidence lines for
    each kind; both surface to the consumer."""
    r = SourceIntelResult(attributes=(
        _wur("validate_input"),
        _nonnull("validate_input"),
    ))
    lines = derive_evidence_strings(r, finding_function="validate_input")
    text = "\n".join(lines)
    assert "warn_unused_result" in text
    assert "nonnull" in text.lower()


# =====================================================================
# alloc_size + returns_nonnull rendering (Phase 3b)
# =====================================================================


def _alloc_size(function_name="my_malloc"):
    from packages.source_intel.analyze import KIND_ALLOC_SIZE, AttributeEvidence
    return AttributeEvidence(
        kind=KIND_ALLOC_SIZE,
        function_name=function_name,
        location=("a.c", 10),
        match_source="literal",
        raw_match="__attribute__((alloc_size(...)))",
    )


def _returns_nonnull(function_name="must_succeed"):
    from packages.source_intel.analyze import (
        KIND_RETURNS_NONNULL, AttributeEvidence,
    )
    return AttributeEvidence(
        kind=KIND_RETURNS_NONNULL,
        function_name=function_name,
        location=("a.c", 10),
        match_source="literal",
        raw_match="__attribute__((returns_nonnull))",
    )


def test_alloc_size_renders_with_fortify_caveat_unknown():
    r = SourceIntelResult(attributes=(_alloc_size("alloc_buf"),))
    lines = derive_evidence_strings(r)
    text = "\n".join(lines)
    assert "alloc_size" in text.lower()
    assert "alloc_buf" in text
    # No FORTIFY signal — caveat must say so.
    assert "fortify_source status unknown" in text.lower()


def test_alloc_size_renders_with_fortify_2_active():
    bf = BuildFlagsContext(
        source="compile_commands.json",
        extraction_confidence="high",
        fortify_source_level=2,
    )
    r = SourceIntelResult(attributes=(_alloc_size(),))
    lines = derive_evidence_strings(r, build_flags=bf)
    text = "\n".join(lines)
    assert "fortify_source" in text.lower()
    assert "runtime" in text.lower()


def test_alloc_size_renders_with_fortify_disabled():
    bf = BuildFlagsContext(
        source="compile_commands.json",
        extraction_confidence="high",
        fortify_source_level=0,
    )
    r = SourceIntelResult(attributes=(_alloc_size(),))
    lines = derive_evidence_strings(r, build_flags=bf)
    text = "\n".join(lines)
    # Should note no runtime protection.
    assert "disabled" in text.lower() or "no runtime" in text.lower()


def test_returns_nonnull_renders_with_caveat():
    r = SourceIntelResult(attributes=(_returns_nonnull("alloc_or_die"),))
    lines = derive_evidence_strings(r)
    text = "\n".join(lines)
    assert "returns_nonnull" in text.lower() or "never to return NULL".lower() in text.lower()
    assert "alloc_or_die" in text


def test_conditional_on_appends_caveat_to_evidence_line():
    """When the observation is under an #ifdef, the rendered line
    must carry an explicit caveat — without it, Stage D may infer
    hardening that doesn't apply in the actual build."""
    from packages.source_intel.analyze import KIND_WUR, AttributeEvidence
    ev = AttributeEvidence(
        kind=KIND_WUR,
        function_name="alloc_thing",
        location=("compiler.h", 5),
        match_source="literal",
        raw_match="__attribute__((warn_unused_result))",
        conditional_on="CONFIG_HARDENING",
    )
    r = SourceIntelResult(attributes=(ev,))
    lines = derive_evidence_strings(r)
    text = "\n".join(lines)
    assert "CONDITIONAL" in text
    assert "CONFIG_HARDENING" in text
    assert "downweight" in text.lower()


def test_no_caveat_when_unconditional():
    """No caveat when conditional_on is None — single rendered line
    without the suffix."""
    from packages.source_intel.analyze import KIND_WUR, AttributeEvidence
    ev = AttributeEvidence(
        kind=KIND_WUR,
        function_name="alloc_thing",
        location=("h.h", 5),
        match_source="literal",
        raw_match="__attribute__((warn_unused_result))",
        # conditional_on=None — the default
    )
    r = SourceIntelResult(attributes=(ev,))
    lines = derive_evidence_strings(r)
    text = "\n".join(lines)
    assert "CONDITIONAL" not in text


def test_noreturn_renders_dos_only_phrasing():
    """noreturn marks a function as a guaranteed abort — the rendered
    line must say "DoS-only" so the LLM understands the implication
    for exploitability."""
    from packages.source_intel.analyze import KIND_NORETURN, AttributeEvidence
    ev = AttributeEvidence(
        kind=KIND_NORETURN,
        function_name="panic_fn",
        location=("a.c", 10),
        match_source="literal",
        raw_match="__attribute__((noreturn))",
    )
    r = SourceIntelResult(attributes=(ev,))
    lines = derive_evidence_strings(r)
    text = "\n".join(lines)
    assert "panic_fn" in text
    assert "noreturn" in text.lower()
    assert "dos" in text.lower() or "aborts" in text.lower()


def test_malloc_renders_allocator_signal():
    from packages.source_intel.analyze import KIND_MALLOC, AttributeEvidence
    ev = AttributeEvidence(
        kind=KIND_MALLOC,
        function_name="my_alloc",
        location=("a.c", 5),
        match_source="literal",
        raw_match="__attribute__((malloc))",
    )
    r = SourceIntelResult(attributes=(ev,))
    lines = derive_evidence_strings(r)
    text = "\n".join(lines)
    assert "my_alloc" in text
    assert "allocator" in text.lower()


def test_no_stack_protector_renders_hardening_hole():
    """no_stack_protector is a hardening HOLE — the rendered line
    must convey that signal so the LLM treats CWE-120 / CWE-787
    findings in such functions as more exploitable."""
    from packages.source_intel.analyze import (
        KIND_NO_STACK_PROTECTOR, AttributeEvidence,
    )
    ev = AttributeEvidence(
        kind=KIND_NO_STACK_PROTECTOR,
        function_name="critical_fn",
        location=("a.c", 20),
        match_source="literal",
        raw_match="__attribute__((no_stack_protector))",
    )
    r = SourceIntelResult(attributes=(ev,))
    lines = derive_evidence_strings(r)
    text = "\n".join(lines)
    assert "critical_fn" in text
    assert "canary" in text.lower() or "bypass" in text.lower()
    assert ("hardening" in text.lower()
            or "opts out" in text.lower()
            or "opt out" in text.lower())


def test_no_stack_protector_correlates_with_build_wide_strong():
    """When the build was using -fstack-protector-strong, the per-
    function opt-out matters MORE — the renderer notes the
    build-wide protection state."""
    bf = BuildFlagsContext(
        source="compile_commands.json",
        extraction_confidence="high",
        stack_protector_level="strong",
    )
    from packages.source_intel.analyze import (
        KIND_NO_STACK_PROTECTOR, AttributeEvidence,
    )
    ev = AttributeEvidence(
        kind=KIND_NO_STACK_PROTECTOR,
        function_name="critical_fn",
        location=("a.c", 20),
        match_source="literal",
        raw_match="__attribute__((no_stack_protector))",
    )
    r = SourceIntelResult(attributes=(ev,))
    lines = derive_evidence_strings(r, build_flags=bf)
    text = "\n".join(lines)
    assert "strong" in text.lower()


def test_access_renders_with_fortify_correlation():
    """access annotation declares parameter intent; with
    FORTIFY_SOURCE=2 active, the runtime-bounds-check signal must
    surface so the LLM correctly weighs CWE-120 findings."""
    bf = BuildFlagsContext(
        source="compile_commands.json",
        extraction_confidence="high",
        fortify_source_level=2,
    )
    from packages.source_intel.analyze import KIND_ACCESS, AttributeEvidence
    ev = AttributeEvidence(
        kind=KIND_ACCESS,
        function_name="ro_fn",
        location=("a.c", 30),
        match_source="literal",
        raw_match="__attribute__((access(read_only, 1)))",
    )
    r = SourceIntelResult(attributes=(ev,))
    lines = derive_evidence_strings(r, build_flags=bf)
    text = "\n".join(lines)
    assert "ro_fn" in text
    assert "access" in text.lower()
    assert "runtime" in text.lower() or "bounds-check" in text.lower()


def test_returns_nonnull_warns_when_delete_null_checks_on():
    """If the annotation is wrong AND -fdelete-null-pointer-checks is
    on, defensive caller null checks may be eliminated. The renderer
    must convey this risk."""
    bf = BuildFlagsContext(
        source="compile_commands.json",
        extraction_confidence="high",
        delete_null_pointer_checks=True,
    )
    r = SourceIntelResult(attributes=(_returns_nonnull(),))
    lines = derive_evidence_strings(r, build_flags=bf)
    text = "\n".join(lines)
    assert "wrong" in text.lower()
    assert "eliminate" in text.lower()
