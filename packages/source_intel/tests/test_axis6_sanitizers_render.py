"""Tests for axis-6 sanitizer rendering in derive_evidence_strings.

Phase B PR4: the renderer surfaces ``build_flags.sanitizers_enabled``
as one prose line per finding when relevant sanitizers are active.
"""

from __future__ import annotations


from core.build.build_flags import BuildFlagsContext
from packages.source_intel.analyze import SourceIntelResult
from packages.source_intel.render import (
    _RELEVANT_SANITIZERS,
    _render_sanitizers_line,
    derive_evidence_strings,
)


# ---- _render_sanitizers_line ------------------------------------------


class TestRenderSanitizersLine:
    def test_none_when_build_flags_missing(self):
        assert _render_sanitizers_line(None, "stage_d") is None

    def test_none_when_extraction_absent(self):
        flags = BuildFlagsContext(extraction_confidence="absent")
        assert _render_sanitizers_line(flags, "stage_d") is None

    def test_none_when_sanitizers_empty(self):
        flags = BuildFlagsContext(
            extraction_confidence="compile_commands",
            sanitizers_enabled=(),
        )
        assert _render_sanitizers_line(flags, "stage_d") is None

    def test_none_when_only_irrelevant_sanitizers(self):
        flags = BuildFlagsContext(
            extraction_confidence="compile_commands",
            sanitizers_enabled=("leak",),  # not in _RELEVANT_SANITIZERS
        )
        assert _render_sanitizers_line(flags, "stage_d") is None

    def test_renders_when_kasan_active(self):
        flags = BuildFlagsContext(
            extraction_confidence="kconfig",
            sanitizers_enabled=("kasan",),
        )
        line = _render_sanitizers_line(flags, "stage_d")
        assert line is not None
        assert "kasan" in line
        assert "panic" in line or "abort" in line  # DoS framing

    def test_renders_when_address_active(self):
        flags = BuildFlagsContext(
            extraction_confidence="compile_commands",
            sanitizers_enabled=("address",),
        )
        line = _render_sanitizers_line(flags, "stage_d")
        assert line is not None
        assert "address" in line

    def test_lists_multiple_sanitizers(self):
        flags = BuildFlagsContext(
            extraction_confidence="kconfig",
            sanitizers_enabled=("kasan", "ubsan", "kcov"),
        )
        line = _render_sanitizers_line(flags, "stage_d")
        assert line is not None
        assert "kasan" in line
        assert "ubsan" in line
        assert "kcov" in line

    def test_filters_to_relevant_only(self):
        flags = BuildFlagsContext(
            extraction_confidence="kconfig",
            sanitizers_enabled=("kasan", "leak", "irrelevant_thing"),
        )
        line = _render_sanitizers_line(flags, "stage_d")
        assert line is not None
        assert "kasan" in line
        assert "leak" not in line
        assert "irrelevant_thing" not in line

    def test_stage_d_prefix(self):
        flags = BuildFlagsContext(
            extraction_confidence="kconfig",
            sanitizers_enabled=("kasan",),
        )
        line = _render_sanitizers_line(flags, "stage_d")
        assert line.startswith("Build-flag context")

    def test_exploit_plan_prefix(self):
        flags = BuildFlagsContext(
            extraction_confidence="kconfig",
            sanitizers_enabled=("kasan",),
        )
        line = _render_sanitizers_line(flags, "exploit_plan")
        assert line.startswith("Constraint")

    def test_agentic_variant_prefix(self):
        flags = BuildFlagsContext(
            extraction_confidence="kconfig",
            sanitizers_enabled=("kasan",),
        )
        line = _render_sanitizers_line(flags, "agentic_variant")
        assert line.startswith("Variant hint")


# ---- integration in derive_evidence_strings ---------------------------


class TestDeriveEvidenceStringsSanitizers:
    def test_sanitizer_line_included_when_active(self):
        result = SourceIntelResult(target="/tmp/x")
        flags = BuildFlagsContext(
            extraction_confidence="kconfig",
            sanitizers_enabled=("kasan",),
        )
        lines = derive_evidence_strings(
            result,
            finding_function="foo",
            build_flags=flags,
            style="stage_d",
        )
        # Will include both the sanitizer line and the "no signal" line.
        joined = "\n".join(lines)
        assert "kasan" in joined
        assert "Build-flag context" in joined

    def test_no_sanitizer_line_when_absent(self):
        result = SourceIntelResult(target="/tmp/x")
        lines = derive_evidence_strings(
            result,
            finding_function="foo",
            build_flags=None,
            style="stage_d",
        )
        joined = "\n".join(lines)
        assert "Build-flag context" not in joined
        assert "kasan" not in joined

    def test_only_no_signal_when_empty_evidence_and_no_sanitizers(self):
        result = SourceIntelResult(target="/tmp/x")
        flags = BuildFlagsContext(
            extraction_confidence="compile_commands",
            sanitizers_enabled=(),  # no sanitizers
        )
        lines = derive_evidence_strings(
            result,
            finding_function="foo",
            build_flags=flags,
            style="stage_d",
        )
        # No evidence, no sanitizer line — falls through to the
        # explicit "no signal" branch.
        joined = "\n".join(lines)
        assert "no attribute or proximity evidence" in joined


# ---- coverage sanity --------------------------------------------------


def test_relevant_sanitizers_includes_kernel_and_userspace():
    """Sanity check: the relevant set covers both -fsanitize=X
    spellings and CONFIG_* derived names."""
    assert "address" in _RELEVANT_SANITIZERS    # userspace ASan
    assert "kasan" in _RELEVANT_SANITIZERS      # kernel ASan
    assert "memory" in _RELEVANT_SANITIZERS     # userspace MSan
    assert "ubsan" in _RELEVANT_SANITIZERS      # kernel UBSan
