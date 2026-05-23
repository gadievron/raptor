"""Tests for ``core.build.build_flags``.

Covers each source extractor (compile_commands.json / Kconfig / Makefile)
across the flag dimensions source_intel consumers care about, plus
edge cases (missing artifacts, malformed JSON, empty files, mixed
signals).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.build.build_flags import (
    BuildFlagsContext,
    SCHEMA_VERSION,
    extract_flags,
)


# =====================================================================
# Target detection / fallback
# =====================================================================

def test_missing_target_returns_absent():
    ctx = extract_flags(Path("/nonexistent/path/does/not/exist"))
    assert ctx.source == "absent"
    assert ctx.extraction_confidence == "absent"


def test_target_is_file_returns_absent(tmp_path):
    f = tmp_path / "not-a-dir"
    f.write_text("")
    ctx = extract_flags(f)
    assert ctx.source == "absent"


def test_empty_dir_returns_absent(tmp_path):
    ctx = extract_flags(tmp_path)
    assert ctx.source == "absent"
    assert ctx.extraction_confidence == "absent"
    # Hard invariant — absent must produce all-None fields, not False.
    assert ctx.werror_unused_result is None
    assert ctx.fortify_source_level is None
    assert ctx.sanitizers_enabled == ()


# =====================================================================
# compile_commands.json — highest signal source
# =====================================================================

def _write_cc(tmp_path, entries):
    p = tmp_path / "compile_commands.json"
    p.write_text(json.dumps(entries))
    return tmp_path


def test_cc_command_string_extracts_werror_unused_result(tmp_path):
    target = _write_cc(tmp_path, [{
        "directory": "/build",
        "file": "/build/foo.c",
        "command": "gcc -O2 -Werror=unused-result foo.c -o foo.o",
    }])
    ctx = extract_flags(target)
    assert ctx.source == "compile_commands.json"
    assert ctx.extraction_confidence == "high"
    assert ctx.werror_unused_result is True


def test_cc_arguments_array_extracts_werror(tmp_path):
    target = _write_cc(tmp_path, [{
        "directory": "/build",
        "file": "/build/foo.c",
        "arguments": ["gcc", "-O2", "-Werror", "foo.c", "-o", "foo.o"],
    }])
    ctx = extract_flags(target)
    assert ctx.werror_all is True
    # Bare -Werror implies unused-result is enforced too.
    assert ctx.werror_unused_result is True


def test_cc_excepted_unused_result_wins(tmp_path):
    """-Wno-error=unused-result must override a bare -Werror for the
    specific unused-result case (gcc semantics)."""
    target = _write_cc(tmp_path, [{
        "directory": "/build",
        "file": "/build/foo.c",
        "command": "gcc -Werror -Wno-error=unused-result foo.c",
    }])
    ctx = extract_flags(target)
    assert ctx.werror_all is True
    assert ctx.werror_unused_result is False


def test_cc_fortify_level(tmp_path):
    target = _write_cc(tmp_path, [{
        "command": "gcc -O2 -D_FORTIFY_SOURCE=2 foo.c",
    }])
    ctx = extract_flags(target)
    assert ctx.fortify_source_level == 2


def test_cc_fortify_undef(tmp_path):
    target = _write_cc(tmp_path, [{
        "command": "gcc -U_FORTIFY_SOURCE foo.c",
    }])
    ctx = extract_flags(target)
    assert ctx.fortify_source_level == 0


def test_cc_stack_protector_strong(tmp_path):
    target = _write_cc(tmp_path, [{
        "command": "gcc -fstack-protector-strong foo.c",
    }])
    ctx = extract_flags(target)
    assert ctx.stack_protector_level == "strong"


def test_cc_stack_protector_disabled(tmp_path):
    """-fno-stack-protector dominates any earlier -fstack-protector*."""
    target = _write_cc(tmp_path, [{
        "command": "gcc -fstack-protector-strong -fno-stack-protector foo.c",
    }])
    ctx = extract_flags(target)
    assert ctx.stack_protector_level == "none"


def test_cc_delete_null_pointer_checks_disabled(tmp_path):
    """Kernel build convention."""
    target = _write_cc(tmp_path, [{
        "command": "gcc -O2 -fno-delete-null-pointer-checks foo.c",
    }])
    ctx = extract_flags(target)
    assert ctx.delete_null_pointer_checks is False


def test_cc_sanitizers_comma_split(tmp_path):
    target = _write_cc(tmp_path, [{
        "command": "gcc -fsanitize=address,undefined foo.c",
    }])
    ctx = extract_flags(target)
    assert ctx.sanitizers_enabled == ("address", "undefined")


def test_cc_sanitizers_dedup_across_entries(tmp_path):
    """Different translation units may name the same sanitizer; dedup."""
    target = _write_cc(tmp_path, [
        {"command": "gcc -fsanitize=address a.c"},
        {"command": "gcc -fsanitize=address,undefined b.c"},
    ])
    ctx = extract_flags(target)
    assert ctx.sanitizers_enabled == ("address", "undefined")


def test_cc_full_kernel_style_flags(tmp_path):
    """Realistic kernel-style compile command exercising every axis."""
    target = _write_cc(tmp_path, [{
        "command": (
            "gcc -O2 -Wall -Werror=unused-result "
            "-D_FORTIFY_SOURCE=1 -fstack-protector-strong "
            "-fno-delete-null-pointer-checks -fsanitize=kernel-address "
            "-c foo.c"
        ),
    }])
    ctx = extract_flags(target)
    assert ctx.source == "compile_commands.json"
    assert ctx.extraction_confidence == "high"
    assert ctx.werror_unused_result is True
    assert ctx.werror_all is None  # specific -Werror=, not bare
    assert ctx.fortify_source_level == 1
    assert ctx.stack_protector_level == "strong"
    assert ctx.delete_null_pointer_checks is False
    assert ctx.sanitizers_enabled == ("kernel-address",)


def test_cc_in_build_subdir(tmp_path):
    """CMake convention: build/compile_commands.json."""
    build_dir = tmp_path / "build"
    build_dir.mkdir()
    (build_dir / "compile_commands.json").write_text(json.dumps([
        {"command": "gcc -Werror=unused-result foo.c"}
    ]))
    ctx = extract_flags(tmp_path)
    assert ctx.werror_unused_result is True


def test_cc_empty_array_falls_through_to_other_sources(tmp_path):
    """Empty compile_commands.json is treated as no-signal; if a
    Makefile is present, fall through to that."""
    (tmp_path / "compile_commands.json").write_text("[]")
    (tmp_path / "Makefile").write_text(
        "CFLAGS = -O2 -Werror=unused-result\n"
    )
    ctx = extract_flags(tmp_path)
    assert ctx.source == "makefile"
    assert ctx.werror_unused_result is True


def test_cc_malformed_json_falls_through(tmp_path):
    """Broken JSON shouldn't crash; fall through to other sources."""
    (tmp_path / "compile_commands.json").write_text("not json {")
    (tmp_path / "Makefile").write_text("CFLAGS = -Werror\n")
    ctx = extract_flags(tmp_path)
    assert ctx.source == "makefile"
    assert ctx.werror_all is True


# =====================================================================
# Kconfig (.config) source
# =====================================================================

def test_kconfig_hardening_flags(tmp_path):
    (tmp_path / ".config").write_text(
        "# Linux kernel config\n"
        "CONFIG_STACK_PROTECTOR=y\n"
        "CONFIG_STACK_PROTECTOR_STRONG=y\n"
        "CONFIG_FORTIFY_SOURCE=y\n"
        "CONFIG_KASAN=y\n"
        "CONFIG_KASAN_GENERIC=y\n"
        "CONFIG_UBSAN=y\n"
        "# CONFIG_KCOV is not set\n"
        "CONFIG_RANDOMIZE_BASE=y\n"
        "CONFIG_UNRELATED=y\n"
    )
    ctx = extract_flags(tmp_path)
    assert ctx.source == "kconfig"
    assert ctx.extraction_confidence == "best_effort"
    assert ctx.stack_protector_level == "strong"
    assert ctx.fortify_source_level == 1
    assert "kasan" in ctx.sanitizers_enabled
    assert "ubsan" in ctx.sanitizers_enabled
    assert "kcov" not in ctx.sanitizers_enabled
    configs = dict(ctx.relevant_configs)
    assert configs["CONFIG_FORTIFY_SOURCE"] is True
    assert configs["CONFIG_KCOV"] is False
    # CONFIG_UNRELATED is not in our hardening list; should NOT appear
    assert "CONFIG_UNRELATED" not in configs


def test_kconfig_weak_stack_protector_only(tmp_path):
    """When STACK_PROTECTOR_STRONG is not set but STACK_PROTECTOR is,
    the level should report ``weak``."""
    (tmp_path / ".config").write_text(
        "CONFIG_STACK_PROTECTOR=y\n"
        "# CONFIG_STACK_PROTECTOR_STRONG is not set\n"
    )
    ctx = extract_flags(tmp_path)
    assert ctx.stack_protector_level == "weak"


def test_kconfig_empty_yields_absent(tmp_path):
    """.config with no recognised hardening keys yields absent — the
    extractor falls through and the final fallback returns source=
    absent so consumers know there was no signal anywhere."""
    (tmp_path / ".config").write_text(
        "# Empty kernel config\n"
        "CONFIG_X86=y\n"
        "CONFIG_64BIT=y\n"
    )
    ctx = extract_flags(tmp_path)
    # No fallback present, no hardening configs matched — fully absent.
    assert ctx.source == "absent"
    assert ctx.extraction_confidence == "absent"


def test_kconfig_no_hardening_falls_through_to_makefile(tmp_path):
    """When .config has no recognised hardening keys but a Makefile
    with real signal is also present, the makefile signal must win
    (don't strand on an empty source)."""
    (tmp_path / ".config").write_text(
        "CONFIG_X86=y\n"
    )
    (tmp_path / "Makefile").write_text(
        "CFLAGS = -Werror=unused-result\n"
    )
    ctx = extract_flags(tmp_path)
    assert ctx.source == "makefile"
    assert ctx.werror_unused_result is True


# =====================================================================
# Makefile source — best-effort regex
# =====================================================================

def test_makefile_simple_cflags(tmp_path):
    (tmp_path / "Makefile").write_text(
        "CC = gcc\n"
        "CFLAGS = -O2 -Werror=unused-result -D_FORTIFY_SOURCE=2\n"
        "TARGET = foo\n"
    )
    ctx = extract_flags(tmp_path)
    assert ctx.source == "makefile"
    assert ctx.extraction_confidence == "best_effort"
    assert ctx.werror_unused_result is True
    assert ctx.fortify_source_level == 2


def test_makefile_extra_cflags_concatenated(tmp_path):
    """``EXTRA_CFLAGS += ...`` should be picked up alongside CFLAGS."""
    (tmp_path / "Makefile").write_text(
        "CFLAGS = -O2\n"
        "EXTRA_CFLAGS += -fstack-protector-strong\n"
        "EXTRA_CFLAGS += -fsanitize=address\n"
    )
    ctx = extract_flags(tmp_path)
    assert ctx.stack_protector_level == "strong"
    assert ctx.sanitizers_enabled == ("address",)


def test_kbuild_recognised_as_makefile(tmp_path):
    (tmp_path / "Kbuild").write_text(
        "KBUILD_CFLAGS += -Werror -fno-delete-null-pointer-checks\n"
    )
    ctx = extract_flags(tmp_path)
    assert ctx.source == "makefile"
    assert ctx.werror_all is True
    assert ctx.delete_null_pointer_checks is False


def test_gnumakefile_recognised(tmp_path):
    (tmp_path / "GNUmakefile").write_text(
        "CFLAGS = -Werror=unused-result\n"
    )
    ctx = extract_flags(tmp_path)
    assert ctx.source == "makefile"
    assert ctx.werror_unused_result is True


def test_makefile_no_cflags_returns_absent(tmp_path):
    """Makefile present but no CFLAGS-family lines → fully absent.
    With no fallback sources, source stays 'absent' so consumers
    don't mistake a file-was-tried marker for actual signal."""
    (tmp_path / "Makefile").write_text(
        "all:\n"
        "\techo hello\n"
    )
    ctx = extract_flags(tmp_path)
    assert ctx.source == "absent"
    assert ctx.extraction_confidence == "absent"


# =====================================================================
# Source priority and fallback
# =====================================================================

def test_cc_beats_kconfig(tmp_path):
    """compile_commands.json is highest signal; if both present, it wins."""
    (tmp_path / "compile_commands.json").write_text(json.dumps([
        {"command": "gcc -Werror=unused-result foo.c"}
    ]))
    (tmp_path / ".config").write_text(
        "CONFIG_FORTIFY_SOURCE=y\nCONFIG_KASAN=y\n"
    )
    ctx = extract_flags(tmp_path)
    assert ctx.source == "compile_commands.json"
    assert ctx.werror_unused_result is True
    # kconfig signals NOT merged in — single-source per extraction
    assert ctx.sanitizers_enabled == ()


def test_kconfig_beats_makefile(tmp_path):
    """When both Kconfig and Makefile are present, Kconfig wins."""
    (tmp_path / ".config").write_text(
        "CONFIG_FORTIFY_SOURCE=y\n"
    )
    (tmp_path / "Makefile").write_text(
        "CFLAGS = -Werror=unused-result\n"
    )
    ctx = extract_flags(tmp_path)
    assert ctx.source == "kconfig"
    # Makefile signal NOT merged in
    assert ctx.werror_unused_result is None


# =====================================================================
# Schema invariants
# =====================================================================

def test_dataclass_is_frozen():
    ctx = BuildFlagsContext()
    with pytest.raises(Exception):  # FrozenInstanceError
        ctx.source = "modified"  # type: ignore[misc]


def test_default_context_is_safely_serializable():
    """Default context must JSON-serializable cleanly — Stage D evidence
    flows through prompt envelopes that serialize via stdlib json."""
    ctx = BuildFlagsContext()
    encoded = json.dumps({
        "source": ctx.source,
        "extraction_confidence": ctx.extraction_confidence,
        "werror_unused_result": ctx.werror_unused_result,
        "sanitizers_enabled": list(ctx.sanitizers_enabled),
        "relevant_configs": list(ctx.relevant_configs),
    })
    decoded = json.loads(encoded)
    assert decoded["source"] == "absent"
    assert decoded["sanitizers_enabled"] == []


def test_schema_version_pinned():
    """Bumping SCHEMA_VERSION should be deliberate — consumers cache
    on it. This test catches accidental shape changes that need a bump."""
    assert SCHEMA_VERSION == 1


def test_default_is_absent_not_empty():
    """The contract is: default == absent, NOT default == observed-nothing.
    Consumers must treat ``absent`` as "unknown", not "no hardening"."""
    ctx = BuildFlagsContext()
    assert ctx.extraction_confidence == "absent"
    assert ctx.source == "absent"
    # None means unknown, not False / disabled
    assert ctx.werror_unused_result is None
    assert ctx.werror_all is None
    assert ctx.fortify_source_level is None
    assert ctx.stack_protector_level is None
    assert ctx.delete_null_pointer_checks is None
