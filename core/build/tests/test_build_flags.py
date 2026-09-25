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
    # Explicitly disabled (0) — a real observation, distinct from
    # None = no mention. Consumers gate on level >= 2, so 0 can never
    # feed suppression; reporting None here hid the only TU's explicit
    # signal.
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
    """Within ONE command line the LAST flag wins (gcc semantics)."""
    target = _write_cc(tmp_path, [{
        "command": "gcc -fstack-protector-strong -fno-stack-protector foo.c",
    }])
    ctx = extract_flags(target)
    assert ctx.stack_protector_level == "none"


def test_cc_stack_protector_reenabled_last_wins(tmp_path):
    # The other direction of last-wins: disable then re-enable.
    target = _write_cc(tmp_path, [{
        "command": "gcc -fno-stack-protector -fstack-protector-strong foo.c",
    }])
    ctx = extract_flags(target)
    assert ctx.stack_protector_level == "strong"


def test_cc_stack_protector_strongest_across_tus(tmp_path):
    """Across TUs the field carries the MOST-HARDENED observed setting
    (the documented union rule): one unprotected TU must not flip a
    mostly -fstack-protector-strong project to "none" — Stage-D
    consumers weight mitigation evidence, and the least-hardened
    reading overstates exploitability."""
    target = _write_cc(tmp_path, [
        {"command": "gcc -fno-stack-protector legacy.c"},
        {"command": "gcc -fstack-protector-strong main.c"},
        {"command": "gcc -fstack-protector util.c"},
    ])
    ctx = extract_flags(target)
    assert ctx.stack_protector_level == "strong"


def test_cc_stack_protector_all_tus_disabled_is_none(tmp_path):
    target = _write_cc(tmp_path, [
        {"command": "gcc -fno-stack-protector a.c"},
        {"command": "gcc -fno-stack-protector b.c"},
    ])
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


# =====================================================================
# Hardened reads — the build artifacts live inside the scanned repo
# =====================================================================


def test_oversized_makefile_refused_gracefully(tmp_path, monkeypatch):
    """A byte-budget-busting Makefile degrades to 'absent' instead of
    being slurped unbounded."""
    import core.build.build_flags as bf
    monkeypatch.setattr(bf, "_MAX_MAKEFILE_BYTES", 16)
    (tmp_path / "Makefile").write_text(
        "CFLAGS = -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2\n",
    )
    ctx = extract_flags(tmp_path)
    assert ctx.source == "absent"
    assert ctx.extraction_confidence == "absent"


def test_oversized_compile_commands_falls_through(tmp_path, monkeypatch):
    """compile_commands.json over budget is refused; extraction falls
    through to the next source rather than raising."""
    import core.build.build_flags as bf
    monkeypatch.setattr(bf, "_MAX_COMPILE_COMMANDS_BYTES", 16)
    (tmp_path / "compile_commands.json").write_text(json.dumps([
        {"file": "a.c", "command": "gcc -fstack-protector-strong a.c"},
    ]))
    (tmp_path / "Makefile").write_text("CFLAGS = -fsanitize=address\n")
    ctx = extract_flags(tmp_path)
    assert ctx.source == "makefile"
    assert ctx.sanitizers_enabled == ("address",)


def test_fifo_makefile_refused_gracefully(tmp_path):
    """A FIFO planted at a build-artifact path must not hang or crash
    the extraction."""
    import os
    if not hasattr(os, "mkfifo"):
        pytest.skip("os.mkfifo not available on this platform")
    os.mkfifo(tmp_path / "Makefile")
    ctx = extract_flags(tmp_path)
    assert ctx.source == "absent"


def test_symlinked_compile_commands_out_of_tree_refused(tmp_path):
    """A symlink at the artifact path resolving OUTSIDE the target is
    refused (containment gate) and the extraction degrades. In-tree
    symlinks — the clangd `ln -s build/compile_commands.json .`
    layout — are accepted via their resolved path instead (see
    TestCompileCommandsCandidates in test_macro_config)."""
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps([
        {"file": "a.c", "command": "gcc -fstack-protector a.c"},
    ]))
    target = tmp_path / "repo"
    target.mkdir()
    (target / "compile_commands.json").symlink_to(outside)
    ctx = extract_flags(target)
    assert ctx.source == "absent"


def test_normal_sized_artifacts_still_parse(tmp_path):
    """Two-direction: the byte budgets are generous — ordinary files
    keep parsing."""
    (tmp_path / "Makefile").write_text(
        "CFLAGS = -fstack-protector-strong\n",
    )
    ctx = extract_flags(tmp_path)
    assert ctx.source == "makefile"
    assert ctx.stack_protector_level == "strong"


class TestPerCommandLastWinsUnion:
    """Per-command effective parse + documented most-hardened union,
    for every field (the rule the stack-protector field established;
    the sibling fields used first-match / any-position parses that
    misreported in BOTH directions)."""

    # -- cross-TU union: most-hardened observed setting per field ----

    def test_undef_tu_plus_level2_tu_unions_to_2(self, tmp_path):
        target = _write_cc(tmp_path, [
            {"command": "gcc -U_FORTIFY_SOURCE a.c"},
            {"command": "gcc -O2 -D_FORTIFY_SOURCE=2 b.c"},
        ])
        assert extract_flags(target).fortify_source_level == 2

    def test_fortify_levels_union_to_max_not_first(self, tmp_path):
        target = _write_cc(tmp_path, [
            {"command": "gcc -D_FORTIFY_SOURCE=1 a.c"},
            {"command": "gcc -D_FORTIFY_SOURCE=3 b.c"},
        ])
        assert extract_flags(target).fortify_source_level == 3

    def test_werror_unused_result_union_enforced_wins(self, tmp_path):
        target = _write_cc(tmp_path, [
            {"command": "gcc -Werror=unused-result a.c"},
            {"command": "gcc -Wno-error=unused-result b.c"},
        ])
        assert extract_flags(target).werror_unused_result is True

    def test_dnpc_union_checks_preserved_wins(self, tmp_path):
        # False (null checks preserved) is the hardened direction.
        target = _write_cc(tmp_path, [
            {"command": "gcc -fdelete-null-pointer-checks a.c"},
            {"command": "gcc -fno-delete-null-pointer-checks b.c"},
        ])
        assert extract_flags(target).delete_null_pointer_checks is False

    def test_dnpc_all_tus_delete_reports_true(self, tmp_path):
        # Union direction pin: with no hardened observation the
        # explicit weaker setting still surfaces.
        target = _write_cc(tmp_path, [
            {"command": "gcc -fdelete-null-pointer-checks a.c"},
        ])
        assert extract_flags(target).delete_null_pointer_checks is True

    def test_stack_protector_union_still_strongest(self, tmp_path):
        # Control: the landed strongest-across-TUs behavior holds
        # through the refactor.
        target = _write_cc(tmp_path, [
            {"command": "gcc -fno-stack-protector a.c"},
            {"command": "gcc -fstack-protector-strong b.c"},
        ])
        assert extract_flags(target).stack_protector_level == "strong"

    # -- within one command: the compiler's own resolution ------------

    def test_set_then_zero_is_effective_zero(self, tmp_path):
        # gcc-effective 0: reporting 3 here OVERSTATED hardening on an
        # unhardened build (exploitability down-weighting steered by a
        # flag the compile never honoured).
        target = _write_cc(tmp_path, [{
            "command": "gcc -D_FORTIFY_SOURCE=3 -D_FORTIFY_SOURCE=0 a.c",
        }])
        assert extract_flags(target).fortify_source_level == 0

    def test_distro_reset_then_set_idiom_keeps_signal(self, tmp_path):
        # The Fedora/Debian spec idiom: -U resets, -D re-arms. An
        # any-position -U voided the real level (signal loss on
        # exactly the distros that harden hardest).
        target = _write_cc(tmp_path, [{
            "command": "gcc -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 a.c",
        }])
        assert extract_flags(target).fortify_source_level == 3

    def test_werror_specificity_beats_position(self, tmp_path):
        # gcc: -Wno-error=unused-result excepts unused-result even
        # when a bare -Werror comes later.
        target = _write_cc(tmp_path, [{
            "command": "gcc -Wno-error=unused-result -Werror a.c",
        }])
        ctx = extract_flags(target)
        assert ctx.werror_unused_result is False
        assert ctx.werror_all is True

    def test_werror_specific_last_wins(self, tmp_path):
        target = _write_cc(tmp_path, [{
            "command": ("gcc -Werror=unused-result "
                        "-Wno-error=unused-result a.c"),
        }])
        assert extract_flags(target).werror_unused_result is False

    def test_dnpc_disable_then_reenable_is_true(self, tmp_path):
        # Last-wins within a command: the old any-position "-fno-"
        # check misread a command that disables then re-enables.
        target = _write_cc(tmp_path, [{
            "command": ("gcc -fno-delete-null-pointer-checks "
                        "-fdelete-null-pointer-checks a.c"),
        }])
        assert extract_flags(target).delete_null_pointer_checks is True


class TestModernKconfigSpellings:
    """Post-5.19 / modern hardening keys carry signal in BOTH .config
    directions; a member deleted from _HARDENING_CONFIGS fails here
    (the executable half of the tuple's transcription stamp)."""

    _MODERN = [
        "CONFIG_RANDSTRUCT_FULL",
        "CONFIG_RANDSTRUCT_PERFORMANCE",
        "CONFIG_KMSAN",
        "CONFIG_KCSAN",
        "CONFIG_KFENCE",
        "CONFIG_INIT_STACK_ALL_ZERO",
        "CONFIG_CFI_CLANG",
        "CONFIG_SHADOW_CALL_STACK",
        "CONFIG_STRICT_KERNEL_RWX",
    ]

    def test_enabled_modern_keys_surface(self, tmp_path):
        (tmp_path / ".config").write_text(
            "".join(f"{k}=y\n" for k in self._MODERN))
        ctx = extract_flags(tmp_path)
        got = dict(ctx.relevant_configs)
        for k in self._MODERN:
            assert got.get(k) is True, k
        # The sanitizer arm consumes the modern family too — a
        # KMSAN/KFENCE-instrumented kernel used to report ().
        assert "kmsan" in ctx.sanitizers_enabled
        assert "kcsan" in ctx.sanitizers_enabled
        assert "kfence" in ctx.sanitizers_enabled

    def test_disabled_modern_keys_surface(self, tmp_path):
        (tmp_path / ".config").write_text(
            "".join(f"# {k} is not set\n" for k in self._MODERN))
        ctx = extract_flags(tmp_path)
        got = dict(ctx.relevant_configs)
        for k in self._MODERN:
            assert got.get(k) is False, k
        assert ctx.sanitizers_enabled == ()

    def test_pre519_randstruct_spelling_still_recognised(self, tmp_path):
        (tmp_path / ".config").write_text(
            "CONFIG_GCC_PLUGIN_RANDSTRUCT=y\n")
        got = dict(extract_flags(tmp_path).relevant_configs)
        assert got.get("CONFIG_GCC_PLUGIN_RANDSTRUCT") is True


class TestMakefileAssignmentGrammar:
    def test_modern_assignment_operators_recognised(self, tmp_path):
        # GNU make ::= (POSIX) and 4.4's :::= dropped whole CFLAGS
        # lines from the scan.
        (tmp_path / "Makefile").write_text(
            "CFLAGS ::= -D_FORTIFY_SOURCE=2\n"
            "CXXFLAGS :::= -fstack-protector-strong\n",
        )
        ctx = extract_flags(tmp_path)
        assert ctx.fortify_source_level == 2
        assert ctx.stack_protector_level == "strong"

    def test_backslash_continuations_join(self, tmp_path):
        # make splices continuation lines; the scan used to keep only
        # the first physical line of a continued assignment.
        (tmp_path / "Makefile").write_text(
            "CFLAGS = -O2 \\\n\t-fstack-protector-strong\n",
        )
        assert extract_flags(tmp_path).stack_protector_level == "strong"

    def test_lowercase_makefile_name_recognised(self, tmp_path):
        # make's own lookup order includes `makefile`; the name set
        # had drifted against the detector's make entry.
        (tmp_path / "makefile").write_text(
            "CFLAGS = -fstack-protector\n",
        )
        assert extract_flags(tmp_path).stack_protector_level == "weak"

    def test_crlf_continuation_folds_like_lf(self, tmp_path):
        """A CRLF checkout of a continued assignment harvests the
        same flags as its LF twin.

        The direction matters: the extractors are last-wins, so an
        UN-folded continuation truncates the flag stream at the
        first physical line — this twin puts the hardening flag
        first and its disablement on the continued line, so a fold
        failure would report STRONGER hardening than the real build
        (suppression-grade evidence on the trust-gated lane)."""
        body_lf = (
            "CFLAGS = -fstack-protector-strong \\\n"
            "\t-fno-stack-protector -D_FORTIFY_SOURCE=0\n"
        )
        ctxs = {}
        for name, data in (
            ("lf", body_lf.encode()),
            ("crlf", body_lf.replace("\n", "\r\n").encode()),
        ):
            root = tmp_path / name
            root.mkdir()
            (root / "Makefile").write_bytes(data)
            ctxs[name] = extract_flags(root)
        assert ctxs["lf"] == ctxs["crlf"]
        # Non-vacuous, in the load-bearing direction: the disabling
        # flags on the continued line win on BOTH twins.
        assert ctxs["crlf"].stack_protector_level == "none"
        assert ctxs["crlf"].fortify_source_level == 0
