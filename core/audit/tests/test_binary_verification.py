"""Tests for binary-target mechanical verification (Phase 1 + 2)."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from core.audit.binary_verification import decompiler_rules_for_hypothesis


class TestDecompilerRuleSelection:
    def test_cwe134_selects_format_string(self):
        rules = decompiler_rules_for_hypothesis("printf is bad", cwe="CWE-134")
        names = [r.name for r in rules]
        assert "format-string.yaml" in names

    def test_cwe120_selects_buffer_overflow(self):
        rules = decompiler_rules_for_hypothesis("overflow", cwe="CWE-120")
        names = [r.name for r in rules]
        assert "buffer-overflow.yaml" in names

    def test_cwe78_selects_command_injection(self):
        rules = decompiler_rules_for_hypothesis("injection", cwe="CWE-78")
        names = [r.name for r in rules]
        assert "command-injection.yaml" in names

    def test_keyword_format_string(self):
        rules = decompiler_rules_for_hypothesis("format string vulnerability")
        names = [r.name for r in rules]
        assert "format-string.yaml" in names

    def test_keyword_strcpy(self):
        rules = decompiler_rules_for_hypothesis("strcpy to stack buffer")
        names = [r.name for r in rules]
        assert "buffer-overflow.yaml" in names

    def test_keyword_use_after_free(self):
        rules = decompiler_rules_for_hypothesis("use after free of ptr")
        names = [r.name for r in rules]
        assert "memory-safety.yaml" in names

    def test_no_match_returns_all(self):
        rules = decompiler_rules_for_hypothesis("something obscure")
        assert len(rules) >= 3

    def test_cwe_normalisation(self):
        rules_dash = decompiler_rules_for_hypothesis("", cwe="CWE-134")
        rules_under = decompiler_rules_for_hypothesis("", cwe="CWE_134")
        rules_bare = decompiler_rules_for_hypothesis("", cwe="134")
        assert [r.name for r in rules_dash] == [r.name for r in rules_under]
        assert [r.name for r in rules_dash] == [r.name for r in rules_bare]



class TestNoAutoLaunchSurface:
    """The dead Frida auto-launch path was removed — the module must not
    grow it back silently. Dynamic engagement lives in dynamic_sweep /
    frida_observe instead."""

    def test_auto_launch_helpers_removed(self):
        import core.audit.binary_verification as bv
        assert not hasattr(bv, "auto_launch_and_observe")
        assert not hasattr(bv, "can_auto_launch")

    def test_orchestrator_has_no_binary_path_gate(self):
        import inspect

        from core.audit import orchestrator
        src = inspect.getsource(orchestrator._sweep_validate)
        assert 'getattr(config, "_binary_path"' not in src


class TestSweepValidateBinary:
    """Verify _sweep_validate handles binary targets."""

    def test_binary_skips_prefilter(self):
        from core.audit.orchestrator import ReviewOutcome, _sweep_validate

        outcome = ReviewOutcome(
            file="binary:target",
            function="lolwot",
            status="finding",
            body="format string bug",
            hypothesis="format string: printf called with variable",
            line=0,
        )

        mock_config = MagicMock()
        mock_config.target_path = Path("/nonexistent")
        mock_config.sweep_validate_findings = True
        mock_config.codeql_db_path = None
        # A bare MagicMock out_dir is truthy and walks into the
        # domain-model loader; the real config carries a Path or None.
        mock_config.out_dir = None

        result = _sweep_validate(
            outcome, mock_config,
            source_override="void lolwot(char *s) { printf(s); }",
            is_binary=True,
        )
        assert result.file == "binary:target"

    def test_binary_auto_detected_from_file_path(self):
        from core.audit.orchestrator import ReviewOutcome, _sweep_validate

        outcome = ReviewOutcome(
            file="binary:foo",
            function="main",
            status="finding",
            body="suspicious pattern",
            hypothesis="something suspicious",
            line=0,
        )

        mock_config = MagicMock()
        mock_config.target_path = Path("/nonexistent")
        mock_config.codeql_db_path = None
        mock_config.out_dir = None

        result = _sweep_validate(outcome, mock_config)
        assert result is not None

    def test_decompilation_temp_file_used_for_sweep(self):
        """When source_override is set, the standard hypothesis-to-rule
        flow should receive a real .c file path that exists."""
        from core.audit.orchestrator import _write_decompilation_tmpfile

        decomp = "void lolwot(char *s) { printf(s); }"
        tmp_dir = _write_decompilation_tmpfile(decomp, "lolwot")
        assert tmp_dir is not None
        assert (tmp_dir / "lolwot.c").exists()
        assert (tmp_dir / "lolwot.c").read_text() == decomp

        import shutil
        shutil.rmtree(tmp_dir)

    def test_decompilation_stub_returns_none(self):
        from core.audit.orchestrator import _write_decompilation_tmpfile
        assert _write_decompilation_tmpfile("(no decompilation)", "f") is None
        assert _write_decompilation_tmpfile("", "f") is None


def _unlink_chain_rules(chain):
    """Remove the on-disk audit_sweep_ rule files a chain carries.

    Production unlinks them in _run_tool_chain's finally; tests that
    only build the chain must clean up themselves or every run strands
    rule files in the system temp dir.
    """
    import os
    for entry in chain:
        rule = entry.get("config", {}).get("rule") or ""
        if isinstance(rule, str) and \
                os.path.basename(rule).startswith("audit_sweep_"):
            Path(rule).unlink(missing_ok=True)


class TestStandardChainOnBinary:
    """The standard _hypothesis_to_tool_chain should produce a normal
    tool chain even when called with a .c filename (the temp file).
    The binary-specific decompiler rules run as a fallback pass."""

    def test_standard_chain_for_c_file(self):
        from core.audit.orchestrator import _hypothesis_to_tool_chain
        chain = _hypothesis_to_tool_chain(
            "format string vulnerability",
            "lolwot.c",
            cwe="CWE-134",
        )
        types = {e["type"] for e in chain}
        _unlink_chain_rules(chain)
        assert "semgrep" in types or "smt" in types or len(chain) > 0

    def test_decompiler_rules_extend_chain(self):
        """Binary path appends decompiler rules to the chain."""
        from core.audit.orchestrator import _hypothesis_to_tool_chain

        chain = _hypothesis_to_tool_chain(
            "format string vulnerability", "lolwot.c", cwe="CWE-134",
        )
        base_len = len(chain)
        _unlink_chain_rules(chain)

        rules = decompiler_rules_for_hypothesis("format string", cwe="CWE-134")
        for r in rules:
            chain.append({"type": "semgrep", "config": {"rule": str(r)}})

        assert len(chain) > base_len
        assert any("decompiler" in e["config"].get("rule", "") for e in chain)

    def test_rules_are_valid_semgrep_entries(self):
        """decompiler rules should be valid semgrep chain entries."""
        rules = decompiler_rules_for_hypothesis("printf", cwe="CWE-134")
        chain = [{"type": "semgrep", "config": {"rule": str(r)}} for r in rules]
        assert len(chain) >= 1
        for entry in chain:
            assert entry["type"] == "semgrep"
            assert Path(entry["config"]["rule"]).exists()

    def test_source_path_unchanged(self):
        from core.audit.orchestrator import _hypothesis_to_tool_chain
        chain = _hypothesis_to_tool_chain(
            "format string vulnerability",
            "src/main.c",
            cwe="CWE-134",
        )
        _unlink_chain_rules(chain)
        assert len(chain) > 0


class TestR2Normaliser:
    def test_printf_normalised_amd64(self):
        from core.audit.orchestrator import _normalise_r2_decompilation

        r2 = """void sym.lolwot (char *arg1) {
        rax = qword [format]
        rdi = rax
        eax = 0
        sym.imp.printf () // int printf(0)
}"""
        result = _normalise_r2_decompilation(r2)
        assert "printf(" in result
        assert "sym.imp.printf" not in result

    def test_puts_normalised(self):
        from core.audit.orchestrator import _normalise_r2_decompilation

        r2 = """        rdi = rax
        sym.imp.puts ()"""
        result = _normalise_r2_decompilation(r2)
        assert "puts(" in result

    def test_no_args_preserved(self):
        from core.audit.orchestrator import _normalise_r2_decompilation

        r2 = """        sym.imp.getpid ()"""
        result = _normalise_r2_decompilation(r2)
        assert "sym.imp.getpid" in result

    def test_passthrough_non_r2(self):
        from core.audit.orchestrator import _normalise_r2_decompilation

        source = "void foo(char *s) { printf(s); }"
        assert _normalise_r2_decompilation(source) == source

    def test_aarch64_printf(self):
        from core.audit.orchestrator import _normalise_r2_decompilation

        r2 = """        x0 = arg1
        sym.imp.printf ()"""
        result = _normalise_r2_decompilation(r2)
        assert "printf(arg1)" in result

    def test_aarch64_two_args(self):
        from core.audit.orchestrator import _normalise_r2_decompilation

        r2 = """        x0 = qword [format]
        x1 = arg2
        sym.imp.fprintf ()"""
        result = _normalise_r2_decompilation(r2)
        assert "fprintf(" in result
        assert "qword [format]" in result

    def test_arm32(self):
        from core.audit.orchestrator import _normalise_r2_decompilation

        r2 = """        r0 = arg1
        sym.imp.printf ()"""
        result = _normalise_r2_decompilation(r2)
        assert "printf(arg1)" in result

    def test_sparc_printf(self):
        from core.audit.orchestrator import _normalise_r2_decompilation

        r2 = """        o0 = arg1
        sym.imp.printf ()"""
        result = _normalise_r2_decompilation(r2)
        assert "printf(arg1)" in result

    def test_sparc_two_args(self):
        from core.audit.orchestrator import _normalise_r2_decompilation

        r2 = """        o0 = qword [format]
        o1 = arg2
        sym.imp.sprintf ()"""
        result = _normalise_r2_decompilation(r2)
        assert "sprintf(" in result
        assert "qword [format]" in result

    def test_x86_32(self):
        from core.audit.orchestrator import _normalise_r2_decompilation

        r2 = """        eax = arg1
        sym.imp.printf ()"""
        result = _normalise_r2_decompilation(r2)
        assert "printf(arg1)" in result

    def test_mips(self):
        from core.audit.orchestrator import _normalise_r2_decompilation

        r2 = """        a0 = arg1
        sym.imp.printf ()"""
        result = _normalise_r2_decompilation(r2)
        assert "printf(arg1)" in result

    def test_riscv(self):
        from core.audit.orchestrator import _normalise_r2_decompilation

        r2 = """        a0 = arg1
        a1 = arg2
        a4 = 0
        a5 = 0
        a6 = 0
        a7 = 0
        sym.imp.printf ()"""
        result = _normalise_r2_decompilation(r2)
        assert "printf(" in result

    def test_macho_underscore_prefix(self):
        from core.audit.orchestrator import _normalise_r2_decompilation

        r2 = """        rdi = arg1
        sym.imp._printf ()"""
        result = _normalise_r2_decompilation(r2)
        assert "printf(arg1)" in result

    def test_direct_sym_no_imp(self):
        from core.audit.orchestrator import _normalise_r2_decompilation

        r2 = """        rdi = arg1
        sym.printf ()"""
        result = _normalise_r2_decompilation(r2)
        assert "printf(arg1)" in result

    def test_pe_msvcrt_printf(self):
        from core.audit.orchestrator import _normalise_r2_decompilation

        r2 = """        rcx = arg1
        sym.imp.MSVCRT.dll_printf ()"""
        result = _normalise_r2_decompilation(r2)
        assert "printf(arg1)" in result
        assert "MSVCRT" not in result

    def test_pe_ucrtbase_sprintf(self):
        from core.audit.orchestrator import _normalise_r2_decompilation

        r2 = """        rcx = buf
        rdx = fmt
        sym.imp.ucrtbase.dll_sprintf ()"""
        result = _normalise_r2_decompilation(r2)
        assert "sprintf(buf, fmt)" in result

    def test_win64_two_args(self):
        from core.audit.orchestrator import _normalise_r2_decompilation

        r2 = """        rcx = arg1
        rdx = arg2
        sym.imp.KERNEL32.dll_WriteFile ()"""
        result = _normalise_r2_decompilation(r2)
        assert "WriteFile(arg1, arg2)" in result


class TestDecompilationTmpfileNameSanitisation:
    """The function name comes from binary symbol tables — path
    separators and ``..`` must not escape the temp directory (same
    rule as rules.save_rule's rule_id check)."""

    def test_slash_rejected(self):
        from core.audit.orchestrator import _write_decompilation_tmpfile
        assert _write_decompilation_tmpfile(
            "void f() {}", "../../tmp/evil") is None
        assert _write_decompilation_tmpfile(
            "void f() {}", "sub/dir") is None

    def test_backslash_rejected(self):
        from core.audit.orchestrator import _write_decompilation_tmpfile
        assert _write_decompilation_tmpfile(
            "void f() {}", "..\\evil") is None

    def test_dotdot_rejected(self):
        from core.audit.orchestrator import _write_decompilation_tmpfile
        assert _write_decompilation_tmpfile("void f() {}", "a..b") is None

    def test_mangled_cpp_name_still_accepted(self):
        """C++-mangled and colon-bearing names are legitimate symbol
        names and must keep working."""
        import shutil

        from core.audit.orchestrator import _write_decompilation_tmpfile
        tmp_dir = _write_decompilation_tmpfile(
            "void f() {}", "_ZN3Foo3barEv")
        assert tmp_dir is not None
        assert (tmp_dir / "_ZN3Foo3barEv.c").is_file()
        shutil.rmtree(tmp_dir)
