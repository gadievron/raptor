"""Tests for core.audit.compiler_sweep.

The sandbox entry (``core.sandbox.context.run``) is monkeypatched in
every test that compiles: the spy records the sandbox kwargs (so we can
assert ``block_network=True`` etc.) and then runs the compiler directly
— the suite must pass on hosts where namespace isolation is
unavailable, and must never require network.

Real gcc / clang are used where present; every compiling test is
guarded by a skipif so the suite degrades gracefully on hosts without
either toolchain.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from core.audit import compiler_sweep
from core.audit.compiler_sweep import (
    COMPILER_CWE_MAP,
    compiler_applicable,
    extract_hypothesis_identifiers,
    get_compiler_check_role,
    run_compiler_analyzer_sweep,
)
from core.audit.evidence_grade import is_tool_evidence
from core.audit.sweep import SweepResult
from core.audit.tests._live_transport import (
    run_compiler_analyzer_sweep_guarded,
)

FIXTURES = Path(__file__).parent / "fixtures" / "compiler_sweep"

compiler_sweep._reset_probe_cache()
_GCC = compiler_sweep._gcc_analyzer()
_CLANG = compiler_sweep._clang_path()
HAVE_GCC = _GCC is not None
HAVE_CLANG = _CLANG is not None
HAVE_ANY = HAVE_GCC or HAVE_CLANG

needs_compiler = pytest.mark.skipif(
    not HAVE_ANY, reason="neither gcc -fanalyzer nor clang installed",
)
needs_clang = pytest.mark.skipif(not HAVE_CLANG, reason="clang not installed")
needs_gcc = pytest.mark.skipif(
    not HAVE_GCC, reason="gcc -fanalyzer not installed",
)


@pytest.fixture(autouse=True)
def _fresh_probe_cache():
    compiler_sweep._reset_probe_cache()
    compiler_sweep._reset_tu_cache()
    yield
    compiler_sweep._reset_probe_cache()
    compiler_sweep._reset_tu_cache()


@pytest.fixture
def sandbox_spy(monkeypatch):
    """Record sandbox kwargs, then execute the compiler directly."""
    calls: list[dict] = []

    def fake_sandbox_run(cmd, **kwargs):
        calls.append({"cmd": cmd, **kwargs})
        fwd = {
            k: kwargs[k]
            for k in ("capture_output", "text", "timeout", "cwd")
            if k in kwargs
        }
        try:
            from core.config import RaptorConfig
            env = RaptorConfig.get_safe_env()
        except ImportError:
            env = None
        return subprocess.run(cmd, check=False, env=env, **fwd)

    monkeypatch.setattr("core.sandbox.context.run", fake_sandbox_run)
    return calls


def _target_with(tmp_path: Path, *fixture_names: str) -> Path:
    target = tmp_path / "repo"
    target.mkdir(exist_ok=True)
    for name in fixture_names:
        shutil.copy(FIXTURES / name, target / name)
    return target


def _guarded_compiler_sweep(
    *, gcc_probed: bool = HAVE_GCC, **kwargs: Any,
) -> SweepResult:
    """Live analyzer runs route through the transport guard: runtime
    degradation (deadline, signal-killed compile, spawn OSError, a
    gcc probe lost under load) skips with the transport's reason;
    every product classification passes through untouched for the
    caller's own hard assertions. ``gcc_probed`` pins the toolchain
    identity this module observed at collection time (legs that
    deliberately mask gcc pass False)."""
    return run_compiler_analyzer_sweep_guarded(
        gcc_probed=gcc_probed, **kwargs,
    )


def _sweep(tmp_path, fixture, cwe, hypothesis, function_name="f",
           line_start=0, line_end=0, gcc_probed: bool = HAVE_GCC):
    target = _target_with(tmp_path, fixture)
    out_dir = tmp_path / "out"
    return _guarded_compiler_sweep(
        gcc_probed=gcc_probed,
        target_path=target,
        file_path=fixture,
        function_name=function_name,
        hypothesis=hypothesis,
        cwe=cwe,
        line_start=line_start,
        line_end=line_end,
        out_dir=out_dir,
    )


# ---------------------------------------------------------------------------
# Outcome mapping per CWE family
# ---------------------------------------------------------------------------


@needs_compiler
class TestFamilyOutcomes:
    def test_use_after_free_confirmed(self, tmp_path, sandbox_spy):
        result = _sweep(
            tmp_path, "uaf.c", "CWE-416",
            "use-after-free of `p` in use_after_free",
            function_name="use_after_free", line_start=3, line_end=9,
        )
        assert result.outcome == "confirmed"
        assert result.tool == "compiler"
        assert result.rule_id.startswith("compiler:")
        assert result.matches and result.matches[0]["line"] == 8
        assert is_tool_evidence(result.rule_id)

    def test_double_free_confirmed(self, tmp_path, sandbox_spy):
        result = _sweep(
            tmp_path, "double_free.c", "CWE-415",
            "double free of `buf` in release_twice",
            function_name="release_twice", line_start=3, line_end=8,
        )
        assert result.outcome == "confirmed"

    def test_null_deref_confirmed(self, tmp_path, sandbox_spy):
        result = _sweep(
            tmp_path, "null_deref.c", "CWE-476",
            "NULL pointer dereference of `ptr` when cond is false",
            function_name="read_maybe_null", line_start=3, line_end=6,
        )
        assert result.outcome == "confirmed"

    def test_malloc_leak_confirmed(self, tmp_path, sandbox_spy):
        result = _sweep(
            tmp_path, "malloc_leak.c", "CWE-401",
            "memory leak of `scratch` in forget_buffer",
            function_name="forget_buffer", line_start=3, line_end=8,
        )
        assert result.outcome == "confirmed"

    def test_format_string_confirmed(self, tmp_path, sandbox_spy):
        result = _sweep(
            tmp_path, "fmt.c", "CWE-134",
            "attacker-controlled format string `msg` reaches printf",
            function_name="log_user", line_start=3, line_end=5,
        )
        assert result.outcome == "confirmed"

    def test_constant_oob_confirmed(self, tmp_path, sandbox_spy):
        result = _sweep(
            tmp_path, "oob.c", "CWE-787",
            "memcpy writes 32 bytes into 8-byte `dst`",
            function_name="copy_fixed", line_start=3, line_end=7,
        )
        assert result.outcome == "confirmed"

    def test_unused_result_confirmed(self, tmp_path, sandbox_spy):
        # CWE-252 family: -Wunused-result on a warn_unused_result-
        # attributed callee whose result is discarded. Corroborates
        # the fail_open channel's ignored-return leg.
        result = _sweep(
            tmp_path, "unused_result.c", "CWE-252",
            "the return value of `must_check` is ignored in "
            "ignores_result",
            function_name="ignores_result", line_start=5, line_end=8,
        )
        assert result.outcome == "confirmed"
        assert "-Wunused-result" in result.rule_id
        assert is_tool_evidence(result.rule_id)

    def test_unused_result_checked_is_inconclusive_not_refuted(
        self, tmp_path, sandbox_spy,
    ):
        # The checked caller produces no diagnostic in range; the
        # family is confirm-only (fires only for TU-visible attributed
        # callees) so silence must never read as refutation.
        result = _sweep(
            tmp_path, "unused_result.c", "CWE-252",
            "the return value of `must_check` is ignored in "
            "checks_result",
            function_name="checks_result", line_start=10, line_end=14,
        )
        assert result.outcome == "inconclusive"


# ---------------------------------------------------------------------------
# In-range / out-of-range
# ---------------------------------------------------------------------------


@needs_compiler
class TestRangeFiltering:
    def test_diagnostic_outside_range_is_refuted(self, tmp_path, sandbox_spy):
        # UAF diagnostic is at line 8; a range elsewhere in the file
        # sees a clean, reliable-family run → refuted.
        result = _sweep(
            tmp_path, "uaf.c", "CWE-416",
            "use-after-free of `p`",
            function_name="use_after_free", line_start=100, line_end=120,
        )
        assert result.outcome == "refuted"
        assert not result.matches

    def test_zero_range_matches_whole_file(self, tmp_path, sandbox_spy):
        result = _sweep(
            tmp_path, "uaf.c", "CWE-416",
            "use-after-free of `p`",
            function_name="use_after_free", line_start=0, line_end=0,
        )
        assert result.outcome == "confirmed"


# ---------------------------------------------------------------------------
# Guarded fixtures (negative controls): must NOT confirm
# ---------------------------------------------------------------------------


@needs_compiler
class TestGuardedNegativeControls:
    def test_null_out_after_free_not_confirmed(self, tmp_path, sandbox_spy):
        result = _sweep(
            tmp_path, "uaf_guarded.c", "CWE-416",
            "use-after-free of `p` in guarded_free",
            function_name="guarded_free", line_start=5, line_end=13,
        )
        # Reliable family + clean analyzer run → the guard earns a
        # mechanical refutation, not just an absence of confirmation.
        assert result.outcome == "refuted"

    def test_bounds_checked_copy_not_confirmed(self, tmp_path, sandbox_spy):
        result = _sweep(
            tmp_path, "bounded_copy.c", "CWE-787",
            "buffer overflow: `len` bytes copied into 8-byte `dst`",
            function_name="copy_bounded", line_start=5, line_end=12,
        )
        assert result.outcome != "confirmed"
        # OOB is confirm-only (compiler proves only constant cases):
        # silence must be inconclusive, never refuted.
        assert result.outcome == "inconclusive"


# ---------------------------------------------------------------------------
# Compile failure must NEVER read as refutation
# ---------------------------------------------------------------------------


@needs_compiler
class TestCompileFailure:
    def test_missing_generated_header_inconclusive(self, tmp_path, sandbox_spy):
        result = _sweep(
            tmp_path, "broken.c", "CWE-416",
            "use-after-free of `thing` in parse_thing",
            function_name="parse_thing", line_start=3, line_end=5,
        )
        assert result.outcome == "inconclusive"
        assert result.outcome not in ("refuted", "confirmed")
        assert any("compile failed" in e for e in result.errors)


# ---------------------------------------------------------------------------
# Identifier negative control
# ---------------------------------------------------------------------------


@needs_compiler
class TestIdentifierAttribution:
    def test_diagnostic_on_other_identifier_not_confirmed(
        self, tmp_path, sandbox_spy,
    ):
        # two_ptrs.c has a real UAF on `p`; the hypothesis names only
        # `other_buf` — the diagnostic must not confirm it.
        result = _sweep(
            tmp_path, "two_ptrs.c", "CWE-416",
            "use-after-free of `other_buf` in mixed_buffers",
            function_name="mixed_buffers", line_start=7, line_end=15,
        )
        assert result.outcome == "inconclusive"
        assert result.details and result.details.get("unattributed")

    def test_prose_only_hypothesis_still_confirms(self, tmp_path, sandbox_spy):
        # No identifier named at all → attribution check is skipped.
        result = _sweep(
            tmp_path, "uaf.c", "CWE-416",
            "memory is freed and then used",
            function_name="use_after_free", line_start=3, line_end=9,
        )
        assert result.outcome == "confirmed"


class TestExtractIdentifiers:
    def test_backtick_ids_win(self):
        ids = extract_hypothesis_identifiers(
            "overflow of `dst` when `count` is large", "int x;", "f",
        )
        assert ids == ["dst", "count"]

    def test_stop_words_filtered(self):
        ids = extract_hypothesis_identifiers(
            "`buffer` overflow via `memcpy_wrapper`", "", "f",
        )
        assert ids == ["memcpy_wrapper"]

    def test_prose_must_be_grounded_in_source(self):
        source = "int msg_qbytes = limit;"
        ids = extract_hypothesis_identifiers(
            "negative msg_qbytes bypasses the limit check", source, "f",
        )
        assert "msg_qbytes" in ids
        assert "bypasses" not in ids

    def test_function_name_excluded(self):
        ids = extract_hypothesis_identifiers(
            "`parse_packet` frees `hdr` twice", "", "parse_packet",
        )
        assert ids == ["hdr"]

    def test_no_identifiers_at_all(self):
        assert extract_hypothesis_identifiers(
            "memory is freed and then used", "int p;", "f",
        ) == []


# ---------------------------------------------------------------------------
# Sandbox invocation contract
# ---------------------------------------------------------------------------


@needs_compiler
class TestSandboxInvocation:
    def test_sandbox_used_with_network_deny(self, tmp_path, sandbox_spy):
        target = _target_with(tmp_path, "uaf.c")
        out_dir = tmp_path / "out"
        _guarded_compiler_sweep(
            target_path=target,
            file_path="uaf.c",
            function_name="use_after_free",
            hypothesis="use-after-free of `p`",
            cwe="CWE-416",
            line_start=3,
            line_end=9,
            out_dir=out_dir,
        )
        assert len(sandbox_spy) == 1
        call = sandbox_spy[0]
        assert call["block_network"] is True
        assert call["target"] == str(target)
        assert str(out_dir) in call["output"]
        assert isinstance(call["cmd"], list)
        assert all(isinstance(a, str) for a in call["cmd"])
        assert "timeout" in call

    def test_single_tu_only_no_build_system(self, tmp_path, sandbox_spy):
        _sweep(
            tmp_path, "uaf.c", "CWE-416", "use-after-free of `p`",
            function_name="use_after_free", line_start=3, line_end=9,
        )
        cmd = sandbox_spy[0]["cmd"]
        binary = Path(cmd[0]).name
        assert binary in ("gcc", "clang", "cc")
        assert not any(b in cmd[0] for b in ("make", "cmake", "configure"))
        # exactly one repo file on the command line: the TU itself
        repo_files = [a for a in cmd if a.endswith(".c")]
        assert repo_files == [a for a in cmd if "uaf.c" in a]

    def test_no_sandbox_no_compile(self, tmp_path, monkeypatch):
        # When core.sandbox cannot be imported, the sweep must refuse
        # to run the compiler on untrusted source (never unsandboxed).
        import builtins
        real_import = builtins.__import__

        def blocked(name, *args, **kwargs):
            if name == "core.sandbox.context":
                raise ImportError("blocked for test")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", blocked)
        result = _sweep(
            tmp_path, "uaf.c", "CWE-416", "use-after-free of `p`",
        )
        assert result.outcome == "error"
        assert any("refusing" in e for e in result.errors)


# ---------------------------------------------------------------------------
# Toolchain availability / fallback
# ---------------------------------------------------------------------------


class TestToolchainFallback:
    # slow: masking gcc sends the sweep down the real-clang analyzer
    # path end to end — genuinely over the default-tier time budget.
    @pytest.mark.slow
    @needs_clang
    def test_gcc_missing_falls_back_to_clang(
        self, tmp_path, sandbox_spy, monkeypatch,
    ):
        real_which = shutil.which
        monkeypatch.setattr(
            shutil, "which",
            lambda name, *a, **k: None if name == "gcc" else real_which(name, *a, **k),
        )
        result = _sweep(
            tmp_path, "uaf.c", "CWE-416",
            "use-after-free of `p` in use_after_free",
            function_name="use_after_free", line_start=3, line_end=9,
            # gcc is masked ON PURPOSE: clang is this leg's expected
            # analyzer, not a degraded fallback, so the guard's
            # probe-flip arm must stay out of the way (the transport
            # arms still cover the live clang run).
            gcc_probed=False,
        )
        assert result.details and result.details["compiler"] == "clang"
        assert result.outcome == "confirmed"

    def test_both_missing_is_error(self, tmp_path, monkeypatch):
        monkeypatch.setattr(shutil, "which", lambda *a, **k: None)
        # Deliberate toolchain fault: this leg MINTS the not-installed
        # error on purpose, so it bypasses the transport guard (which
        # reads exactly that shape as a degraded runtime) and calls
        # the sweep raw.
        target = _target_with(tmp_path, "uaf.c")
        result = run_compiler_analyzer_sweep(
            target_path=target,
            file_path="uaf.c",
            function_name="f",
            hypothesis="use-after-free of `p`",
            cwe="CWE-416",
            out_dir=tmp_path / "out",
        )
        assert result.outcome == "error"
        assert any("not installed" in e for e in result.errors)

    @needs_compiler
    def test_probe_is_cached(self, monkeypatch):
        first = compiler_sweep._gcc_analyzer()

        def boom(*args, **kwargs):
            raise AssertionError("probe re-ran despite cache")

        monkeypatch.setattr(compiler_sweep.subprocess, "run", boom)
        assert compiler_sweep._gcc_analyzer() == first


# ---------------------------------------------------------------------------
# Input validation / mapping edges (no compiler needed)
# ---------------------------------------------------------------------------


class TestMappingEdges:
    def test_unmapped_cwe_inconclusive_without_compiling(
        self, tmp_path, sandbox_spy,
    ):
        result = _sweep(
            tmp_path, "uaf.c", "CWE-89", "SQL injection via `p`",
        )
        assert result.outcome == "inconclusive"
        assert sandbox_spy == []

    def test_non_c_file_inconclusive(self, tmp_path, sandbox_spy):
        target = tmp_path / "repo"
        target.mkdir()
        (target / "app.py").write_text("x = 1\n")
        result = _guarded_compiler_sweep(
            target_path=target, file_path="app.py", function_name="f",
            hypothesis="use-after-free of `x`", cwe="CWE-416",
            out_dir=tmp_path / "out",
        )
        assert result.outcome == "inconclusive"
        assert sandbox_spy == []

    def test_path_escape_is_error(self, tmp_path, sandbox_spy):
        target = tmp_path / "repo"
        target.mkdir()
        result = _guarded_compiler_sweep(
            target_path=target, file_path="../evil.c", function_name="f",
            hypothesis="h", cwe="CWE-416", out_dir=tmp_path / "out",
        )
        assert result.outcome == "error"
        assert sandbox_spy == []

    def test_missing_file_is_error(self, tmp_path, sandbox_spy):
        target = tmp_path / "repo"
        target.mkdir()
        result = _guarded_compiler_sweep(
            target_path=target, file_path="ghost.c", function_name="f",
            hypothesis="h", cwe="CWE-416", out_dir=tmp_path / "out",
        )
        assert result.outcome == "error"

    def test_cwe_normalisation(self):
        assert compiler_applicable("416")
        assert compiler_applicable("cwe-416")
        assert not compiler_applicable("CWE-89")
        assert not compiler_applicable("")

    def test_role_verification_for_mapped_only(self):
        for cwe in COMPILER_CWE_MAP:
            assert get_compiler_check_role(cwe) == "verification"
        assert get_compiler_check_role("CWE-89") == "detection"
        assert get_compiler_check_role("") == "detection"


# ---------------------------------------------------------------------------
# Evidence grading + orchestrator chain integration
# ---------------------------------------------------------------------------


class TestIntegration:
    def test_compiler_namespace_is_tool_evidence(self):
        assert is_tool_evidence("compiler:-Wanalyzer-use-after-free")
        assert is_tool_evidence("compiler:unix.Malloc")
        assert is_tool_evidence("compiler")
        assert is_tool_evidence("compiler:-Wformat-security+semgrep:rule")
        assert not is_tool_evidence("llm-claimed:compiler")

    def test_cwe_chain_gets_compiler_entry_before_smt(self):
        from core.audit.orchestrator import _cwe_fallback_chain
        chain = _cwe_fallback_chain("CWE-416")
        types = [e["type"] for e in chain]
        assert "compiler" in types
        assert types.index("compiler") < types.index("smt")
        entry = chain[types.index("compiler")]
        assert entry["config"]["cwe"] == "CWE-416"

    def test_unmapped_cwe_gets_no_compiler_entry(self):
        from core.audit.orchestrator import _cwe_fallback_chain
        chain = _cwe_fallback_chain("CWE-89")
        assert "compiler" not in [e["type"] for e in chain]

    def test_tier_counters_have_compiler(self):
        from core.audit.orchestrator import _make_tier_counters
        assert "compiler" in _make_tier_counters()


# ---------------------------------------------------------------------------
# Diagnostic-suppression forgery (refutation is repo-steerable)
# ---------------------------------------------------------------------------


class TestSuppressionWitness:
    def test_pragma_ignored_detected(self):
        assert compiler_sweep._suppression_witness(
            '#pragma GCC diagnostic ignored "-Wanalyzer-use-after-free"\n'
            "int f(void) { return 0; }\n",
        )

    def test_clang_pragma_detected(self):
        assert compiler_sweep._suppression_witness(
            '#pragma clang diagnostic ignored "-Wall"\nint x;\n',
        )

    def test_system_header_pragma_detected(self):
        assert compiler_sweep._suppression_witness(
            "#pragma GCC system_header\nint x;\n",
        )

    def test_underscore_pragma_operator_detected(self):
        # The payload lives in a string literal (blanked by the
        # sanitized view) — the operator token alone is the witness.
        assert compiler_sweep._suppression_witness(
            '_Pragma("GCC diagnostic ignored \\"-Wall\\"")\nint x;\n',
        )

    def test_analyzer_detection_macro_detected(self):
        assert compiler_sweep._suppression_witness(
            "#ifndef __clang_analyzer__\nvoid evil(void);\n#endif\n",
        )

    def test_prose_mentions_are_inert(self):
        # Comments and string literals must NOT disqualify: honest
        # code often documents pragmas.
        assert not compiler_sweep._suppression_witness(
            "/* #pragma GCC diagnostic ignored would be wrong */\n"
            'const char *s = "#pragma clang diagnostic ignored";\n'
            "// __clang_analyzer__ is defined under clang --analyze\n"
            "int f(void) { return 0; }\n",
        )

    # Closure over both compilers' documented suppression spellings:
    # the witness exists because analyzer silence on an attacker-
    # authored TU is forgeable, so an enumeration gap (the clang
    # system_header spelling was missing) is a forged-refutation
    # channel on that compiler's path.
    _SUPPRESSION_SPELLINGS = (
        '#pragma GCC diagnostic ignored "-Wanalyzer-use-after-free"',
        '#pragma clang diagnostic ignored "-Wall"',
        "#pragma GCC system_header",
        "#pragma clang system_header",
        "#  pragma clang system_header",  # whitespace-tolerant
        '_Pragma("GCC diagnostic ignored \\"-Wall\\"")',
        "#ifndef __clang_analyzer__",
        "[[clang::suppress]] int *q = p;",
        '[[gsl::suppress("type.1")]] int *q = p;',
        "__attribute__((suppress)) int g(void);",
        # Linemarker system-header flag: silences warnings AND
        # analyzer reports on BOTH compiler paths with no pragma.
        '# 1 "hostile.h" 3',
        '#  1  "hostile.h"  3',  # whitespace-tolerant
        '# 1 "/usr/include/evil.h" 1 3 4',  # preprocessed-output flags
        '#line 1 "hostile.h" 3',
    )

    def test_documented_suppression_spellings_all_detected(self):
        for spelling in self._SUPPRESSION_SPELLINGS:
            assert compiler_sweep._suppression_witness(
                f"{spelling}\nint f(void) {{ return 0; }}\n",
            ), spelling

    def test_benign_pragmas_do_not_trip(self):
        # Over-triggering costs genuine refutations (every hit fails
        # toward inconclusive) — common non-suppression pragmas stay
        # inert.
        for spelling in (
            "#pragma once",
            "#pragma pack(push, 1)",
            '#pragma GCC optimize("O2")',
            "#pragma omp parallel for",
            "#pragma clang loop unroll(full)",
            "#pragma GCC visibility push(default)",
            "__attribute__((unused)) int x;",
            # Flagless / non-3-flag linemarkers renumber only.
            '#line 1 "x.h"',
            '# 1 "x.c"',
            '# 1 "x.c" 1',
            '# 42 "x.c" 2 4',
        ):
            assert not compiler_sweep._suppression_witness(
                f"{spelling}\nint f(void) {{ return 0; }}\n",
            ), spelling


class TestAttributeListSuppressionSpellings:
    """clang honours ``suppress`` anywhere in an attribute list and in
    its reserved / alternate-scope spellings (each verified to silence
    clang --analyze on Apple clang 21). Matching only the canonical
    first-position spelling let every other form forge silence."""

    @pytest.mark.parametrize("spelling", [
        "[[nodiscard, clang::suppress]] int f(void);",
        "[[using clang: suppress]] int f(void);",
        "[[clang::__suppress__]] int f(void);",
        "[[_Clang::suppress]] int f(void);",
        "[[__clang__::suppress]] int f(void);",
        "[[gnu::aligned(8), clang::suppress]] int f(void);",
        "[[clang::\nsuppress]] int f(void);",
        "[ [clang::suppress] ] int f(void);",
        "[[ /*x*/ clang :: suppress]] int f(void);",
        "__attribute__((__suppress__)) int f(void);",
        "__attribute__((noinline, suppress)) int f(void);",
        "__attribute__((aligned((8)), suppress)) int f(void);",
        "__attribute((suppress)) int f(void);",
        "#define NOCHECK __attribute__((noinline, suppress))",
        "#pragma clang attribute push (__attribute__((suppress)), "
        "apply_to = function)",
    ])
    def test_attribute_list_spellings_detected(self, spelling):
        """Each listed spelling silences clang --analyze; a witness that
        misses one lets that TU's silence read as evidence of
        absence."""
        assert compiler_sweep._suppression_witness(
            f"{spelling}\nint g(void) {{ return 0; }}\n",
        ), spelling

    def test_very_long_single_line_list_witnessed(
        self,
    ):
        """A long attribute list on one line must not hide a trailing
        suppress."""
        padding = ", ".join(["nodiscard"] * 8000)  # ~88 KB on one line
        assert compiler_sweep._suppression_witness(
            f"[[{padding}, clang::suppress]] int f(void);\n",
        )

    # The additive attribute check is line-local: ``suppress`` after an
    # attribute-list opener on the same line is a witness even when it
    # is an argument or a declarator name (documented, FN-safe false
    # positive) — only non-``suppress`` words and non-list brackets
    # stay inert.
    @pytest.mark.parametrize("text", [
        "[[clang::suppresx]] int f(void);",
        "__attribute__((noinline, suppresx)) int f(void);",
        "int a[2]; int b = a[a[0]];",
        "/* [[clang::suppress]] __attribute__((suppress)) */ int f;",
    ])
    def test_suppress_outside_an_attribute_list_is_inert(self, text):
        """Near-miss words, ordinary subscripts and commented-out lists
        must not trigger the witness; each false hit costs a genuine
        refutation."""
        assert not compiler_sweep._suppression_witness(
            f"{text}\nint g(void) {{ return 0; }}\n",
        ), text


@needs_compiler
class TestSuppressionForgery:
    def test_pragma_suppressed_silence_cannot_refute(
        self, tmp_path, sandbox_spy,
    ):
        # Regression PoC: a real UAF preceded by the family-suppressing
        # pragma compiles clean (rc 0, zero family diagnostics) — the
        # old code minted a mechanical 'refuted' receipt for a live
        # bug. Suppression in the TU must fail toward unknown.
        target = tmp_path / "repo"
        target.mkdir()
        (target / "poc.c").write_text(
            '#pragma GCC diagnostic ignored '
            '"-Wanalyzer-use-after-free"\n'
            "#include <stdlib.h>\n"
            "int f(void){char *p=malloc(8); if(!p) return 0; "
            "free(p); return p[0];}\n",
        )
        result = _guarded_compiler_sweep(
            target_path=target,
            file_path="poc.c",
            function_name="f",
            hypothesis="use-after-free of `p` in f",
            cwe="CWE-416",
            out_dir=tmp_path / "out",
        )
        assert result.outcome != "refuted", vars(result)
        if result.outcome == "inconclusive":
            assert result.details.get("suppression_witness")

    def test_linemarker_system_header_silence_cannot_refute(
        self, tmp_path, sandbox_spy,
    ):
        # A TU opening with `# 1 "x.h" 3` (linemarker system-header
        # flag, no pragma anywhere) silences clang --analyze AND
        # gcc -fanalyzer on a live double-free — mechanically forged
        # silence must fail toward unknown, never mint 'refuted'.
        target = tmp_path / "repo"
        target.mkdir()
        (target / "poc.c").write_text(
            '# 1 "poc.h" 3\n'
            "#include <stdlib.h>\n"
            "int f(void){char *p=malloc(8); if(!p) return 0; "
            "free(p); free(p); return 0;}\n",
        )
        result = _guarded_compiler_sweep(
            target_path=target,
            file_path="poc.c",
            function_name="f",
            hypothesis="double free of `p` in f",
            cwe="CWE-415",
            out_dir=tmp_path / "out",
        )
        assert result.outcome != "refuted", vars(result)
        if result.outcome == "inconclusive":
            assert result.details.get("suppression_witness")

    def test_clean_tu_with_prose_mentions_still_refutes(
        self, tmp_path, sandbox_spy,
    ):
        # Genuine refutations survive: comment prose naming pragmas
        # is blanked by the sanitized view.
        target = tmp_path / "repo"
        target.mkdir()
        (target / "ok.c").write_text(
            "/* never add #pragma GCC diagnostic ignored here */\n"
            "int f(int y){ return y + 1; }\n",
        )
        result = _guarded_compiler_sweep(
            target_path=target,
            file_path="ok.c",
            function_name="f",
            hypothesis="use-after-free of `y` in f",
            cwe="CWE-416",
            out_dir=tmp_path / "out",
        )
        assert result.outcome == "refuted", vars(result)


@needs_gcc
class TestIncludeClosureSuppressionForgery:
    """The suppression witness must cover the WHOLE translation unit:
    a diagnostic pragma in an included repo header persists past its
    #include into the includer's code, so silence over the primary
    file's text alone is forgeable by one planted header line."""

    def _sweep_uaf(self, tmp_path, fixture, *extra):
        target = _target_with(tmp_path, fixture, *extra)
        return _guarded_compiler_sweep(
            target_path=target,
            file_path=fixture,
            function_name="use_after_free",
            hypothesis="use-after-free of `p` in use_after_free",
            cwe="CWE-416",
            out_dir=tmp_path / "out",
        )

    def test_pragma_in_included_repo_header_cannot_refute(
        self, tmp_path, sandbox_spy,
    ):
        # gcc-confirmed live UAF; the header's pragma silences the
        # family diagnostic for the includer's code after the
        # #include — silence must fail toward unknown with the
        # header named, never mint 'refuted'.
        result = self._sweep_uaf(tmp_path, "uaf_incl.c", "evil_pragma.h")
        assert result.outcome != "refuted", vars(result)
        assert result.outcome == "inconclusive"
        assert "evil_pragma.h" in (
            result.details.get("suppression_witness") or ""
        ), vars(result)

    def test_token_pasted_pragma_cannot_refute(
        self, tmp_path, sandbox_spy,
    ):
        # One level deeper: `_Pra##gma` synthesizes the operator at
        # expansion time, invisible to any raw-text scan of any file
        # — but the resulting `#pragma` line lands in the compiler's
        # own preprocessed output, where the closure vet reads it.
        result = self._sweep_uaf(tmp_path, "uaf_paste.c", "evil_paste.h")
        assert result.outcome != "refuted", vars(result)
        assert result.outcome == "inconclusive"
        assert "pragma" in (
            result.details.get("suppression_witness") or ""
        ).lower(), vars(result)

    def test_laundered_attribution_cannot_refute(
        self, tmp_path, sandbox_spy,
    ):
        # Two levels deeper: a plain linemarker in the repo header
        # re-attributes its own lines to a system path, and the
        # pragma arrives token-pasted — invisible to raw scans AND
        # classified system-authored in -E output. Attribution from
        # an out-of-tree-naming repo linemarker is unverifiable; the
        # vet must refuse, never refute.
        result = self._sweep_uaf(
            tmp_path, "uaf_launder.c", "evil_launder.h",
        )
        assert result.outcome != "refuted", vars(result)
        assert result.outcome == "inconclusive"
        detail = (
            result.details.get("suppression_witness")
            or result.details.get("closure_unvetted")
            or ""
        )
        assert "evil_launder.h" in detail, vars(result)

    def test_in_tree_linemarker_still_refutes(
        self, tmp_path, sandbox_spy,
    ):
        # Generated sources (bison/flex) cite their in-tree grammar
        # files with plain linemarkers — those must not cost the
        # refutation.
        target = tmp_path / "repo"
        target.mkdir()
        (target / "ok.c").write_text(
            '#line 5 "parser.y"\n'
            "int f(int y){ return y + 1; }\n",
        )
        result = _guarded_compiler_sweep(
            target_path=target,
            file_path="ok.c",
            function_name="f",
            hypothesis="use-after-free of `y` in f",
            cwe="CWE-416",
            out_dir=tmp_path / "out",
        )
        assert result.outcome == "refuted", vars(result)

    def test_digraph_pragma_cannot_refute(self, tmp_path, sandbox_spy):
        # Pinned-by-review shape: the digraph spelling `%:pragma`
        # suppresses gcc and carries no literal `#pragma` for a raw
        # scan — the preprocessor normalises it to a `#pragma` line
        # in -E output, where the closure vet reads it.
        result = self._sweep_uaf(
            tmp_path, "uaf_digraph.c", "evil_digraph.h",
        )
        assert result.outcome != "refuted", vars(result)
        assert result.outcome == "inconclusive"
        assert "pragma" in (
            result.details.get("suppression_witness") or ""
        ).lower(), vars(result)

    def test_backslash_spliced_pragma_cannot_refute(
        self, tmp_path, sandbox_spy,
    ):
        # Pinned-by-review shape: `#prag\` + newline + `ma …` splices
        # into a live pragma the raw text never spells — caught
        # post-splice in -E output.
        result = self._sweep_uaf(
            tmp_path, "uaf_splice.c", "evil_splice.h",
        )
        assert result.outcome != "refuted", vars(result)
        assert result.outcome == "inconclusive"
        assert "pragma" in (
            result.details.get("suppression_witness") or ""
        ).lower(), vars(result)

    def test_clean_include_closure_still_refutes(
        self, tmp_path, sandbox_spy,
    ):
        # Two-direction pin: system headers are outside the repo's
        # control — a guarded TU including <stdlib.h> keeps its
        # mechanical refutation.
        result = self._sweep_uaf(tmp_path, "uaf_guarded.c")
        assert result.outcome == "refuted", vars(result)

    def test_conditional_analyzer_token_in_header_cannot_refute(
        self, tmp_path, sandbox_spy,
    ):
        # `#ifndef __clang_analyzer__` in a repo header resolves away
        # in -E output — the raw per-file scan of the closure must
        # still catch the token.
        target = tmp_path / "repo"
        target.mkdir()
        (target / "cond.h").write_text(
            "#ifndef __clang_analyzer__\n"
            "#define MAYBE_FREE(p)\n"
            "#else\n"
            "#define MAYBE_FREE(p) free(p)\n"
            "#endif\n",
        )
        (target / "ok.c").write_text(
            '#include "cond.h"\n'
            "int f(int y){ return y + 1; }\n",
        )
        result = _guarded_compiler_sweep(
            target_path=target,
            file_path="ok.c",
            function_name="f",
            hypothesis="use-after-free of `y` in f",
            cwe="CWE-416",
            out_dir=tmp_path / "out",
        )
        assert result.outcome != "refuted", vars(result)
        assert "cond.h" in (
            result.details.get("suppression_witness") or ""
        ), vars(result)


class TestClosureWitnessParsing:
    """Unit pins for the preprocessed-output walker."""

    def _pp(self, target: Path, tu: Path, text: str):
        # The TU itself is always raw-scanned — make it exist.
        if not tu.exists():
            tu.write_text("int t;\n")
        return compiler_sweep._closure_suppression_witness(
            text, target, tu,
        )

    def test_repo_pragma_attributed(self, tmp_path):
        (tmp_path / "h.h").write_text("int x;\n")
        w, fail = self._pp(
            tmp_path, tmp_path / "a.c",
            f'# 1 "{tmp_path}/h.h" 1\n'
            '#pragma GCC diagnostic ignored "-Wanalyzer-use-after-free"\n',
        )
        assert "h.h" in w and not fail

    def test_system_pragma_trusted(self, tmp_path):
        w, fail = self._pp(
            tmp_path, tmp_path / "a.c",
            '# 1 "/usr/include/glib.h" 1\n'
            '#pragma GCC diagnostic ignored "-Wall"\n',
        )
        assert (w, fail) == ("", "")

    def test_benign_system_macro_expansion_markers_inert(self, tmp_path):
        # gcc emits `# N "tu.c" 3 4` around every system-macro
        # expansion (NULL, offsetof) — those must not read as
        # suppression, or every real TU loses its refutations.
        tu = tmp_path / "a.c"
        tu.write_text("int f(void) { return 0; }\n")
        w, fail = self._pp(
            tmp_path, tu,
            f'# 1 "{tu}"\nint *p =\n# 2 "{tu}" 3 4\n((void *)0)\n'
            f'# 2 "{tu}"\n;\n',
        )
        assert (w, fail) == ("", "")

    def test_repo_system_header_pragma_caught_by_raw_scan(self, tmp_path):
        # The construct that puts a repo region into system-header
        # state is textual in the repo file — the raw closure scan
        # names it.
        (tmp_path / "h.h").write_text("#pragma GCC system_header\n")
        w, fail = self._pp(
            tmp_path, tmp_path / "a.c",
            f'# 1 "{tmp_path}/h.h" 1\nint x;\n',
        )
        assert "system_header" in w and "h.h" in w and not fail

    def test_unreadable_closure_file_fails_vet(self, tmp_path):
        w, fail = self._pp(
            tmp_path, tmp_path / "a.c",
            f'# 1 "{tmp_path}/missing.h" 1\nint x;\n',
        )
        assert not w and "missing.h" in fail

    def test_closure_file_raw_scan_catches_analyzer_token(self, tmp_path):
        (tmp_path / "h.h").write_text(
            "#ifndef __clang_analyzer__\nint x;\n#endif\n",
        )
        w, fail = self._pp(
            tmp_path, tmp_path / "a.c",
            f'# 1 "{tmp_path}/h.h" 1\nint x;\n',
        )
        assert "__clang_analyzer__" in w and not fail


class TestClosureLinemarkerNames:
    """-E linemarkers carry C-escaped file names (``\\"``, ``\\\\``,
    octal for non-ASCII). A marker the walker cannot parse used to be
    read as a code line, so a header with an odd name was never
    raw-scanned and its ``#ifdef __clang_analyzer__`` went unseen —
    the vet failed OPEN."""

    @staticmethod
    def _esc(path: str) -> str:
        out = []
        for b in os.fsencode(path):
            ch = chr(b)
            if ch in '"\\':
                out.append("\\" + ch)
            elif 32 <= b < 127:
                out.append(ch)
            else:
                out.append("\\%03o" % b)
        return "".join(out)

    @pytest.mark.parametrize("name", ['q"x.h', "b\\x.h", "\u00e9.h"])
    def test_odd_header_name_is_raw_scanned(self, tmp_path, name):
        """-E escapes quotes, backslashes and non-ASCII bytes in marker
        names; such a header must still be scanned (or fail the vet),
        never be skipped as a code line."""
        tu = tmp_path / "a.c"
        tu.write_text("int t;\n")
        hdr = tmp_path / name
        hdr.write_text("#ifdef __clang_analyzer__\n#define D 0\n#endif\n")
        pp = (
            f'# 1 "{self._esc(str(tu))}"\n'
            f'# 1 "{self._esc(str(hdr))}" 1\n'
            f'# 2 "{self._esc(str(tu))}" 2\nint t;\n'
        )
        w, fail = compiler_sweep._closure_suppression_witness(
            pp, tmp_path, tu,
        )
        # Base fails closed on the escaped name (unreadable path); the
        # additive decoder raw-scans the header where base read it as
        # a code line (`q"x.h`). Either way the closure is not clean.
        assert w or fail, (w, fail)
        if name == 'q"x.h':
            assert "__clang_analyzer__" in w and name in w, (w, fail)

    def test_unparseable_linemarker_fails_vet(self, tmp_path):
        """A marker the walker cannot parse makes closure attribution
        unknowable, so the vet must fail rather than read the closure
        as clean."""
        tu = tmp_path / "a.c"
        tu.write_text("int t;\n")
        w, fail = compiler_sweep._closure_suppression_witness(
            f'# 1 "{tu}"\n# 1 "{tmp_path}/unterminated.h 1\nint t;\n',
            tmp_path, tu,
        )
        assert not w and "linemarker" in fail

    def test_multiline_attribute_in_repo_region_attributed(self, tmp_path):
        """A list split across lines inside the TU's own region is a
        witness and names the repo file it came from."""
        tu = tmp_path / "a.c"
        tu.write_text("int t;\n")
        w, fail = compiler_sweep._closure_suppression_witness(
            f'# 1 "{tu}"\n[[nodiscard,\n clang::suppress]] int f(void);\n',
            tmp_path, tu,
        )
        assert "suppress" in w and str(tu) in w and not fail

    def test_attribute_in_system_region_trusted(self, tmp_path):
        """System headers legitimately use suppress-like attributes;
        they must not withhold refutations for repo code."""
        tu = tmp_path / "a.c"
        tu.write_text("int t;\n")
        w, fail = compiler_sweep._closure_suppression_witness(
            f'# 1 "{tu}"\n# 1 "/usr/include/sys.h" 1 3 4\n'
            "__attribute__((noinline, suppress)) int g(void);\n"
            f'# 2 "{tu}" 2\nint t;\n',
            tmp_path, tu,
        )
        assert (w, fail) == ("", "")

    @pytest.mark.parametrize("pp", ["", "\n  \n"])
    def test_empty_preprocessed_output_fails_vet(self, tmp_path, pp):
        """Callers coerce a missing stdout to an empty string; that must
        read as an unvetted closure, not a closure with no headers."""
        # Both callers coerce a missing stdout to "" — that must read
        # as unvetted, not as a closure with no headers.
        tu = tmp_path / "a.c"
        tu.write_text("int t;\n")
        w, fail = compiler_sweep._closure_suppression_witness(
            pp, tmp_path, tu,
        )
        assert not w and "empty" in fail

    def test_escaped_source_linemarker_outside_tree_refused(self, tmp_path):
        """A #line name is judged after C escape decoding, so an escaped
        spelling cannot move repo code to a system path unnoticed."""
        # `#line 1 "\057usr/..."` names /usr/... once the C escape is
        # decoded — attribution laundering must be judged on the name
        # the preprocessor uses, not its escaped spelling.
        tu = tmp_path / "a.c"
        tu.write_text('#line 1 "\\057usr/include/evil.h"\nint t;\n')
        w, fail = compiler_sweep._closure_suppression_witness(
            f'# 1 "{tu}"\nint t;\n', tmp_path, tu,
        )
        assert not w and "/usr/include/evil.h" in fail


class TestAdditiveChecks:
    """Additive checks (monotonic over base): escape decoding,
    directive spellings, laundering, attribute lists, linear time."""

    @staticmethod
    def _vet(tmp_path, tu_text, pp=None):
        tu = tmp_path / "a.c"
        tu.write_text(tu_text)
        return compiler_sweep._closure_suppression_witness(
            pp if pp is not None else f'# 1 "{tu}"\nint t;\n', tmp_path, tu,
        )

    # -- C string-literal escape semantics ---------------------------
    @pytest.mark.parametrize("lit,expected", [
        (r'"\x02fusr/x.h"', "/usr/x.h"),  # \x takes ALL hex digits
        (r'"\x2fusr/x.h"', "/usr/x.h"),
        (r'"\057usr/x.h"', "/usr/x.h"),
        (r'"\0571"', "/1"),  # octal stops at three digits
        (r'"t\tb.h"', "t\tb.h"),
        (r'"q\"x.h"', 'q"x.h'),
        (r'"b\\x.h"', "b\\x.h"),
        (r'"\303\251.h"', "\u00e9.h"),
        (r'"\x100"', None),  # value > 0xFF
        (r'"\400"', None),
        (r'"\u0041.h"', None),  # UCN: unproven → unverifiable
        (r'"\q.h"', None),  # unknown escape
        (r'"\x"', None),
        ('"unterminated', None),
        ('u8"x.h"', None),  # prefixed literal is not a #line name
        (r'"/x\0/usr/x.h"', None),  # embedded NUL
        (r'"\e.h"', "\x1b.h"),  # GNU \e escape (gcc and clang accept it)
    ])
    def test_decode_c_string(self, lit, expected):
        """Marker names are decoded exactly as the preprocessor reads
        them, and anything the decoder cannot prove returns None so
        the vet fails closed."""
        assert compiler_sweep._decode_c_string(lit) == expected

    # -- source #line laundering: every directive spelling -----------
    @pytest.mark.parametrize("line", [
        '#line 1 "\\x02fusr/include/stdio.h"',
        '#line 1 "\\x2fusr/include/stdio.h"',
        '\f#line 1 "/usr/include/stdio.h"',
        '\v#line 1 "/usr/include/stdio.h"',
        ' \t#line 1 "/usr/include/stdio.h"',
        '/* c */ # line 1 "/usr/include/stdio.h"',
        '%:line 1 "/usr/include/stdio.h"',
        '#li\\\nne 1 "/usr/include/stdio.h"',
        '# 1 "/usr/include/stdio.h"',
    ])
    def test_laundering_linemarker_spellings_fail_vet(self, tmp_path, line):
        """Every directive spelling that relabels repo code as a system
        header must fail the vet, since clang drops diagnostics
        there."""
        w, fail = self._vet(tmp_path, line + "\nint t;\n")
        assert not w and "/usr/include/stdio.h" in fail, (line, fail)

    @pytest.mark.parametrize("text", [
        '#define P "/usr/include/stdio.h"\n#line 1 P\nint t;\n',
        '#line 1 "\\x100"\nint t;\n',
        '#line 1 "\\u0041"\nint t;\n',
    ])
    def test_unprovable_line_operands_fail_vet(self, tmp_path, text):
        """A #line operand that is a macro or an unprovable escape could
        name any path, so the vet cannot accept it."""
        w, fail = self._vet(tmp_path, text)
        assert not w and "unverifiable operands" in fail, fail

    # -- raw strings / literals vs directives -------------------------
    @pytest.mark.parametrize("sep", ["\n", "\f", "\u2028", "\v"])
    def test_raw_string_cannot_launder_in_pp_output(self, tmp_path, sep):
        """A fake marker inside a C++ raw string must neither hide a
        later attribute nor be read as a real rename into a system
        header."""
        tu = tmp_path / "a.c"
        pp = (
            f'# 1 "{tu}"\nstatic const char *s = R"({sep}'
            '# 1 "/usr/include/stdio.h" 3\n)";\n'
            "__attribute__((suppress)) int f(void);\n"
        )
        w, fail = self._vet(tmp_path, "int t;\n", pp)
        # \f / \v / U+2028: the additive walk splits on \n only, so the
        # attribute stays in the TU (witness); \n: the fake marker is a
        # flagless rename of a repo region to a system path (unvetted).
        assert w or fail, (w, fail)
        if sep != "\n":
            assert "suppress" in w and str(tu) in w, (w, fail)

    def test_raw_string_lines_in_repo_file_are_not_directives(self):
        """Lines inside a raw string literal in a repo file are data,
        not directives; reading them as markers would be a false
        witness."""
        assert not compiler_sweep._suppression_witness(
            'const char *s = R"x(\n# 1 "h.h" 3\n)x";\n',
        )

    def test_unparseable_col0_marker_outside_literals_fails(self, tmp_path):
        """A column-0 '# <digit>' line that is not a valid marker leaves
        attribution unknown, so the vet fails."""
        tu = tmp_path / "a.c"
        w, fail = self._vet(
            tmp_path, "int t;\n", f'# 1 "{tu}"\n# 1. not a marker\n',
        )
        assert not w and "unparseable linemarker" in fail

    def test_macro_produced_hash_is_not_a_directive(self, tmp_path):
        """-E indents a macro-produced '#', so only column-0 markers
        change attribution; an indented one must not hide a repo
        attribute."""
        # The preprocessor prefixes a space to a macro-produced `#` at
        # line start; only column 0 is a directive in -E output.
        tu = tmp_path / "a.c"
        w, fail = self._vet(
            tmp_path, "int t;\n",
            f'# 1 "{tu}"\n # 1 "/usr/include/x.h" 3\n'
            "__attribute__((suppress)) int f(void);\n",
        )
        assert "suppress" in w and str(tu) in w and not fail

    # -- attribute lists (line-local; `suppress` args also witness) ---
    @pytest.mark.parametrize("spelling", [
        "<:<:clang::suppress:>:> int f(void);",
        "<:[clang::suppress]:> int f(void);",
        "[<:clang::suppress:>] int f(void);",
        '__attribute__((annotate("))"), suppress)) int f(void);',
        '[[deprecated("]]"), clang::suppress]] int f(void);',
        "__attribute__((sup\\\npress)) int f(void);",
        '[[gsl::suppress("type.1")]] int f(void);',
        "[[clang::suppress",  # unterminated at EOF
    ])
    def test_attribute_name_spellings_detected(self, spelling):
        """Digraph openers, strings containing closers, line splices and
        an unterminated list all still apply suppress for clang."""
        assert compiler_sweep._suppression_witness(
            f"{spelling}\nint g(void) {{ return 0; }}\n",
        ), spelling

    @pytest.mark.parametrize("text", [
        "__attribute__((cleanup(suppressor))) int x;",
        "[[clang::suppressor]] int f(void);",
        "std::vector<::suppress> v;",
    ])
    def test_non_suppress_words_inert(self, text):
        """Words that only contain 'suppress' and non-attribute scope
        operators must not trigger the witness."""
        assert not compiler_sweep._suppression_witness(
            f"{text}\nint g(void) {{ return 0; }}\n",
        ), text

    def test_list_unterminated_at_end_of_input(self):
        """A list still open at end of input is a witness; the carry
        must not need a closer."""
        assert compiler_sweep._suppression_witness("[[clang::suppress")
        assert compiler_sweep._suppression_witness("__attribute__((suppress")

    def test_system_hit_then_repo_hit_attributes_repo(self, tmp_path):
        """A system-region hit must not mask a later repo-region hit;
        the witness names the repo file."""
        tu = tmp_path / "a.c"
        pp = (
            f'# 1 "{tu}"\n# 1 "/usr/include/sys.h" 1 3 4\n'
            "__attribute__((suppress)) int g(void);\n"
            f'# 2 "{tu}" 2\n[[clang::suppress]] int f(void);\n'
        )
        w, fail = self._vet(tmp_path, "int t;\n", pp)
        assert w.startswith("[[clang::suppress") and str(tu) in w, w
        assert not fail

    def test_tab_named_header_is_raw_scanned(self, tmp_path):
        """A header whose -E name carries an escaped tab is scanned or
        fails the vet, never skipped."""
        hdr = tmp_path / "t\tb.h"
        hdr.write_text("#ifdef __clang_analyzer__\n#endif\n")
        tu = tmp_path / "a.c"
        pp = f'# 1 "{tu}"\n# 1 "{tmp_path}/t\\tb.h" 1\n# 2 "{tu}" 2\nint t;\n'
        w, fail = self._vet(tmp_path, "int t;\n", pp)
        assert w or fail, (w, fail)  # base: escaped name unreadable

    def test_pragma_directive_spellings(self):
        """Suppression pragmas after a form feed, spelled with '%:', or
        split by a line splice are honoured by clang and must be
        witnessed."""
        for text in (
            "\f#pragma GCC system_header",
            "%:pragma clang diagnostic ignored \"-Wall\"",
            "#pra\\\ngma clang system_header",
        ):
            assert compiler_sweep._suppression_witness(
                text + "\nint x;\n",
            ), text

    # -- linear time ---------------------------------------------------
    def test_nested_brackets_linear(self):
        """Deeply nested brackets or parentheses must stay linear: the
        witness runs on attacker-controlled text."""
        import time
        for n in (4000, 300_000):
            # Within the layer-2 nesting limit the balanced input is
            # clean; beyond it the attribute list is unverifiable and
            # reported conservatively. Either way: bounded time.
            for text in ("#define UNUSED " + "[" * n + "]" * n + "\nint x;\n",
                         "__attribute__((" + "(" * n + ")" * n + "))\n"):
                t0 = time.perf_counter()
                w = compiler_sweep._suppression_witness(text)
                # guards against catastrophic (super-linear) blowup, not speed
                assert time.perf_counter() - t0 < 30
                if n <= compiler_sweep._L2_MAX_DEPTH - 2:
                    assert not w
                else:
                    assert "nesting exceeds the scan limit" in w

    def test_large_preprocessed_output_linear(self, tmp_path):
        """The closure walk over multi-MB -E output must scale linearly;
        a quadratic walk would let a repo stall the scan."""
        import time
        tu = tmp_path / "a.c"
        tu.write_text("int t;\n")
        chunk = (
            '# 1 "/usr/include/c++/v1/vector" 1 3 4\n'
            "template <class _Tp> struct __attribute__((visibility(\"default\"))) X;\n"
            f'# 2 "{tu}" 2\n'
            "template <class _Tp, class _Alloc = allocator<_Tp> >\n"
            "class __attribute__((__type_visibility__(\"default\"))) vector {\n"
            "  [[nodiscard]] size_type size() const noexcept { return n_; }\n"
            "  const char *s = \"]] (( suppress\"; int a[4][4];\n"
            "};\n"
        )

        def run(k):
            pp = f'# 1 "{tu}"\n' + chunk * k
            t0 = time.perf_counter()
            assert compiler_sweep._closure_suppression_witness(
                pp, tmp_path, tu,
            ) == ("", "")
            return len(pp), time.perf_counter() - t0

        small = run(2_000)
        big = run(2_000 * 4 * 2)  # ~2.9 MB at chunk ≈ 180 B
        assert big[0] > 2_500_000, big
        assert big[1] < 10.0, big
        # Linear: 8x the input may not cost much more than ~8x (+slack);
        # a quadratic walk would be ~64x.
        assert big[1] < max(small[1], 0.02) * 20, (small, big)


class TestMonotonicOverBase:
    """Canonical form: the witness and the closure vet are the BASE
    implementation (main's, kept verbatim as ``_base_*``) OR additive
    checks — they may only add a witness / vet failure, never remove
    one the base produces."""

    # sha256 of the verbatim base block in compiler_sweep.py (base
    # main's lines 490-677 with the two functions renamed _base_* and
    # the inner raw-scan call pointed at _base_suppression_witness).
    _BASE_BLOCK_SHA256 = (
        "513ffba9c86a39ebb2b0f321fc4454a4a1d090fe4cdd4701b4d9c1643f39421b"
    )

    def test_base_block_is_verbatim(self):
        """The superset guarantee depends on main's witness code staying
        byte-identical; this sha256 pin catches any edit to it."""
        import hashlib
        src = Path(compiler_sweep.__file__).read_text(encoding="utf-8")
        i = src.index(
            "# Diagnostic-suppression witness: any of these in the analysed TU",
        )
        j = src.index(
            "\n\n# -------------------------------------------------------"
            "--------------------\n# Additive suppression checks",
        )
        assert hashlib.sha256(src[i:j].encode()).hexdigest() == (
            self._BASE_BLOCK_SHA256
        ), "the base witness block must stay verbatim (monotonic design)"

    # Adversarial inputs plus constructs the generator mixes.
    _FRAGMENTS = (
        "[[clang::suppress]]", '[[gsl::suppress("t")]]',
        "__attribute__((suppress))", "[[nodiscard, clang::suppress]]",
        "<:<:clang::suppress:>:>", "__attribute__((noinline, suppress))",
        '#pragma GCC diagnostic ignored "-Wall"', "#pragma clang system_header",
        '_Pragma("clang system_header")', "#ifndef __clang_analyzer__",
        "#endif", "#if 0", '# 1 "x.h" 3', '#line 1 "/usr/include/stdio.h"',
        '#line 1 "\\x02fusr/include/stdio.h"', '#line 9', '#line 3 "gram.y"',
        "/*", "*/", "//", '"', "'", 'R"(', ')"', 'R"xy(', ')xy"', "\\\n",
        "\\ \n", "\f", "\v", "\r", "\u00e1", "\u0301", "a\u0301R\"(\"",
        "\u2028", "\ufeff", "\u00a0", "\x00", "<:", ":>", "%:", "#", "##",
        "suppress", "__suppress__", "[[", "]]", "((", "))", "(", ")", "[",
        "]", ",", "::", "int x;", "\n", " ", "\t", "#warning don't",
        "#error \"", "__has_include(<a\"b>)", "#pragma foo ", "cleanup(",
        "deprecated(\"", "using clang: ", "%:pragma clang system_header",
    )

    def _gen(self, rng, k):
        return "".join(
            rng.choice(self._FRAGMENTS) for _ in range(rng.randint(1, k))
        )

    def test_witness_superset_of_base_generated(self):
        """On generated inputs, whenever main's witness fires the new
        witness returns exactly the same result, so no refutation is
        ever gained."""
        import random
        rng = random.Random(20261020)
        base_hits = 0
        for _ in range(10_000):
            x = self._gen(rng, 24)
            b = compiler_sweep._base_suppression_witness(x)
            if b:
                base_hits += 1
                # The base result is returned VERBATIM, not just "some
                # witness" — the additive checks never pre-empt it.
                assert compiler_sweep._suppression_witness(x) == b, repr(x)
        assert base_hits > 1000  # the generator exercises the base

    @pytest.mark.slow
    def test_closure_superset_of_base_generated(self, tmp_path):
        """On generated closures, a non-clean base result is returned
        unchanged, so the closure vet never clears what main flagged."""
        import random
        rng = random.Random(4242)
        tu = tmp_path / "a.c"
        hdr = tmp_path / "h.h"
        hdr.write_text("#ifndef __clang_analyzer__\n#endif\n")
        markers = (
            f'# 1 "{tu}"\n', f'# 1 "{hdr}" 1\n', f'# 2 "{tu}" 2\n',
            '# 1 "/usr/include/sys.h" 1 3 4\n', '# 1 "/usr/include/x.h"\n',
            f'# 1 "{tmp_path}/q\\"x.h" 1\n', '# 1 "<built-in>" 3\n',
        )
        nonclean_base = 0
        for _ in range(10_000):
            tu.write_text(self._gen(rng, 8))
            pp = "".join(
                rng.choice(markers) if rng.random() < 0.3
                else self._gen(rng, 6) + "\n"
                for _ in range(rng.randint(1, 6))
            )
            b = compiler_sweep._base_closure_suppression_witness(
                pp, tmp_path, tu,
            )
            n = compiler_sweep._closure_suppression_witness(pp, tmp_path, tu)
            if b[0] or b[1]:
                nonclean_base += 1
                assert n == b, (pp, b, n)
        assert nonclean_base > 1000

    def test_combining_mark_pragma_keeps_base_witness(self, tmp_path):
        """A phantom raw string after a combining mark blinds the file
        scan (as on main); the -E closure scan must still catch the
        attribute."""
        for attr in ("[[clang::suppress]]", "__attribute__((suppress))"):
            text = (
                '#pragma foo a\u0301R"("\nint f(int *p) {\n  if (p) return 0;\n'
                f"  {attr} return *p;\n}}\n"
            )
            # The raw scan's sanitized view is blinded by the phantom raw
            # string (pre-existing, base too); the -E closure scan is not.
            tu = tmp_path / "a.cpp"
            tu.write_text(text)
            w, fail = compiler_sweep._closure_suppression_witness(
                f'# 1 "{tu}"\n' + text, tmp_path, tu,
            )
            assert w or fail, attr

    def test_long_suppress_list_linear(self):
        """A 2 MB attribute list must be scanned in bounded time, inside
        and outside '#if 0', for both the file and the closure scan."""
        import time
        for text, expect in (
            # Worst case: inside #if 0 (blanked by the sanitized view).
            ("#if 0\n[[" + "suppress," * 230_000 + "]]\n#endif\nint x;\n",
             None),
            ("[[" + "suppress," * 230_000 + "]] int x;\n", True),
            ("[[" + "xuppress," * 230_000 + "]] int x;\n", False),
        ):
            assert len(text) > 2_000_000
            t0 = time.perf_counter()
            w = compiler_sweep._suppression_witness(text)
            # guards against catastrophic (super-linear) blowup, not speed
            assert time.perf_counter() - t0 < 30
            if expect is not None:
                assert bool(w) is expect
        tu_dir = Path(compiler_sweep.__file__).parent
        pp = '# 1 "/r/a.c"\n[[' + "suppress," * 230_000 + "]]\n"
        t0 = time.perf_counter()
        compiler_sweep._closure_suppression_witness(
            pp, tu_dir, tu_dir / "compiler_sweep.py",
        )
        # guards against catastrophic (super-linear) blowup, not speed
        assert time.perf_counter() - t0 < 30


class TestAdditiveCheckPins:
    """Each additive branch, pinned where the base alone stays clean."""

    def test_spliced_with_trailing_space_attribute(self):
        """clang joins a backslash-space-newline splice; the additive
        check must catch suppress split that way where main misses
        it."""
        text = "__attribute__((sup\\ \npress)) int f(void);\n"
        assert not compiler_sweep._base_suppression_witness(text)
        assert compiler_sweep._suppression_witness(text)

    def test_digraph_flag3_linemarker_in_source(self):
        """A flag-3 marker spelled with '%:' marks the rest of the file
        as a system header; main misses it, the additive check must
        not."""
        text = '%: 1 "x.h" 3\nint x;\n'
        assert not compiler_sweep._base_suppression_witness(text)
        assert compiler_sweep._suppression_witness(text)

    def test_nul_name_counts_as_repo_authored(self, tmp_path):
        """A NUL in a marker name cannot be resolved; treating it as
        repo-authored keeps the region subject to the scan."""
        assert compiler_sweep._add_repo_authored("/x\x00y", tmp_path)

    def test_spliced_analyzer_token_in_repo_header(self, tmp_path):
        """__clang_analyzer__ split by a line splice in a repo header
        still selects analyzer-only code; main misses it."""
        hdr = tmp_path / "h.h"
        hdr.write_text("#ifndef __clang_ana\\\nlyzer__\n#endif\n")
        tu = tmp_path / "a.c"
        tu.write_text("int t;\n")
        pp = f'# 1 "{tu}"\n# 1 "{hdr}" 1\n# 2 "{tu}" 2\nint t;\n'
        assert compiler_sweep._base_closure_suppression_witness(
            pp, tmp_path, tu,
        ) == ("", "")
        w, fail = compiler_sweep._closure_suppression_witness(pp, tmp_path, tu)
        assert "__clang_analyzer__" in w and "h.h" in w, (w, fail)

    def test_escaped_missing_header_fails_vet(self, tmp_path):
        """An escaped header name that does not exist must fail the vet;
        main reads it as clean."""
        tu = tmp_path / "a.c"
        tu.write_text("int t;\n")
        pp = f'# 1 "{tu}"\n# 1 "{tmp_path}/q\\"missing.h" 1\nint t;\n'
        assert compiler_sweep._base_closure_suppression_witness(
            pp, tmp_path, tu,
        ) == ("", "")
        w, fail = compiler_sweep._closure_suppression_witness(pp, tmp_path, tu)
        assert not w and "unreadable" in fail and 'q"missing.h' in fail


class TestCompositionPins:
    """How the base and additive layers compose: base result first,
    additive vet failures only on a base-clean closure, no false vet
    failure on legitimate system or escaped names."""
    def test_file_witness_returns_base_result_first(self):
        """When main's witness fires, its result is returned rather than
        an additive one, so callers see the same text as on main."""
        text = "%:pragma clang system_header\n[[clang::suppress]] int x;\n"
        assert compiler_sweep._suppression_witness(text) == "[[clang::suppress"

    def test_nameless_marker_in_pp_fails_vet(self, tmp_path):
        """A nameless marker in -E output cannot be attributed, so the
        vet fails."""
        tu = tmp_path / "a.c"
        tu.write_text("int t;\n")
        pp = f'# 1 "{tu}"\n# 1 "/usr/include/x.h" 1 3 4\n# 5\n'
        w, fail = compiler_sweep._closure_suppression_witness(pp, tmp_path, tu)
        assert not w and "unparseable linemarker" in fail

    def test_system_to_system_rename_stays_vetted(self, tmp_path):
        """Renames between system headers are routine in real -E output
        and must not fail the vet."""
        tu = tmp_path / "a.c"
        tu.write_text("int t;\n")
        pp = (
            f'# 1 "{tu}"\n# 1 "/usr/include/a.h" 1 3 4\n'
            '# 7 "/usr/include/b.h" 3 4\nint s;\n'
            f'# 2 "{tu}" 2\nint t;\n'
        )
        assert compiler_sweep._closure_suppression_witness(
            pp, tmp_path, tu,
        ) == ("", "")

    def test_gnu_escape_line_name_in_repo_header_vetted(self, tmp_path):
        """The GNU '\\e' escape decodes to a plain in-tree name, so it
        must not fail the vet."""
        hdr = tmp_path / "h.h"
        hdr.write_text('#line 1 "\\e.h"\nint h;\n')
        tu = tmp_path / "a.c"
        tu.write_text("int t;\n")
        pp = f'# 1 "{tu}"\n# 1 "{hdr}" 1\n# 2 "{tu}" 2\nint t;\n'
        assert compiler_sweep._closure_suppression_witness(
            pp, tmp_path, tu,
        ) == ("", "")


class TestBaseGolden:
    """Fixed expected outputs of the base layer: one golden input per
    alternative of the base regex, and the base closure result for each
    of its outcomes. These also guard the shared callees
    (``sanitized_view``, ``read_text_capped``) that the historical
    oracle cannot guard independently."""

    @pytest.mark.parametrize("text,expected", [
        ('#pragma GCC diagnostic ignored "-Wall"', "#pragma GCC diagnostic ignored"),
        ("#pragma clang system_header", "#pragma clang system_header"),
        ('# 1 "x.h" 3', '# 1 "   " 3'),
        ('#line 1 "x.h" 3', '#line 1 "   " 3'),
        ('_Pragma("x")', "_Pragma("),
        ("#ifndef __clang_analyzer__", "__clang_analyzer__"),
        ("[[clang::suppress]]", "[[clang::suppress"),
        ('[[gsl::suppress("t")]]', "[[gsl::suppress"),
        ("__attribute__((suppress))", "__attribute__((suppress"),
        ("/* [[clang::suppress]] */", ""),
        ('const char *s = "#pragma clang system_header";', ""),
    ])
    def test_base_witness_golden(self, text, expected):
        """One golden input per alternative of main's witness pins its
        behaviour, not just its text."""
        assert compiler_sweep._base_suppression_witness(
            text + "\nint x;\n",
        ) == expected

    def test_base_closure_golden(self, tmp_path):
        """Golden closures pin main's closure results for pragma,
        attribute, header-conditional, unreadable-file and
        relabelling cases."""
        tu = tmp_path / "a.c"
        tu.write_text("int t;\n")
        hdr = tmp_path / "h.h"
        hdr.write_text("#ifndef __clang_analyzer__\n#endif\n")
        lm = tmp_path / "l.h"
        lm.write_text('#line 1 "/usr/include/z.h"\n')
        base = compiler_sweep._base_closure_suppression_witness
        assert base(f'# 1 "{tu}"\n#pragma clang system_header\n',
                    tmp_path, tu) == (
            f"#pragma clang system_header (in {tu})", "")
        assert base(f'# 1 "{tu}"\n[[gsl::suppress("t")]] int x;\n',
                    tmp_path, tu) == (f"[[gsl::suppress (in {tu})", "")
        assert base(f'# 1 "{hdr}" 1\n', tmp_path, tu) == (
            f"__clang_analyzer__ (in {hdr})", "")
        assert base(f'# 1 "{tmp_path}/missing.h" 1\n', tmp_path, tu) == (
            "", f"closure file {tmp_path}/missing.h unreadable")
        w, fail = base(f'# 1 "{lm}" 1\n', tmp_path, tu)
        assert not w and "/usr/include/z.h" in fail
        assert base(f'# 1 "{tu}"\nint t;\n', tmp_path, tu) == ("", "")


# ---------------------------------------------------------------------------
# Layer 2: further additive checks. The base result and
# the layer-1 result are returned unchanged whenever they are not clean;
# layer 2 runs only on a base- and layer-1-clean input and may only add a
# witness or a vet failure. Each new check is tested DIRECTLY (layer 2 on
# its own) as well as through the composite, so an older broad witness
# cannot mask a broken new check.
# ---------------------------------------------------------------------------

_NULL_FN = "int f(int c){ int *p = 0; if (c) return 0; return *p; }\n"


def _clang_pp(tu: Path, *, cwd: Path | None = None,
              inc: tuple[str, ...] = (), cxx: bool = False) -> str:
    cc = _CLANG
    if cxx and _CLANG:
        cc = str(Path(_CLANG).with_name("clang++"))
    tu_arg = str(tu) if cwd is None else os.path.relpath(tu, cwd)
    proc = subprocess.run(
        [cc, "-E", "-D__clang_analyzer__=1", *inc, tu_arg],
        capture_output=True, text=True, cwd=cwd, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def _clean(result: tuple[str, str]) -> bool:
    return result == ("", "")


@needs_clang
class TestLayer2PresumedNames:
    """A #line / linemarker PRESUMED name that leaves the tree.

    The presumed name is a label, not a path clang resolves. Layer 2
    applies compiler-scan's consumer policy (a relative diagnostic path
    is resolved against the TU directory and dropped when it lands
    outside the target): a relative name is resolved against the TU
    directory; an escaping, unresolvable or Windows-like name
    (conservative policy — backslashes are legal POSIX characters) is a
    vet failure, never "in tree". The sweep's base `_repo_authored`
    rule (relative = in tree) is untouched."""

    def test_relative_rename_escaping_tree_fails_vet(self, tmp_path):
        tu = _write(tmp_path, "t.c", "int t;\n")
        pp = f'# 1 "{tu}"\n# 1 "../outside.c"\nint t;\n'
        w, fail = compiler_sweep._l2_closure(pp, tmp_path, tu)
        assert not w and "../outside.c" in fail
        assert compiler_sweep._closure_suppression_witness(
            pp, tmp_path, tu) == ("", fail)
        ctl = f'# 1 "{tu}"\n# 1 "sub/x.c"\nint t;\n'
        assert _clean(compiler_sweep._closure_suppression_witness(
            ctl, tmp_path, tu))

    @pytest.mark.parametrize("line,escapes", [
        ('#line 1 "../../x.c"', True), ('#line 1 "../x.c"', False),
        ('# 1 "../../x.c"', True),
    ])
    def test_source_line_from_nested_tu(self, tmp_path, line, escapes):
        tu = _write(tmp_path, "tgt/sub/t.c", f"{line}\n{_NULL_FN}")
        _write(tmp_path, "tgt/x.c", "")
        target = tmp_path / "tgt"
        got = compiler_sweep._closure_suppression_witness(
            _clang_pp(tu), target, tu)
        if escapes:
            assert not got[0] and "re-attributes lines to" in got[1], got
        else:
            assert _clean(got), got

    def test_header_authored_line_with_directories(self, tmp_path):
        target = tmp_path / "tgt"
        _write(target, "inc/h.h",
               '#line 1 "../../../escape/x.c"\nstatic int g;\n')
        tu = _write(target, "sub/t.c", '#include "../inc/h.h"\nint t;\n')
        w, fail = compiler_sweep._closure_suppression_witness(
            _clang_pp(tu), target, tu)
        assert not w and "h.h" in fail and "escape/x.c" in fail
        _write(target, "inc/h.h", '#line 1 "dir/x.c"\nstatic int g;\n')
        assert _clean(compiler_sweep._closure_suppression_witness(
            _clang_pp(tu), target, tu))

    def test_symlink_escape_is_unvetted(self, tmp_path):
        target = tmp_path / "tgt"
        (tmp_path / "outside").mkdir()
        target.mkdir()
        (target / "link").symlink_to("../outside")
        tu = _write(target, "t.c", f'#line 1 "link/x.c"\n{_NULL_FN}')
        w, fail = compiler_sweep._closure_suppression_witness(
            _clang_pp(tu), target, tu)
        assert not w and "link/x.c" in fail

    def test_symlinked_target_root_stays_vetted(self, tmp_path):
        real = tmp_path / "real"
        tu_real = _write(real, "t.c", f'#line 1 "x.c"\n{_NULL_FN}')
        (tmp_path / "tgt").symlink_to("real")
        target = tmp_path / "tgt"
        tu = target / "t.c"
        assert tu_real.exists()
        assert _clean(compiler_sweep._closure_suppression_witness(
            _clang_pp(tu), target, tu))

    @pytest.mark.parametrize("inside", [False, True])
    def test_symlinked_tu_fails_closed(self, tmp_path, inside):
        # A TU that is itself a symlink (to a file outside the tree, or
        # inside it) cannot be read by the capped, no-follow reader:
        # the vet fails closed (base result, returned unchanged).
        target = tmp_path / "tgt"
        real = _write(target if inside else tmp_path,
                      "real/t.c" if inside else "outside/t.c", _NULL_FN)
        target.mkdir(exist_ok=True)
        (target / "t.c").symlink_to(real)
        tu = target / "t.c"
        w, fail = compiler_sweep._closure_suppression_witness(
            _clang_pp(tu), target, tu)
        assert not w and "unreadable" in fail, fail

    @pytest.mark.parametrize("name", [
        r"C:\\x\\t.c", r"\\\\srv\\share\\t.c", "C:t.c", r"dir\\t.c",
    ])
    def test_windows_like_names_are_unvetted(self, tmp_path, name):
        tu = _write(tmp_path, "t.c", f'#line 1 "{name}"\n{_NULL_FN}')
        w, fail = compiler_sweep._closure_suppression_witness(
            _clang_pp(tu), tmp_path, tu)
        assert not w and "Windows-like" in fail, fail

    def test_resolution_failure_is_unvetted(self, tmp_path, monkeypatch):
        tu = _write(tmp_path, "t.c", "int t;\n")
        real_resolve = compiler_sweep._bounded_realpath

        def resolve(path, budget):
            if "boom" in path:
                raise OSError("simulated resolution failure")
            return real_resolve(path, budget)

        monkeypatch.setattr(compiler_sweep, "_bounded_realpath", resolve)
        why = compiler_sweep._presumed_name_outside(
            "boom/x.c", tmp_path, tmp_path.resolve())
        assert "unresolvable" in why
        pp = f'# 1 "{tu}"\n# 1 "boom/x.c"\nint t;\n'
        w, fail = compiler_sweep._closure_suppression_witness(
            pp, tmp_path, tu)
        assert not w and "unresolvable" in fail

    def test_cwd_relative_include_marker_resolving_to_wrong_file(
        self, tmp_path, monkeypatch,
    ):
        # A compiler-cwd-relative include marker (relative -I) can name
        # an EXISTING but WRONG file relative to the vetting process's
        # cwd. Base reads the wrong (clean) file and vets clean; layer 2
        # treats any relative include-entry marker as unverifiable.
        target = tmp_path / "tgt"
        _write(target, "inc/h.h",
               "#ifndef __clang_analyzer__\n#endif\nstatic int g;\n")
        tu = _write(target, "sub/t.c", '#include "h.h"\nint t;\n')
        pp = _clang_pp(tu, cwd=target, inc=("-Iinc",))
        assert '"inc/h.h" 1' in pp
        decoy = tmp_path / "decoy"
        _write(decoy, "inc/h.h", "static int g;\n")
        _write(decoy, "sub/t.c", "int t;\n")
        monkeypatch.chdir(decoy)
        assert _clean(compiler_sweep._base_closure_suppression_witness(
            pp, target, tu))
        w, fail = compiler_sweep._closure_suppression_witness(pp, target, tu)
        assert not w and "relative include marker" in fail, (w, fail)

    def test_cwd_relative_include_unreadable_keeps_base_failure(
        self, tmp_path, monkeypatch,
    ):
        target = tmp_path / "tgt"
        _write(target, "inc/h.h", "static int g;\n")
        tu = _write(target, "sub/t.c", '#include "h.h"\nint t;\n')
        pp = _clang_pp(tu, cwd=target, inc=("-Iinc",))
        monkeypatch.chdir(tmp_path)
        assert compiler_sweep._closure_suppression_witness(
            pp, target, tu) == ("", "closure file inc/h.h unreadable")

    @pytest.mark.parametrize("lead", ["\u00a0", "\u2028", "\u3000"])
    def test_unicode_led_line_directive_unvetted(self, tmp_path, lead):
        tu = _write(tmp_path, "t.c",
                    f'{lead}#line 1 "/usr/include/zz.h"\n{_NULL_FN}')
        w, fail = compiler_sweep._closure_suppression_witness(
            _clang_pp(tu), tmp_path, tu)
        assert not w and "/usr/include/zz.h" in fail

    def test_layer2_runs_only_on_clean_lower_layers(self, tmp_path):
        tu = _write(tmp_path, "t.c", "int t;\n")
        base_fail = f'# 1 "{tu}"\n# 1 "/usr/include/a.h"\nint t;\n'
        # layer 1 already fails this (absolute out-of-tree rename):
        layer1 = compiler_sweep._additive_closure(base_fail, tmp_path, tu)
        assert layer1[1]
        assert compiler_sweep._closure_suppression_witness(
            base_fail, tmp_path, tu) == layer1


@needs_clang
@pytest.mark.slow
class TestLayer2SweepEndToEnd:
    """slow: real-clang sweep runs. Forged refutations on head become
    inconclusive."""

    @pytest.mark.parametrize("name,text", [
        ("rel_line.c", f'#line 1 "../outside.c"\n{_NULL_FN}'),
        ("nested_parens.c",
         "__attribute__((aligned(sizeof(int)),\n  suppress)) " + _NULL_FN),
        ("struct_sizeof.c",
         "__attribute__((aligned(sizeof(struct { int x; })),\n  suppress)) "
         + _NULL_FN),
    ])
    def test_forged_refutation_is_inconclusive(
        self, tmp_path, sandbox_spy, monkeypatch, name, text,
    ):
        real_which = shutil.which
        monkeypatch.setattr(shutil, "which", lambda n, *a, **k: None
                            if n == "gcc" else real_which(n, *a, **k))
        target = tmp_path / "repo"
        _write(target, name, text)
        result = _guarded_compiler_sweep(
            gcc_probed=False, target_path=target, file_path=name,
            function_name="f", hypothesis="null dereference of `p` in f",
            cwe="CWE-476", line_start=1, line_end=5, out_dir=tmp_path / "out",
        )
        assert result.outcome == "inconclusive", vars(result)

    def test_control_still_confirms(self, tmp_path, sandbox_spy, monkeypatch):
        real_which = shutil.which
        monkeypatch.setattr(shutil, "which", lambda n, *a, **k: None
                            if n == "gcc" else real_which(n, *a, **k))
        target = tmp_path / "repo"
        _write(target, "ctl.c", _NULL_FN)
        result = _guarded_compiler_sweep(
            gcc_probed=False, target_path=target, file_path="ctl.c",
            function_name="f", hypothesis="null dereference of `p` in f",
            cwe="CWE-476", line_start=1, line_end=5, out_dir=tmp_path / "out",
        )
        assert result.outcome == "confirmed", vars(result)


def _l2_scan(text: str, *, pp: bool = False) -> list:
    return list(compiler_sweep._attr_token_scan(text, preprocessed=pp))


def _l2_file(text: str) -> str:
    return compiler_sweep._l2_file_scan(text).witness


class TestLayer2AttributeScan:
    """Token-aware attribute-list scan (layer 2). Every case is
    asserted on the scanner itself AND through the composite witness."""

    @pytest.mark.parametrize("text", [
        # nested types / expressions in an argument
        "__attribute__((aligned(sizeof(struct { int x; })),\n  suppress)) int f(void);",
        "__attribute__((aligned(sizeof(int)),\n  suppress)) int f(void);",
        "[[gnu::aligned(sizeof(int)),\n  clang::suppress]] int f(void);",
        # literal / comment delimiters
        '__attribute__((annotate("))"),\n\n  suppress)) int f(void);',
        "__attribute__((aligned(16) /* )) */,\n  suppress)) int f(void);",
        # a second opener after a closed list
        "__attribute__((cold)) __attribute__((aligned(16),\n  suppress)) int f(void);",
        # far beyond the layer-1 8-line carry
        "[[\n" + "gnu::cold,\n" * 30 + "clang::suppress]] int f(void);",
        # expanded delimiter macro (raw text: RP is an identifier)
        "#define RP )\n__attribute__((aligned(8 RP,\n  suppress)) int f(void);",
        # whole attribute produced by a macro body
        "#define NOCHECK __attribute__((aligned(sizeof(int)),\\\n  suppress))\nNOCHECK int f(void);",
    ])
    def test_suppress_in_list_is_witnessed(self, text):
        assert _l2_scan(text), text
        assert _l2_file(text), text
        assert compiler_sweep._suppression_witness(text), text

    def test_list_closed_before_suppress_is_not_a_layer2_witness(self):
        assert _l2_scan("__attribute__((cold)) int suppress;\n") == []
        assert _l2_scan("id o = [[NSObject alloc] init]; int suppress;\n") == []

    # -- raw strings (do not nest; only the outer terminator counts) ----
    @pytest.mark.parametrize("text,expect", [
        ('[[deprecated(R"x( R"y( )y" ]] )x"), clang::suppress]] int f();', True),
        ('[[deprecated(R"a(")]]"("[[)a"),\n clang::suppress]] int f();', True),
        ('[[deprecated(R"x(abc )y" ]]\nint f(); int suppress;', True),  # truncated: unverifiable
        ('const char *s = R"(  [[clang::suppress]] )";\nint f();', False),
        ('const char *s = R"q( )" ]] [[ )q";\nint suppress;', False),
    ])
    def test_raw_strings(self, text, expect):
        assert bool(_l2_scan(text)) is expect, _l2_scan(text)

    # -- digraphs / trigraphs ------------------------------------------
    @pytest.mark.parametrize("text,expect", [
        ("<:<:clang::suppress:>:> int f(void);", True),
        ("<:[clang::suppress]:> int f(void);", True),
        ("__attribute__((aligned(sizeof(struct <% int x; %>))),\n suppress)) int f(void);", True),
        ("std::vector<::foo> v;\nint suppress;", False),
        # trigraph mode (off by default in clang's GNU modes) — scanned
        # conservatively under BOTH readings
        ("??(??(clang::suppress??)??) int f(void);", True),
        ("__attribute__((aligned(sizeof(struct ??< int x; ??>))),\n suppress)) int f(void);", True),
    ])
    def test_digraphs_and_trigraphs(self, text, expect):
        assert bool(_l2_scan(text)) is expect, _l2_scan(text)

    # -- line splices (raw-source path; the -E path is tested below) ---
    @pytest.mark.parametrize("text,expect", [
        ("__attri\\\nbute__((sup\\\npress)) int f(void);", True),
        ("__attribute__((aligned(16),\\\r\n  suppress)) int f(void);", True),
        ("__attribute__((aligned(sizeof(int)),\r\n  suppress)) int f(void);", True),
        ("#define A __attribute__((aligned(16), \\\n  suppress))\nA int f(void);", True),
        ("// note \\\n[[clang::suppress]] int f(void);", False),  # continued comment
    ])
    def test_line_splices_raw(self, text, expect):
        assert bool(_l2_file(text)) is expect, _l2_file(text)

    # -- Obj-C / C++ lambdas -------------------------------------------
    def test_objc_selector_named_suppress_is_conservative_fp(self):
        # documented conservative false positive: a message expression
        # opens like an attribute list
        assert _l2_scan("[[obj suppress:1] other];\n")

    @pytest.mark.parametrize("text,expect", [
        ("[[foo::bar([&](int x){ return x; }), clang::suppress]] int f();", True),
        ("[[foo::bar([=]{ int y[2]; return y[0]; }),\n gnu::cold]] int f(); int suppress;", False),
        ("[[gnu::cold, foo::bar([[maybe_unused]] int), clang::suppress]] int f();", True),
    ])
    def test_cxx_lambdas_and_nested_attributes(self, text, expect):
        assert bool(_l2_scan(text)) is expect, _l2_scan(text)

    # -- uncertain input: a witness, never certified absence -----------
    @pytest.mark.parametrize("text,why", [
        ("__attribute__((aligned(8]), int x;", "unbalanced"),
        ("[[gnu::cold,\n" + "gnu::hot,\n" * 5000, "still open"),
        ('[[deprecated("x\n', "still open"),
        ('const char*s = R"x(abc\n[[clang::suppress]] int y;', "unverifiable"),
        ("[[" + "(" * 5000, "nesting"),
    ])
    def test_uncertain_lists_are_witnesses(self, text, why):
        hits = _l2_scan(text)
        assert hits and why in hits[0][1], hits

    def test_runaway_literal_without_opener_is_clean(self):
        assert _l2_scan('const char*s = R"x(abc\nint y;\n') == []

    def test_combining_mark_identifier_is_not_a_raw_prefix(self):
        assert _l2_scan('#pragma foo áR"("\n[[clang::suppress]] int f;')

    # -- preprocessed (-E) path ------------------------------------------
    def test_pp_skips_column0_directives_and_attributes_owner(self, tmp_path):
        tu = _write(tmp_path, "t.c", "int t;\n")
        pp = (f'# 1 "{tu}"\n__attribute__((annotate("))"),\n\n'
              "#pragma clang diagnostic push\n  suppress)) int f(void);\n")
        w, fail = compiler_sweep._l2_closure(pp, tmp_path, tu)
        assert "suppress" in w and str(tu) in w and not fail
        sys_pp = (f'# 1 "{tu}"\n# 1 "/usr/include/s.h" 1 3 4\n'
                  "__attribute__((aligned(sizeof(int)),\n suppress)) int g(void);\n"
                  f'# 2 "{tu}" 2\nint t;\n')
        assert _clean(compiler_sweep._l2_closure(sys_pp, tmp_path, tu))

    @needs_clang
    @pytest.mark.parametrize("src", [
        # spliced source, then real clang -E
        "__attribute__((aligned(sizeof(int)),\\\n  suppress)) " + _NULL_FN,
        # token-pasted name: invisible in raw text, present in -E
        "#define CAT(a,b) a##b\n__attribute__((aligned(sizeof(int)),\n  CAT(sup,press))) "
        + _NULL_FN,
        # macro-produced _Pragma operator inside the argument list
        "#define P(x) _Pragma(#x)\n__attribute__((aligned(sizeof(int)) "
        "P(clang diagnostic push),\n  suppress)) " + _NULL_FN,
    ])
    def test_preprocessed_path_real_clang(self, tmp_path, src):
        tu = _write(tmp_path, "t.c", src)
        pp = _clang_pp(tu)
        w, fail = compiler_sweep._closure_suppression_witness(pp, tmp_path, tu)
        assert w or fail, pp

    @needs_clang
    def test_token_pasted_name_needs_the_pp_path(self, tmp_path):
        src = ("#define CAT(a,b) a##b\n__attribute__((aligned(sizeof(int)),\n"
               "  CAT(sup,press))) " + _NULL_FN)
        assert _l2_scan(src) == []          # raw text: no `suppress` token
        tu = _write(tmp_path, "t.c", src)
        w, _ = compiler_sweep._l2_closure(_clang_pp(tu), tmp_path, tu)
        assert "suppress" in w              # -E text: caught

    # -- complexity --------------------------------------------------------
    def test_scanner_is_linear(self):
        import time

        def cost(k):
            text = ("__attribute__((aligned(sizeof(int)))) int a;\n"
                    '[[deprecated("))")]] int b; const char*s=R"d(x)d";\n'
                    "[ \t\t\t\t x ] <: y :> ( z )\n") * k
            t0 = time.perf_counter()
            assert _l2_scan(text) == []
            return time.perf_counter() - t0

        small, big = cost(5_000), cost(40_000)
        assert big < max(small, 0.01) * 24, (small, big)  # 8x input

    def test_scanner_terminates_on_malformed_input(self):
        import random
        import time
        rng = random.Random(1307)
        alphabet = "[](){}<:%>\"'/*R\\\n #;?suppre__attributé"
        t0 = time.perf_counter()
        for _ in range(3000):
            text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 300)))
            _l2_scan(text)
            _l2_scan(text, pp=True)
        assert time.perf_counter() - t0 < 30


class TestWitnessKind:
    """Presentation-only classification of a witness string."""

    @pytest.mark.parametrize("witness,kind", [
        ("_Pragma( (in /x/platform.h)", "pragma_operator"),
        ("__clang_analyzer__ (in /x/memory.h)", "analyzer_conditional"),
        ("#pragma GCC diagnostic ignored", "diagnostic_pragma"),
        ("#pragma clang system_header (in /x/h.h)", "system_header"),
        ('# 1 "   " 3', "system_header"),
        ("[[clang::suppress", "suppress_attribute"),
        ("__attribute__((aligned(sizeof(int)), suppress (in /x/t.c)", "suppress_attribute"),
        ("[[gnu::cold, gnu::hot … (attribute list still open at end of input)",
         "unverifiable_attribute_list"),
        ("__attribute__((aligned(8] … (unbalanced attribute list)",
         "unverifiable_attribute_list"),
        ("something else", "other"),
    ])
    def test_kinds(self, witness, kind):
        assert compiler_sweep._witness_kind(witness)[0] == kind

    def test_classification_does_not_change_the_witness(self):
        assert compiler_sweep._suppression_witness('_Pragma("x")\nint y;\n') == "_Pragma("


_ORACLE_PATH = Path(__file__).parent / "data" / "compiler_sweep_2ac96303_witness.py"


def _load_oracle():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "compiler_sweep_2ac96303_witness", _ORACLE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestHistoricalOracle:
    """The live base layer is compared against a verbatim historical
    copy of main's witness (tests/data), so the live base and its
    oracle cannot narrow together."""

    # sha256 of tests/data/compiler_sweep_2ac96303_witness.py
    _ORACLE_SHA256 = (
        "59e3730c0662b5c5a63cd722c5c36b67e1e30bae9d6bd85871742cf7d0b77c7d"
    )

    def test_oracle_provenance_is_pinned(self):
        import hashlib
        data = _ORACLE_PATH.read_bytes()
        assert hashlib.sha256(data).hexdigest() == self._ORACLE_SHA256
        text = data.decode()
        assert "commit 2ac96303, lines\n490-677" in text

    def test_oracle_constants_and_dependencies_are_pinned(self):
        o = _load_oracle()
        assert (o._MAX_CLOSURE_FILES, o._MAX_CLOSURE_FILE_BYTES,
                o._MAX_PP_TEXT_BYTES) == (200, 2_000_000, 64_000_000)
        assert (compiler_sweep._MAX_CLOSURE_FILES,
                compiler_sweep._MAX_CLOSURE_FILE_BYTES,
                compiler_sweep._MAX_PP_TEXT_BYTES) == (200, 2_000_000, 64_000_000)
        for name in ("_DIAG_SUPPRESSION_RE", "_PP_LINEMARKER_RE",
                     "_PP_SUPPRESSION_RE", "_SRC_LINEMARKER_RE"):
            live, old = getattr(compiler_sweep, name), getattr(o, name)
            assert (live.pattern, live.flags) == (old.pattern, old.flags), name
        from core.source import read_text_capped
        assert o.read_text_capped is read_text_capped

    def test_shared_sanitized_view_fixed_output(self):
        import hashlib
        from core.audit.source_view import sanitized_view
        src = ('/* [[clang::suppress]] */ int a; // __clang_analyzer__\n'
               'const char *s = "#pragma clang system_header";\n'
               "char c = '\"';\n"
               'const char *r = R"x( _Pragma("y") )x";\n'
               '#if 0\n#pragma GCC diagnostic ignored "-Wall"\n#endif\n'
               '#pragma clang system_header\n_Pragma("z") int b;\n')
        out = sanitized_view(src, "tu.c")
        assert hashlib.sha256(out.encode()).hexdigest() == (
            "3b97c0fec7868ef93bb23626a659db0401bd8db8b99ca5558ea1f45222bb0928"
        ), repr(out)

    def test_shared_read_text_capped_fixed_output(self, tmp_path):
        from core.source import read_text_capped
        cases = {
            "below": ("ab\ncd\n", ("ab\ncd\n", False)),
            "at": ("abcdef\nghi\n", ("abcdef\nghi\n", False)),
            "above": ("abcdef\nghij\nkl\n", ("abcdef\n", True)),
            "oneline": ("x" * 20, ("x" * 11, True)),
        }
        for name, (text, expected) in cases.items():
            p = tmp_path / name
            p.write_text(text)
            assert read_text_capped(p, 11) == expected, name
        link = tmp_path / "link"
        link.symlink_to(tmp_path / "below")
        assert read_text_capped(link, 11) is None

    _FR = ("[[clang::suppress]]", '[[gsl::suppress("t")]]', "__attribute__((suppress))",
           '#pragma GCC diagnostic ignored "-Wall"', "#pragma clang system_header",
           '_Pragma("x")', "#ifndef __clang_analyzer__", '# 1 "x.h" 3',
           '#line 1 "/usr/include/z.h"', "/*", "*/", "//", '"', "'", 'R"(', ')"',
           "\\\n", "\n", " ", "int x;", "#if 0", "#endif", "(", ")", "[", "]")

    @pytest.mark.slow
    def test_live_base_equals_oracle_exactly(self, tmp_path):
        import random
        o = _load_oracle()
        rng = random.Random(2026)
        for _ in range(10_000):
            x = "".join(rng.choice(self._FR) for _ in range(rng.randint(1, 24)))
            assert compiler_sweep._base_suppression_witness(x) == (
                o._suppression_witness(x)), repr(x)
        tu = tmp_path / "a.c"
        hdr = tmp_path / "h.h"
        hdr.write_text("#ifndef __clang_analyzer__\n#endif\n")
        markers = (f'# 1 "{tu}"\n', f'# 1 "{hdr}" 1\n', f'# 2 "{tu}" 2\n',
                   '# 1 "/usr/include/s.h" 1 3 4\n', '# 1 "/usr/include/x.h"\n',
                   f'# 1 "{tmp_path}/missing.h" 1\n')
        for _ in range(5_000):
            tu.write_text("".join(rng.choice(self._FR) for _ in range(rng.randint(1, 8))))
            pp = "".join(rng.choice(markers) if rng.random() < 0.3
                         else "".join(rng.choice(self._FR) for _ in range(5)) + "\n"
                         for _ in range(rng.randint(1, 6)))
            live = compiler_sweep._base_closure_suppression_witness(pp, tmp_path, tu)
            old = o._closure_suppression_witness(pp, tmp_path, tu)
            assert live == old, (pp, live, old)
            if old[0] or old[1]:
                assert compiler_sweep._closure_suppression_witness(
                    pp, tmp_path, tu) == old

    def test_composite_contains_oracle_on_hunt_spellings(self):
        o = _load_oracle()
        for text in (*self._FR, '__attribute__\n((suppress)) int f(void);',
                     'int a; # 1 "x.h" 3', '# 1 "x.h"\n3\nint q;'):
            want = o._suppression_witness(text + "\nint y;\n")
            if want:
                assert compiler_sweep._suppression_witness(
                    text + "\nint y;\n") == want


class TestBaseCaps:
    """Below / at / above each cap, with reduced caps (behaviour),
    plus the production-value pins in TestHistoricalOracle."""

    def _headers(self, tmp_path, n):
        tu = _write(tmp_path, "a.c", "int t;\n")
        lines = [f'# 1 "{tu}"\n']
        for i in range(n):
            h = _write(tmp_path, f"h{i}.h", "int h;\n")
            lines.append(f'# 1 "{h}" 1\n# 2 "{tu}" 2\n')
        return tu, "".join(lines)

    @pytest.mark.parametrize("n,expect_fail", [(2, False), (3, False), (4, True)])
    def test_closure_file_cap(self, tmp_path, monkeypatch, n, expect_fail):
        monkeypatch.setattr(compiler_sweep, "_MAX_CLOSURE_FILES", 4)  # TU + n
        tu, pp = self._headers(tmp_path, n)
        w, fail = compiler_sweep._closure_suppression_witness(pp, tmp_path, tu)
        assert bool(fail and "vet cap" in fail) is expect_fail, (w, fail)

    @pytest.mark.parametrize("size,expect_fail", [(99, False), (100, False), (101, True)])
    def test_closure_file_byte_cap(self, tmp_path, monkeypatch, size, expect_fail):
        monkeypatch.setattr(compiler_sweep, "_MAX_CLOSURE_FILE_BYTES", 100)
        tu = _write(tmp_path, "a.c", "int t;\n")
        h = _write(tmp_path, "h.h", ("x" * (size - 1)) + "\n")
        pp = f'# 1 "{tu}"\n# 1 "{h}" 1\n# 2 "{tu}" 2\n'
        w, fail = compiler_sweep._closure_suppression_witness(pp, tmp_path, tu)
        assert bool(fail and "byte cap" in fail) is expect_fail, (w, fail)

    @pytest.mark.parametrize("extra,expect_fail", [(-1, False), (0, False), (1, True)])
    def test_pp_text_cap(self, tmp_path, monkeypatch, extra, expect_fail):
        tu = _write(tmp_path, "a.c", "int t;\n")
        pp = f'# 1 "{tu}"\n' + "int x;\n" * 10
        monkeypatch.setattr(compiler_sweep, "_MAX_PP_TEXT_BYTES", len(pp) - extra)
        w, fail = compiler_sweep._closure_suppression_witness(pp, tmp_path, tu)
        assert bool(fail and "scan cap" in fail) is expect_fail, (w, fail)


class TestLayer2DirectPins:
    """Direct layer-2 pins for branches the lower layers normally
    pre-empt (so composite tests alone cannot see them)."""

    def test_brace_digraphs_are_typed_delimiters(self):
        # `<%` expects `%>`/`}`: a `]]` inside it is a mismatch, not the
        # end of the list.
        hits = _l2_scan("[[ns::a <% ]] %>,\n clang::suppress]] int f();")
        assert hits and "unbalanced" in hits[0][1], hits

    def test_pp_column0_directive_is_not_code(self, tmp_path):
        tu = _write(tmp_path, "t.c", "int t;\n")
        pp = f'# 1 "{tu}"\n#pragma foo [[\nint t;\n'
        assert _clean(compiler_sweep._l2_closure(pp, tmp_path, tu))
        assert _l2_scan("#pragma foo [[\nint t;\n")          # raw: scanned

    def test_unicode_led_flag3_marker_is_layer2_witness(self):
        assert _l2_file(' # 1 "x.h" 3\nint x;\n')

    def test_layer2_closure_keeps_cap_failures(self, tmp_path, monkeypatch):
        tu = _write(tmp_path, "a.c", "int t;\n")
        h = _write(tmp_path, "h.h", "x" * 200 + "\n")
        pp = f'# 1 "{tu}"\n# 1 "{h}" 1\n# 2 "{tu}" 2\n'
        monkeypatch.setattr(compiler_sweep, "_MAX_CLOSURE_FILE_BYTES", 100)
        assert "byte cap" in compiler_sweep._l2_closure(pp, tmp_path, tu)[1]
        monkeypatch.setattr(compiler_sweep, "_MAX_PP_TEXT_BYTES", 10)
        assert "scan cap" in compiler_sweep._l2_closure(pp, tmp_path, tu)[1]


class TestAuthoredMemo:
    """Both -E walks memoise repo authorship per marker NAME, within one
    call (target fixed for that call). Pins: the key is the exact name,
    and nothing leaks between calls."""

    _HDR = ("#ifndef __clang_analyzer__\n#endif\n"
            "__attribute__((aligned(sizeof(int)),\n  suppress)) int g;\n")

    @pytest.mark.parametrize("walk", ["_additive_closure", "_l2_closure"])
    def test_no_leak_between_calls_on_different_targets(self, tmp_path, walk):
        fn = getattr(compiler_sweep, walk)
        a, b = tmp_path / "A", tmp_path / "B"
        hdr = _write(a, "h.h", self._HDR)
        tu_a = _write(a, "t.c", "int t;\n")
        tu_b = _write(b, "t.c", "int t;\n")
        pp_a = f'# 1 "{tu_a}"\n# 1 "{hdr}" 1\n# 2 "{tu_a}" 2\nint t;\n'
        pp_b = f'# 1 "{tu_b}"\n# 1 "{hdr}" 1\n# 2 "{tu_b}" 2\nint t;\n'
        assert fn(pp_a, a, tu_a)[0], "header inside A is repo-authored"
        assert _clean(fn(pp_b, b, tu_b)), "same header is NOT repo for B"
        assert fn(pp_a, a, tu_a)[0]

    @pytest.mark.parametrize("walk", ["_additive_closure", "_l2_closure"])
    def test_memo_key_is_the_exact_name(self, tmp_path, monkeypatch, walk):
        fn = getattr(compiler_sweep, walk)
        target = tmp_path / "tgt"
        hdr = _write(target, "h.h", self._HDR)
        tu = _write(target, "t.c", "int t;\n")
        real, decoy = str(hdr), str(hdr).upper()
        assert real != decoy
        # A case-SENSITIVE authorship oracle (the host FS may fold case):
        monkeypatch.setattr(
            compiler_sweep, "_add_repo_authored",
            lambda name, t: name.startswith(str(target)))
        pp = (f'# 1 "{tu}"\n# 1 "{decoy}" 1\n# 2 "{tu}" 2\n'
              f'# 1 "{real}" 1\n# 2 "{tu}" 2\nint t;\n')
        w, fail = fn(pp, target, tu)
        assert w and real in w, (w, fail)

    @pytest.mark.parametrize("walk", ["_additive_closure", "_l2_closure"])
    def test_memo_answers_for_the_asked_name_not_the_current_file(
        self, tmp_path, walk,
    ):
        # In-tree renames put the current file into the memo first; a
        # later system-header entry must still be judged on ITS name.
        fn = getattr(compiler_sweep, walk)
        tu = _write(tmp_path, "t.c", "int t;\n")
        x = tmp_path / "sub" / "x.c"
        pp = (f'# 1 "{tu}"\n# 5 "{x}"\nint a;\n# 6 "{tu}"\nint b;\n'
              '# 1 "/usr/include/s.h" 1 3 4\n'
              "__attribute__((aligned(sizeof(int)),\n suppress)) int g(void);\n"
              f'# 7 "{tu}" 2\nint t;\n')
        assert _clean(fn(pp, tmp_path, tu)), fn(pp, tmp_path, tu)

    @pytest.mark.parametrize("walk", ["_additive_closure", "_l2_closure"])
    @pytest.mark.parametrize("first_inside", [True, False])
    def test_same_target_same_name_fresh_across_calls(
        self, tmp_path, walk, first_inside,
    ):
        # The header NAME stays the same; a symlinked directory flips
        # whether it is inside the target between two calls.
        fn = getattr(compiler_sweep, walk)
        target = tmp_path / "tgt"
        inside = target / "real"
        outside = tmp_path / "outside"
        for d in (inside, outside):
            _write(d, "h.h", self._HDR)
        tu = _write(target, "t.c", "int t;\n")
        link = target / "inc"
        name = f"{link}/h.h"
        pp = f'# 1 "{tu}"\n# 1 "{name}" 1\n# 2 "{tu}" 2\nint t;\n'
        results = []
        for in_tree in (first_inside, not first_inside):
            if link.is_symlink():
                link.unlink()
            link.symlink_to(inside if in_tree else outside)
            results.append(bool(fn(pp, target, tu)[0]))
        assert results == [first_inside, not first_inside], results


class TestDistinctNameQuota:
    """Per-call quota on DISTINCT linemarker names reaching the
    classifiers (both walks). Over the quota: "not vetted"."""

    N = 6

    def _pp(self, tu, k, *, repeat=1):
        lines = [f'# 1 "{tu}"\n']
        for _ in range(repeat):
            for i in range(k):
                lines.append(f'# {i + 2} "sub/n{i}.c"\nint a{i};\n')
                lines.append(f'# {i + 3} "{tu}"\n')
        return "".join(lines)

    @pytest.mark.parametrize("walk", ["_additive_closure", "_l2_closure"])
    @pytest.mark.parametrize("extra,over", [(-1, False), (0, False), (1, True)])
    def test_boundary(self, tmp_path, monkeypatch, walk, extra, over):
        monkeypatch.setattr(compiler_sweep, "_MAX_DISTINCT_MARKER_NAMES", self.N)
        tu = _write(tmp_path, "t.c", "int t;\n")
        # distinct names = the TU + k renames
        k = self.N - 1 + extra
        w, fail = getattr(compiler_sweep, walk)(self._pp(tu, k), tmp_path, tu)
        assert not w
        assert ("distinct linemarker names" in fail) is over, fail
        if not over:
            assert fail == ""

    @pytest.mark.parametrize("walk", ["_additive_closure", "_l2_closure"])
    def test_repeated_names_do_not_consume_quota(self, tmp_path, monkeypatch, walk):
        monkeypatch.setattr(compiler_sweep, "_MAX_DISTINCT_MARKER_NAMES", self.N)
        tu = _write(tmp_path, "t.c", "int t;\n")
        pp = self._pp(tu, self.N - 1, repeat=50)
        assert _clean(getattr(compiler_sweep, walk)(pp, tmp_path, tu))

    def test_every_classifier_entry_path_counts(self, tmp_path, monkeypatch):
        # marker names, include-entry names, owner of a reported list,
        # and names in repo-file #line directives all reach the quota.
        tu = _write(tmp_path, "t.c", "int t;\n")
        hdr_lines = "".join(f'#line {i} "sub/h{i}.c"\n' for i in range(1, 5))
        hdr = _write(tmp_path, "h.h", hdr_lines + "int h;\n")
        pp = f'# 1 "{tu}"\n# 1 "{hdr}" 1\n# 2 "{tu}" 2\nint t;\n'
        # Names that reach a classifier: layer 1 asks about the current
        # file on every line (tu, hdr) plus the four repo-file #line names
        # (6); layer 2 asks about the include entry (hdr) and the four
        # #line names (5).
        for walk, distinct in (("_additive_closure", 6), ("_l2_closure", 5)):
            monkeypatch.setattr(compiler_sweep, "_MAX_DISTINCT_MARKER_NAMES", distinct)
            assert _clean(getattr(compiler_sweep, walk)(pp, tmp_path, tu)), walk
            monkeypatch.setattr(compiler_sweep, "_MAX_DISTINCT_MARKER_NAMES", distinct - 1)
            fail = getattr(compiler_sweep, walk)(pp, tmp_path, tu)[1]
            assert "distinct linemarker names" in fail, (walk, fail)
        # the owner of a reported list counts too (layer 2): here the TU
        # is first asked about when the list in its region is attributed
        pp2 = (f'# 1 "{tu}"\n'
               "__attribute__((aligned(sizeof(int)),\n suppress)) int g(void);\n")
        monkeypatch.setattr(compiler_sweep, "_MAX_DISTINCT_MARKER_NAMES", 1)
        assert "suppress" in compiler_sweep._l2_closure(pp2, tmp_path, tu)[0]
        monkeypatch.setattr(compiler_sweep, "_MAX_DISTINCT_MARKER_NAMES", 0)
        assert "distinct linemarker names" in compiler_sweep._l2_closure(
            pp2, tmp_path, tu)[1]

    def test_quota_is_checked_before_resolution(self, tmp_path, monkeypatch):
        calls = []
        real = compiler_sweep._add_repo_authored
        monkeypatch.setattr(compiler_sweep, "_add_repo_authored",
                            lambda n, t: calls.append(n) or real(n, t))
        monkeypatch.setattr(compiler_sweep, "_MAX_DISTINCT_MARKER_NAMES", 2)
        c = compiler_sweep._NameClassifier(tmp_path.resolve(), tmp_path)
        c.repo("a.c")
        c.repo("b.c")
        raised = False
        try:
            c.repo("c.c")
        except compiler_sweep._DistinctNameQuotaExceeded:
            raised = True
        assert raised, "the third distinct name must exceed a quota of 2"
        assert calls == ["a.c", "b.c"]
        assert "c.c" not in c._authored and "c.c" not in c._seen

    def test_predicates_have_separate_stores(self, tmp_path):
        target = tmp_path / "tgt" / "sub"
        target.mkdir(parents=True)
        for order in ("repo-first", "outside-first"):
            c = compiler_sweep._NameClassifier(target.resolve(), target)
            if order == "repo-first":
                first, second = c.repo("../x.c"), c.outside("../x.c")
            else:
                second, first = c.outside("../x.c"), c.repo("../x.c")
            assert first is True, order          # base rule: relative = repo
            assert isinstance(second, str) and "re-attributes" in second, (
                order, second)

    def test_outside_key_is_the_exact_name(self, tmp_path, monkeypatch):
        # case-SENSITIVE presumed-name oracle (the host FS may fold case)
        monkeypatch.setattr(
            compiler_sweep, "_presumed_name_outside",
            lambda n, d, t: "" if n.startswith("IN") else f"re-attributes lines to {n}")
        c = compiler_sweep._NameClassifier(tmp_path.resolve(), tmp_path)
        assert c.outside("in/x.c") == "re-attributes lines to in/x.c"
        assert c.outside("IN/x.c") == ""

    @pytest.mark.parametrize("first_inside", [True, False])
    def test_outside_predicate_fresh_across_calls(self, tmp_path, first_inside):
        target = tmp_path / "tgt"
        (target / "real").mkdir(parents=True)
        (tmp_path / "outside").mkdir()
        tu = _write(target, "t.c", "int t;\n")
        link = target / "inc"
        pp = f'# 1 "{tu}"\n# 5 "inc/x.c"\nint a;\n'
        got = []
        for in_tree in (first_inside, not first_inside):
            if link.is_symlink():
                link.unlink()
            link.symlink_to(target / "real" if in_tree else tmp_path / "outside")
            got.append(_clean(compiler_sweep._l2_closure(pp, target, tu)))
        assert got == [first_inside, not first_inside], got

    def test_outside_predicate_no_cross_target_leak(self, tmp_path):
        a, b = tmp_path / "A", tmp_path / "B"
        tu_a = _write(a, "sub/t.c", "int t;\n")
        tu_b = _write(b, "t.c", "int t;\n")
        pp_a = f'# 1 "{tu_a}"\n# 5 "../x.c"\nint a;\n'     # A/x.c: inside A
        pp_b = f'# 1 "{tu_b}"\n# 5 "../x.c"\nint a;\n'     # tmp/x.c: outside B
        assert _clean(compiler_sweep._l2_closure(pp_a, a, tu_a))
        assert "re-attributes" in compiler_sweep._l2_closure(pp_b, b, tu_b)[1]
        assert _clean(compiler_sweep._l2_closure(pp_a, a, tu_a))


@needs_clang
@pytest.mark.slow
class TestDistinctNameQuotaEndToEnd:
    """slow: real-clang sweep. Quota exhaustion is never clean."""

    def test_quota_exhaustion_is_inconclusive(
        self, tmp_path, sandbox_spy, monkeypatch,
    ):
        real_which = shutil.which
        monkeypatch.setattr(shutil, "which", lambda n, *a, **k: None
                            if n == "gcc" else real_which(n, *a, **k))
        monkeypatch.setattr(compiler_sweep, "_MAX_DISTINCT_MARKER_NAMES", 4)
        target = tmp_path / "repo"
        body = "".join(f'#line {i} "n{i}.c"\nint v{i};\n' for i in range(1, 10))
        # A function the analyzer is silent on: without the quota this
        # silence refutes (control below); over the quota it must not.
        safe = "int f(int c){ int *p = &c; return *p; }\n"
        _write(target, "q.c", body + '#line 100 "q.c"\n' + safe)

        def sweep():
            compiler_sweep._reset_tu_cache()
            return _guarded_compiler_sweep(
                gcc_probed=False, target_path=target, file_path="q.c",
                function_name="f", hypothesis="null dereference of `p` in f",
                cwe="CWE-476", line_start=100, line_end=104,
                out_dir=tmp_path / "out")

        over = sweep()
        assert over.outcome == "inconclusive", vars(over)
        assert "distinct linemarker names" in str(vars(over))
        monkeypatch.setattr(compiler_sweep, "_MAX_DISTINCT_MARKER_NAMES", 20_000)
        assert sweep().outcome == "refuted"


# ---------------------------------------------------------------------
# Per-name resolution limits and the per-TU resolution budget
# ---------------------------------------------------------------------

def _realpath_spy(monkeypatch):
    """Record every ``_bounded_realpath`` call as ``(path, spent before)``."""
    seen: list[tuple[str, int]] = []
    real = compiler_sweep._bounded_realpath

    def spy(path, budget):
        seen.append((path, budget.spent))
        return real(path, budget)

    monkeypatch.setattr(compiler_sweep, "_bounded_realpath", spy)
    return seen


def _fs_spy(monkeypatch):
    """Record the ``os.lstat`` / ``os.readlink`` calls made by
    ``_bounded_realpath`` (and the parts of every target it read)."""
    import sys as _sys
    log: dict = {"lstat": [], "readlink": [], "target": 0, "order": []}
    real_l, real_r = os.lstat, os.readlink

    def mine():
        return _sys._getframe(2).f_code.co_name == "_bounded_realpath"

    def lstat(p, *a, **k):
        if mine():
            log["lstat"].append(str(p))
            log["order"].append("lstat")
        return real_l(p, *a, **k)

    def readlink(p, *a, **k):
        t = real_r(p, *a, **k)
        if mine():
            log["readlink"].append(str(p))
            log["target"] += len(t.split("/"))
            log["order"].append("readlink")
        return t

    monkeypatch.setattr(os, "lstat", lstat)
    monkeypatch.setattr(os, "readlink", readlink)
    return log


def _ops(log) -> int:
    return len(log["lstat"]) + len(log["readlink"]) + log["target"]


def _deep_abs(target: Path, parts: int) -> str:
    """An absolute in-target name whose ``Path(name).parts`` count is
    exactly *parts*."""
    k = parts - len(target.parts)
    assert k >= 1
    return str(target) + "/d" * (k - 1) + "/f.c"


def _long_abs(target: Path, chars: int) -> str:
    """An absolute in-target name of exactly *chars* characters, with
    components of at most 205 characters (few path components)."""
    head = str(target) + "/"
    room = chars - len(head)
    comps = []
    while room > 205:
        comps.append("d" * 199)
        room -= 200
    name = head + "/".join(comps + ["f" * (room - 2) + ".c"])
    assert len(name) == chars, (len(name), chars)
    return name


def _renames_pp(tu: Path, names: list[str]) -> str:
    out = [f'# 1 "{tu}"\n']
    for i, n in enumerate(names):
        out.append(f'# {i + 2} "{n}"\nint a{i};\n# {i + 3} "{tu}"\n')
    return "".join(out)


_LIMIT_WALKS = ["_additive_closure", "_l2_closure", "_closure_suppression_witness"]


class TestNameResolutionLimits:
    """Linemarker names that must be resolved on the filesystem are
    bounded per name (length, path components, symlink hops) and per TU
    (filesystem operations across layer 1 and layer 2, memo misses only,
    checked before each operation). Over a limit the closure is "not
    vetted"."""

    def test_limit_values(self):
        assert compiler_sweep._MAX_DISTINCT_MARKER_NAMES == 20_000
        assert compiler_sweep._MAX_RESOLVED_NAME_CHARS == 4096
        assert compiler_sweep._MAX_RESOLVED_NAME_PARTS == 256
        assert compiler_sweep._MAX_RESOLVE_OPS_PER_TU == 250_000
        assert compiler_sweep._MAX_SYMLINK_HOPS == 40
        assert compiler_sweep._VET_DEADLINE_SECONDS == 60

    @pytest.mark.parametrize("walk", _LIMIT_WALKS)
    @pytest.mark.parametrize("extra,over", [(-1, False), (0, False), (1, True)])
    def test_name_length_boundary(self, tmp_path, walk, extra, over):
        target = tmp_path / "t"
        tu = _write(target, "t.c", "int t;\n")
        name = _long_abs(target, compiler_sweep._MAX_RESOLVED_NAME_CHARS + extra)
        assert len(Path(name).parts) < compiler_sweep._MAX_RESOLVED_NAME_PARTS
        got = getattr(compiler_sweep, walk)(_renames_pp(tu, [name]), target, tu)
        if over:
            assert not got[0] and "resolution limit" in got[1], got
            assert "characters" in got[1] and name not in got[1], got
        else:
            assert _clean(got), got

    @pytest.mark.parametrize("walk", _LIMIT_WALKS)
    @pytest.mark.parametrize("extra,over", [(-1, False), (0, False), (1, True)])
    def test_name_components_boundary(self, tmp_path, walk, extra, over):
        target = tmp_path / "t"
        tu = _write(target, "t.c", "int t;\n")
        name = _deep_abs(target, compiler_sweep._MAX_RESOLVED_NAME_PARTS + extra)
        assert len(name) < compiler_sweep._MAX_RESOLVED_NAME_CHARS
        got = getattr(compiler_sweep, walk)(_renames_pp(tu, [name]), target, tu)
        if over:
            assert not got[0] and "resolution limit" in got[1], got
            assert "path components" in got[1], got
        else:
            assert _clean(got), got

    @pytest.mark.parametrize("extra,over", [(-1, False), (0, False), (1, True)])
    def test_relative_name_counts_the_tu_directory(self, tmp_path, extra, over):
        # layer 2 resolves a relative presumed name against the TU dir:
        # the resolved path's components are what is counted.
        target = tmp_path / "t"
        tu = _write(target, "t.c", "int t;\n")
        k = compiler_sweep._MAX_RESOLVED_NAME_PARTS + extra - len(target.parts)
        name = "d/" * (k - 1) + "f.c"
        got = compiler_sweep._l2_closure(_renames_pp(tu, [name]), target, tu)
        if over:
            assert "resolution limit" in got[1], got
        else:
            assert _clean(got), got

    def _spent(self, monkeypatch, walk, pp, target, tu):
        """Run *walk* with a fresh budget; return (result, spent,
        filesystem operations the bounded resolver really made)."""
        budget = compiler_sweep._ResolveBudget()
        log = _fs_spy(monkeypatch)
        got = getattr(compiler_sweep, walk)(pp, target, tu, budget=budget)
        monkeypatch.undo()
        return got, budget.spent, _ops(log)

    @pytest.mark.parametrize("walk", ["_additive_closure", "_l2_closure"])
    def test_budget_counts_each_resolve_once(self, tmp_path, monkeypatch, walk):
        target = tmp_path / "t"
        tu = _write(target, "t.c", "int t;\n")
        names = [_deep_abs(target, 20 + i) for i in range(8)]
        once = _renames_pp(tu, names)
        got, spent, made = self._spent(monkeypatch, walk, once, target, tu)
        assert _clean(got) and spent > 0
        assert spent == made, (spent, made)
        # repeats are memo hits: they cost nothing
        got2, spent2, _ = self._spent(monkeypatch, walk, once * 40, target, tu)
        assert _clean(got2) and spent2 == spent

    @pytest.mark.parametrize("walk", ["_additive_closure", "_l2_closure"])
    @pytest.mark.parametrize("extra,over", [(-1, True), (0, False), (1, False)])
    def test_budget_boundary(self, tmp_path, monkeypatch, walk, extra, over):
        target = tmp_path / "t"
        tu = _write(target, "t.c", "int t;\n")
        pp = _renames_pp(tu, [_deep_abs(target, 20 + i) for i in range(8)])
        _got, spent, _made = self._spent(monkeypatch, walk, pp, target, tu)
        monkeypatch.setattr(compiler_sweep, "_MAX_RESOLVE_OPS_PER_TU",
                            spent + extra)
        got = getattr(compiler_sweep, walk)(pp, target, tu)
        if over:
            assert not got[0] and "resolution budget" in got[1], got
        else:
            assert _clean(got), got

    @pytest.mark.parametrize("walk", ["_additive_closure", "_l2_closure"])
    def test_over_budget_name_is_never_resolved(self, tmp_path, monkeypatch, walk):
        target = tmp_path / "t"
        tu = _write(target, "t.c", "int t;\n")
        names = [_deep_abs(target, 20 + i) for i in range(6)]
        # the last name is the walk's last resolve: no rename back after it
        pp = _renames_pp(tu, names[:-1]) + f'# 99 "{names[-1]}"\nint z;\n'
        last = names[-1]
        calls = _realpath_spy(monkeypatch)
        getattr(compiler_sweep, walk)(pp, target, tu)
        before_last = next((b for path, b in calls if path == last), None)
        assert before_last is not None, "the last name was never resolved"
        monkeypatch.undo()
        monkeypatch.setattr(compiler_sweep, "_MAX_RESOLVE_OPS_PER_TU", before_last)
        log = _fs_spy(monkeypatch)
        got = getattr(compiler_sweep, walk)(pp, target, tu)
        assert "resolution budget" in got[1], got
        assert names[-2] in log["lstat"]
        assert last not in log["lstat"], "over-budget name reached the filesystem"

    @pytest.mark.parametrize("walk", ["_additive_closure", "_l2_closure"])
    def test_over_cap_name_is_never_resolved(self, tmp_path, monkeypatch, walk):
        target = tmp_path / "t"
        tu = _write(target, "t.c", "int t;\n")
        name = _deep_abs(target, compiler_sweep._MAX_RESOLVED_NAME_PARTS + 1)
        seen = _realpath_spy(monkeypatch)
        got = getattr(compiler_sweep, walk)(_renames_pp(tu, [name]), target, tu)
        assert "resolution limit" in got[1]
        assert name not in [s for s, _p in seen]

    def test_one_budget_spans_both_layers(self, tmp_path, monkeypatch):
        target = tmp_path / "t"
        tu = _write(target, "t.c", "int t;\n")
        pp = _renames_pp(tu, [_deep_abs(target, 20 + i) for i in range(8)])
        _g, s1, _m = self._spent(monkeypatch, "_additive_closure", pp, target, tu)
        _g, s2, _m = self._spent(monkeypatch, "_l2_closure", pp, target, tu)
        monkeypatch.setattr(compiler_sweep, "_MAX_RESOLVE_OPS_PER_TU",
                            max(s1, s2))
        assert _clean(compiler_sweep._additive_closure(pp, target, tu))
        assert _clean(compiler_sweep._l2_closure(pp, target, tu))
        got = compiler_sweep._closure_suppression_witness(pp, target, tu)
        assert not got[0] and "resolution budget" in got[1], got
        monkeypatch.setattr(compiler_sweep, "_MAX_RESOLVE_OPS_PER_TU", s1 + s2)
        assert _clean(compiler_sweep._closure_suppression_witness(pp, target, tu))

    def test_resolve_argument_mirrors_the_predicates(self, tmp_path, monkeypatch):
        # The classifier caps exactly the path each predicate hands to
        # the bounded resolver, and nothing for names it does not resolve.
        target = (tmp_path / "t")
        target.mkdir()
        tu_dir = target / "sub"
        tu_dir.mkdir()
        names = ["", "<built-in>", "<a/../b>", "rel/x.c", "../x.c", "./x.c",
                 str(target / "a.c"), "/usr/include/s.h", "C:\\x.c", "C:t.c",
                 "a\\b.c", "\\\\srv\\s\\x.c", "a<b/../../o.c", "x\0y.c"]
        for name in names:
            for pred in ("repo", "outside"):
                seen = _realpath_spy(monkeypatch)
                if pred == "repo":
                    compiler_sweep._add_repo_authored(name, target)
                    arg = compiler_sweep._repo_resolve_arg(name)
                else:
                    compiler_sweep._presumed_name_outside(name, tu_dir, target)
                    arg = compiler_sweep._outside_resolve_arg(name, tu_dir)
                monkeypatch.undo()
                assert [s for s, _p in seen] == ([] if arg is None else [str(arg)]), (
                    pred, name, seen, arg)

    def test_symlink_then_dotdot_resolves_physically(self, tmp_path):
        # repo/link -> outside/dir: "link/../f.c" lexically stays in the
        # repo but physically lands in outside/ — resolution is kept.
        target = tmp_path / "repo"
        tu = _write(target, "t.c", "int t;\n")
        (tmp_path / "outside" / "dir").mkdir(parents=True)
        (target / "link").symlink_to(tmp_path / "outside" / "dir")
        pp = _renames_pp(tu, ["link/../f.c"])
        got = compiler_sweep._l2_closure(pp, target, tu)
        assert not got[0] and "re-attributes lines to link/../f.c" in got[1], got
        assert compiler_sweep._closure_suppression_witness(pp, target, tu) == got

    @pytest.mark.parametrize("case", ["dangling_out", "dangling_in", "loop"])
    def test_dangling_and_looping_links_follow_resolve(self, tmp_path, case):
        target = tmp_path / "repo"
        tu = _write(target, "t.c", "int t;\n")
        link = target / "l"
        if case == "dangling_out":
            link.symlink_to(tmp_path / "gone" / "x")
        elif case == "dangling_in":
            link.symlink_to(target / "gone" / "x")
        else:
            link.symlink_to(link)
        name = "l/f.c"
        try:
            inside = (tu.parent / name).resolve().is_relative_to(target.resolve())
            expect_clean = inside
        except (OSError, RuntimeError):
            expect_clean = False
        got = compiler_sweep._l2_closure(_renames_pp(tu, [name]), target, tu)
        assert _clean(got) is expect_clean, (case, got)

    def test_earlier_witness_is_kept_over_a_limit(self, tmp_path):
        target = tmp_path / "t"
        tu = _write(target, "t.c", "int t;\n")
        deep = _deep_abs(target, compiler_sweep._MAX_RESOLVED_NAME_PARTS + 1)
        pp = (f'# 1 "{tu}"\n#pragma clang diagnostic ignored "-Wall"\n'
              f'# 2 "{deep}"\nint a;\n')
        w, fail = compiler_sweep._closure_suppression_witness(pp, target, tu)
        assert "diagnostic ignored" in w and fail == "", (w, fail)

    def test_deep_names_under_the_quota_end_not_vetted_quickly(self, tmp_path):
        # Many distinct deep in-tree names, each well under the quota:
        # without a per-name bound every one is resolved component by
        # component and the closure comes back clean.
        import time
        target = tmp_path / "t"
        tu = _write(target, "t.c", "int t;\n")
        lines = [f'# 1 "{tu}"']
        for i in range(400):
            lines.append(f'# 1 "{"x/" * 1500}f{i}.c"')
            lines.append(f"int a{i};")
        pp = "\n".join(lines) + "\n"
        t0 = time.perf_counter()
        got = compiler_sweep._closure_suppression_witness(pp, target, tu)
        took = time.perf_counter() - t0
        assert not got[0] and "resolution limit" in got[1], got
        assert took < 5.0, took


@needs_clang
@pytest.mark.slow
class TestResolutionLimitEndToEnd:
    """slow: real-clang sweep. A resolution limit is never clean."""

    def _sweep(self, tmp_path, monkeypatch, text):
        real_which = shutil.which
        monkeypatch.setattr(shutil, "which", lambda n, *a, **k: None
                            if n == "gcc" else real_which(n, *a, **k))
        target = tmp_path / "repo"
        _write(target, "q.c", text)
        compiler_sweep._reset_tu_cache()
        return _guarded_compiler_sweep(
            gcc_probed=False, target_path=target, file_path="q.c",
            function_name="f", hypothesis="null dereference of `p` in f",
            cwe="CWE-476", line_start=100, line_end=104,
            out_dir=tmp_path / "out")

    @pytest.mark.parametrize("parts,outcome", [(400, "inconclusive"),
                                               (3, "refuted")])
    def test_over_limit_name_is_inconclusive(
        self, tmp_path, sandbox_spy, monkeypatch, parts, outcome,
    ):
        safe = "int f(int c){ int *p = &c; return *p; }\n"
        text = f'#line 1 "{"d/" * parts}x.c"\nint v;\n#line 100 "q.c"\n{safe}'
        got = self._sweep(tmp_path, monkeypatch, text)
        assert got.outcome == outcome, vars(got)
        if outcome == "inconclusive":
            assert "resolution limit" in str(vars(got))

    def test_name_containing_lt_escaping_tree_is_inconclusive(
        self, tmp_path, sandbox_spy, monkeypatch,
    ):
        safe = "int f(int c){ int *p = &c; return *p; }\n"
        text = f'#line 1 "a<b/../../outside.c"\nint v;\n#line 100 "q.c"\n{safe}'
        got = self._sweep(tmp_path, monkeypatch, text)
        assert got.outcome == "inconclusive", vars(got)
        assert "a<b/../../outside.c" in str(vars(got))


class TestNamePins:
    def test_name_containing_lt_is_not_a_pseudo_file(self, tmp_path):
        target = tmp_path / "t"
        tu = _write(target, "t.c", "int t;\n")
        pp = _renames_pp(tu, ["a<b/../../outside.c"])
        got = compiler_sweep._l2_closure(pp, target, tu)
        assert not got[0] and "a<b/../../outside.c" in got[1], got
        assert compiler_sweep._closure_suppression_witness(pp, target, tu) == got
        assert compiler_sweep._presumed_name_outside(
            "<b/../../outside.c", tu.parent, target.resolve()) == ""

    def test_repo_suppress_after_system_suppress_is_reported(self, tmp_path):
        tu = _write(tmp_path, "t.c", "int t;\n")
        pp = (f'# 1 "{tu}"\nint a;\n'
              '# 1 "/usr/include/s.h" 1 3 4\n'
              "[[clang::suppress]] int sysdecl;\n"
              f'# 3 "{tu}" 2\n'
              "[[gnu::cold, clang::suppress]] int x;\n")
        hits = _l2_scan(pp, pp=True)
        assert len(hits) == 2, hits
        w, fail = compiler_sweep._l2_closure(pp, tmp_path, tu)
        assert "gnu::cold, clang::suppress" in w and str(tu) in w, (w, fail)


# ---------------------------------------------------------------------
# Layer-2 owners: change points, not one entry per line
# ---------------------------------------------------------------------

def _per_line_owner(pp: str, tu: Path):
    """Reference: the per-line ownership the layer-2 walk used to build
    (an owner per -E line; a marker's owner starts on the next line)."""
    import bisect
    owners: list[tuple[int, str]] = []
    offset, current = 0, str(tu)
    for line in pp.split("\n"):
        owners.append((offset, current))
        offset += len(line) + 1
        line = line.rstrip("\r")
        if not line.startswith("#"):
            continue
        m = compiler_sweep._ADD_DIRECTIVE_RE.match(line)
        if not m or m.group(1) == "pragma":
            continue
        current = compiler_sweep._parse_marker_operands(line[m.start(1):])[0]
    starts = [o for o, _ in owners]
    return lambda at: owners[max(0, bisect.bisect_right(starts, at) - 1)][1]


def _gen_pp(rng, target: Path, tu: Path) -> str:
    names = [str(tu), str(target / "a.h"), str(target / "sub" / "b.h"),
             str(target / "c.c")]
    pseudo = ["<built-in>", "<command-line>"]
    out = [f'# 1 "{tu}"']
    for _ in range(rng.randint(0, 60)):
        r = rng.random()
        if r < 0.35:
            n = rng.choice(names + pseudo)
            form = rng.choice(["# {l} \"{n}\"", "#line {l} \"{n}\"",
                               "# {l} \"{n}\" 1", "# {l} \"{n}\" 2",
                               "# {l} \"{n}\" 1 3", "# {l} \"{n}\" 3"])
            out.append(form.format(l=rng.randint(1, 99), n=n))
        elif r < 0.4:
            out.append('# 1 "/usr/include/s.h" ' + rng.choice(["1 3 4", "2 3 4"]))
        else:
            out.append(rng.choice(["int a;", "", ";", "  x;", "\r", "int b;\r",
                                   "#pragma once", "#define X 1", " # 1 \"z\"",
                                   "[[gnu::cold]] int c;", "x" * rng.randint(0, 9)]))
        if rng.random() < 0.05:   # dense: markers back to back
            out.append(f'# 1 "{rng.choice(names)}"')
    text = "\n".join(out)
    if rng.random() < 0.7:
        text += "\n"
    if rng.random() < 0.2:
        text = text.replace("\n", "\r\n")
    return text


def _hunt_owner_inputs(target: Path, tu: Path) -> list[str]:
    a, b = target / "sub" / "a.c", target / "sub" / "b.c"
    tri = (f'# 1 "{tu}"\nconst char *s = "{"??!" * 600}";\n'
           '# 1 "/usr/include/s.h" 1 3 4\n' + "int sysdecl_padding;\n" * 50
           + f'# 3 "{tu}" 2\n??(??(clang::suppress??)??) int x;\n')
    quota = "\n".join([f'# 1 "{tu}"'] + [
        ln for i in range(200) for ln in (f'# 1 "{"x/" * 3}f{i}.c"', f"int a{i};")]) + "\n"
    short = f'# 1 "{tu}"\n' + ";\n" * 10_000
    rep = f'# 1 "{tu}"\n' + "".join(
        f'# {i + 2} "{a if i % 2 else b}"\nint v;\n' for i in range(2_000))
    rel = f'# 1 "{tu}"\n' + "".join(f'# 1 "n{i}.c"\nint v;\n' for i in range(2_000))
    return [tri, quota, short, rep, rel]


class TestChangePointOwners:

    def _owners(self, pp, target, tu):
        names = compiler_sweep._NameClassifier(target.resolve(), tu.parent)
        owners, _repo_files, failure = compiler_sweep._l2_marker_pass(
            pp, tu, names)
        assert failure == "", failure
        return owners

    def _check(self, pp, target, tu):
        ref = _per_line_owner(pp, tu)
        owners = self._owners(pp, target, tu)
        # every line start, its neighbours and every newline; offsets past
        # len(pp) are never produced by the scanner
        probes = {0, len(pp)}
        pos = 0
        while True:
            nl = pp.find("\n", pos)
            for d in (-1, 0, 1):
                probes.add(min(len(pp), max(0, pos + d)))
            if nl < 0:
                break
            probes.update((nl, nl + 1))
            pos = nl + 1
        for at in sorted(probes):
            assert owners.at(at) == ref(at), (at, pp[max(0, at - 40):at + 40])
        return owners

    def test_matches_per_line_ownership_on_generated_texts(self, tmp_path):
        import random
        target = tmp_path / "t"
        tu = _write(target, "t.c", "int t;\n")
        rng = random.Random(14_2000)
        for _ in range(2000):
            self._check(_gen_pp(rng, target, tu), target, tu)

    def test_matches_per_line_ownership_on_hunt_inputs(self, tmp_path):
        target = tmp_path / "t"
        tu = _write(target, "t.c", "int t;\n")
        for pp in _hunt_owner_inputs(target, tu):
            self._check(pp, target, tu)

    def test_storage_is_per_owner_change(self, tmp_path):
        target = tmp_path / "t"
        tu = _write(target, "t.c", "int t;\n")
        h = target / "h.h"
        pp = (f'# 1 "{tu}"\n' + "int a;\n" * 5000 + f'# 1 "{h}" 1\n'
              + ";\n" * 5000 + f'# 2 "{tu}" 2\n' + f'# 9 "{tu}"\n' * 50 + "int b;\n")
        owners = self._owners(pp, target, tu)
        assert list(owners.names) == [str(tu), str(h), str(tu)]
        assert owners.at(0) == str(tu)
        first = pp.index(f'# 1 "{h}" 1\n')
        assert owners.at(first) == str(tu)       # the marker line itself
        assert owners.at(pp.index("\n", first) + 1) == str(h)

    def test_layer2_walk_memory_is_not_per_line(self, tmp_path):
        import tracemalloc
        tu = _write(tmp_path, "t.c", "int t;\n")
        pp = f'# 1 "{tu}"\n' + ";\n" * 300_000
        tracemalloc.start()
        try:
            got = compiler_sweep._l2_closure(pp, tmp_path, tu)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        assert _clean(got), got
        assert peak < 8_000_000, peak


# ---------------------------------------------------------------------
# Trigraph pass: offsets map back to the raw -E text
# ---------------------------------------------------------------------

class TestTrigraphOffsets:
    """The trigraph reading is scanned on translated text; its hit
    offsets are mapped back to raw offsets before the owner lookup.
    Covers a path the shipped scan and sweep never reach (neither passes
    ``-trigraphs`` or a strict ``-std``), kept because the scanner
    promises both readings."""

    @staticmethod
    def _pp(tu, n_tri, sys_len=50):
        return (f'# 1 "{tu}"\n'
                f'const char *s = "{"??!" * n_tri}";\n'
                '# 1 "/usr/include/s.h" 1 3 4\n'
                + ("int sysdecl_padding;\n" * sys_len) +
                f'# 3 "{tu}" 2\n'
                "??(??(clang::suppress??)??) int x;\n")

    @pytest.mark.parametrize("n_tri", [0, 10, 300, 600])
    def test_repo_list_after_trigraphs_is_caught(self, tmp_path, n_tri):
        tu = _write(tmp_path, "t.c", "int t;\n")
        pp = self._pp(tu, n_tri)
        w, fail = compiler_sweep._l2_closure(pp, tmp_path, tu)
        assert "clang::suppress" in w and fail == "", (w, fail)
        assert compiler_sweep._closure_suppression_witness(pp, tmp_path, tu)[0]

    def test_hit_offsets_are_raw_offsets(self):
        text = 'x = "' + "??!" * 7 + '";\n??(??(clang::suppress??)??) int x;\n'
        hits = _l2_scan(text, pp=True)
        assert [at for at, _w in hits] == [text.index("suppress")]

    @pytest.mark.parametrize("n_tri", [10, 300])
    def test_system_list_after_trigraph_heavy_repo_text_is_not_repo(
        self, tmp_path, n_tri,
    ):
        tu = _write(tmp_path, "t.c", "int t;\n")
        pp = (f'# 1 "{tu}"\nconst char *s = "{"??!" * n_tri}";\n'
              '# 1 "/usr/include/s.h" 1 3 4\n'
              "??(??(clang::suppress??)??) int sysdecl;\n"
              f'# 3 "{tu}" 2\nint t;\n')
        assert _clean(compiler_sweep._l2_closure(pp, tmp_path, tu))


# ---------------------------------------------------------------------
# Witness snippets carry no directive-line text
# ---------------------------------------------------------------------

class TestWitnessSnippetDirectives:

    def test_directive_lines_become_one_space_before_truncation(self):
        tool = "/opt/toolchain/" + "x" * 380 + "/stdbool.h"
        text = (f'[[gnu::aligned(8),\n# 1 "{tool}" 1 3 4\n'
                '# 4 "t.c" 2\n clang::suppress]] int y;\n')
        hits = _l2_scan(text, pp=True)
        assert len(hits) == 1, hits
        w = hits[0][1]
        assert w == "[[gnu::aligned(8), clang::suppress", w
        assert "/opt/" not in w and "#" not in w

    def test_adjacent_tokens_do_not_merge(self):
        text = '[[gnu::cold\n# 1 "/usr/include/s.h" 3\nclang::suppress]] int y;\n'
        w = _l2_scan(text, pp=True)[0][1]
        assert w == "[[gnu::cold clang::suppress", w

    def test_unterminated_list_snippet_skips_directives(self):
        text = '[[gnu::cold,\n# 1 "/usr/include/stdbool.h" 1 3\nint y;\n'
        w = _l2_scan(text, pp=True)[0][1]
        assert "/usr/include" not in w and "gnu::cold" in w, w

    def test_raw_source_snippet_is_unchanged(self):
        text = '[[gnu::cold,\n#include <stdbool.h>\n clang::suppress]] int y;\n'
        w = _l2_scan(text)[0][1]
        assert w == "[[gnu::cold, #include <stdbool.h> clang::suppress", w

    @needs_clang
    def test_real_clang_include_inside_list(self, tmp_path):
        tu = _write(tmp_path, "leak2.c",
                    "#define S suppress\n[[gnu::aligned(sizeof(int)),\n"
                    "#include <stdbool.h>\n clang::S]] int y;\n"
                    "int g(int *p){ p = 0; return *p; }\n")
        pp = _clang_pp(tu)
        tool = [ln.split('"')[1] for ln in pp.splitlines()
                if ln.startswith("# ") and "stdbool.h" in ln]
        assert tool and Path(tool[0]).is_absolute()
        w, fail = compiler_sweep._closure_suppression_witness(pp, tmp_path, tu)
        assert "clang::suppress" in w and fail == "", (w, fail)
        assert tool[0] not in w and "stdbool" not in w, w


# ---------------------------------------------------------------------
# Bounded resolution: realpath semantics, every filesystem operation
# charged, symlink hops limited, cooperative per-TU deadline
# ---------------------------------------------------------------------

def _trips(fn) -> str | None:
    """The message of the vet limit *fn* trips, or None."""
    try:
        fn()
    except compiler_sweep._VetLimitExceeded as exc:
        return str(exc)
    return None


def _link_tree(base: Path) -> Path:
    root = base.resolve()
    (root / "repo" / "sub" / "deep").mkdir(parents=True)
    (root / "out" / "dir").mkdir(parents=True)
    (root / "repo" / "file.c").write_text("x")
    (root / "repo" / "locked" / "inner").mkdir(parents=True)
    links = {
        "repo/up": "..", "repo/abs_out": str(root / "out" / "dir"),
        "repo/rel_out": "../out/dir", "repo/sub/back": "../..",
        "repo/dangle": "nope/x", "repo/dangle_abs": str(root / "gone"),
        "repo/loop1": "loop2", "repo/loop2": "loop1", "repo/self": "self",
        "repo/chain1": "chain2", "repo/chain2": "sub/deep",
        "repo/to_file": "file.c", "repo/dotdot_after": "sub/deep/../..",
        "repo/trailing": "sub/", "linkroot": "repo", "repo/rootlink": "/",
        "repo/dslash": "//out",
    }
    for rel, tgt in links.items():
        (root / rel).symlink_to(tgt)
    return root


_VOCAB = ["repo", "sub", "deep", "up", "abs_out", "rel_out", "back", "dangle",
          "dangle_abs", "loop1", "self", "chain1", "to_file", "dotdot_after",
          "trailing", "linkroot", "rootlink", "dslash", "..", ".", "",
          "file.c", "missing", "out", "dir", "locked", "inner", "x"]


class TestBoundedRealpath:
    """``_bounded_realpath`` equals ``os.path.realpath(strict=False)`` on
    POSIX whenever no limit trips; every lstat, readlink and spliced
    target component is charged before it happens."""

    def _cases(self, root: Path) -> list[str]:
        r = str(root)
        return [
            f"{r}/repo/up/repo/file.c", f"{r}/repo/rel_out/../x",
            f"{r}/repo/abs_out/../../repo", f"{r}/repo/missing/../file.c",
            f"{r}/repo/sub/", f"{r}/repo/file.c/x", f"{r}/repo/to_file/x",
            f"{r}/repo/locked/inner/x", f"/../../{r}/repo/x", f"//{r[1:]}/repo",
            f"{r}/repo/loop1/x", f"{r}/repo/self", f"{r}/repo/dangle",
            f"{r}/repo/dangle_abs/y", f"{r}/linkroot/sub/back/repo/file.c",
            f"{r}/repo/dotdot_after/x", f"{r}/repo/trailing/deep",
            f"{r}/repo/rootlink/tmp", f"{r}/repo/dslash/x", "/", "//", "/..",
        ]

    @pytest.mark.skipif(
        sys.version_info < (3, 13),
        reason="cases through symlink loops follow the Python 3.13+ "
               "os.path.realpath; 3.12 resolves them differently")
    def test_equivalent_to_realpath(self, tmp_path):
        import random
        root = _link_tree(tmp_path)
        locked = root / "repo" / "locked"
        locked.chmod(0)
        try:
            paths = self._cases(root)
            rng = random.Random(15_2000)
            for _ in range(2000):
                comps = [rng.choice(_VOCAB) for _ in range(rng.randint(1, 8))]
                lead = rng.choice([str(root) + "/", str(root) + "/repo/", "/", "//"])
                tail = rng.choice(["", "/", "//"])
                paths.append(lead + "/".join(comps) + tail)
            for p in paths:
                try:
                    got = compiler_sweep._bounded_realpath(
                        p, compiler_sweep._ResolveBudget())
                except Exception as exc:          # a divergence, not a crash
                    got = f"raised {exc!r}"
                assert got == os.path.realpath(p), p
        finally:
            locked.chmod(0o755)

    def test_symlinked_root_compares_like_with_like(self, tmp_path):
        root = _link_tree(tmp_path)
        tu = _write(root / "repo", "t.c", "int t;\n")
        target = root / "linkroot"                    # symlink to repo/
        pp = _renames_pp(tu, ["sub/x.c"])
        assert _clean(compiler_sweep._l2_closure(pp, target, target / "t.c"))
        bad = _renames_pp(tu, ["rel_out/x.c"])
        assert "re-attributes" in compiler_sweep._l2_closure(
            bad, target, target / "t.c")[1]

    def test_exact_operation_count(self, tmp_path):
        root = tmp_path.resolve()
        (root / "b" / "c").mkdir(parents=True)
        (root / "a").symlink_to("b/c")
        budget = compiler_sweep._ResolveBudget()
        got = compiler_sweep._bounded_realpath(str(root / "a" / "f.c"), budget)
        assert got == str(root / "b" / "c" / "f.c")
        prefix = len(root.parts) - 1        # one lstat per prefix component
        # a: lstat + readlink + 2 target parts; then b, c, f.c: 3 lstats
        assert budget.spent == prefix + 1 + 1 + 2 + 3, budget.spent

    @pytest.mark.parametrize("kind", ["lstat", "readlink", "target"])
    def test_budget_exhausted_before_each_operation(self, tmp_path, monkeypatch, kind):
        root = tmp_path.resolve()
        (root / "b" / "c").mkdir(parents=True)
        (root / "a").symlink_to("b/c")
        path = str(root / "a" / "f.c")
        trace: list[tuple[str, int, int]] = []
        real_op = compiler_sweep._ResolveBudget.op

        def rec(self, k, n=1):
            trace.append((k, n, self.spent))
            return real_op(self, k, n)

        monkeypatch.setattr(compiler_sweep._ResolveBudget, "op", rec)
        compiler_sweep._bounded_realpath(path, compiler_sweep._ResolveBudget())
        monkeypatch.undo()
        i = next(j for j, (k, _n, _s) in enumerate(trace) if k == kind)
        if kind == "lstat":
            i = next(j for j in range(1, len(trace)) if trace[j][0] == "lstat"
                     and trace[j - 1][0] == "target")      # first lstat after the splice
        limit = trace[i][2]
        fs_before = sum(1 for k, _n, _s in trace[:i] if k != "target")
        monkeypatch.setattr(compiler_sweep, "_MAX_RESOLVE_OPS_PER_TU", limit)
        log = _fs_spy(monkeypatch)
        msg = _trips(lambda: compiler_sweep._bounded_realpath(
            path, compiler_sweep._ResolveBudget()))
        assert msg and "resolution budget" in msg, (kind, msg)
        assert len(log["order"]) == fs_before, (kind, log["order"], fs_before)

    @pytest.mark.parametrize("hops,over", [(39, False), (40, False), (41, True)])
    def test_hop_limit(self, tmp_path, hops, over):
        root = tmp_path.resolve()
        (root / "real").mkdir()
        for i in range(hops):
            (root / f"l{i}").symlink_to(f"l{i + 1}" if i < hops - 1 else "real")
        path = str(root / "l0" / "f.c")
        budget = compiler_sweep._ResolveBudget()
        msg = _trips(lambda: compiler_sweep._bounded_realpath(path, budget))
        if over:
            assert msg and "symbolic links" in msg, msg
        else:
            assert msg is None
            assert compiler_sweep._bounded_realpath(
                path, compiler_sweep._ResolveBudget()) == os.path.realpath(path)

    def test_hop_limit_through_layer2(self, tmp_path):
        root = tmp_path.resolve()
        (root / "real").mkdir()
        for i in range(41):
            (root / f"l{i}").symlink_to(f"l{i + 1}" if i < 40 else "real")
        tu = _write(root, "t.c", "int t;\n")
        got = compiler_sweep._closure_suppression_witness(
            _renames_pp(tu, ["l0/f.c"]), root, tu)
        assert not got[0] and "symbolic links" in got[1], got
        assert str(root) not in got[1] and "l0" not in got[1], got

    def test_charging_trips_below_the_hop_limit(self, tmp_path, monkeypatch):
        # 10 hops, each splicing 400 target parts: the budget, not the hop
        # limit, ends the walk.
        root = tmp_path.resolve()
        (root / "d").mkdir()
        (root / "real").mkdir()
        for i in range(10):
            nxt = f"s{i + 1}" if i < 9 else "real"
            (root / f"s{i}").symlink_to("d/../" * 200 + nxt)
        monkeypatch.setattr(compiler_sweep, "_MAX_RESOLVE_OPS_PER_TU", 5_000)
        path = str(root / "s0" / "f.c")
        msg = _trips(lambda: compiler_sweep._bounded_realpath(
            path, compiler_sweep._ResolveBudget()))
        assert msg and "resolution budget" in msg, msg

    def test_symlink_chain_ends_not_vetted_quickly(self, tmp_path):
        # 1,000 links, each target "d/../"*200 + next; three relative names.
        import time
        root = tmp_path.resolve()
        (root / "d").mkdir()
        (root / "real").mkdir()
        for i in range(1000):
            nxt = f"s{i + 1}" if i < 999 else "real"
            (root / f"s{i}").symlink_to("d/../" * 200 + nxt)
        tu = _write(root, "t.c", "int t;\n")
        pp = _renames_pp(tu, [f"s0/f{i}.c" for i in range(3)])
        t0 = time.perf_counter()
        got = compiler_sweep._closure_suppression_witness(pp, root, tu)
        took = time.perf_counter() - t0
        assert not got[0] and got[1], got
        assert "symbolic links" in got[1] or "resolution budget" in got[1], got
        assert took <= 5.0, took

    def test_budget_resets_per_tu(self, tmp_path, monkeypatch):
        target = tmp_path / "t"
        tu = _write(target, "t.c", "int t;\n")
        pp = _renames_pp(tu, [_deep_abs(target, 20 + i) for i in range(6)])
        log = _fs_spy(monkeypatch)
        assert _clean(compiler_sweep._closure_suppression_witness(pp, target, tu))
        monkeypatch.undo()
        monkeypatch.setattr(compiler_sweep, "_MAX_RESOLVE_OPS_PER_TU", _ops(log))
        for _ in range(3):
            assert _clean(compiler_sweep._closure_suppression_witness(pp, target, tu))


class _FakeClock:
    """0.0 until the *n*-th deadline check at *site*, then far past any
    deadline; records the bounded resolver's filesystem call count at
    that moment."""

    def __init__(self, site: str, log: dict | None = None, n: int = 1):
        self.site, self.n, self.log = site, n, log
        self.hits, self.expired, self.ops_at_expiry = 0, False, None

    def __call__(self) -> float:
        import sys as _sys
        site = _sys._getframe(1).f_locals.get("site")
        if not self.expired and site == self.site:
            self.hits += 1
            if self.hits >= self.n:
                self.expired = True
                if self.log is not None:
                    self.ops_at_expiry = len(self.log["order"])
        return 1e9 if self.expired else 0.0


def _deadline_pp(root: Path) -> tuple[Path, Path, str]:
    """A closure that reaches every deadline check: renames resolved on the
    filesystem, an include of a repo header carrying a #line directive,
    and a suppress list in a system region (a non-repo hit)."""
    target = root / "t"
    tu = _write(target, "t.c", "int t;\n")
    hdr = _write(target, "h.h", '#line 5 "sub/x.c"\nint h;\n')
    names = [_deep_abs(target, 15 + i) for i in range(4)]
    pp = (_renames_pp(tu, names) + f'# 1 "{hdr}" 1\nint h;\n# 9 "{tu}" 2\n'
          '# 1 "/usr/include/s.h" 1 3 4\n[[clang::suppress]] int s;\n'
          f'# 10 "{tu}" 2\nint z;\n')
    return target, tu, pp


class TestCooperativeDeadline:
    """A per-TU monotonic deadline, checked at walk entry, before every
    filesystem operation, in the layer-2 loops (markers, attribute hits,
    repo files) and before a "vetted" result is accepted. Expiry is
    "not vetted"; no filesystem operation follows it."""

    @pytest.mark.parametrize("walk,site", [
        ("_additive_closure", "entry"), ("_additive_closure", "resolve"),
        ("_additive_closure", "files"), ("_additive_closure", "accept"),
        ("_l2_closure", "entry"), ("_l2_closure", "resolve"),
        ("_l2_closure", "markers"), ("_l2_closure", "hits"),
        ("_l2_closure", "files"), ("_l2_closure", "accept"),
    ])
    def test_expiry_at_each_check(self, tmp_path, monkeypatch, walk, site):
        target, tu, pp = _deadline_pp(tmp_path)
        assert _clean(getattr(compiler_sweep, walk)(pp, target, tu))
        log = _fs_spy(monkeypatch)
        clock = _FakeClock(site, log)
        monkeypatch.setattr(compiler_sweep, "_vet_clock", clock)
        got = getattr(compiler_sweep, walk)(pp, target, tu)
        assert clock.expired, f"{site} check never reached"
        assert not got[0] and "deadline" in got[1], got
        assert len(log["order"]) == clock.ops_at_expiry, (
            "filesystem work after the deadline expired")
        assert str(target) not in got[1]

    def test_expiry_mid_resolution_stops_the_walk(self, tmp_path, monkeypatch):
        target, tu, pp = _deadline_pp(tmp_path)
        log = _fs_spy(monkeypatch)
        clock = _FakeClock("resolve", log, n=20)
        monkeypatch.setattr(compiler_sweep, "_vet_clock", clock)
        got = compiler_sweep._closure_suppression_witness(pp, target, tu)
        assert "deadline" in got[1], got
        assert clock.ops_at_expiry == len(log["order"]) > 0

    def test_composite_reports_deadline(self, tmp_path, monkeypatch):
        target, tu, pp = _deadline_pp(tmp_path)
        monkeypatch.setattr(compiler_sweep, "_vet_clock", _FakeClock("accept"))
        got = compiler_sweep._closure_suppression_witness(pp, target, tu)
        assert not got[0] and "deadline" in got[1], got


class TestLimitReasonsCarryNoPathText:
    @pytest.mark.parametrize("kind", ["length", "parts", "budget", "hops"])
    def test_reason_has_counts_not_names(self, tmp_path, monkeypatch, kind):
        root = tmp_path.resolve() / ("secret_root_" + "q" * 40)
        tu = _write(root, "t.c", "int t;\n")
        if kind == "length":
            name = _long_abs(root, compiler_sweep._MAX_RESOLVED_NAME_CHARS + 1)
        elif kind == "parts":
            name = _deep_abs(root, compiler_sweep._MAX_RESOLVED_NAME_PARTS + 1)
        elif kind == "budget":
            # enough for the target root and the TU, not for the name
            monkeypatch.setattr(compiler_sweep, "_MAX_RESOLVE_OPS_PER_TU",
                                2 * len(root.parts) + 2)
            name = "zzname/f.c"
        else:
            (root / "real").mkdir()
            for i in range(41):
                (root / f"lnk{i}").symlink_to(f"lnk{i + 1}" if i < 40 else "real")
            name = "lnk0/f.c"
        got = compiler_sweep._l2_closure(_renames_pp(tu, [name]), root, tu)
        assert not got[0] and got[1], got
        for frag in [p for p in root.parts if len(p) > 3] + [name, "zzname", "lnk0"]:
            assert frag not in got[1], (frag, got[1])
        assert "-E line" in got[1], got


def test_marker_on_line_one_before_the_tu_marker_is_pinned(tmp_path):
    """Regression pin for an input clang never emits (its -E line 1 is
    always the TU's own marker): a system-header marker on line 1 owns
    the list that follows."""
    tu = _write(tmp_path, "t.c", "int t;\n")
    pp = '# 1 "/usr/include/s.h" 1 3 4\n[[clang::suppress]] int x;\n'
    assert compiler_sweep._l2_closure(pp, tmp_path, tu) == ("", "")


@needs_clang
@pytest.mark.slow
class TestBoundedResolutionEndToEnd:
    """slow: real-clang sweep; every new limit ends inconclusive."""

    @pytest.mark.parametrize("kind", ["hops", "budget", "deadline"])
    def test_limit_is_inconclusive(self, tmp_path, sandbox_spy, monkeypatch, kind):
        real_which = shutil.which
        monkeypatch.setattr(shutil, "which", lambda n, *a, **k: None
                            if n == "gcc" else real_which(n, *a, **k))
        (tmp_path / "repo").mkdir()
        target = (tmp_path / "repo").resolve()
        (target / "real").mkdir()
        for i in range(41):
            (target / f"l{i}").symlink_to(f"l{i + 1}" if i < 40 else "real")
        name = "l0/x.c" if kind == "hops" else "real/x.c"
        if kind == "budget":
            monkeypatch.setattr(compiler_sweep, "_MAX_RESOLVE_OPS_PER_TU", 5)
        if kind == "deadline":
            monkeypatch.setattr(compiler_sweep, "_vet_clock", _FakeClock("accept"))
        safe = "int f(int c){ int *p = &c; return *p; }\n"
        _write(target, "q.c", f'#line 1 "{name}"\nint v;\n#line 100 "q.c"\n{safe}')
        compiler_sweep._reset_tu_cache()
        got = _guarded_compiler_sweep(
            gcc_probed=False, target_path=target, file_path="q.c",
            function_name="f", hypothesis="null dereference of `p` in f",
            cwe="CWE-476", line_start=100, line_end=104, out_dir=tmp_path / "out")
        assert got.outcome == "inconclusive", vars(got)
        text = str(vars(got))
        expect = {"hops": "symbolic links", "budget": "resolution budget",
                  "deadline": "deadline"}[kind]
        assert expect in text, text
