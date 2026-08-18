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

import shutil
import subprocess
from pathlib import Path

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


@pytest.fixture(autouse=True)
def _fresh_probe_cache():
    compiler_sweep._reset_probe_cache()
    yield
    compiler_sweep._reset_probe_cache()


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


def _sweep(tmp_path, fixture, cwe, hypothesis, function_name="f",
           line_start=0, line_end=0):
    target = _target_with(tmp_path, fixture)
    out_dir = tmp_path / "out"
    return run_compiler_analyzer_sweep(
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
        run_compiler_analyzer_sweep(
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
        )
        assert result.details and result.details["compiler"] == "clang"
        assert result.outcome == "confirmed"

    def test_both_missing_is_error(self, tmp_path, monkeypatch):
        monkeypatch.setattr(shutil, "which", lambda *a, **k: None)
        result = _sweep(
            tmp_path, "uaf.c", "CWE-416", "use-after-free of `p`",
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
        result = run_compiler_analyzer_sweep(
            target_path=target, file_path="app.py", function_name="f",
            hypothesis="use-after-free of `x`", cwe="CWE-416",
            out_dir=tmp_path / "out",
        )
        assert result.outcome == "inconclusive"
        assert sandbox_spy == []

    def test_path_escape_is_error(self, tmp_path, sandbox_spy):
        target = tmp_path / "repo"
        target.mkdir()
        result = run_compiler_analyzer_sweep(
            target_path=target, file_path="../evil.c", function_name="f",
            hypothesis="h", cwe="CWE-416", out_dir=tmp_path / "out",
        )
        assert result.outcome == "error"
        assert sandbox_spy == []

    def test_missing_file_is_error(self, tmp_path, sandbox_spy):
        target = tmp_path / "repo"
        target.mkdir()
        result = run_compiler_analyzer_sweep(
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
