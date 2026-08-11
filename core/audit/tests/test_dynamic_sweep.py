"""Tests for core.audit.dynamic_sweep."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from core.audit.dynamic_sweep import (
    DynamicSweepResult,
    _has_sanitizer_output,
    _is_buffer_overflow,
    _is_compilable_language,
    _is_format_string,
    _is_null_deref,
    _is_use_after_free,
    generate_c_harness,
    generate_python_harness,
    should_run_dynamic,
)


@dataclass
class FakeOutcome:
    file: str = "a.c"
    function: str = "vuln_func"
    status: str = "finding"
    hypothesis: str = "buffer overflow"
    evidence_tool: str = ""
    review_result: Optional[Dict[str, Any]] = None


@dataclass
class FakeConfig:
    dynamic_validation: bool = True
    target_path: str = "/tmp/target"


class TestShouldRunDynamic:
    def test_finding_triggers(self):
        o = FakeOutcome(status="finding", file="a.c")
        c = FakeConfig(dynamic_validation=True)
        assert should_run_dynamic(o, c) is True

    def test_clean_does_not_trigger(self):
        o = FakeOutcome(status="clean")
        c = FakeConfig(dynamic_validation=True)
        assert should_run_dynamic(o, c) is False

    def test_already_dynamic_does_not_trigger(self):
        o = FakeOutcome(status="finding", evidence_tool="dynamic:sanitizer")
        c = FakeConfig(dynamic_validation=True)
        assert should_run_dynamic(o, c) is False

    def test_already_dynamic_crash_does_not_trigger(self):
        o = FakeOutcome(status="finding", evidence_tool="dynamic:crash")
        c = FakeConfig(dynamic_validation=True)
        assert should_run_dynamic(o, c) is False

    def test_disabled_does_not_trigger(self):
        o = FakeOutcome(status="finding")
        c = FakeConfig(dynamic_validation=False)
        assert should_run_dynamic(o, c) is False

    def test_non_compilable_does_not_trigger(self):
        o = FakeOutcome(status="finding", file="a.go")
        c = FakeConfig(dynamic_validation=True)
        assert should_run_dynamic(o, c) is False

    def test_python_triggers(self):
        o = FakeOutcome(status="finding", file="app.py")
        c = FakeConfig(dynamic_validation=True)
        assert should_run_dynamic(o, c) is True

    def test_cpp_triggers(self):
        o = FakeOutcome(status="finding", file="lib.cpp")
        c = FakeConfig(dynamic_validation=True)
        assert should_run_dynamic(o, c) is True


class TestGenerateCHarness:
    def test_buffer_overflow_harness(self):
        o = FakeOutcome(
            review_result={"cwe_class": "CWE-120"},
            hypothesis="buffer overflow in parse",
        )
        ctx = {"source": "void parse(char *buf) {}"}
        code = generate_c_harness(o, ctx)
        assert "#include" in code
        assert "main" in code
        assert "HARNESS_COMPLETE" in code

    def test_format_string_harness(self):
        o = FakeOutcome(
            review_result={"cwe_class": "CWE-134"},
            hypothesis="format string in log",
        )
        ctx = {"source": "void log(char *fmt) {}"}
        code = generate_c_harness(o, ctx)
        assert "main" in code

    def test_use_after_free_harness(self):
        o = FakeOutcome(
            review_result={"cwe_class": "CWE-416"},
            hypothesis="use-after-free",
        )
        ctx = {"source": ""}
        code = generate_c_harness(o, ctx)
        assert "free" in code

    def test_null_deref_harness(self):
        o = FakeOutcome(
            review_result={"cwe_class": "CWE-476"},
            hypothesis="null pointer",
        )
        ctx = {"source": ""}
        code = generate_c_harness(o, ctx)
        assert "NULL" in code

    def test_generic_harness(self):
        o = FakeOutcome(review_result={}, hypothesis="unknown issue")
        ctx = {"source": ""}
        code = generate_c_harness(o, ctx)
        assert "main" in code


class TestGeneratePythonHarness:
    def test_generates_test_script(self):
        o = FakeOutcome(
            file="app/auth.py",
            function="validate",
            hypothesis="injection",
        )
        ctx = {"source": ""}
        code = generate_python_harness(o, ctx)
        assert "from app.auth import validate" in code
        assert "HARNESS_COMPLETE" in code
        assert "test_inputs" in code

    def test_includes_various_inputs(self):
        o = FakeOutcome(file="m.py", function="f")
        ctx = {"source": ""}
        code = generate_python_harness(o, ctx)
        assert "None" in code
        assert "'A' * 10000" in code
        assert "2**31" in code


class TestSanitizerDetection:
    def test_detects_asan(self):
        output = "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602..."
        assert _has_sanitizer_output(output) is True

    def test_detects_ubsan(self):
        output = "runtime error: signed integer overflow: 2147483647 + 1"
        assert _has_sanitizer_output(output) is True

    def test_detects_leak(self):
        output = "ERROR: LeakSanitizer: detected memory leaks"
        assert _has_sanitizer_output(output) is True

    def test_clean_output(self):
        output = "HARNESS_COMPLETE\n"
        assert _has_sanitizer_output(output) is False


class TestBugClassDetection:
    def test_buffer_overflow_by_cwe(self):
        assert _is_buffer_overflow("CWE-120", "") is True
        assert _is_buffer_overflow("CWE-787", "") is True

    def test_buffer_overflow_by_hypothesis(self):
        assert _is_buffer_overflow("", "buffer overflow in parse") is True

    def test_format_string(self):
        assert _is_format_string("CWE-134", "") is True
        assert _is_format_string("", "format string vulnerability") is True

    def test_use_after_free(self):
        assert _is_use_after_free("CWE-416", "") is True
        assert _is_use_after_free("", "use-after-free in handler") is True
        assert _is_use_after_free("CWE-415", "") is True

    def test_null_deref(self):
        assert _is_null_deref("CWE-476", "") is True
        assert _is_null_deref("", "null pointer dereference") is True

    def test_compilable_languages(self):
        assert _is_compilable_language("a.c") is True
        assert _is_compilable_language("b.py") is True
        assert _is_compilable_language("c.cpp") is True
        assert _is_compilable_language("d.go") is False
        assert _is_compilable_language("e.rs") is False


class TestEvidenceStrength:
    """Sanitiser hits and bare crashes must produce different strengths."""

    def test_sanitizer_hit_is_sanitizer(self):
        r = DynamicSweepResult(
            compiled=True, ran=True, crashed=True,
            sanitizer_output="ERROR: AddressSanitizer: heap-buffer-overflow",
            exit_code=1, evidence_strength="sanitizer", duration_s=0.1,
        )
        assert r.evidence_strength == "sanitizer"

    def test_bare_crash_is_crash(self):
        r = DynamicSweepResult(
            compiled=True, ran=True, crashed=True,
            sanitizer_output=None,
            exit_code=139, evidence_strength="crash", duration_s=0.1,
        )
        assert r.evidence_strength == "crash"

    def test_clean_exit_is_inconclusive(self):
        r = DynamicSweepResult(
            compiled=True, ran=True, crashed=False,
            sanitizer_output=None,
            exit_code=0, evidence_strength="inconclusive", duration_s=0.1,
        )
        assert r.evidence_strength == "inconclusive"
