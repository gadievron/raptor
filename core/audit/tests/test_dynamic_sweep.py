"""Tests for core.audit.dynamic_sweep."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from core.audit import dynamic_sweep as _dynamic
from core.testing.module_bindings import mock_module_attribute

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
    review_result: dict[str, Any] | None = None


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


class TestGenerateCHarnessCweDispatch:
    """CWE lookup order in harness dispatch: review_result beats hypothesis."""

    @staticmethod
    def _outcome(function="target_fn", hypothesis="", review_result=None):
        return FakeOutcome(
            function=function,
            hypothesis=hypothesis,
            file="src/a.c",
            review_result=review_result,
        )

    def test_cwe_from_review_result_selects_harness(self):
        harness = generate_c_harness(
            self._outcome(review_result={"cwe_class": "CWE-134"}),
            {"source": "int f;"},
        )
        assert "%s%s" in harness  # format-string harness

    def test_cwe_fallback_key_selects_harness(self):
        harness = generate_c_harness(
            self._outcome(review_result={"cwe": "CWE-476"}),
            {"source": "int f;"},
        )
        assert "NULL" in harness  # null-deref harness

    def test_missing_review_result_falls_back_to_hypothesis(self):
        harness = generate_c_harness(
            self._outcome(hypothesis="buffer overflow in copy"),
            {"source": "int f;"},
        )
        assert "small_buf" in harness  # buffer-overflow harness

    def test_no_cwe_no_hypothesis_gives_generic_harness(self):
        harness = generate_c_harness(self._outcome(), {"source": "int f;"})
        assert "HARNESS_COMPLETE" in harness
        assert "target_fn" not in harness  # generic harness ignores func

    def test_invalid_identifier_rejected(self):
        harness = generate_c_harness(
            self._outcome(function="bad; rm -rf /"),
            {"source": "int f;"},
        )
        assert harness == ""


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


class TestHarnessContainment:
    """LLM-generated harness code must never execute unsandboxed.

    The runners route compile + execute through run_untrusted() and
    deliberately have NO bare-subprocess fallback: when isolation
    cannot engage (SandboxSetupError), the dynamic channel is skipped
    with an inconclusive result instead.
    """

    @staticmethod
    def _ok(returncode: int = 0):
        from types import SimpleNamespace
        return SimpleNamespace(returncode=returncode, stdout="", stderr="")

    def test_c_harness_skips_on_sandbox_setup_error(self, tmp_path):
        import time
        from unittest import mock

        from core.audit.dynamic_sweep import _run_c_harness
        from core.sandbox import SandboxSetupError

        outcome = FakeOutcome(file="a.c", hypothesis="buffer overflow")
        config = FakeConfig(target_path=str(tmp_path))
        with mock.patch("core.sandbox.run_untrusted",
                        side_effect=SandboxSetupError("no ns")), \
             mock_module_attribute(_dynamic, "subprocess", "run") as bare:
            result = _run_c_harness(outcome, {}, config, time.monotonic())
        assert result is not None
        assert result.ran is False
        assert result.evidence_strength == "inconclusive"
        assert "sandbox unavailable" in (result.sanitizer_output or "")
        # The point of the design: no bare-host execution path exists.
        assert not bare.called

    def test_python_harness_skips_on_sandbox_setup_error(self, tmp_path):
        import time
        from unittest import mock

        from core.audit.dynamic_sweep import _run_python_harness
        from core.sandbox import SandboxSetupError

        outcome = FakeOutcome(file="mod.py", hypothesis="null deref")
        config = FakeConfig(target_path=str(tmp_path))
        with mock.patch("core.sandbox.run_untrusted",
                        side_effect=SandboxSetupError("no ns")), \
             mock_module_attribute(_dynamic, "subprocess", "run") as bare:
            result = _run_python_harness(outcome, {}, config, time.monotonic())
        assert result is not None
        assert result.ran is False
        assert "sandbox unavailable" in (result.sanitizer_output or "")
        assert not bare.called

    def test_c_harness_confines_compile_and_run(self, tmp_path):
        """Both steps get target= (read: -I headers) and output= (the
        scratch dir) so Landlock actually engages — the pre-fix call
        passed neither, leaving the harness read-everywhere."""
        import time
        from unittest import mock

        from core.audit.dynamic_sweep import _run_c_harness

        outcome = FakeOutcome(file="a.c", hypothesis="buffer overflow")
        config = FakeConfig(target_path=str(tmp_path))
        with mock.patch("core.sandbox.run_untrusted",
                        return_value=self._ok()) as m:
            result = _run_c_harness(outcome, {}, config, time.monotonic())
        assert result is not None and result.ran is True
        assert m.call_count == 2  # compile, then execute
        for call in m.call_args_list:
            assert call.kwargs["target"] == str(tmp_path)
            assert call.kwargs["output"]  # the scratch tmpdir

    def test_python_harness_preludes_sys_path_not_pythonpath(self, tmp_path):
        """strict_env strips PYTHONPATH, so the target path must ride
        in a sys.path prelude inside the harness script instead."""
        import time
        from pathlib import Path
        from unittest import mock

        from core.audit.dynamic_sweep import _run_python_harness

        outcome = FakeOutcome(file="mod.py", hypothesis="null deref")
        config = FakeConfig(target_path=str(tmp_path))
        seen = {}

        def fake_run(cmd, **kw):
            seen["code"] = Path(cmd[1]).read_text()
            seen["kwargs"] = kw
            return self._ok()

        with mock.patch("core.sandbox.run_untrusted", side_effect=fake_run):
            result = _run_python_harness(outcome, {}, config, time.monotonic())
        assert result is not None and result.ran is True
        prelude = f"sys.path.insert(0, {str(tmp_path)!r})"
        assert prelude in seen["code"].splitlines()[1]
        assert "PYTHONPATH" not in (seen["kwargs"].get("env") or {})
        assert seen["kwargs"]["target"] == str(tmp_path)

    def test_harness_capture_is_bounded(self, tmp_path):
        """Every run_untrusted call carries the per-stream capture
        ceiling, so a spewing harness cannot pin unbounded output in
        memory before the short result slices apply."""
        import time
        from unittest import mock

        from core.audit.dynamic_sweep import (
            _MAX_CAPTURE_BYTES,
            _run_c_harness,
            _run_python_harness,
        )

        config = FakeConfig(target_path=str(tmp_path))
        with mock.patch("core.sandbox.run_untrusted",
                        return_value=self._ok()) as m:
            _run_c_harness(
                FakeOutcome(file="a.c", hypothesis="buffer overflow"),
                {}, config, time.monotonic())
            _run_python_harness(
                FakeOutcome(file="mod.py", hypothesis="null deref"),
                {}, config, time.monotonic())
        assert m.call_count == 3  # compile, C execute, Python execute
        for call in m.call_args_list:
            assert call.kwargs["max_capture_bytes"] == _MAX_CAPTURE_BYTES


class TestGetSafeEnvDegradedFallback:
    """The broken-install fallback is an ALLOWLIST mirroring the
    primary get_safe_env contract: only a literal minimal name set
    (plus the ENUMERATED locale categories — never an open LC_ prefix)
    survives into the child. A deny-list fallback leaked every secret
    whose name its predicates did not recognise (DATABASE_URL, bespoke
    spellings)."""

    def _degraded_env(self, monkeypatch):
        import sys
        import types

        # Force the ImportError arm: a stub core.config with no
        # RaptorConfig makes `from core.config import RaptorConfig`
        # fail exactly like a broken install.
        monkeypatch.setitem(
            sys.modules, "core.config", types.ModuleType("core.config"),
        )
        from core.audit.dynamic_sweep import _get_safe_env
        return _get_safe_env()

    def test_fallback_is_an_allowlist(self, monkeypatch):
        # Exec-capable names and credential vocabulary never survive.
        monkeypatch.setenv("GIT_ASKPASS", "/tmp/steal.sh")
        monkeypatch.setenv(
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER", "/tmp/evil",
        )
        monkeypatch.setenv("BUNDLE_BUILD__NOKOGIRI", "-fplugin=/tmp/e.so")
        monkeypatch.setenv("EXAMPLEVENDOR_API_KEY", "sentinel")
        monkeypatch.setenv("SOME_SERVICE_PASSWORD", "sentinel")
        # NOT credential-shaped and on no deny-list — exactly the leak
        # class only an allowlist stops.
        monkeypatch.setenv("DATABASE_URL", "postgres://u:hunter2@db/x")
        monkeypatch.setenv("MY_BESPOKE_CONNSTRING", "hunter2")
        # Unknown-but-benign names drop too: allowlist, not deny-list.
        monkeypatch.setenv("MY_LEGITIMATE_VAR", "dropped-anyway")
        env = self._degraded_env(monkeypatch)
        assert "GIT_ASKPASS" not in env
        assert "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER" not in env
        assert "BUNDLE_BUILD__NOKOGIRI" not in env
        assert "EXAMPLEVENDOR_API_KEY" not in env
        assert "SOME_SERVICE_PASSWORD" not in env
        assert "DATABASE_URL" not in env
        assert "MY_BESPOKE_CONNSTRING" not in env
        assert "MY_LEGITIMATE_VAR" not in env
        # The fallback's own sanitizer knobs still land.
        assert "ASAN_OPTIONS" in env

    def test_fallback_keeps_the_minimal_tool_set(self, monkeypatch):
        monkeypatch.setenv("PATH", "/usr/bin")
        monkeypatch.setenv("HOME", "/home/x")
        monkeypatch.setenv("LANG", "C.UTF-8")
        monkeypatch.setenv("LC_CTYPE", "C.UTF-8")
        env = self._degraded_env(monkeypatch)
        assert env.get("PATH") == "/usr/bin"
        assert env.get("HOME") == "/home/x"
        assert env.get("LANG") == "C.UTF-8"
        assert env.get("LC_CTYPE") == "C.UTF-8"

    def test_fallback_drops_lc_named_secrets(self, monkeypatch):
        # The locale family is ENUMERATED, never an open LC_ prefix:
        # the primary's prefix is safe only because its credential-shape
        # sweep backstops it, and that vocabulary may not import on the
        # broken-install leg. LC_BESPOKE_CONNSTRING is the proof case —
        # no shape predicate recognises it, only enumeration stops it.
        monkeypatch.setenv("LC_BROKER_API_KEY", "sentinel")
        monkeypatch.setenv("LC_VENDOR_API_TOKEN", "sentinel")
        monkeypatch.setenv("LC_BESPOKE_CONNSTRING", "hunter2")
        monkeypatch.setenv("LC_MESSAGES", "C.UTF-8")
        env = self._degraded_env(monkeypatch)
        assert "LC_BROKER_API_KEY" not in env
        assert "LC_VENDOR_API_TOKEN" not in env
        assert "LC_BESPOKE_CONNSTRING" not in env
        assert env.get("LC_MESSAGES") == "C.UTF-8"

    def test_fallback_allowlist_is_subset_of_primary(self):
        # The fallback carries its own literal copy (it exists because
        # the core.config import FAILED); this pin stops the two
        # allowlists drifting apart silently. Ambient TMPDIR is
        # deliberately absent from both (the primary blocklists it and
        # injects a launcher-owned replacement instead — unavailable on
        # the degraded leg).
        from core.audit.dynamic_sweep import (
            _FALLBACK_ENV_ALLOWLIST,
            _FALLBACK_LOCALE_ENV,
        )
        from core.config import RaptorConfig

        assert _FALLBACK_ENV_ALLOWLIST <= RaptorConfig.SAFE_ENV_ALLOWLIST
        # The enumerated locale names ride the primary's LC_ prefix
        # family rather than its literal allowlist: every one must
        # match a primary prefix (the primary would keep it too), and
        # none may carry a shape the primary's credential sweep exists
        # to stop (the enumeration IS the fallback's substitute for
        # that sweep).
        assert all(
            name.startswith(RaptorConfig.SAFE_ENV_PREFIXES)
            for name in _FALLBACK_LOCALE_ENV)
        assert "TMPDIR" not in _FALLBACK_ENV_ALLOWLIST
        assert not ((_FALLBACK_ENV_ALLOWLIST | _FALLBACK_LOCALE_ENV)
                    & RaptorConfig.DANGEROUS_ENV_VARS)

    def test_fallback_is_loud(self, monkeypatch, caplog):
        with caplog.at_level("WARNING", logger="core.audit.dynamic_sweep"):
            self._degraded_env(monkeypatch)
        assert "degraded minimal env allowlist" in caplog.text
