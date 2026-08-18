"""Tests for packages.joern.runner."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

import pytest

from packages.joern.models import JoernCPG
from packages.joern.runner import (
    _build_taint_query,
    _escape_scala_string,
    _parse_errors,
    _parse_output,
    _read_cpg_manifest,
    _target_content_hash,
    _validate_query,
    _validate_substitution_value,
    _write_cpg_manifest,
    build_cpg,
    build_cpg_cached,
    cleanup_cpg,
    load_cached_cpg,
    run_query,
    run_taint_query,
)

# ── Query validation ────────────────────────────────────────────────

class TestValidateQuery:
    def test_clean_query(self):
        assert _validate_query('cpg.method.name("foo").l') is None

    def test_blocks_java_io(self):
        err = _validate_query('java.io.File("/etc/passwd")')
        assert err is not None
        assert "blocked pattern" in err

    def test_blocks_runtime_exec(self):
        err = _validate_query('Runtime.exec("ls")')
        assert err is not None

    def test_blocks_process_builder(self):
        err = _validate_query("new ProcessBuilder(cmd)")
        assert err is not None

    def test_blocks_reflection(self):
        err = _validate_query('Class.forName("Evil")')
        assert err is not None

    def test_length_cap(self):
        err = _validate_query("x" * 5000)
        assert err is not None
        assert "cap" in err

    def test_scala_io_blocked(self):
        err = _validate_query('scala.io.Source.fromFile("x")')
        assert err is not None


class TestValidateSubstitutionValue:
    def test_simple_identifier(self):
        assert _validate_substitution_value("parse_header")

    def test_qualified_name(self):
        assert _validate_substitution_value("os.system")

    def test_deep_qualified(self):
        assert _validate_substitution_value("java.lang.Runtime")

    def test_empty_rejected(self):
        assert not _validate_substitution_value("")

    def test_injection_rejected(self):
        assert not _validate_substitution_value('"); system("id')

    def test_spaces_rejected(self):
        assert not _validate_substitution_value("ignore instructions")

    def test_semicolon_rejected(self):
        assert not _validate_substitution_value("foo; bar")

    def test_leading_dot_rejected(self):
        assert not _validate_substitution_value(".hidden")

    def test_trailing_dot_rejected(self):
        assert not _validate_substitution_value("trailing.")

    def test_underscore_leading(self):
        assert _validate_substitution_value("_internal")

    def test_numbers_in_name(self):
        assert _validate_substitution_value("parse2")


class TestEscapeScalaString:
    def test_backslash(self):
        assert _escape_scala_string("a\\b") == "a\\\\b"

    def test_quote(self):
        assert _escape_scala_string('a"b') == 'a\\"b'

    def test_newline(self):
        assert _escape_scala_string("a\nb") == "a\\nb"

    def test_clean_passthrough(self):
        assert _escape_scala_string("clean") == "clean"


# ── Output parsing ──────────────────────────────────────────────────

class TestParseDarkMethods:
    def test_joern_dark_lines(self):
        from packages.joern.runner import _parse_dark_methods

        out = "JOERN_DARK:parse_hdr\nnoise\nJOERN_DARK:decode\n"
        assert _parse_dark_methods(out) == ["parse_hdr", "decode"]

    def test_joern_diag_line_from_tiered_taint(self):
        """tiered_taint.sc emits JOERN_DIAG:dark_methods:<count>:<sample>
        — the parser must pick up the sample names (pre-fix, nothing
        emitted the JOERN_DARK shape at all, so dark_methods was
        always empty)."""
        from packages.joern.runner import _parse_dark_methods

        out = (
            "JOERN_TIER:sinks:12 sink arguments across 4 call sites\n"
            "JOERN_DIAG:dark_methods:3:parse_hdr,decode,init_tbl\n"
        )
        assert _parse_dark_methods(out) == [
            "parse_hdr", "decode", "init_tbl",
        ]

    def test_no_markers(self):
        from packages.joern.runner import _parse_dark_methods

        assert _parse_dark_methods("plain output\n") == []


class TestParseOutput:
    def test_empty(self):
        flows, errors = _parse_output("")
        assert flows == []
        assert errors == []

    def test_single_flow(self):
        steps = [
            {"file": "a.c", "function": "f", "line": 1,
             "code": "x", "variable": "x"},
            {"file": "a.c", "function": "f", "line": 5,
             "code": "memcpy(dst, x, n)", "variable": "x"},
        ]
        output = (
            "JOERN_FLOWS_START\n"
            f"JOERN_FLOW:{json.dumps(steps)}\n"
            "JOERN_FLOWS_END\n"
        )
        flows, _errors = _parse_output(output)
        assert len(flows) == 1
        assert len(flows[0].steps) == 2
        assert not flows[0].is_inter_procedural

    def test_inter_procedural(self):
        steps = [
            {"file": "a.c", "function": "caller", "line": 1,
             "code": "x", "variable": "x"},
            {"file": "b.c", "function": "callee", "line": 5,
             "code": "system(x)", "variable": "x"},
        ]
        output = (
            "JOERN_FLOWS_START\n"
            f"JOERN_FLOW:{json.dumps(steps)}\n"
            "JOERN_FLOWS_END\n"
        )
        flows, _ = _parse_output(output)
        assert flows[0].is_inter_procedural

    def test_malformed_json_produces_error(self):
        output = (
            "JOERN_FLOWS_START\n"
            "JOERN_FLOW:{not json\n"
            "JOERN_FLOWS_END\n"
        )
        flows, errors = _parse_output(output)
        assert flows == []
        assert len(errors) == 1

    def test_ignores_lines_outside_markers(self):
        output = (
            "some jvm output\n"
            "JOERN_FLOWS_START\n"
            "JOERN_FLOWS_END\n"
            "more output\n"
        )
        flows, errors = _parse_output(output)
        assert flows == []
        assert errors == []


class TestParseErrors:
    def test_extracts_errors(self):
        stderr = "WARNING: something\nERROR: bad thing\ninfo line\n"
        errors = _parse_errors(stderr)
        assert any("bad thing" in e for e in errors)

    def test_ignores_deprecation_warnings(self):
        stderr = "error: deprecated feature used\n"
        errors = _parse_errors(stderr)
        assert errors == []

    def test_empty(self):
        assert _parse_errors("") == []


# ── Mock runner for integration ─────────────────────────────────────

def _mock_runner(stdout="", stderr="", returncode=0):
    """Create a mock subprocess runner."""
    def runner(cmd, **kwargs):
        return SimpleNamespace(
            stdout=stdout, stderr=stderr,
            returncode=returncode,
        )
    return runner


class TestBuildCpg:
    def test_non_directory_raises(self, tmp_path: Path):
        f = tmp_path / "file.c"
        f.write_text("int main() {}")
        with pytest.raises(ValueError, match="directory"):
            build_cpg(f, subprocess_runner=_mock_runner())

    def test_creates_cpg_handle(self, tmp_path: Path):
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int f() { return 0; }")

        cpg = build_cpg(
            target,
            subprocess_runner=_mock_runner(),
            output_dir=tmp_path / "out",
        )
        assert cpg.target == target
        assert cpg.path.parent == tmp_path / "out"

    def test_timeout_returns_cpg(self, tmp_path: Path):
        target = tmp_path / "src"
        target.mkdir()

        def timeout_runner(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, 10)

        cpg = build_cpg(
            target,
            subprocess_runner=timeout_runner,
            output_dir=tmp_path / "out",
        )
        assert cpg.target == target

    def test_os_error_returns_cpg(self, tmp_path: Path):
        target = tmp_path / "src"
        target.mkdir()

        def error_runner(cmd, **kwargs):
            raise OSError("no joern")

        cpg = build_cpg(
            target,
            subprocess_runner=error_runner,
            output_dir=tmp_path / "out",
        )
        assert cpg.target == target


class TestRunQuery:
    def test_cpg_not_found(self, tmp_path: Path):
        cpg = JoernCPG(path=tmp_path / "missing.bin", target=tmp_path)
        result = run_query(cpg, "cpg.method.l")
        assert not result.ok
        assert "not found" in result.errors[0]

    def test_dangerous_query_rejected(self, tmp_path: Path):
        f = tmp_path / "cpg.bin"
        f.write_bytes(b"fake")
        cpg = JoernCPG(path=f, target=tmp_path)

        result = run_query(cpg, 'java.io.File("/etc/passwd")')
        assert not result.ok
        assert "blocked" in result.errors[0]

    def test_successful_query(self, tmp_path: Path):
        f = tmp_path / "cpg.bin"
        f.write_bytes(b"fake")
        cpg = JoernCPG(path=f, target=tmp_path)

        steps = [
            {"file": "a.c", "function": "f", "line": 1,
             "code": "x", "variable": "x"},
        ]
        stdout = (
            "JOERN_FLOWS_START\n"
            f"JOERN_FLOW:{json.dumps(steps)}\n"
            "JOERN_FLOWS_END\n"
        )
        result = run_query(
            cpg, "cpg.method.l",
            subprocess_runner=_mock_runner(stdout=stdout),
        )
        assert result.ok
        assert result.flow_count == 1


class TestRunTaintQuery:
    def test_invalid_source_method(self, tmp_path: Path):
        f = tmp_path / "cpg.bin"
        f.write_bytes(b"fake")
        cpg = JoernCPG(path=f, target=tmp_path)

        flows = run_taint_query(cpg, '"); evil("', "memcpy")
        assert flows == []

    def test_invalid_sink_call(self, tmp_path: Path):
        f = tmp_path / "cpg.bin"
        f.write_bytes(b"fake")
        cpg = JoernCPG(path=f, target=tmp_path)

        flows = run_taint_query(cpg, "parse_header", "a b c")
        assert flows == []

    def test_valid_query_dispatches(self, tmp_path: Path):
        f = tmp_path / "cpg.bin"
        f.write_bytes(b"fake")
        cpg = JoernCPG(path=f, target=tmp_path)

        steps = [
            {"file": "a.c", "function": "parse_header",
             "line": 1, "code": "len", "variable": "len"},
            {"file": "a.c", "function": "parse_header",
             "line": 5, "code": "memcpy(dst, src, len)",
             "variable": "len"},
        ]
        stdout = (
            "JOERN_FLOWS_START\n"
            f"JOERN_FLOW:{json.dumps(steps)}\n"
            "JOERN_FLOWS_END\n"
        )
        flows = run_taint_query(
            cpg, "parse_header", "memcpy",
            subprocess_runner=_mock_runner(stdout=stdout),
        )
        assert len(flows) == 1
        assert flows[0].source_method == "parse_header"

    def test_qualified_sink_accepted(self, tmp_path: Path):
        f = tmp_path / "cpg.bin"
        f.write_bytes(b"fake")
        cpg = JoernCPG(path=f, target=tmp_path)

        flows = run_taint_query(
            cpg, "handler", "os.system",
            subprocess_runner=_mock_runner(),
        )
        assert isinstance(flows, list)


class TestBuildTaintQuery:
    def test_basic_query(self):
        q = _build_taint_query("foo", "bar")
        assert 'name("foo")' in q
        assert 'name("bar")' in q
        assert "reachableByFlows" in q

    def test_with_param(self):
        q = _build_taint_query("foo", "bar", "len")
        assert 'name("len")' in q


class TestCleanupCpg:
    def test_removes_file(self, tmp_path: Path):
        cpg_dir = tmp_path / "cpg_dir"
        cpg_dir.mkdir()
        f = cpg_dir / "cpg.bin"
        f.write_bytes(b"data")
        cpg = JoernCPG(path=f, target=tmp_path)

        cleanup_cpg(cpg)
        assert not f.exists()
        assert not cpg_dir.exists()

    def test_missing_file_no_error(self, tmp_path: Path):
        cpg = JoernCPG(
            path=tmp_path / "gone.bin", target=tmp_path,
        )
        cleanup_cpg(cpg)

    def test_non_empty_dir_preserved(self, tmp_path: Path):
        cpg_dir = tmp_path / "cpg_dir"
        cpg_dir.mkdir()
        f = cpg_dir / "cpg.bin"
        f.write_bytes(b"data")
        (cpg_dir / "other.txt").write_text("keep")
        cpg = JoernCPG(path=f, target=tmp_path)

        cleanup_cpg(cpg)
        assert not f.exists()
        assert cpg_dir.exists()


# ── Template slot injection defense ─────────────────────────────────

class TestTemplateSlotInjection:
    """Verify that attacker-controlled function/param names cannot
    inject code into Joern query templates."""

    INJECTION_PAYLOADS: ClassVar[list[str]] = [
        '"); Runtime.getRuntime().exec("id"); //',
        "foo\nval x = 1",
        'a"b',
        "os.system; import java.io._",
        "__import__('os').system('id')",
        "${Runtime.getRuntime().exec('id')}",
    ]

    def test_substitution_rejects_injections(self):
        for payload in self.INJECTION_PAYLOADS:
            assert not _validate_substitution_value(payload), (
                f"should have rejected: {payload!r}"
            )

    def test_escape_neutralizes_quotes(self):
        assert '"' not in _escape_scala_string("test").replace('\\"', "")

    def test_query_validation_catches_dangerous_patterns(self):
        for payload in self.INJECTION_PAYLOADS:
            escaped = _escape_scala_string(payload)
            query = f'cpg.method.name("{escaped}").l'
            err = _validate_query(query)
            if "Runtime" in payload or "import java" in payload:
                assert err is not None, (
                    f"should have caught dangerous pattern in: {query}"
                )


class TestCPGCaching:
    def test_content_hash_stable(self, tmp_path):
        (tmp_path / "a.c").write_text("int main() {}")
        h1 = _target_content_hash(tmp_path)
        h2 = _target_content_hash(tmp_path)
        assert h1 == h2

    def test_content_hash_changes_on_edit(self, tmp_path):
        f = tmp_path / "a.c"
        f.write_text("int main() {}")
        import time
        time.sleep(0.05)
        h1 = _target_content_hash(tmp_path)
        import os
        future = int(time.time()) + 100
        os.utime(f, (future, future))
        h2 = _target_content_hash(tmp_path)
        assert h1 != h2

    def test_manifest_roundtrip(self, tmp_path):
        cpg_dir = tmp_path / "joern-cpg"
        cpg_dir.mkdir()
        _write_cpg_manifest(cpg_dir, Path("/src"), "abc123", {"c"}, 500)
        m = _read_cpg_manifest(cpg_dir)
        assert m["content_hash"] == "abc123"
        assert m["build_time_ms"] == 500
        assert "c" in m["languages"]

    def test_manifest_missing_returns_none(self, tmp_path):
        assert _read_cpg_manifest(tmp_path) is None

    def test_load_cached_cpg_miss(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int main() {}")
        cache = tmp_path / "cache"
        cache.mkdir()
        assert load_cached_cpg(target, cache) is None

    def test_load_cached_cpg_hit(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int main() {}")

        cache = tmp_path / "cache"
        cpg_dir = cache / "joern-cpg"
        cpg_dir.mkdir(parents=True)
        (cpg_dir / "cpg.bin").write_bytes(b"\x00")

        content_hash = _target_content_hash(target)
        _write_cpg_manifest(cpg_dir, target, content_hash, {"c"}, 100)

        result = load_cached_cpg(target, cache)
        assert result is not None
        assert result.path == cpg_dir / "cpg.bin"

    def test_load_cached_cpg_stale(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int main() {}")

        cache = tmp_path / "cache"
        cpg_dir = cache / "joern-cpg"
        cpg_dir.mkdir(parents=True)
        (cpg_dir / "cpg.bin").write_bytes(b"\x00")

        _write_cpg_manifest(cpg_dir, target, "stale_hash", {"c"}, 100)

        result = load_cached_cpg(target, cache)
        assert result is None

    def test_build_cpg_cached_uses_cache(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int main() {}")

        cache = tmp_path / "cache"
        cpg_dir = cache / "joern-cpg"
        cpg_dir.mkdir(parents=True)
        (cpg_dir / "cpg.bin").write_bytes(b"\x00")

        content_hash = _target_content_hash(target)
        _write_cpg_manifest(cpg_dir, target, content_hash, {"c"}, 100)

        build_called = []

        def fake_runner(cmd, **kw):
            build_called.append(cmd)
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        result = build_cpg_cached(
            target, cache, subprocess_runner=fake_runner,
        )
        assert result.path == cpg_dir / "cpg.bin"
        assert len(build_called) == 0


class TestValidateSubstitutionValueFullmatch:
    def test_trailing_newline_rejected(self):
        # A $-anchored match() admits "foo\n"; fullmatch must not.
        assert not _validate_substitution_value("parse_header\n")

    def test_trailing_newline_qualified_rejected(self):
        assert not _validate_substitution_value("os.system\n")


class TestBuildCpgSandbox:
    """on_progress must never bypass the sandbox.

    With core.sandbox available, the build routes through the sandbox
    runner (the raw-Popen stall monitor is dropped); the monitor path
    only runs when the sandbox is absent.
    """

    def _spy_runner(self, calls):
        def runner(cmd, **kwargs):
            calls.append({"cmd": cmd, "kwargs": kwargs})
            return SimpleNamespace(stdout="", stderr="", returncode=0)
        return runner

    def test_progress_path_routes_through_sandbox(self, tmp_path, monkeypatch):
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int f() { return 0; }")

        calls: list = []
        monkeypatch.setattr(
            "packages.joern.runner._default_sandbox_runner",
            lambda: self._spy_runner(calls),
        )

        def no_raw_popen(*a, **kw):
            raise AssertionError(
                "stall monitor must not spawn a raw Popen when the "
                "sandbox is available"
            )

        monkeypatch.setattr(
            "packages.joern.runner.subprocess.Popen", no_raw_popen,
        )

        progress: list = []
        cpg = build_cpg(
            target, on_progress=progress.append, output_dir=tmp_path / "out",
        )
        assert cpg.target == target.resolve()
        assert len(calls) == 1
        assert calls[0]["kwargs"]["block_network"] is True
        assert calls[0]["kwargs"]["target"] == str(target.resolve())
        assert progress  # coarse note replaces per-file streaming

    def test_non_monitor_branch_blocks_network(self, tmp_path, monkeypatch):
        target = tmp_path / "src"
        target.mkdir()

        calls: list = []
        monkeypatch.setattr(
            "packages.joern.runner._default_sandbox_runner",
            lambda: self._spy_runner(calls),
        )

        build_cpg(target, output_dir=tmp_path / "out")
        assert calls[0]["kwargs"]["block_network"] is True

    def test_sandbox_unavailable_keeps_stall_monitor(self, tmp_path, monkeypatch):
        target = tmp_path / "src"
        target.mkdir()

        monkeypatch.setattr(
            "packages.joern.runner._default_sandbox_runner",
            lambda: subprocess.run,
        )

        called: dict = {}

        def fake_monitor_build(cmd, cpg_path, target_, languages, timeout,
                               on_progress):
            called["cmd"] = cmd
            return JoernCPG(path=cpg_path, target=target_)

        monkeypatch.setattr(
            "packages.joern.runner._build_cpg_with_stall_monitor",
            fake_monitor_build,
        )

        build_cpg(target, on_progress=lambda m: None,
                  output_dir=tmp_path / "out")
        assert "cmd" in called


class TestStallMonitorStdoutDrain:
    """A chatty joern-parse stdout must not wedge the monitored build.

    Regression: stdout was PIPE'd but only read after exit, so a child
    emitting more than the OS pipe buffer (~64KB) on stdout blocked in
    write(), stalled its stderr progress, and got killed as a spurious
    timeout/stall.
    """

    def test_chatty_stdout_completes_and_is_parsed(self, tmp_path):
        import sys as _sys

        from packages.joern.runner import _build_cpg_with_stall_monitor

        # Writes 256KB of noise plus a language line to stdout — far
        # past the pipe buffer an undrained child deadlocks on.
        script = (
            "import sys\n"
            "sys.stdout.write('noise\\n' * (256 * 1024 // 6))\n"
            "sys.stdout.write('language: c\\n')\n"
        )
        cpg = _build_cpg_with_stall_monitor(
            [_sys.executable, "-c", script],
            cpg_path=tmp_path / "cpg.bin",
            target=tmp_path,
            languages=None,
            timeout=20,
            on_progress=lambda m: None,
        )
        # Pre-fix the child hit the 20s wait timeout and the fallback
        # JoernCPG carried no languages and no build time.
        assert cpg.languages == {"c"}
        assert cpg.build_time_ms < 20_000


class TestDefaultSandboxRunnerFailClosed:
    """The try-import-sandbox-except-bare-subprocess shape is gone:
    sandbox unimportable -> raise naming the remedy, unless the
    operator explicitly opted into unsandboxed execution."""

    def test_raises_when_sandbox_unimportable(self, monkeypatch):
        import sys as _sys

        from unittest.mock import patch as _patch

        from core.run.sandbox_policy import (
            ALLOW_UNSANDBOXED_ENV,
            SandboxUnavailableError,
        )
        from packages.joern.runner import _default_sandbox_runner
        monkeypatch.delenv(ALLOW_UNSANDBOXED_ENV, raising=False)
        with _patch.dict(_sys.modules, {"core.sandbox": None}):
            with pytest.raises(SandboxUnavailableError, match="joern"):
                _default_sandbox_runner()

    def test_optout_returns_bare_subprocess_with_event(self, monkeypatch):
        import sys as _sys

        from unittest.mock import patch as _patch

        import core.run.sandbox_policy as policy_mod
        from packages.joern.runner import _default_sandbox_runner
        monkeypatch.setenv(policy_mod.ALLOW_UNSANDBOXED_ENV, "1")
        events: list = []
        monkeypatch.setattr(
            policy_mod, "log_security_event",
            lambda etype, msg, **kw: events.append(etype),
        )
        with _patch.dict(_sys.modules, {"core.sandbox": None}):
            runner = _default_sandbox_runner()
        assert runner is subprocess.run
        assert events == ["unsandboxed_tool_fallback"]
