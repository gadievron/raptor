"""Tests for core.audit.frida_observe — Frida runtime observation."""

import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import core.audit.frida_observe as fo
from core.audit.frida_observe import (
    FridaObserveResult,
    _build_hook_targets,
    _generate_frida_script,
    _parse_observations,
    should_run_frida,
)


class TestShouldRunFrida:
    def test_disabled_when_no_dynamic_validation(self):
        outcome = mock.Mock(status="finding", evidence_tool="")
        config = mock.Mock(dynamic_validation=False)
        assert not should_run_frida(outcome, config)

    def test_disabled_for_non_finding(self):
        outcome = mock.Mock(status="clean", evidence_tool="")
        config = mock.Mock(dynamic_validation=True)
        assert not should_run_frida(outcome, config)

    def test_disabled_when_already_dynamic(self):
        outcome = mock.Mock(status="finding", evidence_tool="dynamic:sanitizer")
        config = mock.Mock(dynamic_validation=True)
        assert not should_run_frida(outcome, config)

    def test_disabled_when_already_frida(self):
        outcome = mock.Mock(status="finding", evidence_tool="frida:runtime")
        config = mock.Mock(dynamic_validation=True)
        assert not should_run_frida(outcome, config)

    @mock.patch("core.audit.frida_observe._frida_available", return_value=False)
    def test_disabled_when_frida_unavailable(self, _):
        outcome = mock.Mock(status="finding", evidence_tool="")
        config = mock.Mock(dynamic_validation=True)
        assert not should_run_frida(outcome, config)


class TestBuildHookTargets:
    def test_includes_function_and_callees(self):
        ctx = {
            "callees": [
                {"name": "validate", "file": "util.c"},
                {"name": "memcpy"},
            ],
        }
        targets = _build_hook_targets("parse_header", "net.c", ctx)
        assert targets[0] == "parse_header"
        assert "validate" in targets
        assert "memcpy" in targets

    def test_deduplicates(self):
        ctx = {"callees": [{"name": "parse_header"}]}
        targets = _build_hook_targets("parse_header", "a.c", ctx)
        assert targets.count("parse_header") == 1

    def test_string_callees(self):
        ctx = {"callees": ["foo", "bar"]}
        targets = _build_hook_targets("main", "a.c", ctx)
        assert "foo" in targets
        assert "bar" in targets

    def test_caps_at_max(self):
        ctx = {"callees": [{"name": f"f{i}"} for i in range(200)]}
        targets = _build_hook_targets("main", "a.c", ctx)
        assert len(targets) <= 64

    def test_empty_callees(self):
        targets = _build_hook_targets("main", "a.c", {})
        assert targets == ["main"]


class TestGenerateFridaScript:
    def test_contains_targets(self):
        script = _generate_frida_script(["foo", "bar"])
        assert '"foo"' in script
        assert '"bar"' in script

    def test_contains_interceptor(self):
        script = _generate_frida_script(["main"])
        assert "Interceptor.attach" in script

    def test_sends_json(self):
        script = _generate_frida_script(["f"])
        assert "send(JSON.stringify" in script

    def test_ready_message(self):
        script = _generate_frida_script(["f"])
        assert "'ready'" in script


class TestParseObservations:
    def _write_log(self, lines):
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        p = Path(path)
        p.write_text("\n".join(lines))
        return p

    def test_parses_call_and_return(self):
        log = self._write_log([
            json.dumps({"type": "call", "function": "parse", "args": ["0x1"], "ts": 100}),
            json.dumps({"type": "return", "function": "parse", "retval": "0", "ts": 101}),
        ])
        try:
            obs = _parse_observations(log)
            assert len(obs) == 1
            assert obs[0].function == "parse"
            assert obs[0].args == ["0x1"]
            assert obs[0].retval == "0"
        finally:
            log.unlink()

    def test_multiple_functions(self):
        log = self._write_log([
            json.dumps({"type": "call", "function": "a", "args": [], "ts": 1}),
            json.dumps({"type": "call", "function": "b", "args": [], "ts": 2}),
            json.dumps({"type": "return", "function": "b", "retval": "1", "ts": 3}),
            json.dumps({"type": "return", "function": "a", "retval": "0", "ts": 4}),
        ])
        try:
            obs = _parse_observations(log)
            assert len(obs) == 2
            funcs = {o.function for o in obs}
            assert funcs == {"a", "b"}
        finally:
            log.unlink()

    def test_ignores_ready_message(self):
        log = self._write_log([
            json.dumps({"type": "ready", "hooked": 3}),
            json.dumps({"type": "call", "function": "f", "args": [], "ts": 1}),
        ])
        try:
            obs = _parse_observations(log)
            assert len(obs) == 1
        finally:
            log.unlink()

    def test_handles_malformed_lines(self):
        log = self._write_log([
            "not json",
            json.dumps({"type": "call", "function": "f", "args": [], "ts": 1}),
            "also not json",
        ])
        try:
            obs = _parse_observations(log)
            assert len(obs) == 1
        finally:
            log.unlink()

    def test_empty_log(self):
        log = self._write_log([])
        try:
            obs = _parse_observations(log)
            assert obs == []
        finally:
            log.unlink()

    def test_missing_log(self):
        obs = _parse_observations(Path("/nonexistent/file.jsonl"))
        assert obs == []

    def test_prefixed_json(self):
        """Frida CLI may prefix send() output with metadata."""
        log = self._write_log([
            '[*] {"type": "call", "function": "f", "args": [], "ts": 1}',
        ])
        try:
            obs = _parse_observations(log)
            assert len(obs) == 1
            assert obs[0].function == "f"
        finally:
            log.unlink()


class TestFridaObserveResult:
    def test_defaults(self):
        r = FridaObserveResult(attached=False)
        assert r.evidence_strength == "inconclusive"
        assert r.observations == []
        assert r.observed_functions == frozenset()

    def test_confirmed_when_target_observed(self):
        r = FridaObserveResult(
            attached=True,
            observed_functions=frozenset(["parse"]),
            evidence_strength="confirmed",
        )
        assert r.evidence_strength == "confirmed"


def _raise_timeout(*args, **kwargs):
    raise subprocess.TimeoutExpired(cmd=["frida"], timeout=kwargs.get("timeout", 0))


class TestRunFridaSession:
    """Timeout handling in _run_frida_session logs the applied timeout value."""

    def test_config_override_timeout_logged(self, tmp_path, monkeypatch, caplog):
        monkeypatch.setattr(fo.subprocess, "run", _raise_timeout)
        log_file = tmp_path / "obs.jsonl"
        config = SimpleNamespace(frida_timeout_s=7)

        with caplog.at_level(logging.DEBUG, logger="core.audit.frida_observe"):
            ok = fo._run_frida_session(1234, "// script", log_file, config)

        assert ok is False
        timeout_msgs = [
            r.getMessage() for r in caplog.records if "timed out" in r.getMessage()
        ]
        assert timeout_msgs, "expected a timeout log line"
        assert "after 7s" in timeout_msgs[0]
        assert f"after {fo._OBSERVE_TIMEOUT_S}s" not in timeout_msgs[0]

    def test_default_timeout_logged_without_override(
        self, tmp_path, monkeypatch, caplog,
    ):
        monkeypatch.setattr(fo.subprocess, "run", _raise_timeout)
        log_file = tmp_path / "obs.jsonl"
        config = SimpleNamespace()  # no frida_timeout_s

        with caplog.at_level(logging.DEBUG, logger="core.audit.frida_observe"):
            fo._run_frida_session(1234, "// script", log_file, config)

        timeout_msgs = [
            r.getMessage() for r in caplog.records if "timed out" in r.getMessage()
        ]
        assert timeout_msgs
        assert f"after {fo._OBSERVE_TIMEOUT_S}s" in timeout_msgs[0]

    def test_timeout_with_partial_log_reports_success(self, tmp_path, monkeypatch):
        monkeypatch.setattr(fo.subprocess, "run", _raise_timeout)
        log_file = tmp_path / "obs.jsonl"
        log_file.write_text('{"type": "ready", "hooked": 1}\n')
        config = SimpleNamespace(frida_timeout_s=1)

        assert fo._run_frida_session(1234, "// script", log_file, config) is True

    def test_script_tempfile_cleaned_up(self, tmp_path, monkeypatch):
        created: list[Path] = []
        real_mkstemp = fo.tempfile.mkstemp

        def _tracking_mkstemp(*args, **kwargs):
            fd, path = real_mkstemp(*args, **kwargs)
            created.append(Path(path))
            return fd, path

        monkeypatch.setattr(fo.tempfile, "mkstemp", _tracking_mkstemp)
        monkeypatch.setattr(fo.subprocess, "run", _raise_timeout)
        fo._run_frida_session(1234, "// script", tmp_path / "obs.jsonl",
                              SimpleNamespace(frida_timeout_s=1))
        assert created and not any(p.exists() for p in created)
