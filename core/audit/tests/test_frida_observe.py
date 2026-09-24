"""Tests for core.audit.frida_observe — Frida runtime observation."""

import contextlib
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


@contextlib.contextmanager
def _session_log_fd(log_file: Path):
    """The kept-fd contract of _run_frida_session: production keeps
    the mkstemp fd open and every log write/read goes through it."""
    fd = os.open(str(log_file), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        yield fd
    finally:
        os.close(fd)


class TestRunFridaSession:
    """Timeout handling in _run_frida_session logs the applied timeout value."""

    def test_config_override_timeout_logged(self, tmp_path, monkeypatch, caplog):
        monkeypatch.setattr(fo.subprocess, "run", _raise_timeout)
        log_file = tmp_path / "obs.jsonl"
        config = SimpleNamespace(frida_timeout_s=7)

        with caplog.at_level(logging.DEBUG, logger="core.audit.frida_observe"):
            with _session_log_fd(log_file) as log_fd:
                ok = fo._run_frida_session(1234, "// script", log_fd, config)

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
            with _session_log_fd(log_file) as log_fd:
                fo._run_frida_session(1234, "// script", log_fd, config)

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

        with _session_log_fd(log_file) as log_fd:
            assert fo._run_frida_session(
                1234, "// script", log_fd, config) is True

    def test_script_tempfile_cleaned_up(self, tmp_path, monkeypatch):
        created: list[Path] = []
        real_mkstemp = fo.tempfile.mkstemp

        def _tracking_mkstemp(*args, **kwargs):
            fd, path = real_mkstemp(*args, **kwargs)
            created.append(Path(path))
            return fd, path

        monkeypatch.setattr(fo.tempfile, "mkstemp", _tracking_mkstemp)
        monkeypatch.setattr(fo.subprocess, "run", _raise_timeout)
        with _session_log_fd(tmp_path / "obs.jsonl") as log_fd:
            fo._run_frida_session(1234, "// script", log_fd,
                                  SimpleNamespace(frida_timeout_s=1))
        assert created and not any(p.exists() for p in created)


class TestScriptExportResolution:
    """The generated script must survive both Frida API generations:
    modern runtimes removed the static two-arg Module.findExportByName,
    which made every lookup throw and left zero functions hooked."""

    def test_feature_detects_modern_lookup(self):
        script = _generate_frida_script(["parse"])
        assert "Module.findGlobalExportByName" in script
        assert "typeof Module.findGlobalExportByName" in script

    def test_keeps_legacy_lookup_for_old_runtimes(self):
        script = _generate_frida_script(["parse"])
        assert "Module.findExportByName(null, name)" in script


class TestSessionCommandLine:
    def _capture_cmd(self, monkeypatch, tmp_path):
        captured: dict = {}

        def _fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr(fo.subprocess, "run", _fake_run)
        with _session_log_fd(tmp_path / "obs.jsonl") as log_fd:
            fo._run_frida_session(
                1234, "// script", log_fd,
                SimpleNamespace(frida_timeout_s=30),
            )
        return captured["cmd"]

    def test_no_pause_flag_absent(self, tmp_path, monkeypatch):
        # Current frida CLIs reject --no-pause as an unrecognized
        # argument before attaching — the flag must never be passed.
        cmd = self._capture_cmd(monkeypatch, tmp_path)
        assert "--no-pause" not in cmd

    def test_quiet_mode_with_session_window(self, tmp_path, monkeypatch):
        cmd = self._capture_cmd(monkeypatch, tmp_path)
        assert "-q" in cmd
        assert "-t" in cmd
        # Session window sits under the subprocess backstop timeout.
        assert int(cmd[cmd.index("-t") + 1]) < 30

    def test_stdout_persisted_to_log_file(self, tmp_path, monkeypatch):
        stdout = 'message: {\'type\': \'send\', \'payload\': \'{"type":"ready","hooked":2}\'} data: None\n'

        def _fake_run(cmd, **kwargs):
            return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

        monkeypatch.setattr(fo.subprocess, "run", _fake_run)
        log_file = tmp_path / "obs.jsonl"
        with _session_log_fd(log_file) as log_fd:
            ok = fo._run_frida_session(
                1234, "// script", log_fd,
                SimpleNamespace(frida_timeout_s=30),
            )
        assert ok is True
        assert log_file.read_text() == stdout

    def test_timeout_partial_stdout_persisted(self, tmp_path, monkeypatch):
        def _raise_with_partial(*args, **kwargs):
            raise subprocess.TimeoutExpired(
                cmd=["frida"], timeout=1,
                output='message: {\'type\': \'send\', \'payload\': \'{"type":"call","function":"f","args":[]}\'} data: None\n',
            )

        monkeypatch.setattr(fo.subprocess, "run", _raise_with_partial)
        log_file = tmp_path / "obs.jsonl"
        with _session_log_fd(log_file) as log_fd:
            ok = fo._run_frida_session(
                1234, "// script", log_fd,
                SimpleNamespace(frida_timeout_s=1),
            )
        assert ok is True
        assert "call" in log_file.read_text()


class TestParseCliFraming:
    """The frida CLI emits send() payloads on stdout wrapped in a
    Python-repr line — never in the -o log. The parser must unwrap
    that framing AND keep accepting raw JSONL (both directions)."""

    def _log(self, tmp_path, content):
        p = tmp_path / "obs.jsonl"
        p.write_text(content)
        return p

    def test_cli_wrapped_call_and_return(self, tmp_path):
        content = (
            "message: {'type': 'send', 'payload': "
            "'{\"type\":\"call\",\"function\":\"malloc\","
            "\"args\":[\"0x40\"],\"ts\":1}'} data: None\n"
            "message: {'type': 'send', 'payload': "
            "'{\"type\":\"return\",\"function\":\"malloc\","
            "\"retval\":\"0xdead\",\"ts\":2}'} data: None\n"
        )
        obs = _parse_observations(self._log(tmp_path, content))
        assert len(obs) == 1
        assert obs[0].function == "malloc"
        assert obs[0].args == ["0x40"]
        assert obs[0].retval == "0xdead"

    def test_cli_wrapped_ready_ignored(self, tmp_path):
        content = (
            "message: {'type': 'send', 'payload': "
            "'{\"type\":\"ready\",\"hooked\":3}'} data: None\n"
        )
        assert _parse_observations(self._log(tmp_path, content)) == []

    def test_raw_jsonl_still_parses(self, tmp_path):
        content = (
            '{"type": "call", "function": "f", "args": ["1"], "ts": 1}\n'
        )
        obs = _parse_observations(self._log(tmp_path, content))
        assert len(obs) == 1
        assert obs[0].function == "f"


class TestParseLogBounds:
    """A busy 30s session exceeds 8KiB within its first fraction of a
    second, so a whole-log prefix cap dropped every observation from
    later in the window — the target function read as unobserved
    (evidence_strength stayed inconclusive), worsening the
    observation-window bias. The parser now streams line by line
    under byte + line-count bounds: late observations are counted,
    memory stays bounded."""

    def _log(self, tmp_path, content):
        p = tmp_path / "obs.jsonl"
        p.write_text(content)
        return p

    def test_observation_past_8kib_is_counted(self, tmp_path):
        spam = json.dumps(
            {"type": "call", "function": "noise", "args": [], "ts": 1},
        )
        # ~12 KiB of early traffic before the target's first hit.
        lines = [spam] * 200
        lines.append(json.dumps(
            {"type": "call", "function": "late_target", "args": [], "ts": 2},
        ))
        content = "\n".join(lines) + "\n"
        assert len(content) > 8192
        obs = _parse_observations(self._log(tmp_path, content))
        assert any(o.function == "late_target" for o in obs)

    def test_log_over_byte_bound_truncates_safely(self, tmp_path):
        line = json.dumps(
            {"type": "call", "function": "f", "args": [], "ts": 1},
        ) + "\n"
        n = fo._MAX_LOG_BYTES // len(line) + 100
        p = tmp_path / "obs.jsonl"
        with p.open("w") as fh:
            for _ in range(n):
                fh.write(line)
        assert p.stat().st_size > fo._MAX_LOG_BYTES
        obs = _parse_observations(p)
        # Parses without error, keeps a bounded prefix, drops the rest.
        assert 0 < len(obs) < n

    def test_line_count_bound(self, tmp_path, monkeypatch):
        monkeypatch.setattr(fo, "_MAX_LOG_LINES", 10)
        line = json.dumps({"type": "call", "function": "f", "args": []})
        obs = _parse_observations(
            self._log(tmp_path, "\n".join([line] * 50) + "\n"),
        )
        assert len(obs) == 10

    def test_oversized_single_line_fragments_safely(self, tmp_path, monkeypatch):
        # A single line larger than the whole byte budget must come
        # back as bounded fragments, never one giant allocation.
        monkeypatch.setattr(fo, "_MAX_LOG_BYTES", 1024)
        p = self._log(tmp_path, "x" * 10_000 + "\n")
        assert _parse_observations(p) == []


class TestKeptFdSessionLog:
    """The session log lives in shared /tmp while the observed
    SAME-UID target runs: every write and read must go through the fd
    mkstemp returned (the original inode), so a path swapped under us
    never receives our writes and never feeds us forged content."""

    def test_write_survives_path_swap(self, tmp_path):
        log_file = tmp_path / "obs.jsonl"
        fd = os.open(str(log_file), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            victim = tmp_path / "victim"
            victim.write_text("do not touch")
            # Attacker swaps the path between mkstemp and the write.
            log_file.unlink()
            log_file.symlink_to(victim)

            payload = json.dumps(
                {"type": "call", "function": "f", "args": []}) + "\n"
            fo._write_session_log(fd, payload)

            assert victim.read_text() == "do not touch"
            # The kept-fd read still sees our own bytes.
            obs = fo._parse_observations(log_file, log_fd=fd)
            assert [o.function for o in obs] == ["f"]
        finally:
            os.close(fd)

    def test_fd_read_ignores_swapped_path_content(self, tmp_path):
        log_file = tmp_path / "obs.jsonl"
        fd = os.open(str(log_file), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fo._write_session_log(fd, "")
            forged = tmp_path / "forged.jsonl"
            forged.write_text(json.dumps(
                {"type": "call", "function": "attacker", "args": []}) + "\n")
            log_file.unlink()
            log_file.symlink_to(forged)
            assert fo._parse_observations(log_file, log_fd=fd) == []
        finally:
            os.close(fd)

    def test_write_truncates_previous_content(self, tmp_path):
        log_file = tmp_path / "obs.jsonl"
        fd = os.open(str(log_file), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fo._write_session_log(fd, "long previous content\n")
            fo._write_session_log(fd, "short\n")
            assert log_file.read_text() == "short\n"
        finally:
            os.close(fd)
