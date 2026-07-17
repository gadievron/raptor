"""Tests for packages.frida.active — programmatic observation API."""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

from packages.frida.active import (
    _extract_output_dir,
    _safe_env,
    auto_observe,
    observe_paired,
    observe_target,
)


# ── _extract_output_dir ───────────────────────────────────────────────


class TestExtractOutputDir:

    def test_parses_valid_line(self, tmp_path):
        d = tmp_path / "out" / "frida_123"
        d.mkdir(parents=True)
        stdout = f"some preamble\nOUTPUT_DIR={d}\nmore stuff\n"
        assert _extract_output_dir(stdout) == d

    def test_returns_none_on_missing(self):
        assert _extract_output_dir("no output dir here\n") is None

    def test_returns_none_on_nonexistent_path(self):
        stdout = "OUTPUT_DIR=/tmp/nonexistent_abcdef_xyz\n"
        assert _extract_output_dir(stdout) is None

    def test_handles_path_with_equals(self, tmp_path):
        d = tmp_path / "out=test" / "frida_123"
        d.mkdir(parents=True)
        stdout = f"OUTPUT_DIR={d}\n"
        assert _extract_output_dir(stdout) == d


# ── _safe_env ────────────────────────────────────────────────────────


class TestSafeEnv:

    def test_includes_raptor_dir(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_DIR", "/opt/raptor")
        env = _safe_env()
        assert env["RAPTOR_DIR"] == "/opt/raptor"
        assert env["CLAUDECODE"] == "1"
        assert env["PYTHONPATH"] == "/opt/raptor"

    def test_does_not_leak_sensitive_vars(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_DIR", "/opt/raptor")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret123")
        monkeypatch.setenv("LD_PRELOAD", "/evil/lib.so")
        env = _safe_env()
        assert "AWS_SECRET_ACCESS_KEY" not in env
        assert "LD_PRELOAD" not in env


# ── observe_target ────────────────────────────────────────────────────


class TestObserveTarget:

    def test_returns_none_when_frida_unavailable(self, tmp_path):
        binary = tmp_path / "app"
        binary.write_bytes(b"\x7fELF")
        with patch("packages.frida.available", return_value=False):
            result = observe_target(str(binary))
        assert result is None

    def test_returns_none_when_binary_missing(self):
        with patch("packages.frida.available", return_value=True):
            result = observe_target("/nonexistent/path/binary")
        assert result is None

    def test_returns_none_when_raptor_dir_unset(self, tmp_path, monkeypatch):
        binary = tmp_path / "app"
        binary.write_bytes(b"\x7fELF")
        monkeypatch.delenv("RAPTOR_DIR", raising=False)
        with patch("packages.frida.available", return_value=True):
            result = observe_target(str(binary))
        assert result is None

    def test_invokes_libexec_and_returns_run_dir(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
        binary = tmp_path / "app"
        binary.write_bytes(b"\x7fELF")
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        (run_dir / "metadata.json").write_text('{"ok": true}')
        (run_dir / "events.jsonl").write_text("")

        fake_result = MagicMock()
        fake_result.returncode = 0
        fake_result.stdout = f"OUTPUT_DIR={run_dir}\n"
        fake_result.stderr = ""

        with patch("packages.frida.available", return_value=True), \
             patch("subprocess.run", return_value=fake_result) as mock_run:
            result = observe_target(str(binary), template="api-trace",
                                    duration_sec=10)

        assert result == run_dir
        call_args = mock_run.call_args[0][0]
        assert "--target" in call_args
        assert "--template" in call_args
        assert "api-trace" in call_args
        assert "--spawn" in call_args

        call_kwargs = mock_run.call_args[1]
        env = call_kwargs["env"]
        assert "AWS_SECRET_ACCESS_KEY" not in env
        assert "LD_PRELOAD" not in env

    def test_returns_none_on_nonzero_exit(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
        binary = tmp_path / "app"
        binary.write_bytes(b"\x7fELF")

        fake_result = MagicMock()
        fake_result.returncode = 1
        fake_result.stderr = "crash"
        fake_result.stdout = ""

        with patch("packages.frida.available", return_value=True), \
             patch("subprocess.run", return_value=fake_result):
            result = observe_target(str(binary))
        assert result is None

    def test_returns_none_on_timeout(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
        binary = tmp_path / "app"
        binary.write_bytes(b"\x7fELF")

        with patch("packages.frida.available", return_value=True), \
             patch("subprocess.run",
                   side_effect=subprocess.TimeoutExpired("cmd", 60)):
            result = observe_target(str(binary), duration_sec=10)
        assert result is None

    def test_passes_out_dir_when_provided(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
        binary = tmp_path / "app"
        binary.write_bytes(b"\x7fELF")
        out_dir = tmp_path / "custom_out"
        out_dir.mkdir()
        (out_dir / "metadata.json").write_text('{"ok": true}')

        fake_result = MagicMock()
        fake_result.returncode = 0
        fake_result.stdout = f"OUTPUT_DIR={out_dir}\n"
        fake_result.stderr = ""

        with patch("packages.frida.available", return_value=True), \
             patch("subprocess.run", return_value=fake_result) as mock_run:
            observe_target(str(binary), out_dir=out_dir)

        call_args = mock_run.call_args[0][0]
        assert "--out" in call_args
        idx = call_args.index("--out")
        assert call_args[idx + 1] == str(out_dir)

    def test_enforces_minimum_duration(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
        binary = tmp_path / "app"
        binary.write_bytes(b"\x7fELF")

        fake_result = MagicMock()
        fake_result.returncode = 0
        fake_result.stdout = ""
        fake_result.stderr = ""

        with patch("packages.frida.available", return_value=True), \
             patch("subprocess.run", return_value=fake_result) as mock_run:
            observe_target(str(binary), duration_sec=-5)

        call_args = mock_run.call_args[0][0]
        idx = call_args.index("--duration")
        assert int(call_args[idx + 1]) >= 1


# ── observe_paired ────────────────────────────────────────────────────


class TestObservePaired:

    def test_returns_none_when_frida_unavailable(self):
        with patch("packages.frida.available", return_value=False):
            result = observe_paired(["./server"])
        assert result is None

    def test_returns_none_when_coordinator_missing(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
        with patch("packages.frida.available", return_value=True):
            result = observe_paired(["./server"])
        assert result is None

    def test_returns_none_on_empty_target_cmd(self):
        with patch("packages.frida.available", return_value=True):
            result = observe_paired([])
        assert result is None

    def test_returns_none_when_raptor_dir_unset(self, monkeypatch):
        monkeypatch.delenv("RAPTOR_DIR", raising=False)
        with patch("packages.frida.available", return_value=True):
            result = observe_paired(["./server"])
        assert result is None

    def test_sends_correct_protocol_to_coordinator(self, tmp_path, monkeypatch):
        raptor_dir = str(tmp_path)
        monkeypatch.setenv("RAPTOR_DIR", raptor_dir)

        coord = tmp_path / "core" / "sandbox" / "netns_coordinator.py"
        coord.parent.mkdir(parents=True)
        coord.write_text("# placeholder")

        run_dir = tmp_path / "out" / "frida_run"
        run_dir.mkdir(parents=True)
        (run_dir / "metadata.json").write_text('{"ok": true}')
        (run_dir / "events.jsonl").write_text("")

        response = {
            "target": {"returncode": 0, "error": None},
            "exploit": {"returncode": 0, "error": None},
            "listen_observed": True,
            "namespace_path": "/proc/self/ns/net",
            "error": None,
        }

        fake_proc = MagicMock()
        fake_proc.communicate.return_value = (
            json.dumps(response).encode(),
            b"",
        )
        fake_proc.returncode = 0
        fake_proc.pid = 12345

        def fake_popen(*args, **kwargs):
            return fake_proc

        with patch("packages.frida.available", return_value=True), \
             patch("subprocess.Popen", side_effect=fake_popen) as mock_popen:
            result = observe_paired(
                ["./myserver", "--port", "8080"],
                template="api-trace",
                out_dir=run_dir,
                wait_port=8080,
                duration_sec=15,
            )

        assert result == run_dir
        call_kwargs = mock_popen.call_args[1]
        assert call_kwargs["stdin"] == subprocess.PIPE
        assert call_kwargs["start_new_session"] is True
        request_bytes = fake_proc.communicate.call_args[0][0]
        request = json.loads(request_bytes)
        assert request["target"]["cmd"] == ["./myserver", "--port", "8080"]
        assert request["target"]["profile"] == "target_run"
        assert request["exploit"]["profile"] == "frida"
        assert request["wait_listen_port"] == 8080
        assert "--target" in " ".join(request["exploit"]["cmd"])

        env = call_kwargs["env"]
        assert "_RAPTOR_TRUSTED" not in env

    def test_truncates_long_target_name(self, tmp_path, monkeypatch):
        raptor_dir = str(tmp_path)
        monkeypatch.setenv("RAPTOR_DIR", raptor_dir)

        coord = tmp_path / "core" / "sandbox" / "netns_coordinator.py"
        coord.parent.mkdir(parents=True)
        coord.write_text("# placeholder")

        run_dir = tmp_path / "out" / "frida_run"
        run_dir.mkdir(parents=True)
        (run_dir / "metadata.json").write_text('{"ok": true}')

        response = {"error": None}
        fake_proc = MagicMock()
        fake_proc.communicate.return_value = (
            json.dumps(response).encode(), b"")
        fake_proc.returncode = 0
        fake_proc.pid = 12345

        with patch("packages.frida.available", return_value=True), \
             patch("subprocess.Popen", return_value=fake_proc):
            observe_paired(
                ["./very-long-binary-name-exceeding-15"],
                out_dir=run_dir,
            )

        request_bytes = fake_proc.communicate.call_args[0][0]
        request = json.loads(request_bytes)
        cmd = request["exploit"]["cmd"]
        target_idx = cmd.index("--target") + 1
        assert len(cmd[target_idx]) <= 15

    def test_returns_none_on_coordinator_error(self, tmp_path, monkeypatch):
        raptor_dir = str(tmp_path)
        monkeypatch.setenv("RAPTOR_DIR", raptor_dir)

        coord = tmp_path / "core" / "sandbox" / "netns_coordinator.py"
        coord.parent.mkdir(parents=True)
        coord.write_text("# placeholder")

        fake_proc = MagicMock()
        fake_proc.communicate.return_value = (b"", b"setup failed")
        fake_proc.returncode = 2
        fake_proc.pid = 12345

        with patch("packages.frida.available", return_value=True), \
             patch("subprocess.Popen", return_value=fake_proc):
            result = observe_paired(
                ["./server"],
                out_dir=tmp_path / "out",
            )
        assert result is None

    def test_returns_none_on_timeout(self, tmp_path, monkeypatch):
        raptor_dir = str(tmp_path)
        monkeypatch.setenv("RAPTOR_DIR", raptor_dir)

        coord = tmp_path / "core" / "sandbox" / "netns_coordinator.py"
        coord.parent.mkdir(parents=True)
        coord.write_text("# placeholder")

        fake_proc = MagicMock()
        fake_proc.communicate.side_effect = [
            subprocess.TimeoutExpired("cmd", 60),
            (b"", b""),
        ]
        fake_proc.pid = 12345

        with patch("packages.frida.available", return_value=True), \
             patch("subprocess.Popen", return_value=fake_proc), \
             patch("os.getpgid", return_value=12345), \
             patch("os.killpg"):
            result = observe_paired(["./server"], out_dir=tmp_path / "out")
        assert result is None


# ── auto_observe ──────────────────────────────────────────────────────


class TestAutoObserve:

    def _write_evidence(self, run_dir: Path, target: str, age_s: float = 0):
        run_dir.mkdir(parents=True, exist_ok=True)
        meta = {
            "ok": True,
            "target": {"raw": target, "binary": target,
                       "kind": "binary", "pid": None, "name": None},
        }
        meta_path = run_dir / "metadata.json"
        meta_path.write_text(json.dumps(meta))
        (run_dir / "events.jsonl").write_text('{"ts":1,"type":"send"}\n')
        if age_s > 0:
            old_time = time.time() - age_s
            os.utime(meta_path, (old_time, old_time))

    def test_skips_when_fresh_evidence_exists(self, tmp_path):
        run_dir = tmp_path / "frida-run-1"
        target = "/tmp/build/app"
        self._write_evidence(run_dir, target, age_s=60)

        result = auto_observe(
            target_path=target,
            search_dirs=[tmp_path],
            staleness_s=3600,
        )
        assert result is None

    def test_observes_when_evidence_is_stale(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
        run_dir = tmp_path / "frida-run-old"
        target = str(tmp_path / "app")
        (tmp_path / "app").write_bytes(b"\x7fELF")
        self._write_evidence(run_dir, target, age_s=7200)

        new_run = tmp_path / "new-run"
        new_run.mkdir()
        (new_run / "metadata.json").write_text('{"ok": true}')

        fake_result = MagicMock()
        fake_result.returncode = 0
        fake_result.stdout = f"OUTPUT_DIR={new_run}\n"
        fake_result.stderr = ""

        with patch("packages.frida.available", return_value=True), \
             patch("subprocess.run", return_value=fake_result):
            result = auto_observe(
                target_path=target,
                search_dirs=[tmp_path],
                staleness_s=3600,
            )
        assert result == new_run

    def test_observes_when_no_evidence(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
        target = str(tmp_path / "app")
        (tmp_path / "app").write_bytes(b"\x7fELF")

        new_run = tmp_path / "out-run"
        new_run.mkdir()
        (new_run / "metadata.json").write_text('{"ok": true}')

        fake_result = MagicMock()
        fake_result.returncode = 0
        fake_result.stdout = f"OUTPUT_DIR={new_run}\n"
        fake_result.stderr = ""

        with patch("packages.frida.available", return_value=True), \
             patch("subprocess.run", return_value=fake_result):
            result = auto_observe(
                target_path=target,
                search_dirs=[tmp_path],
            )
        assert result == new_run

    def test_skips_evidence_for_different_target(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
        run_dir = tmp_path / "frida-run-other"
        self._write_evidence(run_dir, "/opt/other-binary", age_s=10)

        target = str(tmp_path / "app")
        (tmp_path / "app").write_bytes(b"\x7fELF")

        new_run = tmp_path / "out-run"
        new_run.mkdir()
        (new_run / "metadata.json").write_text('{"ok": true}')

        fake_result = MagicMock()
        fake_result.returncode = 0
        fake_result.stdout = f"OUTPUT_DIR={new_run}\n"
        fake_result.stderr = ""

        with patch("packages.frida.available", return_value=True), \
             patch("subprocess.run", return_value=fake_result):
            result = auto_observe(
                target_path=target,
                search_dirs=[tmp_path],
            )
        assert result == new_run

    def test_negative_age_triggers_reobservation(self, tmp_path, monkeypatch):
        """If clock goes backward (NTP), negative age should not be treated as fresh."""
        monkeypatch.setenv("RAPTOR_DIR", str(tmp_path))
        run_dir = tmp_path / "frida-run-future"
        target = str(tmp_path / "app")
        (tmp_path / "app").write_bytes(b"\x7fELF")
        self._write_evidence(run_dir, target, age_s=0)
        meta_path = run_dir / "metadata.json"
        future_time = time.time() + 3600
        os.utime(meta_path, (future_time, future_time))

        new_run = tmp_path / "out-run"
        new_run.mkdir()
        (new_run / "metadata.json").write_text('{"ok": true}')

        fake_result = MagicMock()
        fake_result.returncode = 0
        fake_result.stdout = f"OUTPUT_DIR={new_run}\n"
        fake_result.stderr = ""

        with patch("packages.frida.available", return_value=True), \
             patch("subprocess.run", return_value=fake_result):
            result = auto_observe(
                target_path=target,
                search_dirs=[tmp_path],
                staleness_s=3600,
            )
        assert result == new_run
