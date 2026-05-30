"""CLI tests for core.dynamic.frida.cli.

These exercise argument parsing and the wiring from CLI flags to
``runner.RunConfig``. The actual frida call is mocked via the same
``frida_mod_override`` injection point used in test_runner.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.dynamic.frida import cli, runner


class _FakeDevice:
    def __init__(self):
        self.id = "local"
        self.attach_calls: list = []
        self.spawn_calls: list = []
        self.resume_calls: list = []

    def attach(self, target):
        self.attach_calls.append(target)
        return _FakeSession()

    def spawn(self, argv):
        self.spawn_calls.append(argv)
        return 9999

    def resume(self, pid):
        self.resume_calls.append(pid)


class _FakeSession:
    def __init__(self):
        self.pid = 1234
        self.detached = False

    def create_script(self, src):
        return _FakeScript()

    def detach(self):
        self.detached = True


class _FakeScript:
    def on(self, ev, cb):
        pass

    def load(self):
        pass


def _fake_frida():
    dev = _FakeDevice()
    return dev, SimpleNamespace(
        __version__="test",
        get_local_device=lambda: dev,
        get_device_manager=lambda: SimpleNamespace(
            add_remote_device=lambda h: dev),
        get_usb_device=lambda timeout=5: dev,
    )


def test_list_templates_exits_zero(capsys):
    rc = cli.main(["--list-templates"])
    assert rc == 0
    out = capsys.readouterr().out.strip().splitlines()
    # At minimum, api-trace and ssl-unpin ship with the package.
    assert "api-trace" in out
    assert "ssl-unpin" in out


def test_cli_requires_target_and_source():
    # Missing --target should exit non-zero (argparse 2).
    with pytest.raises(SystemExit) as exc:
        cli.main(["--template", "api-trace", "--out", "/tmp/x"])
    assert exc.value.code == 2


def test_cli_template_and_script_mutually_exclusive():
    with pytest.raises(SystemExit) as exc:
        cli.main([
            "--target", "1",
            "--out", "/tmp/x",
            "--template", "api-trace",
            "--script", "/tmp/h.js",
        ])
    assert exc.value.code == 2


def test_cli_host_and_usb_mutually_exclusive():
    with pytest.raises(SystemExit) as exc:
        cli.main([
            "--target", "1",
            "--out", "/tmp/x",
            "--template", "api-trace",
            "--host", "10.0.0.1",
            "--usb",
        ])
    assert exc.value.code == 2


def test_cli_happy_path_runs(tmp_path: Path, monkeypatch):
    dev, fake_frida = _fake_frida()
    # Patch the runner's frida-import to return our fake.
    monkeypatch.setattr(runner, "_import_frida", lambda: fake_frida)

    rc = cli.main([
        "--target", "1234",
        "--out", str(tmp_path),
        "--template", "api-trace",
        "--duration", "0.05",
    ])
    assert rc == 0
    # The runner produces these three artefacts on success.
    assert (tmp_path / "metadata.json").is_file()
    assert (tmp_path / "frida-report.md").is_file()
    assert (tmp_path / "script.js").is_file()
    meta = json.loads((tmp_path / "metadata.json").read_text())
    assert meta["ok"] is True
    assert meta["target"]["pid"] == 1234


def test_cli_invalid_template_name(tmp_path: Path):
    rc = cli.main([
        "--target", "1234",
        "--out", str(tmp_path),
        "--template", "../../etc/passwd",
        "--duration", "0.05",
    ])
    assert rc == 2  # parse_target succeeds; template validation fails


def test_cli_missing_script_file(tmp_path: Path):
    rc = cli.main([
        "--target", "1234",
        "--out", str(tmp_path),
        "--script", str(tmp_path / "nonexistent.js"),
        "--duration", "0.05",
    ])
    assert rc == 2


def test_cli_spawn_with_pid_rejected(tmp_path: Path):
    # --spawn names a program to launch; a PID is already running, so the
    # combination is contradictory and must be rejected (exit 2) rather
    # than silently trying to spawn a program named after the PID.
    rc = cli.main([
        "--target", "1234",
        "--out", str(tmp_path),
        "--template", "api-trace",
        "--spawn",
        "--duration", "0.05",
    ])
    assert rc == 2


def test_cli_frida_unavailable_exit_3(tmp_path: Path, monkeypatch):
    def boom():
        raise runner.FridaUnavailable("missing")
    monkeypatch.setattr(runner, "_import_frida", boom)
    rc = cli.main([
        "--target", "1234",
        "--out", str(tmp_path),
        "--template", "api-trace",
        "--duration", "0.05",
    ])
    assert rc == 3
