"""Unit tests for packages.frida.runner.

The runner integrates with the real frida-python binding when present,
but the binding requires a running target to attach to and shells out
to platform-specific binaries - neither suitable for CI. We inject a
fake frida module with the minimal API surface the runner touches
(get_local_device / get_device_manager.add_remote_device /
get_usb_device, device.attach / spawn / resume, session.create_script /
detach, script.on / load) and assert the runner orchestrates them
correctly.

Coverage:
  * Target parsing: PID, name, binary-path.
  * Template name validation (path-traversal defence).
  * Script source loading from template OR file (xor).
  * Run with attach-by-pid emits events.jsonl + metadata.json + report.
  * Run with spawn calls device.spawn + device.resume in correct order.
  * Remote --host routes via get_device_manager().add_remote_device.
  * --usb routes via get_usb_device.
  * Script error messages get written to events.jsonl.
  * Frida ImportError is mapped to FridaUnavailable.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from packages.frida import runner


class FakeScript:
    """Stand-in for frida.Script with the runner-touched surface."""
    def __init__(self):
        self._cb = None
        self.loaded = False

    def on(self, event: str, cb):
        assert event == "message"
        self._cb = cb

    def load(self):
        self.loaded = True

    def fire(self, message: dict, data: bytes | None = None):
        """Test helper - simulate a message from the JS side."""
        assert self._cb is not None, "load() must be called first"
        self._cb(message, data)


class FakeSession:
    def __init__(self, pid: int):
        self.pid = pid
        self.detached = False
        self.script = FakeScript()

    def create_script(self, source: str):
        self.last_source = source
        return self.script

    def detach(self):
        self.detached = True


class FakeDevice:
    def __init__(self, id_: str = "local"):
        self.id = id_
        self.spawn_calls: list[list[str]] = []
        self.resume_calls: list[int] = []
        self.attach_calls: list[Any] = []
        self._next_spawn_pid = 9999

    def spawn(self, argv: list[str], env: dict | None = None) -> int:
        self.spawn_calls.append(argv)
        return self._next_spawn_pid

    def resume(self, pid: int):
        self.resume_calls.append(pid)

    def attach(self, target) -> FakeSession:
        self.attach_calls.append(target)
        # PID-by-int when target is int; else use a placeholder.
        pid = target if isinstance(target, int) else 7777
        return FakeSession(pid=pid)


class FakeDeviceManager:
    def __init__(self, remote_device: FakeDevice):
        self._remote = remote_device
        self.add_remote_calls: list[str] = []

    def add_remote_device(self, host: str) -> FakeDevice:
        self.add_remote_calls.append(host)
        return self._remote


def _fake_frida(local_device: FakeDevice,
               remote_device: FakeDevice | None = None,
               usb_device: FakeDevice | None = None):
    """Build a minimal fake frida module."""
    rdev = remote_device or FakeDevice("remote")
    udev = usb_device or FakeDevice("usb")
    return SimpleNamespace(
        __version__="test-fake",
        get_local_device=lambda: local_device,
        get_device_manager=lambda: FakeDeviceManager(rdev),
        get_usb_device=lambda timeout=5: udev,
    )


# --- parse_target ----------------------------------------------------

def test_parse_target_pid():
    t = runner.parse_target("1234")
    assert t.pid == 1234 and t.binary is None and t.name is None
    assert t.kind == "pid"


def test_parse_target_binary(tmp_path: Path):
    binary = tmp_path / "victim"
    binary.write_text("#!/bin/sh\n")
    t = runner.parse_target(str(binary))
    assert t.binary == str(binary.resolve())
    assert t.kind == "binary"


def test_parse_target_name():
    t = runner.parse_target("Safari")
    assert t.name == "Safari" and t.pid is None and t.binary is None
    assert t.kind == "name"


def test_parse_target_empty_rejected():
    with pytest.raises(ValueError):
        runner.parse_target("")


# --- resolve_template ------------------------------------------------

def test_resolve_template_traversal_rejected():
    with pytest.raises(ValueError):
        runner.resolve_template("../../../etc/passwd")


def test_resolve_template_disallowed_chars():
    with pytest.raises(ValueError):
        runner.resolve_template("api trace")  # space


def test_resolve_template_missing():
    with pytest.raises(FileNotFoundError):
        runner.resolve_template("does-not-exist-zzz")


def test_resolve_template_real_one_exists():
    # api-trace.js ships with the package - sanity-check the lookup.
    p = runner.resolve_template("api-trace")
    assert p.is_file() and p.name == "api-trace.js"


# --- load_script_source ----------------------------------------------

def test_load_script_xor_required():
    with pytest.raises(ValueError):
        runner.load_script_source(None, None)
    with pytest.raises(ValueError):
        runner.load_script_source("api-trace", "/tmp/foo.js")


def test_load_script_from_template():
    src, origin = runner.load_script_source("api-trace", None)
    assert origin == "template:api-trace"
    assert "send(" in src or "Interceptor" in src  # smoke


def test_load_script_from_file(tmp_path: Path):
    js = tmp_path / "h.js"
    js.write_text("send({hello: 'world'});\n")
    src, origin = runner.load_script_source(None, str(js))
    assert origin == f"file:{js.resolve()}"
    assert "hello" in src


def test_binary_flow_trace_parser_hooks_render_from_taxonomy():
    """Drift guard: the parser hook list is generated, not hand-copied.

    The template used to carry a hand-written subset of the taxonomy's
    PARSER_FUNCS that silently drifted; the rendered source must now
    contain every taxonomy parser name and the template file none.
    """
    from core.function_taxonomy import PARSER_FUNCS

    template_body = runner.resolve_template("binary-flow-trace").read_text(
        encoding="utf-8",
    )
    assert runner._PARSER_HOOKS_SLOT in template_body

    src, origin = runner.load_script_source("binary-flow-trace", None)
    assert origin == "template:binary-flow-trace"
    assert runner._PARSER_HOOKS_SLOT not in src
    for name in PARSER_FUNCS:
        assert f'"{name}"' in src, name
    # Arg readers remain for the historically-instrumented entries.
    assert "'ZSTD_decompress': a => ({ size: a[3].toInt32() })" in src


def test_binary_flow_trace_hooks_include_pack_derived_names():
    """The hook list is regenerated from the seeds|pack union (WP6):
    names that live only in the parser_apis data pack — never in the
    seed literal — must reach the rendered JS."""
    from core.function_taxonomy import PARSER_FUNCS, PARSER_SEED_FUNCS

    pack_only = PARSER_FUNCS - PARSER_SEED_FUNCS
    assert pack_only, "pack contributed nothing to PARSER_FUNCS"
    src, _ = runner.load_script_source("binary-flow-trace", None)
    # TIFFOpen is a stable legacy-catalog pack entry; also spot-check
    # an arbitrary pack-only name so the assertion tracks the pack.
    assert '"TIFFOpen"' in src
    assert f'"{min(pack_only)}"' in src


def test_non_template_scripts_are_not_rendered(tmp_path: Path):
    js = tmp_path / "h.js"
    js.write_text("const x = /*__PARSER_HOOKS__*/ [];\n")
    src, _ = runner.load_script_source(None, str(js))
    assert runner._PARSER_HOOKS_SLOT in src


# --- run() with attach-by-PID ----------------------------------------

def test_run_attach_pid_writes_outputs(tmp_path: Path):
    device = FakeDevice("local")
    fake = _fake_frida(device)
    cfg = runner.RunConfig(
        target=runner.parse_target("1234"),
        out_dir=tmp_path,
        script_source="send({hi: 1});",
        script_origin="file:test.js",
        duration_sec=0.3,
    )

    events: list[dict] = []
    def on_event(rec: dict):
        events.append(rec)

    original_load = FakeScript.load
    fired = threading.Event()
    def load_and_fire(self):
        original_load(self)
        self.fire({"type": "send", "payload": {"hi": 1}})
        fired.set()
    FakeScript.load = load_and_fire
    try:
        result = runner.run(cfg, on_event=on_event, frida_mod_override=fake)
    finally:
        FakeScript.load = original_load
    assert fired.is_set()

    assert result.ok is True
    assert result.resolved_pid == 1234
    assert device.attach_calls == [1234]
    assert device.spawn_calls == []  # attach mode → no spawn
    assert (tmp_path / "events.jsonl").is_file()
    assert (tmp_path / "metadata.json").is_file()
    assert (tmp_path / "frida-report.md").is_file()
    assert (tmp_path / "script.js").read_text() == "send({hi: 1});"
    # Event captured?
    lines = (tmp_path / "events.jsonl").read_text().strip().splitlines()
    assert len(lines) >= 1
    parsed = json.loads(lines[0])
    assert parsed["type"] == "send"
    assert parsed["payload"] == {"hi": 1}
    # Metadata
    meta = json.loads((tmp_path / "metadata.json").read_text())
    assert meta["ok"] is True
    assert meta["target"]["pid"] == 1234


def test_run_spawn_resumes_after_load(tmp_path: Path):
    device = FakeDevice("local")
    fake = _fake_frida(device)
    binary = tmp_path / "victim"
    binary.write_text("#!/bin/sh\necho hi\n")
    cfg = runner.RunConfig(
        target=runner.parse_target(str(binary)),
        out_dir=tmp_path,
        script_source="// noop",
        script_origin="file:noop.js",
        duration_sec=0.02,
    )
    result = runner.run(cfg, frida_mod_override=fake)
    assert result.ok is True
    assert device.spawn_calls == [[str(binary.resolve())]]
    assert device.resume_calls == [9999]   # spawn returned 9999 above
    # Attach must be called with the spawn PID.
    assert device.attach_calls == [9999]
    assert result.resolved_pid == 9999


class EnvCapturingFakeDevice(FakeDevice):
    """FakeDevice whose spawn accepts the env kwarg (modern bindings)."""

    def __init__(self, id_: str = "local"):
        super().__init__(id_)
        self.spawn_envs: list[dict | None] = []

    def spawn(self, argv: list[str], env: dict | None = None) -> int:
        self.spawn_envs.append(env)
        return super().spawn(argv)


def test_spawn_env_is_allowlist_derived_not_operator_environ(
    tmp_path: Path, monkeypatch,
):
    """The spawned process is untrusted TARGET code. In --unsafe-attach /
    direct-CLI mode the driver runs in the operator's full environment,
    so the child env must be built from the safe-env allowlist — a raw
    os.environ copy hands the target every credential the operator
    carries (getenv is all it takes)."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret-do-not-leak")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
    monkeypatch.setenv("GH_TOKEN", "gh-secret")
    # On the allowlist for RAPTOR's own tooling (RAPTOR_ prefix) but in
    # the target-facing strip set — must not reach target code.
    monkeypatch.setenv("RAPTOR_SESSION_TOKEN", "session-secret")

    device = EnvCapturingFakeDevice("local")
    binary = tmp_path / "victim"
    binary.write_text("#!/bin/sh\necho hi\n")
    cfg = runner.RunConfig(
        target=runner.parse_target(str(binary)),
        out_dir=tmp_path,
        script_source="// noop",
        script_origin="file:noop.js",
        duration_sec=0.02,
    )
    _session, pid = runner._attach_or_spawn(None, device, cfg)
    assert pid == 9999
    assert len(device.spawn_envs) == 1
    env = device.spawn_envs[0]
    assert env is not None
    for secret in ("ANTHROPIC_API_KEY", "AWS_SECRET_ACCESS_KEY",
                   "GH_TOKEN", "RAPTOR_SESSION_TOKEN"):
        assert secret not in env, f"{secret} leaked into spawn env"
    # A desktop target still needs the basics.
    assert "PATH" in env


def test_spawn_env_strips_session_credential_without_config(monkeypatch):
    """Fallback lane (core.config unavailable) must still be a minimal
    env, never a fall-open to the full operator environment."""
    import builtins

    real_import = builtins.__import__

    def _no_core_config(name, *args, **kwargs):
        if name == "core.config" or name.startswith("core.config."):
            raise ImportError("simulated missing core.config")
        return real_import(name, *args, **kwargs)

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret-do-not-leak")
    monkeypatch.setenv("RAPTOR_SESSION_TOKEN", "session-secret")
    monkeypatch.setattr(builtins, "__import__", _no_core_config)
    env = runner._spawn_env()
    assert "ANTHROPIC_API_KEY" not in env
    assert "RAPTOR_SESSION_TOKEN" not in env
    assert "PATH" in env


def test_run_zero_events_still_creates_events_jsonl(tmp_path: Path):
    # frida-report.md unconditionally points at events.jsonl, so the file
    # must exist even when the script emits nothing during the window.
    device = FakeDevice("local")
    fake = _fake_frida(device)
    cfg = runner.RunConfig(
        target=runner.parse_target("1"),
        out_dir=tmp_path,
        script_source="// emits nothing",
        script_origin="file:noop.js",
        duration_sec=0.02,
    )
    result = runner.run(cfg, frida_mod_override=fake)
    assert result.ok is True
    assert result.events_captured == 0
    events = tmp_path / "events.jsonl"
    assert events.is_file()
    assert events.read_text() == ""   # created, but empty


def test_run_remote_host_routes_correctly(tmp_path: Path):
    local = FakeDevice("local")
    remote = FakeDevice("remote-host")
    fake = _fake_frida(local, remote_device=remote)
    cfg = runner.RunConfig(
        target=runner.parse_target("victim-proc"),
        out_dir=tmp_path,
        script_source="// noop",
        script_origin="file:noop.js",
        duration_sec=0.02,
        host="10.10.20.1",
    )
    result = runner.run(cfg, frida_mod_override=fake)
    assert result.ok is True
    # Local device must NOT have been used.
    assert local.attach_calls == []
    # Remote device was used; attach by name.
    assert remote.attach_calls == ["victim-proc"]


def test_run_usb_routes_correctly(tmp_path: Path):
    local = FakeDevice("local")
    usb = FakeDevice("usb-dev")
    fake = _fake_frida(local, usb_device=usb)
    cfg = runner.RunConfig(
        target=runner.parse_target("com.example.app"),
        out_dir=tmp_path,
        script_source="// noop",
        script_origin="file:noop.js",
        duration_sec=0.02,
        use_usb=True,
    )
    result = runner.run(cfg, frida_mod_override=fake)
    assert result.ok is True
    assert local.attach_calls == []
    assert usb.attach_calls == ["com.example.app"]


def test_run_script_error_persisted(tmp_path: Path):
    device = FakeDevice("local")
    fake = _fake_frida(device)
    cfg = runner.RunConfig(
        target=runner.parse_target("1"),
        out_dir=tmp_path,
        script_source="// crash",
        script_origin="file:crash.js",
        duration_sec=0.3,
    )

    original_load = FakeScript.load
    def load_and_error(self):
        original_load(self)
        self.fire({
            "type": "error",
            "description": "ReferenceError: blah is not defined",
            "stack": "...",
            "fileName": "/agent/script1.js",
            "lineNumber": 3,
        })
    FakeScript.load = load_and_error
    try:
        result = runner.run(cfg, frida_mod_override=fake)
    finally:
        FakeScript.load = original_load

    assert result.ok is True   # run completes; error logged not raised
    body = (tmp_path / "events.jsonl").read_text()
    assert "ReferenceError" in body


def test_run_attach_failure_marks_failed(tmp_path: Path):
    class BrokenDevice(FakeDevice):
        def attach(self, target):
            raise RuntimeError("ptrace denied")
    device = BrokenDevice("local")
    fake = _fake_frida(device)
    cfg = runner.RunConfig(
        target=runner.parse_target("1"),
        out_dir=tmp_path,
        script_source="// noop",
        script_origin="file:noop.js",
        duration_sec=0.02,
    )
    result = runner.run(cfg, frida_mod_override=fake)
    assert result.ok is False
    assert "ptrace denied" in (result.error or "")
    # metadata + report still written so the operator has a trail.
    meta = json.loads((tmp_path / "metadata.json").read_text())
    assert meta["ok"] is False
    assert "ptrace denied" in (meta["error"] or "")
    report = (tmp_path / "frida-report.md").read_text()
    assert "**Status:** Failed" in report
    # events.jsonl is created up-front, so it exists even on a failed run.
    assert (tmp_path / "events.jsonl").is_file()


def test_frida_unavailable_raises(monkeypatch, tmp_path: Path):
    """When frida-python isn't installed, _import_frida must raise
    FridaUnavailable rather than the bare ImportError so the CLI can
    print an actionable message."""
    # Force _import_frida to raise ImportError by stubbing the inner
    # ``import frida``. We do that by monkey-patching the helper itself
    # - simpler than swapping sys.modules.
    def _boom():
        raise runner.FridaUnavailable("frida-python not installed")
    monkeypatch.setattr(runner, "_import_frida", _boom)
    cfg = runner.RunConfig(
        target=runner.parse_target("1"),
        out_dir=tmp_path,
        script_source="// noop",
        script_origin="file:noop.js",
        duration_sec=0.02,
    )
    with pytest.raises(runner.FridaUnavailable):
        runner.run(cfg)


def test_capture_window_not_eroded_by_slow_setup(tmp_path: Path):
    """The observation deadline is anchored where capture begins:
    attach/spawn and script-load latency must extend the run, never be
    deducted from the requested duration (a slow init would otherwise
    collapse the effective window to near zero while metadata reported
    a full-length run)."""
    import time as _time

    device = FakeDevice("local")
    fake = _fake_frida(device)
    cfg = runner.RunConfig(
        target=runner.parse_target("1234"),
        out_dir=tmp_path,
        script_source="// noop",
        script_origin="file:noop.js",
        duration_sec=0.3,
    )

    original_load = FakeScript.load
    def slow_load(self):
        _time.sleep(0.4)  # longer than the whole requested window
        original_load(self)
    FakeScript.load = slow_load
    try:
        start = _time.monotonic()
        result = runner.run(cfg, frida_mod_override=fake)
        elapsed = _time.monotonic() - start
    finally:
        FakeScript.load = original_load

    assert result.ok is True
    # setup + a full-length capture window, not setup alone.
    assert elapsed >= 0.65
    assert result.setup_sec >= 0.35
    meta = json.loads((tmp_path / "metadata.json").read_text())
    assert meta["setup_sec"] == result.setup_sec
    assert meta["duration_actual_sec"] >= meta["setup_sec"] + 0.25


def test_fast_setup_reports_small_setup_sec(tmp_path: Path):
    device = FakeDevice("local")
    fake = _fake_frida(device)
    cfg = runner.RunConfig(
        target=runner.parse_target("1234"),
        out_dir=tmp_path,
        script_source="// noop",
        script_origin="file:noop.js",
        duration_sec=0.05,
    )
    result = runner.run(cfg, frida_mod_override=fake)
    assert result.ok is True
    # Sanity ceiling only: with all-fake devices setup is ~ms, and
    # the semantics of what setup_sec measures are pinned by the
    # slow-setup companion above. 5s absorbs a loaded runner's stall
    # where the old 0.5s bound false-failed on one deschedule.
    assert result.setup_sec < 5.0
    assert result.duration_actual_sec >= 0.05


class OldBindingsFakeDevice(FakeDevice):
    """frida bindings predating the spawn env kwarg."""

    def spawn(self, argv: list[str]) -> int:  # type: ignore[override]
        self.spawn_calls.append(argv)
        return self._next_spawn_pid


def test_old_bindings_spawn_refuses_instead_of_leaking_env(
    tmp_path: Path, monkeypatch,
):
    """Bindings without env control would spawn the untrusted target
    with the driver's FULL environment — refuse instead of leaking."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret-do-not-leak")
    device = OldBindingsFakeDevice("local")
    binary = tmp_path / "victim"
    binary.write_text("#!/bin/sh\necho hi\n")
    cfg = runner.RunConfig(
        target=runner.parse_target(str(binary)),
        out_dir=tmp_path,
        script_source="// noop",
        script_origin="file:noop.js",
        duration_sec=0.02,
    )
    fake = _fake_frida(device)
    result = runner.run(cfg, frida_mod_override=fake)
    assert result.ok is False
    assert "refusing to spawn" in (result.error or "")


def test_spawn_env_carries_no_raptor_markers(tmp_path: Path, monkeypatch):
    """Allowlist survivors like RAPTOR_EF_* / RAPTOR_CI serve RAPTOR's
    own tool children, but to the spawned TARGET every RAPTOR_* name
    is a one-getenv framework fingerprint (anti-analysis trigger).
    The target env must carry none."""
    monkeypatch.setenv("RAPTOR_EF_TIMEOUT_FAST", "5")
    monkeypatch.setenv("RAPTOR_EF_VERBOSE", "1")
    monkeypatch.setenv("RAPTOR_CI", "1")
    monkeypatch.setenv("RAPTOR_CC_TRANSPORT_DISABLED", "1")

    env = runner._spawn_env()
    raptor_names = [k for k in env
                    if k.startswith(("RAPTOR_", "_RAPTOR"))
                    or k == "CLAUDECODE"]
    assert raptor_names == [], raptor_names
    # A desktop target still needs the basics.
    assert "PATH" in env


def test_tooling_safe_env_still_carries_ef_knobs(monkeypatch):
    """Both directions: the marker strip is TARGET-exec only — the
    tooling baseline (get_safe_env) must keep the documented
    RAPTOR_EF_* budget knobs for scrub-spawned tool children."""
    from core.config import RaptorConfig

    monkeypatch.setenv("RAPTOR_EF_TIMEOUT_FAST", "5")
    env = RaptorConfig.get_safe_env()
    assert env.get("RAPTOR_EF_TIMEOUT_FAST") == "5"
