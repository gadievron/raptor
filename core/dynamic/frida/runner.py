"""Frida session runner.

Wraps the frida-python API into a single ``run()`` entry point:

  * Resolve the device (local / USB / remote frida-server).
  * Resolve the target (PID, name, bundle id, or binary path).
  * Spawn or attach.
  * Load the hook script (template or operator-supplied JS).
  * Capture ``send(...)`` messages into ``events.jsonl``.
  * Run for ``duration`` seconds, detach cleanly, write
    ``metadata.json`` + ``frida-report.md``.

The frida import is deferred so a) ``raptor doctor`` and the SKILL.md
remain usable on a host without frida-python installed and b) unit
tests can monkey-patch frida.* without import-time side effects.
"""

from __future__ import annotations

import json
import signal
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from .platform import HostInfo, detect_host


TEMPLATES_DIR = Path(__file__).parent / "templates"


class FridaUnavailable(RuntimeError):
    """Raised when frida-python isn't installed.

    Kept as a distinct exception so callers (CLI, libexec wrapper)
    can give an actionable error rather than a bare ImportError.
    """


@dataclass
class TargetSpec:
    """Parsed target descriptor.

    ``raw`` is what the operator typed; ``pid``, ``name``, ``binary``
    are the resolved interpretations. Exactly one of pid/name/binary
    is set after :func:`parse_target`.
    """
    raw: str
    pid: Optional[int] = None
    name: Optional[str] = None         # process name OR bundle id
    binary: Optional[str] = None       # filesystem path → spawn

    @property
    def kind(self) -> str:
        if self.pid is not None:
            return "pid"
        if self.binary is not None:
            return "binary"
        return "name"


def parse_target(raw: str) -> TargetSpec:
    """Classify a ``--target`` value.

    Order: numeric → PID; existing file → binary (spawn); else name
    (process name or bundle id, distinguished by frida at attach time).
    """
    raw = raw.strip()
    if not raw:
        raise ValueError("empty target")
    if raw.isdigit():
        return TargetSpec(raw=raw, pid=int(raw))
    p = Path(raw)
    if p.exists() and p.is_file():
        return TargetSpec(raw=raw, binary=str(p.resolve()))
    return TargetSpec(raw=raw, name=raw)


@dataclass
class RunConfig:
    """Inputs to one :func:`run` invocation.

    All fields besides ``target`` and ``out_dir`` have sensible
    defaults; the CLI populates from argparse.
    """
    target: TargetSpec
    out_dir: Path
    script_source: str
    script_origin: str                  # "template:<name>" or "file:<path>"
    duration_sec: float = 60.0
    host: Optional[str] = None          # frida-server host[:port]
    use_usb: bool = False
    spawn: bool = False
    unsafe_attach: bool = False         # informational; logged in metadata


@dataclass
class RunResult:
    """Outcome of a run. Populated incrementally; the JSON-serialisable
    fields are what gets written to ``metadata.json``.
    """
    ok: bool = False
    error: Optional[str] = None
    events_captured: int = 0
    duration_actual_sec: float = 0.0
    resolved_pid: Optional[int] = None
    device_id: Optional[str] = None
    host_info: Optional[HostInfo] = None


def resolve_template(name: str) -> Path:
    """Map a ``--template`` name to its on-disk JS file.

    Restricts to ``[a-zA-Z0-9_-]`` to defend against ``--template
    ../../../etc/passwd``. The eventual real path must live inside
    TEMPLATES_DIR; symlink-escape is rejected via ``.resolve()``
    comparison against the templates root.
    """
    if not name or not all(c.isalnum() or c in "-_" for c in name):
        raise ValueError(f"invalid template name: {name!r}")
    candidate = (TEMPLATES_DIR / f"{name}.js").resolve()
    root = TEMPLATES_DIR.resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        raise ValueError(f"template path escaped templates dir: {name!r}")
    if not candidate.is_file():
        raise FileNotFoundError(f"template not found: {name}")
    return candidate


def list_templates() -> list[str]:
    """Names of the bundled hook templates (sans .js)."""
    if not TEMPLATES_DIR.is_dir():
        return []
    return sorted(p.stem for p in TEMPLATES_DIR.glob("*.js"))


def load_script_source(template: Optional[str],
                      script_path: Optional[str]) -> tuple[str, str]:
    """Return (source, origin_label). Exactly one input must be set."""
    if bool(template) == bool(script_path):
        raise ValueError("specify exactly one of --template or --script")
    if template:
        path = resolve_template(template)
        return path.read_text(encoding="utf-8"), f"template:{template}"
    assert script_path is not None
    p = Path(script_path).resolve()
    if not p.is_file():
        raise FileNotFoundError(f"script not found: {script_path}")
    return p.read_text(encoding="utf-8"), f"file:{p}"


def _import_frida():
    """Late-bind frida-python with a useful error.

    Returning the module rather than importing at module-scope keeps
    this whole package importable on hosts without frida - important
    for `raptor doctor` and for unit tests that inject a fake.
    """
    try:
        import frida  # type: ignore
        return frida
    except ImportError as e:
        raise FridaUnavailable(
            "frida-python not installed. Install via: "
            "pipx install frida-tools  (or pip install --user frida-tools)"
        ) from e


def _resolve_device(frida_mod: Any, cfg: RunConfig):
    """Pick the device per the CLI flags.

    Mutually exclusive with --usb / --host already enforced at parse
    time in cli.py; here we just translate to frida-API calls.
    """
    if cfg.host:
        return frida_mod.get_device_manager().add_remote_device(cfg.host)
    if cfg.use_usb:
        return frida_mod.get_usb_device(timeout=5)
    return frida_mod.get_local_device()


def _attach_or_spawn(frida_mod: Any, device: Any, cfg: RunConfig
                     ) -> tuple[Any, int]:
    """Return (session, pid). Spawned processes start suspended;
    caller must ``device.resume(pid)`` after script load.
    """
    t = cfg.target
    if t.binary or cfg.spawn:
        # Spawn: argv0 = binary. No further args supported in v1 -
        # operator can wrap with a shell script if they need them.
        binary = t.binary or t.raw
        pid = device.spawn([binary])
        session = device.attach(pid)
        return session, pid
    if t.pid is not None:
        session = device.attach(t.pid)
        return session, t.pid
    # name or bundle id
    session = device.attach(t.name)
    # Pid resolution after attach: frida exposes session.pid only
    # since 16.x; fall back to None if absent for older bindings.
    return session, int(getattr(session, "pid", 0) or 0)


def run(cfg: RunConfig,
        on_event: Optional[Callable[[dict], None]] = None,
        frida_mod_override: Any = None) -> RunResult:
    """Execute one Frida session.

    Side effects in ``cfg.out_dir``:
      * ``events.jsonl`` - one JSON object per ``send()`` from the script
      * ``script.js`` - copy of the script source (template or file)
      * ``metadata.json`` - run shape, host info, target, timings
      * ``frida-report.md`` - human-readable summary

    ``on_event`` is called for every message in addition to being
    serialised - used by tests to assert events without parsing the
    jsonl file.
    """
    cfg.out_dir.mkdir(parents=True, exist_ok=True)
    (cfg.out_dir / "script.js").write_text(cfg.script_source, encoding="utf-8")

    host_info = detect_host()
    result = RunResult(host_info=host_info)

    frida_mod = frida_mod_override or _import_frida()

    events_path = cfg.out_dir / "events.jsonl"
    # Create up-front so the file frida-report.md points to always
    # exists - even for a run that captures zero events or fails
    # before the first send().
    events_path.touch()
    events_lock = threading.Lock()
    event_count = {"n": 0}

    def _message_cb(message: dict, data: Optional[bytes]) -> None:
        """Frida's on('message') callback. Both ``send()`` payloads
        (type='send') and uncaught script errors (type='error')
        flow through here. We persist both so a hook crashing
        mid-run leaves a trail.
        """
        record: dict[str, Any] = {
            "ts": time.time(),
            "type": message.get("type"),
        }
        if message.get("type") == "send":
            record["payload"] = message.get("payload")
        elif message.get("type") == "error":
            record["error"] = {
                "description": message.get("description"),
                "stack": message.get("stack"),
                "fileName": message.get("fileName"),
                "lineNumber": message.get("lineNumber"),
            }
        else:
            record["raw"] = message
        if data is not None:
            # Binary blobs (rare; emitted via send(payload, data) in JS)
            # are summarised, not embedded - JSONL stays line-grep-able.
            record["binary_len"] = len(data)
        with events_lock:
            with events_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=str) + "\n")
            event_count["n"] += 1
        if on_event is not None:
            try:
                on_event(record)
            except Exception:
                pass  # never let a test callback break the run

    started = time.monotonic()
    session = None
    device = None
    pid: Optional[int] = None

    try:
        device = _resolve_device(frida_mod, cfg)
        result.device_id = getattr(device, "id", None) or str(device)
        session, pid = _attach_or_spawn(frida_mod, device, cfg)
        result.resolved_pid = pid

        script = session.create_script(cfg.script_source)
        script.on("message", _message_cb)
        script.load()

        # If we spawned, the process is suspended pre-load. Resume it
        # AFTER load so hooks are in place before main() runs.
        if cfg.target.binary or cfg.spawn:
            device.resume(pid)

        # Sleep loop with SIGINT trap so Ctrl-C in the operator's shell
        # terminates the run cleanly rather than orphaning the script.
        stop = threading.Event()

        def _on_sigint(_signum, _frame):
            stop.set()

        prev_handler = signal.signal(signal.SIGINT, _on_sigint)
        try:
            deadline = started + cfg.duration_sec
            while time.monotonic() < deadline and not stop.is_set():
                time.sleep(0.1)
        finally:
            signal.signal(signal.SIGINT, prev_handler)

        result.ok = True
    except FridaUnavailable:
        raise
    except Exception as e:
        result.ok = False
        result.error = f"{type(e).__name__}: {e}"
    finally:
        try:
            if session is not None:
                session.detach()
        except Exception:
            pass
        result.duration_actual_sec = round(time.monotonic() - started, 3)
        result.events_captured = event_count["n"]
        _write_metadata(cfg, result)
        _write_report(cfg, result)

    return result


def _write_metadata(cfg: RunConfig, result: RunResult) -> None:
    payload = {
        "ok": result.ok,
        "error": result.error,
        "target": {
            "raw": cfg.target.raw,
            "kind": cfg.target.kind,
            "pid": cfg.target.pid,
            "name": cfg.target.name,
            "binary": cfg.target.binary,
        },
        "script_origin": cfg.script_origin,
        "duration_requested_sec": cfg.duration_sec,
        "duration_actual_sec": result.duration_actual_sec,
        "events_captured": result.events_captured,
        "device": {
            "id": result.device_id,
            "host": cfg.host,
            "usb": cfg.use_usb,
        },
        "host": {
            "system": result.host_info.system if result.host_info else None,
            "arch": result.host_info.arch if result.host_info else None,
            "frida_version": (result.host_info.frida_version
                              if result.host_info else None),
            "frida_bin": (result.host_info.frida_bin
                          if result.host_info else None),
            "sip_status": (result.host_info.sip_status
                           if result.host_info else None),
            "ptrace_scope": (result.host_info.ptrace_scope
                             if result.host_info else None),
        },
        "spawn": cfg.spawn or bool(cfg.target.binary),
        "unsafe_attach": cfg.unsafe_attach,
        "resolved_pid": result.resolved_pid,
    }
    (cfg.out_dir / "metadata.json").write_text(
        json.dumps(payload, indent=2, default=str), encoding="utf-8")


def _write_report(cfg: RunConfig, result: RunResult) -> None:
    lines: list[str] = []
    lines.append("# RAPTOR Frida Run")
    lines.append("")
    status = "OK" if result.ok else "FAILED"
    lines.append(f"**Status:** {status}")
    if result.error:
        lines.append(f"**Error:** `{result.error}`")
    lines.append(f"**Target:** `{cfg.target.raw}` ({cfg.target.kind})")
    if result.resolved_pid:
        lines.append(f"**PID:** {result.resolved_pid}")
    lines.append(f"**Script:** `{cfg.script_origin}`")
    lines.append(f"**Events captured:** {result.events_captured}")
    lines.append(
        f"**Duration:** {result.duration_actual_sec:.2f}s "
        f"(requested {cfg.duration_sec:.0f}s)"
    )
    if cfg.host:
        lines.append(f"**Remote frida-server:** `{cfg.host}`")
    if cfg.use_usb:
        lines.append("**Device:** USB")
    if cfg.unsafe_attach:
        lines.append("**Mode:** `--unsafe-attach` (sandbox bypass)")
    lines.append("")
    lines.append("Raw events: see `events.jsonl`. Run metadata: see "
                 "`metadata.json`. Script as executed: see `script.js`.")
    (cfg.out_dir / "frida-report.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8")
