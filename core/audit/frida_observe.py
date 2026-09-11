"""Frida-based runtime observation for audit review.

Hooks target functions via Frida to observe argument values, return
values, and call sequences at runtime.  Positive-only signal: observing
a function confirms reachability; not observing it is inconclusive
(observation window bias).

Requires: ``frida`` Python package + a running target process.
Gate: ``config.dynamic_validation`` + Frida available + process target.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_OBSERVE_TIMEOUT_S = 30
_ATTACH_TIMEOUT_S = 10
_MAX_HOOKS = 64
_MAX_LOG_BYTES = 8192


@dataclass
class FridaObservation:
    """A single observed function invocation."""

    function: str
    file: str
    args: list[str] = field(default_factory=list)
    retval: str | None = None
    callees: list[str] = field(default_factory=list)


@dataclass
class FridaObserveResult:
    """Result of a Frida observation session."""

    attached: bool
    observations: list[FridaObservation] = field(default_factory=list)
    observed_functions: frozenset[str] = field(default_factory=frozenset)
    evidence_strength: str = "inconclusive"
    duration_s: float = 0.0
    error: str | None = None


def should_run_frida(
    outcome: Any,
    config: Any,
) -> bool:
    """Gate: should we run Frida observation for this finding?"""
    if not getattr(config, "dynamic_validation", False):
        return False

    status = getattr(outcome, "status", "")
    if status != "finding":
        return False

    evidence_tool = getattr(outcome, "evidence_tool", "")
    if evidence_tool and evidence_tool.startswith(("dynamic:sanitizer", "frida:")):
        return False

    if not _frida_available():
        return False

    target_pid = _resolve_target_pid(config)
    return target_pid is not None


def run_frida_observation(
    outcome: Any,
    ctx: dict[str, Any],
    config: Any,
) -> FridaObserveResult | None:
    """Observe a function via Frida instrumentation.

    Attaches to the target process, hooks the function under review
    plus its callees, exercises the target (if a trigger is available),
    and collects observations.
    """
    start = time.monotonic()
    function_name = getattr(outcome, "function", "")
    file_path = getattr(outcome, "file", "")

    if not function_name:
        return None

    target_pid = _resolve_target_pid(config)
    if target_pid is None:
        return None

    hook_targets = _build_hook_targets(function_name, file_path, ctx)

    script_source = _generate_frida_script(hook_targets)

    log_file = None
    try:
        fd, log_path = tempfile.mkstemp(suffix=".frida.jsonl", prefix="raptor_")
        os.close(fd)
        log_file = Path(log_path)

        success = _run_frida_session(
            target_pid, script_source, log_file, config,
        )

        observations = _parse_observations(log_file) if success else []
        observed_set: set[str] = set()
        target_observed = False

        for obs in observations:
            key = f"{obs.file}:{obs.function}" if obs.file else obs.function
            observed_set.add(key)
            if obs.function == function_name:
                target_observed = True

        evidence_strength = "confirmed" if target_observed else "inconclusive"

        duration = time.monotonic() - start
        return FridaObserveResult(
            attached=success,
            observations=observations,
            observed_functions=frozenset(observed_set),
            evidence_strength=evidence_strength,
            duration_s=duration,
        )

    except Exception as exc:
        duration = time.monotonic() - start
        logger.debug("Frida observation failed: %s", exc, exc_info=True)
        return FridaObserveResult(
            attached=False,
            evidence_strength="inconclusive",
            duration_s=duration,
            error=str(exc),
        )
    finally:
        if log_file and log_file.exists():
            try:
                log_file.unlink()
            except OSError:
                pass


def collect_observed_functions(
    config: Any,
    functions: list[dict[str, Any]],
) -> frozenset[str]:
    """Run a broad Frida session to observe which functions are hit.

    Intended pre-loop populator for the observation set consumed by
    ``layer_resolution.assign_observation_status`` — NOT currently
    invoked by the orchestrator (the only production frida entry
    points are should_run_frida/run_frida_observation). Hooks up to
    ``_MAX_HOOKS`` functions and collects which ones fire during a
    test/exercise window.
    """
    if not _frida_available():
        return frozenset()

    target_pid = _resolve_target_pid(config)
    if target_pid is None:
        return frozenset()

    hook_targets = []
    for func in functions[:_MAX_HOOKS]:
        name = func.get("name", "")
        if name:
            hook_targets.append(name)

    if not hook_targets:
        return frozenset()

    script_source = _generate_frida_script(hook_targets)

    log_file = None
    try:
        fd, log_path = tempfile.mkstemp(suffix=".frida.jsonl", prefix="raptor_")
        os.close(fd)
        log_file = Path(log_path)

        success = _run_frida_session(target_pid, script_source, log_file, config)
        if not success:
            return frozenset()

        observations = _parse_observations(log_file)
        return frozenset(
            obs.function for obs in observations
        )
    except Exception:
        logger.debug("broad Frida observation failed", exc_info=True)
        return frozenset()
    finally:
        if log_file and log_file.exists():
            try:
                log_file.unlink()
            except OSError:
                pass


# -- Internal helpers --


def _frida_available() -> bool:
    """Check if the frida Python package is importable."""
    try:
        import importlib
        importlib.import_module("frida")
        return True
    except ImportError:
        return False


def _resolve_target_pid(config: Any) -> int | None:
    """Resolve the target process PID for Frida attachment.

    Checks (in order):
    1. Explicit ``config.frida_pid``
    2. ``config.frida_process_name`` — find by name

    (Container-based resolution is not implemented — setting a
    ``target_container`` on the config has no effect here.)
    """
    pid = getattr(config, "frida_pid", None)
    if pid is not None:
        try:
            os.kill(pid, 0)
            return pid
        except (OSError, PermissionError):
            return None

    process_name = getattr(config, "frida_process_name", None)
    if process_name:
        return _find_pid_by_name(process_name)

    return None


def _find_pid_by_name(name: str) -> int | None:
    """Find a process PID by name via /proc."""
    try:
        result = subprocess.run(
            ["pgrep", "-x", name],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            first_line = result.stdout.strip().splitlines()[0]
            return int(first_line)
    except (subprocess.TimeoutExpired, ValueError, OSError):
        pass
    return None


def _build_hook_targets(
    function_name: str,
    _file_path: str,
    ctx: dict[str, Any],
) -> list[str]:
    """Build the list of function names to hook.

    Includes the target function plus its immediate callees
    (to observe call sequences).
    """
    targets = [function_name]

    callees = ctx.get("callees", [])
    for ce in callees:
        name = ce.get("name", "") if isinstance(ce, dict) else str(ce)
        if name and name not in targets:
            targets.append(name)

    return targets[:_MAX_HOOKS]


def _generate_frida_script(hook_targets: list[str]) -> str:
    """Generate a Frida instrumentation script.

    Hooks each target function's export, logging arguments on
    enter and return values on leave.  Output is JSONL to the
    log file via ``send()``.
    """
    targets_json = json.dumps(hook_targets)
    return f"""\
'use strict';

var targets = {targets_json};
var hooked = 0;

function resolveExport(name) {{
    // Frida >= 17 removed the static Module.findExportByName —
    // relying on it made every lookup throw into the per-target
    // catch below, so zero functions were hooked and the whole
    // channel silently observed nothing. Feature-detect the
    // replacement and keep the legacy form for older runtimes.
    if (typeof Module.findGlobalExportByName === 'function') {{
        return Module.findGlobalExportByName(name);
    }}
    var addr = Module.findExportByName(null, name);
    if (addr) return addr;
    var matches = [];
    Process.enumerateModules().forEach(function(m) {{
        var exp = Module.findExportByName(m.name, name);
        if (exp) matches.push(exp);
    }});
    return matches.length > 0 ? matches[0] : null;
}}

targets.forEach(function(name) {{
    var addrs;
    try {{
        addrs = resolveExport(name);
    }} catch(e) {{
        return;
    }}
    if (!addrs) return;

    try {{
        Interceptor.attach(addrs, {{
            onEnter: function(args) {{
                var argv = [];
                // Log a fixed 6 arg slots; args[i] beyond the real
                // arity throws and is caught per-slot, padding with '?'.
                for (var i = 0; i < 6; i++) {{
                    try {{
                        argv.push(args[i].toString());
                    }} catch(e) {{
                        argv.push('?');
                    }}
                }}
                this._obs = {{
                    'type': 'call',
                    'function': name,
                    'args': argv,
                    'ts': Date.now()
                }};
                send(JSON.stringify(this._obs));
            }},
            onLeave: function(retval) {{
                var obs = {{
                    'type': 'return',
                    'function': name,
                    'retval': retval.toString(),
                    'ts': Date.now()
                }};
                send(JSON.stringify(obs));
            }}
        }});
        hooked++;
    }} catch(e) {{
        // Symbol exists but can't be hooked (e.g. inlined)
    }}
}});

send(JSON.stringify({{'type': 'ready', 'hooked': hooked}}));
"""


def _run_frida_session(
    pid: int,
    script_source: str,
    log_file: Path,
    config: Any,
) -> bool:
    """Run a Frida session, writing observations to log_file.

    Uses the frida CLI tool (``frida -p PID -l script.js``) rather
    than the Python API to stay within the sandbox policy (subprocess
    with timeout rather than in-process attachment).
    """
    script_file = None
    try:
        fd, script_path = tempfile.mkstemp(suffix=".js", prefix="raptor_frida_")
        os.close(fd)
        script_file = Path(script_path)
        script_file.write_text(script_source)

        timeout = getattr(config, "frida_timeout_s", _OBSERVE_TIMEOUT_S)
        # frida exits on its own after the -t window (quiet mode);
        # the subprocess timeout stays above it as a backstop for a
        # wedged CLI.
        session_s = max(1, timeout - 5)

        # No ``--no-pause``: the flag only ever applied to spawn mode
        # and current CLIs reject it as an unrecognized argument
        # before attaching — the whole session died on argv parsing.
        # No ``-o`` either: script ``send()`` payloads are emitted on
        # the REPL's stdout, not the -o log (which stays empty), so
        # the captured stdout is persisted to ``log_file`` below for
        # ``_parse_observations``.
        cmd = [
            "frida",
            "-p", str(pid),
            "-l", str(script_file),
            "-q",
            "-t", str(session_s),
        ]

        env = _safe_env()

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            check=False,
        )

        _write_session_log(log_file, result.stdout)
        return result.returncode == 0 or log_file.stat().st_size > 0

    except subprocess.TimeoutExpired as exc:
        logger.debug("Frida session timed out after %ds", timeout)
        partial = exc.stdout
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", errors="replace")
        if partial:
            # Keep whatever the killed CLI managed to emit; when the
            # exception carries nothing, leave any existing log
            # content untouched rather than clobbering it with "".
            _write_session_log(log_file, partial)
        return log_file.exists() and log_file.stat().st_size > 0
    except FileNotFoundError:
        logger.debug("frida CLI not found")
        return False
    except Exception as exc:  # noqa: BLE001 — dynamic observation is best-effort: report unobserved
        logger.debug("Frida session error: %s", exc)
        return False
    finally:
        if script_file and script_file.exists():
            try:
                script_file.unlink()
            except OSError:
                pass


def _write_session_log(log_file: Path, content: str | None) -> None:
    """Persist a Frida session's captured stdout for parsing."""
    try:
        log_file.write_text(content or "")
    except OSError:
        logger.debug("could not persist frida session log", exc_info=True)


def _parse_observations(log_file: Path) -> list[FridaObservation]:
    """Parse observations from a Frida session log.

    Accepts both raw JSONL and the frida CLI's stdout framing, where
    each ``send()`` payload arrives wrapped in a Python-repr line::

        message: {'type': 'send', 'payload': '{"type":"call",...}'} data: None

    The wrapper is single-quoted (not JSON), so the payload — the
    first ``{"``-opening object on the line — is decoded with
    ``raw_decode``, which tolerates the trailing wrapper text.
    """
    observations: list[FridaObservation] = []

    if not log_file.exists():
        return observations

    try:
        content = log_file.read_text(errors="replace")[:_MAX_LOG_BYTES]
    except OSError:
        return observations

    call_stack: dict[str, FridaObservation] = {}
    decoder = json.JSONDecoder()

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            msg_start = line.find('{"')
            if msg_start < 0:
                msg_start = line.find("{")
            if msg_start >= 0:
                try:
                    data, _end = decoder.raw_decode(line[msg_start:])
                except json.JSONDecodeError:
                    continue
            else:
                continue

        if not isinstance(data, dict):
            continue

        msg_type = data.get("type", "")

        if msg_type == "call":
            func_name = data.get("function", "")
            if not func_name:
                continue
            obs = FridaObservation(
                function=func_name,
                file="",
                args=data.get("args", []),
            )
            call_stack[func_name] = obs
            observations.append(obs)

        elif msg_type == "return":
            func_name = data.get("function", "")
            pending = call_stack.pop(func_name, None)
            if pending is not None:
                pending.retval = data.get("retval")

    return observations


def _safe_env() -> dict[str, str]:
    """Build a sanitised environment for the Frida subprocess.

    This is a RAW spawn (no core.sandbox chokepoint), and frida
    spawn-mode TARGETS inherit the CLI's environ — so the
    target-strip set (trust markers + session credential) must be
    removed here explicitly; the frida CLI needs none of them.
    """
    try:
        from core.config import RaptorConfig
        env = RaptorConfig.get_safe_env()
        for key in RaptorConfig.TARGET_ENV_STRIP_SET:
            env.pop(key, None)
        return env
    except Exception:  # noqa: BLE001 — config unavailable: fall back to manual scrub
        env = dict(os.environ)
        for key in ("CLAUDECODE", "_RAPTOR_TRUSTED",
                    "RAPTOR_SESSION_PID", "RAPTOR_SESSION_TOKEN"):
            env.pop(key, None)
        for key in ("TERMINAL", "EDITOR", "VISUAL", "BROWSER", "PAGER"):
            env.pop(key, None)
        return env
