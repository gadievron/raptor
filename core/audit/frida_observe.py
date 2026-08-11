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
from typing import Any, Dict, FrozenSet, List, Optional, Set

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
    args: List[str] = field(default_factory=list)
    retval: Optional[str] = None
    callees: List[str] = field(default_factory=list)
    timestamp_ms: float = 0.0


@dataclass
class FridaObserveResult:
    """Result of a Frida observation session."""

    attached: bool
    observations: List[FridaObservation] = field(default_factory=list)
    observed_functions: FrozenSet[str] = field(default_factory=frozenset)
    evidence_strength: str = "inconclusive"
    duration_s: float = 0.0
    error: Optional[str] = None


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
    if target_pid is None:
        return False

    return True


def run_frida_observation(
    outcome: Any,
    ctx: Dict[str, Any],
    config: Any,
) -> Optional[FridaObserveResult]:
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
        observed_set: Set[str] = set()
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
    functions: List[Dict[str, Any]],
) -> FrozenSet[str]:
    """Run a broad Frida session to observe which functions are hit.

    Used pre-loop to populate the observation set for
    ``assign_observation_status``.  Hooks up to ``_MAX_HOOKS``
    functions and collects which ones fire during a test/exercise
    window.
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


def _resolve_target_pid(config: Any) -> Optional[int]:
    """Resolve the target process PID for Frida attachment.

    Checks (in order):
    1. Explicit ``config.frida_pid``
    2. ``config.frida_process_name`` — find by name
    3. ``config.target_container`` — find main process in container
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


def _find_pid_by_name(name: str) -> Optional[int]:
    """Find a process PID by name via /proc."""
    try:
        result = subprocess.run(
            ["pgrep", "-x", name],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            first_line = result.stdout.strip().splitlines()[0]
            return int(first_line)
    except (subprocess.TimeoutExpired, ValueError, OSError):
        pass
    return None


def _build_hook_targets(
    function_name: str,
    file_path: str,
    ctx: Dict[str, Any],
) -> List[str]:
    """Build the list of function names to hook.

    Includes the target function plus its immediate callees
    (to observe call sequences).
    """
    targets = [function_name]

    callees = ctx.get("callees", [])
    for ce in callees:
        if isinstance(ce, dict):
            name = ce.get("name", "")
        else:
            name = str(ce)
        if name and name not in targets:
            targets.append(name)

    return targets[:_MAX_HOOKS]


def _generate_frida_script(hook_targets: List[str]) -> str:
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

targets.forEach(function(name) {{
    var syms = Module.enumerateExports ? undefined : [];
    try {{
        var addrs = Module.findExportByName(null, name);
        if (!addrs) {{
            var matches = [];
            Process.enumerateModules().forEach(function(m) {{
                var exp = Module.findExportByName(m.name, name);
                if (exp) matches.push(exp);
            }});
            if (matches.length > 0) addrs = matches[0];
        }}
    }} catch(e) {{
        return;
    }}
    if (!addrs) return;

    try {{
        Interceptor.attach(addrs, {{
            onEnter: function(args) {{
                var argv = [];
                for (var i = 0; i < Math.min(6, 6); i++) {{
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

        cmd = [
            "frida",
            "-p", str(pid),
            "-l", str(script_file),
            "--no-pause",
            "-o", str(log_file),
        ]

        env = _safe_env()

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )

        return result.returncode == 0 or log_file.stat().st_size > 0

    except subprocess.TimeoutExpired:
        logger.debug("Frida session timed out after %ds", _OBSERVE_TIMEOUT_S)
        return log_file.exists() and log_file.stat().st_size > 0
    except FileNotFoundError:
        logger.debug("frida CLI not found")
        return False
    except Exception as exc:
        logger.debug("Frida session error: %s", exc)
        return False
    finally:
        if script_file and script_file.exists():
            try:
                script_file.unlink()
            except OSError:
                pass


def _run_frida_session_pid(
    pid: int,
    script_source: str,
    log_file: Path,
    timeout: int = _OBSERVE_TIMEOUT_S,
) -> bool:
    """Run a Frida session by PID without requiring a config object.

    Thin wrapper around the CLI invocation for use by auto-launch
    callers that manage their own process lifecycle.
    """
    script_file = None
    try:
        fd, script_path = tempfile.mkstemp(suffix=".js", prefix="raptor_frida_")
        os.close(fd)
        script_file = Path(script_path)
        script_file.write_text(script_source)

        cmd = [
            "frida",
            "-p", str(pid),
            "-l", str(script_file),
            "--no-pause",
            "-o", str(log_file),
        ]

        env = _safe_env()

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )

        return result.returncode == 0 or log_file.stat().st_size > 0

    except subprocess.TimeoutExpired:
        logger.debug("Frida session timed out after %ds", timeout)
        return log_file.exists() and log_file.stat().st_size > 0
    except FileNotFoundError:
        logger.debug("frida CLI not found")
        return False
    except Exception as exc:
        logger.debug("Frida session error: %s", exc)
        return False
    finally:
        if script_file and script_file.exists():
            try:
                script_file.unlink()
            except OSError:
                pass


def _parse_observations(log_file: Path) -> List[FridaObservation]:
    """Parse JSONL observations from a Frida session log."""
    observations: List[FridaObservation] = []

    if not log_file.exists():
        return observations

    try:
        content = log_file.read_text(errors="replace")[:_MAX_LOG_BYTES]
    except OSError:
        return observations

    call_stack: Dict[str, FridaObservation] = {}

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            msg_start = line.find('{')
            if msg_start >= 0:
                try:
                    data = json.loads(line[msg_start:])
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
                timestamp_ms=data.get("ts", 0.0),
            )
            call_stack[func_name] = obs
            observations.append(obs)

        elif msg_type == "return":
            func_name = data.get("function", "")
            pending = call_stack.pop(func_name, None)
            if pending is not None:
                pending.retval = data.get("retval")

    return observations


def _safe_env() -> Dict[str, str]:
    """Build a sanitised environment for the Frida subprocess."""
    try:
        from core.config import RaptorConfig
        return RaptorConfig.get_safe_env()
    except Exception:
        env = dict(os.environ)
        for key in ("TERMINAL", "EDITOR", "VISUAL", "BROWSER", "PAGER"):
            env.pop(key, None)
        return env
