"""Binary-target mechanical verification for /audit.

Decompiler rule selection: curated Semgrep YAML rules that tolerate
synthetic variable names and decompiler output quirks. Fed into the
standard tool chain via ``decompiler_rules_for_hypothesis``.

Frida auto-launch: when the binary is executable and --dynamic is set,
launch it under Frida observation with lightweight input stimulation.
Confirms function reachability at runtime.
"""

from __future__ import annotations

import importlib
import logging
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_RULES_DIR = Path(__file__).parent / "rules" / "decompiler"


def _safe_env() -> Dict[str, str]:
    """Build a sanitised environment for binary subprocesses."""
    try:
        from core.config import RaptorConfig
        return RaptorConfig.get_safe_env()
    except Exception:
        env = dict(os.environ)
        for key in ("TERMINAL", "EDITOR", "VISUAL", "BROWSER", "PAGER"):
            env.pop(key, None)
        return env

_CWE_RULE_MAP: Dict[str, List[str]] = {
    "CWE-134": ["format-string.yaml"],
    "CWE-120": ["buffer-overflow.yaml"],
    "CWE-121": ["buffer-overflow.yaml"],
    "CWE-122": ["buffer-overflow.yaml", "memory-safety.yaml"],
    "CWE-78": ["command-injection.yaml"],
    "CWE-416": ["memory-safety.yaml"],
    "CWE-415": ["memory-safety.yaml"],
}

_KEYWORD_RULE_MAP: Dict[str, str] = {
    "format string": "format-string.yaml",
    "printf": "format-string.yaml",
    "buffer overflow": "buffer-overflow.yaml",
    "stack overflow": "buffer-overflow.yaml",
    "heap overflow": "buffer-overflow.yaml",
    "strcpy": "buffer-overflow.yaml",
    "command injection": "command-injection.yaml",
    "os command": "command-injection.yaml",
    "use after free": "memory-safety.yaml",
    "use-after-free": "memory-safety.yaml",
    "double free": "memory-safety.yaml",
    "double-free": "memory-safety.yaml",
    "memcpy": "memory-safety.yaml",
}


def decompiler_rules_for_hypothesis(
    hypothesis: str,
    cwe: str = "",
) -> List[Path]:
    """Select decompiler Semgrep rules for a hypothesis + CWE.

    Returns resolved paths to YAML rule files.
    """
    rule_files: set[str] = set()

    if cwe:
        normalised = cwe.upper().replace("_", "-")
        if not normalised.startswith("CWE-"):
            normalised = "CWE-" + normalised
        for rf in _CWE_RULE_MAP.get(normalised, []):
            rule_files.add(rf)

    hyp_lower = hypothesis.lower()
    for keyword, rf in _KEYWORD_RULE_MAP.items():
        if keyword in hyp_lower:
            rule_files.add(rf)

    if not rule_files:
        for yaml_file in _RULES_DIR.glob("*.yaml"):
            rule_files.add(yaml_file.name)

    resolved = []
    for rf in sorted(rule_files):
        path = _RULES_DIR / rf
        if path.is_file():
            resolved.append(path)

    return resolved


# ── Frida auto-launch ─────────────────────────────────────────────────


_AUTO_LAUNCH_TIMEOUT_S = 10
_STIMULATE_TIMEOUT_S = 5


def can_auto_launch(binary_path: Optional[Path]) -> bool:
    """Check if a binary can be auto-launched for Frida observation."""
    if binary_path is None:
        return False
    p = Path(binary_path)
    return p.is_file() and os.access(p, os.X_OK)


def auto_launch_and_observe(
    *,
    binary_path: Path,
    function_name: str,
    stimulate_args: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """Launch a binary under Frida, stimulate it, observe function calls.

    Returns a dict with ``evidence_strength`` ("confirmed" or
    "inconclusive") and ``observations``, or None on failure.

    The binary is launched as a subprocess, Frida attaches, the
    stimulation input is sent, and observations are collected before
    the process is terminated.
    """
    try:
        importlib.import_module("frida")
    except ImportError:
        logger.debug("frida not available — skipping auto-launch")
        return None

    binary_path = Path(binary_path).resolve()
    if not can_auto_launch(binary_path):
        return None

    proc = None
    try:
        args = [str(binary_path)]
        if stimulate_args:
            args.extend(stimulate_args)

        safe_env = _safe_env()

        proc = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=safe_env,
        )

        time.sleep(0.3)

        if proc.poll() is not None:
            return {
                "evidence_strength": "inconclusive",
                "reason": "process exited before Frida could attach",
                "exit_code": proc.returncode,
            }

        from .frida_observe import (
            _generate_frida_script,
            _parse_observations,
            _run_frida_session_pid,
        )

        fd, log_path = tempfile.mkstemp(
            suffix=".frida.jsonl", prefix="raptor_auto_",
        )
        os.close(fd)
        log_file = Path(log_path)

        try:
            hook_targets = [function_name]
            script_source = _generate_frida_script(hook_targets)
            success = _run_frida_session_pid(
                proc.pid, script_source, log_file,
                timeout=_AUTO_LAUNCH_TIMEOUT_S,
            )

            if proc.stdin:
                try:
                    proc.stdin.write(b"AAAA\n")
                    proc.stdin.flush()
                except OSError:
                    pass

            time.sleep(_STIMULATE_TIMEOUT_S)

            observations = _parse_observations(log_file) if success else []
            target_observed = any(
                obs.function == function_name for obs in observations
            )

            return {
                "evidence_strength": "confirmed" if target_observed else "inconclusive",
                "observations": [
                    {"function": obs.function, "args": obs.args}
                    for obs in observations
                ],
                "pid": proc.pid,
            }
        finally:
            try:
                log_file.unlink()
            except OSError:
                pass

    except Exception as exc:
        logger.debug(
            "auto-launch Frida observation failed for %s: %s",
            binary_path.name, exc, exc_info=True,
        )
        return None
    finally:
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
