"""
engine/codeql/env.py

Safe detection and configuration helper for CodeQL within RAPTOR.
"""

from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Optional, Literal, Dict, Any
import os
import shutil
import subprocess

CodeQLMode = Literal["disabled", "detect", "require"]

@dataclass
class CodeQLEnv:
    mode: CodeQLMode
    available: bool
    cli_path: Optional[str] = None
    version: Optional[str] = None
    queries: Optional[str] = None
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

def _run_codeql_version(cli_path: str, timeout_seconds: int = 10) -> Optional[str]:
    # Use a sanitised env for the version probe. Pre-fix the
    # subprocess inherited the parent's full environment —
    # `LD_PRELOAD` / `LD_LIBRARY_PATH` / `PYTHONPATH` set in the
    # operator's shell flowed into the codeql binary. CodeQL is a
    # JVM host, so JAVA_TOOL_OPTIONS / _JAVA_OPTIONS also injected
    # JVM args at startup including the `-javaagent:...` form
    # which loads attacker-controlled .jar files and runs them
    # inside the JVM. The detection probe ran this on every
    # codeql startup-check call, expanding the attack surface to
    # include "anyone who can set env vars in the parent shell
    # can run code via the version probe".
    #
    # Use core.config.RaptorConfig.get_safe_env() — same allowlist
    # used by the actual codeql analyse / database-create paths,
    # so the probe and the analysis run with consistent env shape.
    try:
        from core.config import RaptorConfig
        env = RaptorConfig.get_safe_env()
    except ImportError:
        # Fall back to default env rather than crashing the probe
        # if core.config isn't importable (unusual install layout).
        env = None
    try:
        completed = subprocess.run(
            [cli_path, "version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout_seconds,
            check=False,
            env=env,
        )
    except Exception:
        return None

    output = (completed.stdout or "").strip()
    if completed.returncode != 0:
        return None
    return output

def detect_codeql(mode: CodeQLMode = "detect") -> CodeQLEnv:
    mode = mode or "disabled"
    if mode not in ("disabled", "detect", "require"):
        return CodeQLEnv(
            mode="detect",
            available=False,
            reason=f"Unknown mode value {mode!r}, defaulting to 'detect'.",
        )

    if mode == "disabled":
        return CodeQLEnv(
            mode="disabled",
            available=False,
            reason="CodeQL mode is disabled by configuration.",
        )

    env_cli = os.environ.get("CODEQL_CLI")
    cli_path: Optional[str] = None
    reason: Optional[str] = None

    if env_cli:
        if os.path.isfile(env_cli) and os.access(env_cli, os.X_OK):
            cli_path = env_cli
        else:
            reason = f"CODEQL_CLI is set to {env_cli!r} but the file is not executable."

    if cli_path is None:
        resolved = shutil.which("codeql")
        if resolved:
            cli_path = resolved
        elif reason is None:
            reason = "CodeQL CLI not found on PATH and CODEQL_CLI is not set."

    if cli_path is None:
        return CodeQLEnv(
            mode=mode,
            available=False,
            cli_path=None,
            version=None,
            queries=os.environ.get("CODEQL_QUERIES"),
            reason=reason,
        )

    version = _run_codeql_version(cli_path)
    if not version:
        return CodeQLEnv(
            mode=mode,
            available=False,
            cli_path=cli_path,
            version=None,
            queries=os.environ.get("CODEQL_QUERIES"),
            reason="Failed to execute 'codeql version' successfully.",
        )

    queries = os.environ.get("CODEQL_QUERIES")
    return CodeQLEnv(
        mode=mode,
        available=True,
        cli_path=cli_path,
        version=version,
        queries=queries,
        reason=None,
    )
