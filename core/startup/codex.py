"""Codex CLI readiness and delegated login helpers.

RAPTOR treats Codex authentication as Codex-owned state. These helpers
detect the executable and ask the CLI for status, but never inspect,
copy, persist, or log credential material from ``~/.codex`` or any
other credential store.
"""

from __future__ import annotations

from dataclasses import dataclass
import shutil
import subprocess
from typing import Sequence

from core.config import RaptorConfig
from core.security.log_sanitisation import escape_nonprintable


DEFAULT_TIMEOUT = 10
MAX_DIAGNOSTIC_CHARS = 500


@dataclass(frozen=True)
class CodexAuthStatus:
    """Result of a ``codex login status`` readiness check."""

    executable: str | None
    authenticated: bool
    available: bool
    detail: str = ""


def find_codex_executable() -> str | None:
    """Return the Codex executable path if it is on ``PATH``."""

    return shutil.which("codex")


def _tail(text: str, limit: int = MAX_DIAGNOSTIC_CHARS) -> str:
    """Bound and terminal-sanitize subprocess diagnostics."""

    clean = escape_nonprintable(text.strip())
    if len(clean) <= limit:
        return clean
    return "..." + clean[-limit:]


def check_codex_auth(
    *,
    executable: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> CodexAuthStatus:
    """Check whether Codex CLI is installed and authenticated.

    The supported boundary is ``codex login status``. Exit code zero
    means authenticated; non-zero means setup is needed. Captured output
    is used only for bounded diagnostics and is sanitized before any
    caller can print it.
    """

    codex = executable or find_codex_executable()
    if not codex:
        return CodexAuthStatus(
            executable=None,
            authenticated=False,
            available=False,
            detail="Codex CLI not found on PATH",
        )

    try:
        proc = subprocess.run(
            [codex, "login", "status"],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=RaptorConfig.get_safe_env(preserve_proxy=True),
        )
    except subprocess.TimeoutExpired:
        return CodexAuthStatus(
            executable=codex,
            authenticated=False,
            available=True,
            detail=f"`codex login status` timed out after {timeout}s",
        )
    except OSError as exc:
        return CodexAuthStatus(
            executable=codex,
            authenticated=False,
            available=False,
            detail=f"could not run Codex CLI: {_tail(str(exc))}",
        )

    diagnostic = _tail(
        "\n".join(part for part in (proc.stdout, proc.stderr) if part)
    )
    if proc.returncode == 0:
        return CodexAuthStatus(
            executable=codex,
            authenticated=True,
            available=True,
            detail=diagnostic,
        )
    return CodexAuthStatus(
        executable=codex,
        authenticated=False,
        available=True,
        detail=diagnostic or f"`codex login status` exited {proc.returncode}",
    )


def codex_login_command(*, device_auth: bool = False) -> list[str]:
    """Return the delegated Codex login command."""

    cmd = ["login"]
    if device_auth:
        cmd.append("--device-auth")
    return cmd


def run_codex_login(
    *,
    executable: str | None = None,
    device_auth: bool = False,
    extra_args: Sequence[str] = (),
) -> int:
    """Delegate interactive authentication to ``codex login``.

    The child inherits stdio so Codex can open a browser, print a device
    code, or prompt as needed. RAPTOR does not capture credentials or
    read Codex credential files.
    """

    codex = executable or find_codex_executable()
    if not codex:
        print("Codex CLI not found on PATH. Install Codex, then rerun this command.")
        return 1

    cmd = [codex, *codex_login_command(device_auth=device_auth), *extra_args]
    try:
        return subprocess.run(
            cmd,
            env=RaptorConfig.get_safe_env(preserve_proxy=True),
        ).returncode
    except OSError as exc:
        print(f"Could not run Codex CLI: {_tail(str(exc))}")
        return 1
