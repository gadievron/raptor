"""Rule of Two enforcement for CI/CD safety.

Meta's "Agents Rule of Two": any agent with ≥2 of {A=untrusted input,
B=sensitive access, C=external state change} requires human-in-the-loop.

In interactive mode (TTY on stdin), Claude Code's permission prompt IS
the HITL — it asks before each Write/Bash. In CI/CD (no TTY), there's
no permission prompt, so RAPTOR must gate at the dispatch level.

Two gates:

1. **Weakened defenses**: --accept-weakened-defenses is blocked in
   non-interactive mode. CI pipelines must use a model that passes
   the defense envelope probe.

2. **Agentic passes with Write/Bash**: --understand/--validate grant
   Write+Bash to an agent processing untrusted target code (A+B).
   Blocked in non-interactive mode — no HITL to catch prompt-injected
   file writes or command execution.
"""

from __future__ import annotations

import logging
import sys

logger = logging.getLogger("raptor.security")


def is_interactive() -> bool:
    """True if stdin is a TTY (interactive session with a human)."""
    return hasattr(sys.stdin, "isatty") and sys.stdin.isatty()


class NonInteractiveError(RuntimeError):
    """Raised when a CI/CD safety gate blocks an operation."""


def require_interactive_for_weakened_defenses() -> None:
    """Block --accept-weakened-defenses in non-interactive mode.

    CI pipelines must use a model that passes the envelope probe.
    There is no override — this is a hard gate.
    """
    if not is_interactive():
        raise NonInteractiveError(
            "--accept-weakened-defenses is not allowed in non-interactive mode. "
            "CI/CD pipelines must use a model that passes the defense envelope "
            "probe. Configure a supported model (Claude, GPT, Gemini) or remove "
            "the flag."
        )


def require_interactive_for_agentic_pass(pass_name: str) -> None:
    """Block agentic passes with Write/Bash in non-interactive mode.

    These passes grant Write+Bash tools to an agent processing untrusted
    target code (Rule of Two: A=untrusted input + B=sensitive access).
    In interactive mode, Claude Code's permission prompt gates each action.
    In CI/CD, there is no permission prompt.

    Args:
        pass_name: "understand" or "validate" — for the error message.
    """
    if not is_interactive():
        raise NonInteractiveError(
            f"--{pass_name} agentic pass is not allowed in non-interactive mode. "
            f"The {pass_name} pass grants Write and Bash tools to an agent "
            f"processing untrusted target code. In an interactive session, "
            f"Claude Code's permission prompt gates each action. In CI/CD, "
            f"there is no such gate (Rule of Two: untrusted input + write "
            f"access requires human-in-the-loop)."
        )
