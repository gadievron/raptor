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
import os
import sys

logger = logging.getLogger("raptor.security")


# Well-known CI environment variables. Presence of any of these (with
# a non-empty / non-"false" value) indicates a CI/CD runner is in
# control regardless of TTY allocation. Some CI providers allocate a
# pseudo-TTY (`docker run -t`, GitHub Actions with `tty: true`,
# Jenkins ssh agent), so `isatty()` alone is insufficient — a TTY-on-
# CI passed the gate, defeating the rule-of-two intent.
#
# Coverage: the broad `CI` flag (used by GitHub Actions, GitLab,
# CircleCI, Travis, Drone, Buildkite, Cirrus, Woodpecker), plus
# vendor-specific names that tooling sometimes sets without `CI`
# (notably Jenkins, TeamCity, Bamboo, Azure Pipelines).
_CI_ENV_VARS: tuple[str, ...] = (
    "CI",
    "CONTINUOUS_INTEGRATION",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "CIRCLECI",
    "TRAVIS",
    "JENKINS_URL",
    "JENKINS_HOME",
    "TEAMCITY_VERSION",
    "TF_BUILD",         # Azure Pipelines
    "BUILDKITE",
    "DRONE",
    "BAMBOO_BUILDKEY",
    "CODEBUILD_BUILD_ID",  # AWS CodeBuild
    "CIRRUS_CI",
    "WOODPECKER",
)


def _is_ci() -> bool:
    """True if a well-known CI env var is present and not falsy.

    "Falsy" treats `"0"`, `"false"`, `"no"`, `"off"` (case-insensitive)
    as not-set so a runner explicitly disabling the flag (uncommon
    but legal) doesn't false-positive. Empty string also treated as
    not-set so `CI=` is benign.
    """
    falsy = {"", "0", "false", "no", "off"}
    for name in _CI_ENV_VARS:
        val = os.environ.get(name)
        if val is None:
            continue
        if val.strip().lower() in falsy:
            continue
        return True
    return False


def is_interactive() -> bool:
    """True if a human is at the keyboard.

    Two conditions both required:
      * stdin is a TTY (rules out pipes, redirects, daemonised runs).
      * No well-known CI env var indicates a CI/CD runner is in
        control. Some CI providers allocate a pseudo-TTY (Docker -t,
        GitHub Actions tty: true), so the TTY check alone false-
        positives there. Pre-fix, a CI run with TTY allocation passed
        the rule-of-two gate and silently bypassed the
        `--accept-weakened-defenses` and agentic-pass blocks.
    """
    has_tty = hasattr(sys.stdin, "isatty") and sys.stdin.isatty()
    return has_tty and not _is_ci()


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
