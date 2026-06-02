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

2. **Agentic passes with Write/Bash**: --understand/--validate dispatch an
   autonomous ``claude -p`` sub-agent with Write+Bash over untrusted target
   code (A + B/C). Rule of Two is satisfied by removing a leg (containment)
   OR by a human in the loop, so this gate allows the pass when EITHER holds:
   a human-attended session, OR an effective sandbox confining the sub-agent.
   It blocks only the one quadrant with neither — a non-interactive run that
   also has no sandbox.

   Note on detecting "human-attended": stdin.isatty() is NOT used here.
   Claude Code detaches the controlling terminal from its tool subprocesses,
   so the local TTY check reports non-interactive even with a human driving
   the session. Instead we walk the process tree for an ancestor that still
   holds a controlling terminal (the interactive ``claude`` process does);
   headless contexts (CI/cron/SDK) have none. See _has_terminal_ancestor().
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


def _proc_tty_and_ppid(pid: int):
    """Return ``(tty_nr, ppid)`` for a Linux pid from ``/proc/<pid>/stat``.

    ``None`` on any read/parse error. The comm field (stat field 2) is wrapped
    in parens and may itself contain spaces or ``)``; split on the LAST ``)``
    so the numeric fields after it parse regardless of the process name.
    """
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8", errors="replace") as fh:
            data = fh.read()
        rp = data.rindex(")")
        fields = data[rp + 2:].split()
        ppid = int(fields[1])    # overall stat field 4 — parent pid
        tty_nr = int(fields[4])  # overall stat field 7 — controlling tty (0 = none)
        return tty_nr, ppid
    except (OSError, ValueError, IndexError):
        return None


def _has_terminal_ancestor() -> bool:
    """True if this process or any ancestor holds a controlling terminal (Linux).

    Claude Code runs its tool subprocesses with the controlling terminal
    detached — ``stdin.isatty()`` is False and ``/dev/tty`` is ENXIO — so a
    local TTY check can't see the human. But the interactive ``claude``
    process itself keeps its controlling terminal, so walking the parent chain
    finds it. A headless run (cron, systemd, CI, SDK daemon) has no
    controlling terminal anywhere in the chain and returns False.

    Linux-only (reads ``/proc``); other platforms rely on the caller's
    stdin-TTY fallback. Bounded hop count + visited-set guard against a
    pathological/looping process table.
    """
    pid = os.getpid()
    seen: set[int] = set()
    hops = 0
    while pid and pid not in seen and hops < 256:
        seen.add(pid)
        hops += 1
        res = _proc_tty_and_ppid(pid)
        if res is None:
            break
        tty_nr, ppid = res
        if tty_nr != 0:
            return True
        if ppid == pid:
            break
        pid = ppid
    return False


def _session_has_human_terminal() -> bool:
    """Best-effort 'a human is at a terminal in this session' probe.

    True only when a controlling terminal is present AND no CI env var is set
    (a CI runner that allocated a pseudo-TTY must not count as human-attended,
    matching is_interactive()'s hardening). Fail-closed: any error → False.
    """
    if _is_ci():
        return False
    try:
        if sys.platform.startswith("linux") and _has_terminal_ancestor():
            return True
        # Non-Linux, or /proc walk found nothing: fall back to the local TTY
        # check (covers a human running RAPTOR directly in a terminal).
        return bool(hasattr(sys.stdin, "isatty") and sys.stdin.isatty())
    except Exception:  # noqa: BLE001 — detection must never crash the gate
        return False


def _sandbox_will_contain() -> bool:
    """True if the untrusted-dispatch sandbox will actually confine the sub-agent.

    The understand/validate sub-agent runs under ``run_untrusted_networked``,
    whose threat is a prompt-injected agent writing/exec-ing outside its run
    dir. "Contained" therefore means **filesystem confinement is in force**,
    which requires all of:

      1. the operator hasn't disabled the sandbox (--no-sandbox), AND
      2. the *effective profile* actually engages filesystem confinement —
         i.e. ``use_landlock`` is set for that profile. ``none`` and
         ``network-only`` both have ``use_landlock=False`` (network-only
         restricts egress but leaves the filesystem open), so neither
         counts, AND
      3. the platform can enforce it — Landlock on Linux, Seatbelt on macOS.

    Fail-closed: any uncertainty (unknown profile, import error, capability
    probe failure) returns False, so the pass falls back to requiring a human
    terminal rather than running unconfined. Checking the profile's declared
    intent — not just kernel capability — closes the network-only fail-open
    where Landlock is available but the chosen profile doesn't use it.
    """
    try:
        from core.sandbox import state
        from core.sandbox.profiles import DEFAULT_PROFILE, PROFILES

        if bool(getattr(state, "_cli_sandbox_disabled", False)):
            return False
        profile_name = getattr(state, "_cli_sandbox_profile", None) or DEFAULT_PROFILE
        profile = PROFILES.get(profile_name)
        # Unknown profile or one that doesn't engage filesystem confinement
        # (none, network-only) → not contained for this purpose.
        if not profile or not profile.get("use_landlock"):
            return False

        from core.sandbox.context import (
            check_landlock_available,
            check_seatbelt_available,
        )
        if sys.platform == "darwin":
            return bool(check_seatbelt_available())
        return bool(check_landlock_available())
    except Exception:  # noqa: BLE001
        return False


def require_human_or_sandbox_for_agentic_pass(pass_name: str) -> None:
    """Gate the understand/validate agentic pass (Rule of Two).

    The pass dispatches an autonomous ``claude -p`` sub-agent with Write+Bash
    over untrusted target code (A=untrusted input + B/C=write/exec). Rule of
    Two is satisfied by removing a leg (containment) OR by a human in the loop,
    so the pass is allowed when EITHER holds:

      * **human-attended session** — the operator asked for this at a terminal
        (detected by walking the process tree for a controlling terminal,
        since Claude Code detaches the TTY from tool subprocesses), OR
      * **effective sandbox** — run_untrusted_networked confines the
        sub-agent's writes to target + run dir, proxies network, and applies
        Landlock/seccomp.

    Blocks ONLY when NEITHER holds: a non-interactive run (CI/cron/SDK) that
    also disabled the sandbox or runs where it can't be enforced. That single
    quadrant — untrusted input + write/exec with no human and no containment —
    is the genuine Rule-of-Two danger zone::

                     | sandbox effective | sandbox off / unavailable
        -------------+-------------------+--------------------------
        interactive  |      allow        |        allow
        non-interact |      allow        |        BLOCK

    Args:
        pass_name: "understand" or "validate" — for the error message.
    """
    if _sandbox_will_contain() or _session_has_human_terminal():
        return
    raise NonInteractiveError(
        f"--{pass_name} dispatches an autonomous agent with Write and Bash "
        f"over untrusted target code, which requires either a human-attended "
        f"session or an effective sandbox — this run has neither: it is "
        f"non-interactive AND the sandbox is disabled or unavailable "
        f"(Rule of Two: untrusted input + write access). Re-run with the "
        f"sandbox enabled, or from an interactive session, to use "
        f"--{pass_name}."
    )
