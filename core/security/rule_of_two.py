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
    # RAPTOR's own verdict marker: get_safe_env() sets RAPTOR_CI=1 in
    # child envs whenever the PARENT judged itself in CI, so the gate
    # keeps working in children whose scrubbed env lost the vendor
    # markers. Listed first — it is authoritative when present.
    "RAPTOR_CI",
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


# Public aliases for consumers outside this module (core.config's
# env scrubbing keeps the markers allowlisted and re-stamps the
# parent's verdict; keeping one source of truth here prevents the
# lists drifting apart).
def is_ci() -> bool:
    """Public wrapper — see _is_ci."""
    return _is_ci()


def ci_env_vars() -> tuple[str, ...]:
    """The CI marker names, for env-allowlist composition."""
    return _CI_ENV_VARS


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


# Staleness bound on the controlling-terminal probe. A TTY ancestor
# alone would treat a nohup'd or tmux-detached session as
# human-attended INDEFINITELY — the terminal exists but nobody has
# touched it for days. Where the tty device is cheaply statable we
# additionally require recent activity: the device's atime is bumped
# by keystrokes (reads), so "atime within the threshold" ≈ "a human
# typed recently". The default is deliberately generous (24 h — also
# relatime's fallback refresh window) so a long think-pause never
# locks an operator out. Override via the env knob; a value <= 0
# disables the recency requirement (pure presence check, the pre-fix
# behaviour).
_TTY_MAX_AGE_ENV = "RAPTOR_HITL_TTY_MAX_AGE_S"
_TTY_MAX_AGE_DEFAULT_S = 86400.0


def _tty_max_age_s() -> float:
    raw = os.environ.get(_TTY_MAX_AGE_ENV)
    if not raw:
        return _TTY_MAX_AGE_DEFAULT_S
    try:
        return float(raw)
    except ValueError:
        logger.warning(
            "%s=%r is not a number; using default %ss",
            _TTY_MAX_AGE_ENV, raw, _TTY_MAX_AGE_DEFAULT_S,
        )
        return _TTY_MAX_AGE_DEFAULT_S


def _tty_recently_active(pid: int, tty_nr: int, *,
                         _readlink=os.readlink,
                         _stat=os.stat,
                         _now=None) -> bool:
    """Best-effort: was ``pid``'s controlling terminal used recently?

    Resolves the process's std fds via ``/proc/<pid>/fd`` and stats
    the one whose device number matches ``tty_nr`` (i.e. the actual
    controlling terminal, not just any /dev file); its atime is the
    last keystroke. LOUD LIMITATION: this is only *cheaply knowable*
    for same-uid ancestors — a root-owned ancestor (sshd) or a gone
    tty makes the fds unreadable, and we then fall back to counting
    the terminal's mere presence as attended (the pre-fix behaviour)
    rather than failing the whole probe. The recency layer therefore
    tightens the common nohup/detached-tmux case without ever
    breaking a legitimate interactive session.
    """
    max_age = _tty_max_age_s()
    if max_age <= 0:
        return True
    import time
    newest = None
    for fd in (0, 1, 2):
        try:
            path = _readlink(f"/proc/{pid}/fd/{fd}")
        except OSError:
            continue
        if not path.startswith("/dev/"):
            continue
        try:
            st = _stat(path)
        except OSError:
            continue
        if tty_nr and st.st_rdev != tty_nr:
            continue  # some other /dev file, not the controlling tty
        newest = st.st_atime if newest is None else max(newest,
                                                        st.st_atime)
    if newest is None:
        # Activity not cheaply knowable — see the docstring. Presence
        # of the controlling terminal counts, as before.
        return True
    now = _now() if _now is not None else time.time()
    return (now - newest) <= max_age


def _has_terminal_ancestor() -> bool:
    """True if this process or an ancestor holds a RECENTLY ACTIVE
    controlling terminal (Linux).

    Claude Code runs its tool subprocesses with the controlling terminal
    detached — ``stdin.isatty()`` is False and ``/dev/tty`` is ENXIO — so a
    local TTY check can't see the human. But the interactive ``claude``
    process itself keeps its controlling terminal, so walking the parent chain
    finds it. A headless run (cron, systemd, CI, SDK daemon) has no
    controlling terminal anywhere in the chain and returns False.

    Recency: a bare presence check treated nohup'd / tmux-detached
    sessions as human-attended forever. Each terminal-holding ancestor
    is now additionally checked for recent tty activity (atime of the
    controlling device, threshold ``RAPTOR_HITL_TTY_MAX_AGE_S``,
    default 24 h); a stale terminal does not count, but the walk
    continues — an outer, recently-used terminal still satisfies the
    probe. Where activity is not cheaply knowable (root-owned
    ancestor, vanished device), presence alone counts — best-effort
    tightening, never a lock-out. See _tty_recently_active.

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
        if tty_nr != 0 and _tty_recently_active(pid, tty_nr):
            return True
        if ppid == pid:
            break
        pid = ppid
    return False


def _session_has_human_terminal() -> bool:
    """Best-effort 'a human is at a terminal in this session' probe.

    True only when a controlling terminal is present AND no CI env var is set
    (a CI runner that allocated a pseudo-TTY must not count as human-attended,
    matching is_interactive()'s hardening). On Linux the terminal must also
    show recent activity where cheaply knowable — a nohup'd / detached-tmux
    terminal that nobody has touched within RAPTOR_HITL_TTY_MAX_AGE_S
    (default 24 h) no longer counts; see _tty_recently_active for the
    best-effort limits. Fail-closed: any error → False.
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


# Agents whose Rule-of-Two score is 3 (untrusted input + sensitive
# access + external state) with no severable leg — the job itself spans
# all three axes, so containment cannot bring the score under the
# threshold the way it does for the understand/validate sub-agent
# (which has no external-state leg to begin with). Dispatching one of
# these headlessly is therefore never allowed: a human-attended session
# is the only satisfying condition, and the sandbox does NOT substitute.
#
# There is currently no in-repo programmatic dispatcher for these
# agents (they are .claude/agents definitions launched via the Task
# tool from an interactive session, where Claude Code's permission
# prompt is the HITL). This registry + require_human_for_agent_dispatch
# exist so that any FUTURE headless dispatcher must route through the
# gate — an inventory test walks libexec/, core/, and packages/ and
# fails on any reference to these agent names outside the files
# allowlisted as non-dispatch (see
# core/security/tests/test_hitl_dispatch_inventory.py).
HITL_REQUIRED_AGENTS: frozenset[str] = frozenset({
    "offsec-specialist",
})


def require_human_for_agent_dispatch(agent_name: str) -> None:
    """Refuse headless dispatch of a HITL-required agent (Rule of Two).

    Agents in :data:`HITL_REQUIRED_AGENTS` carry all three Rule-of-Two
    legs by construction (A=untrusted input, B=sensitive access,
    C=external state), so unlike the understand/validate agentic pass
    there is no "effective sandbox" escape hatch: filesystem
    containment severs at most the write/exec leg, leaving untrusted
    input + external reach — still over the threshold. The ONLY
    allowed condition is a human-attended session, where the operator
    (and Claude Code's permission prompt) is the loop.

    No-op for agents not in the registry — callers may gate every
    dispatch unconditionally and let the registry decide.

    Args:
        agent_name: the .claude/agents definition name being dispatched.

    Raises:
        NonInteractiveError: HITL-required agent + no human terminal
            anywhere in the session's process ancestry.
    """
    if agent_name not in HITL_REQUIRED_AGENTS:
        return
    if _session_has_human_terminal():
        return
    raise NonInteractiveError(
        f"Agent '{agent_name}' spans all three Rule-of-Two legs "
        f"(untrusted input + sensitive access + external state) and "
        f"requires a human-attended session — this run is non-interactive "
        f"(CI/cron/SDK), and a sandbox does not substitute because the "
        f"agent's job inherently keeps at least two legs even when "
        f"contained (Rule of Two: needs-HITL). Dispatch '{agent_name}' "
        f"from an interactive session."
    )


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
