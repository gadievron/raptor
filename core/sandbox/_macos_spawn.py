"""macOS sandbox-exec wrapper.

This module mirrors core.sandbox._spawn.run_sandboxed() — same kwarg
contract, same return shape (subprocess.CompletedProcess with
.sandbox_info attached) — so context.py can dispatch to the
appropriate backend (Linux vs Darwin) at the spawn-eligibility check
without callers caring about platform.

Feature parity table (Linux ⇄ macOS):

    Linux layer                       → macOS equivalent
    ─────────────────────────────────  ────────────────────────────────
    Landlock writable_paths            → SBPL (deny file-write*
                                        (require-not (subpath ...)))
    Landlock readable_paths            → SBPL (deny file-read*
                                        (require-not ...)) under
                                        restrict_reads=True
    Landlock TCP allowlist             → SBPL (allow network-outbound
                                        (remote tcp "*:PORT"))
    user-ns network block              → SBPL (deny network*)
    user-ns PID isolation              → ⚠  no equivalent — host PIDs
                                        remain visible inside sandbox
    user-ns IPC isolation              → partial: SBPL (deny mach-
                                        lookup ...) for specific
                                        services (not blanket)
    mount-ns + pivot_root              → ⚠  no equivalent — sandbox
                                        sees host filesystem (reads
                                        unrestricted unless restrict_
                                        reads=True)
    seccomp filter                     → partial: SBPL (deny process-
                                        info* (target others)) when
                                        seccomp_profile is set
    rlimits via prlimit + preexec      → preexec rlimits (same code
                                        path); ⚠  RLIMIT_NPROC is
                                        per-UID host-wide on macOS,
                                        not per-namespace — applied
                                        as current-count + budget
                                        (the Linux no-namespace
                                        lane's relative ceiling),
                                        never as an absolute cap
    ptrace tracer (audit_mode)         → `log stream` reader (see
                                        seatbelt_audit.LogStreamer)
    fake_home env override             → identical (env mutation)
    egress proxy + HTTPS_PROXY env     → identical (env mutation +
                                        SBPL allow for proxy_port)
    pid-1 shim (signal forwarding)     → ⚠  not needed (no PID-ns)
    audit_verbose strace-style         → partial: SBPL `(allow X
                                        (with report))` for an
                                        extended category set
                                        (file-read-data, mach-lookup,
                                        process-exec*, process-fork,
                                        signal, plus budget-tracked
                                        file-read-metadata,
                                        process-info*, iokit-open,
                                        sysctl-read — full list in
                                        run_sandboxed's docstring).
                                        Coarser than Linux's
                                        per-syscall trace and no argv,
                                        but operationally similar
                                        signal-volume control. See
                                        seatbelt.build_profile.
    map_root (--map-root-user)         → ⚠  no equivalent — sandboxed
                                        process keeps caller UID

Implications of the ⚠ items for the threat model:

  1. PID visibility: a sandboxed child that compromises a same-UID
     process can still see / signal it. Linux's PID-ns hides this.
     Mitigation: don't run RAPTOR alongside other valuable same-UID
     processes; consider a dedicated user account for RAPTOR on
     shared macOS hosts.
  2. Filesystem read scope: under default kwargs the sandboxed
     child can read everything the calling user can. Always pass
     restrict_reads=True for untrusted code (run_untrusted does this
     by default).
  3. RLIMIT_NPROC: the cap counts the calling user's TOTAL
     simultaneous processes, so the configured budget is applied as
     a ceiling RELATIVE to current usage (count + budget, clamped to
     the hard limit and to the kernel's silent kern.maxprocperuid
     bound, which macOS imposes on setrlimit regardless of what is
     requested) — a fork bomb is bounded to the budget's
     headroom, while pre-existing same-UID processes (browser
     sessions, sibling runs) no longer push every in-sandbox fork
     into EAGAIN. Growth beyond the ceiling still lands on the
     shared per-UID table; keep budgets modest on shared hosts.
  4. audit_verbose granularity: macOS records are SBPL-action-level
     (e.g. "file-read-data /etc/foo") rather than syscall+argv
     level. Linux's tracer can show "openat(/etc/foo, O_RDONLY)";
     macOS can't distinguish reads-of-foo from stats-of-foo. For
     debugging targets that need argv-level fidelity, use Linux.

What's identical and needs no special handling:

  * Resource limits via POSIX setrlimit (preexec_fn pattern).
  * fake_home env override (mirrors Linux's per-XDG-subdir layout
    in core/sandbox/context.py — HOME, XDG_CONFIG_HOME,
    XDG_CACHE_HOME, XDG_DATA_HOME, XDG_STATE_HOME each point at a
    distinct subdir of {output}/.home/ so configs don't collide
    with caches).
  * Egress proxy + audit-degraded marker semantics (handled at the
    context.py layer, identical to Linux).
  * Sandbox-summary JSONL aggregation (same schema, same writer).
  * Audit budget: same core.sandbox.audit_budget.AuditBudget on
    both backends — token-bucket + per-category + per-PID +
    1-in-N sampling + --audit-budget CLI override.
"""

from __future__ import annotations

import logging
import os
import re
import signal
import stat
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path

from . import seatbelt
from ._fork_safe_warn import warn_post_fork
from .preexec import _make_preexec_fn

logger = logging.getLogger(__name__)


SANDBOX_EXEC = "/usr/bin/sandbox-exec"

# The macOS seatbelt shim (libexec/raptor-seatbelt-shim). Interposed around
# sandbox-exec to give the macOS backend the two guarantees the Linux backend
# already has: fail-loud setup detection (an unspoofable in-sandbox readiness
# byte) and orphan teardown (a death-pipe watcher that SIGKILLs the sandbox
# process group when the orchestrator is hard-killed — macOS has no pid-ns
# kernel cascade). See that file's docstring for the full design.
SEATBELT_SHIM = str(
    Path(__file__).resolve().parents[2] / "libexec" / "raptor-seatbelt-shim"
)

# Status-pipe byte vocabulary. Each writer emits one small (atomic)
# write; the parent reads the pipe to EOF after the shim exits and
# parses the accumulated bytes order-independently:
#   b"K"        in-sandbox /bin/sh trampoline — the profile applied and
#               the trampoline ran INSIDE it (must match the `printf K`
#               in run_sandboxed's trampoline). Absence => profile did
#               not apply (fail loud).
#   b"P"        watcher shim — a granted path's identity pin (dev/ino)
#               stopped matching mid-run; the shim SIGKILLed the
#               sandbox tree. Outranks K: the run is tainted even
#               though setup succeeded.
#   b"G<pid>\n" watcher shim — the sandbox process-group leader's pid,
#               reported so the parent's backstop sweep can attribute
#               group members even after the shim itself is gone.
_READY_BYTE = b"K"
_PIN_TAMPER_BYTE = b"P"


def _parse_group_report(data: bytes) -> int | None:
    """Sandbox process-group leader pid from the status-channel bytes
    (the watcher's ``G<pid>\\n`` report), or None when absent."""
    m = re.search(rb"G(\d{1,9})\n", data)
    return int(m.group(1)) if m else None


def is_available() -> bool:
    """True iff /usr/bin/sandbox-exec exists. Caller (context.py) is
    expected to have already checked check_seatbelt_available() for
    the deeper smoke-test gate; this is the cheap presence check."""
    return os.path.exists(SANDBOX_EXEC)


# ---- post-wait descendant sweep ----------------------------------------
#
# macOS teardown is process-group based (death-pipe → sandbox pgrp
# SIGKILL in the shim; killpg of the shim session as backstop) and the
# groups only cover processes that stayed IN them. The allow-default
# seatbelt profile does not deny setsid, so a fork+setsid descendant
# leaves both kill groups — and macOS has no pid-namespace cascade to
# catch it. The sweep below walks the process table (macOS has no
# /proc; `ps -axo pid,ppid,pgid` is the portable enumeration) from the
# shim pid, collects descendants transitively via the ppid chain (a
# setsid call changes pgid/session, NOT ppid — the walk still finds the
# escapee while its ancestors are alive), and SIGKILLs them. Applied on
# every exit path: normal completion, timeout, and exception/abort.
#
# Known blind spot, by construction: once a descendant's intermediate
# ancestors have exited, it reparents to launchd (ppid 1) and a fresh
# snapshot can no longer attribute it — from that point it is
# indistinguishable from an unrelated process. Callers therefore pass a
# snapshot captured while the tree was still alive (the timeout path
# snapshots BEFORE killing; the shim accumulates a cumulative lineage
# ledger across its periodic snapshots — pids AND the process groups
# attributed descendants lead after a setsid); a descendant that
# forked, setsid'd, and was orphaned entirely within one snapshot
# interval escapes attribution (documented residual — it stays inside
# the inherited seatbelt profile, so confinement holds; the leak is
# persistence, not escape). The mirrored sweep in
# libexec/raptor-seatbelt-shim (keep the logic in sync — the shim runs
# `python -I` with no repo on sys.path and cannot import this module)
# owns the normal-completion path, where it can still see the live
# tree; this parent's sweeps are the backstop for a shim that died
# without sweeping, attributing through the shim's G sandbox-group
# report on the status pipe. launchd-submitted jobs sit outside every
# ppid/pgid universe (children of launchd); the hardened profiles'
# mach-lookup allowlist-deny closes that submission vector instead.

# Absolute paths ONLY (macOS pins ps at /bin/ps). No bare-name
# PATH fallback: these helpers run in the UNSANDBOXED parent, and a
# PATH-planted stub would execute with the operator's ambient
# authority — the exact shape the sandbox binary-resolution doctrine
# names (the Linux arm hard-fails the same way). A macOS install
# without /bin/ps is broken beyond this helper's remit; the callers
# degrade best-effort on None.
_PS_CANDIDATES = ("/bin/ps", "/usr/bin/ps")
_PS_ARGS = ["-axo", "pid=,ppid=,pgid="]
_SWEEP_MAX_PASSES = 3
_PS_TIMEOUT_S = 10



def _safe_probe_env() -> dict:
    """Scrubbed allowlist env for the parent-side ps/sysctl probes —
    binaries are invoked by absolute path, but env steering
    (DYLD_INSERT_LIBRARIES-class variables) reaches even a pinned
    binary; the doctrine the Linux probe helpers already follow."""
    from core.config import RaptorConfig
    return RaptorConfig.get_safe_env()


def _parse_ps_table(text: str) -> list:
    """Parse `ps -axo pid=,ppid=,pgid=` output into (pid, ppid, pgid)
    int tuples. Unparseable lines are skipped (ps localisation noise,
    truncated reads) — the sweep is best-effort."""
    table = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            table.append((int(parts[0]), int(parts[1]), int(parts[2])))
        except ValueError:
            continue
    return table


def collect_descendants(table, root_pid, extra_pgids=(), protect=()):
    """Pure kill-list derivation: (pid, ppid, pgid) table in → pid set out.

    Collects, transitively, every process reachable from ``root_pid``
    via the ppid chain (a setsid escapee changed its pgid, not its
    ppid, so it is still collected while its ancestors live), plus
    every member of ``extra_pgids`` (process groups known to belong to
    the sandbox — catches group members whose ppid chain already
    broke) and THEIR ppid-descendants. ``root_pid`` itself, pids <= 1,
    and anything in ``protect`` are never returned; processes with no
    ancestry path to the root and no membership in ``extra_pgids`` are
    never returned, however suspicious they look. Bounded: each pid is
    visited at most once, so a cyclic/garbage table cannot hang the
    walk.

    Blind spot (see module comment above): a descendant already
    reparented to pid 1 in THIS table is unreachable from the root —
    bridging that needs a snapshot taken while the tree was alive,
    which _sweep_descendants handles.
    """
    kids = {}
    pgid_members = {}
    for pid, ppid, pgid in table:
        kids.setdefault(ppid, []).append(pid)
        pgid_members.setdefault(pgid, []).append(pid)
    out = set()
    visited = {root_pid}
    stack = [root_pid]
    for pg in extra_pgids:
        for pid in pgid_members.get(pg, ()):
            if pid not in visited:
                visited.add(pid)
                out.add(pid)
                stack.append(pid)
    while stack:
        cur = stack.pop()
        for child in kids.get(cur, ()):
            if child in visited:
                continue
            visited.add(child)
            out.add(child)
            stack.append(child)
    banned = set(protect)
    banned.add(root_pid)
    return {p for p in out if p > 1 and p not in banned}


def _ps_snapshot():
    """(pid, ppid, pgid) table from ps, or None when unavailable.
    Best-effort by design — a missing/hung ps must not break the run
    result path."""
    for ps in _PS_CANDIDATES:
        try:
            proc = subprocess.run(
                [ps, *_PS_ARGS], capture_output=True, text=True,
                timeout=_PS_TIMEOUT_S, check=False,
                env=_safe_probe_env(),
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if proc.returncode == 0:
            return _parse_ps_table(proc.stdout)
    return None


def _kill_pid(pid: int) -> None:
    """SIGKILL one pid, best-effort. Module-level so tests can observe
    the sweep hermetically without patching os.kill globally."""
    try:
        os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def _same_uid_process_count() -> int | None:
    """Current same-UID process count via ps (macOS has no /proc), or
    None when ps is unavailable/broken. RLIMIT_NPROC on macOS counts
    the user's simultaneous PROCESSES (unlike Linux, where the task
    count includes threads — see the Linux lane's thread-aware count
    in context.py), so a plain pid count is the right denominator for
    the count-plus-budget ceiling."""
    uid = str(os.geteuid())
    for ps in _PS_CANDIDATES:
        try:
            proc = subprocess.run(
                [ps, "-xo", "pid=", "-U", uid],
                capture_output=True, text=True,
                timeout=_PS_TIMEOUT_S, check=False,
                env=_safe_probe_env(),
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if proc.returncode == 0:
            count = sum(
                1 for line in proc.stdout.splitlines() if line.strip())
            if count > 0:
                return count
    return None


def _darwin_nproc_kernel_clamp() -> int | None:
    """kern.maxprocperuid on darwin, or None (other platforms /
    unreadable sysctl). macOS setrlimit(RLIMIT_NPROC) silently stores
    at most this value regardless of the requested number and of the
    hard limit (observed live: a requested six-figure ceiling read
    back as the sysctl value from inside the child), so any ceiling
    above it is a number the kernel will never honour — clamp what we
    request so reads, logs, and tests see the enforced truth."""
    if sys.platform != "darwin":
        return None
    # Absolute paths only + scrubbed env — same doctrine as
    # _PS_CANDIDATES above.
    for sysctl in ("/usr/sbin/sysctl", "/sbin/sysctl"):
        try:
            proc = subprocess.run(
                [sysctl, "-n", "kern.maxprocperuid"],
                capture_output=True, text=True,
                timeout=_PS_TIMEOUT_S, check=False,
                env=_safe_probe_env(),
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if proc.returncode == 0:
            try:
                value = int(proc.stdout.strip())
            except ValueError:
                continue
            if value > 0:
                return value
    return None


def _grant_pin_mismatch(path: str, dev: int, ino: int,
                        btime: "float | None" = None) -> str:
    """Reason string when ``path`` no longer carries its pinned
    identity, or "" while the pin holds. One lstat decides all four
    tamper shapes: the path vanished, a symlink now sits at it (lstat
    reports the LINK, so a symlink to the original inode — a
    relocate-and-link-back — is caught too, not just links to foreign
    victims), a different filesystem object was renamed into it
    (dev/ino mismatch), or the birth-time witness stopped matching
    with dev/ino EQUAL — the unlink+recreate signature on a
    filesystem that recycles freed inode numbers, which a dev/ino-only
    pin cannot see. This pin is serialized to the watcher shim (env,
    across an exec), so no held fd can anchor it; the birth time is
    the secondary identity witness. ``btime is None`` means the
    capture host could not observe a birth time (identity-weak pin,
    stamped on the result) — the arm is skipped rather than silently
    treated as matching; a pin CARRYING a birth time that the current
    stat cannot reproduce refuses (fail closed), never downgrades to
    dev+ino-only equivalence. Mirrored inline in
    libexec/raptor-seatbelt-shim (`python -I`, cannot import this
    module) — keep the two in sync."""
    import stat as _stat
    try:
        st = os.lstat(path)
    except OSError:
        return "no longer exists"
    if _stat.S_ISLNK(st.st_mode):
        return "is now a symlink"
    if (int(st.st_dev), int(st.st_ino)) != (int(dev), int(ino)):
        return (f"changed identity (dev/ino "
                f"{st.st_dev}/{st.st_ino} != pinned {dev}/{ino})")
    if btime is not None:
        current_btime = getattr(st, "st_birthtime", None)
        if current_btime != btime:
            return (f"changed identity (birth time "
                    f"{current_btime} != pinned {btime} with dev/ino "
                    f"matching — a recycled inode number)")
    return ""


def _sweep_descendants(root_pid, *, live_snapshot=None, extra_pgids=(),
                       snapshot_fn=None, max_passes=_SWEEP_MAX_PASSES,
                       protect=None):
    """Post-wait sweep: SIGKILL every process still attributable to the
    shim's tree, independent of process group. Best-effort, bounded to
    ``max_passes`` snapshot+kill rounds (later rounds catch children
    forked while the earlier round was killing).

    ``live_snapshot`` is a (pid, ppid, pgid) table captured while the
    tree was still alive: descendants recorded there are still killed
    after they reparent to launchd, provided they still exist AND still
    carry the pgid the snapshot saw (a cheap pid-reuse guard — a
    recycled pid lands in a different process group; a process only
    changes its own pgid via setsid/setpgid, which cannot silently
    recreate the recorded value for an unrelated process in practice).

    ``protect`` overrides the never-kill set (default: the calling
    process and its parent). Callers exercising the sweep against a
    synthetic table pass an explicit set so the verdict cannot depend
    on which live pids the caller happens to run under.

    Returns the set of pids signalled (for logging/tests).
    """
    snapshot_fn = snapshot_fn or _ps_snapshot
    if protect is None:
        protect = {os.getpid(), os.getppid()}
    else:
        protect = set(protect)
    known = {}
    if live_snapshot:
        live_pgids = {pid: pgid for pid, _ppid, pgid in live_snapshot}
        for pid in collect_descendants(
                live_snapshot, root_pid,
                extra_pgids=extra_pgids, protect=protect):
            known[pid] = live_pgids.get(pid)
    swept = set()
    for _ in range(max_passes):
        table = snapshot_fn()
        if not table:
            break
        current_pgid = {pid: pgid for pid, _ppid, pgid in table}
        targets = collect_descendants(
            table, root_pid, extra_pgids=extra_pgids, protect=protect)
        for pid, seen_pgid in known.items():
            if (pid not in targets and pid in current_pgid
                    and current_pgid[pid] == seen_pgid):
                targets.add(pid)
        targets = {p for p in targets if p > 1 and p not in protect
                   and p != root_pid}
        if not targets:
            break
        for pid in sorted(targets):
            _kill_pid(pid)
        for pid in targets:
            known.setdefault(pid, current_pgid.get(pid))
        swept |= targets
    if swept:
        logger.warning(
            "macOS sandbox teardown: post-wait sweep SIGKILLed %d "
            "orphaned descendant process(es): %s",
            len(swept), sorted(swept),
        )
    return swept


def _refuse_hijacked_scratch_dir(paths: Iterable[str]) -> None:
    """Refuse per-call scratch materialisation over a replaced path.

    A sandboxed child holds write access to ``output``; with one
    sandbox() context issuing multiple run() calls, a child from run N
    can delete ``{output}/.home`` or ``{output}/.tmp`` (empty after
    initial creation) and swap in a symlink pointing at a
    user-writable location outside ``output``. The parent-side
    symlink-following ``os.makedirs`` would then create directories at
    the attacker-chosen destination — the bounded write-outside-
    sandbox escape the Linux fake-home guard
    (context.py, sandbox() construction) exists to close. That guard
    runs ONCE at construction; this backend (re)creates the scratch
    dirs on EVERY call, so the same lstat refusal must run per call.
    Anything that exists but is not a regular directory — a symlink,
    a FIFO (parent-side chmod/stat hang), a socket, a device node —
    refuses loudly instead of proceeding.
    """
    for _p in paths:
        try:
            _st = os.lstat(_p)
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(_st.st_mode) or stat.S_ISLNK(_st.st_mode):
            msg = (
                f"sandbox scratch path refuses to materialise: {_p!r} "
                f"exists but is not a regular directory "
                f"(mode=0o{_st.st_mode:o}). A prior sandboxed process "
                f"may have replaced it to redirect parent-side file "
                f"operations or cause a hang. Clean the output dir or "
                f"use a fresh one."
            )
            raise ValueError(msg)


def run_sandboxed(cmd: list[str], *,
                  target: str | None = None,
                  output: str | None = None,
                  block_network: bool = False,
                  nproc_limit: int | None = None,
                  limits: dict | None = None,
                  writable_paths: Iterable[str] | None = None,
                  readable_paths: Iterable[str] | None = None,
                  allowed_tcp_ports: Iterable[int] | None = None,
                  # seccomp_profile: macOS has no direct equivalent
                  # to Linux's libseccomp filter, but we use the
                  # profile NAME as a coarse "harden" signal — when
                  # set to anything non-None and not "none", SBPL adds
                  # a small set of process-info denies (see
                  # seatbelt.build_profile's docstring). Accepted as
                  # Linux-named kwarg for signature parity.
                  # seccomp_block_udp: Linux-only (no UDP-specific
                  # SBPL primitive). Use block_network=True for the
                  # macOS equivalent of "no UDP egress".
                  seccomp_profile: str | None = None,
                  # sandbox_profile: the PROFILE NAME ("full"/"strict"/
                  # "debug"/...). seccomp_profile alone cannot
                  # distinguish strict from full (both map to "full");
                  # seatbelt layers the probe-validated macos-strict
                  # extras only for the strict name.
                  sandbox_profile: str | None = None,
                  seccomp_block_udp: bool = False,
                  # map_root: Linux-only (`unshare --map-root-user`
                  # remaps caller UID to 0 inside the user-ns). macOS
                  # sandbox-exec keeps caller UID; there's no
                  # unprivileged way to remap. Accepted for signature
                  # parity, ignored.
                  map_root: bool = False,
                  env: dict | None = None,
                  cwd: str | None = None,
                  timeout: float | None = None,
                  # Defaults match core/sandbox/_spawn.run_sandboxed
                  # so callers reaching either entry point with the
                  # same arg list get the same result. (Earlier
                  # signatures defaulted these to False, diverging
                  # from Linux; in practice context.py always passes
                  # the value explicitly so the mismatch was
                  # invisible — but the signature now lies less.)
                  capture_output: bool = True,
                  text: bool = True,
                  # max_capture_bytes: accepted for signature parity
                  # with Linux _spawn, which clamps its pipe drain to
                  # it. This backend wraps subprocess.run (full
                  # buffering); the caller-facing bound is applied by
                  # context.py's dispatch-chokepoint result clamp, so
                  # the value is not consulted here.
                  max_capture_bytes: int | None = None,
                  stdin=None,
                  # stdout=/stderr= redirects, honoured only when not
                  # capturing (subprocess plumbs them natively here) —
                  # signature parity with Linux _spawn, which needs
                  # them for run_untrusted's write-only tty reopen.
                  stdout=None,
                  stderr=None,
                  # Unlike Linux _spawn's os.fork() chain, this backend
                  # wraps subprocess.run, which plumbs both of these
                  # natively — the shim chain preserves inherited
                  # non-CLOEXEC fds across its execs, and input= is
                  # handled by subprocess's own communicate machinery.
                  # Caller fds are unioned with the shim's status/death
                  # pipe fds at the run call.
                  pass_fds: Iterable[int] | None = None,
                  input: bytes | str | None = None,  # noqa: A002 — subprocess parity
                  audit_mode: bool = False,
                  audit_run_dir: str | None = None,
                  audit_required: bool = False,
                  audit_verbose: bool = False,
                  observe_mode: bool = False,
                  observe_nonce: str | None = None,
                  restrict_reads: bool = False,
                  start_new_session: bool = True,
                  use_egress_proxy: bool = False,
                  proxy_port: int | None = None,
                  fake_home: bool = False,
                  exclude_tmp_baseline: bool = False,
                  strict_env: bool = False,
                  # keep_trust_markers: mirror of the Linux pid1-shim
                  # argv flag (context injects --keep-trust-markers on
                  # that lane). The keep decision travels OUT-OF-BAND
                  # as watcher-shim argv, mintable only by this spawn
                  # layer — an env key would be smuggleable through any
                  # caller-supplied env dict. Passed by the context
                  # dispatch off keep_trust_markers_for_dispatch (the
                  # run_untrusted_networked(keep_trust_markers=True)
                  # skill-dispatch lane); without it the seatbelt shim
                  # applied the FULL strip tuple and RAPTOR's own
                  # dispatched children lost the trust markers and
                  # session credential they need to drive libexec
                  # helpers.
                  keep_trust_markers: bool = False,
                  # persona: host-fingerprint sanitisation is Linux-only
                  # (bind-mount + UTS-ns + sched_setaffinity primitives).
                  # macOS lacks unprivileged equivalents; most host-
                  # identity reads there are sysctlbyname/IOKit-based,
                  # not file-based, so file substitution wouldn't catch
                  # them anyway. Accepted for signature parity and
                  # silently ignored — context.py already gates on
                  # fingerprint.is_supported() so the value reaches us
                  # only as None when sanitisation was requested but
                  # platform unsupported.
                  persona=None,
                  # inherit_netns: Linux-only — used by _spawn to skip
                  # CLONE_NEWNET when target/exploit are forked from the
                  # coordinator already inside the shared netns. macOS
                  # has no network namespaces; accepted + ignored for
                  # signature parity with _spawn.run_sandboxed.
                  inherit_netns=False,
                  # etc_overlay: Linux-only — uses mount-ns + bind-mounts
                  # to overlay per-Problem files at /etc/<...> inside
                  # the sandbox. macOS sandbox-exec has no equivalent
                  # mount primitive; accepted + ignored for signature
                  # parity with _spawn.run_sandboxed.
                  etc_overlay=None,
                  # skip_pid_ns: Linux-only — opts out of the nested
                  # CLONE_NEWPID so gdb's host-info probe can read
                  # /proc/1/* without the systemd-init permission gap
                  # described in _spawn.run_sandboxed. macOS sandbox-
                  # exec has no pid-namespace concept (host PIDs are
                  # always visible inside the SBPL sandbox), so this
                  # kwarg is accepted + ignored for signature parity.
                  skip_pid_ns=False,
                  # skip_mount_ns: Linux-only — skips mount-ns pivot_root
                  # so the host filesystem stays visible (used by frida
                  # profile). macOS sandbox-exec doesn't use mount-ns;
                  # accepted + ignored for signature parity.
                  skip_mount_ns=False,
                  # require_fresh_procfs: Linux-only — makes the
                  # pid-ns-local /proc mount mandatory (abort instead
                  # of host-procfs degrade). macOS has no procfs;
                  # Seatbelt provides the process-info contract.
                  require_fresh_procfs=False,
                  # landlock_required: Linux-only floor plumbing (the
                  # Landlock-absent tolerance mode). macOS has no
                  # Landlock layer at all; accepted + ignored for
                  # signature parity.
                  landlock_required=True,
                  # rootfs: Linux-only — mount-ns pivot into an unpacked
                  # container-image tree. Accepted for signature parity
                  # but NOT ignored like the kwargs above: those are
                  # protection extras whose absence weakens nothing the
                  # SBPL profile promised, whereas rootfs names the
                  # execution SUBSTRATE — ignoring it would run the
                  # command against the HOST filesystem. context.py's
                  # fail-closed gate raises before dispatch ever reaches
                  # darwin; the body-level raise is defence in depth.
                  rootfs: str | None = None,
                  # proxy_unix_socket / proxy_forwarder_port: Linux-only
                  # — used by _spawn to fork a TCP-to-Unix relay inside
                  # the child's empty netns for proxy enforcement on
                  # kernels with Landlock ABI < 4. macOS uses sandbox-
                  # exec network rules instead; accepted + ignored for
                  # signature parity.
                  proxy_unix_socket=None,
                  proxy_forwarder_port=None,
                  # extra_unix_bridges: Linux-only — additional
                  # (port, unix_path) relays inside the child's netns
                  # (LLM-dispatcher bridge for credential-proxy CLI
                  # children). No netns on macOS; accepted + ignored
                  # for signature parity. context.py only passes it on
                  # the netns tier, which never engages on darwin.
                  extra_unix_bridges=None,
                  # exec_pid_callback: Linux-only — the fork-based spawn
                  # backend delivers the live grandchild pid to this
                  # callable mid-run (used for /proc/<pid>/maps
                  # sampling). The SBPL backend wraps a blocking
                  # subprocess.run, so there is no live-pid window (and
                  # no /proc on macOS anyway); accepted + ignored for
                  # signature parity. Callers gate on
                  # context.spawn_backend_available(), which is False
                  # on darwin.
                  exec_pid_callback=None,
                  # child_pid_callback: Linux-only — used by context.py
                  # to register the spawn child's process tree with the
                  # egress proxy's unix-lane peer-credential gate. macOS
                  # has no unix lanes (netns tier never engages on
                  # darwin); accepted + ignored for signature parity.
                  child_pid_callback=None,
                  ) -> subprocess.CompletedProcess:
    """Run ``cmd`` under macOS sandbox-exec with an SBPL profile
    derived from the logical sandbox kwargs.

    Same return shape as the Linux ``_spawn.run_sandboxed()``; same
    contract for ``audit_mode`` / ``audit_run_dir`` (caller writes
    .sandbox-denials.jsonl into audit_run_dir; we route the kernel
    sandbox log into that file via seatbelt_audit's log streamer).

    observe_mode: when True (with audit_mode=True), the seatbelt
    log streamer routes records to ``.sandbox-observe.jsonl``
    (instead of ``.sandbox-denials.jsonl``) and stamps each record
    with ``"observe": True`` (instead of ``"audit": True``). Mirror
    of the Linux tracer behaviour — profile-extraction probes
    (sandbox(observe=True)) get a separate JSONL file the
    denial-summary aggregator does not consume. On macOS, observe
    signal comes from the same SBPL ``(allow X (with report))``
    rules as audit_verbose; observe_mode therefore implies
    audit_verbose at the SBPL layer (engaged by the upstream
    sandbox() context).

    audit_verbose: when True (with audit_mode=True), engages the
    extended SBPL audit category set in seatbelt.build_profile.
    Each of the following is emitted as `(allow X (with report))`:
      * file-read-data
      * file-read-metadata
      * mach-lookup
      * process-exec*
      * process-fork
      * process-info*
      * signal
      * iokit-open
      * sysctl-read
    Closest macOS analogue to Linux's strace-style audit. Less
    fidelity than Linux (no per-syscall, no argv) — see
    seatbelt.build_profile docstring for the rationale on which
    categories are included. High-volume categories
    (file-read-metadata, process-info*, iokit-open, sysctl-read)
    are bounded by core.sandbox.audit_budget.AuditBudget's per-
    category caps + 1-in-N sampling so the JSONL doesn't bloat.
    """
    if rootfs is not None:
        from .errors import SandboxSetupError
        msg = (
            "sandbox(rootfs=...) requires the Linux mount-namespace "
            "backend; macOS sandbox-exec cannot pivot into an image "
            "rootfs — refusing to run against the host filesystem."
        )
        raise SandboxSetupError(
            msg,
            "run image-rootfs sandboxes on a Linux host.",
        )
    # 0. Validate audit-mode + audit_run_dir invariant. Mirrors
    # core/sandbox/_spawn.py for parity — caller asking for audit
    # without giving the tracer a place to write JSONL is almost
    # certainly a mistake (the streamer would no-op silently and
    # operators would see no audit signal). Raise loudly so they
    # see the typo at spawn time.
    if audit_mode and not audit_run_dir:
        msg = (
            "audit_mode=True requires audit_run_dir= so the macOS "
            "log-stream reader has a directory to write "
            ".sandbox-denials.jsonl into. Pass audit_run_dir=<dir> "
            "(typically the run's output dir)."
        )
        raise ValueError(msg)

    # 0b. Evidence directory (F11): pre-create <run_dir>/.audit 0700
    # so the profile can deny the target all writes beneath it and the
    # log streamer's evidence file lands in a target-unwritable spot.
    _evidence_dir: str | None = None
    if audit_mode and audit_run_dir:
        from . import evidence as _evidence_mod
        _evidence_dir = str(_evidence_mod.ensure_audit_dir(audit_run_dir))

    # 0c. Key-exposure posture for triage (summary.record_run_posture):
    # macOS has no mount namespace, so only restrict_reads can hide the
    # telemetry-MAC key from the child; without it a read-unrestricted
    # target can read the key and mint valid telemetry tokens. Recorded
    # per invocation, weakest-wins across the run. This layer only
    # knows the run directory when audit_run_dir names it — postures of
    # non-audit invocations are attributed at the dispatching layer.
    # Stamp what is ENFORCED, not what was requested: audit mode
    # converts the read deny into (allow file-read* (with report)) —
    # observe, don't block (seatbelt.build_profile) — so a darwin
    # audit run's read wall does not exist and an audited hostile
    # child CAN read the key and mint tokens. Recording the requested
    # value made triage trust token-verified telemetry it must not
    # (Linux differs: its audit tier keeps Landlock enforcing, so the
    # requested value is honest there).
    if audit_run_dir:
        from . import summary as _posture_mod
        _posture_mod.record_run_posture(
            Path(audit_run_dir),
            mount_ns_active=False,
            restrict_reads=bool(restrict_reads) and not audit_mode,
        )

    # 0d. Grant-path identity pins — the darwin twin of the Linux
    # bind-source P-byte pin (context._grant_path_identities +
    # _spawn's abort), adapted to seatbelt's constraint that SBPL
    # grants are path STRINGS with no kernel-held inode reference:
    # a real directory renamed into a granted path mid-run INHERITS
    # the grant, and on current macOS (26.6.2, observed live) even a
    # symlink swapped into the granted path lets writes flow through
    # to its destination. SBPL itself cannot express "this grant is
    # for THIS inode", so the pin is enforced procedurally:
    #   * snapshot (dev, ino) for every caller grant here, at the
    #     same instant the path strings are frozen into the profile
    #     (same realpath the profile emission applies);
    #   * re-verify immediately before spawn (after the parent's own
    #     fake-home/.tmp writes below — O_NOFOLLOW-style discipline
    #     for RAPTOR's own writes into output);
    #   * the watcher shim re-verifies on every poll tick for the
    #     whole run and SIGKILLs the sandbox tree on mismatch,
    #     reporting b"P" on the status pipe (fail loud, never a
    #     normal-looking result).
    # HONEST RESIDUAL, two halves: (a) writes between a swap and the
    # watcher's next poll tick land before the kill (one ~0.1s poll
    # cadence; longer only while a process-table snapshot stalls the
    # loop); (b) detection requires the swap to PERSIST across a poll
    # tick — a same-UID accomplice OUTSIDE the sandbox that swaps and
    # restores within one tick lands its window of writes AND the run
    # returns clean. A path-string sandbox cannot close either half;
    # the pin bounds the damage and guarantees refusal only for
    # persistent tampering. The swap-and-restore variant needs an
    # unsandboxed same-UID process, which is already outside this
    # sandbox's threat boundary (documented, not defended).
    # The /private/tmp baseline seed and the /dev literals are
    # system-owned paths outside same-UID rename control and are
    # deliberately not pinned.
    _grant_pins: list[dict] = []
    # Serialized pins cannot hold an fd (they cross an exec into the
    # `python -I` shim), so the (dev, ino) identity alone is forgeable
    # on a filesystem that recycles freed inode numbers: an
    # unlink+recreate swap can re-mint the pinned pair. The birth time
    # is the secondary identity witness — a recreated object carries a
    # NEW birth time even when it inherits the old inode number. When
    # the capture host reports no birth time the pin is IDENTITY-WEAK:
    # recorded as such on the result (grant_pin_identity_degraded) so
    # readers never mistake a recycling-blind pin for the full
    # guarantee — the remaining arms (vanish / symlink / dev-ino)
    # still enforce. Honest bounds: APFS allocates inode numbers
    # monotonically (never recycled), so on the default macOS
    # filesystem dev/ino is already recycle-proof and the witness is
    # belt-and-braces for HFS+ and network mounts; and a birth time is
    # owner-settable (setattrlist crtime), so a DELIBERATE same-UID
    # forger sits outside what a serialized pin can refuse — the same
    # unsandboxed-accomplice boundary the watcher residuals above
    # document.
    _weak_grant_pins: list[str] = []
    import stat as _stat_mod
    for _gp in dict.fromkeys(
            p for p in (target, output,
                        *(writable_paths or ()),
                        *(readable_paths or ()))
            if p):
        _resolved = os.path.realpath(os.path.abspath(_gp))
        try:
            _st = os.stat(_resolved)
        except OSError:
            # Not (yet) existing / unreadable: nothing to pin — the
            # profile clause for a nonexistent path grants nothing
            # until something exists there. Linux parity: the
            # identity snapshot skips OSError paths the same way.
            continue
        if not _stat_mod.S_ISDIR(_st.st_mode):
            # Directories only: a granted FILE's identity changes
            # legitimately when the workload rewrites it atomically
            # (tmp + rename), so pinning it would SIGKILL legitimate
            # runs; the enforced boundary is the containing directory
            # grant. A file-only grant therefore carries no pin
            # (documented residual).
            continue
        _pin_btime = getattr(_st, "st_birthtime", None)
        if _pin_btime is None:
            _weak_grant_pins.append(_resolved)
        _grant_pins.append({
            "path": _resolved,
            "dev": int(_st.st_dev),
            "ino": int(_st.st_ino),
            "btime": (float(_pin_btime)
                      if _pin_btime is not None else None),
        })

    # 1. Build SBPL profile from the kwargs.
    profile = seatbelt.build_profile(
        target=target,
        output=output,
        block_network=block_network,
        allowed_tcp_ports=list(allowed_tcp_ports) if allowed_tcp_ports else None,
        use_egress_proxy=use_egress_proxy,
        proxy_port=proxy_port,
        restrict_reads=restrict_reads,
        readable_paths=list(readable_paths) if readable_paths else None,
        writable_paths=list(writable_paths) if writable_paths else None,
        fake_home=fake_home,
        exclude_tmp_baseline=exclude_tmp_baseline,
        audit_mode=audit_mode,
        audit_verbose=audit_verbose,
        seccomp_profile=seccomp_profile,
        audit_evidence_dir=_evidence_dir,
        profile_name=sandbox_profile,
    )

    # 2. fake_home: redirect HOME + XDG_*_HOME into output/.home/
    #    so the child sees no dotfiles. Pre-populate the dir empty.
    if env is not None:
        child_env = dict(env)
        if strict_env:
            # is_dangerous_env_name = DANGEROUS_ENV_VARS plus the
            # credential-env name patterns (unenumerable spellings).
            from core.config import RaptorConfig
            child_env = {
                k: v for k, v in child_env.items()
                if (not RaptorConfig.is_dangerous_env_name(k)
                    or RaptorConfig.GIT_ENV_VARS.get(k) == v)
            }
    else:
        from core.config import RaptorConfig
        child_env = RaptorConfig.get_safe_env()
    if fake_home and output:
        # Mirror the Linux layout (context.py:fake_home_env) exactly:
        # HOME → {output}/.home/
        # XDG_CONFIG_HOME → {output}/.home/.config
        # XDG_CACHE_HOME  → {output}/.home/.cache
        # XDG_DATA_HOME   → {output}/.home/.local/share
        # XDG_STATE_HOME  → {output}/.home/.local/state
        # Earlier code mapped ALL XDG vars to the same directory,
        # which made caches and configs collide for any tool that
        # writes to multiple XDG roots (e.g., pip, conda). The
        # docstring claimed "identical (env mutation)" — now true.
        fake_home_dir = os.path.join(output, ".home")
        xdg_layout = {
            "XDG_CONFIG_HOME": os.path.join(fake_home_dir, ".config"),
            "XDG_CACHE_HOME":  os.path.join(fake_home_dir, ".cache"),
            "XDG_DATA_HOME":   os.path.join(fake_home_dir, ".local",
                                              "share"),
            "XDG_STATE_HOME":  os.path.join(fake_home_dir, ".local",
                                              "state"),
        }
        # Symlink-TOCTOU defence before the per-call makedirs — same
        # path list as the Linux construction-time guard, including
        # the .local intermediate that makedirs would traverse.
        _refuse_hijacked_scratch_dir(
            [fake_home_dir, os.path.join(fake_home_dir, ".local"),
             *xdg_layout.values()])
        os.makedirs(fake_home_dir, mode=0o700, exist_ok=True)
        child_env["HOME"] = fake_home_dir
        for var, path in xdg_layout.items():
            child_env[var] = path
            try:
                os.makedirs(path, mode=0o700, exist_ok=True)
            except OSError:
                # Best-effort. If a fresh sandbox can't pre-create
                # an XDG dir (e.g., the parent's umask is unusual),
                # the env var still points to the right location and
                # the child's first write will create it.
                pass

    # 2b. TMPDIR steering under write isolation: whenever the profile
    #     engages the file-write deny (same condition as
    #     seatbelt.build_profile's write_isolation_engaged gate — keep
    #     them in sync), the child's default TMPDIR (the per-user
    #     /var/folders/... DARWIN_USER_TEMP_DIR, which rides the
    #     safe-env allowlist into every child env) sits OUTSIDE every
    #     write exception: python's tempfile silently falls back to
    #     /tmp, but tools that honour TMPDIR directly (clang
    #     intermediates, git, tar) get EPERM — confirmed on current
    #     macOS (26.6.2) for every write-isolated shape left at the
    #     host-default TMPDIR. Linux has no such gap (its default
    #     TMPDIR=/tmp IS seeded writable). Redirect TMPDIR into
    #     {output}/.tmp, which rides the output writable exception —
    #     never widen the profile's write exceptions to the
    #     /var/folders tree instead (host-shared, cross-run mutable).
    #     Earlier code steered only under exclude_tmp_baseline (the
    #     untrusted lane), leaving every trusted-lane write-isolated
    #     run with an unwritable default TMPDIR.
    #     Without an output dir there is nowhere writable to point it;
    #     for exclude_tmp_baseline that is fatal for tmp-dependent
    #     tools (every /tmp spelling is denied too) — warn, per the
    #     flag's contract: only use it when the workload doesn't need
    #     tmp. (With the /private/tmp seed intact, tempfile's /tmp
    #     fallback still works, so no warning there.)
    _write_isolation_engaged = bool(
        output or writable_paths or target or restrict_reads
    )
    if _write_isolation_engaged and output:
        _scratch_tmp = os.path.join(output, ".tmp")
        # Same symlink-TOCTOU refusal as the fake-home paths: this
        # dir is re-created per call inside the child-writable output
        # tree, and TMPDIR steering through a swapped link would aim
        # the parent's makedirs (and the child's tmp writes) at an
        # attacker-chosen destination.
        _refuse_hijacked_scratch_dir([_scratch_tmp])
        try:
            os.makedirs(_scratch_tmp, mode=0o700, exist_ok=True)
        except OSError:
            pass
        child_env["TMPDIR"] = _scratch_tmp
    elif exclude_tmp_baseline:
        logger.warning(
            "exclude_tmp_baseline without output=: tmp writes are "
            "denied and TMPDIR has no writable redirect target — "
            "tmp-dependent tools in this sandbox will fail"
        )

    # 3. rlimits via preexec_fn.
    #
    # _make_preexec_fn handles memory / CPU / file-size via setrlimit
    # — works as-is on macOS (POSIX). It deliberately skips
    # RLIMIT_NPROC on Linux because Linux applies nproc via the
    # prlimit-inside-unshare wrapper (so the limit counts against the
    # ns-local UID, not the host's). macOS has no unshare wrapper, so
    # nproc is applied INSIDE preexec here, where it counts against
    # the calling UID host-wide. That is why the configured budget
    # cannot be applied as an ABSOLUTE ceiling (the pre-fix shape):
    # on a host already running more same-UID processes than the
    # budget — an interactive Mac with a browser session gets there —
    # an absolute cap sits BELOW current usage and every fork inside
    # the sandbox fails EAGAIN; on a quiet host it admits
    # (budget - count) forks instead of the budget. Mirror the Linux
    # no-namespace lane instead: ceiling = current same-UID process
    # count + configured budget, clamped to the hard limit (same
    # arithmetic as preexec._make_preexec_fn's host_nproc_cap arm).
    # When ps cannot produce a count, skip the cap with a warning
    # (Linux parity: the /proc-unreadable case skips there too) — a
    # blind absolute cap risks breaking the run outright.
    effective_limits = dict(limits or {})
    base_preexec = _make_preexec_fn(effective_limits)
    preexec = base_preexec
    if nproc_limit and nproc_limit > 0:
        _uid_count = _same_uid_process_count()
        if _uid_count is None:
            logger.warning(
                "sandbox: could not count same-UID processes via ps — "
                "skipping the RLIMIT_NPROC fork-bomb bound for this "
                "run (an absolute cap below current usage would make "
                "every fork in the sandbox fail)"
            )
        else:
            import resource as _resource
            _nproc_ceiling = _uid_count + int(nproc_limit)
            # macOS silently stores at most kern.maxprocperuid for
            # RLIMIT_NPROC whatever we request (even under an infinite
            # hard limit) — the enforcement is unchanged either way,
            # but requesting a number the kernel will not honour makes
            # every read-back (child getrlimit, diagnostics, the probe
            # kit) disagree with the computed ceiling. Request the
            # honoured value. When the count already exceeds the
            # kernel clamp the relative headroom is unobtainable on
            # this host — the clamp still wins (the kernel would
            # impose it regardless).
            _kernel_clamp = _darwin_nproc_kernel_clamp()
            if _kernel_clamp is not None:
                _nproc_ceiling = min(_nproc_ceiling, _kernel_clamp)

            def preexec() -> None:
                base_preexec()
                try:
                    _, _hard = _resource.getrlimit(
                        _resource.RLIMIT_NPROC)
                    _eff = (_nproc_ceiling
                            if _hard == _resource.RLIM_INFINITY
                            else min(_nproc_ceiling, _hard))
                    _resource.setrlimit(
                        _resource.RLIMIT_NPROC, (_eff, _eff)
                    )
                except (ValueError, OSError):
                    # Best-effort. Some macOS versions cap NPROC via
                    # different sysctls and setrlimit may EPERM the
                    # call when NPROC > kern.maxproc/UID. The module
                    # docstring already documents this as soft posture;
                    # emit a fork-safe warning so operators can observe
                    # when the documented-soft bound becomes a silent no-op.
                    warn_post_fork(b"sandbox: _macos_spawn RLIMIT_NPROC setrlimit failed -- documented soft posture became silent no-op\n")

    # 4. Wrap cmd with sandbox-exec, interposed by the seatbelt shim.
    #    Layout (outermost first):
    #      outer shim (UNSANDBOXED python watcher: fail-loud + teardown)
    #        -> sandbox-exec applies the SBPL profile
    #          -> /bin/sh trampoline (INSIDE the profile) writes the
    #             readiness byte to fd 3, closes it (so the untrusted target
    #             never inherits the status pipe), then execs the target.
    #    The inner trampoline is /bin/sh, not python: its startup deps
    #    (exec /bin/sh + libSystem + dyld cache) are a strict SUBSET of any
    #    dynamically-linked target's, so "no readiness byte" can only mean
    #    the profile cannot run the target either (a genuine setup failure),
    #    never "our trampoline needs files the target doesn't." The profile
    #    is pinned to always permit /bin/sh (seatbelt.build_profile). fd 3 is
    #    wired to the status pipe by the outer shim before exec.
    #    Invoke the outer shim via this interpreter (+ -I) rather than its
    #    shebang: macOS /usr/bin/python3 is the Command-Line-Tools stub, so
    #    relying on the shebang is unsafe; sys.executable is RAPTOR's python.
    #    It runs UNSANDBOXED, so its stdlib reads are never restricted.
    import sys as _sys
    _py = _sys.executable or "/usr/bin/python3"
    _inner = ["/bin/sh", "-c", 'printf K >&3; exec 3>&-; exec "$@"',
              "raptor-seatbelt-rdy"] + list(cmd)
    _sandboxed = [SANDBOX_EXEC, "-p", profile, "--"] + _inner
    # --keep-trust-markers precedes the sandbox-exec argv; the shim
    # parses it before anything else (see its main()).
    sandbox_cmd = (
        [_py, "-I", SEATBELT_SHIM]
        + (["--keep-trust-markers"] if keep_trust_markers else [])
        + _sandboxed
    )

    # 5. Audit mode: start log streamer BEFORE the workload to capture
    #    kernel sandbox events. Stop after workload exits.
    audit_streamer = None
    if audit_mode and audit_run_dir:
        from . import seatbelt_audit
        try:
            # require_scope: the streamer must not attribute ANY
            # host-wide Sandbox.kext event to this run until the
            # workload's PID is registered (right after the Popen
            # below). `log stream` is a host-wide feed — without the
            # scope gate, every kext event on the machine (sibling
            # RAPTOR runs, unrelated sandboxed apps, an attacker's
            # deliberate sandbox-exec noise on a shared host) would
            # be nonce-stamped into this run's JSONL and flow into
            # denial summaries, triage, and calibration-derived
            # allowlists.
            audit_streamer = seatbelt_audit.start_log_streamer(
                Path(audit_run_dir),
                observe_mode=bool(observe_mode),
                observe_nonce=observe_nonce,
                # Mandatory scope gate: the kext sender predicate
                # alone admits every sandboxed process on the host —
                # only records attributable to OUR workload's process
                # tree may be nonce-stamped into this run's JSONL.
                # The shim PID is registered right after Popen below.
                require_scope=True,
                # audit_required is a fail-closed contract: the
                # warm-up attachment gate failing must raise (caught
                # below, converted to SandboxSetupError) rather than
                # proceed best-effort with an unproven log-stream
                # attachment and a healthy-looking zero-record
                # summary.
                warm_up_required=bool(audit_required),
            )
        except Exception as exc:
            logger.warning(
                "seatbelt audit log streamer failed to start: %s",
                exc, exc_info=True,
            )
            # F064: write the audit-degraded marker so operators
            # inspecting the run dir can distinguish "audit ran,
            # found nothing" from "audit was requested but the log
            # streamer failed to attach." Mirrors the Linux pattern
            # at _spawn.py and the existing context.py:1328 wire.
            from . import summary as _summary_mod
            _summary_mod.record_audit_degraded(
                Path(audit_run_dir),
                reason=(
                    f"audit_mode=True but seatbelt log streamer failed "
                    f"to start: {type(exc).__name__}: {exc}"
                ),
                instructions=(
                    "check the macOS unified log subsystem is reachable "
                    "(log show / log stream); verify the user has rights "
                    "to read kernel-sandbox events; or run without "
                    "audit_mode on hosts where the streamer cannot attach"
                ),
            )
            if audit_required:
                # Fail closed BEFORE spawning the workload: the caller
                # demanded audit evidence and macOS has no other audit
                # tier to fall back to. Marker above is kept — it
                # documents the refused degradation.
                from .errors import SandboxSetupError
                msg = (
                    f"audit_required=True but the seatbelt log "
                    f"streamer failed to start "
                    f"({type(exc).__name__}: {exc}) — refusing to "
                    f"run the target unaudited."
                )
                raise SandboxSetupError(
                    msg,
                    "check the macOS unified log subsystem (log show "
                    "/ log stream), or drop audit_required= to accept "
                    "marker-recorded degradation.",
                ) from exc

    # 5b. Status + death pipes for the seatbelt shim.
    #     status: the inner shim writes one readiness byte after the profile
    #             applies; its absence => fail loud (sandbox did not engage).
    #     death:  the outer shim watches it; when THIS orchestrator process
    #             dies (incl. SIGKILL/OOM/crash), every write-end copy closes,
    #             the outer shim reads EOF and SIGKILLs the sandbox group.
    #     Both are passed via pass_fds (subprocess clears CLOEXEC on those) so
    #     status_w reaches the inner shim and death_r reaches the outer shim.
    #     We hold death_w for the whole synchronous run, so EOF (=> teardown)
    #     fires only when this process actually dies — never on a healthy run.
    status_r, status_w = os.pipe()
    try:
        death_r, death_w = os.pipe()
    except OSError:
        os.close(status_r)
        os.close(status_w)
        raise
    child_env["_RAPTOR_STATUS_FD"] = str(status_w)
    child_env["_RAPTOR_DEATH_FD"] = str(death_r)
    # Grant-path identity pins for the watcher shim (see step 0d).
    # Consumed by the shim like the fd markers: verified in the child
    # branch before exec, polled by the watcher for the whole run,
    # stripped from the environment before anything sandboxed starts.
    # No new disclosure: every pinned path already appears verbatim in
    # the profile text riding argv. Pop-then-set: only THIS spawn
    # layer may mint pins — a caller-supplied env dict carrying the
    # key must never steer the watcher's kill decision (same
    # no-env-authority rule as the keep-trust key).
    child_env.pop("_RAPTOR_GRANT_PINS", None)
    if _grant_pins:
        import json as _json
        child_env["_RAPTOR_GRANT_PINS"] = _json.dumps(_grant_pins)
    # The seatbelt shim is RAPTOR's own dispatch helper and refuses to run
    # without a trust marker (guards against a human/attacker invoking the
    # internal script directly). THIS code path is the trusted invoker, so
    # assert the marker explicitly instead of depending on bin/raptor having
    # exported it into the ambient env — get_safe_env() preserves it when set,
    # but a direct API or test caller (no bin/raptor, no CLAUDECODE) would
    # otherwise trip the gate and every macOS sandbox run would fail loud.
    # The marker authorizes the OUTER (unsandboxed) shim ONLY: the shim strips
    # it — and the fd markers — from the environment before exec'ing
    # sandbox-exec, so nothing _RAPTOR_* ever crosses into the sandboxed
    # target's env. See raptor-seatbelt-shim's child branch.
    child_env["_RAPTOR_TRUSTED"] = "1"

    # 6. Run.
    #
    # Popen + communicate rather than subprocess.run: run()'s own
    # timeout path SIGKILLs only the DIRECT child — the seatbelt shim,
    # detached in its own session — while the sandbox-exec process
    # group the shim forked (deliberately placed in a separate pgrp so
    # the shim can killpg it) survived, and the shim's death-pipe
    # teardown died with the shim. A hostile target that simply hung
    # past its timeout kept running on the operator host, unaudited,
    # after the log streamer was stopped. Owning the Popen lets the
    # timeout path fire the DESIGNED teardown channel first — closing
    # death_w makes the still-alive shim killpg the sandbox group and
    # exit — with a killpg of the shim's own session as the backstop.
    def _teardown_shim_tree(process) -> None:
        """Kill the shim and its sandbox subtree on timeout/abort."""
        # 0. Snapshot the process table FIRST, while the tree is still
        #    alive: a fork+setsid descendant has left both kill groups
        #    below, but its ppid chain back to the shim is intact until
        #    its ancestors die — after the kills it reparents to
        #    launchd and a fresh snapshot can no longer attribute it.
        try:
            _live_table = _ps_snapshot()
        except Exception:
            _live_table = None
        # 1. Death-pipe EOF: the shim's watcher loop (0.1s poll) reads
        #    EOF and SIGKILLs the sandbox process group + child, then
        #    exits. This reaches the sandbox-exec pgrp, which is NOT
        #    in the shim's own process group.
        try:
            os.close(death_w)
        except OSError:
            pass
        try:
            process.wait(timeout=5)
        except (subprocess.TimeoutExpired, OSError):
            pass
        # 2. Backstop: SIGKILL the shim's whole session-leader group
        #    (start_new_session=True → pgid == shim pid; killpg cannot
        #    reach this orchestrator). Without a new session the shim
        #    shares our pgrp — fall back to killing just the shim.
        if start_new_session:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
        try:
            process.kill()
        except OSError:
            pass
        # 3. Post-wait descendant sweep, independent of process group:
        #    catches setsid escapees the two killpg's above cannot
        #    reach. The shim is dead by now, so the status channel is
        #    drainable — the G report lets the sweep attribute sandbox
        #    process-group members even though their ppid link to the
        #    (dead) shim is gone. Best-effort with logging — teardown
        #    must never raise over sweep failure.
        try:
            _grp = _parse_group_report(_harvest_status())
            _sweep_descendants(process.pid, live_snapshot=_live_table,
                               extra_pgids=(_grp,) if _grp else ())
        except Exception:
            logger.warning(
                "macOS sandbox teardown: descendant sweep failed",
                exc_info=True,
            )

    # Status-channel harvest: close our write end, then drain the read
    # end to EOF. Idempotent (memoised) because both the normal path
    # (which needs the sandbox-group report BEFORE its backstop sweep)
    # and the finally (exception paths) call it. The drain can only
    # block while another write-end copy lives — the watcher shim
    # holds one for its P/G reports — and every route here has the
    # shim already reaped (Popen.__exit__ waits; the teardown paths
    # kill it), so EOF is guaranteed.
    _status_state: dict = {"done": False, "data": b""}

    def _harvest_status() -> bytes:
        if _status_state["done"]:
            return _status_state["data"]
        _status_state["done"] = True
        try:
            os.close(status_w)
        except OSError:
            pass
        data = b""
        try:
            while True:
                chunk = os.read(status_r, 4096)
                if not chunk:
                    break
                data += chunk
        except OSError:
            pass
        try:
            os.close(status_r)
        except OSError:
            pass
        _status_state["data"] = data
        return data

    if input is not None and stdin is not None:
        msg = "stdin and input arguments may not both be used."
        raise ValueError(msg)
    _popen_stdin = subprocess.PIPE if input is not None else stdin
    # Loader-variable quarantine: the seatbelt shim is an UNSANDBOXED
    # trusted dispatcher carrying _RAPTOR_TRUSTED — DYLD_*/LD_* from a
    # caller-supplied env dict must not inject code into it. The shim
    # re-applies the quarantined pairs before exec'ing sandbox-exec so
    # the target-side semantics are unchanged (SIP may still strip
    # DYLD_* across the protected sandbox-exec binary, exactly as it
    # did pre-quarantine).
    from ._env_quarantine import quarantine_loader_env
    child_env = quarantine_loader_env(child_env)
    # Last-moment pin re-verify before spawn (step 0d): the parent
    # itself wrote into output above (fake-home layout, .tmp scratch)
    # — those makedirs follow symlinks, so a swap in the capture→spawn
    # window would have steered THIS process's writes as well as the
    # child's grant. Refuse rather than hand a tampered path a live
    # sandbox. From here the watcher shim owns the check.
    for _pin in _grant_pins:
        _pin_err = _grant_pin_mismatch(
            _pin["path"], _pin["dev"], _pin["ino"], _pin["btime"])
        if _pin_err:
            # The status/death pipes were already created — close all
            # four ends before raising (this refusal predates the
            # try/finally that owns their lifecycle).
            for _fd in (status_r, status_w, death_r, death_w):
                try:
                    os.close(_fd)
                except OSError:
                    pass
            from .errors import SandboxSetupError
            raise SandboxSetupError(
                f"sandbox grant-path pin violated before spawn: "
                f"{_pin['path']} {_pin_err}",
                "a granted target/output/writable path changed "
                "identity between validation and spawn (symlink or "
                "rename swap). Re-create the directory and re-run; "
                "never point grants at attacker-writable parents.",
                setup_category="P",
            )
    try:
        with subprocess.Popen(
            sandbox_cmd,
            env=child_env,
            cwd=cwd,
            stdout=subprocess.PIPE if capture_output else stdout,
            stderr=subprocess.PIPE if capture_output else stderr,
            stdin=_popen_stdin,
            text=text,
            preexec_fn=preexec,
            start_new_session=start_new_session,
            pass_fds=(status_w, death_r, *tuple(pass_fds or ())),
        ) as _process:
            try:
                # Register the workload root with the audit streamer's
                # scope gate: everything the sandboxed workload does
                # descends from the shim process, so registering its
                # PID (plus lineage widening inside the streamer) is
                # what keeps host-wide kext events from unrelated
                # sandboxed processes out of this run's JSONL. When
                # the run's evidence MUST be attributable — observe
                # mode feeds derived allowlists, audit_required is an
                # explicit fail-closed contract — a registration
                # failure refuses the run rather than proceeding
                # unscoped (the raise lands in the BaseException arm
                # below, which tears down the shim tree).
                if audit_streamer is not None:
                    try:
                        audit_streamer.register_target_pid(_process.pid)
                    except Exception as _scope_exc:
                        logger.warning(
                            "seatbelt audit: failed to register the "
                            "workload root with the log streamer; "
                            "audit records will be dropped as "
                            "unattributable",
                            exc_info=True,
                        )
                        if observe_mode or audit_required:
                            from .errors import SandboxSetupError
                            raise SandboxSetupError(
                                f"audit scoping could not be "
                                f"established for the sandboxed "
                                f"workload "
                                f"({type(_scope_exc).__name__}: "
                                f"{_scope_exc}) — refusing to run "
                                f"with host-wide, unattributable "
                                f"audit evidence.",
                                "check the log-streamer state, or "
                                "drop observe/audit_required to "
                                "accept unattributed degradation.",
                            ) from _scope_exc
                _stdout, _stderr = _process.communicate(
                    input, timeout=timeout,
                )
            except subprocess.TimeoutExpired:
                _teardown_shim_tree(_process)
                _process.wait()
                raise
            except BaseException:
                # Mirror subprocess.run: never leave the tree running
                # on KeyboardInterrupt or any other abort either.
                _teardown_shim_tree(_process)
                raise
            _retcode = _process.poll()
        # Post-wait descendant sweep on the NORMAL-completion path
        # too — pre-fix, normal completion just reaped the shim and a
        # fork+setsid descendant survived the run outright. By this
        # point the shim has exited, so its own exit-time sweep (see
        # libexec/raptor-seatbelt-shim, which still saw the live tree)
        # is the primary owner of this path; this parent-side pass is
        # the backstop for a shim that died without sweeping. The
        # ppid walk from the dead shim pid finds nothing once
        # survivors reparent to launchd, so the sweep leans on the
        # shim's G group report (written right after fork, before any
        # target code ran, so a shim killed later cannot have skipped
        # it): sandbox process-group members stay attributable even
        # with the shim gone. Best-effort.
        try:
            _grp = _parse_group_report(_harvest_status())
            _sweep_descendants(_process.pid,
                               extra_pgids=(_grp,) if _grp else ())
        except Exception:
            logger.warning(
                "macOS sandbox: post-run descendant sweep failed",
                exc_info=True,
            )
        result = subprocess.CompletedProcess(
            sandbox_cmd, _retcode, _stdout, _stderr,
        )
    finally:
        # Close our copies and drain the status channel (idempotent —
        # the normal path already harvested before its backstop
        # sweep). _harvest_status closes status_w first: with our
        # write end gone and the shim reaped, the drain returns the
        # accumulated bytes then EOF, never blocks.
        for _fd in (death_r, death_w):
            try:
                os.close(_fd)
            except OSError:
                pass
        _status_bytes = _harvest_status()
        if audit_streamer is not None:
            try:
                audit_streamer.stop()
            except Exception:
                # Pre-fix this swallowed failures at DEBUG level
                # — operators rarely run with debug logging on,
                # so audit-streamer stop failures went invisible.
                # The streamer holds OS resources (kqueue fd,
                # spawn-helper subprocess, log-rotation handles);
                # silent failure here means those resources leak
                # over the lifetime of a long-running session.
                # Bump to WARNING so the next sandbox invocation
                # surfaces the leak hint to the operator. Still
                # catches Exception (don't propagate to mask the
                # original sandbox-launch outcome) — the goal is
                # visibility, not failure-propagation.
                logger.warning(
                    "seatbelt audit streamer stop failed — "
                    "resources may have leaked from this sandbox call",
                    exc_info=True,
                )

    # 6b. Fail-loud signal for context.py (mirrors the Linux exec-status
    #     pipe's result._setup_status contract):
    #       None      -> target was reached inside the applied profile;
    #                    the result is genuine.
    #       ("P", ..) -> a granted path's identity pin stopped matching
    #                    mid-run and the watcher SIGKILLed the sandbox
    #                    tree. Outranks the readiness byte: setup DID
    #                    succeed, but the result is tainted — caller
    #                    raises, never returns it (Linux P parity:
    #                    fail-loud, never degrade).
    #       ("E", ..) -> the in-sandbox readiness byte never arrived =>
    #                    sandbox-exec did not apply the profile / the inner
    #                    shim never ran => caller raises SandboxSetupError.
    #     Unlike Linux there is no Landlock layer to degrade to, so the only
    #     safe response to "did not engage" is to fail loud — never silently
    #     run unsandboxed.
    _leftover = re.sub(rb"G\d{1,9}\n", b"", _status_bytes)
    _leftover = _leftover.replace(_READY_BYTE, b"").replace(
        _PIN_TAMPER_BYTE, b"")
    if _PIN_TAMPER_BYTE in _status_bytes:
        result._setup_status = (  # type: ignore[attr-defined]
            "P",
            ("a granted path's identity (dev/ino) changed mid-run — "
             "symlink or rename swapped into a granted target/output/"
             "writable path; the watcher shim SIGKILLed the sandbox "
             "tree and this result must not be trusted"),
        )
    elif _leftover:
        # Default-DENY bytes this parent does not recognise — a writer
        # this parser predates, or channel corruption. Treating them
        # as noise beside a readiness byte would be the default-allow
        # shape the context layer's unknown-category arm exists to
        # refuse; mint a category that arm does not know so it does.
        result._setup_status = (  # type: ignore[attr-defined]
            "B",
            (f"unrecognised bytes on the seatbelt status channel "
             f"({_leftover[:16]!r}) — protocol violation; refusing "
             f"to trust the result"),
        )
    elif _READY_BYTE in _status_bytes:
        result._setup_status = None
    else:
        result._setup_status = (
            "E",
            ("seatbelt profile did not apply: the in-sandbox readiness "
             "byte was not received from raptor-seatbelt-shim"),
        )

    # 7. Attach sandbox_info — caller (context.py) populates the rest;
    #    we just guarantee the attribute exists so callers don't have
    #    to defensive-attr it.
    if not hasattr(result, "sandbox_info"):
        result.sandbox_info = {}
    result.sandbox_info.setdefault("backend", "macos-seatbelt")
    if _weak_grant_pins:
        # Identity-weak pins (no birth-time witness at capture): the
        # dev/ino arms enforced for the whole run, but an
        # unlink+recreate swap on an inode-recycling filesystem was
        # invisible to them. Stamp the paths so a "no P report" run is
        # never silently read as the full pin guarantee.
        result.sandbox_info.setdefault(  # type: ignore[attr-defined]
            "grant_pin_identity_degraded", sorted(_weak_grant_pins))
    return result
