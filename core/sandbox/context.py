"""The `sandbox()` context manager and the top-level run wrappers.

This is the only module that talks to subprocess directly. It threads
Landlock + seccomp + rlimits + namespace flags through to subprocess.run,
handles per-call kwarg validation, and attaches structured sandbox_info
to each result.
"""

import errno
import logging
import re
import os
import shutil
import signal
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from . import landlock as _landlock
from . import probes as _probes
# Module alias (not `from .errors import SandboxSetupError`): run()'s
# closure contains function-local `from .errors import ...` statements,
# which make the bare name function-local for the WHOLE scope — an
# except clause naming it before those lines execute would hit
# UnboundLocalError. The alias sidesteps the scoping trap.
from . import errors as _errors
from . import tiers as _tiers
from ._env_quarantine import ENV_RESTORE_KEY as _ENV_RESTORE_KEY
from . import seccomp as _seccomp
from . import state

# mount.py retained for its standalone tests; no longer imported from
# context — mount-ns goes through core.sandbox._spawn / mount_ns.
from .observe import (
    _CMD_DISPLAY_MAX_ARGS,
    _check_blocked,
    _interpret_result,
)
from .preexec import _DEFAULT_LIMITS, _load_user_limits, _make_preexec_fn
from .profiles import (
    _SANDBOX_KWARGS,
    DEFAULT_PROFILE,
    PROFILES,
    host_recon_threshold_for_profile,
)


# Attribute indirection so tests can patch these at the submodule level.
# `patch.object(core.sandbox.landlock, "check_landlock_available", ...)`
# reaches these callsites; direct `from .landlock import check_landlock_available`
# would bind once at import and ignore the patch.
def check_landlock_available():
    return _landlock.check_landlock_available()
def _get_landlock_abi():
    return _landlock._get_landlock_abi()
def check_net_available():
    return _probes.check_net_available()
def check_mount_available():
    return _probes.check_mount_available()
def check_seccomp_available():
    return _seccomp.check_seccomp_available()
def check_seatbelt_available():
    return _probes.check_seatbelt_available()


def spawn_backend_available() -> bool:
    """True when sandbox().run() will route through the Linux fork-based
    spawn backend (core.sandbox._spawn.run_sandboxed) on this host.

    The spawn backend is the only execution path that can deliver a live
    child pid to an ``exec_pid_callback=`` caller before the sandboxed
    target exits — the subprocess fallback paths (Landlock-only, unshare
    CLI) and the macOS seatbelt path run the command to completion before
    returning. Callers that need mid-run visibility of the child (e.g.
    /proc/<pid>/maps sampling of an untrusted binary) must check this
    predicate first and degrade to a "not sampled" result when it is
    False, rather than running the target on a weaker or absent backend.

    Mirrors the routing decision made inside sandbox().run(): Linux,
    sandbox not disabled (per-CLI), a CLI profile (when set) that keeps
    Landlock engaged, user-namespace capability, mount-namespace
    capability, and the newuidmap/newgidmap helpers present.
    """
    if sys.platform == "darwin":
        return False
    if state._cli_sandbox_profile is not None:
        _profile_cfg = PROFILES.get(state._cli_sandbox_profile)
        if not _profile_cfg or not _profile_cfg.get("use_landlock"):
            return False
    elif state._cli_sandbox_disabled:
        return False
    if not (check_net_available() and check_mount_available()):
        return False
    from . import _spawn as _spawn_mod
    return _spawn_mod.mount_ns_available()


logger = logging.getLogger(__name__)


def _first_external_caller() -> str:
    """``file:line`` of the nearest stack frame outside core/sandbox.

    The bare-run posture advisory fires once per process, so without
    caller identity a legitimately-unconfined network-only invocation
    is indistinguishable from an untrusted-bytes call that forgot its
    confinement arguments. Best-effort: unattributable frames report
    a placeholder rather than raising into the warning path.
    """
    try:
        pkg_dir = os.path.dirname(os.path.abspath(__file__)) + os.sep
        frame = sys._getframe(1)
        while frame is not None:
            path = frame.f_code.co_filename
            if not os.path.abspath(path).startswith(pkg_dir):
                return f"{path}:{frame.f_lineno}"
            frame = frame.f_back
    except Exception:  # noqa: BLE001 — attribution must never break the warning
        pass
    return "<unattributable>"

# Framework-named temp paths (the launcher's per-session scratch
# <base>/raptor-<uid>/session-<pid>-<rand>, harness session dirs,
# any /tmp component naming the framework). Values matching it are
# rewritten out of target-bound envs and skipped by the mount-ns
# temp-dir re-creation — the NAME is the leak (framework, uid, host
# pid), and re-creating it plants the same name inside the target's
# private /tmp. Keep in sync with core/sandbox/mount_ns.py.
_BRANDED_TMP_RE = re.compile(r"/[^/]*raptor[^/]*(/|$)", re.IGNORECASE)


def _audit_degrade_reason(b_fallback_reason, b_fallback_instr,
                          target, output, kwargs) -> tuple:
    """Return (reason, instructions) explaining why audit can't engage.

    Called when ``audit_mode`` was requested but ``spawn_eligible`` is
    False, to populate the operator-facing WARNING and the
    ``sandbox-audit-degraded.json`` marker.

    Resolution order — the first matching cause wins, so check the
    most specific causes first:

      1. B fallback / cache hit set ``b_fallback_reason`` upstream
         (cmd[0] outside mount tree, or cached as known-failing).
         Their reason is the most specific: it names the binary.
      2. ``check_mount_available()`` False — host kernel refuses
         unprivileged mount-ns (Ubuntu 24.04 default sysctl).
      3. ``pass_fds=`` kwarg set (Linux only) — _spawn's fork chain
         doesn't plumb inherited fds; the call had to go
         subprocess+preexec. The macOS backend plumbs pass_fds
         natively, so this cause never applies on darwin.
      4. ``input=`` kwarg set (Linux only) — same reason; piping
         stdin via input= can't survive mount-ns fork+exec. Plumbed
         natively on darwin.
      5. ``target`` and ``output`` both None — mount-ns has nothing
         to bind-mount as the working area; the tracer has nowhere
         to attach in the new namespace.
      6. Catch-all — reachable only if a future change adds a new
         spawn-eligibility gate without updating this helper.

    Each branch returns a short ``reason`` (what failed) and
    ``instructions`` (operator action to fix). Both flow into the
    WARNING and the per-output-dir marker so audit operators can
    diagnose without cross-referencing source.
    """
    if b_fallback_reason:
        return (b_fallback_reason, b_fallback_instr)
    if sys.platform == "darwin":
        # macOS path. The only spawn-disabling host condition on
        # darwin is sandbox-exec being missing or smoke-test-failing
        # (pass_fds / input= are plumbed natively by the
        # subprocess-backed macOS spawn and never disqualify there).
        if not check_seatbelt_available():
            return (
                ("macOS sandbox-exec is unavailable (smoke test "
                "failed or /usr/bin/sandbox-exec missing)"),
                ("verify `sandbox-exec -p '(version 1)(allow default)' "
                "/usr/bin/true` succeeds on this host; reinstall "
                "Command Line Tools if missing."),
            )
    elif not check_mount_available():
        # Pre-fix this branch hardcoded the AppArmor diagnostic — but
        # ``check_mount_available()`` can fail for at least four
        # distinct reasons (AppArmor sysctl, missing uidmap binaries,
        # SELinux enforcing, outer seccomp / nested userns), each with
        # its own remediation. Misattributing to AppArmor on a
        # SELinux-using host sent operators chasing the wrong sysctl
        # entirely. Route to ``mount_unavailable_reason()`` which
        # re-probes the specific conditions in priority order and
        # returns a routed ``(condition, fix)``.
        from .probes import mount_unavailable_reason
        return mount_unavailable_reason()
    if sys.platform != "darwin" and kwargs.get("pass_fds"):
        return (
            "call uses pass_fds= which the Linux spawn chain doesn't "
            "plumb through",
            ("rework the caller to avoid pass_fds or accept that this "
            "call won't audit"),
        )
    if sys.platform != "darwin" and kwargs.get("input") is not None:
        return (
            "call uses input= which the Linux spawn chain doesn't "
            "plumb through",
            ("pipe via stdin= instead of input=, or accept that this "
            "call won't audit"),
        )
    if not (target or output):
        # Common case: callers that pass audit_run_dir= alone for
        # audit-signal routing but no target/output for filesystem
        # isolation (codeql analyze, helper subprocesses).
        return (
            ("call has no target= or output= — mount-ns has nothing "
            "to bind-mount, so the tracer can't attach"),
            ("pass target=<repo_path> and/or output=<run_dir> for "
            "full mount-ns isolation + audit, or accept that this "
            "call runs at Landlock-only."),
        )
    # Reachable only if a future change adds a spawn-eligibility gate
    # without updating this helper. Better than lying with a specific
    # message; the docstring above tells the reader to update both.
    return (
        "spawn-path unavailable for this call (unknown reason)",
        ("inspect core/sandbox/context.py spawn_eligible determination "
        "and update _audit_degrade_reason with the new branch."),
    )


# Serialises seq assignment across concurrent sandbox() exits in one
# process: two writers counting the same file then appending would
# mint duplicate sequence numbers and read as tampering at triage.
_PROXY_PERSIST_LOCK = threading.Lock()


def _sweep_marked_processes(token: str) -> list:
    """SIGKILL every process whose environment carries this run's
    marker (`_SBX_RUN_ID=<token>`).

    Backstop teardown for the no-namespace path: the in-line subreaper
    sweeper (preexec._reaper_split) catches orphans while it lives,
    but a subprocess timeout kills the sweeper itself (Popen.pid) —
    this parent-side pass then reaps the marked survivors. Two passes,
    because a dying daemon can fork once more between scan and kill.
    Only same-uid processes are readable in /proc, and the token is a
    per-run random UUID, so a false-positive kill requires the exact
    128-bit value in a foreign process env. Returns the pids killed.
    """
    needle = f"_SBX_RUN_ID={token}".encode()
    me = os.getpid()
    killed: list = []
    for _pass in range(2):
        found = False
        try:
            names = os.listdir("/proc")
        except OSError:
            return killed
        for name in names:
            if not name.isdigit() or int(name) == me:
                continue
            try:
                with open(f"/proc/{name}/environ", "rb") as f:
                    env_blob = f.read(1024 * 1024)
            except OSError:
                continue
            if needle not in env_blob:
                continue
            found = True
            try:
                os.kill(int(name), signal.SIGKILL)
                killed.append(int(name))
            except OSError:
                continue
        if not found:
            break
        time.sleep(0.05)
    if killed:
        logger.warning(
            "Sandbox: teardown backstop killed %d marked survivor(s) "
            "on the no-namespace path: %s", len(killed), killed,
        )
    return killed


# Grace window for the teardown-first timeout below: how long the
# sweeper gets to reap its subtree after the death-pipe EOF before the
# parent falls back to SIGKILL. Sized above preexec._SWEEP_DEADLINE_S
# so a healthy sweeper always finishes on its own.
_TEARDOWN_SWEEP_GRACE_S = 3.0


def _run_teardown_first_timeout(
    cmd: list, pk: dict, death_w_holder: list, start_new_session: bool,
) -> subprocess.CompletedProcess:
    """subprocess.run equivalent whose TIMEOUT tears down sweeper-first.

    No-pid-namespace posture only (see the call site): the direct
    child is the PR_SET_CHILD_SUBREAPER sweeper and the target is its
    child. subprocess.run's own timeout handling SIGKILLs the direct
    child — killing the sweeper before it can sweep, so a timed-out
    hostile target's descendants survived into the (weaker,
    marker-based) parent-side backstop. Here the deadline closes the
    per-run death pipe FIRST: the sweeper sees EOF, SIGKILLs the
    payload subtree (preexec._reaper_split), and exits on its own;
    only if it fails to exit within the grace window does the parent
    SIGKILL it. The subprocess.run contract is preserved: returns
    CompletedProcess on normal exit, raises subprocess.TimeoutExpired
    (with captured output) on deadline.

    Remaining arms of this posture, DOCUMENTED as the degraded
    envelope rather than fixed (the userns gate refuses namespace-less
    hosts without an explicit operator opt-in):

    * marker scrub — the parent-side backstop finds survivors via the
      ``_SBX_RUN_ID`` environ marker; a descendant that re-execs
      with a scrubbed environment is invisible to it. Inherent to
      marker-based sweeps; the pid-namespace cascade is the real
      containment and every namespace-capable host uses it.
    * sweeper killability — on Landlock ABI < 6 there is no signal
      scoping, so a hostile target can SIGKILL the same-UID sweeper
      before spawning daemons (the marker backstop then applies, with
      the scrub caveat above). Such runs are stamped
      ``teardown_sweep_signal_unscoped`` in ``sandbox_info`` — see
      the stamp block in run().
    """
    timeout = pk.pop("timeout", None)
    capture = pk.pop("capture_output", False)
    if capture:
        pk.setdefault("stdout", subprocess.PIPE)
        pk.setdefault("stderr", subprocess.PIPE)
    inp = pk.pop("input", None)
    if inp is not None:
        pk["stdin"] = subprocess.PIPE
    proc = subprocess.Popen(
        cmd, start_new_session=start_new_session, **pk,
    )
    try:
        out, err = proc.communicate(input=inp, timeout=timeout)
        return subprocess.CompletedProcess(
            cmd, proc.returncode, out, err,
        )
    except subprocess.TimeoutExpired:
        _death_w = death_w_holder[0]
        if _death_w is not None:
            death_w_holder[0] = None
            try:
                os.close(_death_w)
            except OSError:
                pass
        try:
            out, err = proc.communicate(
                timeout=_TEARDOWN_SWEEP_GRACE_S,
            )
        except subprocess.TimeoutExpired:
            logger.warning(
                "Sandbox: teardown-first sweep did not complete "
                "within %.1fs after the run timeout — killing the "
                "sweeper directly (marker backstop still runs).",
                _TEARDOWN_SWEEP_GRACE_S,
            )
            proc.kill()
            out, err = proc.communicate()
        raise subprocess.TimeoutExpired(
            cmd, timeout, output=out, stderr=err,
        )


# Byte ceiling for recounting the (target-writable) event log. A
# planted multi-GiB file must not serialize the parent's I/O under the
# persist lock; past the cap the recount aborts with the overflow flag
# set, which the sidecar carries as tamper evidence.
_RECOUNT_MAX_BYTES = 64 * 1024 * 1024


def _count_lines_bounded(path, max_bytes: int = _RECOUNT_MAX_BYTES):
    """``(newline_count, overflowed)`` of the existing event log, same
    open discipline as the writer (O_NOFOLLOW/O_NONBLOCK +
    fstat-regular); ``(0, False)`` on any refusal — a refused file
    also refuses the append below. ``overflowed`` is True when the
    file exceeded *max_bytes* and the count stopped early."""
    try:
        fd = os.open(str(path),
                     os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                     | os.O_CLOEXEC)
    except OSError:
        return 0, False
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return 0, False
        count = 0
        seen = 0
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                return count, False
            seen += len(chunk)
            count += chunk.count(b"\n")
            if seen > max_bytes:
                return count, True
    except OSError:
        return 0, False
    finally:
        os.close(fd)


# Per-path stream state for the proxy-events writer, guarded by
# _PROXY_PERSIST_LOCK: the authoritative next sequence number and the
# accumulated writer-side tamper flags. Parent memory is the
# out-of-band anchor the target cannot touch — deriving seq purely by
# recounting the target-writable file let a child truncate the suffix
# (or delete the whole file) between batches and have the next batch
# renumber contiguously over the erased history.
_PROXY_STREAM_STATE: dict = {}

# Cap on the count sidecar read-back (it is a ~200-byte JSON document;
# anything larger is a planted object).
_COUNT_SIDECAR_MAX_BYTES = 64 * 1024


def _read_proxy_count_sidecar(output, run_binding):
    """Load + verify the existing count sidecar.

    Returns ``(count, flags, invalid)``: ``count`` is the verified
    count (None when absent/unverifiable), ``flags`` the verified
    writer flags, ``invalid`` True when a sidecar file EXISTS but does
    not verify (tamper evidence in itself)."""
    from . import proxy as _proxy_mod
    from . import telemetry_mac as _tmac
    path = os.path.join(output, _proxy_mod.PROXY_EVENTS_COUNT_FILENAME)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                     | os.O_CLOEXEC)
    except FileNotFoundError:
        return None, set(), False
    except OSError:
        return None, set(), True
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None, set(), True
        raw = os.read(fd, _COUNT_SIDECAR_MAX_BYTES + 1)
    except OSError:
        return None, set(), True
    finally:
        os.close(fd)
    if len(raw) > _COUNT_SIDECAR_MAX_BYTES:
        return None, set(), True
    import json as _json
    try:
        data = _json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None, set(), True
    if not isinstance(data, dict):
        return None, set(), True
    count = data.get("count")
    flags = data.get("flags") or []
    token = data.get("mac")
    fields = _tmac.proxy_events_count_fields(count, flags, run_binding)
    if not (isinstance(count, int) and count >= 0
            and _tmac.verify(fields, token)):
        return None, set(), True
    return count, {str(f) for f in flags}, False


def _write_proxy_count_sidecar(output, count, flags, run_binding):
    """Atomically persist the MAC'd count sidecar (temp + rename).

    Skipped when no token can be minted (no usable key): an unstamped
    sidecar carries no authority, and its absence is the consistent
    legacy shape. Never raises — sidecar persistence must not break
    the caller."""
    from . import proxy as _proxy_mod
    from . import telemetry_mac as _tmac
    # Parent-memory mirror FIRST (out of the target's reach and not
    # dependent on a mintable token): the sidecar closes suffix/whole
    # truncation of the EVENTS file, but a target that erases BOTH
    # artifacts leaves nothing on disk — in-lifecycle triage then
    # consults this record (summary.get_proxy_persist_state) instead
    # of reading the run as telemetry-free. Strictly one-way: the
    # record condemns shortened/erased streams, never excuses.
    try:
        from . import summary as _summary_pm
        _summary_pm.record_proxy_persist_state(
            Path(output), expected_count=int(count),
            flags=sorted(str(f) for f in flags))
    except Exception:  # noqa: BLE001 — accounting is best-effort
        logger.debug("proxy persist accounting failed", exc_info=True)
    token = _tmac.mint(_tmac.proxy_events_count_fields(
        count, flags, run_binding))
    if not token:
        return
    import json as _json
    payload = _json.dumps({
        "count": int(count),
        "flags": sorted(str(f) for f in flags),
        "mac": token,
    })
    path = os.path.join(output, _proxy_mod.PROXY_EVENTS_COUNT_FILENAME)
    tmp = f"{path}.tmp.{os.getpid()}"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | os.O_CLOEXEC, 0o600)
        try:
            os.write(fd, payload.encode("utf-8"))
            # fsync before the rename: a power loss between replace
            # and writeback must not surface a zero-length/garbage
            # sidecar (which reads as count_sidecar_invalid — a
            # tamper flag — on the next honest batch).
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except OSError:
        logger.debug("Sandbox: could not write %s", path, exc_info=True)
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _persist_proxy_events(
    events,
    *,
    output,
    target=None,
) -> None:
    """Append proxy events to ``<output>/proxy-events.jsonl``.

    Safe-open machinery (O_NOFOLLOW + O_NONBLOCK + ``fstat`` regular-
    file check, plus the target-pollution skip) is shared between
    two callers in this module:

      * Per-spawn write inside ``_run()`` — fires after each
        sandboxed subprocess completes, capturing that spawn's
        proxy-event slice as soon as the spawn returns.
      * Block-level write inside ``sandbox()`` ``__exit__`` —
        captures events recorded against the block token (i.e.,
        from non-subprocess HTTPClient calls inside the with-
        block, such as ``agent.py`` running ``analyse()`` in-
        process). Caller pre-dedups against per-spawn events so a
        single ``proxy-events.jsonl`` doesn't carry duplicates of
        what the per-spawn writes already persisted.

    No-op when:
      * ``events`` is empty (no payload to write).
      * ``output`` is ``None`` (no persistence target configured).
      * ``output`` resolves inside ``target`` (target-pollution
        skip — some callers pass ``output=target`` for writable
        Landlock surface; persisting the JSONL there would
        pollute the scanned tree).

    Non-fatal on every write failure. Observability is nice-to-
    have, not a reason to break the caller — the write failure
    surfaces in a DEBUG log line so operators investigating
    missing audit data can find the cause.
    """
    if not events or not output:
        return

    # Target-pollution skip: if the persistence target is inside
    # the scanned tree, drop the write. See per-spawn site for
    # the original rationale.
    if target:
        try:
            _norm_out = os.path.realpath(output)
            _norm_tgt = os.path.realpath(target)
            if _norm_out == _norm_tgt or _norm_out.startswith(
                _norm_tgt + os.sep
            ):
                logger.debug(
                    "Sandbox: output (%s) lies within target (%s); "
                    "skipping proxy-events.jsonl persistence to "
                    "avoid polluting the scanned tree (in-memory "
                    "events unaffected)", _norm_out, _norm_tgt,
                )
                return
        except OSError:
            # ``realpath`` raised — likely a dangling component.
            # Fall through to the write attempt rather than break
            # the scan over an observability check.
            pass

    from . import proxy as _proxy_mod
    from . import telemetry_mac as _tmac
    _log_path = os.path.join(output, _proxy_mod.PROXY_EVENTS_FILENAME)
    _run_binding = _tmac.run_binding(output)
    _persist_lock = _PROXY_PERSIST_LOCK
    _persist_lock.acquire()
    _state = _PROXY_STREAM_STATE.setdefault(
        os.path.realpath(_log_path), {"next_seq": None, "flags": set()},
    )
    try:
        # Opened with O_NOFOLLOW + O_NONBLOCK so a child-planted
        # symlink (→ ~/.ssh/authorized_keys etc.) can't redirect
        # the write outside the sandbox boundary, and a child-
        # planted FIFO without a reader can't hang the parent.
        # fstat S_ISREG below confirms we got a regular file and
        # not, e.g., a TTY device the child pre-opened.
        _log_fd = os.open(
            _log_path,
            os.O_WRONLY | os.O_APPEND | os.O_CREAT
            | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            0o600,
        )
    except OSError as _log_err:
        logger.debug(
            "Sandbox: could not open %s for proxy-event "
            "persistence: %s", _log_path, _log_err,
        )
        # A planted symlink/FIFO at the events path used to suppress
        # evidence with only this DEBUG line. Record it as a
        # MAC-bound tamper flag in the count sidecar (whose atomic
        # rename is not affected by the planted object) so triage
        # fails toward suspicious instead of clean.
        # try/finally like the main-path branch below: an exception
        # from the sidecar read/write here used to leak the persist
        # lock, deadlocking ALL future proxy-event persistence in
        # this process.
        try:
            _state["flags"].add("persist_open_failure")
            _count = _state["next_seq"]
            if _count is None:
                _count = _read_proxy_count_sidecar(
                    output, _run_binding)[0] or 0
            _write_proxy_count_sidecar(
                output, _count, _state["flags"], _run_binding)
        finally:
            _persist_lock.release()
        return
    _fd_owned = True
    try:
        _log_st = os.fstat(_log_fd)
        if not stat.S_ISREG(_log_st.st_mode):
            logger.debug(
                "Sandbox: %s exists but is not a regular file "
                "(mode=0o%o); skipping proxy event persistence",
                _log_path, _log_st.st_mode,
            )
            os.close(_log_fd)
            _fd_owned = False
            # Same tamper class as the open failure above.
            _state["flags"].add("persist_open_failure")
            _count = _state["next_seq"]
            if _count is None:
                _count = _read_proxy_count_sidecar(
                    output, _run_binding)[0] or 0
            _write_proxy_count_sidecar(
                output, _count, _state["flags"], _run_binding)
            return
        # Clear O_NONBLOCK for the actual append: only needed to
        # stop a FIFO-open hang at the os.open() above; on a
        # regular file it's harmless but pointless.
        import fcntl as _fcntl
        _flags = _fcntl.fcntl(_log_fd, _fcntl.F_GETFL)
        _fcntl.fcntl(_log_fd, _fcntl.F_SETFL, _flags & ~os.O_NONBLOCK)
        import json as _json

        # Sequence base: the max of the (bounded) file recount, the
        # verified count sidecar, and this process's own counter.
        # Parent memory and the MAC'd sidecar are the out-of-band
        # anchors: deriving seq from the recount alone let a child
        # truncate the SUFFIX (or delete the whole file) between
        # batches and have the next batch renumber contiguously over
        # the erased history — fully verifying, history silently
        # gone. When the recount comes up short the erased range
        # stays un-renumbered (the verifier sees the gap) and the
        # sidecar carries an explicit MAC-bound flag.
        _recount, _overflowed = _count_lines_bounded(_log_path)
        _side_count, _side_flags, _side_invalid = (
            _read_proxy_count_sidecar(output, _run_binding))
        _state["flags"] |= _side_flags
        if _side_invalid:
            _state["flags"].add("count_sidecar_invalid")
        _anchored = (_side_count is not None
                     or _state["next_seq"] is not None)
        if _overflowed and not _anchored:
            # A >cap events file with NO anchor (no parent memory, no
            # verified sidecar): our writer would have left a sidecar,
            # so this is a planted/foreign stream — tamper-flagged.
            # ANCHORED runs never flag here: the seq base comes from
            # the anchor, the aborted recount is merely unusable for
            # writer-side truncation detection, and the read-side
            # count check still catches erasures — an honest, very
            # chatty (>cap) run stays clean.
            _state["flags"].add("recount_overflow")
        _seq_start = max(
            _recount,
            _side_count or 0,
            _state["next_seq"] or 0,
        )
        if not _overflowed and _recount < _seq_start:
            _state["flags"].add("stream_truncated")
        with os.fdopen(_log_fd, "a", encoding="utf-8") as _f:
            _fd_owned = False  # fdopen took ownership
            _written = 0
            for _i, e in enumerate(events):
                # Provenance stamp: triage verifies this token before
                # letting the event drive a verdict — the target can
                # append to this file mid-run (it holds Landlock write
                # on `output`), and an unstampable environment (no
                # usable key) degrades to the legacy unstamped shape
                # triage already accepts with a caveat. ``seq`` rides
                # inside the MAC so deleting stamped lines leaves a
                # detectable gap.
                stamped = {**e, "seq": _seq_start + _i}
                token = _tmac.mint(_tmac.proxy_event_fields(
                    stamped, run=_run_binding))
                line = {**stamped, "mac": token} if token else e
                _f.write(_json.dumps(line) + "\n")
                _written += 1
        _state["next_seq"] = _seq_start + _written
        # Ordering note (inherent two-file window): events append
        # first, sidecar second. A crash between the two leaves
        # survivors AHEAD of the sidecar count — the verifier fails
        # that shape toward suspicious but names it as the
        # interrupted-persist direction (distinct from truncation,
        # where survivors fall BEHIND the count).
        _write_proxy_count_sidecar(
            output, _state["next_seq"], _state["flags"], _run_binding)
    except BaseException as _persist_exc:
        # os.fdopen takes ownership on success; on any pre-fdopen
        # failure we still own the fd and must close.  Post-fdopen
        # the `with` block already closed it — a second os.close
        # would risk closing another thread's newly-opened fd.
        if _fd_owned:
            try:
                os.close(_log_fd)
            except OSError:
                pass
        if not isinstance(_persist_exc, Exception):
            raise
        # Demoted from raise → debug-log: persistence failure
        # shouldn't poison the caller, same posture as the open
        # failure above.
        logger.debug(
            "Sandbox: could not write proxy events to %s",
            _log_path, exc_info=True,
        )
    finally:
        _persist_lock.release()


def _cmd_visible_in_mount_tree(cmd, target, output, extra_paths) -> bool:
    """Check if cmd[0] resolves to a path visible inside the mount-ns
    bind tree.

    The mount-ns sandbox bind-mounts a fixed set of system directories
    (see core.sandbox.mount_ns._SYSTEM_RO_DIRS), plus target/output/
    /tmp (per-sandbox tmpfs replaces host /tmp), plus any extra
    readable/tool paths the caller supplied. Anything else is invisible
    inside the new rootfs — invoking it produces ENOENT (subprocess
    exit 127) with empty stderr.

    Returns True if cmd[0] resolves to a path within any bind-mount
    prefix, False otherwise. Returns True (don't trigger fallback) when
    cmd is empty or cmd[0] can't be resolved at all — in that case the
    subprocess will fail with the normal command-not-found error
    regardless of which path we take.
    """
    from .mount_ns import _SYSTEM_RO_DIRS
    if not cmd:
        return True
    cmd0 = cmd[0]
    # Resolve to absolute path. shutil.which honours $PATH for relative
    # invocations; for absolute or "./relative" paths it returns the
    # input unchanged if executable. Returns None if not findable.
    resolved = shutil.which(cmd0) or cmd0
    if not resolved or not os.path.isabs(resolved):
        # Can't determine — let the call proceed; the subprocess will
        # fail with a clear ENOENT if the binary doesn't exist anywhere.
        return True
    # Follow symlinks so we check the real binary path. A symlink at
    # /usr/local/bin/X → /home/USER/bin/X resolves to the home path
    # and would correctly fail the visibility check.
    abs_path = os.path.realpath(resolved)
    # System bind-mount prefixes (must match mount_ns._SYSTEM_RO_DIRS).
    # /tmp is the per-sandbox tmpfs — host /tmp content is NOT visible,
    # so a binary at /tmp/X would be invisible inside the sandbox; we
    # deliberately do NOT add /tmp to the visible list.
    for sysdir in _SYSTEM_RO_DIRS:
        prefix = f"/{sysdir}"
        if abs_path == prefix or abs_path.startswith(prefix + "/"):
            return True
    # target / output bind-mounts (visible at original absolute path).
    for d in (target, output):
        if d:
            d_abs = os.path.realpath(d)
            if abs_path == d_abs or abs_path.startswith(d_abs + "/"):
                return True
    # Caller-supplied extras (readable_paths + tool_paths union).
    for d in (extra_paths or []):
        if not d:
            continue
        d_abs = os.path.realpath(d)
        if abs_path == d_abs or abs_path.startswith(d_abs + "/"):
            return True
    return False


_UNSET = object()

# Containment tier each execution lane DELIVERS, keyed by the lane name
# used at its dispatch site (core/sandbox/tiers.py holds the lattice).
# The checked dispatch resolves its declared tier through this table so
# (a) the declaration is auditable in one place, (b) the "future lane"
# contract test can inject a below-floor lane and prove the assertion
# catches it, and (c) a lane routed through the chokepoint cannot ship
# without an explicit entry (KeyError fails closed) — while the AST
# executor gate in the contract tests forbids spawning a process in
# this module ANY other way, so the chokepoint cannot be routed
# around by a new bare call site either. Per-call caps
# (skip_pid_ns keeps host procfs on the mount lane; a Landlock-less
# kernel reduces the plain-subprocess lane to rlimits+seccomp) are
# applied at the call sites via the check's ``cap=``.
#
# The former "unshare-CLI subprocess" lane (NS_NOMOUNT via the
# unshare/prlimit/pid1-shim chain, HOST procfs visible) is deleted:
# every namespace-needing shape now routes through the modern spawn
# backend, whose Landlock-absent mode delivers the redefined
# NS_NOMOUNT tier (namespaces + FRESH procfs + seccomp) as a ``cap=``
# on the mountless lane rather than as a separate registry entry.
_LANE_TIERS: "dict[str, _tiers.ContainmentTier]" = {
    "seatbelt spawn": _tiers.ContainmentTier.SEATBELT,
    "mount-ns spawn": _tiers.ContainmentTier.MOUNT_NS,
    "mountless namespace backend": _tiers.ContainmentTier.MOUNTLESS_NS,
    "Landlock-only subprocess": _tiers.ContainmentTier.LANDLOCK_ONLY,
}

#: Per-file /etc grants substituted for the wholesale "/etc" read grant
#: under ``omit_etc_reads=True``: what the dynamic loader and TLS stacks
#: need to run a tool, and nothing that names the host or its users.
#: Missing entries are skipped at grant time (Landlock rules bind to
#: existing inodes).
_ETC_MINIMAL_READS: tuple[str, ...] = (
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/alternatives",
    # CA trust only — deliberately NOT the whole /etc/ssl, which would
    # include /etc/ssl/private (DAC-protected, but no business being
    # in the grant set at all).
    "/etc/ssl/certs",
    "/etc/ssl/openssl.cnf",
    "/etc/ca-certificates",
    "/etc/pki",
    "/etc/crypto-policies",
    "/etc/localtime",
)


@contextmanager
def sandbox(block_network=_UNSET, target: str | None = None, output: str | None = None,
            map_root: bool = False, limits: dict | None = None,
            allowed_tcp_ports: list | None = None, profile: str | None = None,
            disabled: bool = False,
            use_egress_proxy: bool = False, proxy_hosts: list | None = None,
            proxy_allowed_ports: list | None = None,
            restrict_reads=_UNSET, readable_paths: list | None = None,
            caller_label: str | None = None,
            fake_home=_UNSET,
            tool_paths: list | None = None,
            audit: bool = False, audit_verbose: bool = False,
            audit_run_dir: str | None = None,
            audit_required: bool = False,
            observe: bool = False,
            writable_paths: list | None = None,
            exclude_tmp_baseline: bool = False,
            sanitise_host_fingerprint: bool = False,
            cpu_count: int | None = None,
            require_sanitisation: bool = False,
            etc_overlay: dict | None = None,
            degraded_net_deny: bool = True,
            loopback_unix_bridges: dict | None = None,
            omit_proc_reads: bool = False,
            omit_etc_reads: bool = False,
            require_proxy_netns: bool = False,
            rootfs: str | None = None):
    """Context manager for sandboxed subprocess execution.

    Each run() call inside the context runs the target command with the
    isolation configured here. When `block_network=True`, mount
    isolation, or a read restriction is active, each run() launches its
    command through the fork-based spawn backend inside fresh user/pid/
    ipc/cgroup(+net) namespaces (with the pivot_root bind tree when
    target/output engage it, mountlessly otherwise); Landlock-only runs
    do NOT use namespaces and execute in the calling process's
    namespace (Landlock is applied in the child via preexec_fn).
    Resource rlimits always apply.

    Args:
        block_network: If True, block all network access via a fresh
                      network namespace. Overridden by profile=
                      and by --sandbox/--no-sandbox CLI flags.
        target: Path to target repo. Engages Landlock. Under Landlock, the
               path is an engagement marker only (Landlock does not restrict
               reads); under mount-namespace mode, it is bind-mounted read-
               only at its original absolute path inside the namespace.
        output: Path to output dir (always writable inside the sandbox).
               Engages Landlock and — when mount is active — bind-mounted
               writable at its original absolute path.
        map_root: Map current UID to root inside namespace (needed by some
                 builds that check `getuid() == 0`).
        limits: Resource limit overrides (memory_mb, max_file_mb, cpu_seconds).
        allowed_tcp_ports: If set, Landlock restricts TCP connect() to these
                          ports only (e.g. [443] for HTTPS API access).
                          Requires ABI v4 (kernel 6.7+); earlier kernels
                          emit a WARNING. Engages Landlock.

                          Landlock's network rule covers ONLY TCP connect().
                          UDP, raw sockets, and inbound TCP are NOT
                          restricted by this parameter — set
                          `block_network=True` for a hard network-off
                          policy (but then allowed_tcp_ports is useless
                          because the namespace removes all interfaces;
                          mixing the two produces a warning).
        profile: Named profile ('full', 'network-only', 'none'). Forces
                block_network to the profile's value AND — when the profile
                disables Landlock — nulls `target`, `output`, and
                `allowed_tcp_ports` (with a WARNING log if any were set).
                Unknown profile strings raise ValueError. Use --sandbox
                <profile> on the command line.
        disabled: Shortcut for `profile='none'`. All isolation off; only
                 rlimits apply. Kept as a separate param because its call
                 sites in code are easier to audit than an opaque profile
                 string.
        use_egress_proxy: If True, route the child's outbound HTTPS
                 traffic through a local HTTPS-CONNECT proxy with a
                 hostname allowlist. Enforcement is tiered (strongest
                 available wins): with netns capability the child runs
                 in an EMPTY network namespace (loopback up) and
                 reaches the proxy only via a unix-socket bridge —
                 DNS/UDP exfil is impossible topologically and no
                 seccomp UDP block is needed, so loopback-UDP tools
                 (gradle) work. Without netns, Landlock pins TCP
                 connect to the proxy port and seccomp blocks
                 AF_INET/AF_INET6 SOCK_DGRAM to close the DNS/UDP
                 exfil channel (gradle-class UDP-at-startup tools
                 break there). The child env is extended with
                 HTTPS_PROXY/http_proxy (both cases, for Node/curl/
                 Python AND CodeQL's Java stack). Pair with
                 `proxy_hosts=[...]` to declare the hostname
                 allowlist.
        proxy_allowed_ports: Destination-port allowlist for this
                 context's proxy lane (gate 1b, always enforcing).
                 None = any port (legacy behaviour). The networked
                 untrusted helper passes [443] to make its docstring
                 contract real — hostname authorisation alone would
                 let the child CONNECT to any 1-65535 service on an
                 allowlisted host.
        proxy_hosts: Hostname allowlist for the egress proxy. Union'd
                 with any existing allowlist if the proxy singleton is
                 already running. Required when use_egress_proxy=True.
        loopback_unix_bridges: Mapping of {port: unix_socket_path}
                 relayed inside the child's empty network namespace:
                 the child connects to 127.0.0.1:<port> and the
                 pre-Landlock relay forwards the bytes to the named
                 unix socket on the host. Requires
                 use_egress_proxy=True (ValueError) AND the netns
                 egress tier (SandboxSetupError when only the
                 Landlock/advisory tiers are available). When set, the
                 staged proxy env carries NO_PROXY=127.0.0.1,localhost
                 so bridged loopback traffic goes direct instead of
                 dying at the CONNECT proxy's loopback rejection.
        require_proxy_netns: Fail-closed switch for the egress tiers
                 (Linux only; inert on macOS): when True and
                 use_egress_proxy cannot engage the netns tier, raise
                 SandboxSetupError instead of degrading to the
                 port-scoped Landlock pin — which does not enforce the
                 hostname allowlist. RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1
                 is the operator override that accepts the weaker tier.
        restrict_reads: If True, flip Landlock's default "read everywhere"
                 to "read only in allowed paths". Defaults to a system-
                 dirs allowlist that covers what normal compiled binaries
                 need (libc, ld.so, /proc, /dev, target, output, /tmp)
                 but excludes $HOME — so a sandboxed attacker binary
                 can't read ~/.ssh, ~/.aws/credentials, ~/.config/raptor/
                 models.json. Extend with `readable_paths=[...]` if the
                 tool needs more.
        readable_paths: Extra read-allowed paths (adds to the default
                 system-dirs list when restrict_reads=True). Ignored
                 when restrict_reads=False (reads are already wide).
        tool_paths: Extra read-allowed directories for the TOOLCHAIN
                 being run — unioned with readable_paths into the
                 Landlock read allowlist and the mount-ns read-only
                 bind set, so a tool installed outside the system dirs
                 is visible and executable inside the sandbox. PATH
                 entries under a declared dir also survive the child
                 env's home-scrub (home-rooted PATH entries are
                 otherwise dropped), so a $HOME-resident toolchain
                 declared here resolves by name. A multi-dir toolchain
                 needs EVERY dir it execs through declared — rustup's
                 ~/.cargo/bin proxies re-exec ~/.rustup/toolchains/*,
                 so both dirs belong in the list.
                 Extended by the --sandbox-tool-path CLI flag. Callers
                 spawning user-local toolchains under strict/
                 restrict_reads need this (see
                 python_runtime_tool_paths()).
        writable_paths: Extra write-allowed paths (absolutized),
                 layered on top of the canonical writable surface
                 (output + the /tmp baseline). Use case: resolver
                 scratch dirs (~/.cache/pip, ~/.npm, ~/.m2) that live
                 outside the per-run output dir.
        exclude_tmp_baseline: If True, drop /tmp (and /dev/shm) from
                 the writable baseline so the child cannot write
                 ANYWHERE under /tmp (exploit-engine wrapper-script
                 defence). Only use when the sandboxed program is
                 known not to need /tmp to start — a normal python3
                 import writes pyc cache there.
        caller_label: Optional short identifier (e.g. "claude-sub-agent",
                 "codeql-pack-download") that propagates into proxy
                 event records. Used for per-caller filtering of
                 sandbox_info["proxy_events"] when multiple callers
                 share the proxy singleton.
        fake_home: If True, the child's HOME and XDG_*_HOME env vars
                 are overridden to point at `{output}/.home/` — an
                 empty directory created for this sandbox. Tools see a
                 fresh, credential-free home: `~/.ssh`, `~/.aws/...`,
                 `~/.config/gh/...` etc. are absent (not just EACCES
                 via Landlock — they don't exist). Complements
                 `restrict_reads=True` by converting the HOME-denial
                 from "Landlock blocks reads" into "there's nothing
                 there to read". Callers that need specific files
                 available in the fake HOME (e.g. an API-key config)
                 should pre-populate `{output}/.home/` before invoking.
                 Requires `output=` to be set. Defaults to True on
                 `run_untrusted()`, False on direct `sandbox()` use.
        audit: If True, engage the audit evidence channel for this
                 context's run() calls: a spawn-tier syscall tracer
                 records JSONL evidence under `<dir>/.audit` of the
                 audit target dir (audit_run_dir or output). Per-call
                 equivalent of the --audit CLI flag; silently no-ops
                 when the sandbox is effectively disabled.
        audit_verbose: Trace every syscall, not just those outside the
                 enforcement allowlist. Only takes effect when audit
                 mode is engaged; forced on by observe=True.
        audit_run_dir: Directory the audit tiers write evidence into
                 (they create only the `.audit/` subdir — the dir
                 itself must already exist and be writable, else
                 ValueError). Decouples "where audit JSONL goes" from
                 Landlock's output= restriction: pass it alone for
                 audit signal without a writable-path restriction.
                 When unset, audit falls back to output; audit mode
                 requires one of the two.
        observe: Observe mode — implies audit and audit_verbose,
                 writes to a separate observe JSONL, extends the trace
                 set with the stat family, and stamps a per-run
                 128-bit nonce into
                 result.sandbox_info["observe_nonce"] for
                 spoof-resistant parse_observe_log() parsing.
        audit_required: (default False) Fail-closed switch for the audit
                 evidence channel (precedent: `require_sanitisation`).
                 When True and audit mode is engaged for a run() call but
                 NO audit tier can attach (mount-ns/seatbelt spawn tracer
                 AND the Landlock-only tracer both unavailable or failed),
                 raise SandboxSetupError instead of degrading to an
                 unaudited subprocess — the command does not execute.
                 When False (default), degradation is permitted but is
                 always recorded: the per-run
                 ``sandbox-audit-degraded.json`` marker is written and
                 ``result.sandbox_info["audit_engaged"]`` is False. Inert
                 when audit mode is not engaged for the call.
        degraded_net_deny: (default True) When `block_network=True` was
                 requested but no namespace backend is available on this
                 host (Landlock-only degradation — Ubuntu 24.04+ AppArmor
                 userns default, SELinux, nested containers), fall back
                 to Landlock's TCP-connect deny (ABI v4+): every outbound
                 TCP connect fails with EACCES instead of silently running
                 with full host network. Loopback connects are denied too
                 (Landlock net rules are port-scoped, not address-scoped),
                 which breaks daemon-IPC tools; known offenders are nudged
                 to no-daemon mode via env (GRADLE_OPTS, NX_DAEMON). bind/
                 listen and UDP are untouched. When the degraded deny
                 cannot engage either (no Landlock ABI v4+ — which also
                 leaves an allowed_tcp_ports allowlist unenforceable on
                 this path), the context raises SandboxSetupError
                 rather than running with the demanded block silently
                 absent. On Linux with the default True, block_network=
                 True therefore always yields a deny layer, an enforced
                 port allowlist, or a refusal — never silently open
                 egress; the explicit acceptance levers are False here
                 (per call: a workload that genuinely needs loopback
                 TCP / egress on a degraded host) and
                 RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1 (host-wide, converts
                 the refusal to a loud warning). No effect when a
                 namespace backend is available or on macOS (whose
                 seatbelt lane has its own posture).
        omit_proc_reads: (default False) Remove `/proc` from the
                 default read allowlist computed under
                 `restrict_reads=True`. Set by `run_untrusted()` /
                 `run_untrusted_networked()` on hosts where the PID
                 namespace cannot engage (no unprivileged userns) and
                 the operator overrode the fail-closed refusal via
                 RAPTOR_ALLOW_DEGRADED_UNTRUSTED: without a pid-ns, a
                 compromised child in the HOST pid namespace can read
                 `/proc/<pid>/environ` of any same-UID process — the
                 credential-exfil channel the untrusted contract
                 exists to close. Cost: tools that read `/proc/self/*`
                 (ASAN, IFUNC dispatch, runtime CPU detection) fail
                 with EACCES; extend `readable_paths=` for specific
                 needs. Inert when `restrict_reads` is off (no read
                 allowlist exists).
        omit_etc_reads: (default False) Swap the wholesale `/etc` grant
                 in the `restrict_reads=True` read allowlist for the
                 minimal per-file set the loader and TLS stacks need
                 (`_ETC_MINIMAL_READS`: ld.so cache/conf, alternatives,
                 CA material, localtime). For callers whose payload has
                 no business enumerating host identity files
                 (`/etc/passwd`, `/etc/hosts`, `/etc/machine-id`, ...)
                 this holds on the Landlock-only tier too, where no
                 private mount view exists. Cost: anything else under
                 /etc reads as EACCES — extend `readable_paths=` for
                 specific needs. Inert when `restrict_reads` is off.
        sanitise_host_fingerprint: If True, build a host-fingerprint
                 persona once per context (synthetic cpuinfo etc.
                 bind-mounted over the real files, plus UTS/identity
                 and CPU-affinity changes) so the child sees a
                 sanitised host identity. Requires Linux, the mount-ns
                 backend, and at least one of target=/output=; when
                 any is missing it degrades to a one-shot WARNING (the
                 identity surfaces stay host-real) unless
                 require_sanitisation=True.
        cpu_count: CPU count the fingerprint persona claims (its
                 cpuinfo), default 4; set_cpu_affinity clamps to the
                 host's actual CPUs at apply time. Ignored with a
                 warning when sanitise_host_fingerprint=False.
        require_sanitisation: Fail-closed switch for the persona: when
                 True and sanitisation cannot engage (unsupported
                 platform, no mount-ns, no target/output), raise
                 RuntimeError instead of logging the degradation
                 warning. Also binds PER-RUN coverage: a per-overlay
                 bind failure or missing target inside the mount-ns
                 child aborts setup (instead of skip-and-continue),
                 and a mount-ns setup/exec failure raises
                 SandboxSetupError instead of degrading to the
                 Landlock-only fallback (which cannot apply the
                 persona at all).
        etc_overlay: Dict mapping in-sandbox /etc paths (e.g.
                 "/etc/sudoers") to host source files bind-mounted
                 over them during mount-ns init (mount-ns backend
                 only; non-str or missing-source entries are skipped
                 with a warning). Keys are also appended to the read
                 allowlist under restrict_reads=True.
        rootfs: Directory holding an unpacked container-image filesystem
                 (e.g. `docker create` + `docker export`). When set, the
                 mount namespace pivots into THAT tree instead of the
                 tmpfs-of-host-system-dirs — the command runs against
                 the image's own /usr, /lib, /etc with per-namespace
                 /dev, /proc, /sys, /tmp, /run on top, ns-local pids
                 (an in-process PID-1 waiter reaps and mirrors exit
                 status), and a subuid/subgid RANGE map so image
                 entrypoints can chown/setuid to non-root uids.
                 FAIL-CLOSED: rootfs requires the Linux mount-ns spawn
                 backend — every degradation that other calls tolerate
                 (Landlock-only fallback, seatbelt, profile 'none',
                 pass_fds/input kwargs) raises SandboxSetupError
                 instead, because "degraded" here means the command
                 would run against the HOST filesystem while the caller
                 believes it is containerised. The rootfs directory is
                 the sacrificial writable upper layer: the environment
                 writes into it host-side; treat it as consumed after
                 the run. target/output binds, readable_paths,
                 audit/observe, and network policy compose unchanged.

    Landlock activation: engaged when any of `target`, `output`, or
    `allowed_tcp_ports` is set. Default filesystem policy is read-
    everywhere, write-nowhere-except-`/tmp`-and-`output`. `target` and
    `output` are independent — you can pass either, both, or neither.

    Profiles:
        full:         network blocked + Landlock + seccomp + rlimits (default)
        strict:       full + fail-closed backend checks + restrict_reads
                      defaulted True (and fake_home when output= is set).
                      Explicit restrict_reads=/fake_home= kwargs override
                      the profile defaults. Callers spawning user-local
                      toolchains (pip --user, pyenv, ~/venv) under strict
                      must pass tool_paths=[...] (see
                      python_runtime_tool_paths()).
        debug:        full, but seccomp permits ptrace (for gdb/rr use cases
                      under /crash-analysis). All other seccomp blocks remain.
        network-only: network blocked + rlimits only (no Landlock, no seccomp)
        none:         rlimits only, no isolation
    """
    # Rootfs pre-flight: cheap shape errors raise here (caller bug,
    # ValueError); "the backend can't honour rootfs on this host/config"
    # raises SandboxSetupError at the use_mount decision below.
    if rootfs is not None:
        rootfs = os.path.abspath(rootfs)
        if not os.path.isdir(rootfs):
            msg = f"sandbox(rootfs=...): not a directory: {rootfs}"
            raise ValueError(msg)

    # Initialize seccomp from the default profile. When the caller passes
    # a specific `profile=`, the value below is overridden; otherwise we
    # apply the default full-seccomp blocklist as a safety default. This
    # is a behaviour change vs the pre-seccomp era: callers who relied on
    # AF_UNIX/ptrace/keyctl etc. must drop to `--sandbox network-only` or
    # `--sandbox none` to opt out (documented in the threat-model section).
    seccomp_profile = PROFILES[DEFAULT_PROFILE]["seccomp"] or None

    # Egress proxy setup — must happen before the Landlock / network
    # config decisions below, because it mutates them.
    #
    # When use_egress_proxy is set:
    #   1. Start/get the proxy singleton, register proxy_hosts.
    #   2. Force block_network=False (net-ns would make the loopback
    #      proxy unreachable) and set allowed_tcp_ports to [proxy.port]
    #      so Landlock's TCP allowlist pins TCP connects to the proxy.
    #   3. Enable the UDP block in seccomp (closes DNS/UDP exfil).
    #   4. Mark the env to receive HTTPS_PROXY/http_proxy at run-time
    #      (injected in run() once the env dict is finalised).
    # The proxy_* state is threaded through the `run()` closure below.
    proxy_instance = None
    # Audit-mode ref-count flags — initialised at function top so the
    # post-yield finally can reference them safely regardless of which
    # setup-path branches were taken.
    #   _will_engage_audit: decision made during setup ("audit will
    #     engage at yield-time"). Set inside the use_egress_proxy
    #     block when audit_mode is True.
    #   _engaging_audit: actually acquired the proxy ref-count. Set
    #     immediately before yield, after successful acquire. The
    #     post-yield finally checks this to decide whether to release.
    _will_engage_audit = False
    _engaging_audit = False
    proxy_env_overrides: dict = {}
    seccomp_block_udp = False

    # Audit-mode resolution. Three inputs:
    # 1. CLI flag (state._cli_sandbox_audit) — set by --audit
    # 2. Per-call kwarg (audit) — set by sandbox(audit=True)
    # 3. Effective enforcement: audit is incoherent without
    #    enforcement layers active. Per-call disabled=True OR CLI
    #    --no-sandbox / --sandbox none → no enforcement → audit
    #    silently no-ops (CLI form is validated at apply_cli_args
    #    entry; per-call form is silently demoted here so callers
    #    passing disabled=True without thinking about audit aren't
    #    surprised by a ValueError).
    #
    # We need to know "is the sandbox effectively disabled" BEFORE
    # acquiring the egress-proxy audit ref-count below — otherwise a
    # `sandbox(audit=True, disabled=True)` call would acquire the
    # ref-count without ever using audit, leaking the count if the
    # release path doesn't fire (which it does, but defensive).
    if state._cli_sandbox_profile is not None:
        _effectively_disabled = (state._cli_sandbox_profile == "none")
    elif profile is not None:
        _effectively_disabled = (profile == "none")
    else:
        _effectively_disabled = bool(disabled) or bool(state._cli_sandbox_disabled)
    # Observe mode is "audit + audit_verbose + write to a separate
    # JSONL file + extend the trace set with stat-family". Engaging
    # observe implies audit (TRACE action requires a tracer) and
    # audit_verbose (we want every traced syscall, not just the ones
    # outside an enforcement allowlist). Force both upstream so a
    # caller passing only observe=True gets coherent behaviour.
    audit_mode = (
        (bool(state._cli_sandbox_audit) or bool(audit) or bool(observe))
        and not _effectively_disabled
    )
    audit_verbose_active = (
        (bool(state._cli_sandbox_audit_verbose)
            or bool(audit_verbose)
            or bool(observe))
        and audit_mode
    )
    # Per-run observe nonce — 128 bits, generated up here so we can
    # both forward it to the spawn layer (which threads it into the
    # audit-config tempfile the tracer reads) AND retain it locally
    # to stamp `result.sandbox_info["observe_nonce"]` after each run
    # so the operator can pass it to parse_observe_log() for spoof-
    # resistant parsing. The audit-config tempfile lives in /tmp
    # outside the sandbox view, so a target binary cannot read the
    # nonce; the JSONL records the binary CAN read carry the nonce
    # but the binary can't reuse it without the parser noticing
    # (parser pins to the per-run nonce, not "any nonce on record").
    # None when observe is off.
    if observe and audit_mode:
        import secrets as _secrets
        nonlocal_observe_nonce = _secrets.token_hex(16)
    else:
        nonlocal_observe_nonce = None

    # NOTE on audit + output=None: validation deferred to spawn-time
    # (run_sandboxed) — sandbox() entry just stages config; tests and
    # programmatic users may construct a context purely to observe
    # ref-count wiring without ever calling run(), and we shouldn't
    # require output for those cases. When run() IS called and audit
    # is engaged with no output, spawn raises ValueError with a
    # clear "audit_mode=True requires audit_run_dir=" message.

    # Resolve profile-implied defaults for the _UNSET kwargs BEFORE the
    # fake-home setup below consumes fake_home (the authoritative
    # profile-override block further down runs too late for it). The
    # profile choice mirrors that block exactly: CLI wins, then
    # disabled, then the caller's profile=. Unknown profile strings
    # resolve to no implications here; the authoritative block still
    # raises ValueError for them.
    if state._cli_sandbox_profile is not None:
        _profile_for_defaults = state._cli_sandbox_profile
    elif disabled or state._cli_sandbox_disabled:
        _profile_for_defaults = "none"
    else:
        _profile_for_defaults = profile
    _profile_defaults: Mapping[str, object] = (
        PROFILES.get(_profile_for_defaults)
        if _profile_for_defaults else None
    ) or {}
    if restrict_reads is _UNSET:
        restrict_reads = bool(_profile_defaults.get("restrict_reads", False))
    if fake_home is _UNSET:
        # Profiles that imply restrict_reads imply the fake HOME too —
        # the EACCES-vs-ENOENT pairing (git and friends hard-fail on an
        # unreadable ~/.gitconfig but tolerate a missing one; verified
        # 2026-08-15 in the Landlock-only battery). Only when output=
        # is set: fake_home needs a writable location to materialise.
        fake_home = bool(_profile_defaults.get("restrict_reads", False)
                         and output)

    # Fake-HOME setup — create an empty home dir under `output` and
    # stage env overrides for the run() closure. Deferred to run-time
    # creation would add a race; we set up now so that Landlock's
    # writable_paths covers it. Requires output= so Landlock can write.
    fake_home_env: dict = {}
    if fake_home:
        if not output:
            msg = (
                "fake_home=True requires output= so the fake home "
                "directory is in a Landlock-writable location."
            )
            raise ValueError(msg)
        fake_home_path = os.path.join(output, ".home")
        # Symlink-TOCTOU defence. A sandboxed child has write access
        # to `output`; in a callsite that reuses `output` across
        # multiple sandbox() calls, an earlier child could have
        # deleted `.home` (plus its XDG subdirs — all empty after
        # initial creation) and replaced it with a symlink pointing
        # at a user-writable location outside `output`. Without this
        # check, the parent-side os.makedirs() below would follow the
        # symlink and create `.config`, `.cache`, `.local/share`,
        # `.local/state` inside the attacker-chosen directory (e.g.
        # under `~/.ssh`, `~/Documents`, a backup root) — a bounded
        # but real "write outside the sandbox" escape. We refuse to
        # proceed if any of the paths we would materialise is already
        # a symlink, forcing the caller to clean up `output` between
        # runs or use a fresh dir.
        _fake_home_paths = [
            fake_home_path,
            os.path.join(fake_home_path, ".config"),
            os.path.join(fake_home_path, ".cache"),
            os.path.join(fake_home_path, ".local"),
            os.path.join(fake_home_path, ".local", "share"),
            os.path.join(fake_home_path, ".local", "state"),
        ]
        for _p in _fake_home_paths:
            try:
                _st = os.lstat(_p)
            except FileNotFoundError:
                continue
            # Anything that's not a regular directory is suspect: a
            # prior sandboxed child could have replaced the expected
            # dir with a symlink (→ parent mkdirs into attacker-chosen
            # dir outside `output`), a FIFO (→ parent's chmod/stat
            # hangs), a socket, or a device node. Refuse to proceed.
            if not stat.S_ISDIR(_st.st_mode) or stat.S_ISLNK(_st.st_mode):
                msg = (
                    f"fake_home refuses to materialise: {_p!r} exists "
                    f"but is not a regular directory "
                    f"(mode=0o{_st.st_mode:o}). A prior sandboxed "
                    f"process may have replaced it to redirect "
                    f"parent-side file operations or cause a hang. "
                    f"Clean the output dir or use a fresh one."
                )
                raise ValueError(msg)
        os.makedirs(fake_home_path, mode=0o700, exist_ok=True)
        # Override HOME and the XDG base dirs so that tools which
        # resolve ~ or $XDG_CONFIG_HOME etc. land inside the fake
        # home. We deliberately DO NOT override XDG_RUNTIME_DIR —
        # that has system semantics (per-user tmpfs managed by
        # systemd-logind) and tools rarely need it for state.
        fake_home_env = {
            "HOME": fake_home_path,
            "XDG_CONFIG_HOME": os.path.join(fake_home_path, ".config"),
            "XDG_CACHE_HOME": os.path.join(fake_home_path, ".cache"),
            "XDG_DATA_HOME": os.path.join(fake_home_path, ".local", "share"),
            "XDG_STATE_HOME": os.path.join(fake_home_path, ".local", "state"),
            # Identity follows the fake home: a child that gets a
            # synthetic $HOME must not keep the operator's login name
            # — USER/LOGNAME are pure host-identity leaks to a target
            # that is being told it lives somewhere else. Tools that
            # need "a" user name still get one.
            "USER": "sandbox",
            "LOGNAME": "sandbox",
        }
        # Pre-create the XDG subdirs so tools that stat them first
        # (rather than mkdir-on-write) behave correctly.
        for xdg_dir in ("XDG_CONFIG_HOME", "XDG_CACHE_HOME",
                        "XDG_DATA_HOME", "XDG_STATE_HOME"):
            try:
                os.makedirs(fake_home_env[xdg_dir], mode=0o700, exist_ok=True)
            except OSError:
                pass

    # The launcher's per-session temp dir names the framework AND the
    # host (<base>/raptor-<uid>/session-<pid>-<rand>): a target that
    # reads $TMPDIR learns all three in one getenv, and the mount-ns
    # setup would even re-create that branded path inside the private
    # tmpfs. Point the temp vars at a run-scoped neutral dir instead
    # (mirrors the fake-home pattern; the output path is target-visible
    # by definition). Any framework-named /tmp//var/tmp value is
    # rewritten (an operator dir that happens to carry the name is
    # rewritten too — the NAME is the leak regardless of who minted
    # it); unbranded operator TMPDIRs pass through so nested test
    # harnesses that share temp files with the child keep working.
    for _tv in ("TMPDIR", "TEMP", "TMP"):
        _tval = os.environ.get(_tv, "")
        if (_tval.startswith(("/tmp/", "/var/tmp/"))
                and _BRANDED_TMP_RE.search(_tval)):
            # "/tmp" is the semantics the value would have had with no
            # override at all: the mount-ns lane serves a private
            # tmpfs there (where the unix-scope supervisor's pinned
            # device set expects pathname sockets like the Python
            # forkserver's to live), and the restricted Landlock-only
            # posture re-steers the temp vars to its private scratch
            # dir further down regardless.
            fake_home_env[_tv] = "/tmp"
    _use_proxy_netns = False
    _proxy_tcp_lane_port = None
    _proxy_unix_path: str | None = None
    _proxy_lane_dir: str | None = None
    _proxy_forwarder_port: int | None = None
    if loopback_unix_bridges and not use_egress_proxy:
        msg = (
            "loopback_unix_bridges requires use_egress_proxy=True — "
            "the bridge relay rides the netns egress tier."
        )
        raise ValueError(msg)
    if use_egress_proxy:
        if not proxy_hosts:
            msg = (
                "use_egress_proxy=True requires proxy_hosts=[...] "
                "— an empty allowlist would block every connection."
            )
            raise ValueError(msg)

        from . import proxy as _proxy_mod
        proxy_instance = _proxy_mod.get_proxy(proxy_hosts)

        # Decide enforcement path, strongest first.
        #
        # Tier 1 — netns bridge (any Landlock ABI; needs the SPAWN
        # backend): the child runs in an EMPTY netns (loopback
        # brought up by the spawn layer) and reaches the proxy only
        # through the forwarder that relays loopback TCP → unix
        # socket. Containment is topological: no interfaces, no
        # routes out, so DNS/UDP exfil is impossible WITHOUT the
        # seccomp UDP block — which means JVM tools that open a
        # loopback UDP socket before any build (gradle's
        # FileLockContentionHandler / local-IP detection) work here.
        # Previously this tier engaged only on ABI < 4 hosts; it is
        # strictly stronger than the Landlock pin (port-scoped to ANY
        # host) on every host, so it is the default whenever it can
        # actually engage.
        #
        # "Can actually engage" means more than netns capability: the
        # forwarder that bridges the empty netns to the proxy's unix
        # socket is forked by _spawn.run_sandboxed, and that backend
        # is only used when the mount-ns tier is live (use_mount —
        # see the backend selection below and `spawn_eligible`). On a
        # host with netns but WITHOUT the spawn backend (no uidmap
        # helpers, LSM-restricted unprivileged userns → the CLI
        # `unshare` fallback path), choosing this tier used to hand
        # the child an empty netns with NO forwarder: the proxy was
        # unreachable, every use_egress_proxy child silently lost all
        # network, and the proxy's audit stream recorded nothing.
        # Mirror use_mount's condition here so such hosts take Tier 2
        # — the tier the design assigns to "no netns" hosts, and the
        # tier they took before the netns default — keeping the
        # chokepoint reachable and its event telemetry live.
        #
        # Tier 2 — Landlock TCP pin (ABI >= 4, no netns bridge):
        # connect pinned to the proxy port + seccomp UDP block for
        # DNS/UDP exfil. Known cost: gradle-class UDP-at-startup
        # tools break ("Could not determine a usable local IP").
        #
        # Tier 3 — advisory (ABI < 4, no netns bridge): env vars only.
        _proxy_abi = (
            _get_landlock_abi() if check_landlock_available() else 0
        )
        _proxy_netns_capable = (
            sys.platform != "darwin" and check_net_available()
            # The forwarder rides the spawn backend: engaged only when
            # the mount-ns tier will be used for this context (same
            # condition as `use_mount` below, which cannot be computed
            # yet — `effectively_disabled` resolves after profile
            # parsing; a disabled sandbox never reaches enforcement).
            and bool(target or output) and check_mount_available()
        )
        if _proxy_netns_capable:
            _use_proxy_netns = True
            from .proxy import lane_socket_path, make_lane_dir
            # Per-instance PRIVATE lane directory, mode 0700 with a
            # random per-context name. The lane socket used to live in
            # the shared OUTPUT dir, where it was readdir-discoverable
            # and connectable by every process that shares the rw
            # bind: a sibling sandbox using the same output dir could
            # connect to THIS context's lane and have its CONNECTs
            # judged by THIS lane's allowlist and audit bit (cross-
            # context confused deputy), and the sandboxed child itself
            # could reach the lane directly through the rw bind. Only
            # the parent-side forwarder needs the socket — it snapshots
            # the HOST mount view before the child pivots — so the
            # socket needs no presence inside the sandbox at all.
            # make_lane_dir gives 0700 + a unique name AND a socket
            # path guaranteed to fit sun_path regardless of how deep
            # the ambient temp dir is; the SO_PEERCRED gate at the
            # proxy lane (see proxy._handle_unix_client) is the
            # enforcement backstop for same-uid processes that still
            # reach the inode.
            _proxy_lane_dir = make_lane_dir()
            _proxy_unix_path = lane_socket_path(_proxy_lane_dir)
            try:
                proxy_instance.bind_unix(
                    _proxy_unix_path,
                    label=caller_label or "sandbox",
                    # Scope this lane to THIS sandbox's hosts — the
                    # proxy's global allowlist is a union across
                    # concurrent runs (cross-run confused-deputy
                    # defence; gate 1 checks both) — and to the
                    # caller-declared destination ports (gate 1b).
                    allowed_hosts=proxy_hosts,
                    allowed_ports=proxy_allowed_ports,
                )
            except Exception as e:  # noqa: BLE001
                logger.warning(
                    "Sandbox: proxy unix socket bind failed (%s); "
                    "falling back to Landlock TCP pin%s", e,
                    "" if _proxy_abi >= 4 else
                    " — which is INERT on this kernel (Landlock ABI "
                    f"{_proxy_abi} < 4): egress allowlist is advisory "
                    "only",
                )
                _use_proxy_netns = False
                _proxy_unix_path = None
                if _proxy_lane_dir is not None:
                    import shutil as _shutil
                    _shutil.rmtree(_proxy_lane_dir, ignore_errors=True)
                    _proxy_lane_dir = None
        elif _proxy_abi < 4:
            logger.warning(
                "Sandbox: no netns bridge (netns capability or the "
                "mount-ns spawn backend is unavailable) AND Landlock "
                "ABI %d < 4 (no TCP allowlist) — egress proxy "
                "allowlist is advisory only on this host.",
                _proxy_abi,
            )

        # 00015: fail closed when an untrusted-egress caller requires
        # the netns tier but only the port-scoped Landlock tier is
        # available. On a Linux net-yes/mount-no host the child would
        # silently degrade to a Landlock port pin, where a direct
        # connect() on the proxy port reaches ANY host (the hostname
        # allowlist is bypassed). Refuse unless the operator explicitly
        # accepts the weaker tier.
        #
        # Scoped to non-darwin: this is the Linux Landlock Tier-2 gap.
        # macOS uses a different enforcement path (seatbelt SBPL, which
        # can express address-scoped loopback egress) where _use_proxy_netns
        # is always False, so an unscoped guard would wrongly refuse every
        # macOS untrusted-egress caller. macOS egress scoping is out of
        # this finding's scope and unchanged here.
        _degraded_ok = os.environ.get(
            'RAPTOR_ALLOW_DEGRADED_UNTRUSTED', '',
        ).strip().lower() in ('1', 'true', 'yes', 'on')
        if (
            sys.platform != 'darwin'
            and use_egress_proxy
            and require_proxy_netns
            and not _use_proxy_netns
            and not _degraded_ok
        ):
            from .errors import SandboxSetupError
            msg = (
                'use_egress_proxy with require_proxy_netns=True needs the '
                'netns egress tier, but it is unavailable on this host '
                '(mount-ns / user-ns capability missing). The port-scoped '
                'Landlock fallback does not enforce the hostname allowlist '
                '(a direct connect on the proxy port reaches any host). '
                'Install uidmap / enable unprivileged user namespaces to '
                'restore the netns tier, or set '
                'RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1 to accept the weaker tier.'
            )
            raise SandboxSetupError(msg)

        if _use_proxy_netns:
            # Netns enforcement: the child gets CLONE_NEWNET; the
            # forwarder bridges TCP on loopback → Unix socket.
            # Reuse the proxy's TCP port number for the forwarder
            # inside the empty netns — no collision because the netns
            # is fresh.
            _proxy_forwarder_port = proxy_instance.port
            if loopback_unix_bridges:
                # Caller-declared bridge ports are baked into the
                # child's env (base URLs) before this point, so THEY
                # cannot move — shift the forwarder port instead on
                # the (rare, ephemeral-port) collision. The netns is
                # fresh; any free port number serves the forwarder.
                while _proxy_forwarder_port in loopback_unix_bridges:
                    _proxy_forwarder_port += 1
            block_network = True
            allowed_tcp_ports = None
        else:
            # TCP-only path (ABI >= 4 or fallback).
            if block_network:
                logger.debug(
                    "Sandbox: use_egress_proxy=True overrides "
                    "block_network=True (net-ns would hide the "
                    "loopback proxy from the child)"
                )
                block_network = False
            if allowed_tcp_ports:
                logger.debug(
                    "Sandbox: use_egress_proxy=True overrides "
                    "allowed_tcp_ports=%s with proxy port",
                    allowed_tcp_ports,
                )
            # Dedicated per-context lane: attribution for the audit
            # decision, and the Landlock/SBPL pin keeps this context's
            # children off the shared main listener entirely. On bind
            # failure FAIL THE CONTEXT: the shared listener's gate 1
            # enforces the process-global UNION of every registered
            # context's hosts, so falling back there silently widens a
            # lane-failed context from its own allowlist to whatever
            # its concurrent siblings declared — and lane-bind failure
            # is plausibly forceable (fd/port exhaustion by a sibling
            # child). Mirrors the loopback_unix_bridges fail-closed
            # shape below; the caller decides whether to retry.
            try:
                _proxy_tcp_lane_port = proxy_instance.bind_tcp_lane(
                    label=caller_label or "sandbox",
                    # Same lane-scoping as the unix-socket tier above.
                    allowed_hosts=proxy_hosts,
                    allowed_ports=proxy_allowed_ports,
                )
            except Exception as _lane_exc:  # noqa: BLE001 — any bind failure is fail-closed
                from .errors import SandboxSetupError
                msg = (
                    "egress-proxy TCP lane bind failed for this "
                    "context — refusing to fall back to the shared "
                    "listener, whose connect gate enforces the union "
                    "of ALL registered contexts' allowlists rather "
                    "than this context's own. Free up local "
                    "ports/file descriptors and retry."
                )
                raise SandboxSetupError(msg) from _lane_exc
            allowed_tcp_ports = [_proxy_tcp_lane_port]
            # Operator-visible engagement notice for tier 2, once per
            # process (mirrors the tier-3 advisory warning above).
            # Pre-fix this tier engaged with only DEBUG lines, yet it
            # is a real weakening: Landlock's TCP rule is port-scoped,
            # not (host, port)-scoped, so the pin admits a connect to
            # ANY address that happens to listen on the pinned port —
            # only traffic that actually goes through the proxy gets
            # the hostname-allowlist gate. The ABI < 4 case is the
            # tier-3 advisory warning above; this one covers the
            # kernel that CAN pin (ABI >= 4) but only by port.
            if _proxy_abi >= 4 and state.warn_once(
                    "_proxy_tier2_port_pin_warned"):
                # The UDP-exfil closure on this tier IS the seccomp
                # block — on a libseccomp-less host the filter never
                # engages, and a message claiming the channel is
                # closed would be actively misleading about an open
                # DNS-exfil path. Word the message by what actually
                # engages.
                _udp_closed = _seccomp.check_seccomp_available()
                logger.warning(
                    "Sandbox: egress enforcement degraded to the "
                    "Landlock TCP port pin (tier 2 — no netns bridge "
                    "on this host). Landlock scopes TCP connect by "
                    "PORT only, so the child can reach ANY address "
                    "on port %d, not just the proxy — the hostname "
                    "allowlist applies only to connections that ride "
                    "the proxy. %s Enabling unprivileged user "
                    "namespaces restores the stronger netns tier.",
                    allowed_tcp_ports[0],
                    ("DNS/UDP exfil stays closed by the seccomp UDP "
                     "block." if _udp_closed else
                     "DNS/UDP exfil is OPEN on this host: the seccomp "
                     "UDP block cannot engage (libseccomp unavailable "
                     "or non-functional)."),
                )

        _will_engage_audit = bool(audit_mode)

        # UDP block only where containment needs it: on the netns tier
        # the empty namespace already contains UDP topologically (no
        # interfaces, no routes), and blocking UDP socket creation
        # there would only re-break loopback-UDP tools (gradle). On
        # the Landlock tier the block is what closes DNS/UDP exfil.
        seccomp_block_udp = not _use_proxy_netns

        # Caller-declared loopback bridges (LLM dispatcher for
        # credential-proxy CLI children) exist only on the netns tier —
        # the relay lives inside the child's fresh namespace. On the
        # Landlock/advisory tiers there is no namespace to host it and
        # binding on the HOST loopback would expose the bridged service
        # to every local process. Fail closed with a clear error; the
        # caller decides whether to fall back.
        if loopback_unix_bridges and not _use_proxy_netns:
            from .errors import SandboxSetupError
            msg = (
                "loopback_unix_bridges requires the netns egress tier "
                "(netns capability or the mount-ns spawn backend is "
                "unavailable on this host, or the proxy unix lane "
                "failed to bind) — refusing to run the child without "
                "its bridged loopback service."
            )
            raise SandboxSetupError(msg)
        # Bridged children must reach their loopback service DIRECT —
        # routing 127.0.0.1 through the CONNECT proxy would be denied
        # (gate 2 rejects loopback targets by design). Everything
        # non-loopback still routes through the chokepoint.
        _no_proxy_value = (
            "127.0.0.1,localhost" if loopback_unix_bridges else ""
        )

        _effective_proxy_port = (
            _proxy_forwarder_port
            if _use_proxy_netns
            else (_proxy_tcp_lane_port or proxy_instance.port)
        )
        proxy_url = f"http://127.0.0.1:{_effective_proxy_port}"
        proxy_env_overrides = {
            "HTTPS_PROXY": proxy_url, "https_proxy": proxy_url,
            "HTTP_PROXY": proxy_url, "http_proxy": proxy_url,
            "NO_PROXY": _no_proxy_value, "no_proxy": _no_proxy_value,
            # JVM tools (Maven, Gradle, sbt — NOT CodeQL, which reads
            # lowercase https_proxy itself) ignore proxy env entirely
            # and need java.net sysprops. JAVA_TOOL_OPTIONS is picked
            # up by every HotSpot JVM, including Gradle's daemon.
            # Empty nonProxyHosts mirrors NO_PROXY="" — nothing
            # bypasses the chokepoint (the JVM default would bypass
            # localhost/127.*, and direct TCP is blocked anyway).
            # The JVM prints "Picked up JAVA_TOOL_OPTIONS: ..." on
            # stderr; harmless, and the value contains no secrets.
            "JAVA_TOOL_OPTIONS": (
                f"-Dhttp.proxyHost=127.0.0.1"
                f" -Dhttp.proxyPort={_effective_proxy_port}"
                f" -Dhttps.proxyHost=127.0.0.1"
                f" -Dhttps.proxyPort={_effective_proxy_port}"
                f" -Dhttp.nonProxyHosts="
            ),
        }

    # Operator allowlist extensions (--sandbox-readable-path /
    # --sandbox-tool-path). Merged into the caller's kwargs here — once,
    # before any consumption — so every backend sees them uniformly:
    # the Linux Landlock preexec, the mount-ns extra read-only binds,
    # and the macOS SBPL read rules all read these two variables.
    # CLI-parsed values only (validated in cli.apply_cli_args); same
    # prompt-injection contract as the profile override below. Note
    # readable_paths still has effect only under restrict_reads=True —
    # the existing warning covers the no-op case.
    if state._cli_sandbox_readable_paths:
        readable_paths = list(readable_paths or []) + [
            p for p in state._cli_sandbox_readable_paths
            if p not in (readable_paths or [])
        ]
    if state._cli_sandbox_tool_paths:
        tool_paths = list(tool_paths or []) + [
            p for p in state._cli_sandbox_tool_paths
            if p not in (tool_paths or [])
        ]

    # Apply profile overrides. CLI flag is authoritative — it wins over
    # caller-supplied `profile=` AND caller-supplied `disabled=True`, so a
    # user's explicit --sandbox full / --sandbox none cannot be silently
    # undone by library code passing disabled=True.
    if state._cli_sandbox_profile is not None:
        profile = state._cli_sandbox_profile
        # effectively_disabled is derived from the CLI choice only — ignore
        # library's `disabled=` flag, since the user asked for a specific
        # profile.
        effectively_disabled = (profile == "none")
    else:
        effectively_disabled = disabled or state._cli_sandbox_disabled
        if effectively_disabled:
            profile = "none"
    if profile is not None:
        if profile not in PROFILES:
            msg = (
                f"Unknown sandbox profile {profile!r}. "
                f"Valid profiles: {sorted(PROFILES)}."
            )
            raise ValueError(msg)
        p = PROFILES[profile]
        if block_network is _UNSET:
            block_network = p["block_network"]
        seccomp_profile = p["seccomp"] or None
        if not p["use_landlock"]:
            # Profile forces Landlock off — warn if the caller handed us
            # Landlock-engaging args, they'd otherwise silently disappear.
            # Truthy check — `target=""` and `allowed_tcp_ports=[]` are
            # treated as "not set" everywhere else in this module; using
            # `is not None` here would spuriously warn about empty values.
            discarded = [name for name, val in (("target", target),
                                                 ("output", output),
                                                 ("allowed_tcp_ports", allowed_tcp_ports))
                         if val]
            if discarded and not effectively_disabled:
                logger.warning(
                    "Sandbox: profile=%r ignores %s — Landlock is disabled under this profile.", profile, discarded
                )
            target = None
            output = None
            allowed_tcp_ports = None
        if rootfs is not None and not p["use_landlock"]:
            # Rootfs fail-closed gate #0: 'none' and 'network-only'
            # are no-mount-ns-by-contract profiles. target/output are
            # silently DISCARDED above (warned, nulled) because they
            # are protection requests — dropping them weakens nothing
            # the profile promised. rootfs is different: it is the
            # EXECUTION SUBSTRATE ("run against this image tree"), and
            # discarding it would run the command against the host
            # filesystem while the caller believes it is containerised.
            # Raise instead — whichever of the caller kwarg / CLI
            # --sandbox flag chose this profile must be reconciled by
            # the operator, not silently overridden in either direction.
            from .errors import SandboxSetupError
            msg = (
                f"sandbox(rootfs=...) is incompatible with profile "
                f"{profile!r} (no mount namespace under this profile) "
                f"— refusing to run against the host filesystem."
            )
            raise SandboxSetupError(
                msg,
                "use profile 'full'/'strict'/'debug' (or drop the "
                "--sandbox override) for image-rootfs runs.",
            )
    if block_network is _UNSET:
        # Bare sandbox() (no profile=, no block_network=) follows the
        # documented default profile: 'full' blocks network. Seccomp
        # already seeds from DEFAULT_PROFILE above — letting network
        # silently fall OPEN here contradicted the docstring's
        # "full (default)" contract. Callers that genuinely want an
        # open-network sandbox say block_network=False explicitly.
        block_network = PROFILES[DEFAULT_PROFILE]["block_network"]
    strict_required = profile == "strict"
    # Explicitly disabled: no seccomp either (rlimits-only contract).
    if effectively_disabled:
        seccomp_profile = None
    # Backend selection. Linux uses mount-ns + Landlock + seccomp gated
    # on `check_net_available()` (the user-namespace foundation); macOS
    # uses sandbox-exec / SBPL gated on `check_seatbelt_available()`.
    # `use_sandbox` is the platform-aware "is some host-level isolation
    # backend live for this call" flag — without the per-platform gate
    # here, macOS would always see use_sandbox=False (no unshare
    # binary) and silently never engage seatbelt. Both `use_mount` and
    # `use_seatbelt` are derived from `use_sandbox` so the rest of the
    # module reads them uniformly. Truthy check on target/output
    # matches the rest of the module — empty string / empty list are
    # treated consistently as "not provided".
    if sys.platform == "darwin":
        use_sandbox = not effectively_disabled and check_seatbelt_available()
        use_mount = False
        use_seatbelt = use_sandbox
    else:
        use_sandbox = not effectively_disabled and check_net_available()
        use_mount = (use_sandbox and bool(target or output or rootfs)
                     and check_mount_available())
        use_seatbelt = False

    # Rootfs fail-closed gate #1 (context setup): rootfs is meaningless
    # without the Linux mount-ns backend — every other execution path
    # runs the command against the HOST filesystem, which for a caller
    # that asked for an image rootfs is a silent contract violation, not
    # a degradation. Covers: darwin/seatbelt, profile 'none'/disabled,
    # missing userns/mount capability.
    if rootfs is not None and not use_mount:
        from .errors import SandboxSetupError
        msg = (
            "sandbox(rootfs=...) requires the Linux mount-namespace "
            "backend, which cannot engage here (platform, profile "
            "'none'/disabled, or missing unprivileged-userns/mount "
            "capability) — refusing to run against the host filesystem."
        )
        raise SandboxSetupError(
            msg,
            "check `sysctl kernel.unprivileged_userns_clone` / AppArmor "
            "userns restrictions, and do not combine rootfs= with "
            "disabled=True or profile='none'.",
        )

    # Bare-run posture, named once per process: with NO target/output/
    # rootfs there is nothing for the mount namespace or Landlock to
    # anchor on, so the call gets network/rlimit/seccomp containment
    # and UNRESTRICTED filesystem access. Legitimate for network-only
    # tool invocations (pack downloads, wrapper probes); a caller
    # expecting filesystem confinement must pass target= or output=.
    if (use_sandbox and not use_seatbelt
            and not (target or output or rootfs)
            and state.warn_once("_bare_run_posture_warned")):
        logger.warning(
            "sandbox: run() without target=/output=/rootfs= applies "
            "no filesystem confinement (network/seccomp/rlimits only). "
            "Pass target= or output= if this call handles untrusted "
            "bytes. First caller: %s (warned once per process — later "
            "bare-run callers are not attributed).",
            _first_external_caller(),
        )

    # Degraded-mode network fallback. block_network=True is normally
    # enforced by the network namespace; when no namespace backend is
    # available (use_sandbox False — AppArmor userns sysctl, SELinux,
    # nested containers), the block previously evaporated to a one-shot
    # warning and the child ran with full host network. Landlock ABI v4+
    # can express "deny every TCP connect" with a handled-but-empty net
    # ruleset, restoring most of the intent: no TCP egress (EACCES), UDP
    # and bind/listen untouched (see the BIND_TCP design rationale).
    # Deliberately NOT engaged when the caller supplied their own
    # allowed_tcp_ports — that allowlist is already the network policy.
    # Loopback caveat: Landlock net rules are port-scoped, so the deny
    # hits self-loopback IPC too (gradle daemon et al.) — mitigated by
    # the env nudge in run() and the degraded_net_deny=False opt-out.
    _degraded_tcp_deny = False
    if (not effectively_disabled
            and degraded_net_deny
            and block_network
            and not use_sandbox):
        # darwin reaches this block too (pre-fix it was scoped
        # != "darwin", so a trusted block_network=True run on a
        # seatbelt-less Mac silently kept FULL host network behind the
        # once-per-process "Sandbox unavailable" warning — while
        # run()'s docstring promised the refusal). There is no
        # Landlock lane on darwin at all, so _ll_net_capable is
        # structurally False there and the flow lands on the same
        # fail-closed arm with the same two acceptance levers. This
        # is deliberately a capability-axis refusal in context, not a
        # tier: the floor lattice (tiers.py) orders CONTAINMENT
        # backends, and its design notes keep per-axis enforceability
        # (Landlock ABI, seccomp presence, network layers) as refusal
        # conditions here, never tiers.
        _ll_net_capable = (sys.platform != "darwin"
                           and check_landlock_available()
                           and _get_landlock_abi() >= 4)
        if _ll_net_capable and not allowed_tcp_ports:
            _degraded_tcp_deny = True
            if state.warn_once("_degraded_tcp_deny_warned"):
                logger.warning(
                    "Sandbox: block_network requested but no namespace "
                    "backend is available — falling back to Landlock "
                    "TCP-connect deny (all TCP connects fail with "
                    "EACCES, including loopback; bind/listen and UDP "
                    "are unaffected). Daemon-IPC tools are nudged to "
                    "no-daemon mode via env. Pass "
                    "degraded_net_deny=False to opt out for workloads "
                    "that need loopback TCP."
                )
        elif _ll_net_capable:
            # allowed_tcp_ports supplied: the port allowlist IS the
            # caller's network policy and Landlock (ABI v4+) enforces
            # it on this backend-less path — the deny-all lane would
            # break the allowlist. The block_network+allowed_tcp_ports
            # combination itself gets the dead-combo warning below.
            pass
        elif not strict_required:
            # Neither deny lane can engage: no namespace backend for
            # the interface-level block, no Landlock v4+ for the
            # degraded TCP-connect deny — and when allowed_tcp_ports
            # was supplied, no enforcement for that allowlist either
            # (Landlock TCP rules are an ABI v4+ feature). The caller
            # demanded a network policy; running with unrestricted
            # network after a one-shot warning made that policy
            # evaporate exactly on the hosts that can least afford it
            # (and only the FIRST such call even saw the warning).
            # Fail closed, with two explicit acceptance levers:
            #   * degraded_net_deny=False (per call, library callers)
            #     skips this whole block — "this run may egress";
            #   * RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1 (host-wide, the
            #     documented degraded-tier acceptance) converts the
            #     refusal into a loud warning naming what is being
            #     accepted.
            # strict defers to its own gate below so that one abort
            # names EVERY unmet strict requirement, this one included.
            if sys.platform == "darwin":
                from .probes import SEATBELT_FAIL_INSTRUCTIONS
                _no_layer_reason = (
                    "seatbelt (sandbox-exec) is unavailable on this "
                    "host and macOS has no fallback network-deny layer"
                )
                _no_layer_fix = SEATBELT_FAIL_INSTRUCTIONS
                _ports_clause = (
                    " The supplied allowed_tcp_ports allowlist is "
                    "equally unenforceable (the SBPL port rules need "
                    "the seatbelt backend)." if allowed_tcp_ports
                    else "")
            else:
                from .probes import ENGAGE_FAIL_INSTRUCTIONS
                _no_layer_reason = (
                    "no namespace backend is available on this host "
                    "AND Landlock ABI v4+ is missing"
                )
                _no_layer_fix = ENGAGE_FAIL_INSTRUCTIONS
                _ports_clause = (
                    " The supplied allowed_tcp_ports allowlist is "
                    "equally unenforceable (Landlock TCP rules need "
                    "ABI v4+)." if allowed_tcp_ports else "")
            _degraded_ok = os.environ.get(
                "RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "",
            ).strip().lower() in ("1", "true", "yes", "on")
            if _degraded_ok:
                if state.warn_once("_degraded_net_open_override_warned"):
                    logger.warning(
                        "Sandbox: block_network requested but %s — "
                        "RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1 accepts "
                        "running with NETWORK UNRESTRICTED on this "
                        "host%s.",
                        _no_layer_reason,
                        (" (the allowed_tcp_ports allowlist is "
                         "unenforced too)" if allowed_tcp_ports else ""),
                    )
            else:
                from .errors import SandboxSetupError
                raise SandboxSetupError(
                    "Sandbox: block_network=True was requested, but "
                    + _no_layer_reason + " — no layer can enforce "
                    "the requested network block." + _ports_clause,
                    _no_layer_fix + " Alternatively: choose "
                    "a profile without the network block when the "
                    "workload genuinely needs egress (e.g. `--sandbox "
                    "target_run`, which keeps filesystem confinement), "
                    "pass degraded_net_deny=False (library callers) to "
                    "accept an unrestricted-network run per call, or "
                    "set RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1 to accept "
                    "the degraded tier host-wide.",
                )

    # strict is fail-closed: it refuses to run rather than degrade. The
    # aborts raise SandboxSetupError (not RuntimeError) so (a) the
    # message carries the host-specific remediation alongside the
    # explicit-downgrade escape hatch, and (b) the BaseException
    # propagation + SANDBOX_ENGAGE_EXIT_CODE subprocess convention
    # apply — a strict abort inside a scanner child surfaces as
    # "isolation could not engage", never as a silent "0 findings".
    if strict_required:
        from .errors import SandboxSetupError
        if not use_sandbox and sys.platform == "darwin":
            msg = (
                "sandbox profile 'strict' requires the seatbelt "
                "backend, but sandbox-exec is unavailable or failed "
                "its smoke test on this host"
            )
            raise SandboxSetupError(
                msg,
                "verify /usr/bin/sandbox-exec exists and can run a "
                "minimal profile; or explicitly choose a profile "
                "that degrades gracefully (e.g. `--sandbox full`). "
                "RAPTOR will not silently downgrade for you.",
            )
        # Linux: collect EVERY unmet strict requirement before
        # raising. Constrained hosts frequently miss several at once
        # (no userns implies no mount-ns; minimal runners lack
        # libseccomp too), and raising on the first check hid the
        # rest — the operator fixed one gate only to hit the next
        # run-through, and the later gates' diagnostics were
        # unobservable wherever an earlier gate also fired. One
        # abort names everything missing.
        unmet: list[tuple[str, str]] = []
        if not use_sandbox:
            from .probes import ENGAGE_FAIL_INSTRUCTIONS
            unmet.append((
                "namespace isolation, but user namespaces are "
                "unavailable on this host",
                ENGAGE_FAIL_INSTRUCTIONS + " For profile 'strict' "
                "specifically, `--sandbox full` is the explicit "
                "step-down: it degrades to Landlock + seccomp with "
                "warnings instead of aborting.",
            ))
        if sys.platform != "darwin" and (target or output) and not use_mount:
            from .probes import mount_unavailable_reason
            condition, fix = mount_unavailable_reason()
            unmet.append((
                "mount-namespace isolation for target/output, "
                f"but {condition}",
                fix + " Or explicitly choose a profile that degrades "
                "gracefully (e.g. `--sandbox full`). RAPTOR will not "
                "silently downgrade for you.",
            ))
        # strict's resolved profile requests a seccomp filter; when
        # libseccomp is absent/broken the filter builder returns None
        # and both spawn paths silently run FILTERLESS — the AF_UNIX
        # blocklist, the io_uring/keyring/bpf blocks and the UDP
        # block all vanish under a profile sold as fail-closed. The
        # engagement report mentioned it; nothing aborted. Require a
        # working libseccomp up front, like the namespace/mount gates
        # above.
        if (sys.platform != "darwin" and seccomp_profile
                and not _seccomp.check_seccomp_available()):
            unmet.append((
                "a seccomp filter, but libseccomp is unavailable or "
                "non-functional on this host — the syscall blocklist "
                "would silently not engage",
                "install libseccomp (libseccomp2 package) so the "
                "filter can load, or explicitly choose a profile that "
                "degrades gracefully (e.g. `--sandbox full`). RAPTOR "
                "will not silently downgrade for you.",
            ))
        if len(unmet) == 1:
            raise SandboxSetupError(
                f"sandbox profile 'strict' requires {unmet[0][0]}",
                unmet[0][1],
            )
        if unmet:
            missing = "; ".join(
                f"({i}) {m}" for i, (m, _f) in enumerate(unmet, 1))
            fixes = " ".join(
                f"({i}) {f}" for i, (_m, f) in enumerate(unmet, 1))
            raise SandboxSetupError(
                f"sandbox profile 'strict' has {len(unmet)} unmet "
                f"requirements on this host — it requires {missing}",
                fixes,
            )

    if effectively_disabled and not state._cli_sandbox_disabled:
        logger.info("Sandbox disabled for this call")
    elif not use_sandbox:
        if state.warn_once("_sandbox_unavailable_warned"):
            logger.warning(
                "Sandbox unavailable — subprocesses run without namespace isolation"
            )
    elif sys.platform != "darwin" and use_sandbox and not use_mount and (target or output):  # noqa: SIM102
        # Linux Landlock-only mode: sandbox engaged but mount-ns
        # didn't (typically because unprivileged user namespaces are
        # disabled — Ubuntu 24.04+ ships with
        # ``kernel.apparmor_restrict_unprivileged_userns=1`` as the
        # default).  Without mount-ns, ``$HOME`` and the host's
        # ``/tmp`` are visible to the sandboxed child, and same-UID
        # ``/proc/<pid>/`` reads are not UID-remapped.  ``restrict_reads=True``
        # is the load-bearing defence in this mode.  See
        # ``core/security/THREAT_MODEL.md`` (invariant I2-(a)).
        if state.warn_once("_sandbox_landlock_only_warned"):
            # Pre-fix this warning hardcoded
            # "kernel.apparmor_restrict_unprivileged_userns=1" as the
            # likely cause. Operator on PR #777 hit this on a SELinux
            # + rootless-podman host where the AppArmor sysctl doesn't
            # exist — being told to flip a non-existent sysctl is
            # active misdirection. Route through ``mount_unavailable_
            # reason()`` (same helper the spawn-blockers branch uses)
            # so AppArmor / uidmap / SELinux / nested-userns all get
            # their own diagnostic instead of all collapsing to
            # "AppArmor".
            from .probes import mount_unavailable_reason
            _condition, _ = mount_unavailable_reason()
            logger.warning(
                "sandbox: running in Landlock-only mode — "
                "%s. Credential exfil is bounded only by Landlock; "
                "callers that dispatch LLM-driven sub-agents on "
                "hostile source should set restrict_reads=True. "
                "See core/security/THREAT_MODEL.md (I2-(a)).",
                _condition,
            )

    effective_limits = dict(_DEFAULT_LIMITS)
    effective_limits.update(_load_user_limits())  # User config overrides defaults
    if limits:
        effective_limits.update(limits)  # Caller overrides everything

    # Filesystem isolation: Landlock + (optional) mount namespace.
    # Landlock and mount-ns combine cleanly because the mount-ns path
    # engages via core.sandbox._spawn, which runs mount ops BEFORE
    # landlock_restrict_self — Landlock doesn't block them.
    # `writable_paths` from caller is layered on top of the canonical
    # writable surface (output + /tmp). Use case: SCA agents whose
    # resolver subprocesses (pip-compile, npm install
    # --package-lock-only, mvn dependency:resolve) need to write
    # into their own scratch dirs (~/.cache/pip, ~/.npm, ~/.m2)
    # outside the per-run output dir. Pre-fix the only way to
    # extend the surface was to add the path to `output`, which
    # broke Landlock's invariant that `output` is the canonical
    # write location. Naming `writable_paths` separately keeps
    # the canonical / extra distinction explicit.
    extra_writable_paths = list(writable_paths or [])
    writable_paths = None
    _private_scratch_dir: str | None = None
    # Per-CALL private scratch dirs minted when a mount-ns run is
    # demoted to the Landlock-only path mid-call (see the demotion
    # hardening in run()); cleaned up with the context.
    _demoted_scratch_dirs: list[str] = []
    if target or output or allowed_tcp_ports or extra_writable_paths:
        # ``/tmp`` is in the writable baseline so Python's pyc cache
        # and the C compiler's intermediate files survive. Callers that
        # specifically don't want a sandboxed child to be able to write
        # ANYWHERE under /tmp (e.g. the exploit-engine substrate, where
        # an LLM-emitted producer could otherwise rewrite the target
        # wrapper script at ``/tmp/compile-and-run-target-*/target``)
        # set ``exclude_tmp_baseline=True``. ONLY use this when you've
        # verified the sandboxed program doesn't need /tmp to start —
        # ``python3 -S`` exploits don't write pyc cache, but a normal
        # ``python3`` import will.
        import tempfile as _tempfile
        # Private scratch dir for the RESTRICTED Landlock-only posture.
        # In mount-ns mode /tmp and /dev/shm are per-sandbox tmpfs, so
        # granting them wholesale is private by construction. Without
        # the mount namespace they are the HOST-SHARED directories:
        # granting all of /tmp made a target repo living under /tmp
        # writable (scanned-tree self-modification despite a read-only
        # profile), and granting host /dev/shm handed the child a
        # cross-process plant/poison surface. When the caller asked for
        # the restricted posture (restrict_reads — the strict/untrusted
        # signal) on a host without mount-ns, swap the blanket grants
        # for a fresh 0700 per-context scratch dir and steer tools to
        # it via TMPDIR/TEMP/TMP (see the env staging in run()). Cost:
        # tools that write literal /tmp paths (ignoring TMPDIR) and
        # multiprocessing SemLock (needs /dev/shm) fail closed in this
        # posture — acceptable for untrusted/strict work, and the
        # mount-ns path keeps full /tmp semantics.
        _use_private_scratch = (
            sys.platform == "linux" and not use_seatbelt
            and restrict_reads and not use_mount
            and not effectively_disabled
        )
        if exclude_tmp_baseline:
            writable_paths = []
        elif _use_private_scratch:
            _private_scratch_dir = _tempfile.mkdtemp(
                prefix=".scr-")
            # The reaper lists this prefix; a sandboxed campaign
            # (uncapped fuzz durations) legitimately holds the dir
            # mtime-quiet past the age floor while its TMPDIR still
            # points here. The keepalive registration for the
            # context's lifetime happens adjacent to the try/finally
            # that unregisters it, NOT here — a setup failure in
            # between must not orphan a registration that would pin
            # the stray dir against reaping for the process lifetime.
            writable_paths = [_private_scratch_dir]
        else:
            writable_paths = [_tempfile.gettempdir()]
            # /dev/shm rides the scratch baseline for the same reason
            # as /tmp: POSIX shared memory and named semaphores
            # (sem_open/shm_open) are created there, and Python's
            # multiprocessing primitives (SemLock behind Queue/Lock)
            # fail with EPERM without it. In mount-ns mode this is the
            # per-sandbox private tmpfs, not the host's shm.
            if os.path.isdir("/dev/shm"):
                writable_paths.append("/dev/shm")
            # /dev/pts is deliberately NOT granted here: this list is
            # shared by every lane, and only the mount-ns spawn lane
            # serves a per-sandbox devpts — on the mountless retries
            # and the subprocess fallbacks /dev/pts is the HOST's pty
            # slaves (a write grant there hands sandboxed code the
            # operator's terminal). run_sandboxed adds the grant
            # itself, keyed on the lane actually building the mount
            # tree.
            # When TMPDIR points somewhere custom, ALSO keep /tmp in
            # the baseline: tools fall back to it (gcc's "Cannot
            # create temporary file in /tmp/" path), and in mount-ns
            # mode the private tmpfs lives at /tmp regardless of what
            # the host TMPDIR says. This is not a widening — with the
            # default TMPDIR the baseline IS /tmp; a custom TMPDIR
            # previously just broke that same posture.
            if os.path.realpath(_tempfile.gettempdir()) != "/tmp":
                writable_paths.append("/tmp")
        if output:
            # Absolutize: a relative path like "out/foo" fails Landlock
            # open in the mount-ns child after pivot_root (the new
            # rootfs has no `out/` directory) and triggers the
            # "sandbox: Landlock writable path could not be opened"
            # stderr line. The bind-mount fallback masks the failure
            # as a silent enforcement gap on writes to `output`.
            writable_paths.append(os.path.abspath(output))
        for extra in extra_writable_paths:
            writable_paths.append(os.path.abspath(extra))

    # Loud warnings when caller requested Landlock features but the kernel
    # does not actually support them — silent degradation here would mean
    # the caller thinks they have protection they don't. Throttled to once
    # per process since kernel capability is static and scan loops can
    # open many sandbox() contexts.

    # Dead combination: `block_network=True` removes all network interfaces
    # via the user namespace, so no TCP connection is reachable from the
    # sandbox regardless of what Landlock's allow-rule permits. Callers
    # mixing the two usually intend "block all network except 443" — that
    # intent requires `block_network=False` + allowed_tcp_ports=[443].
    if block_network and allowed_tcp_ports and not effectively_disabled:  # noqa: SIM102
        if state.warn_once("_net_and_tcp_allowlist_warned"):
            logger.warning(
                "Sandbox: block_network=True makes allowed_tcp_ports=%s unreachable — the namespace has no network interface for Landlock's TCP allow-rule to apply to. For a network allowlist, pass block_network=False.", allowed_tcp_ports
            )

    # Landlock's NET rules are the ONLY enforcement for
    # allowed_tcp_ports on Linux: mount-ns isolates the filesystem,
    # not TCP connect, and the netns backend is not engaged on
    # allowlist runs (allowed_tcp_ports implies reachable network).
    # The availability block below is rightly skipped when mount-ns
    # engages — but that skip also swallowed the ABI-v4 warning, so a
    # supplied port allowlist on an ABI < 4 kernel (5.13–6.6,
    # including LTS) ran silently unenforced exactly when everything
    # else looked healthy. Warn here for the mount-ns shape; the
    # non-mount shape warns inside the block below as before.
    # (block_network=True is excluded: that shape already gets the
    # more accurate dead-combo warning above — the namespace leaves no
    # interface for ANY allow-rule regardless of ABI.)
    if (not effectively_disabled and not use_seatbelt and use_mount
            and allowed_tcp_ports and not block_network
            and (not check_landlock_available()
                 or _get_landlock_abi() < 4)
            and state.warn_once("_landlock_warned_abi_v4")):
        logger.warning(
            "Sandbox: allowed_tcp_ports=%s requires Landlock ABI v4 "
            "(kernel 6.7+); current ABI is %s — the TCP allowlist is "
            "NOT enforced (mount-ns isolates the filesystem, not TCP "
            "connect). Pass block_network=True for a full network "
            "block, or upgrade the kernel.",
            allowed_tcp_ports,
            _get_landlock_abi() if check_landlock_available() else 0,
        )

    # Skip the entire Landlock-availability warning block on macOS:
    # seatbelt provides the equivalent enforcement (writable_paths,
    # readable_paths, allowed_tcp_ports all flow into the SBPL profile).
    # Without this gate, every macOS sandbox call would fire the
    # "Landlock unavailable" warning even when seatbelt is fully
    # engaged — confusing and Linux-flavoured.
    if (not effectively_disabled and not use_mount and not use_seatbelt
            and (target or output or allowed_tcp_ports
                 or restrict_reads or extra_writable_paths)):
        # restrict_reads is part of the declared policy too: a
        # read-restricted caller without target/output (possible under
        # skip-mount / helper shapes) would otherwise silently lose
        # its read restriction here instead of failing closed. So are
        # caller-supplied writable_paths extras — a write-scoping
        # request with nothing to enforce it used to slip past this
        # predicate and run silently unconfined.
        if not check_landlock_available():
            # Acceptance lever, mirroring the degraded-net-deny arm
            # above: RAPTOR_ALLOW_DEGRADED_UNTRUSTED is the documented
            # host-wide acceptance of degraded containment tiers, and
            # on a Landlock-less kernel it converts this refusal into
            # a loud warning so the namespace lanes can still serve
            # the workload — the modern spawn backend's ns-only tier
            # (namespaces + fresh procfs + seccomp, floor-checked at
            # dispatch) is what such a host has left, and refusing at
            # construction made that tier unreachable for exactly the
            # consented runs the waiver exists for. Filesystem-write /
            # TCP-port / read-allowlist policy is genuinely unenforced
            # under the acceptance, and the per-call floor comparison
            # still refuses every unconsented untrusted call.
            #
            # The acceptance follows the full consent chain (per-run
            # --sandbox-floor flag > project sandbox-floor setting >
            # the legacy env var): a floor at or below ns-only IS the
            # consent to run without the Landlock policy layer, from
            # whichever surface set it — and an explicitly RAISED
            # floor (flag/project mountless-ns or mount-ns) refuses
            # here even when the env waiver is set, because the
            # explicit surface wins in both directions. An explicit
            # BARE ("none") consents to nothing on this arm.
            _consent_floor, _consent_src = resolve_untrusted_floor()
            _degraded_ll_ok = (
                _tiers.ContainmentTier.LANDLOCK_ONLY
                <= _consent_floor
                <= _tiers.ContainmentTier.NS_NOMOUNT
            )
            if _degraded_ll_ok:
                if _consent_src == _tiers.FLOOR_SOURCE_ENV:
                    _ll_accept_surface = "RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1"
                elif _consent_src == _tiers.FLOOR_SOURCE_FLAG:
                    _ll_accept_surface = (
                        f"--sandbox-floor "
                        f"{_tiers.tier_label(_consent_floor)}")
                else:
                    _ll_accept_surface = (
                        f"the project sandbox-floor="
                        f"{_tiers.tier_label(_consent_floor)} setting")
                if state.warn_once("_degraded_landlock_override_warned"):
                    logger.warning(
                        "Sandbox: target/output/writable_paths/"
                        "allowed_tcp_ports/restrict_reads were set "
                        "but Landlock is unavailable on this kernel — "
                        "%s accepts "
                        "running WITHOUT filesystem-write/TCP/read "
                        "policy enforcement; namespace containment "
                        "(fresh procfs, pid/ipc/net isolation) still "
                        "applies where a namespace lane engages, and "
                        "the containment floor still gates every "
                        "dispatch.",
                        _ll_accept_surface,
                    )
            else:
                from .errors import SandboxSetupError
                msg = (
                    "Sandbox: target/output/writable_paths/"
                    "allowed_tcp_ports/restrict_reads were set but "
                    "Landlock is unavailable on this kernel — filesystem writes "
                    "and TCP ports would NOT be restricted."
                )
                _ll_fix = (
                    "Upgrade to kernel 5.13+ for Landlock, pass "
                    "--sandbox network-only to keep namespace/network isolation "
                    "without filesystem restriction, or --sandbox none to "
                    "disable all isolation. To accept running without "
                    "the Landlock policy layer, pass --sandbox-floor "
                    "ns-only (this run), set sandbox-floor via "
                    "/project set sandbox-floor ns-only (standing for "
                    "the project), or set "
                    "RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1 (host-wide)."
                )
                if _consent_src in (_tiers.FLOOR_SOURCE_FLAG,
                                    _tiers.FLOOR_SOURCE_PROJECT):
                    # Honesty rule: an explicitly pinned floor is not
                    # relaxed by the env var or a lower-precedence
                    # surface — say so instead of steering the
                    # operator at overrides that would lose.
                    _pin_surface = (
                        "--sandbox-floor" if _consent_src
                        == _tiers.FLOOR_SOURCE_FLAG
                        else "the project sandbox-floor setting")
                    if _consent_floor is _tiers.ContainmentTier.BARE:
                        _ll_fix += (
                            f" Note: {_pin_surface}=none is not a "
                            f"consentable floor — untrusted work "
                            f"never runs bare by consent; use "
                            f"--sandbox none / --no-sandbox for the "
                            f"operator-explicit sandbox-off."
                        )
                    else:
                        _ll_fix += (
                            f" Note: {_pin_surface} currently pins "
                            f"the floor at "
                            f"'{_tiers.tier_label(_consent_floor)}'"
                            f", which the env var and lower-"
                            f"precedence surfaces do not override — "
                            f"change that surface itself to consent."
                        )
                raise SandboxSetupError(msg, _ll_fix)
        else:
            abi = _get_landlock_abi()
            # Each ABI level adds a restriction mask bit. Warn once per
            # process when the kernel is below what we need — makes the
            # silent coverage gap visible to the operator.
            if allowed_tcp_ports and abi < 4 and state.warn_once("_landlock_warned_abi_v4"):
                logger.warning(
                    "Sandbox: allowed_tcp_ports=%s requires Landlock ABI v4 (kernel 6.7+); current ABI is %s — TCP allowlist is NOT enforced. Pass block_network=True for full network block, or upgrade the kernel.", allowed_tcp_ports, abi
                )
            if abi < 3 and state.warn_once("_landlock_warned_abi_v3"):
                logger.warning(
                    "Sandbox: Landlock ABI v3 (kernel 6.2+) adds TRUNCATE coverage; current ABI is %s — existing files outside the writable paths can still be truncated via O_TRUNC (though DAC may still block it).", abi
                )
            if abi < 2 and state.warn_once("_landlock_warned_abi_v2"):
                logger.warning(
                    "Sandbox: Landlock ABI v2 (kernel 5.19+) adds REFER coverage; current ABI is %s — cross-directory rename/hardlink is NOT blocked. A process with write access to /tmp can rename files across writable boundaries. Upgrade the kernel to close this.", abi
                )

    # Compute the effective read-allowlist when restrict_reads is on.
    # The default covers everything a statically-linked binary, gcc-built
    # ELF, or Python interpreter needs to start: libc via ld.so, system
    # headers (gcc -include), /proc/self/maps (ASAN, ptrace), /etc/ld.so.
    # cache, CA bundle under /etc/ssl. Everything else — critically
    # $HOME with its credentials — is denied.
    # target is added because read-everywhere callers use target=repo
    # as the "code being analysed" path. readable_paths extends the
    # defaults with caller-specific additions.
    #
    # /dev is DELIBERATELY NOT granted wholesale — doing so would include
    # /dev/shm, a tmpfs shared across all same-UID processes on the
    # host. A compromised sandboxed child could then read secrets another
    # app wrote to /dev/shm (e.g. gnome-keyring session tokens). On
    # hosts without mount-ns (Ubuntu 24.04 + AppArmor), this is the only
    # way to keep /dev/shm out of the child's read-scope. Specific /dev
    # files that are genuinely needed by tools (null/zero/random/urandom/
    # full/tty) are granted by the Landlock preexec as per-file rules
    # alongside the writable /dev/null. stdin/stdout/stderr resolve to
    # /proc/self/fd symlinks covered by the /proc grant.
    #
    # /proc is granted wholesale. Narrowing to /proc/self + specific
    # system-info files was attempted and reverted: Landlock rules
    # bind to specific inodes, and /proc/self at rule-creation time
    # resolves to the preexec child's pid-specific inode. When the
    # child then forks subprocesses (shell→command, make→cc, etc.),
    # each subprocess has a different pid and therefore a different
    # /proc/<pid>/ inode, not covered by the inherited rule. Tools
    # reading /proc/self/maps (ASAN, IFUNC resolvers, runtime CPU
    # detection) break. Accepted residual: in Landlock-only mode (no
    # PID namespace), a compromised child can read /proc/<host_pid>/
    # environ for same-UID host processes. run_untrusted() forces
    # block_network=True → PID namespace → host PIDs invisible inside
    # /proc — ON HOSTS WITH UNPRIVILEGED USERNS. On hosts without it
    # the namespace tier never engages, so run_untrusted() FAILS
    # CLOSED there instead of degrading (see
    # _require_userns_or_optin; RAPTOR_ALLOW_DEGRADED_UNTRUSTED is
    # the explicit operator override). Under that override the
    # whole-of-/proc grant — and with it the same-UID environ
    # channel — is withdrawn per call via omit_proc_reads; the
    # per-call warning at the run_untrusted entry names the tool
    # breakage this trades for.
    def _restricted_read_allowlist() -> list[str]:
        paths = [
            "/usr", "/lib", "/lib64", "/bin", "/sbin",
            "/etc", "/proc", "/sys",
        ]
        if omit_proc_reads:
            paths.remove("/proc")
        if omit_etc_reads:
            # Swap the wholesale /etc grant for the loader/TLS minimum.
            # Host-identity files (/etc/passwd, /etc/hosts,
            # /etc/machine-id, ...) stay denied — this matters most on
            # the Landlock-only tier, where no private mount view
            # narrows /etc for the child. Existing paths only:
            # Landlock rules bind to inodes and the preexec treats a
            # missing grant path as a setup failure.
            paths.remove("/etc")
            paths.extend(
                p for p in _ETC_MINIMAL_READS if os.path.exists(p))
        if target:
            paths.append(target)
        if readable_paths:
            paths.extend(readable_paths)
        if etc_overlay:
            for ns_path in etc_overlay:
                if isinstance(ns_path, str) and ns_path not in paths:
                    paths.append(ns_path)
        return paths

    effective_read_paths: list | None = None
    if restrict_reads:
        effective_read_paths = _restricted_read_allowlist()
    elif readable_paths:
        logger.warning(
            "Sandbox: readable_paths=%s ignored because restrict_reads=False "
            "(reads are unrestricted by default).",
            readable_paths,
        )

    _preexec_readable = list(effective_read_paths or []) if effective_read_paths else None
    if _preexec_readable is not None:
        for _tp in (tool_paths or []):
            if _tp and _tp not in _preexec_readable:
                _preexec_readable.append(_tp)

    # NPROC bound for the no-namespace path. The namespace paths count
    # RLIMIT_NPROC against the ns-local uid (nobody = zero pre-existing
    # processes) via the prlimit wrapper / grandchild setrlimit; the
    # Landlock-only subprocess path shares the HOST uid, where a flat
    # cap would count the operator's unrelated processes — so it
    # historically applied NO process bound at all and a fork bomb ran
    # to the host ceiling. Bound it relative to the current same-uid
    # process count instead: ceiling = count-at-setup + configured
    # nproc headroom. Growth is capped at the same budget the
    # namespace paths grant, without starving concurrent RAPTOR work.
    _host_nproc_cap = None
    # Teardown-sweep cell for the same no-namespace posture: the
    # composed preexec forks a PR_SET_CHILD_SUBREAPER sweeper that
    # SIGKILLs every surviving descendant (setsid daemons, SIGSTOP-
    # parked children, delayed writers) when the payload exits or the
    # per-run death pipe hits EOF. Namespace paths don't need it — the
    # pid-ns cascade kill is stronger. See preexec._reaper_split.
    #
    # The death-pipe slot is a threading.local, NOT a plain cell key:
    # the cell itself is shared by every run() inside this sandbox()
    # context, and a plain key let CONCURRENT run() calls overwrite
    # each other's fd between assignment and fork — run A's sweeper
    # then watched run B's pipe (spurious cross-run SIGKILL on B's
    # teardown, lost death watch for A). The fork inherits the calling
    # thread's slot, so _reaper_split's post-fork read is per-run by
    # construction (one run() per thread at a time).
    # Minted for every Linux context that could dispatch on the plain
    # subprocess lane. That used to exclude namespace-triggering
    # shapes (their lane was the unshare-CLI chain, whose pid-ns
    # cascade made the sweeper redundant); with that lane deleted, a
    # namespace-shaped call whose spawn backend fails mid-setup
    # demotes to the plain lane per call — the sweeper must exist for
    # it. The cell is inert on runs that stay on the spawn lanes (the
    # sweeper only forks inside the subprocess-lane preexec), and the
    # teardown_sweep posture stamp below is scoped to runs that
    # actually executed there.
    _reaper_cell: dict | None = None
    if (sys.platform == "linux" and not use_seatbelt
            and not effectively_disabled):
        _reaper_cell = {"death_local": threading.local()}
        _nproc_budget = int(effective_limits.get("nproc", 0) or 0)
        if _nproc_budget > 0:
            try:
                _uid = os.geteuid()
                _count = 0
                for _d in os.listdir("/proc"):
                    if not _d.isdigit():
                        continue
                    try:
                        if os.stat(f"/proc/{_d}").st_uid != _uid:
                            continue
                        # RLIMIT_NPROC counts TASKS (threads), not
                        # processes — counting tgids alone would set a
                        # ceiling BELOW the current usage on any
                        # thread-heavy host and make every fork in the
                        # sandbox fail EAGAIN.
                        with open(f"/proc/{_d}/status", "rb") as _f:
                            for _line in _f.read(4096).splitlines():
                                if _line.startswith(b"Threads:"):
                                    _count += int(_line.split()[1])
                                    break
                            else:
                                _count += 1
                    except (OSError, ValueError, IndexError):
                        continue
                _host_nproc_cap = _count + _nproc_budget
            except OSError:
                _host_nproc_cap = None  # /proc unreadable — skip the cap

    _preexec_build_kwargs: dict[str, Any] = dict(
        writable_paths=writable_paths,
        allowed_tcp_ports=allowed_tcp_ports,
        seccomp_profile=seccomp_profile,
        seccomp_block_udp=seccomp_block_udp,
        readable_paths=_preexec_readable,
        deny_all_tcp_connect=_degraded_tcp_deny,
        host_nproc_cap=_host_nproc_cap,
        reaper_cell=_reaper_cell,
    )
    # Plain-subprocess preexec with the namespace-creation deny rules
    # (unshare/clone CLONE_NEW*, setns; clone3→ENOSYS). The fork
    # backend's grandchild always installs these, and with the
    # unshare-CLI lane deleted the plain subprocess lane is the ONLY
    # lane that still execs through a preexec — its payload never
    # legitimately unshares, so the deny rules apply blanket. (The
    # legacy lane could not take them because its own `unshare`
    # bootstrap ran under the filter — the documented residual that
    # died with the lane.)
    preexec_ns_blocked = _make_preexec_fn(
        effective_limits, seccomp_block_ns_creation=True,
        **_preexec_build_kwargs)

    # Host-fingerprint persona — opt-in. Built once per sandbox() context
    # and reused across every run() call inside it. Cleanup happens in
    # the finally block at the end of sandbox().
    #
    # Three failure modes, each with explicit behaviour so operators can
    # see what's actually engaged:
    #
    #   1. is_supported() == False (macOS, etc.): persona stays None,
    #      a one-shot WARNING tells the operator. require_sanitisation
    #      raises RuntimeError instead.
    #
    #   2. mount-ns probe returns False (no uidmap, apparmor sysctl,
    #      Landlock-only mode): persona stays None, one-shot WARNING.
    #      require_sanitisation raises.
    #
    #   3. cpu_count > host's available CPUs: persona builds with the
    #      requested count; set_cpu_affinity clamps at apply time and
    #      logs INFO (the persona's cpuinfo still claims cpu_count,
    #      creating a paranoid-cross-check tell — documented residual).
    _persona = None
    _persona_tmpdir = None
    if sanitise_host_fingerprint:
        from ._spawn import mount_ns_available
        from .fingerprint import build_persona, is_supported
        _fp_unsupported_reason = None
        if not is_supported():
            _fp_unsupported_reason = (
                "platform unsupported (Linux required; macOS lacks "
                "bind-mount + UTS-namespace primitives — run RAPTOR "
                "in a Linux VM for untrusted-binary analysis)"
            )
        elif not check_mount_available():
            # Same gate run() uses to decide mount-ns engagement.
            # Pre-fix this branch probed only mount_ns_available()
            # (uidmap binaries), so a host whose kernel/LSM refuses
            # unprivileged userns but has uidmap installed passed the
            # gate, built the persona, and then mount-ns never engaged
            # — sanitisation silently never applied. And the
            # diagnostic hardcoded uidmap+AppArmor: route through
            # mount_unavailable_reason() (the helper the strict and
            # Landlock-only siblings already use) so SELinux / nested
            # userns / missing-package hosts each get their own cause.
            from .probes import mount_unavailable_reason
            _fp_condition, _fp_fix = mount_unavailable_reason()
            _fp_unsupported_reason = f"{_fp_condition}. {_fp_fix}"
        elif not mount_ns_available():
            # check_mount_available() passed but the newuidmap/
            # newgidmap execution probe failed (missing or broken
            # install) — the spawn backend cannot run its uid-mapping
            # step, so mount-ns (and with it the persona overlay)
            # will not engage.
            _fp_unsupported_reason = (
                "uidmap helpers unusable (newuidmap/newgidmap missing "
                "or not executable) — install/repair the uidmap "
                "package"
            )
        elif not (target or output):
            # mount-ns engagement requires at least one of target/output
            # — _spawn.run_sandboxed skips setup_mount_ns when both are
            # falsy. Without mount-ns, the persona's file bind-mounts
            # never apply; UTS + affinity would partially engage, which
            # is a confusing half-state that lets the caller think they
            # got sanitisation when they didn't.
            _fp_unsupported_reason = (
                "sandbox has no target/output set — mount-ns is skipped "
                "in that case, so persona file overlays can't apply. "
                "Pass at least one of target= or output= to engage "
                "sanitisation"
            )
        if _fp_unsupported_reason:
            msg = (
                f"sanitise_host_fingerprint requested but {_fp_unsupported_reason}"
            )
            if require_sanitisation:
                raise RuntimeError(msg + " (require_sanitisation=True)")
            logger.warning("Sandbox: %s; identity surfaces will be host-real.", msg)
        else:
            import shutil as _shutil
            import tempfile as _tf
            _persona_tmpdir = _tf.mkdtemp(prefix=".fp-")
            _effective_cpu_count = cpu_count if cpu_count is not None else 4
            try:
                # strict rides ON the persona: apply_overlay (in the
                # mount-ns child) treats per-target failures as setup
                # failures instead of skip-and-continue, so a
                # fail-closed persona request cannot silently run
                # with host-real identity files.
                _persona = build_persona(
                    Path(_persona_tmpdir), cpu_count=_effective_cpu_count,
                    strict=bool(require_sanitisation),
                )
            except BaseException:
                _shutil.rmtree(_persona_tmpdir, ignore_errors=True)
                raise
    elif cpu_count is not None:
        # cpu_count without the master switch is a caller mistake — the
        # CPU-mask change is part of the fingerprint persona, not an
        # independent knob. Don't silently engage it.
        logger.warning(
            "Sandbox: cpu_count=%d ignored because sanitise_host_fingerprint=False",
            cpu_count,
        )
    if _persona is not None and os.environ.get(
            "TERM", "").startswith(("screen", "tmux")):
        # A screen/tmux-flavoured TERM says "interactive operator
        # multiplexer" — contradicting the persona's headless-VM
        # story in one getenv. Normalise to the boring default.
        # Rides the fake_home_env overlay (same merge point).
        fake_home_env["TERM"] = "xterm-256color"


    # Cumulative proxy-event list spanning every run() call in this
    # sandbox() context. Per-run slices live on each result.sandbox_info;
    # this is the unified view exposed as `run.events`.
    _sandbox_events: list = []

    def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
        """Run a command inside the sandbox namespace defined by the enclosing
        `with sandbox(...)` block.

        Same signature as subprocess.run() for non-sandbox kwargs (env, cwd,
        capture_output, text, timeout, stdin, etc.). Sandbox configuration is
        fixed by the enclosing context and CANNOT be overridden per-call —
        passing block_network=, target=, output=, profile=, etc. here raises
        TypeError. To change isolation, open a new `sandbox()` context.

        PATH-divergence gate: when run() builds the child env itself
        (no caller env=), a BARE command name that would resolve to a
        different binary inside the sandbox than in the caller's
        environment — the child-env scrub drops home-rooted PATH
        entries, so a venv/rustup tool silently falls through to a
        same-named system binary or to nothing — raises
        SandboxSetupError naming both resolutions. Remedies, in
        preference order: declare the toolchain via tool_paths= (run
        the caller's binary inside the sandbox), invoke by absolute
        path, or pass allow_path_divergence=True to state that the
        child SHOULD resolve the name against its own PATH.
        """
        from core.config import RaptorConfig

        # Reject sandbox kwargs — they'd be silently ignored otherwise and
        # callers would wrongly assume per-call overrides took effect.
        misused = _SANDBOX_KWARGS & kwargs.keys()
        if misused:
            msg_0 = (
                f"sandbox().run() does not accept sandbox kwargs "
                f"{sorted(misused)} — isolation is fixed by the enclosing "
                f"sandbox() context. Open a new sandbox(...) block to change it."
            )
            raise TypeError(msg_0)

        # Audit-mode + missing output= handling. Two distinct cases:
        #
        # 1. EXPLICIT per-call kwarg `audit=True` + no output= →
        #    operator-level mistake (caller deliberately asked for
        #    audit on a call that has no output dir). Raise loudly.
        #
        # 2. CLI flag `--audit` set, but THIS particular sandbox call
        #    happens to have no output= (internal helper sandboxes
        #    like git-init on a temp target dir, capability probes,
        #    etc.). The operator asked for audit at process level;
        #    they didn't necessarily mean "audit every internal
        #    helper". Silently skip audit for this call so the
        #    workflow continues — sandbox calls that DO have output
        #    still produce audit signal as the operator intended.
        nonlocal_audit_mode = audit_mode
        # `audit_run_dir` decouples "where audit JSONL goes" from
        # "what Landlock restricts writes to". Either output= or
        # audit_run_dir= satisfies the audit-target requirement.
        # Callers that want audit signal WITHOUT a Landlock writable-
        # path restriction (e.g. codeql analyze, where writes
        # legitimately go to ~/.codeql, the database dir, etc.) pass
        # audit_run_dir= alone.
        _has_audit_target = bool(output) or bool(audit_run_dir)
        if audit_mode and not _has_audit_target:
            if audit:  # case 1 — explicit per-call kwarg
                msg_0 = (
                    "audit mode requires output= or audit_run_dir= so "
                    "the tracer has a directory to write "
                    "sandbox-summary.json into. Pass output=<dir> "
                    "when constructing sandbox(...) (which also "
                    "engages Landlock writable-path restriction) or "
                    "audit_run_dir=<dir> (audit-only, no Landlock "
                    "impact). run_untrusted() enforces output=."
                )
                raise ValueError(msg_0)
            # case 2 — CLI flag + internal helper without output.
            # Silently demote audit for this call only. The state
            # flag stays True for other sandbox calls in the process.
            logger.debug(
                "Sandbox: --audit flag is set but this call has no "
                "output= or audit_run_dir= path; tracer cannot write "
                "JSONL — audit demoted for this call only."
            )
            nonlocal_audit_mode = False

        def _audit_target_dir_problem() -> str | None:
            """Why the effective audit target dir is unusable, or None.

            The audit tiers create ``<dir>/.audit`` inside the target
            dir but never the dir itself (see evidence.ensure_audit_dir)
            — the contract is "caller supplies an existing writable
            directory" (lifecycle-created run dirs at every production
            call site). A missing/unwritable dir is therefore a
            caller-input error, categorically different from the
            environmental degradations (no userns, no libseccomp, no
            ptrace) the fallback ladder legitimately absorbs.
            """
            _d = audit_run_dir or output
            if not (nonlocal_audit_mode and _d):
                return None
            if not os.path.isdir(_d):
                return f"is not an existing directory: {_d!r}"
            if not os.access(_d, os.W_OK | os.X_OK):
                return f"is not writable: {_d!r}"
            return None

        # Fail-closed validation of the audit target BEFORE any spawn
        # tier runs. Pre-fix, a typo'd audit_run_dir= surfaced as
        # ENOENT deep inside the mount-ns spawn setup, was swallowed
        # by the environmental-degradation excepts below, and the call
        # cascaded mount-ns → Landlock-only → bare subprocess.run:
        # the command executed with reduced containment and NO audit
        # evidence, while the API call looked successful (fail-open
        # on the evidence channel).
        _audit_dir_problem = _audit_target_dir_problem()
        if _audit_dir_problem:
            _src = ("audit_run_dir" if audit_run_dir
                    else "output (audit target fallback)")
            msg_0 = (
                f"audit mode is engaged but the audit target directory "
                f"from {_src}= {_audit_dir_problem}. The sandbox creates "
                f"only the .audit/ evidence subdirectory inside it, "
                f"never the directory itself — create it before the "
                f"call (production callers pass lifecycle-created run "
                f"dirs). Refusing to run: silently continuing here "
                f"previously disabled BOTH the mount-ns containment "
                f"tier and the requested audit evidence."
            )
            raise ValueError(msg_0)

        # Always use safe env unless caller provided their own.
        # env=None is treated as "no env kwarg" — the subprocess
        # default of env=None is "inherit os.environ wholesale",
        # which would bypass our sanitiser entirely. A caller writing
        # `run(cmd, env=None)` (either explicitly or by passing
        # through an opts dict whose env field is None) almost
        # certainly wants default behaviour, not to inherit
        # LD_PRELOAD from whatever shell invoked RAPTOR.
        #
        # When a caller supplies a concrete env= dict we pass it
        # through verbatim and log at INFO for audit. We deliberately
        # do NOT strip DANGEROUS_ENV_VARS from caller-supplied env:
        # callers legitimately use those names as defensive
        # neutralisers (GIT_CONFIG_GLOBAL=/dev/null to isolate git
        # from user config, SSL_CERT_FILE pointing at a controlled
        # CA bundle for a specific operation, etc.). Stripping
        # there would silently defeat those hardenings. The
        # blocklist is belt-and-braces on the os.environ →
        # get_safe_env path (see core/config.py); the caller path
        # is "you know what you're doing".
        strict_env = kwargs.pop("strict_env", False)
        # allow_path_divergence: opt-out for the PATH-divergence gate
        # below. Default False — a bare command that resolves to a
        # DIFFERENT binary inside the sandbox than in the caller's
        # environment (because the child-env home-scrub dropped the
        # caller's venv/toolchain PATH entry) is refused with a named
        # error instead of quietly execing the wrong binary. True is an
        # explicit statement of intent: "the sandboxed child SHOULD
        # resolve this name against its own (scrubbed) PATH even when
        # that picks a different binary than my shell would".
        allow_path_divergence = kwargs.pop("allow_path_divergence", False)
        # ``strip_trust_markers``: opt-in from run_untrusted() /
        # run_untrusted_networked(). CLAUDECODE / _RAPTOR_TRUSTED pass
        # through get_safe_env(), but an untrusted TARGET holding them
        # could invoke libexec scripts as a "trusted caller". Every
        # lane execs the target directly (fork backend, seatbelt,
        # Landlock-only subprocess — the shim-bearing unshare chain is
        # deleted), so the env handed to the target has both markers
        # removed. RAPTOR_DIR is stripped on the same contract: the
        # libexec trust gate never accepted it, in-tree sandboxed
        # children self-anchor via __file__, and to an untrusted
        # target it is a pure "inside RAPTOR at <path>" tell.
        # Dispatch children keep it alongside the markers
        # (keep_trust_markers_for_dispatch).
        # Popped for API compatibility; the strip is the default now
        # (see the target-env staging below), so the flag's only
        # remaining meaning is "do not warn about the subsumed kwarg".
        kwargs.pop("strip_trust_markers", False)
        # ``keep_trust_markers_for_dispatch``: the ONLY sanctioned way
        # to keep CLAUDECODE/_RAPTOR_TRUSTED in a sandboxed target's
        # env (RAPTOR's own Claude Code skill dispatches — see
        # run_untrusted_networked(keep_trust_markers=True)). Travels
        # as an explicit call kwarg and reaches the pid1 shim as an
        # ARGV flag: the old in-band _RAPTOR_KEEP_TRUST_MARKERS env
        # key meant ANY caller-supplied env dict carrying that key
        # silently preserved the markers for untrusted code.
        keep_trust_markers_for_dispatch = kwargs.pop(
            "keep_trust_markers_for_dispatch", False)
        # ``env_caller_filtered``: opt-in assertion from the caller
        # that the env dict was constructed from a get_safe_env-
        # equivalent base AND that any DANGEROUS_ENV_VARS present
        # are INTENTIONAL caller overrides (not operator-secret
        # leakage). Suppresses the operational-hygiene warning
        # below. ``strict_env=True`` is still preferable when the
        # caller's intent is "neutralise a few keys on top of a
        # base I trust" — but callers that INTENTIONALLY inject
        # DANGEROUS_ENV_VARS as primitives (e.g. LD_PRELOAD /
        # LD_LIBRARY_PATH for a controlled scenario) would have
        # those stripped by ``strict_env=True``.
        # ``env_caller_filtered=True`` is the "I know what I'm
        # doing AND I can't use strict_env" escape valve.
        env_caller_filtered = kwargs.pop("env_caller_filtered", False)
        _skip_pid_ns = kwargs.pop("skip_pid_ns", False)
        _skip_mount_ns = kwargs.pop("skip_mount_ns", False)
        # Kept separate from require_fresh_procfs: the operator's degraded
        # untrusted opt-in relaxes the fresh-procfs requirement, but it must
        # not erase the fact that the workload is untrusted. The waived
        # containment floor and the mountless ABI predicate below still
        # apply to every untrusted workload.
        _untrusted_workload = kwargs.pop("_untrusted_workload", False)
        # Untrusted-target contract knob (set by run_untrusted*): the
        # grandchild's fresh-procfs mount stops being best-effort —
        # a failure aborts the spawn (status byte 'F') instead of
        # leaving the host-pid procfs bind visible to the target.
        # Tri-state pop: None = the kwarg was never passed (trusted
        # default); False = passed-but-zeroed — the caller derived the
        # flag from untrusted_fresh_procfs_required() and the operator
        # waiver is in force, so the call is untrusted-class work
        # running at the waived floor rather than a trusted call.
        # ``landlock_required`` is the BACKEND's floor-plumbing
        # parameter, never a caller kwarg: the Landlock-absent
        # tolerance mode is reachable ONLY via the resolved
        # containment floor below. Refuse loudly instead of letting
        # the name ride the loose **kwargs surface into (silent)
        # nothing — a caller writing it believed it did something.
        if "landlock_required" in kwargs:
            msg_0 = (
                "sandbox run() does not accept landlock_required= — "
                "the Landlock-absent tolerance is derived from the "
                "resolved containment floor, never from a caller "
                "kwarg."
            )
            raise TypeError(msg_0)
        _rfp_kwarg = kwargs.pop("require_fresh_procfs", None)
        if _rfp_kwarg is not None:
            # Normalise truthy/falsy literals (0/1, "" ...) at the
            # boundary so the tri-state contract below sees exactly
            # {None, True, False} — a literal 0 must resolve like
            # False (present-but-zeroed), not like an absent kwarg.
            _rfp_kwarg = bool(_rfp_kwarg)
        _require_fresh_procfs = bool(_rfp_kwarg)

        # ---- containment-floor contract, side 1: entry-time check ----
        # The caller's requirement is stated ONCE as a floor
        # (core/sandbox/tiers.py); the per-lane enforcement lives at
        # the dispatch sites (_dispatch_floor_check below), so a new
        # demotion lane cannot silently run below the floor. This
        # entry check exists for fast, fully-remediated refusals on
        # statically-knowable shapes — probes are probabilistic, so
        # soundness comes from the dispatch assertion, not from here.
        #
        # The floor short-circuits at BARE for the operator's explicit
        # sandbox-off surface (--sandbox none / --no-sandbox /
        # disabled=True): that surface stays authoritative and is NOT
        # second-guessed (a LIBRARY caller's profile='none' is not
        # operator consent — it does not set effectively_disabled and
        # does not lower the floor), at the documented cost that the
        # explicit global disable also silences the per-call contract
        # flag, exactly as it silences every other containment layer.
        # Both directions are pinned by tests.
        def _note_floor_refusal(
                exc: "_errors.SandboxFloorError",
        ) -> "_errors.SandboxFloorError":
            """Record a containment-floor refusal into the run-dir
            evidence stream (best-effort) and return ``exc`` for the
            caller to raise.

            The verification seams (dark verification, exploit
            execution, mitigation replay) map these refusals to the
            ``unverifiable_environment`` status per finding; this is
            the sandbox-side half — the refusal chokepoint writes a
            typed record so ``sandbox-summary.json`` carries the
            run-level count line even when no denial was ever
            recorded. Never raises on its own; a refusal must not be
            masked by evidence I/O."""
            _refusal_dir = audit_run_dir or output
            if _refusal_dir and not effectively_disabled:
                try:
                    from . import summary as _summary_refusal
                    _summary_refusal.record_floor_refusal(
                        Path(_refusal_dir),
                        floor=_tiers.tier_label(exc.floor),
                        achievable=_tiers.tier_label(exc.achievable),
                        reason=str(exc),
                        remedies=exc.instructions or "",
                    )
                except Exception:  # noqa: BLE001 — evidence recording is best-effort
                    logger.debug("floor-refusal record failed",
                                 exc_info=True)
            return exc

        _explicit_tier, _explicit_src = _explicit_untrusted_floor()
        try:
            _floor, _floor_source = _tiers.resolve_call_floor(
                operator_disabled=effectively_disabled,
                require_fresh_procfs=_rfp_kwarg,
                untrusted_workload=_untrusted_workload,
                # tiers.py reads no environment by design — hand it the
                # env truth so the floor source is attributed honestly
                # (a literal require_fresh_procfs=False without the
                # waiver must not banner/warn in the waiver's name).
                waiver_active=_degraded_untrusted_waiver(),
                # Explicit consent surfaces (per-run flag > project
                # setting), read from the argparse / run-start state
                # slots — they apply to untrusted-class calls only and
                # win over the env waiver in both directions.
                explicit_floor=_explicit_tier,
                explicit_source=_explicit_src,
            )
        except _errors.SandboxFloorError as _resolve_exc:
            # The never-BARE-by-consent refusal ("--sandbox-floor
            # none" / a bare project floor on untrusted-class work):
            # record it into the run-dir evidence stream like every
            # other floor refusal, then let it propagate.
            raise _note_floor_refusal(_resolve_exc)

        if (_floor_source == _tiers.FLOOR_SOURCE_ENV
                and sys.platform == "linux"
                and state.warn_once("_floor_lowered_banner_warned")):
            # Consent banner (once per process; the per-call warning
            # in _dispatch_floor_check fires whenever the lowered
            # floor actually bites).
            logger.warning(
                "sandbox: untrusted containment floor lowered to '%s' "
                "(source: RAPTOR_ALLOW_DEGRADED_UNTRUSTED).",
                _tiers.tier_label(_floor),
            )
        elif (_floor_source == _tiers.FLOOR_SOURCE_FLAG
                and sys.platform == "linux"
                and state.warn_once("_floor_flag_banner_warned")):
            logger.warning(
                "sandbox: untrusted containment floor set to '%s' "
                "(source: --sandbox-floor).",
                _tiers.tier_label(_floor),
            )
        elif (_floor_source == _tiers.FLOOR_SOURCE_PROJECT
                and sys.platform == "linux"
                and state.warn_once("_floor_project_banner_warned")):
            logger.warning(
                "sandbox: untrusted containment floor set to '%s' "
                "(source: project setting sandbox-floor; per-run "
                "--sandbox-floor overrides).",
                _tiers.tier_label(_floor),
            )
        if (_floor_source in (_tiers.FLOOR_SOURCE_FLAG,
                              _tiers.FLOOR_SOURCE_PROJECT)
                and sys.platform == "linux"):
            # Disagreement banner: an explicit surface won over a
            # lower-precedence surface that named a DIFFERENT floor.
            # Explicit-wins is the documented precedence; the banner
            # makes the overridden surface visible (once per process),
            # naming both surfaces and both values.
            _overridden: list = []
            if (_floor_source == _tiers.FLOOR_SOURCE_FLAG
                    and state._project_sandbox_floor is not None
                    and _tiers.label_tier(state._project_sandbox_floor)
                    != _floor):
                _overridden.append(
                    f"project setting sandbox-floor="
                    f"'{state._project_sandbox_floor}'")
            if (_degraded_untrusted_waiver()
                    and _tiers.waived_untrusted_floor() != _floor):
                _overridden.append(
                    "RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1 (frozen "
                    "meaning: untrusted floor 'landlock')")
            if _overridden and state.warn_once(
                    "_floor_surface_disagreement_warned"):
                _winner = ("--sandbox-floor"
                           if _floor_source == _tiers.FLOOR_SOURCE_FLAG
                           else "project setting sandbox-floor")
                logger.warning(
                    "sandbox: consent surfaces disagree on the "
                    "untrusted containment floor — %s='%s' wins over "
                    "%s (precedence: per-run flag > project setting "
                    "> env var).",
                    _winner, _tiers.tier_label(_floor),
                    "; ".join(_overridden),
                )
        if _require_fresh_procfs and _skip_pid_ns:
            # Contradictory by construction: skip_pid_ns keeps the
            # host procfs on purpose (gdb lane), which is exactly the
            # posture require_fresh_procfs refuses — a skip_pid_ns run
            # can never satisfy a mount-tier floor. The untrusted
            # entry points reject skip_pid_ns outright; a direct
            # caller combining the two gets a loud error rather than
            # a silently-neutralised contract.
            msg = (
                "sandbox run(): require_fresh_procfs=True cannot be "
                "combined with skip_pid_ns=True — the skip keeps the "
                "host-pid /proc visible, which is the exact posture "
                "the requirement refuses."
            )
            raise _note_floor_refusal(_errors.SandboxFloorError(
                msg, "",
                # skip_pid_ns keeps the HOST procfs, which the
                # redefined ns-only tier explicitly negates — the
                # honest achievable claim is the policy-layer tier.
                achievable=_tiers.ContainmentTier.LANDLOCK_ONLY,
                floor=_floor,
            ))
        from ._spawn import mount_ns_available as _mount_ns_avail

        # ---- Landlock-absent tolerance (the ported ns-only mode) ----
        # On a kernel WITHOUT Landlock, the spawn backend may run
        # without the Landlock layer WHEN the call's resolved floor
        # admits the ns-only tier — floor resolution is the ONLY way
        # to reach the mode (run()/sandbox() expose no kwarg for it;
        # _spawn's landlock_required is set exclusively from this
        # flag). With the mount tree engaged the lane keeps its
        # MOUNT_NS declaration (the tree, not Landlock, is that
        # tier's filesystem enforcement); without the tree the lane
        # is capped to what the redefined NS_NOMOUNT tier honestly
        # promises, computed by _ported_ns_tier below.
        _landlock_tolerated = (
            sys.platform == "linux"
            and not effectively_disabled
            and not check_landlock_available()
            and _floor <= _tiers.ContainmentTier.NS_NOMOUNT
        )

        def _ported_ns_tier() -> "_tiers.ContainmentTier":
            """Tier the spawn backend delivers WITHOUT the mount tree
            and WITHOUT Landlock on this host + call shape.

            NS_NOMOUNT promises namespaces + a FRESH pid-ns procfs +
            seccomp; when any of those is unavailable up front the
            lane must not claim the tier — it collapses to BARE
            (understating the namespaces that may still engage is
            safe; overstating never is). The entry-time probe verdict
            here is advisory ordering; delivery stays fail-closed in
            the child ('U'/'S'/'F' status bytes — the checked
            dispatch passes require_fresh_procfs through whenever
            this returns NS_NOMOUNT)."""
            if not (seccomp_profile and check_seccomp_available()):
                return _tiers.ContainmentTier.BARE
            if _skip_pid_ns:
                # Host procfs by caller declaration — the exact
                # posture the tier negates.
                return _tiers.ContainmentTier.BARE
            from .probes import check_pidns_fresh_proc_available
            if not check_pidns_fresh_proc_available():
                return _tiers.ContainmentTier.BARE
            return _tiers.ContainmentTier.NS_NOMOUNT

        # Whether a mountless spawn in the tolerance mode must treat
        # the fresh procfs mount as MANDATORY ('F' fail-closed): yes
        # exactly when the lane declares NS_NOMOUNT — a tier that
        # promises fresh procfs may not deliver the host view.
        _ported_hard_fresh = (
            _landlock_tolerated
            and _ported_ns_tier() is _tiers.ContainmentTier.NS_NOMOUNT)

        def _spawn_tier_cap(
                without_mount: bool,
        ) -> "_tiers.ContainmentTier | None":
            """Per-call cap on the spawn lanes' declared tier.

            * skip_pid_ns keeps the HOST procfs on both spawn lanes
              (the fresh-proc remount rides the pid-ns grandchild
              fork) — under the redefined NS_NOMOUNT (which promises
              a FRESH procfs) the honest cap is the policy-layer tier
              (LANDLOCK_ONLY), or BARE on a Landlock-less kernel.
              Caps may understate delivered isolation; they must
              never overstate it.
            * The Landlock-absent tolerance caps a MOUNTLESS spawn to
              what the ported ns-only tier honestly promises
              (_ported_ns_tier). The mount lane keeps MOUNT_NS — the
              bind tree, not Landlock, is that tier's filesystem
              enforcement.
            """
            cap: "_tiers.ContainmentTier | None" = None
            if _skip_pid_ns:
                cap = (_tiers.ContainmentTier.LANDLOCK_ONLY
                       if check_landlock_available()
                       else _tiers.ContainmentTier.BARE)
            if _landlock_tolerated and without_mount:
                ported = _ported_ns_tier()
                cap = ported if cap is None else min(cap, ported)
            return cap

        if _floor > _tiers.ContainmentTier.BARE:
            # Highest tier this call can INTEND on this host + shape.
            # Deliberately coarse — per-command demotions (B fallback,
            # speculative cache, M/X status bytes, mid-setup spawn
            # exceptions) are caught by the dispatch assertions.
            if sys.platform == "darwin":
                _intended = (_tiers.ContainmentTier.SEATBELT
                             if use_sandbox
                             else _tiers.ContainmentTier.BARE)
            elif not use_sandbox:
                # Environmental use_sandbox=False (userns probe
                # refused: container default seccomp, the Ubuntu
                # 24.04 AppArmor userns sysctl, missing uidmap
                # tooling): the call lands on the plain-subprocess
                # lane. Pre-fix, a contract-carrying call ran there
                # with the HOST process table visible behind nothing
                # louder than a once-per-process warning.
                _intended = _tiers.ContainmentTier.LANDLOCK_ONLY
            elif use_mount and _mount_ns_avail():
                # The mount tiers need BOTH availability views to
                # agree: `use_mount` (the capability probe) AND
                # mount_ns_available() (the spawn-backend probe that
                # actually routes the run) — they cache independently,
                # and the subprocess fallback engages whenever the
                # LATTER is false.
                if _skip_mount_ns:
                    _intended = (_ported_ns_tier() if _landlock_tolerated
                                 else _tiers.ContainmentTier.MOUNTLESS_NS)
                else:
                    _intended = _tiers.ContainmentTier.MOUNT_NS
            elif ((block_network or use_mount or restrict_reads)
                  and _mount_ns_avail()):
                # Namespace-needing shape without the mount tier
                # (no target/output, or the mount capability probe
                # refused): the modern spawn backend serves it
                # mountlessly — MOUNTLESS_NS with Landlock, the
                # ported ns-only tier without it.
                _intended = (_ported_ns_tier() if _landlock_tolerated
                             else _tiers.ContainmentTier.MOUNTLESS_NS)
            elif block_network or use_mount or restrict_reads:
                # uidmap helpers missing: no spawn backend at all —
                # the plain subprocess lane is all this host offers.
                _intended = _tiers.ContainmentTier.LANDLOCK_ONLY
            else:
                _intended = _tiers.ContainmentTier.LANDLOCK_ONLY
            if _intended < _floor:
                raise _note_floor_refusal(_entry_floor_refusal(
                    _intended, _floor,
                    environmental=not use_sandbox,
                    skip_mount_ns=_skip_mount_ns,
                    literal_contract=(_rfp_kwarg is True),
                ))

        def _floor_remedy(extra: str = "") -> str:
            """Remedy sentence for a floor refusal: the situation-
            specific fix first (when the demotion route carries one),
            then the honesty-checked override sentence — it names the
            RAPTOR_ALLOW_DEGRADED_UNTRUSTED escape when the env var
            genuinely relaxes this call's floor, and says the override
            will NOT relax it when the caller passed a literal
            require_fresh_procfs=True (see _fresh_procfs_override_hint)."""
            hint = _fresh_procfs_override_hint(
                literal_contract=(_rfp_kwarg is True))
            return f"{extra} {hint}".strip() if extra else hint

        def _dispatch_floor_check(
                lane: str, *,
                executor: "Callable[[], subprocess.CompletedProcess]",
                cap: "_tiers.ContainmentTier | None" = None,
                cause: BaseException | None = None,
                detail: str = "",
                remedy: str = "",
                setup_category: str | None = None,
        ) -> subprocess.CompletedProcess:
            """Containment-floor contract, side 2: the checked dispatch
            CHOKEPOINT — the only way run() hands a command to an
            executor.

            The lane's declared tier resolves through the module-level
            _LANE_TIERS registry (KeyError on an unregistered lane
            fails closed), the hard pre-exec assertion runs, and only
            then is ``executor`` invoked. Structural guarantee: the
            AST gate in the contract tests forbids bare
            process-spawning calls in this module outside this
            chokepoint (and the named executor helpers it invokes), so
            a future lane cannot ship an unchecked executor — the
            check is not a convention beside the spawn, it IS the
            spawn's entry point. ``cap`` lowers the declared tier for
            per-call posture reductions (skip_pid_ns keeps the host
            procfs on both spawn lanes; a Landlock-less kernel or the
            operator disable reduces the plain-subprocess lane to
            rlimits-only). ``cause`` chains the original backend
            failure that demoted the call here.

            When the floor holds only because the operator's waiver
            lowered it (floor source "env") and the lane leaves the
            host process table visible, the consented-degrade warning
            fires on EVERY such call — each one runs attacker-derived
            code under a reduced contract, and an operator watching a
            long run must see every instance, not just the first.
            """
            delivered = _LANE_TIERS[lane]
            if cap is not None and cap < delivered:
                delivered = cap
            try:
                _tiers.assert_floor(
                    delivered, _floor, lane=lane, cause=cause,
                    detail=detail,
                    remedy=remedy or _floor_remedy(),
                    setup_category=setup_category,
                )
            except _errors.SandboxFloorError as _floor_exc:
                # Refusal chokepoint: record the run-dir evidence the
                # verification seams' summary line counts, then let
                # the typed refusal propagate unchanged.
                _note_floor_refusal(_floor_exc)
                raise
            if (_landlock_tolerated
                    and _floor_source not in _tiers.CONSENT_FLOOR_SOURCES
                    and delivered <= _tiers.ContainmentTier.NS_NOMOUNT
                    and (target or output or allowed_tcp_ports
                         or restrict_reads or extra_writable_paths)
                    and state.warn_once(
                        "_tolerated_policy_unenforced_warned")):
                # Trusted-floor tolerance bite: the call REQUESTED a
                # filesystem/TCP policy, the kernel has no Landlock,
                # and this lane has no mount tree — the policy is not
                # enforced. The consented (env) case warns per call
                # below; the trusted case must not be silent either
                # (pre-port the spawn shapes aborted 'L' here).
                logger.warning(
                    "Sandbox: Landlock is unavailable on this kernel "
                    "and this call runs on the %s lane without a "
                    "mount tree — the requested filesystem/TCP "
                    "policy (target/output/writable_paths/"
                    "allowed_tcp_ports/restrict_reads) is NOT "
                    "enforced for it. Upgrade to a kernel with "
                    "Landlock (5.13+) to restore enforcement. "
                    "(Warned once per process.)",
                    lane,
                )
            if (_floor_source in _tiers.CONSENT_FLOOR_SOURCES
                    and sys.platform == "linux"
                    and delivered <= _tiers.ContainmentTier.NS_NOMOUNT):
                # Consented-degrade warning, per call. The exposure
                # named must match what the admitted lane actually
                # leaves open: the redefined ns-only tier keeps a
                # fresh pid-ns procfs (its exposure is the missing
                # Landlock policy layer); everything below it leaves
                # the HOST process table itself visible.
                if delivered >= _tiers.ContainmentTier.NS_NOMOUNT:
                    _waived_exposure = (
                        "WITHOUT Landlock filesystem/TCP policy "
                        "enforcement (namespace containment and a "
                        "fresh procfs still apply)")
                else:
                    _waived_exposure = (
                        "with the HOST process table visible to the "
                        "untrusted target")
                if _floor_source == _tiers.FLOOR_SOURCE_ENV:
                    _consent_surface = ("RAPTOR_ALLOW_DEGRADED_"
                                        "UNTRUSTED waives")
                elif _floor_source == _tiers.FLOOR_SOURCE_FLAG:
                    _consent_surface = (
                        f"--sandbox-floor "
                        f"{_tiers.tier_label(_floor)} lowers")
                else:
                    _consent_surface = (
                        f"the project sandbox-floor="
                        f"{_tiers.tier_label(_floor)} setting lowers")
                logger.warning(
                    "sandbox: %s the "
                    "untrusted containment floor and %s — proceeding on "
                    "the %s lane %s.",
                    _consent_surface,
                    detail or ("the mount-ns backend cannot engage for "
                               "this call"),
                    lane,
                    _waived_exposure,
                )
            _executed = executor()
            # Runtime dominance stamp: run()'s epilogue refuses any
            # result that did not come through this chokepoint, so an
            # executor added in ANOTHER module (out of the AST gate's
            # sight) is caught at its first use instead of silently
            # feeding results downstream.
            _executed._floor_checked = True  # type: ignore[attr-defined]
            return _executed
        _inherit_netns = kwargs.pop("inherit_netns", False)
        # inherit_netns drops CLONE_NEWNET / `--net` from every Linux
        # lane, so a block_network run keeps the CALLER's network
        # namespace — the sanctioned use (netns-coordinator paired
        # isolation: the caller already sits in a shared ISOLATED
        # netns the child must stay in to reach its peer), but for a
        # caller in the HOST netns it silently neutralised the
        # requested block: host interfaces and the host TCP table
        # were reachable from a "network-blocked" run with no warning
        # and no posture record. Network isolation is part of what a
        # tier delivers for a block_network-bearing call, so the drop
        # is now explicit: the untrusted contract refuses it (its
        # network block may not be inherited away — run_untrusted*
        # already reject the kwarg outright), every other caller gets
        # a once-per-process warning naming the posture, and the
        # per-run stamp below records it unconditionally.
        _netns_inherited_drop = bool(
            _inherit_netns and block_network
            and sys.platform == "linux" and not effectively_disabled)
        if _netns_inherited_drop:
            if _floor >= _tiers.ContainmentTier.MOUNTLESS_NS:
                raise _note_floor_refusal(_errors.SandboxFloorError(
                    "sandbox run(): inherit_netns=True drops the "
                    "network namespace from a block_network run — "
                    "the untrusted contract's network block cannot "
                    "be inherited away.",
                    "run the untrusted call without inherit_netns=, "
                    "or route coordinator-paired work through a "
                    "trusted context.",
                    achievable=_tiers.ContainmentTier.NS_NOMOUNT,
                    floor=_floor,
                ))
            if state.warn_once("_inherit_netns_block_warned"):
                logger.warning(
                    "sandbox: inherit_netns=True keeps the caller's "
                    "network namespace on a block_network run — the "
                    "child shares whatever network the CALLER has "
                    "(sanctioned for netns-coordinator paired runs, "
                    "whose callers sit in a shared isolated netns; a "
                    "host-netns caller just lost the requested "
                    "block). Stamped per run as netns_inherited.",
                )
        _start_new_session = kwargs.pop("start_new_session", True)
        # Deterministic child cwd. With no cwd= the two execution paths
        # diverged: the mount-ns child lands in "/" (post-pivot_root
        # chdir), while the Landlock-only subprocess child inherits the
        # ORCHESTRATOR's cwd — leaking the host checkout path through
        # getcwd() and pointing every relative-path write at the
        # driver's directory instead of a sanctioned writable one.
        # Default to the output dir (the canonical writable surface,
        # bind-mounted on the spawn path) so both paths agree and
        # relative writes land where the policy says writes go.
        # Callers that pass cwd= keep full control, as before.
        if (not effectively_disabled and output
                and kwargs.get("cwd") is None):
            kwargs["cwd"] = os.path.abspath(output)
        # exec_pid_callback: live-pid observation hook, honoured only by
        # the Linux fork-based spawn backend (see _spawn.run_sandboxed).
        # Popped unconditionally so the subprocess fallback paths never
        # forward an unknown kwarg to subprocess.run. Callers must gate
        # on spawn_backend_available() — on the fallback paths the
        # callback simply never fires.
        _exec_pid_callback = kwargs.pop("exec_pid_callback", None)
        if kwargs.get("env") is None:
            kwargs.pop("env", None)  # drop any explicit None
            kwargs["env"] = RaptorConfig.get_safe_env()
            if not effectively_disabled:
                # Host-layout scrub for sandboxed children. get_safe_env()
                # serves every subprocess in the codebase, so it keeps
                # PWD and home-rooted PATH entries for plain tool spawns;
                # a SANDBOXED child has no business learning the
                # operator's home layout from either. PWD names the
                # orchestrator's cwd (usually the RAPTOR checkout) and is
                # recomputed by any shell; PATH entries under the
                # operator's home (~/.local/bin, ~/bin) leak the home
                # path while pointing at directories that are invisible
                # (mount-ns) or read-restricted (Landlock) inside the
                # sandbox anyway. Exception: entries under a DECLARED
                # tool_paths dir stay — the caller explicitly named that
                # toolchain dir, the same declaration already binds it
                # read-only into the mount view and grants it in the
                # Landlock read allowlist, and dropping it from PATH
                # made the declared tool unresolvable (execvp ENOENT,
                # exit 127) on hosts whose toolchains live under $HOME
                # (rustup's ~/.cargo/bin being the canonical case).
                # Caller-supplied env= dicts stay verbatim, as
                # documented below.
                _scrubbed = dict(kwargs["env"])
                _scrubbed.pop("PWD", None)
                _scrubbed.pop("OLDPWD", None)  # belt-and-braces (allowlist already drops it)
                # Host-identity tells: the operator's login name and
                # the machine hostname identify the analysis host to
                # the sandboxed target. Tools that genuinely need a
                # user name fall back to getpwuid(), which the env
                # cannot fix (documented residual — the mount-ns
                # map-root path presents ns-root there anyway).
                _scrubbed.pop("USER", None)
                _scrubbed.pop("LOGNAME", None)
                _scrubbed.pop("HOSTNAME", None)
                _home_prefix = os.path.expanduser("~")
                _path_val = _scrubbed.get("PATH")
                if _path_val:
                    # Both spellings of each declared tool dir: the
                    # literal (what a PATH entry usually matches) and
                    # the resolved one (covers a symlinked declaration
                    # meeting a resolved PATH entry, and vice versa).
                    _declared_tool_dirs: list[str] = []
                    for _tp in (tool_paths or []):
                        if not _tp:
                            continue
                        for _cand in (os.path.normpath(_tp),
                                      os.path.realpath(_tp)):
                            if _cand not in _declared_tool_dirs:
                                _declared_tool_dirs.append(_cand)

                    def _under_declared_tool_dir(entry: str) -> bool:
                        for _e in (os.path.normpath(entry),
                                   os.path.realpath(entry)):
                            for _d in _declared_tool_dirs:
                                if _e == _d or _e.startswith(_d + os.sep):
                                    return True
                        return False

                    _kept = [
                        c for c in _path_val.split(os.pathsep)
                        if c
                        and (not (c.startswith("/home/")
                                  or c == _home_prefix
                                  or c.startswith(_home_prefix + os.sep))
                             or _under_declared_tool_dir(c))
                    ]
                    if _kept:
                        _scrubbed["PATH"] = os.pathsep.join(_kept)
                    # PATH-divergence gate. The home-scrub above can
                    # change what a BARE command name resolves to: the
                    # caller's shell would run the venv/toolchain copy
                    # (~/.venv/bin/pip, ~/.cargo/bin/cargo) while the
                    # child's scrubbed PATH resolves a same-named
                    # SYSTEM binary — or nothing. Execing a different
                    # binary than the caller's environment names is
                    # silent wrongness (results attributed to the
                    # wrong tool version); refuse with the remedy
                    # spelled out instead. Scope: bare names only
                    # (path-carrying invocations never consult PATH),
                    # only when the scrub actually changed PATH, and
                    # only when the caller's PATH resolves the name at
                    # all (otherwise the run fails not-found on its
                    # own, unchanged). Caller-supplied env= is exempt
                    # by construction — this branch only builds envs.
                    # rootfs mode is exempt: cmd[0] resolves inside the
                    # IMAGE filesystem, so a host-side which() over
                    # either PATH names binaries the child will never
                    # exec — host divergence is meaningless there and
                    # refusing on it would reject valid image commands.
                    _child_path_val = _scrubbed.get("PATH")
                    if (not allow_path_divergence
                            and rootfs is None
                            and cmd and cmd[0]
                            and os.sep not in cmd[0]
                            and _child_path_val != _path_val):
                        _caller_res = shutil.which(cmd[0], path=_path_val)
                        _child_res = (
                            shutil.which(cmd[0], path=_child_path_val)
                            if _caller_res is not None else None)
                        if _caller_res is not None and (
                                _child_res is None
                                or os.path.realpath(_child_res)
                                != os.path.realpath(_caller_res)):
                            from .errors import SandboxSetupError
                            msg_0 = (
                                f"sandbox run(): target {cmd[0]!r} "
                                f"resolves to {_caller_res!r} in the "
                                f"caller environment but "
                                f"{_child_res!r} inside the sandbox "
                                f"(the child-env scrub drops "
                                f"home-rooted PATH entries) — "
                                f"refusing to exec a different binary "
                                f"than the caller's environment names."
                            )
                            raise SandboxSetupError(
                                msg_0,
                                "declare the toolchain dir via "
                                "tool_paths=[...] so it stays visible "
                                "and PATH-resolvable inside the "
                                "sandbox, invoke the binary by "
                                "absolute path, or pass "
                                "allow_path_divergence=True if the "
                                "sandboxed child is MEANT to resolve "
                                "the name against its own PATH.",
                            )
                kwargs["env"] = _scrubbed
        else:
            # Promote to WARNING — pre-fix this was INFO, which meant
            # operators almost never noticed that a caller had passed
            # custom env and the codebase-wide ``get_safe_env`` posture
            # was being bypassed for that call. The bypass IS
            # intentional (callers neutralise specific vars like
            # ``GIT_CONFIG_GLOBAL=/dev/null``) but it should be visible
            # in normal-verbosity logs so a stray ``env=`` argument
            # doesn't quietly wave through ``EDITOR`` / ``PAGER`` /
            # ``BROWSER`` from an attacker-influenced parent.
            #
            # Gate on ``not strict_env`` AND ``not env_caller_filtered``:
            # either flag is a caller-side assertion that the warning
            # is contradictory noise — the warning literally tells the
            # caller to pass ``strict_env=True`` as the fix.
            # ``env_caller_filtered`` covers the case (engine
            # local_lowpriv_shell, semgrep config-merger, etc.) where
            # the caller has built the env from get_safe_env()
            # upstream AND deliberately added DANGEROUS_ENV_VARS as
            # intentional primitives that ``strict_env=True`` would
            # incorrectly strip.
            if not strict_env and not env_caller_filtered:
                logger.warning(
                    "Sandbox: caller supplied custom env= for "
                    "%s — get_safe_env() not applied; caller env "
                    "passed through. Pass strict_env=True to strip "
                    "DANGEROUS_ENV_VARS from the caller env, OR "
                    "env_caller_filtered=True to acknowledge the "
                    "caller has already filtered upstream.",
                    " ".join(cmd[:_CMD_DISPLAY_MAX_ARGS]) or repr(cmd),
                )
            if strict_env:
                # Preserve only RAPTOR's exact inert Git neutralisers. They
                # are classified as dangerous because caller-controlled
                # alternate paths can load config, but get_safe_env() resets
                # them to /dev/null before this second-stage scrub. Removing
                # those safe values makes git fall back to an unreadable real
                # HOME and abort under Landlock instead of treating config as
                # absent.
                _safe_git = RaptorConfig.GIT_ENV_VARS
                _stripped = [
                    k for k, v in kwargs["env"].items()
                    if k in RaptorConfig.DANGEROUS_ENV_VARS
                    and _safe_git.get(k) != v
                ]
                if _stripped:
                    kwargs["env"] = {
                        k: v for k, v in kwargs["env"].items()
                        if (k not in RaptorConfig.DANGEROUS_ENV_VARS
                            or _safe_git.get(k) == v)
                    }
                    logger.info(
                        "Sandbox: strict_env=True — stripped DANGEROUS_ENV_VARS from caller env: %s", sorted(_stripped)
                    )

        # Egress-proxy env injection — overlays AFTER get_safe_env() so
        # the proxy vars aren't stripped by the PROXY_ENV_VARS blocklist
        # (which is there to defeat user-env poisoning, not our own
        # injection). Applied whether the caller supplied env= or not;
        # if they did, we still override the proxy vars so proxy mode
        # stays coherent.
        if proxy_env_overrides:
            kwargs["env"] = {**kwargs["env"], **proxy_env_overrides}

        # Fake-HOME env injection — overrides HOME/XDG_*_HOME to point
        # at the per-sandbox empty dir. Same precedence rule as proxy:
        # our override wins, even if the caller passed their own env=
        # (otherwise fake_home=True with a caller env= that contains
        # HOME=/home/user would silently defeat the feature).
        if fake_home_env:
            kwargs["env"] = {**kwargs["env"], **fake_home_env}

        # Private-scratch steering (restricted Landlock-only posture,
        # see the writable-baseline construction): Landlock denies the
        # host-shared /tmp, so TMPDIR must name the one scratch dir
        # that IS writable or every tempfile-using tool fails at
        # startup. Overlays caller env= too — the grant and the
        # steering must not diverge.
        if _private_scratch_dir:
            kwargs["env"] = {
                **kwargs["env"],
                "TMPDIR": _private_scratch_dir,
                "TEMP": _private_scratch_dir,
                "TMP": _private_scratch_dir,
            }

        # Degraded-mode daemon nudge. The Landlock TCP-connect deny hits
        # loopback too, and several build tools default to a client/
        # daemon model over loopback TCP. Steer known offenders to their
        # no-daemon mode through their own documented config — the same
        # trusted-injection pattern as the JAVA_TOOL_OPTIONS proxy
        # sysprops. Policy is unchanged: a tool that ignores the nudge
        # (explicit --daemon, Bazel's client/server) still fails CLOSED,
        # and _check_blocked names the opt-out.
        if _degraded_tcp_deny:
            kwargs["env"] = dict(kwargs["env"])
            _daemon_off = "-Dorg.gradle.daemon=false"
            _gopts = kwargs["env"].get("GRADLE_OPTS", "")
            if _daemon_off not in _gopts:
                kwargs["env"]["GRADLE_OPTS"] = (
                    f"{_gopts} {_daemon_off}".strip()
                )
            kwargs["env"].setdefault("NX_DAEMON", "false")

        # Target-bound env view — the ONE seam every direct-exec
        # backend (fork, seatbelt, Landlock-only subprocess) hands to
        # the child, and the named extension point for the sandbox
        # re-anonymisation follow-up. The
        # TARGET_ENV_STRIP_SET (trust markers + the session
        # credential) is stripped by DEFAULT: the pre-fix strip was
        # opt-in per caller, and its only setters were run_untrusted*
        # — every other sandboxed spawn (CodeQL autobuild running
        # repo-supplied build scripts, fuzz target execution) leaked
        # CLAUDECODE/_RAPTOR_TRUSTED to target code on the primary
        # fork backend. The keep-trust dispatch path (RAPTOR's own
        # claude -p skill children, which drive libexec helpers and
        # need both the markers and the session credential) is the
        # ONLY exception, signalled by the sanctioned call kwarg.
        # The legacy strip_trust_markers kwarg is still accepted —
        # marker-stripping is now a subset of the default, and the
        # flag additionally drops RAPTOR_DIR on untrusted-target
        # paths — so existing callers keep working unchanged.
        # The keep decision comes from the SANCTIONED call kwarg only.
        # Pre-fix this probed the in-band _RAPTOR_KEEP_TRUST_MARKERS
        # env key: a poisoned caller-supplied env dict carrying it
        # delivered the full strip set (trust markers AND the session
        # credential) to sandboxed target code on the direct-exec
        # backends — while the kwarg the design sanctions never
        # reached this seam at all, so RAPTOR's own fork-backend
        # dispatches LOST their markers. The env key is still
        # stripped from the child env below (defense in depth), but
        # it no longer carries authority.
        _keep_for_dispatch = keep_trust_markers_for_dispatch
        if _keep_for_dispatch:
            _env_for_target = {
                k: v for k, v in kwargs["env"].items()
                if k != "_RAPTOR_KEEP_TRUST_MARKERS"
            }
        else:
            from core.config import RaptorConfig as _RC
            # RAPTOR_DIR (plus the other framework-identity values)
            # now lives in TARGET_ENV_STRIP_SET itself: the libexec
            # trust gate never accepted it, no sandboxed child
            # legitimately derives paths from it (libexec scripts
            # self-anchor via __file__; the netns coordinator exports
            # its own), and to a target it is a pure "you are inside
            # RAPTOR at <checkout path>" tell. The old opt-in
            # strip_trust_markers add is therefore subsumed.
            _env_for_target = {
                k: v for k, v in kwargs["env"].items()
                if k not in _RC.TARGET_ENV_STRIP_SET
                and k != "_RAPTOR_KEEP_TRUST_MARKERS"
            }
        if _ENV_RESTORE_KEY in _env_for_target:
            # RAPTOR-minted quarantine payload key (see
            # _env_quarantine) — only ever set by run() itself on the
            # launcher-bound view; a caller-supplied copy must not
            # reach direct-exec children either.
            _env_for_target = {
                k: v for k, v in _env_for_target.items()
                if k != _ENV_RESTORE_KEY
            }

        _mountless_call_writable: list[str] | None = None
        _mountless_private_scratch: str | None = None

        def _mountless_write_policy() -> tuple[list[str], dict]:
            """Return write grants and env for a host-visible filesystem.

            Construction assumes the mount backend has private tmpfs mounts at
            /tmp and /dev/shm. If this call later uses a mountless lane under
            read restriction, replace those host-shared grants with the same
            private scratch policy used by the legacy demotion path.
            """
            nonlocal _env_for_target
            nonlocal _mountless_call_writable
            nonlocal _mountless_private_scratch

            if _mountless_call_writable is not None:
                return _mountless_call_writable, _env_for_target
            if (not use_mount or rootfs is not None
                    or sys.platform != "linux" or effectively_disabled
                    or not restrict_reads or exclude_tmp_baseline):
                return list(writable_paths or []), _env_for_target

            import tempfile as _tempfile_mountless
            scratch = _tempfile_mountless.mkdtemp(prefix=".scr-")
            _demoted_scratch_dirs.append(scratch)
            from core.run.scratch import keepalive_register
            keepalive_register(scratch)
            shared = {
                "/tmp", "/dev/shm",
                os.path.realpath(_tempfile_mountless.gettempdir()),
            }
            _mountless_call_writable = [scratch] + [
                path for path in (writable_paths or [])
                if path not in shared and os.path.realpath(path) not in shared
            ]
            _mountless_private_scratch = scratch
            scratch_env = {"TMPDIR": scratch, "TEMP": scratch, "TMP": scratch}
            kwargs["env"] = {**kwargs["env"], **scratch_env}
            _env_for_target = {**_env_for_target, **scratch_env}
            logger.debug(
                "Sandbox: read-restricted mountless execution replaces "
                "host-shared /tmp and /dev/shm grants with private scratch.",
            )
            return _mountless_call_writable, _env_for_target


        # Force FD close at fork. Python defaults close_fds=True on POSIX
        # but we reject explicit overrides — inheriting FDs from RAPTOR
        # into a sandboxed child is a capability leak (the child can read
        # / write parent FDs regardless of Landlock's path rules). Callers
        # that legitimately need to pass specific FDs (pipes for stdin
        # content, file handles for output) can use `pass_fds=[...]` which
        # is the documented subprocess.run escape hatch.
        if kwargs.get("close_fds") is False:
            msg_0 = (
                "sandbox().run() does not accept close_fds=False — "
                "inheriting open FDs into the sandboxed child defeats the "
                "isolation. Use `pass_fds=[fd, ...]` to pass specific FDs "
                "through while still closing the rest."
            )
            raise TypeError(msg_0)
        kwargs["close_fds"] = True

        # Reject shell=True. subprocess with shell=True reinterprets argv:
        # it invokes `/bin/sh -c argv[0]` with argv[1:] as $0/$1/...,
        # which interleaves catastrophically with our `unshare … -- cmd`
        # list construction — the sandbox bootstrap silently malfunctions
        # (unshare flags become sh arguments, target cmd becomes $0).
        # Also: a shell=True string is a trivial shell-injection surface
        # if any part is attacker-influenced. Force callers to pass a
        # list of args.
        if kwargs.get("shell"):
            msg_0 = (
                "sandbox().run() does not accept shell=True — pass the "
                "command as a list of args (e.g. [\"sh\", \"-c\", script]) "
                "so argv construction stays deterministic and no implicit "
                "shell expansion happens on attacker-influenced strings."
            )
            raise TypeError(msg_0)

        # pass_fds audit + socket guard. Inherited sockets bypass the
        # seccomp socket() / socketpair() filter entirely — a caller
        # that passes an AF_UNIX fd pointing at /var/run/docker.sock
        # (or similar) hands the sandboxed child a direct channel to
        # host services. Reject socket FDs outright; allow regular
        # files, pipes, block devices, TTYs. Runtime cost: one fstat
        # per pass_fds entry.
        _pass_fds_declared = kwargs.pop("pass_fds_declared", False)
        # stdin= carries a descriptor capability past every path-based
        # layer exactly like a pass_fds entry: the spawn backends dup2
        # it onto fd 0 unaudited, so a write-capable file fd, a dirfd
        # (getdents/openat into unlisted trees) or a socket smuggled
        # as stdin quietly bypassed the pass_fds gate below — whose
        # own refusal text even recommended "pass stdin= directly".
        # Audit it with the same policy (FIFO/tty/devnull exempt,
        # pass_fds_declared parity, sockets always refused).
        _stdin_kw = kwargs.get("stdin")
        _stdin_audit_fd = None
        if isinstance(_stdin_kw, int) and _stdin_kw >= 0:
            _stdin_audit_fd = _stdin_kw
        elif _stdin_kw is not None and hasattr(_stdin_kw, "fileno"):
            try:
                _stdin_audit_fd = _stdin_kw.fileno()
            except (OSError, ValueError):
                _stdin_audit_fd = None
        if kwargs.get("pass_fds") or _stdin_audit_fd is not None:
            import fcntl as _fcntl
            import stat as _stat

            def _fd_policy_problem(fd: int) -> str | None:
                """Why this fd grants an out-of-policy capability, or None.

                An inherited fd is a kernel capability that bypasses
                every path-based layer: Landlock attached its access
                rights when the PARENT opened it (pre-restriction), and
                the mount namespace never sees it. A $HOME file fd is
                readable under restrict_reads; a dirfd allows getdents/
                openat into unlisted trees; an anonymous fd (memfd,
                deleted inode) can smuggle executable content. Compare
                the fd's real target against the same policy the
                sandbox enforces on paths.
                """
                mode = os.fstat(fd).st_mode
                if _stat.S_ISFIFO(mode) or _stat.S_ISCHR(mode):
                    # Pipes are the documented stdio-plumbing shape;
                    # character devices (tty, /dev/null) grant nothing
                    # a sandboxed child doesn't already have.
                    return None
                if not (_stat.S_ISREG(mode) or _stat.S_ISDIR(mode)):
                    return "not a regular file, directory, pipe, or tty"
                try:
                    fd_target = os.readlink(f"/proc/self/fd/{fd}")
                except OSError:
                    fd_target = ""
                if not fd_target.startswith("/") or fd_target.endswith(
                        " (deleted)"):
                    return (f"anonymous or unlinked inode "
                            f"({fd_target or 'unresolvable'})")
                _writable = [os.path.abspath(w)
                             for w in (writable_paths or [])]
                _readable = [os.path.abspath(rp)
                             for rp in (effective_read_paths or [])]
                _readable.extend(os.path.abspath(base) for base in (target, output) if base)

                def _under(path: str, bases: list) -> bool:
                    return any(
                        path == b or path.startswith(b.rstrip("/") + "/")
                        for b in bases
                    )

                try:
                    _acc = _fcntl.fcntl(fd, _fcntl.F_GETFL) & os.O_ACCMODE
                except OSError:
                    _acc = os.O_RDWR
                _write_capable = (
                    _stat.S_ISREG(mode) and _acc in (os.O_WRONLY, os.O_RDWR)
                )
                if _write_capable and not _under(fd_target, _writable):
                    return (f"write-capable fd to {fd_target!r}, outside "
                            f"the sandbox's writable paths")
                if restrict_reads and not _under(
                        fd_target, _readable + _writable):
                    return (f"{'directory' if _stat.S_ISDIR(mode) else 'readable'} "
                            f"fd to {fd_target!r}, outside the read "
                            f"allowlist while restrict_reads is on")
                return None

            for fd in (kwargs.get("pass_fds") or ()):
                try:
                    mode = os.fstat(fd).st_mode
                except OSError as e:
                    msg_0 = (
                        f"sandbox().run(): pass_fds entry fd={fd} is not "
                        f"a valid open file descriptor ({e.__class__.__name__}: {e})"
                    )
                    raise TypeError(msg_0) from e
                if _stat.S_ISSOCK(mode):
                    # Sockets stay refused even under pass_fds_declared:
                    # they bypass the seccomp socket-family filter
                    # outright and there is no in-policy socket shape.
                    msg_0 = (
                        f"sandbox().run(): pass_fds entry fd={fd} is a "
                        f"socket. Inherited sockets bypass the seccomp "
                        f"socket() family filter — a compromised child "
                        f"could connect to the socket's peer (e.g. "
                        f"/var/run/docker.sock). Refusing. If you need "
                        f"to pass a pipe for stdin content, use a pipe "
                        f"fd (S_ISFIFO) or pass stdin= directly."
                    )
                    raise TypeError(msg_0)
                _problem = _fd_policy_problem(fd)
                if _problem:
                    if _pass_fds_declared:
                        logger.warning(
                            "Sandbox: pass_fds entry fd=%d grants an "
                            "out-of-policy capability (%s) — allowed "
                            "because the caller declared it with "
                            "pass_fds_declared=True.", fd, _problem,
                        )
                    else:
                        msg_0 = (
                            f"sandbox().run(): pass_fds entry fd={fd} "
                            f"grants an out-of-policy capability: "
                            f"{_problem}. Inherited fds bypass Landlock "
                            f"and the mount namespace (rights attached "
                            f"at open time, before restrictions). Pass "
                            f"pass_fds_declared=True to declare this "
                            f"capability grant explicitly, or open the "
                            f"file inside the sandbox's allowed paths."
                        )
                        raise TypeError(msg_0)
            if kwargs.get("pass_fds"):
                logger.info(
                    "Sandbox: caller passed pass_fds=%s for %r — these FDs are inherited by the sandboxed child.", kwargs['pass_fds'], ' '.join(cmd[:_CMD_DISPLAY_MAX_ARGS]) or cmd
                )
            if _stdin_audit_fd is not None:
                try:
                    _stdin_mode = os.fstat(_stdin_audit_fd).st_mode
                except OSError as e:
                    raise TypeError(
                        f"sandbox().run(): stdin= fd={_stdin_audit_fd} "
                        f"is not a valid open file descriptor "
                        f"({e.__class__.__name__}: {e})"
                    ) from e
                if _stat.S_ISSOCK(_stdin_mode):
                    raise TypeError(
                        f"sandbox().run(): stdin= fd={_stdin_audit_fd} "
                        f"is a socket. Inherited sockets bypass the "
                        f"seccomp socket() family filter — refusing "
                        f"(same policy as pass_fds)."
                    )
                _stdin_problem = _fd_policy_problem(_stdin_audit_fd)
                if _stdin_problem:
                    if _pass_fds_declared:
                        logger.warning(
                            "Sandbox: stdin= fd=%d grants an "
                            "out-of-policy capability (%s) — allowed "
                            "because the caller declared it with "
                            "pass_fds_declared=True.",
                            _stdin_audit_fd, _stdin_problem,
                        )
                    else:
                        raise TypeError(
                            f"sandbox().run(): stdin= fd="
                            f"{_stdin_audit_fd} grants an out-of-"
                            f"policy capability: {_stdin_problem}. "
                            f"The spawn backends dup2 caller stdin "
                            f"onto fd 0, so it is a descriptor "
                            f"capability exactly like a pass_fds "
                            f"entry (fd 0 even survives pivot_root). "
                            f"Use a pipe / input= for content, or "
                            f"pass pass_fds_declared=True to declare "
                            f"this grant explicitly."
                        )

        # Honor caller-supplied check= with subprocess.run semantics
        # (raise CalledProcessError on nonzero exit). Popped here — the
        # subprocess.run call sites below pass check=False explicitly
        # (PLW1510), so a duplicate from **kwargs would raise TypeError
        # — and applied at the single `return result` at the end.
        # Silently dropping it left callers' CalledProcessError
        # handlers dead while the docstring promised subprocess.run
        # parity (the binary-oracle corpus drivers pass check=True and
        # expect the raise to gate their build steps).
        _check_requested = bool(kwargs.pop("check", False))

        # `need_unshare`: this call's policy wants NAMESPACE isolation
        # (network block, mount tier, or a read restriction whose
        # /proc-credential closure needs a pid-ns). The modern spawn
        # backend is the only namespace lane — the legacy unshare-CLI
        # chain is deleted — so the predicate now steers spawn
        # eligibility (mountless mode when the mount tier isn't in
        # play) and the per-call fallback rechecks, never a
        # subprocess bootstrap.
        need_unshare = (use_sandbox
                        and not use_seatbelt
                        and (block_network or use_mount or restrict_reads))

        # Always set resource limits via preexec_fn. Only the plain
        # subprocess lane execs through it (the spawn backends run
        # their own child-side chain), and its payload never
        # legitimately unshares — so every subprocess-lane child gets
        # the variant that additionally denies namespace creation
        # (unshare/clone CLONE_NEW*, setns; clone3→ENOSYS). The
        # legacy unshare-CLI lane was the one lane that could not
        # take these rules (its bootstrap had to unshare under the
        # filter); that documented residual died with the lane.
        existing_preexec = kwargs.pop("preexec_fn", None)
        if existing_preexec:
            def combined() -> None:
                existing_preexec()      # Caller's setup first (may open FDs)
                preexec_ns_blocked()    # Our limits + Landlock last
            kwargs["preexec_fn"] = combined
        else:
            kwargs["preexec_fn"] = preexec_ns_blocked

        # Missing-tool resolution check, BEFORE any lane dispatch. A
        # command that resolves NOWHERE — not on the caller's PATH, not
        # on the child env's PATH, and (for absolute invocations) not
        # on the filesystem — cannot exec on ANY non-rootfs lane: the
        # mount view's bind sources, the private /tmp tmpfs (fresh and
        # empty per call), and the host-visible lanes are all subsets
        # of the host namespace, so an in-sandbox resolution can never
        # succeed where the host's failed. Raise the subprocess-parity
        # FileNotFoundError here, exactly what the plain-subprocess
        # lane raises natively and what callers' tool-missing arms
        # (`except FileNotFoundError: <tool> not installed`) have
        # always been written against. Routing this shape into the
        # spawn lane instead produced two doomed spawn attempts, a
        # speculative-failure cache entry that steered every LATER
        # call for the same name onto the mountless backend, and a
        # category-'X' SandboxSetupError — a containment-flavoured
        # refusal (BaseException, uncatchable by the tool-missing
        # arms) for what is a plain missing binary, not a containment
        # failure. Scope guards: rootfs runs resolve cmd[0] inside the
        # IMAGE tree (host resolution is meaningless there — the
        # existing rootfs gates own that shape); relative-with-
        # separator invocations resolve against the CHILD cwd (which
        # differs from the caller's) and are left to the lane; the
        # operator-disabled path already gets this exact exception
        # from subprocess.run itself.
        if (not effectively_disabled and rootfs is None
                and cmd and cmd[0]):
            _cmd0 = cmd[0]
            if os.sep not in _cmd0:
                _resolvable = bool(
                    shutil.which(_cmd0)
                    or shutil.which(_cmd0,
                                    path=kwargs["env"].get("PATH")))
            elif os.path.isabs(_cmd0):
                _resolvable = os.path.exists(_cmd0)
            else:
                _resolvable = True  # relative-with-sep: cwd-dependent
            if not _resolvable:
                raise FileNotFoundError(
                    errno.ENOENT, os.strerror(errno.ENOENT), _cmd0)

        # Namespace isolation is wanted whenever network / mount / read
        # policy is in play. Landlock filesystem isolation works
        # without namespaces, BUT in Landlock-only mode (no PID
        # namespace) a compromised child running under the host pid-ns
        # can read /proc/<host_pid>/environ for any same-UID host
        # process — including the parent RAPTOR process's env, which
        # is how ANTHROPIC_API_KEY / SSH credentials leak. Narrowing
        # /proc in the read allowlist doesn't work (Landlock
        # path_beneath binds to a specific inode, so subprocesses in
        # the sandbox get their OWN /proc/<pid>/ inode denied,
        # breaking ASAN/IFUNC/etc.). The fix is a PID namespace: the
        # kernel enforces ns-level access to /proc/<pid>/ entries
        # independently of the /proc mount. Trigger the namespace lane
        # whenever restrict_reads is on — PID ns + IPC ns + user ns,
        # without network ns unless block_network is also set (the
        # egress proxy needs the shared net ns to be reachable on
        # loopback). All namespace shapes run through the fork-based
        # spawn backend (mount tree when target/output engage it,
        # mountless otherwise); on macOS isolation comes from
        # sandbox-exec / SBPL via _macos_spawn (use_seatbelt vetoes
        # need_unshare above).

        # Representative engagement gate. The availability probes that
        # set `use_sandbox` test a NARROWER op (`unshare --user
        # --net`) than the spawn backend's os.unshare flag set
        # (user+pid+ipc[+net][+cgroup]+mount). On rootless podman /
        # distrobox (nested userns) the narrow probe can pass while
        # the full flag-set fails: the child dies BEFORE exec and the
        # call would surface as a late setup failure. Verify the full
        # flag-set engages (cached per flag-set, probed via the
        # unshare CLI as a stand-in for the same kernel capability)
        # and fail LOUD if it doesn't — RAPTOR does not silently
        # downgrade; the operator picks `--sandbox network-only`/
        # `none`. The mount-ns layer is additionally gated by
        # check_mount_available() upstream.
        if need_unshare:
            from .errors import SandboxSetupError
            from .probes import (
                ENGAGE_FAIL_INSTRUCTIONS,
                check_unshare_engages,
            )
            _engage_flags = ["--user", "--pid", "--fork", "--ipc"]
            # Same inherit_netns gate as the spawn backend's ns_flags:
            # the probe must test the flag-set the run will use.
            if block_network and not _inherit_netns:
                _engage_flags.append("--net")
            # CLONE_NEWCGROUP joins the spawn backend's flag set
            # unconditionally; probe it when the CLI can express it —
            # a kernel/policy that refuses CLONE_NEWCGROUP must not
            # slip past the gate.
            from .probes import unshare_supports_cgroup
            if unshare_supports_cgroup():
                _engage_flags.append("--cgroup")
            _engages, _engage_reason = check_unshare_engages(_engage_flags)
            if _engages is False:
                # Definitive kernel refusal (rootless podman / nested userns).
                msg_0 = (
                    f"sandbox namespace setup failed "
                    f"(unshare {' '.join(_engage_flags)}): {_engage_reason}"
                )
                raise SandboxSetupError(
                    msg_0,
                    ENGAGE_FAIL_INSTRUCTIONS,
                )
            if _engages is None:  # noqa: SIM102
                # Probe couldn't RUN (transient load) — NOT a verdict. Do
                # NOT abort a possibly-working scan; proceed and let a real
                # engagement failure surface at spawn (exec-status pipe).
                if state.warn_once("_engage_probe_indeterminate_warned"):
                    logger.warning(
                        "Sandbox: engagement probe could not run (%s) — "
                        "proceeding; a real namespace failure will still be "
                        "caught at spawn.", _engage_reason,
                    )

        # Log active sandbox layers for this command. Cache the Landlock
        # probe locally so we don't reacquire the cache lock 2-3× per run().
        landlock_available = check_landlock_available()
        layers = []
        if need_unshare and block_network:
            layers.append("net")
        if need_unshare:
            layers.append("pid")
        if use_mount:
            layers.append("mount")
        if writable_paths and landlock_available:
            layers.append("landlock")
        if allowed_tcp_ports and landlock_available:
            layers.append(f"tcp:{','.join(str(p) for p in allowed_tcp_ports)}")
        elif _degraded_tcp_deny and landlock_available:
            layers.append("tcp:deny-all")
        if seccomp_profile and check_seccomp_available():
            layers.append(f"seccomp:{seccomp_profile}")
        # NPROC enforcement (spawn grandchild setrlimit), only
        # meaningful when the fresh user-ns makes the ns-UID's process
        # count start at zero. Per-run() because need_unshare is
        # per-call.
        nproc_limit = effective_limits.get("nproc", 0)
        if need_unshare and nproc_limit > 0:
            layers.append(f"nproc:{nproc_limit}")
        layers.append("limits")
        # Sanitise cmd_display before it reaches any logger. cmd args
        # can originate from filenames in a target repo (e.g. gcc -c
        # /path/to/repo/src/evil\x1b[31m.c), and a logger.info that
        # interpolates raw control chars into a live terminal lets the
        # repo author inject ANSI escape sequences into operator output
        # — colour flips, title spoofing, cursor moves that forge prior
        # log lines. See core.security.log_sanitisation.
        from core.security.log_sanitisation import escape_nonprintable
        cmd_display = escape_nonprintable(
            " ".join(cmd[:_CMD_DISPLAY_MAX_ARGS]) or "<empty cmd>"
        )
        logger.debug("Sandbox (%s): %s", "+".join(layers), cmd_display)

        # Register this run with the proxy BEFORE the subprocess so every
        # tunnel event generated during the call is fanned into a per-run
        # buffer. Unlike the old shared-deque + time-cutoff design (which a
        # misbehaving child could flood to push earlier denied CONNECTs out
        # of the 1024-entry ring before the sandbox ended), each run's
        # buffer grows independently. Must be unregistered in a finally so
        # a subprocess exception doesn't leak the registration and slowly
        # leak memory across future sandbox()/run() calls.
        #
        # Why per-run rather than per-sandbox-context: the proxy's isolation
        # guarantee (concurrent sandbox A can't flood sandbox B's buffer)
        # needs one distinct token per observation window. Per-run tokens
        # give each result.sandbox_info["proxy_events"] exactly the events
        # that happened during THAT subprocess. For a sandbox() block with
        # multiple run() calls, the accumulated view is exposed as
        # `run.events` (see below).
        proxy_token = None
        # Mount-ns path: bypass subprocess+preexec entirely. _spawn
        # handles fork + newuidmap + mount + Landlock + seccomp + pid-ns
        # in the right order (mount ops MUST precede Landlock install on
        # kernel 6.15+). Falls back to the subprocess+preexec path if
        # the spawn raises FileNotFoundError (no newuidmap) or the child
        # setup fails — adaptive so we still get Landlock-only when
        # mount-ns is unusable.
        used_spawn = False
        # Reason string when the mount-ns spawn path was ATTEMPTED but
        # fell back (exec failure retry, setup exception). Distinct
        # from "never eligible": a caller that relied on mount-ns
        # semantics (map_root pivot_root, per-ns /tmp, binds) can
        # check result.sandbox_info["mount_ns_degraded"] instead of
        # scraping stderr warnings.
        _mount_ns_degraded = None
        # The original backend failure when the demotion came via the
        # mid-setup spawn EXCEPTION ladder (the environmental except arm
        # below) or a synthesised carrier when it came via a status-byte
        # / achievability rerouting, kept so the fallback lanes' floor
        # checks can chain their refusal to the real failure. None on
        # every other demotion route.
        _spawn_ladder_err: BaseException | None = None
        _audit_landlock_engaged = False
        # Why audit could not engage for this call, for the degrade
        # marker / audit_required raise at the no-audit bottleneck
        # below. Set by the pre-flight ineligibility block and by the
        # runtime failure sites (spawn exception, Landlock-only tracer
        # exception); None while audit is still expected to engage.
        _audit_no_engage_reason = None
        _audit_no_engage_instr = ""
        # _spawn doesn't replicate every subprocess.run kwarg through its
        # manual os.fork() path. The Landlock-only subprocess.run path
        # handles them natively via Python's posix_spawn logic. Route
        # callers that use one of these kwargs down the Landlock-only
        # path rather than silently dropping them:
        #   - `pass_fds`: inherited FDs into the child
        #   - `input`: bytes/str piped to child's stdin (needs a writer
        #     thread to avoid pipe-fill deadlock on large inputs)
        # (`stdin=<fd>` IS plumbed through _spawn.run_sandboxed, so we
        # only exclude `input=` here, not plain stdin=.)
        # The kwarg-compat gate is LINUX-ONLY: _spawn's os.fork()
        # chain can't plumb pass_fds/input=. macOS _macos_spawn wraps
        # subprocess.run, which handles both natively (caller fds
        # union with the shim's status/death pipes; input= uses
        # subprocess's own communicate machinery) — disqualifying
        # darwin here used to SILENTLY drop seatbelt for such calls,
        # leaving the child rlimits-only with no signal outside audit
        # mode.
        _kwarg_plumb_native = use_seatbelt  # subprocess-backed spawn
        # input= no longer disqualifies the fork backend: the spawn
        # chain maps stdin FDs natively, so witness bytes convert to
        # an UNLINKED private tempfile served as fd 0. Pre-fix,
        # feeding a PoC its witness via input= silently routed the
        # run onto the no-mount-ns fallback — host-pid /proc visible
        # to exactly the attacker-derived code the witness drives
        # (the full host argv surface, including concurrent runs'
        # credential-bearing command lines). pass_fds remains the one
        # disqualifier (real multi-fd plumbing, no caller on the
        # untrusted contract).
        if (sys.platform != "darwin" and (use_mount or need_unshare)
                and kwargs.get("input") is not None
                and not kwargs.get("pass_fds")):
            # subprocess.run's own contract, enforced here because the
            # conversion below would otherwise silently prefer input=.
            if kwargs.get("stdin") is not None:
                raise ValueError(
                    "stdin and input arguments may not both be used.")
            import tempfile as _tf_mod
            _in_payload = kwargs.pop("input")
            if isinstance(_in_payload, str):
                _enc = kwargs.get("encoding") or "utf-8"
                _in_payload = _in_payload.encode(_enc, "strict")
            _stdin_spool = _tf_mod.TemporaryFile()
            _stdin_spool.write(_in_payload)
            _stdin_spool.flush()
            # Re-open the spool read-only through the fd-path so the
            # target's fd 0 carries no write capability — the RW
            # description would let it grow a host-tmp file to
            # RLIMIT_FSIZE. The new description starts at offset 0.
            _ro_fd = os.open(f"/proc/self/fd/{_stdin_spool.fileno()}",
                             os.O_RDONLY)
            _stdin_spool.close()
            _stdin_spool_ro = open(_ro_fd, "rb")
            # Integrity gate on the description the child will read:
            # a short or empty spool silently turns a witness-driven
            # run into "input never arrived" — the target exits clean
            # and the caller records a wrong verdict instead of an
            # error. Fail loud here instead.
            _spool_size = os.fstat(_ro_fd).st_size
            if _spool_size != len(_in_payload):
                _stdin_spool_ro.close()
                from .errors import SandboxSetupError
                msg_0 = (
                    f"sandbox stdin spool integrity check failed: "
                    f"wrote {len(_in_payload)} input= bytes but the "
                    f"re-opened spool holds {_spool_size} — refusing "
                    f"to run the target with truncated stdin."
                )
                raise SandboxSetupError(
                    msg_0,
                    "the tempdir filesystem dropped buffered writes "
                    "on reopen; check TMPDIR (disk full, exotic "
                    "filesystem) or pass stdin=<fd> directly.",
                )
            kwargs["stdin"] = _stdin_spool_ro
            # Lifetime: this frame outlives the synchronous spawn (the
            # child dup2s the fd before exec), and CPython closes the
            # unlinked spool at frame exit — no path ever exists for
            # any principal to race, and nothing leaks.
        # need_unshare joins the eligibility predicate: with the
        # unshare-CLI lane deleted, the fork-based spawn backend is
        # the ONLY namespace lane, so every namespace-needing shape —
        # including no-target/output block_network runs and
        # restrict_reads on mount-incapable hosts — routes through it
        # (mountlessly when the mount tier isn't in play).
        spawn_eligible = ((use_mount or use_seatbelt or need_unshare)
                          and (_kwarg_plumb_native
                               or (not kwargs.get("pass_fds")
                                   and kwargs.get("input") is None)))
        # Rootfs fail-closed gate #2 (per-call): the kwarg-compat gate
        # above routes pass_fds/input= callers to the Landlock-only
        # subprocess path, which for a rootfs run means executing
        # against the HOST filesystem. Refuse instead.
        if rootfs is not None and not spawn_eligible:
            from .errors import SandboxSetupError
            msg_0 = (
                "sandbox(rootfs=...).run() cannot engage the mount-ns "
                "spawn backend for this call (pass_fds= / input= are "
                "not plumbed through the fork-based spawn path) — "
                "refusing to run against the host filesystem."
            )
            raise SandboxSetupError(
                msg_0,
                "drop pass_fds=/input= (write stdin via stdin=<fd> "
                "instead) or run without rootfs=.",
            )
        # Track the audit-degraded reason so the audit-mode degraded
        # diagnostic block (further down) can attribute correctly.
        # B fallback and speculative-cache hit are NEW failure paths
        # added in PR #265; the audit code's existing block only knew
        # about mount-ns/pass_fds/input. Distinct reason strings help
        # operators understand WHY audit didn't engage.
        _b_fallback_reason = None
        _b_fallback_instr = None
        _prefer_mountless_spawn = False
        _spawn_without_mount = _skip_mount_ns
        # Per-call check that cmd[0] is visible inside the mount-ns
        # bind tree. The bind tree is fixed: standard system dirs,
        # target/output, /tmp (per-sandbox tmpfs), and the union of
        # readable_paths + tool_paths. Anything else (pip --user
        # install at ~/.local/bin, homebrew at /opt/homebrew/bin,
        # pyenv shims, ad-hoc /home/USER/bin) is invisible inside
        # the new rootfs — the subprocess fails with ENOENT (exit
        # 127) and an empty stderr that operators may misread as
        # "tool found nothing" rather than "tool didn't run".
        # macOS sandbox-exec doesn't change the filesystem view, so
        # this check + the speculative-C cache it feeds are skipped
        # on Darwin (use_mount is always False there).
        # Both per-command mountless selections below (B fallback and the
        # speculative-C cache) reason about the host-mode bind tree;
        # in rootfs mode cmd[0] resolves inside the IMAGE filesystem
        # (its /bin/sh, its entrypoint script), so the host visibility
        # check would demote perfectly valid commands — and demotion
        # is forbidden for rootfs anyway (gate #2). Skip both.
        if spawn_eligible and use_mount and cmd and rootfs is None:
            _all_extra = list(effective_read_paths or []) + list(tool_paths or [])
            _resolved = shutil.which(cmd[0]) or cmd[0]
            # B fallback: cmd[0] not in mount-ns bind tree → skip
            # mount-ns directly.
            if not _cmd_visible_in_mount_tree(cmd, target, output, _all_extra):
                logger.debug(
                    "Sandbox: mountless namespace backend for cmd[0]=%r "
                    "(resolved=%r, outside mount-ns bind tree). "
                    "Install under a system dir (/usr/local/bin) "
                    "or pass tool_paths=[<dir>] to engage mount-ns.",
                    cmd[0], _resolved,
                )
                _prefer_mountless_spawn = True
                _b_fallback_reason = (
                    f"cmd[0]={cmd[0]!r} (resolved={_resolved!r}) is "
                    f"outside the mount-ns bind tree; sandbox used the "
                    f"mountless namespace backend")
                _b_fallback_instr = (
                    "install the tool under a system dir "
                    "(/usr/local/bin) or pass tool_paths=[<bin_dir>] "
                    "to extend the mount-ns bind tree.")
            # Speculative-C cache: cmd[0] previously failed mount-ns
            # at exec (typical Python tool with native exec deps not
            # in any reasonable bind set). Skip the doomed mount-ns
            # attempt entirely — saves ~100-300ms per call.
            elif _resolved in state._speculative_failure_cache:
                logger.debug(
                    "Sandbox: mountless namespace backend for cmd[0]=%r; "
                    "speculative-failure cache hit (mount-ns "
                    "previously failed at exec for this binary)",
                    cmd[0],
                )
                _prefer_mountless_spawn = True
                _b_fallback_reason = (
                    f"cmd[0]={cmd[0]!r} previously failed mount-ns at "
                    f"exec; cached for the mountless namespace backend")
                _b_fallback_instr = (
                    "the binary's native exec deps are outside any "
                    "reasonable mount-ns bind set; audit can't engage "
                    "for this tool. Other tools in the same workflow "
                    "still audit normally.")

        def _mountless_unachievable_reason() -> "str | None":
            """Why the mountless namespace backend is not ACHIEVABLE
            for this workload on this host, or None.

            Landlock ABI is a host property identical at every tier —
            a capability axis, never a tier — so a low ABI does not
            move a lane in the lattice; it removes the mountless lane
            from the achievable set for the workloads whose write
            policy it breaks: without the TRUNCATE access right
            (ABI 3, kernel 6.2), truncate(2)/open(O_TRUNC) outside the
            write allowlist cannot be blocked on a host-visible
            filesystem, so the mountless lane cannot honour an
            untrusted or read-restricted call's write policy. A
            demotion that would have retried mountlessly continues
            down the ladder instead, where the floor comparison
            decides admission: an unwaived untrusted call is refused
            (its floor is the mount tier), a waived one proceeds on a
            lane whose weaker contract the waiver documents (host-path
            and host-procfs exposure) rather than on a lane with an
            exposure the waiver never covered. Scoped to the automatic
            demotion routes only — a caller-declared skip_mount_ns=True
            lane choice is not second-guessed here.
            """
            if ((_untrusted_workload or restrict_reads)
                    and check_landlock_available()
                    and _get_landlock_abi() < 3):
                return ("Landlock ABI is below 3 — truncate operations "
                        "outside the write allowlist cannot be blocked "
                        "on a host-visible filesystem")
            return None

        if _prefer_mountless_spawn:
            _mountless_abi_block = _mountless_unachievable_reason()
            if _mountless_abi_block:
                # The mountless lane is out of the achievable set for
                # this workload — continue down the demotion ladder
                # (the fallback dispatch's floor check decides whether
                # the demoted lane is admitted for this call).
                _prefer_mountless_spawn = False
                spawn_eligible = False
                _why = (_b_fallback_reason
                        or "command is outside the bind tree")
                _mount_ns_degraded = (
                    f"{_why}; mountless namespace backend not "
                    f"achievable ({_mountless_abi_block})")
                _spawn_ladder_err = _errors.SandboxSetupError(
                    _mount_ns_degraded, setup_category="X")
                if state.warn_once("_mountless_unachievable_warned"):
                    # Loud like every other demotion route — see the
                    # M/X reroute's rationale.
                    logger.warning(
                        "Sandbox: the mountless namespace backend is "
                        "not achievable for this call (%s) — "
                        "continuing down the demotion ladder; the "
                        "containment floor decides admission, and the "
                        "demoted lane enforces read/write policy with "
                        "Landlock alone.",
                        _mountless_abi_block,
                    )
        if _prefer_mountless_spawn:
            if state.warn_once("_mountless_backend_warned"):
                logger.warning(
                    "Sandbox: bind-tree isolation unavailable for %r; using "
                    "the mountless namespace backend. Host paths remain "
                    "visible by name; Landlock enforces the requested read "
                    "and write policy. Later cache hits log at debug level.",
                    cmd[0],
                )
        # Persona fail-closed gate (pre-spawn arm): every route that
        # abandons the mount-ns spawn path — pass_fds/input= kwarg
        # compat, the B fallback (cmd[0] outside the bind tree), a
        # speculative-failure-cache hit, or a per-call
        # skip_mount_ns=True — runs the command WITHOUT the
        # fingerprint persona (it only rides run_sandboxed's mount-ns
        # setup). A require_sanitisation caller must get a refusal,
        # not a silent host-real run. Mirrors rootfs gate #2 above;
        # the post-spawn M/X arm is gated separately below.
        if (_persona is not None and require_sanitisation
                and (not spawn_eligible or _skip_mount_ns
                     or _prefer_mountless_spawn)):
            from .errors import SandboxSetupError
            _reason = (
                _b_fallback_reason
                or ("per-call skip_mount_ns=True bypasses the "
                    "mount-ns backend" if _skip_mount_ns else
                    "pass_fds=/input= are not plumbed through the "
                    "fork-based spawn path")
            )
            msg_0 = (
                f"sandbox(require_sanitisation=True).run() cannot "
                f"engage the mount-ns spawn backend for this call "
                f"({_reason}) — refusing the reduced filesystem path, "
                f"which cannot apply the fingerprint persona."
            )
            raise SandboxSetupError(
                msg_0,
                _b_fallback_instr
                or "drop pass_fds=/input=/skip_mount_ns= for this "
                   "call, or drop require_sanitisation= to accept "
                   "host-real identity surfaces on degrade.",
            )
        # NOTE: the former fresh-procfs pre-spawn gate lived here. Its
        # shapes are now covered by the containment-floor contract:
        # per-call skip_mount_ns= refuses at the entry-time check, the
        # B-fallback / speculative-cache routes refuse at the mountless
        # dispatch (with the route's own tool_paths= remedy), and the
        # pass_fds kwarg-demoted route refuses at the fallback-lane
        # dispatch — all before any spawn attempt, all naming the
        # override through the same honesty-checked hint.
        # Audit mode (b2/b3) requires the _spawn path because the
        # tracer needs to PTRACE_SEIZE a target the parent forked
        # itself. The Landlock-only fallback uses bare subprocess.run
        # which doesn't surface the target's pid for ptrace attach.
        # If audit was requested but spawn isn't eligible, warn the
        # operator that b2/b3 silently degrade. b1 (egress proxy
        # log-mode) is independent and still works.
        # Use `nonlocal_audit_mode` (the per-call effective state) not
        # `audit_mode` (the global request) — internal helper sandboxes
        # without target/output have already been silently demoted at
        # line ~620 ("case 2: CLI flag + internal helper without
        # output"). Firing the degradation warning for those calls is
        # noise.
        # Probe whether the Landlock-only audit helper can engage on
        # this host. When True, the spawn dispatch will route through
        # ``_landlock_audit.run_landlock_audit`` instead of bare
        # ``subprocess.run``, restoring observe signal. Suppress the
        # degrade marker / warning in that case — audit IS engaging,
        # just via a different mechanism. Probed eagerly here so the
        # marker decision and the eventual dispatch agree on whether
        # this run is "audit-degraded" or not.
        _landlock_audit_eligible = False
        if nonlocal_audit_mode and not spawn_eligible:
            try:
                from .ptrace_probe import (
                    check_ptrace_available as _la_pre_ptp,
                )
                from .seccomp import (
                    check_seccomp_available as _la_pre_sca,
                )
                _landlock_audit_eligible = bool(
                    _la_pre_sca() and _la_pre_ptp() and seccomp_profile
                )
            except ImportError:
                _landlock_audit_eligible = False
        if (nonlocal_audit_mode and not spawn_eligible
                and not _landlock_audit_eligible):
            # Distinguish the actual root cause. PR #265 added two new
            # failure paths (B fallback, cache hit) — those provide
            # their own _b_fallback_reason; otherwise fall through to
            # the audit-PR's original reasons (host blocked, pass_fds,
            # input).
            degrade_reason, degrade_instr = _audit_degrade_reason(
                _b_fallback_reason, _b_fallback_instr,
                target, output, kwargs,
            )
            _audit_no_engage_reason = degrade_reason
            _audit_no_engage_instr = degrade_instr
            if state.warn_once("_audit_warned_no_spawn"):
                logger.warning(
                    "Sandbox: --audit requested but %s; syscall + "
                    "filesystem audit (b2/b3) silently degrade to "
                    "enforcement. Network audit (b1): on the netns "
                    "tier the fallback child has NO network path (its "
                    "empty netns has no forwarder), so b1 records "
                    "nothing for it; on the Landlock-TCP tier b1 is "
                    "unaffected. Fix: %s",
                    degrade_reason, degrade_instr,
                )
            # Per-call marker so operators inspecting an output dir can
            # distinguish "audit ran, found nothing" (no marker, no
            # sandbox-summary.json) from "audit was requested but didn't
            # actually run on this host" (this marker present). A
            # log-only warning is easy to miss in agentic where dozens
            # of subprocesses run in parallel and the first warning
            # scrolls off; the marker is per-output-dir and discoverable
            # after the fact.
            #
            # Marker location: audit_run_dir takes precedence (it's the
            # canonical "where audit signal lands" path); fall back to
            # output. Callers like codeql analyze pass audit_run_dir
            # WITHOUT output (they want audit signal in a specific dir
            # without taking a Landlock writable_paths restriction). If
            # neither is set, the call's audit was already demoted
            # silently upstream — no marker needed.
            _marker_dir = audit_run_dir or output
            # Floor guard: a call whose containment floor sits above
            # every fallback lane is about to REFUSE, not degrade —
            # writing the audit-degraded marker for a run that never
            # executes would make marker consumers count phantom
            # degraded runs.
            if _marker_dir and _floor <= _tiers.ContainmentTier.NS_NOMOUNT:
                from pathlib import Path as _Path

                from . import summary as _summary_mod
                _summary_mod.record_audit_degraded(
                    _Path(_marker_dir),
                    reason=degrade_reason,
                    instructions=degrade_instr,
                )
        # The try/finally that unregisters the proxy token must wrap
        # BOTH paths (spawn + subprocess.run). Without this, an
        # unexpected exception from _spawn.run_sandboxed (anything
        # other than the FileNotFoundError/RuntimeError we catch for
        # graceful fallback) would escape and leak the proxy token
        # plus lose any events that had been buffered — the proxy's
        # per-sandbox dict would grow unboundedly across a long
        # session with flaky sandboxes.
        try:
            # Lane-scoped buffer (D3): subscribe to THIS context's
            # transport so concurrent runs' events segregate. No lane
            # (bind failure / advisory tier) degrades to the
            # run-global view — over-capture, never dropped.
            proxy_token = (
                proxy_instance.register_sandbox(
                    caller_label=caller_label,
                    lane_key=(_proxy_unix_path if _use_proxy_netns
                              else _proxy_tcp_lane_port),
                    host_recon_threshold=host_recon_threshold_for_profile(
                        profile or DEFAULT_PROFILE,
                        _proxy_mod.DEFAULT_HOST_RECON_THRESHOLD,
                    ),
                )
                if proxy_instance is not None else None
            )
            if spawn_eligible and use_seatbelt:
                # macOS sandbox-exec path. No fork/pivot_root chain; no
                # mount-ns fallback ladder. sandbox-exec wraps a single
                # execvp with the SBPL profile applied via Sandbox.kext.
                # No bind-tree visibility check, no speculative-C cache —
                # the filesystem view is unchanged, so the typical
                # mount-ns failure modes don't exist.
                from . import _macos_spawn as _macos_mod
                _audit_run_dir = (
                    (audit_run_dir or output)
                    if nonlocal_audit_mode else None
                )
                _mac_readable = list(effective_read_paths or [])
                for _tp in (tool_paths or []):
                    if _tp and _tp not in _mac_readable:
                        _mac_readable.append(_tp)
                # Containment-floor contract, side 2: seatbelt is the
                # platform's top tier — the check never refuses here,
                # but every executor routes through the checked
                # dispatch so the contract stays total.
                result = _dispatch_floor_check(
                    "seatbelt spawn",
                    executor=lambda: _macos_mod.run_sandboxed(
                    cmd,
                    target=target, output=output,
                    block_network=block_network,
                    nproc_limit=nproc_limit,
                    limits=effective_limits,
                    writable_paths=writable_paths or [],
                    readable_paths=_mac_readable,
                    allowed_tcp_ports=list(allowed_tcp_ports)
                        if allowed_tcp_ports else None,
                    # Linux-only kwargs accepted for signature parity
                    # with _spawn.run_sandboxed; ignored by SBPL backend.
                    seccomp_profile=seccomp_profile,
                    # profile NAME so seatbelt can layer the
                    # macos-strict extras (strict and full share
                    # seccomp_profile="full").
                    sandbox_profile=(profile if profile is not None
                                     else DEFAULT_PROFILE),
                    seccomp_block_udp=seccomp_block_udp,
                    env=_env_for_target,
                    cwd=kwargs.get("cwd"),
                    timeout=kwargs.get("timeout"),
                    capture_output=kwargs.get("capture_output", False),
                    text=kwargs.get("text", False),
                    stdin=kwargs.get("stdin"),
                    # Plumbed natively by the subprocess-backed macOS
                    # spawn (see the spawn_eligible gate) — these two
                    # kwargs must never silently cost the seatbelt.
                    pass_fds=kwargs.get("pass_fds"),
                    input=kwargs.get("input"),
                    audit_mode=nonlocal_audit_mode,
                    audit_run_dir=_audit_run_dir,
                    audit_required=audit_required,
                    audit_verbose=audit_verbose_active and nonlocal_audit_mode,
                    observe_mode=observe and nonlocal_audit_mode,
                    observe_nonce=(nonlocal_observe_nonce
                                   if observe and nonlocal_audit_mode
                                   else None),
                    restrict_reads=restrict_reads,
                    use_egress_proxy=use_egress_proxy,
                    proxy_port=(
                        (_proxy_tcp_lane_port or proxy_instance.port)
                        if proxy_instance is not None else None),
                    fake_home=fake_home,
                    exclude_tmp_baseline=exclude_tmp_baseline,
                    map_root=map_root,
                    start_new_session=_start_new_session,
                    # Keep-trust decision, out-of-band (watcher-shim
                    # argv): only this dispatch may mint it, keyed on
                    # the sanctioned kwarg. Pre-fix the seatbelt dispatch never sent
                    # it, so run_untrusted_networked(
                    # keep_trust_markers=True) — RAPTOR's own claude -p
                    # skill-dispatch lane — delivered children on macOS
                    # that could not pass the libexec trust gates or
                    # resolve their session binding.
                    keep_trust_markers=keep_trust_markers_for_dispatch,
                    # The public wrapper has already filtered the caller's
                    # environment above, before adding RAPTOR-owned HOME,
                    # proxy, and scratch overrides.  Reapplying strict_env in
                    # the backend would remove those trusted overrides (most
                    # importantly TMPDIR) and send grandchildren back to the
                    # host /tmp.  Direct backend callers still retain the
                    # backend's defence-in-depth filtering.
                    strict_env=False,
                ))
                used_spawn = True
                # Fail-loud parity with the Linux exec-status pipe. The macOS
                # seatbelt shim reports via result._setup_status:
                #   None     -> target reached inside the applied profile.
                #   ("P", m) -> a granted path's identity pin (dev/ino)
                #               stopped matching mid-run; the watcher shim
                #               SIGKILLed the sandbox tree. Linux 'P'
                #               parity: fail loud, never degrade, never
                #               return the tainted result.
                #   ("E", m) -> the in-sandbox readiness byte never arrived =>
                #               sandbox-exec did not apply the profile. There
                #               is no Landlock layer to degrade to on macOS, so
                #               the only safe response is to fail loud rather
                #               than silently run unsandboxed ("0 findings").
                #   other    -> default-DENY, mirroring the Linux parent's
                #               unknown-category arm: a category this parent
                #               does not recognise means a setup/tamper step
                #               reported something it cannot interpret, and
                #               falling through as a genuine target result
                #               is the same default-allow shape that let a
                #               new demotion lane ship ungated on Linux.
                _mac_status = getattr(result, "_setup_status", None)
                if _mac_status is not None and _mac_status[0] == "E":
                    from .errors import SandboxSetupError
                    from .probes import SEATBELT_FAIL_INSTRUCTIONS
                    msg_0 = f"sandbox seatbelt setup failed: {_mac_status[1]}"
                    raise SandboxSetupError(
                        msg_0,
                        SEATBELT_FAIL_INSTRUCTIONS,
                        setup_category=_mac_status[0],
                    )
                if _mac_status is not None and _mac_status[0] == "P":
                    from .errors import SandboxSetupError
                    msg_0 = (
                        f"sandbox grant-path pin violated: "
                        f"{_mac_status[1]}"
                    )
                    raise SandboxSetupError(
                        msg_0,
                        "a granted target/output/writable path changed "
                        "identity mid-run (symlink or rename swap) and "
                        "the sandbox was killed. Re-create the directory "
                        "and re-run; never point grants at "
                        "attacker-writable parents.",
                        setup_category="P",
                    )
                if _mac_status is not None:
                    from .errors import SandboxSetupError
                    raise SandboxSetupError(
                        f"sandbox seatbelt backend reported an "
                        f"unrecognised setup-status category "
                        f"{_mac_status[0]!r}: {_mac_status[1]}",
                        "treating an unknown status as a genuine result "
                        "would be a default-allow on the security "
                        "boundary. Update RAPTOR so this parent and the "
                        "seatbelt backend agree on the status "
                        "vocabulary.",
                        setup_category=_mac_status[0],
                    )
            elif spawn_eligible:
                try:
                    from . import _spawn as _spawn_mod
                    if rootfs is not None and not _spawn_mod.mount_ns_available():
                        # Rootfs fail-closed gate #3: use_mount passed at
                        # context setup but the spawn backend's own probe
                        # disagrees — the Landlock-only fallback below
                        # would run against the host filesystem.
                        from .errors import SandboxSetupError
                        msg_0 = (
                            "sandbox(rootfs=...): mount-ns spawn backend "
                            "unavailable — refusing to run against the "
                            "host filesystem."
                        )
                        raise SandboxSetupError(
                            msg_0,
                            "check unprivileged-userns support "
                            "(kernel.unprivileged_userns_clone, AppArmor "
                            "userns restrictions) and uidmap tooling.",
                        )
                    if _spawn_mod.mount_ns_available():
                        # Union readable_paths + tool_paths into the
                        # single readable_paths list _spawn forwards as
                        # mount-ns extra_ro_paths. tool_paths is just a
                        # named view of "extra dirs to bind-mount so a
                        # caller-known tool's binary/deps are visible";
                        # mount-ns layer doesn't need to distinguish.
                        _readable_with_tools = list(effective_read_paths or [])
                        for _tp in (tool_paths or []):
                            if _tp and _tp not in _readable_with_tools:
                                _readable_with_tools.append(_tp)
                        # Audit mode: thread audit_mode + audit_run_dir
                        # through to _spawn so the seccomp filter uses
                        # SCMP_ACT_TRACE and the tracer subprocess runs.
                        # Resolution order for the JSONL home:
                        #   1. explicit audit_run_dir kwarg — for callers
                        #      that want audit signal WITHOUT taking a
                        #      Landlock writable_paths restriction (e.g.
                        #      codeql analyze, where writes legitimately
                        #      go to ~/.codeql/cache, the database dir,
                        #      etc., none of which can be enumerated as
                        #      writable_paths without breaking the tool)
                        #   2. fall back to `output` — preserves the
                        #      original behaviour for callers that
                        #      already pass output and want a single
                        #      directory for both purposes.
                        _audit_run_dir = (
                            (audit_run_dir or output)
                            if nonlocal_audit_mode else None
                        )
                        # skip_mount_ns: no bind-tree, host FS visible.
                        # Landlock enforces the read allowlist directly —
                        # effective_read_paths already enumerates the same
                        # system-dirs floor the reduced filesystem path
                        # uses (/usr, /lib, /etc, /proc, /sys, target,
                        # tool_paths), so restrict_reads works without a
                        # mount tree. Pre-fix this branch forced
                        # restrict_reads=False, which silently stripped
                        # read protection from skip_mount_ns callers that
                        # asked for it (frida's wrapper passes both).
                        # Without restrict_reads there is nothing to
                        # enforce: pass None so tool_paths alone never
                        # engages read restriction on a host-visible fs.
                        _spawn_readable = (
                            (_readable_with_tools if restrict_reads else None)
                            if _skip_mount_ns
                            else _readable_with_tools
                        )
                        _spawn_restrict_reads = restrict_reads
                        # Unix-lane peer gate registration: hand the
                        # spawn child's pid (root of the sandbox
                        # process tree, including the proxy forwarder)
                        # to the proxy so the lane's SO_PEERCRED gate
                        # admits THIS run's tree and nothing else.
                        # Deregistered in the finally below.
                        _lane_peer_pids: list[int] = []

                        def _register_lane_peer(pid: int) -> None:
                            if _use_proxy_netns and _proxy_unix_path:
                                if proxy_instance.add_lane_peer_root(
                                        _proxy_unix_path, pid):
                                    _lane_peer_pids.append(pid)

                        def _run_spawn_backend(
                                *, skip_mount: bool,
                        ) -> subprocess.CompletedProcess:
                            _call_writable = list(writable_paths or [])
                            _call_env = _env_for_target
                            if skip_mount:
                                _call_writable, _call_env = (
                                    _mountless_write_policy()
                                )
                            return _spawn_mod.run_sandboxed(
                                cmd,
                                target=target, output=output,
                                rootfs=rootfs,
                                block_network=block_network,
                                nproc_limit=nproc_limit,
                                limits=effective_limits,
                                writable_paths=_call_writable,
                                readable_paths=_spawn_readable,
                                allowed_tcp_ports=list(allowed_tcp_ports)
                                if allowed_tcp_ports else None,
                                seccomp_profile=seccomp_profile,
                                seccomp_block_udp=seccomp_block_udp,
                                env=_call_env,
                                cwd=kwargs.get("cwd"),
                                timeout=kwargs.get("timeout"),
                                capture_output=kwargs.get("capture_output", False),
                                text=kwargs.get("text", False),
                                stdin=kwargs.get("stdin"),
                                stdout=kwargs.get("stdout"),
                                stderr=kwargs.get("stderr"),
                                audit_mode=nonlocal_audit_mode,
                                audit_run_dir=_audit_run_dir,
                                audit_required=audit_required,
                                audit_verbose=audit_verbose_active and nonlocal_audit_mode,
                                observe_mode=observe and nonlocal_audit_mode,
                                observe_nonce=(nonlocal_observe_nonce
                                           if observe and nonlocal_audit_mode
                                           else None),
                                restrict_reads=_spawn_restrict_reads,
                                # _env_for_target/run_env is already filtered
                                # by this wrapper.  It also contains trusted
                                # sandbox-generated overrides such as the
                                # private mountless TMPDIR; do not strip those
                                # a second time in the lower backend.
                                strict_env=False,
                                persona=_persona,
                                etc_overlay=etc_overlay,
                                # Default True here even though subprocess.run
                                # defaults to False — _spawn's historical
                                # behaviour was unconditional os.setsid() and
                                # that's the stronger posture for a mount-ns
                                # child (no inherited controlling tty, so
                                # /dev/tty → ENXIO, so no tty-read leak to
                                # operator keystrokes). Callers who need an
                                # inherited session (interactive gdb under
                                # /crash-analysis per run_untrusted's
                                # docstring) pass start_new_session=False
                                # explicitly and that is honoured.
                                start_new_session=_start_new_session,
                                inherit_netns=_inherit_netns,
                                skip_pid_ns=_skip_pid_ns,
                                skip_mount_ns=skip_mount,
                                # The ported ns-only mode hard-requires
                                # the fresh procfs mount ('F' fail-
                                # closed) whenever its declared tier
                                # claims it — the caller's contract
                                # flag stays authoritative everywhere
                                # else.
                                require_fresh_procfs=(
                                    _require_fresh_procfs
                                    or (skip_mount and _ported_hard_fresh)),
                                # Floor-resolved, never caller-chosen:
                                # Landlock ABSENCE is tolerated only
                                # when the resolved floor admits the
                                # ns-only tier (see _landlock_tolerated).
                                landlock_required=not _landlock_tolerated,
                                proxy_unix_socket=_proxy_unix_path if _use_proxy_netns else None,
                                proxy_forwarder_port=_proxy_forwarder_port if _use_proxy_netns else None,
                                extra_unix_bridges=(
                                    sorted(loopback_unix_bridges.items())
                                    if (loopback_unix_bridges
                                        and _use_proxy_netns)
                                    else None
                                ),
                                exec_pid_callback=_exec_pid_callback,
                                child_pid_callback=_register_lane_peer,
                            )

                        def _grant_path_identities() -> dict[str, tuple]:
                            identities = {}
                            grant_paths = [
                                target, output,
                                *(writable_paths or []),
                                *(_spawn_readable or []),
                            ]
                            for grant_path in grant_paths:
                                if not grant_path:
                                    continue
                                absolute = os.path.abspath(grant_path)
                                try:
                                    resolved = os.path.realpath(absolute)
                                    path_stat = os.stat(resolved)
                                except OSError:
                                    continue
                                identities[absolute] = (
                                    resolved, path_stat.st_dev,
                                    path_stat.st_ino,
                                )
                            return identities

                        _spawn_without_mount = (
                            _skip_mount_ns or _prefer_mountless_spawn
                            or not use_mount)
                        if (_prefer_mountless_spawn
                                and _b_fallback_reason):
                            _mount_ns_degraded = _b_fallback_reason
                        # Containment-floor contract, side 2: the
                        # spawn dispatch routes through the checked
                        # chokepoint with its lane's declared tier.
                        # The mountless lane is below the unwaived
                        # untrusted floor — the B-fallback /
                        # speculative-cache / per-call skip_mount_ns
                        # routes refuse here with the route's own
                        # remedy. Per-call caps (_spawn_tier_cap):
                        # skip_pid_ns keeps the HOST procfs on both
                        # spawn lanes, and the Landlock-absent
                        # tolerance bounds a mountless spawn at the
                        # ported ns-only tier.
                        if _spawn_without_mount:
                            if (_b_fallback_reason
                                    and "previously failed mount-ns"
                                    in _b_fallback_reason):
                                # The speculative-cache route needs its
                                # own remedy — the shared audit-oriented
                                # text talks about tracer attachment,
                                # which is not what this refusal is
                                # about.
                                _mountless_fix = (
                                    "the binary previously failed to "
                                    "exec inside the mount-ns view; "
                                    "extend tool_paths=/readable_paths= "
                                    "to cover its runtime dependencies "
                                    "so the mount-ns lane can serve it.")
                            else:
                                _mountless_fix = _b_fallback_instr or ""
                            _spawn_lane = "mountless namespace backend"
                            if not use_mount:
                                _no_mount_why = (
                                    "no target/output engages the "
                                    "mount tier for this call"
                                    if not (target or output or rootfs)
                                    else "the mount-namespace "
                                         "capability is unavailable "
                                         "on this host")
                            else:
                                _no_mount_why = ("per-call "
                                                 "skip_mount_ns=True "
                                                 "bypasses the "
                                                 "mount-ns backend")
                            _spawn_lane_kwargs: dict = {
                                "detail": (_b_fallback_reason
                                           or _no_mount_why),
                                "remedy": _floor_remedy(_mountless_fix),
                                "setup_category": (
                                    "X" if _prefer_mountless_spawn
                                    else None),
                            }
                        else:
                            _spawn_lane = "mount-ns spawn"
                            _spawn_lane_kwargs = {}
                        _grant_ids_before = (
                            _grant_path_identities()
                            if not _spawn_without_mount else None
                        )
                        try:
                            result = _dispatch_floor_check(
                                _spawn_lane,
                                executor=lambda: _run_spawn_backend(
                                    skip_mount=_spawn_without_mount,
                                ),
                                cap=_spawn_tier_cap(_spawn_without_mount),
                                **_spawn_lane_kwargs,
                            )
                        finally:
                            for _pp in _lane_peer_pids:
                                proxy_instance.discard_lane_peer_root(
                                    _proxy_unix_path, _pp)
                        used_spawn = True
                        # Authoritative setup-failure signal from the exec-
                        # status pipe (core/sandbox/_spawn.py) — unspoofable
                        # by the target, unambiguous vs exit codes/stderr:
                        #   None  → the target execed; result is genuine.
                        #   L/S/U → Landlock/seccomp/namespace-unshare failed
                        #           to APPLY though its probe passed → a real
                        #           "can't engage" → fail loud.
                        #   P     → a bind source stopped resolving to its
                        #           validation-time inode (tamper signal from
                        #           the pinned mount setup) → fail loud; the
                        #           M-degrade below would re-run without the
                        #           bind tree, where the planted
                        #           symlink resolves on the host filesystem
                        #           and the refused steering would succeed.
                        #   M/X   → mount-ns setup, or exec inside the
                        #           sandbox, failed → retry with namespaces
                        #           intact but without the bind tree.
                        _setup_status = getattr(result, "_setup_status", None)
                        if _setup_status is not None and _setup_status[0] == "P":
                            from .errors import SandboxSetupError
                            msg_0 = (
                                f"sandbox bind-source pin violation: "
                                f"{_setup_status[1]}"
                            )
                            raise SandboxSetupError(
                                msg_0,
                                "a target/output/readable bind source was "
                                "replaced after this call validated it — "
                                "treat this as concurrent tampering with "
                                "the run's paths, not an environment "
                                "problem. Stop whatever is rewriting the "
                                "path (a sibling run sharing the output "
                                "tree, or hostile code with write access "
                                "to an ancestor directory) and re-run.",
                                setup_category=_setup_status[0],
                            )
                        if _setup_status is not None and _setup_status[0] == "F":
                            from .errors import SandboxSetupError
                            msg_0 = (
                                f"sandbox fresh-procfs mount failed for an "
                                f"untrusted run: {_setup_status[1]}"
                            )
                            raise SandboxSetupError(
                                msg_0,
                                "the sandbox could not replace the host-pid "
                                "procfs bind with a pid-namespace-local "
                                "/proc, and untrusted targets are refused "
                                "host-procfs visibility (it exposes the "
                                "spawn chain's pre-strip environment). "
                                "This mount is expected to succeed on any "
                                "user-namespace-capable kernel — treat a "
                                "persistent failure as an environment bug "
                                "worth reporting. "
                                + _fresh_procfs_override_hint(
                                    literal_contract=(_rfp_kwarg is True)),
                                setup_category=_setup_status[0],
                            )
                        if _setup_status is not None and _setup_status[0] == "C":
                            # Fail-closed child setup abort: the spawn
                            # child refused to continue (unusable
                            # caller cwd= inside the pivoted root, a
                            # caller-named readable path that failed
                            # its read-only bind, a mandatory
                            # hardening rlimit that could not apply)
                            # and reported it on the exec-status pipe.
                            # Pre-fix these sites os._exit'd with NO
                            # status byte, so the parent read
                            # EOF-no-byte as "the target execed" and
                            # returned the aborted setup as a genuine
                            # CompletedProcess whose rc (126/127)
                            # collided with the shell not-found/not-
                            # executable conventions — downstream
                            # returncode oracles were fed fabricated
                            # target results.
                            from .errors import SandboxSetupError
                            msg_0 = (
                                f"sandbox child setup aborted "
                                f"fail-closed: {_setup_status[1]}"
                            )
                            raise SandboxSetupError(
                                msg_0,
                                "the target never executed. Fix the "
                                "named caller input (cwd=, "
                                "readable_paths=) or host condition "
                                "and retry — this category is "
                                "fail-closed by contract and has no "
                                "degrade path.",
                                setup_category=_setup_status[0],
                            )
                        if _setup_status is not None and _setup_status[0] == "!":
                            # EOF with NO exec confirmation: the spawn
                            # child died mid-setup without reaching any
                            # reporting site — involuntary termination
                            # (external SIGKILL, OOM kill, a hard cap
                            # landing between fork and exec). Every
                            # VOLUNTARY exit writes its category first
                            # and a successful exec writes 'G', so this
                            # shape is never a target result: the wait
                            # status the backend collected belongs to
                            # the setup child. Pre-fix, bare EOF read
                            # as "the target execed" and the death came
                            # back as a genuine-looking
                            # CompletedProcess (e.g. rc=-9), feeding
                            # crash oracles a fabricated target crash.
                            from .errors import SandboxSetupError
                            msg_0 = (
                                f"sandbox spawn child died during "
                                f"setup (rc={result.returncode}): "
                                f"{_setup_status[1]}"
                            )
                            raise SandboxSetupError(
                                msg_0,
                                "the target never executed and the "
                                "returncode belongs to the setup "
                                "child, not the target. Retry the "
                                "run; if it recurs, check for OOM "
                                "kills (dmesg) or an external "
                                "process sweeper.",
                                setup_category=_setup_status[0],
                            )
                        if _setup_status is not None and _setup_status[0] in ("L", "S", "U"):
                            from .errors import SandboxSetupError
                            from .probes import (
                                ENGAGE_FAIL_INSTRUCTIONS,
                                LAYER_FAIL_INSTRUCTIONS,
                            )
                            _layer = {"L": "Landlock", "S": "seccomp",
                                      "U": "namespace unshare"}.get(
                                          _setup_status[0], _setup_status[0])
                            # Namespace (U) failures need the same remedy as the
                            # engagement gate — network-only also needs the
                            # namespace, so only `none` avoids it. Landlock/
                            # seccomp (L/S) ARE dropped by network-only, so it
                            # is a real downgrade for those.
                            _instr = (ENGAGE_FAIL_INSTRUCTIONS
                                      if _setup_status[0] == "U"
                                      else LAYER_FAIL_INSTRUCTIONS)
                            msg_0 = (
                                f"sandbox {_layer} setup failed in the spawn "
                                f"child: {_setup_status[1]}"
                            )
                            raise SandboxSetupError(
                                msg_0,
                                _instr,
                                setup_category=_setup_status[0],
                            )
                        # Retry without the bind tree on a mount-ns ('M') or
                        # in-sandbox exec ('X') failure reported by the exec-
                        # status pipe. 'X' is the common tool_paths case: the
                        # bind set was insufficient (typical Python tool: bin
                        # dir bound but stdlib at sys.prefix/lib was not), so
                        # the target couldn't exec inside the mount-ns view.
                        # Re-run through the namespace backend without
                        # mount-ns bind-tree visibility. The
                        # signal is authoritative and unspoofable (a tool can
                        # no longer defeat OR forge this via stderr; the old
                        # rc==126/127 + empty-stderr heuristic could be both).
                        if _setup_status is not None and _setup_status[0] in ("M", "X"):
                            # Rootfs fail-closed gate #4: an M/X status
                            # for a rootfs run means the image pivot or
                            # the exec inside the image failed. The
                            # mountless retry below would re-run the
                            # command against the HOST filesystem —
                            # forbidden. Raise with the child's detail;
                            # 'X' usually means cmd[0] doesn't exist in
                            # the image (wrong entrypoint path) or its
                            # interpreter/loader is missing there.
                            if rootfs is not None:
                                from .errors import SandboxSetupError
                                msg_0 = (
                                    f"sandbox(rootfs=...): mount-ns "
                                    f"setup or exec inside the image "
                                    f"rootfs failed: {_setup_status[1]} "
                                    f"— refusing the mountless "
                                    f"host-filesystem retry."
                                )
                                raise SandboxSetupError(
                                    msg_0,
                                    "verify the rootfs is a complete "
                                    "unpacked image (loader + libs "
                                    "present) and cmd[0] names a path "
                                    "that exists INSIDE the image.",
                                    setup_category=_setup_status[0],
                                )
                            # Persona fail-closed gate: the mountless
                            # retry below runs WITHOUT the bind tree,
                            # so the fingerprint persona (bind-mounts
                            # + UTS) silently does not apply — the
                            # exact half-state require_sanitisation
                            # forbids. This is also where a strict
                            # apply_overlay per-target failure lands
                            # ('M' status from the spawn child).
                            if _persona is not None and require_sanitisation:
                                from .errors import SandboxSetupError
                                msg_0 = (
                                    f"sandbox(require_sanitisation="
                                    f"True): mount-ns setup or exec "
                                    f"failed ({_setup_status[0]}: "
                                    f"{_setup_status[1]}) — refusing "
                                    f"the mountless fallback, "
                                    f"which cannot apply the "
                                    f"fingerprint persona."
                                )
                                raise SandboxSetupError(
                                    msg_0,
                                    "fix the mount-ns failure (see "
                                    "the child diagnostic above) or "
                                    "drop require_sanitisation= to "
                                    "accept host-real identity "
                                    "surfaces on degrade.",
                                    setup_category=_setup_status[0],
                                )
                            # Keep the namespace backend and retry without
                            # the bind tree. This still enters a PID namespace,
                            # mounts a fresh /proc, applies Landlock + seccomp,
                            # and retains the isolated network/proxy lane. It
                            # avoids the host-pid /proc exposure of the legacy
                            # subprocess fallback on kernels/filesystems that
                            # reject one of the bind mounts with EINVAL.
                            _failed_setup_status = _setup_status
                            # Synthesised carrier for the child's M/X
                            # diagnostic (the status byte is in-band,
                            # not an exception) — chained by the
                            # checked dispatch below, or by the
                            # fallback lanes when the mountless
                            # backend is unachievable.
                            _mx_cause = _errors.SandboxSetupError(
                                f"sandbox mount-ns setup or exec "
                                f"failed ({_setup_status[0]}: "
                                f"{_setup_status[1]})",
                                setup_category=_setup_status[0],
                            )
                            _mx_abi_block = (
                                _mountless_unachievable_reason())
                            if _mx_abi_block:
                                # Mountless is out of the achievable
                                # set for this workload (see
                                # _mountless_unachievable_reason) —
                                # continue down the demotion ladder;
                                # the fallback dispatch's floor check
                                # decides whether the demoted lane is
                                # admitted for this call.
                                _mount_ns_degraded = (
                                    "bind-tree setup failed "
                                    f"({_failed_setup_status[0]}: "
                                    f"{_failed_setup_status[1]}); "
                                    "mountless namespace backend not "
                                    f"achievable ({_mx_abi_block})")
                                _spawn_ladder_err = _mx_cause
                                used_spawn = False
                                if state.warn_once(
                                        "_mountless_unachievable_warned"):
                                    # The reroute must be as loud as
                                    # every other demotion on this
                                    # file: pre-fix shapes either
                                    # refused with an explanatory
                                    # message or warned — a silent
                                    # stamp-only degrade of a
                                    # read-restricted run to a
                                    # host-visible lane is not
                                    # acceptable.
                                    logger.warning(
                                        "Sandbox: the mountless "
                                        "namespace backend is not "
                                        "achievable for this call "
                                        "(%s) — continuing down the "
                                        "demotion ladder; the "
                                        "containment floor decides "
                                        "admission, and the demoted "
                                        "lane enforces read/write "
                                        "policy with Landlock alone.",
                                        _mx_abi_block,
                                    )
                            else:
                                # Refuse BEFORE the speculative-cache
                                # write and the grant-pin re-check: a
                                # refused run must not steer FUTURE
                                # runs onto the mountless lane (the
                                # cache is consulted by every later
                                # call for the same binary, trusted
                                # ones included). The checked dispatch
                                # below re-asserts at the executor.
                                _mx_declared = _LANE_TIERS[
                                    "mountless namespace backend"]
                                _mx_cap = _spawn_tier_cap(True)
                                if (_mx_cap is not None
                                        and _mx_cap < _mx_declared):
                                    _mx_declared = _mx_cap
                                try:
                                    _tiers.assert_floor(
                                        _mx_declared, _floor,
                                        lane=("mountless namespace "
                                              "backend"),
                                        cause=_mx_cause,
                                        detail=(f"{_setup_status[0]}: "
                                                f"{_setup_status[1]}"),
                                        remedy=_floor_remedy(
                                            "fix the bind-tree/"
                                            "tool-path failure."),
                                        setup_category=_setup_status[0],
                                    )
                                except _errors.SandboxFloorError as \
                                        _floor_exc:
                                    _note_floor_refusal(_floor_exc)
                                    raise
                                if (_grant_ids_before is not None
                                        and _grant_path_identities()
                                        != _grant_ids_before):
                                    from .errors import SandboxSetupError
                                    raise SandboxSetupError(
                                        "sandbox grant-source pin violation "
                                        "during bind-tree fallback",
                                        "a target, output, writable, or readable "
                                        "path changed while the first sandbox "
                                        "backend was starting; refusing to grant "
                                        "the replacement path to the retry.",
                                        setup_category="P",
                                    )
                                _resolved_cmd0 = shutil.which(cmd[0]) or cmd[0]
                                with state._cache_lock:
                                    _first_seen = (
                                        _resolved_cmd0
                                        not in state._speculative_failure_cache
                                    )
                                    if _first_seen:
                                        state._speculative_failure_cache[
                                            _resolved_cmd0] = True
                                if _first_seen:
                                    logger.info(
                                        "Sandbox: %r bind tree is unusable; "
                                        "future runs will use the reduced "
                                        "namespace backend.",
                                        cmd[0],
                                    )
                                else:
                                    logger.debug(
                                        "Sandbox: bind-tree failure cache hit "
                                        "for cmd[0]=%r.",
                                        cmd[0],
                                    )
                                result = _dispatch_floor_check(
                                    "mountless namespace backend",
                                    executor=lambda: _run_spawn_backend(
                                        skip_mount=True),
                                    cap=_spawn_tier_cap(True),
                                    cause=_mx_cause,
                                    detail=(f"{_setup_status[0]}: "
                                            f"{_setup_status[1]}"),
                                    remedy=_floor_remedy(
                                        "fix the bind-tree/tool-path "
                                        "failure."),
                                    setup_category=_setup_status[0],
                                )
                                _retry_status = getattr(
                                    result, "_setup_status", None)
                                if _retry_status is not None:
                                    from .errors import SandboxSetupError
                                    raise SandboxSetupError(
                                        "sandbox bind-tree fallback failed "
                                        f"({_retry_status[0]}: "
                                        f"{_retry_status[1]})",
                                        "the reduced mount backend could not "
                                        "engage Landlock, seccomp, namespaces, "
                                        "fresh procfs, or execute the target; "
                                        "the target was not run.",
                                        setup_category=_retry_status[0],
                                    )
                                _mount_ns_degraded = (
                                    "bind-tree setup failed "
                                    f"({_failed_setup_status[0]}: "
                                    f"{_failed_setup_status[1]}); retried with "
                                    "Landlock + PID namespace + fresh procfs")
                                _spawn_without_mount = True
                                used_spawn = True
                                if state.warn_once(
                                        "_mountless_backend_warned"):
                                    logger.warning(
                                        "Sandbox: bind-tree isolation "
                                        "unavailable for %r; using Landlock "
                                        "+ PID namespace + fresh procfs. "
                                        "Later cache hits log at debug "
                                        "level.",
                                        cmd[0],
                                    )
                        elif _setup_status is not None:
                            # Default-DENY unknown status categories.
                            # The known letters are handled above; a
                            # byte from a future writer that none of
                            # those arms recognise means a setup step
                            # failed in a way this parent does not
                            # understand — treating it as a genuine
                            # run (the old fall-through) is the same
                            # default-allow shape that produced the
                            # ungated-ladder bug. The child never
                            # execed (a successful exec reaps the
                            # CLOEXEC status fd and the parent reads
                            # EOF), so fail loud.
                            from .errors import SandboxSetupError
                            raise SandboxSetupError(
                                f"sandbox spawn child reported an "
                                f"unrecognised setup-status category "
                                f"{_setup_status[0]!r}: "
                                f"{_setup_status[1]}",
                                "the target never executed. This "
                                "parent predates the status category "
                                "— update RAPTOR so the parent and "
                                "spawn backend agree on the status "
                                "vocabulary.",
                                setup_category=_setup_status[0],
                            )
                except (FileNotFoundError, RuntimeError, OSError,
                        _errors.SandboxSetupError) as _spawn_err:
                    # _spawn raised mid-setup (uidmap uninstalled,
                    # kernel quirk, libc soname absent on minimal
                    # containers, etc.). Fall back to the plain
                    # subprocess+preexec lane via the `if not
                    # used_spawn` branch below — with the unshare-CLI
                    # chain deleted there is no namespace fallback:
                    # the per-call rechecks there (Landlock, network
                    # block) and the floor dispatch decide whether the
                    # demoted call may run at all.
                    # OSError covers ctypes.CDLL failures on exotic
                    # libc layouts (musl, minimal busybox images);
                    # FileNotFoundError is a subclass but we list
                    # it explicitly for documentation.
                    #
                    # SandboxSetupError from _spawn rides the ladder
                    # ONLY for setup_category 'U' — the spawn child
                    # dying at its unshare stage (userns refused at
                    # runtime), the typed replacement for the bare
                    # RuntimeError this environmental catch has always
                    # degraded on. Every other category (P pin
                    # violations, L/S hardening-layer failures, F
                    # fresh-procfs contract) keeps its fail-loud
                    # BaseException contract and is re-raised
                    # untouched. Floor-contract invariant: the
                    # SandboxFloorError raises inside this try (the
                    # mount/mountless dispatch checks and the M/X
                    # retry check) never carry category 'U' — their
                    # categories come from status bytes or the
                    # X-synthesised carriers — so a floor refusal can
                    # never ride this ladder; and even a hypothetical
                    # ladder-caught floor error would be re-refused at
                    # the fallback dispatch (the floor is fixed for
                    # the call and every fallback lane sits below any
                    # floor that refused a spawn lane). The degrade below is loud (warning +
                    # sandbox_info.mount_ns_degraded) and the strict /
                    # persona / fresh-procfs (untrusted) / Landlock-
                    # recheck gates in the `if not used_spawn` block
                    # still decide whether the demoted call may
                    # actually run.
                    if (isinstance(_spawn_err, _errors.SandboxSetupError)
                            and _spawn_err.setup_category != "U"):
                        raise
                    #
                    # This except is for ENVIRONMENTAL failures only.
                    # A caller-input error — the audit target dir
                    # vanished after the entry validation above (the
                    # tracer's ENOENT on <dir>/.audit lands here as a
                    # FileNotFoundError) — must NOT ride the
                    # degradation ladder: fail loudly instead of
                    # silently trading away mount-ns containment AND
                    # the requested audit evidence.
                    #
                    # Rootfs fail-closed gate #5: same principle for
                    # rootfs runs — a spawn-setup failure must not
                    # degrade to running the command on the host fs.
                    if rootfs is not None:
                        from .errors import SandboxSetupError
                        msg_0 = (
                            f"sandbox(rootfs=...): mount-ns spawn setup "
                            f"failed ({_spawn_err.__class__.__name__}: "
                            f"{_spawn_err}) — refusing the Landlock-only "
                            f"host-filesystem fallback."
                        )
                        raise SandboxSetupError(
                            msg_0,
                            "fix the host (uidmap package, userns "
                            "sysctl, /etc/subuid+/etc/subgid allotment) "
                            "to restore the mount-ns tier.",
                        ) from _spawn_err
                    _vanished = _audit_target_dir_problem()
                    if _vanished:
                        from .errors import SandboxSetupError
                        msg_0 = (
                            f"sandbox mount-ns spawn failed "
                            f"({_spawn_err}) and the audit target "
                            f"directory {_vanished} — refusing the "
                            f"Landlock-only fallback: the caller asked "
                            f"for audit evidence and the target dir is "
                            f"gone (caller-input error, not an "
                            f"environmental degradation)."
                        )
                        raise SandboxSetupError(
                            msg_0,
                            "recreate the audit_run_dir/output "
                            "directory (production callers pass "
                            "lifecycle-created run dirs) and retry.",
                        ) from _spawn_err
                    if nonlocal_audit_mode:
                        _audit_no_engage_reason = (
                            f"mount-ns spawn path failed "
                            f"({_spawn_err.__class__.__name__}: "
                            f"{_spawn_err}) — audit falls back to the "
                            f"Landlock-only tracer if available")
                        _audit_no_engage_instr = (
                            "see the sandbox log for the spawn "
                            "failure; fix the host (uidmap package, "
                            "userns sysctl) to restore the mount-ns "
                            "audit tier.")
                    _mount_ns_degraded = f"spawn setup failed: {_spawn_err}"
                    # Keep the exception object itself: the except
                    # binding is unset when this block exits, and the
                    # fresh-procfs gate below needs it for `raise ...
                    # from` chaining and its setup_category.
                    _spawn_ladder_err = _spawn_err
                    logger.warning(
                        "Sandbox: mount-ns spawn path failed (%s); "
                        "falling back to Landlock-only subprocess path."
                        "%s",
                        _spawn_err,
                        (" Caller passed map_root/target and relied on "
                         "mount-ns semantics (pivot_root, per-ns /tmp, "
                         "binds) — those are LOST for this call."
                         if (map_root or target) else ""),
                    )
            if not used_spawn:
                # ---- Mount-ns demotion hardening -------------------
                # Reaching here with use_mount True means THIS CALL was
                # demoted from the mount-ns backend to the Landlock-only
                # subprocess path (pass_fds/input= kwarg compat, the
                # B-fallback cmd-visibility check, the speculative-
                # failure cache, an M/X setup status, or a mid-setup
                # spawn error). Two contracts must survive that:
                #
                # 1. strict is fail-closed. The construction-time gate
                #    runs before any per-call demotion exists — without
                #    a per-call recheck, strict silently degraded here
                #    (the rootfs gates #2/#4 are the model).
                # 2. The construction-time writable grants were computed
                #    for the mount backend, where /tmp and /dev/shm are
                #    per-sandbox tmpfs. On the demoted path they are the
                #    HOST-SHARED directories — exactly the grants the
                #    private-scratch posture exists to withhold from
                #    restricted (restrict_reads) runs. Recompute them
                #    for this call.
                _demoted_call_writable: list[str] | None = None
                if (use_mount and rootfs is None
                        and sys.platform == "linux"
                        and not effectively_disabled):
                    if strict_required:
                        from .errors import SandboxSetupError
                        _demote_why = (
                            _mount_ns_degraded or _b_fallback_reason
                            or "pass_fds=/input= are not plumbed "
                               "through the fork-based spawn path")
                        raise SandboxSetupError(
                            "sandbox profile 'strict': this call was "
                            "demoted from the mount-ns backend to the "
                            f"Landlock-only path ({_demote_why}) — "
                            "strict does not degrade silently.",
                            "drop pass_fds=/input= (write stdin via "
                            "stdin=<fd> instead), make cmd[0] visible "
                            "in the mount-ns bind tree (tool_paths=), "
                            "or explicitly choose a profile that "
                            "degrades gracefully (e.g. `--sandbox "
                            "full`). RAPTOR will not silently "
                            "downgrade for you.",
                        )
                    # Persona fail-closed gate (catch-all arm): the
                    # Landlock-only path never applies the fingerprint
                    # persona, so any demotion reaching here —
                    # including mid-setup spawn errors and an
                    # availability flap after the context-entry check
                    # — is the host-real half-state
                    # require_sanitisation forbids. The early gates
                    # (pre-spawn kwarg/B-fallback/cache/skip_mount_ns,
                    # post-spawn M/X) give more specific messages;
                    # this one backstops every other route.
                    if _persona is not None and require_sanitisation:
                        from .errors import SandboxSetupError
                        _demote_why = (
                            _mount_ns_degraded or _b_fallback_reason
                            or "mount-ns spawn was demoted for this "
                               "call")
                        raise SandboxSetupError(
                            "sandbox(require_sanitisation=True): this "
                            "call was demoted from the mount-ns "
                            f"backend ({_demote_why}) — refusing the "
                            "Landlock-only path, which cannot apply "
                            "the fingerprint persona.",
                            "fix the demotion cause, or drop "
                            "require_sanitisation= to accept "
                            "host-real identity surfaces on degrade.",
                        )
                    # NOTE: the former fresh-procfs catch-all gate
                    # lived here. Every route into the fallback lanes
                    # — the mid-setup spawn EXCEPTION ladder, the
                    # kwarg demotions, and the achievability rerouting
                    # — now passes the containment-floor dispatch
                    # check immediately before its executor runs (see
                    # _dispatch_floor_check at the run_landlock_audit
                    # and subprocess dispatches below), with the
                    # original backend failure chained so the real
                    # cause stays diagnosable.
                    # Landlock recheck (fail-closed). The construction-
                    # time "confinement requested but Landlock
                    # unavailable" refusal only runs when the mount
                    # backend was ruled out at setup (`not use_mount`).
                    # A call that CHOSE mount-ns and was then demoted
                    # here lands on the Landlock-only subprocess path,
                    # where the requested filesystem/TCP policy is
                    # enforced by Landlock ALONE — and _make_preexec_fn
                    # silently skips its Landlock arm when the kernel
                    # lacks it. Without this recheck the demoted call
                    # ran to completion with NO confinement at all
                    # (rc=0, host /tmp writable, target not read-only)
                    # while the caller had explicitly requested
                    # target/output/allowed_tcp_ports/restrict_reads.
                    # Mirrors the construction-time gate: same policy
                    # kwargs, same refusal, per-call.
                    if ((target or output or allowed_tcp_ports
                            or restrict_reads)
                            and not check_landlock_available()):
                        from .errors import SandboxSetupError
                        _demote_why = (
                            _mount_ns_degraded or _b_fallback_reason
                            or "pass_fds= demoted this call from the "
                               "mount-ns backend")
                        raise SandboxSetupError(
                            "sandbox: this call was demoted from the "
                            f"mount-ns backend ({_demote_why}) and "
                            "Landlock is unavailable on this kernel — "
                            "the Landlock-only path would enforce NONE "
                            "of the requested target/output/"
                            "allowed_tcp_ports/restrict_reads policy.",
                            "fix the demotion cause so the mount "
                            "namespace can enforce the policy, run on "
                            "a kernel with Landlock (>= 5.13), or drop "
                            "the confinement kwargs to explicitly "
                            "accept an unconfined run. RAPTOR will not "
                            "silently downgrade for you.",
                        )
                # (The private-scratch write-policy recompute and the
                # per-call preexec rebuild moved BELOW the floor
                # assert: a refused call must not mint scratch dirs
                # or rebuild grants for a dispatch that never runs.)
                # Containment-floor contract, side 2: shared demotion
                # context for the fallback-lane dispatch checks below.
                # _spawn_ladder_err carries the mid-setup backend
                # exception (or the synthesised M/X / achievability
                # carrier) so a refusing check chains the real cause;
                # the detail names the route so both the refusal and
                # the consented-degrade warning stay diagnosable.
                if _spawn_ladder_err is not None:
                    _fallback_floor_detail = (
                        "demoted from the mount-ns backend "
                        f"({_spawn_ladder_err.__class__.__name__}: "
                        f"{_spawn_ladder_err})")
                elif _mount_ns_degraded or _b_fallback_reason:
                    _fallback_floor_detail = (
                        "demoted from the mount-ns backend "
                        f"({_mount_ns_degraded or _b_fallback_reason})")
                elif use_mount and kwargs.get("pass_fds"):
                    _fallback_floor_detail = (
                        "demoted from the mount-ns backend (per-call "
                        "pass_fds= is not plumbed through the "
                        "fork-based spawn path)")
                elif (sys.platform == "linux" and not landlock_available
                        and not effectively_disabled):
                    # No demotion happened — the plain lane simply
                    # cannot deliver its nominal tier on this kernel.
                    # The remedy must name THAT, not a spawn failure
                    # that never occurred.
                    _fallback_floor_detail = (
                        "the kernel has no Landlock, so this lane "
                        "delivers rlimits/seccomp only")
                else:
                    _fallback_floor_detail = ""
                if (sys.platform == "linux" and not landlock_available
                        and not effectively_disabled
                        and _spawn_ladder_err is None
                        and not (_mount_ns_degraded
                                 or _b_fallback_reason)):
                    _fallback_floor_remedy = _floor_remedy(
                        "upgrade to a kernel with Landlock (5.13+) so "
                        "the floor can be met.")
                else:
                    _fallback_floor_remedy = _floor_remedy(
                        "this lane exposes the host-pid /proc to the "
                        "target; fix the demotion cause (see the sandbox "
                        "log for the spawn failure; typical hosts need the "
                        "uidmap package and the userns sysctl)."
                        if sys.platform == "linux" else "")
                # Declared tier of the plain-subprocess lane: rlimits
                # only when the operator disabled the sandbox or the
                # kernel has no Landlock to enforce with (dispatch
                # tags must never overstate what a lane delivers).
                _plain_lane_cap = (
                    _tiers.ContainmentTier.BARE
                    if (effectively_disabled or not landlock_available)
                    else None)
                # Refuse the fallback lane BEFORE any audit machinery
                # runs: a refused call must not write audit-degraded
                # markers or trade its floor refusal for an
                # audit_required one. The checked dispatches below
                # remain the hard per-executor guarantee; this early
                # assert only fixes refusal PRIORITY. The plain
                # subprocess lane is the ONLY fallback — the
                # unshare-CLI namespace fallback is deleted; namespace
                # shapes that cannot spawn land here and the floor
                # decides admission.
                _fallback_lane = "Landlock-only subprocess"
                _fallback_delivered = _LANE_TIERS[_fallback_lane]
                if (_plain_lane_cap is not None
                        and _plain_lane_cap < _fallback_delivered):
                    _fallback_delivered = _plain_lane_cap
                try:
                    _tiers.assert_floor(
                        _fallback_delivered, _floor, lane=_fallback_lane,
                        cause=_spawn_ladder_err,
                        detail=_fallback_floor_detail,
                        remedy=_fallback_floor_remedy,
                    )
                except _errors.SandboxFloorError as _floor_exc:
                    _note_floor_refusal(_floor_exc)
                    raise
                # Per-call network-block recheck. Construction
                # resolved block_network to the NAMESPACE tier for
                # this call (need_unshare), so the construction-time
                # degraded-net-deny arm never evaluated — and this
                # demoted call is about to execute on the plain lane
                # with NO network namespace. (The deleted unshare-CLI
                # fallback used to keep a netns for these demotions.)
                # Mirror the construction arm per call, same
                # precedence, same acceptance levers: Landlock ABI
                # v4+ TCP-connect deny (loud), else the operator's
                # degraded acceptance env (loud), else refuse.
                # degraded_net_deny=False is the caller's per-call
                # "this run may egress" opt-out, honoured exactly as
                # at construction. allowed_tcp_ports is excluded from
                # the deny-all lane for the same reason as at
                # construction (the allowlist IS the network policy).
                _demoted_net_deny = False
                if (sys.platform == "linux" and not effectively_disabled
                        and need_unshare and block_network
                        and degraded_net_deny):
                    if (landlock_available and _get_landlock_abi() >= 4
                            and not allowed_tcp_ports):
                        _demoted_net_deny = True
                        if state.warn_once("_demoted_tcp_deny_warned"):
                            logger.warning(
                                "Sandbox: block_network requested but "
                                "this call was demoted from the "
                                "namespace backend — falling back to "
                                "Landlock TCP-connect deny for this "
                                "call (all TCP connects fail with "
                                "EACCES, including loopback; "
                                "bind/listen and UDP are unaffected).",
                            )
                    # Network-axis waiver: deliberately the RAW env
                    # var, not the floor consent chain — a tier floor
                    # (--sandbox-floor / project setting) never
                    # consents the network axis; accepting an
                    # unrestricted-network run stays env-var-only.
                    elif _degraded_untrusted_waiver():
                        if state.warn_once(
                                "_demoted_net_open_override_warned"):
                            logger.warning(
                                "Sandbox: block_network requested but "
                                "this call was demoted from the "
                                "namespace backend and Landlock ABI "
                                "v4+ is missing — "
                                "RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1 "
                                "accepts running with NETWORK "
                                "UNRESTRICTED for such calls.",
                            )
                    else:
                        from .errors import SandboxSetupError
                        from .probes import ENGAGE_FAIL_INSTRUCTIONS
                        _demote_net_why = (_fallback_floor_detail
                                           or "spawn backend unavailable")
                        raise SandboxSetupError(
                            "Sandbox: block_network=True was requested "
                            "but this call was demoted from the "
                            f"namespace backend ({_demote_net_why}) "
                            "and Landlock ABI v4+ is missing — no "
                            "layer can enforce the requested network "
                            "block for this call.",
                            ENGAGE_FAIL_INSTRUCTIONS + " Alternatively "
                            "pass degraded_net_deny=False (library "
                            "callers) to accept an unrestricted-network "
                            "run per call, or set "
                            "RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1 to "
                            "accept the degraded tier host-wide.",
                        )
                # Private-scratch write-policy recompute for demoted
                # restrict_reads calls (the construction grants
                # assumed the mount backend's per-sandbox tmpfs), and
                # the per-call preexec rebuild that carries it and/or
                # the per-call TCP deny. The rebuild keeps the
                # namespace-creation deny rules — the plain lane's
                # payload never legitimately unshares.
                if (use_mount and rootfs is None
                        and sys.platform == "linux"
                        and not effectively_disabled
                        and restrict_reads and not exclude_tmp_baseline):
                    _demoted_call_writable, _demoted_env = (
                        _mountless_write_policy()
                    )
                    kwargs["env"] = dict(_demoted_env)
                if (_demoted_call_writable is not None
                        or _demoted_net_deny):
                    _dem_preexec = _make_preexec_fn(
                        effective_limits,
                        writable_paths=(
                            _demoted_call_writable
                            if _demoted_call_writable is not None
                            else writable_paths),
                        allowed_tcp_ports=allowed_tcp_ports,
                        seccomp_profile=seccomp_profile,
                        seccomp_block_udp=seccomp_block_udp,
                        readable_paths=_preexec_readable,
                        deny_all_tcp_connect=(_degraded_tcp_deny
                                              or _demoted_net_deny),
                        host_nproc_cap=_host_nproc_cap,
                        reaper_cell=_reaper_cell,
                        seccomp_block_ns_creation=True,
                    )
                    if existing_preexec:
                        def _dem_combined(_ep=existing_preexec,
                                          _np=_dem_preexec):
                            _ep()
                            _np()
                        kwargs["preexec_fn"] = _dem_combined
                    else:
                        kwargs["preexec_fn"] = _dem_preexec
                if _exec_pid_callback is not None:
                    logger.debug(
                        "Sandbox: exec_pid_callback supplied but this "
                        "call is not routed through the spawn backend — "
                        "the callback will not fire for %s",
                        " ".join(cmd[:_CMD_DISPLAY_MAX_ARGS]) or repr(cmd),
                    )
                # Audit/observe in Landlock-only mode: the bare
                # subprocess.run path has no tracer-fork machinery,
                # so audit silently degraded pre-PR. _landlock_audit
                # restores observe signal here by forking a tracer
                # subprocess in parallel with the target child.
                # Engaged only when the operator asked for audit
                # AND we have the prerequisites (libseccomp + ptrace);
                # any failure path falls back cleanly to the bare
                # subprocess.run below. mount-ns absent is acceptable
                # — Landlock + seccomp + ptrace are sufficient for
                # observe semantics; the THREAT_MODEL.md
                # Landlock-only-mode warning still applies.
                _audit_landlock_engaged = False
                if nonlocal_audit_mode:
                    try:
                        from . import _landlock_audit as _la
                        from .landlock import (
                            _make_landlock_preexec as _la_make_landlock,
                        )
                        from .ptrace_probe import (
                            check_ptrace_available as _la_ptrace_check,
                        )
                        from .seccomp import (
                            _make_seccomp_preexec as _la_make_seccomp,
                        )
                        from .seccomp import (
                            check_seccomp_available as _la_seccomp_check,
                        )
                        if (_la_seccomp_check()
                                and _la_ptrace_check()):
                            # Build the rlimit-only preexec (no
                            # Landlock — we install it separately
                            # post-sync), the Landlock preexec, and
                            # the seccomp preexec with audit_mode=True.
                            _rlimit_only = _make_preexec_fn(
                                effective_limits,
                                writable_paths=None,
                                readable_paths=None,
                                allowed_tcp_ports=None,
                            )
                            _wp = list(
                                _demoted_call_writable
                                if _demoted_call_writable is not None
                                else (writable_paths or []))
                            # Honour exclude_tmp_baseline: the caller
                            # explicitly stripped the scratch dirs
                            # (exploit-engine wrapper-script defence)
                            # and the audit tracer must not silently
                            # re-open them. The plain (non-audit)
                            # preexec at the sandbox() baseline obeys
                            # the same flag. Same for BOTH private-
                            # scratch postures (construction-time and
                            # per-call demoted): the whole point of
                            # the scratch swap is to withhold the
                            # host-shared /tmp, and the audit branch
                            # must not silently re-open it.
                            if (not exclude_tmp_baseline
                                    and "/tmp" not in _wp
                                    and _private_scratch_dir is None
                                    and _demoted_call_writable is None):
                                _wp.append("/tmp")
                            _la_readable = (
                                list(effective_read_paths)
                                if effective_read_paths else None
                            )
                            if _la_readable is not None:
                                for _tp in (tool_paths or []):
                                    if _tp and _tp not in _la_readable:
                                        _la_readable.append(_tp)
                            _ll_preexec = _la_make_landlock(
                                _wp,
                                list(allowed_tcp_ports)
                                    if allowed_tcp_ports else None,
                                readable_paths=_la_readable,
                                # Degraded-host TCP deny must survive
                                # the audit branch: the plain preexec
                                # carries it, and dropping it here
                                # silently restored outbound network
                                # exactly when block_network had
                                # downgraded to Landlock-only. The
                                # PER-CALL demoted deny rides along
                                # for the same reason — the audit
                                # branch builds its own preexecs, so
                                # omitting it here let an audit-mode
                                # demoted block_network call connect
                                # freely while the demotion warning
                                # claimed EACCES.
                                deny_all_tcp_connect=(
                                    _degraded_tcp_deny
                                    or _demoted_net_deny),
                            )
                            _sc_preexec = _la_make_seccomp(
                                seccomp_profile,
                                block_udp=seccomp_block_udp,
                                audit_mode=True,
                                observe_mode=bool(observe and nonlocal_audit_mode),
                                # The audit fallback executes the BARE
                                # target (the unshare-CLI bootstrap
                                # that once forced the permissive
                                # filter is deleted) — the payload
                                # never legitimately unshares, so the
                                # namespace-creation deny applies here
                                # exactly as on the plain lane.
                                block_ns_creation=True,
                            ) if seccomp_profile else None
                            _audit_run_dir_la = (
                                audit_run_dir or output
                            )
                            # Containment-floor contract, side 2: the
                            # Landlock-only audit helper executes the
                            # same cmd as the plain dispatches below
                            # (tracer is observability, not
                            # containment — same tier as its lane).
                            try:
                                result = _dispatch_floor_check(
                                    "Landlock-only subprocess",
                                    cap=_plain_lane_cap,
                                    cause=_spawn_ladder_err,
                                    detail=_fallback_floor_detail,
                                    remedy=_fallback_floor_remedy,
                                    executor=lambda: _la.run_landlock_audit(
                                    cmd,
                                    audit_run_dir=str(_audit_run_dir_la),
                                    audit_verbose=audit_verbose_active,
                                    observe_mode=bool(observe and nonlocal_audit_mode),
                                    observe_nonce=(
                                        nonlocal_observe_nonce
                                        if observe and nonlocal_audit_mode
                                        else None
                                    ),
                                    writable_paths=(
                                        _demoted_call_writable
                                        if _demoted_call_writable
                                        is not None
                                        else (writable_paths or [])),
                                    readable_paths=_la_readable or effective_read_paths or [],
                                    allowed_tcp_ports=(
                                        list(allowed_tcp_ports)
                                        if allowed_tcp_ports else None
                                    ),
                                    target=target, output=output,
                                    restrict_reads=restrict_reads,
                                    landlock_preexec=_ll_preexec,
                                    seccomp_preexec=_sc_preexec,
                                    rlimit_preexec=_rlimit_only,
                                    # cmd IS the target on this lane
                                    # (no bootstrap hops — the
                                    # unshare/prlimit/pid1-shim chain
                                    # is deleted), so it gets the
                                    # stripped target view directly.
                                    env=_env_for_target,
                                    cwd=kwargs.get("cwd"),
                                    timeout=kwargs.get("timeout"),
                                    capture_output=kwargs.get(
                                        "capture_output", False),
                                    text=kwargs.get("text", False),
                                    stdin=kwargs.get("stdin"),
                                    start_new_session=_start_new_session,
                                ))
                                _audit_landlock_engaged = True
                            except (RuntimeError, OSError) as _la_err:
                                # Environmental tracer-fork failures
                                # fall through to plain subprocess.run
                                # (recorded at the no-audit bottleneck
                                # below). A vanished audit target dir
                                # is a caller-input error — the same
                                # class the entry validation rejects —
                                # and must not silently cost the
                                # requested evidence channel.
                                _vanished = _audit_target_dir_problem()
                                if _vanished:
                                    from .errors import SandboxSetupError
                                    msg_0 = (
                                        f"sandbox Landlock-only audit "
                                        f"tracer failed ({_la_err}) and "
                                        f"the audit target directory "
                                        f"{_vanished} — refusing the "
                                        f"non-audit fallback for a "
                                        f"caller-input error."
                                    )
                                    raise SandboxSetupError(
                                        msg_0,
                                        "recreate the audit_run_dir/"
                                        "output directory and retry.",
                                    ) from _la_err
                                _audit_no_engage_reason = (
                                    f"Landlock-only audit tracer "
                                    f"failed "
                                    f"({_la_err.__class__.__name__}: "
                                    f"{_la_err}) — no audit tier "
                                    f"engaged for this call")
                                _audit_no_engage_instr = (
                                    "see the sandbox log for the "
                                    "tracer failure; b2/b3 audit "
                                    "signal is absent for this call.")
                                logger.warning(
                                    "Sandbox: Landlock-only audit "
                                    "tracer failed (%s); falling back "
                                    "to non-audit subprocess.run",
                                    _la_err,
                                )
                        elif _audit_no_engage_reason is None:
                            # Runtime-probe miss on the Landlock-only
                            # tier (the eager pre-flight above only
                            # probes when spawn was ineligible, so a
                            # spawn-path runtime failure lands here
                            # with no reason recorded yet).
                            _audit_no_engage_reason = (
                                "Landlock-only audit tracer "
                                "unavailable (libseccomp/ptrace probe "
                                "failed or no seccomp profile) — no "
                                "audit tier engaged for this call")
                            _audit_no_engage_instr = (
                                "install libseccomp and permit "
                                "PTRACE_SEIZE (Yama scope <= 1), or "
                                "run without audit mode.")
                    except ImportError:
                        # Sandbox helpers missing — let the bare
                        # path run.
                        if _audit_no_engage_reason is None:
                            _audit_no_engage_reason = (
                                "sandbox audit helpers unavailable "
                                "(ImportError) — no audit tier "
                                "engaged for this call")
                            _audit_no_engage_instr = (
                                "reinstall RAPTOR's sandbox package; "
                                "core.sandbox._landlock_audit failed "
                                "to import.")
                if not _audit_landlock_engaged:
                    if nonlocal_audit_mode:
                        # No-audit bottleneck: EVERY audit-requested
                        # call that is about to execute via bare
                        # subprocess.run (no tracer of any tier)
                        # passes through here — pre-flight
                        # ineligibility, spawn runtime failure, M/X
                        # retry, Landlock-only tracer failure and
                        # ImportError alike. Two guarantees:
                        #   1. the degradation is machine-readable
                        #      (per-run marker, idempotent — the
                        #      pre-flight sites keep their richer
                        #      reason; plus sandbox_info
                        #      ["audit_engaged"]=False stamped after
                        #      the run), and
                        #   2. audit_required=True refuses to execute
                        #      the command at all (fail-closed on the
                        #      evidence channel) instead of returning
                        #      a successful-looking result with no
                        #      observe record.
                        _reason = (
                            _audit_no_engage_reason
                            or "no audit tier could engage for this "
                               "call (unattributed degradation)")
                        _marker_dir = audit_run_dir or output
                        if _marker_dir:
                            from pathlib import Path as _Path

                            from . import summary as _summary_mod
                            _summary_mod.record_audit_degraded(
                                _Path(_marker_dir),
                                reason=_reason,
                                instructions=_audit_no_engage_instr,
                            )
                        if audit_required:
                            from .errors import SandboxSetupError
                            msg_0 = (
                                f"audit was requested with "
                                f"audit_required=True but no audit "
                                f"tier could engage: {_reason}. "
                                f"Refusing to run the command without "
                                f"the requested audit evidence."
                            )
                            raise SandboxSetupError(
                                msg_0,
                                _audit_no_engage_instr
                                or "fix the host's audit "
                                   "prerequisites (userns/libseccomp/"
                                   "ptrace) or drop audit_required= "
                                   "to accept marker-recorded "
                                   "degradation.",
                            )
                    # Containment-floor contract, side 2: the
                    # plain-subprocess lane (Landlock + seccomp +
                    # rlimits, host namespaces; rlimits only under
                    # the operator disable or on a Landlock-less
                    # kernel) — both executor shapes below route
                    # through the checked dispatch.
                    # No shim, no pid namespace on this path —
                    # teardown containment comes from the preexec
                    # sweeper (reaper cell) plus a parent-side
                    # marked-process sweep. The env marker is a
                    # per-run random token every descendant
                    # inherits; after the run (normal return,
                    # timeout, or exception) any /proc process
                    # still carrying it is SIGKILLed — the
                    # backstop for the paths that kill the sweeper
                    # itself (subprocess timeout kills Popen.pid,
                    # which IS the sweeper).
                    _reap_token = None
                    _death_r = _death_w = None
                    _penv = _env_for_target
                    if not effectively_disabled:
                        import uuid as _uuid
                        _reap_token = _uuid.uuid4().hex
                        _penv = dict(_env_for_target)
                        _penv["_SBX_RUN_ID"] = _reap_token
                    if _reaper_cell is not None:
                        _death_r, _death_w = os.pipe()
                        # Thread-local slot — see the cell's
                        # construction comment for why this must
                        # not be a plain shared key.
                        _reaper_cell["death_local"].fd = _death_r
                    _death_w_holder = [_death_w]
                    try:
                        # cmd IS the target (no bootstrap wrapper on
                        # this lane), so it gets the marker-stripped
                        # env view.
                        _pk = dict(kwargs)
                        _pk["env"] = _penv
                        if (
                            _reaper_cell is not None
                            and _death_w is not None
                            and _pk.get("timeout")
                        ):
                            # Teardown-first timeout: a plain
                            # subprocess.run timeout SIGKILLs
                            # Popen.pid, which on this path IS the
                            # subreaper sweeper — the sweep dies
                            # before it can run and containment
                            # falls back to the (scrub-able)
                            # marker backstop. Close the death
                            # pipe FIRST so the sweeper reaps its
                            # subtree and exits on its own; only
                            # then kill.
                            result = _dispatch_floor_check(
                                "Landlock-only subprocess",
                                cap=_plain_lane_cap,
                                cause=_spawn_ladder_err,
                                detail=_fallback_floor_detail,
                                remedy=_fallback_floor_remedy,
                                executor=lambda:
                                    _run_teardown_first_timeout(
                                        cmd, _pk,
                                        _death_w_holder,
                                        _start_new_session,
                                    ),
                            )
                        else:
                            result = _dispatch_floor_check(
                                "Landlock-only subprocess",
                                cap=_plain_lane_cap,
                                cause=_spawn_ladder_err,
                                detail=_fallback_floor_detail,
                                remedy=_fallback_floor_remedy,
                                executor=lambda: subprocess.run(
                                    cmd,
                                    start_new_session=(
                                        _start_new_session),
                                    **_pk,
                                    check=False,
                                ),
                            )
                    except OSError as _ebadf:
                        if _ebadf.errno != errno.EBADF:
                            raise
                        result = subprocess.CompletedProcess(
                            cmd, returncode=-9,
                        )
                        # Post-check executor death — see above.
                        result._floor_checked = True  # type: ignore[attr-defined]
                    finally:
                        if _reaper_cell is not None:
                            _reaper_cell["death_local"].fd = None
                        for _dfd in (_death_w_holder[0], _death_r):
                            if _dfd is not None:
                                try:
                                    os.close(_dfd)
                                except OSError:
                                    pass
                        if _reap_token is not None:
                            _sweep_marked_processes(_reap_token)
        finally:
            events = (
                proxy_instance.unregister_sandbox(proxy_token)
                if proxy_token is not None else []
            )
        # Accumulate into the sandbox()-scoped cumulative view so callers
        # can inspect `run.events` for a unified stream across multiple
        # run() calls within one `with sandbox()` block.
        _sandbox_events.extend(events)

        # Runtime dominance backstop for the chokepoint: every result
        # consumed by run() must carry the checked-dispatch stamp. The
        # AST gate covers executors added in THIS module; this covers
        # a lane that spawns from another module entirely — post-exec
        # (a lane the contract does not know about cannot be asserted
        # pre-exec), so it converts a silent bypass into a loud
        # failure at first use rather than preventing the first run.
        if not getattr(result, "_floor_checked", False):
            raise _errors.SandboxFloorError(
                "sandbox internal invariant violated: a result reached "
                "run()'s epilogue without passing the checked-dispatch "
                "chokepoint — an executor lane is bypassing the "
                "containment-floor contract.",
                "route the lane through _dispatch_floor_check(lane, "
                "executor=...) so its declared tier is asserted "
                "against the floor.",
                achievable=_tiers.ContainmentTier.BARE,
                floor=_floor,
            )
        # Interpret process termination for observability
        _interpret_result(result, cmd_display)

        # Record whether mount-ns engaged on this run so per-run
        # forensic readers (sandbox-summary.json consumers) can tell
        # if the child had mount-ns isolation or fell back to
        # Landlock-only mode. See ``core/security/THREAT_MODEL.md``
        # I2-(a) for why this matters.
        # not `use_mount` alone: a per-call skip_mount_ns=True child has
        # no bind tree even on a mount-capable host — reporting True
        # would tell forensic readers the child had fs isolation it
        # didn't have.
        result.sandbox_info["mount_ns_active"] = bool(
            used_spawn and use_mount
            and not _spawn_without_mount
        )
        if (used_spawn
                and _spawn_without_mount):
            # Backend vocabulary: "landlock-pidns" when the Landlock
            # policy layer engaged (the historical mountless posture),
            # "pidns-nomount" when the floor-consented Landlock-absent
            # mode ran without it (the ported ns-only lane).
            result.sandbox_info["backend"] = (
                "landlock-pidns" if landlock_available
                else "pidns-nomount")
            if _require_fresh_procfs or _ported_hard_fresh:
                # Stamped when the fresh procfs mount was ENFORCED
                # ('F' fail-closed): the caller's contract flag, or
                # the ported ns-only lane's own tier promise.
                result.sandbox_info["fresh_procfs"] = True
        # Containment-tier posture: the tier this call actually
        # DELIVERED, the floor in force, and where the floor came
        # from. Always stamped — the canonical answer to "what
        # contained this run" (mount_ns_active/backend stay for
        # compatibility). Mirrors the dispatch tags exactly,
        # including the per-call caps (_spawn_tier_cap): a skip_pid_ns
        # run keeps the HOST procfs on both spawn lanes (the
        # fresh-proc remount rides the pid-ns grandchild fork), so
        # its posture is capped at the policy-layer tier — under the
        # redefined ns-only tier (which PROMISES a fresh procfs),
        # stamping ns-only would tell forensic readers the run had a
        # procfs isolation it did not have. The Landlock-absent
        # tolerance stamps a mountless run at the ported ns-only
        # tier (or lower, per the same cap the dispatch asserted).
        if effectively_disabled:
            _delivered_tier = _tiers.ContainmentTier.BARE
        elif used_spawn and use_seatbelt:
            _delivered_tier = _tiers.ContainmentTier.SEATBELT
        elif used_spawn and _skip_pid_ns and sys.platform == "linux":
            _delivered_tier = (
                _tiers.ContainmentTier.LANDLOCK_ONLY
                if landlock_available
                else _tiers.ContainmentTier.BARE)
        elif used_spawn and not _spawn_without_mount:
            _delivered_tier = _tiers.ContainmentTier.MOUNT_NS
        elif used_spawn and _landlock_tolerated:
            _delivered_tier = _ported_ns_tier()
        elif used_spawn:
            _delivered_tier = _tiers.ContainmentTier.MOUNTLESS_NS
        elif sys.platform == "linux" and landlock_available:
            _delivered_tier = _tiers.ContainmentTier.LANDLOCK_ONLY
        else:
            _delivered_tier = _tiers.ContainmentTier.BARE
        _tier_info = result.sandbox_info  # type: ignore[attr-defined]
        _tier_info["containment_tier"] = _tiers.tier_label(
            _delivered_tier)
        _tier_info["containment_floor"] = _tiers.tier_label(_floor)
        _tier_info["floor_source"] = _floor_source
        if _netns_inherited_drop:
            # The requested network block was inherited away (see the
            # inherit_netns gate at the kwarg pop) — forensic readers
            # must see that this "network-blocked" run shared the
            # caller's netns.
            _tier_info["netns_inherited"] = True
        # Fresh-procfs posture for pid-ns runs. When the host refuses
        # the grandchild's procfs remount (static kernel policy —
        # probed once, warned once per process by _spawn), stamp the
        # per-run consequence so forensic readers see the degradation
        # on every affected run, not only in the deduplicated log:
        # /proc/<ns-pid> lookups ENOENT for ptrace-family tools inside
        # the sandbox, and the host-pid procfs listing surface stays
        # visible on runs that accept the degrade. NOT stamped on the
        # require_fresh_procfs contract lane: a contract run that got
        # this far PROVED its procfs was fresh (a grandchild mount
        # failure aborts the run before any result exists), so a
        # divergent probe verdict must not mislabel it degraded.
        if (used_spawn and not _skip_pid_ns
                and not (_require_fresh_procfs or _ported_hard_fresh)
                and sys.platform == "linux"):
            from .probes import check_pidns_fresh_proc_available
            if not check_pidns_fresh_proc_available():
                result.sandbox_info[  # type: ignore[attr-defined]
                    "pidns_proc_mount_unavailable"] = True
        # Telemetry-key posture (weakest-wins per run dir): without a
        # mount namespace or a read allowlist the child can read the
        # telemetry-MAC key and mint valid tokens — triage demotes
        # token-verified telemetry for such runs. Recorded per call
        # so multi-call runs take the weakest posture.
        # Seatbelt audit runs stamp what is ENFORCED: audit mode drops
        # the SBPL read deny for allow-with-report (observe, don't
        # block), so restrict_reads was requested but NOT delivered —
        # the honest value is False, and weakest-wins then does the
        # right thing across the run. Linux keeps Landlock enforcing
        # under its audit tier, so the requested value stays honest
        # there.
        _seatbelt_audit_observe_only = bool(
            used_spawn and use_seatbelt and nonlocal_audit_mode
            and restrict_reads)
        # Landlock-less honesty (Linux): a requested read restriction
        # is DELIVERED only by the mount tree (visibility — unbound
        # paths do not exist in the pivoted view) or by Landlock's
        # read allowlist. When the run executed without either — the
        # ported ns-only lane, or a trusted demotion to the plain
        # lane on a Landlock-less kernel — nothing enforced it, and
        # stamping the REQUEST would both self-contradict the tier
        # stamp and defeat the telemetry-key forgery demotion
        # (mac_key_hidden would claim a key the child could read was
        # hidden). Same honesty rule the seatbelt audit tier applies.
        _reads_unenforced_no_landlock = bool(
            sys.platform == "linux" and restrict_reads
            and not effectively_disabled
            and not landlock_available
            and not result.sandbox_info["mount_ns_active"])
        _reads_enforced = bool(
            restrict_reads and not _seatbelt_audit_observe_only
            and not _reads_unenforced_no_landlock)
        _posture_dir = audit_run_dir or output
        if _posture_dir and not effectively_disabled:
            try:
                from . import summary as _summary_posture
                _summary_posture.record_run_posture(
                    Path(_posture_dir),
                    mount_ns_active=bool(
                        result.sandbox_info["mount_ns_active"]),
                    restrict_reads=_reads_enforced,
                    mountless_backend=bool(
                        used_spawn and _spawn_without_mount),
                    containment_tier=_tiers.tier_label(_delivered_tier),
                    containment_floor=_tiers.tier_label(_floor),
                )
            except Exception:  # noqa: BLE001 — best-effort telemetry posture
                logger.debug("run posture record failed",
                             exc_info=True)
        if _mount_ns_degraded:
            result.sandbox_info["mount_ns_degraded"] = _mount_ns_degraded
        # restrict_reads is enforced on every engaged path — mount-ns
        # via the bind tree + Landlock, skip_mount_ns and Landlock-only
        # via the Landlock read allowlist alone — EXCEPT the seatbelt
        # audit tier, where the read wall is observe-only (see the
        # posture note above): stamp the enforced truth plus an
        # explicit marker so forensic readers can tell "no read wall"
        # from "read wall demoted by audit mode".
        result.sandbox_info["restrict_reads"] = _reads_enforced
        if _seatbelt_audit_observe_only:
            result.sandbox_info[  # type: ignore[attr-defined]
                "read_enforcement"] = "observe-only"
        elif _reads_unenforced_no_landlock:
            # Requested but nothing could enforce it (Landlock-less
            # kernel, no mount tree) — distinct marker so forensic
            # readers can tell "no read wall requested" from
            # "requested, unenforceable, consented".
            result.sandbox_info[  # type: ignore[attr-defined]
                "read_enforcement"] = "unenforced"
        if _private_scratch_dir or _mountless_private_scratch:
            # Restricted host-visible posture: the host-shared /tmp and
            # /dev/shm grants were replaced by a 0700 TMPDIR-steered scratch
            # directory, whether namespaces remain active or not.
            result.sandbox_info["private_scratch"] = True
        if (_reaper_cell is not None and not used_spawn
                and not _audit_landlock_engaged):
            # No-namespace posture: teardown containment came from the
            # subreaper sweeper + marked-process backstop rather than
            # a pid-namespace cascade. The audit-engaged exclusion
            # keeps the stamp honest: run_landlock_audit spawns the
            # payload with a reaper-less rlimit preexec (no
            # _reaper_split, no sweeper, no marker backstop) —
            # teardown containment there is the tracer's
            # PTRACE_O_EXITKILL, so neither sweep stamp applies. The
            # used_spawn exclusion is load-bearing since the reaper
            # cell became unconditional: a spawn-lane run's teardown
            # is the pid-ns cascade, and its preexec (where the
            # sweeper forks) never runs.
            _sweep_info = result.sandbox_info
            _sweep_info["teardown_sweep"] = True
            # Sweeper-killability gap (kernel limitation, stamped
            # honestly like the Landlock metadata/TRUNCATE gaps
            # below): the sweeper forks BEFORE Landlock restrict_self,
            # so on scoping kernels (ABI >= 6, kernel 6.12) it sits
            # outside the payload's Landlock domain and the payload
            # cannot signal it. Without scoping (ABI < 6, or no
            # Landlock ruleset engaged for the payload) a hostile
            # same-UID payload can SIGKILL the sweeper before
            # spawning daemons, leaving only the (env-scrub-able)
            # marker backstop. landlock.py warns once per process at
            # ruleset build time; this stamp gives forensic readers
            # the per-run posture. ``signal_scoped`` is recorded by
            # _make_preexec_fn next to the ruleset-engagement
            # predicate so the stamp cannot drift from it.
            if not _reaper_cell.get("signal_scoped"):
                _sweep_info["teardown_sweep_signal_unscoped"] = True
        # Landlock metadata gap (kernel limitation, stamped honestly):
        # Landlock has no access right for metadata-only operations —
        # chmod/chown/utimensat/setxattr on any same-UID file OUTSIDE
        # the writable allowlist still succeed when Landlock is the
        # only filesystem barrier. Under mount-ns the read-only binds
        # close this (metadata writes fail EROFS); seccomp cannot
        # close it (the target path lives behind a pointer argument
        # classic BPF cannot dereference). Stamp the posture so
        # forensic readers know metadata trust does not hold for this
        # run. See docs/sandbox.md "Known limitations".
        if (sys.platform == "linux"
                and not result.sandbox_info["mount_ns_active"]
                and writable_paths and check_landlock_available()):
            result.sandbox_info["landlock_metadata_ops_unrestricted"] = True
            # Landlock TRUNCATE gap (ABI < 3, kernel < 6.2, stamped
            # honestly like the metadata gap above): the TRUNCATE
            # access right doesn't exist before ABI 3, so truncate(2)
            # / open(O_TRUNC) on same-UID files OUTSIDE the writable
            # allowlist still succeeds when Landlock is the only
            # filesystem barrier. Under mount-ns the read-only binds
            # close this (EROFS). landlock.py warns once at ruleset
            # build time; the stamp lets forensic readers see the
            # posture per run.
            if _get_landlock_abi() < 3:
                result.sandbox_info["landlock_truncate_unrestricted"] = True
        if _degraded_tcp_deny:
            result.sandbox_info["degraded_net_deny"] = True
        if _use_proxy_netns:
            result.sandbox_info["proxy_enforcement"] = "netns"
        elif use_egress_proxy:
            result.sandbox_info["proxy_enforcement"] = "landlock_tcp"
            # Record the tier-2 weakening in the per-run evidence so
            # forensic readers of sandbox_info see the reduced
            # guarantee alongside the enforcement label, not only in
            # process logs: the Landlock pin is port-scoped, so any
            # address on the pinned port is reachable without the
            # proxy's hostname gate.
            _t2_note = (
                "egress tier: landlock_tcp port pin — Landlock scopes "
                "TCP connect by port only; any address on the proxy "
                "port is reachable without the hostname allowlist"
            )
            _t2_existing = result.sandbox_info.get("evidence", "")
            result.sandbox_info["evidence"] = (
                f"{_t2_existing} — {_t2_note}" if _t2_existing
                else _t2_note
            )
        # Observe nonce — only present when sandbox(observe=True)
        # actually engaged audit mode at spawn time; absent under
        # plain audit and absent when observe was requested but
        # audit-mode degraded silently (libseccomp unavailable,
        # mount-ns blocked by host, etc.). Operator pipes this into
        # parse_observe_log(expected_nonce=...) for spoof-resistant
        # parsing. None when not engaged so a naive
        # ``info.get("observe_nonce")`` reader gets a falsy value
        # that signals "no provenance proof available".
        #
        # spawn_eligible is the load-bearing gate: a False value
        # means we routed to the Landlock-only subprocess path
        # which has no tracer-fork, so even though we generated a
        # nonce upstream, no records carry it. Stamping the nonce
        # would make a confused operator pass it to
        # parse_observe_log() and get an empty profile back; better
        # to surface None and let the operator notice their probe
        # didn't engage. The sandbox-audit-degraded.json marker
        # explains why.
        # Either the spawn-path engaged the tracer (mount-ns spawn
        # OR macOS seatbelt) OR the Landlock-only audit helper did.
        # Stamp the nonce in either case so the operator can pass
        # it to parse_observe_log() for spoof-resistant parsing.
        _audit_engaged_anywhere = (
            used_spawn or _audit_landlock_engaged
        )
        # Machine-readable evidence-channel record: when the caller
        # asked for audit, say whether ANY audit tier engaged for
        # this call. False pairs with the per-run
        # sandbox-audit-degraded.json marker (which carries the why);
        # consumers (triage provenance, run-metadata readers) get a
        # per-call signal instead of parsing warnings out of stderr.
        # Absent when audit was not requested/engaged for the call.
        if nonlocal_audit_mode:
            result.sandbox_info["audit_engaged"] = bool(
                _audit_engaged_anywhere
            )
        if (nonlocal_observe_nonce is not None
                and nonlocal_audit_mode
                and _audit_engaged_anywhere):
            result.sandbox_info["observe_nonce"] = nonlocal_observe_nonce
            # Record HOW the nonce reached the tracer so
            # parse_observe_log's backstop can refuse nonce-based
            # trust if a future regression re-introduces a delivery
            # channel the target could read on a namespace-less
            # host. macOS: the nonce stays in parent-process state
            # (seatbelt_audit.LogStreamer) and never touches disk;
            # Linux spawn paths (mount-ns _spawn AND the Landlock-
            # only _landlock_audit helper): anonymous fd — memfd
            # passed as /proc/self/fd/N, no filesystem name.
            result.sandbox_info["nonce_delivery"] = (
                "in_process"
                if (spawn_eligible and use_seatbelt)
                else "anonymous_fd"
            )
        else:
            result.sandbox_info["observe_nonce"] = None

        # Attach proxy events (allow + deny + dns_fail + bytes) to
        # sandbox_info. Available to callers as
        # `result.sandbox_info["proxy_events"]` for diagnostics — lets
        # operators see what hosts the child tried to reach and whether
        # they were allowed, without hunting through the proxy log.
        # caller_label has already been stamped by the proxy at
        # unregister time (one copy, authoritative).
        if events:
            result.sandbox_info["proxy_events"] = events
            # Surface a concise summary in the top-level evidence for
            # quick-triage readers of sandbox_info.
            allowed = sum(1 for e in events if e["result"] == "allowed")
            denied = sum(1 for e in events
                         if e["result"] in ("denied_host", "denied_resolved_ip"))
            summary = (
                f"egress: {allowed} allowed, {denied} denied "
                f"({len(events)} total)"
            )
            existing = result.sandbox_info.get("evidence", "")
            result.sandbox_info["evidence"] = (
                f"{existing} — {summary}" if existing else summary
            )

            # Per-spawn persistence: write this subprocess's events
            # to ``<output>/proxy-events.jsonl`` immediately. The
            # block-level write at ``sandbox()`` ``__exit__`` covers
            # events from non-subprocess code inside the with-block
            # (e.g. ``agent.py``'s in-process ``analyse()``); both
            # writers share the same safe-open helper + the target-
            # pollution skip so the file format stays unified.
            _persist_proxy_events(events, output=output, target=target)

        # Check for sandbox enforcement. Each category is only reported when
        # its layer is actually engaged for this call — prevents false
        # positives from ordinary EACCES on unsandboxed systems and from
        # stale writable_paths when Landlock is unavailable.
        # Decode bytes stderr the same way _interpret_result does —
        # otherwise callers passing capture_output=True without text=True
        # would silently lose all enforcement detection while still
        # getting sanitizer detection (which _interpret_result decodes).
        raw_stderr = result.stderr
        if isinstance(raw_stderr, str):
            stderr_text = raw_stderr
        elif isinstance(raw_stderr, bytes):
            stderr_text = raw_stderr.decode("utf-8", errors="replace")
        else:
            stderr_text = ""
        # Engagement booleans tell _check_blocked which stderr patterns
        # are admissible evidence of a sandbox firing. macOS via SBPL
        # uses the SAME stderr patterns ("Permission denied",
        # "PermissionError", connection refused, ...) — the kernel
        # turns SBPL denies into the standard EACCES/EPERM errno that
        # tools surface as the same messages — so we just OR in the
        # seatbelt-equivalent for each layer:
        #   network: SBPL (deny network*) is emitted when block_network
        #     OR use_egress_proxy → network_engaged on the macOS side.
        #   landlock: the seatbelt profile ALWAYS emits a write-deny
        #     clause (the default exception list is /private/tmp +
        #     output + writable_paths), so use_seatbelt itself is
        #     sufficient signal that fs writes are gated.
        #   seccomp: macOS has no real equivalent; we treat the
        #     SBPL hardening clauses (Tier 1.4, deny process-info etc.)
        #     as a coarse stand-in when seccomp_profile is requested.
        network_engaged = bool(
            (need_unshare and block_network)
            or (use_seatbelt and (block_network or use_egress_proxy))
            or (_degraded_tcp_deny and landlock_available)
        )
        landlock_engaged = bool(
            ((writable_paths or allowed_tcp_ports or effective_read_paths)
             and landlock_available)
            or use_seatbelt
        )
        seccomp_engaged = bool(
            (seccomp_profile and check_seccomp_available())
            or (use_seatbelt and seccomp_profile and seccomp_profile != "none")
        )
        if stderr_text and (network_engaged or landlock_engaged or seccomp_engaged):
            _check_blocked(stderr_text, cmd_display, result.returncode,
                          result.sandbox_info,
                          network_engaged=network_engaged,
                          landlock_engaged=landlock_engaged,
                          writable_paths=writable_paths,
                          seccomp_engaged=seccomp_engaged,
                          seccomp_profile=seccomp_profile,
                          degraded_net_deny=_degraded_tcp_deny,
                          # Linux: the SOCK_DGRAM block rides the
                          # seccomp filter, so it is only live when
                          # seccomp is. macOS: seatbelt's blanket
                          # network deny covers UDP/loopback wholesale.
                          udp_block_engaged=bool(
                              (seccomp_block_udp and seccomp_engaged)
                              or (use_seatbelt
                                  and (block_network
                                       or use_egress_proxy))))

        # subprocess.run parity for check= — after interpretation and
        # event accounting so a raising run still leaves run.events
        # and the blocked-operation diagnostics populated.
        if _check_requested and result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode, getattr(result, "args", list(cmd)),
                output=result.stdout, stderr=result.stderr,
            )
        return result

    # Expose the cumulative per-sandbox event view as an attribute on the
    # yielded run. Each inner run() call appends its per-call slice to this
    # list, so callers can do `run.events` after one or more run()s for a
    # unified audit trail (whereas result.sandbox_info["proxy_events"]
    # remains the per-call slice). Holds a live reference, not a copy —
    # still-executing concurrent threads would see mutations in real time.
    run.events = _sandbox_events  # type: ignore[attr-defined]

    # Mount-ns stubs are cleaned up per-call inside _spawn.run_sandboxed;
    # the sandbox() context manager itself has nothing to tear down
    # EXCEPT the audit-mode ref-count on the egress proxy.
    #
    # ACQUIRE the audit ref-count HERE (just before yield), not earlier
    # in the use_egress_proxy block. If we acquired earlier, any
    # exception in the intermediate setup code would leave the count
    # incremented forever — the contextmanager's try/finally below
    # only fires after the yield is reached. Acquiring immediately
    # before the yield ensures the matching release is guaranteed by
    # the finally below.
    # Block-level proxy-event token: captures events from
    # non-subprocess HTTPClient calls inside ``with sandbox():``.
    # The per-spawn token inside ``_run()`` already captures
    # subprocess-attributed events; this block token fills the gap
    # for callers like ``agent.py`` that wrap pure-Python work in
    # the sandbox (no subprocess via ``run()``). Persistence at
    # ``__exit__`` dedups against ``_sandbox_events`` so a single
    # ``proxy-events.jsonl`` doesn't carry duplicates of events
    # that the per-spawn writer already persisted. Only acquired
    # when audit-mode IS engaging — same operator-intent gate as
    # the audit ref-count acquire below. Registered BEFORE the
    # audit acquire so the audit-acquire-to-yield gap stays
    # minimal (pinned by ``test_acquire_happens_immediately_
    # before_yield``); if ``register_sandbox`` raises, the audit
    # acquire never runs so there's no ref-count leak.
    _block_token: int | None = None
    if (use_egress_proxy and _will_engage_audit and output
            and proxy_instance is not None):
        # Same lane subscription as the per-spawn buffers (D3): the
        # cm-block view collects THIS context's would-deny records,
        # not a concurrent run's.
        _block_token = proxy_instance.register_sandbox(
            caller_label=(
                f"{caller_label}:cm-block" if caller_label
                else "sandbox:cm-block"
            ),
            lane_key=(_proxy_unix_path if _use_proxy_netns
                      else _proxy_tcp_lane_port),
            host_recon_threshold=host_recon_threshold_for_profile(
                profile or DEFAULT_PROFILE,
                _proxy_mod.DEFAULT_HOST_RECON_THRESHOLD,
            ),
        )
    if _private_scratch_dir is not None:
        # Registered here, adjacent to the try whose finally
        # unregisters (only the guard-tested non-raising audit
        # acquire sits between), so no setup-failure path can strand
        # the registration. The dir is seconds old during setup, so
        # late registration loses no reaper protection.
        from core.run.scratch import keepalive_register
        keepalive_register(_private_scratch_dir)
    if _persona_tmpdir is not None:
        # Same contract as the scratch above: the persona home is
        # reaper-listed and mtime-quiet after build_persona writes it
        # once, but a long-lived context making run() calls past the
        # age floor still needs its source files — losing them would
        # skip the overlay and leak host-real identity to the target.
        from core.run.scratch import keepalive_register
        keepalive_register(_persona_tmpdir)
    if use_egress_proxy and _will_engage_audit:
        # Scope the leniency to THIS context's lane. Concurrent
        # sandboxes and in-process consumers (main listener) stay
        # enforcing. set_lane_audit returning False means no lane
        # exists (tcp lane bind failed) — fail CLOSED: the audit run
        # proceeds with gate 1 enforcing and the operator is told the
        # would-deny signal is incomplete.
        _lane_key = (
            _proxy_unix_path if _use_proxy_netns
            else _proxy_tcp_lane_port
        )
        if _lane_key is not None and proxy_instance.set_lane_audit(
                _lane_key, True):
            _engaging_audit = True
        else:
            logger.warning(
                "Sandbox: audit-log mode unavailable for this "
                "context (no proxy lane) — egress allowlist stays "
                "ENFORCING; would-deny events will appear as real "
                "denials."
            )
    try:
        yield run
    finally:
        # Drain + dedup + persist the block-token events before
        # releasing the audit ref-count. Per-spawn events were
        # fanned into BOTH the per-spawn token (already persisted
        # by ``_run()``) AND the block token; dedup on
        # ``(t, host, port)`` so the JSONL doesn't carry
        # duplicates. ``_sandbox_events`` is the cumulative
        # per-spawn view appended after each inner ``run()``.
        if _block_token is not None and proxy_instance is not None:
            try:
                _block_events = proxy_instance.unregister_sandbox(
                    _block_token,
                )
            except Exception:                       # noqa: BLE001
                _block_events = []
            if _block_events:
                _seen = {
                    (e.get("t"), e.get("host"), e.get("port"))
                    for e in _sandbox_events
                }
                _block_only = [
                    e for e in _block_events
                    if (e.get("t"), e.get("host"), e.get("port"))
                    not in _seen
                ]
                if _block_only:
                    _persist_proxy_events(
                        _block_only, output=output, target=target,
                    )
        if use_egress_proxy and _engaging_audit:
            # Clear the audit bit BEFORE unbind/close pops the lane
            # from the registry: set_lane_audit resolves the key
            # through the registry and returns False once the lane is
            # popped, so a clear placed after unbind/close was a
            # silent no-op — in-flight connections (handlers hold the
            # lane object) kept log-and-allow leniency until they
            # finished. Clearing first flips the shared lane object's
            # bit while it is still resolvable, so in-flight handlers
            # revert to enforcing immediately.
            try:
                _lane_key = (
                    _proxy_unix_path if _use_proxy_netns
                    else _proxy_tcp_lane_port
                )
                if _lane_key is not None:
                    proxy_instance.set_lane_audit(_lane_key, False)
            except Exception:
                # WARNING-level (not debug): a failed clear leaves
                # connections in flight on this context's lane in
                # audit-log mode until they finish — the operator
                # should see it, because a recurring failure here
                # means the teardown path is broken.
                logger.warning(
                    "audit lane clear failed — in-flight connections "
                    "on this context's lane may keep audit-log mode "
                    "until they finish.",
                    exc_info=True,
                )
        if _use_proxy_netns and _proxy_unix_path and proxy_instance is not None:
            try:
                proxy_instance.unbind_unix(_proxy_unix_path)
            except Exception:
                logger.debug(
                    "proxy unix socket cleanup failed", exc_info=True,
                )
        if _proxy_tcp_lane_port is not None and proxy_instance is not None:
            try:
                proxy_instance.close_tcp_lane(_proxy_tcp_lane_port)
            except Exception:
                logger.debug(
                    "proxy tcp lane cleanup failed", exc_info=True,
                )
        # Per-instance lane directory follows its socket.
        if _proxy_lane_dir is not None:
            import shutil as _shutil
            try:
                _shutil.rmtree(_proxy_lane_dir, ignore_errors=True)
            except Exception:
                logger.debug(
                    "proxy lane dir cleanup failed for %s",
                    _proxy_lane_dir, exc_info=True,
                )
        # Persona tmpdir lifecycle: created in build_persona above; the
        # source files were bind-mounted into the sandbox children but
        # bind sources can be unlinked after the bind is established —
        # the kernel keeps the inode alive for the lifetime of the mount.
        # Cleanup now is safe even mid-run (rare: with sandbox() used as
        # a long-lived context wrapping many run() calls). For simplicity
        # we only clean up at __exit__; the file count is small.
        if _persona_tmpdir is not None:
            import shutil as _shutil
            from core.run.scratch import keepalive_unregister
            keepalive_unregister(_persona_tmpdir)
            try:
                _shutil.rmtree(_persona_tmpdir, ignore_errors=True)
            except Exception:
                logger.debug(
                    "persona tmpdir cleanup failed for %s",
                    _persona_tmpdir, exc_info=True,
                )
        # Private scratch dir (restricted Landlock-only posture) —
        # per-context, so it goes with the context.
        if _private_scratch_dir is not None:
            import shutil as _shutil
            from core.run.scratch import keepalive_unregister
            keepalive_unregister(_private_scratch_dir)
            try:
                _shutil.rmtree(_private_scratch_dir, ignore_errors=True)
            except Exception:
                logger.debug(
                    "private scratch cleanup failed for %s",
                    _private_scratch_dir, exc_info=True,
                )
        # Per-call scratch dirs minted by mount-ns demotions.
        if _demoted_scratch_dirs:
            import shutil as _shutil
            from core.run.scratch import keepalive_unregister
            for _dsd in _demoted_scratch_dirs:
                keepalive_unregister(_dsd)
                try:
                    _shutil.rmtree(_dsd, ignore_errors=True)
                except Exception:
                    logger.debug(
                        "demoted scratch cleanup failed for %s",
                        _dsd, exc_info=True,
                    )


# Convenience: standalone run function for one-off sandboxed commands
def run(cmd: list[str], block_network: bool = True, target: str | None = None,
        output: str | None = None, allowed_tcp_ports: list | None = None,
        profile: str | None = None, disabled: bool = False, limits: dict | None = None,
        map_root: bool = False,
        use_egress_proxy: bool = False, proxy_hosts: list | None = None,
        proxy_allowed_ports: list | None = None,
        require_proxy_netns: bool = False,
        restrict_reads=_UNSET, readable_paths: list | None = None,
        caller_label: str | None = None,
        fake_home=_UNSET,
        tool_paths: list | None = None,
        audit: bool = False, audit_verbose: bool = False,
        audit_run_dir: str | None = None,
        audit_required: bool = False,
        observe: bool = False,
        writable_paths: list | None = None,
        exclude_tmp_baseline: bool = False,
        sanitise_host_fingerprint: bool = False,
        cpu_count: int | None = None,
        require_sanitisation: bool = False,
        etc_overlay: dict | None = None,
        degraded_net_deny: bool = True,
        loopback_unix_bridges: dict | None = None,
        omit_proc_reads: bool = False,
        omit_etc_reads: bool = False,
        rootfs: str | None = None,
        **kwargs) -> subprocess.CompletedProcess:
    """Run a single command in a sandbox. Convenience wrapper.

    Use this instead of subprocess.run() for any command that processes
    untrusted content — and prefer run_untrusted() when the COMMAND
    ITSELF comes from or is influenced by the analysed target: it is
    the fail-closed variant (refuses to execute whenever the sandbox
    cannot engage). This wrapper degrades with a warning ONLY while
    some layer can still enforce what the caller asked for; it too
    refuses (SandboxSetupError) when nothing can — a mount-ns demotion
    on a Landlock-less kernel with target/output/allowed_tcp_ports/
    restrict_reads set, or block_network=True with no enforcing layer
    left (Linux: neither the namespace backend nor Landlock ABI v4+;
    macOS: seatbelt unavailable — there is no fallback network-deny
    layer there at all).
    Applies get_safe_env(), resource limits, and namespace isolation
    automatically.

    Accepts the same sandbox-configuration kwargs as sandbox() — forwards
    them into a one-shot context.
    """
    with sandbox(block_network=block_network, target=target, output=output,
                 allowed_tcp_ports=allowed_tcp_ports, profile=profile,
                 disabled=disabled, limits=limits, map_root=map_root,
                 use_egress_proxy=use_egress_proxy,
                 proxy_hosts=proxy_hosts,
                 proxy_allowed_ports=proxy_allowed_ports,
                 require_proxy_netns=require_proxy_netns,
                 restrict_reads=restrict_reads,
                 readable_paths=readable_paths,
                 caller_label=caller_label,
                 fake_home=fake_home,
                 tool_paths=tool_paths,
                 audit=audit, audit_verbose=audit_verbose,
                 audit_run_dir=audit_run_dir,
                 audit_required=audit_required,
                 observe=observe,
                 writable_paths=writable_paths,
                 exclude_tmp_baseline=exclude_tmp_baseline,
                 sanitise_host_fingerprint=sanitise_host_fingerprint,
                 cpu_count=cpu_count,
                 require_sanitisation=require_sanitisation,
                 etc_overlay=etc_overlay,
                 degraded_net_deny=degraded_net_deny,
                 loopback_unix_bridges=loopback_unix_bridges,
                 omit_proc_reads=omit_proc_reads,
                 omit_etc_reads=omit_etc_reads,
                 rootfs=rootfs) as _run:
        return _run(cmd, **kwargs)


def run_trusted(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a command whose input was chosen by RAPTOR itself (not the target).

    Example uses: readelf/nm/strings on a RAPTOR-picked binary path,
    `ldd --version` capability probes, `file -b` metadata extraction.

    Applies get_safe_env() and resource rlimits but skips namespace/Landlock
    isolation — there is no attacker-controlled input to contain. For any
    command that runs attacker-derived content (LLM-generated code, target
    binaries, target build scripts), use `run_untrusted()` or `sandbox()`.

    Note: still forwards `env=`, `cwd=`, `preexec_fn=`, etc. via **kwargs,
    so callers can override safe env or cwd if they know what they are
    doing. The guard below only rejects sandbox-level kwargs which would
    be silently ignored under `profile='none'`.
    """
    misused = _SANDBOX_KWARGS & kwargs.keys()
    if misused:
        msg = (
            f"run_trusted() does not accept sandbox kwargs {sorted(misused)} — "
            f"it always runs with profile='none'. Use run_untrusted(), run() "
            f"or sandbox() for isolated execution."
        )
        raise TypeError(msg)
    return run(cmd, profile="none", **kwargs)


def _require_userns_or_optin(entry: str, restrict_reads: bool=True) -> bool:
    """Fail closed when the untrusted-execution contract cannot hold.

    The contract's credential-exfil defence is the PID/user namespace:
    without it the child runs as caller_uid in the HOST namespaces,
    where /proc/<host_pid>/environ of same-UID processes is readable
    (restrict_reads grants /proc wholesale — see the rationale at the
    effective_read_paths block). On hosts without unprivileged userns
    the namespace tier silently never engaged, so "untrusted" ran with
    the exact exposure the helper exists to prevent.

    Default: refuse loudly. RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1 is the
    explicit operator acknowledgement that Landlock/seccomp-only
    containment is acceptable on this host. macOS is exempt from the
    NAMESPACE requirement because the seatbelt tier provides the
    isolation contract there — but only when seatbelt actually
    engages: a missing/smoke-failing sandbox-exec would otherwise let
    the default (non-strict) profile degrade to a bare subprocess
    with a warn_once, silently violating the fail-closed contract the
    Linux arm enforces. The darwin arm therefore requires
    check_seatbelt_available() or the same explicit operator
    override.

    Returns True when the override engaged degraded mode AND the read
    allowlist is in force — callers then pass omit_proc_reads=True so
    the whole-of-/proc grant (and with it the same-UID environ
    credential channel) is withdrawn for that call. The override
    warning fires on EVERY degraded call (deliberately not warn_once):
    each such call runs ATTACKER-DERIVED code with a reduced contract,
    and an operator watching a long run must see every instance, not
    just the first. With restrict_reads=False there is no read
    allowlist to withdraw /proc from, so the warning names the open
    exposure instead and False is returned.
    """
    if sys.platform == "darwin":
        if check_seatbelt_available():
            return False
        if os.environ.get(
            "RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "",
        ).strip().lower() in ("1", "true", "yes", "on"):
            logger.warning(
                "%s: sandbox-exec unavailable or failed its smoke "
                "test — running UNTRUSTED code with rlimits-only "
                "containment (operator override "
                "RAPTOR_ALLOW_DEGRADED_UNTRUSTED).", entry,
            )
            return False
        from .errors import SandboxSetupError
        raise SandboxSetupError(
            f"{entry}: the seatbelt tier provides the untrusted-"
            f"execution contract on macOS, but sandbox-exec is "
            f"unavailable or failed its smoke test on this host — "
            f"refusing to run attacker-derived code unconfined.",
            "verify /usr/bin/sandbox-exec exists and can run a "
            "minimal profile, or set RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1 "
            "to explicitly accept rlimits-only containment.",
        )
    # libseccomp is part of the untrusted-execution contract on
    # Linux, not an optional layer: the AF_UNIX blocklist, the
    # io_uring/keyring/bpf escape-primitive blocks and the argument
    # rules (dgram socketpair, MSG_FASTOPEN) all live in the filter.
    # strict fail-closes at profile resolution; the default full
    # profile silently degraded to FILTERLESS with only a warning —
    # the exact silent-downgrade shape the userns gate below exists
    # to refuse. Same explicit operator override governs it.
    if not _seccomp.check_seccomp_available():
        # The seccomp filter is part of EVERY tier's delivery
        # (LANDLOCK_ONLY is "Landlock+seccomp+rlimits"), so a tier
        # floor never consents its absence — accepting filterless
        # from `--sandbox-floor landlock` would run BELOW the flag's
        # documented meaning. Only the legacy env var waives this
        # axis, and ONLY while no explicit surface pins a floor:
        # an explicit surface names a tier whose contract includes
        # the filter, so it wins over the env waiver here exactly as
        # it does on the tier chain.
        _floor_e, _src_e = _explicit_untrusted_floor()
        if _floor_e is not None:
            from .errors import SandboxSetupError
            _surface_e = ("--sandbox-floor" if _src_e
                          == _tiers.FLOOR_SOURCE_FLAG
                          else "the project sandbox-floor setting")
            if _floor_e is _tiers.ContainmentTier.BARE:
                # The "none" edge: not a tier-includes-the-filter
                # story — never-BARE-by-consent is the reason.
                _pin_clause = (
                    f"{_surface_e}=none is not a consentable "
                    f"untrusted floor — untrusted work never runs "
                    f"bare by consent; use --sandbox none / "
                    f"--no-sandbox for the operator-explicit "
                    f"sandbox-off."
                )
            else:
                _pin_clause = (
                    f"{_surface_e} pins the containment floor at "
                    f"'{_tiers.tier_label(_floor_e)}', a tier whose "
                    f"contract includes the filter — "
                    f"RAPTOR_ALLOW_DEGRADED_UNTRUSTED does not "
                    f"override an explicit surface."
                )
            raise SandboxSetupError(
                f"{entry}: libseccomp is unavailable or non-functional "
                f"on this host — the untrusted-execution contract "
                f"includes the seccomp syscall filter (socket-family "
                f"blocklist, escape-primitive blocks, send-flag "
                f"argument rules), which would silently not engage. "
                f"{_pin_clause}",
                "install libseccomp (libseccomp2 package); no "
                "--sandbox-floor tier waives seccomp absence (every "
                "tier includes the filter).",
            )
        if _degraded_untrusted_waiver():
            logger.warning(
                "%s: libseccomp unavailable — running UNTRUSTED code "
                "WITHOUT a seccomp filter (operator override "
                "RAPTOR_ALLOW_DEGRADED_UNTRUSTED): socket-family, "
                "escape-primitive and send-flag argument blocks are "
                "all inactive for this call.", entry,
            )
        else:
            from .errors import SandboxSetupError
            raise SandboxSetupError(
                f"{entry}: libseccomp is unavailable or non-functional "
                f"on this host — the untrusted-execution contract "
                f"includes the seccomp syscall filter (socket-family "
                f"blocklist, escape-primitive blocks, send-flag "
                f"argument rules), which would silently not engage.",
                "install libseccomp (libseccomp2 package), or set "
                "RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1 to explicitly "
                "accept running untrusted code without a syscall "
                "filter (no --sandbox-floor tier waives seccomp "
                "absence — every tier includes the filter).",
            )
    if check_net_available():
        return False
    # Namespace loss on a userns-blocked host is acceptable only when
    # the consent chain lowered the untrusted floor to EXACTLY the
    # landlock tier (per-run flag > project setting > legacy env var).
    # A floor above it (the default, or an explicitly RAISED
    # flag/project floor — which wins over the env waiver in both
    # directions) refuses; an explicit BARE ("none") consents to
    # nothing and refuses too — untrusted work never runs bare by
    # consent.
    _floor, _floor_src = resolve_untrusted_floor()
    if (_floor is _tiers.ContainmentTier.LANDLOCK_ONLY
            and _floor_src in _tiers.CONSENT_FLOOR_SOURCES):
        if _floor_src == _tiers.FLOOR_SOURCE_FLAG:
            _consent_name = "operator consent --sandbox-floor landlock"
        elif _floor_src == _tiers.FLOOR_SOURCE_PROJECT:
            _consent_name = ("operator consent: project setting "
                             "sandbox-floor=landlock")
        else:
            _consent_name = ("operator override "
                             "RAPTOR_ALLOW_DEGRADED_UNTRUSTED")
        if restrict_reads is not _UNSET and not restrict_reads:
            logger.warning(
                "%s: unprivileged user namespaces unavailable — running "
                "UNTRUSTED code with Landlock/seccomp-only containment "
                "(%s) "
                "AND restrict_reads=False: same-UID /proc/<pid>/environ "
                "credential reads are NOT blocked for this call.", entry,
                _consent_name,
            )
            return False
        logger.warning(
            "%s: unprivileged user namespaces unavailable — running "
            "UNTRUSTED code with Landlock/seccomp-only containment "
            "(%s). "
            "/proc is dropped from the read allowlist for this call "
            "so same-UID /proc/<pid>/environ credential reads stay "
            "blocked; tools that read /proc/self/* (ASAN, IFUNC "
            "dispatch, runtime CPU detection) may fail with EACCES — "
            "pass readable_paths= for specific needs, or fix the "
            "host's userns restriction.", entry, _consent_name,
        )
        return True
    from .errors import SandboxSetupError
    msg = (
        f"{entry}: this host cannot create unprivileged user "
        f"namespaces, so the untrusted-execution contract (PID-ns "
        f"hides host /proc; credential exfil blocked) cannot be met. "
        f"Refusing to run untrusted code with degraded containment. "
        f"Fix the host (e.g. the kernel/LSM userns restriction — see "
        f"core/sandbox/helpers/) or explicitly accept "
        f"Landlock/seccomp-only containment: --sandbox-floor landlock "
        f"(this run), /project set sandbox-floor landlock (standing "
        f"for the project), or RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1 "
        f"(host-wide)."
    )
    if _floor_src in (_tiers.FLOOR_SOURCE_FLAG,
                      _tiers.FLOOR_SOURCE_PROJECT):
        _surface = ("--sandbox-floor" if _floor_src
                    == _tiers.FLOOR_SOURCE_FLAG
                    else "the project sandbox-floor setting")
        if _floor is _tiers.ContainmentTier.BARE:
            msg += (
                f" Note: {_surface}=none is not a consentable "
                f"untrusted floor — untrusted work never runs bare "
                f"by consent; use --sandbox none / --no-sandbox for "
                f"the operator-explicit sandbox-off."
            )
        else:
            msg += (
                f" Note: {_surface} currently pins the floor at "
                f"'{_tiers.tier_label(_floor)}', which the env var "
                f"does not override."
            )
    raise SandboxSetupError(msg)


def _reopen_write_only(fd: int, flags: int) -> "int | None":
    """Reopen *fd*'s file write-only, returning the new fd or None.

    Linux's /proc/self/fd magic links honour the requested flags. BSD
    /dev/fd opens are dup(2)s — flags are ignored and the descriptor
    keeps its original access mode — so the result is VERIFIED
    write-only; when it is not, fall back to a true reopen by real
    path (F_GETPATH, macOS) pinned by device/inode identity against
    the original descriptor. Returns None when no verified write-only
    reopen exists (caller must fail closed, e.g. plug with /dev/null).
    """
    import fcntl as _fcntl
    fd_link = (
        f"/proc/self/fd/{fd}" if sys.platform != "darwin"
        else f"/dev/fd/{fd}"
    )
    try:
        wfd = os.open(fd_link, flags)
    except OSError:
        wfd = -1
    if wfd >= 0:
        try:
            if _fcntl.fcntl(wfd, _fcntl.F_GETFL) & os.O_ACCMODE \
                    == os.O_WRONLY:
                return wfd
        except OSError:
            pass
        os.close(wfd)
    getpath = getattr(_fcntl, "F_GETPATH", None)
    if getpath is None:
        return None
    try:
        raw = _fcntl.fcntl(fd, getpath, bytes(1024))
        path = raw.split(b"\x00", 1)[0].decode(
            sys.getfilesystemencoding(), "surrogateescape")
        cand = os.open(path, flags)
    except OSError:
        return None
    try:
        st_old, st_new = os.fstat(fd), os.fstat(cand)
        if (st_old.st_dev, st_old.st_ino) \
                == (st_new.st_dev, st_new.st_ino):
            return cand
    except OSError:
        pass
    os.close(cand)
    return None


def _fresh_procfs_override_hint(
        literal_contract: "bool | None" = None) -> str:
    """The override sentence for a fresh-procfs refusal, told honestly.

    Every in-tree untrusted caller derives require_fresh_procfs from
    :func:`untrusted_fresh_procfs_required`, so for them the consent
    chain IS consulted (a lowered floor means the flag arrives False
    and no refusal fires). The remedy sentence therefore reflects the
    reader's ACTUAL situation:

    * an explicit surface (per-run flag / project setting) pinned the
      floor — say so, name the surface, and say the env var will NOT
      relax it (explicit wins on disagreement);
    * the chain is at the default and a lowered floor would relax the
      refusal — name every override surface with the exact re-run
      spelling;
    * the chain is already lowered but the refusal still fired.
      ``literal_contract`` carries the call's truth from the refusal
      site: ``True`` = the call carried a literal
      ``require_fresh_procfs=True`` — an explicit caller ask no
      consent surface relaxes (telling that caller to consent again
      would be a lie); ``False`` = the call honoured the lowered
      floor and this host cannot deliver even the consented tier —
      no consent surface admits a bare untrusted run; ``None`` =
      unknown (out-of-run callers), told as the literal-ask case
      (the only reachable shape for derived callers).
    """
    _floor, _source = resolve_untrusted_floor()
    if _source == _tiers.FLOOR_SOURCE_FLAG:
        if untrusted_fresh_procfs_required():
            return (
                f"--sandbox-floor {_tiers.tier_label(_floor)} pins the "
                f"untrusted containment floor for this run "
                f"(RAPTOR_ALLOW_DEGRADED_UNTRUSTED does not override "
                f"it). To accept host-procfs-visible containment, "
                f"re-run with --sandbox-floor landlock."
            )
        if literal_contract is False:
            return (
                f"--sandbox-floor {_tiers.tier_label(_floor)} already "
                f"lowers the untrusted containment floor, but this "
                f"host cannot deliver even that tier for this call — "
                f"no consent surface admits a bare untrusted run; fix "
                f"the host, or use the operator-explicit "
                f"--sandbox none / --no-sandbox."
            )
        return (
            f"--sandbox-floor {_tiers.tier_label(_floor)} already "
            f"lowers the untrusted containment floor, but this call "
            f"passed an explicit require_fresh_procfs=True, which no "
            f"consent surface relaxes — drop the explicit flag (or "
            f"derive it from untrusted_fresh_procfs_required()) to "
            f"honour the consent."
        )
    if _source == _tiers.FLOOR_SOURCE_PROJECT:
        if untrusted_fresh_procfs_required():
            return (
                f"the active project's sandbox-floor="
                f"{_tiers.tier_label(_floor)} setting pins the "
                f"untrusted containment floor "
                f"(RAPTOR_ALLOW_DEGRADED_UNTRUSTED does not override "
                f"it). To accept host-procfs-visible containment, "
                f"re-run with --sandbox-floor landlock (per-run flag "
                f"overrides the project setting) or change the "
                f"standing consent via /project set sandbox-floor "
                f"landlock."
            )
        if literal_contract is False:
            return (
                f"the active project's sandbox-floor="
                f"{_tiers.tier_label(_floor)} setting already lowers "
                f"the untrusted containment floor, but this host "
                f"cannot deliver even that tier for this call — no "
                f"consent surface admits a bare untrusted run; fix "
                f"the host, or use the operator-explicit "
                f"--sandbox none / --no-sandbox."
            )
        return (
            f"the active project's sandbox-floor="
            f"{_tiers.tier_label(_floor)} setting already lowers the "
            f"untrusted containment floor, but this call passed an "
            f"explicit require_fresh_procfs=True, which no consent "
            f"surface relaxes — drop the explicit flag (or derive it "
            f"from untrusted_fresh_procfs_required()) to honour the "
            f"consent."
        )
    if not untrusted_fresh_procfs_required():
        if literal_contract is False:
            return (
                "RAPTOR_ALLOW_DEGRADED_UNTRUSTED already lowers the "
                "untrusted containment floor, but this host cannot "
                "deliver even the waived tier for this call — no "
                "consent surface admits a bare untrusted run; fix "
                "the host, or use the operator-explicit "
                "--sandbox none / --no-sandbox."
            )
        return (
            "RAPTOR_ALLOW_DEGRADED_UNTRUSTED is already set, but this "
            "call passed an explicit require_fresh_procfs=True, which "
            "the override does not relax — drop the explicit flag (or "
            "derive it from untrusted_fresh_procfs_required()) to "
            "honour the override."
        )
    return (
        "Alternatively re-run with --sandbox-floor landlock (this "
        "run), persist the consent with /project set sandbox-floor "
        "landlock (standing for the project), or set "
        "RAPTOR_ALLOW_DEGRADED_UNTRUSTED=1 (host-wide) to "
        "explicitly accept host-procfs-visible containment."
    )


def _fresh_procfs_env_refusal(
    achievable: "_tiers.ContainmentTier | None" = None,
    floor: "_tiers.ContainmentTier | None" = None,
    literal_contract: "bool | None" = None,
) -> "_errors.SandboxFloorError":
    """Build the refusal for a fresh-procfs contract call on a host
    where no isolation backend engaged for ENVIRONMENTAL reasons
    (``use_sandbox`` computed False without an operator disable).

    Split out of run() so the darwin remedy arm is unit-testable
    off-platform. The remedy names the actual host condition (Linux:
    :func:`mount_unavailable_reason`, the host diagnostic for the
    userns-founded backends — legitimate here because the mount
    probe is definitionally False whenever the net probe is; macOS:
    the sandbox-exec binary / smoke test) and appends
    :func:`_fresh_procfs_override_hint`, which tells the
    literal-True vs derived-flag override story honestly.
    """
    if sys.platform == "darwin":
        condition = ("the seatbelt backend (sandbox-exec) is "
                     "unavailable or failed its smoke test")
        exposure = ("the fallback would run the untrusted target "
                    "with rlimits-only containment")
        fix = ("verify /usr/bin/sandbox-exec exists and can run a "
               "minimal profile.")
        if achievable is None:
            achievable = _tiers.ContainmentTier.BARE
    else:
        from .probes import mount_unavailable_reason
        condition, fix = mount_unavailable_reason()
        exposure = ("the fallback lanes leave the HOST process table "
                    "visible to the untrusted target")
        if achievable is None:
            achievable = _tiers.ContainmentTier.LANDLOCK_ONLY
    msg = (
        "sandbox run(): the fresh-procfs contract cannot be met — no "
        f"isolation backend engaged on this host ({condition}), and "
        f"{exposure}."
    )
    return _errors.SandboxFloorError(
        msg, fix + " " + _fresh_procfs_override_hint(
            literal_contract=literal_contract),
        achievable=achievable,
        floor=(floor if floor is not None
               else _tiers.untrusted_default_floor()))


def _entry_floor_refusal(
    intended: "_tiers.ContainmentTier",
    floor: "_tiers.ContainmentTier",
    *,
    environmental: bool,
    skip_mount_ns: bool,
    literal_contract: "bool | None" = None,
) -> "_errors.SandboxFloorError":
    """Build the entry-time containment-floor refusal for the shape
    at hand, preserving the message texts operators (and tests) know
    from the per-lane gates this check subsumed.

    Every entry refusal reachable in phase 2 belongs to the
    fresh-procfs contract class (the waived floor is below every
    intended tier), so the wording stays fresh-procfs-specific and
    the remedy always routes through the honesty-checked
    :func:`_fresh_procfs_override_hint`.
    """
    if environmental:
        return _fresh_procfs_env_refusal(achievable=intended, floor=floor,
                                         literal_contract=literal_contract)
    if skip_mount_ns:
        msg = (
            "sandbox run(): the fresh-procfs contract cannot be met "
            "for this call (per-call skip_mount_ns=True bypasses the "
            "mount-ns backend) — the fallback lanes leave the "
            "host-pid /proc visible to the untrusted target."
        )
        return _errors.SandboxFloorError(
            msg, _fresh_procfs_override_hint(
                literal_contract=literal_contract),
            achievable=intended, floor=floor)
    msg = (
        "sandbox run(): the fresh-procfs contract cannot be "
        "met — the mount-namespace backend is unavailable on "
        "this host, and the fallback lanes leave the host-pid "
        "/proc visible to the untrusted target."
    )
    return _errors.SandboxFloorError(
        msg,
        "install newuidmap/newgidmap (uidmap package) so the "
        "mount-ns backend can engage. "
        + _fresh_procfs_override_hint(literal_contract=literal_contract),
        achievable=intended, floor=floor)


def _degraded_untrusted_waiver() -> bool:
    """Raw truth of the legacy ``RAPTOR_ALLOW_DEGRADED_UNTRUSTED`` env
    var (same idiom as the userns entry gate). FROZEN meaning:
    "untrusted floor := landlock" (Linux) — kept indefinitely as the
    escape-hatch alias; all new consent semantics ship only on the
    explicit surfaces (``--sandbox-floor`` / project ``sandbox-floor``),
    which win over it on disagreement, with a banner naming both.
    The network-axis waivers (degraded net-deny, proxy tier) keep
    their own reads of this var by design — a tier floor never
    consents the network axis.
    """
    return os.environ.get(
        "RAPTOR_ALLOW_DEGRADED_UNTRUSTED", ""
    ).strip().lower() in ("1", "true", "yes", "on")


def _explicit_untrusted_floor() -> (
        "tuple[_tiers.ContainmentTier | None, str | None]"):
    """The explicit consent surfaces' untrusted floor, flag first.

    Reads only the two state slots the argparse / project run-start
    plumbing populated (core.sandbox.cli setters) — never the
    environment, never project files, never repo content.
    """
    label = state._cli_sandbox_floor
    if label is not None:
        return _tiers.label_tier(label), _tiers.FLOOR_SOURCE_FLAG
    label = state._project_sandbox_floor
    if label is not None:
        return _tiers.label_tier(label), _tiers.FLOOR_SOURCE_PROJECT
    return None, None


def resolve_untrusted_floor() -> "tuple[_tiers.ContainmentTier, str]":
    """Resolve the untrusted containment floor from the consent chain.

    Precedence (highest wins), evaluated fresh on every call:

        per-run ``--sandbox-floor`` flag  >  project ``sandbox-floor``
        setting  >  legacy env var  >  class default (refuse below
        MOUNT_NS / SEATBELT)

    The explicit surfaces win in BOTH directions — a flag/project
    ``mount-ns`` refuses the degraded tiers even when the env waiver
    is set, and a flag/project ``landlock`` lowers without the env
    var. Returns ``(tier, source)``; a flag value of ``none`` resolves
    to BARE here and is refused for untrusted-class work at floor
    resolution (tiers.resolve_call_floor's never-BARE-by-consent arm)
    — BARE consents to nothing on any acceptance arm.
    """
    tier, source = _explicit_untrusted_floor()
    if tier is not None and source is not None:
        return tier, source
    if _degraded_untrusted_waiver():
        return _tiers.waived_untrusted_floor(), _tiers.FLOOR_SOURCE_ENV
    return _tiers.untrusted_default_floor(), _tiers.FLOOR_SOURCE_DEFAULT


def untrusted_fresh_procfs_required() -> bool:
    """True while the resolved untrusted floor demands a fresh pid-ns
    procfs — i.e. every tier the consent chain admits delivers one
    (Linux: floor above the landlock tier; macOS: the unwaived
    seatbelt contract).

    Consent chain: per-run ``--sandbox-floor`` flag > project
    ``sandbox-floor`` setting > the legacy
    ``RAPTOR_ALLOW_DEGRADED_UNTRUSTED`` env var (frozen alias for
    "untrusted floor := landlock") > the fail-closed class default.

    The untrusted entry points consume this internally. Direct
    ``run()`` callers that execute attacker-derived payloads (LLM
    exploits, candidate PoCs, target binaries) pass it as
    ``require_fresh_procfs=`` so their runs carry the same
    fresh-procfs contract instead of silently accepting host-procfs
    visibility.
    """
    floor, _source = resolve_untrusted_floor()
    if sys.platform == "darwin":
        return floor >= _tiers.ContainmentTier.SEATBELT
    return floor >= _tiers.ContainmentTier.NS_NOMOUNT


def run_untrusted(cmd: list[str], *, target: str | None = None, output: str | None = None,
                  limits: dict | None = None,
                  restrict_reads: bool = True,
                  readable_paths: list | None = None,
                  writable_paths: list | None = None,
                  fake_home: bool = True,
                  **kwargs) -> subprocess.CompletedProcess:
    """Run a command whose input is attacker-derived or otherwise untrusted.

    Always engages the full sandbox: network blocked by namespace, Landlock
    filesystem restriction (via `target`/`output`), resource rlimits. At
    least one of `target` or `output` must be truthy so Landlock actually
    engages — empty strings are rejected.

    Network block cannot be disabled here. `allowed_tcp_ports` is
    intentionally not accepted: this function forces `block_network=True`
    at the namespace level, which removes all network interfaces inside
    the sandbox — so any Landlock TCP allow-rule would be inert. Callers
    wanting a network allowlist (e.g. Claude sub-agents on port 443) must
    use `sandbox()` directly with `block_network=False` and their own
    `allowed_tcp_ports=[...]`.

    `restrict_reads` defaults to True for run_untrusted() — the premise
    is "we're running attacker-derived code, protect the invoking user's
    credentials". With restrict_reads=True, reads are limited to system
    dirs (/usr, /lib, /etc, /proc, /sys), target, output, /tmp, and
    specific safe /dev files (null/zero/random/urandom/full/tty).
    Critically, $HOME is NOT readable — so a compromised PoC cannot
    exfiltrate ~/.ssh, ~/.aws/credentials, ~/.config/raptor/models.json,
    etc. If a specific tool needs more, pass readable_paths=[...] to
    extend, or pass restrict_reads=False to opt back into the old
    read-everywhere behaviour (please don't unless absolutely necessary
    — credential exfil is the primary attack surface here).

    `fake_home` also defaults to True: the child's HOME and XDG_*_HOME
    point at `{output}/.home/` (an empty per-sandbox directory) so the
    child sees a clean home containing no dotfiles. Complements
    restrict_reads by converting HOME-denial from "Landlock blocks the
    read" into "the file isn't there to be read" — tools that
    hard-fail on EACCES now get ENOENT (or an empty home) and fall
    back to defaults. Pre-populate `{output}/.home/` before calling
    run_untrusted() if the child needs specific files in its home.

    For compiling/running LLM-generated code, running target binaries,
    invoking target build scripts, or anything else where the command or
    its inputs trace back to untrusted material.

    The trust markers (``CLAUDECODE`` / ``_RAPTOR_TRUSTED``) are
    stripped from the child environment so a target-spawned process
    cannot invoke RAPTOR's ``libexec/`` scripts as a "trusted caller"
    — it hits their refusal path instead. ``RAPTOR_DIR`` is stripped
    on the same contract: the libexec trust gate does not accept it
    and an untrusted target has no legitimate use for the checkout
    path.

    `**kwargs` forwards to run() — composable with audit/audit_verbose
    (audit-mode applies to the run_untrusted's full-strict profile),
    caller_label=, env=, cwd=, etc. `profile=` is accepted as a RATCHET
    only: 'full' (the default) or 'strict' (fail-closed — aborts with
    SandboxSetupError instead of degrading when an isolation layer is
    unavailable; see PROFILES). Weaker profiles are rejected via
    TypeError because they would relax the untrusted-execution contract
    this helper exists to enforce. Also forbidden via TypeError:
    `block_network` and `allowed_tcp_ports` — run_untrusted's contract
    is namespace-level network block, no TCP allowlist — and
    `start_new_session` — setsid is part of the same contract (no
    controlling tty, so /dev/tty cannot read the operator's
    keystrokes); callers needing varied network/session policy use
    sandbox() directly.
    """
    # Truthy check — `target=""` and `output=""` must also be rejected,
    # otherwise the caller thinks they engaged Landlock but got no
    # isolation whatsoever (every downstream check is truthy-based).
    if not (target or output):
        msg = (
            "run_untrusted() requires at least one non-empty of target= or "
            "output= so Landlock actually engages. Pass a read-only target "
            "dir and/or a writable output dir."
        )
        raise ValueError(msg)
    # Fail closed on namespace-less hosts; under the explicit operator
    # override the helper warns on EVERY call (attacker-derived code
    # under a reduced contract) and returns True so the /proc read
    # grant is withdrawn — keeping the same-UID environ credential
    # channel closed. See _require_userns_or_optin.
    _degraded_no_pidns = _require_userns_or_optin(
        "run_untrusted", restrict_reads,
    )
    # start_new_session is deliberately NOT accepted: the setsid
    # detachment below is part of the untrusted-execution contract
    # (without it /dev/tty resolves to the operator's controlling
    # terminal and a sandboxed target polls their keystrokes), so a
    # caller-supplied False would silently reopen that channel.
    # Callers that genuinely need a controlling tty (interactive gdb
    # under /crash-analysis) use sandbox() directly, per the setsid
    # rationale comment below.
    _UNTRUSTED_ALLOWED_KWARGS = frozenset({
        "env", "cwd", "timeout", "capture_output", "text",
        "encoding", "errors",
        "stdin", "input", "pass_fds",
        "caller_label",
        "audit", "audit_verbose", "audit_run_dir", "audit_required",
        "observe", "exclude_tmp_baseline",
        "tool_paths",
        "profile",
        # PATH-divergence gate opt-out. Allowed through because it is
        # a CORRECTNESS declaration, not an isolation control: the
        # alternatively-resolved binary still runs under the full
        # untrusted contract. Default False — an untrusted run whose
        # bare command would resolve to a different binary inside the
        # sandbox than in the caller's environment is refused with the
        # named remedy (tool_paths= / absolute path) unless the caller
        # states divergence is intended.
        "allow_path_divergence",
        # Anti-fingerprint persona: STRENGTHENS the untrusted
        # contract (identity surfaces get masked), so it passes the
        # ratchet the other rejections enforce. run_untrusted always
        # has target|output, which guarantees the mount-ns backend
        # the persona needs on any host where untrusted runs at all
        # (the fresh-procfs contract refuses the rest).
        "sanitise_host_fingerprint", "require_sanitisation",
        "cpu_count",
    })
    rejected = set(kwargs.keys()) - _UNTRUSTED_ALLOWED_KWARGS
    if rejected:
        msg = (
            f"run_untrusted() does not accept {sorted(rejected)} — "
            f"isolation policy (network, writable_paths, namespace "
            f"controls) is fixed. Use sandbox() directly for varied "
            f"policy."
        )
        raise TypeError(msg)
    # profile= is a ratchet, not a free choice: only the default
    # ('full') or the stronger fail-closed 'strict' may pass through.
    # Anything weaker (none, network-only, debug, target_run, frida)
    # would relax the very contract this helper exists to enforce.
    # The --sandbox CLI flag remains authoritative over this value,
    # as everywhere.
    _profile = kwargs.get("profile")
    if _profile is not None and _profile not in ("full", "strict"):
        msg = (
            f"run_untrusted() accepts only profile='strict' or 'full' "
            f"(got {_profile!r}) — weaker profiles would relax the "
            f"untrusted-execution contract. Use sandbox() directly "
            f"for varied policy."
        )
        raise TypeError(msg)
    # Default stdin to DEVNULL for untrusted code. If the parent's stdin
    # is the operator's TTY (common for interactive RAPTOR use) and the
    # sandboxed target reads stdin, the target gets a live channel to
    # the operator's keystrokes — a passive keystroke-sniffer for
    # whatever the operator types while the target is running. Callers
    # that legitimately need to pipe input (gcc -, shell scripts) can
    # explicitly pass stdin=subprocess.PIPE / input= / a file / another
    # fd — we only override the DEFAULT inherit behaviour.
    if "stdin" not in kwargs and "input" not in kwargs:
        kwargs["stdin"] = subprocess.DEVNULL
    # Detach from the parent's controlling tty. Stdin=DEVNULL above
    # plugs fd 0, but /dev/tty is a SEPARATE magic file that always
    # refers to the CONTROLLING tty — independent of stdin/stdout/
    # stderr. A child inherits its parent's session and therefore its
    # controlling tty; `open("/dev/tty", O_RDONLY)` inside a sandboxed
    # tool running under an interactive RAPTOR invocation would return
    # a readable handle to the operator's real terminal. The child
    # then polls it for keystrokes (TIOCSTI *injection* is already
    # blocked by seccomp, but READS aren't). setsid() makes the child
    # a new session leader with no controlling tty, so /dev/tty returns
    # ENXIO. Callers who actually want a controlling tty (interactive
    # gdb under /crash-analysis) must use sandbox() directly and can
    # pass start_new_session=False explicitly — this helper refuses
    # the kwarg outright (allowlist above), so setsid is unconditional.
    kwargs["start_new_session"] = True
    # macOS has no private mount view: unless excluded, Seatbelt seeds
    # host-shared /private/tmp into the write exceptions (and, under
    # restrict_reads, the read allowlist), so same-UID cross-run temp
    # artifacts are writable and a /tmp-resident target is mutable —
    # the class the Linux private-scratch posture closes. Default the
    # untrusted contract to the per-run scratch posture (the spawn
    # layer steers TMPDIR into {output}/.tmp); callers may override
    # explicitly.
    if sys.platform == "darwin" and "exclude_tmp_baseline" not in kwargs:
        kwargs["exclude_tmp_baseline"] = True
    # fd 1/2 pass-through: the stdin/setsid defences above plug fd 0
    # and /dev/tty, but when the caller doesn't capture, the child
    # inherits the operator's fd 1/2 with whatever access mode the
    # PARENT opened them — and read rights ride the descriptor past
    # every path-based layer. Two readable shapes exist:
    #   * a PTY slave is opened O_RDWR, which setsid() does NOT
    #     revoke — a target that read()s its OWN stdout/stderr taps
    #     the operator's keystrokes;
    #   * a non-tty O_RDWR descriptor (regular file opened rw, a
    #     socket, an rw FIFO) hands the child read access to content
    #     the sandbox policy never granted.
    # Hand the child a WRITE-ONLY reopen instead (output identical;
    # reads fail EBADF). ttys reopen via ttyname; other reopenable
    # objects (regular files, FIFOs) via the fd's /proc//dev magic
    # link with the original O_APPEND preserved. Sockets have no
    # write-only reopen — plug with DEVNULL and tell the operator to
    # capture instead (discarding output is strictly safer than
    # granting a read channel to the operator's socket peer).
    # Write-only pass-throughs (the normal shell-redirect shape) are
    # untouched.
    _wo_fds: list = []
    if not kwargs.get("capture_output"):
        import fcntl as _fcntl
        import stat as _stat
        for _name, _fd in (("stdout", 1), ("stderr", 2)):
            if _name in kwargs:
                continue
            try:
                _is_tty = os.isatty(_fd)
                if not _is_tty:
                    _mode = os.fstat(_fd).st_mode
                    try:
                        _acc = _fcntl.fcntl(
                            _fd, _fcntl.F_GETFL) & os.O_ACCMODE
                    except OSError:
                        _acc = os.O_RDWR  # unknown → treat as readable
                    if _acc == os.O_WRONLY:
                        continue  # not readable — safe to inherit
                    if _stat.S_ISSOCK(_mode):
                        logger.warning(
                            "run_untrusted: %s is a readable socket "
                            "descriptor — plugging with /dev/null "
                            "(no write-only reopen exists for "
                            "sockets). Pass capture_output=True or "
                            "an explicit %s= pipe to keep the "
                            "output.", _name, _name,
                        )
                        kwargs[_name] = subprocess.DEVNULL
                        continue
                    _flags = os.O_WRONLY | os.O_NOCTTY
                    try:
                        if _fcntl.fcntl(_fd, _fcntl.F_GETFL) \
                                & os.O_APPEND:
                            _flags |= os.O_APPEND
                    except OSError:
                        pass
                    _wfd_opt = _reopen_write_only(_fd, _flags)
                    if _wfd_opt is None:
                        logger.warning(
                            "run_untrusted: %s has no verified "
                            "write-only reopen on this platform — "
                            "plugging with /dev/null. Pass "
                            "capture_output=True or an explicit "
                            "%s= pipe to keep the output.",
                            _name, _name,
                        )
                        kwargs[_name] = subprocess.DEVNULL
                        continue
                    _wfd = _wfd_opt
                    if _stat.S_ISREG(_mode) and not (
                            _flags & os.O_APPEND):
                        # A fresh open starts at offset 0; carry the
                        # inherited stream position so the child
                        # appends after prior parent output instead
                        # of clobbering it.
                        try:
                            os.lseek(_wfd,
                                     os.lseek(_fd, 0, os.SEEK_CUR),
                                     os.SEEK_SET)
                        except OSError:
                            pass
                else:
                    _wfd = os.open(os.ttyname(_fd),
                                   os.O_WRONLY | os.O_NOCTTY)
            except OSError as _tty_exc:
                # Fail CLOSED like the socket / no-reopen branches
                # above: inheriting the descriptor here would hand the
                # untrusted child the readable handle (an O_RDWR pty
                # slave taps the operator's keystrokes) that this whole
                # block exists to revoke. Discarding output is strictly
                # safer than granting the read channel.
                logger.warning(
                    "run_untrusted: could not reopen the %s "
                    "descriptor write-only for the child (%s) — "
                    "plugging with /dev/null (the inherited "
                    "descriptor may be readable). Pass "
                    "capture_output=True or an explicit %s= pipe to "
                    "keep the output.",
                    _name, _tty_exc, _name,
                )
                kwargs[_name] = subprocess.DEVNULL
                continue
            kwargs[_name] = _wfd
            _wo_fds.append(_wfd)
    # Waived-contract degradations warn per call at the dispatch site
    # that actually delivers the reduced lane (the consented-degrade
    # branch of run()'s containment-floor check).
    try:
        return run(cmd, block_network=True, target=target, output=output,
                   limits=limits,
                   restrict_reads=restrict_reads,
                   readable_paths=readable_paths,
                   writable_paths=writable_paths,
                   fake_home=fake_home,
                   omit_proc_reads=_degraded_no_pidns,
                   strict_env=True,
                   strip_trust_markers=True,
                   _untrusted_workload=True,
                   # Untrusted contract: the fresh-procfs mount is
                   # mandatory (host-procfs visibility exposes the
                   # spawn chain's pre-strip environ image) unless the
                   # operator explicitly accepted the degraded posture
                   # (same truthiness idiom as the entry gate).
                   require_fresh_procfs=untrusted_fresh_procfs_required(),
                   **kwargs)
    finally:
        for _wfd in _wo_fds:
            try:
                os.close(_wfd)
            except OSError:
                pass


def run_untrusted_networked(
    cmd: list[str],
    *,
    target: str | None = None,
    output: str | None = None,
    proxy_hosts: list,
    limits: dict | None = None,
    restrict_reads: bool = True,
    readable_paths: list | None = None,
    writable_paths: list | None = None,
    fake_home: bool = False,
    keep_trust_markers: bool = False,
    loopback_unix_bridges: dict | None = None,
    **kwargs,
) -> subprocess.CompletedProcess:
    """Variant of :func:`run_untrusted` that allows hostname-allowlisted
    HTTPS egress instead of full network block.

    Use case: an LLM-driven sub-agent or tool that must reach a known
    upstream API (e.g. ``api.anthropic.com``) but is otherwise treated
    as adversarial — Claude Code dispatches, future LLM-callers that
    need network. ``run_untrusted()``'s namespace-level network block
    makes those calls impossible; ad-hoc :func:`sandbox()` callers
    forget to set ``restrict_reads=True`` and lose credential isolation
    on Landlock-only hosts (Ubuntu 24.04+ default — see
    ``core/security/THREAT_MODEL.md`` I2-(a)).

    This helper enforces the safe defaults for that case:

      * ``restrict_reads=True`` — kernel-level read allowlist; $HOME
        is denied. Callers that need extra paths pass
        ``readable_paths=[...]``.
      * ``fake_home=False`` — Claude Code reads ``~/.claude.json`` and
        is incompatible with HOME-redirection; callers with no such
        constraint can override.
      * ``use_egress_proxy=True`` + ``proxy_hosts=[...]`` — egress
        proxy with hostname allowlist (the only network this child can
        reach is the listed hosts on port 443).
      * ``allowed_tcp_ports=[443]`` — only HTTPS to the proxy.
      * ``proxy_allowed_ports=[443]`` — the proxy's own lane refuses
        CONNECTs to any other destination port, making the
        hosts-on-443 contract real at the enforcement point.
      * ``block_network=False`` — must be False so the proxy is
        reachable from inside the sandbox.

    Mirrors :func:`run_untrusted`'s stdin / start_new_session
    defaults — DEVNULL stdin, setsid — and its trust-marker hygiene
    (``CLAUDECODE`` / ``_RAPTOR_TRUSTED`` stripped from the child
    env) for the same reasons.

    ``keep_trust_markers=True`` opts OUT of that strip for RAPTOR's
    own Claude Code skill dispatches (``core.orchestration.
    skill_dispatch``): the spawned CLI is RAPTOR's trusted binary
    operating on the same operator-approved run — its whole job is to
    drive ``libexec/`` helpers whose preamble refuses callers without
    a marker — and the dispatch is already gated by cc-trust and the
    rule-of-two before it reaches this helper. The markers only pass
    through when the PARENT actually holds them (an untrusted parent
    has nothing to propagate). NEVER set this for commands derived
    from target-repo content; ``run_untrusted`` deliberately has no
    such opt-out.

    ``loopback_unix_bridges`` — mapping of ``{port: unix_socket_path}``
    relayed INSIDE the child's empty network namespace: the child
    reaches ``127.0.0.1:<port>`` and the pre-Landlock relay forwards
    the bytes to the named Unix socket on the host (same mechanism as
    the egress-proxy bridge). Used by credential-proxy CLI children to
    reach the LLM dispatcher without holding provider credentials.
    Netns-tier only: on hosts where the netns tier cannot engage the
    sandbox raises ``SandboxSetupError`` rather than running the child
    without its bridged service (fail closed). When set, the sandbox's
    proxy env carries ``NO_PROXY=127.0.0.1,localhost`` so bridged
    loopback traffic goes direct instead of dying at the CONNECT
    proxy's loopback rejection.

    Callers: Claude Code sub-agent dispatch (packages/llm_analysis/
    cc_dispatch.py, core/orchestration/agentic_passes.py,
    core/audit/validate.py), git network operations
    (core/git/clone.py), the BigQuery query child
    (libexec/raptor-bq-query → core/forensics/bq_query.py), and other
    hostname-allowlisted egress consumers; see THREAT_MODEL.md.
    """
    if not (target or output):
        msg = (
            "run_untrusted_networked() requires at least one non-empty of "
            "target= or output= so Landlock actually engages."
        )
        raise ValueError(msg)
    if not proxy_hosts:
        msg = (
            "run_untrusted_networked() requires proxy_hosts=[...] — "
            "the egress allowlist is mandatory; callers wanting unrestricted "
            "network should use sandbox() directly."
        )
        raise ValueError(msg)
    # Same degraded-host handling as run_untrusted: fail closed, and
    # under the operator override warn per call + withdraw the /proc
    # read grant.
    _degraded_no_pidns = _require_userns_or_optin(
        "run_untrusted_networked", restrict_reads,
    )
    # start_new_session refused for the same reason as run_untrusted:
    # setsid detachment is contract, not preference (see the rationale
    # there).
    _NETWORKED_ALLOWED_KWARGS = frozenset({
        "env", "cwd", "timeout", "capture_output", "text",
        "encoding", "errors",
        "stdin", "input", "pass_fds",
        "caller_label",
        "audit", "audit_verbose", "audit_run_dir", "audit_required",
        "observe", "exclude_tmp_baseline",
        "tool_paths",
    })
    rejected = set(kwargs.keys()) - _NETWORKED_ALLOWED_KWARGS
    if rejected:
        msg = (
            f"run_untrusted_networked() does not accept {sorted(rejected)} — "
            f"network and isolation policy is fixed to egress-proxy-only. "
            f"Use sandbox() directly for varied policy."
        )
        raise TypeError(msg)
    if "stdin" not in kwargs and "input" not in kwargs:
        kwargs["stdin"] = subprocess.DEVNULL
    kwargs["start_new_session"] = True
    if keep_trust_markers:
        # Tells run()'s target-env staging that this child is
        # RAPTOR's own trusted dispatch — every lane execs the target
        # directly, and the sanctioned kwarg is the only way the
        # markers survive the default strip.
        base_env = kwargs.get("env")
        if base_env is None:
            from core.config import RaptorConfig
            base_env = RaptorConfig.get_safe_env()
        kwargs["env"] = dict(base_env)
        kwargs["keep_trust_markers_for_dispatch"] = True
    # Waived-contract degradations warn per call at the dispatch site
    # that actually delivers the reduced lane (the consented-degrade
    # branch of run()'s containment-floor check).
    return run(
        cmd,
        block_network=False,
        target=target, output=output,
        limits=limits,
        restrict_reads=restrict_reads,
        readable_paths=readable_paths,
        writable_paths=writable_paths,
        fake_home=fake_home,
        use_egress_proxy=True,
        require_proxy_netns=True,
        proxy_hosts=list(proxy_hosts),
        # The docstring contract is "the listed hosts on port 443".
        # allowed_tcp_ports is consumed by the LOCAL pin (and replaced
        # by the lane port on the TCP tier); the proxy-side lane port
        # allowlist is what actually bounds the DESTINATION port of a
        # CONNECT — without it any 1-65535 port on an allowlisted
        # host was reachable.
        allowed_tcp_ports=[443],
        proxy_allowed_ports=[443],
        omit_proc_reads=_degraded_no_pidns,
        strict_env=True,
        strip_trust_markers=not keep_trust_markers,
        _untrusted_workload=True,
        # Same untrusted contract as run_untrusted(): mandatory
        # fresh-procfs mount unless the operator accepted the
        # degraded posture. Applies to the keep-trust dispatch lane
        # too — dispatch children are trusted, but the pid-ns/procfs
        # posture is about what the SANDBOXED TREE can read, and the
        # dispatch tree runs target-influenced tools.
        require_fresh_procfs=untrusted_fresh_procfs_required(),
        loopback_unix_bridges=loopback_unix_bridges,
        **kwargs,
    )
