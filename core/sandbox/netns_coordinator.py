"""Per-run coordinator for paired-process isolation in a shared netns.

Spawned as a subprocess by callers that need two sibling-sandboxed
processes to share a single isolated user-namespace + network-namespace.
Reads a JSON request from stdin describing the two commands, sets up the
shared namespaces, forks both children (each inheriting the shared
namespaces via the fork), waits for both, writes a JSON response to
stdout, exits.

Architecture rationale. The naïve substrate — two sandbox.run calls each
``setns()``-ing into a shared netns fd — has two fundamental problems on
real Linux hosts:

  1. ``setns(fd, CLONE_NEWNET)`` requires CAP_SYS_ADMIN in the user-ns
     that owns the netns. An unprivileged sandbox child doesn't have
     that, so setns silently fails and each sandbox.run creates its own
     private netns — sharing does not actually happen.

  2. To make setns work the sandbox child needs BOTH a user-ns fd and a
     net-ns fd, kept open across exec. Those fds are permission tokens —
     adversarial code in the sandbox could ``setns()`` them to re-enter
     the shared user-ns and gain caps over the shared netns.

The coordinator pattern avoids both: the two children are FORKS of the
coordinator, so they inherit the user-ns and net-ns by the kernel's normal
fork-inheritance mechanism. No setns call, no namespace fd inside the
sandbox.

Two paths for namespace setup:

  A. Direct unshare from this script. Works on hosts where the operator
     has disabled the LSM restriction
     (``kernel.apparmor_restrict_unprivileged_userns=0`` on Ubuntu, or the
     distro's equivalent). Tried first.

  B. Via the privileged launcher binary at
     ``core/sandbox/helpers/raptor-coord-launcher``. The launcher creates
     the namespaces in a brief privileged window, drops every capability,
     and execs THIS script with ``RAPTOR_COORD_FROM_LAUNCHER=1`` set. The
     script then proceeds as if it had done the unshare itself.

If both paths fail, the script writes a structured error to stdout and
exits non-zero. The caller surfaces the message to the operator.

JSON protocol — see ``core/sandbox/_netns_protocol.py``.
"""

from __future__ import annotations

import os
import sys

# The coordinator is spawned as a fresh Python interpreter by TcpAdapter
# (or via the launcher binary which execs us). RAPTOR's Python-path rule:
# never add anything to sys.path except os.environ["RAPTOR_DIR"], hard
# lookup so a missing env var fails loudly. Caller (TcpAdapter) is
# responsible for setting RAPTOR_DIR in the subprocess env.
sys.path.insert(0, os.environ["RAPTOR_DIR"])

import base64  # noqa: E402
import ctypes  # noqa: E402
import ctypes.util  # noqa: E402
import errno  # noqa: E402
import fcntl  # noqa: E402
import json  # noqa: E402
import socket  # noqa: E402
import struct  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Any, Dict, Optional  # noqa: E402

CLONE_NEWUSER = 0x10000000
CLONE_NEWNET = 0x40000000

HELPER_PATH = (
    Path(__file__).resolve().parent / "helpers" / "raptor-coord-launcher"
)


# ----------------------------------------------------------------------
# Namespace setup
# ----------------------------------------------------------------------


def _bring_lo_up() -> None:
    """SIOCSIFFLAGS to set IFF_UP on the loopback inside the current netns.
    Same kernel ABI as the C launcher; needed when we're on the direct path
    (the launcher does it itself when used)."""
    SIOCSIFFLAGS = 0x8914
    IFF_UP, IFF_LOOPBACK, IFF_RUNNING = 0x1, 0x8, 0x40
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifr = b"lo".ljust(16, b"\x00") + struct.pack(
            "h", IFF_UP | IFF_LOOPBACK | IFF_RUNNING
        )
        fcntl.ioctl(s, SIOCSIFFLAGS, ifr)
    finally:
        s.close()


def _setup_direct() -> None:
    """Try to set up shared user-ns + net-ns ourselves. Raises OSError on
    LSM rejection (typical: EPERM writing uid_map under AppArmor's
    unprivileged_userns confinement)."""
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    # Capture pre-unshare euid/egid. After unshare(CLONE_NEWUSER) we appear
    # as the overflow uid (65534) inside the new user-ns until uid_map is
    # written, and the single-line bypass write in user_namespaces(7)
    # requires "the effective UID of the writing process in the PARENT
    # user-namespace" — i.e. our pre-unshare euid.
    parent_uid = os.geteuid()
    parent_gid = os.getegid()
    if libc.unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), "unshare(NEWUSER|NEWNET)")
    with open("/proc/self/uid_map", "w", encoding="utf-8") as f:
        f.write(f"0 {parent_uid} 1\n")
    with open("/proc/self/setgroups", "w", encoding="utf-8") as f:
        f.write("deny\n")
    with open("/proc/self/gid_map", "w", encoding="utf-8") as f:
        f.write(f"0 {parent_gid} 1\n")
    _bring_lo_up()


def _setup_via_launcher_reexec() -> None:
    """Re-exec ourselves through the privileged launcher binary. The
    launcher does the namespace setup that the direct path couldn't, then
    execs us back with RAPTOR_COORD_FROM_LAUNCHER=1. This function does
    not return — execv replaces the process image."""
    if not HELPER_PATH.exists():
        _emit_error(
            "namespace_setup_failed",
            (
                "direct unshare failed AND the launcher binary is not built. "
                f"Build it: cd {HELPER_PATH.parent} && make. "
                "Then grant ONE of: AppArmor profile (Ubuntu hardened), "
                "setcap (Debian/older Ubuntu), or SELinux module (RHEL "
                "hardened) — see core/sandbox/helpers/ for templates."
            ),
        )
        sys.exit(2)
    # Avoid an infinite re-exec loop if the launcher fails to set the
    # sentinel before exec'ing us back.
    if os.environ.get("RAPTOR_COORD_REEXEC_GUARD") == "1":
        _emit_error(
            "namespace_setup_failed",
            (
                "launcher execv'd us back without "
                "RAPTOR_COORD_FROM_LAUNCHER=1 — the launcher's privileged "
                "setup did not complete. Check the launcher's stderr for "
                "the actual reason (typically an LSM block on uid_map "
                "write)."
            ),
        )
        sys.exit(2)
    # Sanitise the env we hand off to the launcher trampoline BEFORE
    # execve. Raw ``os.environ`` carries every ambient var — including
    # ANTHROPIC_API_KEY / LLM_MODEL / operator secrets that the
    # coordinator does not need and MUST NOT persist into the
    # long-lived post-launcher process. Every child spawn from that
    # process inherits the coordinator's env by default, so a leaked
    # API key here reaches every target invocation.
    #
    # Strategy: start from ``RaptorConfig.get_safe_env()`` (the
    # allowlist strips ANTHROPIC_API_KEY et al — see
    # ``core/config``'s SAFE_ENV_ALLOWLIST) then ADD BACK just the
    # RAPTOR_COORD_* sentinels the launcher looks for.
    try:
        from core.config import RaptorConfig
        env = RaptorConfig.get_safe_env()
    except Exception:  # noqa: BLE001
        # If the config import fails (dev tree without the package)
        # fall back to a hand-picked minimal env. Missing PATH would
        # break execve on many systems, so preserve it plus the
        # coord-critical sentinels.
        env = {
            k: v for k, v in os.environ.items()
            if k in ("PATH", "LANG", "LC_ALL", "HOME", "TERM")
        }
    # Preserve every RAPTOR_COORD_* sentinel the launcher shim reads.
    # This includes RAPTOR_COORD_FROM_LAUNCHER (set by the launcher on
    # re-entry) and any future coordination flags.
    for k, v in os.environ.items():
        if k.startswith("RAPTOR_COORD_"):
            env[k] = v
    env["RAPTOR_COORD_REEXEC_GUARD"] = "1"
    os.execve(
        str(HELPER_PATH),
        [str(HELPER_PATH), sys.executable, __file__],
        env,
    )


def _setup_namespaces() -> str:
    """Set up the shared user-ns + net-ns. Returns a label describing
    which path was taken ("via_launcher" or "direct_unshare"). On failure,
    writes an error response and exits.

    Path priority: launcher first when built, direct second.

    Why launcher-first: a failed direct attempt under an LSM-hardened
    host succeeds at the unshare(CLONE_NEWUSER) step (creating a new
    user-ns) and fails at the uid_map write — leaving us in the new
    user-ns and auto-confined to the global ``unprivileged_userns``
    AppArmor profile. From that confined state, execv'ing the launcher
    does NOT transition us to the launcher's named profile (LSM
    transitions are unconfined→named, not confined→named), so the
    launcher inherits the same restrictive confinement and can't do its
    privileged setup either. Net effect: trying direct first POISONS
    the fallback. Going via launcher first sidesteps this entirely.

    On hosts with no LSM restriction (e.g. operator set sysctl=0): if
    the launcher is built we still go through it (one extra exec, no
    correctness difference). If no launcher exists, direct works fine.
    """
    if os.environ.get("RAPTOR_COORD_FROM_LAUNCHER") == "1":
        # Launcher already did the setup.
        return "via_launcher"

    if HELPER_PATH.exists():
        # This call does not return — execv replaces the process image.
        _setup_via_launcher_reexec()

    # No launcher built. Try direct as the only remaining option.
    try:
        _setup_direct()
        return "direct_unshare"
    except OSError as exc:
        if exc.errno in (errno.EPERM, errno.EACCES):
            _emit_error(
                "namespace_setup_failed",
                (
                    f"direct unshare blocked by host LSM ({exc}). "
                    "Build the launcher: cd "
                    f"{HELPER_PATH.parent} && make. Then grant ONE of: "
                    "AppArmor profile (Ubuntu hardened), setcap "
                    "(Debian/older Ubuntu), or SELinux module (RHEL). "
                    "Templates in core/sandbox/helpers/."
                ),
            )
            sys.exit(2)
        _emit_error(
            "namespace_setup_failed",
            f"direct unshare unexpected error: {exc}",
        )
        sys.exit(2)


# ----------------------------------------------------------------------
# Child process management
# ----------------------------------------------------------------------


class _ChildResult:
    __slots__ = (
        "returncode", "stdout", "stderr", "wallclock_s",
        "sandbox_info", "error",
    )

    def __init__(self) -> None:
        self.returncode: Optional[int] = None
        self.stdout: bytes = b""
        self.stderr: bytes = b""
        self.wallclock_s: float = 0.0
        # sandbox_info is the dict produced by observe._interpret_result
        # — carries the sanitizer marker (from stderr ASan scan), crash
        # signal, seccomp-killed flag, etc. The witness outcome oracle
        # reads it to classify the target's execution; without it we'd
        # collapse every run to NO_OBVIOUS_EFFECT regardless of what
        # actually happened.
        self.sandbox_info: Optional[Dict[str, Any]] = None
        self.error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "returncode": self.returncode,
            "stdout_b64": base64.b64encode(self.stdout).decode("ascii"),
            "stderr_b64": base64.b64encode(self.stderr).decode("ascii"),
            "wallclock_s": self.wallclock_s,
            "sandbox_info": self.sandbox_info,
            "error": self.error,
        }


def _run_child(role: str, spec: Dict[str, Any], result: _ChildResult) -> None:
    """Run one sandbox.run command as a child of THIS process. The fork
    inside sandbox.run inherits our user-ns + net-ns, which is the
    architectural point — target and exploit land in the same netns
    without setns and without an external fd."""
    # Import inside the function so a missing import surfaces as a
    # structured error rather than a hard ImportError at module load time.
    from core.sandbox import run as sandbox_run

    cmd = spec["cmd"]
    env = spec.get("env", {})
    try:
        timeout = float(spec.get("timeout_s", 10.0))
    except (TypeError, ValueError):
        timeout = 10.0
    profile = spec.get("profile", "target_run")
    block_network = bool(spec.get("block_network", True))
    allowed_tcp_ports = spec.get("allowed_tcp_ports") or None
    restrict_reads = bool(spec.get("restrict_reads", False))
    stdin_b64 = spec.get("stdin_b64")
    stdin_bytes = base64.b64decode(stdin_b64) if stdin_b64 else None

    # Additional sandbox hardening params forwarded from the RPC so
    # the coordinator path applies the same substrate posture as the
    # stdin/argv adapters. Silently absent on legacy specs — kwargs
    # only get set when the RPC populates them.
    #
    # Narrow types at the RPC boundary: ``list(writable_paths)`` on a
    # bare string yields per-char paths (12-char path → 12 tiny
    # Landlock entries); ``dict(etc_overlay)`` on a list-of-pairs
    # silently succeeds with wrong keys. A caller typo should fail
    # loudly here rather than at Landlock-rule installation.
    target_path = spec.get("target")
    output_path = spec.get("output")
    writable_paths = spec.get("writable_paths")
    if writable_paths is not None and not isinstance(writable_paths, list):
        raise TypeError(
            f"spec['writable_paths'] must be list, got {type(writable_paths).__name__}",
        )
    readable_paths = spec.get("readable_paths")
    if readable_paths is not None and not isinstance(readable_paths, list):
        raise TypeError(
            f"spec['readable_paths'] must be list, got {type(readable_paths).__name__}",
        )
    exclude_tmp_baseline = spec.get("exclude_tmp_baseline")
    etc_overlay = spec.get("etc_overlay")
    if etc_overlay is not None and not isinstance(etc_overlay, dict):
        raise TypeError(
            f"spec['etc_overlay'] must be dict, got {type(etc_overlay).__name__}",
        )
    strict_env = spec.get("strict_env")
    env_caller_filtered = spec.get("env_caller_filtered")
    observe = spec.get("observe")

    t0 = time.monotonic()
    try:
        kwargs = dict(
            profile=profile,
            block_network=block_network,
            inherit_netns=True,
            env=env if env else None,
            capture_output=True,
            timeout=timeout,
            restrict_reads=restrict_reads,
        )
        if allowed_tcp_ports is not None:
            kwargs["allowed_tcp_ports"] = list(allowed_tcp_ports)
        if stdin_bytes is not None:
            kwargs["input"] = stdin_bytes
        # Regression pin: the coordinator RPC previously dropped these
        # hardening kwargs silently, so callers that opted a target
        # into a locked-down sandbox posture (path restrictions, etc.
        # overlay, strict env) got a baseline sandbox instead — with
        # /tmp writable and every mount default. Forward them all so
        # the coordinator path matches the direct sandbox_run posture.
        if target_path is not None:
            kwargs["target"] = target_path
        if output_path is not None:
            kwargs["output"] = output_path
        if writable_paths is not None:
            kwargs["writable_paths"] = list(writable_paths)
        if readable_paths is not None:
            kwargs["readable_paths"] = list(readable_paths)
        if exclude_tmp_baseline is not None:
            kwargs["exclude_tmp_baseline"] = bool(exclude_tmp_baseline)
        if etc_overlay is not None:
            kwargs["etc_overlay"] = dict(etc_overlay)
        if strict_env is not None:
            kwargs["strict_env"] = bool(strict_env)
        if env_caller_filtered is not None:
            kwargs["env_caller_filtered"] = bool(env_caller_filtered)
        if observe is not None:
            kwargs["observe"] = bool(observe)
        r = sandbox_run(cmd, **kwargs)
        result.returncode = r.returncode
        result.stdout = r.stdout or b""
        result.stderr = r.stderr or b""
        # sandbox_info is attached to the CompletedProcess by
        # core.sandbox.observe._interpret_result. Coerce to a plain dict
        # so json.dumps can serialise it — observe attaches a mapping
        # which may or may not be a plain dict depending on path.
        info = getattr(r, "sandbox_info", None)
        if info is not None:
            try:
                result.sandbox_info = dict(info)
            except (TypeError, ValueError):
                result.sandbox_info = None
    except Exception as exc:  # noqa: BLE001
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        result.wallclock_s = time.monotonic() - t0


def _wait_listen_port(port: int, timeout: float) -> bool:
    """Poll /proc/self/net/tcp for ``port`` in TCP_LISTEN state inside the
    coordinator's netns (which is the same shared netns target binds in,
    because target is our fork). Non-intrusive — no probe connect, so
    single-shot accept servers don't get their accept slot consumed."""
    port_hex = f"{port:04X}"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with open("/proc/self/net/tcp", "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    local = parts[1]
                    if ":" not in local:
                        continue
                    _ip, p_hex = local.rsplit(":", 1)
                    if p_hex.upper() == port_hex and parts[3] == "0A":
                        return True
        except OSError:
            pass
        time.sleep(0.02)
    return False


# ----------------------------------------------------------------------
# Output helpers
# ----------------------------------------------------------------------


def _emit_error(reason: str, message: str) -> None:
    """Write a single-line error response to stdout. Caller parses it."""
    json.dump(
        {
            "error": {"reason": reason, "message": message},
            "target": None,
            "exploit": None,
            "listen_observed": False,
        },
        sys.stdout,
    )
    sys.stdout.write("\n")
    sys.stdout.flush()


def _emit_response(response: Dict[str, Any]) -> None:
    json.dump(response, sys.stdout)
    sys.stdout.write("\n")
    sys.stdout.flush()


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------


def main() -> None:
    # Order matters: namespace setup BEFORE reading stdin. The setup may
    # execv to the launcher which re-execs this script. Stdin survives
    # the execve as the same pipe — but any bytes already read by the
    # pre-execve Python are GONE. So defer the read until we're in the
    # final incarnation (either the direct path or the post-launcher
    # path), where it executes exactly once.
    ns_path = _setup_namespaces()

    request_raw = sys.stdin.read()
    try:
        request = json.loads(request_raw)
    except json.JSONDecodeError as exc:
        _emit_error("bad_request", f"could not parse request JSON: {exc}")
        sys.exit(2)

    # Request validation. Surface protocol violations as structured
    # errors rather than letting a KeyError / ValueError / AttributeError
    # propagate as a Python traceback on stderr — the caller parses
    # stdout as JSON and a traceback there would mask the real issue.
    if not isinstance(request, dict):
        _emit_error(
            "bad_request",
            f"request must be a JSON object, got {type(request).__name__}",
        )
        sys.exit(2)
    target_spec = request.get("target")
    exploit_spec = request.get("exploit")
    if not isinstance(target_spec, dict) or not isinstance(exploit_spec, dict):
        _emit_error(
            "bad_request",
            "request must contain 'target' and 'exploit' objects",
        )
        sys.exit(2)
    try:
        wait_port = int(request.get("wait_listen_port", 0))
        wait_timeout = float(request.get("wait_listen_timeout_s", 5.0))
        target_timeout = float(target_spec.get("timeout_s", 5.0))
    except (TypeError, ValueError) as exc:
        _emit_error(
            "bad_request",
            f"numeric field in request not coercible: {exc}",
        )
        sys.exit(2)

    target_result = _ChildResult()
    exploit_result = _ChildResult()

    target_thread = threading.Thread(
        target=_run_child, args=("target", target_spec, target_result),
        daemon=True,
    )
    target_thread.start()

    listen_ok = (
        _wait_listen_port(wait_port, wait_timeout)
        if wait_port > 0 else True
    )

    _run_child("exploit", exploit_spec, exploit_result)

    # Give target a brief window to finish post-exploit (e.g. flush an
    # ASan report after a crash). It will usually exit on its own once
    # the exploit closes its socket. ``daemon=True`` on the target
    # thread means it dies at interpreter exit if the join times out —
    # but sandbox.run inside the thread holds its own timeout that
    # SIGKILLs the child subprocess before we get here, so the window
    # for a leaked subprocess is bounded by ``timeout_s`` + 1.0s.
    target_thread.join(timeout=target_timeout + 1.0)

    _emit_response({
        "target": target_result.to_dict(),
        "exploit": exploit_result.to_dict(),
        "listen_observed": listen_ok,
        "namespace_path": ns_path,
        "error": None,
    })


if __name__ == "__main__":
    main()
