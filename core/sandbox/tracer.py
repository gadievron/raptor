"""Ptrace tracer subprocess for `--audit` mode.

Spawned by the sandbox parent when audit mode is engaged. Attaches via
PTRACE_SEIZE to the sandboxed child, listens for SECCOMP_RET_TRACE
events (set up by core/sandbox/seccomp.py's audit_mode filter), reads
the offending syscall via PTRACE_GETREGSET, and writes a structured
JSONL denial record directly to the run's
`<run_dir>/.sandbox-denials.jsonl` file (POSIX O_APPEND atomicity —
same trick `core.sandbox.summary.record_denial` uses).

Why a separate process rather than a thread inside RAPTOR:
- ptrace + multi-threaded parents fight for signal delivery: SIGCHLD
  for the traced child, signals to the tracer thread, and ordinary
  RAPTOR signal handling all collide. A dedicated tracer process
  decouples the signal landscape entirely.
- Tracer crash doesn't take down the whole RAPTOR run.
- Cleaner lifecycle isolation — sandbox parent can wait on the
  tracer's exit independently of its own work.

Architecture:
- Sandbox parent forks the target child AND this tracer.
- Child waits in a SIGSTOP'd state (set up by _spawn.py via a sync
  pipe — the child blocks on a read until the parent writes the
  "go" byte).
- This tracer process attaches via PTRACE_SEIZE, sets options,
  signals "ready" to the parent.
- Parent unblocks the child.
- Tracer enters event loop until child exits.

x86_64 + aarch64. Register-read code uses PTRACE_GETREGSET / NT_PRSTATUS;
new arches are added by appending to _ARCH_INFO (one syscall table
per arch + one register-layout entry).

**Yama scope 1 constraint (commit-4 hazard).** This tracer attaches
to a target via PTRACE_SEIZE. Yama scope 1 (the default on Ubuntu /
Debian / Fedora) only permits tracing one's own descendants — siblings
are forbidden. So commit-4 spawn integration must EITHER:
  (a) make the tracer fork the target itself (target is a descendant
      of the tracer process), OR
  (b) have the target call prctl(PR_SET_PTRACER, tracer_pid) before
      exec, declaring the tracer as an authorised tracer of this
      specific target.
The tracer code itself works for either relationship; callers of
`trace()` are responsible for setting up the Yama-permissible
arrangement.

**Tracer-death contract (commit-4 hazard).** If the tracer process
dies while the target is mid-trace, all tracees are immediately
SIGKILL'd by the kernel (PTRACE_O_EXITKILL is set on attach). This
is different from b1 (egress proxy crash → sandbox continues without
proxy). Commit-4 spawn integration must monitor the tracer's health
so the operator gets a clear "audit infrastructure failed" message
rather than mysterious SIGKILLs in the target's output.

**Audit mode is observable to traced code (anti-debug surface).**
Code running inside an audited sandbox can detect that it's being
traced — `/proc/self/status` exposes `TracerPid: <our pid>`, and
the typical ptrace-detection idioms (`ptrace(PTRACE_TRACEME, ...)`
self-test, syscall timing measurement, `/proc/self/syscall` reads)
all work normally. Hiding this would require process-namespace
games or an eBPF /proc rewriter — both out of scope.

This is acceptable for RAPTOR's threat model: audit mode is for
operator workflows (gcc/make/python builds, claude sub-agents)
that don't try to detect or evade observation. RAPTOR is NOT a
malware-analysis sandbox; if that use case ever lands, the
anti-anti-debug story is a separate engineering effort (PID-ns
isolation, syscall timing normalization, /proc lying, etc.) — not
a tweak to this tracer.

Invocation:
    python -m core.sandbox.tracer <child_pid> <run_dir> [<sync_fd> [<config_path>]]

The sync_fd is an optional file descriptor inherited from the parent
on which we write a single byte once attach + setoptions have
succeeded. Used by _spawn.py to coordinate the "tracer is ready,
unblock the child" handshake. When omitted, no handshake is performed.

The config_path is an optional path to a JSON file containing audit-
mode filter configuration (writable_paths, read_allowlist,
allowed_tcp_ports, verbose flag). When omitted, the tracer runs in
unfiltered (verbose) mode — every traced syscall produces a record.

Required when omitted: nothing (testing path).
Required when present: pid + run_dir + sync_fd + config_path
positional ordering. Both ends — _spawn.py constructs argv, this
module parses it — must agree on positional ordering. See the
TestTracerArgvContract structural test.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import json
import logging
import os
import platform
import signal
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import audit_budget

logger = logging.getLogger(__name__)

# ----- ptrace request constants (see <sys/ptrace.h>) -----
_PTRACE_CONT = 7
_PTRACE_DETACH = 17
_PTRACE_SETOPTIONS = 0x4200
_PTRACE_GETEVENTMSG = 0x4201
_PTRACE_GETREGSET = 0x4204
_PTRACE_SEIZE = 0x4206
_PTRACE_INTERRUPT = 0x4207

# ptrace options
_PTRACE_O_TRACEFORK = 0x00000002
_PTRACE_O_TRACEVFORK = 0x00000004
_PTRACE_O_TRACECLONE = 0x00000008
_PTRACE_O_TRACEEXIT = 0x00000040
_PTRACE_O_TRACESECCOMP = 0x00000080
# EXITKILL: when tracer exits, kernel SIGKILLs all tracees immediately.
# Without it, surviving tracees would SIGSYS-die on their next traced
# syscall (kernel default action for SCMP_ACT_TRACE with no tracer
# attached) — same end result but slower and noisier. EXITKILL gives
# clean predictable teardown.
_PTRACE_O_EXITKILL = 0x00100000

# regset types (see <sys/uio.h> / <linux/elf.h>)
_NT_PRSTATUS = 1

# ptrace event codes (in upper bits of waitpid status)
_PTRACE_EVENT_FORK = 1
_PTRACE_EVENT_VFORK = 2
_PTRACE_EVENT_CLONE = 3
_PTRACE_EVENT_EXIT = 6
_PTRACE_EVENT_SECCOMP = 7
# Set of "child created" events all handled identically: get new PID,
# add to traced set, continue both parent and (when its SIGSTOP arrives)
# new child.
_NEW_TRACEE_EVENTS = frozenset((
    _PTRACE_EVENT_FORK, _PTRACE_EVENT_VFORK, _PTRACE_EVENT_CLONE,
))

# Per-record cap moved to core.sandbox.audit_budget.AuditBudget so
# the macOS seatbelt LogStreamer and Linux ptrace tracer share one
# budget mechanism. See audit_budget.DEFAULT_GLOBAL_CAP for the
# default ceiling and AuditBudget for the token-bucket / per-cat /
# per-PID / sampling refinements.

# JSONL file lives in the run dir. Same name as record_denial uses so
# both writers append to the same aggregation target.
_DENIALS_FILENAME = ".sandbox-denials.jsonl"


# ----- Architecture-specific syscall ABI -----
#
# Each supported arch contributes a row to _ARCH_INFO with:
#   user_regs_size      bytes returned by PTRACE_GETREGSET(NT_PRSTATUS)
#   syscall_nr_offset   byte offset of the syscall number register
#   arg_offsets         6 byte offsets for args 0..5 in syscall ABI order
#   syscall_table       int → name map for the syscalls we care about
#
# x86_64 ABI: syscall nr in orig_rax (preserved across syscall), args
# in rdi/rsi/rdx/r10/r8/r9 (Linux ABI; differs from C calling
# convention which uses rcx in slot 4).
#
# aarch64 ABI: syscall nr in x8, args in x0-x5. user_regs_struct is
# {regs[31], sp, pc, pstate} = 34 * 8 = 272 bytes; x_N is at offset N*8.
#
# Unsupported archs (riscv64, loongarch64, s390x, armv7l, etc.) are
# detected at startup and cause the tracer to bail with exit code 2.
# The sandbox parent observes that and degrades audit mode for the
# tracer-dependent layers (b2/b3) the same way it does for ptrace-
# blocked environments — b1 (network) is unaffected.

_ARCH = platform.machine()


# x86_64 syscall numbers (subset). Sourced from
# arch/x86/entry/syscalls/syscall_64.tbl in the Linux source.
_X86_64_SYSCALL_NAMES = {
    # File-path syscalls (b3)
    2: "open",
    257: "openat",
    437: "openat2",          # Linux 5.6+, used by glibc/io_uring
    # Network syscall (b3)
    42: "connect",
    # Existing seccomp blocklist (b2)
    101: "ptrace",
    250: "keyctl",
    248: "add_key",
    249: "request_key",
    321: "bpf",
    323: "userfaultfd",
    298: "perf_event_open",
    310: "process_vm_readv",
    311: "process_vm_writev",
    425: "io_uring_setup",
    426: "io_uring_enter",
    427: "io_uring_register",
    438: "pidfd_getfd",
    312: "kcmp",
    304: "open_by_handle_at",
    303: "name_to_handle_at",
    41: "socket",
    16: "ioctl",
}

# aarch64 syscall numbers. Sourced from
# include/uapi/asm-generic/unistd.h in the Linux source. NOTE: aarch64
# does NOT have a separate `open` syscall — only `openat` exists, so
# entry 2 is omitted. b3 path-coverage on aarch64 relies on openat
# alone (which is what every modern userspace uses anyway).
_AARCH64_SYSCALL_NAMES = {
    # File-path syscalls (b3)
    56: "openat",
    437: "openat2",          # Linux 5.6+, same number on x86_64+aarch64
    # Network syscall (b3)
    203: "connect",
    # Existing seccomp blocklist (b2)
    117: "ptrace",
    219: "keyctl",
    217: "add_key",
    218: "request_key",
    280: "bpf",
    282: "userfaultfd",
    241: "perf_event_open",
    270: "process_vm_readv",
    271: "process_vm_writev",
    425: "io_uring_setup",
    426: "io_uring_enter",
    427: "io_uring_register",
    438: "pidfd_getfd",
    272: "kcmp",
    265: "open_by_handle_at",
    264: "name_to_handle_at",
    198: "socket",
    29: "ioctl",
}

_ARCH_INFO = {
    "x86_64": {
        # 27 * 8 bytes — see arch/x86/include/uapi/asm/ptrace.h
        "user_regs_size": 216,
        # orig_rax (preserves syscall nr across the syscall)
        "syscall_nr_offset": 120,
        # rdi, rsi, rdx, r10, r8, r9 — Linux x86_64 syscall ABI
        "arg_offsets": (112, 104, 96, 56, 72, 64),
        "syscall_table": _X86_64_SYSCALL_NAMES,
    },
    "aarch64": {
        # 34 * 8 bytes — {regs[31], sp, pc, pstate}
        "user_regs_size": 272,
        # x8 = regs[8] = offset 8 * 8 = 64
        "syscall_nr_offset": 64,
        # x0..x5 = regs[0..5] at offsets 0, 8, 16, 24, 32, 40
        "arg_offsets": (0, 8, 16, 24, 32, 40),
        "syscall_table": _AARCH64_SYSCALL_NAMES,
    },
}


def _is_supported_arch() -> bool:
    """True iff the tracer can run on this CPU architecture.

    Currently x86_64 and aarch64 — matches the production-deployment
    intersection of Landlock and mount-ns sandbox support. Other archs
    (riscv64, loongarch64, s390x, armv7l, ppc64le) are cheap to add:
    one row in _ARCH_INFO + one syscall-number table. Defer until
    asked for.
    """
    return _ARCH in _ARCH_INFO


def _arch_info() -> Optional[dict]:
    """Return the active arch's info dict, or None if unsupported."""
    return _ARCH_INFO.get(_ARCH)




# ----- Type mapping: syscall name → denial type for sandbox-summary.json -----
#
# The tracer writes records to the same JSONL the summary aggregates,
# so the `type` field has to match the existing taxonomy. b1 uses
# "network", existing seccomp blocklist hits use "seccomp", and b3
# path syscalls are "write" (paths the child tried to open/write).
_NAME_TO_TYPE = {
    "open": "write", "openat": "write", "openat2": "write",
    "connect": "network",
    "socket": "seccomp",   # AF_UNIX/PACKET/NETLINK family check still seccomp-style
    "ioctl": "seccomp",
    # Everything else in the blocklist → "seccomp"
}

# Syscalls that signal an operator-visibility gap — the call itself is
# logged, but follow-on operations issued via the same mechanism are
# invisible to seccomp tracing. Used by the tracer to enrich the audit
# record with a `note:` field so operators understand "we saw the
# setup, but we cannot see what came next".
_VISIBILITY_GAP_NOTES = {
    "io_uring_setup": (
        "io_uring SQEs (read/write/openat/connect submitted via the ring "
        "after this setup) bypass the syscall layer and are NOT captured "
        "by this audit. Treat any subsequent file/network activity by "
        "the same process as untraceable."
    ),
}


def _denial_type(syscall_name: str) -> str:
    """Map a syscall name to the sandbox-summary denial type taxonomy."""
    return _NAME_TO_TYPE.get(syscall_name, "seccomp")


# ----- libc / ptrace ctypes plumbing -----

# Sentinel for "we tried, libc isn't usable." Distinct from None
# (=unprobed) so a cached failure doesn't trigger repeated find_library
# calls. find_library("c") is moderately slow (filesystem walks); on a
# system without libc the re-probes would add up across many ptrace
# helper calls.
_LIBC_UNAVAILABLE = object()
_libc: object = None


def _get_libc() -> Optional[ctypes.CDLL]:
    """Resolve libc via find_library, lazy and cached.

    Caches BOTH success (the CDLL handle) AND failure (the
    _LIBC_UNAVAILABLE sentinel) so the cost of the find_library +
    CDLL load is paid at most once per process.
    """
    global _libc
    if _libc is _LIBC_UNAVAILABLE:
        return None
    if _libc is not None:
        return _libc  # type: ignore[return-value]
    name = ctypes.util.find_library("c")
    if name is None:
        _libc = _LIBC_UNAVAILABLE
        return None
    try:
        lib = ctypes.CDLL(name, use_errno=True)
    except OSError:
        _libc = _LIBC_UNAVAILABLE
        return None
    if not hasattr(lib, "ptrace"):
        _libc = _LIBC_UNAVAILABLE
        return None
    lib.ptrace.restype = ctypes.c_long
    lib.ptrace.argtypes = [
        ctypes.c_long, ctypes.c_int,
        ctypes.c_void_p, ctypes.c_void_p,
    ]
    _libc = lib
    return _libc


class _Iovec(ctypes.Structure):
    """`struct iovec` from <sys/uio.h>."""
    _fields_ = [
        ("iov_base", ctypes.c_void_p),
        ("iov_len", ctypes.c_size_t),
    ]


def _ptrace_seize(pid: int) -> bool:
    """PTRACE_SEIZE the target. Returns True on success.

    SEIZE attaches without stopping the target — unlike PTRACE_ATTACH
    which sends SIGSTOP. The data arg is the options bitfield (set
    atomically with the attach).

    Options set:
    - TRACESECCOMP: get PTRACE_EVENT_SECCOMP for SCMP_ACT_TRACE syscalls
    - TRACEEXIT: get PTRACE_EVENT_EXIT just before tracee dies (clean
      tear-down opportunity)
    - TRACEFORK / TRACEVFORK / TRACECLONE: auto-attach to new processes
      AND new threads created by the tracee. Without these, a
      `make -j 8` build would only audit the make process and miss
      every gcc subprocess — most of the actual work goes dark.
      The kernel auto-stops the new child with SIGSTOP, which the
      tracer's wait loop sees and continues.
    """
    libc = _get_libc()
    if libc is None:
        return False
    options = (
        _PTRACE_O_TRACESECCOMP | _PTRACE_O_TRACEEXIT
        | _PTRACE_O_TRACEFORK | _PTRACE_O_TRACEVFORK
        | _PTRACE_O_TRACECLONE
        # EXITKILL: tracer crash → kernel SIGKILLs all tracees
        # immediately, rather than letting them SIGSYS-die on their
        # next traced syscall. Cleaner failure mode for K7.
        | _PTRACE_O_EXITKILL
    )
    ctypes.set_errno(0)
    rc = libc.ptrace(_PTRACE_SEIZE, pid, None,
                     ctypes.c_void_p(options))
    err = ctypes.get_errno()
    if rc != 0:
        logger.error(f"tracer: PTRACE_SEIZE({pid}) failed errno={err}")
        return False
    return True


def _read_tracee_string(pid: int, addr: int,
                        max_bytes: int = 4096) -> Optional[str]:
    """Read a NUL-terminated string from the tracee's address space.

    Used to dereference path pointers in syscall args (open's arg0,
    openat's arg1, etc.). Without this, audit records show only the
    raw uint64 pointer value — useless for operators trying to see
    WHICH path the workload tried.

    Uses process_vm_readv(2) — single syscall, no per-byte ptrace
    overhead. Available since Linux 3.2; same permissions as ptrace
    (already satisfied since we're attached).

    Returns the decoded string (UTF-8 with errors='replace' so
    operator-visible records are always printable; raw filename
    bytes get smuggled in via surrogateescape elsewhere). Returns
    None on read failure or when addr is null.

    Bounds:
    - max_bytes: PATH_MAX-equivalent (4096). Prevents a malicious
      tracee from making us read arbitrary amounts of memory by
      passing a never-NUL'd buffer. Caller wishing to read sockaddr
      structures or other bounded blobs can pass a smaller cap.
    - Returns the bytes-up-to-first-NUL, or all of max_bytes if no
      NUL is found.
    """
    if addr == 0:
        return None
    libc = _get_libc()
    if libc is None:
        return None
    if not hasattr(libc, "process_vm_readv"):
        return None
    libc.process_vm_readv.restype = ctypes.c_ssize_t
    libc.process_vm_readv.argtypes = [
        ctypes.c_int,                     # pid
        ctypes.POINTER(_Iovec),           # local_iov
        ctypes.c_ulong,                   # liovcnt
        ctypes.POINTER(_Iovec),           # remote_iov
        ctypes.c_ulong,                   # riovcnt
        ctypes.c_ulong,                   # flags
    ]

    buf = (ctypes.c_uint8 * max_bytes)()
    local = _Iovec(iov_base=ctypes.cast(buf, ctypes.c_void_p).value,
                   iov_len=max_bytes)
    remote = _Iovec(iov_base=addr, iov_len=max_bytes)
    ctypes.set_errno(0)
    n = libc.process_vm_readv(
        pid,
        ctypes.byref(local), 1,
        ctypes.byref(remote), 1,
        0,
    )
    if n <= 0:
        # Common cases: page boundary issue (the tracee's path may
        # be at the end of a page and reading max_bytes crosses an
        # unmapped page); EFAULT, EPERM. Caller falls back to None
        # which the record-writer renders as a missing path.
        return None
    raw = bytes(buf[:n])
    nul = raw.find(b"\0")
    if nul >= 0:
        raw = raw[:nul]
    try:
        return raw.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        # Defence-in-depth — utf-8 errors='replace' shouldn't ever
        # raise, but a future Python change could. Return repr to
        # keep the audit record useful.
        return repr(raw)


def _read_tracee_bytes(pid: int, addr: int, n_bytes: int) -> Optional[bytes]:
    """Read exactly ``n_bytes`` from the tracee's address space.

    Used for fixed-size struct reads where _read_tracee_string's
    NUL-termination semantics don't apply (e.g. ``struct open_how``
    for openat2 audit). Same process_vm_readv plumbing as the string
    reader; returns None on read failure or null addr.

    Bounds: caller-supplied; this helper does not enforce a max.
    Use the smallest size needed (open_how flags = 8 bytes).
    """
    if addr == 0 or n_bytes <= 0:
        return None
    libc = _get_libc()
    if libc is None or not hasattr(libc, "process_vm_readv"):
        return None
    libc.process_vm_readv.restype = ctypes.c_ssize_t
    libc.process_vm_readv.argtypes = [
        ctypes.c_int,
        ctypes.POINTER(_Iovec),
        ctypes.c_ulong,
        ctypes.POINTER(_Iovec),
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    buf = (ctypes.c_uint8 * n_bytes)()
    local = _Iovec(iov_base=ctypes.cast(buf, ctypes.c_void_p).value,
                   iov_len=n_bytes)
    remote = _Iovec(iov_base=addr, iov_len=n_bytes)
    ctypes.set_errno(0)
    n = libc.process_vm_readv(
        pid,
        ctypes.byref(local), 1,
        ctypes.byref(remote), 1,
        0,
    )
    if n <= 0:
        return None
    return bytes(buf[:n])


def _path_arg_index(syscall_name: str) -> Optional[int]:
    """Return the index of the path argument for a given syscall, or
    None if the syscall has no path argument worth dereferencing.

    The mapping is per-syscall ABI: for `open(path, flags, mode)` it's
    arg 0; for `openat(dirfd, path, flags, mode)` it's arg 1; etc.
    Used by the trace loop to know which arg to feed into
    _read_tracee_string.

    `connect(sockfd, sockaddr, addrlen)` is a sockaddr STRUCT — handled
    by `_decode_sockaddr` below, not by string dereference.
    """
    if syscall_name in ("open",):
        return 0
    if syscall_name in ("openat", "openat2"):
        # openat:  (dirfd, pathname, flags, mode)            → idx 1
        # openat2: (dirfd, pathname, struct open_how *, ...) → idx 1
        # Same path-arg position; differs in how flags/mode are
        # encoded, which we don't decode in audit (would-be-blocked
        # determination only needs dirfd + path).
        return 1
    return None


# AT_FDCWD constant (from <fcntl.h>). Value is the same on every Linux
# arch we support — relative-path syscalls with this dirfd are
# resolved against the tracee's current working directory.
_AT_FDCWD = -100


def _resolve_tracee_path(pid: int, path: str, dirfd: int) -> str:
    """Resolve a path argument to an absolute path AS THE TRACEE
    would see it.

    Rules (matching openat(2) semantics):
    - Absolute path: return as-is, lexically normalised.
    - Relative path + AT_FDCWD: resolve via ``/proc/<pid>/cwd``.
    - Relative path + real dirfd: resolve via ``/proc/<pid>/fd/<dirfd>``
      (which symlinks to the directory the fd refers to).

    Failure modes (return the input path unchanged): /proc not
    available, readlink permission denied, stale fd. Better to log
    the un-resolved path than to drop the record entirely — the
    operator can still tell what the target tried even if we couldn't
    pin down where.

    Multi-thread caveat: ``/proc/<pid>/cwd`` is per-task on Linux.
    We use the tid (the tracee's pid as kernel-level thread id) so
    multi-threaded targets that unshare CLONE_FS get correct results.
    The same path also works for single-threaded targets where
    pid == tid for the main thread.

    TOCTOU caveat: by the time we readlink /proc/<pid>/cwd, the
    target may have chdir'd. Best-effort. For audit purposes this is
    acceptable — if the target races us, we under-report rather
    than over-report (same audit-mode promise as elsewhere).

    Mount-namespace assumption: this resolution gives the path as
    the TRACER (parent ns) sees it, not as the tracee's mount-ns
    sees it. This is correct for RAPTOR's standard sandbox layout
    where _spawn.py bind-mounts target/output at their ORIGINAL
    absolute paths inside the pivoted root — the tracee's
    `/etc/hostname` resolves to the same dentry as the parent's
    `/etc/hostname` because /etc is bind-mounted at /etc. Custom
    mount-ns layouts that move target paths to different mount
    points inside the sandbox WOULD see audit-allowlist mismatch.
    Document and constrain at the spawn layer if such layouts are
    ever introduced.
    """
    # Absolute path: just normalize.
    if path.startswith("/"):
        return os.path.normpath(path)

    # Relative path: resolve via /proc.
    if dirfd == _AT_FDCWD:
        proc_link = f"/proc/{pid}/cwd"
    elif dirfd >= 0:
        proc_link = f"/proc/{pid}/fd/{dirfd}"
    else:
        # Negative dirfd that's NOT AT_FDCWD: the tracee passed a bad
        # value; the kernel will EBADF the syscall. Return path as-is.
        return path

    try:
        base = os.readlink(proc_link)
    except OSError:
        # /proc not readable, fd stale, or other races. Best-effort.
        return path

    # Concatenate + normalise. os.path.join handles trailing slashes;
    # os.path.normpath collapses // and resolves .. lexically.
    return os.path.normpath(os.path.join(base, path))


# open(2) flag bits (from <fcntl.h>) — the same on x86_64 / aarch64.
# Only the bits we care about for write-intent detection.
_O_WRONLY = 0o0000001
_O_RDWR = 0o0000002
_O_CREAT = 0o0000100
_O_TRUNC = 0o0001000
_O_APPEND = 0o0002000


def _is_write_intent(flags: int) -> bool:
    """True if `flags` indicate the open is for writing.

    Used by the audit allowlist filter — write opens face a stricter
    Landlock check than read opens, so they're more likely to be
    blocked. We use the broader writable_paths set for write opens
    and the broader readable allowlist for read-only opens.
    """
    if flags & (_O_WRONLY | _O_RDWR):
        return True
    if flags & (_O_CREAT | _O_TRUNC | _O_APPEND):
        # CREAT/TRUNC/APPEND imply write even with O_RDONLY=0.
        return True
    return False


def _path_in_allowlist(path: str, allowlist: list) -> bool:
    """True if `path` is under any prefix in `allowlist`.

    Prefix match with directory boundary: ``/a/b`` matches
    ``/a`` but ``/abc`` does NOT match ``/a`` (the boundary char
    must be a separator or end-of-string).

    Allowlist must contain ABSOLUTE, NORMALISED paths — caller
    ensures this at config-build time.
    """
    for prefix in allowlist:
        if not prefix:
            continue
        if path == prefix:
            return True
        # Boundary: prefix + "/" matches the prefix's children but
        # not "/abc" matching "/a".
        if path.startswith(prefix.rstrip("/") + "/"):
            return True
    return False


def _decode_sockaddr(pid: int, addr: int,
                    addrlen: int) -> Optional[tuple]:
    """Decode a sockaddr struct from the tracee's address space.

    Returns (family_name, port, ip_str) for AF_INET / AF_INET6, or
    None for unsupported families / read failures. The tracer logs
    only the AF_INET/AF_INET6 cases; other families
    (AF_UNIX/PACKET/NETLINK) are blocked by the seccomp blocklist
    on the family argument of socket(), so a connect() to one would
    only happen for an already-open fd of that family — relevant
    audit signal sits at the socket() rule level, not connect().
    """
    if addr == 0 or addrlen < 4:
        return None
    libc = _get_libc()
    if libc is None or not hasattr(libc, "process_vm_readv"):
        return None
    # Cap addrlen to the largest we'll decode — sockaddr_in6 is
    # 28 bytes. Don't trust caller-supplied addrlen above that.
    n_to_read = min(addrlen, 28)
    buf = (ctypes.c_uint8 * n_to_read)()
    local = _Iovec(iov_base=ctypes.cast(buf, ctypes.c_void_p).value,
                   iov_len=n_to_read)
    remote = _Iovec(iov_base=addr, iov_len=n_to_read)
    ctypes.set_errno(0)
    got = libc.process_vm_readv(
        pid,
        ctypes.byref(local), 1,
        ctypes.byref(remote), 1,
        0,
    )
    if got < 4:
        return None
    raw = bytes(buf[:got])
    # sa_family is the first 2 bytes (sa_family_t = uint16_t),
    # native byte order on Linux.
    family = struct.unpack_from("<H", raw, 0)[0]
    AF_INET = 2
    AF_INET6 = 10
    if family == AF_INET and got >= 8:
        # struct sockaddr_in: family (2), port (2 BE), addr (4)
        port = struct.unpack_from(">H", raw, 2)[0]
        ip = ".".join(str(b) for b in raw[4:8])
        return ("AF_INET", port, ip)
    if family == AF_INET6 and got >= 28:
        # struct sockaddr_in6: family (2), port (2 BE), flowinfo (4),
        # addr (16), scope_id (4)
        port = struct.unpack_from(">H", raw, 2)[0]
        addr_bytes = raw[8:24]
        # Format as colon-separated 16-bit groups.
        groups = [
            f"{(addr_bytes[i] << 8) | addr_bytes[i+1]:x}"
            for i in range(0, 16, 2)
        ]
        ip = ":".join(groups)
        return ("AF_INET6", port, ip)
    return None


def _ptrace_get_event_msg(pid: int) -> Optional[int]:
    """PTRACE_GETEVENTMSG — fetch the event-specific data from the
    most recent ptrace event on `pid`.

    For PTRACE_EVENT_FORK / VFORK / CLONE, the event message is the
    PID of the newly-created child. Used to track new tracees that
    the kernel auto-attaches via TRACEFORK / TRACEVFORK / TRACECLONE.
    """
    libc = _get_libc()
    if libc is None:
        return None
    msg = ctypes.c_long(0)
    ctypes.set_errno(0)
    rc = libc.ptrace(_PTRACE_GETEVENTMSG, pid, None, ctypes.byref(msg))
    if rc != 0:
        logger.debug(f"tracer: PTRACE_GETEVENTMSG({pid}) failed")
        return None
    return msg.value


def _read_regs(pid: int, arch_info: dict) -> Optional[bytes]:
    """Read the target's user_regs_struct via PTRACE_GETREGSET.

    Returns the raw bytes (caller decodes via _decode_syscall + arch_info)
    or None on error. Uses GETREGSET (not the older GETREGS) because
    GETREGSET is the portable interface — the same call works on x86_64
    and aarch64 with different iovec sizes.

    arch_info is REQUIRED (no implicit fallback to _arch_info()) so
    callers can't silently get whatever the module-level _ARCH happens
    to resolve to. The trace loop passes it explicitly after the
    arch-supported check.
    """
    libc = _get_libc()
    if libc is None:
        return None
    size = arch_info["user_regs_size"]
    buf = (ctypes.c_uint8 * size)()
    iov = _Iovec(iov_base=ctypes.cast(buf, ctypes.c_void_p).value,
                 iov_len=size)
    ctypes.set_errno(0)
    rc = libc.ptrace(_PTRACE_GETREGSET, pid,
                     ctypes.c_void_p(_NT_PRSTATUS),
                     ctypes.byref(iov))
    err = ctypes.get_errno()
    if rc != 0:
        logger.debug(f"tracer: PTRACE_GETREGSET({pid}) failed errno={err}")
        return None
    # The kernel updates iov.iov_len to the actual bytes written. If
    # smaller than expected, decoding via fixed offsets would read
    # past the filled region into our zero-init buffer and silently
    # produce false records (e.g. syscall 0 = read on x86_64). Refuse
    # the partial read.
    if iov.iov_len < size:
        logger.debug(
            f"tracer: PTRACE_GETREGSET({pid}) returned partial regset "
            f"({iov.iov_len} of {size} bytes); refusing decode"
        )
        return None
    return bytes(buf)


def _decode_syscall(regs: bytes, arch_info: dict) -> tuple:
    """Extract (syscall_number, [arg0..arg5]) from a user_regs_struct.

    Arch-agnostic: uses the offsets in arch_info to locate the syscall
    nr and the six syscall-ABI args. All values are uint64. Caller
    interprets pointer args by reading the tracee's memory (deferred
    to a later commit; first version logs raw values).
    """
    nr_off = arch_info["syscall_nr_offset"]
    nr = struct.unpack_from("<Q", regs, nr_off)[0]
    args = [
        struct.unpack_from("<Q", regs, off)[0]
        for off in arch_info["arg_offsets"]
    ]
    return nr, args


def _ptrace_cont(pid: int, signal_num: int = 0) -> bool:
    """PTRACE_CONT — resume the traced process.

    Logs a debug message on failure so a developer chasing "why is
    my target stuck?" can find the issue. Common failure causes:
    tracee already dead (ESRCH — usually benign, the next waitpid
    catches the exit) or the tracee isn't in a ptrace-stop state
    (rare; suggests state corruption).
    """
    libc = _get_libc()
    if libc is None:
        return False
    ctypes.set_errno(0)
    rc = libc.ptrace(_PTRACE_CONT, pid, None,
                     ctypes.c_void_p(signal_num))
    if rc != 0:
        err = ctypes.get_errno()
        logger.debug(f"tracer: PTRACE_CONT({pid}, sig={signal_num}) "
                     f"failed errno={err}")
        return False
    return True


def _ptrace_interrupt(pid: int) -> bool:
    """PTRACE_INTERRUPT — bring a SEIZE'd tracee to a group-stop.

    Required before PTRACE_DETACH on a tracee that hasn't naturally
    hit a stop event (e.g., one we SEIZE'd but didn't drive to a
    SECCOMP/SYSCALL stop). Without an intervening stop, DETACH
    returns ESRCH.
    """
    libc = _get_libc()
    if libc is None:
        return False
    ctypes.set_errno(0)
    rc = libc.ptrace(_PTRACE_INTERRUPT, pid, None, None)
    return rc == 0


def _ptrace_detach(pid: int) -> bool:
    """PTRACE_DETACH — release the traced process cleanly.

    Caller must ensure the tracee is in a ptrace-stop state. For a
    SEIZE'd-but-not-driven tracee that means PTRACE_INTERRUPT followed
    by waitpid for the stop, THEN DETACH.
    """
    libc = _get_libc()
    if libc is None:
        return False
    ctypes.set_errno(0)
    rc = libc.ptrace(_PTRACE_DETACH, pid, None, None)
    return rc == 0


# ----- JSONL record writer -----

def _write_record(run_dir: Path, syscall_name: str, syscall_nr: int,
                  args: list, target_pid: int,
                  path: Optional[str] = None) -> bool:
    """Append one denial record to the run's JSONL file.

    Returns True on successful write, False otherwise. Open/write/close
    per record so each line lands atomically (POSIX guarantees writes
    < PIPE_BUF on O_APPEND fds are atomic against concurrent writers).
    Same file/format as core.sandbox.summary.record_denial uses, so the
    summary aggregator picks both up transparently.

    `path`: if provided (non-None), included in the record AND used
    to construct a more useful `cmd` string ("openat /etc/hostname"
    rather than the generic "traced PID N"). The tracer's main loop
    derefs path pointers via process_vm_readv when the syscall has
    one (open/openat); for syscalls without a path argument (or when
    the deref failed), this stays None.
    """
    # Sanitisation pipeline:
    # 1. escape_nonprintable: paths come from the tracee's address
    #    space and may contain control characters (intentional or
    #    not). JSON encoding with ensure_ascii=True escapes control
    #    chars to \uXXXX in the on-disk file, BUT operators using
    #    `jq -r '.path'` would re-decode the escape and feed raw
    #    bytes to their terminal — terminal-injection risk. Escape
    #    BEFORE JSON encoding so the post-decode string is still
    #    escape-safe text.
    # 2. redact_url_secrets_only: scrub URL-embedded credentials.
    #    We use the URL-only variant (not redact_secrets) because
    #    paths are STRUCTURED — Bearer/Basic header patterns
    #    generate false positives on filenames containing those
    #    substrings (e.g., `/tmp/Bearer abc...` is a filename,
    #    not an auth header).
    #
    # Both applied to BOTH path and cmd because cmd embeds path.
    # Lazy imports — keeps tracer subprocess startup cheap.
    try:
        from core.security.log_sanitisation import escape_nonprintable
        from core.security.redaction import redact_url_secrets_only
        if path is not None:
            path = escape_nonprintable(path)
            path = redact_url_secrets_only(path)
        # Re-build cmd AFTER sanitising path so cmd inherits the
        # safe path string (rather than re-sanitising the cmd as
        # a whole, which would double-escape the syscall_name).
        if path is not None:
            cmd = f"<sandbox audit: {syscall_name} {path}>"
        else:
            cmd = f"<sandbox audit: traced PID {target_pid}>"
        # cmd's syscall_name and PID come from RAPTOR-controlled
        # internals (no attacker influence) so we don't need to
        # escape cmd separately.
    except Exception:
        # Best-effort. If sanitisation is broken / unimportable, log
        # the raw values rather than dropping the record. Reconstruct
        # cmd from raw values too — _read_tracee_string already
        # decoded with errors='replace' so utf-8-invalid bytes are
        # �, JSON-safe.
        logger.debug("sanitisation failed in tracer", exc_info=True)
        if path is not None:
            cmd = f"<sandbox audit: {syscall_name} {path}>"
        else:
            cmd = f"<sandbox audit: traced PID {target_pid}>"
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "cmd": cmd,
        "returncode": 0,
        "type": _denial_type(syscall_name),
        "audit": True,
        "syscall": syscall_name,
        "syscall_nr": syscall_nr,
        # Always include the traced PID as a separate field —
        # operators correlate audit records to subprocesses, and the
        # cmd string omits PID when path is present (cmd shows the
        # path instead, more useful for the common case).
        "target_pid": target_pid,
        # All six syscall ABI args. Useful args differ per syscall —
        # openat puts the path at arg1, connect's addr is at arg1,
        # socket's family is at arg0, etc. Logging all six lets
        # consumers extract the right one per syscall without per-
        # syscall decoding logic in the tracer. Pointer args appear
        # as raw uint64 values; for path syscalls (open/openat) we
        # dereference via process_vm_readv and surface the resolved
        # string in the `path` field — operators get something
        # actionable instead of a raw pointer.
        "args": list(args),
    }
    if path is not None:
        record["path"] = path
    # Visibility-gap enrichment: some syscalls signal that follow-on
    # operations are invisible to seccomp tracing (notably io_uring,
    # which submits I/O via SQEs in shared memory after this setup
    # call). Surface that explicitly so an operator reading the
    # record knows the audit signal is incomplete for this process.
    note = _VISIBILITY_GAP_NOTES.get(syscall_name)
    if note:
        record["note"] = note
    try:
        line = json.dumps(record, ensure_ascii=True) + "\n"
        # NOTE: deliberately a different name from the `path` parameter
        # (which is the syscall's path arg). Earlier versions of this
        # function shadowed `path` with the file path and worked by
        # accident — would confuse a reader and break if record-build
        # ever moved below this line.
        jsonl_path = run_dir / _DENIALS_FILENAME
        jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        # O_NOFOLLOW + O_APPEND match summary.record_denial exactly.
        fd = os.open(
            str(jsonl_path),
            os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(line)
        return True
    except OSError as e:
        logger.debug(f"tracer: write_record failed: {e}")
        return False


def _write_record_dict(run_dir: Path, record: dict) -> bool:
    """Append a pre-built record dict to the run's JSONL file.

    Used for AuditBudget markers and the end-of-run summary —
    structures that don't fit the syscall-shaped _write_record
    signature. Same O_NOFOLLOW + O_APPEND atomicity as
    _write_record and core.sandbox.summary.record_denial.
    """
    try:
        line = json.dumps(record, ensure_ascii=True, default=str) + "\n"
        jsonl_path = run_dir / _DENIALS_FILENAME
        jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(
            str(jsonl_path),
            os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(line)
        return True
    except OSError as e:
        logger.debug(f"tracer: write_record_dict failed: {e}")
        return False


# ----- Event loop -----

def _signal_ready(sync_fd: Optional[int]) -> None:
    """Signal the parent that we're attached and ready to trace.

    The parent writes a "go" byte on the OTHER end of this pipe to
    unblock the child once we acknowledge. Optional — when sync_fd is
    None we skip the handshake (testing path).

    Closes sync_fd via try/finally so the fd doesn't leak if os.write
    raises (disk full, broken pipe, etc.). Without finally, an exception
    in os.write would skip os.close and leave a leaked fd in the tracer
    process for its remaining lifetime.
    """
    if sync_fd is None:
        return
    try:
        try:
            os.write(sync_fd, b"\x01")
        except OSError as e:
            logger.debug(f"tracer: sync write failed: {e}")
    finally:
        try:
            os.close(sync_fd)
        except OSError:
            pass


def trace(target_pid: int, run_dir: Path,
          sync_fd: Optional[int] = None,
          audit_filter: Optional[dict] = None) -> int:
    """Main tracer loop. Returns process exit code.

    1. PTRACE_SEIZE the target with TRACESECCOMP + TRACEEXIT +
       TRACEFORK + TRACEVFORK + TRACECLONE options.
    2. Signal "ready" to the parent (if sync_fd given).
    3. Loop on waitpid(-1) for ptrace events from any tracee:
       - PTRACE_EVENT_SECCOMP: read regs, identify syscall, write
         JSONL record, PTRACE_CONT to resume.
       - PTRACE_EVENT_FORK / VFORK / CLONE: extract new tracee PID
         via PTRACE_GETEVENTMSG, add to traced set. Kernel has
         auto-attached the new child; its SIGSTOP arrives on a
         subsequent waitpid.
       - PTRACE_EVENT_EXIT: tracee is exiting, let it.
       - SIGSTOP from auto-attached new tracee: continue without
         forwarding (else it stays stopped).
       - Other group stops / signals: pass-through via PTRACE_CONT.
    4. Loop terminates when the traced set is empty (all processes
       and threads under the original target have exited).

    Multi-process / multi-thread coverage: TRACEFORK + TRACEVFORK +
    TRACECLONE auto-attach the kernel-side, so a `make -j N` build
    produces audit records for every gcc subprocess, a multi-threaded
    target produces records for every thread, etc. Without these
    options, audit signal would be limited to the root process and
    most of the actual workload would go dark.

    SIGSTOP semantics caveat (O1, very rare): if something external
    sends SIGSTOP to a traced target, the tracer's PTRACE_EVENT_STOP
    handler resumes the target rather than leaving it group-stopped.
    Operators who SIGSTOP a sandbox child to debug would see the
    target keep running. Negligible workflow impact (RAPTOR users
    don't typically SIGSTOP children); preserved here as a known
    behavioural difference vs no-audit mode.

    Exit codes (contract for commit-4 spawn integration):
      0  clean exit (all tracees exited normally or by signal)
      2  unsupported architecture (tracer can't run on this CPU)
      3  PTRACE_SEIZE failed (Yama scope, perms, dead target, etc.)
      4  waitpid failed unexpectedly
    """
    arch_info = _arch_info()
    if arch_info is None:
        logger.error(
            f"tracer: unsupported arch {_ARCH} "
            f"(supported: {sorted(_ARCH_INFO)})"
        )
        return 2

    if not _ptrace_seize(target_pid):
        return 3

    _signal_ready(sync_fd)

    syscall_table = arch_info["syscall_table"]
    # Audit budget — shared with macOS seatbelt LogStreamer via
    # core.sandbox.audit_budget. Token-bucket + per-category +
    # per-PID sub-caps + 1-in-N post-cap sampling; markers and
    # final summary appear in the JSONL alongside data records
    # (see audit_budget.AuditBudget docstring). The budget is read
    # from `audit_filter["audit_budget"]` (passed in via the
    # filter-config JSON _spawn.py wrote at parent-side spawn time)
    # because the tracer subprocess has its own fresh state module
    # and can't inherit the parent's --audit-budget override
    # through state._cli_sandbox_audit_budget directly.
    from . import audit_budget as _audit_budget_mod
    _budget_override = (
        audit_filter.get("audit_budget") if audit_filter else None
    )
    budget = _audit_budget_mod.AuditBudget(global_cap=_budget_override)

    # Set of currently-traced PIDs. Starts with the original target;
    # grows when fork/vfork/clone events fire (kernel auto-attaches
    # the new child); shrinks when each tracee exits. Loop terminates
    # when the set is empty.
    traced = {target_pid}

    while traced:
        try:
            # waitpid(-1) catches events from ANY tracee — required for
            # multi-process / multi-thread audit. ptrace re-parents
            # tracees to the tracer for waitpid purposes, so this works
            # even though target_pid wasn't biologically forked by us.
            #
            # Assumption: this tracer process has NO biological children
            # of its own. That's true today (the tracer is invoked as
            # a Python -m subprocess that doesn't fork). If a future
            # change adds bio children to the tracer, waitpid(-1) would
            # also pick up their events and this loop would treat them
            # as tracees (`traced.discard(wpid)` would be silent no-op
            # for the unrelated bio child, but the SIGSTOP-based add
            # in the dispatch below would mistakenly add them to the
            # traced set). Adjust the wait pattern (e.g. switch to
            # waitid with P_PID per known tracee) if that day comes.
            wpid, status = os.waitpid(-1, 0)
        except InterruptedError:
            continue
        except ChildProcessError:
            # All tracees gone — clean exit.
            return 0
        except OSError as e:
            logger.error(f"tracer: waitpid failed: {e}")
            return 4

        _handle_waitpid_event(
            wpid, status, traced, target_pid, arch_info,
            run_dir, budget,
            audit_filter=audit_filter,
        )

    # End-of-run summary record so the sandbox-summary aggregator
    # has total/dropped counts even when the run didn't hit any cap.
    try:
        _write_record_dict(run_dir, budget.summary_record())
    except OSError:
        # Best-effort. Don't crash the tracer on a transient FS
        # error during summary append.
        logger.debug("tracer: summary record append failed",
                     exc_info=True)
    return 0


def _handle_waitpid_event(
    wpid: int, status: int,
    traced: set, target_pid: int,
    arch_info: dict, run_dir: Path,
    budget: "audit_budget.AuditBudget",
    *,
    audit_filter: Optional[dict] = None,
    # Injection points so tests can substitute synthetic helpers
    # without forking real children. Defaults are the production
    # implementations; tests pass mocks.
    ptrace_cont=None,
    read_regs=None,
    decode_syscall=None,
    read_tracee_string=None,
    get_event_msg=None,
    write_record=None,
    resolve_path=None,
    decode_sockaddr=None,
) -> None:
    """Handle one waitpid event.

    Mutates `traced` in place: removes exited PIDs, adds new tracees
    on FORK/VFORK/CLONE events. The wait loop calls this once per
    waitpid result; refactored out as a separate function purely so
    tests can construct synthetic status values + mock the ptrace
    helpers, exercising every branch without needing real ptrace.

    Status encoding (Linux waitpid):
    - exited: WIFEXITED, low byte 0
    - signalled: WIFSIGNALED, low byte = signal
    - stopped: WIFSTOPPED, status = (event << 16) | (sig << 8) | 0x7f
      - event=0 means a plain signal-stop (e.g., SIGSTOP from new tracee)
      - event=PTRACE_EVENT_SECCOMP|FORK|VFORK|CLONE|EXIT → ptrace event
    """
    # Resolve helpers — default to module-level production impls.
    if ptrace_cont is None:
        ptrace_cont = _ptrace_cont
    if read_regs is None:
        read_regs = _read_regs
    if decode_syscall is None:
        decode_syscall = _decode_syscall
    if read_tracee_string is None:
        read_tracee_string = _read_tracee_string
    if get_event_msg is None:
        get_event_msg = _ptrace_get_event_msg
    if write_record is None:
        write_record = _write_record
    if resolve_path is None:
        resolve_path = _resolve_tracee_path
    if decode_sockaddr is None:
        decode_sockaddr = _decode_sockaddr

    syscall_table = arch_info["syscall_table"]

    if os.WIFEXITED(status) or os.WIFSIGNALED(status):
        # This tracee exited; remove from set. Loop ends when
        # `traced` is empty (all tracees gone).
        traced.discard(wpid)
        return

    if not os.WIFSTOPPED(status):
        return

    sig = os.WSTOPSIG(status)
    # Ptrace event codes are encoded in the upper 16 bits of status
    # when SIGTRAP is the stop signal: status >> 16 yields the event.
    event = (status >> 16) & 0xffff

    if event == _PTRACE_EVENT_SECCOMP:
        # SECCOMP_RET_TRACE event: read syscall, decide whether to log.
        # Budget enforcement is moved INSIDE this branch and runs
        # AFTER syscall identification — we need the syscall name to
        # evaluate per-category caps. The legacy fixed-cap approach
        # has been replaced by core.sandbox.audit_budget.AuditBudget
        # (token-bucket + per-category + per-PID + sampling).
        regs = read_regs(wpid, arch_info)
        if regs is not None:
            nr, args = decode_syscall(regs, arch_info)
            name = syscall_table.get(nr, f"unknown_{nr}")

            # Default: log every event (audit-verbose / no filter).
            # The filter logic below short-circuits to drop legitimate
            # events when audit_filter is configured for filtered
            # mode (i.e., the `audit` profile).
            should_log = True
            path = None
            path_idx = _path_arg_index(name)
            if path_idx is not None:
                path = read_tracee_string(wpid, args[path_idx])

            if audit_filter is not None and not audit_filter.get("verbose"):
                # Filtered mode: drop events that would have been
                # ALLOWED under enforcement. The signal then becomes
                # "what would have been blocked" — the operator's
                # actual question.
                if name in ("openat", "open", "openat2"):
                    # Resolve path argument to absolute, check
                    # against Landlock-equivalent allowlist.
                    if path is not None:
                        # openat / openat2 dirfd lives at args[0];
                        # for open(), there is no dirfd, treat as
                        # AT_FDCWD.
                        dirfd = (args[0] if name in ("openat", "openat2")
                                 else _AT_FDCWD)
                        # Treat dirfd as signed — kernel passes
                        # AT_FDCWD as -100 which arrives as a
                        # very large unsigned in our regs.
                        if dirfd > 0x7fffffffffffffff:
                            dirfd = dirfd - (1 << 64)
                        abs_path = resolve_path(wpid, path, dirfd)
                        # Flag location differs by syscall:
                        #   open(path, flags, mode)            → args[1]
                        #   openat(dirfd, path, flags, mode)   → args[2]
                        #   openat2(dirfd, path, &how, size)   → deref args[2]
                        #     `struct open_how` { __u64 flags; __u64 mode;
                        #                        __u64 resolve; }
                        #     so flags = first 8 bytes of *args[2].
                        if name == "openat2":
                            # Best-effort struct read. If process_vm_readv
                            # fails (bad pointer, stale memory), default
                            # to write_intent=True so we don't silently
                            # miss writes — over-reporting reads is
                            # acceptable, missing writes is not.
                            how_bytes = _read_tracee_bytes(wpid, args[2], 8)
                            if how_bytes is not None and len(how_bytes) == 8:
                                import struct as _struct
                                flags = _struct.unpack("<Q", how_bytes)[0]
                            else:
                                flags = _O_WRONLY  # safe default
                        else:
                            flags_idx = 2 if name == "openat" else 1
                            flags = args[flags_idx]
                        write_intent = _is_write_intent(flags)
                        # When read_allowlist is None, Landlock is
                        # in restrict_reads=False mode (allows all
                        # reads). Reads can never be would-blocked,
                        # so we drop them unconditionally and only
                        # filter writes against writable_paths.
                        if (not write_intent
                                and audit_filter.get("read_allowlist") is None):
                            should_log = False
                        else:
                            # .get with [] default — defensive
                            # against malformed/partial configs.
                            # Empty list → _path_in_allowlist
                            # always False → record kept.
                            allowlist = (
                                audit_filter.get("writable_paths") or []
                                if write_intent
                                else audit_filter.get("read_allowlist") or []
                            )
                            if _path_in_allowlist(abs_path, allowlist):
                                should_log = False
                            else:
                                # Useful surface form: replace
                                # `path` with the resolved
                                # absolute (relative paths in
                                # the raw record are ambiguous
                                # to operators).
                                path = abs_path
                elif name == "connect":
                    # Decode sockaddr at args[1], length at args[2].
                    # If destination port is in the allowed set,
                    # drop. Otherwise log with decoded ip:port in
                    # the path field for operator readability.
                    sock = decode_sockaddr(wpid, args[1], args[2])
                    if sock is not None:
                        family, port, ip = sock
                        allowed_ports = audit_filter.get(
                            "allowed_tcp_ports", [])
                        if port in allowed_ports:
                            should_log = False
                        else:
                            path = f"{ip}:{port} ({family})"
                # For seccomp blocklist syscalls (ptrace, bpf, etc.)
                # we don't filter — they're rare and ALWAYS
                # would-be-blocked under enforcement, so the audit
                # signal is exactly what the operator wants.

            if should_log:
                decision, marker = budget.evaluate(name, wpid)
                if marker is not None:
                    _write_record_dict(run_dir, marker)
                if decision == audit_budget.KEEP:
                    write_record(run_dir, name, nr, args, wpid,
                                 path=path)
                # First-time global-cap exhaustion: emit a one-time
                # stderr line. Restores the operator-visible cue
                # the legacy tracer printed ("hit per-run record
                # cap ..."). Per-category and per-PID drops show
                # up as in-band JSONL markers AND in audit_summary
                # at end-of-run, so they don't need stderr noise;
                # only the global cap (which truncates audit
                # entirely) gets the stderr ping.
                if budget.pop_global_cap_notice():
                    os.write(2, (
                        f"RAPTOR tracer: audit-record global cap "
                        f"({budget.global_cap}) reached; further "
                        f"events dropped (sub-caps still apply; "
                        f"sampling continues for high-volume "
                        f"categories). End-of-run audit_summary "
                        f"record has totals.\n"
                    ).encode("ascii", errors="replace"))
        # Continue regardless — audit mode allows the syscall.
        ptrace_cont(wpid, 0)
        return

    if event in _NEW_TRACEE_EVENTS:
        # fork/vfork/clone — the tracee created a new process or
        # thread. Get its PID and add to the traced set. The new
        # child has been kernel-auto-attached (PTRACE_O_TRACE*
        # options ensured this) and will hit a SIGSTOP that we'll
        # see on a subsequent waitpid; until then we just record
        # its existence.
        new_pid = get_event_msg(wpid)
        if new_pid is not None and new_pid > 0:
            traced.add(new_pid)
        ptrace_cont(wpid, 0)
        return

    if event == _PTRACE_EVENT_EXIT:
        # Tracee is about to exit; let it.
        ptrace_cont(wpid, 0)
        return

    # SIGSTOP from a newly-auto-attached tracee: kernel paused the
    # new child as part of TRACEFORK/CLONE delivery. Resume it
    # without forwarding the SIGSTOP (otherwise the child would
    # stay stopped). All other unrelated signals are passed
    # through to preserve original signal semantics.
    #
    # M1: also `traced.add(wpid)` here — defensive against the
    # FORK_EVENT-add path missing this PID (e.g. GETEVENTMSG
    # failed). Set is idempotent so a duplicate add is harmless;
    # the worst-case-without-this is the loop terminating with
    # tracees still alive, leading to SIGSYS/SIGKILL of the
    # orphaned tracee mid-workflow.
    if sig == signal.SIGSTOP and wpid != target_pid:
        traced.add(wpid)
        ptrace_cont(wpid, 0)
    else:
        ptrace_cont(wpid, sig if sig != signal.SIGTRAP else 0)
    return


def _cli_main(argv: Optional[list] = None) -> int:
    """CLI entry point:
    ``python -m core.sandbox.tracer <pid> <run_dir> [<sync_fd> [<config_path>]]``

    Validates inputs at startup so a typo in the operator's invocation
    fails fast with a clear message, rather than attaching to the
    target and discovering per-event that records can't be written.

    config_path: optional path to a JSON file containing the audit
    filter config. Required for the `audit` profile (filtered mode);
    omitted for `audit-verbose` (every traced syscall logged).
    Schema: {
        "verbose": bool,
        "writable_paths": [str, ...],   # write-intent allowlist
        "read_allowlist": [str, ...],   # read-intent allowlist
        "allowed_tcp_ports": [int, ...],
    }

    Exit codes:
      0  clean (target exited)
      1  invalid arguments (bad pid, missing/unwritable run_dir)
      2  usage error / unsupported arch (also returned by trace())
      3  PTRACE_SEIZE failed (returned by trace())
      4  waitpid failed (returned by trace())
    """
    args = argv if argv is not None else sys.argv[1:]
    if len(args) not in (2, 3, 4):
        sys.stderr.write(
            "Usage: python -m core.sandbox.tracer "
            "<pid> <run_dir> [<sync_fd> [<config_path>]]\n"
        )
        return 2
    try:
        pid = int(args[0])
        run_dir = Path(args[1])
        sync_fd = int(args[2]) if len(args) >= 3 else None
        config_path = args[3] if len(args) == 4 else None
    except ValueError:
        sys.stderr.write("error: <pid> and <sync_fd> must be integers\n")
        return 2

    # L2: reject non-positive PIDs at parse time. PID 0 means "current
    # process group" in some contexts and is a footgun; negative PIDs
    # are never valid as process targets.
    if pid <= 0:
        sys.stderr.write(f"error: <pid> must be positive (got {pid})\n")
        return 1
    if sync_fd is not None and sync_fd < 0:
        sys.stderr.write(
            f"error: <sync_fd> must be non-negative (got {sync_fd})\n"
        )
        return 1

    # L1: validate run_dir is writable BEFORE attaching to the target.
    # If we can't write, every per-event record_write would fail
    # silently; better to abort cleanly here.
    if not run_dir.is_dir():
        sys.stderr.write(f"error: {run_dir} is not a directory\n")
        return 1
    if not os.access(run_dir, os.W_OK):
        sys.stderr.write(f"error: {run_dir} is not writable by this user\n")
        return 1

    # Optional audit-filter config. If config_path was given, parse it
    # and pass to trace(); else the tracer runs in unfiltered (verbose)
    # mode by default — every traced syscall produces a record. The
    # presence/absence of config_path is the audit-mode selector at the
    # CLI layer; the spawn parent decides which profile passes which.
    audit_filter = None
    if config_path is not None:
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                audit_filter = json.load(f)
        except OSError as e:
            sys.stderr.write(
                f"error: cannot read audit config {config_path}: {e}\n"
            )
            return 1
        except ValueError as e:
            sys.stderr.write(
                f"error: invalid JSON in audit config {config_path}: {e}\n"
            )
            return 1

    return trace(pid, run_dir, sync_fd, audit_filter)


if __name__ == "__main__":
    raise SystemExit(_cli_main())
