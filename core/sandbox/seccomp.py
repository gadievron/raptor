"""Seccomp-bpf syscall-level filter.

Layered on top of Landlock to close escape vectors Landlock doesn't cover:
AF_UNIX / AF_PACKET / AF_NETLINK socket() (docker.sock escape, raw packets),
ptrace (cross-process attacks on same-UID host processes when ptrace_scope=0),
keyctl/bpf/user_faultfd/perf_event_open (weird-corner syscalls historically
used in container escapes).

Blocklist not allowlist: RAPTOR runs arbitrary target builds, so default-
deny would require per-tool syscall profiles. Blocklist has near-zero
breakage risk because we only block things gcc/make/python/etc. don't use.

Default action: ALLOW. Blocked syscalls return EPERM (not SIGSYS / kill)
so processes fail gracefully — connect() returns -1, caller can handle it,
and _check_blocked can suggest --sandbox debug / network-only if needed.
"""

import ctypes
import ctypes.util
import logging
import os

from . import state

logger = logging.getLogger(__name__)

# libseccomp action constants (from include/seccomp.h)
_SCMP_ACT_ALLOW = 0x7fff0000
_SCMP_ACT_KILL_PROCESS = 0x80000000

# Filter attribute numbers (from include/seccomp.h, enum scmp_filter_attr).
_SCMP_FLTATR_ACT_BADARCH = 2


def _SCMP_ACT_ERRNO(errno_val):
    return 0x00050000 | (errno_val & 0x0000ffff)


def _SCMP_ACT_TRACE(msg_num: int = 0):
    """Construct the SCMP_ACT_TRACE action value.

    When a syscall hits a TRACE-action rule, the kernel pauses the tracee
    and notifies the attached ptrace tracer with PTRACE_EVENT_SECCOMP
    (event code 7). The tracer reads the offending syscall via
    PTRACE_GETREGSET and decides what to do (in audit mode: log + resume).

    REQUIRES a tracer to be attached when the rule fires. If no tracer
    is attached, the kernel default action is to kill the process with
    SIGSYS. Used by `--audit` mode (orthogonal flag, composes with any
    enforcement profile that has a seccomp filter) where
    core/sandbox/tracer.py is the attached tracer; never use TRACE
    without ensuring a tracer is wired in for the target's lifetime.
    """
    return 0x7ff00000 | (msg_num & 0x0000ffff)


# Additional syscalls traced under audit mode (b3: filesystem path
# audit + connect-attempt audit). These are NOT in the blocklist —
# under enforcement they're allowed normally; under audit_mode they
# get the TRACE action so the tracer logs each call and the operator
# sees what files / connect targets the workload uses.
_AUDIT_EXTRA_TRACE_SYSCALLS = (
    "open", "openat", "openat2",  # b3: filesystem path coverage
    "connect",                    # b3: outbound network attempts
)


# libseccomp comparison ops (scmp_compare)
_SCMP_CMP_EQ = 4         # equal to: arg == datum_a
_SCMP_CMP_MASKED_EQ = 7  # masked equal: (arg & datum_a) == datum_b

# Linux extracts the socket type from the (type | flags) arg with this
# mask (linux/socket.h SOCK_TYPE_MASK). Without it, exact-equality rules
# on `arg=1` for `SOCK_DGRAM` (2) miss the very common
# `SOCK_DGRAM | SOCK_CLOEXEC` (524290 = 0x80002) and
# `SOCK_DGRAM | SOCK_NONBLOCK` (2050 = 0x802) variants. Same for
# SOCK_RAW (3). Use SCMP_CMP_MASKED_EQ with this mask so the rule matches
# regardless of the flag bits.
_SOCK_TYPE_MASK = 0xf


class _ScmpArgCmp(ctypes.Structure):
    """Matches `struct scmp_arg_cmp` from seccomp.h."""
    _fields_ = [
        ("arg", ctypes.c_uint),
        ("op", ctypes.c_int),
        ("datum_a", ctypes.c_uint64),
        ("datum_b", ctypes.c_uint64),
    ]


# Syscalls that are DEFINITELY blocked in every filter mode (even `debug`)
# because they have no legitimate use in a target build or a debugger and are
# well-known container-escape primitives. Names are resolved per-architecture
# at install time via seccomp_syscall_resolve_name().
_SECCOMP_BLOCK_ALWAYS = (
    "keyctl", "add_key", "request_key",     # kernel keyring
    "bpf",                                    # eBPF program loading
    "userfaultfd",                            # userspace page-fault handler
    "perf_event_open",                        # perf subsystem
    "process_vm_readv", "process_vm_writev",  # cross-process memory access
    # io_uring bypasses Landlock on kernels 5.13-6.2 — Landlock hooks don't
    # cover io_uring opcodes for file ops, so a sandboxed process can use
    # io_uring to read/write/unlink files Landlock would otherwise block.
    # Kernel 6.3+ integrated Landlock+io_uring, but we block unconditionally
    # because tools we run (gcc, make, python, semgrep, etc.) don't use
    # io_uring — zero breakage risk, closes the bypass on older kernels.
    "io_uring_setup", "io_uring_enter", "io_uring_register",
    # pidfd_getfd extracts a file descriptor from another process. In our
    # PID namespace only our own process tree is visible, so targets are
    # self or ancestors — not useful for cross-sandbox attacks today. But
    # blocking it costs nothing and forecloses an easy escalation route if
    # future RAPTOR layouts share a PID namespace across sandboxes.
    "pidfd_getfd",
    # Defense-in-depth adds — Docker's default profile blocks all of these.
    # None is a verified bypass in our current config; each forecloses a
    # category we'd otherwise be relying on user-ns capability semantics
    # to block.
    # kcmp: compare two processes' kernel resources (fd table, vm, sighand,
    # io context). Within our PID ns only our own tree is visible, but the
    # syscall is a side-channel and info-leak primitive with no legitimate
    # use for build tools.
    "kcmp",
    # open_by_handle_at / name_to_handle_at: open a file by a filesystem
    # handle rather than a path. Bypasses path-based checks. The open side
    # requires CAP_DAC_READ_SEARCH in init_user_ns (not granted in
    # user-ns), so not exploitable today — but Landlock is path-based, so
    # any future relaxation of the capability check would route around it.
    "open_by_handle_at", "name_to_handle_at",
)
# NOTE on namespace/mount syscalls (unshare, setns, mount, umount2,
# pivot_root, chroot): we do NOT block these at the seccomp layer. Our
# own sandbox bootstrap uses the `unshare` CLI, which calls unshare(2)
# AFTER seccomp is installed in preexec_fn — blocking the syscall kills
# our own unshare exec. Reinstalling seccomp after unshare would need a
# C wrapper (unshare → prctl(PR_SET_SECCOMP) → execve) which is not
# worth the complexity today. The residual risk — a child on a distro
# without kernel.apparmor_restrict_unprivileged_userns=1 calling
# unshare(CLONE_NEWUSER|CLONE_NEWNS) to get CAP_SYS_ADMIN in a nested
# mount-ns and then attempting bind-mount tricks against Landlock's
# path resolution — is bounded by: (1) Landlock path_beneath uses
# dentry chains, not the bind-mount-visible path, so re-mounting
# doesn't grant access to a new dentry; (2) NO_NEW_PRIVS is inherited
# across fork/clone so seccomp can't be dropped; (3) Landlock rules
# inherit across nested namespaces. Documented in the threat model.

# Syscalls blocked in full, allowed in debug profile
_SECCOMP_BLOCK_UNLESS_DEBUG = (
    "ptrace",
)

# socket() family / type values we reject (via argument filter on arg 0 / 1).
# AF_INET/AF_INET6 continue to be allowed — namespace --net removes the
# interfaces anyway, so allowing AF_INET costs nothing and avoids breakage
# for tools that create a socket and check if it works.
_AF_UNIX = 1
_AF_NETLINK = 16
_AF_PACKET = 17
_SOCK_RAW = 3
_SOCK_DGRAM = 2

# AF_INET / AF_INET6 constants — used by the UDP block. Only filtered
# when the caller requests it (proxy mode); otherwise DNS via UDP/53
# is needed for normal operation. Under proxy mode, the proxy resolves
# on the child's behalf — DNS client-side is unnecessary.
_AF_INET = 2
_AF_INET6 = 10

# ioctl command numbers we reject via argument filter on arg 1 (cmd).
# Values are the asm-generic encodings used by x86_64, aarch64, riscv64,
# s390x, loongarch64 — i.e. every architecture in _LANDLOCK_ARCH_OK. On
# legacy archs (powerpc, alpha, mips, sparc, parisc) the per-arch
# <asm/ioctls.h> overrides these with _IOW()-derived numbers, so a
# sandbox running on those archs would not match and the filter would
# silently let the ioctl through. We do not support those archs.
# TIOCSTI — "Simulate Terminal Input" — pushes a character into the tty's
# input buffer. When RAPTOR is run interactively, stdin is the invoking
# user's tty; a sandboxed process can ioctl(0, TIOCSTI, &c) in a loop to
# queue arbitrary commands into the user's shell, executed the instant
# the sandbox exits. Classic escape vector blocked by Docker's default.
_TIOCSTI = 0x5412
# TIOCCONS — redirect console (/dev/console) output to the caller's tty.
# Requires CAP_SYS_ADMIN in init_user_ns so not exploitable from our
# unprivileged user-ns, but blocked in Docker's default profile. No
# legitimate use for the tools we run.
_TIOCCONS = 0x541D
# TIOCSCTTY — make caller's tty the controlling terminal of its session.
# Requires the caller to be a session leader AND the tty to have no
# controlling session — so not exploitable by a sandboxed child that's
# not a session leader. Blocked by Docker's default profile.
_TIOCSCTTY = 0x540E

_BLOCKED_IOCTL_CMDS = (_TIOCSTI, _TIOCCONS, _TIOCSCTTY)


def check_seccomp_available() -> bool:
    """Check whether libseccomp is loadable. Cached per process."""
    with state._cache_lock:
        if state._libseccomp_cache is not None:
            return bool(state._libseccomp_cache)
        libname = ctypes.util.find_library("seccomp")
        if not libname:
            logger.debug("Sandbox: libseccomp not found on system")
            state._libseccomp_cache = 0
            return False
        try:
            lib = ctypes.CDLL(libname, use_errno=True)
            # Sanity: the functions we need must exist
            _ = lib.seccomp_init
            _ = lib.seccomp_rule_add_array
            _ = lib.seccomp_load
            _ = lib.seccomp_release
            _ = lib.seccomp_syscall_resolve_name
        except (OSError, AttributeError) as e:
            logger.debug(f"Sandbox: libseccomp load failed: {e}")
            state._libseccomp_cache = 0
            return False
        state._libseccomp_cache = lib
        logger.debug("Sandbox: libseccomp available")
        return True


def _make_seccomp_preexec(profile: str, block_udp: bool = False,
                          audit_mode: bool = False):
    """Create a preexec_fn that installs the seccomp filter for `profile`.

    Runs POST-fork in the child. Same fork-safety rules as Landlock: capture
    libc/libseccomp handles in parent, use os.write(2, ...) for errors
    instead of the Python logger (which is not fork-safe).

    `block_udp=True` additionally rejects socket(AF_INET|AF_INET6, SOCK_DGRAM)
    — enabled by the use_egress_proxy mode in context.sandbox() so that a
    sandboxed child can't do DNS (UDP/53) or any UDP protocol directly.
    With the proxy allowlisting hostnames, the proxy resolves on behalf of
    the child, so UDP client-side is unnecessary. Disabled by default
    because UDP/DNS is needed for normal sandbox use (e.g. block_network=True
    with no proxy — DNS still used inside the net-ns for loopback lookups).

    `audit_mode=True` swaps the deny action from SCMP_ACT_ERRNO(EPERM) to
    SCMP_ACT_TRACE — the kernel pauses the tracee and notifies the
    attached ptrace tracer (core/sandbox/tracer.py) instead of erroring
    the syscall. Also adds open/openat/connect to the trace set for b3
    filesystem + network audit coverage. CRITICAL: requires a ptrace
    tracer to be attached for the target's lifetime; without it, the
    kernel default action for unhandled TRACE is SIGSYS-kill the
    process. The caller (_spawn.py) is responsible for ensuring tracer
    is attached before any traced syscall fires.

    Returns None if libseccomp is unavailable or the profile
    indicates "no seccomp" — both falsy values (None, "") and the
    literal string "none" are accepted as disable triggers, matching
    callers that may convert via `profile_dict["seccomp"] or None`
    (context.py) and callers that pass the raw profile name.
    """
    if not profile or profile == "none" or not check_seccomp_available():
        return None

    lib = state._libseccomp_cache  # CDLL captured at check time

    # Declare signatures so ctypes doesn't mangle pointer-sized returns on 64-bit.
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_attr_set.restype = ctypes.c_int
    lib.seccomp_attr_set.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32]
    lib.seccomp_rule_add_array.restype = ctypes.c_int
    lib.seccomp_rule_add_array.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int,
        ctypes.c_uint, ctypes.POINTER(_ScmpArgCmp),
    ]
    lib.seccomp_load.restype = ctypes.c_int
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.restype = None
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]

    # Resolve syscall names to numbers in the PARENT so the child doesn't
    # need to call back into libseccomp's name tables post-fork.
    def _resolve(name: str) -> int:
        num = lib.seccomp_syscall_resolve_name(name.encode("ascii"))
        return num  # negative means unknown on this arch; caller checks

    blocked_syscalls = list(_SECCOMP_BLOCK_ALWAYS)
    if profile != "debug":
        blocked_syscalls += list(_SECCOMP_BLOCK_UNLESS_DEBUG)
    # Audit mode: add b3 syscalls (open/openat/connect) to the trace
    # set so the tracer logs every file path attempt and connect
    # target. Under enforcement these aren't blocked at all (Landlock
    # / egress proxy handle them at other layers); under audit they
    # become observable via SCMP_ACT_TRACE.
    audit_extra: list = []
    if audit_mode:
        audit_extra = [(name, _resolve(name))
                       for name in _AUDIT_EXTRA_TRACE_SYSCALLS]
    resolved_blocks = [(name, _resolve(name)) for name in blocked_syscalls]
    # Sockets: filter by argument (family). Same syscall number, multiple rules.
    socket_num = _resolve("socket")
    # ioctl — filter only specific cmd numbers (TIOCSTI for tty injection).
    # Most ioctls are legitimate (FIONBIO, TIOCGWINSZ, etc.); we only
    # reject the known-dangerous ones.
    ioctl_num = _resolve("ioctl")

    # Gap 6: warn once per process when intended blocks silently skip
    # because the syscall isn't defined on this architecture. libseccomp
    # returns a negative value for unresolved names — RISC-V older cores
    # and some cross-compiled builds hit this for specific syscalls. We
    # name the missing ones so operators can decide if the gap is tolerable.
    # (socketpair() is deliberately NOT filtered — see the comment in the
    # rule-installation loop below — so we don't report it as "missing".)
    missing = [name for name, num in resolved_blocks if num < 0]
    if socket_num < 0:
        missing.append("socket")
    if ioctl_num < 0:
        missing.append("ioctl")
    if missing and state.warn_once("_seccomp_arch_missing_warned"):
        logger.warning(
            f"Sandbox: seccomp could not resolve syscall(s) {missing} on this "
            f"architecture — those blocks are NOT installed. Likely harmless "
            f"on x86_64/aarch64 (this should be empty); investigate on other "
            f"architectures if any entries appear."
        )
    # Block AF_UNIX/NETLINK/PACKET via arg 0; block SOCK_RAW via arg 1.
    socket_family_blocks = [_AF_UNIX, _AF_NETLINK, _AF_PACKET]
    socket_type_block = _SOCK_RAW

    _os_write = os.write

    # Resolve libc.prctl in the parent so the child doesn't have to dlopen.
    # PR_SET_NO_NEW_PRIVS is a hard prerequisite for seccomp_load() unless
    # the caller has CAP_SYS_ADMIN. Landlock's preexec sets it when it's
    # configured; without Landlock (no writable_paths and no allowed_tcp_ports),
    # nobody set NNP and seccomp_load fails with EPERM — silently degrading
    # to "no seccomp" before this commit's fail-closed change at load,
    # and to a hard exit (126) afterwards. Either way the operator's
    # filter never installed. Set NNP unconditionally inside _apply_seccomp
    # so the filter installs regardless of whether Landlock ran. NNP is
    # one-way / idempotent: calling it twice (once from Landlock, once
    # from here) is a no-op.
    _libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6",
                        use_errno=True)
    _libc.prctl.restype = ctypes.c_int
    _libc.prctl.argtypes = [
        ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
        ctypes.c_ulong, ctypes.c_ulong,
    ]
    _PR_SET_NO_NEW_PRIVS = 38

    def _apply_seccomp():
        try:
            if _libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
                _os_write(2, b"RAPTOR: prctl(PR_SET_NO_NEW_PRIVS) failed -- "
                             b"seccomp filter cannot be installed\n")
                os._exit(126)

            ctx = lib.seccomp_init(_SCMP_ACT_ALLOW)
            if not ctx:
                # Fail-closed: was a bare `return`, which let the child
                # exec with NO seccomp filter despite the operator
                # asking for one. Match the policy at seccomp_load:
                # a security layer that the operator requested but
                # failed to install MUST NOT silently degrade.
                _os_write(2, b"RAPTOR: seccomp_init failed -- "
                             b"refusing to exec without filter\n")
                os._exit(126)
            try:
                # Explicitly set BADARCH = KILL_PROCESS. Current libseccomp
                # (2.5.x) defaults to KILL_PROCESS, but we've relied on
                # that implicitly — a future libseccomp release or a
                # patched build could silently weaken it to ALLOW. Setting
                # it explicitly makes the 32-bit-compat-arch protection
                # robust against supply-chain drift (int 0x80 / x32 / AArch32
                # syscalls arrive with arch != native and get killed rather
                # than falling through to the native filter rules).
                lib.seccomp_attr_set(ctx, _SCMP_FLTATR_ACT_BADARCH,
                                     _SCMP_ACT_KILL_PROCESS)

                errno_eperm = 1  # EPERM
                # Audit mode: swap the deny action from ERRNO to TRACE.
                # Under TRACE, the kernel pauses on the offending syscall
                # and notifies our ptrace tracer (core/sandbox/tracer.py)
                # which logs the event and resumes the syscall. CRITICAL:
                # with no tracer attached, the kernel default for TRACE
                # is to SIGSYS the process — _spawn.py is responsible
                # for ensuring the tracer is attached BEFORE any traced
                # syscall fires.
                if audit_mode:
                    deny = _SCMP_ACT_TRACE(0)
                else:
                    deny = _SCMP_ACT_ERRNO(errno_eperm)

                for name, num in resolved_blocks:
                    if num < 0:
                        # Unknown syscall on this arch — harmless to skip
                        continue
                    null_args = ctypes.POINTER(_ScmpArgCmp)()
                    ret = lib.seccomp_rule_add_array(ctx, deny, num, 0, null_args)
                    if ret < 0:
                        _os_write(2, b"RAPTOR: seccomp add_rule failed\n")

                # Audit-mode-only extras: open/openat/connect get the
                # TRACE action so the tracer logs every file path and
                # connect attempt for b3 coverage. Skipped under
                # enforcement (these aren't blocked at the seccomp
                # layer in any non-audit profile).
                if audit_mode:
                    trace_act = _SCMP_ACT_TRACE(0)
                    for name, num in audit_extra:
                        if num < 0:
                            continue
                        null_args = ctypes.POINTER(_ScmpArgCmp)()
                        ret = lib.seccomp_rule_add_array(
                            ctx, trace_act, num, 0, null_args,
                        )
                        if ret < 0:
                            _os_write(2, b"RAPTOR: seccomp audit rule failed\n")

                # socket() with blocked family — one rule per family
                if socket_num >= 0:
                    for fam in socket_family_blocks:
                        arg = _ScmpArgCmp(arg=0, op=_SCMP_CMP_EQ,
                                          datum_a=fam, datum_b=0)
                        arg_arr = (_ScmpArgCmp * 1)(arg)
                        ret = lib.seccomp_rule_add_array(
                            ctx, deny, socket_num, 1, arg_arr,
                        )
                        if ret < 0:
                            _os_write(2, b"RAPTOR: seccomp socket family rule failed\n")

                    # socket() with SOCK_RAW — argument 1 is type (with optional
                    # SOCK_NONBLOCK/CLOEXEC bits). Use MASKED_EQ with the
                    # kernel's SOCK_TYPE_MASK (0xf) so the rule matches the
                    # bare `SOCK_RAW` and also `SOCK_RAW | SOCK_CLOEXEC` /
                    # `SOCK_RAW | SOCK_NONBLOCK`. Raw sockets also require
                    # CAP_NET_RAW on the host which the sandbox doesn't grant,
                    # so this is belt-and-braces. Lives alongside the other
                    # socket() rules (was previously nested inside the ioctl
                    # block by accident — it depends on socket_num, not
                    # ioctl_num).
                    arg = _ScmpArgCmp(arg=1, op=_SCMP_CMP_MASKED_EQ,
                                      datum_a=_SOCK_TYPE_MASK,
                                      datum_b=socket_type_block)
                    arg_arr = (_ScmpArgCmp * 1)(arg)
                    ret = lib.seccomp_rule_add_array(
                        ctx, deny, socket_num, 1, arg_arr,
                    )
                    if ret < 0:
                        _os_write(2, b"RAPTOR: seccomp SOCK_RAW rule failed\n")

                # UDP block — only when proxy mode is active. We can't
                # filter on (family, type) simultaneously in a single
                # rule (libseccomp's scmp_rule_add takes multiple arg
                # comparators but they're AND'd, so we'd need one rule
                # per (family, type) combination — which is exactly
                # what we do). Rejects AF_INET/AF_INET6 + SOCK_DGRAM.
                # Allows UDP for other families (AF_UNIX/NETLINK etc.
                # are already blocked above regardless of type).
                if block_udp and socket_num < 0:
                    # Fail-closed: caller asked for proxy-mode UDP block
                    # but we can't install the rule (socket() syscall
                    # unresolved on this arch). Silently skipping would
                    # let DNS/UDP exfil through despite the operator
                    # selecting the hardened mode.
                    _os_write(2, b"RAPTOR: seccomp block_udp requested but "
                                 b"socket() syscall unresolved -- refusing to "
                                 b"exec without UDP filter\n")
                    os._exit(126)
                if block_udp and socket_num >= 0:
                    for fam in (_AF_INET, _AF_INET6):
                        # arg 1 is type | flags (SOCK_CLOEXEC / SOCK_NONBLOCK).
                        # Use MASKED_EQ with SOCK_TYPE_MASK (0xf) so
                        # `SOCK_DGRAM | SOCK_CLOEXEC` (524290) and
                        # `SOCK_DGRAM | SOCK_NONBLOCK` (2050) both match the
                        # block — exact equality misses both common variants.
                        args = (_ScmpArgCmp * 2)(
                            _ScmpArgCmp(arg=0, op=_SCMP_CMP_EQ,
                                        datum_a=fam, datum_b=0),
                            _ScmpArgCmp(arg=1, op=_SCMP_CMP_MASKED_EQ,
                                        datum_a=_SOCK_TYPE_MASK,
                                        datum_b=_SOCK_DGRAM),
                        )
                        ret = lib.seccomp_rule_add_array(
                            ctx, deny, socket_num, 2, args,
                        )
                        if ret < 0:
                            _os_write(2, b"RAPTOR: seccomp UDP block rule failed\n")

                # socketpair() is DELIBERATELY NOT filtered here. Unlike
                # socket(AF_UNIX) which returns a socket that can then
                # connect() to a filesystem path (e.g. /var/run/docker.sock
                # — a real escape vector), socketpair() returns two
                # already-connected sockets within a single process with
                # NO external address. The "peer" is the other half of the
                # pair, not anything reachable on the host. Blocking
                # socketpair(AF_UNIX) was attempted as defence-in-depth
                # but broke Rust's std::process::Command — Rust uses
                # AF_UNIX socketpair internally for fork+exec error
                # reporting (the child writes its exec errno through the
                # pair back to the parent). With no real security benefit
                # and real compatibility cost, we leave socketpair alone.

                # ioctl(fd, <cmd>, ...) — filter by cmd argument (arg 1).
                # Blocks tty-input injection (TIOCSTI) and two other tty
                # ioctls Docker's default profile rejects (TIOCCONS,
                # TIOCSCTTY). Most ioctl cmds are legitimate (FIONBIO,
                # TIOCGWINSZ, FIONREAD, etc.) — we only filter the
                # known-dangerous list, one rule per cmd value.
                if ioctl_num >= 0:
                    for cmd_val in _BLOCKED_IOCTL_CMDS:
                        arg = _ScmpArgCmp(arg=1, op=_SCMP_CMP_EQ,
                                          datum_a=cmd_val, datum_b=0)
                        arg_arr = (_ScmpArgCmp * 1)(arg)
                        ret = lib.seccomp_rule_add_array(
                            ctx, deny, ioctl_num, 1, arg_arr,
                        )
                        if ret < 0:
                            _os_write(2, b"RAPTOR: seccomp ioctl rule failed\n")

                ret = lib.seccomp_load(ctx)
                if ret < 0:
                    # Fail-closed (was: write to stderr + continue,
                    # which silently fails OPEN — child execs without
                    # seccomp despite operator running --sandbox full).
                    # Match Landlock's posture: a security layer that
                    # the operator asked for but fails to install MUST
                    # NOT silently degrade enforcement.
                    _os_write(2, b"RAPTOR: seccomp_load failed -- "
                                 b"refusing to exec without filter\n")
                    os._exit(126)
            finally:
                lib.seccomp_release(ctx)
        except BaseException:
            # Fail-closed on any unexpected exception -- same reason.
            # BaseException so SystemExit / KeyboardInterrupt also
            # route through the safe-exit path rather than letting
            # the child continue with no seccomp.
            _os_write(2, b"RAPTOR: seccomp enforcement failed -- "
                         b"refusing to exec without filter\n")
            os._exit(126)

    return _apply_seccomp
