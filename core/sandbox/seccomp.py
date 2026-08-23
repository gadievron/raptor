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
# SCMP_ACT_NOTIFY: route the syscall to a userspace supervisor over
# the filter's notification fd (include/uapi/linux/seccomp.h
# SECCOMP_RET_USER_NOTIF, libseccomp >= 2.5). Used by the AF_UNIX
# connect-scoping path only.
_SCMP_ACT_NOTIFY = 0x7FC00000
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
    # Filesystem-mutation families: destructive / namespace-changing
    # ops that need no open() and were previously invisible to the
    # audit JSONL — including exactly the metadata ops (chmod / chown
    # / xattr) the Landlock metadata gap leaves unrestricted at the
    # enforcement layer. Legacy non-at names (unlink, rename, link,
    # symlink, mkdir, mknod, chmod, chown, lchown) resolve to -1 on
    # at-only ABIs (aarch64); the install loop skips negative
    # resolutions so listing them is harmless there.
    "unlink", "unlinkat",
    "rename", "renameat", "renameat2",
    "link", "linkat",
    "symlink", "symlinkat",
    "mkdir", "mkdirat",
    "mknod", "mknodat",
    "truncate",
    "chmod", "fchmodat",
    "chown", "fchownat", "lchown",
    "setxattr", "lsetxattr",
    "removexattr", "lremovexattr",
)

# Additional syscalls traced under observe mode ON TOP OF the audit
# set. Stat-family covers "binary probed for X but didn't open" — a
# common shape for config-discovery in tools like Claude Code that
# enumerate candidate config locations. Pure read access, no write
# intent; never blocked at any layer (Landlock applies to opens not
# stats), so they're observe-only signal — no use under enforcement
# audit, where the question is "what got denied".
#
# `stat`/`lstat` are x86_64-only — aarch64 userspace uses newfstatat
# exclusively. libseccomp's seccomp_syscall_resolve_name returns -1
# for unsupported names on the current arch; the install loop skips
# negative resolutions so this is harmless.
_OBSERVE_EXTRA_TRACE_SYSCALLS = (
    "stat", "lstat",        # legacy x86_64 stat syscalls
    "newfstatat",            # AT_*-aware variant; aarch64 + modern x86_64
    "access", "faccessat", "faccessat2",
)


# libseccomp comparison ops (scmp_compare)
_SCMP_CMP_EQ = 4         # equal to: arg == datum_a
_SCMP_CMP_MASKED_EQ = 7  # masked equal: (arg & datum_a) == datum_b

# MSG_FASTOPEN (include/linux/socket.h): sendto/sendmsg flag that makes
# the kernel perform the TCP connect INSIDE the send path — no
# connect(2) is ever issued, so address-based connect controls
# (connect-scoping supervisor, Landlock CONNECT_TCP) never see it.
_MSG_FASTOPEN = 0x20000000

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
    # process_vm_readv / process_vm_writev: cross-process memory access.
    # Moved to _SECCOMP_BLOCK_UNLESS_DEBUG (2026-06-13) because gdb's
    # inferior-memory plumbing under runtime_inspect needs them. The
    # debug profile is only used by runtime_inspect; widening its
    # surface to enable real interactive debugging is the explicit
    # tradeoff (an operator opting into exploit-dev tooling accepts
    # this; the surface stays narrow for every other profile).
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

# Syscalls blocked in full, allowed in the debug AND frida profiles
# (both are opt-in instrumentation profiles; the constant's name
# predates the frida exemption — see the profile check in
# _make_seccomp_preexec).
_SECCOMP_BLOCK_UNLESS_DEBUG = (
    "ptrace",
    # gdb's read/write of the inferior's memory. Without these gdb
    # has to fall back to /proc/PID/mem which has tighter Yama-policy
    # constraints under non-init-userns.
    "process_vm_readv",
    "process_vm_writev",
)

# Escape-primitive subset that stays HARD-DENIED (SCMP_ACT_ERRNO)
# even under audit mode. Audit mode exists to OBSERVE what a workload
# does so operators can build policy — but converting these
# particular denials into allow-and-log hands an audited child the
# exact capability the sandbox exists to deny for the duration of the
# audit run: ptrace/process_vm_* read same-UID host process memory
# (credential exfil), keyctl/add_key/request_key reach the kernel
# keyring, bpf/userfaultfd are classic container-escape primitives,
# and io_uring_* bypasses Landlock's file hooks on pre-6.3 kernels.
# None of these has observational value that justifies granting it —
# unlike open/connect/stat (the _AUDIT_EXTRA/_OBSERVE_EXTRA sets),
# which stay trace-allow so the tracer can report what the workload
# wanted.
#
# The blocked tty ioctls (TIOCSTI et al) get the same treatment via
# an unconditional ERRNO action on the ioctl rules — TIOCSTI injects
# keystrokes into the operator's shell, which is not observable-then-
# harmless either.
#
# The socket()-argument rules (AF_UNIX/AF_NETLINK/AF_PACKET, SOCK_RAW,
# and the proxy-mode UDP block) are escape primitives too and keep the
# ERRNO action under audit mode: socket(AF_UNIX)+connect() reaches
# /var/run/docker.sock (root-equivalent when the operator is in the
# docker group) on Landlock-only hosts where the mount-ns cannot mask
# /run, AF_PACKET/SOCK_RAW sniff host traffic, and the UDP block is an
# operator-selected exfil control. Converting those denials into
# allow-and-log would hand an audited child the capability for the
# duration of the run — the same rationale as this set. The cost is
# the same logging residual described below (the child sees EPERM
# instead of the tracer seeing an event).
#
# Logging residual: SCMP_ACT_ERRNO does not notify the tracer, so an
# attempt on this set surfaces to the child as EPERM (picked up by
# the stderr-pattern enforcement detection) rather than as a tracer
# JSONL record. Logging AND denying in one filter would need a
# tracer-side syscall rewrite (PTRACE_SETREGSET per arch), which is
# not worth the complexity for syscalls that are pure attack signal.
_AUDIT_HARD_DENY_SYSCALLS = frozenset({
    "ptrace", "process_vm_readv", "process_vm_writev",
    "keyctl", "add_key", "request_key",
    "bpf", "userfaultfd",
    "io_uring_setup", "io_uring_enter", "io_uring_register",
})

# socket() family / type values we reject (via argument filter on arg 0 / 1).
# AF_INET/AF_INET6 continue to be allowed — namespace --net removes the
# interfaces anyway, so allowing AF_INET costs nothing and avoids breakage
# for tools that create a socket and check if it works.
_AF_UNIX = 1
_AF_NETLINK = 16
_AF_PACKET = 17
_SOCK_RAW = 3
_SOCK_DGRAM = 2

# Kernel-bypass stream transports (denied unconditionally, hard_deny).
# Landlock's network rules cover IPPROTO_TCP only and the UDP block
# matches SOCK_DGRAM only, so an SCTP one-to-one socket —
# socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP) — was created past every
# socket() rule and connect(2)ed past Landlock CONNECT_TCP: full
# bidirectional stream egress to any host:port on the Landlock-port-pin
# postures (egress-proxy tier 2, any caller passing allowed_tcp_ports
# on the shared netns). Worse, SCTP_SOCKOPT_CONNECTX performs the
# connect IN-KERNEL through a setsockopt pointer no seccomp filter can
# inspect, so even the connect-notify supervisor is architecturally
# blind to it — denying socket creation covers connectx by
# construction. DCCP has the same shape (its own socket type, not
# covered by Landlock TCP rules), and MPTCP (IPPROTO_MPTCP=262) is a
# distinct sk_protocol that predates Landlock's TCP hook on some
# kernels — denied alongside rather than audited per kernel version.
# Judgment, documented: nothing in RAPTOR's sandboxed tool population
# (compilers, scanners, interpreters, fuzzers, LLM-emitted exploits,
# build systems) legitimately speaks SCTP, DCCP, or opts into MPTCP;
# apps must request these protocols explicitly, so the deny costs
# nothing on the supported workloads. The netns egress tier was never
# exposed (no route out); this closes the tier-2 / shared-netns arm.
# SOCK_SEQPACKET / SOCK_DCCP on AF_INET* are denied by TYPE as well:
# protocol=0 with those types defaults to SCTP / DCCP in the kernel,
# dodging a protocol-only match. AF_UNIX SOCK_SEQPACKET is unaffected
# (family-scoped rules).
_IPPROTO_SCTP = 132
_IPPROTO_DCCP = 33
_IPPROTO_MPTCP = 262
_SOCK_SEQPACKET = 5
_SOCK_DCCP = 6

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
# TIOCLINUX — Linux virtual-console multiplexer ioctl. Subcommand 2
# ("set selection" + paste) injects bytes into the console input
# buffer on a real VT — the TIOCSTI-adjacent console-injection
# escape. Harmless on ptys (ENOTTY) so blocking costs nothing on the
# common path.
_TIOCLINUX = 0x541C

_BLOCKED_IOCTL_CMDS = (_TIOCSTI, _TIOCCONS, _TIOCSCTTY, _TIOCLINUX)

# 32-bit argument mask for MASKED_EQ deny rules. The kernel truncates
# socket()'s family and ioctl()'s cmd to int/unsigned int, but seccomp
# compares the RAW 64-bit register — an exact-equality rule misses
# ``AF_UNIX | 1<<32``, which the kernel then treats as plain AF_UNIX
# (default-allow => blocklist bypass). Masking the compare to the low
# 32 bits makes the rule see exactly what the kernel will use.
_ARG32_MASK = 0xFFFFFFFF


def _seccomp_functional_selftest(lib) -> bool:
    """Fork a child, ACTUALLY apply a minimal allow-all seccomp filter, and
    verify it loads.

    Library-loadable is necessary but NOT sufficient: the kernel can still
    reject ``seccomp_load()`` (no ``CONFIG_SECCOMP_FILTER``, a restrictive
    container/seccomp policy, etc.). If we only checked loadability, such a
    host would pass the probe, set a seccomp_profile, then die mid-spawn in
    the child (``seccomp_load`` raises → exit 126 + empty stdout), which a
    consumer reads as a silent "0 findings". Applying the filter for real
    here — same sequence as ``_make_seccomp_preexec``: ``PR_SET_NO_NEW_PRIVS``
    → ``seccomp_init`` → ``seccomp_load`` — reports unavailability up front so
    seccomp is simply SKIPPED (real results under weaker isolation) instead.
    Mirrors ``check_landlock_available()``'s functional self-test.

    Child is ctypes + ``os._exit`` only (no Python logger — not fork-safe).
    """
    # Resolve all ctypes handles + signatures in the PARENT, before fork, so
    # the forked child does NO dlopen/CDLL — a child that dlopens can deadlock
    # if a sibling thread (the scanner's ThreadPoolExecutor workers) holds
    # glibc's malloc-arena lock at the fork instant. The child only CALLS
    # already-resolved functions.
    _PR_SET_NO_NEW_PRIVS = 38
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl.restype = ctypes.c_int
        libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong,
                               ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
        lib.seccomp_init.restype = ctypes.c_void_p
        lib.seccomp_init.argtypes = [ctypes.c_uint32]
        lib.seccomp_load.restype = ctypes.c_int
        lib.seccomp_load.argtypes = [ctypes.c_void_p]
        lib.seccomp_release.restype = None
        lib.seccomp_release.argtypes = [ctypes.c_void_p]
    except (OSError, AttributeError):
        return False
    import warnings as _warnings
    with _warnings.catch_warnings():
        _warnings.filterwarnings(
            "ignore", category=DeprecationWarning,
            message=r".*fork.*may lead to deadlocks.*",
        )
        pid = os.fork()
    if pid == 0:
        # ===== CHILD ===== (calls only — no dlopen/CDLL)
        try:
            if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
                os._exit(1)
            ctx = lib.seccomp_init(_SCMP_ACT_ALLOW)
            if not ctx:
                os._exit(1)
            rc = lib.seccomp_load(ctx)
            lib.seccomp_release(ctx)
            os._exit(0 if rc == 0 else 1)
        except BaseException:  # noqa: BLE001 — post-fork: must never unwind into parent state
            os._exit(1)
    # ===== PARENT =====
    try:
        _, status = os.waitpid(pid, 0)
    except ChildProcessError:
        return False
    return os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0


def check_seccomp_available() -> bool:
    """Check whether libseccomp is loadable AND seccomp_load() functions.
    Cached per process."""
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
            # Sanity: the functions we need must exist — including
            # seccomp_attr_set, which _make_seccomp_preexec calls
            # unconditionally (bad-arch action). Omitting it would
            # pass the probe on a build lacking it and then die with
            # AttributeError inside the spawn child.
            _ = lib.seccomp_init
            _ = lib.seccomp_rule_add_array
            _ = lib.seccomp_load
            _ = lib.seccomp_release
            _ = lib.seccomp_syscall_resolve_name
            _ = lib.seccomp_attr_set
        except (OSError, AttributeError) as e:
            logger.debug("Sandbox: libseccomp load failed: %s", e)
            state._libseccomp_cache = 0
            return False
        # Functional self-test (see _seccomp_functional_selftest): loadable
        # libseccomp is necessary but not sufficient. A host where the
        # kernel rejects seccomp_load() must report unavailable here so
        # seccomp is skipped, rather than dying mid-spawn with empty output.
        if not _seccomp_functional_selftest(lib):
            logger.debug("Sandbox: libseccomp loads but seccomp_load() "
                         "self-test failed — treating seccomp as unavailable")
            state._libseccomp_cache = 0
            return False
        state._libseccomp_cache = lib
        logger.debug("Sandbox: libseccomp available (functional self-test passed)")
        return True


def _make_seccomp_preexec(profile: str, block_udp: bool = False,
                          audit_mode: bool = False,
                          observe_mode: bool = False,
                          allow_unix_sockets: bool = False,
                          unix_scope_export_sock=None):
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
    filesystem + network audit coverage. EXCEPTION: the escape-primitive
    subset (_AUDIT_HARD_DENY_SYSCALLS — ptrace/process_vm_*, keyring,
    bpf/userfaultfd, io_uring_*), the blocked tty ioctls, AND the
    socket()-argument rules (blocked families, SOCK_RAW, the
    SCTP/DCCP/MPTCP kernel-bypass transports, the UDP block)
    keep the ERRNO action under audit too; converting THOSE denials
    into allow-and-log would grant an audited child the very
    capabilities the sandbox exists to deny (e.g. socket(AF_UNIX) →
    connect("/var/run/docker.sock") on a Landlock-only host where /run
    is not masked). CRITICAL: TRACE rules require a ptrace
    tracer to be attached for the target's lifetime; without it, the
    kernel default action for unhandled TRACE is SIGSYS-kill the
    process. The caller (_spawn.py) is responsible for ensuring tracer
    is attached before any traced syscall fires.

    `allow_unix_sockets=True` drops AF_UNIX from the socket-family
    blocklist. Only pass this when BOTH isolation layers that make
    AF_UNIX harmless are engaged for this child: the mount namespace
    (fresh tmpfs over /run masks pathname sockets like docker.sock;
    pivot_root leaves the rest of the host read-only, and connect(2)
    to a pathname socket on a read-only mount fails the MAY_WRITE
    inode check) and a fresh/coordinator network namespace (abstract-
    namespace AF_UNIX sockets are netns-scoped, so the host's are
    unreachable). Blanket-blocking socket(AF_UNIX) breaks Python >=
    3.14 inside the sandbox: multiprocessing's default start method
    changed to forkserver, whose listener needs socket(AF_UNIX) —
    observed as the CodeQL python extractor dying with EPERM. The
    preexec-only path (no mount-ns) must keep the block.

    `observe_mode=True` extends the trace set with stat-family syscalls
    (stat/lstat/newfstatat/access/faccessat/faccessat2) on top of the
    audit set. Stat-family events surface "binary probed candidate
    paths" — useful for profile-extraction probes (e.g., calibrating
    Claude Code's filesystem reach) where the question is "what does
    this binary touch", not "what did the sandbox deny". Implies
    audit_mode (TRACE action, tracer attached); enforcement-shape
    audits should leave it off.

    `unix_scope_export_sock` (a connected AF_UNIX socket object, the
    child end of a parent-created socketpair) engages CONNECT SCOPING
    alongside `allow_unix_sockets=True` in enforcement mode: connect(2)
    gets the SCMP_ACT_NOTIFY action, the resulting notify fd is shipped
    to the parent over the socketpair (SCM_RIGHTS) for the
    core/sandbox/_unix_scope.py supervisor, and socket(AF_UNIX,
    SOCK_DGRAM) is denied (datagram sendto-with-address would bypass
    the connect chokepoint; nothing sandboxed needs unix datagrams).
    socketpair(AF_UNIX, SOCK_DGRAM) is denied alongside it — Linux
    permits sendto/sendmsg with an explicit destination on a
    socketpair half, recreating the same destination-bearing datagram
    primitive without any connect(2) reaching the supervisor.
    SOCK_STREAM / SOCK_SEQPACKET socketpair stays unfiltered (Python
    multiprocessing forkserver and Rust's spawn plumbing need it).
    Fail-closed: if the notify fd cannot be created or exported the
    child exits 126 — an unsupervised NOTIFY filter would leave every
    connect(2) blocking forever. Mutually exclusive with audit_mode
    (audit routes connect through the ptrace tracer instead).

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
    if unix_scope_export_sock is not None:
        # Present on libseccomp >= 2.5; probed by _unix_scope before
        # any caller passes an export sock.
        lib.seccomp_notify_fd.restype = ctypes.c_int
        lib.seccomp_notify_fd.argtypes = [ctypes.c_void_p]

    # Resolve syscall names to numbers in the PARENT so the child doesn't
    # need to call back into libseccomp's name tables post-fork.
    def _resolve(name: str) -> int:
        num = lib.seccomp_syscall_resolve_name(name.encode("ascii"))
        return num  # negative means unknown on this arch; caller checks

    if unix_scope_export_sock is not None and audit_mode:
        # The tracer owns connect observability under audit; a NOTIFY
        # rule would fight the TRACE rule for the same syscall.
        msg = "unix_scope_export_sock is incompatible with audit_mode"
        raise ValueError(msg)

    blocked_syscalls = list(_SECCOMP_BLOCK_ALWAYS)
    if profile not in ("debug", "frida"):
        blocked_syscalls += list(_SECCOMP_BLOCK_UNLESS_DEBUG)
    # Audit mode: add b3 syscalls (open/openat/connect) to the trace
    # set so the tracer logs every file path attempt and connect
    # target. Under enforcement these aren't blocked at all (Landlock
    # / egress proxy handle them at other layers); under audit they
    # become observable via SCMP_ACT_TRACE.
    audit_extra: list = []
    if audit_mode:
        audit_names = list(_AUDIT_EXTRA_TRACE_SYSCALLS)
        if observe_mode:
            # Stat-family on top of audit's open/connect. Resolves
            # to -1 on arches missing a given syscall (e.g. aarch64
            # has no `stat`/`lstat`); the install loop below skips
            # negative resolutions so this is a no-op on those
            # arches rather than an error.
            audit_names += list(_OBSERVE_EXTRA_TRACE_SYSCALLS)
        audit_extra = [(name, _resolve(name)) for name in audit_names]
    resolved_blocks = [(name, _resolve(name)) for name in blocked_syscalls]
    # Sockets: filter by argument (family). Same syscall number, multiple rules.
    socket_num = _resolve("socket")
    socketpair_num = _resolve("socketpair")
    connect_num = (_resolve("connect")
                   if unix_scope_export_sock is not None else -1)
    # ioctl — filter only specific cmd numbers (TIOCSTI for tty injection).
    # Most ioctls are legitimate (FIONBIO, TIOCGWINSZ, etc.); we only
    # reject the known-dangerous ones.
    ioctl_num = _resolve("ioctl")
    # send-path syscalls carrying a flags argument that can smuggle an
    # in-kernel connect (MSG_FASTOPEN): sendto(arg 3), sendmsg(arg 2),
    # sendmmsg(arg 3 — the call-level flags; per-message msg_hdr flags
    # do not carry MSG_FASTOPEN through the TFO path).
    send_flag_syscalls = [("sendto", _resolve("sendto"), 3),
                          ("sendmsg", _resolve("sendmsg"), 2),
                          ("sendmmsg", _resolve("sendmmsg"), 3)]

    # socketpair(AF_UNIX, SOCK_DGRAM) is denied exactly when the
    # matching socket(AF_UNIX, SOCK_DGRAM) is denied: either AF_UNIX
    # is in the family blocklist (default posture) or connect scoping
    # is engaged (AF_UNIX allowed but datagrams denied). A dgram
    # socketpair half accepts sendto/sendmsg with an EXPLICIT
    # destination address, so leaving socketpair unfiltered recreates
    # the destination-bearing datagram primitive those denies exist
    # to remove — without any connect(2) reaching the supervisor.
    # SOCK_STREAM / SOCK_SEQPACKET socketpair stays unfiltered in all
    # postures (see the rule-installation comment below).
    deny_unix_dgram_socketpair = (
        (profile != "frida" and not allow_unix_sockets)
        or unix_scope_export_sock is not None
    )

    # Gap 6: warn once per process when intended blocks silently skip
    # because the syscall isn't defined on this architecture. libseccomp
    # returns a negative value for unresolved names — RISC-V older cores
    # and some cross-compiled builds hit this for specific syscalls. We
    # name the missing ones so operators can decide if the gap is tolerable.
    # (socketpair() is filtered only for the AF_UNIX+SOCK_DGRAM shape —
    # see the rule-installation comment below — so it's reported as
    # "missing" only when that rule was going to be installed.)
    missing = [name for name, num in resolved_blocks if num < 0]
    if socket_num < 0:
        missing.append("socket")
    if ioctl_num < 0:
        missing.append("ioctl")
    if deny_unix_dgram_socketpair and socketpair_num < 0:
        missing.append("socketpair")
    missing += [name for name, num, _arg in send_flag_syscalls
                if num < 0]
    if missing and state.warn_once("_seccomp_arch_missing_warned"):
        logger.warning(
            "Sandbox: seccomp could not resolve syscall(s) %s on this architecture — those blocks are NOT installed. Likely harmless on x86_64/aarch64 (this should be empty); investigate on other architectures if any entries appear.", missing
        )
    # Block AF_UNIX/NETLINK/PACKET via arg 0; block SOCK_RAW via arg 1.
    # "frida" profile: allow AF_UNIX (frida-helper uses Unix sockets for
    # its internal IPC with the target process) but keep NETLINK/PACKET
    # and SOCK_RAW blocked.
    if profile == "frida" or allow_unix_sockets:
        socket_family_blocks = [_AF_NETLINK, _AF_PACKET]
    else:
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
                ret = lib.seccomp_attr_set(ctx, _SCMP_FLTATR_ACT_BADARCH,
                                          _SCMP_ACT_KILL_PROCESS)
                if ret < 0:
                    _os_write(2, b"RAPTOR: seccomp BADARCH attr_set failed -- "
                                 b"refusing to exec without filter\n")
                    os._exit(126)

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
                # Escape primitives never downgrade to allow-and-log:
                # under audit mode the _AUDIT_HARD_DENY_SYSCALLS
                # subset (and the blocked tty ioctls below) keeps the
                # enforcement action while everything else in the
                # blocklist becomes trace-observable. See the constant
                # for the rationale + logging residual.
                hard_deny = _SCMP_ACT_ERRNO(errno_eperm)

                for name, num in resolved_blocks:
                    if num < 0:
                        # Unknown syscall on this arch — harmless to skip
                        continue
                    act = (hard_deny
                           if audit_mode and name in _AUDIT_HARD_DENY_SYSCALLS
                           else deny)
                    null_args = ctypes.POINTER(_ScmpArgCmp)()
                    ret = lib.seccomp_rule_add_array(ctx, act, num, 0, null_args)
                    if ret < 0:
                        _os_write(2, b"RAPTOR: seccomp add_rule failed -- "
                                     b"refusing to exec without filter\n")
                        os._exit(126)

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
                            _os_write(2, b"RAPTOR: seccomp audit rule failed -- "
                                         b"refusing to exec without filter\n")
                            os._exit(126)

                # socket() with blocked family — one rule per family.
                # MASKED_EQ on the low 32 bits, not EQ: the kernel
                # truncates the family to int, so EQ misses
                # `fam | 1<<32` while the kernel still sees `fam`.
                # hard_deny (not deny): the socket-argument rules are
                # escape primitives (docker.sock via AF_UNIX on
                # Landlock-only hosts, host-traffic sniffing via
                # AF_PACKET/SOCK_RAW) and must NOT downgrade to
                # allow-and-log under audit mode — see the
                # _AUDIT_HARD_DENY_SYSCALLS rationale.
                if socket_num >= 0:
                    for fam in socket_family_blocks:
                        arg = _ScmpArgCmp(arg=0, op=_SCMP_CMP_MASKED_EQ,
                                          datum_a=_ARG32_MASK, datum_b=fam)
                        arg_arr = (_ScmpArgCmp * 1)(arg)
                        ret = lib.seccomp_rule_add_array(
                            ctx, hard_deny, socket_num, 1, arg_arr,
                        )
                        if ret < 0:
                            _os_write(2, b"RAPTOR: seccomp socket family rule failed"
                                         b" -- refusing to exec without filter\n")
                            os._exit(126)

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
                        ctx, hard_deny, socket_num, 1, arg_arr,
                    )
                    if ret < 0:
                        _os_write(2, b"RAPTOR: seccomp SOCK_RAW rule failed -- "
                                     b"refusing to exec without filter\n")
                        os._exit(126)

                    # Kernel-bypass stream transports — see the
                    # _IPPROTO_SCTP constant block for the full
                    # rationale (SCTP dodges Landlock's TCP-only port
                    # rules and its CONNECTX setsockopt dodges the
                    # connect-notify supervisor; DCCP/MPTCP share the
                    # not-IPPROTO_TCP gap). Unconditional and
                    # hard_deny: escape-primitive class, must not
                    # downgrade to allow-and-log under audit mode.
                    # (a) protocol-argument denies, family-agnostic:
                    # MASKED_EQ low-32 on arg 2 for the same
                    # high-bit-set reason as the family rules.
                    for proto in (_IPPROTO_SCTP, _IPPROTO_DCCP,
                                  _IPPROTO_MPTCP):
                        arg = _ScmpArgCmp(arg=2, op=_SCMP_CMP_MASKED_EQ,
                                          datum_a=_ARG32_MASK,
                                          datum_b=proto)
                        arg_arr = (_ScmpArgCmp * 1)(arg)
                        ret = lib.seccomp_rule_add_array(
                            ctx, hard_deny, socket_num, 1, arg_arr,
                        )
                        if ret < 0:
                            _os_write(2, b"RAPTOR: seccomp SCTP-family "
                                         b"protocol rule failed -- refusing"
                                         b" to exec without filter\n")
                            os._exit(126)
                    # (b) type-argument denies on AF_INET/AF_INET6:
                    # socket(AF_INET, SOCK_SEQPACKET, 0) defaults to
                    # SCTP and socket(AF_INET, SOCK_DCCP, 0) to DCCP,
                    # so a zero protocol argument would dodge (a).
                    # Family-scoped: AF_UNIX SOCK_SEQPACKET (legit
                    # IPC) is untouched.
                    for fam in (_AF_INET, _AF_INET6):
                        for sock_type in (_SOCK_SEQPACKET, _SOCK_DCCP):
                            args = (_ScmpArgCmp * 2)(
                                _ScmpArgCmp(arg=0, op=_SCMP_CMP_MASKED_EQ,
                                            datum_a=_ARG32_MASK,
                                            datum_b=fam),
                                _ScmpArgCmp(arg=1, op=_SCMP_CMP_MASKED_EQ,
                                            datum_a=_SOCK_TYPE_MASK,
                                            datum_b=sock_type),
                            )
                            ret = lib.seccomp_rule_add_array(
                                ctx, hard_deny, socket_num, 2, args,
                            )
                            if ret < 0:
                                _os_write(2, b"RAPTOR: seccomp SCTP-family"
                                             b" type rule failed -- "
                                             b"refusing to exec without "
                                             b"filter\n")
                                os._exit(126)

                # AF_UNIX connect scoping (enforcement only): route
                # every connect(2) to the parent-side supervisor via
                # SCMP_ACT_NOTIFY. The supervisor executes the connect
                # on the child's behalf (see _unix_scope.py), so no
                # TOCTOU-prone CONTINUE is ever issued. Also deny
                # socket(AF_UNIX, SOCK_DGRAM): datagram
                # sendto-with-address would bypass the connect
                # chokepoint entirely, and nothing sandboxed needs
                # unix datagrams (forkserver and Rust's spawn plumbing
                # are SOCK_STREAM / socketpair).
                if unix_scope_export_sock is not None:
                    if connect_num < 0:
                        _os_write(2, b"RAPTOR: seccomp connect scoping "
                                     b"requested but connect() is "
                                     b"unresolved -- refusing to exec\n")
                        os._exit(126)
                    null_args = ctypes.POINTER(_ScmpArgCmp)()
                    ret = lib.seccomp_rule_add_array(
                        ctx, _SCMP_ACT_NOTIFY, connect_num, 0, null_args,
                    )
                    if ret < 0:
                        _os_write(2, b"RAPTOR: seccomp connect NOTIFY "
                                     b"rule failed -- refusing to exec\n")
                        os._exit(126)
                    if socket_num >= 0:
                        args = (_ScmpArgCmp * 2)(
                            _ScmpArgCmp(arg=0, op=_SCMP_CMP_MASKED_EQ,
                                        datum_a=_ARG32_MASK,
                                        datum_b=_AF_UNIX),
                            _ScmpArgCmp(arg=1, op=_SCMP_CMP_MASKED_EQ,
                                        datum_a=_SOCK_TYPE_MASK,
                                        datum_b=_SOCK_DGRAM),
                        )
                        ret = lib.seccomp_rule_add_array(
                            ctx, deny, socket_num, 2, args,
                        )
                        if ret < 0:
                            _os_write(2, b"RAPTOR: seccomp AF_UNIX DGRAM"
                                         b" rule failed -- refusing to "
                                         b"exec\n")
                            os._exit(126)

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
                            # MASKED_EQ low-32 on the family — see the
                            # blocked-family rules above for why EQ is
                            # bypassable via high-bit-set values.
                            _ScmpArgCmp(arg=0, op=_SCMP_CMP_MASKED_EQ,
                                        datum_a=_ARG32_MASK, datum_b=fam),
                            _ScmpArgCmp(arg=1, op=_SCMP_CMP_MASKED_EQ,
                                        datum_a=_SOCK_TYPE_MASK,
                                        datum_b=_SOCK_DGRAM),
                        )
                        # hard_deny: the UDP block is an operator-
                        # selected exfil control (proxy mode) — it
                        # must not void under audit mode either.
                        ret = lib.seccomp_rule_add_array(
                            ctx, hard_deny, socket_num, 2, args,
                        )
                        if ret < 0:
                            _os_write(2, b"RAPTOR: seccomp UDP block rule failed"
                                         b" -- refusing to exec without filter\n")
                            os._exit(126)

                # socketpair(): only the AF_UNIX + SOCK_DGRAM shape is
                # filtered. SOCK_STREAM / SOCK_SEQPACKET socketpair is
                # DELIBERATELY left alone: it returns two already-
                # connected sockets with NO external address — the
                # "peer" is the other half of the pair — and blocking
                # it breaks Rust's std::process::Command (AF_UNIX
                # socketpair for fork+exec error reporting) and Python
                # multiprocessing. The DGRAM shape is different: Linux
                # permits sendto/sendmsg with an EXPLICIT destination
                # on a connected dgram socket, so a dgram socketpair
                # half can address any reachable pathname/abstract
                # dgram socket directly — recreating the primitive the
                # socket(AF_UNIX, SOCK_DGRAM) denies exist to remove,
                # with no connect(2) ever reaching the supervisor.
                # MASKED_EQ with SOCK_TYPE_MASK on arg 1 so
                # SOCK_CLOEXEC / SOCK_NONBLOCK flag bits can't dodge
                # the rule; MASKED_EQ low-32 on the family (arg 0) for
                # the same reason as the socket() family rules.
                # hard_deny: same escape-primitive rationale as the
                # socket()-argument rules — this must not downgrade to
                # allow-and-log under audit mode.
                if deny_unix_dgram_socketpair and socketpair_num >= 0:
                    args = (_ScmpArgCmp * 2)(
                        _ScmpArgCmp(arg=0, op=_SCMP_CMP_MASKED_EQ,
                                    datum_a=_ARG32_MASK,
                                    datum_b=_AF_UNIX),
                        _ScmpArgCmp(arg=1, op=_SCMP_CMP_MASKED_EQ,
                                    datum_a=_SOCK_TYPE_MASK,
                                    datum_b=_SOCK_DGRAM),
                    )
                    ret = lib.seccomp_rule_add_array(
                        ctx, hard_deny, socketpair_num, 2, args,
                    )
                    if ret < 0:
                        _os_write(2, b"RAPTOR: seccomp socketpair DGRAM"
                                     b" rule failed -- refusing to exec"
                                     b" without filter\n")
                        os._exit(126)

                # MSG_FASTOPEN on the send path: TCP Fast Open performs
                # the connect IN-KERNEL inside sendto/sendmsg — no
                # connect(2) is ever issued, so neither the connect-
                # scoping supervisor nor Landlock CONNECT_TCP evaluates,
                # and a child under allowed_tcp_ports could open (and
                # deliver data on) a TCP connection to any host:port.
                # Nothing in RAPTOR's tool population legitimately uses
                # client-side TFO (a reconnect-latency micro-
                # optimisation), so the flag is denied wholesale for
                # sandboxed children rather than policied per-address.
                # MASKED_EQ on the flag bit alone: any flag combination
                # (or high-bit garnish) containing MSG_FASTOPEN matches.
                # hard_deny: same escape-primitive rationale as the
                # socket()-argument rules — this must not downgrade to
                # allow-and-log under audit mode.
                for _sf_name, _sf_num, _sf_arg in send_flag_syscalls:
                    if _sf_num < 0:
                        continue
                    _sf = _ScmpArgCmp(arg=_sf_arg,
                                      op=_SCMP_CMP_MASKED_EQ,
                                      datum_a=_MSG_FASTOPEN,
                                      datum_b=_MSG_FASTOPEN)
                    _sf_arr = (_ScmpArgCmp * 1)(_sf)
                    ret = lib.seccomp_rule_add_array(
                        ctx, hard_deny, _sf_num, 1, _sf_arr,
                    )
                    if ret < 0:
                        _os_write(2, b"RAPTOR: seccomp MSG_FASTOPEN rule"
                                     b" failed -- refusing to exec"
                                     b" without filter\n")
                        os._exit(126)

                # ioctl(fd, <cmd>, ...) — filter by cmd argument (arg 1).
                # Blocks tty-input injection (TIOCSTI) and two other tty
                # ioctls Docker's default profile rejects (TIOCCONS,
                # TIOCSCTTY). Most ioctl cmds are legitimate (FIONBIO,
                # TIOCGWINSZ, FIONREAD, etc.) — we only filter the
                # known-dangerous list, one rule per cmd value.
                # hard_deny (not deny): these stay ERRNO under audit
                # mode too — TIOCSTI queues keystrokes into the
                # operator's shell; allow-and-log would execute the
                # injection while recording it.
                if ioctl_num >= 0:
                    for cmd_val in _BLOCKED_IOCTL_CMDS:
                        # MASKED_EQ low-32 on cmd — the kernel reads
                        # an unsigned int, so EQ misses
                        # `TIOCSTI | 1<<32` (see _ARG32_MASK).
                        arg = _ScmpArgCmp(arg=1, op=_SCMP_CMP_MASKED_EQ,
                                          datum_a=_ARG32_MASK,
                                          datum_b=cmd_val)
                        arg_arr = (_ScmpArgCmp * 1)(arg)
                        ret = lib.seccomp_rule_add_array(
                            ctx, hard_deny, ioctl_num, 1, arg_arr,
                        )
                        if ret < 0:
                            _os_write(2, b"RAPTOR: seccomp ioctl rule failed -- "
                                         b"refusing to exec without filter\n")
                            os._exit(126)

                ret = lib.seccomp_load(ctx)
                if ret >= 0 and unix_scope_export_sock is not None:
                    # Ship the notify fd to the parent supervisor.
                    # From this instant every connect(2) in this
                    # process blocks until supervised — fail-closed if
                    # the export cannot happen (an unsupervised NOTIFY
                    # filter would hang the child forever instead).
                    _nfd = lib.seccomp_notify_fd(ctx)
                    if _nfd < 0:
                        _os_write(2, b"RAPTOR: seccomp_notify_fd failed"
                                     b" -- refusing to exec\n")
                        os._exit(126)
                    try:
                        import array as _array
                        import socket as _socket
                        unix_scope_export_sock.sendmsg(
                            [b"F"],
                            [(_socket.SOL_SOCKET, _socket.SCM_RIGHTS,
                              _array.array("i", [_nfd]))],
                        )
                        unix_scope_export_sock.close()
                        os.close(_nfd)
                    except OSError:
                        _os_write(2, b"RAPTOR: seccomp notify fd export "
                                     b"failed -- refusing to exec\n")
                        os._exit(126)
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
        except BaseException:  # noqa: BLE001 — fail-closed: abort child on ANY install error
            # Fail-closed on any unexpected exception -- same reason.
            # BaseException so SystemExit / KeyboardInterrupt also
            # route through the safe-exit path rather than letting
            # the child continue with no seccomp.
            _os_write(2, b"RAPTOR: seccomp enforcement failed -- "
                         b"refusing to exec without filter\n")
            os._exit(126)

    return _apply_seccomp
