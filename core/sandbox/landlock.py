"""Landlock filesystem + network + scoping restriction.

Landlock works without mount namespaces, without privileges, and without
AppArmor exceptions. It restricts filesystem access via syscall filtering.

ABI levels (kernel):
- 1 (5.13+)  : basic filesystem write restriction (incl. REMOVE_*)
- 2 (5.19+)  : + REFER (cross-directory rename/link)
- 3 (6.2+)   : + TRUNCATE (O_TRUNC on existing files)
- 4 (6.7+)   : + NET_CONNECT_TCP (TCP allowlist / deny-all fallback)
- 5 (6.10+)  : + IOCTL_DEV (device ioctl restriction)
- 6 (6.12+)  : + scoping (signal + abstract Unix socket isolation)
- 7 (6.15+)  : audit log flags on restrict_self — not used (RAPTOR has
               its own ptrace/seccomp audit pipeline)
- 8          : TSYNC (restrict all threads) — not needed (Landlock is
               always applied in a freshly forked, single-threaded
               child before exec)

We build the access masks at runtime based on the kernel's ABI, so
a newer kernel gives more coverage; an older one degrades cleanly.
"""

import ctypes
import ctypes.util
import errno
import logging
import os
import platform
import stat
from collections.abc import Callable

from . import state
from ._pathpin import ViewAnchoredPath, is_per_process_procfs, open_pinned
from .exit_codes import SANDBOX_EXIT_LANDLOCK_DOWNGRADE

logger = logging.getLogger(__name__)

# Landlock syscall numbers from asm-generic/unistd.h. All post-2011
# architectures use this table. Older archs (i386, arm32) have their own
# tables where these numbers map to different syscalls — skip Landlock there.
_LANDLOCK_ARCH_OK = platform.machine() in (
    "x86_64", "aarch64", "riscv64", "loongarch64", "s390x",
    # NOT mips64 — MIPS n64 ABI offsets syscall numbers by 5000,
    # so 444 would be ENOSYS (harmless) but is architecturally wrong.
)
_SYS_LANDLOCK_CREATE = 444
_SYS_LANDLOCK_ADD_RULE = 445
_SYS_LANDLOCK_RESTRICT = 446

# Linux prctl(2) constants — UAPI-stable. Ref: include/uapi/linux/prctl.h.
_PR_SET_NO_NEW_PRIVS = 38

# ---- Landlock UAPI shape (single source of truth) ----
# Access bits, rule types, and struct layouts from
# /usr/include/linux/landlock.h. Defined ONCE at module level and used
# by BOTH the availability probe (functional self-test) and the
# enforcement closure (_make_landlock_preexec): the probe's whole
# point is to predict whether the closure's install will succeed, so
# the two must be constructed from the same shape — a probe that
# creates a smaller/older-ABI ruleset than the install can pass in an
# environment (e.g. a seccomp supervisor filtering on syscall
# arguments) where the real install then fails.
_LL_EXECUTE = 1 << 0
_LL_WRITE_FILE = 1 << 1
_LL_READ_FILE = 1 << 2
_LL_READ_DIR = 1 << 3
_LL_REMOVE_DIR = 1 << 4
_LL_REMOVE_FILE = 1 << 5
_LL_MAKE_CHAR = 1 << 6
_LL_MAKE_DIR = 1 << 7
_LL_MAKE_REG = 1 << 8
_LL_MAKE_SOCK = 1 << 9
_LL_MAKE_FIFO = 1 << 10
_LL_MAKE_BLOCK = 1 << 11
_LL_MAKE_SYM = 1 << 12
_LL_REFER = 1 << 13      # ABI v2+ (kernel 5.19) — rename/link across dirs
_LL_TRUNCATE = 1 << 14   # ABI v3+ (kernel 6.2)
_LL_IOCTL_DEV = 1 << 15  # ABI v5+ (kernel 6.10) — ioctl on device files

# Network (ABI v4+, kernel 6.7) and scoping (ABI v6+, kernel 6.12).
_LL_NET_CONNECT_TCP = 1 << 1
_LL_SCOPE_ABSTRACT_UNIX_SOCKET = 1 << 0
_LL_SCOPE_SIGNAL = 1 << 1

_LL_RULE_PATH_BENEATH = 1
_LL_RULE_NET_PORT = 2


class _RulesetAttr(ctypes.Structure):
    # Always includes handled_access_net and scoped even on older ABIs.
    # Landlock's forward-compat design accepts extra zero bytes in the
    # struct — the kernel uses the struct size passed to create_ruleset
    # to determine which fields are present.
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
        ("scoped", ctypes.c_uint64),
    ]


class _PathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int),
    ]


class _NetPortAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("port", ctypes.c_uint64),
    ]


def _write_mask_for_abi(abi: int) -> int:
    """The full ABI-gated write mask (see the REMOVE_* rationale at the
    _make_landlock_preexec call site)."""
    mask = (_LL_WRITE_FILE | _LL_REMOVE_DIR | _LL_REMOVE_FILE |
            _LL_MAKE_CHAR | _LL_MAKE_DIR | _LL_MAKE_REG | _LL_MAKE_SOCK |
            _LL_MAKE_FIFO | _LL_MAKE_BLOCK | _LL_MAKE_SYM)
    if abi >= 2:
        mask |= _LL_REFER   # Block rename/link across directories
    if abi >= 3:
        mask |= _LL_TRUNCATE
    if abi >= 5:
        mask |= _LL_IOCTL_DEV
    return mask


def _read_mask() -> int:
    return _LL_READ_FILE | _LL_READ_DIR


def _net_mask_for_abi(abi: int) -> int:
    return _LL_NET_CONNECT_TCP if abi >= 4 else 0


def _scoped_mask_for_abi(abi: int) -> int:
    if abi >= 6:
        return _LL_SCOPE_ABSTRACT_UNIX_SOCKET | _LL_SCOPE_SIGNAL
    return 0


def check_landlock_available() -> bool:
    """Check if Landlock filesystem isolation is available AND functional.

    Two steps:
      1. Ask the kernel for the ABI version via the standard probe call.
         Returns a positive integer on success (the ABI version), negative
         on failure.
      2. Functional self-test: fork a child and walk the ENTIRE install
         sequence the enforcement closure (_make_landlock_preexec) will
         later run, in the same shape — the full 3-field ruleset attr
         with the ABI-gated fs/net/scope masks, at least one
         path_beneath add_rule, prctl(NO_NEW_PRIVS), restrict_self —
         then verify enforcement both ways (denied outside the grant,
         allowed inside it). ANY failure — EPERM, EOPNOTSUPP, ENOSYS,
         a supervisor (seccomp/ptrace/hypervisor) filtering on syscall
         arguments, wrong UAPI bit values, a kernel quirk where
         restrict_self returns 0 but nothing is enforced — means the
         real install would fail or silently not enforce, so the
         answer is "not capable" and callers take their degraded tier
         up front. A probe that exercises LESS than the install (the
         historic 2-field/no-rule shape) reports capable in
         environments where the install then fails, turning a
         clean degradation into a hard fail-closed storm.

    Both steps must pass for Landlock to be considered usable. Result is
    cached for the process — self-test runs once.
    """
    with state._cache_lock:
        if state._landlock_cache is not None:
            return state._landlock_cache > 0

        if not _LANDLOCK_ARCH_OK:
            state._landlock_cache = -1  # type: ignore[assignment]
            logger.debug("Sandbox: Landlock skipped — unknown syscall table for %s", platform.machine())
            return False

        try:
            libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
            # Step 1: ABI probe — landlock_create_ruleset(NULL, 0, version=1).
            # ABI versions start at 1, so <= 0 is the failure test: a
            # zero would otherwise be accepted here but read as
            # unavailable by every later cache check (`cache > 0`) —
            # first call True, every subsequent call False. Treat any
            # non-positive result as unavailable (fail closed,
            # consistently).
            result = libc.syscall(_SYS_LANDLOCK_CREATE, 0, 0, 1)
            if result <= 0:
                state._landlock_cache = -1  # type: ignore[assignment]
                logger.debug("Sandbox: Landlock not available (errno=%d)", ctypes.get_errno())
                return False
            abi = int(result)
        except Exception:  # noqa: BLE001 — any probe failure (missing libc, ctypes quirk) means Landlock is unusable; fail closed to unavailable
            state._landlock_cache = -1  # type: ignore[assignment]
            return False

        # Step 2: Functional self-test in a child process. Must run in a
        # child because Landlock is a one-way restriction on the current
        # task — applying it here would irreversibly restrict the RAPTOR
        # Python process.
        if not _landlock_functional_self_test(abi):
            logger.error(
                "Sandbox: Landlock ABI probe succeeds but the "
                "end-to-end self-test (full-shape ruleset create + "
                "add_rule + restrict_self + enforcement check) failed — "
                "treating as unavailable. Either something between "
                "RAPTOR and the kernel (a seccomp/ptrace supervisor, a "
                "container runtime) blocks part of the install "
                "sequence, or enforcement is silently broken (wrong "
                "UAPI bit values / kernel quirk). Do not rely on "
                "Landlock restrictions until this is resolved."
            )
            state._landlock_cache = -1  # type: ignore[assignment]
            return False

        state._landlock_cache = abi  # type: ignore[assignment]
        logger.debug("Sandbox: Landlock available and functional (ABI version %d)", abi)
        return True


def _landlock_functional_self_test(abi: int) -> bool:
    """Verify the REAL install sequence works and enforces on this host.

    Runs in a forked child: performs the same install the enforcement
    closure (_make_landlock_preexec) performs — full 3-field ruleset
    attr carrying the ABI-gated fs/net/scope masks, one path_beneath
    add_rule (a read+exec grant on a fresh probe directory, the same
    rule shape as the closure's readable-path grants), prctl
    NO_NEW_PRIVS, restrict_self — then verifies enforcement BOTH ways:
    reopening a probe file outside the grant for write and for read
    must fail (EACCES), reading the granted file must succeed (proving
    the add_rule registered, not merely that everything is broken
    shut). Returns True only when the whole sequence succeeds AND
    enforcement is confirmed.

    Why this design:
      - Fork so the parent (RAPTOR) stays unrestricted.
      - Same-shape install: the probe exists to predict the closure's
        install. Any environment that interferes with part of the
        sequence the historic minimal probe didn't exercise (24-byte
        attr create, add_rule, the net/scope fields) produced
        "probe capable, install fails" — a fail-closed storm where a
        consented degraded tier was the correct outcome.
      - Probe artifacts (file + grant dir) are created HERE in the
        parent and cleaned up here too: the full write mask handles
        REMOVE_FILE/REMOVE_DIR, so the restricted child cannot unlink
        its own droppings.
      - Parent reaps the child via waitpid, not via subprocess module —
        we want minimal dependencies during startup.
    """
    import os
    import shutil
    import tempfile

    # libc resolved HERE, pre-fork: find_library("c") can shell out
    # to /sbin/ldconfig, and spawning a subprocess from the forked
    # self-test child of this (possibly multi-threaded) parent is the
    # banned fork-storm pattern — a wedged child would hang the
    # parent's os.read on the verdict pipe indefinitely. None → the
    # child reports 0 (broken), the same fail-safe as the historic
    # load-failure branch.
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    except Exception:  # noqa: BLE001 — any libc-load failure means the test cannot run; fail closed to unavailable
        libc = None

    # Probe artifacts, created PRE-fork in the parent (tempfile.mkstemp
    # gives atomic O_EXCL|O_CREAT creation on an unpredictable path —
    # a predictable-path O_CREAT|O_TRUNC open here would be a
    # symlink-TOCTOU against a same-user planter) and removed in the
    # parent's finally below: the child's full write mask handles
    # REMOVE_FILE/REMOVE_DIR, so post-restrict the child cannot clean
    # up after itself. The artifact dir is tempfile.gettempdir(), NOT
    # a hardcoded "/tmp": it honours TMPDIR, so a host whose /tmp is
    # unwritable/full doesn't lose the whole Landlock tier (point
    # TMPDIR elsewhere), and tests can key their leftover-artifact
    # checks on a private dir instead of racing sibling processes'
    # concurrent probes in a shared namespace.
    #   probe_path — a file OUTSIDE any grant: reopening it for write
    #     and for read after restrict_self must fail.
    #   grant_dir/grant_file — the subtree granted via add_rule:
    #     reading grant_file after restrict_self must SUCCEED.
    probe_path: "str | None" = None
    grant_dir: "str | None" = None
    try:
        try:
            fd, probe_path = tempfile.mkstemp(
                prefix=".raptor_landlock_selftest_",
                dir=tempfile.gettempdir())
            try:
                os.write(fd, b"x")
            finally:
                os.close(fd)
            grant_dir = tempfile.mkdtemp(
                prefix=".raptor_landlock_selftest_grant_",
                dir=tempfile.gettempdir())
            grant_file = os.path.join(grant_dir, "readable")
            fd = os.open(grant_file,
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, b"x")
            finally:
                os.close(fd)
        except OSError:
            return False
        return _fork_and_run_selftest(
            libc, abi, probe_path, grant_dir, grant_file)
    finally:
        if probe_path is not None:
            try:
                os.unlink(probe_path)
            except OSError:
                pass
        if grant_dir is not None:
            shutil.rmtree(grant_dir, ignore_errors=True)


def _fork_and_run_selftest(libc: "ctypes.CDLL | None", abi: int,
                           probe_path: str, grant_dir: str,
                           grant_file: str) -> bool:
    """Fork bookkeeping for the self-test: pipe, fork, verdict byte, reap."""
    import os
    import warnings

    r, w = os.pipe()
    try:
        # Suppress Python 3.12+ DeprecationWarning about multi-threaded
        # fork(). The hazard the warning targets is a forked child
        # blocking on a lock some OTHER thread held at fork time. The
        # child here narrows that exposure rather than eliminating it:
        # it DOES run Python (ctypes struct construction allocates,
        # and os.fork runs CPython's at-fork handlers), but it takes
        # no new imports, resolves no libraries (libc arrived
        # pre-fork), and touches no logging/threading machinery before
        # os._exit. A child that dies anyway surfaces as pipe EOF →
        # DEGRADED (fail-safe); a child that wedges blocks the
        # parent's verdict read (pre-existing shape — hang, never a
        # false 'available'). The standard guidance
        # ("use multiprocessing.spawn") would drag a full interpreter
        # bootstrap into the availability probe.
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore", category=DeprecationWarning,
                message=r".*fork.*may lead to deadlocks.*",
            )
            pid = os.fork()
    except OSError:
        # Both pipe ends leak unless we close them here — the finally
        # below only covers `r` (it expects the child to have closed
        # its inherited `r`, and the parent to have closed `w` right
        # after a successful fork).
        # Fork failures are rare (ENOMEM / nr-limit) but a leaked pipe
        # pair is still two FDs gone until the Python process exits.
        for fd in (r, w):
            try:
                os.close(fd)
            except OSError:
                pass
        return False
    if pid == 0:
        # Child — apply Landlock and test. The whole body is guarded:
        # an uncaught exception (ctypes.ArgumentError from the CDLL
        # syscall, Structure construction TypeError, ...) would
        # otherwise unwind into the duplicated interpreter state and
        # run the parent's atexit handlers / buffered-IO flushes a
        # second time. Swallow and _exit — the parent then reads EOF
        # and correctly reports Landlock unavailable (fail-safe).
        try:
            os.close(r)
            result_code = _run_selftest_in_child(
                libc, abi, probe_path, grant_dir, grant_file)
            os.write(w, bytes([result_code]))
            os.close(w)
        except BaseException:  # noqa: BLE001 — post-fork child must never unwind
            pass
        os._exit(0)
    os.close(w)
    try:
        data = os.read(r, 1)
        return data == b"\x01"
    except OSError:
        return False
    finally:
        # Reap in the finally: an OSError from os.read used to jump
        # straight to the except arm, skipping the waitpid and
        # leaving the self-test child a zombie for the life of the
        # process. The verdict is carried by the pipe byte, not the
        # exit status, so reaping here is correct on every path (the
        # child always _exit(0)s promptly).
        try:
            os.waitpid(pid, 0)
        except OSError:
            pass
        try:
            os.close(r)
        except OSError:
            pass


def _run_selftest_in_child(libc: "ctypes.CDLL | None", abi: int,
                           probe_path: str, grant_dir: str,
                           grant_file: str) -> int:
    """Run the end-to-end Landlock install + enforcement test.

    Executes in the forked child (kept separate from the fork
    bookkeeping): the SAME install sequence _make_landlock_preexec's
    closure performs, built from the same module-level shape — the
    full-mask 3-field ruleset attr, one path_beneath read+exec rule
    (the closure's readable-directory grant shape), NO_NEW_PRIVS,
    restrict_self — then the enforcement checks. Returns 1 on
    confirmed end-to-end capability, 0 on ANY failure. Fork-safe:
    bare syscalls on pre-resolved handles and paths only — libc was
    resolved PRE-fork (find_library can shell out to ldconfig, the
    banned fork-storm pattern), the probe artifacts were created
    pre-fork by the parent.
    """
    import os

    if libc is None:
        return 0

    # Worker-shaped ruleset: everything the enforcement closure can
    # handle on this ABI, in the closure's own struct. handled fs =
    # the ABI-gated write mask + read mask + EXECUTE (the
    # restrict-reads posture — the strictest shape a consumer
    # requests, used verbatim by e.g. the parser-jail worker); net =
    # CONNECT_TCP on ABI>=4 (the deny-all-TCP / port-allowlist lanes);
    # scoped = signal + abstract-unix isolation on ABI>=6.
    attr = _RulesetAttr(
        handled_access_fs=(_write_mask_for_abi(abi) | _read_mask()
                           | _LL_EXECUTE),
        handled_access_net=_net_mask_for_abi(abi),
        scoped=_scoped_mask_for_abi(abi),
    )
    ruleset_fd = libc.syscall(_SYS_LANDLOCK_CREATE, ctypes.byref(attr),
                              ctypes.sizeof(attr), 0)
    if ruleset_fd < 0:
        return 0

    # One path_beneath rule in the closure's readable-directory shape:
    # read+exec on grant_dir. An add_rule failure is FATAL here — in
    # the closure a failed rule merely drops one grant under the
    # global deny, but the probe exists to certify the whole install
    # channel; a supervisor that filters add_rule would otherwise be
    # certified capable and then cripple every real install.
    try:
        dir_fd = os.open(grant_dir, os.O_PATH)
    except OSError:
        os.close(ruleset_fd)
        return 0
    rule = _PathBeneathAttr(
        allowed_access=_read_mask() | _LL_EXECUTE, parent_fd=dir_fd)
    ret = libc.syscall(_SYS_LANDLOCK_ADD_RULE, ruleset_fd,
                       _LL_RULE_PATH_BENEATH, ctypes.byref(rule), 0)
    os.close(dir_fd)
    if ret < 0:
        os.close(ruleset_fd)
        return 0

    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0:
        os.close(ruleset_fd)
        return 0
    ret = libc.syscall(_SYS_LANDLOCK_RESTRICT, ruleset_fd, 0)
    os.close(ruleset_fd)
    if ret < 0:
        return 0

    # Enforcement probe 1: write outside the grant — must be denied.
    try:
        fd = os.open(probe_path, os.O_WRONLY)
        os.close(fd)
        return 0        # Write succeeded = WRITE_FILE enforcement broken.
    except PermissionError:
        pass
    except OSError:
        return 0

    # Enforcement probe 2: read outside the grant — must be denied.
    try:
        fd = os.open(probe_path, os.O_RDONLY)
        os.close(fd)
        return 0        # Read succeeded = READ_FILE enforcement broken.
    except PermissionError:
        pass
    except OSError:
        return 0

    # Enforcement probe 3: read INSIDE the grant — must succeed.
    # Proves the add_rule registered and grants are honoured, not
    # merely that the domain denies everything.
    try:
        fd = os.open(grant_file, os.O_RDONLY)
        os.close(fd)
    except OSError:
        return 0
    return 1


def _get_landlock_abi() -> int:
    """Get the Landlock ABI version. Returns 0 if unavailable."""
    check_landlock_available()  # Ensures cache is populated
    return max(state._landlock_cache or 0, 0)


_scoping_warned = False


def _warn_scoping_unavailable_once(abi: int) -> None:
    """One process-wide notice that Landlock scoping (ABI v6) is
    unavailable, matching the throttled-warning convention of the
    other ABI-gated degradations."""
    global _scoping_warned
    if _scoping_warned:
        return
    _scoping_warned = True
    logger.warning(
        "Landlock scoping unavailable (kernel ABI %d < 6): "
        "abstract-unix-socket and signal isolation are NOT enforced "
        "for sandboxed children on this kernel; filesystem/network "
        "Landlock rules are unaffected.", abi,
    )


_truncate_warned = False


def _warn_truncate_unavailable_once(abi: int) -> None:
    """One process-wide notice that the TRUNCATE access right (ABI v3)
    is unavailable, matching the throttled-warning convention of the
    other ABI-gated degradations. On such kernels truncate(2) /
    open(O_TRUNC) on same-UID files OUTSIDE the writable allowlist
    still succeeds whenever Landlock is the only filesystem barrier
    (mount-ns read-only binds close it with EROFS); the per-run
    posture stamp is ``landlock_truncate_unrestricted`` in
    sandbox_info, next to the metadata-ops stamp."""
    global _truncate_warned
    if _truncate_warned:
        return
    _truncate_warned = True
    logger.warning(
        "Landlock TRUNCATE right unavailable (kernel ABI %d < 3, "
        "pre-6.2): truncation of same-UID files outside the writable "
        "allowlist is NOT restricted in Landlock-only posture on this "
        "kernel; content read/write rules are unaffected. Runs are "
        "stamped landlock_truncate_unrestricted.", abi,
    )


# (requested, resolved) grant redirects already announced — once per
# pair, matching the throttled-warning convention above (a benignly
# symlinked output tree would otherwise warn on every spawn).
_grant_redirects_warned: set = set()

# (requested, kind) per-process procfs grant paths already announced —
# same once-per-pair convention (calibrated CLI profiles carry several
# such entries, which would otherwise log on every spawn).
_per_process_grants_noted: set = set()

# The canonical usrmerge aliases: exactly these top-level directories,
# each a distro-installed symlink to the same-named directory under
# /usr. An exact-match allowlist — never a prefix rule.
_USRMERGE_CANONICAL_GRANTS: frozenset[str] = frozenset(
    {"/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"},
)


def _is_canonical_usrmerge_redirect(
    requested: str,
    resolved: str,
    lstat_fn: Callable[[str], os.stat_result] | None = None,
) -> bool:
    """True iff a grant redirect is the distro's own usrmerge aliasing.

    All three must hold, checked against the live filesystem via
    ``lstat_fn`` (injectable — and late-bound to ``os.lstat`` when
    None — so the predicate is unit-testable without root or a
    usrmerged host):

    1. ``requested`` is exactly one of the canonical top-level
       usrmerge paths (:data:`_USRMERGE_CANONICAL_GRANTS`) — exact
       string match, never a prefix rule;
    2. ``resolved`` is exactly ``/usr/<same basename>``;
    3. the symlink at ``requested`` is itself root-owned
       (``lstat().st_uid == 0``, belt-and-braces).

    An ``OSError`` from ``lstat_fn``, a non-symlink, or a non-root
    owner answers False — the caller keeps warning. Only ``OSError``
    is caught: any other exception from an injected ``lstat_fn``
    propagates (unreachable at the real ``os.lstat`` call site).
    """
    if requested not in _USRMERGE_CANONICAL_GRANTS:
        return False
    if resolved != "/usr" + requested:
        return False
    if lstat_fn is None:
        lstat_fn = os.lstat
    try:
        st = lstat_fn(requested)
    except OSError:
        return False
    return stat.S_ISLNK(st.st_mode) and st.st_uid == 0


def _resolve_grant_paths(paths: list, kind: str) -> list:
    """Resolve rule paths to canonical form at VALIDATION time.

    Runs in the PARENT, when the preexec closure is built — never in
    the forked child at grant time. The child walks each pre-resolved
    canonical string with the symlink-refusing pinned walk
    (core/sandbox/_pathpin.open_pinned), so a symlink planted anywhere
    in the validate/fork/grant window surfaces as ELOOP and the rule
    falls under the global deny instead of silently landing the WRITE
    grant beneath the symlink's target. Resolving in the child (the
    previous shape) left that whole window open, and the planter need
    not be an unconfined same-UID process: a Landlock-confined sibling
    with write access to a shared output tree can create symlinks
    there (MAKE_SYM is in the granted write mask) pointing at trees it
    canNOT write — a steered grant would hand the next sandbox access
    the planter never had.

    A symlink already resolving at validation time is indistinguishable
    from operator intent (usrmerge ``/bin``, symlinked home trees) and
    resolves normally, but the redirect is announced once per
    (requested, resolved) pair so a pre-planted steer is at least
    visible in the run log. The canonical root-owned usrmerge aliases
    are exempt from the announcement (see
    :func:`_is_canonical_usrmerge_redirect`) — the grant semantics are
    identical, only the log noise differs.

    Per-process procfs magic-link paths (``/proc/self/*``,
    ``/proc/thread-self/*``) yield NO rule — see the inline comment
    for why neither the parent-resolved nor any other inode-bound
    grant can be correct for them.
    """
    resolved_paths: list = []
    for path in paths:
        requested = os.path.normpath(os.path.abspath(path))
        if is_per_process_procfs(requested):
            # Per-reader procfs magic links (/proc/self/*,
            # /proc/thread-self/*): the realpath below runs in the
            # PARENT, so the rule would bind the inode of the
            # PARENT's pid dir — granting the sandboxed child this
            # process's files (its maps, cgroup, ...) while never
            # matching the child's own reads, since every process
            # resolves the link to its own pid dir and Landlock rules
            # bind inodes, not path spellings. No per-inode rule is
            # expressible for the class: reads are served by the
            # wholesale /proc grant where the read allowlist carries
            # it, and where /proc reads are deliberately withdrawn
            # (omit_proc_reads) they must stay withdrawn — a
            # parent-pid rule here would quietly re-open the
            # same-UID /proc channel that withdrawal exists to close.
            key = (requested, kind)
            if key not in _per_process_grants_noted:
                _per_process_grants_noted.add(key)
                logger.info(
                    "Landlock %s grant path %s is a per-process procfs "
                    "magic link — skipped (per-reader resolution; "
                    "served by the /proc read grant where present).",
                    kind, requested,
                )
            continue
        if isinstance(path, ViewAnchoredPath):
            # Mount-view-anchored rule (spawn assembly verified this
            # entry against the bind set): the child opens it
            # POST-pivot, where the bind serves the validated inode at
            # exactly this path — a host-view realpath here would
            # re-resolve any symlink SPELLING of the bind target to a
            # destination the view does not carry, failing the rule
            # open and dropping the caller's write grant under the
            # global deny. No redirect announcement either: the bind
            # source pin already validated the inode identity.
            resolved_paths.append(requested)
            continue
        resolved = os.path.realpath(path)
        if resolved != requested:
            # Canonical usrmerge aliasing (/bin -> /usr/bin etc.) is
            # exempt from the announcement — logging policy only, the
            # grant still applies to the resolved tree either way. The
            # fixed set is trust-equivalent because planting one of
            # these symlinks requires replacing a root-owned top-level
            # directory, and an attacker with that power already owns
            # every library and binary the sandbox loads — the threat
            # model is void before the redirect matters; warning on
            # every run on usrmerged distros only trains operators to
            # ignore the warning class. Everything else keeps the
            # warning verbatim: the exemption is exact-match on the
            # canonical names (never a prefix rule), requires the
            # resolved target to be /usr/<same basename>, and requires
            # the symlink itself to be root-owned — so redirects an
            # unprivileged planter CAN place (home trees, shared output
            # dirs, non-/usr targets) are still announced.
            if not _is_canonical_usrmerge_redirect(requested, resolved):
                key = (requested, resolved)
                if key not in _grant_redirects_warned:
                    _grant_redirects_warned.add(key)
                    logger.warning(
                        "Landlock %s grant path %s resolves through a "
                        "symlink to %s — the rule applies to the resolved "
                        "tree. If that symlink is not operator-intended, "
                        "inspect the path for a planted redirect.",
                        kind, requested, resolved,
                    )
        resolved_paths.append(resolved)
    return resolved_paths


def _open_grant_pinned(canonical: str) -> tuple:
    """(fd, is_dir) for a pre-resolved rule path, symlink-refusing.

    Runs POST-fork in the child. ``canonical`` must come from
    :func:`_resolve_grant_paths` in the parent; any symlink met during
    the component walk appeared after that validation and refuses
    (OSError ELOOP). Fork-safe: os/stat syscall wrappers and
    ``open_pinned``, all bound at module import long before any fork —
    no imports, no locks.
    """
    fd = open_pinned(canonical)
    try:
        is_dir = stat.S_ISDIR(os.fstat(fd).st_mode)
    except OSError:
        os.close(fd)
        raise
    return fd, is_dir


class LandlockInstallError(RuntimeError):
    """A requested Landlock policy could not be installed in the child.

    Raised (instead of the async-signal-safe ``os._exit(126)``) when the
    closure is built with ``fail_raise=True`` — the mount-ns spawn
    grandchild's lane, where an ordinary exception reaches the setup-
    status pipe ('L' + reason) and the parent fails LOUD with a typed
    SandboxSetupError. The silent-exit form is kept for the preexec_fn
    lane, where the fork context forbids anything beyond os.write +
    os._exit and the 126 convention is documented in exit_codes.py.
    """


def _make_landlock_preexec(writable_paths: list, allowed_tcp_ports: list | None = None,
                           readable_paths: list | None = None,
                           deny_all_tcp_connect: bool = False,
                           fail_raise: bool = False):
    """Create a preexec_fn that applies Landlock restrictions.

    Filesystem:
      - writes allowed only in `writable_paths`.
      - if `readable_paths` is None (default): reads allowed EVERYWHERE.
        Preserves compatibility with tools that need to #include from
        /usr/..., read /proc/cpuinfo, load shared libraries, etc.
      - if `readable_paths` is provided: reads allowed ONLY in those
        paths plus writable_paths (writes imply reads). Use for
        executing attacker-controlled binaries (PoC exec) where the
        risk of credential-exfil via read-everywhere outweighs the
        tool-compatibility cost.
      - restricted reads also engage EXEC scoping: the EXECUTE right
        (ABI v1) is handled, granted on the readable DIRECTORY rules
        (except /proc and /sys) and on the writable rules, denied
        everywhere else. This makes exec-denial an explicit policy
        rather than a side effect of the exec-open's FMODE_READ, and
        covers the on-filesystem fileless spellings (O_TMPFILE /
        unlinked inodes inherit their directory's hierarchy). It can
        NOT cover memfd — kernel-internal SB_NOUSER mounts are exempt
        from Landlock rules (live-verified) — which is closed at the
        seccomp layer (deny_fd_exec).

    Network (ABI v4+): if allowed_tcp_ports is set, restricts TCP connect
    to those ports only. If `deny_all_tcp_connect` is set (and no port
    allowlist is), CONNECT_TCP is handled with ZERO allow rules — every
    TCP connect (loopback included; Landlock net rules are port-scoped,
    not address-scoped) fails with EACCES. bind/listen and UDP are
    deliberately untouched (see the degraded-mode rationale in
    context.py). When only the connect-deny is requested (no writable
    paths, no read restriction, no port allowlist), the ruleset handles
    ONLY the net access — filesystem semantics stay exactly as without
    Landlock, so a net-only deny never sneaks in fs restrictions.

    Device ioctl (ABI v5+): blanket-denied on all device files.

    Scoping (ABI v6+): signal delivery and abstract Unix socket connections
    restricted to processes within the same Landlock domain. Always-on
    when the kernel supports it.

    fail_raise: fail-closed reporting mode. False (default, preexec_fn
    lane) keeps the async-signal-safe ``os.write(2) + os._exit(126)``
    aborts. True (mount-ns spawn grandchild) raises
    ``LandlockInstallError`` after the stderr line instead, so the
    spawn chain's setup-status pipe reports 'L' + the reason and the
    parent raises a typed SandboxSetupError — pre-fix these aborts
    bypassed the status pipe and surfaced as an unattributed child
    exit 126, indistinguishable from a target that chose that code.
    """
    SYS_create = _SYS_LANDLOCK_CREATE
    SYS_add_rule = _SYS_LANDLOCK_ADD_RULE
    SYS_restrict = _SYS_LANDLOCK_RESTRICT

    RULE_PATH_BENEATH = _LL_RULE_PATH_BENEATH

    # Landlock access bits from /usr/include/linux/landlock.h, shared
    # module-level with the availability probe's self-test (which must
    # install the SAME shape this closure will — see the shape block
    # at the top of the module). They MUST match the kernel's
    # LANDLOCK_ACCESS_FS_* ordering exactly: the kernel reads
    # handled_access_fs as a bitmask, and a wrong bit means we restrict
    # a different operation than we intended. Previous versions of this
    # file had bits shifted by 2 from EXECUTE onwards — reads were
    # never restricted (READ_FILE was miscoded as EXECUTE) and MAKE_SYM
    # was never restricted (shifted off the end of the write mask).
    # Verified against the uapi header on kernel 6.x.
    # EXECUTE (ABI v1, kernel 5.13 — no ABI gate needed beyond Landlock
    # availability) is handled ONLY under restrict_reads (the untrusted
    # / strict posture): exec is then granted exactly where the read
    # allowlist and the writable grants reach, making exec scoping an
    # EXPLICIT policy instead of a side effect of the exec-open's
    # FMODE_READ check. Read-everywhere rulesets leave the bit
    # unhandled (RAPTOR must exec arbitrary target build tools there).
    #
    # HONEST LIMIT (live-verified on kernel 7.0 / ABI 8): Landlock
    # exempts inodes on kernel-internal SB_NOUSER mounts — a
    # memfd_create fd is NOT subject to EXECUTE (or READ) rules, so
    # execve("/proc/self/fd/<memfd>") passes every Landlock layer.
    # The memfd/fileless-exec deny is therefore enforced at the
    # seccomp layer (deny_fd_exec in seccomp.py: memfd_create denied
    # wholesale + execveat AT_EMPTY_PATH denied); this EXECUTE
    # handling covers the on-filesystem spellings (O_TMPFILE and
    # unlinked files inherit their directory's hierarchy and ARE
    # covered, verified live) and decouples exec-denial from the read
    # mask.
    EXECUTE = _LL_EXECUTE
    WRITE_FILE = _LL_WRITE_FILE
    READ_FILE = _LL_READ_FILE
    TRUNCATE = _LL_TRUNCATE

    # REMOVE_DIR / REMOVE_FILE are handled: deletion is only permitted
    # where writing already is (the writable-path grants include the
    # full write mask). Without them, a sandboxed child could unlink or
    # rmdir ANYTHING the user's DAC permits — write-integrity without
    # delete-integrity. An earlier version excluded both, claiming
    # unshare needs to remove namespace dirs and importlib unlinks
    # stale .pyc files during import; neither reproduces (2026-08-15):
    # importlib only unlinks when rewriting a cache file, which already
    # requires write access we grant on the same paths, and the ns
    # bootstrap runs before restrict_self. Verified across a 22-workload
    # toolchain battery (gcc/clang incl. LTO, make clean, cargo clean,
    # cmake+ninja -t clean, meson, autotools distclean, npm, ccache -C,
    # go clean -cache, gradle, git gc --prune, venv, tar) plus the full
    # sandbox suite and binary-oracle e2e — zero regressions; an strace
    # census showed no tool deletes outside its writable set. Known
    # benign residual: CPython multiprocessing's sem_unlink in /dev/shm
    # is denied and leaks a few bytes per run (resource tracker warns
    # and continues).
    # Build mask based on ABI version to avoid EINVAL on older kernels.
    # Ref: https://tuxownia.pl/en/blog/linux-landlock-sandboxing-without-root/
    # Delegates to the module-level shape helpers the availability
    # probe's self-test installs from too.
    def _build_write_mask():
        return _write_mask_for_abi(_get_landlock_abi())

    def _build_read_mask():
        return _read_mask()

    # Read-granted trees that do NOT get the EXECUTE grant under
    # restrict_reads. Nothing legitimately execs from /proc or /sys,
    # and for /proc the grant would be inert anyway: exec through a
    # /proc/<pid>/fd or /proc/<pid>/exe magic link is checked against
    # the RESOLVED file's own hierarchy, never against /proc's.
    # Matching is on the parent-resolved canonical rule path (exact or
    # beneath), so the default context.py allowlist entries are caught
    # regardless of how the caller spelled them.
    _NOEXEC_READ_GRANTS = ("/proc", "/sys")

    def _exec_exempt(canonical: str) -> bool:
        return any(canonical == p or canonical.startswith(p + "/")
                   for p in _NOEXEC_READ_GRANTS)

    # Landlock network constants (ABI v4+, kernel 6.7)
    LANDLOCK_ACCESS_NET_CONNECT_TCP = _LL_NET_CONNECT_TCP
    RULE_NET_PORT = _LL_RULE_NET_PORT

    # Struct layouts shared module-level with the probe's self-test —
    # same forward-compat rationale (see _RulesetAttr).
    RulesetAttr = _RulesetAttr
    PathBeneathAttr = _PathBeneathAttr
    NetPortAttr = _NetPortAttr

    paths = list(writable_paths)  # capture for closure
    ports = list(allowed_tcp_ports) if allowed_tcp_ports else None
    # readable_paths=None -> reads everywhere (current default). Empty
    # list [] would mean "only readable where also writable" which is
    # extremely restrictive; we treat empty as "reads are restricted to
    # writable_paths only" (intentional — use [...] explicitly to add
    # system dirs).
    restrict_reads = readable_paths is not None
    read_paths = list(readable_paths) if readable_paths else []

    # Capture ABI version NOW (in the parent) so the preexec_fn closure
    # doesn't need to call _get_landlock_abi() in the forked child
    _abi = _get_landlock_abi()
    _write_access = _build_write_mask()
    _read_access = _build_read_mask() if restrict_reads else 0
    # EXECUTE rides the restrict_reads posture: the untrusted / strict
    # read allowlist doubles as the exec allowlist (writable grants —
    # output, the /tmp baseline — carry it too, so compile-and-run
    # PoC/conftest shapes keep working; see the rule sites below).
    # Read-everywhere rulesets keep exec unhandled — trusted lanes are
    # byte-identical. ABI v1 bit; no version gate needed.
    _exec_access = EXECUTE if restrict_reads else 0
    # handled_access_fs is the SET of accesses the ruleset governs —
    # any access bit NOT set here is allowed unrestricted. We add read
    # bits only when restrict_reads is on; otherwise reads stay wide.
    # Net-only deny (no writable paths, no reads restriction, no port
    # allowlist): handle NO fs accesses at all, so the ruleset governs
    # only TCP connect and filesystem behaviour is untouched.
    _net_only = (deny_all_tcp_connect and not paths
                 and not restrict_reads and ports is None)
    _handled_fs = (0 if _net_only
                   else (_write_access | _read_access | _exec_access))
    # ABI < 3 (pre-6.2): the TRUNCATE right doesn't exist, so the
    # handled write mask silently lacks it — announce the degradation
    # once whenever this ruleset actually governs filesystem writes,
    # mirroring the scoping (ABI 6) treatment above. The per-run
    # sandbox_info stamp (landlock_truncate_unrestricted) is applied
    # at the context layer next to the metadata-ops stamp.
    if _handled_fs and 1 <= _abi < 3:
        _warn_truncate_unavailable_once(_abi)
    _net_access = (
        LANDLOCK_ACCESS_NET_CONNECT_TCP
        if ((ports is not None or deny_all_tcp_connect) and _abi >= 4)
        else 0
    )
    _scoped = _scoped_mask_for_abi(_abi)
    if not _scoped and _abi >= 1:
        # Every other ABI-gated feature announces itself when it
        # degrades; scoping silently no-oping left operators on
        # ABI 4-5 kernels believing abstract-unix-socket + signal
        # isolation was active. Once per process — the gap is a host
        # property, not per-call news.
        _warn_scoping_unavailable_once(_abi)

    # Capture references to os syscalls up-front — the closure runs
    # POST-fork in the child. Doing `import os` inside the child risks
    # deadlock if another thread in the parent held Python's import lock
    # at fork time. Module-level `os` was imported long before any fork
    # happens, so we just take stable references.
    _os_open = os.open
    _os_close = os.close
    _os_write = os.write
    _O_PATH = os.O_PATH
    _ENOTDIR = errno.ENOTDIR
    # Grant-open pinning: writable/readable rule paths are the same
    # attacker-adjacent names as the mount-ns bind sources (a shared
    # output tree, readable paths inside the scanned repo). Resolve
    # them to canonical form NOW — in the parent, at validation time —
    # and let the child walk the pre-resolved string with the
    # symlink-refusing pinned walk (core/sandbox/_pathpin.open_pinned).
    # A symlink planted anywhere between this resolution and the
    # add_rule (the whole fork/spawn window included) surfaces as
    # ELOOP and the rule falls under the global deny, instead of
    # silently landing a WRITE grant beneath the symlink's target.
    # See _resolve_grant_paths for why child-side realpath was not
    # enough (a Landlock-confined sibling planter gains access it
    # never had). References captured in the parent for fork-safety.
    _open_grant = _open_grant_pinned
    _resolved_writable = _resolve_grant_paths(paths, "writable")
    _resolved_readable = _resolve_grant_paths(read_paths, "readable")

    # Same rationale for libc: `ctypes.util.find_library("c")` on Linux
    # can shell out to `/sbin/ldconfig`, spawning a subprocess from the
    # forked child — a fork-storm pattern that has deadlocked real code.
    # Resolve in the parent, share the CDLL handle with the child.
    _libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

    # Parent-side probe verdict, captured at BUILD time (cached — no
    # extra syscalls) so the child's create-failure diagnosis states
    # what actually happened. This builder is invoked on kernels WHOSE
    # PROBE FAILED too: when the resolved containment floor requires
    # the Landlock layer (landlock_required), _spawn builds the
    # ruleset regardless of availability so the spawn fails CLOSED
    # instead of delivering an unconsented weaker tier. Pre-fix the
    # child's message unconditionally claimed "a kernel whose probe
    # succeeded" — on a Landlock-less host that misdirected the
    # operator toward a kernel anomaly when the real story is
    # "kernel lacks Landlock + the policy refuses to run without it".
    _kernel_probe_ok = check_landlock_available()
    # WSL remedy hint, resolved in the PARENT for the same fork-safety
    # reason as everything above (is_wsl caches a /proc read; the
    # child must not do fresh imports or I/O). On a WSL host the
    # fail-closed message below additionally names the standing
    # host-scoped consent ceremony — stock WSL2 kernels are the
    # common Landlock-less shape, and the generic remedies alone send
    # WSL operators kernel-building when a documented consent path
    # exists (docs/wsl.md covers both).
    _wsl_consent_hint = ""
    if not _kernel_probe_ok:
        try:
            from core.startup.wsl import is_wsl as _is_wsl
            if _is_wsl():
                _wsl_consent_hint = (
                    " This looks like a WSL host: stock WSL2 kernels "
                    "ship without Landlock — see docs/wsl.md for the "
                    "kernel recipe, or grant the standing host-scoped "
                    "ns-only consent at your terminal: "
                    "`bin/raptor wsl-consent grant` (TTY-gated)."
                )
        except Exception:  # noqa: BLE001 — a hint probe must never break the builder
            logger.debug("WSL consent-hint probe failed", exc_info=True)

    def _apply_landlock():
        try:
            libc = _libc

            attr = RulesetAttr(handled_access_fs=_handled_fs,
                               handled_access_net=_net_access,
                               scoped=_scoped)
            fd = libc.syscall(SYS_create, ctypes.byref(attr), ctypes.sizeof(attr), 0)
            if fd < 0:
                # The ruleset cannot be installed at all — the child
                # would proceed without filesystem-write or net-bind
                # restrictions. Fail-closed either way: the parent
                # expected an enforced sandbox, so silently
                # downgrading is a contract violation. TWO distinct
                # stories share this branch (see _kernel_probe_ok):
                # a kernel whose probe succeeded failing here is an
                # anomaly worth investigating; a kernel whose probe
                # FAILED reaches here because the call's containment
                # floor requires the Landlock layer and refusing to
                # run is the consented outcome. Say which one it is.
                _os_write(2, b"sandbox: landlock: SYS_landlock_create_ruleset failed post-fork\n")
                if fail_raise:
                    if _kernel_probe_ok:
                        msg = ("Landlock ruleset creation failed "
                               "post-fork (SYS_landlock_create_ruleset "
                               "returned an error for a kernel whose "
                               "probe succeeded)")
                    else:
                        msg = ("Landlock ruleset creation failed "
                               "post-fork: this kernel has no usable "
                               "Landlock (the availability probe "
                               "already failed) and the call's "
                               "resolved containment floor requires "
                               "the Landlock layer, so the spawn "
                               "fails closed rather than run without "
                               "the requested policy. Use a kernel "
                               ">= 5.13 with Landlock enabled, or a "
                               "containment floor that admits the "
                               "ns-only tier." + _wsl_consent_hint)
                    raise LandlockInstallError(msg)
                os._exit(SANDBOX_EXIT_LANDLOCK_DOWNGRADE)

            try:
                # Filesystem rules: allow writes (and if restrict_reads
                # is on, also reads) to specified paths. Non-zero return
                # from SYS_add_rule means the rule didn't register —
                # that path will fall under the global deny. Log to
                # stderr (fork-safe) so users can correlate an unexpected
                # "Permission denied" build failure with a specific rule-
                # registration failure.
                # Writable paths also get read access implicitly — if
                # restrict_reads is on, including READ_FILE|READ_DIR in
                # the rule means the child can both read and write these
                # paths. If restrict_reads is off, _read_access is 0 and
                # the rule is identical to the old write-only rule.
                # Exec too (restrict_reads only): output and the /tmp
                # baseline are where PoCs and conftest-style probes are
                # compiled AND run — withholding EXECUTE there breaks
                # every compile-and-run caller. Accepted residual,
                # stated: a sandboxed payload can write a binary under
                # a writable grant and exec it — but that artifact is
                # ON the filesystem under the run's own trees
                # (auditable, swept at teardown), unlike the anonymous
                # memfd image the seccomp deny_fd_exec layer refuses.
                writable_access = _write_access | _read_access | _exec_access
                for path in _resolved_writable:
                    try:
                        # Pinned open of the parent-resolved canonical
                        # path (symlink-swap refusing) — see
                        # _resolve_grant_paths. Non-directories keep
                        # the historical ENOTDIR refusal: a writable
                        # rule is a subtree grant.
                        dir_fd, _is_dir = _open_grant(path)
                        try:
                            if not _is_dir:
                                raise OSError(_ENOTDIR, path)
                            rule = PathBeneathAttr(allowed_access=writable_access,
                                                   parent_fd=dir_fd)
                            ret = libc.syscall(SYS_add_rule, fd, RULE_PATH_BENEATH,
                                               ctypes.byref(rule), 0)
                            if ret < 0:
                                _os_write(2, b"sandbox: Landlock add_rule failed for a writable path\n")
                        finally:
                            _os_close(dir_fd)
                    except (OSError, ValueError):
                        # Name the failing path — a bare message is
                        # unattributable when several grants are in
                        # play, and the line surfaces in the CHILD's
                        # stderr where consumers read tool output.
                        _os_write(2, b"sandbox: Landlock writable path "
                                     b"could not be opened: "
                                  + os.fsencode(path) + b"\n")

                # Writable device files — /dev/null is the bit-bucket that
                # shell scripts universally use (`cmd >/dev/null 2>&1`).
                # Without this, any tool whose wrapper script redirects
                # stderr/stdout to /dev/null fails with EACCES even though
                # the write has no effect.
                # We deliberately do NOT grant /dev wholesale: that would
                # include /dev/shm (cross-sandbox POSIX shm visibility)
                # which is the existing gap on hosts without mount-ns.
                # Reads to /dev/zero, /dev/urandom, /dev/random etc. work
                # regardless because Landlock's default is read-everywhere;
                # writes to those devices are virtually never legitimate
                # (they're sources, not sinks) so we don't grant them
                # write access.
                # /dev/tty is included for clarity but is a no-op in
                # practice — the child has no controlling tty in our PID
                # ns, so open("/dev/tty") returns ENXIO at the VFS layer
                # before Landlock even sees it.
                # Uses path_beneath with a file fd (O_PATH without
                # O_DIRECTORY) — Landlock accepts path_beneath on files
                # since ABI v1 and the rule applies only to that exact
                # inode.
                # File-only access mask — directory-specific bits
                # (MAKE_*, REMOVE_*, REFER) return EINVAL when added via
                # path_beneath with a file fd. Keep only WRITE_FILE (+
                # TRUNCATE on ABI v3+, since truncate is a file op;
                # REFER isn't applicable to files at all).
                dev_access = WRITE_FILE
                if _abi >= 3:
                    dev_access |= TRUNCATE
                # READ_FILE only if we're restricting reads (otherwise
                # reads to dev files work via the read-everywhere
                # default) — including it doesn't hurt but is a no-op
                # when _read_access==0.
                dev_access |= _read_access & READ_FILE

                # Net-only ruleset (_handled_fs == 0): no fs accesses are
                # handled, so writes to /dev/null work without a rule —
                # and adding one whose bits aren't in the handled mask
                # would EINVAL. Skip the device rules entirely.
                for dev_path in (("/dev/null", "/dev/tty")
                                 if _handled_fs else ()):
                    try:
                        dev_fd = _os_open(dev_path, _O_PATH)
                        try:
                            rule = PathBeneathAttr(allowed_access=dev_access,
                                                   parent_fd=dev_fd)
                            ret = libc.syscall(SYS_add_rule, fd, RULE_PATH_BENEATH,
                                               ctypes.byref(rule), 0)
                            if ret < 0:
                                _os_write(2, b"sandbox: Landlock add_rule failed for a writable device\n")
                        finally:
                            _os_close(dev_fd)
                    except OSError:
                        # Device may not exist on minimal container images
                        # — non-fatal, just skip.
                        pass

                # Read-only device file rules (only under restrict_reads).
                # The context.py default read-allowlist excludes /dev as a
                # whole to keep /dev/shm out of scope — individual safe
                # /dev files are granted here instead. Tools typically
                # need /dev/urandom (libc/crypto init), /dev/random,
                # /dev/zero, /dev/full for entropy / discard / testing.
                # /dev/stdin, /dev/stdout, /dev/stderr, /dev/fd all
                # resolve to /proc/self/fd symlinks covered by the
                # /proc read-rule already; no separate grant needed.
                if restrict_reads and _read_access:
                    dev_read_access = READ_FILE
                    for dev_path in ("/dev/null", "/dev/zero", "/dev/full",
                                     "/dev/random", "/dev/urandom",
                                     "/dev/tty"):
                        try:
                            dev_fd = _os_open(dev_path, _O_PATH)
                            try:
                                rule = PathBeneathAttr(
                                    allowed_access=dev_read_access,
                                    parent_fd=dev_fd,
                                )
                                libc.syscall(SYS_add_rule, fd, RULE_PATH_BENEATH,
                                             ctypes.byref(rule), 0)
                            finally:
                                _os_close(dev_fd)
                        except OSError:
                            pass

                # Read-only path rules (restrict_reads mode only). Each
                # rule grants read access but NOT write — gcc can
                # #include from /usr/include, ld.so can map libc.so.6,
                # /etc/ld.so.cache is readable, etc., but writes to
                # these paths fall under global deny.
                #
                # Paths can be either directories (rule covers the whole
                # subtree) or individual files (rule covers only that
                # inode). We try O_DIRECTORY first; on ENOTDIR we retry
                # as a file and switch to a file-only access mask —
                # path_beneath on a file-fd rejects directory-only bits
                # (READ_DIR/MAKE_*/REMOVE_*/REFER) with EINVAL. Per-file
                # rules are used for narrowing /proc (cpuinfo, meminfo,
                # etc.) without granting wholesale /proc access that
                # would expose /proc/<host_pid>/environ for credential
                # exfil in Landlock-only mode.
                if restrict_reads and _read_access:
                    _read_file_access = _read_access & READ_FILE
                    for path in _resolved_readable:
                        try:
                            # Pinned open of the parent-resolved
                            # canonical path (symlink-swap refusing) —
                            # see _resolve_grant_paths. Directory rules
                            # keep the full read mask; files get the
                            # file-only mask (READ_FILE, no READ_DIR),
                            # matching the historical two-step open.
                            # Directory grants carry EXECUTE (the read
                            # allowlist IS the exec allowlist: system
                            # toolchain trees, target build scripts,
                            # tool_paths interpreters) except /proc
                            # and /sys — see _NOEXEC_READ_GRANTS.
                            # Per-FILE read grants stay exec-less:
                            # none of them (dev nodes, the /etc
                            # minimal files) is a legitimate exec
                            # target.
                            path_fd, _is_dir = _open_grant(path)
                            if _is_dir:
                                access = _read_access | (
                                    0 if _exec_exempt(path)
                                    else _exec_access)
                            else:
                                access = _read_file_access
                            try:
                                rule = PathBeneathAttr(allowed_access=access,
                                                       parent_fd=path_fd)
                                ret = libc.syscall(SYS_add_rule, fd, RULE_PATH_BENEATH,
                                                   ctypes.byref(rule), 0)
                                if ret < 0:
                                    _os_write(2, b"sandbox: Landlock add_rule failed for a readable path\n")
                            finally:
                                _os_close(path_fd)
                        except (OSError, ValueError):
                            # Read path may not exist on all hosts (e.g.
                            # /sbin on usrmerge systems) — non-fatal.
                            _os_write(2, b"sandbox: Landlock readable path "
                                         b"could not be opened (skipped): "
                                      + os.fsencode(path) + b"\n")

                # Network rules: allow TCP connect to specified ports only (ABI v4+)
                if ports is not None and _net_access > 0:
                    for port in ports:
                        rule = NetPortAttr(allowed_access=LANDLOCK_ACCESS_NET_CONNECT_TCP,
                                          port=port)
                        ret = libc.syscall(SYS_add_rule, fd, RULE_NET_PORT,
                                           ctypes.byref(rule), 0)
                        if ret < 0:
                            _os_write(2, b"sandbox: Landlock TCP port allow-rule failed\n")

                # prctl(PR_SET_NO_NEW_PRIVS, 1) -- required before restrict_self.
                # NO_NEW_PRIVS is a hard prereq; if it fails, so will
                # restrict_self. check_landlock_available() returned True
                # before we got here, so a failure at this point is
                # anomalous. Fail-closed rather than silently running
                # the child without isolation.
                prctl_ret = libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
                if prctl_ret < 0:
                    _os_write(2, b"sandbox: prctl(PR_SET_NO_NEW_PRIVS) failed -- aborting sandboxed exec\n")
                    if fail_raise:
                        msg = "prctl(PR_SET_NO_NEW_PRIVS) failed"
                        raise LandlockInstallError(msg)
                    os._exit(126)
                result = libc.syscall(SYS_restrict, fd, 0)
                if result < 0:
                    # Same fail-closed rationale -- don't silently run
                    # the child with weaker isolation than the caller
                    # expected. os.write + os._exit are async-signal-
                    # safe; Python logging is NOT safe here because a
                    # parent thread may hold logging locks at fork time.
                    _os_write(2, b"sandbox: Landlock restrict_self failed -- aborting sandboxed exec\n")
                    if fail_raise:
                        msg = "Landlock restrict_self failed"
                        raise LandlockInstallError(msg)
                    os._exit(126)
            finally:
                # Runs on the success path AND on the fail_raise arm
                # (LandlockInstallError propagates through this
                # finally); os._exit skips it, where the kernel
                # reclaims the fd anyway.
                _os_close(fd)
        except Exception:  # noqa: BLE001 — fail-closed by design: ANY exception here means the isolation guarantee is broken
            # Any unexpected exception during Landlock installation
            # means the caller's isolation guarantee is broken; abort
            # rather than run without Landlock.
            _os_write(2, b"sandbox: Landlock enforcement failed -- aborting sandboxed exec\n")
            if fail_raise:
                raise
            os._exit(126)

    return _apply_landlock
