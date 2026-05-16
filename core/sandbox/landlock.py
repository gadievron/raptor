"""Landlock filesystem + TCP-connect restriction.

Landlock works without mount namespaces, without privileges, and without
AppArmor exceptions. It restricts filesystem access via syscall filtering.

ABI levels (kernel):
- 1 (5.13+)  : basic filesystem write restriction
- 2 (5.19+)  : + REFER (cross-directory rename/link)
- 3 (6.2+)   : + TRUNCATE (O_TRUNC on existing files)
- 4 (6.7+)   : + NET_CONNECT_TCP (TCP allowlist)

We build the write-access mask at runtime based on the kernel's ABI, so
a newer kernel gives more coverage; an older one degrades cleanly.
"""

import ctypes
import ctypes.util
import errno
import logging
import os
import platform

from . import state
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


def check_landlock_available() -> bool:
    """Check if Landlock filesystem isolation is available AND functional.

    Two steps:
      1. Ask the kernel for the ABI version via the standard probe call.
         Returns a positive integer on success (the ABI version), negative
         on failure.
      2. Functional self-test: fork a child, install a minimal Landlock
         ruleset that blocks writes to /proc, and verify the write IS
         blocked. Catches silent breakage like wrong UAPI bit values or
         kernel quirks where restrict_self returns 0 but no restrictions
         actually apply. A "looks green but isn't enforcing" bug is
         strictly worse than "explicitly unavailable".

    Both steps must pass for Landlock to be considered usable. Result is
    cached for the process — self-test runs once.
    """
    with state._cache_lock:
        if state._landlock_cache is not None:
            return state._landlock_cache > 0

        if not _LANDLOCK_ARCH_OK:
            state._landlock_cache = -1
            logger.debug(f"Sandbox: Landlock skipped — unknown syscall table for {platform.machine()}")
            return False

        try:
            libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
            # Step 1: ABI probe — landlock_create_ruleset(NULL, 0, version=1).
            result = libc.syscall(_SYS_LANDLOCK_CREATE, 0, 0, 1)
            if result < 0:
                state._landlock_cache = -1
                logger.debug(f"Sandbox: Landlock not available (errno={ctypes.get_errno()})")
                return False
            abi = int(result)
        except Exception:
            state._landlock_cache = -1
            return False

        # Step 2: Functional self-test in a child process. Must run in a
        # child because Landlock is a one-way restriction on the current
        # task — applying it here would irreversibly restrict the RAPTOR
        # Python process.
        if not _landlock_functional_self_test():
            logger.error(
                "Sandbox: Landlock syscalls succeed but self-test shows "
                "restrictions are NOT enforced — treating as unavailable. "
                "This typically indicates wrong UAPI bit values or a "
                "kernel quirk. Landlock protection is SILENTLY BROKEN; "
                "do not rely on filesystem write restrictions until this "
                "is resolved."
            )
            state._landlock_cache = -1
            return False

        state._landlock_cache = abi
        logger.debug(f"Sandbox: Landlock available and functional (ABI version {abi})")
        return True


def _landlock_functional_self_test() -> bool:
    """Verify Landlock actually enforces restrictions on this kernel.

    Runs in a forked child: installs a Landlock ruleset that restricts
    WRITE_FILE with NO allowed paths, then attempts to open a known
    writable path (/tmp/landlock_selftest_<pid>) for write. If Landlock
    is functional, the open must fail with EACCES. Returns True when
    enforcement is confirmed.

    Why this design:
      - Fork so the parent (RAPTOR) stays unrestricted.
      - Use WRITE_FILE (bit 1) — the kernel's most stable Landlock
        semantic, present since ABI v1. If WRITE_FILE is broken,
        everything else is broken too.
      - Test open(O_WRONLY|O_CREAT) on a fresh path — we create the
        file, set Landlock, then try to reopen. Open should return -1
        with EACCES when enforced; any other outcome signals breakage.
      - Parent reaps the child via waitpid, not via subprocess module —
        we want minimal dependencies during startup.
    """
    import os
    import warnings
    r, w = os.pipe()
    try:
        # Suppress Python 3.12+ DeprecationWarning about multi-threaded
        # fork(). Our post-fork code is fork-safe: the child only does
        # bare syscalls (Landlock test, _exit), no Python objects, no
        # GIL acquisition, no malloc-arena access. The standard guidance
        # ("use multiprocessing.spawn") doesn't apply — we need raw
        # fork to keep the test minimal-dependency at startup.
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore", category=DeprecationWarning,
                message=r".*fork.*may lead to deadlocks.*",
            )
            pid = os.fork()
    except OSError:
        # Both pipe ends leak unless we close them here — the finally
        # below only covers `r` (it expected the child to already have
        # closed `r`, and the parent to have closed `w` at line 133).
        # Fork failures are rare (ENOMEM / nr-limit) but a leaked pipe
        # pair is still two FDs gone until the Python process exits.
        for fd in (r, w):
            try:
                os.close(fd)
            except OSError:
                pass
        return False
    if pid == 0:
        # Child — apply Landlock and test
        os.close(r)
        result_code = _run_selftest_in_child(w)
        os.write(w, bytes([result_code]))
        os.close(w)
        os._exit(0)
    os.close(w)
    try:
        data = os.read(r, 1)
        _, status = os.waitpid(pid, 0)
        # status 0 and data == b"\x01" means success
        return data == b"\x01"
    except OSError:
        return False
    finally:
        try:
            os.close(r)
        except OSError:
            pass


def _run_selftest_in_child(write_fd: int) -> int:
    """Run the Landlock enforcement test in the forked child.

    Returns 1 on confirmed enforcement, 0 on failure/breakage.
    Tests BOTH WRITE_FILE and READ_FILE — if either is silently broken
    (e.g. bit-value drift that matches a different kernel constant),
    the test fails. Kept as a separate function so the child's logic is
    isolated from the fork bookkeeping.
    """
    import os
    import tempfile
    # Use tempfile.mkstemp for atomic O_EXCL|O_CREAT creation on an
    # unpredictable path. The earlier approach (os.open on a per-pid
    # path with O_CREAT|O_TRUNC, no O_EXCL) was a symlink-TOCTOU: a
    # same-user attacker who pre-planted /tmp/.raptor_landlock_selftest_
    # <expected_pid> as a symlink to any user-writable file would get
    # that file truncated and have "x" written to it when the self-test
    # ran. mkstemp picks a random suffix AND opens with O_EXCL, so an
    # existing path (file or symlink) causes fresh retry until unique.
    try:
        fd, test_path = tempfile.mkstemp(
            prefix=".raptor_landlock_selftest_", dir="/tmp"
        )
    except OSError:
        return 0
    # Split the mkstemp/write sequence so a failing write closes the fd
    # AND unlinks the stub. Without this, ENOSPC or a transient I/O
    # error during write would leave behind both an open fd (until gc)
    # and a /tmp/.raptor_landlock_selftest_* stub.
    try:
        os.write(fd, b"x")
    except OSError:
        try:
            os.close(fd)
        except OSError:
            pass
        _cleanup(test_path)
        return 0
    try:
        os.close(fd)
    except OSError:
        pass

    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    except Exception:
        _cleanup(test_path)
        return 0

    class RulesetAttr(ctypes.Structure):
        _fields_ = [("handled_access_fs", ctypes.c_uint64),
                    ("handled_access_net", ctypes.c_uint64)]

    # Bits per the UAPI header — if either drifts, the self-test will
    # detect the failed enforcement and we'll flag Landlock broken.
    WRITE_FILE = 1 << 1
    READ_FILE = 1 << 2
    attr = RulesetAttr(handled_access_fs=WRITE_FILE | READ_FILE,
                       handled_access_net=0)
    fd = libc.syscall(_SYS_LANDLOCK_CREATE, ctypes.byref(attr),
                      ctypes.sizeof(attr), 0)
    if fd < 0:
        _cleanup(test_path)
        return 0

    # Apply restrictions with NO allowed paths — any write or read
    # should be denied.
    libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    ret = libc.syscall(_SYS_LANDLOCK_RESTRICT, fd, 0)
    os.close(fd)
    if ret < 0:
        _cleanup(test_path)
        return 0

    # Probe 1: open for write — must fail with EACCES.
    try:
        fd = os.open(test_path, os.O_WRONLY)
        os.close(fd)
        _cleanup(test_path)
        return 0        # Write succeeded = WRITE_FILE enforcement broken.
    except PermissionError:
        pass
    except OSError:
        _cleanup(test_path)
        return 0

    # Probe 2: open for read — must also fail with EACCES.
    try:
        fd = os.open(test_path, os.O_RDONLY)
        os.close(fd)
        _cleanup(test_path)
        return 0        # Read succeeded = READ_FILE enforcement broken.
    except PermissionError:
        _cleanup(test_path)
        return 1        # Both correctly blocked — enforcement confirmed.
    except OSError:
        _cleanup(test_path)
        return 0


def _cleanup(path: str) -> None:
    import os
    try:
        os.unlink(path)
    except OSError:
        pass


def _get_landlock_abi() -> int:
    """Get the Landlock ABI version. Returns 0 if unavailable."""
    check_landlock_available()  # Ensures cache is populated
    return max(state._landlock_cache or 0, 0)


def _make_landlock_preexec(writable_paths: list, allowed_tcp_ports: list = None,
                           readable_paths: list = None):
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

    Network (ABI v4+): if allowed_tcp_ports is set, restricts TCP connect
    to those ports only.
    """
    SYS_create = _SYS_LANDLOCK_CREATE
    SYS_add_rule = _SYS_LANDLOCK_ADD_RULE
    SYS_restrict = _SYS_LANDLOCK_RESTRICT

    RULE_PATH_BENEATH = 1

    # Landlock access bits from /usr/include/linux/landlock.h. These
    # MUST match the kernel's LANDLOCK_ACCESS_FS_* ordering exactly:
    # the kernel reads handled_access_fs as a bitmask, and a wrong bit
    # means we restrict a different operation than we intended. Previous
    # versions of this file had bits shifted by 2 from EXECUTE onwards
    # — reads were never restricted (READ_FILE was miscoded as EXECUTE)
    # and MAKE_SYM was never restricted (shifted off the end of the
    # write mask). Verified against the uapi header on kernel 6.x.
    EXECUTE = 1 << 0
    WRITE_FILE = 1 << 1
    READ_FILE = 1 << 2
    READ_DIR = 1 << 3
    REMOVE_DIR = 1 << 4
    REMOVE_FILE = 1 << 5
    MAKE_CHAR = 1 << 6
    MAKE_DIR = 1 << 7
    MAKE_REG = 1 << 8
    MAKE_SOCK = 1 << 9
    MAKE_FIFO = 1 << 10
    MAKE_BLOCK = 1 << 11
    MAKE_SYM = 1 << 12
    REFER = 1 << 13      # ABI v2+ (kernel 5.19) — rename/link across dirs
    TRUNCATE = 1 << 14   # ABI v3+ (kernel 6.2)

    # Note: REMOVE_DIR and REMOVE_FILE excluded — unshare needs to remove
    # namespace dirs, and Python's importlib needs to unlink .pyc cache files
    # during module loading. Blocking either prevents basic operation.
    # Build mask based on ABI version to avoid EINVAL on older kernels.
    # Ref: https://tuxownia.pl/en/blog/linux-landlock-sandboxing-without-root/
    def _build_write_mask():
        mask = (WRITE_FILE | MAKE_CHAR |
                MAKE_DIR | MAKE_REG | MAKE_SOCK | MAKE_FIFO |
                MAKE_BLOCK | MAKE_SYM)
        if _get_landlock_abi() >= 2:
            mask |= REFER   # Block rename/link across directories
        if _get_landlock_abi() >= 3:
            mask |= TRUNCATE
        return mask

    def _build_read_mask():
        return READ_FILE | READ_DIR

    # Landlock network constants (ABI v4+, kernel 6.7)
    LANDLOCK_ACCESS_NET_CONNECT_TCP = 1 << 1
    RULE_NET_PORT = 2

    class RulesetAttr(ctypes.Structure):
        # Always includes handled_access_net even on ABI < 4. Landlock's
        # forward-compat design accepts extra zero bytes in the struct.
        _fields_ = [
            ("handled_access_fs", ctypes.c_uint64),
            ("handled_access_net", ctypes.c_uint64),
        ]

    class PathBeneathAttr(ctypes.Structure):
        _fields_ = [
            ("allowed_access", ctypes.c_uint64),
            ("parent_fd", ctypes.c_int),
        ]

    class NetPortAttr(ctypes.Structure):
        _fields_ = [
            ("allowed_access", ctypes.c_uint64),
            ("port", ctypes.c_uint64),
        ]

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
    # handled_access_fs is the SET of accesses the ruleset governs —
    # any access bit NOT set here is allowed unrestricted. We add read
    # bits only when restrict_reads is on; otherwise reads stay wide.
    _handled_fs = _write_access | _read_access
    _net_access = LANDLOCK_ACCESS_NET_CONNECT_TCP if (ports is not None and _abi >= 4) else 0

    # Capture references to os syscalls up-front — the closure runs
    # POST-fork in the child. Doing `import os` inside the child risks
    # deadlock if another thread in the parent held Python's import lock
    # at fork time. Module-level `os` was imported long before any fork
    # happens, so we just take stable references.
    _os_open = os.open
    _os_close = os.close
    _os_write = os.write
    _O_PATH = os.O_PATH
    _O_DIRECTORY = os.O_DIRECTORY
    _ENOTDIR = errno.ENOTDIR

    # Same rationale for libc: `ctypes.util.find_library("c")` on Linux
    # can shell out to `/sbin/ldconfig`, spawning a subprocess from the
    # forked child — a fork-storm pattern that has deadlocked real code.
    # Resolve in the parent, share the CDLL handle with the child.
    _libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

    def _apply_landlock():
        try:
            libc = _libc

            attr = RulesetAttr(handled_access_fs=_handled_fs,
                               handled_access_net=_net_access)
            fd = libc.syscall(SYS_create, ctypes.byref(attr), ctypes.sizeof(attr), 0)
            if fd < 0:
                # Probe succeeded in the parent (check_landlock_available)
                # so the kernel ABI is present. A post-fork syscall failure
                # here means the ruleset cannot be installed at all — the
                # child would proceed without filesystem-write or net-bind
                # restrictions. Fail-closed: the parent expected an enforced
                # sandbox, so silently downgrading is a contract violation.
                _os_write(2, b"RAPTOR: landlock: SYS_landlock_create_ruleset failed post-fork\n")
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
                writable_access = _write_access | _read_access
                for path in paths:
                    try:
                        dir_fd = _os_open(path, _O_PATH | _O_DIRECTORY)
                        try:
                            rule = PathBeneathAttr(allowed_access=writable_access,
                                                   parent_fd=dir_fd)
                            ret = libc.syscall(SYS_add_rule, fd, RULE_PATH_BENEATH,
                                               ctypes.byref(rule), 0)
                            if ret < 0:
                                _os_write(2, b"RAPTOR: Landlock add_rule failed for a writable path\n")
                        finally:
                            _os_close(dir_fd)
                    except OSError:
                        _os_write(2, b"RAPTOR: Landlock writable path could not be opened\n")

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
                if _get_landlock_abi() >= 3:
                    dev_access |= TRUNCATE
                # READ_FILE only if we're restricting reads (otherwise
                # reads to dev files work via the read-everywhere
                # default) — including it doesn't hurt but is a no-op
                # when _read_access==0.
                dev_access |= _read_access & READ_FILE

                for dev_path in ("/dev/null", "/dev/tty"):
                    try:
                        dev_fd = _os_open(dev_path, _O_PATH)
                        try:
                            rule = PathBeneathAttr(allowed_access=dev_access,
                                                   parent_fd=dev_fd)
                            ret = libc.syscall(SYS_add_rule, fd, RULE_PATH_BENEATH,
                                               ctypes.byref(rule), 0)
                            if ret < 0:
                                _os_write(2, b"RAPTOR: Landlock add_rule failed for a writable device\n")
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
                    for path in read_paths:
                        try:
                            try:
                                path_fd = _os_open(path, _O_PATH | _O_DIRECTORY)
                                access = _read_access
                            except OSError as e:
                                if e.errno != _ENOTDIR:
                                    raise
                                # Not a directory — retry as a file. File-only
                                # access mask (READ_FILE), no READ_DIR.
                                path_fd = _os_open(path, _O_PATH)
                                access = _read_file_access
                            try:
                                rule = PathBeneathAttr(allowed_access=access,
                                                       parent_fd=path_fd)
                                ret = libc.syscall(SYS_add_rule, fd, RULE_PATH_BENEATH,
                                                   ctypes.byref(rule), 0)
                                if ret < 0:
                                    _os_write(2, b"RAPTOR: Landlock add_rule failed for a readable path\n")
                            finally:
                                _os_close(path_fd)
                        except OSError:
                            # Read path may not exist on all hosts (e.g.
                            # /sbin on usrmerge systems) — non-fatal.
                            _os_write(2, b"RAPTOR: Landlock readable path could not be opened (skipped)\n")

                # Network rules: allow TCP connect to specified ports only (ABI v4+)
                if ports is not None and _net_access > 0:
                    for port in ports:
                        rule = NetPortAttr(allowed_access=LANDLOCK_ACCESS_NET_CONNECT_TCP,
                                          port=port)
                        ret = libc.syscall(SYS_add_rule, fd, RULE_NET_PORT,
                                           ctypes.byref(rule), 0)
                        if ret < 0:
                            _os_write(2, b"RAPTOR: Landlock TCP port allow-rule failed\n")

                # prctl(PR_SET_NO_NEW_PRIVS, 1) -- required before restrict_self.
                # NO_NEW_PRIVS is a hard prereq; if it fails, so will
                # restrict_self. check_landlock_available() returned True
                # before we got here, so a failure at this point is
                # anomalous. Fail-closed rather than silently running
                # the child without isolation.
                prctl_ret = libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
                if prctl_ret < 0:
                    _os_write(2, b"RAPTOR: prctl(PR_SET_NO_NEW_PRIVS) failed -- aborting sandboxed exec\n")
                    os._exit(126)
                result = libc.syscall(SYS_restrict, fd, 0)
                if result < 0:
                    # Same fail-closed rationale -- don't silently run
                    # the child with weaker isolation than the caller
                    # expected. os.write + os._exit are async-signal-
                    # safe; Python logging is NOT safe here because a
                    # parent thread may hold logging locks at fork time.
                    _os_write(2, b"RAPTOR: Landlock restrict_self failed -- aborting sandboxed exec\n")
                    os._exit(126)
            finally:
                # os._exit skips finally, so this only runs on the
                # success path. Kernel reclaims the fd on _exit.
                _os_close(fd)
        except Exception:
            # Any unexpected exception during Landlock installation
            # means the caller's isolation guarantee is broken; abort
            # rather than run without Landlock.
            _os_write(2, b"RAPTOR: Landlock enforcement failed -- aborting sandboxed exec\n")
            os._exit(126)

    return _apply_landlock
