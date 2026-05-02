"""Mount-namespace setup via ctypes syscalls.

Runs inside a forked child of `_spawn.run_sandboxed()` after the child has
entered a fresh user-ns (via newuidmap-based mapping in the parent) and
acquired CAP_SYS_ADMIN in that ns. Executes BEFORE Landlock is installed,
because landlock_restrict_self() blocks subsequent mount topology changes
on kernel 6.15+.

Architecture summary — see `core/sandbox/_spawn.py` for the full flow:

    parent:          child (forked):
    1. fork ───────▶ 2. os.unshare(USER|NS|IPC|[NET])
    3. newuidmap ──▶ 4. wait for pipe signal
                     5. setup_mount_ns()   ← this module
                     6. install Landlock
                     7. install seccomp
                     8. os.unshare(NEWPID) + fork-into-new-pid-ns
                     9. execvp(cmd)

The module exposes `setup_mount_ns(target, output)` which:
    1. Makes / rprivate so our mounts don't leak back.
    2. Creates a fresh tmpfs at /tmp/.raptor-sbx-<pid> to become the new root.
    3. Bind-mounts system dirs (/usr, /lib, /lib64, /etc, /bin, /sbin)
       read-only into the new root.
    4. rbind-mounts /dev and /sys from the host.
    5. Mounts fresh tmpfs at /run and /tmp for per-sandbox isolation.
    6. Bind-mounts target (read-only) and output (writable) at their
       ORIGINAL absolute paths (no caller argv rewriting needed).
    7. pivot_root onto the new tmpfs.

Shadow-paths that collide with per-ns mounts (/tmp, /dev, etc.) are
skipped — the per-ns mount already serves them.
"""

import ctypes
import os
from typing import Iterable, Optional

# Linux mount(2) flag bits (from <linux/mount.h>). Values match the
# kernel UAPI — do not "fix" without checking <sys/mount.h> on target.
# In particular: MS_PRIVATE = 1<<18 (0x40000), NOT 1<<17 (0x20000 is
# MS_UNBINDABLE). Getting this wrong yields the visible-from-strace
# "MS_UNBINDABLE" on `mount --make-rprivate /` and then EINVAL on
# subsequent bind mounts — the mount-ns is in unbindable propagation
# mode, which rejects bind sources.
MS_RDONLY      = 0x1
MS_REMOUNT     = 0x20
MS_BIND        = 0x1000
MS_REC         = 0x4000
MS_UNBINDABLE  = 0x20000  # 1<<17
MS_PRIVATE     = 0x40000  # 1<<18
MS_SLAVE       = 0x80000  # 1<<19
MS_SHARED      = 0x100000 # 1<<20

# umount2(2) flags.
MNT_DETACH = 0x2

# pivot_root(2) syscall numbers per architecture. glibc provides no
# libc wrapper for pivot_root, so we have to call syscall() directly
# with the right number. Values from <asm-generic/unistd.h> and the
# per-arch syscall tables in the Linux source.
_PIVOT_ROOT_SYSCALL_NR = {
    "x86_64":  155,
    "i386":    217,
    "i686":    217,
    "aarch64": 41,
    "armv7l":  218,
    "armv6l":  218,
    "riscv64": 41,
    "ppc64le": 203,
    "s390x":   217,
}


def _pivot_root_nr() -> int:
    """Resolve the pivot_root syscall number for this architecture.
    Raises NotImplementedError if we don't have a mapping."""
    import platform
    arch = platform.machine()
    try:
        return _PIVOT_ROOT_SYSCALL_NR[arch]
    except KeyError:
        raise NotImplementedError(
            f"mount-ns sandbox: pivot_root syscall number unknown for "
            f"architecture {arch!r} — add to _PIVOT_ROOT_SYSCALL_NR in "
            f"core/sandbox/mount_ns.py (see asm-generic/unistd.h)."
        )

# System directories bind-mounted read-only into the new root. Present-if-
# present: if the host lacks /lib64 the loop silently skips it.
#
# Deliberately excludes /home, /root, /mnt, /media, /srv, /opt, /var —
# they may contain host data the sandbox should not see.
_SYSTEM_RO_DIRS = ("usr", "lib", "lib64", "etc", "bin", "sbin")

# Paths owned by per-ns mounts we create. Target/output bind-mounts that
# equal one of these are skipped so we don't try to stack a bind-mount
# over our own per-ns mount (which generally fails with EPERM or
# "mount point does not exist").
_SHADOW_PATHS = frozenset((
    "/", "/dev", "/proc", "/sys", "/run", "/tmp",
    *(f"/{d}" for d in _SYSTEM_RO_DIRS),
))

# Resolve libc via ctypes.util.find_library so we cope with glibc's
# "libc.so.6" soname on Debian/Ubuntu AND musl's "libc.musl-*.so.1" on
# Alpine. Hardcoding "libc.so.6" would make module import fail on
# musl-based distros — and because every caller of core.sandbox.run()
# ultimately imports _spawn → mount_ns, that import failure escapes
# the graceful-degrade logic in context.py (which only catches
# FileNotFoundError / RuntimeError, not the OSError raised by CDLL on
# a missing soname). find_library returns None on failure, which CDLL
# also rejects — but it rejects consistently with "no libc at all",
# not "wrong libc name on this distro".
import ctypes.util as _ctypes_util
_libc = ctypes.CDLL(_ctypes_util.find_library("c"), use_errno=True)


def _mount(source: Optional[str], target: str,
           fs_type: Optional[str], flags: int = 0,
           data: Optional[str] = None) -> None:
    """Thin wrapper around mount(2). Raises OSError on failure."""
    src = source.encode() if source else None
    tgt = target.encode()
    fst = fs_type.encode() if fs_type else None
    dat = data.encode() if data else None
    r = _libc.mount(src, tgt, fst, flags, dat)
    if r != 0:
        err = ctypes.get_errno()
        raise OSError(
            err,
            f"mount({source!r}, {target!r}, {fs_type!r}, "
            f"flags={flags:#x}): {os.strerror(err)}",
        )


def _pivot_root(new_root: str, put_old: str) -> None:
    """pivot_root(2) wrapper. Raises OSError on failure,
    NotImplementedError on unknown arch."""
    r = _libc.syscall(_pivot_root_nr(),
                      new_root.encode(), put_old.encode())
    if r != 0:
        err = ctypes.get_errno()
        raise OSError(
            err,
            f"pivot_root({new_root!r}, {put_old!r}): {os.strerror(err)}",
        )


def _umount(target: str, flags: int = 0) -> None:
    """umount2(2) wrapper. Non-raising — umount is best-effort cleanup."""
    _libc.umount2(target.encode(), flags)


def _shadows_per_ns(path: str) -> bool:
    """Return True if `path` is served by one of our per-ns mounts."""
    norm = path.rstrip("/") or "/"
    return norm in _SHADOW_PATHS


def setup_mount_ns(target: Optional[str], output: Optional[str],
                   extra_ro_paths: Optional[Iterable[str]] = None,
                   root_path: Optional[str] = None) -> None:
    """Establish pivot_root'd tmpfs sandbox root.

    Must be called AFTER the child has entered the new user-ns and acquired
    CAP_SYS_ADMIN (via the parent's newuidmap setup), and BEFORE
    landlock_restrict_self() — Landlock blocks mount operations on kernel
    6.15+.
    """
    # Absolutize target/output BEFORE any bind-mount work. A relative
    # path here produces a malformed bind-target like
    # "/root_path" + "out/X" → "/root_pathout/X" (no slash separator,
    # wrong tree). Companion to the absolutize in
    # core/sandbox/context.py at writable_paths construction —
    # WITHOUT this, the writable_paths Landlock rule references the
    # absolutized path while the bind-mount happens at the malformed
    # path → Landlock rejects-open the writable rule with "Landlock
    # writable path could not be opened" + the child can't write to
    # output even via fallback. Discovered by E2E scan against
    # /tmp/vulns where output= was passed relative.
    if target:
        target = os.path.abspath(target)
    if output:
        output = os.path.abspath(output)
    # 1. Make propagation private — our mounts do not leak back.
    _mount(None, "/", None, MS_REC | MS_PRIVATE)

    # 2. Fresh tmpfs to become the new root. Either caller provides the
    # path (typical: parent pre-created via tempfile.mkdtemp so the
    # name is random and a same-UID attacker can't pre-plant the stub
    # as a symlink to an interesting target), or fall back to a
    # pid-based name for standalone use.
    if root_path:
        root = root_path
    else:
        root = f"/tmp/.raptor-sbx-{os.getpid()}"
        os.makedirs(root, exist_ok=True)
    _mount("tmpfs", root, "tmpfs", 0, "mode=755")

    # 3. Create standard-dir mount points in the new tmpfs root. We own
    # the tmpfs inodes here so mkdir is not blocked by host-/ ACL
    # (which was the failure mode of the legacy mount_script).
    for d in (*_SYSTEM_RO_DIRS, "dev", "proc", "sys", "run", "tmp"):
        os.makedirs(f"{root}/{d}", exist_ok=True)

    # 4. Bind system dirs read-only. Two-step bind + remount-ro because
    # one-step `--bind -o ro` sometimes fails with EPERM on unprivileged
    # user-ns — the ro attribute can only be set by a subsequent remount.
    for d in _SYSTEM_RO_DIRS:
        host_dir = f"/{d}"
        if not os.path.isdir(host_dir):
            continue
        inside = f"{root}/{d}"
        _mount(host_dir, inside, None, MS_BIND)
        _mount(host_dir, inside, None, MS_REMOUNT | MS_BIND | MS_RDONLY)

    # 5. /dev and /sys: recursive bind from host. A minimal /dev would
    # be more conservative but real tools (ASAN, glibc, curl) need
    # /dev/null, /dev/urandom, /dev/tty, /dev/pts etc.; narrowing breaks
    # in subtle ways. rbind + Landlock narrowing is the practical
    # compromise.
    _mount("/dev", f"{root}/dev", None, MS_BIND | MS_REC)
    _mount("/sys", f"{root}/sys", None, MS_BIND | MS_REC)

    # 6. /proc: bind host /proc. Fresh procfs would require a pid-ns
    # which we haven't entered yet at this point. Host pids remain
    # visible in /proc listings — accepted residual (matches
    # Landlock-only mode behaviour).
    _mount("/proc", f"{root}/proc", None, MS_BIND | MS_REC)

    # 7. /tmp and /run: fresh tmpfs per sandbox. This is the main
    # isolation win over Landlock-only — per-sandbox /tmp closes the
    # cross-sandbox symlink-race class.
    _mount("tmpfs", f"{root}/tmp", "tmpfs")
    _mount("tmpfs", f"{root}/run", "tmpfs")

    # 8. Bind target and output at their ORIGINAL absolute paths.
    # After pivot_root, the child still refers to /tmp/vulns (or whatever
    # the caller passed) — no argv rewriting needed. If the caller's
    # path is one we've already served via a per-ns mount, skip so we
    # don't fight our own stack.
    if target and not _shadows_per_ns(target):
        inside = f"{root}{target}"
        os.makedirs(inside, exist_ok=True)
        _mount(target, inside, None, MS_BIND)
        # Remount-bind-ro is best-effort. The kernel rejects remount-ro
        # with EPERM when the source filesystem isn't owned by our
        # user-ns (common when target is under the HOST's /tmp tmpfs
        # and our sandbox also has a fresh tmpfs at /tmp — stacking
        # rules interact). Landlock enforces read-only on target at
        # the filesystem-access layer independently, so the ro mount
        # flag is defence-in-depth rather than the primary control.
        try:
            _mount(target, inside, None, MS_REMOUNT | MS_BIND | MS_RDONLY)
        except OSError:
            pass
    if output and output != target and not _shadows_per_ns(output):
        inside = f"{root}{output}"
        os.makedirs(inside, exist_ok=True)
        _mount(output, inside, None, MS_BIND)

    # 8b. Bind any extra read-only paths the caller requested (via
    # readable_paths in the public sandbox API). Each is bind-mounted
    # at its original absolute path, so the child sees it exactly where
    # the caller expects. Same two-step bind+remount-ro, and same
    # shadow-skip rule.
    if extra_ro_paths:
        for path in extra_ro_paths:
            if not path or _shadows_per_ns(path):
                continue
            if not os.path.isdir(path) and not os.path.isfile(path):
                continue
            inside = f"{root}{path}"
            try:
                if os.path.isdir(path):
                    os.makedirs(inside, exist_ok=True)
                else:
                    # File bind-mount: create an empty regular file to
                    # serve as the mount point.
                    os.makedirs(os.path.dirname(inside), exist_ok=True)
                    open(inside, "a").close()
                _mount(path, inside, None, MS_BIND)
                try:
                    _mount(path, inside, None, MS_REMOUNT | MS_BIND | MS_RDONLY)
                except OSError:
                    pass
            except OSError:
                # Best-effort: skip any path that fails to bind. The
                # caller's sandbox just won't see it — no harder than
                # if the path didn't exist on the host.
                continue

    # 9. pivot_root. put_old must be a directory INSIDE new_root.
    os.chdir(root)
    os.makedirs(".oldroot", exist_ok=True)
    _pivot_root(".", ".oldroot")
    os.chdir("/")
    # Detach the old root (lazy — subtrees like cgroup/binfmt_misc keep
    # it busy, so plain umount fails).
    _umount("/.oldroot", MNT_DETACH)
    try:
        os.rmdir("/.oldroot")
    except OSError:
        pass
