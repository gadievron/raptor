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

The module exposes `setup_mount_ns(target, output)` which (numbering
matches the inline step comments in the function body):
    1. Makes / rprivate so our mounts don't leak back.
    2. Creates a fresh tmpfs at /tmp/.raptor-sbx-<pid> to become the new root.
    3. Creates the standard-dir mount points inside the new root.
    4. Bind-mounts system dirs (/usr, /lib, /lib64, /etc, /bin, /sbin)
       read-only into the new root.
    5. rbind-mounts /dev and /sys from the host.
    6. Bind-mounts host /proc (a fresh procfs would need a pid-ns first).
    7. Mounts fresh tmpfs at /run and /tmp for per-sandbox isolation
       (7b: re-creates inherited temp-dir env paths inside it).
    8. Bind-mounts target (read-only) and output (writable) at their
       ORIGINAL absolute paths (no caller argv rewriting needed);
       sub-steps 8a-8d: evidence-dir shadow, caller extra read-only
       binds, host-fingerprint overlay, etc_overlay.
    9. pivot_root onto the new tmpfs.

Shadow-paths that collide with per-ns mounts (/tmp, /dev, etc.) are
skipped — the per-ns mount already serves them.
"""

import ctypes
import os
import stat as stat_module
from collections.abc import Iterable
from typing import TYPE_CHECKING, Optional

from ._fork_safe_warn import warn_post_fork
from .exit_codes import SANDBOX_EXIT_MOUNT_NS_BIND_FAIL

if TYPE_CHECKING:
    # Avoid runtime circular import: fingerprint.apply_overlay imports
    # _mount + MS_BIND from this module, so we keep the Persona
    # annotation as a forward reference and import apply_overlay
    # lazily inside setup_mount_ns when a persona is provided.
    from .fingerprint import Persona

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
# Captured as a module constant (not `import errno` in the post-fork
# path) — same fork-safety convention as the other constants here.
_EINVAL        = 22
_ELOOP         = 40
MS_NOSUID      = 0x2
MS_NODEV       = 0x4
MS_NOEXEC      = 0x8
MS_NOATIME     = 0x400
MS_NODIRATIME  = 0x800
MS_RELATIME    = 0x200000  # 1<<21
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
        msg = (
            f"mount-ns sandbox: pivot_root syscall number unknown for "
            f"architecture {arch!r} — add to _PIVOT_ROOT_SYSCALL_NR in "
            f"core/sandbox/mount_ns.py (see asm-generic/unistd.h)."
        )
        raise NotImplementedError(msg) from None

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
# not "wrong libc name on this distro".  (Import placed here, next to
# its rationale, after the syscall-number guard above — E402 accepted.)
import ctypes.util as _ctypes_util  # noqa: E402

_libc = ctypes.CDLL(_ctypes_util.find_library("c"), use_errno=True)


def _mount(source: str | None, target: str,
           fs_type: str | None, flags: int = 0,
           data: str | None = None) -> None:
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


def _bind_pinned_source(source: str, inside: str, flags: int) -> None:
    """Bind-mount *source* onto *inside* with the SOURCE inode pinned.

    Generalises the ``.audit`` dirfd pin to the bind
    sources themselves: ``target=`` / ``output=`` / readable-path bind
    sources were pathname-resolved at mount(2), so a concurrent
    sibling sandbox sharing a writable tree could rmdir+symlink-swap a
    component between the parent's validation and the mount — steering
    a bind (the OUTPUT one writable) onto an arbitrary host directory.

    ``os.path.realpath`` runs immediately before the pinned walk so
    benign pre-existing symlinks in operator paths still resolve; a
    symlink encountered DURING the walk appeared after
    canonicalisation — the swap — and fails the setup loudly (OSError
    ELOOP out of ``open_pinned``). The mount source is
    ``/proc/self/fd/<fd>``: the magic-link resolves to exactly the
    pinned inode with no re-resolution window. The bind lands at the
    caller's original ``inside`` path, so the child-visible layout is
    unchanged.

    Scope: window-narrowing only — a symlink PRE-PLANTED before this
    function's realpath resolves like any operator symlink and still
    steers the bind (unchanged from the pathname-mount behaviour this
    replaces). See core/sandbox/_pathpin.py for the full scope
    statement and the validation-time inode-pinning follow-up that
    would close the pre-planted class.
    """
    from ._pathpin import open_pinned

    src_fd = open_pinned(os.path.realpath(source))
    try:
        _mount(f"/proc/self/fd/{src_fd}", inside, None, flags)
    finally:
        os.close(src_fd)


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


def _refuse_image_symlink_components(root: str, abs_path: str) -> None:
    """Rootfs mode: refuse pre-existing symlink components below the
    image root.

    Pre-pivot setup performs path-based ``makedirs``/``mount(2)``
    through ``{root}{abs_path}``. In rootfs mode every pre-existing
    component below ``root`` is ATTACKER-AUTHORED image content, and a
    symlink component resolves in the HOST namespace at this point —
    redirecting inode creation (and the subsequent bind) onto host
    paths. Walk the components with lstat and fail closed on any
    symlink. Components that do not exist yet are fine: the caller's
    makedirs will create real directories. The image tree is static
    during setup (the child has not exec'd), so the lstat walk is not
    raceable in-boundary. Host-root mode needs no such walk — there
    the tree under ``root`` is a fresh tmpfs populated only by this
    function.
    """
    cur = root
    for comp in abs_path.lstrip("/").split("/"):
        if not comp:
            continue
        cur = f"{cur}/{comp}"
        try:
            _st = os.lstat(cur)
        except OSError:
            return
        if stat_module.S_ISLNK(_st.st_mode):
            raise OSError(
                _ELOOP,
                f"mount_ns: image path component {cur!r} is a symlink "
                f"(hostile-image shape); refusing setup",
            )


def _copy_etc_tree(src: str, dst: str) -> None:
    """Recursively copy *src* into *dst*, preserving directory
    structure and permission MODE BITS.

    (Renamed from ``_copy_dir_shallow`` — the old name claimed a
    shallow copy while the implementation always walked the whole
    tree.)

    Files are hard-linked when possible (same filesystem — preserves
    the source inode's mode/owner exactly), otherwise copied
    byte-for-byte with the source's mode bits re-applied.  Symlinks
    are recreated as symlinks.  Ownership is NOT preserved and cannot
    be: the copy runs inside an unprivileged user-ns whose uid map
    contains only the caller's uid, so every new inode is owned by
    ns-root regardless.  Preserving the mode bits keeps
    group/other-restricted host files (e.g. a 0640 config) from
    flattening to world-readable 0644 copies that an in-sandbox
    process which later drops groups could still read.

    This is intentionally lightweight: it runs post-fork / pre-exec in
    the sandbox child, where no allocator-heavy stdlib
    (shutil.copytree) should be used.  Errors on individual entries
    are silently skipped — the host /etc may contain entries readable
    only by host-root (shadow, gshadow).
    """
    for dirpath, dirnames, filenames in os.walk(src):
        rel = os.path.relpath(dirpath, src)
        dst_dir = os.path.join(dst, rel) if rel != "." else dst
        for dn in dirnames:
            src_sub = os.path.join(dirpath, dn)
            try:
                mode = stat_module.S_IMODE(os.lstat(src_sub).st_mode)
            except OSError:
                mode = 0o755
            try:
                os.makedirs(os.path.join(dst_dir, dn), mode, exist_ok=True)
            except OSError:
                pass
        for fn in filenames:
            src_file = os.path.join(dirpath, fn)
            dst_file = os.path.join(dst_dir, fn)
            try:
                if os.path.islink(src_file):
                    link_target = os.readlink(src_file)
                    os.symlink(link_target, dst_file)
                    continue
                # Try hard-link first (fast, no copy; shares the
                # source inode so mode/owner carry over exactly).
                try:
                    os.link(src_file, dst_file)
                    continue
                except OSError:
                    pass
                # Byte copy, then re-apply the source's mode bits.
                with open(src_file, "rb") as sf, open(dst_file, "wb") as df:
                    while True:
                        chunk = sf.read(65536)
                        if not chunk:
                            break
                        df.write(chunk)
                try:
                    mode = stat_module.S_IMODE(os.lstat(src_file).st_mode)
                except OSError:
                    mode = 0o644
                os.chmod(dst_file, mode)
            except OSError:
                pass  # skip unreadable entries (shadow, etc.)


def _ro_remount_flags(path: str) -> int:
    """MS_* flags for a read-only bind remount of *path* that PRESERVE
    the source mount's locked attributes.

    In a user namespace, mount(2) refuses (EPERM) a MS_REMOUNT|MS_BIND
    that would CLEAR flags the original (init-ns) mount carried —
    nosuid/nodev/noexec/atime attributes are "locked". Host /tmp is
    typically mounted nosuid,nodev, so the plain
    MS_REMOUNT|MS_BIND|MS_RDONLY used here failed EPERM for any
    /tmp-resident bind and the code fell back to "relying on Landlock"
    — which is no backstop at all for targets UNDER /tmp, because /tmp
    is in the Landlock writable baseline (the per-sandbox-tmpfs
    rationale). Net effect: a target repo under /tmp was writable
    through its supposedly read-only bind. Read the live flags via
    statvfs and repeat them in the remount so the kernel accepts it.
    """
    flags = MS_REMOUNT | MS_BIND | MS_RDONLY
    try:
        st = os.statvfs(path)
    except OSError:
        return flags
    f_flag = st.f_flag
    for st_bit, ms_bit in (
        (getattr(os, "ST_NOSUID", 0), MS_NOSUID),
        (getattr(os, "ST_NODEV", 0), MS_NODEV),
        (getattr(os, "ST_NOEXEC", 0), MS_NOEXEC),
        (getattr(os, "ST_NOATIME", 0), MS_NOATIME),
        (getattr(os, "ST_NODIRATIME", 0), MS_NODIRATIME),
        (getattr(os, "ST_RELATIME", 0), MS_RELATIME),
    ):
        if st_bit and (f_flag & st_bit):
            flags |= ms_bit
    return flags


def setup_mount_ns(target: str | None, output: str | None,
                   extra_ro_paths: Iterable[str] | None = None,
                   root_path: str | None = None,
                   persona: Optional["Persona"] = None,
                   etc_overlay: dict | None = None,
                   stage_files: dict | None = None,
                   rw_submounts_ok: bool = False,
                   rootfs: str | None = None,
                   require_target_ro: bool = False) -> None:
    """Establish pivot_root'd tmpfs sandbox root.

    Must be called AFTER the child has entered the new user-ns and acquired
    CAP_SYS_ADMIN (via the parent's newuidmap setup), and BEFORE
    landlock_restrict_self() — Landlock blocks mount operations on kernel
    6.15+.

    `rootfs`: when set, the new root is THAT directory (an unpacked
    container-image filesystem, e.g. from ``docker create`` +
    ``docker export``) instead of a tmpfs populated with host system
    dirs. The environment then runs against the image's own /usr, /lib,
    /etc — no host system dirs leak in — while /dev, /sys, /proc and the
    fresh per-sandbox /tmp, /run, /dev/shm are provided per-namespace
    exactly as in the host-root mode (the grandchild's fresh procfs
    remount in _spawn gives ns-local pids on top). The rootfs directory
    is the sacrificial WRITABLE upper layer: environment writes land in
    it on the host side (Landlock-wise, _spawn grants the post-pivot
    "/" — the mount namespace is the write boundary in this mode), and
    callers must treat the directory as consumed after the run.
    Everything downstream — target/output binds at their
    original paths, evidence-dir shadowing, extra_ro_paths, stage_files,
    pivot_root — behaves identically in both modes.

    `rw_submounts_ok`: parent-computed "Landlock is active as the
    write-enforcement backstop" signal. Permits the recursive-bind
    fallback for extra_ro_paths trees containing locked submounts
    (Docker overlays etc.); see the EINVAL comment at the bind site.
    Defaults False = original fail-closed behaviour.

    `persona` (Optional[Persona]): when provided, after pivot_root completes
    every persona.files[target] is bind-mounted over its target path
    (/proc/cpuinfo, /etc/os-release, ...). Built by
    `core.sandbox.fingerprint.build_persona()` when the caller passed
    `sanitise_host_fingerprint=True`. Imported lazily to avoid a circular
    import (fingerprint.apply_overlay imports _mount/MS_BIND from this
    module).

    `stage_files` (Optional[dict[str, bytes]]): when provided, materialise
    each ``{target_path_in_sandbox: content_bytes}`` entry in the tmpfs
    root BEFORE pivot_root. Post-pivot the file is visible at
    ``target_path_in_sandbox``. Useful for staging sentinel files (e.g.
    a flag file for leak-oracle targets) without polluting the host
    filesystem or requiring root.  Files are created with mode 0o644
    (world-readable, owner-writable) since the target may run as an
    unprivileged UID inside the user-ns. A staging failure logs via
    ``warn_post_fork`` and continues — partial staging is better than
    an aborted sandbox setup.
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
    # as a symlink to an interesting target). The previous fallback —
    # ``/tmp/.raptor-sbx-{getpid()}`` — was predictable: a same-UID
    # attacker who could win the PID-reuse race could pre-plant the
    # path as a symlink to a chosen target, and ``makedirs(exist_ok=
    # True)`` would accept it. The subsequent bind-mount then
    # operated on the symlink target. Require ``root_path`` from a
    # ``tempfile.mkdtemp`` (random suffix) — refuse the fallback so
    # the predictable PID path can never be reached.
    if not root_path:
        msg = (
            "mount_ns: root_path is required (use tempfile.mkdtemp "
            "for a random-suffix path; the prior predictable "
            "/tmp/.raptor-sbx-<pid> fallback was a same-UID "
            "symlink-pre-plant target)"
        )
        raise RuntimeError(msg)
    root = root_path

    if rootfs:
        # Rootfs mode (steps 2-4 replacement): bind the image rootfs
        # onto the mkdtemp'd mount point — it becomes the new root
        # directly. No tmpfs, no host system-dir binds: the environment
        # sees only the image's own filesystem plus the per-namespace
        # mounts below. The bind is left WRITABLE — the rootfs dir is
        # the environment's upper layer (_spawn grants the post-pivot
        # "/" to Landlock when a write mask engages; the namespace
        # itself is the write boundary in this mode).
        rootfs = os.path.abspath(rootfs)
        _mount(rootfs, root, None, MS_BIND)
        # Exported image tarballs routinely lack /run, ship an empty
        # /dev, etc. — create the per-namespace mount points inside
        # the (writable) rootfs so steps 5-7 can stack their mounts.
        # The image tree is ATTACKER-AUTHORED content: an image
        # shipping one of these names as a symlink would make the
        # path-based makedirs/mount(2) below resolve it in the HOST
        # namespace pre-pivot (host-side inode creation, mount
        # diversion). lstat and fail closed on anything that is not a
        # real directory.
        for d in ("dev", "proc", "sys", "run", "tmp"):
            _mp = f"{root}/{d}"
            try:
                _mpst = os.lstat(_mp)
            except FileNotFoundError:
                os.makedirs(_mp, exist_ok=True)
                continue
            if not stat_module.S_ISDIR(_mpst.st_mode):
                raise OSError(
                    _ELOOP,
                    f"mount_ns: rootfs entry /{d} is a symlink or "
                    f"non-directory (hostile-image shape); refusing "
                    f"setup",
                )
    else:
        _mount("tmpfs", root, "tmpfs", 0, "mode=755")

        # 3. Create standard-dir mount points in the new tmpfs root. We
        # own the tmpfs inodes here so mkdir is not blocked by host-/
        # ACL (which was the failure mode of the legacy mount_script).
        for d in (*_SYSTEM_RO_DIRS, "dev", "proc", "sys", "run", "tmp"):
            os.makedirs(f"{root}/{d}", exist_ok=True)

    # 4. Bind system dirs read-only (host-root mode only — in rootfs
    # mode the image supplies /usr, /lib, /etc and no host system dir
    # may leak in). Two-step bind + remount-ro because
    # one-step `--bind -o ro` sometimes fails with EPERM on unprivileged
    # user-ns — the ro attribute can only be set by a subsequent remount.
    #
    # /etc with etc_overlay: when overlay entries target paths that don't
    # exist on the host, the bind mount's underlying FS permissions block
    # creation (EACCES — namespace uid != host root), and the MNT_LOCKED
    # flag (kernel ≥5.12) blocks remounting RW.  Fix: mount a tmpfs on
    # {root}/etc and shallow-copy the host /etc contents into it.  This
    # gives us a writable /etc where mount-point stubs for overlay files
    # can be created freely.  The copy is O(entries-in-etc) — typically
    # a few hundred inodes, negligible vs LLM latency.
    _etc_has_missing_targets = False
    if etc_overlay:
        for ns_target in etc_overlay:
            if (isinstance(ns_target, str)
                    and ns_target.startswith("/etc/")
                    and not os.path.exists(ns_target)):
                _etc_has_missing_targets = True
                break

    for d in (() if rootfs else _SYSTEM_RO_DIRS):
        host_dir = f"/{d}"
        if not os.path.isdir(host_dir):
            continue
        inside = f"{root}/{d}"
        if d == "etc" and _etc_has_missing_targets:
            _mount("tmpfs", inside, "tmpfs", 0, "mode=755")
            _copy_etc_tree(host_dir, inside)
            # Pre-create mount-point stubs for overlay targets that
            # don't exist on the host.
            for ns_target in etc_overlay:
                if not isinstance(ns_target, str):
                    continue
                # Same normalized-absolute-key rule as the 8d bind
                # loop: startswith("/etc/") alone would still pass
                # "/etc/../..."-style keys into the {root} concat.
                if (not ns_target.startswith("/etc/")
                        or os.path.normpath(ns_target) != ns_target):
                    continue
                stub = f"{root}{ns_target}"
                if not os.path.exists(stub):
                    try:
                        host_source = etc_overlay[ns_target]
                        if isinstance(host_source, str) and os.path.isdir(host_source):
                            os.makedirs(stub, exist_ok=True)
                        else:
                            os.makedirs(os.path.dirname(stub), exist_ok=True)
                            fd = os.open(
                                stub,
                                os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW,
                                0o600,
                            )
                            os.close(fd)
                    except OSError as exc:
                        warn_post_fork(
                            b"RAPTOR: mount_ns: etc_overlay pre-create "
                            b"failed (errno=%d)\n" % (exc.errno or 0,)
                        )
            _mount("tmpfs", inside, None,
                   MS_REMOUNT | MS_BIND | MS_RDONLY)
        else:
            _mount(host_dir, inside, None, MS_BIND)
            _mount(host_dir, inside, None, _ro_remount_flags(inside))

    # 5. /dev and /sys: recursive bind from host. A minimal /dev would
    # be more conservative but real tools (ASAN, glibc, curl) need
    # /dev/null, /dev/urandom, /dev/tty, /dev/pts etc.; narrowing breaks
    # in subtle ways. rbind + Landlock narrowing is the practical
    # compromise.
    _mount("/dev", f"{root}/dev", None, MS_BIND | MS_REC)
    # /dev/shm: fresh tmpfs stacked over the rbind so POSIX shared
    # memory / named semaphores (shm_open, sem_open — Python
    # multiprocessing's SemLock lives here) work inside the sandbox
    # WITHOUT exposing the host's shm segments. Same per-sandbox
    # isolation rationale as /tmp below; mode 1777 matches the
    # host convention (sticky world-writable scratch).
    if os.path.isdir("/dev/shm"):
        _mount("tmpfs", f"{root}/dev/shm", "tmpfs", 0, "mode=1777")
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

    # 7b. Re-create inherited temp-dir env paths inside the fresh
    # tmpfs. The child inherits TMPDIR/TEMP/TMP from the host; a value
    # under /tmp (operator TMPDIR, nested pytest basetemp) would
    # otherwise name a directory that doesn't exist in the private
    # /tmp — gcc et al. then fail with "Cannot create temporary
    # file". normpath first so "/tmp/../etc" can't escape the
    # prefix check. Mode 0o1777 matches the /tmp contract the child
    # expects. Best-effort: a failure here degrades to the pre-fix
    # behaviour, never aborts setup.
    for _var in ("TMPDIR", "TEMP", "TMP"):
        _val = os.environ.get(_var, "")
        if not _val:
            continue
        _norm = os.path.normpath(_val)
        if not _norm.startswith("/tmp/"):
            continue
        try:
            os.makedirs(f"{root}{_norm}", mode=0o1777, exist_ok=True)
        except OSError as exc:
            warn_post_fork(
                b"RAPTOR: mount_ns: temp-env dir re-create failed "
                b"(errno=%d)\n" % (exc.errno or 0)
            )

    # 8. Bind target and output at their ORIGINAL absolute paths.
    # After pivot_root, the child still refers to /tmp/vulns (or whatever
    # the caller passed) — no argv rewriting needed. If the caller's
    # path is one we've already served via a per-ns mount, skip so we
    # don't fight our own stack.
    # ``_step8_bound_dirs``: the target/output directories this step
    # actually bind-mounts. Step 8b seeds its ``_bound_dirs`` predicate
    # with them so an extra_ro_paths FILE living under the target or
    # output bind (readable_paths naming files inside the scanned tree —
    # the normal shape when the target contains the orchestrator's own
    # helper scripts) skips placeholder creation: its mount point
    # already exists, populated by the parent bind, and the
    # O_CREAT|O_EXCL stub open would otherwise fail EEXIST and abort
    # the whole spawn (exit 126) — observed as flaky sandboxed runs
    # whenever the scanned tree names its own files in readable_paths.
    _step8_bound_dirs: set = set()
    if target and not _shadows_per_ns(target):
        inside = f"{root}{target}"
        if rootfs:
            _refuse_image_symlink_components(root, target)
        os.makedirs(inside, exist_ok=True)
        _bind_pinned_source(target, inside, MS_BIND)
        _step8_bound_dirs.add(target)
        # Remount-bind-ro is best-effort. Skip when output == target
        # since output must remain writable. Landlock enforces
        # read-only on target at the filesystem-access layer
        # independently, so the ro mount flag is defence-in-depth
        # rather than the primary control.
        if output != target:
            try:
                _mount(target, inside, None, _ro_remount_flags(inside))
            except OSError as exc:
                # ``require_target_ro`` means the caller determined the
                # ro bind is the ONLY read-only enforcement for the
                # target on this spawn (no Landlock backstop: Landlock
                # unavailable/unengaged, the target sits under a
                # writable grant, or rootfs mode grants the image
                # tree). "Relying on Landlock" would be vacuous — fail
                # closed instead of executing with a writable target.
                if require_target_ro:
                    raise
                warn_post_fork(
                    b"mount_ns: target remount-ro failed (errno=%d); "
                    b"relying on Landlock for read-only enforcement\n"
                    % (exc.errno or 0)
                )
    if output and output != target and not _shadows_per_ns(output):
        inside = f"{root}{output}"
        if rootfs:
            _refuse_image_symlink_components(root, output)
        os.makedirs(inside, exist_ok=True)
        _bind_pinned_source(output, inside, MS_BIND)
        _step8_bound_dirs.add(output)

    # 8a. Shadow the evidence directory (<dir>/.audit — see
    # core/sandbox/evidence.py) inside the rw-bound target/output
    # views. The parent-side tracer/summary writers append sandbox
    # evidence there through held fds in the PARENT namespace; the
    # child must not be able to reach the real files through its rw
    # bind, so an empty read-only tmpfs is stacked over the mount
    # point. Landlock's writable grant may still nominally cover the
    # path, but every write lands on (and is refused by) the ro
    # tmpfs. Failure is warned, not fatal: the inode-verification at
    # evidence-file close still detects tampering after the fact.
    for _evdir_base in {p for p in (output, target) if p}:
        _evdir = f"{root}{_evdir_base}/.audit"
        # Pin the mount target with an O_PATH dirfd, never a pathname:
        # the .audit entry inside the TARGET bind is attacker-authored
        # content (a hostile repo can ship it), and the OUTPUT bind can
        # be shared with an already-executing sibling sandbox — a
        # symlink (shipped, or rmdir+swapped between a check and the
        # mount) would steer the ro-tmpfs onto an arbitrary in-root
        # directory (e.g. {root}/usr — hiding the interpreter, forcing
        # an X-status and the automatic backend retry: a posture-
        # downgrade lever). O_PATH|O_NOFOLLOW|O_DIRECTORY refuses
        # symlinks and non-directories ATOMICALLY, and mounting via
        # /proc/self/fd/<fd> targets exactly the pinned directory with
        # no re-resolution window. Refusals proceed WITHOUT the shadow;
        # the evidence-file inode verification remains the (documented)
        # tamper backstop. Single read-only tmpfs mount — no remount
        # step that would need a second (re-raceable) resolution.
        try:
            _evfd = os.open(_evdir, os.O_PATH | os.O_NOFOLLOW
                            | os.O_DIRECTORY | os.O_CLOEXEC)
        except FileNotFoundError:
            continue
        except OSError as exc:
            if exc.errno in (_ELOOP, 20):  # ELOOP / ENOTDIR
                warn_post_fork(
                    b"RAPTOR: mount_ns: refusing evidence-dir shadow "
                    b"- .audit is a symlink or non-directory "
                    b"(hostile-tree shape); relying on evidence-file "
                    b"inode verification\n"
                )
            continue
        try:
            _mount("tmpfs", f"/proc/self/fd/{_evfd}", "tmpfs",
                   MS_RDONLY, "mode=700")
        except OSError as exc:
            warn_post_fork(
                b"RAPTOR: mount_ns: evidence-dir shadow mount failed "
                b"(errno=%d); relying on evidence-file inode "
                b"verification\n" % (exc.errno or 0)
            )
        finally:
            os.close(_evfd)

    # 8b. Bind any extra read-only paths the caller requested (via
    # readable_paths in the public sandbox API). Each is bind-mounted
    # at its original absolute path, so the child sees it exactly where
    # the caller expects. Same two-step bind+remount-ro, and same
    # shadow-skip rule.
    #
    # ``_bound_dirs``: directories already bind-mounted into the
    # namespace — step 4's system dirs plus any directories this loop
    # binds. When a file path falls under a bound directory, its
    # mount point already exists (populated by the parent bind) so we
    # skip the O_CREAT | O_EXCL creation step and go straight to the
    # overlay bind. This is a precise predicate: we only skip
    # creation when *we* know the parent was bound, not for arbitrary
    # pre-existing paths.
    #
    # NOT the full _SHADOW_PATHS set: /tmp and /run are fresh EMPTY
    # tmpfs (step 7), not host binds — nothing populated their
    # subtrees, so mount-point stubs beneath them must still be
    # created. Pre-fix, seeding with _SHADOW_PATHS made a FILE bind
    # under /tmp (e.g. a repo checkout under /tmp naming its own
    # libexec helpers via readable_paths) skip stub creation and fail
    # with ENOENT at mount(2). "/" is harmless either way (the
    # `d + "/"` prefix test never matches it) but excluded for
    # accuracy.
    #
    # Seeded with the step-8 target/output binds: file paths beneath
    # them are already visible through the parent bind, so the
    # O_CREAT|O_EXCL stub open would fail EEXIST (fail-closed exit
    # 126) for a path that needs no stub at all.
    _bound_dirs: set = {
        "/dev", "/proc", "/sys",
        *(f"/{d}" for d in _SYSTEM_RO_DIRS),
        *_step8_bound_dirs,
    }
    _seen_extra_ro: set = set()
    if extra_ro_paths:
        for path in extra_ro_paths:
            if not path:
                continue
            # Normalize like target/output above — a relative or
            # non-normalized entry ("etc", "/tmp/../etc") would evade
            # the exact-string shadow check and produce a malformed
            # bind target ("{root}etc") that diverges from the path
            # the caller's Landlock read rule references.
            path = os.path.abspath(path)
            # Duplicate entries (the same path arriving via both
            # readable_paths and tool_paths, or repeated caller
            # entries) would hit the O_CREAT|O_EXCL stub open twice —
            # the second pass fails EEXIST on the stub the first pass
            # created and aborts the spawn. One bind per path.
            if path in _seen_extra_ro:
                continue
            _seen_extra_ro.add(path)
            if _shadows_per_ns(path):
                continue
            # Paths already served by the step-8 target/output binds
            # keep their step-8 rw/ro semantics. Without this skip, a
            # target that is ALSO the output (writable clone/build
            # destinations — restrict_reads callers put target in the
            # read allowlist, which forwards here) gets an ro bind
            # stacked ON TOP of its rw bind and every child write
            # fails with EROFS.
            if path in (target, output):
                continue
            if not os.path.isdir(path) and not os.path.isfile(path):
                continue
            inside = f"{root}{path}"
            # _step names which sub-operation is running so the outer
            # OSError handler can report the actual failing step
            # ("makedirs" / "open mount-point" / "bind") instead of
            # always saying "bind failed" — pre-fix `os.makedirs` /
            # `os.open` failures (e.g. ENOENT on a malformed path)
            # were reported as "bind failed (errno=2)", which an
            # operator inspecting the kernel log could not match
            # against the actual syscall that errored.
            #
            # ASCII-only short labels so the bytes concat in the
            # except clause stays fork-safe + allocation-bounded.
            _step = b"setup"
            try:
                if rootfs:
                    _refuse_image_symlink_components(root, path)
                if os.path.isdir(path):
                    _step = b"makedirs"
                    os.makedirs(inside, exist_ok=True)
                    _bound_dirs.add(path)
                elif any(path.startswith(d + "/") for d in _bound_dirs):
                    # Mount point already exists — a parent directory
                    # (e.g. /etc from step 4, or an earlier
                    # extra_ro_paths entry) was bind-mounted into the
                    # namespace, which populated this path.  Skip
                    # creation and proceed to the overlay bind.
                    pass
                elif rootfs and os.path.lexists(inside):
                    # Rootfs mode: the whole root came from the image
                    # bind, so an existing path here is image content —
                    # binding over it is exactly the caller's intent
                    # (the host-mode O_EXCL planted-state defence guards
                    # a fresh private tmpfs, which doesn't apply).
                    pass
                else:
                    # File bind-mount: create an empty regular file to
                    # serve as the mount point.
                    #
                    # Use os.open with O_NOFOLLOW + 0o600 instead of
                    # `open(inside, "a")`:
                    #   * O_NOFOLLOW refuses to follow a symlink at
                    #     `inside` — defence-in-depth even though our
                    #     tmpfs root was freshly mkdir'd.
                    #   * O_CREAT | O_EXCL refuses to reuse a pre-existing
                    #     mount-point (which would also indicate something
                    #     planted state we don't expect).
                    #   * mode 0o600 — the mount-point itself shouldn't
                    #     be world-readable (was 0o644 default via umask).
                    _step = b"makedirs (parent)"
                    os.makedirs(os.path.dirname(inside), exist_ok=True)
                    _step = b"open mount-point"
                    fd = os.open(
                        inside,
                        os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW | os.O_EXCL,
                        0o600,
                    )
                    os.close(fd)
                _step = b"bind"
                try:
                    _bind_pinned_source(path, inside, MS_BIND)
                except OSError as bind_exc:
                    # EINVAL: a NON-recursive bind of a tree containing
                    # locked submounts (mounts created by a more-
                    # privileged namespace — e.g. Docker's overlays
                    # under /var/lib/docker) is refused by the kernel
                    # in a user namespace, because it would expose the
                    # paths hidden underneath them. A RECURSIVE bind
                    # carries the submounts along instead — legal, and
                    # it never reveals anything the host didn't already
                    # show. But the remount-ro below covers the top
                    # mount only, so the carried submounts stay rw at
                    # the mount layer; that is acceptable ONLY when
                    # Landlock is active as the write-enforcement
                    # backstop (its write mask is unconditional and
                    # covers these paths). Without Landlock, keep the
                    # original fail-closed behaviour — a degraded
                    # sandbox masquerading as the requested one is
                    # worse than a loud setup failure.
                    if bind_exc.errno != _EINVAL or not rw_submounts_ok:
                        raise
                    _bind_pinned_source(path, inside, MS_BIND | MS_REC)
                    try:
                        _path_b = path.encode("utf-8", errors="replace")
                    except Exception:  # noqa: BLE001
                        _path_b = b"<unencodable>"
                    warn_post_fork(
                        b"mount_ns: extra_ro_paths recursive bind for "
                        + _path_b
                        + b" (locked submounts); submount ro relies on"
                        b" Landlock\n"
                    )
                try:
                    _mount(path, inside, None, _ro_remount_flags(inside))
                except OSError as exc:
                    # bytes(path) keeps the message fork-safe (no f-string
                    # allocation pulling locks); fallback to a placeholder
                    # if encoding ever fails. errno also encoded as integer.
                    try:
                        _path_b = path.encode("utf-8", errors="replace")
                    except Exception:  # noqa: BLE001
                        _path_b = b"<unencodable>"
                    warn_post_fork(
                        b"mount_ns: extra_ro_paths remount-ro failed for "
                        + _path_b
                        + b" (errno=%d); relying on Landlock\n"
                        % (exc.errno or 0)
                    )
            except OSError as exc:
                # Caller explicitly named this path via readable_paths
                # in the public sandbox API — silently dropping it
                # leaves a hole the caller did not authorise (the path
                # is either missing from the sandbox, or worse, still
                # writable when the caller asked for read-only). Fail-
                # closed so the parent observes the failed setup
                # instead of getting a degraded sandbox masquerading
                # as the requested one.
                #
                # Per W35.C convention, fail-CLOSED sites use direct
                # os.write(2, ...) + os._exit(N) rather than the
                # warn_post_fork helper (helper is reserved for
                # DiD warn-only sites).
                try:
                    _path_b = path.encode("utf-8", errors="replace")
                except Exception:  # noqa: BLE001
                    _path_b = b"<unencodable>"
                try:
                    os.write(
                        2,
                        b"RAPTOR: mount_ns: extra_ro_paths "
                        + _step
                        + b" failed for "
                        + _path_b
                        + b" (errno=%d), exiting\n" % (exc.errno or 0),
                    )
                except OSError:
                    pass
                os._exit(SANDBOX_EXIT_MOUNT_NS_BIND_FAIL)

    # 8c. Host-fingerprint overlay (opt-in via sanitise_host_fingerprint).
    # MUST happen BEFORE pivot_root — the persona's source files live
    # in the parent's /tmp, which becomes inaccessible after pivot_root
    # (the per-sandbox tmpfs at {root}/tmp shadows it). The overlay
    # targets `{root}{target}` paths (e.g. `{root}/proc/cpuinfo`),
    # which exist because /proc, /etc, /sys have already been bind-
    # mounted into {root} in steps 5-6. After pivot_root, those binds
    # are visible at the unprefixed path (`/proc/cpuinfo`) — same
    # mechanism as the system-dir bind-mounts in step 4.
    if persona is not None:
        from .fingerprint import apply_overlay
        apply_overlay(persona, root_prefix=root)

    # 8d. Caller-supplied etc_overlay. ``etc_overlay`` is a dict mapping
    # the in-sandbox target path (e.g. ``/etc/sudoers``) to the host
    # source path (a file under work_dir the caller pre-populated).
    # Each pair is bind-mounted with ``MS_BIND`` before pivot_root and
    # before Landlock — same window the persona overlay uses, for the
    # same reason: mount topology changes are blocked once Landlock is
    # installed on kernel 6.15+, and mounting on top of the RO /etc
    # bind from step 4 only succeeds while we still have CAP_SYS_ADMIN
    # in the user-ns.
    #
    # Mount-point stubs for /etc paths that don't exist on the host
    # were already created in step 4 (between bind and remount-RO).
    # On kernel ≥5.12, MNT_LOCKED prevents remounting RO bind mounts
    # back to RW, so the old remount-RW approach silently failed.
    if etc_overlay:
        for ns_target, host_source in etc_overlay.items():
            if not isinstance(ns_target, str) or not isinstance(host_source, str):
                warn_post_fork(
                    b"RAPTOR: mount_ns: etc_overlay entry skipped - "
                    b"both keys and values must be str paths\n"
                )
                continue
            # Keys are concatenated onto the staging root below —
            # accept only normalized absolute paths so a "..", "" or
            # relative key can never drive the pre-pivot makedirs /
            # O_CREAT / mount(2) OUTSIDE the staging root on the host
            # (today's producers are internal, but image-derived
            # values will flow here; fail safe now).
            if (not ns_target.startswith("/")
                    or os.path.normpath(ns_target) != ns_target
                    or ns_target == "/"):
                warn_post_fork(
                    b"RAPTOR: mount_ns: etc_overlay entry skipped - "
                    b"key must be a normalized absolute path\n"
                )
                continue
            inside = f"{root}{ns_target}"
            if not os.path.exists(host_source):
                warn_post_fork(
                    b"RAPTOR: mount_ns: etc_overlay source missing; "
                    b"skipping bind\n"
                )
                continue
            if rootfs:
                _refuse_image_symlink_components(root, ns_target)
            # For non-/etc paths (e.g. /tmp/<x>, /run/<x>) the mount
            # point may still need creating — those dirs are fresh tmpfs
            # (step 7), not host bind-mounts.
            if not os.path.exists(inside):
                try:
                    if os.path.isdir(host_source):
                        os.makedirs(inside, exist_ok=True)
                    else:
                        os.makedirs(os.path.dirname(inside), exist_ok=True)
                        fd = os.open(
                            inside,
                            os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW,
                            0o600,
                        )
                        os.close(fd)
                except OSError:
                    warn_post_fork(
                        b"RAPTOR: mount_ns: etc_overlay could not "
                        b"create in-sandbox target; skipping bind\n"
                    )
                    continue
            try:
                _bind_pinned_source(host_source, inside, MS_BIND)
            except OSError:
                # Accurate in BOTH /etc branches: on the plain-bind
                # path the target sees the host file at this path; on
                # the tmpfs+copy path it sees the copied (un-overlaid)
                # /etc view — never "host /etc" as the old message
                # claimed.
                warn_post_fork(
                    b"RAPTOR: mount_ns: etc_overlay bind failed; "
                    b"overlay entry absent - target sees the "
                    b"un-overlaid view of this path\n"
                )
                continue
            # Overlay entries are configuration VIEWS, never write
            # surfaces — and in rootfs mode the Landlock write mask
            # covers the image tree, so a writable bind here would be
            # a write-through hole onto the LIVE host source file.
            # Remount read-only; on failure withdraw the bind rather
            # than leave the host file writable (fail closed — the
            # target then sees the un-overlaid view, same as a failed
            # bind).
            try:
                _mount(host_source, inside, None,
                       _ro_remount_flags(inside))
            except OSError as exc:
                _umount(inside, MNT_DETACH)
                warn_post_fork(
                    b"RAPTOR: mount_ns: etc_overlay remount-ro failed "
                    b"(errno=%d); overlay entry withdrawn "
                    b"(fail-closed)\n" % (exc.errno or 0)
                )

    # 8e. Caller-supplied stage_files — materialise arbitrary files in
    # the tmpfs root so they appear at their namespace path post-pivot.
    if stage_files:
        for stage_target, stage_content in stage_files.items():
            if not isinstance(stage_target, str) or not stage_target.startswith("/"):
                warn_post_fork(
                    b"RAPTOR: mount_ns: stage_files target must be an "
                    b"absolute path str; skipping\n"
                )
                continue
            if not isinstance(stage_content, (bytes, bytearray)):
                warn_post_fork(
                    b"RAPTOR: mount_ns: stage_files content must be "
                    b"bytes; skipping\n"
                )
                continue
            inside = f"{root}{stage_target}"
            try:
                os.makedirs(os.path.dirname(inside), exist_ok=True)
                fd = os.open(
                    inside,
                    os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW | os.O_EXCL,
                    0o644,
                )
                try:
                    os.write(fd, bytes(stage_content))
                finally:
                    os.close(fd)
            except OSError as exc:
                try:
                    _target_b = stage_target.encode("utf-8", errors="replace")
                except Exception:  # noqa: BLE001
                    _target_b = b"<unencodable>"
                warn_post_fork(
                    b"RAPTOR: mount_ns: stage_files failed for "
                    + _target_b
                    + b" (errno=%d); target will not see this file\n"
                    % (exc.errno or 0)
                )

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
