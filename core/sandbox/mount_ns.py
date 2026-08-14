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
        ) from None

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


def _copy_dir_shallow(src: str, dst: str) -> None:
    """Recursively copy *src* into *dst*, preserving directory structure.

    Files are hard-linked when possible (same filesystem), otherwise copied
    byte-for-byte via sendfile.  Symlinks are recreated as symlinks.
    Permissions and ownership are NOT preserved — every entry is owned by
    the caller's uid/gid with mode 0o644 (files) / 0o755 (dirs).

    This is intentionally lightweight: it runs post-fork / pre-exec in the
    sandbox child, where no allocator-heavy stdlib (shutil.copytree) should
    be used.  Errors on individual entries are silently skipped — the host
    /etc may contain entries readable only by host-root (shadow, gshadow).
    """
    for dirpath, dirnames, filenames in os.walk(src):
        rel = os.path.relpath(dirpath, src)
        dst_dir = os.path.join(dst, rel) if rel != "." else dst
        for dn in dirnames:
            try:
                os.makedirs(os.path.join(dst_dir, dn), 0o755, exist_ok=True)
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
                # Try hard-link first (fast, no copy).
                try:
                    os.link(src_file, dst_file)
                    continue
                except OSError:
                    pass
                # Byte copy via sendfile.
                with open(src_file, "rb") as sf, open(dst_file, "wb") as df:
                    while True:
                        chunk = sf.read(65536)
                        if not chunk:
                            break
                        df.write(chunk)
                os.chmod(dst_file, 0o644)
            except OSError:
                pass  # skip unreadable entries (shadow, etc.)


def setup_mount_ns(target: str | None, output: str | None,
                   extra_ro_paths: Iterable[str] | None = None,
                   root_path: str | None = None,
                   persona: Optional["Persona"] = None,
                   etc_overlay: dict | None = None,
                   stage_files: dict | None = None,
                   rw_submounts_ok: bool = False) -> None:
    """Establish pivot_root'd tmpfs sandbox root.

    Must be called AFTER the child has entered the new user-ns and acquired
    CAP_SYS_ADMIN (via the parent's newuidmap setup), and BEFORE
    landlock_restrict_self() — Landlock blocks mount operations on kernel
    6.15+.

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
        raise RuntimeError(
            "mount_ns: root_path is required (use tempfile.mkdtemp "
            "for a random-suffix path; the prior predictable "
            "/tmp/.raptor-sbx-<pid> fallback was a same-UID "
            "symlink-pre-plant target)"
        )
    root = root_path
    _mount("tmpfs", root, "tmpfs", 0, "mode=755")

    # 3. Create standard-dir mount points in the new tmpfs root. We own
    # the tmpfs inodes here so mkdir is not blocked by host-/ ACL
    # (which was the failure mode of the legacy mount_script).
    for d in (*_SYSTEM_RO_DIRS, "dev", "proc", "sys", "run", "tmp"):
        os.makedirs(f"{root}/{d}", exist_ok=True)

    # 4. Bind system dirs read-only. Two-step bind + remount-ro because
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

    for d in _SYSTEM_RO_DIRS:
        host_dir = f"/{d}"
        if not os.path.isdir(host_dir):
            continue
        inside = f"{root}/{d}"
        if d == "etc" and _etc_has_missing_targets:
            _mount("tmpfs", inside, "tmpfs", 0, "mode=755")
            _copy_dir_shallow(host_dir, inside)
            # Pre-create mount-point stubs for overlay targets that
            # don't exist on the host.
            for ns_target in etc_overlay:
                if not isinstance(ns_target, str):
                    continue
                if not ns_target.startswith("/etc/"):
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
            _mount(host_dir, inside, None,
                   MS_REMOUNT | MS_BIND | MS_RDONLY)

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
        # Remount-bind-ro is best-effort. Skip when output == target
        # since output must remain writable. Landlock enforces
        # read-only on target at the filesystem-access layer
        # independently, so the ro mount flag is defence-in-depth
        # rather than the primary control.
        if output != target:
            try:
                _mount(target, inside, None, MS_REMOUNT | MS_BIND | MS_RDONLY)
            except OSError as exc:
                warn_post_fork(
                    b"mount_ns: target remount-ro failed (errno=%d); "
                    b"relying on Landlock for read-only enforcement\n"
                    % (exc.errno or 0)
                )
    if output and output != target and not _shadows_per_ns(output):
        inside = f"{root}{output}"
        os.makedirs(inside, exist_ok=True)
        _mount(output, inside, None, MS_BIND)

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
    _bound_dirs: set = set(_SHADOW_PATHS)
    if extra_ro_paths:
        for path in extra_ro_paths:
            if not path or _shadows_per_ns(path):
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
                    _mount(path, inside, None, MS_BIND)
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
                    _mount(path, inside, None, MS_BIND | MS_REC)
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
                    _mount(path, inside, None, MS_REMOUNT | MS_BIND | MS_RDONLY)
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
            inside = f"{root}{ns_target}"
            if not os.path.exists(host_source):
                warn_post_fork(
                    b"RAPTOR: mount_ns: etc_overlay source missing; "
                    b"skipping bind\n"
                )
                continue
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
                _mount(host_source, inside, None, MS_BIND)
            except OSError:
                warn_post_fork(
                    b"RAPTOR: mount_ns: etc_overlay bind failed; "
                    b"target will see host /etc\n"
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
