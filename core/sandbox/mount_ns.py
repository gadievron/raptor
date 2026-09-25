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
       read-only into the new root. When an etc_overlay targets paths
       missing on the host, /etc becomes a tmpfs populated by a
       breadth-first, budgeted copy of host /etc — /etc/skel (new-user
       home templates; CI runner images stuff whole toolchains into
       it) is never copied, and the copy stops at a total
       bytes/entry budget rather than crawling a pathological host
       /etc (see _copy_etc_tree).
    5. builds a minimal per-sandbox /dev (fresh tmpfs, per-node binds,
       fresh devpts — never the host's pty slaves) and rbinds /sys.
    6. Bind-mounts host /proc (a fresh procfs would need a pid-ns first).
    7. Mounts fresh tmpfs at /run and /tmp for per-sandbox isolation
       (7b: re-creates inherited temp-dir env paths inside it).
    8. Bind-mounts target (read-only) and output (writable) at their
       ORIGINAL absolute paths (no caller argv rewriting needed);
       sub-steps 8a-8d: evidence-dir shadow, caller extra read-only
       binds, host-fingerprint overlay, etc_overlay. Binds are
       ordered ancestors-first across target/output/extra paths: a
       mount attached later covers earlier mounts below it, so an
       extra read-only bind naming an ancestor of the output dir
       must mount BEFORE the rw output bind (see the ordering
       invariant comment in the function body).
    9. pivot_root onto the new tmpfs.

Shadow-paths that collide with per-ns mounts (/tmp, /dev, etc.) are
skipped — the per-ns mount already serves them.
"""

import ctypes
import os
import re
import stat as stat_module
import time
from collections.abc import Iterable
from typing import TYPE_CHECKING, Optional

from ._fork_safe_warn import warn_post_fork
from ._pathpin import canonical_bind_path, is_per_process_procfs

# See core/sandbox/context.py (_BRANDED_TMP_RE) — same shape.
_BRANDED_TMP_RE = re.compile(r"/[^/]*raptor[^/]*(/|$)", re.IGNORECASE)


class ExtraRoBindError(OSError):
    """A caller-named ``readable_paths`` entry failed its read-only
    bind inside the mount namespace — fail-closed by contract (the
    path would be missing from the sandbox, or worse, still writable
    when the caller asked for read-only).

    Typed so ``_spawn``'s setup handler can report the fail-closed
    category ('C') on the exec-status pipe before the child exits:
    the old direct ``os._exit`` emitted no status byte, so the parent
    read EOF-no-byte as "the target execed" and returned the aborted
    setup as a genuine CompletedProcess. ``errno`` is preserved from
    the underlying mount failure so the bind-source pin tamper check
    (ESTALE → category 'P') still outranks the fail-closed category.
    """

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
_ESTALE        = 116
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

# WSL-host mask set (engaged only when the running kernel identifies
# as WSL — inert everywhere else). These are the Windows-interop and
# driver surfaces a WSL host leaks into an otherwise-Linux-shaped
# sandbox view; interop in particular lets code spawn WINDOWS-side
# processes that no Linux containment layer (namespaces, Landlock,
# seccomp) governs:
#   /run/WSL                  — the WSL_INTEROP socket dir (the
#                               channel /init uses to launch Windows
#                               processes). Structurally invisible
#                               already: step 7's fresh /run tmpfs is
#                               fail-closed (a mount failure aborts
#                               setup), and get_safe_env() drops
#                               WSL_INTEROP/WSLENV (allowlist scrub).
#                               Listed here so a readable/tool-path
#                               bind can never re-grant the live host
#                               socket dir into the fresh tmpfs.
#   /proc/sys/fs/binfmt_misc  — the interop exec plumbing's
#                               registration view (WSL registers the
#                               PE interpreter here). Rides into the
#                               sandbox on step 6's recursive /proc
#                               bind; masked in step 8f. The mask is
#                               a visibility control: binfmt dispatch
#                               happens in the kernel regardless of
#                               the mount view — what the masked
#                               interpreter cannot do is REACH
#                               Windows, because the socket dir and
#                               env vars above are withheld.
#   /usr/lib/wsl              — the Windows-driver/GPU library mounts
#                               (lib/, drivers/) host-bound under the
#                               step 4 /usr bind; masked in step 8f.
#   /dev/dxg                  — the GPU-paravirtualisation device.
#                               Structurally invisible already: step
#                               5's minimal /dev never creates it,
#                               and the extra-bind plan skips device
#                               nodes (neither dir nor regular file),
#                               so it cannot be re-granted either.
# Membership in the plan loop's masked-path refusal keeps every
# entry authoritative against caller-supplied readable binds — on
# the caller's spelling AND on the bind's resolved destination (a
# symlink to a masked path is refused too); the two step 8f mask
# mounts follow the 8a evidence-dir shadow convention (O_PATH-pinned
# mount point, empty read-only tmpfs, warn-not-abort —
# deny-direction hardening whose primary closures are the
# structural ones named above).
_WSL_MASKED_PATHS: tuple[str, ...] = (
    "/run/WSL",
    "/proc/sys/fs/binfmt_misc",
    "/usr/lib/wsl",
    "/dev/dxg",
)

#: The step 8f mask-mount subset of ``_WSL_MASKED_PATHS`` (the other
#: entries are structurally absent from the sandbox view — see above).
_WSL_MASK_MOUNT_DIRS: tuple[str, ...] = (
    "/proc/sys/fs/binfmt_misc",
    "/usr/lib/wsl",
)


def _is_wsl_host() -> bool:
    """WSL detection for the mask set, fail-toward-False.

    Lazy import: core.sandbox must stay importable without pulling
    core.startup in at module-import time, and by the time this runs
    the parent's own WSL consumers (context.py's dispatch gate) have
    already imported and cached the answer in the normal spawn flow,
    so the post-fork call is a sys.modules + cache lookup. A failure
    here reads as plain Linux — the detection contract every
    core.startup.wsl consumer keeps (the masks are deny-direction
    defence-in-depth; the load-bearing closures are structural).
    """
    try:
        from core.startup import wsl as _startup_wsl
        return bool(_startup_wsl.is_wsl())
    except Exception:  # noqa: BLE001 — detection must never break setup
        return False

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


def _bind_pinned_source(source: str, inside: str, flags: int,
                        pinned_fd: int | None = None) -> None:
    """Bind-mount *source* onto *inside* with the SOURCE inode pinned.

    Generalises the ``.audit`` dirfd pin to the bind
    sources themselves: ``target=`` / ``output=`` / readable-path bind
    sources were pathname-resolved at mount(2), so a concurrent
    sibling sandbox sharing a writable tree could rmdir+symlink-swap a
    component between the parent's validation and the mount — steering
    a bind (the OUTPUT one writable) onto an arbitrary host directory.

    Always: ``os.path.realpath`` runs immediately before a
    symlink-refusing component walk (``open_pinned``), so benign
    pre-existing symlinks in operator paths resolve while a symlink
    that appears DURING the walk fails the setup loudly (OSError
    ELOOP), and the mount consumes ``/proc/self/fd/<fd>`` of the
    walked fd — the magic-link resolves to exactly the walked inode
    with no re-resolution window. The walk must run HERE, in the
    mount-ns child: mount(2) requires the bind source's vfsmount to
    belong to the caller's mount namespace (``check_mnt`` — EINVAL
    otherwise), so an fd opened by the parent pre-unshare cannot be
    mounted directly.

    ``pinned_fd`` (the production spawn path) raises this from
    window-narrowing to CLOSED for the pre-planted class: it is the
    VALIDATION-TIME pin — an O_PATH fd the parent opened via the same
    symlink-refusing walk before forking this child. The freshly
    walked inode must be IDENTICAL (st_dev, st_ino) to the
    validation-pinned one, else the bind is refused (OSError ESTALE)
    — so no swap of the source path at ANY point after the caller's
    validation (rename swap, rmdir+symlink re-plant, the whole
    fork/newuidmap window) can steer the mount; it can only fail it,
    loudly. The held fd is also what makes the comparison sound: it
    keeps the validation-time inode allocated, so its (st_dev,
    st_ino) cannot be recycled by an attacker-created replacement.
    The fd is NOT closed here — the caller owns its lifetime (it may
    be reused for the recursive-bind retry).

    Without ``pinned_fd`` (direct/legacy callers, etc_overlay
    sources) the walk alone is window-narrowing only: a symlink
    pre-planted before the mount-time realpath resolves like any
    operator symlink and still steers the bind. See
    core/sandbox/_pathpin.py for the full scope statement.

    Either way the bind lands at the caller's original ``inside``
    path, so the child-visible layout is unchanged.
    """
    from ._pathpin import open_pinned

    try:
        src_fd = open_pinned(os.path.realpath(source))
    except OSError as walk_exc:
        if pinned_fd is None:
            raise
        # The parent pinned this source at validation (the held fd
        # still names a live inode), yet the same path no longer
        # resolves to ANY pinnable inode — it was unlinked, renamed
        # away, or a component swapped to a symlink (ELOOP). Uniform
        # tamper signal: ESTALE, so the spawn layer can distinguish
        # "source tampered after validation" (fail loud) from an
        # environmental mount failure (degradable).
        raise OSError(
            _ESTALE,
            f"mount_ns: bind source {source!r} failed re-resolution "
            f"at mount time (errno={walk_exc.errno}) though it was "
            f"pinned at validation; refusing the bind (source "
            f"tampered after validation)",
        ) from walk_exc
    try:
        if pinned_fd is not None:
            pinned_st = os.fstat(pinned_fd)
            walked_st = os.fstat(src_fd)
            if ((pinned_st.st_dev, pinned_st.st_ino)
                    != (walked_st.st_dev, walked_st.st_ino)):
                raise OSError(
                    _ESTALE,
                    f"mount_ns: bind source {source!r} no longer "
                    f"resolves to its validation-time inode "
                    f"(dev/ino {pinned_st.st_dev}/{pinned_st.st_ino} "
                    f"-> {walked_st.st_dev}/{walked_st.st_ino}); "
                    f"refusing the bind (source swapped after "
                    f"validation)",
                )
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
    if norm.startswith("//"):
        # POSIX preserves an exactly-two-slash prefix through abspath
        # and normpath, so "//tmp" names the same file as "/tmp" while
        # evading this exact-string check — the bind would then stack
        # HOST /tmp read-only OVER the fresh per-sandbox tmpfs.
        # Callers canonicalise via _canonical_bind_path already; the
        # collapse here is belt-and-braces for any other caller.
        norm = "/" + norm.lstrip("/")
    return norm in _SHADOW_PATHS


# Shared per-reader procfs classifier (also consumed by the parent-
# side pin skip and the Landlock grant resolution) — see
# _pathpin.is_per_process_procfs for the volatility contract. Bound
# at module import: the extra_ro loop runs post-fork in the mount-ns
# child, where imports are forbidden.
_is_per_process_procfs = is_per_process_procfs
# Same import-time binding for the bind-path canonicaliser (abspath +
# leading-double-slash collapse — see _pathpin.canonical_bind_path for
# why the two-slash spelling must never reach a policy comparison).
_canonical_bind_path = canonical_bind_path


def _required_pin_fd(
    src_fds: dict[str, int] | None, path: str,
) -> int | None:
    """Pin lookup for a REQUIRED bind source (target/output/rootfs).

    When the parent supplied pins at all, every required bind was
    pinned (``_pin_bind_sources`` raises otherwise), so a lookup miss
    here is always a JOIN BUG (parent/child key-spelling drift) or
    tampering — and ``_bind_pinned_source`` with ``pinned_fd=None``
    silently downgrades to mount-time window-narrowing, losing the
    validation→mount containment on exactly the surfaces the pin was
    built for. Refuse with the tamper convention (ESTALE) instead:
    a produced-but-unconsumed pin must fail the spawn loudly, never
    weaken it silently.
    """
    if src_fds is None:
        return None
    fd = src_fds.get(path)
    if fd is None:
        msg = (
            f"mount_ns: no validation pin under key {path!r} — "
            "required bind would silently lose its inode pin "
            "(parent/child key drift or tampering)"
        )
        raise OSError(_ESTALE, msg)
    return fd


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


_PHASE_TRACE_ENV = "RAPTOR_SANDBOX_PHASE_TRACE"
# Per-entry copy markers are capped so a pathological host /etc can't
# grow the trace file without bound. This caps TRACE LINES only — the
# copy itself is bounded separately by the _ETC_COPY_MAX_* budget
# below (which is deliberately larger: entries past the trace cap
# still copy, silently; a one-line marker records that the cap
# tripped so a trace reader knows why per-entry markers stopped).
_PHASE_TRACE_MAX_ENTRIES = 4096

# Top-level host-/etc directories the overlay copy never descends
# into. /etc/skel is the new-user home-directory TEMPLATE tree — no
# sandboxed target consumes it, and CI runner images stuff whole
# toolchains into it (rustup under .cargo/bin, nvm test corpora,
# dotnet tool stores: tens of thousands of entries, hundreds of MB)
# which the pre-fix linear copy crawled until the caller's timeout.
# Each skip emits a loud named phase-trace marker.
_ETC_COPY_SKIP_TOP_DIRS = frozenset({"skel"})

# Total copy budget (belt-and-braces behind the skel skip). The copy
# exists to carry config files — passwd, group, hosts, resolv.conf,
# nsswitch.conf, ssl/, ld.so.* — into the sandbox's private /etc; a
# host /etc large enough to trip these bounds is carrying non-config
# payload the sandbox doesn't need. Hitting the ENTRY budget stops
# the copy (loud marker + post-fork warning) and setup continues with
# what was copied; a file larger than the remaining BYTE budget is
# skipped individually (loud marker) while smaller entries keep
# copying. Breadth-first ordering guarantees root-level files and
# shallow config trees are copied long before either bound can trip,
# so passwd/hosts/ssl are never the casualties.
_ETC_COPY_MAX_BYTES = 64 * 1024 * 1024
_ETC_COPY_MAX_ENTRIES = 8192


def _phase_trace(marker: bytes) -> None:
    """Append one setup-phase marker to the file named by
    ``$RAPTOR_SANDBOX_PHASE_TRACE``. No-op when the variable is unset.

    Diagnostic aid for setup wedges that only occur on specific hosts
    (a CI runner whose /etc holds an entry this code blocks on): the
    caller sets the env var to a host-visible path, and after a
    timeout the LAST line of the file names the phase that never
    completed.

    Post-fork/pre-exec safe by construction: pure ``os.*`` fd ops,
    one O_APPEND write per call, never raises. Written from the
    sandbox child BEFORE pivot_root — the target file must live on a
    host path (the caller's /tmp); markers stop at pivot_root by
    design, so "trace ends at the pivot marker" means the wedge is
    post-pivot.
    """
    path = os.environ.get(_PHASE_TRACE_ENV)
    if not path:
        return
    try:
        # O_NOFOLLOW: the trace path is typically under /tmp — refuse
        # a symlink swap at the final component rather than append
        # through it (same defence the safe-open pattern uses
        # elsewhere in this module).
        fd = os.open(path,
                     os.O_WRONLY | os.O_APPEND | os.O_CREAT
                     | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, b"mount_ns t=%dns: %s\n"
                     % (time.monotonic_ns(), marker))
        finally:
            os.close(fd)
    except OSError:
        pass


def _copy_etc_tree(src: str, dst: str) -> None:
    """Copy *src* into *dst* breadth-first, preserving directory
    structure and permission MODE BITS, under a total copy budget.

    Ordering is breadth-first — every file at depth k is copied before
    any directory at depth k+1 is entered — so the root-level config
    files the sandbox actually needs (passwd, group, hosts,
    resolv.conf, nsswitch.conf) and shallow trees (ssl/) land first
    and can never be starved by a deep payload subtree.

    Bounds (all loud, named in the phase trace; none may wedge or fail
    the setup):

    * ``/etc/skel`` (any name in ``_ETC_COPY_SKIP_TOP_DIRS`` at the
      TOP level of *src*) is never copied — new-user home templates
      that no sandboxed target consumes; CI runner images stuff whole
      toolchains into it (100k+ entries, hundreds of MB).
    * ``_ETC_COPY_MAX_ENTRIES`` total entries (files, dirs, symlinks,
      FIFOs): reaching it stops the copy with a marker + post-fork
      warning; the sandbox proceeds with what was copied.
    * ``_ETC_COPY_MAX_BYTES`` total bytes byte-copied: a file larger
      than the remaining byte budget is skipped individually (marker)
      while smaller entries keep copying.

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
    _traced = 0
    _trace_capped = False
    entries = 0
    copied_bytes = 0
    # BFS queue of (src_dir, dst_dir); list-with-cursor instead of
    # collections.deque to keep the post-fork path on plain builtins.
    queue: list[tuple[str, str]] = [(src, dst)]
    qi = 0
    while qi < len(queue):
        dirpath, dst_dir = queue[qi]
        qi += 1
        try:
            names = sorted(os.listdir(dirpath))
        except OSError:
            continue
        subdirs: list[str] = []
        for name in names:
            src_entry = os.path.join(dirpath, name)
            try:
                st = os.lstat(src_entry)
            except OSError:
                continue
            if stat_module.S_ISDIR(st.st_mode):
                if dirpath == src and name in _ETC_COPY_SKIP_TOP_DIRS:
                    # Loud named skip — always emitted, never counted
                    # against the per-entry trace cap.
                    _phase_trace(
                        b"etc copy skip: " + os.fsencode(src_entry)
                        + b" (new-user home templates; never copied)"
                    )
                    continue
                subdirs.append(name)
                continue
            if entries >= _ETC_COPY_MAX_ENTRIES:
                _phase_trace(
                    b"etc copy budget exceeded (entries=%d): skipping "
                    b"remaining entries" % entries
                )
                warn_post_fork(
                    b"sandbox: mount_ns: /etc overlay copy stopped at "
                    b"the entry budget -- host /etc is pathologically "
                    b"large; the sandbox keeps the entries copied so "
                    b"far (root-level config files copy first)\n"
                )
                return
            entries += 1
            dst_file = os.path.join(dst_dir, name)
            if _traced < _PHASE_TRACE_MAX_ENTRIES:
                # Marker BEFORE the entry is touched: on a wedge the
                # last line of the trace names the offending entry.
                _traced += 1
                _phase_trace(b"etc copy entry: " + os.fsencode(src_entry))
            elif not _trace_capped:
                _trace_capped = True
                _phase_trace(
                    b"etc copy trace: per-entry markers capped at %d "
                    b"(copy continues)" % _PHASE_TRACE_MAX_ENTRIES
                )
            try:
                if stat_module.S_ISLNK(st.st_mode):
                    link_target = os.readlink(src_entry)
                    os.symlink(link_target, dst_file)
                    continue
                if stat_module.S_ISFIFO(st.st_mode):
                    # Recreate FIFOs instead of copying: the byte
                    # copy below would block forever on a FIFO with
                    # no writer (the hard-link fast path never saves
                    # it — dst is a fresh tmpfs, so link(2) is always
                    # EXDEV), wedging the whole sandbox setup until
                    # the caller's timeout kills it.
                    # mkfifo's mode argument is masked by the process
                    # umask (it can only narrow, never widen, so it
                    # stays as a tight initial mode); chmod to the
                    # exact source mode afterwards — consistent with
                    # the byte-copy path below.
                    os.mkfifo(dst_file, stat_module.S_IMODE(st.st_mode))
                    os.chmod(dst_file, stat_module.S_IMODE(st.st_mode))
                    continue
                if not stat_module.S_ISREG(st.st_mode):
                    continue  # sockets, device nodes: nothing to copy
                # Try hard-link first (fast, no copy; shares the
                # source inode so mode/owner carry over exactly).
                try:
                    os.link(src_entry, dst_file)
                    continue
                except OSError:
                    pass
                # Byte-budget check applies to the byte-copy path only
                # (a successful hard link above shares the inode and
                # copies nothing).
                if copied_bytes + st.st_size > _ETC_COPY_MAX_BYTES:
                    _phase_trace(
                        b"etc copy skip (size budget): "
                        + os.fsencode(src_entry)
                        + b" (%dB > %dB remaining)"
                        % (st.st_size,
                           _ETC_COPY_MAX_BYTES - copied_bytes)
                    )
                    continue
                # Byte copy, then re-apply the source's mode bits.
                # O_NOFOLLOW + O_NONBLOCK + fstat S_ISREG re-check:
                # the lstat above is advisory — an entry swapped for
                # a FIFO/device between lstat and open must fail or
                # be skipped, never block this pre-exec child.
                sfd = os.open(
                    src_entry,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                )
                try:
                    if not stat_module.S_ISREG(os.fstat(sfd).st_mode):
                        continue
                    with open(dst_file, "wb") as df:
                        while True:
                            chunk = os.read(sfd, 65536)
                            if not chunk:
                                break
                            df.write(chunk)
                            copied_bytes += len(chunk)
                finally:
                    os.close(sfd)
                os.chmod(dst_file, stat_module.S_IMODE(st.st_mode))
            except OSError:
                pass  # skip unreadable entries (shadow, etc.)
        # Enqueue subdirectories AFTER this directory's files so the
        # walk stays breadth-first; the dst dir is created at enqueue
        # time so deeper levels always have their parent.
        for dn in subdirs:
            if entries >= _ETC_COPY_MAX_ENTRIES:
                _phase_trace(
                    b"etc copy budget exceeded (entries=%d): skipping "
                    b"remaining entries" % entries
                )
                warn_post_fork(
                    b"sandbox: mount_ns: /etc overlay copy stopped at "
                    b"the entry budget -- host /etc is pathologically "
                    b"large; the sandbox keeps the entries copied so "
                    b"far (root-level config files copy first)\n"
                )
                return
            entries += 1
            src_sub = os.path.join(dirpath, dn)
            dst_sub = os.path.join(dst_dir, dn)
            try:
                mode = stat_module.S_IMODE(os.lstat(src_sub).st_mode)
            except OSError:
                mode = 0o755
            try:
                os.makedirs(dst_sub, mode, exist_ok=True)
                # makedirs' mode argument is masked by the process
                # umask; re-apply the exact source mode the same way
                # the byte-copy path does (chmod is not umask-masked).
                os.chmod(dst_sub, mode)
            except OSError:
                continue
            queue.append((src_sub, dst_sub))


def _mount_etc_tmpfs_copy(root: str, host_dir: str, inside: str,
                          etc_overlay) -> None:
    """Serve /etc from a private tmpfs populated by a budgeted copy of
    the host /etc, then remount it read-only.

    Used in two situations, both of which make the plain non-recursive
    bind of /etc unusable:

      * etc_overlay entries target paths that don't exist on the host —
        the bind mount's underlying FS permissions block stub creation
        (EACCES: namespace uid != host root) and MNT_LOCKED (kernel
        >= 5.12) blocks remounting RW.
      * The bind itself is refused with EINVAL because /etc carries
        locked child mounts. Container runtimes bind files into /etc
        (resolv.conf, hostname, hosts); those mounts are MNT_LOCKED in
        our fresh user namespace, and the kernel refuses a
        NON-recursive bind of a subtree with locked children (it would
        unmask them). Every standard docker/containerd container hits
        this, so without the tmpfs copy the whole mount-ns backend was
        unavailable inside containers.

    The copy is O(entries-in-etc) with a hard bytes/entry budget (see
    _copy_etc_tree) and is strictly narrowing versus the bind: the
    child sees a private, read-only snapshot; writes can never reach
    host /etc, and the container's locked submounts are not dragged
    into the sandbox.
    """
    _phase_trace(b"etc tmpfs mount: start")
    _mount("tmpfs", inside, "tmpfs", 0, "mode=755")
    _phase_trace(b"etc tmpfs mount: done; etc copy: start")
    _copy_etc_tree(host_dir, inside)
    _phase_trace(b"etc copy: done; stub pre-create: start")
    # Pre-create mount-point stubs for overlay targets that
    # don't exist on the host.
    for ns_target in (etc_overlay or {}):
        if not isinstance(ns_target, str):
            continue
        # Same normalized-absolute-key rule as the 8d bind
        # loop: startswith("/etc/") alone would still pass
        # "/etc/../..."-style keys into the {root} concat.
        if (not ns_target.startswith("/etc/")
                or os.path.normpath(ns_target) != ns_target):
            continue
        stub = f"{root}{ns_target}"
        # lstat, not exists(): _copy_etc_tree recreates host symlinks
        # verbatim, and the stock /etc/resolv.conf ->
        # /run/systemd/resolve/stub-resolv.conf shape resolves in the
        # PRE-pivot namespace — exists() follows it off-path (to the
        # HOST /run), the stub step skips, and the 8d bind then lands
        # at the link's host-side destination instead of
        # {root}/etc/<name>, leaving the post-pivot view dangling and
        # the overlay silently absent. The private tmpfs copy is
        # still RW here: drop the link and let the stub creation
        # below give the bind a real mount point.
        try:
            _stub_st = os.lstat(stub)
        except OSError:
            _stub_st = None
        if (_stub_st is not None
                and stat_module.S_ISLNK(_stub_st.st_mode)):
            try:
                os.unlink(stub)
                _stub_st = None
            except OSError as exc:
                warn_post_fork(
                    b"sandbox: mount_ns: etc_overlay pre-create "
                    b"failed (errno=%d)\n" % (exc.errno or 0,)
                )
                continue
        if _stub_st is None:
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
                    b"sandbox: mount_ns: etc_overlay pre-create "
                    b"failed (errno=%d)\n" % (exc.errno or 0,)
                )
    _phase_trace(b"stub pre-create: done; etc ro remount: start")
    _mount("tmpfs", inside, None,
           MS_REMOUNT | MS_BIND | MS_RDONLY)
    _phase_trace(b"etc ro remount: done")


def _bind_system_ro_dir(d: str, root: str, host_dir: str, inside: str,
                        etc_overlay,
                        etc_has_missing_targets: bool) -> None:
    """Bind one host system dir read-only into the new root (step 4
    unit). /etc routes to the tmpfs+copy lane when overlay targets are
    missing on the host, or when the non-recursive bind is refused with
    EINVAL (locked child mounts — the container-runtime shape described
    on _mount_etc_tmpfs_copy). Any other bind failure, and EINVAL on a
    non-/etc dir, propagates: those are not the known-benign container
    shape, and mounting on regardless would hide a genuinely broken
    system-dir view from the operator.
    """
    if d == "etc" and etc_has_missing_targets:
        _mount_etc_tmpfs_copy(root, host_dir, inside, etc_overlay)
        return
    try:
        _mount(host_dir, inside, None, MS_BIND)
    except OSError as exc:
        if d != "etc" or exc.errno != _EINVAL:
            raise
        warn_post_fork(
            b"sandbox: mount_ns: non-recursive /etc bind refused "
            b"(EINVAL: locked child mounts, typical inside container "
            b"runtimes) -- serving a private read-only tmpfs copy of "
            b"/etc instead\n"
        )
        _mount_etc_tmpfs_copy(root, host_dir, inside, etc_overlay)
        return
    _mount(host_dir, inside, None, _ro_remount_flags(inside))


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


# The device nodes a per-sandbox /dev carries. Everything real tools
# need to START (glibc, ld.so, ASAN, curl, gcc, interpreters): the
# bit-bucket/entropy/discard set plus /dev/tty (a per-process virtual
# device — it resolves to the OPENER's controlling terminal, and the
# sandboxed child is setsid'd with no ctty, so opening it is ENXIO at
# the VFS layer, never the operator's terminal). Deliberately absent:
# host /dev/pts/* (the operator's pty slaves — a fresh devpts instance
# below serves openpty()), block devices, /dev/kvm, /dev/fuse,
# hugepages/mqueue, and every other host node the former recursive
# bind dragged in.
_MINIMAL_DEV_NODES = ("null", "zero", "full", "random", "urandom", "tty")


def _mount_minimal_dev(root: str) -> None:
    """Build a minimal per-sandbox /dev instead of recursively binding
    the host's.

    The recursive host bind carried ALL host nodes — including
    /dev/pts/* — into the sandbox, and the default posture
    (``restrict_reads=False``) leaves reads unrestricted, so a hostile
    build script or fuzz target in the default lane could read-open
    the operator's same-uid pty slave and compete for keystrokes.
    Landlock narrowing never covered this lane. A fresh tmpfs with
    per-node binds (the rootless-container construction: mknod needs
    CAP_MKNOD in the INIT userns, but bind-mounting an existing host
    node re-uses the host devtmpfs superblock, which the userns
    SB_I_NODEV restriction does not apply to) provides exactly the
    nodes tools need and nothing else.

    Failure policy: a missing ESSENTIAL node (null/zero/urandom —
    everything from shell redirection to glibc startup assumes them)
    raises (OSError → the spawn child's setup handler; a host without
    a bindable /dev/null is broken, and continuing would produce
    subtly-wrong tool behaviour). The optional nodes (full, random,
    tty) and the fresh devpts instance degrade with a warning — their
    absence costs capability but exposes nothing, the correct failure
    direction for this control. A host /dev entry that is not a char
    device refuses setup outright (tampered/exotic host).
    """
    dev = f"{root}/dev"
    _mount("tmpfs", dev, "tmpfs", 0, "mode=755")
    _essential = ("null", "zero", "urandom")
    for name in _MINIMAL_DEV_NODES:
        host_node = f"/dev/{name}"
        try:
            st = os.lstat(host_node)
        except OSError as exc:
            if name in _essential:
                # See the failure policy in the docstring: a host
                # without /dev/null (or zero/urandom) is broken, and
                # a sandbox silently missing it produces subtly-wrong
                # tool behaviour downstream.
                raise OSError(
                    exc.errno or _ELOOP,
                    f"mount_ns: essential host node {host_node} is "
                    f"missing; refusing a degraded /dev",
                ) from exc
            # Optional node absent (containers sometimes lack
            # /dev/full): nothing to expose, nothing to bind.
            warn_post_fork(
                b"mount_ns: host /dev/" + name.encode()
                + b" missing; sandbox /dev goes without it\n")
            continue
        if not stat_module.S_ISCHR(st.st_mode):
            # A host /dev entry that is not a character device is a
            # tampered or exotic host; refuse to carry it in. NOTE:
            # this raise surfaces as an 'M' setup status, whose
            # degrade path retries MOUNTLESS — where the host's whole
            # /dev is visible again. Acceptable: triggering this
            # requires a root-tampered host /dev, and the mountless
            # lane's posture is stamped/warned on its own terms.
            raise OSError(
                _ELOOP,
                f"mount_ns: host {host_node} is not a character "
                f"device; refusing to bind it into the sandbox",
            )
        stub = f"{dev}/{name}"
        os.close(os.open(stub, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                         0o600))
        _mount(host_node, stub, None, MS_BIND)
    # Self-referential conveniences every /dev ships (bash process
    # substitution reads /dev/fd; tools open /dev/std*). Symlinks into
    # the (per-pid-ns, freshly remounted) procfs.
    os.symlink("/proc/self/fd", f"{dev}/fd")
    os.symlink("/proc/self/fd/0", f"{dev}/stdin")
    os.symlink("/proc/self/fd/1", f"{dev}/stdout")
    os.symlink("/proc/self/fd/2", f"{dev}/stderr")
    # /dev/shm: fresh tmpfs so POSIX shared memory / named semaphores
    # (shm_open, sem_open — Python multiprocessing's SemLock) work
    # WITHOUT exposing the host's shm segments. Mode 1777 matches the
    # host convention (sticky world-writable scratch).
    os.makedirs(f"{dev}/shm", exist_ok=True)
    _mount("tmpfs", f"{dev}/shm", "tmpfs", 0, "mode=1777")
    # Fresh devpts instance: serves openpty()/script/expect INSIDE the
    # sandbox with pty pairs that exist only in this namespace — the
    # host's pts nodes are simply not present. ptmxmode=0666 lets the
    # (non-root-mapped) child open the multiplexor; the ptmx symlink
    # is the modern layout glibc's openpty resolves.
    pts = f"{dev}/pts"
    os.makedirs(pts, exist_ok=True)
    try:
        _mount("devpts", pts, "devpts", 0,
               "newinstance,ptmxmode=0666,mode=0620")
    except OSError:
        # Capability degrade, not exposure: no ptys inside the
        # sandbox. Kernels that refuse a userns devpts mount are the
        # only known shape.
        warn_post_fork(
            b"mount_ns: fresh devpts mount failed; openpty() will not "
            b"work inside this sandbox (host ptys stay hidden)\n")
    else:
        os.symlink("pts/ptmx", f"{dev}/ptmx")


def setup_mount_ns(target: str | None, output: str | None,
                   extra_ro_paths: Iterable[str] | None = None,
                   extra_rw_paths: Iterable[str] | None = None,
                   root_path: str | None = None,
                   persona: Optional["Persona"] = None,
                   etc_overlay: dict | None = None,
                   stage_files: dict | None = None,
                   rw_submounts_ok: bool = False,
                   rootfs: str | None = None,
                   require_target_ro: bool = False,
                   src_fds: dict[str, int] | None = None,
                   fresh_netns: bool = False) -> None:
    """Establish pivot_root'd tmpfs sandbox root.

    `fresh_netns`: the caller unshared a NEW network namespace for
    this child. Enables the fresh per-namespace sysfs at /sys (only
    mountable when the userns owns the netns), which hides host NIC
    names/MACs; False keeps the host /sys rbind.

    `extra_rw_paths`: caller-granted WRITABLE roots that live outside
    every tree this view otherwise carries, bound READ-WRITE at their
    original paths (the deliberate view extension for legitimate
    cross-lane write grants — e.g. a shared log directory that is
    live policy on the host-view lanes). Same normalisation, shadow /
    masked-path and pinning rules as `extra_ro_paths`; the only
    difference is that no read-only remount follows the bind. When
    pinning is engaged (`src_fds`), every entry here MUST carry a pin
    — the parent takes them as REQUIRED pins
    (`_spawn._pin_bind_sources`), so an unpinned entry means a direct
    caller skipped that step and the entry is skipped fail-closed
    like an unpinned read-only extra (the write grant stays dead
    rather than re-opening the mount-time-resolution window).

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

    `src_fds` (Optional[dict[str, int]]): validation-time O_PATH pins
    for the bind SOURCES, keyed by ``_pathpin.canonical_bind_path`` of
    the caller path (target / output / rootfs / each extra_ro_paths
    entry). The
    parent opens these via a symlink-refusing walk BEFORE forking this
    child (fds survive fork), and every bind here refuses to mount
    unless its freshly-walked source inode is IDENTICAL to the
    validation-pinned one (see ``_bind_pinned_source``) — so a
    symlink planted at a source path any time after the parent's
    validation (including the whole fork/newuidmap window) cannot
    steer a bind; it can only fail the setup loudly. Fd type (dir vs
    file) decisions for extra_ro_paths use ``fstat`` on the pinned
    fd, never the (swappable) pathname. When ``src_fds`` is provided,
    an extra_ro_paths entry WITHOUT a pin is skipped outright (the
    parent found it non-pinnable at validation; falling back to
    mount-time resolution would reopen the window as a downgrade
    lever). When ``src_fds`` is None (direct/legacy callers), every
    bind falls back to mount-time pinning — see
    ``_bind_pinned_source``. The fds are NOT closed here; the caller
    owns their lifetime.
    """
    def _src_fd(path: str) -> int | None:
        return None if src_fds is None else src_fds.get(path)

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
    # Canonicalise, not just absolutize: POSIX preserves an exactly-
    # two-slash prefix through abspath, so a "//"-spelled path names
    # the same file under a spelling every exact-string policy check
    # in this function (shadow-path refusal, ancestor classification,
    # masked-path refusal, target/output identity, pin lookup) would
    # miss. _canonical_bind_path collapses it; the parent-side pin
    # keys use the same helper.
    if target:
        target = _canonical_bind_path(target)
    if output:
        output = _canonical_bind_path(output)
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
        # Canonicalise with the SAME helper the parent keys pins
        # with — plain abspath preserves an exactly-two-slash prefix,
        # so a "//"-spelled rootfs looked its pin up under the wrong
        # key, missed, and downgraded to mount-time window-narrowing
        # on the environment's ROOT (bound writable).
        rootfs = _canonical_bind_path(rootfs)
        _bind_pinned_source(rootfs, root, MS_BIND,
                            pinned_fd=_required_pin_fd(src_fds, rootfs))
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
        _bind_system_ro_dir(d, root, host_dir, inside, etc_overlay,
                            _etc_has_missing_targets)

    # 5. /dev: minimal per-sandbox device set (see _mount_minimal_dev
    # — the former recursive host bind carried EVERY host node,
    # including /dev/pts/*, into the sandbox, and the default
    # read-unrestricted posture let the child read-open the operator's
    # pty slave). /sys: a FRESH sysfs instance when the caller created
    # a fresh network namespace — sysfs's net class is netns-tagged,
    # so the fresh instance shows only ns-local devices, while the
    # host rbind exposed every host NIC name and MAC address
    # (/sys/class/net/*/address) inside "network-blocked" runs — a
    # host fingerprint the anti-fingerprint posture is supposed to
    # withhold. (The kernel permits the sysfs mount exactly when the
    # mounting userns owns the netns.) Without a fresh netns the
    # kernel refuses the sysfs mount, so the host rbind remains the
    # only option there; a refusal on the fresh-netns lane degrades
    # the same way, warned (fingerprint residual, not a containment
    # loss).
    _mount_minimal_dev(root)
    _fresh_sys = False
    if fresh_netns:
        try:
            _mount("sysfs", f"{root}/sys", "sysfs")
            _fresh_sys = True
        except OSError:
            warn_post_fork(
                b"mount_ns: fresh sysfs mount failed; host /sys "
                b"(incl. NIC names/MACs) stays visible in the "
                b"sandbox\n")
    if not _fresh_sys:
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
        if (_norm.startswith(("/tmp/", "/var/tmp/"))
                and _BRANDED_TMP_RE.search(_norm)):
            # Framework-named temp path (launcher session scratch,
            # harness session dirs): the target env no longer
            # references it (context rewrites the temp vars away),
            # so re-creating it would only replant the framework-
            # naming directory into the target-visible private
            # tmpfs. Keep in sync with core/sandbox/context.py.
            continue
        if not _norm.startswith("/tmp/"):
            # Re-creation stays /tmp-anchored (the per-ns tmpfs);
            # /var/tmp sits under the read-only /var bind where a
            # makedirs would only warn-spam.
            continue
        try:
            os.makedirs(f"{root}{_norm}", mode=0o1777, exist_ok=True)
        except OSError as exc:
            warn_post_fork(
                b"sandbox: mount_ns: temp-env dir re-create failed "
                b"(errno=%d)\n" % (exc.errno or 0)
            )

    # Mount-ordering invariant (steps 8 / 8b): a mount attached at a
    # path COVERS (shadows) every earlier mount attached at or below
    # that path — path resolution always enters the topmost (most
    # recently attached) mount on a dentry. So for any two binds where
    # one path is a proper ancestor of the other, the ANCESTOR must
    # mount first; the descendant then stacks on top of the ancestor's
    # mount and keeps its own semantics (rw output visible over an ro
    # ancestor, ro file visible over the rw output). The pre-fix code
    # ordered by CLASS — target/output in step 8, every extra_ro_paths
    # entry in step 8b — so an extra read-only bind naming an ancestor
    # of the output dir (an output dir living inside a readable tree,
    # e.g. a run dir under a repo checkout that is itself in
    # readable_paths) mounted AFTER the rw output bind and shadowed
    # it: the child's own output dir went read-only and every write
    # crashed, while a sibling extra_ro entry under the same ancestor
    # stayed visible only because the caller happened to list the
    # ancestor first. Fix: classify the extra binds up front, mount
    # the proper ancestors of target/output BEFORE step 8 (so the
    # target/output binds — and the 8a/8a2 shadows stacked on them —
    # always end up on top), keep the rest after 8a/8a2, and process
    # the whole list ancestors-first (stable component-count sort)
    # so intra-list nesting never depends on caller order.
    #
    # ``_bound_dirs``: directories already bind-mounted into the
    # namespace — step 4's system dirs plus target/output plus any
    # directory the extra loop binds. When an extra FILE path falls
    # under a bound directory, its mount point already exists
    # (populated by the covering bind) so stub creation is skipped:
    # the O_CREAT|O_EXCL stub open would otherwise fail EEXIST and
    # abort the whole spawn (exit 126) — observed as flaky sandboxed
    # runs whenever the scanned tree names its own files in
    # readable_paths. This is a precise predicate: creation is only
    # skipped when *we* know the parent was bound, not for arbitrary
    # pre-existing paths. NOT the full _SHADOW_PATHS set: /tmp and
    # /run are fresh EMPTY tmpfs (step 7), not host binds — nothing
    # populated their subtrees, so mount-point stubs beneath them must
    # still be created. "/" is harmless either way (the `d + "/"`
    # prefix test never matches it) but excluded for accuracy.
    _bound_dirs: set = {
        "/dev", "/proc", "/sys",
        *(f"/{d}" for d in _SYSTEM_RO_DIRS),
    }

    # Normalise + classify the caller's extra read-only paths into an
    # ordered mount plan (path, pinned_fd, is_dir, is_file). Each check
    # keeps its pre-existing semantics; only the TIME of classification
    # moves (a few syscalls earlier in the same child — the pinned-fd
    # lane was race-free either way, and the legacy no-pin lane keeps
    # its documented window-narrowing-only contract).
    # 8a/8a2 masked views inside the target/output binds: the
    # evidence dir and the run-marker content are deliberately hidden
    # from the child. An extra bind at or below a masked path would
    # mount in the post pass — AFTER the masks — and stack a live
    # host view over them, unmasking the finder dossier / evidence
    # dir through the child's own readable_paths. Refused loudly in
    # the plan loop below; dropping the bind NARROWS the child's view
    # and keeps the mask — the correct failure direction for a
    # masking control. On a WSL host the Windows-interop/driver mask
    # set (see _WSL_MASKED_PATHS) joins the same policy: the 8f mask
    # mounts and the per-ns tmpfs/minimal-dev structural absences
    # must stay authoritative against caller-supplied readable binds.
    # Off-WSL the tuple is byte-identical to the pre-WSL shape.
    _wsl_host = _is_wsl_host()
    _masked_paths: tuple = tuple(
        {f"{p}/.audit" for p in (target, output) if p}
        | ({f"{output}/.raptor-run.json"} if output else set())
        | (set(_WSL_MASKED_PATHS) if _wsl_host else set())
    )
    # Resolved twins of the masked paths, for the DESTINATION leg of
    # the refusal below: the lexical check compares the caller's
    # spelling, but the bind machinery mounts the RESOLVED source
    # (inode-pinned), so a symlink whose destination sits at/below a
    # masked path would bind the live host view at an off-mask
    # spelling. realpath never raises and normalises nonexistent
    # tails component-wise (the .audit dir may not exist yet).
    _masked_paths_resolved: tuple = tuple(dict.fromkeys(
        os.path.realpath(m) for m in _masked_paths))

    _extra_entries: list[tuple[str, int | None, bool, bool, bool]] = []
    _seen_extra_ro: set = set()
    # Read-write extras first: a path arriving through BOTH lists gets
    # ONE bind and it must be the read-write one (the rw grant is the
    # caller's stronger declared intent; an ro bind stacked instead
    # would kill every child write with EROFS).
    for path, _extra_rw in (
            *((p, True) for p in (extra_rw_paths or ())),
            *((p, False) for p in (extra_ro_paths or ())),
    ):
        if not path:
            continue
        # Canonicalise like target/output above — a relative or
        # non-normalized entry ("etc", "/tmp/../etc") would evade
        # the exact-string shadow check and produce a malformed
        # bind target ("{root}etc") that diverges from the path
        # the caller's Landlock read rule references; a "//"-spelled
        # entry ("//tmp") would evade the shadow check outright and
        # bind HOST /tmp over the fresh per-ns tmpfs, or miss the
        # ancestor classification and re-shadow the rw output.
        path = _canonical_bind_path(path)
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
        # Per-process procfs magic links (/proc/self/*,
        # /proc/thread-self/*) resolve to a DIFFERENT file for
        # every walking process, so a validation-time pin taken
        # in the parent can never match this child's mount-time
        # walk — an identity mismatch here is inherent volatility,
        # never a replaced source, and must not trip the tamper
        # refusal below. There is also nothing to bind: the /proc
        # mount already serves these paths per-reader, and
        # freezing one process's view over the magic link would
        # hand every sandboxed process the binder's own
        # per-process files (e.g. a host-layout cgroup path the
        # fresh cgroup namespace exists to hide). Skip the bind.
        # Every other source class names one stable filesystem
        # object, where an identity change can only mean the
        # object was swapped after validation — the tamper
        # refusal stays authoritative there.
        if _is_per_process_procfs(path):
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
        if any(path == m or path.startswith(m + "/")
               for m in _masked_paths):
            # Masked-view policy (see _masked_paths above): never
            # bind a readable view at or below the evidence dir or
            # the run marker — the mask must stay on top.
            try:
                _path_b = path.encode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                _path_b = b"<unencodable>"
            warn_post_fork(
                b"mount_ns: refusing readable bind at masked path "
                + _path_b
                + b" (evidence-dir shadow / run-marker mask stays "
                b"authoritative)\n"
            )
            continue
        # Dir-vs-file decides stub creation below; derive it from
        # the PINNED inode when a validation-time fd exists — the
        # pathname isdir/isfile pair follows symlinks and is
        # swappable between here and the bind. With pinning
        # engaged (src_fds is not None), an entry the parent could
        # not pin is skipped outright: it did not exist at
        # validation, and falling back to mount-time resolution
        # would hand a concurrent writer a downgrade lever (plant
        # the path after validation, get it bound).
        _extra_fd = _src_fd(path)
        if _extra_fd is not None:
            _pin_mode = os.fstat(_extra_fd).st_mode
            _extra_is_dir = stat_module.S_ISDIR(_pin_mode)
            _extra_is_file = stat_module.S_ISREG(_pin_mode)
        elif src_fds is not None:
            continue
        else:
            _extra_is_dir = os.path.isdir(path)
            _extra_is_file = os.path.isfile(path)
        if not _extra_is_dir and not _extra_is_file:
            continue
        # Masked-path refusal, DESTINATION leg: the lexical check
        # above compares the caller's spelling, but what a bind
        # mounts is the RESOLVED source — a symlink at an off-mask
        # spelling whose destination sits at/below a masked path
        # would stack the live host view of the masked content into
        # the child at the link path. Refuse on the destination too:
        # the pinned lane reads the PIN's own resolution (the exact
        # inode path the bind would mount, immune to a post-pin
        # re-point of the link); the legacy lane realpaths the
        # entry. Same failure direction as the lexical leg —
        # dropping the bind narrows the view and keeps the mask.
        if _masked_paths:
            _dest = None
            if _extra_fd is not None:
                try:
                    _dest = os.readlink(f"/proc/self/fd/{_extra_fd}")
                except OSError:
                    _dest = None
            if _dest is None:
                _dest = os.path.realpath(path)
            if any(_dest == m or _dest.startswith(m + "/")
                   for m in _masked_paths_resolved):
                try:
                    _dest_b = _dest.encode("utf-8", errors="replace")
                except Exception:  # noqa: BLE001
                    _dest_b = b"<unencodable>"
                warn_post_fork(
                    b"mount_ns: refusing readable bind at masked path "
                    + _dest_b
                    + b" (resolved destination of a caller entry; "
                    b"evidence-dir shadow / run-marker mask / WSL "
                    b"interop mask stays authoritative)\n"
                )
                continue
        _extra_entries.append(
            (path, _extra_fd, _extra_is_dir, _extra_is_file,
             _extra_rw))
    # Ancestors before descendants: component count orders any
    # ancestor strictly before its descendants; the sort is stable,
    # so unrelated entries keep caller order.
    _extra_entries.sort(key=lambda entry: entry[0].count("/"))

    def _bind_one_extra_ro(path: str, _extra_fd: int | None,
                           _extra_is_dir: bool,
                           _extra_is_file: bool,
                           _extra_rw: bool = False) -> None:
        """Bind one extra path (step 8b unit). Read-only entries get
        the same two-step bind+remount-ro as target; read-write
        entries (`extra_rw_paths` — the deliberate out-of-view grant
        carry) keep the bind writable, exactly like the output bind.
        Shadow-skip rules already applied by the mount-plan
        normalisation above."""
        _label = b"extra_rw_paths" if _extra_rw else b"extra_ro_paths"
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
            if _extra_is_dir:
                _step = b"makedirs"
                os.makedirs(inside, exist_ok=True)
                _bound_dirs.add(path)
            elif any(path.startswith(d + "/") for d in _bound_dirs):
                # Mount point already exists — a parent directory
                # (e.g. /etc from step 4, the step-8 target/output
                # bind, or an earlier extra_ro_paths entry) was
                # bind-mounted into the namespace, which populated
                # this path.  Skip creation and proceed to the
                # overlay bind.
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
                _bind_pinned_source(path, inside, MS_BIND,
                                    pinned_fd=_extra_fd)
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
                # Read-write entries may recurse unconditionally: the
                # whole bind is writable by declaration, so carried
                # submounts staying rw claims nothing the top mount
                # doesn't already.
                if bind_exc.errno != _EINVAL or not (rw_submounts_ok
                                                     or _extra_rw):
                    raise
                _bind_pinned_source(path, inside, MS_BIND | MS_REC,
                                    pinned_fd=_extra_fd)
                try:
                    _path_b = path.encode("utf-8", errors="replace")
                except Exception:  # noqa: BLE001
                    _path_b = b"<unencodable>"
                warn_post_fork(
                    b"mount_ns: " + _label + b" recursive bind for "
                    + _path_b
                    + (b" (locked submounts)\n" if _extra_rw else
                       b" (locked submounts); submount ro relies on"
                       b" Landlock\n")
                )
            if _extra_rw:
                # Read-write carry: no ro remount — the bind stays
                # writable like the output bind; Landlock's write
                # rule (view-anchored to this path) scopes it.
                return
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
            # The stderr line stays the human-readable diagnostic;
            # the typed raise (instead of the old direct
            # os._exit, which emitted NO status byte and let the
            # parent misread the aborted setup as a genuine
            # rc=126 target result) reaches _spawn's setup
            # handler, which reports fail-closed category 'C' on
            # the exec-status pipe and exits — same fail-closed
            # outcome, now observable and unspoofable.
            try:
                _path_b = path.encode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                _path_b = b"<unencodable>"
            try:
                os.write(
                    2,
                    b"sandbox: mount_ns: " + _label + b" "
                    + _step
                    + b" failed for "
                    + _path_b
                    + b" (errno=%d), exiting\n" % (exc.errno or 0),
                )
            except OSError:
                pass
            _step_s = _step.decode("ascii", "replace")
            _label_s = _label.decode("ascii", "replace")
            raise ExtraRoBindError(
                exc.errno or 0,
                f"{_label_s} {_step_s} failed for {path!r}",
            ) from exc

    # Split the plan: DIRECTORY entries that are proper ancestors of
    # the step-8 target/output paths mount NOW, before step 8, so the
    # rw output bind (and the ro target bind with its 8a evidence
    # shadow and 8a2 marker mask) stacks on top of them and stays the
    # child-visible view; everything else keeps its step-8b slot. A
    # regular-file entry can never be a path ancestor of a directory,
    # so file entries always stay in the 8b pass.
    _step8_paths = tuple(
        p for p in (target, output) if p and not _shadows_per_ns(p))
    _extra_pre = [
        entry for entry in _extra_entries
        if entry[2] and any(p.startswith(entry[0] + "/")
                            for p in _step8_paths)
    ]
    _extra_post = [e for e in _extra_entries if e not in _extra_pre]
    for _entry in _extra_pre:
        _bind_one_extra_ro(*_entry)

    # 8. Bind target and output at their ORIGINAL absolute paths.
    # After pivot_root, the child still refers to /tmp/vulns (or whatever
    # the caller passed) — no argv rewriting needed. If the caller's
    # path is one we've already served via a per-ns mount, skip so we
    # don't fight our own stack.
    def _step8_refuse_symlink_walk(path: str) -> None:
        """Refuse symlink components under {root}{path} for a step-8
        bind whose mount point lies BELOW a pre-mounted readable
        ancestor (and in rootfs mode, unconditionally — the original
        contract). With an ancestor bind in place, the makedirs and
        the mount(2) pathname below walk THROUGH that bind's
        (potentially hostile) repo content pre-pivot: a symlink
        component would divert inode creation or the mount TARGET
        onto host paths. The lstat walk refuses that shape. On a live
        host tree this is window-narrowing (the bind source can
        change between walk and mount, unlike the static rootfs
        image); the residual is contained regardless: the bind
        SOURCE is inode-pinned (cannot be steered), the mount lands
        only in this PRIVATE namespace (step 1 rprivate — never the
        host's view), and any diverted makedirs runs as the caller's
        own uid (no privilege gained), with Landlock's write mask as
        the backstop."""
        if rootfs or any(path.startswith(e[0] + "/")
                         for e in _extra_pre):
            _refuse_image_symlink_components(root, path)

    def _bind_target_step8() -> None:
        inside = f"{root}{target}"
        _step8_refuse_symlink_walk(target)
        os.makedirs(inside, exist_ok=True)
        _bind_pinned_source(target, inside, MS_BIND,
                            pinned_fd=_required_pin_fd(src_fds, target))
        _bound_dirs.add(target)
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

    def _bind_output_step8() -> None:
        inside = f"{root}{output}"
        _step8_refuse_symlink_walk(output)
        os.makedirs(inside, exist_ok=True)
        _bind_pinned_source(output, inside, MS_BIND,
                            pinned_fd=_required_pin_fd(src_fds, output))
        _bound_dirs.add(output)

    _do_target = bool(target and not _shadows_per_ns(target))
    _do_output = bool(output and output != target
                      and not _shadows_per_ns(output))
    if (_do_target and _do_output
            and target.startswith(output + "/")):
        # Output is a proper ancestor of target: same ancestors-first
        # invariant as above — the output bind mounts first so the ro
        # target bind stacks on top of it and the target stays
        # read-only through the child's view (target-then-output
        # order would shadow the ro target under the rw output bind).
        _bind_output_step8()
        _bind_target_step8()
    else:
        if _do_target:
            _bind_target_step8()
        if _do_output:
            _bind_output_step8()

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
                    b"sandbox: mount_ns: refusing evidence-dir shadow "
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
                b"sandbox: mount_ns: evidence-dir shadow mount failed "
                b"(errno=%d); relying on evidence-file inode "
                b"verification\n" % (exc.errno or 0)
            )
        finally:
            os.close(_evfd)

    # 8a2. Mask the run-marker CONTENT inside the rw output bind.
    # ``.raptor-run.json`` records the RAPTOR git sha/version, the
    # operator's finder identity, the target's provenance, and the
    # exact command line — a one-read dossier for any payload with the
    # rw output grant. The child never needs it (every reader/writer
    # is parent-side), so stack an empty read-only file over the
    # child-view mount point. Same O_PATH pinning discipline as the
    # .audit shadow above: the output bind can be shared with a live
    # sibling, so never resolve a pathname twice. The lock file is
    # 0-byte by contract already; the marker name itself remains
    # visible (renaming the on-disk marker is a run-machinery contract
    # change, out of scope here) — the CONTENT is the disclosure.
    if output:
        _mask_stub = f"{root}/run/.marker-mask"
        _stub_fd_ok = False
        try:
            _sfd = os.open(_mask_stub,
                           os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o444)
            os.close(_sfd)
            _stub_fd_ok = True
        except OSError:
            pass
        if _stub_fd_ok:
            _marker = f"{root}{output}/.raptor-run.json"
            try:
                _mfd = os.open(_marker,
                               os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
            except OSError:
                _mfd = -1
            if _mfd >= 0:
                try:
                    _mst = os.fstat(_mfd)
                    if stat_module.S_ISREG(_mst.st_mode):
                        _mount(_mask_stub, f"/proc/self/fd/{_mfd}",
                               None, MS_BIND)
                except OSError as exc:
                    warn_post_fork(
                        b"sandbox: mount_ns: run-marker mask failed "
                        b"(errno=%d); the run metadata stays readable "
                        b"through the output bind\n" % (exc.errno or 0)
                    )
                finally:
                    os.close(_mfd)

    # 8b. Bind the remaining extra read-only paths the caller
    # requested (via readable_paths in the public sandbox API). Each
    # is bind-mounted at its original absolute path, so the child sees
    # it exactly where the caller expects. The mount plan was
    # normalised, classified, and ancestor-sorted before step 8;
    # proper ancestors of target/output already mounted there — these
    # entries are the rest (files under the target/output binds,
    # unrelated trees, nested entries in ancestor-first order). Safe
    # to stack after the 8a/8a2 shadows: none of them covers the
    # output or the target (ancestors were hoisted, exact matches
    # skipped), and entries at or below the two MASKED paths were
    # refused in the plan loop — a later bind there would land on top
    # of the mask and unmask it.
    for _entry in _extra_post:
        _bind_one_extra_ro(*_entry)

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
        _phase_trace(b"etc_overlay binds: start")
        for ns_target, host_source in etc_overlay.items():
            if not isinstance(ns_target, str) or not isinstance(host_source, str):
                warn_post_fork(
                    b"sandbox: mount_ns: etc_overlay entry skipped - "
                    b"both keys and values must be str paths\n"
                )
                continue
            # Keys are concatenated onto the staging root below —
            # accept only normalized absolute paths so a "..", "" or
            # relative key can never drive the pre-pivot makedirs /
            # O_CREAT / mount(2) OUTSIDE the staging root on the host
            # (today's producers are internal, but image-derived
            # values will flow here; fail safe now).
            # normpath PRESERVES the POSIX two-slash prefix, so a
            # "//etc/x" key would pass as normalized; the {root}
            # concat stays in-tree (an empty path component), but the
            # "/etc/"-prefix stub logic and every exact-string
            # comparison would misclassify the spelling — reject it.
            if (not ns_target.startswith("/")
                    or ns_target.startswith("//")
                    or os.path.normpath(ns_target) != ns_target
                    or ns_target == "/"):
                warn_post_fork(
                    b"sandbox: mount_ns: etc_overlay entry skipped - "
                    b"key must be a normalized absolute path\n"
                )
                continue
            inside = f"{root}{ns_target}"
            _phase_trace(b"etc_overlay bind: " + os.fsencode(ns_target))
            if not os.path.exists(host_source):
                warn_post_fork(
                    b"sandbox: mount_ns: etc_overlay source missing; "
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
                        b"sandbox: mount_ns: etc_overlay could not "
                        b"create in-sandbox target; skipping bind\n"
                    )
                    continue
            # Refuse to bind onto a symlink: mount(2) takes a
            # pathname and resolves it in the PRE-pivot namespace, so
            # a symlinked target (the host /etc plain-bind lane
            # serving the stock resolv.conf link) lands the overlay
            # at the link's HOST-side destination — silently
            # off-path, with the post-pivot view dangling. The
            # tmpfs-copy lane replaces such links with stubs before
            # this loop; anything still a symlink here sits on a
            # read-only view this code must not follow (fail closed:
            # same honest un-overlaid outcome as a failed bind).
            try:
                if stat_module.S_ISLNK(os.lstat(inside).st_mode):
                    warn_post_fork(
                        b"sandbox: mount_ns: etc_overlay target is a "
                        b"symlink in the sandbox view; refusing to "
                        b"follow it - overlay entry absent, target "
                        b"sees the un-overlaid view of this path\n"
                    )
                    continue
            except OSError:
                # Missing/vanished: the bind below reports it.
                pass
            try:
                _bind_pinned_source(host_source, inside, MS_BIND)
            except OSError:
                # Accurate in BOTH /etc branches: on the plain-bind
                # path the target sees the host file at this path; on
                # the tmpfs+copy path it sees the copied (un-overlaid)
                # /etc view — never "host /etc" as the old message
                # claimed.
                warn_post_fork(
                    b"sandbox: mount_ns: etc_overlay bind failed; "
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
                    b"sandbox: mount_ns: etc_overlay remount-ro failed "
                    b"(errno=%d); overlay entry withdrawn "
                    b"(fail-closed)\n" % (exc.errno or 0)
                )
        _phase_trace(b"etc_overlay binds: done")

    # 8e. Caller-supplied stage_files — materialise arbitrary files in
    # the tmpfs root so they appear at their namespace path post-pivot.
    if stage_files:
        for stage_target, stage_content in stage_files.items():
            if not isinstance(stage_target, str) or not stage_target.startswith("/"):
                warn_post_fork(
                    b"sandbox: mount_ns: stage_files target must be an "
                    b"absolute path str; skipping\n"
                )
                continue
            if not isinstance(stage_content, (bytes, bytearray)):
                warn_post_fork(
                    b"sandbox: mount_ns: stage_files content must be "
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
                    b"sandbox: mount_ns: stage_files failed for "
                    + _target_b
                    + b" (errno=%d); target will not see this file\n"
                    % (exc.errno or 0)
                )

    # 8f. WSL host: mask the Windows-interop/driver directories that
    # ride the host binds into the view (the binfmt_misc registration
    # mount under the step 6 /proc bind; /usr/lib/wsl under the step 4
    # /usr bind — host-root mode; in rootfs mode the path exists only
    # if the image ships it, and masking an image copy is harmless in
    # the deny direction). Placed LAST among the mount steps so no
    # extra bind, persona overlay, or etc_overlay entry can stack a
    # live view back on top; the plan loop's masked-path refusal
    # already rejects binds at or below each entry. Same convention
    # as the 8a evidence-dir shadow: O_PATH-pinned mount point (never
    # a twice-resolved pathname), a single empty read-only tmpfs, and
    # a warn-not-abort failure direction — these masks are
    # deny-direction hardening; the interop ESCAPE channel is closed
    # structurally (fresh /run tmpfs is fail-closed, WSL_INTEROP /
    # WSLENV are dropped by the env allowlist scrub). Inert off-WSL:
    # _wsl_host is False and no mount is attempted.
    if _wsl_host:
        for _wsl_dir in _WSL_MASK_MOUNT_DIRS:
            _wsl_mp = f"{root}{_wsl_dir}"
            try:
                _wfd = os.open(_wsl_mp, os.O_PATH | os.O_NOFOLLOW
                               | os.O_DIRECTORY | os.O_CLOEXEC)
            except FileNotFoundError:
                continue
            except OSError:
                warn_post_fork(
                    b"sandbox: mount_ns: WSL mask target "
                    + _wsl_dir.encode("ascii")
                    + b" is not an openable directory; mask skipped\n"
                )
                continue
            try:
                _mount("tmpfs", f"/proc/self/fd/{_wfd}", "tmpfs",
                       MS_RDONLY, "mode=700")
            except OSError as exc:
                warn_post_fork(
                    b"sandbox: mount_ns: WSL interop mask failed for "
                    + _wsl_dir.encode("ascii")
                    + b" (errno=%d); the host view of this path stays "
                    b"readable in the sandbox\n" % (exc.errno or 0)
                )
            finally:
                os.close(_wfd)

    # 9. pivot_root. put_old must be a directory INSIDE new_root.
    # Last pre-pivot marker: the trace file lives on a HOST path, so
    # by design no marker can follow this one — a trace ending here
    # means the wedge (if any) is post-pivot (Landlock/seccomp/exec).
    _phase_trace(b"pivot_root: start (final pre-pivot marker)")
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
