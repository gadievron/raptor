"""Static guards for the 2026-06-15 sandbox substrate fixes.

Three orthogonal sandbox-side fixes landed together to unblock the
exploit-engine's runtime_inspect tool and its etc_overlay file-creation
path. Each fix has its own static guard so a regression of one
doesn't silently re-introduce the bug class while leaving the others
intact:

  1. ``skip_pid_ns`` opt-in on ``_spawn.run_sandboxed`` (and the
     context.sandbox forwarder). When set, the sandbox child does
     NOT enter a fresh ``CLONE_NEWPID``. gdb's host-info probe
     reads ``/proc/1/*`` at startup; in a nested pid-ns init resolves
     to systemd via ``init_user_ns`` where our nested CAP_SYS_PTRACE
     doesn't apply, so the probe returns -EPERM and gdb aborts before
     it can place breakpoints. Found via bpftrace 2026-06-14.

  2. ``etc_overlay`` remount-rw cycle in ``mount_ns.setup_mount_ns``.
     Step 4 binds the host's ``/etc`` into the sandbox read-only. If
     any etc_overlay entry needs a new file/dir created under ``/etc``
     (e.g. ``/etc/pam.d/sudoedit`` for the sudo Problem) the
     subsequent ``open()`` raised EROFS and the overlay was silently
     dropped. The fix flips /etc rw via MS_REMOUNT|MS_BIND, creates
     the placeholder targets, then leaves the overlay binds intact.

  3. ``process_vm_readv`` / ``process_vm_writev`` moved out of
     ``_SECCOMP_BLOCK_ALWAYS`` in ``seccomp.py``. gdb's inferior-memory
     plumbing under runtime_inspect needs both. The default posture
     still blocks them — only callers asking for the explicit
     debug-permissive profile widen the surface.

These are STATIC GUARDS: they read the affected source files and
assert the fix-defining structures are present. Driving the actual
fix through the kernel paths would need user-ns + fork + seccomp
filter loading; those integration tests live elsewhere and skip
gracefully on dev boxes without the right prerequisites. The static
guards are the fast/cheap layer that catches "someone deleted the
relevant lines" type regressions deterministically.
"""

from __future__ import annotations

import re
from pathlib import Path


_SANDBOX = Path(__file__).resolve().parent.parent
_SPAWN = _SANDBOX / "_spawn.py"
_CONTEXT = _SANDBOX / "context.py"
_MOUNT_NS = _SANDBOX / "mount_ns.py"
_SECCOMP = _SANDBOX / "seccomp.py"
_MACOS_SPAWN = _SANDBOX / "_macos_spawn.py"


# ---------------------------------------------------------------------------
# Fix 1: skip_pid_ns opt-in
# ---------------------------------------------------------------------------


def test_spawn_run_sandboxed_accepts_skip_pid_ns_kwarg() -> None:
    """``run_sandboxed`` exposes ``skip_pid_ns: bool = False``."""
    src = _SPAWN.read_text()
    # Find the def line — single-line or wrapped.
    m = re.search(
        r"def\s+run_sandboxed\s*\(\s*(.*?)\)\s*->",
        src, re.DOTALL,
    )
    assert m, "could not locate run_sandboxed signature"
    params = m.group(1)
    assert "skip_pid_ns" in params, (
        "skip_pid_ns kwarg missing from run_sandboxed signature; "
        "the gdb-host-info-probe escape hatch was removed"
    )
    assert re.search(r"skip_pid_ns\s*:\s*bool\s*=\s*False", params), (
        "skip_pid_ns must default to False so existing callers are "
        "unaffected; the fix is opt-in only"
    )


def test_spawn_clone_newpid_gated_by_skip_pid_ns() -> None:
    """The ``os.unshare(CLONE_NEWPID)`` call sits behind ``if not skip_pid_ns``."""
    src = _SPAWN.read_text()
    # Locate the unshare call, then walk back to its guard.
    m = re.search(r"os\.unshare\(CLONE_NEWPID\)", src)
    assert m, "os.unshare(CLONE_NEWPID) call missing — pid-ns isolation removed?"
    # Within the 200 chars immediately preceding the unshare, the
    # guarding ``if not skip_pid_ns`` should be present. (The fix sits
    # right above the unshare line; any larger gap means someone
    # restructured the guard incorrectly.)
    window = src[max(0, m.start() - 200): m.start()]
    assert re.search(r"if\s+not\s+skip_pid_ns\s*:", window), (
        "os.unshare(CLONE_NEWPID) is no longer guarded by "
        "``if not skip_pid_ns`` — pid-ns will be entered "
        "unconditionally and gdb's host-info probe will fail again"
    )


def test_spawn_fresh_proc_remount_in_grandchild() -> None:
    """Grandchild remounts ``/proc`` so ns-local pids resolve.

    The bind from setup_mount_ns step 6 was taken BEFORE the pid-ns
    existed, so /proc exposes host pids. Inside the new pid-ns the
    grandchild has ns-local PIDs (1, 2, ...); without a fresh proc
    mount, ``/proc/<ns-pid>`` ENOENTs and ptrace/gdb path lookups
    break in a different way than the skip_pid_ns gap above.
    """
    src = _SPAWN.read_text()
    assert re.search(
        r'_libc\.mount\(\s*b"proc"\s*,\s*b"/proc"\s*,\s*b"proc"',
        src,
    ), (
        "fresh procfs remount in pid-ns grandchild missing — "
        "ns-pid /proc paths will ENOENT for gdb under runtime_inspect"
    )


def test_context_sandbox_forwards_skip_pid_ns() -> None:
    """``context.sandbox`` (and ``context.run`` by extension) plumb the kwarg."""
    src = _CONTEXT.read_text()
    # context.py forwards kwargs to _spawn.run_sandboxed; check
    # skip_pid_ns is in the forward path.
    assert "skip_pid_ns" in src, (
        "context.py doesn't mention skip_pid_ns — kwarg plumb broken; "
        "callers using core.sandbox.run(..., skip_pid_ns=True) will "
        "either error on unexpected kwarg or be silently ignored"
    )


def test_macos_spawn_accepts_skip_pid_ns_kwarg() -> None:
    """Parallel macOS path accepts the kwarg (no-op on darwin)."""
    src = _MACOS_SPAWN.read_text()
    assert "skip_pid_ns" in src, (
        "_macos_spawn.py doesn't accept skip_pid_ns — calls from a "
        "cross-platform caller (which doesn't know whether it's on "
        "Linux or macOS) will raise TypeError on darwin"
    )


# ---------------------------------------------------------------------------
# Fix 2: etc_overlay remount-rw cycle
# ---------------------------------------------------------------------------


def test_mount_ns_remounts_etc_rw_for_etc_overlay_creation() -> None:
    """``setup_mount_ns`` flips /etc rw when an overlay needs a new file."""
    src = _MOUNT_NS.read_text()
    # The fix uses MS_REMOUNT | MS_BIND on /etc to flip rw, AFTER the
    # initial RO bind. Anchor on the specific call + the etc_overlay
    # context.
    m = re.search(
        r'_mount\(\s*"/etc"\s*,\s*f"\{root\}/etc"\s*,'
        r'\s*None\s*,\s*MS_REMOUNT\s*\|\s*MS_BIND\s*\)',
        src,
    )
    assert m, (
        "MS_REMOUNT|MS_BIND on /etc missing — etc_overlay entries "
        "that need a new file under /etc will silently drop with EROFS"
    )

    # The remount-rw must be conditional: only fires when an overlay
    # entry's in-sandbox target doesn't already exist. Check the
    # surrounding loop walks `etc_overlay` and tests for missing
    # targets before flipping rw.
    pre = src[: m.start()]
    assert re.search(
        r'for\s+ns_target\s+in\s+etc_overlay\s*:',
        pre[-1500:],
    ), (
        "etc_overlay rw flip should be preceded by a scan for "
        "missing targets — flipping unconditionally widens the "
        "write surface for every etc_overlay invocation"
    )


def test_mount_ns_creates_placeholder_for_missing_etc_overlay_target() -> None:
    """If the in-sandbox target is missing, the substrate creates a placeholder
    of matching kind (dir → mkdir, file → touch) so the bind succeeds.

    Previously the bind silently dropped with ``etc_overlay target does
    not exist inside sandbox`` because the bind needs a target of the
    right type.
    """
    src = _MOUNT_NS.read_text()
    # Look for the placeholder-creation block under the etc_overlay loop.
    assert re.search(
        r'if\s+os\.path\.isdir\(host_source\)\s*:\s*\n'
        r'\s*os\.makedirs\(inside',
        src,
    ), (
        "dir-shape placeholder creation missing — etc_overlay dirs "
        "will fail to bind when the target doesn't exist"
    )
    assert re.search(
        r'open\(inside\s*,\s*"w"\)\.close\(\)',
        src,
    ), (
        "file-shape placeholder creation missing — etc_overlay files "
        "(/etc/pam.d/sudoedit etc.) will fail to bind when the target "
        "doesn't exist"
    )


# ---------------------------------------------------------------------------
# Fix 3: process_vm_readv / process_vm_writev moved to debug-only
# ---------------------------------------------------------------------------


def test_seccomp_process_vm_not_in_block_always() -> None:
    """``process_vm_readv`` and ``process_vm_writev`` were moved out of the
    ``_SECCOMP_BLOCK_ALWAYS`` tuple so the debug-permissive profile can
    allow them for gdb's inferior-memory plumbing.
    """
    src = _SECCOMP.read_text()
    # Find the _SECCOMP_BLOCK_ALWAYS literal.
    m = re.search(
        r"_SECCOMP_BLOCK_ALWAYS\s*=\s*\((.*?)\)",
        src, re.DOTALL,
    )
    assert m, "could not locate _SECCOMP_BLOCK_ALWAYS tuple"
    block_always = m.group(1)
    # The two ptrace-mem syscalls must NOT appear as block targets here.
    # The fix moved them to the debug-conditional list (or wherever the
    # debug profile sources its allowance from); the precise mechanism
    # is an implementation detail — the contract is "not in
    # BLOCK_ALWAYS". We tolerate the names appearing in nearby comments
    # because the original block-list entry had an inline comment; only
    # quoted occurrences inside the tuple matter.
    quoted = re.findall(r'"([a-zA-Z0-9_]+)"', block_always)
    assert "process_vm_readv" not in quoted, (
        "process_vm_readv is still in _SECCOMP_BLOCK_ALWAYS — "
        "gdb under runtime_inspect (debug profile) will be blocked "
        "from reading inferior memory, breaking breakpoint inspection"
    )
    assert "process_vm_writev" not in quoted, (
        "process_vm_writev is still in _SECCOMP_BLOCK_ALWAYS — "
        "gdb under runtime_inspect (debug profile) will be blocked "
        "from writing inferior memory, breaking variable assignment"
    )


def test_seccomp_default_posture_unchanged_for_non_debug_callers() -> None:
    """The default posture still blocks process_vm_*; only the debug
    profile widens. Detect this by confirming the file documents the
    debug-conditional intent (it's the contract the commit made).
    """
    src = _SECCOMP.read_text()
    assert "process_vm_readv" in src and "process_vm_writev" in src, (
        "process_vm_* syscalls completely absent from seccomp.py — "
        "the policy authoring contract is missing; debug profile "
        "callers will have no way to allow these syscalls"
    )
    # The commit body documents the rationale — make sure the comment
    # naming "debug" appears near the syscalls so future readers know
    # the contract is "debug-only allow".
    pos = src.find("process_vm_readv")
    context = src[max(0, pos - 600): pos + 600]
    assert re.search(r"debug", context, re.IGNORECASE), (
        "process_vm_* allowance is undocumented — the surrounding "
        "comment should explain that they're debug-profile-only "
        "(otherwise reviewers will think they're broadly allowed)"
    )
