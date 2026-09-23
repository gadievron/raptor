"""Validation-time inode pinning for mount-ns bind sources.

Threat under test: a symlink planted at a bind source (target= /
output= / readable_paths) AFTER the caller-side validation but BEFORE
the mount-ns child's mount(2). The child's mount-time canonicalisation
used to resolve such a "pre-planted" symlink exactly like a benign
operator symlink, steering the (writable, for output=) bind onto an
arbitrary same-UID directory. Verified empirically on the pre-fix
tree: the TestAttackRegression scenario below — rename the output dir
away and plant a symlink to VICTIM inside the validate→mount window —
ended with the sandboxed child's write landing in VICTIM/proof
(rc=0, bind steered) on the pre-fix code; with the pin it ends in a
refused spawn and no write anywhere.

Defense: the spawn parent opens an O_PATH fd per bind source at
validation time (symlink-refusing walk); the fd rides the fork into
the mount-ns child, which refuses each bind unless its own mount-time
walk resolves to the identical (st_dev, st_ino). Refusals surface as
exec-status 'P' and fail LOUD at the context layer — never the
Landlock-only degrade, where the planted symlink would resolve on the
host filesystem and the steering would succeed at the fallback tier.

Hermeticity: everything above the mount boundary (pin construction,
identity refusal, fd hygiene) runs on any Linux kernel with O_PATH and
needs no namespaces, no sudo, no ptrace. The end-to-end attack
regressions additionally need a working mount-ns (uidmap binaries +
unprivileged userns permitted) and skip cleanly where the runner lacks
them — same gating as test_spawn_mount_ns.py.
"""

from __future__ import annotations

import fcntl
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import pytest
from core.sandbox.tests.capability import (
    requires_landlock,
    requires_mount,
    requires_userns,
)

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "O_PATH"),
    reason="Linux-only sandbox internals (O_PATH pinning / mount-ns)",
)


def _mount_ns_usable() -> bool:
    """True iff the fork+newuidmap+mount chain can actually run here."""
    if not shutil.which("newuidmap") or not shutil.which("newgidmap"):
        return False
    sysctl = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    if sysctl.exists() and sysctl.read_text().strip() == "1":
        return False
    return True


def _fds_into(prefix: str) -> set[int]:
    """fds whose /proc readlink target lives under *prefix*.

    Leak assertions attribute by TARGET, never by table size: a
    process-global fd count is shifted by any concurrent churn in a
    shared test process (GC finalising a prior test's socket, a lazy
    import opening a resource) — observed as a once-per-42k-tests
    flake. Only this test opens fds into its private tmp base, so a
    surviving fd under it is attributably ours.
    """
    fds: set[int] = set()
    for name in os.listdir("/proc/self/fd"):
        try:
            target = os.readlink(f"/proc/self/fd/{name}")
        except OSError:
            continue  # closed between listdir and readlink
        if target == prefix or target.startswith(prefix + os.sep):
            fds.add(int(name))
    return fds


def _close_all(fds: dict[str, int]) -> None:
    for fd in fds.values():
        try:
            os.close(fd)
        except OSError:
            pass


class TestPinBindSources(unittest.TestCase):
    """_spawn._pin_bind_sources — parent-side validation-time pins."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        (self.base / "tgt").mkdir()
        (self.base / "out").mkdir()
        (self.base / "ro").mkdir()

    def test_pins_keyed_by_abspath_and_identity_matches(self) -> None:
        from core.sandbox._spawn import _pin_bind_sources
        tgt = str(self.base / "tgt")
        out = str(self.base / "out")
        ro = str(self.base / "ro")
        fds = _pin_bind_sources(tgt, out, None, [ro])
        self.addCleanup(_close_all, fds)
        self.assertEqual(set(fds), {tgt, out, ro})
        for path, fd in fds.items():
            st_fd = os.fstat(fd)
            st_path = os.stat(path)
            self.assertEqual(
                (st_fd.st_dev, st_fd.st_ino),
                (st_path.st_dev, st_path.st_ino),
                f"pin for {path} names a different inode",
            )

    def test_fds_are_cloexec(self) -> None:
        """Pins must survive fork but never an exec — CLOEXEC set."""
        from core.sandbox._spawn import _pin_bind_sources
        fds = _pin_bind_sources(str(self.base / "tgt"), None, None, None)
        self.addCleanup(_close_all, fds)
        for path, fd in fds.items():
            flags = fcntl.fcntl(fd, fcntl.F_GETFD)
            self.assertTrue(flags & fcntl.FD_CLOEXEC,
                            f"pin fd for {path} is not CLOEXEC")

    def test_benign_preexisting_symlink_resolves(self) -> None:
        """An output path that IS a symlink at validation resolves like
        any operator symlink: key is the caller path, pinned inode is
        the link target's."""
        from core.sandbox._spawn import _pin_bind_sources
        real = self.base / "real-out"
        real.mkdir()
        link = self.base / "link-out"
        link.symlink_to(real)
        fds = _pin_bind_sources(None, str(link), None, None)
        self.addCleanup(_close_all, fds)
        self.assertEqual(set(fds), {str(link)})
        st_fd = os.fstat(fds[str(link)])
        st_real = os.stat(real)
        self.assertEqual((st_fd.st_dev, st_fd.st_ino),
                         (st_real.st_dev, st_real.st_ino))

    def test_target_equals_output_single_pin(self) -> None:
        from core.sandbox._spawn import _pin_bind_sources
        tgt = str(self.base / "tgt")
        fds = _pin_bind_sources(tgt, tgt, None, [tgt])
        self.addCleanup(_close_all, fds)
        self.assertEqual(list(fds), [tgt])

    def test_missing_readable_path_skipped(self) -> None:
        """A readable_paths entry that does not exist at validation is
        skipped (the child then refuses to bind it at all) — matching
        the previous 'not a dir or file → skip' behaviour without the
        late re-resolution a planter could steer."""
        from core.sandbox._spawn import _pin_bind_sources
        tgt = str(self.base / "tgt")
        ghost = str(self.base / "does-not-exist")
        fds = _pin_bind_sources(tgt, None, None, [ghost, ""])
        self.addCleanup(_close_all, fds)
        self.assertEqual(set(fds), {tgt})

    def test_missing_required_source_raises_without_fd_leak(self) -> None:
        """target/output/rootfs pins are REQUIRED; a failure must close
        every fd already opened (no leak on the raise path)."""
        from core.sandbox._spawn import _pin_bind_sources
        tgt = str(self.base / "tgt")
        ghost_out = str(self.base / "no-such-out")
        with self.assertRaises(FileNotFoundError):
            _pin_bind_sources(tgt, ghost_out, None, None)
        self.assertEqual(_fds_into(os.path.realpath(self.base)), set(),
                         "fd leaked on the pin-failure path")

    def test_no_leak_across_many_pin_cycles(self) -> None:
        """Repeated pin/close cycles must not creep the fd table —
        the exhaustion-DoS shape."""
        from core.sandbox._spawn import _pin_bind_sources
        tgt = str(self.base / "tgt")
        out = str(self.base / "out")
        for _ in range(64):
            _close_all(_pin_bind_sources(tgt, out, None, [out]))
        self.assertEqual(_fds_into(os.path.realpath(self.base)), set(),
                         "pin cycles left fds open into the test base")


class TestBindPinnedSourceIdentityRefusal(unittest.TestCase):
    """mount_ns._bind_pinned_source with a validation-time fd refuses —
    BEFORE any mount(2) — when the source no longer resolves to the
    pinned inode. Runs unprivileged: every asserted path raises ahead
    of the mount call."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def _pin(self, path: str) -> int:
        from core.sandbox._pathpin import open_pinned
        fd = open_pinned(os.path.realpath(path))
        self.addCleanup(os.close, fd)
        return fd

    def test_symlink_swap_refused_estale(self) -> None:
        """The attack shape: rename the source away, plant a symlink
        to VICTIM. The mount-time walk resolves VICTIM; identity
        differs from the pinned inode → ESTALE, no mount attempted."""
        from core.sandbox.mount_ns import (
            _ESTALE,
            MS_BIND,
            _bind_pinned_source,
        )
        src = self.base / "out"
        victim = self.base / "victim"
        src.mkdir()
        victim.mkdir()
        fd = self._pin(str(src))
        os.rename(src, self.base / "out-moved")
        os.symlink(victim, src)
        with self.assertRaises(OSError) as cm:
            _bind_pinned_source(str(src), str(self.base / "inside"),
                                MS_BIND, pinned_fd=fd)
        self.assertEqual(cm.exception.errno, _ESTALE)

    def test_rename_swap_to_real_dir_refused_estale(self) -> None:
        """Swap to a REAL directory (no symlink at all) is refused
        too: the identity check is on inodes, not link-shape."""
        from core.sandbox.mount_ns import (
            _ESTALE,
            MS_BIND,
            _bind_pinned_source,
        )
        src = self.base / "out"
        src.mkdir()
        fd = self._pin(str(src))
        os.rename(src, self.base / "out-moved")
        (self.base / "out").mkdir()  # attacker's replacement dir
        with self.assertRaises(OSError) as cm:
            _bind_pinned_source(str(src), str(self.base / "inside"),
                                MS_BIND, pinned_fd=fd)
        self.assertEqual(cm.exception.errno, _ESTALE)

    def test_vanished_source_refused_estale(self) -> None:
        """A pinned source that stops resolving entirely (rmdir'd) is
        the same tamper signal — uniform ESTALE, not a bare ENOENT
        that the spawn layer would degrade on."""
        from core.sandbox.mount_ns import (
            _ESTALE,
            MS_BIND,
            _bind_pinned_source,
        )
        src = self.base / "out"
        src.mkdir()
        fd = self._pin(str(src))
        os.rmdir(src)
        with self.assertRaises(OSError) as cm:
            _bind_pinned_source(str(src), str(self.base / "inside"),
                                MS_BIND, pinned_fd=fd)
        self.assertEqual(cm.exception.errno, _ESTALE)

    def test_regular_file_swap_refused_estale(self) -> None:
        """A regular-FILE source replaced after validation (rename
        away + new file at the same path) is refused with the tamper
        signal — the volatile-procfs exemption must not weaken the
        real-filesystem classes."""
        from core.sandbox.mount_ns import (
            _ESTALE,
            MS_BIND,
            _bind_pinned_source,
        )
        src = self.base / "notes.txt"
        src.write_text("validated content\n")
        fd = self._pin(str(src))
        os.rename(src, self.base / "notes-moved.txt")
        src.write_text("replacement content\n")
        with self.assertRaises(OSError) as cm:
            _bind_pinned_source(str(src), str(self.base / "inside"),
                                MS_BIND, pinned_fd=fd)
        self.assertEqual(cm.exception.errno, _ESTALE)
        self.assertIn("validation-time inode", str(cm.exception))

    def test_legacy_no_pin_keeps_original_errno(self) -> None:
        """Without a validation fd (direct/legacy callers) the walk's
        own errno propagates unchanged — no ESTALE masquerade."""
        import errno
        from core.sandbox.mount_ns import MS_BIND, _bind_pinned_source
        ghost = str(self.base / "never-existed")
        with self.assertRaises(OSError) as cm:
            _bind_pinned_source(ghost, str(self.base / "inside"),
                                MS_BIND, pinned_fd=None)
        self.assertEqual(cm.exception.errno, errno.ENOENT)


class TestPerProcessProcfsExemption(unittest.TestCase):
    """/proc/self/* and /proc/thread-self/* bind sources are volatile
    by construction: procfs synthesises a different file for every
    walking process, so a parent-side validation pin can never match
    the forked mount-ns child's walk — an identity mismatch there
    carries no tamper signal. The class is exempt from pinning and
    from the extra_ro bind (procfs serves it per-reader); every
    real-filesystem class keeps the refusal (see the swap tests
    above)."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        (self.base / "tgt").mkdir()

    def test_classifier_boundaries(self) -> None:
        from core.sandbox.mount_ns import _is_per_process_procfs
        for path in ("/proc/self", "/proc/self/cgroup",
                     "/proc/self/fd/0", "/proc/thread-self",
                     "/proc/thread-self/stat",
                     # POSIX preserves an exactly-two-slash prefix
                     # through abspath/normpath, while realpath still
                     # resolves it into a pid dir — the spelling must
                     # not escape the class.
                     "//proc/self/cgroup", "///proc/self/cgroup",
                     "//proc/thread-self"):
            self.assertTrue(_is_per_process_procfs(path), path)
        # pid-named procfs paths are stable across processes (they
        # name ONE pid) and real-filesystem paths never qualify —
        # both keep the pin + tamper refusal.
        for path in ("/proc", "/proc/selfish", "/proc/1234/cgroup",
                     "/proc/cpuinfo", "/tmp/proc/self", "/",
                     "//proc", "//tmp/proc/self"):
            self.assertFalse(_is_per_process_procfs(path), path)

    def test_pin_skips_double_slash_spelling(self) -> None:
        """abspath preserves '//proc/self/...' — the pin skip must
        classify the spelling, not just the canonical form."""
        from core.sandbox._spawn import _pin_bind_sources
        tgt = str(self.base / "tgt")
        fds = _pin_bind_sources(tgt, None, None,
                                ["//proc/self/cgroup", tgt])
        self.addCleanup(_close_all, fds)
        self.assertEqual(set(fds), {tgt})

    def test_pin_skips_per_process_procfs_readables(self) -> None:
        """The parent takes no pin for the volatile class — the child
        then serves the path through the /proc mount instead of a
        bind, so no identity comparison can misfire."""
        from core.sandbox._spawn import _pin_bind_sources
        tgt = str(self.base / "tgt")
        fds = _pin_bind_sources(
            tgt, None, None,
            ["/proc/self/cgroup", "/proc/thread-self/stat", tgt],
        )
        self.addCleanup(_close_all, fds)
        self.assertEqual(set(fds), {tgt})

    def test_identity_change_across_fork_succeeds_via_exemption(self) -> None:
        """The defect shape, at the pin layer: the same /proc/self
        path names different inodes for parent and child (fork
        changes the reader), so any retained pin would ESTALE. The
        exemption removes the pin, so the child-side lookup misses
        and the bind is skipped rather than refused."""
        from core.sandbox._spawn import _pin_bind_sources
        tgt = str(self.base / "tgt")
        fds = _pin_bind_sources(tgt, None, None, ["/proc/self/cgroup"])
        self.addCleanup(_close_all, fds)
        pid = os.fork()
        if pid == 0:
            # Child: mimic the mount-time walk for the volatile path.
            try:
                st_child = os.stat(os.path.realpath("/proc/self/cgroup"))
                st_parent_seen = "/proc/self/cgroup" in fds
                ok = (not st_parent_seen) and st_child.st_ino != 0
                os._exit(0 if ok else 1)
            except OSError:
                os._exit(2)
        _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)


class TestPerProcessProcfsE2E(unittest.TestCase):
    """End-to-end: a /proc/self/* readable path must not fail the
    spawn (the pre-fix pin refused it as tampering — errno ESTALE,
    exec-status 'P'), and the path stays readable inside the sandbox
    through the /proc mount."""

    def setUp(self) -> None:
        if not _mount_ns_usable():
            self.skipTest(
                "mount-ns unusable here (needs uidmap package + "
                "kernel.apparmor_restrict_unprivileged_userns=0)"
            )
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.tgt = self.base / "tgt"
        self.out = self.base / "out"
        for d in (self.tgt, self.out):
            d.mkdir()

    @requires_userns
    def test_proc_self_readable_path_spawn_succeeds(self) -> None:
        from core.sandbox._spawn import run_sandboxed
        # landlock_required=False: this test's subject is the
        # bind-source PIN behaviour for the volatile /proc/self class,
        # not the containment floor. The default (True) makes a
        # Landlock-LESS kernel abort the spawn fail-closed at 'L'
        # before the pin scenario ever runs — the documented floor
        # behaviour, but it turned this test into a floor test on
        # such hosts. Tolerating kernel absence (the ns-only tier)
        # lets the pin scenario run everywhere; on kernels WITH
        # Landlock the flag is inert and the full stack is exercised
        # unchanged.
        r = run_sandboxed(
            ["cat", "/proc/self/cgroup"],
            target=str(self.tgt), output=str(self.out),
            block_network=True, nproc_limit=1024,
            limits={"memory_mb": 0, "max_file_mb": 10240,
                    "cpu_seconds": 300},
            writable_paths=[str(self.out), "/tmp"],
            readable_paths=["/proc/self/cgroup"],
            allowed_tcp_ports=None,
            seccomp_profile=None, seccomp_block_udp=False,
            env=None, cwd=None, timeout=30,
            capture_output=True, text=True,
            landlock_required=False,
        )
        status = getattr(r, "_setup_status", None)
        self.assertIsNone(
            status,
            f"volatile procfs readable path failed setup: {status}",
        )
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertTrue((r.stdout or "").strip(),
                        "/proc/self/cgroup unreadable inside the sandbox")

    @requires_landlock
    @requires_userns
    def test_proc_self_maps_readable_without_per_entry_grant(self) -> None:
        """The Landlock grant resolution yields NO rule for the
        per-reader class (a parent-resolved rule would name the wrong
        pid dir), so the child's read must be served by the wholesale
        /proc read grant — end to end, under the full read-restricted
        stack."""
        from core.sandbox._spawn import run_sandboxed
        r = run_sandboxed(
            ["cat", "/proc/self/maps"],
            target=str(self.tgt), output=str(self.out),
            block_network=True, nproc_limit=1024,
            limits={"memory_mb": 0, "max_file_mb": 10240,
                    "cpu_seconds": 300},
            writable_paths=[str(self.out), "/tmp"],
            readable_paths=["/proc/self/maps"],
            allowed_tcp_ports=None,
            seccomp_profile=None, seccomp_block_udp=False,
            env=None, cwd=None, timeout=30,
            capture_output=True, text=True,
        )
        status = getattr(r, "_setup_status", None)
        self.assertIsNone(
            status,
            f"volatile procfs readable path failed setup: {status}",
        )
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertTrue((r.stdout or "").strip(),
                        "/proc/self/maps unreadable inside the sandbox")


class TestPinTimeFailureNeverDegrades(unittest.TestCase):
    """A required-pin failure at VALIDATION time must raise
    SandboxSetupError — never a plain OSError. The context layer's
    environmental-fallback ladder catches (FileNotFoundError,
    RuntimeError, OSError) and would re-run the command at the
    Landlock-only tier, where a symlink the attacker plants at the
    source path resolves on the host filesystem and steers the
    fallback's write grants — demonstrated empirically during review:
    a pin-time ELOOP surfaced as a generic degrade warning and the
    fallback wrote through the planted symlink (rc=0). These run
    unprivileged: the raise happens before any fork."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        (self.base / "tgt").mkdir()

    def _kwargs(self, out: str) -> dict:
        return dict(
            target=str(self.base / "tgt"), output=out,
            block_network=True, nproc_limit=1024,
            limits={"memory_mb": 0, "max_file_mb": 10240,
                    "cpu_seconds": 300},
            writable_paths=[out, "/tmp"],
            readable_paths=None, allowed_tcp_ports=None,
            seccomp_profile=None, seccomp_block_udp=False,
            env=None, cwd=None, timeout=30,
            capture_output=True, text=True,
        )

    def test_pin_eloop_raises_sandbox_setup_error(self) -> None:
        """Mid-validation symlink plant (ELOOP out of the pin walk)."""
        import errno
        from unittest.mock import patch

        from core.sandbox import _spawn
        from core.sandbox.errors import SandboxSetupError
        out = self.base / "out"
        out.mkdir()
        eloop = OSError(errno.ELOOP,
                        "open_pinned: component is a symlink")
        with patch.object(_spawn, "_pin_bind_sources",
                          side_effect=eloop), \
                self.assertRaises(SandboxSetupError):
            _spawn.run_sandboxed(["true"], **self._kwargs(str(out)))

    def test_pin_enoent_raises_sandbox_setup_error(self) -> None:
        """A required source missing at validation (real ENOENT from
        the pin walk, no mocking) is caller-input error — fail loud,
        never FileNotFoundError (which the fallback ladder absorbs)."""
        from core.sandbox import _spawn
        from core.sandbox.errors import SandboxSetupError
        ghost_out = str(self.base / "no-such-out")
        with self.assertRaises(SandboxSetupError):
            _spawn.run_sandboxed(["true"], **self._kwargs(ghost_out))

    def test_no_stub_dir_leak_on_pin_failure(self) -> None:
        """The mkdtemp sandbox-root stub must be cleaned up when the
        pin raises (the raise happens after the stub is created)."""
        import tempfile as _tf
        from unittest.mock import patch

        from core.sandbox import _spawn
        from core.sandbox.errors import SandboxSetupError
        captured: list[str] = []
        real_mkdtemp = _tf.mkdtemp

        def recording_mkdtemp(*args, **kwargs):
            path = real_mkdtemp(*args, **kwargs)
            if kwargs.get("prefix", "").startswith(".raptor-sbx-"):
                captured.append(path)
            return path

        ghost_out = str(self.base / "no-such-out")
        with patch("tempfile.mkdtemp", side_effect=recording_mkdtemp), \
                self.assertRaises(SandboxSetupError):
            _spawn.run_sandboxed(["true"], **self._kwargs(ghost_out))
        self.assertEqual(len(captured), 1)
        self.assertFalse(os.path.exists(captured[0]),
                         "sandbox-root stub leaked on the pin-failure "
                         "path")


class TestAttackRegressionE2E(unittest.TestCase):
    """End-to-end: post-validation swap of the output= bind source.

    Interposition point: a wrapper around _spawn._pin_bind_sources
    performs the swap immediately AFTER the parent's validation-time
    pin — i.e. inside the exact window (fork, newuidmap handshake,
    mount setup) that the pin exists to cover. On the pre-fix tree
    the equivalent scenario (hooking the parent's post-validation
    mkdtemp, since _pin_bind_sources did not exist) ended STEERED:
    rc=0 and the child's write in VICTIM/proof through the writable
    bind. With the pin the spawn refuses with exec-status 'P' and no
    write lands anywhere.
    """

    def setUp(self) -> None:
        if not _mount_ns_usable():
            self.skipTest(
                "mount-ns unusable here (needs uidmap package + "
                "kernel.apparmor_restrict_unprivileged_userns=0)"
            )
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.tgt = self.base / "tgt"
        self.out = self.base / "out"
        self.victim = self.base / "victim"
        for d in (self.tgt, self.out, self.victim):
            d.mkdir()

    def _swap_after_pin(self):
        """Patch _pin_bind_sources: pin normally, then swap out →
        symlink(victim). Returns the patcher (caller enters it)."""
        from unittest.mock import patch

        from core.sandbox import _spawn
        real_pin = _spawn._pin_bind_sources
        out, victim, moved = self.out, self.victim, self.base / "out-moved"

        def pin_then_swap(*args, **kwargs):
            fds = real_pin(*args, **kwargs)
            os.rename(out, moved)
            os.symlink(victim, out)
            return fds

        return patch.object(_spawn, "_pin_bind_sources",
                            side_effect=pin_then_swap)

    def _spawn_kwargs(self) -> dict:
        return dict(
            target=str(self.tgt), output=str(self.out),
            block_network=True, nproc_limit=1024,
            limits={"memory_mb": 0, "max_file_mb": 10240,
                    "cpu_seconds": 300},
            writable_paths=[str(self.out), "/tmp"],
            readable_paths=None, allowed_tcp_ports=None,
            seccomp_profile=None, seccomp_block_udp=False,
            env=None, cwd=None, timeout=30,
            capture_output=True, text=True,
        )

    @requires_userns
    # Exercises mount-delivered capability; hosts with userns but no mount capability degrade by design -> named SKIP. Siblings that pass mountlessly (validation refusals, degraded-posture checks) stay ungated.
    @requires_mount
    def test_post_validation_swap_refused_at_spawn_layer(self) -> None:
        from core.sandbox._spawn import run_sandboxed
        with self._swap_after_pin():
            r = run_sandboxed(
                ["sh", "-c", f"echo PWNED > {self.out}/proof"],
                **self._spawn_kwargs(),
            )
        self.assertNotEqual(r.returncode, 0,
                            "spawn must refuse the swapped bind source")
        status = getattr(r, "_setup_status", None)
        if status is None:
            self.fail("expected a setup-failure status on the pipe")
        self.assertEqual(status[0], "P",
                         f"expected pin-violation category, got {status}")
        for where in (self.victim, self.base / "out-moved", self.out):
            self.assertFalse(
                (Path(where) / "proof").exists(),
                f"write escaped the refused spawn into {where}",
            )

    @requires_userns
    # Exercises mount-delivered capability; hosts with userns but no mount capability degrade by design -> named SKIP. Siblings that pass mountlessly (validation refusals, degraded-posture checks) stay ungated.
    @requires_mount
    def test_context_layer_fails_loud_no_landlock_demotion(self) -> None:
        """The 'P' refusal must NOT ride the M-degrade ladder: the
        Landlock-only retry would re-run the command on the host
        filesystem where the planted symlink resolves and the write
        lands in VICTIM anyway. context.run must raise
        SandboxSetupError and nothing may be written."""
        from core.sandbox import context as ctx
        from core.sandbox.errors import SandboxSetupError
        with self._swap_after_pin(), self.assertRaises(SandboxSetupError):
            ctx.run(
                ["sh", "-c", f"echo PWNED > {self.out}/proof"],
                target=str(self.tgt), output=str(self.out),
                timeout=30, capture_output=True, text=True,
            )
        for where in (self.victim, self.base / "out-moved", self.out):
            self.assertFalse(
                (Path(where) / "proof").exists(),
                f"write escaped into {where} — the refusal degraded "
                f"to a tier the planted symlink steers",
            )

    @requires_userns
    # Exercises mount-delivered capability; hosts with userns but no mount capability degrade by design -> named SKIP. Siblings that pass mountlessly (validation refusals, degraded-posture checks) stay ungated.
    @requires_mount
    def test_pin_time_plant_fails_loud_at_context_layer(self) -> None:
        """Reviewer-demonstrated shape: the symlink lands DURING the
        validation walk (pin raises ELOOP with the plant already in
        place). Pre-remediation this rode context.py's environmental
        except (FileNotFoundError, RuntimeError, OSError) into the
        Landlock-only fallback, whose write grants resolved the
        planted symlink on the HOST filesystem — the probe observed
        rc=0 and the write inside VICTIM. Must now raise
        SandboxSetupError with nothing written anywhere."""
        import errno
        from unittest.mock import patch

        from core.sandbox import _spawn
        from core.sandbox import context as ctx
        from core.sandbox.errors import SandboxSetupError

        out, victim = self.out, self.victim

        def plant_and_eloop(*args, **kwargs):
            os.rename(out, out.parent / "out-moved")
            os.symlink(victim, out)
            raise OSError(errno.ELOOP,
                          "open_pinned: component is a symlink")

        with patch.object(_spawn, "_pin_bind_sources",
                          side_effect=plant_and_eloop), \
                self.assertRaises(SandboxSetupError):
            ctx.run(
                ["sh", "-c", f"echo PWNED > {out}/proof"],
                target=str(self.tgt), output=str(out),
                timeout=30, capture_output=True, text=True,
            )
        for where in (victim, self.base / "out-moved", out):
            self.assertFalse(
                (Path(where) / "proof").exists(),
                f"write escaped into {where} — a pin-time failure "
                f"degraded to a tier the planted symlink steers",
            )

    @requires_userns
    def test_planted_readable_path_not_bound(self) -> None:
        """A readable_paths entry that did NOT exist at validation and
        is planted (as a symlink to a secret-bearing directory) before
        the mount must not be bound: the child skips unpinned entries
        outright instead of re-resolving. Pre-fix the child's
        mount-time isdir()+realpath accepted the plant and bound the
        symlink target read-only into the sandbox."""
        from core.sandbox._spawn import run_sandboxed
        secret_dir = self.base / "secrets"
        secret_dir.mkdir()
        (secret_dir / "token").write_text("SECRET-CONTENT\n")
        ghost = self.base / "ghost-ro"  # absent at validation

        from unittest.mock import patch

        from core.sandbox import _spawn
        real_pin = _spawn._pin_bind_sources

        def pin_then_plant(*args, **kwargs):
            fds = real_pin(*args, **kwargs)
            os.symlink(secret_dir, ghost)
            return fds

        kwargs = self._spawn_kwargs()
        kwargs["readable_paths"] = [str(ghost)]
        with patch.object(_spawn, "_pin_bind_sources",
                          side_effect=pin_then_plant):
            r = run_sandboxed(
                ["cat", str(ghost / "token")], **kwargs,
            )
        self.assertNotEqual(r.returncode, 0,
                            "planted readable path must not be bound")
        self.assertNotIn("SECRET-CONTENT", r.stdout or "",
                         "planted symlink content leaked into sandbox")

    @requires_userns
    def test_swapped_readable_path_refused_at_spawn_layer(self) -> None:
        """A readable_paths dir that EXISTED at validation and is
        swapped to a symlink inside the validate→mount window must
        refuse the whole spawn with the pin-violation category (the
        per-process procfs exemption must not soften the refusal for
        the real-filesystem readable class)."""
        from unittest.mock import patch

        from core.sandbox import _spawn
        from core.sandbox._spawn import run_sandboxed
        ro = self.base / "ro"
        ro.mkdir()
        (self.victim / "token").write_text("SECRET-CONTENT\n")
        real_pin = _spawn._pin_bind_sources
        victim, moved = self.victim, self.base / "ro-moved"

        def pin_then_swap(*args, **kwargs):
            fds = real_pin(*args, **kwargs)
            os.rename(ro, moved)
            os.symlink(victim, ro)
            return fds

        kwargs = self._spawn_kwargs()
        kwargs["readable_paths"] = [str(ro)]
        with patch.object(_spawn, "_pin_bind_sources",
                          side_effect=pin_then_swap):
            r = run_sandboxed(["cat", str(ro / "token")], **kwargs)
        self.assertNotEqual(r.returncode, 0,
                            "swapped readable bind source must refuse")
        status = getattr(r, "_setup_status", None)
        if status is None:
            self.fail("expected a setup-failure status on the pipe")
        self.assertEqual(status[0], "P",
                         f"expected pin-violation category, got {status}")
        self.assertNotIn("SECRET-CONTENT", r.stdout or "",
                         "swapped readable source leaked into sandbox")

    @requires_landlock
    @requires_userns
    # Exercises mount-delivered capability; hosts with userns but no mount capability degrade by design -> named SKIP. Siblings that pass mountlessly (validation refusals, degraded-posture checks) stay ungated.
    @requires_mount
    def test_benign_run_unaffected(self) -> None:
        """No swap: pinned spawn works end-to-end, including an output
        path that is a benign pre-existing symlink."""
        from core.sandbox._spawn import run_sandboxed
        real = self.base / "real-out"
        real.mkdir()
        link = self.base / "link-out"
        link.symlink_to(real)
        kwargs = self._spawn_kwargs()
        kwargs["output"] = str(link)
        kwargs["writable_paths"] = [str(link), "/tmp"]
        r = run_sandboxed(
            ["sh", "-c", f"echo OK > {link}/proof && cat {link}/proof"],
            **kwargs,
        )
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertIn("OK", r.stdout)
        self.assertTrue((real / "proof").exists(),
                        "benign symlink output should resolve normally")


if __name__ == "__main__":
    unittest.main()


class TestRequiredPinJoin(unittest.TestCase):
    """The parent keys pins with canonical_bind_path; the child's
    REQUIRED-bind lookups must join on the same key, and a miss must
    refuse (ESTALE tamper convention) instead of silently downgrading
    to mount-time window-narrowing — a produced-but-unconsumed pin is
    always a join bug or tampering."""

    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp(prefix="pinjoin-"))
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)

    def test_double_slash_rootfs_pin_joins_canonical_key(self) -> None:
        from core.sandbox._pathpin import canonical_bind_path
        from core.sandbox._spawn import _pin_bind_sources
        from core.sandbox.mount_ns import _required_pin_fd

        tgt = self.base / "tgt"
        tgt.mkdir()
        rootfs = self.base / "rootfs"
        rootfs.mkdir()
        spelled = "//" + str(rootfs).lstrip("/")
        fds = _pin_bind_sources(str(tgt), None, spelled, None)
        self.addCleanup(_close_all, fds)
        child_key = canonical_bind_path(spelled)
        # The join: the child's canonicalised key finds the pin...
        self.assertIsNotNone(_required_pin_fd(fds, child_key))
        # ...while the pre-fix child spelling (plain abspath keeps
        # the '//' prefix) does not name any pinned key.
        self.assertNotIn(os.path.abspath(spelled), fds)

    def test_missing_required_pin_refuses_estale(self) -> None:
        from core.sandbox.mount_ns import _ESTALE, _required_pin_fd

        with self.assertRaises(OSError) as ctx:
            _required_pin_fd({"/some/other": 7}, "/required/bind")
        self.assertEqual(ctx.exception.errno, _ESTALE)

    def test_no_pins_supplied_is_legacy_unpinned(self) -> None:
        from core.sandbox.mount_ns import _required_pin_fd

        self.assertIsNone(_required_pin_fd(None, "/required/bind"))


class TestBindViewGrantAnchoring(unittest.TestCase):
    """Landlock rule paths for a mount-tree spawn open POST-pivot: the
    spawn assembly must anchor bind-target grants to their in-view
    bind paths and refuse grants the view can never carry — a named
    error at grant time, not a bare EACCES at first use."""

    def setUp(self) -> None:
        # Base OFF /tmp: under the default tmp base every path is
        # beneath the per-namespace /tmp view tree and the refusal arm
        # has nothing out-of-view to classify.
        if not os.path.isdir("/var/tmp"):
            self.skipTest("no /var/tmp on this host")
        self.base = Path(tempfile.mkdtemp(prefix="bindview-",
                                          dir="/var/tmp"))
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)
        self.tgt = self.base / "tgt"
        self.tgt.mkdir()
        self.real_out = self.base / "real-out"
        self.real_out.mkdir()
        self.link_out = self.base / "link-out"
        self.link_out.symlink_to(self.real_out)

    def _anchor(self, grants, **kw):
        from core.sandbox._spawn import _anchor_grants_to_bind_view
        args = dict(target=str(self.tgt), output=str(self.link_out),
                    rootfs=None, readable_paths=None, kind="writable")
        args.update(kw)
        return _anchor_grants_to_bind_view(grants, **args)

    def test_symlink_spelled_output_grant_anchors_to_bind_path(self):
        from core.sandbox._pathpin import ViewAnchoredPath
        out, carry = self._anchor([str(self.link_out), "/tmp"])
        self.assertIsInstance(out[0], ViewAnchoredPath)
        self.assertEqual(str(out[0]), str(self.link_out))
        self.assertEqual(out[1], "/tmp")  # view tree: passes through
        self.assertNotIsInstance(out[1], ViewAnchoredPath)
        self.assertEqual(carry, [])  # bind targets need no carry

    def test_resolved_spelling_of_bound_output_anchors_to_bind_path(
            self):
        # The realpath spelling names the SAME validated source; the
        # view carries it at the bind path, so the rule must anchor
        # there instead of failing its open post-pivot.
        from core.sandbox._pathpin import ViewAnchoredPath
        out, carry = self._anchor([str(self.real_out)])
        self.assertIsInstance(out[0], ViewAnchoredPath)
        self.assertEqual(str(out[0]), str(self.link_out))
        self.assertEqual(carry, [])

    def test_subpath_of_target_passes_through_unanchored(self):
        from core.sandbox._pathpin import ViewAnchoredPath
        sub = self.tgt / "build"
        sub.mkdir()
        out, carry = self._anchor([str(sub)])
        self.assertEqual(out, [str(sub)])
        self.assertNotIsInstance(out[0], ViewAnchoredPath)
        self.assertEqual(carry, [])

    def test_out_of_view_existing_dir_is_carried_rw(self):
        # The legitimate cross-lane shape (a shared log dir granted
        # writable while run output lives elsewhere): the view is
        # extended DELIBERATELY — the root joins the carry list and
        # its rule anchors to the bind the spawn will create.
        from core.sandbox._pathpin import ViewAnchoredPath
        unbound = self.base / "unbound"
        unbound.mkdir()
        out, carry = self._anchor([str(unbound)])
        self.assertEqual(carry, [str(unbound)])
        self.assertIsInstance(out[0], ViewAnchoredPath)
        self.assertEqual(str(out[0]), str(unbound))

    def test_out_of_view_missing_grant_refused_with_named_error(self):
        # Never-carriable: out-of-view AND nothing to bind — no lane
        # could ever honour it, so the refusal (named, at assembly)
        # stays.
        from core.sandbox.errors import SandboxSetupError
        ghost = self.base / "no-such-grant-dir"
        with self.assertRaises(SandboxSetupError) as ctx:
            self._anchor([str(ghost)])
        self.assertIn("outside the mount view", str(ctx.exception))
        self.assertIn(str(ghost), str(ctx.exception))

    def test_out_of_view_readable_never_carries(self):
        # Readable entries are their own read-only binds; the carry
        # list is a WRITE-grant mechanism only.
        ro = self.base / "ro"
        ro.mkdir()
        out, carry = self._anchor([str(ro)], readable_paths=[str(ro)],
                                  kind="readable")
        self.assertEqual(str(out[0]), str(ro))
        self.assertEqual(carry, [])

    def test_rootfs_mode_skips_the_carry_and_refusal_arms(self):
        # Image roots carry arbitrary top-level trees; only the
        # bind-target anchoring applies there.
        out, carry = self._anchor(["/opt", str(self.link_out)],
                                  rootfs=str(self.base))
        self.assertEqual(out[0], "/opt")
        self.assertEqual(carry, [])

    def test_readable_bind_grant_is_in_view(self):
        ro = self.base / "ro"
        ro.mkdir()
        out, carry = self._anchor([str(ro)], readable_paths=[str(ro)])
        self.assertEqual(str(out[0]), str(ro))
        self.assertEqual(carry, [])


class TestBindViewGrantContractE2E(unittest.TestCase):
    """End-to-end bind-view grant contract on the real spawn backend,
    with the sandbox base OFF /tmp (the shape a relocated TMPDIR
    produces): a symlink-spelled output grant must work through its
    bind, and an out-of-view writable grant must refuse at spawn
    assembly."""

    def setUp(self) -> None:
        if not _mount_ns_usable():
            self.skipTest(
                "mount-ns unusable here (needs uidmap package + "
                "kernel.apparmor_restrict_unprivileged_userns=0)"
            )
        base_root = "/var/tmp" if os.path.isdir("/var/tmp") else None
        if base_root is None:
            self.skipTest("no /var/tmp on this host")
        self.base = Path(tempfile.mkdtemp(prefix="bindview-e2e-",
                                          dir=base_root))
        self.addCleanup(shutil.rmtree, self.base, ignore_errors=True)
        self.tgt = self.base / "tgt"
        self.tgt.mkdir()

    def _spawn_kwargs(self, out) -> dict:
        return dict(
            target=str(self.tgt), output=str(out),
            block_network=True, nproc_limit=1024,
            limits={"memory_mb": 0, "max_file_mb": 10240,
                    "cpu_seconds": 300},
            writable_paths=[str(out), "/tmp"],
            readable_paths=None, allowed_tcp_ports=None,
            seccomp_profile=None, seccomp_block_udp=False,
            env=None, cwd=None, timeout=30,
            capture_output=True, text=True,
        )

    @requires_landlock
    @requires_userns
    # Exercises mount-delivered capability; hosts with userns but no mount capability degrade by design -> named SKIP.
    @requires_mount
    def test_symlinked_output_grant_works_off_tmp(self) -> None:
        """The write grant for a symlink-spelled output must land on
        the bound inode even when the resolved tree sits outside every
        blanket view grant (no /tmp accident to hide behind)."""
        from core.sandbox._spawn import run_sandboxed
        real = self.base / "real-out"
        real.mkdir()
        link = self.base / "link-out"
        link.symlink_to(real)
        r = run_sandboxed(
            ["sh", "-c", f"echo OK > {link}/proof && cat {link}/proof"],
            **self._spawn_kwargs(link),
        )
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertIn("OK", r.stdout)
        self.assertTrue((real / "proof").exists())

    @requires_landlock
    @requires_userns
    # Exercises mount-delivered capability; hosts with userns but no mount capability degrade by design -> named SKIP.
    @requires_mount
    def test_out_of_view_writable_dir_carried_and_writable(self) -> None:
        """The legitimate cross-lane grant shape (shared log dir
        outside the run's trees): the spawn carries it into the view
        as a pinned read-write bind, the child's write lands on the
        HOST directory, and nothing demotes. At BASE this grant was
        silently dead on the mount lane (rule-open failure + EACCES
        at first use)."""
        from core.sandbox._spawn import run_sandboxed
        out = self.base / "out"
        out.mkdir()
        unbound = self.base / "unbound"
        unbound.mkdir()
        kwargs = self._spawn_kwargs(out)
        kwargs["writable_paths"] = [str(out), str(unbound), "/tmp"]
        r = run_sandboxed(
            ["sh", "-c", f"echo carried > {unbound}/proof"], **kwargs)
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertIsNone(getattr(r, "_setup_status", None))
        self.assertEqual((unbound / "proof").read_text().strip(),
                         "carried")

    @requires_landlock
    @requires_userns
    # Exercises mount-delivered capability; hosts with userns but no mount capability degrade by design -> named SKIP.
    @requires_mount
    def test_carried_grant_swap_refused_at_spawn_layer(self) -> None:
        """The carried read-write bind is a bind source like any
        other: a swap inside the validate->mount window refuses the
        spawn with the pin-violation category instead of steering the
        WRITE bind onto the replacement."""
        from unittest.mock import patch

        from core.sandbox import _spawn
        from core.sandbox._spawn import run_sandboxed
        out = self.base / "out"
        out.mkdir()
        unbound = self.base / "unbound"
        unbound.mkdir()
        victim = self.base / "victim"
        victim.mkdir()
        real_pin = _spawn._pin_bind_sources
        moved = self.base / "unbound-moved"

        def pin_then_swap(*args, **kwargs):
            fds = real_pin(*args, **kwargs)
            os.rename(unbound, moved)
            os.symlink(victim, unbound)
            return fds

        kwargs = self._spawn_kwargs(out)
        kwargs["writable_paths"] = [str(out), str(unbound), "/tmp"]
        with patch.object(_spawn, "_pin_bind_sources",
                          side_effect=pin_then_swap):
            r = run_sandboxed(
                ["sh", "-c", f"echo PWNED > {unbound}/proof"], **kwargs)
        self.assertNotEqual(r.returncode, 0,
                            "swapped carry bind source must refuse")
        status = getattr(r, "_setup_status", None)
        if status is None:
            self.fail("expected a setup-failure status on the pipe")
        self.assertEqual(status[0], "P",
                         f"expected pin-violation category, got {status}")
        for where in (victim, moved, unbound):
            self.assertFalse(
                (Path(where) / "proof").exists(),
                f"write escaped the refused spawn into {where}",
            )

    @requires_landlock
    @requires_userns
    # Exercises mount-delivered capability; hosts with userns but no mount capability degrade by design -> named SKIP.
    @requires_mount
    def test_out_of_view_missing_writable_refuses_before_spawn(
            self) -> None:
        """A writable grant that is out-of-view AND does not exist is
        never-carriable — no lane could honour it — and refuses at
        spawn assembly with the named error, not a use-time EACCES
        after a buried rule-open warning."""
        from core.sandbox._spawn import run_sandboxed
        from core.sandbox.errors import SandboxSetupError
        out = self.base / "out"
        out.mkdir()
        ghost = self.base / "no-such-grant-dir"
        kwargs = self._spawn_kwargs(out)
        kwargs["writable_paths"] = [str(out), str(ghost), "/tmp"]
        with self.assertRaises(SandboxSetupError) as ctx:
            run_sandboxed(["sh", "-c", "echo never"], **kwargs)
        self.assertIn("outside the mount view", str(ctx.exception))
