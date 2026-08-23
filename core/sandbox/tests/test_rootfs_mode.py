"""Tests for image-rootfs mode: sandbox(rootfs=<unpacked image dir>).

Two layers:

1. Fail-closed contract tests — run everywhere, no namespace needed.
   Rootfs mode's defining property is that it NEVER degrades: every
   path that other sandbox calls tolerate as a fallback (profile
   'none', Landlock-only subprocess, pass_fds/input kwargs) must raise
   SandboxSetupError/ValueError for a rootfs caller, because degraded
   means "ran against the host filesystem while the caller believed it
   was containerised".

2. End-to-end pivot tests — gated like test_spawn_mount_ns.py on the
   mount-ns prerequisites, plus a working `cc -static` (the image
   rootfs is built in-test around one static binary, so the tests need
   no docker and no network). They exercise the full chain: image bind
   as new root, no host system dirs inside, per-ns /dev + /proc +
   fresh /tmp, ns-local pids with the in-process PID-1 waiter (target
   runs as PID 2, signalled deaths mirror as 128+N), image tree
   writable as the upper layer, host-side write landing in the rootfs
   dir.
"""

from __future__ import annotations

import sys as _sys

import pytest as _pytest

pytestmark = _pytest.mark.skipif(
    _sys.platform != "linux",
    reason="Linux-only sandbox internals (mount-ns rootfs pivot)",
)

import os  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402
import unittest  # noqa: E402
from pathlib import Path  # noqa: E402


def _mount_ns_usable() -> bool:
    """Same predicate as test_spawn_mount_ns.py: both prerequisites."""
    if not shutil.which("newuidmap") or not shutil.which("newgidmap"):
        return False
    sysctl = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    if sysctl.exists() and sysctl.read_text().strip() == "1":
        return False
    return True


# ── static-binary image builder ───────────────────────────────────────

_INIT_C = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char **argv) {
    if (argc > 1 && strncmp(argv[1], "exit", 4) == 0)
        return atoi(argv[1] + 4);
    if (argc > 1 && strncmp(argv[1], "die", 3) == 0) {
        kill(getpid(), atoi(argv[1] + 3));
        pause();
    }
    if (argc > 2 && strcmp(argv[1], "wr") == 0) {
        FILE *w = fopen(argv[2], "w");
        if (w) { fputs("X", w); fclose(w); printf("devwrite=ok\n"); }
        else   { printf("devwrite=fail errno=%d\n", errno); }
        return 0;
    }
    printf("pid=%d\n", (int)getpid());
    printf("uid=%d\n", (int)getuid());
    FILE *f = fopen("/etc/img-id", "r");
    if (f) {
        char buf[64] = {0};
        if (fgets(buf, sizeof buf, f)) printf("img=%s", buf);
        fclose(f);
    } else {
        printf("img=MISSING\n");
    }
    /* /etc/passwd exists on every host; the image below ships none.
       "absent" proves no host /etc leaked into the pivoted root. */
    printf("passwd=%s\n",
           access("/etc/passwd", F_OK) == 0 ? "present" : "absent");
    f = fopen("/var/testwrite", "w");
    if (f) { fputs("W\n", f); fclose(f); printf("write=ok\n"); }
    else   { printf("write=fail\n"); }
    return 0;
}
"""

# Session-scoped compile cache: (ok, path-or-None). Compiling once is
# ~200ms; recompiling per test would dominate the suite.
_static_bin_cache: tuple[bool, str | None] | None = None
_static_bin_dir: tempfile.TemporaryDirectory | None = None


def _static_init_binary() -> str | None:
    """Path to a statically linked test binary, or None when the host
    toolchain can't produce one (no cc, or no static libc)."""
    global _static_bin_cache, _static_bin_dir
    if _static_bin_cache is not None:
        return _static_bin_cache[1]
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc:
        _static_bin_cache = (False, None)
        return None
    _static_bin_dir = tempfile.TemporaryDirectory(prefix="raptor-rootfs-cc-")
    src = Path(_static_bin_dir.name) / "init.c"
    out = Path(_static_bin_dir.name) / "init"
    src.write_text(_INIT_C)
    try:
        r = subprocess.run(
            [cc, "-static", "-O1", "-o", str(out), str(src)],
            capture_output=True, timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        _static_bin_cache = (False, None)
        return None
    if r.returncode != 0 or not out.is_file():
        _static_bin_cache = (False, None)  # e.g. glibc-static missing
        return None
    _static_bin_cache = (True, str(out))
    return str(out)


def _build_rootfs(base: str) -> str:
    """Minimal unpacked-image layout: /bin/init (static), /etc/img-id
    sentinel, /var for the write probe. Deliberately NO /etc/passwd,
    /usr, /lib — host-leak assertions depend on their absence."""
    rootfs = Path(base) / "rootfs"
    (rootfs / "bin").mkdir(parents=True)
    (rootfs / "etc").mkdir()
    (rootfs / "var").mkdir()
    shutil.copy2(_static_init_binary(), rootfs / "bin" / "init")
    (rootfs / "etc" / "img-id").write_text("IMAGE-SENTINEL\n")
    return str(rootfs)


# ── layer 1: fail-closed contract (no namespace needed) ───────────────


class TestRootfsFailClosedContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_nonexistent_rootfs_raises_valueerror(self):
        from core.sandbox import sandbox
        with self.assertRaises(ValueError):
            with sandbox(rootfs=os.path.join(self.tmp.name, "nope")):
                pass

    def test_rootfs_file_not_dir_raises_valueerror(self):
        from core.sandbox import sandbox
        f = Path(self.tmp.name) / "afile"
        f.write_text("x")
        with self.assertRaises(ValueError):
            with sandbox(rootfs=str(f)):
                pass

    def test_rootfs_with_disabled_raises_setup_error(self):
        """disabled=True means rlimits-only — no mount ns exists to
        pivot into, so a rootfs request must refuse, not silently run
        the command on the host."""
        from core.sandbox import sandbox
        from core.sandbox.errors import SandboxSetupError
        with self.assertRaises(SandboxSetupError):
            with sandbox(rootfs=self.tmp.name, disabled=True):
                pass

    def test_rootfs_with_profile_none_raises_setup_error(self):
        from core.sandbox import sandbox
        from core.sandbox.errors import SandboxSetupError
        with self.assertRaises(SandboxSetupError):
            with sandbox(rootfs=self.tmp.name, profile="none"):
                pass

    def test_inner_run_rejects_rootfs_kwarg(self):
        """rootfs is context-level configuration; a per-call value
        would silently no-op, so run() must reject it like the other
        _SANDBOX_KWARGS."""
        from core.sandbox import sandbox
        with sandbox(block_network=False) as run:
            with self.assertRaises(TypeError):
                run(["true"], rootfs=self.tmp.name)

    def test_run_sandboxed_rejects_skip_mount_ns(self):
        """The spawn seam itself refuses the incoherent combination —
        defence in depth below the context-level gates."""
        from core.sandbox._spawn import run_sandboxed
        with self.assertRaises(ValueError):
            run_sandboxed(
                ["true"],
                target=None, output=None,
                rootfs=self.tmp.name, skip_mount_ns=True,
                block_network=True, nproc_limit=64,
                limits={"memory_mb": 0, "max_file_mb": 1, "cpu_seconds": 5},
                writable_paths=[], readable_paths=None,
                allowed_tcp_ports=None,
                seccomp_profile=None, seccomp_block_udp=False,
                env=None, cwd=None, timeout=5,
            )

    def test_run_sandboxed_rejects_missing_rootfs_dir(self):
        from core.sandbox._spawn import run_sandboxed
        with self.assertRaises(ValueError):
            run_sandboxed(
                ["true"],
                target=None, output=None,
                rootfs=os.path.join(self.tmp.name, "nope"),
                block_network=True, nproc_limit=64,
                limits={"memory_mb": 0, "max_file_mb": 1, "cpu_seconds": 5},
                writable_paths=[], readable_paths=None,
                allowed_tcp_ports=None,
                seccomp_profile=None, seccomp_block_udp=False,
                env=None, cwd=None, timeout=5,
            )


class TestSubidRangeParser(unittest.TestCase):
    """_subid_range parses /etc/subuid-format files; None on trouble."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "subuid")

    def _write(self, text: str) -> str:
        Path(self.path).write_text(text)
        return self.path

    def test_match_by_name(self):
        from core.sandbox._spawn import _subid_range
        self._write("alice:100000:65536\nbob:200000:65536\n")
        self.assertEqual(_subid_range(self.path, "bob", "1001"),
                         (200000, 65536))

    def test_match_by_numeric_id(self):
        from core.sandbox._spawn import _subid_range
        self._write("1001:300000:65536\n")
        self.assertEqual(_subid_range(self.path, "bob", "1001"),
                         (300000, 65536))

    def test_first_entry_wins(self):
        from core.sandbox._spawn import _subid_range
        self._write("bob:100000:65536\nbob:900000:65536\n")
        self.assertEqual(_subid_range(self.path, "bob", "1001"),
                         (100000, 65536))

    def test_count_capped(self):
        from core.sandbox._spawn import _subid_range
        self._write("bob:100000:10000000\n")
        self.assertEqual(_subid_range(self.path, "bob", "1001"),
                         (100000, 65536))

    def test_malformed_lines_skipped(self):
        from core.sandbox._spawn import _subid_range
        self._write("# comment\n\nnot-a-triple\nbob:100000:4096\n")
        self.assertEqual(_subid_range(self.path, "bob", "1001"),
                         (100000, 4096))

    def test_missing_file_returns_none(self):
        from core.sandbox._spawn import _subid_range
        self.assertIsNone(
            _subid_range(os.path.join(self.tmp.name, "gone"), "bob", "1001"))

    def test_non_numeric_returns_none(self):
        from core.sandbox._spawn import _subid_range
        self._write("bob:xxx:yyy\n")
        self.assertIsNone(_subid_range(self.path, "bob", "1001"))


# ── layer 2: end-to-end pivot (gated) ─────────────────────────────────


class _RootfsE2EBase(unittest.TestCase):
    def setUp(self):
        if not _mount_ns_usable():
            self.skipTest(
                "mount-ns unusable here (needs uidmap package + "
                "kernel.apparmor_restrict_unprivileged_userns=0)"
            )
        if _static_init_binary() is None:
            self.skipTest("no working `cc -static` on this host")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.rootfs = _build_rootfs(self.tmp.name)
        self.out = os.path.join(self.tmp.name, "out")
        os.makedirs(self.out)


class TestRootfsPivotE2E(_RootfsE2EBase):
    def _run(self, argv, **kw):
        from core.sandbox import run as sandbox_run
        return sandbox_run(
            argv, rootfs=self.rootfs, output=self.out,
            block_network=True, capture_output=True, text=True,
            timeout=60, **kw,
        )

    def test_image_view_pids_and_upper_layer(self):
        """One pivoted run proves the core contract: the child sees the
        image filesystem (sentinel present, host /etc/passwd absent),
        runs as ns-uid 0 with an ns-local pid (2 — the in-process PID-1
        waiter holds pid 1), can write into the image tree, and the
        write lands host-side in the rootfs upper layer."""
        r = self._run(["/bin/init"])
        self.assertEqual(r.returncode, 0, f"stderr: {r.stderr!r}")
        self.assertIn("img=IMAGE-SENTINEL", r.stdout)
        self.assertIn("passwd=absent", r.stdout)
        self.assertIn("uid=0", r.stdout)
        # ns-local pid, and NOT pid 1: the in-process waiter holds
        # PID 1 so kill(2)-delivered self-signals reach the target
        # (exact value depends on the spawn chain's fork count).
        pid = int(r.stdout.split("pid=", 1)[1].split()[0])
        self.assertGreater(pid, 1, "target must not be pid-ns PID 1")
        self.assertLess(pid, 16, "pid not ns-local — pid-ns did not engage")
        self.assertIn("write=ok", r.stdout)
        host_side = Path(self.rootfs) / "var" / "testwrite"
        self.assertTrue(host_side.is_file(),
                        "image write did not land in the rootfs dir")
        self.assertEqual(host_side.read_text(), "W\n")

    def test_exit_status_mirrored_through_waiter(self):
        r = self._run(["/bin/init", "exit7"])
        self.assertEqual(r.returncode, 7, f"stderr: {r.stderr!r}")

    def test_signal_death_mirrored_as_128_plus_n(self):
        """abort()-class deaths are the raison d'être of the PID-1
        waiter: a PID-1 target would have the self-signal filtered by
        the kernel and hang; as PID 2 it dies and the waiter mirrors
        the shim convention observe._interpret_result decodes."""
        r = self._run(["/bin/init", "die6"])  # SIGABRT
        self.assertEqual(r.returncode, 128 + 6, f"stderr: {r.stderr!r}")

    def test_missing_cmd_in_image_fails_closed(self):
        """cmd[0] absent from the image → exec fails inside the mount
        ns → for rootfs this must raise, never retry on the host
        (where /bin/sh would happily exist)."""
        from core.sandbox.errors import SandboxSetupError
        with self.assertRaises(SandboxSetupError):
            self._run(["/bin/sh", "-c", "true"])

    def test_input_kwarg_fails_closed(self):
        """input= routes other callers to the Landlock-only subprocess
        path; for rootfs that is a host-fs run and must refuse."""
        from core.sandbox.errors import SandboxSetupError
        with self.assertRaises(SandboxSetupError):
            self._run(["/bin/init"], input="x")


class TestRootfsHostDeviceContainment(_RootfsE2EBase):
    """rootfs mode rbinds host /dev and /sys. The Landlock write grant
    must NOT cover them — otherwise same-UID host device nodes (the
    operator's other ptys, most damningly) are writable from inside
    the image sandbox — while /dev/null (file-scoped device rule) and
    the image's own tree keep working."""

    def _run(self, argv, **kw):
        from core.sandbox import run as sandbox_run
        return sandbox_run(
            argv, rootfs=self.rootfs, output=self.out,
            block_network=True, capture_output=True, text=True,
            timeout=60, **kw,
        )

    def setUp(self):
        super().setUp()
        from core.sandbox.landlock import check_landlock_available
        if not check_landlock_available():
            self.skipTest("Landlock unavailable — the write-grant "
                          "narrowing under test cannot engage")

    def test_operator_pty_not_writable(self):
        master, slave = os.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        pty_path = os.ttyname(slave)
        r = self._run(["/bin/init", "wr", pty_path])
        self.assertEqual(r.returncode, 0, r.stderr[-300:])
        self.assertIn("devwrite=fail", r.stdout, (
            f"sandboxed rootfs child wrote to the operator's pty "
            f"{pty_path}: {r.stdout!r}"
        ))

    def test_dev_null_still_writable(self):
        r = self._run(["/bin/init", "wr", "/dev/null"])
        self.assertEqual(r.returncode, 0, r.stderr[-300:])
        self.assertIn("devwrite=ok", r.stdout, (
            f"/dev/null write must keep working via the file-scoped "
            f"device rule: {r.stdout!r} {r.stderr!r}"
        ))

    def test_image_tree_still_writable(self):
        r = self._run(["/bin/init", "wr", "/var/g2probe"])
        self.assertEqual(r.returncode, 0, r.stderr[-300:])
        self.assertIn("devwrite=ok", r.stdout, (
            f"image upper layer must stay writable: {r.stdout!r}"
        ))


class TestRootfsEtcOverlayReadOnly(_RootfsE2EBase):
    """Overlay entries are configuration views, never write surfaces.
    In rootfs mode the Landlock grant covers the image's /etc, so a
    writable overlay bind would be a write-through hole onto the LIVE
    host source file — the bind must be remounted read-only."""

    def test_overlay_write_refused_and_host_source_intact(self):
        overlay_source = os.path.join(self.tmp.name, "overlay-src.conf")
        sentinel = "RAPTOR-OVERLAY-RO-SENTINEL\n"
        with open(overlay_source, "w") as f:
            f.write(sentinel)
        from core.sandbox import run as sandbox_run
        r = sandbox_run(
            ["/bin/init", "wr", "/etc/g2-overlay.conf"],
            rootfs=self.rootfs, output=self.out, block_network=True,
            capture_output=True, text=True, timeout=60,
            etc_overlay={"/etc/g2-overlay.conf": overlay_source},
        )
        self.assertEqual(r.returncode, 0, r.stderr[-300:])
        self.assertIn("devwrite=fail", r.stdout, (
            f"child wrote through the etc_overlay bind onto the live "
            f"host source: {r.stdout!r}"
        ))
        with open(overlay_source) as f:
            self.assertEqual(f.read(), sentinel,
                             "host overlay source file was mutated "
                             "through the sandbox bind")


class TestRootfsSymlinkedMountpointRefused(_RootfsE2EBase):
    """An image shipping one of the per-namespace mountpoint names
    (dev/proc/sys/run/tmp) as a symlink must be refused outright:
    pre-pivot path-based makedirs/mount(2) would resolve it in the
    HOST namespace, diverting inode creation and the /dev,/proc,/sys
    binds."""

    def test_symlinked_dev_refused(self):
        os.symlink("var", os.path.join(self.rootfs, "dev"))
        from core.sandbox import run as sandbox_run
        from core.sandbox.errors import SandboxSetupError
        try:
            r = sandbox_run(
                ["/bin/init", "exit0"], rootfs=self.rootfs,
                output=self.out, block_network=True,
                capture_output=True, text=True, timeout=60,
            )
        except SandboxSetupError:
            return  # fail-closed refusal — expected
        self.assertNotEqual(r.returncode, 0, (
            "image with a symlinked /dev mountpoint must be refused, "
            "not silently set up with diverted binds"
        ))


class TestRootfsGate5LoadBearing(unittest.TestCase):
    """Rootfs fail-closed gate #5 is LOAD-BEARING for the loader-var
    posture: a rootfs run whose mount-ns spawn setup fails mid-flight
    must raise SandboxSetupError, never degrade to the Landlock-only
    host-filesystem path — on that path the (image-config-derived,
    target-influenceable) caller env would be applied to launcher
    execs on the host. core/env/handle.py's strict_env is the second
    gate; this test pins the first so a future tier change cannot
    silently remove it."""

    def test_spawn_setup_failure_raises_not_degrades(self):
        if not _mount_ns_usable():
            self.skipTest(
                "mount-ns unusable here (gate #3 fires before gate #5)"
            )
        import unittest.mock as mock

        from core.sandbox import _spawn as spawn_mod
        from core.sandbox import run as sandbox_run
        from core.sandbox.errors import SandboxSetupError

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        rootfs = os.path.join(tmp.name, "rootfs")
        os.makedirs(os.path.join(rootfs, "bin"))

        with mock.patch.object(
            spawn_mod, "run_sandboxed",
            side_effect=RuntimeError("simulated spawn-setup failure"),
        ), self.assertRaises(SandboxSetupError) as ctx:
            sandbox_run(
                ["/bin/true"], rootfs=rootfs, block_network=True,
                capture_output=True, text=True, timeout=30,
            )
        self.assertIn("refusing the Landlock-only", str(ctx.exception))
