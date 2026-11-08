"""Per-sandbox minimal /dev: the mount-ns lane no longer carries the
host's device tree into the sandbox.

The gap: step 5 recursively bind-mounted host /dev — every node,
including /dev/pts/* — and the DEFAULT posture
(``restrict_reads=False``) leaves reads unrestricted, so a hostile
build script or fuzz target could read-open the operator's same-uid
pty slave and compete for the operator's keystrokes (write was caught
by the Landlock write mask; read was not).

Post-fix contract, two directions:
- host pty slaves are NOT reachable from the mount-ns lane (the node
  does not exist in the per-sandbox /dev), on the DEFAULT
  read-unrestricted posture;
- the nodes tools actually need keep working: /dev/null write,
  /dev/urandom read, /dev/fd + /dev/std* indirection, POSIX shm, and
  a working openpty() from the fresh (namespace-local) devpts.
"""

from __future__ import annotations

import os
import pty
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
if __name__ == "__main__":
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))

from core.sandbox.tests.capability import requires_mount

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="Linux mount-ns"),
    requires_mount,
]


# A system-dir interpreter: the venv/user python lives outside the
# mount-ns bind tree, which would (correctly) drop the run to the
# fallback tier and test the wrong path.
_PY = "/usr/bin/python3"


def _run_in_mount_ns(child_src: str, tmp_path: Path,
                     **kwargs) -> subprocess.CompletedProcess:
    from core.sandbox import run

    target = tmp_path / "target"
    output = tmp_path / "output"
    target.mkdir(exist_ok=True)
    output.mkdir(exist_ok=True)
    return run(
        [_PY, "-c", child_src],
        target=str(target), output=str(output),
        capture_output=True, text=True, timeout=60,
        **kwargs,
    )


def _require_mount_ns_taken(r) -> None:
    info = getattr(r, "sandbox_info", None) or {}
    if not info.get("mount_ns_active"):
        pytest.skip("mount-ns lane not taken on this host")


class TestHostPtysHidden:
    def test_host_pts_slave_not_reachable(self, tmp_path):
        """The audit shape: allocate a pty pair on the HOST, then try
        to read-open the slave from inside a default-posture mount-ns
        run. Pre-fix the open succeeded (terminal-input sniffing
        surface); post-fix the node does not exist in the sandbox."""
        master, slave = pty.openpty()
        try:
            slave_path = os.ttyname(slave)
            child = textwrap.dedent(f"""
                import errno, sys
                try:
                    fd = open({slave_path!r}, "rb")
                except OSError as e:
                    print("DENIED errno=%d" % (e.errno or -1))
                    sys.exit(0)
                fd.close()
                print("OPENED-HOST-PTY")
                sys.exit(1)
            """)
            r = _run_in_mount_ns(child, tmp_path)
            _require_mount_ns_taken(r)
            assert "OPENED-HOST-PTY" not in r.stdout, (
                "host pty slave readable from the sandbox: "
                + r.stdout + r.stderr)
            assert r.returncode == 0, r.stdout + r.stderr
        finally:
            os.close(master)
            os.close(slave)

    def test_dev_carries_only_the_minimal_set(self, tmp_path):
        child = textwrap.dedent("""
            import os
            print(sorted(os.listdir("/dev")))
        """)
        r = _run_in_mount_ns(child, tmp_path)
        _require_mount_ns_taken(r)
        assert r.returncode == 0, r.stdout + r.stderr
        listed = set(eval(r.stdout.strip()))  # noqa: S307 — test-owned literal
        expected = {"null", "zero", "full", "random", "urandom", "tty",
                    "fd", "stdin", "stdout", "stderr", "shm", "pts",
                    "ptmx"}
        assert listed <= expected, (
            f"unexpected /dev entries leaked in: {listed - expected}")
        assert {"null", "zero", "urandom", "shm"} <= listed, (
            f"essential nodes missing: {listed}")


class TestPtsGrantIsLaneScoped:
    def test_mountless_retry_cannot_write_host_pty(
            self, tmp_path, monkeypatch):
        """The /dev/pts write grant belongs to the mount-ns lane ONLY
        (there it names the per-sandbox devpts). On the mountless
        retry /dev/pts is the HOST's pty slaves — a context-level
        grant leaked exactly there and let sandboxed code inject
        bytes into the operator's terminal. Force the retry (fake 'M'
        on the first spawn) and prove the host slave stays
        write-denied; also pin that the shared writable_paths never
        carries /dev/pts on any dispatch."""
        import subprocess as _subprocess

        from core.sandbox import _spawn as _spawn_mod
        from core.sandbox import context as _ctx
        from core.sandbox.landlock import check_landlock_available

        if not check_landlock_available():
            # The write-deny under test IS Landlock's: on the mountless
            # retry there is no mount tree, so the host pty slave is
            # only unreachable because the Landlock policy carries no
            # /dev/pts grant there. On a Landlock-less kernel this
            # trusted-class call degrades (floor BARE, warn-once) to
            # the ns-only tier, which honestly promises no filesystem
            # confinement — nothing enforces the deny being pinned.
            pytest.skip("Landlock unavailable — the mountless /dev/pts "
                        "write-deny under test is Landlock-enforced")

        real_spawn = _spawn_mod.run_sandboxed
        calls = []

        def fail_first_bind(cmd, **kwargs):
            calls.append(kwargs)
            if len(calls) == 1:
                cp = _subprocess.CompletedProcess(
                    cmd, returncode=126, stdout="", stderr="")
                cp._setup_status = ("M", "forced mount-ns failure")
                return cp
            return real_spawn(cmd, **kwargs)

        monkeypatch.setattr(_spawn_mod, "run_sandboxed", fail_first_bind)
        master, slave = pty.openpty()
        try:
            slave_path = os.ttyname(slave)
            child = textwrap.dedent(f"""
                import sys
                try:
                    fd = open({slave_path!r}, "wb", buffering=0)
                except OSError as e:
                    print("WRITE-DENIED errno=%d" % (e.errno or -1))
                    sys.exit(0)
                fd.write(b"INJECTED-BY-SANDBOX")
                fd.close()
                print("WROTE-HOST-PTY")
                sys.exit(1)
            """)
            target = tmp_path / "t"
            output = tmp_path / "o"
            target.mkdir()
            output.mkdir()
            try:
                r = _ctx.run([_PY, "-c", child], target=str(target),
                             output=str(output), capture_output=True,
                             text=True, timeout=60)
            except Exception as e:  # noqa: BLE001 — host capability gate
                pytest.skip(f"mountless retry unavailable: {e}")
            if len(calls) < 2 or r.sandbox_info.get("mount_ns_active"):
                pytest.skip("mountless retry not taken on this host")
            assert "WROTE-HOST-PTY" not in r.stdout, (
                "sandboxed code wrote to the operator's pty from the "
                "mountless lane: " + r.stdout + (r.stderr or ""))
            assert r.returncode == 0, r.stdout + (r.stderr or "")
            for kwargs in calls:
                assert "/dev/pts" not in (
                    kwargs.get("writable_paths") or []), (
                    "the shared writable_paths must never carry "
                    "/dev/pts — the grant is added lane-scoped inside "
                    "run_sandboxed")
        finally:
            os.close(master)
            os.close(slave)


class TestMinimalDevCapability:
    def test_workhorse_nodes_work(self, tmp_path):
        child = textwrap.dedent("""
            import os
            with open("/dev/null", "wb") as f:
                f.write(b"x")
            with open("/dev/urandom", "rb") as f:
                assert len(f.read(16)) == 16
            with open("/dev/zero", "rb") as f:
                assert f.read(4) == b"\\x00" * 4
            # /dev/fd + /dev/std* indirection (bash process
            # substitution, `tool -o /dev/stdout`).
            assert os.path.isdir("/dev/fd")
            with open("/dev/stdout", "w") as f:
                f.write("STDOUT-VIA-DEV OK\\n")
        """)
        r = _run_in_mount_ns(child, tmp_path)
        _require_mount_ns_taken(r)
        assert "STDOUT-VIA-DEV OK" in r.stdout, r.stdout + r.stderr
        assert r.returncode == 0, r.stdout + r.stderr

    def test_posix_shm_works(self, tmp_path):
        child = textwrap.dedent("""
            from multiprocessing import shared_memory
            shm = shared_memory.SharedMemory(create=True, size=64)
            shm.buf[:2] = b"ok"
            assert bytes(shm.buf[:2]) == b"ok"
            shm.close(); shm.unlink()
            print("SHM OK")
        """)
        r = _run_in_mount_ns(child, tmp_path)
        _require_mount_ns_taken(r)
        assert "SHM OK" in r.stdout, r.stdout + r.stderr

    def test_openpty_uses_namespace_local_devpts(self, tmp_path):
        child = textwrap.dedent("""
            import os, pty
            m, s = pty.openpty()
            name = os.ttyname(s)
            assert name.startswith("/dev/pts/"), name
            os.write(m, b"ping\\n")
            assert os.read(s, 5) == b"ping\\n"[:5]
            os.close(m); os.close(s)
            print("OPENPTY OK", name)
        """)
        r = _run_in_mount_ns(child, tmp_path)
        _require_mount_ns_taken(r)
        if "devpts mount failed" in (r.stderr or ""):
            pytest.skip("kernel refused the userns devpts instance")
        assert "OPENPTY OK" in r.stdout, r.stdout + r.stderr
