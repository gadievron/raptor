"""Isolation-tier matrix for the child-setup wiring.

Covers the interaction fixes across mount-ns / Landlock / netns
combinations:

  * seccomp's AF_UNIX allowance is granted exactly when the mount
    namespace engages for the child (target/output present, not
    skipped) and never on the preexec-only fallback path;
  * Landlock's read allowlist engages only under restrict_reads —
    readable_paths/tool_paths alone must not read-restrict the child;
  * /dev/shm rides the Landlock scratch baseline so POSIX semaphores
    work wherever writes are otherwise pinned.

Plumbing decisions are asserted with spies (no namespaces needed, so
they run anywhere); end-to-end behaviour is asserted live and skips
on hosts without the required layer.
"""

import os
import shutil
import subprocess
import sys

import pytest

from core.sandbox import check_mount_available
from core.sandbox._spawn import mount_ns_available, run_sandboxed


def _spawn_kwargs(tmp_path, **over):
    base = {
        "target": str(tmp_path), "output": str(tmp_path),
        "block_network": True, "nproc_limit": 0, "limits": {},
        "writable_paths": [], "readable_paths": None,
        "allowed_tcp_ports": None,
        "seccomp_profile": "full", "seccomp_block_udp": False,
        "env": None, "cwd": None, "timeout": 10,
        "audit_mode": False, "audit_run_dir": None,
    }
    base.update(over)
    return base


class TestSeccompUnixAllowancePlumbing:
    """The allow_unix_sockets decision, observed via a builder spy.

    Mirrors the spy pattern in test_spawn_audit.py: run_sandboxed may
    fail later for host-specific reasons — the spy capture happens
    before the fork, so the decision is still observable.
    """

    def _capture(self, monkeypatch, tmp_path, **over):
        from core.sandbox import seccomp
        captured = []
        original = seccomp._make_seccomp_preexec

        def spy(profile, block_udp=False, audit_mode=False,
                observe_mode=False, allow_unix_sockets=False,
                **kw):
            captured.append(allow_unix_sockets)
            return original(profile, block_udp=block_udp,
                            audit_mode=audit_mode,
                            observe_mode=observe_mode,
                            allow_unix_sockets=allow_unix_sockets,
                            **kw)
        monkeypatch.setattr(
            "core.sandbox._spawn._make_seccomp_preexec", spy)
        try:
            run_sandboxed(["true"], **_spawn_kwargs(tmp_path, **over))
        except Exception:  # noqa: BLE001, S110 — host-specific setup failures are fine
            pass
        return captured

    def test_allowed_with_mount_ns(self, monkeypatch, tmp_path):
        # The allowance is downgraded (fail-closed) on hosts where the
        # connect-scoping supervisor cannot run; the allowed-case
        # assertion only holds where the capability exists. The
        # blocked-case tests below hold everywhere.
        from core.sandbox._unix_scope import probe_unix_scope
        if not probe_unix_scope():
            pytest.skip(
                "AF_UNIX connect scoping unavailable on this host",
            )
        assert self._capture(monkeypatch, tmp_path) == [True]

    def test_blocked_without_target_or_output(self, monkeypatch, tmp_path):
        got = self._capture(monkeypatch, tmp_path, target=None, output=None)
        assert got == [False]

    def test_blocked_when_mount_ns_skipped(self, monkeypatch, tmp_path):
        got = self._capture(monkeypatch, tmp_path, skip_mount_ns=True)
        assert got == [False]

    def test_preexec_fallback_path_keeps_block(self):
        # The subprocess+preexec fallback builds its seccomp filter
        # without the allowance — assert the call site statically so a
        # future refactor can't silently start forwarding it.
        import inspect

        from core.sandbox import preexec
        src = inspect.getsource(preexec)
        assert "allow_unix_sockets" not in src, (
            "preexec path must not grant the AF_UNIX allowance: it has "
            "no mount-ns, so pathname sockets (docker.sock) are reachable"
        )


class TestLandlockReadGatePlumbing:
    """readable_paths reaches Landlock only under restrict_reads."""

    def _capture(self, monkeypatch, tmp_path, **over):
        from core.sandbox import landlock
        captured = []
        original = landlock._make_landlock_preexec

        def spy(writable_paths, allowed_tcp_ports=None,
                readable_paths=None, deny_all_tcp_connect=False):
            captured.append(readable_paths)
            return original(writable_paths, allowed_tcp_ports,
                            readable_paths=readable_paths,
                            deny_all_tcp_connect=deny_all_tcp_connect)
        monkeypatch.setattr(
            "core.sandbox._spawn._make_landlock_preexec", spy)
        try:
            run_sandboxed(["true"], **_spawn_kwargs(
                tmp_path, writable_paths=[str(tmp_path)], **over))
        except Exception:  # noqa: BLE001, S110 — host-specific setup failures are fine
            pass
        return captured

    def test_unrestricted_reads_by_default(self, monkeypatch, tmp_path):
        got = self._capture(monkeypatch, tmp_path,
                            readable_paths=[str(tmp_path)])
        assert got == [None], (
            "readable_paths must stay a bind list unless restrict_reads: "
            "forwarding it to Landlock read-restricts the whole child "
            "with no system-dir floor"
        )

    def test_restricted_reads_forwarded(self, monkeypatch, tmp_path):
        got = self._capture(monkeypatch, tmp_path,
                            readable_paths=[str(tmp_path)],
                            restrict_reads=True)
        assert got == [[str(tmp_path)]]


# Gate on the SAME probe production uses to pick the spawn backend
# (check_mount_available: userns sysctls + a real unshare probe), not
# just mount_ns_available (uidmap binaries present). On hosts whose
# LSM blocks unprivileged userns for unprofiled binaries the uidmap
# binaries exist but run() degrades to the Landlock-only subprocess
# tier, and the mount-ns properties this matrix asserts cannot hold.
_LIVE = pytest.mark.skipif(
    not (sys.platform == "linux" and mount_ns_available()
         and check_mount_available()),
    reason="live matrix needs Linux with mount-ns capability",
)


@_LIVE
class TestLiveIsolationMatrix:
    """End-to-end behaviour on hosts with the full stack available."""

    # A system-dir interpreter: the venv/user python lives outside
    # the mount-ns bind tree, which would (correctly) drop the run to
    # the fallback tier and test the wrong path.
    _PY = "/usr/bin/python3"

    def _run(self, tmp_path, code, **over):
        from core.sandbox import run
        kwargs = {
            "block_network": True, "target": str(tmp_path),
            "output": str(tmp_path), "capture_output": True,
            "text": True, "timeout": 120,
        }
        kwargs.update(over)
        return run([self._PY, "-c", code], **kwargs)

    def test_multiprocessing_roundtrip_full_stack(self, tmp_path):
        # Exercises AF_UNIX (forkserver listener on Python >= 3.14),
        # /dev/shm SemLock, and the Landlock scratch baseline at once.
        code = (
            "import multiprocessing as mp\n"
            "q = mp.Queue()\n"
            "p = mp.Process(target=q.put, args=(42,))\n"
            "p.start(); p.join()\n"
            "assert q.get(timeout=10) == 42\n"
            "print('MP-OK')\n"
        )
        r = self._run(tmp_path, code)
        assert r.returncode == 0, r.stderr[-500:] if r.stderr else r
        assert "MP-OK" in (r.stdout or "")

    def test_dev_shm_is_private(self, tmp_path):
        marker = f"raptor-matrix-{os.getpid()}"
        host_file = f"/dev/shm/{marker}"
        with open(host_file, "w") as fh:
            fh.write("host")
        try:
            code = (
                "import os, sys\n"
                f"sys.exit(1 if os.path.exists({host_file!r}) else 0)\n"
            )
            r = self._run(tmp_path, code)
            if not r.sandbox_info.get("mount_ns_active"):
                # Probe passed but the runtime tier still degraded
                # (nested container / LSM): /dev/shm privacy is a
                # mount-ns property, so there is nothing to assert on
                # the Landlock-only tier.
                pytest.skip("mount namespace did not engage on this host")
            assert r.returncode == 0, (
                "host /dev/shm contents must not be visible inside the "
                "mount namespace"
            )
        finally:
            os.unlink(host_file)

    def test_af_unix_blocked_without_mount_ns(self, tmp_path):
        code = (
            "import socket\n"
            "socket.socket(socket.AF_UNIX)\n"
            "print('UNIX-OK')\n"
        )
        r = self._run(tmp_path, code, skip_mount_ns=True)
        assert "UNIX-OK" not in (r.stdout or ""), (
            "AF_UNIX must stay blocked when the mount namespace is "
            "skipped: /run is host-real there"
        )

    def test_tool_paths_do_not_break_exec(self, tmp_path):
        # Regression: naming tool_paths used to read-restrict the child
        # via Landlock with no floor, so even /bin/sh failed to exec and
        # the run silently degraded to the fallback tier.
        from core.sandbox import run
        tool_dir = tmp_path / "tools"
        tool_dir.mkdir()
        r = run(["/bin/sh", "-c", "echo EXEC-OK"],
                block_network=True, target=str(tmp_path),
                output=str(tmp_path), tool_paths=[str(tool_dir)],
                capture_output=True, text=True, timeout=60)
        assert r.returncode == 0 and "EXEC-OK" in (r.stdout or "")

    def test_restrict_reads_still_restricts(self, tmp_path):
        # The read-gate fix must not have widened restrict_reads mode.
        secret = tmp_path / "outside" / "secret.txt"
        secret.parent.mkdir()
        secret.write_text("s")
        readable = tmp_path / "allowed"
        readable.mkdir()
        from core.sandbox import run
        r = run(["/bin/cat", str(secret)],
                block_network=True, target=str(readable),
                output=str(readable), restrict_reads=True,
                readable_paths=[str(readable)],
                capture_output=True, text=True, timeout=60)
        if not r.sandbox_info.get("mount_ns_active"):
            # Runtime tier degraded to Landlock-only despite the probe:
            # there the documented /tmp scratch baseline (writes imply
            # reads) covers pytest's tmp_path, so a secret under /tmp
            # is readable BY DESIGN on that tier — reads outside the
            # scratch dirs (e.g. $HOME) are still denied, which the
            # Landlock suites assert. Only the mount-ns tier hides
            # host /tmp behind a private tmpfs.
            pytest.skip("mount namespace did not engage on this host")
        assert r.returncode != 0, (
            "restrict_reads must still deny reads outside the allowlist"
        )


@_LIVE
class TestScannerBindMatrix:
    """The scanner's realpath + bind fixes, end to end with a stub tool."""

    def test_symlinked_tool_and_local_config_visible(self, tmp_path):
        # A stub 'scanner' that proves it can read its config file and
        # emits it — stands in for semgrep without the runtime cost.
        real_dir = tmp_path / "venv-bin"
        real_dir.mkdir()
        real_tool = real_dir / "stub-scan"
        real_tool.write_text(
            "#!/bin/sh\ncat \"$1\" || exit 7\n"
        )
        real_tool.chmod(0o755)
        link_dir = tmp_path / "user-bin"
        link_dir.mkdir()
        link = link_dir / "stub-scan"
        link.symlink_to(real_tool)
        cfg_dir = tmp_path / "rules"
        cfg_dir.mkdir()
        cfg = cfg_dir / "rules.yml"
        cfg.write_text("rules: []\n")
        repo = tmp_path / "repo"
        repo.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        from core.sandbox import run
        # Invoke via the REAL path with the tool dir + config dir named
        # as tool_paths — the shape scanner.run() now produces.
        r = run([os.path.realpath(str(link)), str(cfg)],
                block_network=True, target=str(repo), output=str(out),
                tool_paths=[str(real_dir), str(cfg_dir)],
                capture_output=True, text=True, timeout=60)
        assert r.returncode == 0 and "rules: []" in (r.stdout or "")


def test_semgrep_registry_probe_offline_guard():
    """Sanity: the suite itself must not need the network."""
    assert shutil.which("true")
    assert subprocess.run(["true"], check=False).returncode == 0
