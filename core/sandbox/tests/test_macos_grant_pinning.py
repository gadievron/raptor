"""Grant-path identity pinning on the macOS seatbelt lane.

SBPL grants are path STRINGS: seatbelt holds no inode reference, so a
real directory renamed into a granted path inherits the grant, and on
current macOS even a symlink swapped into a granted path routes writes
through to its destination (both confirmed live on macOS 26.6.2). The
darwin twin of the Linux bind-source P-byte pin is therefore
procedural: `_macos_spawn` snapshots (dev, ino) for every caller grant
at profile-emission time, re-verifies immediately before spawn, and
the watcher shim re-verifies every poll tick — on a mismatch that
PERSISTS across a tick it reports ``P`` on the status pipe and
SIGKILLs the sandbox tree; the context layer raises the typed refusal
instead of returning the tainted result.

Cross-platform: SANDBOX_EXEC is swapped for a pass-through script so
the REAL watcher shim + trampoline run on Linux too (the pin machinery
is plain lstat/fork/kill, nothing Apple-specific). Documented
residuals deliberately NOT asserted here: writes between a swap and
the next poll tick land before the kill, and a swap-and-restore
completed entirely within one tick evades detection (both need an
unsandboxed same-UID accomplice — outside this sandbox's threat
boundary).
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from unittest import mock

import pytest

from core.sandbox import _macos_spawn
from core.sandbox.errors import SandboxSetupError

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX-only",
)

_PIN_VIOLATION_EXIT = 121


def _fake_sandbox_exec(tmp_path):
    fake = tmp_path / "fake-sandbox-exec"
    fake.write_text('#!/bin/sh\nshift 3\nexec "$@"\n')  # drop -p <profile> --
    fake.chmod(0o755)
    return str(fake)


def _writer_loop(out_dir: str) -> list[str]:
    """Target that appends to {output}/marker every 50ms, bounded."""
    return ["/bin/sh", "-c",
            f'i=0; while [ $i -lt 100 ]; do '
            f'echo hit >> "{out_dir}/marker" 2>/dev/null; '
            f'sleep 0.05; i=$((i+1)); done']


def _swap_when_running(out_dir: str, swap) -> threading.Thread:
    """Fire `swap()` once the target's first write proves it is live."""
    marker = os.path.join(out_dir, "marker")

    def _waiter():
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not os.path.exists(marker):
            time.sleep(0.02)
        swap()

    th = threading.Thread(target=_waiter, daemon=True)
    th.start()
    return th


class TestPinTeardown:
    def test_symlink_swap_mid_run_kills_sandbox(self, tmp_path,
                                                monkeypatch):
        """A symlink swapped into the granted output path mid-run must
        end the run with the typed P status, not a clean result — on
        macOS the kernel routes writes through the link (observed
        live), so the watcher's dev/ino poll is the enforcement."""
        monkeypatch.setattr(_macos_spawn, "SANDBOX_EXEC",
                            _fake_sandbox_exec(tmp_path))
        out = tmp_path / "out"
        out.mkdir()
        victim = tmp_path / "victim"
        victim.mkdir()
        moved = str(out) + ".moved"

        def swap():
            os.rename(str(out), moved)
            os.symlink(str(victim), str(out))

        th = _swap_when_running(str(out), swap)
        started = time.monotonic()
        r = _macos_spawn.run_sandboxed(
            _writer_loop(str(out)),
            output=str(out),
            env={"PATH": "/usr/bin:/bin"},
            capture_output=True, text=True, timeout=30,
        )
        th.join(timeout=10)
        status = getattr(r, "_setup_status", None)
        assert status is not None and status[0] == "P", status
        assert r.returncode == _PIN_VIOLATION_EXIT
        # The teardown fired well before the writer's natural 5s end —
        # the poll-tick residual is bounded, not open-ended.
        assert time.monotonic() - started < 4.5

    def test_rename_swap_mid_run_kills_sandbox(self, tmp_path,
                                               monkeypatch):
        """A real directory renamed into the granted path inherits the
        SBPL grant (path-string semantics) — the pin must catch the
        identity change and kill the run."""
        monkeypatch.setattr(_macos_spawn, "SANDBOX_EXEC",
                            _fake_sandbox_exec(tmp_path))
        out = tmp_path / "out"
        out.mkdir()
        newdir = tmp_path / "newdir"
        newdir.mkdir()

        def swap():
            os.rename(str(out), str(out) + ".moved")
            os.rename(str(newdir), str(out))

        th = _swap_when_running(str(out), swap)
        r = _macos_spawn.run_sandboxed(
            _writer_loop(str(out)),
            output=str(out),
            env={"PATH": "/usr/bin:/bin"},
            capture_output=True, text=True, timeout=30,
        )
        th.join(timeout=10)
        status = getattr(r, "_setup_status", None)
        assert status is not None and status[0] == "P", status
        assert r.returncode == _PIN_VIOLATION_EXIT

    def test_clean_run_unaffected_by_pins(self, tmp_path, monkeypatch):
        """Pins engaged (output grant) but never violated: the run
        completes normally with a clean setup status."""
        monkeypatch.setattr(_macos_spawn, "SANDBOX_EXEC",
                            _fake_sandbox_exec(tmp_path))
        out = tmp_path / "out"
        out.mkdir()
        r = _macos_spawn.run_sandboxed(
            ["/bin/sh", "-c", "echo ok"],
            output=str(out),
            env={"PATH": "/usr/bin:/bin"},
            capture_output=True, text=True, timeout=15,
        )
        assert r.returncode == 0
        assert r.stdout.strip() == "ok"
        assert getattr(r, "_setup_status", "missing") is None

    def test_pin_env_not_visible_to_target(self, tmp_path, monkeypatch):
        """_RAPTOR_GRANT_PINS is consumed by the shim (child pre-exec
        check + watcher polling) and stripped — the sandboxed target
        must never see it."""
        monkeypatch.setattr(_macos_spawn, "SANDBOX_EXEC",
                            _fake_sandbox_exec(tmp_path))
        out = tmp_path / "out"
        out.mkdir()
        r = _macos_spawn.run_sandboxed(
            ["/bin/sh", "-c", 'printf %s "${_RAPTOR_GRANT_PINS:-ABSENT}"'],
            output=str(out),
            env={"PATH": "/usr/bin:/bin"},
            capture_output=True, text=True, timeout=15,
        )
        assert r.returncode == 0
        assert r.stdout == "ABSENT"

    def test_swap_between_validation_and_spawn_refused(self, tmp_path,
                                                       monkeypatch):
        """A swap landing between pin capture and the spawn (the window
        where the parent itself writes the fake-home/.tmp layout into
        output) must refuse BEFORE the sandbox starts — the last-moment
        re-verify, not the watcher, owns this window."""
        from core.sandbox import seatbelt as seatbelt_mod
        monkeypatch.setattr(_macos_spawn, "SANDBOX_EXEC",
                            _fake_sandbox_exec(tmp_path))
        out = tmp_path / "out"
        out.mkdir()
        victim = tmp_path / "victim"
        victim.mkdir()
        real_build = seatbelt_mod.build_profile

        def swapping_build(**kwargs):
            profile = real_build(**kwargs)
            # Pin capture has happened (it precedes profile emission);
            # swap now, before the spawn.
            os.rename(str(out), str(out) + ".moved")
            os.symlink(str(victim), str(out))
            return profile

        monkeypatch.setattr(seatbelt_mod, "build_profile", swapping_build)
        with pytest.raises(SandboxSetupError) as excinfo:
            _macos_spawn.run_sandboxed(
                ["/bin/sh", "-c", "echo never"],
                output=str(out),
                env={"PATH": "/usr/bin:/bin"},
                capture_output=True, text=True, timeout=15,
            )
        assert excinfo.value.setup_category == "P"
        assert "pin violated before spawn" in str(excinfo.value)

    def test_stale_pin_refused_by_shim_child_before_exec(self, tmp_path):
        """Direct shim invocation with an already-mismatched pin: the
        child branch verifies right before exec and aborts with the
        pin-violation exit code, reporting P — the target never runs."""
        import json
        shim = str(_macos_spawn.SEATBELT_SHIM)
        pinned = tmp_path / "pinned"
        pinned.mkdir()
        st = os.stat(pinned)
        pins = json.dumps([{"path": str(pinned), "dev": int(st.st_dev),
                            "ino": int(st.st_ino) + 1}])  # stale ino
        sr, sw = os.pipe()
        witness = tmp_path / "ran"
        p = subprocess.Popen(
            [sys.executable, "-I", shim,
             "/bin/sh", "-c", f'printf K >&3; exec 3>&-; exec "$@"',
             "raptor-seatbelt-rdy", "/bin/sh", "-c",
             f'touch "{witness}"'],
            pass_fds=(sw,),
            env=dict(os.environ, _RAPTOR_TRUSTED="1",
                     _RAPTOR_STATUS_FD=str(sw),
                     _RAPTOR_GRANT_PINS=pins),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        os.close(sw)
        _, err = p.communicate(timeout=10)
        data = b""
        while True:
            chunk = os.read(sr, 4096)
            if not chunk:
                break
            data += chunk
        os.close(sr)
        assert p.returncode == _PIN_VIOLATION_EXIT
        assert b"P" in data
        assert b"K" not in data, "target trampoline ran despite stale pin"
        assert not witness.exists()
        assert "pin violated before exec" in err

    def test_missing_pins_env_is_inert(self, tmp_path, monkeypatch):
        """No grants → no pins → no _RAPTOR_GRANT_PINS in the child
        env and no behaviour change (network-only-equivalent shape)."""
        monkeypatch.setattr(_macos_spawn, "SANDBOX_EXEC",
                            _fake_sandbox_exec(tmp_path))
        r = _macos_spawn.run_sandboxed(
            ["/bin/sh", "-c", "echo ok"],
            block_network=True,
            env={"PATH": "/usr/bin:/bin"},
            capture_output=True, text=True, timeout=15,
        )
        assert r.returncode == 0
        assert getattr(r, "_setup_status", "missing") is None


class TestDarwinStatusDecisionTable:
    """Context-layer decision table for the seatbelt setup-status
    channel — the darwin twin of test_setup_status_integrity's parent
    arms: 'P' raises typed and never degrades; unknown categories are
    default-DENIED, never returned as a genuine result."""

    def _run_with_fake_status(self, tmp_path, status):
        from core.sandbox import _macos_spawn as macos_mod
        from core.sandbox import context

        def fake_run(cmd, **kwargs):
            cp = subprocess.CompletedProcess(cmd, returncode=0,
                                             stdout="", stderr="")
            cp._setup_status = status
            cp.sandbox_info = {"backend": "macos-seatbelt"}
            return cp

        with mock.patch.object(sys, "platform", "darwin"), \
             mock.patch.object(context, "check_seatbelt_available",
                               return_value=True), \
             mock.patch.object(context, "check_mount_available",
                               return_value=False), \
             mock.patch.object(context, "check_net_available",
                               return_value=False), \
             mock.patch.object(macos_mod, "run_sandboxed", fake_run):
            return context.run(["/usr/bin/true"], target=str(tmp_path),
                               output=str(tmp_path), timeout=30)

    def test_p_status_raises_typed_refusal(self, tmp_path):
        with pytest.raises(SandboxSetupError) as excinfo:
            self._run_with_fake_status(
                tmp_path, ("P", "a granted path's identity changed"))
        assert excinfo.value.setup_category == "P"
        assert "grant-path pin violated" in str(excinfo.value)

    def test_unknown_status_category_default_denied(self, tmp_path):
        with pytest.raises(SandboxSetupError) as excinfo:
            self._run_with_fake_status(
                tmp_path, ("Z", "from a future status writer"))
        assert "unrecognised setup-status category 'Z'" in str(
            excinfo.value)
        assert excinfo.value.setup_category == "Z"

    def test_clean_status_returns_result(self, tmp_path):
        r = self._run_with_fake_status(tmp_path, None)
        assert r.returncode == 0


class TestPinAuthorityAndProtocol:
    def test_caller_env_pins_carry_no_authority(self, tmp_path,
                                                monkeypatch):
        """Only the spawn layer may mint pins: a caller env smuggling
        _RAPTOR_GRANT_PINS on a grant-less run must be dropped, not
        enforced (an attacker-chosen stale pin would otherwise kill
        the run and write into fd 3)."""
        import json
        monkeypatch.setattr(_macos_spawn, "SANDBOX_EXEC",
                            _fake_sandbox_exec(tmp_path))
        pinned = tmp_path / "pinned"
        pinned.mkdir()
        st = os.stat(pinned)
        stale = json.dumps([{"path": str(pinned), "dev": int(st.st_dev),
                             "ino": int(st.st_ino) + 1}])
        r = _macos_spawn.run_sandboxed(
            ["/bin/sh", "-c", 'printf %s "${_RAPTOR_GRANT_PINS:-ABSENT}"'],
            block_network=True,  # no grants → no minted pins
            env={"PATH": "/usr/bin:/bin", "_RAPTOR_GRANT_PINS": stale},
            capture_output=True, text=True, timeout=15,
        )
        assert r.returncode == 0
        assert r.stdout == "ABSENT"
        assert getattr(r, "_setup_status", "missing") is None

    def test_file_grants_are_not_pinned(self, tmp_path, monkeypatch):
        """A granted FILE is legitimately rewritten atomically
        (tmp+rename) by workloads — its identity change must not kill
        the run; only directory grants carry pins."""
        monkeypatch.setattr(_macos_spawn, "SANDBOX_EXEC",
                            _fake_sandbox_exec(tmp_path))
        out = tmp_path / "out"
        out.mkdir()
        granted_file = tmp_path / "artifact.bin"
        granted_file.write_text("v1")
        replacement = tmp_path / "artifact.new"
        replacement.write_text("v2")
        r = _macos_spawn.run_sandboxed(
            ["/bin/sh", "-c",
             f'mv "{replacement}" "{granted_file}"; sleep 0.4; echo ok'],
            output=str(out),
            writable_paths=[str(granted_file), str(tmp_path)],
            env={"PATH": "/usr/bin:/bin"},
            capture_output=True, text=True, timeout=15,
        )
        assert r.returncode == 0, (r.stdout, r.stderr)
        assert getattr(r, "_setup_status", "missing") is None
        assert granted_file.read_text() == "v2"

    def test_unknown_status_bytes_default_denied(self, tmp_path,
                                                 monkeypatch):
        """Bytes the parent's channel parser does not recognise must
        mint a status category (default-deny at the context layer),
        never be dropped as noise beside the readiness byte."""
        import subprocess as _sp
        import types as _types

        class _NoisyPopen:
            def __init__(self, cmd, **kwargs):
                self.cmd = cmd
                self.pid = 4190401
                fd = int(kwargs["env"]["_RAPTOR_STATUS_FD"])
                os.write(fd, b"K")
                os.write(fd, b"Q")  # a writer this parser predates

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def communicate(self, input=None, timeout=None):
                return ("", "")

            def poll(self):
                return 0

            def wait(self, timeout=None):
                return 0

            def kill(self):
                pass

        fake_subprocess = _types.SimpleNamespace(
            Popen=_NoisyPopen,
            TimeoutExpired=_sp.TimeoutExpired,
            CompletedProcess=_sp.CompletedProcess,
            PIPE=_sp.PIPE,
        )
        monkeypatch.setattr(_macos_spawn, "subprocess", fake_subprocess)
        monkeypatch.setattr(_macos_spawn, "_ps_snapshot", lambda: [])
        r = _macos_spawn.run_sandboxed(["/usr/bin/true"], env={})
        status = getattr(r, "_setup_status", None)
        assert status is not None and status[0] == "B", status
        assert "unrecognised bytes" in status[1]


class TestBirthTimeWitness:
    """Serialized pins cannot hold an fd across the exec into the
    shim, so (dev, ino) alone is re-mintable on an inode-recycling
    filesystem. The birth time is the secondary identity witness;
    where the capture host cannot observe one, the run is stamped
    identity-weak instead of silently claiming the full guarantee."""

    def test_capture_without_birthtime_stamps_identity_weak(
            self, tmp_path, monkeypatch):
        """Hosts whose stat reports no st_birthtime (Linux) produce
        identity-weak pins: the clean run must carry the degraded
        stamp naming the pinned roots — never read as the full pin
        guarantee."""
        monkeypatch.setattr(_macos_spawn, "SANDBOX_EXEC",
                            _fake_sandbox_exec(tmp_path))
        out = tmp_path / "out"
        out.mkdir()
        if getattr(os.stat(out), "st_birthtime", None) is not None:
            pytest.skip("host stat reports a birth time")
        r = _macos_spawn.run_sandboxed(
            ["/bin/sh", "-c", "echo ok"],
            output=str(out),
            env={"PATH": "/usr/bin:/bin"},
            capture_output=True, text=True, timeout=15,
        )
        assert r.returncode == 0
        assert r.sandbox_info.get("grant_pin_identity_degraded") == [
            os.path.realpath(str(out))]

    def test_pinned_birthtime_that_vanishes_fails_closed(
            self, tmp_path, monkeypatch):
        """A pin CARRYING the birth-time witness that later stats
        cannot reproduce must refuse — never downgrade to
        dev+ino-only equivalence. Staged by injecting st_birthtime
        into the capture stat only: the parent's last-moment
        re-verify (lstat) sees none and refuses before spawn with the
        typed P-category error."""
        monkeypatch.setattr(_macos_spawn, "SANDBOX_EXEC",
                            _fake_sandbox_exec(tmp_path))
        out = tmp_path / "out"
        out.mkdir()
        if getattr(os.stat(out), "st_birthtime", None) is not None:
            pytest.skip("host stat reports a birth time (cannot stage "
                        "the witness-vanishes shape)")
        real_stat = os.stat
        out_real = os.path.realpath(str(out))

        class _WithBirthtime:
            def __init__(self, st):
                self._st = st
                self.st_birthtime = 1700000000.0

            def __getattr__(self, name):
                return getattr(self._st, name)

        def stat_with_birthtime(target, *args, **kwargs):
            st = real_stat(target, *args, **kwargs)
            if isinstance(target, (str, bytes)) and \
                    os.fspath(target) == out_real:
                return _WithBirthtime(st)
            return st

        monkeypatch.setattr(os, "stat", stat_with_birthtime)
        with pytest.raises(SandboxSetupError, match="birth time"):
            _macos_spawn.run_sandboxed(
                ["/bin/sh", "-c", "echo never"],
                output=str(out),
                env={"PATH": "/usr/bin:/bin"},
                capture_output=True, text=True, timeout=15,
            )
