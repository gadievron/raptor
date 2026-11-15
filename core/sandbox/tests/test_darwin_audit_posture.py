"""Posture honesty for seatbelt audit runs: stamp what is enforced.

Audit mode converts the SBPL read deny into ``(allow file-read* (with
report))`` — observe, don't block — so a darwin ``restrict_reads=True``
audit run has NO read wall: an audited hostile child can read the
telemetry-MAC key and mint tokens. The posture record and
``sandbox_info`` previously stamped the REQUESTED value, so triage
trusted token-verified telemetry exactly on the runs where the target
could mint it. Both stamps now carry the enforced truth (with an
explicit ``read_enforcement: observe-only`` marker at the context
layer), and weakest-wins merging does the rest. Linux is untouched:
its audit tier keeps Landlock enforcing, so the requested value stays
honest there.
"""

from __future__ import annotations

import subprocess
import sys
import types
from unittest import mock

import pytest

from core.sandbox import _macos_spawn
from core.sandbox import summary as summary_mod

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX-only",
)


class _FakePopen:
    """Stand-in for the seatbelt shim process — never spawns."""

    stdin = stdout = stderr = None

    def __init__(self, cmd, **kwargs):
        self.cmd = cmd
        self.pid = 4190301  # never signalled on the normal path

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


class _FakeStreamer:
    def register_target_pid(self, pid):
        pass

    def stop(self, **kw):
        pass


def _spawn(tmp_path, monkeypatch, **kwargs):
    fake_subprocess = types.SimpleNamespace(
        Popen=_FakePopen,
        TimeoutExpired=subprocess.TimeoutExpired,
        CompletedProcess=subprocess.CompletedProcess,
        PIPE=subprocess.PIPE,
    )
    monkeypatch.setattr(_macos_spawn, "subprocess", fake_subprocess)
    monkeypatch.setattr(_macos_spawn, "_ps_snapshot", lambda: [])
    from core.sandbox import seatbelt_audit
    monkeypatch.setattr(seatbelt_audit, "start_log_streamer",
                        lambda *a, **kw: _FakeStreamer())
    return _macos_spawn.run_sandboxed(
        ["/usr/bin/true"], env={}, audit_run_dir=str(tmp_path), **kwargs)


class TestSpawnLayerStamp:
    def test_audit_mode_demotes_restrict_reads_stamp(self, tmp_path,
                                                     monkeypatch):
        _spawn(tmp_path, monkeypatch, restrict_reads=True,
               audit_mode=True)
        posture = summary_mod.get_run_posture(tmp_path)
        assert posture is not None
        assert posture["restrict_reads"] is False, (
            "audit mode emits allow-with-report — the read wall was "
            "not enforced and the posture must say so")
        assert posture["mac_key_hidden"] is False

    def test_non_audit_restrict_reads_stamp_unchanged(self, tmp_path,
                                                      monkeypatch):
        _spawn(tmp_path, monkeypatch, restrict_reads=True)
        posture = summary_mod.get_run_posture(tmp_path)
        assert posture["restrict_reads"] is True
        assert posture["mac_key_hidden"] is True


class TestContextLayerStamp:
    def _run(self, tmp_path, **run_kwargs):
        from core.sandbox import _macos_spawn as macos_mod
        from core.sandbox import context

        def fake_run(cmd, **kwargs):
            cp = subprocess.CompletedProcess(cmd, returncode=0,
                                             stdout="", stderr="")
            cp._setup_status = None
            cp.sandbox_info = {"backend": "macos-seatbelt"}
            return cp

        with mock.patch.object(sys, "platform", "darwin"), \
             mock.patch.object(context, "check_seatbelt_available",
                               return_value=True), \
             mock.patch.object(context, "check_mount_available",
                               return_value=False), \
             mock.patch.object(context, "check_net_available",
                               return_value=False):
            with mock.patch.object(macos_mod, "run_sandboxed", fake_run):
                return context.run(
                    ["/usr/bin/true"], target=str(tmp_path),
                    output=str(tmp_path), timeout=30, **run_kwargs)

    def test_audit_run_stamps_observe_only(self, tmp_path):
        r = self._run(tmp_path, restrict_reads=True, audit=True)
        assert r.sandbox_info["restrict_reads"] is False
        assert r.sandbox_info["read_enforcement"] == "observe-only"
        posture = summary_mod.get_run_posture(tmp_path)
        assert posture is not None
        assert posture["restrict_reads"] is False
        assert posture["mac_key_hidden"] is False

    def test_enforcing_run_keeps_true_stamp(self, tmp_path):
        r = self._run(tmp_path, restrict_reads=True)
        assert r.sandbox_info["restrict_reads"] is True
        assert "read_enforcement" not in r.sandbox_info
        posture = summary_mod.get_run_posture(tmp_path)
        assert posture["restrict_reads"] is True

    def test_audit_without_restrict_reads_not_marked(self, tmp_path):
        # No read wall was requested: nothing was demoted, so no
        # observe-only marker (False stamp is the plain truth).
        r = self._run(tmp_path, restrict_reads=False, audit=True)
        assert r.sandbox_info["restrict_reads"] is False
        assert "read_enforcement" not in r.sandbox_info
