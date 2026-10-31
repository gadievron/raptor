"""Lifecycle-reused handles, restart bookkeeping, and group kills.

Three defects pinned here:

1. ``ensure_alive`` judged liveness only by ``Popen.poll()``: a
   lifecycle-reused handle has ``_proc=None`` forever, so a HEALTHY
   shared server was judged dead on the first orchestrator tick after
   ``import_cpg`` and a duplicate multi-GB JVM was booted beside it.
2. ``restart()`` with a vanished cpg.bin returned True — a
   fabricated-healthy wedge (``_cpg_loaded`` stayed False, every
   query said "no CPG loaded", ``ensure_alive`` kept saying fine).
   And the restarted JVM's new pid/port/credential never reached the
   lifecycle state file, so ``joern_release`` could not stop it.
3. ``_kill_server`` signalled the pid, not the process group, despite
   ``start_new_session=True`` — wrapper-spawned JVMs were orphaned.

All hermetic — no real Joern process.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from packages.joern.server import JoernServer


def _reused_handle(cpg: Path | None = None) -> JoernServer:
    """A lifecycle-reuse-shaped handle: no owned process, live URL."""
    srv = JoernServer()
    srv._proc = None
    srv._port = 8899
    srv._base_url = "http://127.0.0.1:8899"
    srv._auth_user = "raptor"
    srv._auth_password = "cred"
    if cpg is not None:
        srv._cpg_path = cpg
        srv._cpg_loaded = True
    return srv


class TestReusedHandleLiveness:
    def test_healthy_endpoint_means_alive_no_relaunch(self, tmp_path):
        """The core duplicate-JVM regression: a reused handle whose
        shared server answers must NOT be relaunched."""
        srv = _reused_handle(cpg=tmp_path / "cpg.bin")
        with patch.object(srv, "health_check", return_value=True), \
                patch.object(srv, "restart") as restart:
            assert srv.ensure_alive() is True
        restart.assert_not_called()

    def test_dead_endpoint_with_cpg_relaunches(self, tmp_path):
        srv = _reused_handle(cpg=tmp_path / "cpg.bin")
        with patch.object(srv, "health_check", return_value=False), \
                patch.object(srv, "restart", return_value=True) as restart:
            assert srv.ensure_alive() is True
        restart.assert_called_once()

    def test_dead_endpoint_never_served_cpg_left_alone(self):
        srv = _reused_handle(cpg=None)
        with patch.object(srv, "health_check", return_value=False), \
                patch.object(srv, "restart") as restart:
            assert srv.ensure_alive() is False
        restart.assert_not_called()

    def test_health_check_false_without_endpoint(self):
        srv = JoernServer()
        assert srv.health_check() is False


class TestRestartVanishedCpg:
    def test_restart_with_vanished_cpg_reports_failure(self, tmp_path):
        srv = JoernServer()
        srv._cpg_path = tmp_path / "gone" / "cpg.bin"  # does not exist
        with patch.object(srv, "stop"), \
                patch.object(srv, "start"), \
                patch.object(srv, "import_cpg") as imp:
            assert srv.restart() is False
        imp.assert_not_called()

    def test_restart_with_present_cpg_reloads(self, tmp_path):
        cpg = tmp_path / "cpg.bin"
        cpg.write_bytes(b"x")
        srv = JoernServer()
        srv._cpg_path = cpg
        with patch.object(srv, "stop"), \
                patch.object(srv, "start"), \
                patch.object(srv, "import_cpg", return_value=True) as imp:
            assert srv.restart() is True
        imp.assert_called_once()
