"""Host-global JVM heap admission ledger.

Pre-fix, N concurrent sessions each derived a near-host-sized -Xmx
independently; the committed sum crossed physical RAM and the kernel
OOM-killed whichever JVM grew last. The ledger clamps DERIVED grants
to the remaining budget at spawn time; explicit operator heaps
register but are never reduced; dead owners' rows self-evict.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
from pathlib import Path

import pytest

from packages.joern import heap_ledger
from packages.joern.heap_ledger import (
    _HEAP_GRANT_FLOOR_MB,
    _pid_starttime,
    heap_admission,
    reserve_heap_mb,
)


def _rows(path: Path) -> list[dict]:
    return json.loads(path.read_text())["rows"]


def _set_budget(monkeypatch, mb: int | None) -> None:
    monkeypatch.setattr(heap_ledger, "_host_budget_mb", lambda: mb)


class TestAdmission:
    def test_empty_ledger_grants_full(self, tmp_path, monkeypatch):
        # The one-session case must be unaffected: committed=0 →
        # full grant, whatever the budget.
        _set_budget(monkeypatch, 8192)
        res = reserve_heap_mb(
            8192, derived=True, ledger_path=tmp_path / "l.json")
        assert res.granted_mb == 8192

    def test_derived_clamped_to_remaining_budget(self, tmp_path,
                                                 monkeypatch, caplog):
        _set_budget(monkeypatch, 10000)
        ledger = tmp_path / "l.json"
        first = reserve_heap_mb(6000, derived=True, ledger_path=ledger)
        assert first.granted_mb == 6000
        with caplog.at_level("WARNING"):
            second = reserve_heap_mb(
                6000, derived=True, ledger_path=ledger)
        assert second.granted_mb == 4000
        assert "6000" in caplog.text and "clamped" in caplog.text

    def test_explicit_registers_but_is_never_reduced(self, tmp_path,
                                                     monkeypatch, caplog):
        # Operator assertion, both directions of the rule: the
        # explicit heap keeps its exact value even over budget, AND
        # a later derived spawn sees its pressure.
        _set_budget(monkeypatch, 10000)
        ledger = tmp_path / "l.json"
        with caplog.at_level("WARNING"):
            explicit = reserve_heap_mb(
                12000, derived=False, ledger_path=ledger)
        assert explicit.granted_mb == 12000
        assert "operator assertion" in caplog.text
        derived = reserve_heap_mb(4000, derived=True, ledger_path=ledger)
        assert derived.granted_mb == _HEAP_GRANT_FLOOR_MB

    def test_floor_grant_when_budget_exhausted(self, tmp_path,
                                               monkeypatch, caplog):
        _set_budget(monkeypatch, 5000)
        ledger = tmp_path / "l.json"
        reserve_heap_mb(5000, derived=True, ledger_path=ledger)
        with caplog.at_level("WARNING"):
            res = reserve_heap_mb(4000, derived=True, ledger_path=ledger)
        # Never refused: the floor keeps the joern channel bootable.
        assert res.granted_mb == _HEAP_GRANT_FLOOR_MB
        # The loud warning names the committed total.
        assert "5000" in caplog.text and "exhausted" in caplog.text

    def test_floor_never_inflates_a_small_request(self, tmp_path,
                                                  monkeypatch):
        # The floor's other direction: a request BELOW the floor is
        # granted as requested, not raised to it.
        _set_budget(monkeypatch, 5000)
        ledger = tmp_path / "l.json"
        reserve_heap_mb(5000, derived=True, ledger_path=ledger)
        small = reserve_heap_mb(512, derived=True, ledger_path=ledger)
        assert small.granted_mb == 512

    def test_undetectable_ram_registers_without_clamp(self, tmp_path,
                                                      monkeypatch):
        _set_budget(monkeypatch, None)
        ledger = tmp_path / "l.json"
        a = reserve_heap_mb(60000, derived=True, ledger_path=ledger)
        b = reserve_heap_mb(60000, derived=True, ledger_path=ledger)
        assert a.granted_mb == b.granted_mb == 60000
        assert len(_rows(ledger)) == 2


class TestRowLifecycle:
    def test_dead_row_evicted_at_admission(self, tmp_path, monkeypatch):
        # The self-heal path: a reservation whose recorded starttime
        # no longer matches its pid (owner died, pid possibly reused)
        # frees its heap at the next admission — no release protocol.
        _set_budget(monkeypatch, 10000)
        ledger = tmp_path / "l.json"
        me = os.getpid()
        dead = {"id": "dead", "pid": me,
                "starttime": (_pid_starttime(me) or 0) + 12345,
                "mb": 9000, "derived": True, "created_at": 0.0}
        live = {"id": "live", "pid": me, "starttime": _pid_starttime(me),
                "mb": 2000, "derived": True, "created_at": 0.0}
        ledger.write_text(json.dumps({"version": 1,
                                      "rows": [dead, live]}))
        res = reserve_heap_mb(9000, derived=True, ledger_path=ledger)
        # Only the live 2000 counted: 8000 remained.
        assert res.granted_mb == 8000
        ids = {r["id"] for r in _rows(ledger)}
        assert "dead" not in ids
        assert "live" in ids

    def test_release_is_idempotent(self, tmp_path):
        ledger = tmp_path / "l.json"
        res = reserve_heap_mb(2048, derived=True, ledger_path=ledger)
        assert len(_rows(ledger)) == 1
        res.release()
        res.release()
        assert _rows(ledger) == []

    def test_rebind_rekeys_row_to_jvm(self, tmp_path):
        # The shared server outlives its spawner: after rebind the
        # row must live and die with the JVM process, not with the
        # session that booted it.
        ledger = tmp_path / "l.json"
        proc = subprocess.Popen(["sleep", "60"])
        try:
            res = reserve_heap_mb(2048, derived=True, ledger_path=ledger)
            res.rebind(proc.pid)
            (row,) = _rows(ledger)
            assert row["pid"] == proc.pid
            assert row["starttime"] == _pid_starttime(proc.pid)
        finally:
            proc.terminate()
            proc.wait(timeout=10)
        # Owner dead → the row evicts at the next admission.
        reserve_heap_mb(1, derived=True, ledger_path=ledger)
        assert all(r["pid"] != proc.pid for r in _rows(ledger))

    def test_corrupt_ledger_treated_as_empty(self, tmp_path, monkeypatch):
        _set_budget(monkeypatch, 4096)
        ledger = tmp_path / "l.json"
        ledger.write_text("{not json")
        res = reserve_heap_mb(4096, derived=True, ledger_path=ledger)
        assert res.granted_mb == 4096
        assert len(_rows(ledger)) == 1  # rewritten valid


class TestConcurrentAdmission:
    def test_racing_reservations_never_oversubscribe(self, tmp_path,
                                                     monkeypatch):
        # Two sessions admit at once: the flock serialises them, so
        # the second sees the first's row — grants sum to the budget,
        # not to 2x the derivation.
        _set_budget(monkeypatch, 10000)
        ledger = tmp_path / "l.json"
        grants: list[int] = []
        barrier = threading.Barrier(2)

        def worker() -> None:
            barrier.wait(timeout=30)
            res = reserve_heap_mb(6000, derived=True, ledger_path=ledger)
            grants.append(res.granted_mb)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        assert sorted(grants) == [4000, 6000]


class TestHostileRowSchema:
    """The ledger file is same-uid writable: admission must not trust
    row schema it did not write. A crafted row may steer grants but
    must never OPEN the budget (negative sums) or become immortal."""

    def test_negative_mb_does_not_open_the_budget(self, tmp_path,
                                                  monkeypatch):
        _set_budget(monkeypatch, 10000)
        ledger = tmp_path / "l.json"
        me = os.getpid()
        rows = [
            {"id": "neg", "pid": me, "starttime": _pid_starttime(me),
             "mb": -(10 ** 9), "derived": True, "created_at": 0.0},
            {"id": "real", "pid": me, "starttime": _pid_starttime(me),
             "mb": 6000, "derived": True, "created_at": 0.0},
        ]
        ledger.write_text(json.dumps({"version": 1, "rows": rows}))
        res = reserve_heap_mb(6000, derived=True, ledger_path=ledger)
        # The poisoned row counts as 0, not -1e9: only 4000 remains.
        assert res.granted_mb == 4000

    def test_bool_mb_counts_as_zero(self, tmp_path, monkeypatch):
        _set_budget(monkeypatch, 4096)
        ledger = tmp_path / "l.json"
        me = os.getpid()
        row = {"id": "b", "pid": me, "starttime": _pid_starttime(me),
               "mb": True, "derived": True, "created_at": 0.0}
        ledger.write_text(json.dumps({"version": 1, "rows": [row]}))
        res = reserve_heap_mb(4096, derived=True, ledger_path=ledger)
        assert res.granted_mb == 4096

    def test_null_starttime_row_evicts(self, tmp_path, monkeypatch):
        # A row with starttime null would otherwise live as long as
        # its pid NUMBER stays occupied by anyone — immortal when
        # pinned to pid 1 — defeating the pid-reuse defense.
        if _pid_starttime(1) is None:
            pytest.skip("no readable /proc/1/stat on this platform")
        _set_budget(monkeypatch, 10000)
        ledger = tmp_path / "l.json"
        row = {"id": "immortal", "pid": 1, "starttime": None,
               "mb": 9000, "derived": True, "created_at": 0.0}
        ledger.write_text(json.dumps({"version": 1, "rows": [row]}))
        res = reserve_heap_mb(9000, derived=True, ledger_path=ledger)
        assert res.granted_mb == 9000
        assert "immortal" not in {r["id"] for r in _rows(ledger)}


class TestLedgerUnavailable:
    def test_reserve_degrades_when_ledger_write_fails(
            self, tmp_path, monkeypatch, caplog):
        # The ledger is advisory bookkeeping — a full or read-only
        # state dir must not kill the JVM boot it arbitrates (the
        # release/rebind paths already degrade to a debug log).
        _set_budget(monkeypatch, 8192)

        def boom(path, rows):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(heap_ledger, "_write_rows", boom)
        with caplog.at_level("WARNING"):
            res = reserve_heap_mb(
                4096, derived=True, ledger_path=tmp_path / "l.json")
        assert res.granted_mb == 4096
        assert "ledger unavailable" in caplog.text
        res.release()  # must not raise either

    def test_reserve_degrades_when_ledger_dir_unwritable(
            self, tmp_path, monkeypatch):
        if os.geteuid() == 0:
            pytest.skip("root bypasses directory permissions")
        _set_budget(monkeypatch, 8192)
        ro = tmp_path / "ro"
        ro.mkdir()
        ro.chmod(0o500)
        try:
            res = reserve_heap_mb(
                4096, derived=True,
                ledger_path=ro / "sub" / "l.json")
        finally:
            ro.chmod(0o700)
        assert res.granted_mb == 4096


class TestHeapAdmissionContext:
    def test_reserves_for_the_call_and_releases(self, tmp_path,
                                                monkeypatch):
        _set_budget(monkeypatch, 10000)
        ledger = tmp_path / "l.json"
        with heap_admission(6000, derived=True,
                            ledger_path=ledger) as granted:
            assert granted == 6000
            assert len(_rows(ledger)) == 1
        assert _rows(ledger) == []

    def test_none_heap_is_a_no_op(self, tmp_path):
        ledger = tmp_path / "l.json"
        with heap_admission(None, derived=True,
                            ledger_path=ledger) as granted:
            assert granted is None
        assert not ledger.exists()


class TestServerHeapAdmission:
    """The query-server seam: admission before exec, rebind to the
    JVM member, release on stop and on boot failure."""

    @staticmethod
    def _fake_popen_factory(captured_cmd: list, *, poll_result=None):
        from unittest.mock import MagicMock

        def fake_popen(cmd, **kwargs):
            captured_cmd.extend(cmd)
            mock_proc = MagicMock()
            mock_proc.pid = 2_000_000_000  # inert: beyond pid_max
            mock_proc.poll.return_value = poll_result
            mock_proc.stderr = MagicMock()
            mock_proc.wait = MagicMock()
            return mock_proc

        return fake_popen

    def _boot(self, srv, captured_cmd: list, *, ready=True):
        from unittest.mock import patch

        with (
            patch("packages.joern.prereqs._java_version",
                  return_value=21),
            patch("packages.joern.server._server_auth_supported",
                  return_value=True),
            patch("packages.joern.server._netns_isolation_available",
                  return_value=False),
            patch("packages.joern.server.os.killpg",
                  side_effect=ProcessLookupError),
            patch("packages.joern.server.subprocess.Popen",
                  side_effect=self._fake_popen_factory(captured_cmd)),
            patch.object(srv, "_wait_for_ready", return_value=ready),
            patch.object(srv, "_warmup_imports"),
        ):
            srv.start()

    @staticmethod
    def _safe_stop(srv):
        from unittest.mock import patch

        with patch("packages.joern.server.os.killpg",
                   side_effect=ProcessLookupError):
            srv.stop()

    def test_derived_heap_clamped_in_argv_and_released_on_stop(
            self, tmp_path, monkeypatch):
        from packages.joern.server import JoernServer

        _set_budget(monkeypatch, 10000)
        ledger = tmp_path / "server-ledger.json"
        monkeypatch.setattr(heap_ledger, "_LEDGER_PATH", ledger)
        sibling = reserve_heap_mb(6000, derived=True, ledger_path=ledger)

        srv = JoernServer(heap_mb=6000, heap_is_derived=True)
        captured: list = []
        self._boot(srv, captured)
        try:
            assert "-J-Xmx4000m" in captured
            assert "-J-Xmx6000m" not in captured
            assert len(_rows(ledger)) == 2
        finally:
            self._safe_stop(srv)
        (row,) = _rows(ledger)  # only the sibling's row remains
        assert row["mb"] == 6000
        sibling.release()

    def test_explicit_heap_not_clamped(self, tmp_path, monkeypatch):
        from packages.joern.server import JoernServer

        _set_budget(monkeypatch, 10000)
        ledger = tmp_path / "server-ledger.json"
        monkeypatch.setattr(heap_ledger, "_LEDGER_PATH", ledger)
        reserve_heap_mb(9000, derived=True, ledger_path=ledger)

        srv = JoernServer(heap_mb=6000, heap_is_derived=False)
        captured: list = []
        self._boot(srv, captured)
        try:
            assert "-J-Xmx6000m" in captured
        finally:
            self._safe_stop(srv)

    def test_boot_failure_releases_reservation(self, tmp_path,
                                               monkeypatch):
        import pytest

        from packages.joern.server import JoernServer

        _set_budget(monkeypatch, 10000)
        ledger = tmp_path / "server-ledger.json"
        monkeypatch.setattr(heap_ledger, "_LEDGER_PATH", ledger)

        srv = JoernServer(heap_mb=6000, heap_is_derived=True)
        with pytest.raises(RuntimeError):
            self._boot(srv, [], ready=False)
        # A boot that never yielded a live server holds no phantom
        # reservation that would clamp sibling sessions.
        assert _rows(ledger) == []

    def test_reservation_rebinds_to_jvm_member(self, tmp_path,
                                               monkeypatch):
        # The property the rebind exists for: the row follows the JVM
        # process, so it outlives the booting session and evicts when
        # the JVM (not the booter) dies.
        from unittest.mock import patch

        from packages.joern.server import JoernServer

        ledger = tmp_path / "server-ledger.json"
        monkeypatch.setattr(heap_ledger, "_LEDGER_PATH", ledger)
        jvm = subprocess.Popen(["sleep", "60"])
        try:
            srv = JoernServer(heap_mb=2048, heap_is_derived=True)
            member = (jvm.pid, _pid_starttime(jvm.pid), "java")
            with patch("packages.joern.server._find_jvm_member",
                       return_value=member):
                self._boot(srv, [])
            try:
                (row,) = _rows(ledger)
                assert row["pid"] == jvm.pid
                assert row["starttime"] == _pid_starttime(jvm.pid)
            finally:
                self._safe_stop(srv)
        finally:
            jvm.terminate()
            jvm.wait(timeout=10)


class TestBuildCpgAdmission:
    """The joern-parse seam: admission spans exactly the build call."""

    @staticmethod
    def _make_target(tmp_path: Path) -> Path:
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int main() {}")
        return target

    def test_derived_parse_heap_clamped_and_released(self, tmp_path,
                                                     monkeypatch):
        from types import SimpleNamespace

        from packages.joern.runner import build_cpg

        _set_budget(monkeypatch, 10000)
        ledger = tmp_path / "build-ledger.json"
        monkeypatch.setattr(heap_ledger, "_LEDGER_PATH", ledger)
        reserve_heap_mb(7000, derived=True, ledger_path=ledger)

        seen: dict = {}

        def fake_runner(cmd, **kw):
            seen["cmd"] = list(cmd)
            seen["rows_during_build"] = len(_rows(ledger))
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        build_cpg(
            self._make_target(tmp_path),
            output_dir=tmp_path / "out",
            subprocess_runner=fake_runner,
            heap_mb=6000,
            heap_is_derived=True,
        )
        assert "-J-Xmx3000m" in seen["cmd"]
        assert seen["rows_during_build"] == 2  # held across the JVM run
        assert len(_rows(ledger)) == 1        # released after

    def test_explicit_parse_heap_unclamped(self, tmp_path, monkeypatch):
        from types import SimpleNamespace

        from packages.joern.runner import build_cpg

        _set_budget(monkeypatch, 10000)
        ledger = tmp_path / "build-ledger.json"
        monkeypatch.setattr(heap_ledger, "_LEDGER_PATH", ledger)
        reserve_heap_mb(9000, derived=True, ledger_path=ledger)

        seen: dict = {}

        def fake_runner(cmd, **kw):
            seen["cmd"] = list(cmd)
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        build_cpg(
            self._make_target(tmp_path),
            output_dir=tmp_path / "out",
            subprocess_runner=fake_runner,
            heap_mb=6000,
            heap_is_derived=False,
        )
        assert "-J-Xmx6000m" in seen["cmd"]
